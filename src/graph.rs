//! Resolving a build file's dependency graph, and building it.
//!
//! A build used to discover its dependencies while building them: each one was
//! loaded at the moment the walk reached it. That is fine while the walk is
//! sequential and hopeless once it is not, because the two things a concurrent
//! walk most needs to know - is this a cycle, and have I already built this -
//! are questions about the *shape* of the graph, asked from inside the walk
//! that is still discovering it.
//!
//! So the shape is settled first. [`Graph::resolve`] reads every build file
//! reachable from the root, keyed by canonical path, and rejects a cycle, a
//! missing build file, an unclassifiable command or two packages fighting over
//! one archive name **before a single build step runs** - the same order
//! [`crate::bf::BuildFile`] already used when it derived a policy before
//! walking dependencies. A diamond becomes one node by construction, so the
//! "build it once" rule stops being something the walk has to remember.

use std::{
    any::Any,
    collections::HashMap,
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread::{available_parallelism, scope},
};

use miette::{IntoDiagnostic, WrapErr, miette};
use tracing::{debug, info, warn};

use crate::{
    bf::{BuildFile, BuildOptions, Verification},
    cancel::Cancel,
    context::BuildContext,
    policy::BuildPolicy,
    progress::{Progress, Task},
};

/// Every build file reachable from a root, resolved and checked.
///
/// Holding one of these is the statement that the graph is buildable: the
/// checks that could reject it have already run.
pub struct Graph {
    nodes: Vec<Node>,
    /// The package the caller asked for, whose archive is the build's result.
    root: usize,
    /// Node indices in an order where every dependency precedes its dependents.
    order: Vec<usize>,
}

/// One package in the graph.
struct Node {
    /// Canonical path of the build file. Two build files at one path are one
    /// package, which is what makes a diamond a single node.
    key: PathBuf,
    build: BuildFile,
    policy: BuildPolicy,
    /// Indices into [`Graph::nodes`].
    dependencies: Vec<usize>,
}

/// What every worker in one [`Graph::build_with`] call needs, and does not
/// change while the schedule runs.
///
/// Bundled into one value instead of three parameters on [`Graph::work`]: it
/// is exactly the set of things every worker shares unchanged for the whole
/// build, as distinct from `schedule`, `wakeup` and `summary`, which are the
/// scheduler's own mutable state. `cancel` itself is not here: cancellation is
/// checked as `Schedule::cancelled`, under the same lock a worker already
/// holds while deciding whether to park - see `Graph::build_with`.
struct BuildRun<'a> {
    ctx: &'a BuildContext,
    options: BuildOptions,
    progress: &'a Progress,
}

impl Graph {
    /// Read the whole graph rooted at `root` and check that it can be built.
    ///
    /// Every build file is loaded at `root`'s own strictness: a signed root
    /// checks signatures all the way down, an unverified one never starts.
    /// Each node's sandbox policy is derived here too, so a dependency whose
    /// commands match no fingerprint is reported before the packages ahead of
    /// it in the queue have built anything.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when a dependency path is not a build file or
    /// cannot be canonicalised, when a build file cannot be loaded or
    /// verified, when the dependencies close a cycle, when a build file's
    /// commands cannot be classified, or when two packages in the graph would
    /// be packaged to the same archive name.
    pub fn resolve(root: &BuildFile, options: BuildOptions) -> miette::Result<Self> {
        Self::resolve_in(&BuildContext::from_env()?, root, options)
    }

    /// As [`Graph::resolve`], resolving relative dependency paths against
    /// `ctx.cwd` and verifying signed dependencies against `ctx.trust_dir`
    /// instead of reading either from the process.
    ///
    /// # Errors
    ///
    /// As [`Graph::resolve`].
    pub fn resolve_in(
        ctx: &BuildContext,
        root: &BuildFile,
        options: BuildOptions,
    ) -> miette::Result<Self> {
        let key = match root.source() {
            // Fall back to the path as given when it cannot be canonicalised,
            // exactly as parsing does: identity degrades, resolution still runs.
            Some(source) => source
                .canonicalize()
                .unwrap_or_else(|_| source.to_path_buf()),
            // A build file built in memory rather than read off disk has no
            // path to be identified by. It is the root, so nothing can point
            // back at it and it needs no identity beyond being first.
            None => PathBuf::from("<in-memory build file>"),
        };

        let mut resolver = Resolver {
            ctx,
            nodes: Vec::new(),
            order: Vec::new(),
            state: HashMap::new(),
            verification: root.verification(),
            permissive: options.permissive,
        };

        let root_index = resolver.visit(key, root.clone(), &mut Vec::new())?;
        let graph = Self {
            nodes: resolver.nodes,
            root: root_index,
            order: resolver.order,
        };
        graph.reject_archive_collisions()?;

        info!(packages = graph.len(), "resolved the dependency graph");
        Ok(graph)
    }

    /// How many packages the graph holds, the root included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph holds no packages at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Package names, every dependency ahead of the packages that need it.
    pub fn order(&self) -> impl Iterator<Item = &str> {
        self.order
            .iter()
            .map(|index| self.nodes[*index].build.name())
    }

    /// Build every package in the graph, returning the root's archive.
    ///
    /// Up to `options.jobs` packages build at once, on dedicated threads rather
    /// than the global Rayon pool. That is deliberate: a package build blocks in
    /// `wait` on a subprocess, which a Rayon worker cannot steal its way out of,
    /// and the pool is already carrying the parallel downloads of
    /// [`crate::step::Step`] and the source scan of [`crate::perms::source`]
    /// *inside* each of those builds.
    ///
    /// A package whose dependency failed is never started. Everything that does
    /// not depend on a failure keeps building, so one run reports every
    /// independent breakage rather than the first one.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic naming every package that failed, and how many were
    /// skipped because something they needed did.
    pub fn build(&self, options: BuildOptions, progress: &Progress) -> miette::Result<PathBuf> {
        self.build_in(&BuildContext::from_env()?, options, progress)
    }

    /// As [`Graph::build`], with the caller's environment made explicit: every
    /// package's archive lands under `ctx.output_dir`, and its sandbox reads
    /// `ctx.path`/`ctx.home`/`ctx.scratch_root` instead of the process's.
    ///
    /// # Errors
    ///
    /// As [`Graph::build`].
    pub fn build_in(
        &self,
        ctx: &BuildContext,
        options: BuildOptions,
        progress: &Progress,
    ) -> miette::Result<PathBuf> {
        self.build_with(ctx, options, progress, &Cancel::new())
    }

    /// As [`Graph::build_in`], with a [`Cancel`] token the caller can trip to
    /// stop the scheduler handing out any package that has not already
    /// started. Best-effort: a package already claimed keeps running to
    /// completion, since nothing here kills it.
    ///
    /// # Errors
    ///
    /// As [`Graph::build_in`], and also when the schedule this call built is
    /// somehow still shared once every worker has joined - see the comment
    /// where it is unwrapped below. That should be unreachable.
    pub fn build_with(
        &self,
        ctx: &BuildContext,
        options: BuildOptions,
        progress: &Progress,
        cancel: &Cancel,
    ) -> miette::Result<PathBuf> {
        let jobs = options
            .jobs
            .map_or_else(default_jobs, NonZeroUsize::get)
            // More workers than packages just means idle threads.
            .min(self.len().max(1));
        info!(packages = self.len(), jobs, "building the dependency graph");

        let summary = progress.task(format!("{} packages", self.len()));
        // `Arc`-wrapped so the closure registered with `cancel` below can hold
        // its own clone, outliving this function if a caller keeps `cancel`
        // around after the build returns - `clear_wakeup` drops that clone
        // again once every worker has joined, before `schedule` is unwrapped.
        let schedule = Arc::new(Mutex::new(Schedule::new(self)));
        let wakeup = Arc::new(Condvar::new());

        // `cancel.cancel()` runs this closure in addition to setting its own
        // flag. It locks `schedule` - the exact mutex `claim`'s check-then-park
        // sequence holds throughout - sets `Schedule::cancelled` WHILE HOLDING
        // that lock, then releases it and only afterwards notifies `wakeup`.
        // The notify need not happen before the unlock - a condvar does not
        // require that, and this one does not do it. What closes the race is
        // that the WRITE happens under the same lock a worker's
        // check-then-park sequence also holds throughout: by the time the
        // write lands, a worker has either not yet checked (and will see the
        // new value) or has already parked (and is registered as a waiter the
        // notify will reach). There is no instant where the flag is set and a
        // worker holds neither the lock nor a wait registration. A plain flag
        // set outside this lock, followed by a separately locked
        // `notify_all`, gives you no such thing: a worker can see the flag
        // still clear, decide to park, and only reach `Condvar::wait` after
        // the notification already fired - a condvar remembers nothing, so
        // that wakeup is simply lost, and the worker would sleep until an
        // unrelated package happened to settle and notify for its own
        // reasons, possibly the rest of that package's build time later.
        let bridge_schedule = Arc::clone(&schedule);
        let bridge_wakeup = Arc::clone(&wakeup);
        cancel.register_wakeup(move || {
            lock(&bridge_schedule).cancelled = true;
            bridge_wakeup.notify_all();
        });

        let run = BuildRun {
            ctx,
            options,
            progress,
        };

        scope(|threads| {
            for _ in 0..jobs {
                threads.spawn(|| self.work(&run, &schedule, &wakeup, &summary));
            }
        });

        // Every worker has joined, so the closure above will never run again
        // for this build. Drop it before reclaiming `schedule`, or the `Arc`
        // below would still be shared and `try_unwrap` would fail.
        cancel.clear_wakeup();

        let schedule = Arc::try_unwrap(schedule).map_err(|_| {
            miette!(
                "the build's schedule was still shared after every worker had joined; this is a bug"
            )
        })?;
        schedule
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .outcome(self)
    }

    /// One worker: take a ready package, build it, release what it unblocks.
    fn work(&self, run: &BuildRun, schedule: &Mutex<Schedule>, wakeup: &Condvar, summary: &Task) {
        while let Some((index, archives)) = self.claim(schedule, wakeup, summary) {
            let node = &self.nodes[index];
            // Built outside the lock: this is the part that takes minutes.
            //
            // A panic has to be caught rather than allowed to unwind. This
            // worker would never reach `settle`, so the package it claimed
            // would stay `running` for ever, the other workers would wait on a
            // condvar nobody can notify, and `scope` would block joining them:
            // a hang instead of a failure. Sequentially a panic simply
            // propagated; making the walk concurrent is what introduced this.
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                node.build
                    .build_alone(run.ctx, run.options, &node.policy, run.progress, &archives)
            }));
            let result = attempt
                .unwrap_or_else(|panic| {
                    Err(miette!(
                        "the build of {} panicked: {}",
                        node.build.name(),
                        describe_panic(&panic)
                    ))
                })
                .wrap_err_with(|| format!("package {} failed", node.build.name()));

            let mut state = lock(schedule);
            state.settle(self, index, result);
            state.describe(summary, self.len());
            drop(state);
            wakeup.notify_all();
        }
    }

    /// Wait for a package to become ready and claim it, with its dependencies'
    /// archives. `None` means there is no work left for anybody, or that the
    /// build has been cancelled.
    ///
    /// `cancelled` lives on `Schedule` itself rather than being read off a
    /// [`Cancel`] token directly: this loop's check and its `wakeup.wait`
    /// below both run under `schedule`'s lock, and `Cancel::register_wakeup`
    /// (see `Graph::build_with`) sets this same field under that same lock,
    /// which is what makes a tripped cancellation impossible to miss between
    /// the check and the park.
    fn claim(
        &self,
        schedule: &Mutex<Schedule>,
        wakeup: &Condvar,
        summary: &Task,
    ) -> Option<(usize, Vec<PathBuf>)> {
        let mut state = lock(schedule);

        loop {
            // Checked before anything else, on every pass through this loop -
            // including the one right after this worker parks and is woken
            // again - so a package that becomes ready only after cancellation
            // is never handed out either.
            if state.cancelled {
                return None;
            }

            if let Some(index) = state.ready.pop() {
                state.running += 1;
                let archives = state.archives_for(self, index);
                state.describe(summary, self.len());
                return Some((index, archives));
            }

            if state.unsettled == 0 {
                return None;
            }

            // Nothing ready, nothing running, yet packages remain: no worker
            // can ever wake this up. A correct schedule cannot reach here, so
            // rather than block forever, abandon what is left and let
            // `outcome` report it.
            if state.running == 0 {
                warn!("the build schedule stalled; abandoning the packages left in it");
                state.abandon_remaining();
                return None;
            }

            state = wakeup.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Reject two packages that would be packaged to the same file name.
    ///
    /// They are distinct build files, so the graph is happy to hold both - but
    /// `<name>-<version>.cpkg` is derived from their contents rather than their
    /// path, and both would be renamed onto one destination. Sequentially that
    /// was a silent overwrite; concurrently it is a race. Neither is worth
    /// letting through when one pass over the nodes finds it.
    fn reject_archive_collisions(&self) -> miette::Result<()> {
        let mut claimed: HashMap<String, &Path> = HashMap::new();

        for node in &self.nodes {
            let archive = archive_name(&node.build);
            if let Some(first) = claimed.insert(archive.clone(), &node.key) {
                return Err(miette!(
                    "two build files in this graph both package to `{archive}`: {} and {}; \
                     rename or re-version one of them",
                    first.display(),
                    node.key.display()
                ));
            }
        }

        Ok(())
    }
}

impl std::fmt::Debug for Graph {
    /// The graph's shape: each package followed by what it depends on, in
    /// build order. `BuildFile` and `BuildPolicy` carry a lot that says nothing
    /// about the graph, so this prints the edges rather than deriving.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut listing = f.debug_struct("Graph");
        listing.field("root", &self.nodes[self.root].build.name());
        for index in &self.order {
            let node = &self.nodes[*index];
            let needs: Vec<&str> = node
                .dependencies
                .iter()
                .map(|dependency| self.nodes[*dependency].build.name())
                .collect();
            listing.field(node.build.name(), &needs);
        }
        listing.finish()
    }
}

/// The archive file name a build file packages to.
fn archive_name(build: &BuildFile) -> String {
    format!("{}-{}.cpkg", build.name(), build.version_string())
}

/// Depth-first resolution state.
struct Resolver<'a> {
    ctx: &'a BuildContext,
    nodes: Vec<Node>,
    order: Vec<usize>,
    state: HashMap<PathBuf, State>,
    verification: Verification,
    permissive: bool,
}

/// How far a build file has got through resolution.
enum State {
    /// On the current depth-first stack. Reaching it again closes a cycle.
    Visiting,
    /// Fully resolved, at this index.
    Resolved(usize),
}

impl Resolver<'_> {
    /// Resolve `build` and everything under it, returning its node index.
    ///
    /// `stack` is the current depth-first path, used to render a cycle.
    fn visit(
        &mut self,
        key: PathBuf,
        build: BuildFile,
        stack: &mut Vec<PathBuf>,
    ) -> miette::Result<usize> {
        self.state.insert(key.clone(), State::Visiting);
        stack.push(key.clone());

        let policy = BuildPolicy::derive(&build, self.permissive).wrap_err_with(|| {
            format!(
                "cannot derive a sandbox policy for {}; run `pm explain` on it to see the \
                 whole build file, or build with --permissive to allow the commands anyway",
                build.name()
            )
        })?;

        let mut dependencies = Vec::with_capacity(build.dependencies().len());
        for dependency in build.dependencies() {
            dependencies.push(self.visit_dependency(dependency, build.name(), stack)?);
        }

        stack.pop();

        // Pushed after its dependencies, so `order` comes out with every
        // dependency ahead of whatever needs it.
        let index = self.nodes.len();
        self.nodes.push(Node {
            key: key.clone(),
            build,
            policy,
            dependencies,
        });
        self.order.push(index);
        self.state.insert(key, State::Resolved(index));
        Ok(index)
    }

    /// Resolve one dependency of `parent`, loading it if this is its first visit.
    fn visit_dependency(
        &mut self,
        dependency: &Path,
        parent: &str,
        stack: &mut Vec<PathBuf>,
    ) -> miette::Result<usize> {
        // A relative dependency path is resolved against the CALLER's cwd, not
        // the process's: a daemon builds on a client's behalf, whose working
        // directory is not the daemon's own.
        let resolved = if dependency.is_relative() {
            self.ctx.cwd.join(dependency)
        } else {
            dependency.to_path_buf()
        };

        if !resolved.is_file() {
            return Err(miette!(
                "dependency of {parent} is not a build file: {}",
                dependency.display()
            ));
        }
        let key = resolved
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot resolve dependency {}", dependency.display()))?;

        match self.state.get(&key) {
            Some(State::Resolved(index)) => {
                debug!("reusing already resolved dependency {}", key.display());
                return Ok(*index);
            }
            Some(State::Visiting) => {
                return Err(miette!("dependency cycle: {}", cycle_chain(stack, &key)));
            }
            None => {}
        }

        // A dependency is loaded exactly as strictly as the root was:
        // signatures are checked all the way down, or not at all.
        let build = match self.verification {
            Verification::Signed => BuildFile::load_in(self.ctx, &key),
            Verification::Unverified => BuildFile::load_unverified(&key),
        }
        .wrap_err_with(|| format!("dependency {} failed", key.display()))?;

        self.visit(key, build, stack)
    }
}

/// Render the cycle `visiting` closes when `key` is entered again.
pub(crate) fn cycle_chain(visiting: &[PathBuf], key: &Path) -> String {
    let start = visiting.iter().position(|seen| seen == key).unwrap_or(0);
    visiting[start..]
        .iter()
        .map(|path| path.display().to_string())
        .chain(std::iter::once(key.display().to_string()))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Pull a readable message out of whatever was panicked with.
fn describe_panic(panic: &Box<dyn Any + Send>) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic carrying no message".to_string())
}

/// How many packages build at once when nothing said otherwise.
fn default_jobs() -> usize {
    available_parallelism().map_or(1, NonZeroUsize::get)
}

/// Take the schedule lock, surviving a poisoned mutex.
///
/// A panic in one package's build must not turn every other worker's next lock
/// into a second panic that buries it.
fn lock(schedule: &Mutex<Schedule>) -> MutexGuard<'_, Schedule> {
    schedule.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the scheduler knows about a package.
enum Progression {
    /// Not started, and not yet ready to be.
    Waiting,
    /// Built, leaving this archive behind.
    Built(PathBuf),
    /// Attempted and failed.
    Failed(miette::Report),
    /// Never attempted, because something it depends on failed.
    Skipped,
}

/// The state every worker shares: what is ready, what is running, what is done.
struct Schedule {
    /// How many of each package's dependencies are still unbuilt.
    blocked_by: Vec<usize>,
    /// Packages whose dependencies are all built, waiting for a worker.
    ready: Vec<usize>,
    /// Which packages depend on each package - the graph's edges, reversed.
    dependents: Vec<Vec<usize>>,
    progression: Vec<Progression>,
    /// Packages that have not reached a final state yet.
    unsettled: usize,
    /// Packages currently being built.
    running: usize,
    /// Packages built successfully, for the summary line.
    done: usize,
    /// Set under this struct's own lock by the closure `Graph::build_with`
    /// registers with a [`Cancel`] token, so [`Graph::claim`]'s
    /// check-then-park sequence can never miss it: see the comment there.
    cancelled: bool,
}

impl Schedule {
    fn new(graph: &Graph) -> Self {
        let mut dependents = vec![Vec::new(); graph.len()];
        for (index, node) in graph.nodes.iter().enumerate() {
            for dependency in &node.dependencies {
                dependents[*dependency].push(index);
            }
        }

        let blocked_by: Vec<usize> = graph
            .nodes
            .iter()
            .map(|node| node.dependencies.len())
            .collect();
        // A package with no dependencies can start immediately.
        let ready = blocked_by
            .iter()
            .enumerate()
            .filter(|(_, blocking)| **blocking == 0)
            .map(|(index, _)| index)
            .collect();

        Self {
            blocked_by,
            ready,
            dependents,
            progression: (0..graph.len()).map(|_| Progression::Waiting).collect(),
            unsettled: graph.len(),
            running: 0,
            done: 0,
            cancelled: false,
        }
    }

    /// The archives of everything `index` depends on.
    ///
    /// Every one of them is `Built`: a package only becomes ready once all its
    /// dependencies have settled successfully.
    fn archives_for(&self, graph: &Graph, index: usize) -> Vec<PathBuf> {
        graph.nodes[index]
            .dependencies
            .iter()
            .filter_map(|dependency| match &self.progression[*dependency] {
                Progression::Built(archive) => Some(archive.clone()),
                _ => None,
            })
            .collect()
    }

    /// Record how `index` turned out, and release or skip what was waiting on it.
    fn settle(&mut self, graph: &Graph, index: usize, result: miette::Result<PathBuf>) {
        self.running -= 1;
        self.unsettled -= 1;

        match result {
            Ok(archive) => {
                self.progression[index] = Progression::Built(archive);
                self.done += 1;
                for dependent in self.dependents[index].clone() {
                    self.blocked_by[dependent] -= 1;
                    if self.blocked_by[dependent] == 0 {
                        self.ready.push(dependent);
                    }
                }
            }
            Err(report) => {
                self.progression[index] = Progression::Failed(report);
                let skipped = self.skip_dependents_of(index);
                // Say what was actually skipped. A package nothing depends on
                // takes nothing down with it, and claiming otherwise sends
                // whoever is reading the log looking for casualties there
                // aren't any of.
                if skipped == 0 {
                    warn!(package = graph.nodes[index].build.name(), "package failed");
                } else {
                    warn!(
                        package = graph.nodes[index].build.name(),
                        skipped, "package failed; skipping what depends on it"
                    );
                }
            }
        }
    }

    /// Mark everything transitively depending on `index` as skipped, and say
    /// how many that was.
    fn skip_dependents_of(&mut self, index: usize) -> usize {
        let mut doomed = self.dependents[index].clone();
        let mut skipped = 0;

        while let Some(next) = doomed.pop() {
            // Already settled: reached twice through a diamond, or failed on
            // its own. Skipping it again would decrement `unsettled` twice for
            // one package and end the build with work still outstanding.
            if !matches!(self.progression[next], Progression::Waiting) {
                continue;
            }
            self.progression[next] = Progression::Skipped;
            self.unsettled -= 1;
            skipped += 1;
            doomed.extend_from_slice(&self.dependents[next]);
        }

        skipped
    }

    /// Give up on whatever is left, so a stalled schedule reports instead of hanging.
    fn abandon_remaining(&mut self) {
        for progression in &mut self.progression {
            if matches!(progression, Progression::Waiting) {
                *progression = Progression::Skipped;
            }
        }
        self.unsettled = 0;
    }

    /// Update the one line that says how the run as a whole is going.
    fn describe(&self, summary: &Task, total: usize) {
        summary.set_message(format!(
            "{} building, {} of {total} done",
            self.running, self.done
        ));
    }

    /// The build's result: the root's archive, or every failure it ran into.
    fn outcome(self, graph: &Graph) -> miette::Result<PathBuf> {
        let mut failures = Vec::new();
        let mut skipped = Vec::new();

        for (index, progression) in self.progression.iter().enumerate() {
            let name = graph.nodes[index].build.name();
            match progression {
                Progression::Failed(report) => failures.push((name, render(report))),
                Progression::Skipped | Progression::Waiting => skipped.push(name),
                Progression::Built(_) => {}
            }
        }

        if failures.is_empty() {
            return match &self.progression[graph.root] {
                Progression::Built(archive) => Ok(archive.clone()),
                // Unreachable with no failures, but a wrong answer here would
                // be a build reporting success without an archive.
                _ => Err(miette!(
                    "the build finished without producing an archive for {}",
                    graph.nodes[graph.root].build.name()
                )),
            };
        }

        let mut report = format!("{} of {} packages failed\n", failures.len(), graph.len());
        for (name, detail) in &failures {
            report.push_str(&format!("\n  {name}\n    {detail}\n"));
        }
        if !skipped.is_empty() {
            report.push_str(&format!(
                "\n{} skipped because a dependency failed: {}\n",
                skipped.len(),
                skipped.join(", ")
            ));
        }
        Err(miette!("{report}"))
    }
}

/// Flatten a report and its causes into one indented block.
///
/// The nested reports are being folded into a bigger diagnostic, so they are
/// rendered as text rather than handed to miette's own printer, which would
/// format each as though it were the only thing that went wrong.
fn render(report: &miette::Report) -> String {
    let mut text = report.to_string();
    for cause in report.chain().skip(1) {
        text.push_str(&format!("\n      {cause}"));
    }
    text
}
