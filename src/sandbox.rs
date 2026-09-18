//! The jail build steps run in.
//!
//! [`crate::policy::BuildPolicy`] decides *what* a build is allowed to do by
//! reading the build file; this module turns that decision into a real
//! `hakoniwa` container and executes step commands inside it.
//!
//! # Shape of the jail
//!
//! - `rootfs("/")` mirrors the host's `/bin /etc /lib /lib32 /lib64 /sbin /usr`
//!   read-only, so the toolchain and the dynamic loader are reachable.
//! - Toolchain directories that live outside those roots (see
//!   [`toolchain_roots`]) are bind-mounted read-only at their own paths.
//! - `/dev` is a minimal devfs and `/tmp` a fresh tmpfs, so the host's `/tmp` -
//!   which is where every other build's workspace lives - is invisible.
//! - The step's working directory and staging directory are bind-mounted
//!   read-write at the stable in-container paths [`CONTAINER_WORKDIR`] and
//!   [`CONTAINER_DESTDIR`]. **They are the only writable mounts.**
//! - Each caller-supplied `extra_ro` path is bind-mounted read-only at its own
//!   path.
//! - The network namespace is unshared unless the policy carries
//!   [`Capability::Network`].
//!
//! `$HOME`, `/root` and `/var` are never mounted, so a hostile build file
//! cannot read the user's SSH keys or write anywhere outside the two staging
//! directories.
//!
//! # Commands
//!
//! A command string is split on whitespace and executed directly, exactly as
//! [`crate::step::Step`] does on the host: **there is no shell**, so quoting,
//! globbing, pipes, redirection and variable expansion are not available.
//! `DESTDIR` reaches the child through the environment because that is the
//! Makefile convention.

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs::File,
    io::{BufRead as _, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as HostCommand, Stdio as HostStdio},
    thread::scope,
};

use hakoniwa::{Container, MountOptions, Namespace, Runctl, Stdio};
use miette::{IntoDiagnostic, WrapErr, miette};
use tracing::{debug, info, warn};

use crate::{
    context::BuildContext,
    policy::{BuildPolicy, Capability},
    progress::Task,
};

/// Where the step's working directory is mounted inside the jail.
///
/// The host-side workspace is a throwaway temporary path, so commands always
/// see this stable path instead.
pub const CONTAINER_WORKDIR: &str = "/build";

/// Where the staging directory is mounted inside the jail, and the value of
/// `DESTDIR` for every sandboxed command.
pub const CONTAINER_DESTDIR: &str = "/dest";

/// `PATH` handed to sandboxed commands.
///
/// It is only a courtesy to build systems that re-exec their own helpers:
/// `pm` itself never relies on it, because `hakoniwa` execs the program path
/// verbatim without a `PATH` search (see [`BuildSandbox::resolve`]).
///
/// `pub(crate)` so [`crate::context::BuildContext::from_env`] can fall back to
/// it when the process has no `PATH` at all - the same fallback `resolve`
/// used to apply itself before it started taking `PATH` from a context.
pub(crate) const CONTAINER_PATH: &str = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin";

/// The directories `Container::rootfs("/")` mirrors from the host.
///
/// Kept in sync by hand with `hakoniwa::Container::rootfs_imp`, which hard-codes
/// exactly this list when the rootfs is `/`.
const ROOTFS_ROOTS: [&str; 7] = ["/bin", "/etc", "/lib", "/lib32", "/lib64", "/sbin", "/usr"];

/// Immutable store a Nix-provisioned toolchain resolves into.
///
/// Every binary under a Nix profile is a symlink chain ending here, and so are
/// its libraries and its dynamic loader, so nothing from such a toolchain runs
/// unless the store is visible. It is world-readable and immutable by
/// construction, so exposing it read-only costs no confinement.
const NIX_STORE: &str = "/nix/store";

/// Flags for a read-only bind mount.
///
/// **Not** `Container::bindmount_ro`, which asks for `BIND|REC|NOSUID|RDONLY`
/// and is a trap in combination with [`Runctl::MountFallback`]. `hakoniwa`
/// applies `RDONLY` through a second `MS_REMOUNT`, and the kernel refuses a
/// remount inside a user namespace that drops a flag the source filesystem has
/// locked. A `/tmp` mounted `nosuid,nodev` - the norm, and where every `pm`
/// workspace and most `extra_ro` paths live - locks `nodev`, which
/// `bindmount_ro` never asks for, so that remount fails. The fallback then
/// recomputes the flags from `statfs` and, because it *drops* `MS_RDONLY`
/// before re-adding only what the source filesystem itself carries, a
/// read-write tmpfs comes back read-write. The mount is then silently writable.
/// Verified by hand: `touch` inside a `bindmount_ro` of a `/tmp` directory
/// succeeded.
///
/// Asking for `nodev` up front makes the first remount succeed, so the fallback
/// is never reached and `RDONLY` survives. `noexec` is deliberately absent:
/// the toolchain mounts have to be executable.
fn ro_flags() -> MountOptions {
    MountOptions::BIND
        | MountOptions::REC
        | MountOptions::NOSUID
        | MountOptions::NODEV
        | MountOptions::RDONLY
}

/// Flags for the two writable bind mounts.
///
/// Same reasoning as [`ro_flags`] minus `RDONLY`: `nodev` is requested up front
/// so the remount matches what a `nosuid,nodev` `/tmp` has locked.
fn rw_flags() -> MountOptions {
    MountOptions::BIND | MountOptions::REC | MountOptions::NOSUID | MountOptions::NODEV
}

/// A `hakoniwa` jail for build steps, configured from a [`BuildPolicy`].
pub struct BuildSandbox {
    mode: Mode,
    /// Host-side working directory. Only used by [`Mode::Host`] and to rewrite
    /// absolute program paths that point into the workspace.
    workdir: PathBuf,
    /// Host-side staging directory (`DESTDIR`).
    destdir: PathBuf,
    /// Host paths that are reachable inside the jail *at the same path*. Used
    /// to reject a program the jail could never exec, with a diagnostic that
    /// says what to do about it, instead of a bare `ENOENT` from `execve`.
    visible: Vec<PathBuf>,
    /// The progress line this sandbox's package owns, if any.
    ///
    /// Detached by default, which is what keeps stdout inherited for every
    /// caller that has no region to draw into.
    progress: Task,
    /// `PATH` used to resolve a step's first word, from the [`BuildContext`]
    /// this sandbox was built with. Unused in [`Mode::Host`]: a command run
    /// there goes through [`std::process::Command`] directly, which lets the
    /// host's own `execvp` do its own `PATH` search over the *process's*
    /// environment rather than this one.
    path: OsString,
}

/// Whether commands are confined or run straight on the host.
enum Mode {
    /// Confined. `Container` is large and cloned per command, so it is boxed to
    /// keep the enum small.
    Jailed(Box<Container>),
    /// The [`BuildSandbox::unsandboxed`] escape hatch.
    Host,
}

impl BuildSandbox {
    /// As [`BuildSandbox::new_in`], reading `PATH` and `$HOME` from the
    /// process instead of an explicit context.
    ///
    /// # Errors
    ///
    /// As [`BuildSandbox::new_in`], plus whatever [`BuildContext::from_env`]
    /// itself can fail on.
    pub fn new(
        policy: &BuildPolicy,
        workdir: &Path,
        destdir: &Path,
        extra_ro: &[&Path],
    ) -> miette::Result<Self> {
        Self::new_in(&BuildContext::from_env()?, policy, workdir, destdir, extra_ro)
    }

    /// Build a jail for `policy`, staging into `workdir` and `destdir`.
    ///
    /// `extra_ro` are host paths the build legitimately needs to READ - the
    /// build file's own directory, dependency archives. They are mounted
    /// read-only at their own paths, so a command can refer to them by the
    /// same absolute path it would use on the host. `ctx` supplies the `PATH`
    /// used to resolve a step's first word and the `PATH`/`$HOME` that decide
    /// which toolchain directories get mounted - see [`toolchain_roots`].
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `workdir` or `destdir` is missing or is not a
    /// directory, when an `extra_ro` path does not exist, when any of those
    /// paths is not valid UTF-8 (`hakoniwa` mount points are `&str`), or when
    /// the host's system directories cannot be enumerated for the rootfs.
    pub fn new_in(
        ctx: &BuildContext,
        policy: &BuildPolicy,
        workdir: &Path,
        destdir: &Path,
        extra_ro: &[&Path],
    ) -> miette::Result<Self> {
        let workdir = existing_dir(workdir, "working directory")?;
        let destdir = existing_dir(destdir, "staging directory")?;

        let mut container = Container::new();
        container
            .rootfs("/")
            .into_diagnostic()
            .wrap_err("cannot mirror the host system directories into the build sandbox")?
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            // Not optional. The workspace lives under `TMPDIR`, and a `/tmp`
            // mounted `nosuid,nodev` - the norm - has those flags locked inside
            // a user namespace: the read-only remount behind `bindmount_ro`
            // drops them and the kernel answers EPERM. The fallback re-reads the
            // source filesystem's flags and keeps them, which is the only way to
            // bind a `/tmp` path read-only unprivileged.
            .runctl(Runctl::MountFallback);

        // The only two writable mounts in the whole jail.
        container
            .mount(as_utf8(&workdir)?, CONTAINER_WORKDIR, "", rw_flags())
            .mount(as_utf8(&destdir)?, CONTAINER_DESTDIR, "", rw_flags());

        let mut visible: Vec<PathBuf> = ROOTFS_ROOTS.iter().map(PathBuf::from).collect();

        for root in toolchain_roots(ctx) {
            let root_str = as_utf8(&root)?;
            debug!(path = %root_str, "mounting toolchain directory read-only");
            container.mount(root_str, root_str, "", ro_flags());
            visible.push(root);
        }

        for path in extra_ro {
            let path = path.canonicalize().into_diagnostic().wrap_err_with(|| {
                format!(
                    "cannot expose `{}` to the build sandbox: it does not exist",
                    path.display()
                )
            })?;
            let path_str = as_utf8(&path)?;
            debug!(path = %path_str, "mounting caller-supplied path read-only");
            container.mount(path_str, path_str, "", ro_flags());
            visible.push(path);
        }

        let networked = policy.capabilities().contains(&Capability::Network);
        if networked {
            warn!(
                fingerprint = policy.fingerprint(),
                "build policy grants network access; the build sandbox SHARES the host network"
            );
        } else {
            container.unshare(Namespace::Network);
            info!(
                fingerprint = policy.fingerprint(),
                "build sandbox runs in its own empty network namespace"
            );
        }

        info!(
            capabilities = ?policy.capabilities(),
            workdir = %workdir.display(),
            destdir = %destdir.display(),
            "build sandbox configured"
        );

        Ok(Self {
            mode: Mode::Jailed(Box::new(container)),
            workdir,
            destdir,
            visible,
            progress: Task::detached(),
            path: ctx.path.clone(),
        })
    }

    /// An unsandboxed escape hatch for debugging: commands run unconfined on
    /// the host, as the calling user.
    ///
    /// Unlike [`BuildSandbox::new_in`], this takes no [`BuildContext`]: a
    /// command run this way goes through [`std::process::Command`] directly,
    /// which searches the *process's* `PATH` itself rather than going through
    /// [`BuildSandbox::resolve`].
    #[must_use]
    pub fn unsandboxed(workdir: &Path, destdir: &Path) -> Self {
        warn!(
            workdir = %workdir.display(),
            destdir = %destdir.display(),
            "BUILD SANDBOX DISABLED: build steps will run UNCONFINED on this host, with the \
             calling user's full access to $HOME, the network and every file they can reach. \
             This is a debugging aid; never use it on a build file you did not write."
        );
        Self {
            mode: Mode::Host,
            workdir: workdir.to_path_buf(),
            destdir: destdir.to_path_buf(),
            visible: Vec::new(),
            progress: Task::detached(),
            // Never read: `run_on_host` does not call `resolve`.
            path: OsString::new(),
        }
    }

    /// Report this sandbox's commands under `task`, one nested line each.
    ///
    /// Attaching a live task also changes where a command's stdout goes: it is
    /// captured rather than inherited, because a command writing freely to the
    /// terminal would shred the region redrawing underneath it. The captured
    /// output is not thrown away - its latest line becomes the command's
    /// progress message, and the whole of it is reported if the command fails.
    ///
    /// Without this, stdout is inherited exactly as it always was.
    #[must_use]
    pub fn with_progress(mut self, task: Task) -> Self {
        self.progress = task;
        self
    }

    /// The progress line this sandbox reports under.
    ///
    /// [`crate::step::Step`] needs it to open a line per download, which is
    /// work the sandbox itself never sees.
    pub fn progress(&self) -> &Task {
        &self.progress
    }

    /// Run one command string, waiting for it to finish.
    ///
    /// The string is split on whitespace: the first word is the program, the
    /// rest are its arguments. No shell is involved. `step_name` is used in
    /// diagnostics and tracing only.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the command is blank, when the program cannot
    /// be found or is not reachable inside the jail, when it cannot be spawned,
    /// or when it exits non-zero - in which case the diagnostic carries the
    /// command, the exit status and the child's captured stderr.
    pub fn run(&self, command: &str, step_name: &str) -> miette::Result<()> {
        let mut words = command.split_whitespace();

        // A blank `run` entry has no program to spawn and is a mistake worth
        // reporting rather than skipping silently.
        let Some(program) = words.next() else {
            return Err(miette!(
                "Step `{step_name}` contains an empty command; every entry of `run` must name a program"
            ));
        };
        let args: Vec<&str> = words.collect();

        match &self.mode {
            Mode::Jailed(container) => {
                self.run_jailed(container, program, &args, command, step_name)
            }
            Mode::Host => self.run_on_host(program, &args, command, step_name),
        }
    }

    /// Run `program` inside the container.
    fn run_jailed(
        &self,
        container: &Container,
        program: &str,
        args: &[&str],
        command: &str,
        step_name: &str,
    ) -> miette::Result<()> {
        // Labelled with the program the build file NAMED, before resolution
        // rewrites it: a step that says `/bin/sh` should not report itself as
        // `bash` just because that is what /bin/sh points at on this host.
        let task = self.progress.child(basename(program));

        let program = self.resolve(program, step_name)?;
        debug!(step = %step_name, command = %command, program = %program, "executing in the build sandbox");
        let mut jailed = container.command(&program);
        let jailed = jailed
            .args(args.iter().copied())
            .current_dir(CONTAINER_WORKDIR)
            // A jailed process inherits nothing: `hakoniwa` execs with exactly
            // the environment set here. Keep it small and deterministic.
            .env("DESTDIR", CONTAINER_DESTDIR)
            .env("PATH", CONTAINER_PATH)
            // $HOME is not mounted; point HOME at the workspace so a build
            // system that insists on a home directory gets a writable one
            // instead of failing on a path that does not exist.
            .env("HOME", CONTAINER_WORKDIR)
            .env("TMPDIR", "/tmp")
            .env("LC_ALL", "C")
            .stdin(Stdio::from(devnull()?))
            .stderr(Stdio::piped());

        let failure =
            || format!("Failed to run `{command}` for step `{step_name}` in the build sandbox");

        let (status, out) = if task.is_live() {
            // A live region owns the terminal, so the command's stdout is
            // captured and fed to its progress line instead of written over
            // the region.
            let mut child = jailed
                .stdout(Stdio::piped())
                .spawn()
                .into_diagnostic()
                .wrap_err_with(failure)?;
            let out = pump(child.stdout.take(), child.stderr.take(), &task);
            let status = child.wait().into_diagnostic().wrap_err_with(failure)?;
            (status, out)
        } else {
            // The build's own stdout is the user's primary progress feedback
            // when nothing else is drawing, so it is passed through.
            let output = jailed
                .stdout(Stdio::inherit())
                .output()
                .into_diagnostic()
                .wrap_err_with(failure)?;
            (output.status, Captured::stderr_only(output.stderr))
        };

        if status.success() {
            report_stderr(step_name, command, &out.stderr);
            return Ok(());
        }

        Err(miette!(
            "Command `{command}` in step `{step_name}` failed inside the build sandbox with code {} ({})\n{}",
            status.code,
            status.reason,
            out.describe()
        ))
    }

    /// Run `program` unconfined on the host. Only reachable through
    /// [`BuildSandbox::unsandboxed`].
    fn run_on_host(
        &self,
        program: &str,
        args: &[&str],
        command: &str,
        step_name: &str,
    ) -> miette::Result<()> {
        warn!(
            step = %step_name,
            command = %command,
            "running a build command UNSANDBOXED on the host"
        );

        let task = self.progress.child(basename(program));
        let mut host = HostCommand::new(program);
        let host = host
            .args(args)
            .current_dir(&self.workdir)
            .env("DESTDIR", &self.destdir)
            .stdin(HostStdio::null())
            .stderr(HostStdio::piped());

        let failure = || {
            format!(
                "Failed to spawn `{command}` in `{}` for step `{step_name}`",
                self.workdir.display()
            )
        };

        let (status, out) = if task.is_live() {
            let mut child = host
                .stdout(HostStdio::piped())
                .spawn()
                .into_diagnostic()
                .wrap_err_with(failure)?;
            let out = pump(child.stdout.take(), child.stderr.take(), &task);
            let status = child.wait().into_diagnostic().wrap_err_with(failure)?;
            (status, out)
        } else {
            let output = host
                .stdout(HostStdio::inherit())
                .output()
                .into_diagnostic()
                .wrap_err_with(failure)?;
            (output.status, Captured::stderr_only(output.stderr))
        };

        if status.success() {
            report_stderr(step_name, command, &out.stderr);
            return Ok(());
        }

        Err(miette!(
            "Command `{command}` in step `{step_name}` failed with {}\n{}",
            status,
            out.describe()
        ))
    }

    /// Turn the first word of a command into a path the jail can actually exec.
    ///
    /// `hakoniwa` passes the program string straight to `execve`, so there is no
    /// `PATH` search and no shell to do one: a bare `make` would fail with
    /// `ENOENT`. This resolves the name against the *caller's* `PATH` - taken
    /// from the [`BuildContext`] this sandbox was built with, which falls back
    /// to [`CONTAINER_PATH`] exactly as this used to when the process had no
    /// `PATH` of its own (see [`crate::context::BuildContext::from_env`]) -
    /// the toolchain the caller actually has - and then hands back the fully
    /// canonicalised path, which is what survives being re-resolved inside the
    /// jail where the intermediate symlink farms of a Nix or Homebrew profile
    /// are not mounted.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the program is not on `PATH`, when an absolute
    /// program path does not exist, or when the resolved binary lives outside
    /// every directory the jail can see.
    fn resolve(&self, program: &str, step_name: &str) -> miette::Result<String> {
        if program.contains('/') {
            return self.resolve_path(Path::new(program), step_name);
        }

        let mut rejected: Vec<PathBuf> = Vec::new();

        for dir in env::split_paths(&self.path) {
            // A relative or empty `PATH` entry means "the current directory",
            // which inside the jail is the workspace. Refusing it keeps program
            // resolution independent of what the build happens to have unpacked.
            if !dir.is_absolute() {
                continue;
            }
            let candidate = dir.join(program);
            if !is_executable(&candidate) {
                continue;
            }
            let Ok(canonical) = candidate.canonicalize() else {
                continue;
            };
            if self.is_visible(&canonical) {
                return as_utf8(&canonical).map(ToOwned::to_owned);
            }
            // Keep looking: a second `PATH` entry may hold a copy that the jail
            // can actually reach.
            rejected.push(canonical);
        }

        if rejected.is_empty() {
            return Err(miette!(
                "Step `{step_name}` wants `{program}`, which is not on PATH. The build sandbox \
                 execs programs directly - there is no shell and no PATH search inside it - so \
                 the program has to exist on the host that configures the jail."
            ));
        }
        Err(miette!(
            "Step `{step_name}` wants `{program}`, which resolves to {} on this host - outside \
             every directory the build sandbox can see. Pass the directory holding it to \
             `BuildSandbox::new` as an `extra_ro` path, or install the program under /usr.",
            describe_paths(&rejected)
        ))
    }

    /// Resolve a program the command spelled with a `/` in it.
    fn resolve_path(&self, program: &Path, step_name: &str) -> miette::Result<String> {
        // `./configure` and friends: relative to the working directory, which is
        // mounted, so `execve` resolves it against the in-container cwd as-is.
        if program.is_relative() {
            return as_utf8(program).map(ToOwned::to_owned);
        }

        // An absolute path into the workspace or the staging tree is spelled
        // with the host path, which the jail mounts elsewhere. Rewrite it.
        for (host, container) in [
            (&self.workdir, CONTAINER_WORKDIR),
            (&self.destdir, CONTAINER_DESTDIR),
        ] {
            if let Ok(relative) = program.strip_prefix(host) {
                let mapped = Path::new(container).join(relative);
                return as_utf8(&mapped).map(ToOwned::to_owned);
            }
        }

        let canonical = program.canonicalize().into_diagnostic().wrap_err_with(|| {
            format!(
                "Step `{step_name}` wants `{}`, which does not exist on this host",
                program.display()
            )
        })?;
        if !self.is_visible(&canonical) {
            return Err(miette!(
                "Step `{step_name}` wants `{}`, which resolves to `{}` - outside every directory \
                 the build sandbox can see. Pass the directory holding it to `BuildSandbox::new` \
                 as an `extra_ro` path.",
                program.display(),
                canonical.display()
            ));
        }
        as_utf8(&canonical).map(ToOwned::to_owned)
    }

    /// Is `path` reachable inside the jail at this very path?
    fn is_visible(&self, path: &Path) -> bool {
        self.visible.iter().any(|root| path.starts_with(root))
    }
}

/// Directories holding executables that `rootfs("/")` does not already mirror.
///
/// `rootfs("/")` covers a distribution toolchain, but not one installed into a
/// user profile: on a Nix-provisioned host `make` lives under `$HOME/.local/bin`
/// as a symlink chain into [`NIX_STORE`], and neither end is inside `/usr`.
/// Without these mounts such a host cannot build anything at all under the jail.
///
/// Only directories are exposed, and only read-only. Any `PATH` entry that
/// touches `$HOME` - inside it, equal to it, or an ancestor of it - is refused
/// outright, so the jail never has a `/home` at all. That costs nothing on the
/// usual setup, because the `$HOME/.local/bin` entry it skips holds symlinks
/// whose real binaries are in the store the next mount exposes, and
/// [`BuildSandbox::resolve`] hands `execve` the canonicalised path.
///
/// `PATH` and `$HOME` both come from `ctx` rather than the process: a daemon
/// building on a caller's behalf must mount the caller's toolchain, not its
/// own.
fn toolchain_roots(ctx: &BuildContext) -> Vec<PathBuf> {
    let home = ctx.home.as_deref();

    // Sorted, so an ancestor is always visited before anything nested in it.
    let mut candidates: BTreeSet<PathBuf> = BTreeSet::new();

    let store = PathBuf::from(NIX_STORE);
    if store.is_dir() {
        candidates.insert(store);
    }

    candidates.extend(
        env::split_paths(&ctx.path)
            .filter(|dir| dir.is_absolute())
            .filter_map(|dir| dir.canonicalize().ok())
            .filter(|dir| dir.is_dir()),
    );

    let mut roots: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        if candidate.parent().is_none() {
            warn!("refusing to mount `/` into the build sandbox as a toolchain directory");
            continue;
        }
        if ROOTFS_ROOTS
            .iter()
            .any(|root| candidate.starts_with(Path::new(root)))
        {
            continue;
        }
        if home.is_some_and(|home| home.starts_with(&candidate) || candidate.starts_with(home)) {
            debug!(
                path = %candidate.display(),
                "not mounting a PATH entry inside $HOME into the build sandbox"
            );
            continue;
        }
        // Already covered by a shallower root that was kept.
        if roots.iter().any(|root| candidate.starts_with(root)) {
            continue;
        }
        roots.push(candidate);
    }
    roots
}

/// Canonicalise a path that has to be an existing directory.
fn existing_dir(path: &Path, what: &str) -> miette::Result<PathBuf> {
    let canonical = path.canonicalize().into_diagnostic().wrap_err_with(|| {
        format!(
            "the build sandbox {what} `{}` does not exist",
            path.display()
        )
    })?;
    if !canonical.is_dir() {
        return Err(miette!(
            "the build sandbox {what} `{}` is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// `hakoniwa` mount points and program paths are `&str`, so a path that is not
/// valid UTF-8 cannot be handed to it at all.
fn as_utf8(path: &Path) -> miette::Result<&str> {
    path.to_str().ok_or_else(|| {
        miette!(
            "Path `{}` is not valid UTF-8 and cannot be used inside the build sandbox",
            path.display()
        )
    })
}

/// Open `/dev/null` for a sandboxed command's stdin.
///
/// A build step has nobody to answer a prompt, so stdin is closed rather than
/// inherited - otherwise a step that reads stdin steals the terminal, or blocks
/// forever.
fn devnull() -> miette::Result<File> {
    File::open("/dev/null")
        .into_diagnostic()
        .wrap_err("cannot open /dev/null for a sandboxed command's stdin")
}

/// What a command wrote, as far as it was captured.
///
/// stderr is always captured; stdout only when a progress region is drawing and
/// the command could not be allowed to write to the terminal itself.
struct Captured {
    stdout: Option<Vec<u8>>,
    stderr: Vec<u8>,
}

impl Captured {
    /// The inherited-stdout case: only stderr came back.
    fn stderr_only(stderr: Vec<u8>) -> Self {
        Self {
            stdout: None,
            stderr,
        }
    }

    /// The captured output, formatted for a failure diagnostic.
    ///
    /// stdout is included only when it was captured. When it was inherited the
    /// user has already seen it scroll past, and printing `<no output>` for it
    /// would claim the command was silent when nobody was listening.
    fn describe(&self) -> String {
        let stderr = format!("stderr:\n{}", describe_stream(&self.stderr));
        match &self.stdout {
            Some(stdout) => format!("stdout:\n{}\n{stderr}", describe_stream(stdout)),
            None => stderr,
        }
    }
}

/// Read a command's output, feeding stdout to `task` line by line.
///
/// stdout and stderr have to be drained concurrently or the command deadlocks:
/// a child that fills one pipe's buffer blocks forever while the parent waits
/// on the other. stderr goes to a scoped thread, stdout stays here so each line
/// can update the progress message as it arrives.
fn pump<O, E>(stdout: Option<O>, stderr: Option<E>, task: &Task) -> Captured
where
    O: Read,
    E: Read + Send,
{
    scope(|threads| {
        let errors = threads.spawn(move || {
            let mut captured = Vec::new();
            if let Some(mut stderr) = stderr {
                stderr.read_to_end(&mut captured).ok();
            }
            captured
        });

        let stdout = stdout.map(|stdout| drain_into(stdout, task));

        Captured {
            stdout,
            stderr: errors.join().unwrap_or_default(),
        }
    })
}

/// Capture `reader` whole, making each line the task's latest message.
fn drain_into<R: Read>(reader: R, task: &Task) -> Vec<u8> {
    let mut reader = BufReader::new(reader);
    let mut captured = Vec::new();
    let mut line = Vec::new();

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        captured.extend_from_slice(&line);

        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end();
        if !text.is_empty() {
            task.set_message(text);
        }
    }

    captured
}

/// The last path component of a program, which is what a progress line shows.
///
/// Programs are resolved to absolute paths before they are executed, and
/// `/usr/bin/make` is not what a person reading a progress line wants to see.
fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Render one captured stream for a diagnostic.
fn describe_stream(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.is_empty() {
        "<no output>".to_owned()
    } else {
        text.to_owned()
    }
}

/// Log the stderr of a command that nonetheless succeeded; warnings from a
/// compiler are worth keeping, but not worth raising to the user by default.
fn report_stderr(step_name: &str, command: &str, stderr: &[u8]) {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    if !text.is_empty() {
        debug!(step = %step_name, command = %command, "stderr:\n{text}");
    }
}

/// Comma-separated path list for diagnostics.
fn describe_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| format!("`{}`", path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Is `path` a file this user could exec?
fn is_executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}
