# pm D-Bus daemon: design spec

This is the binding design for splitting `pm` into a session-bus daemon
(`pmd`) and a thin client (`pm`). It is a specification, not an essay: every
later implementation phase resolves its conflicts against this document.
It supersedes the raw design material it was drawn from.

## 1. Context and goals

`pm` today is a single short-lived CLI process that does everything itself:
it parses a build file, resolves a dependency graph, spawns hakoniwa
containers, ptraces audited entrypoints, owns the terminal, holds the
Ed25519 signing key, and reads its whole operating context (cwd, PATH, HOME,
TMPDIR, trust dir) straight out of its own environment. That shape has real
costs: concurrent builds cannot cooperate on one `-j` budget, a long build
is tied to the terminal that started it, there is no way to list or stop
work in flight, and audit results are logged and thrown away.

The project splits `pm` into a session-bus daemon, `pmd` (one per user,
running as the invoking uid), plus a thin client, `pm`. The split exists to
deliver four goals:

- supervised long-lived jobs, so a build or run outlives the terminal that
  started it and can be listed, watched and stopped;
- one owner of the sandbox, landlock and ptrace machinery, so container and
  tracer lifecycle rules live in one process instead of being re-derived by
  every caller;
- one serialized owner of scratch and the job pool, so concurrent clients
  share one `-j` budget and one scratch root instead of racing on a shared
  temp directory;
- a real D-Bus API other programs, not only `pm`, can consume.

The result is a three-tier system: `pm` (client, owns the terminal and the
private key), `pmd` (daemon, owns the bus name, the job registry, the log
store, the slot budget and the scratch root), and one short-lived worker
process per job (`pmd --worker`) plus one `pm-trace` process per audit. The
library keeps every public signature it has today, so the large majority of
the existing 7,096-line integration suite, which calls `pm::bf`,
`pm::graph`, `pm::run`, `pm::sandbox` and `pm::progress` directly, compiles
and passes untouched.

## 2. Fixed decisions

These are settled. Later phases implement them; they are not re-argued
here.

- Session bus. One `pmd` per user, running as the invoking uid. Never root.
- `pm run` is always detached. It prints a job id and exits once the job is
  running, not once it finishes. `pm wait <id>` subscribes to the job and
  restores an exit code. `pm build` is the one exception named by this
  decision: it stays foreground, tailing the log and blocking on
  `Finished`.
- The daemon is mandatory. There is one code path for `pm build`, `pm run`
  and `pm run --audit`, and no in-process fallback when the bus is
  unreachable.
- Signing stays client side, permanently. The daemon never holds the
  Ed25519 private key. `pm sign`, `pm keygen`, `pm trust`, `pm explain`,
  `pm generate`, `pm profile` and `pm promote` never open a bus connection:
  none of them has privilege, shared state or supervision value, and the
  signing key must never leave the client process (signing.rs:63-82).
- Every method carries the caller's cwd, output dir, trust dir, PATH and
  HOME explicitly, as a `CallerContext` argument. The daemon never reads
  its own environment for them.
- `zbus` 5.19, pure Rust, with the `p2p` feature. There are no libdbus
  headers on this machine, so binding to the C library is not an option.

## 3. Process model

Four process kinds, one crate, one protocol.

### `pm`, the client

`src/bin/pm.rs`, moved from `src/main.rs`. clap parses first, deleting the
raw-argv verbose scan at main.rs:432-434, which is why `pm build -vj4`
misses `-v` today. It captures `CallerContext { cwd, output_dir, trust_dir,
path, home }` from its own environment, canonicalises the file or package
argument against its own cwd so the daemon only ever sees absolute paths,
connects to the session bus, submits one job, subscribes, renders, and
exits. It owns the terminal: dialoguer, `Progress::to_terminal()` and the
entrypoint prompt all live here.

`pm sign`, `pm keygen`, `pm trust`, `pm explain`, `pm generate`, `pm
profile` and `pm promote` never touch the bus, per decision 4.

### `pmd`, the daemon

`src/bin/pmd.rs`, `src/daemon/`. Owns `org.pm1` on the session bus, the
object tree, the in-memory job registry, the log ring buffers, the
persisted state directory, the slot budget and the scratch root
`$XDG_STATE_HOME/pm/work/<job>/`. It builds nothing, jails nothing, traces
nothing, and never calls `waitpid(-1)`. It runs exactly four long-lived
threads:

- The zbus executor thread (zbus's own, connection/builder.rs:784-801).
  Every `#[interface]` method is an `async fn` whose body validates,
  mutates the registry under a `std::sync::Mutex` held across no `.await`,
  and calls `object_server.at(path, JobIface).await`. See invariant 1.
- The supervisor thread (`src/daemon/supervisor.rs`). Never returns while
  the daemon lives. Owns the job table's side effects: writes `job.json`,
  forks every worker, drains each worker's socketpair and pipes, runs the
  80 ms progress tick and the GC timer, and calls `waitpid(worker_pid)`,
  pid-specific, never `-1`. See invariants 2 and 3.
- The emitter thread (`src/daemon/emit.rs`). The only caller of
  `blocking::Connection::emit_signal`. See invariant 4.
- The name watcher (`blocking::MessageIterator` over `NameOwnerChanged`),
  for jobs with `lifetime: "tied"`.

### `pmd --worker --fd 3`, one process per job

A re-exec of `/proc/self/exe`, so there is no version skew between the
daemon and its workers. It sets `PR_SET_PDEATHSIG(SIGKILL)` and re-checks
`getppid()` in `pre_exec` to close the fork-or-parent-death race, installs
its own `tracing_subscriber::fmt().with_env_filter(..)` from the job's
`log_filter` option, `chdir`s to `ctx.cwd`, sets PATH, HOME and TMPDIR, and
then runs the whole job in one stack frame: `BuildFile::run_with_progress_in`
for a build, or `PackageRunner::run_with(bin, &hooks)` for a run or audit.
Its stdout and stderr are pipes the supervisor drains into the job's ring
buffer and `log.ndjson`. Structured events (progress snapshots, package
outcomes, state transitions, slot requests, prompts) go over the socketpair
as length-prefixed JSON frames.

Because the whole job is one frame, the drop-order invariant at
run.rs:283-288 and 436-437 is preserved literally: `workspace` is still
declared before the `SandboxedChild`, locals still drop in reverse, and no
state machine owns a live child. This is the reason process-per-job was
chosen over thread-per-job: both prior thread-based designs had to
re-express the invariant, one as struct field order on a `JobBody`, one as
a borrow that could not be stored anywhere, and both got the ordering
subtly different. Here nothing changes at all.

### `pm-trace`, one process per audit

`src/bin/pm-trace.rs`. Spawned by the worker. Reads a `TraceRequest` as
YAML on stdin, runs `monitor::preflight()`, calls `pm::perms::monitor::trace`
on its main thread, writes a `TraceReport` as YAML to a file named by
`--report <path>`, and exits with the tracee's code. stdout and stderr are
inherited from the worker, so trace logging lands in the job log and there
are no pipes to deadlock on; the worker waits on one specific pid. It forks
nothing else and reaps nothing else, so `waitpid(-1, WNOHANG|__WALL)` at
monitor.rs:1265 and 1289 can only see tracees, and monitor.rs:648-654's
requirement that a trace be the only child-reaping work in flight is
satisfied by construction.

Exit codes: 0 ok, 2 unsupported architecture, 3 ptrace denied, 4 the tracee
never reached its exec trap, 5 usage, 124 timeout (matching
`AUDIT_UNFINISHED` at run.rs:116).

### Why process-per-job is forced, not chosen

Five independent facts in the existing code, each verified against the
source, rule out a thread-based worker:

1. `PR_SET_PDEATHSIG` binds to the creating thread, not the process
   (hakoniwa runc.rs:121, 246). A worker thread that returns while its
   container still runs SIGKILLs the container with the daemon perfectly
   healthy. A worker process whose main thread spawns and waits makes the
   invariant trivially true, because the daemon forks every worker from
   the supervisor thread, which never returns while the daemon lives.
2. `PTRACE_TRACEME`-only tracing with `waitpid(-1, __WALL)` (monitor.rs:677,
   1265, 1289) demands a process that reaps nothing else. `static TRACER`
   (monitor.rs:654) only serialises tracers; it does not give a
   thread-based daemon a wait queue nothing else shares.
3. The global `tracing` subscriber is process-wide (main.rs:280,
   progress.rs:221-226) and cannot be multiplexed per client. A
   thread-local layer would silently lose lines emitted from graph.rs:157's
   scope threads and step.rs:106's rayon pool, because tracing spans do not
   propagate to spawned threads.
4. `catch_unwind` at graph.rs:189-200 contains a panicking package but not
   a panicking job. Per-job isolation needs a kernel-level boundary: a
   worker process's panic unwinds out of `main`, and the process exits 101.
5. A wedged `minreq` read (download.rs:43-50, 190-206) is uninterruptible
   in-process, because minreq exposes neither the `TcpStream` nor a
   per-read timeout, but is trivially killable as a process.

## 4. The D-Bus surface

Bus name: `org.pm1` (session bus; the version is in the name so `org.pm2`
can coexist through a future break). All interfaces are `org.pm1.*`; all
errors are `org.pm1.Error.*`.

### Object paths

| Path | Interfaces |
|---|---|
| `/org/pm1` | `org.pm1.Manager`, `org.freedesktop.DBus.ObjectManager`, `.Properties`, `.Introspectable`, `.Peer` |
| `/org/pm1/job/<id>` | `org.pm1.Job`, plus exactly one of `org.pm1.Job.Build`, `org.pm1.Job.Run`, `org.pm1.Job.Audit` |

`<id>` is `build_17`, `run_3` or `audit_2`: a legal D-Bus path element
(`[A-Za-z0-9_]` only, so no hyphen), taken from a counter persisted in the
state directory, and typeable at a shell (`pm logs build_17`). Job ids, not
object paths or prefixes, are the handle for every supervisory command; a
prefix that is unique today becomes ambiguous tomorrow and would break a
script silently. `pm ps --format=id` exists for scripting.

### `org.pm1.Manager` at `/org/pm1`

Methods:

| Method | In to out |
|---|---|
| `Ping()` | `""` to `"ssu"` (version, protocol, pid) |
| `StartBuild(ctx, build_file, options)` | `"(sssss)sa{sv}"` to `"o"` |
| `StartRun(ctx, package, options)` | `"(sssss)sa{sv}"` to `"o"` |
| `StartAudit(ctx, package, options)` | `"(sssss)sa{sv}"` to `"o"` |
| `ListJobs(filter)` | `"a{sv}"` to `"a(ossssxxi)"` |
| `GetJob(id)` | `"s"` to `"o"` |
| `Forget(id)` | `"s"` to `"b"` |
| `Prune(finished_before_usec)` | `"t"` to `"u"` |

`Prune`'s argument is `t`, not the `x` the raw design material gives it;
see "Wall-clock microsecond values" under Wire types for why.

Every method on `org.pm1.Manager` is O(registry lock). The three `Start*`
methods allocate an id, insert a record, call `object_server.at(..).await`,
push a spawn request to the supervisor thread, and return a path; the
supervisor, not the method body, writes `job.json` and forks. `ListJobs`,
`GetJob`, `Forget`, `Prune` and `Ping` only read or mutate memory. No
method on this interface can approach the default 25 second reply timeout.

Properties: `Version s`, `Protocol s`, `Uid u`, `StateDirectory s`, `Slots
u`, `Features as`, `Jobs ao`.

`Features` is a subset of `build, run, audit, landlock, userns`. `audit` is
absent on a non-x86_64 host (monitor.rs:228-240) or where `PTRACE_TRACEME`
is denied, so a GUI greys the audit button instead of discovering the
failure at job-start time.

Signals: `JobAdded(path, id, kind, subject)` `"osss"`; `JobRemoved(path,
id)` `"os"`.

### Options vocabulary

Carried as `a{sv}` on every `Start*` call. An unknown key is
`org.pm1.Error.InvalidOption`, naming the key: silently dropping a flag is
exactly the bug `tests/cli_build.rs` exists to catch.

| Scope | Keys |
|---|---|
| Common | `lifetime s` (`"detach"`, the default, or `"tied"`), `log_filter s` (an `EnvFilter` spec; the client reads its own `RUST_LOG` and sends it), `description s` |
| Build | `permissive b`, `unsandboxed b`, `jobs u` |
| Run and audit | `bin s`, `network b`, `enforce b`, `unsigned b` |

### `org.pm1.Job` at `/org/pm1/job/<id>`

Methods:

| Method | In to out |
|---|---|
| `Cancel()` | `""` to `""`, asynchronous and idempotent; observe `State` |
| `Forget()` | `""` to `""`, terminal jobs only, else `org.pm1.Error.WrongState` |
| `ReadLog(from_seq, max)` | `"tu"` to `"a(tys)tb"` (lines, next_seq, more), capped at 10000 records per call |
| `Choose(entrypoint)` | `"s"` to `""`, run jobs in `needs-input` only, by name, never by index |

Properties: `Id s`, `Kind s`, `State s`, `Subject s`, `Owner s`, `Lifetime
s`, `CreatedUsec t`, `StartedUsec t`, `FinishedUsec t`, `ExitCode i` (-1
until terminal), `ExitReason s` (hakoniwa's `reason`, verbatim), `Diagnostic
(sssas)`, `Result a{sv}`, `Entrypoints as`, `WorkspacePath s`, `LogCursor
t`, `Progress a(uuusysttt)`, `Resources a{sv}`.

`Progress`, `Resources` and `LogCursor` carry `#[zbus(property(emits_changed_signal
= "false"))]`. They move on every chunk, and a `PropertiesChanged` per tick
is exactly the signal storm the progress-volume hazard warns about; their
data arrives on `ProgressChanged` and `LogLines` instead.

Signals:

| Signal | Signature |
|---|---|
| `StateChanged(old, new, usec)` | `"sst"` |
| `LogLines(first_seq, dropped, lines)` | `"tta(tys)"` |
| `ProgressChanged(usec, nodes)` | `"ta(uuusysttt)"`, a full snapshot, at most 12.5 Hz per job |
| `Finished(state, exit_code, result, diagnostic)` | `"sia{sv}(sssas)"` |

`ProgressChanged` is always a full snapshot, never a delta: the tree is a
few dozen lines, a late subscriber is instantly correct, and there is no
resync protocol to get wrong.

### `org.pm1.Job.Build`

Properties: `BuildFile s`, `Jobs u`, `Packages as` (graph order), `Archive
s`, `PolicyFingerprint s`.

Method: `GetOutcomes()` `""` to `"a(ssss)"`.

Signal: `PackageSettled((ssss))`.

This exposes graph.rs:509-556 per package instead of flattening it into
one string (graph.rs:584-621), and it is what makes `pm ps` worth looking
at during a build.

### `org.pm1.Job.Run`

Properties: `Package s`, `Entrypoint s`, `Args as`, `Network b`, `Enforce
b`, `Enforcing b`, `ProfileRecorded b`, `Unsigned b`.

### `org.pm1.Job.Audit`

Properties: `Package s`, `Entrypoint s`, `Jailed b` (documented as
permanently `false`: an audit traces, it does not contain, run.rs:669-673),
`TimedOut b`, `OutsideCount u`, `MissingPermissionsYaml s` (a `serde_yaml`
rendering of `Permissions`, which already derives `Serialize` at
perms/mod.rs:209, so a client round-trips it and calls
`Permissions::report()` for byte-identical output).

Method: `GetObservations(after, max)` `"tu"` to `"a(sisssbbs)t"`, paged,
because a real trace produces tens of thousands of observations.

Signal: `Violation((sisssbbs))`, streaming each out-of-profile access live;
today this is only visible through a `warn!` at run.rs:706-717.

### Errors

`#[derive(zbus::DBusError)] #[zbus(prefix = "org.pm1.Error")]`, deliberately
short: work failures travel on a job's `Diagnostic` property, not as method
errors.

| Error | Meaning |
|---|---|
| `InvalidContext` | a `CallerContext` field is empty, relative, or not valid UTF-8; an empty `trust_dir` is refused rather than defaulted |
| `InvalidOption` | an unknown option key, or a malformed value |
| `NoSuchJob` | the id names no job |
| `WrongState` | `Choose` on a job not in `needs-input`, `Forget` on a job that is not terminal |
| `NotSupported` | audit requested on a non-x86_64 host |
| `PtraceDenied` | `PTRACE_TRACEME` denied at preflight |
| `Busy` | the submission queue is full |
| `Draining` | the daemon is shutting down and refuses new work |
| `Internal` | always carries a `Diagnostic` body |

`NotSupported` and `PtraceDenied` are separate on purpose: they are the two
failure modes that are silent today, and both are raised synchronously from
`StartAudit`, before a job object exists.

## 5. Wire types

All defined in `src/wire/types.rs`, all `#[derive(Serialize, Deserialize,
zbus::zvariant::Type)]`. Every constructor routes its string fields
through `pm::progress::sanitise` and a stated per-field cap; see
invariant 5.

| Rust type | Signature | Notes |
|---|---|---|
| `CallerContext { cwd, output_dir, trust_dir, path, home: String }` | `(sssss)` | every field absolute; an empty `home` means none |
| `Diagnostic { name, message, help: String, causes: Vec<String> }` | `(sssas)` | `name` is a stable key (for example `pm::run::untrusted_signature`); all fields sanitised; 64 KiB cap total across message, help and causes |
| `ProgressNode { id, parent, depth: u32, label: String, kind: u8, text: String, done, total, started_usec: u64 }` | `(uuusysttt)` | `parent == 0` means root (`Screen::next_id` starts at 1); `kind` is 0 Silent, 1 Message, 2 Bytes; `total == 0` means unknown; `text` is sanitised and capped at 512 characters |
| `LogLine { seq: u64, stream: u8, text: String }` | `(tys)` | `stream` is 0 stdout, 1 stderr, 2 log |
| `JobRow { path: OwnedObjectPath, id, kind, state, subject: String, created_usec, finished_usec: i64, exit_code: i32 }` | `(ossssxxi)` | eight fields, eight type letters: `o` path, `s` id, `s` kind, `s` state, `s` subject, `x` created_usec, `x` finished_usec, `i` exit_code |
| `Observation { syscall, pid: i32, permission, label, path: String, resolved, succeeded: bool, evidence: String }` | `(sisssbbs)` | `syscall` is an owned `String`; monitor.rs:319's `&'static str` into `TABLE` cannot cross a process boundary |
| `PackageOutcome { name, outcome, archive, error: String }` | `(ssss)` | `outcome` is one of `built`, `failed`, `skipped` |

`Resources` rides as `a{sv}` rather than a fixed-signature struct:
`cpu-user-usec t`, `cpu-system-usec t`, `max-rss-kib t`, `vm-hwm-kib t`,
`pss-kib t`, `real-usec t`, lifted from
`hakoniwa::ExitStatus::{rusage, proc_pid_status, proc_pid_smaps_rollup}`.

### Wall-clock microsecond values: t versus x

`JobRow.created_usec` and `JobRow.finished_usec` are `x` (signed), matching
`org.freedesktop.DBus`'s own convention for realtime stamps. Every other
wall-clock microsecond value on the surface, `Job.CreatedUsec`,
`Job.StartedUsec`, `Job.FinishedUsec`, `StateChanged`'s `usec`,
`ProgressChanged`'s `usec`, `ProgressNode.started_usec`, and
`Manager.Prune`'s argument, is `t` (unsigned), where 0 is the "not yet"
sentinel and a negative value is meaningless. The split between `JobRow`
and everything else is deliberate: `JobRow` is a flat row inside a
lock-free snapshot returned to any caller, where a value predating the
epoch is at least a possible (if useless) input, and the `Job` properties
and signals are a live view of one job's own timeline, where negative is
simply invalid.

The one place this document departs from the raw design material is
`Manager.Prune`'s argument, which the raw material gives as `x` without
comment even though it is compared directly against `Job.FinishedUsec`
(`t`). This document uses `t`, because `Prune` is not part of the `JobRow`
snapshot the `x` exception above is scoped to, and a caller filtering on
"jobs finished before this instant" should use the same signedness as the
property it is filtering.

## 6. The job model

### States

A closed set of strings on the wire, self-describing under `gdbus monitor`
in a way a `u` enum is not, monotone toward terminal, never re-entered.

- `pending`: record exists, no worker yet.
- `preparing`: worker up, verifying the signature, creating the workspace,
  extracting, resolving.
- `needs-input`: parked on `Job.Choose`; a workspace is alive, nothing is
  running.
- `running`: the payload is executing, build steps, the jailed entrypoint,
  or the trace.
- `succeeded`: terminal.
- `failed`: terminal, `Diagnostic` populated.
- `cancelled`: terminal, `Cancel()` was called, or a tied client vanished.
- `crashed`: terminal, the worker died without a `Completed` frame (panic,
  signal, OOM).
- `orphaned`: terminal, recovered from disk after a daemon restart.

### Transitions

```
pending     -> preparing | cancelled | crashed
preparing   -> running | needs-input | failed | cancelled | crashed
needs-input -> running | failed | cancelled | crashed
running     -> succeeded | failed | cancelled | crashed
(any non-terminal job found at a stale Generation, at startup) -> orphaned
```

`crashed` and `orphaned` are distinct from `failed` and are rendered as
their own words in `pm ps`: "your build broke", "the process holding your
build died" and "the daemon restarted under you" are three different
facts, and a monitoring UI must be able to tell them apart. Every
transition emits `StateChanged` plus a `PropertiesChanged` for `State`;
terminal transitions also emit `Finished`. Because state is monotone, a
subscriber that missed signals recovers by reading `State` once; there is
no ordering puzzle to solve.

### Ownership

`Owner` is the creating connection's unique bus name. It governs the
disconnect policy only, not access: every connection from the same uid can
inspect, cancel and forget any job, because they are all the same person.
`Forget()` drops the object (`InterfacesRemoved` and `JobRemoved`) and
deletes the persisted record; it is refused on a live job. Terminal jobs
are retained until `Forget`, `Prune(before)`, or the 200-job or 7-day cap
evicts the oldest.

### Drop order

The whole job runs in one stack frame inside the worker process, so
run.rs:283-288's declaration order is preserved literally: `workspace` is
declared before the `SandboxedChild`, locals drop in reverse, the child is
killed and reaped before the tree is unlinked. No state machine owns a
running child; the states are a view of where that one frame is blocked,
published as frames on a socketpair.

### `needs-input` and the entrypoint prompt

`pick_entrypoint` (run.rs:828-896) builds a sorted, validated list of
declared entrypoint names, filtered so an escaping or non-regular
entrypoint is never offered. Two changes remove the positional-index
protocol that `choose_interactively` (run.rs:973-1032) uses today:

1. `PackageRunner::run_with(bin, &RunHooks)`: `RunHooks::choose` receives
   `&[String]` of declared names and returns a `String`. The worker's
   implementation sends `Frame::NeedsInput { entrypoints }` and blocks on a
   channel inside the same stack frame. The RPC is split; the frame is
   not. `run(bin)` keeps passing the dialoguer chooser, so every existing
   library caller of `PackageRunner::run` is untouched.
2. `Job.Choose(name)` takes the name; `pick_entrypoint` re-resolves it
   against its own list and returns `org.pm1.Error.WrongState` otherwise.
   The client's index never leaves the client, so a stale or hostile
   answer can never select a different binary.

`pm run`'s own behaviour: submit, then block on `StateChanged` until the
job leaves `preparing`, not until it finishes. On `running`, print the job
id and exit 0 (detached, per decision 2). On `needs-input`, run
`run::choose_binary` locally, where `stdin().is_terminal()` is actually
meaningful, call `Choose`, print the id, exit 0; if stdin is not a
terminal, print run.rs:984-992's refusal verbatim, call `Cancel()`, and
exit non-zero. On any terminal state reached during `preparing` (bad
signature, `--bin` matched nothing, no usable entrypoints), print
`Diagnostic` and exit with `ExitCode`. No D-Bus reply is pending during any
of this, it is a signal subscription, so the 25 second method-reply
timeout never applies.

### Client disconnect

Written into the protocol, not inherited from process lifetime. `lifetime:
"detach"` is the default and means the job outlives the client; that is
the entire point of detaching `pm run`. `lifetime: "tied"` makes the
daemon watch `NameOwnerChanged` on the submitter's unique name and cancel
the job when the owner vanishes. `pm build` sets `tied`, so Ctrl-C kills
the build the way a user expects; `pm run` sets `detach`. `Job.Lifetime`
and `Job.Owner` are properties, and `pm ps` prints a `tied` column, so the
policy is inspectable per job rather than folklore. On a p2p connection
there is no `NameOwnerChanged`, so a loopback (test) daemon treats peer
loss as owner loss.

### Cancellation

Three layers, in order:

1. `Cancel` (an `Arc<Inner>` holding an `AtomicBool`, a `Mutex<bool>` and a
   `Condvar`) rides on `BuildContext`. `Graph::claim` checks it at the top
   of its loop (graph.rs:213-245) and returns `None`; `abandon_remaining`
   marks the rest skipped; `Downloader` checks it per 64 KiB chunk
   (download.rs:199).
2. Parked workers are woken by a scoped watcher thread, not an
   `AtomicBool`, because an `AtomicBool` does not notify a `Condvar` and
   `claim` blocks in `wakeup.wait(state)` (graph.rs:244). `Graph::build_with`
   spawns one extra thread inside the same `std::thread::scope` that waits
   on the cancel token's own condvar and calls `wakeup.notify_all()`; the
   last worker to exit wakes the watcher so it returns and `scope` can
   join. Without this, `pm stop` on a build with a dependency edge hangs
   until some other package settles, which for a cancelled build is never.
3. `Job.Cancel()` sends `SIGTERM` to the worker process; its handler sets
   the token. After a 5 second grace the daemon sends `SIGKILL`, and
   hakoniwa's `PR_SET_PDEATHSIG(SIGKILL)` (runc.rs:121, 246) takes every
   container down with it, while `PTRACE_O_EXITKILL` (monitor.rs:1228)
   takes every tracee down with `pm-trace`.

There is deliberately no `Stop(signal, grace)` method.
`hakoniwa::Child::retrieve_exit_status` (child.rs:250-260) special-cases
only `Signaled(SIGKILL)`; a SIGTERM'd container falls into `read_exact` on
a status pipe whose writer died and returns `UnexpectedEof`, a wait error
rather than a status. Offering a graceful signal the implementation cannot
honour would be worse than not offering one.

Layer 3 is also the real fix for the downloader hazard: minreq's
`with_timeout` is absolute, not idle, and minreq exposes neither the
`TcpStream` nor a per-read timeout, so a wedged read blocks inside
`response.read()` where nothing in-process can reach it. Killing the
worker process frees the socket, the thread and the workspace; this is one
of the five reasons for process-per-job.

### Slots

`Slots` is a trait on `BuildContext`. `Graph::work` acquires one permit
after `claim` returns `Some` and releases it as soon as `build_alone`
returns. Acquiring before `claim` would leave a permit held by a thread
parked on the Condvar, so one job with a dependency chain would hold the
whole budget asleep and starve every other client, which is the opposite
of goal 3. The daemon's `RemoteSlots` round-trips `Frame::AcquireSlot` and
`Frame::SlotGranted` to the supervisor, which owns a counting semaphore
sized by `Slots` (default `available_parallelism()`), one round trip per
package.

### Restart and crash recovery

Workers are forked with `PR_SET_PDEATHSIG(SIGKILL)`, so containers die with
their worker and tracees die with `pm-trace`. Processes do not survive a
daemon restart; records do. Double-forking out of PDEATHSIG would destroy
the property that makes a killed supervisor leave nothing behind, so it is
not a trade worth making. `Manager` keeps a monotonic `Generation` written
into every `jobs/<id>/state.json`; at startup, any non-terminal job from a
previous generation becomes `orphaned` with the verbatim message "the
daemon that owned this job exited; its processes were killed by PDEATHSIG
when it did", and `Finished(-1, "orphaned", ..)` is emitted so a
reconnecting `pm wait` gets an answer instead of hanging.

### Panic isolation

graph.rs:189-200's `catch_unwind` is unchanged; it contains a panicking
package inside one build, backed by the poison-tolerant `lock()` at
graph.rs:427-429 and progress.rs:284-289. Per-job isolation is the worker
process itself: a panic unwinds out of `main`, the process exits 101, the
supervisor reads EOF without a `Completed` frame, `waitpid(worker_pid)`
returns the real exit status, and that one job becomes `crashed` with the
worker's captured stderr, which is where the panic message already is. One
bad package fails one package; one panicking job fails one job; and it is
a kernel guarantee rather than a Rust one. The registry lock and the
log-store lock use the same `unwrap_or_else(PoisonError::into_inner)`
idiom as graph.rs:427-429, so a job that poisoned the registry cannot turn
every subsequent `ListJobs` into a second panic that buries the first.

### The worker to daemon protocol

Not on D-Bus. `pmd --worker` and the supervisor exchange length-prefixed
JSON `Frame` values over the socketpair created before the fork. Frames
out (worker to supervisor): a full `Progress` node snapshot (emitted only
when the tree differs from the last one, at most every 80 ms),
`PackageSettled`, `NeedsInput { entrypoints }`, `Completed { status,
result }`. Frames in (supervisor to worker): `Choose(name)`,
`SlotGranted`. Because the daemon is its own worker (`/proc/self/exe`),
there is no version skew across this boundary; see the open risk on
introspection below.

### Garbage collection

State layout under `$XDG_STATE_HOME/pm/`:

```
generation                 monotonic u64
counter                    next job number
jobs/<id>/{job.json,state.json,log.ndjson,result.json,diagnostic.txt}
work/<id>/                 the job's entire scratch root
```

The supervisor creates `work/<id>/` before the fork and passes it as
`ctx.scratch_root`, so every `Workspace` the job creates, including the one
bf.rs:326-329 deliberately retains via `keep()` for post-mortem inspection,
lives inside one daemon-owned directory recorded in `job.json`. GC only
ever removes paths it recorded this way: it never globs a shared `TMPDIR`
for `pm-*`, because `Workspace::new` (workspace.rs:54-58) uses that prefix
and is called directly by the library, by every one of the 13 existing
test binaries, by a second checkout, and, on a shared `/tmp`, by another
user; a glob sweep would delete workspaces belonging to processes the
daemon has never heard of. GC removes `work/<id>/` wholesale for terminal
jobs past the 200-job or 7-day retention cap, and publishes a retained
failure's path as `Job.WorkspacePath` so `pm ps --failed` can point at it
and `pm prune` can remove it. GC runs at startup, recovering orphans
first, and every 6 hours after that.

## 7. Invariants

Seven rules the implementation must hold. Each was a bug a reviewer found
in an earlier draft.

1. No `#[interface]` body does I/O, spawns a process, or calls blocking
   `ObjectServer::{at,interface}`. zbus has exactly one executor thread
   (connection/builder.rs:784-801) that dispatches every method's future
   onto itself (object_server/mod.rs:417-428). `blocking::ObjectServer::at`
   is `block_on` (blocking/object_server.rs:153, 213) and would park that
   one thread. A synchronous body freezes the socket reader, the socket
   writer, all signal delivery, and every other client's calls for its
   whole duration; a client-side `method_timeout` cannot rescue one slow
   method, because it is `Builder`-scoped (blocking/connection/builder.rs:300).
   This is why every interface method is `async fn` and does nothing but
   validate, mutate the in-memory registry, and hand off to the
   supervisor.
2. Only the supervisor thread forks workers, and it never returns.
   `PR_SET_PDEATHSIG` binds to the creating thread, not the process
   (hakoniwa runc.rs:121, 246). A worker thread that returns while its
   container still runs SIGKILLs the container with the daemon perfectly
   healthy; a `std::thread::scope` thread inside `Graph::build_with` that
   finishes while a step still runs does the same. Forking exclusively
   from a thread that outlives every job, plus a `pre_exec` recheck of
   `getppid()` to close the fork-or-parent-death race, makes the invariant
   hold by construction rather than by convention.
3. `pmd` never calls `waitpid(-1)`. hakoniwa's `Child::{wait,try_wait}` and
   std's `Child::wait` are `waitpid(self.pid, ..)` (child.rs:221, 244);
   the daemon and its workers use only pid-specific waits. A periodic
   `waitpid(-1, WNOHANG)` zombie sweep, proposed in earlier drafts as GC,
   is a pure TOCTOU: it would reap a container's outer pid out from under
   the thread blocked in `Child::wait`, turning a real exit status into a
   spurious `ECHILD` I/O error. Every child the daemon creates has an
   owner, so there is nothing unowned left to reap.
4. Only the emitter thread emits signals, and `StateChanged` and
   `Finished` survive backpressure. `blocking::Connection::emit_signal`
   blocks the calling thread until the message is written. If the thread
   that owns the 80 ms tick and the cancel grace timer were also the
   emitter, one subscriber that stops reading, a scrolled-back `pm logs
   -f`, would back up the outgoing queue and freeze progress, resource
   reporting and the SIGKILL escalation for every job. The emitter drains
   a bounded channel and, under backpressure, drops only coalescable
   payloads (progress snapshots, which are idempotent, and log batches,
   which are seq-numbered and refillable via `ReadLog`); it never drops
   `StateChanged` or `Finished`.
5. Sanitise and cap on ingest, once, and it must cover progress text, log
   lines and diagnostics. `collapse_control` moves from render time
   (progress.rs:431-438) to `Task::set_message`, because a failed step's
   miette report interpolates raw, uncapped `from_utf8_lossy` stdout and
   stderr (sandbox.rs:684-690, 755-763, 443-448) into `Job.Diagnostic`,
   the `Finished` payload and `PackageSettled`; observation paths and
   evidence are attacker-chosen strings from a traced program; and
   entrypoint names feed a `dialoguer::Select` on the client's real
   terminal. `pm::progress::sanitise` becomes the single choke point
   every `wire::` constructor passes through, with a stated cap per field
   (512 characters for a progress message, 16 KiB head plus 16 KiB tail
   for a captured stream, 64 KiB total for a whole `Diagnostic`).
   Sanitising at ingest is also the only placement that is correct with N
   subscribers; at render it would be N places to get right against one
   hostile build file.
6. GC sweeps only paths the daemon recorded, never a glob over a shared
   `TMPDIR`. `Workspace::new` (workspace.rs:54-58) uses a
   `TempDir::with_prefix("pm-{label}-")` pattern that the library and
   every one of the 13 existing test binaries also use, directly. A
   `pm-*` sweep would delete a live workspace belonging to a process the
   daemon never heard of: another test binary, a second checkout, or, on
   a shared `/tmp`, another user. One daemon-created scratch root per
   job, recorded in `job.json`, is what GC is allowed to touch.
7. `panic = unwind` is a requirement, not an accident. graph.rs:189-200's
   `catch_unwind` is the only reason a panicking package fails instead of
   hanging every other worker on a `Condvar` nobody can notify (commit
   0760806). Under a daemon, that failure mode is every client's work,
   not one build. `src/lib.rs` gains `#[cfg(panic = "abort")]
   compile_error!` naming graph.rs:189-200 and the commit, so a future
   switch to `panic = "abort"` for binary size is a build failure that
   names the exact line it would break, rather than a silent hang
   discovered in production. `panic = "unwind"` is already Cargo's
   default, so no `[profile]` entry is added; that would be a second,
   weaker copy of the same rule.

## 8. Test strategy

### Transport

zbus `p2p` over a socketpair, built with `Builder::async_io_unix_stream`,
is the default transport for protocol tests. There is no `dbus-daemon`,
`dbus-run-session`, `busctl` or `systemctl` on this machine, and
`/usr/share/dbus-1/services` does not exist, so p2p is the only transport
that always works: no broker, no environment variable, no name leak when a
test panics, and both ends live in one `cargo test` process, so a
serialisation mismatch produces a server-side backtrace too.
`Builder::unix_stream` is `#[deprecated]` in zbus 5.19.0
(blocking/connection/builder.rs:107-122) and would fail the project's
`clippy -D warnings` gate, which is why `async_io_unix_stream` is the
spelling used throughout. Both ends of a p2p connection must be built
concurrently, since the handshake is symmetric and building one side alone
deadlocks; this is documented in `tests/common/p2p.rs`. Proxies are
declared `#[zbus::proxy(assume_defaults = false)]` with no
`default_service`, so the same proxy type drives both a real bus (client
sets `.destination(BUS_NAME)`) and p2p (client omits it); that one
attribute is the entire transport difference, which keeps the harness
honest rather than a parallel mock.

### What `tests/dbus_bus.rs` covers that p2p structurally cannot

Well-known-name acquisition and the `RequestName` collision path;
`NameOwnerChanged`-driven `lifetime: "tied"` teardown; and the client's
flocked self-spawn end to end. Names are `org.pm1.test_<pid>_<nonce>` so
parallel test binaries never collide with each other or with a
developer's real daemon. The suite prints a skip line and returns `Ok(())`
on a bus-less machine rather than being `#[ignore]`d, because the session
bus is reachable on this box and an ignored test on the one machine that
can run it is a test that never runs.

### The contract test replacing a golden introspection file

zbus cannot produce a byte-stable introspection XML: the root element is a
bare `<node>` with no name attribute, interfaces are iterated from a
`BTreeMap` so the standard `org.freedesktop.*` ones sort first, children
are iterated from a `HashMap` so two or more job objects give
nondeterministic order, and children are inlined recursively with full
interface bodies (object_server/node.rs:171-177, 189-196, 22-23). The
replacement is two assertions that pin pm's API rather than zbus's
formatting: every wire type's `<T as zbus::zvariant::Type>::SIGNATURE`
compared against a string literal, and a parsed introspection check that
canonicalises `Introspect()` output on a childless path into a sorted set
of `(interface, member, in_signature, out_signature, access)` tuples, with
the `org.freedesktop.*` interfaces dropped, asserted to contain the
committed model.

### Fate of the 13 existing test binaries

Roughly 85 percent of the existing 7,096-line suite calls the library
directly and needs no edits at all, because every changed public signature
keeps a delegating wrapper.

| Binaries | Change |
|---|---|
| `build_file`, `command_output`, `config_file`, `download`, `graph`, `landlock`, `metadata`, `packaging`, `perms`, `progress`, `steps` | none, except `packaging` loses its `CwdGuard` use |
| `sandbox` | `CWD_LOCK` deleted; its one CLI call site (`pm_command` at :432, used at :404) is a refusal test whose wording is preserved client-side |
| `cli_build` | gains a `common::daemon::Daemon` guard; exit-code and archive-location assertions are unchanged because `pm build` stays foreground |

`landlock:150-157` calls `PackageRunner::new(..).run(..)` directly rather
than the CLI, so "`pm run` is always detached" never reaches it; all of
its assertions stand untouched. `tests/common/mod.rs` and
`tests/sandbox.rs` lose their `CWD_LOCK`/`CwdGuard` copies and move to
`BuildContext { output_dir, .. }`; this is an honest edit, not a free one,
because `BuildFile::run()` still delegates through `BuildContext::from_env()`,
which still reads `current_dir()`, so any call site that still resolves
against the process cwd flakes immediately once the lock is gone and
`cargo test` runs in parallel. `src/bin/pm-fuzz.rs` moves its liveness
oracle from `pm` to `pmd`, since the worker is now the process holding the
jail; each fuzz worker starts its own private daemon.

Phase 1's gate is `cargo test --all-targets` fully green before a single
line of daemon code exists, which is what makes the 85 percent figure a
verified fact rather than a hopeful estimate.

### New suites

`tests/context.rs` (output_dir, trust_dir and path honoured from a foreign
cwd, the test that makes `CWD_LOCK` deletable). `tests/worker.rs`
(socketpair plus forked worker plus frame assertions, no D-Bus at all, the
fastest place to debug the actual work). `tests/dbus_proto.rs` (the full
lifecycle for build, run and audit jobs, including `needs-input`/`Choose`,
`ReadLog` cursor paging with a deliberately dropped signal refilled from
`ReadLog`, cancellation, and slot exclusion). `tests/gc.rs` (orphan
recovery, the never-glob-a-shared-tmpdir regression guard, retention).
`tests/dbus_bus.rs`, described above.

### Named regression guards

Three guards are worth naming because each is a bug this design exists to
prevent, and none would be caught by ordinary coverage:

1. Progress volume: a build step printing 10000 lines must produce no more
   than 13 `ProgressChanged` signals per second (the 80 ms tick is a hard
   12.5 Hz ceiling; 13 is the integer test tolerance), and the job log
   must contain no ESC bytes.
2. Cancellation of a parked graph: a build on a dependency chain,
   cancelled while workers are blocked in `wakeup.wait`, must reach
   `cancelled` within 7 seconds.
3. PDEATHSIG thread scope: spawn a container from a thread, exit the
   thread, and assert the child is still alive after 1 second.

## 9. Breaking changes

- `pm run` is always detached, so `$?` no longer carries the package's
  exit code. `pm run pkg` now prints a job id and exits 0 once the job is
  running. `if pm run pkg; then ..` now tests whether the job started, not
  whether the program succeeded. `pm run --wait pkg` restores the old
  behaviour (submit, block on `Finished`, exit with the job's code), as
  does `pm run pkg` followed by `pm wait <id>`.
- `pm` can no longer run inside a pm sandbox. The run container unshares
  the network namespace and never mounts the session bus socket, so a
  packaged `pm` cannot reach the daemon and exits with a connection error
  instead of clap's exit 2. No replacement is offered: mounting the bus
  socket into the jail would hand every packaged program the ability to
  submit jobs as the invoking user.
- A daemon is now mandatory for `pm build`, `pm run` and `pm run --audit`.
  `pm sign`, `pm keygen`, `pm trust`, `pm explain`, `pm generate`, `pm
  profile` and `pm promote` stay entirely local.
- Processes do not survive a daemon restart. A `systemctl --user restart
  pmd`, a crash, or an OOM kill terminates every in-flight build and run,
  because hakoniwa's `PR_SET_PDEATHSIG(SIGKILL)` and `PTRACE_O_EXITKILL`
  have no API to disable. Affected jobs become `orphaned` with a
  `Finished(-1, "orphaned")`, which is reporting, not resilience.
- A non-UTF-8 `$PATH` entry, `$HOME`, cwd or trust dir now fails the
  command with `InvalidContext`, naming the offending variable, rather
  than lossy-converting a path the jail then cannot find. Build output is
  unaffected, since `drain_into` and `describe_stream` already use
  `from_utf8_lossy`.
- `pm run --audit` on a non-x86_64 host now errors instead of silently
  running the package unaudited and unenforced. `StartAudit` fails with
  `NotSupported` before a job exists, and `Manager.Features` omits
  `audit`. A denied `PTRACE_TRACEME` is now `PtraceDenied` instead of an
  empty successful report indistinguishable from a clean audit.
- `pm::perms::monitor::trace` returns `Err` where it used to return an
  empty successful report. Any library caller that treated a
  zero-observation report as clean now gets an error instead; this is the
  point of the change.
- Build output in a failure diagnostic is truncated to a 16 KiB head plus
  16 KiB tail. The full text remains in `jobs/<id>/log.ndjson` and
  `diagnostic.txt`, whose paths are job properties, but grepping a large
  piped `pm build` failure for a string deep in the output no longer finds
  it there.
- Progress messages are sanitised and truncated to 512 characters at
  ingest, not at render, on a terminal as well as through the daemon. A
  build tool emitting a carriage-return-animated progress bar looks worse
  under `pm` than it does today.
- `pm build` now dies with its client: it submits with `lifetime: "tied"`,
  so Ctrl-C or a closed terminal cancels the build. `pm build --detach`
  opts out.
- Job ids, not paths or prefixes, are the handle for `pm ps`, `pm logs`,
  `pm wait` and `pm stop`.
- `pm-fuzz`'s 20 second `RUN_TIMEOUT` now cancels the job rather than
  killing the client process; a hostile package that ignores `SIGTERM`
  gets the 5 second grace before `SIGKILL`, and a job that never reaches a
  terminal state is itself a finding.
- `tests/common/mod.rs` and `tests/sandbox.rs` lose `CWD_LOCK`/`CwdGuard`,
  and `tests/packaging.rs` loses its use of them, a deliberate edit whose
  removal is what proves the context-passing seam actually works under
  parallel `cargo test`.

## 10. Open risks

- The downloader still cannot be interrupted in place. minreq's
  `with_timeout` is absolute, not idle, and exposes neither the socket nor
  a per-read timeout, so a build sitting on a dead mirror produces no
  output until someone runs `pm stop`. Process-per-job makes `SIGKILL` a
  real remedy, which is strictly better than the alternatives, but it is
  not a fix for the underlying library. The real fix is replacing minreq
  with a client that exposes socket timeouts, complicated on this machine
  by the fact that only the `https-rustls` TLS backend links; the others
  want OpenSSL headers that are absent.
- Cancelling a build step kills the worker; it does not stop the step and
  unwind cleanly. A forty-minute `cargo build` ignores the cooperative
  cancel token entirely, and escalation is `SIGKILL` with no chance for
  the build system to clean up. The workspace left behind is removed by
  GC, not by `Workspace::drop`.
- Poison tolerance in a long-lived process is arguably wrong.
  `unwrap_or_else(PoisonError::into_inner)` is unambiguously right for a
  short-lived CLI, and the daemon's registry copies the idiom so one
  panicking job cannot bury every subsequent `ListJobs` call in a second
  panic. In a process that runs for weeks, continuing with half-updated
  state after a panic may be worse than restarting. Revisit after the
  first real deadlock or corrupted-registry report.
- One daemon per user is one blast radius per user. `pm build
  --unsandboxed` runs with the caller's own privileges, unchanged from
  today, but that build now shares a machine with every other job the
  same user is running and can ptrace or kill `pmd`. Calling this
  "privilege separation" oversells it: what separates is concerns (one
  process owns landlock, userns and ptrace; one owns the key), not
  privilege. A compromised `pmd` is exactly as bad as a compromised `pm`.
- The worker to daemon frame protocol is a second wire format with no
  introspection. Skew is impossible, since the daemon is its own worker
  via `/proc/self/exe`, and it is covered by `tests/worker.rs`, but it is
  a serialisation surface a third party cannot inspect without reading
  the code.
- `Runctl::GetProcPidStatus`/`GetProcPidSmapsRollup` turn hakoniwa's
  reaper into a tracer for the one container they are set on, changing
  signal-delivery semantics for it. This has not been exercised together
  with landlock enforcement under load.
- `a{sv}` option bags are typed at runtime, not in the method signature. A
  typo'd key is a hard failure at call time rather than a compile-time
  one. The alternative, a full positional signature per `Start*` method,
  would be unreadable at a dozen options each and unextendable without a
  break; this was chosen knowingly as the weaker part of the surface.
- `org.pm1` is not a domain anyone owns. It will not collide in practice
  and version-in-name follows freedesktop convention, but it violates
  reverse-DNS and would need changing before any distribution packaging.
  Changing a well-known bus name later breaks every installed `.service`
  file and every third-party consumer, so it is cheaper to settle the
  final name before the first GUI consumes it.
- No idle-exit policy is specified, and it would interact badly with
  `lifetime: "detach"` if added carelessly: the design ships an
  activation `.service` file, implying the unit may exit when idle, while
  also forking every worker with PDEATHSIG, so "detach" means "survives
  the client" but never "survives the daemon". If an idle timeout is ever
  added, it must refuse to fire while any job is non-terminal. For now
  `pmd` runs until `SIGTERM`.
- `BuildContext` grows every time something turns out to read the process
  environment. It is `#[non_exhaustive]` for that reason, but each
  addition is another thing a caller can forget, and another silent
  divergence between a library call and a daemon call.
- `ReadLog` against a cold `log.ndjson` is blocking file I/O, moved off
  the executor thread to the supervisor behind a channel and capped at
  10000 records, but the supervisor also owns the 80 ms tick and the
  cancel grace timer, so a very slow filesystem could still delay
  progress emission and SIGKILL escalation.
- Protocol-version skew is detected but not prevented. `Ping()` returns a
  protocol string the client compares, and a mismatch names `pm daemon
  restart`, but a stale `pmd` from a previous build holding the
  well-known name while the client is rebuilt remains the single most
  likely source of confusing failures.

## 11. Open questions

Left open because the source material does not specify an answer, and this
document does not invent API to fill the gap.

- The submission-queue depth that triggers `org.pm1.Error.Busy`. The error
  is named with the gloss "queue full", but no bound, backing data
  structure, or admission point (per-connection, per-uid, or
  daemon-wide) is given anywhere in the source material.
- The trigger and lifecycle for `org.pm1.Error.Draining`. It is named as
  an error but never connected to a described shutdown sequence; the
  closest related material is the open risk on idle-exit policy above,
  which says the daemon currently just runs until `SIGTERM` with no drain
  phase. Whether `Draining` belongs to a future graceful-shutdown feature,
  or should exist from the first release with `SIGTERM` alone triggering
  it, is unspecified.
- The wire format of `Manager.Protocol` and the `PROTOCOL` constant it
  exposes. The source material establishes that the client compares it
  for equality and refuses on mismatch, but not whether it is a semver
  string, an integer rendered as a string, or something else.
