//! Permissions derived by watching one real execution with `ptrace`.
//!
//! [`trace`] forks, puts the child under `ptrace`, `execve`s the program and then steps
//! it with `PTRACE_SYSCALL`, decoding every syscall that names a path, starts a process
//! or reaches for a socket. What comes back is a [`TraceReport`]: the raw
//! [`Observation`]s in the order they happened, and a [`Permissions`] set folded out of
//! them with [`Provenance::RuntimeMonitor`] and one evidence line per syscall.
//!
//! Everything here is done in-process through `nix`. `strace` is not involved and is not
//! required to be installed.
//!
//! # This sees ONE execution, and only that one
//!
//! A monitor records the paths a single run happened to take. It cannot see the branch
//! that was not taken, the error handler that did not fire, the locale file that a
//! different `LANG` would have opened, or the plugin that only loads on a machine with
//! the hardware for it. **A package that works perfectly while traced will still hit an
//! unobserved path in production.** Widening a profile after the fact is a support
//! ticket; that is precisely why a derived profile is [`Enforcement::Audit`] and is never
//! promoted without a human reading [`Permissions::report`].
//!
//! Two further honesty notes about what a grant here does and does not mean:
//!
//! - A syscall that *failed* produces an [`Observation`] with
//!   [`Observation::succeeded`] false and contributes **no** grant. Dynamic linkers probe
//!   dozens of paths that do not exist; granting those would describe the loader's search
//!   order rather than the package's needs.
//! - A *metadata probe* - `stat`, `lstat`, `newfstatat`, `statx`, `access`, `faccessat`,
//!   `readlink`, `readlinkat` - on a **directory** is observed but grants nothing, so
//!   [`Observation::grants`] is false while [`Observation::succeeded`] is true.
//!   [`Permission::ReadPath`] means "this path and everything under it", and glibc's
//!   resolver alone probes `/` on the way to `/etc/resolv.conf`: folding that into a
//!   grant turns one `st_mode` lookup into read access to the whole filesystem, and the
//!   ancestor-collapsing in [`Permissions::merge`] then swallows every other read grant
//!   into it. Opening a directory still grants it - that is a deliberate `readdir`, not
//!   a probe.
//! - A relative path is resolved against its `dirfd` through `/proc/<pid>/fd` while the
//!   tracee is stopped. When that lookup fails the path is recorded **exactly as the
//!   tracee passed it** and [`Observation::path_is_resolved`] is false, with the evidence
//!   line saying so. Inventing a plausible absolute path would be worse than admitting
//!   the gap.
//!
//! [`Enforcement::Audit`]: crate::perms::Enforcement::Audit

use std::{path::PathBuf, time::Duration};

use nix::errno::Errno;
use serde::Serialize;

use crate::perms::{Permission, Permissions, Provenance};

/// How to run the program being traced.
///
/// [`TraceOptions::default`] gives a 30-second timeout, the current working directory,
/// an empty environment and fork following enabled.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Wall-clock budget for the whole traced process group. When it runs out the group
    /// is killed and [`TraceReport::timed_out`] is true.
    pub timeout: Duration,
    /// Directory to `chdir` into before `execve`. `None` inherits ours.
    pub working_dir: Option<PathBuf>,
    /// The complete environment for the tracee. This is *not* merged with ours: a
    /// monitor that inherited the developer's `$HOME` and `$LANG` would record their
    /// machine rather than the package.
    pub env: Vec<(String, String)>,
    /// Trace children too, via `PTRACE_O_TRACEFORK`/`TRACEVFORK`/`TRACECLONE`. A build
    /// tool that does its real work in a child is invisible without this.
    pub follow_forks: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            working_dir: None,
            env: Vec::new(),
            follow_forks: true,
        }
    }
}

/// One syscall the tracee made, decoded into the permission it implies.
///
/// A single syscall can yield more than one observation (`rename` names two paths,
/// `execve` implies both [`Permission::Spawn`] and [`Permission::ExecPath`]), so
/// observations are per-permission rather than per-syscall.
///
/// Only [`Serialize`] is derived here, not `Deserialize`: `syscall` is `&'static str`,
/// interned in the `x86_64` module's private `TABLE`, and there is no lookup yet that
/// turns a deserialised owned string back into one of those statics. `pm-trace` (the
/// only thing writing this out today) only ever serialises a report, never reads one
/// back, so a `Deserialize` impl - and the `TABLE` lookup it needs - is left for
/// whichever future caller does, most likely a daemon reading `pm-trace`'s report file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    pid: i32,
    syscall: &'static str,
    permission: Permission,
    path_resolved: bool,
    succeeded: bool,
    granting: bool,
}

impl Observation {
    /// The thread that made the call.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The syscall's name, e.g. `openat`.
    pub fn syscall(&self) -> &'static str {
        self.syscall
    }

    /// The permission this call implies.
    pub fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Whether a relative path was successfully resolved against its `dirfd`.
    ///
    /// `false` means the path inside [`Observation::permission`] is verbatim what the
    /// tracee passed and is **not** an absolute path. Always `true` for a pathless
    /// permission or one that arrived absolute.
    pub fn path_is_resolved(&self) -> bool {
        self.path_resolved
    }

    /// Whether the syscall returned success. Failed calls grant nothing.
    pub fn succeeded(&self) -> bool {
        self.succeeded
    }

    /// Whether this observation contributes a grant to [`TraceReport::permissions`].
    ///
    /// A successful syscall can still grant nothing. The case that matters is a
    /// *metadata probe* - `stat`, `access`, `readlink` and friends - on a path that is a
    /// directory. [`Permission::ReadPath`] means "this path **and everything under it**",
    /// so folding a `stat("/")` into a grant would hand the package the entire
    /// filesystem on the strength of one `st_mode` lookup. Those observations are kept
    /// and reported, but they do not widen the profile. See [`trace`] for the full list.
    pub fn grants(&self) -> bool {
        self.succeeded && self.granting
    }

    /// The evidence line this observation contributes, naming the syscall and the path.
    pub fn evidence(&self) -> String {
        let subject = self
            .permission
            .path()
            .map_or_else(|| "(no path)".to_owned(), |path| path.display().to_string());
        let mut line = format!("{} {subject} (pid {})", self.syscall, self.pid);
        if !self.path_resolved {
            line.push_str(" [relative, dirfd unresolved - recorded as passed]");
        }
        line
    }
}

/// What one traced execution did.
///
/// Read [`TraceReport::permissions`] for the profile and [`TraceReport::observations`]
/// for the unfolded detail behind it. Always check [`TraceReport::timed_out`]: a report
/// from a run that was killed describes a prefix of the program's behaviour, so it is
/// even less complete than a monitor report normally is.
///
/// Derives [`Serialize`] only, for the same reason [`Observation`] does - see its doc.
#[derive(Debug, Clone, Serialize)]
pub struct TraceReport {
    permissions: Permissions,
    observations: Vec<Observation>,
    timed_out: bool,
    exit_status: Option<i32>,
}

impl TraceReport {
    /// The permission set folded out of the successful observations.
    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    /// Every decoded syscall, in the order it happened, failures included.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Whether the timeout fired and the traced process group was killed.
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// The traced program's exit code, or `None` if it was killed by a signal, timed out
    /// or never got far enough to exit.
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }
}

/// Why the traced child never reached its `execve`.
///
/// [`trace`]'s forked child has exactly four ways to die before the tracee's image is
/// replaced - see `child` in the x86_64 implementation - and every one of them used to
/// `_exit(127)` indistinguishably from a program that ran and genuinely exited 127 on its
/// own. That collapsed "ptrace was denied" and "the binary does not exist" into the same
/// empty, successful-looking [`TraceReport`]. This names which of the four it was and
/// carries the syscall's own `errno`.
///
/// [`ChildFailure::Traceme`] is the one worth a [`miette::Diagnostic::help`]: a hardened
/// kernel's `/proc/sys/kernel/yama/ptrace_scope` or an LSM policy can refuse it outright,
/// and that describes the *host*, not the package, so it is the one thing here a caller
/// can actually go fix.
#[derive(Debug, Clone, Copy)]
pub enum ChildFailure {
    /// `setpgid` into a fresh process group failed.
    SetPgid(Errno),
    /// `chdir` into [`TraceOptions::working_dir`] failed - most often because it does not
    /// exist.
    Chdir(Errno),
    /// `ptrace::traceme()` was refused. See [`ChildFailure`]'s docs for what to check.
    Traceme(Errno),
    /// `execve` failed: a missing or non-executable program.
    Execve(Errno),
}

impl ChildFailure {
    /// What a user can do about a denied `ptrace`: the two levers a hardened host
    /// restricts it with. Shared with `preflight`'s own denial - the two mean exactly the
    /// same thing.
    const PTRACE_DENIED_HELP: &'static str = "ptrace was denied. Check \
        /proc/sys/kernel/yama/ptrace_scope (0 permits tracing your own processes, a \
        higher value restricts it further) and whether an LSM such as SELinux or \
        AppArmor is blocking PTRACE for this program.";

    /// Discriminant bytes the child-failure pipe carries. See `fail` and
    /// `read_child_failure` in the x86_64 implementation for the wire format itself.
    const WIRE_SETPGID: u8 = 1;
    const WIRE_CHDIR: u8 = 2;
    const WIRE_TRACEME: u8 = 3;
    const WIRE_EXECVE: u8 = 4;

    /// `1` discriminant byte plus `4` bytes of the raw errno, native-endian.
    const WIRE_LEN: usize = 5;

    /// Reconstruct a `ChildFailure` from the discriminant byte and raw errno the pipe
    /// carried. `None` for a byte the child could never have sent, which would mean the
    /// wire format and this function have drifted apart.
    #[cfg_attr(
        not(target_arch = "x86_64"),
        allow(
            dead_code,
            reason = "only produced by the x86_64 tracer's failure pipe"
        )
    )]
    fn from_wire(kind: u8, errno: i32) -> Option<Self> {
        let errno = Errno::from_raw(errno);
        match kind {
            Self::WIRE_SETPGID => Some(Self::SetPgid(errno)),
            Self::WIRE_CHDIR => Some(Self::Chdir(errno)),
            Self::WIRE_TRACEME => Some(Self::Traceme(errno)),
            Self::WIRE_EXECVE => Some(Self::Execve(errno)),
            _ => None,
        }
    }
}

impl std::fmt::Display for ChildFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetPgid(errno) => {
                write!(
                    f,
                    "the traced child could not join its own process group: {errno}"
                )
            }
            Self::Chdir(errno) => write!(
                f,
                "the traced child could not chdir into its working directory: {errno}"
            ),
            Self::Traceme(errno) => write!(f, "ptrace::traceme() was refused: {errno}"),
            Self::Execve(errno) => {
                write!(f, "the traced program could not be executed: {errno}")
            }
        }
    }
}

impl std::error::Error for ChildFailure {}

impl miette::Diagnostic for ChildFailure {
    fn help(&self) -> Option<Box<dyn std::fmt::Display + '_>> {
        match self {
            Self::Traceme(_) => Some(Box::new(Self::PTRACE_DENIED_HELP)),
            Self::SetPgid(_) | Self::Chdir(_) | Self::Execve(_) => None,
        }
    }
}

/// Build a report from raw observations, folding the successful ones into a profile.
#[cfg_attr(
    not(target_arch = "x86_64"),
    allow(dead_code, reason = "no tracer on this arch")
)]
fn report(
    observations: Vec<Observation>,
    timed_out: bool,
    exit_status: Option<i32>,
) -> TraceReport {
    let permissions: Permissions = observations
        .iter()
        .filter(|observation| observation.grants())
        .map(|observation| {
            crate::perms::Grant::new(
                observation.permission.clone(),
                Provenance::RuntimeMonitor,
                [observation.evidence()],
            )
        })
        .collect();
    TraceReport {
        permissions,
        observations,
        timed_out,
        exit_status,
    }
}

#[cfg(not(target_arch = "x86_64"))]
/// The diagnostic every non-`x86_64` entry point in this module returns: there is no
/// syscall table for anything but `x86_64` (see [`trace`]), so neither deriving nor
/// verifying a profile is possible here. Shared between [`trace`] and [`preflight`] so
/// the wording cannot drift apart between the two stubs.
fn unsupported_architecture<T>() -> miette::Result<T> {
    Err(miette::miette!(
        help = "run the runtime monitor on an x86_64 host, or extend the syscall table in \
                src/perms/monitor.rs for this architecture",
        "the ptrace runtime monitor is implemented for x86_64 only (this is {})",
        std::env::consts::ARCH
    ))
}

#[cfg(not(target_arch = "x86_64"))]
/// Run `program` with `args` under ptrace and record what it actually touched.
///
/// **Only implemented for `x86_64`.** Syscall numbers and the argument registers are
/// per-architecture, and a table from the wrong architecture would decode `openat` as
/// something else entirely and quietly write a wrong profile. On any other target this
/// returns a diagnostic instead.
///
/// # Errors
///
/// Always, on a non-`x86_64` target.
pub fn trace(
    program: &std::path::Path,
    args: &[String],
    options: &TraceOptions,
) -> miette::Result<TraceReport> {
    let _ = (program, args, options);
    unsupported_architecture()
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::trace;

#[cfg(not(target_arch = "x86_64"))]
/// Whether this host can actually run [`trace`] at all, without running any package.
///
/// See the x86_64 implementation for what "actually" means: a probe that never `execve`s
/// cannot tell "ptrace denied" apart from "ptrace fully permitted", so it has to do more
/// than call `ptrace::traceme()` and look at the result.
///
/// # Errors
///
/// Always, on a non-`x86_64` target, for the same reason [`trace`] always errors here.
pub fn preflight() -> miette::Result<()> {
    unsupported_architecture()
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::preflight;

/// The x86_64 implementation: syscall table, argument decoding and the tracer loop.
///
/// Everything in here is architecture-specific by construction - see [`TABLE`].
#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use std::{
        collections::HashMap,
        ffi::{CString, OsString},
        io::Read as _,
        os::{
            fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
            unix::ffi::OsStringExt as _,
        },
        path::{Path, PathBuf},
        sync::{Mutex, PoisonError},
        time::{Duration, Instant},
    };

    use miette::{IntoDiagnostic as _, Result, WrapErr as _, miette};
    use nix::{
        errno::Errno,
        libc,
        sys::{
            ptrace,
            signal::Signal,
            wait::{WaitPidFlag, WaitStatus, waitpid},
        },
        unistd::{ForkResult, Pid, execve, fork, setpgid},
    };
    use tracing::{debug, trace as trace_log, warn};

    use super::{ChildFailure, Observation, TraceOptions, TraceReport, report};
    use crate::perms::Permission;

    /// What a decoded syscall argument turns into.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// `open`-family: `(path, flags)`, write-ness read out of the flags.
        Open {
            dirfd: Option<u8>,
            path: u8,
            flags: u8,
        },
        /// `openat2`: flags live in a `struct open_how` rather than a register.
        OpenHow { dirfd: u8, path: u8, how: u8 },
        /// Reads metadata or contents at a path.
        Read { dirfd: Option<u8>, path: u8 },
        /// Creates, removes or renames a path.
        Write { dirfd: Option<u8>, path: u8 },
        /// Renames: two paths, both written.
        Rename {
            old_dirfd: Option<u8>,
            old_path: u8,
            new_dirfd: Option<u8>,
            new_path: u8,
        },
        /// `execve`-family: [`Permission::Spawn`] plus [`Permission::ExecPath`].
        Exec { dirfd: Option<u8>, path: u8 },
        /// `fork`/`clone`-family: [`Permission::Spawn`] and nothing else.
        Spawn,
        /// `socket(domain, ...)`: the address family is a plain register.
        SocketDomain { domain: u8 },
        /// `connect`/`bind`/`sendto`: the family lives in the `sockaddr` at `addr`.
        SockAddr { addr: u8, len: u8, binds: bool },
    }

    /// The syscalls worth decoding, by **x86_64** syscall number.
    ///
    /// The numbers come from `libc`'s `SYS_*` constants for this target rather than from
    /// memory, so the table cannot drift from the kernel ABI. It is nevertheless
    /// x86_64-only: `SYS_open` is 2 here and something else on every other architecture,
    /// and several entries (`open`, `stat`, `access`, `unlink`, `mkdir`, `rename`,
    /// `fork`, `vfork`) do not exist at all on the newer architectures that only ship
    /// the `*at` forms. The whole module is gated on `target_arch = "x86_64"` for that
    /// reason.
    ///
    /// Register order for a syscall on this ABI is `rdi, rsi, rdx, r10, r8, r9`, which is
    /// what the `u8` argument indices below mean.
    const TABLE: &[(i64, &str, Shape)] = &[
        // --- files: open ---
        (
            libc::SYS_open,
            "open",
            Shape::Open {
                dirfd: None,
                path: 0,
                flags: 1,
            },
        ),
        (
            libc::SYS_openat,
            "openat",
            Shape::Open {
                dirfd: Some(0),
                path: 1,
                flags: 2,
            },
        ),
        (
            libc::SYS_openat2,
            "openat2",
            Shape::OpenHow {
                dirfd: 0,
                path: 1,
                how: 2,
            },
        ),
        // --- files: metadata reads ---
        (
            libc::SYS_stat,
            "stat",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_lstat,
            "lstat",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_newfstatat,
            "newfstatat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_statx,
            "statx",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_access,
            "access",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_faccessat,
            "faccessat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_faccessat2,
            "faccessat2",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_readlink,
            "readlink",
            Shape::Read {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_readlinkat,
            "readlinkat",
            Shape::Read {
                dirfd: Some(0),
                path: 1,
            },
        ),
        // --- files: mutations ---
        (
            libc::SYS_unlink,
            "unlink",
            Shape::Write {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_unlinkat,
            "unlinkat",
            Shape::Write {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_mkdir,
            "mkdir",
            Shape::Write {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_mkdirat,
            "mkdirat",
            Shape::Write {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (
            libc::SYS_rename,
            "rename",
            Shape::Rename {
                old_dirfd: None,
                old_path: 0,
                new_dirfd: None,
                new_path: 1,
            },
        ),
        (
            libc::SYS_renameat,
            "renameat",
            Shape::Rename {
                old_dirfd: Some(0),
                old_path: 1,
                new_dirfd: Some(2),
                new_path: 3,
            },
        ),
        (
            libc::SYS_renameat2,
            "renameat2",
            Shape::Rename {
                old_dirfd: Some(0),
                old_path: 1,
                new_dirfd: Some(2),
                new_path: 3,
            },
        ),
        // --- processes ---
        (
            libc::SYS_execve,
            "execve",
            Shape::Exec {
                dirfd: None,
                path: 0,
            },
        ),
        (
            libc::SYS_execveat,
            "execveat",
            Shape::Exec {
                dirfd: Some(0),
                path: 1,
            },
        ),
        (libc::SYS_fork, "fork", Shape::Spawn),
        (libc::SYS_vfork, "vfork", Shape::Spawn),
        (libc::SYS_clone, "clone", Shape::Spawn),
        (libc::SYS_clone3, "clone3", Shape::Spawn),
        // --- sockets ---
        (
            libc::SYS_socket,
            "socket",
            Shape::SocketDomain { domain: 0 },
        ),
        (
            libc::SYS_connect,
            "connect",
            Shape::SockAddr {
                addr: 1,
                len: 2,
                binds: false,
            },
        ),
        (
            libc::SYS_bind,
            "bind",
            Shape::SockAddr {
                addr: 1,
                len: 2,
                binds: true,
            },
        ),
        (
            libc::SYS_sendto,
            "sendto",
            Shape::SockAddr {
                addr: 4,
                len: 5,
                binds: false,
            },
        ),
    ];

    /// Longest path we will copy out of a tracee, matching `PATH_MAX`.
    const PATH_MAX: usize = libc::PATH_MAX as usize;

    /// How long to sleep when no tracee has an event pending. Short enough that the
    /// timeout stays sharp, long enough not to spin a core while a tracee sleeps.
    const IDLE_POLL: Duration = Duration::from_micros(200);

    /// How long to keep reaping after a timeout kill before giving up on a stuck tracee.
    const REAP_BUDGET: Duration = Duration::from_secs(2);

    /// Per-tracee bookkeeping. `PTRACE_SYSCALL` stops on both entry and exit, and only
    /// the pair together tells us both the arguments and whether the call worked.
    ///
    /// A new tracee - ours after `execve`, or a child the fork options handed us - starts
    /// outside a syscall: its first stop is an entry. See [`phase`].
    #[derive(Default)]
    struct State {
        /// Fallback for [`phase`] on a kernel without `PTRACE_GET_SYSCALL_INFO`: whether
        /// the last stop was an entry, so the next one should be its exit.
        in_syscall: bool,
        /// Observations decoded at entry, waiting for the exit stop to say if they count.
        pending: Vec<Observation>,
        /// Whether `pending` came from an `execve`, whose "exit" arrives as a plain
        /// `SIGTRAP` after the new image is in place rather than as a syscall stop.
        pending_is_exec: bool,
    }

    /// Run `program` with `args` under ptrace and record what it actually touched.
    ///
    /// The child is put in its own process group, `chdir`ed into
    /// [`TraceOptions::working_dir`], given exactly [`TraceOptions::env`] as its
    /// environment, and traced with `PTRACE_O_TRACESYSGOOD` (plus the fork options when
    /// [`TraceOptions::follow_forks`] is set) and `PTRACE_O_EXITKILL`, so nothing
    /// survives us. When [`TraceOptions::timeout`] expires the whole group is killed and
    /// the report says [`TraceReport::timed_out`].
    ///
    /// The returned profile is **incomplete by construction** - it describes the paths
    /// this one execution took and no others - which is why a profile derived from it
    /// stays in [`Enforcement::Audit`] until a human promotes it.
    ///
    /// Only one trace runs at a time per process; a concurrent caller blocks until the
    /// first finishes. `ptrace` reports stops through the process-wide wait queue, so
    /// two tracers would steal each other's syscall stops and both write a wrong
    /// profile. See `TRACER`.
    ///
    /// # Errors
    ///
    /// A diagnostic if `program` or an argument contains an interior NUL, if `fork`
    /// fails, or if the child cannot be waited for at all. A tracee that exits non-zero
    /// is *not* an error: that is reported through [`TraceReport::exit_status`].
    ///
    /// [`Enforcement::Audit`]: crate::perms::Enforcement::Audit
    pub fn trace(program: &Path, args: &[String], options: &TraceOptions) -> Result<TraceReport> {
        // See `TRACER`: one tracer per process, or two of them quietly rob each other.
        // A poisoned lock still guards the right to call `waitpid` correctly - the mutex
        // protects no data that a panic could have left half-written - so the poison is
        // stepped over rather than turned into a failure.
        let _tracer = TRACER.lock().unwrap_or_else(PoisonError::into_inner);

        let program_c = cstring(program.as_os_str().as_encoded_bytes())
            .wrap_err_with(|| format!("program path {}", program.display()))?;
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(program_c.clone());
        for arg in args {
            argv.push(cstring(arg.as_bytes()).wrap_err_with(|| format!("argument {arg:?}"))?);
        }
        let mut envp = Vec::with_capacity(options.env.len());
        for (key, value) in &options.env {
            envp.push(
                cstring(format!("{key}={value}").as_bytes())
                    .wrap_err_with(|| format!("environment variable {key:?}"))?,
            );
        }
        let working_dir = options
            .working_dir
            .as_deref()
            .map(|dir| cstring(dir.as_os_str().as_encoded_bytes()))
            .transpose()
            .wrap_err("working directory")?;

        debug!(
            program = %program.display(),
            args = args.len(),
            timeout_ms = options.timeout.as_millis(),
            follow_forks = options.follow_forks,
            "starting ptrace runtime monitor"
        );

        // A CLOEXEC pipe is how the child reports *which* of its four failure paths
        // fired before `execve` - see `fail` and `read_child_failure` below. This is
        // created before `fork` so both ends already exist when the child branch starts;
        // creating it after would race the child against its own pipe.
        let (failure_read, failure_write) = cloexec_pipe()?;

        // SAFETY: the child branch below touches nothing but pre-allocated CStrings, a
        // raw fd and async-signal-safe syscalls before `execve` replaces the image.
        match unsafe { fork() }
            .into_diagnostic()
            .wrap_err("fork for ptrace monitor")?
        {
            ForkResult::Child => {
                // The child never reads from this pipe; keeping its copy around would
                // only stop the read end's own CLOEXEC from doing anything useful.
                drop(failure_read);
                child(
                    &program_c,
                    &argv,
                    &envp,
                    working_dir.as_deref(),
                    failure_write.as_raw_fd(),
                );
            }
            ForkResult::Parent { child } => {
                // Fork duplicated our copy of the write end, and CLOEXEC only closes it
                // on an *exec* - which we, the parent, are never going to do. Keeping it
                // open here would mean the pipe always has a writer, so `supervise`'s
                // read would block forever waiting for an EOF that never comes.
                drop(failure_write);
                supervise(child, program, options, failure_read)
            }
        }
    }

    /// Create a pipe whose both ends are `O_CLOEXEC`, atomically.
    ///
    /// `nix::unistd::pipe2` would need the crate's `fs` feature, which is not on (see the
    /// module doc), so this calls `libc::pipe2` directly - the same pattern already used
    /// for `chdir`. Atomicity matters here: a plain `pipe` followed by a separate
    /// `fcntl(F_SETFD)` leaves a window where a concurrent `exec` elsewhere in this
    /// process would leak the fd across it.
    fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [-1_i32; 2];
        // SAFETY: `fds` is a valid, correctly sized buffer; `pipe2` either fills both
        // slots or returns an error and leaves them untouched.
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if result != 0 {
            return Err(Errno::last())
                .into_diagnostic()
                .wrap_err("cannot create the child-failure pipe");
        }
        // SAFETY: `pipe2` returned success, so both fds are open, valid and not owned
        // anywhere else yet.
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Serialises [`trace`] and [`preflight`] calls within one process.
    ///
    /// `ptrace`'s wait interface is process-wide: the tracer loop calls `waitpid(-1)`,
    /// which reaps *any* child of this process, because a tracee's forked children are
    /// not known by pid until their first stop arrives. Two tracers running side by side
    /// therefore consume each other's syscall stops and each writes a profile built from
    /// half of the other program's behaviour - silently, and with no error anywhere. A
    /// second caller waits here instead. [`preflight`] forks a tracee of its own for the
    /// same reason: without this lock, a concurrent [`trace`]'s `waitpid(-1)` could reap
    /// `preflight`'s probe child before `preflight`'s own targeted wait ever sees it.
    ///
    /// This guards only *other tracers*. Any other code in the process that spawns and
    /// reaps its own children concurrently - a `std::process::Command`, a build step -
    /// is still racing the tracer for the same wait queue, so a trace should be the only
    /// child-reaping work in flight.
    static TRACER: Mutex<()> = Mutex::new(());

    /// Whether this host can actually run [`trace`] at all: fork, ask to be traced, exec
    /// something trivial and confirm the kernel raises the post-exec stop.
    ///
    /// A child that only calls `ptrace::traceme()` and then `_exit(0)` proves nothing: it
    /// produces a plain [`WaitStatus::Exited`], not a stop, **even on a host where ptrace
    /// is fully permitted**, because there was never a syscall for the kernel to trap.
    /// Only a completed `execve` raises the `SIGTRAP` that [`trace`] itself depends on
    /// for its own first wait, so this has to actually exec something - `/bin/true`,
    /// since shipping a private helper binary just for this check is a later phase's
    /// job. A [`WaitStatus::Stopped`] here is the proof; anything else means `ptrace` did
    /// not work end to end, whether because it was denied or for some other reason.
    ///
    /// Later phases lean on this without running a package at all: `pm-trace` checks it
    /// before tracing anything, and the daemon uses it to decide whether to advertise an
    /// `audit` feature in the first place.
    ///
    /// # Errors
    ///
    /// A diagnostic if `fork` itself fails, or if the probe child never reached a traced
    /// stop - most often because `/proc/sys/kernel/yama/ptrace_scope` or an LSM policy
    /// refused `ptrace::traceme()`, which is why that is the one case with a `help`.
    pub fn preflight() -> Result<()> {
        let _tracer = TRACER.lock().unwrap_or_else(PoisonError::into_inner);

        // SAFETY: the child branch touches nothing but `traceme` and `execve`, both
        // async-signal-safe, before `_exit`.
        match unsafe { fork() }
            .into_diagnostic()
            .wrap_err("fork for the ptrace preflight check")?
        {
            ForkResult::Child => {
                if ptrace::traceme().is_err() {
                    // SAFETY: `_exit` is async-signal-safe and does not unwind.
                    unsafe { libc::_exit(1) }
                }
                let program = c"/bin/true";
                let argv = [program];
                let envp: [&std::ffi::CStr; 0] = [];
                let _ = execve(program, &argv, &envp);
                // SAFETY: `_exit` is async-signal-safe and does not unwind.
                unsafe { libc::_exit(1) }
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None)
                    .into_diagnostic()
                    .wrap_err("waiting for the ptrace preflight probe")?;
                match status {
                    WaitStatus::Stopped(..) => {
                        // Alive, traced and stopped right after `execve` - ptrace works
                        // end to end. There is no further use for it; kill and reap it
                        // the same defensive way `drain` does for a stopped tracee.
                        let _ = ptrace::kill(child);
                        let _ = ptrace::cont(child, Signal::SIGKILL);
                        let _ = waitpid(child, None);
                        Ok(())
                    }
                    // Exited or Signaled are both terminal: the single `waitpid` above
                    // already reaped the probe, so there is nothing left to clean up.
                    _ => Err(miette!(
                        help = ChildFailure::PTRACE_DENIED_HELP,
                        "ptrace preflight failed: the probe never reached a traced stop \
                         ({status:?})"
                    )),
                }
            }
        }
    }

    /// The child half of [`trace`]: become a process group leader, ask to be traced and
    /// exec. Never returns - every failure path writes to `failure_pipe` and then
    /// `_exit`s, because returning would leave a duplicate of the tracer running.
    fn child(
        program: &CString,
        argv: &[CString],
        envp: &[CString],
        working_dir: Option<&std::ffi::CStr>,
        failure_pipe: RawFd,
    ) -> ! {
        // Own process group, so the timeout can kill the whole tree with one killpg.
        if let Err(errno) = setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
            fail(
                failure_pipe,
                ChildFailure::WIRE_SETPGID,
                errno_to_wire(errno),
            );
        }
        if let Some(dir) = working_dir {
            // SAFETY: `dir` is a live NUL-terminated string; `chdir` is async-signal-safe.
            // `nix::unistd::chdir` would need the crate's `fs` feature, which is not on.
            if unsafe { libc::chdir(dir.as_ptr()) } != 0 {
                fail(
                    failure_pipe,
                    ChildFailure::WIRE_CHDIR,
                    errno_to_wire(Errno::last()),
                );
            }
        }
        if let Err(errno) = ptrace::traceme() {
            fail(
                failure_pipe,
                ChildFailure::WIRE_TRACEME,
                errno_to_wire(errno),
            );
        }
        match execve(program, argv, envp) {
            // `execve` has no successful return - the image it names is running instead
            // of this one - so `Infallible` has no value to match here.
            Ok(never) => match never {},
            Err(errno) => fail(
                failure_pipe,
                ChildFailure::WIRE_EXECVE,
                errno_to_wire(errno),
            ),
        }
    }

    /// A future `nix` that changes `Errno`'s size would silently change what
    /// `errno_to_wire` puts on the wire; this fails the build instead, the moment that
    /// version is compiled against.
    const _: () = assert!(size_of::<Errno>() == size_of::<i32>());

    /// The raw errno [`fail`] puts on the wire, as a plain discriminant read rather than
    /// a bit-reinterpretation - sound only because `nix` declares `Errno` `#[repr(i32)]`,
    /// which is what keeps this allocation-free and safe to call between `fork` and
    /// `execve`. Re-check this on a `nix` upgrade; the `const` assertion above catches a
    /// size change but not a repr change that keeps the same size.
    fn errno_to_wire(errno: Errno) -> i32 {
        errno as i32
    }

    /// Write one discriminant byte and the raw `errno` to the CLOEXEC failure pipe, then
    /// `_exit(127)`.
    ///
    /// This is exactly how `std::process` reports a pre-exec failure back to its parent,
    /// and for the same reason: `write` is async-signal-safe and `child`'s `-> !` return
    /// type requires everything on its failure paths to be. The exit code stays 127 on
    /// every path - a distinct code per failure would collide with a tracee that
    /// genuinely exits 127 or 126 on its own, and `supervise` would have no way to tell
    /// a denied `traceme` from a program that just happens to exit 127.
    fn fail(write_fd: RawFd, kind: u8, errno: i32) -> ! {
        let mut message = [0_u8; ChildFailure::WIRE_LEN];
        message[0] = kind;
        message[1..].copy_from_slice(&errno.to_ne_bytes());

        // SAFETY: `write_fd` is the write end of the pipe `trace` created for this
        // child and is still open; `BorrowedFd` here does not take ownership or close
        // it, which matters because this fd must remain valid across the retry loop.
        let write_fd = unsafe { BorrowedFd::borrow_raw(write_fd) };
        let mut sent = 0_usize;
        while sent < message.len() {
            match nix::unistd::write(write_fd, &message[sent..]) {
                Ok(0) | Err(_) => break, // best effort: nothing more to do before _exit.
                Ok(n) => sent += n,
            }
        }
        // SAFETY: `_exit` is async-signal-safe and does not unwind.
        unsafe { libc::_exit(127) }
    }

    /// Read whatever [`fail`] left in the child-failure pipe, once the tracee has
    /// already exited.
    ///
    /// `Ok(None)` is a clean EOF: nothing was ever written, because a successful
    /// `execve` closed the write end via `O_CLOEXEC` before the tracee went on to exit
    /// entirely on its own. Any other outcome - a full wire-format message, or a
    /// malformed one - is surfaced rather than folded back into "clean", which is the
    /// one behaviour this whole pipe exists to rule out.
    fn read_child_failure(read_end: OwnedFd) -> Result<Option<ChildFailure>> {
        let mut file = std::fs::File::from(read_end);
        let mut message = [0_u8; ChildFailure::WIRE_LEN];
        let mut filled = 0_usize;
        loop {
            match file.read(&mut message[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(error)
                        .into_diagnostic()
                        .wrap_err("reading the child-failure pipe");
                }
            }
            if filled == message.len() {
                break;
            }
        }
        match filled {
            0 => Ok(None),
            n if n == ChildFailure::WIRE_LEN => {
                let errno = i32::from_ne_bytes([message[1], message[2], message[3], message[4]]);
                ChildFailure::from_wire(message[0], errno)
                    .map(Some)
                    .ok_or_else(|| {
                        miette!(
                            "the child-failure pipe named an unknown failure kind {}",
                            message[0]
                        )
                    })
            }
            n => Err(miette!(
                "the child-failure pipe delivered {n} of {} expected bytes",
                ChildFailure::WIRE_LEN
            )),
        }
    }

    /// The tracer loop: step every tracee through its syscalls until they all exit or
    /// the timeout fires.
    ///
    /// `failure_read` is the read end of the pipe [`child`] reports a pre-exec failure
    /// through. It is only ever consulted once, on the very first wait: past that first
    /// stop the tracee has already exec'd, so there is nothing left for it to say.
    fn supervise(
        root: Pid,
        program: &Path,
        options: &TraceOptions,
        failure_read: OwnedFd,
    ) -> Result<TraceReport> {
        let deadline = Instant::now() + options.timeout;
        let mut observations: Vec<Observation> = Vec::new();

        // The first stop is the SIGTRAP the kernel raises once our own execve has
        // installed the new image. Until it arrives the tracee has no options set.
        match wait_any(deadline)? {
            Wait::Event(WaitStatus::Exited(_, code)) => {
                // The tracee is dead, so every fd it held is already closed - whatever
                // is sitting in the pipe now is everything there will ever be. Zero
                // bytes means a successful `execve` closed the write end via CLOEXEC
                // before this arrived, i.e. the tracee really did exec and exit on its
                // own. Anything else means `child` never got that far, and reporting
                // this as a clean, empty audit would be exactly the bug this pipe
                // exists to close.
                return match read_child_failure(failure_read)? {
                    None => {
                        warn!(code, "tracee exited before the initial exec trap");
                        Ok(report(observations, false, Some(code)))
                    }
                    Some(failure) => Err(failure.into()),
                };
            }
            Wait::Event(WaitStatus::Stopped(pid, _)) => set_options(pid, options.follow_forks)?,
            Wait::Event(other) => {
                return Err(miette!(
                    "unexpected first wait status from the tracee: {other:?}"
                ));
            }
            Wait::Timeout => {
                kill_group(root);
                drain(root);
                return Ok(report(observations, true, None));
            }
            Wait::NoChildren => {
                return Err(miette!(
                    "the traced child vanished before it could be traced - \
                     was another thread reaping our children?"
                ));
            }
        }

        // Our own execve is not visible as a syscall stop, so record it by hand.
        observations.push(Observation {
            pid: root.as_raw(),
            syscall: "execve",
            permission: Permission::Spawn,
            path_resolved: true,
            succeeded: true,
            granting: true,
        });
        observations.push(Observation {
            pid: root.as_raw(),
            syscall: "execve",
            permission: Permission::ExecPath(program.to_path_buf()),
            path_resolved: true,
            succeeded: true,
            granting: true,
        });

        let mut states: HashMap<Pid, State> = HashMap::new();
        states.insert(root, State::default());
        resume(root);

        let mut exit_status = None;
        let mut timed_out = false;

        while !states.is_empty() {
            let status = match wait_any(deadline)? {
                Wait::Event(status) => status,
                Wait::Timeout => {
                    warn!(
                        timeout_ms = options.timeout.as_millis(),
                        alive = states.len(),
                        "ptrace monitor timed out; killing the traced process group"
                    );
                    timed_out = true;
                    kill_group(root);
                    drain(root);
                    break;
                }
                // Not a timeout: there is simply nobody left to wait for, so the run is
                // over even though a pid we were tracking never reported its exit.
                Wait::NoChildren => {
                    warn!(
                        unreported = states.len(),
                        "every tracee is gone but some never reported an exit"
                    );
                    break;
                }
            };
            match status {
                WaitStatus::StillAlive => std::thread::sleep(IDLE_POLL),
                WaitStatus::Exited(pid, code) => {
                    states.remove(&pid);
                    if pid == root {
                        exit_status = Some(code);
                    }
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    states.remove(&pid);
                    if pid == root {
                        warn!(%signal, "traced program was killed by a signal");
                    }
                }
                WaitStatus::PtraceSyscall(pid) => {
                    let state = states.entry(pid).or_default();
                    syscall_stop(pid, state, &mut observations);
                    resume(pid);
                }
                WaitStatus::PtraceEvent(pid, _, _) => {
                    // A fork/clone event on the parent. The new child announces itself
                    // with its own stop, handled below.
                    states.entry(pid).or_default();
                    resume(pid);
                }
                WaitStatus::Stopped(pid, signal) => {
                    stopped(pid, signal, &mut states, &mut observations);
                }
                WaitStatus::Continued(_) => {}
            }
        }

        debug!(
            observations = observations.len(),
            timed_out, exit_status, "ptrace runtime monitor finished"
        );
        Ok(report(observations, timed_out, exit_status))
    }

    /// Handle a plain signal-delivery stop.
    ///
    /// Three cases hide in here. A pid we have never seen is a child the fork options
    /// just handed us; it is stopped with `SIGSTOP` and starts its life at a syscall
    /// *exit* (the `clone` it was born from). A `SIGTRAP` is the post-`execve` trap - the
    /// only reason `PTRACE_O_TRACESYSGOOD` is set is so that it is distinguishable from a
    /// real syscall stop here, because an `execve` that succeeds never delivers a
    /// syscall-exit stop and would otherwise desynchronise entry/exit pairing for the
    /// rest of the run. Anything else is a real signal and is forwarded to the tracee.
    fn stopped(
        pid: Pid,
        signal: Signal,
        states: &mut HashMap<Pid, State>,
        observations: &mut Vec<Observation>,
    ) {
        let known = states.contains_key(&pid);
        let state = states.entry(pid).or_default();
        if !known {
            trace_log!(pid = pid.as_raw(), "new tracee joined");
            resume(pid);
            return;
        }
        if signal == Signal::SIGTRAP {
            if state.pending_is_exec {
                // The exec landed: the arguments we decoded at entry are now fact.
                for mut observation in state.pending.drain(..) {
                    observation.succeeded = true;
                    observations.push(observation);
                }
                state.pending_is_exec = false;
                state.in_syscall = false;
            }
            resume(pid);
            return;
        }
        if matches!(signal, Signal::SIGSTOP) {
            resume(pid);
            return;
        }
        resume_with(pid, signal);
    }

    /// What came back from a wait.
    ///
    /// "No children left" is deliberately not folded into "timed out". Both end the
    /// loop, but only one of them means the report is a truncated prefix, and
    /// [`TraceReport::timed_out`] would be lying if it could not tell them apart.
    enum Wait {
        /// A tracee changed state.
        Event(WaitStatus),
        /// The budget in [`TraceOptions::timeout`] ran out.
        Timeout,
        /// Every child is gone, whether or not we were still expecting one.
        NoChildren,
    }

    /// Which half of a syscall a `PTRACE_SYSCALL` stop is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Phase {
        /// The arguments are in the registers and the call has not run yet.
        Entry,
        /// The call has run and `rax` holds its result.
        Exit,
    }

    /// Ask the kernel which half of a syscall this stop is.
    ///
    /// `PTRACE_SYSCALL` reports entry and exit identically, so a tracer normally just
    /// alternates - and gets it wrong the moment the sequence is perturbed. It is: a
    /// freshly cloned child's *first* syscall stop is an entry, not the exit of the
    /// `clone` it was born from, and a successful `execve` never delivers a syscall-exit
    /// stop at all. Both were observed here, and an alternating tracer mis-pairs every
    /// syscall afterwards, decoding return values as arguments.
    ///
    /// `PTRACE_GET_SYSCALL_INFO` answers the question outright, so use it and keep the
    /// alternating flag only as a fallback for a kernel too old to have it (< 5.3).
    fn phase(pid: Pid, state: &State) -> Phase {
        match ptrace::syscall_info(pid) {
            Ok(info) if info.op == libc::PTRACE_SYSCALL_INFO_ENTRY => Phase::Entry,
            Ok(info) if info.op == libc::PTRACE_SYSCALL_INFO_EXIT => Phase::Exit,
            _ if state.in_syscall => Phase::Exit,
            _ => Phase::Entry,
        }
    }

    /// Handle one `PTRACE_SYSCALL` stop: decode arguments on entry, judge them on exit.
    fn syscall_stop(pid: Pid, state: &mut State, observations: &mut Vec<Observation>) {
        let Ok(regs) = ptrace::getregs(pid) else {
            trace_log!(
                pid = pid.as_raw(),
                "could not read registers at a syscall stop"
            );
            return;
        };
        if phase(pid, state) == Phase::Exit {
            state.in_syscall = false;
            state.pending_is_exec = false;
            let succeeded = !is_errno(regs.rax);
            for mut observation in state.pending.drain(..) {
                observation.succeeded = succeeded;
                observations.push(observation);
            }
            return;
        }
        state.in_syscall = true;
        // A pending entry still here at the next entry belongs to an `execve` whose
        // post-exec `SIGTRAP` we did not see. Reaching another syscall at all proves the
        // exec worked, so count it rather than losing it.
        if state.pending_is_exec {
            for mut observation in state.pending.drain(..) {
                observation.succeeded = true;
                observations.push(observation);
            }
        }
        state.pending.clear();
        state.pending_is_exec = false;

        #[allow(clippy::cast_possible_wrap)]
        let number = regs.orig_rax as i64;
        let Some(&(_, name, shape)) = TABLE.iter().find(|(nr, _, _)| *nr == number) else {
            return;
        };
        let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        state.pending = decode(pid, name, shape, &args);
        state.pending_is_exec = matches!(shape, Shape::Exec { .. });
    }

    /// Turn one syscall's arguments into the permissions it implies.
    fn decode(pid: Pid, name: &'static str, shape: Shape, args: &[u64; 6]) -> Vec<Observation> {
        let at = |index: u8| args[usize::from(index)];
        let make = |permission: Permission, resolved: bool| Observation {
            pid: pid.as_raw(),
            syscall: name,
            permission,
            path_resolved: resolved,
            succeeded: false,
            granting: true,
        };
        // A metadata probe reads one inode, not a subtree - see [`probe`].
        let probe = |permission: Permission, resolved: bool| Observation {
            granting: !names_a_directory(&permission),
            ..make(permission, resolved)
        };
        match shape {
            Shape::Open { dirfd, path, flags } => {
                let Some((path, resolved)) = path_arg(pid, dirfd.map(at), at(path)) else {
                    return Vec::new();
                };
                vec![make(open_permission(path, at(flags)), resolved)]
            }
            Shape::OpenHow { dirfd, path, how } => {
                let Some((path, resolved)) = path_arg(pid, Some(at(dirfd)), at(path)) else {
                    return Vec::new();
                };
                // struct open_how { __u64 flags, mode, resolve; } - flags come first.
                let flags = read_u64(pid, at(how)).unwrap_or(0);
                vec![make(open_permission(path, flags), resolved)]
            }
            Shape::Read { dirfd, path } => path_arg(pid, dirfd.map(at), at(path))
                .map(|(path, resolved)| vec![probe(Permission::ReadPath(path), resolved)])
                .unwrap_or_default(),
            Shape::Write { dirfd, path } => path_arg(pid, dirfd.map(at), at(path))
                .map(|(path, resolved)| vec![make(Permission::WritePath(path), resolved)])
                .unwrap_or_default(),
            Shape::Rename {
                old_dirfd,
                old_path,
                new_dirfd,
                new_path,
            } => [
                path_arg(pid, old_dirfd.map(at), at(old_path)),
                path_arg(pid, new_dirfd.map(at), at(new_path)),
            ]
            .into_iter()
            .flatten()
            .map(|(path, resolved)| make(Permission::WritePath(path), resolved))
            .collect(),
            Shape::Exec { dirfd, path } => {
                let mut out = vec![make(Permission::Spawn, true)];
                if let Some((path, resolved)) = path_arg(pid, dirfd.map(at), at(path)) {
                    out.push(make(Permission::ExecPath(path), resolved));
                }
                out
            }
            Shape::Spawn => vec![make(Permission::Spawn, true)],
            Shape::SocketDomain { domain } => {
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let family = at(domain) as u32 as i32;
                if is_inet(family) {
                    vec![make(Permission::Network, true)]
                } else {
                    Vec::new()
                }
            }
            Shape::SockAddr { addr, len, binds } => sockaddr(pid, at(addr), at(len))
                .map(|family| match family {
                    // AF_INET/AF_INET6 is the network. AF_UNIX is NOT: it is a path on
                    // the filesystem, and folding it into Network would silently hand
                    // every package that talks to a local daemon a network grant.
                    Family::Inet => vec![make(Permission::Network, true)],
                    Family::Unix(path) if binds => {
                        vec![make(Permission::WritePath(path), true)]
                    }
                    Family::Unix(path) => vec![make(Permission::ReadPath(path), true)],
                    Family::Other => Vec::new(),
                })
                .unwrap_or_default(),
        }
    }

    /// Whether a permission names a path that is a directory on this machine.
    ///
    /// Used to stop a metadata probe from granting a subtree. It is a question about the
    /// tracing host, asked while the tracee is stopped mid-syscall, so it is as accurate
    /// as anything else the monitor records; a path that does not exist or cannot be
    /// stat'd counts as "not a directory" and keeps its grant.
    fn names_a_directory(permission: &Permission) -> bool {
        permission
            .path()
            .and_then(|path| std::fs::metadata(path).ok())
            .is_some_and(|metadata| metadata.is_dir())
    }

    /// `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` or `O_APPEND` make an open a write;
    /// anything else is a read.
    fn open_permission(path: PathBuf, flags: u64) -> Permission {
        #[allow(clippy::cast_sign_loss)]
        let writing = {
            let access = flags & libc::O_ACCMODE as u64;
            access == libc::O_WRONLY as u64
                || access == libc::O_RDWR as u64
                || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u64 != 0
        };
        if writing {
            Permission::WritePath(path)
        } else {
            Permission::ReadPath(path)
        }
    }

    /// The address family behind a `sockaddr`, with the `AF_UNIX` path already extracted.
    enum Family {
        /// `AF_INET` or `AF_INET6`: this is the network.
        Inet,
        /// `AF_UNIX`: a filesystem path, not the network.
        Unix(PathBuf),
        /// Anything else - netlink, packet, bluetooth - which we do not model.
        Other,
    }

    /// Read a `sockaddr` out of the tracee and classify it.
    fn sockaddr(pid: Pid, addr: u64, len: u64) -> Option<Family> {
        if addr == 0 || len < 2 {
            return None;
        }
        let want = usize::try_from(len).unwrap_or(2).min(2 + PATH_MAX);
        let bytes = read_bytes(pid, addr, want)?;
        let family = i32::from(u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]));
        if is_inet(family) {
            return Some(Family::Inet);
        }
        if family != libc::AF_UNIX {
            return Some(Family::Other);
        }
        let sun_path = bytes.get(2..)?;
        // An abstract socket starts with a NUL and has no filesystem path at all.
        if sun_path.first() == Some(&0) || sun_path.is_empty() {
            return Some(Family::Other);
        }
        let end = sun_path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(sun_path.len());
        Some(Family::Unix(PathBuf::from(OsString::from_vec(
            sun_path[..end].to_vec(),
        ))))
    }

    /// Whether an address family is the actual network.
    fn is_inet(family: i32) -> bool {
        family == libc::AF_INET || family == libc::AF_INET6
    }

    /// Whether a syscall return value is a negated errno rather than a result.
    ///
    /// The kernel returns errors in `[-4095, -1]`; every other value is success, which
    /// matters for the syscalls that legitimately return large unsigned-looking numbers.
    fn is_errno(rax: u64) -> bool {
        #[allow(clippy::cast_possible_wrap)]
        let value = rax as i64;
        (-4095..0).contains(&value)
    }

    /// Read a path argument and make it absolute if we honestly can.
    ///
    /// Returns the path and whether it is resolved. An absolute path needs no work. A
    /// relative one is joined onto the directory its `dirfd` names, read out of
    /// `/proc/<pid>/cwd` for `AT_FDCWD` or `/proc/<pid>/fd/<n>` otherwise - both readable
    /// because the tracee is stopped in a syscall right now. If that readlink fails the
    /// path is returned **verbatim** with `resolved` false rather than guessed at.
    fn path_arg(pid: Pid, dirfd: Option<u64>, addr: u64) -> Option<(PathBuf, bool)> {
        let path = read_path(pid, addr)?;
        if path.is_absolute() {
            return Some((path, true));
        }
        // `execveat`/`openat` with an empty path and AT_EMPTY_PATH means "the fd itself".
        let base = match dirfd {
            None => proc_link(pid, "cwd"),
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            Some(fd) if fd as u32 as i32 == libc::AT_FDCWD => proc_link(pid, "cwd"),
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            Some(fd) => proc_link(pid, &format!("fd/{}", fd as u32 as i32)),
        };
        match base {
            Some(base) if path.as_os_str().is_empty() => Some((base, true)),
            Some(base) => Some((base.join(&path), true)),
            None => Some((path, false)),
        }
    }

    /// Read one of the tracee's `/proc` symlinks.
    fn proc_link(pid: Pid, what: &str) -> Option<PathBuf> {
        let link = format!("/proc/{}/{what}", pid.as_raw());
        let target = std::fs::read_link(link).ok()?;
        // Sockets and pipes read back as "socket:[12345]", which is not a directory.
        target.is_absolute().then_some(target)
    }

    /// Copy a NUL-terminated path out of the tracee, capped at `PATH_MAX`.
    ///
    /// A null pointer, an unreadable address or a string with no terminator inside
    /// `PATH_MAX` all yield `None` instead of a panic.
    fn read_path(pid: Pid, addr: u64) -> Option<PathBuf> {
        if addr == 0 {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(64);
        let mut cursor = addr;
        while out.len() < PATH_MAX {
            // Never cross a page boundary in one read: the next page may be unmapped,
            // and a single oversized read would fail outright instead of returning the
            // bytes that *are* there.
            let page = 4096 - (cursor % 4096);
            let want = page.min((PATH_MAX - out.len()) as u64).min(256);
            let want = usize::try_from(want).ok()?;
            let chunk = read_bytes(pid, cursor, want)?;
            if chunk.is_empty() {
                return None;
            }
            if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
                out.extend_from_slice(&chunk[..end]);
                return Some(PathBuf::from(OsString::from_vec(out)));
            }
            out.extend_from_slice(&chunk);
            cursor += chunk.len() as u64;
        }
        None
    }

    /// Read a little-endian `u64` out of the tracee.
    fn read_u64(pid: Pid, addr: u64) -> Option<u64> {
        let bytes = read_bytes(pid, addr, 8)?;
        Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?))
    }

    /// Copy `len` bytes out of the tracee's address space.
    ///
    /// `process_vm_readv` is the cheap path - one syscall for the whole buffer. When it
    /// is unavailable or refuses (a hardened kernel, a partially mapped range) this falls
    /// back to word-at-a-time `PTRACE_PEEKDATA`, which reaches anything ptrace itself
    /// can. A short read is returned as-is; an unreadable first word gives `None`.
    fn read_bytes(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let mut buffer = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: usize::try_from(addr).ok()? as *mut libc::c_void,
            iov_len: len,
        };
        // SAFETY: both iovecs describe live, correctly sized buffers; the remote one is
        // only ever dereferenced by the kernel, which validates it and returns EFAULT.
        let read = unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) };
        if read > 0 {
            buffer.truncate(usize::try_from(read).ok()?);
            return Some(buffer);
        }
        peek_bytes(pid, addr, len)
    }

    /// `PTRACE_PEEKDATA` fallback for [`read_bytes`], a machine word at a time.
    fn peek_bytes(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
        let word = size_of::<libc::c_long>();
        let mut out: Vec<u8> = Vec::with_capacity(len);
        while out.len() < len {
            let at = addr.checked_add(out.len() as u64)?;
            let value = match ptrace::read(pid, usize::try_from(at).ok()? as ptrace::AddressType) {
                Ok(value) => value,
                Err(Errno::EFAULT | Errno::EIO) if !out.is_empty() => break,
                Err(_) => return None,
            };
            let take = word.min(len - out.len());
            out.extend_from_slice(&value.to_ne_bytes()[..take]);
        }
        Some(out)
    }

    /// Turn a byte string into a `CString`, rejecting an interior NUL with a diagnostic
    /// rather than truncating silently.
    fn cstring(bytes: &[u8]) -> Result<CString> {
        CString::new(bytes)
            .into_diagnostic()
            .wrap_err("cannot pass a string containing a NUL byte to the traced program")
    }

    /// Ask the kernel for distinguishable syscall stops, child tracing and a dead-man
    /// switch that kills the tracees if we die.
    fn set_options(pid: Pid, follow_forks: bool) -> Result<()> {
        let mut options =
            ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL;
        if follow_forks {
            options |= ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE;
        }
        ptrace::setoptions(pid, options)
            .into_diagnostic()
            .wrap_err("could not set ptrace options on the tracee")
    }

    /// Let a tracee run to its next syscall stop. A tracee that died between the stop and
    /// here is not an error worth failing the whole trace over.
    fn resume(pid: Pid) {
        if let Err(errno) = ptrace::syscall(pid, None) {
            trace_log!(pid = pid.as_raw(), %errno, "could not resume tracee");
        }
    }

    /// Resume a tracee, delivering the signal that stopped it.
    fn resume_with(pid: Pid, signal: Signal) {
        if let Err(errno) = ptrace::syscall(pid, signal) {
            trace_log!(pid = pid.as_raw(), %errno, "could not resume tracee with signal");
        }
    }

    /// Wait for any tracee, returning `None` once `deadline` has passed.
    ///
    /// `WNOHANG` plus a short sleep is what makes the timeout real: a blocking `waitpid`
    /// on a tracee that sleeps forever would hang the build, which is worse than having
    /// no monitor at all.
    fn wait_any(deadline: Instant) -> Result<Wait> {
        let flags = WaitPidFlag::WNOHANG | WaitPidFlag::__WALL;
        loop {
            if Instant::now() >= deadline {
                return Ok(Wait::Timeout);
            }
            match waitpid(Pid::from_raw(-1), Some(flags)) {
                Ok(WaitStatus::StillAlive) => std::thread::sleep(IDLE_POLL),
                Ok(status) => return Ok(Wait::Event(status)),
                Err(Errno::EINTR) => {}
                Err(Errno::ECHILD) => return Ok(Wait::NoChildren),
                Err(errno) => {
                    return Err(miette!("waitpid failed while tracing: {errno}"));
                }
            }
        }
    }

    /// Kill the traced process group, and the leader directly in case it never managed
    /// its own `setpgid`.
    fn kill_group(root: Pid) {
        let _ = nix::sys::signal::killpg(root, Signal::SIGKILL);
        let _ = nix::sys::signal::kill(root, Signal::SIGKILL);
    }

    /// Reap everything left after a kill so the tracer leaves no zombies behind.
    fn drain(root: Pid) {
        let until = Instant::now() + REAP_BUDGET;
        let flags = WaitPidFlag::WNOHANG | WaitPidFlag::__WALL;
        while Instant::now() < until {
            match waitpid(Pid::from_raw(-1), Some(flags)) {
                Ok(WaitStatus::StillAlive) => std::thread::sleep(IDLE_POLL),
                // A tracee stopped in ptrace-stop has to be resumed to notice the SIGKILL.
                Ok(status) => {
                    if let Some(pid) = status.pid()
                        && matches!(
                            status,
                            WaitStatus::Stopped(..)
                                | WaitStatus::PtraceSyscall(_)
                                | WaitStatus::PtraceEvent(..)
                        )
                    {
                        let _ = ptrace::kill(pid);
                        let _ = ptrace::cont(pid, Signal::SIGKILL);
                    }
                }
                Err(Errno::EINTR) => {}
                Err(_) => return,
            }
        }
        warn!(
            root = root.as_raw(),
            "gave up reaping the traced process group"
        );
    }
}
