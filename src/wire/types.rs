//! Structs that travel as D-Bus method arguments and replies.
//!
//! Every type here mirrors something that already exists on this side of the
//! process boundary, flattened into what `zvariant` can encode: no borrowed
//! data, no `Instant` (meaningless the moment it is read back in another
//! process), no `&'static str` pointing at a table that only exists here.
//! `tests/wire.rs` asserts each `SIGNATURE` below as a string literal, so a
//! field reorder is a test failure long before it is a mis-decoded message.
//!
//! Derive order matters for nothing here except readability - it is field
//! order, not derive order, that fixes the signature. Do not reorder a
//! struct's fields to chase a signature string; if the macro disagrees with
//! what was predicted, the macro is right.

use serde::{Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};

/// The paths and identity a client's request carries into the daemon.
///
/// The daemon is a long-lived service with no controlling terminal and no
/// `$PWD` of its own that means anything to a build - every path a build
/// needs has to arrive explicitly with the request instead of being read out
/// of the daemon's own environment, which belongs to whichever client
/// happened to start it first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct CallerContext {
    /// The client's working directory, for build files given as relative paths.
    pub cwd: String,
    /// Where built archives are written.
    pub output_dir: String,
    /// Where trusted signing keys are read from.
    pub trust_dir: String,
    /// The client's `$PATH`, for resolving toolchain programs the same way
    /// the client's own shell would.
    pub path: String,
    /// The client's `$HOME`, for build systems that insist on one existing.
    pub home: String,
}

/// A build failure, flattened for a client with no shared address space to
/// read a `miette::Report` out of.
///
/// Construct one with `From<&miette::Report>` (see [`crate::wire::error`]),
/// which is the only place raw, untrusted command output is sanitised before
/// it can reach a field here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Diagnostic {
    /// A short diagnostic code, e.g. one of the `org.pm1.Error.*` constants.
    pub name: String,
    /// The top-level failure message.
    pub message: String,
    /// A hint for the user, empty when the underlying error offered none.
    pub help: String,
    /// The error's source chain, outermost first, not counting `message`
    /// itself.
    pub causes: Vec<String>,
}

/// One line of a [`crate::progress::Progress`] tree, flattened for polling.
///
/// A daemon has no terminal to redraw and no client watching every
/// `set_message`/`set_bytes` call - `set_bytes` alone fires once per 64 KiB
/// of a download - so instead of one event per update, a client polls
/// [`crate::progress::Progress::nodes`] on its own schedule and diffs the
/// tree against what it saw last time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ProgressNode {
    /// This node's id. Never 0 - 0 is reserved for "no parent" in
    /// [`ProgressNode::parent`], so ids start at 1.
    pub id: u32,
    /// The id of the node this one is nested under, or 0 for a top-level
    /// node.
    pub parent: u32,
    /// How many levels of nesting this node sits under its top-level
    /// ancestor.
    pub depth: u32,
    /// What the node is doing, e.g. a package or command name.
    pub label: String,
    /// 0 = silent (nothing reported yet), 1 = message, 2 = a byte transfer.
    pub kind: u8,
    /// The last message reported, for `kind == 1`. Empty otherwise.
    pub text: String,
    /// Bytes transferred so far, for `kind == 2`. 0 otherwise.
    pub done: u64,
    /// The declared size of the transfer, for `kind == 2`. 0 means unknown,
    /// same as it does when there is no transfer at all.
    pub total: u64,
    /// When this node was opened, in `CLOCK_REALTIME` microseconds. Not an
    /// `Instant`: an `Instant` recorded in this process cannot be compared to
    /// anything read back in a client's own process.
    pub started_usec: u64,
}

/// One line of build output, or a `tracing` record, for a client watching a
/// job live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct LogLine {
    /// Monotonically increasing within one job, so a client can tell it
    /// received every line in order and none twice.
    pub seq: u64,
    /// 0 = stdout, 1 = stderr, 2 = a `tracing` record.
    pub stream: u8,
    /// The line's text.
    pub text: String,
}

/// One row of a job listing: everything a client needs to show a job without
/// opening it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct JobRow {
    /// The object path this job is reachable at over D-Bus.
    pub path: OwnedObjectPath,
    /// The job's own identifier, independent of its object path.
    pub id: String,
    /// What kind of job this is, e.g. "build" or "run".
    pub kind: String,
    /// The job's current state, e.g. "running", "done" or "failed".
    pub state: String,
    /// What the job is building or running, e.g. a package name.
    pub subject: String,
    /// When the job started, in `CLOCK_REALTIME` microseconds.
    pub created_usec: i64,
    /// When the job finished, in `CLOCK_REALTIME` microseconds; 0 while it is
    /// still running.
    pub finished_usec: i64,
    /// The job's exit code. Meaningless (0) while the job is still running.
    pub exit_code: i32,
}

/// One traced syscall, flattened for a client with no access to the
/// daemon's `Permission` enum or its `&'static str` syscall-name table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Observation {
    /// The syscall's name, e.g. `openat`. Owned: the in-process
    /// `Observation` this is built from returns `&'static str` pointing at a
    /// table that lives only in the daemon.
    pub syscall: String,
    /// The thread that made the call.
    pub pid: i32,
    /// The kind of permission this call implies, e.g. `read` or `network`.
    pub permission: String,
    /// A short, stable label for `permission`, safe to match on.
    pub label: String,
    /// The path this call names, or empty for a pathless permission.
    pub path: String,
    /// Whether a relative path was successfully resolved against its `dirfd`.
    pub resolved: bool,
    /// Whether the syscall returned success.
    pub succeeded: bool,
    /// A human-readable justification, e.g. a locator plus a reason.
    pub evidence: String,
}

/// The result of building one package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct PackageOutcome {
    /// The package's name.
    pub name: String,
    /// What happened, e.g. "built", "failed" or "skipped".
    pub outcome: String,
    /// The path to the produced archive, empty when none was produced.
    pub archive: String,
    /// Why the package failed, empty on success.
    pub error: String,
}
