//! `pm-trace`: a single-purpose process whose entire job is one `monitor::trace` call.
//!
//! # Why a whole process, and not a thread or a plain function call
//!
//! `monitor::supervise`'s tracer loop waits with `waitpid(-1)`, which reaps *any* child
//! of this process - a tracee's own forked children are not knowable by pid until their
//! first stop, so there is no narrower wait that would work. A caller that spawns its
//! own children concurrently - a daemon running sandboxed containers and `tar` - would
//! have them silently reaped out from under it if a trace ran inline on one of its
//! threads. Living in a separate process makes that impossible instead of merely
//! disciplined.
//!
//! There is a second, independent reason. Attachment goes through `PTRACE_TRACEME`
//! only, and Linux binds the tracer identity to the *thread* that the tracee attached
//! to. `monitor::trace` therefore has to run inline on the very thread that forked the
//! child, which an event loop cannot promise about any of its workers. A dedicated
//! process sidesteps the question entirely.
//!
//! # Where the report goes, and why not stdout
//!
//! The traced program's own stdout and stderr are inherited untouched, so its output -
//! and this binary's own `tracing` lines - land wherever the caller pointed them. The
//! `TraceReport` itself goes to the file named by `--report`, written atomically (see
//! [`write_report_atomically`]), never to stdout: observations are emitted one per
//! *permission* rather than per syscall, so a thorough audit produces thousands of them,
//! comfortably past a pipe's buffer. A parent that read the report from a pipe instead
//! of a file would deadlock the moment the child filled that buffer while the parent was
//! still blocked in `wait` - a bug that only shows up under load. The caller waits on
//! one pid and then reads the file.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::Parser;
use miette::{IntoDiagnostic as _, WrapErr as _};
use pm::perms::monitor::{self, ChildFailure, TraceOptions, TraceReport};
use tracing::{debug, error, info};
use tracing_subscriber::fmt;

/// Traced to completion; the report was written. Also the exit code when the traced
/// program itself exited non-zero - that is reported through the file's `exit_status`,
/// not through this process's own exit code.
const EXIT_OK: u8 = 0;

/// `TraceOptions::timeout` fired. The report is still written, with `timed_out: true`.
const EXIT_TIMED_OUT: u8 = 3;

/// `ChildFailure::Execve`: the program named on the command line could not be executed.
const EXIT_EXECVE_FAILED: u8 = 4;

/// `ChildFailure::Traceme`: `ptrace` was denied.
const EXIT_TRACEME_DENIED: u8 = 5;

/// `ChildFailure::Chdir` or `ChildFailure::SetPgid`: the child could not finish its own
/// setup before asking to be traced.
const EXIT_CHILD_SETUP_FAILED: u8 = 6;

/// `monitor::preflight` failed - including simply not running on x86_64.
const EXIT_PREFLIGHT_FAILED: u8 = 7;

/// The trace ran to completion but its report could not be serialised or written.
const EXIT_REPORT_WRITE_FAILED: u8 = 8;

/// Catch-all for a `monitor::trace` failure that is not one of the four
/// [`ChildFailure`] variants: `fork` itself failing, an interior NUL in an argument, or
/// an internal invariant violation such as an unexpected wait status. None of these are
/// named in the exit-code contract because they are not expected to happen in practice;
/// 1 is the one code the contract leaves unclaimed, so it is what is left for them.
const EXIT_INTERNAL_FAILURE: u8 = 1;

/// Trace one program under `ptrace` and write what it touched to a report file.
///
/// Runs `monitor::preflight` first and refuses to trace at all if that fails. Otherwise
/// runs the program to completion or until the timeout fires, then writes the resulting
/// report as YAML to `--report` and exits with a code that says which of those happened.
#[derive(Parser)]
#[clap(name = "pm-trace", version, about = "Trace one program under ptrace and record what it touched")]
struct Args {
    /// Where the trace report is written, as YAML.
    ///
    /// Written atomically: a temporary file is created next to this path and renamed
    /// over it once it is complete, so a reader polling this path never observes a
    /// half-written report.
    #[arg(short, long, value_name = "PATH")]
    report: PathBuf,

    /// Wall-clock budget for the whole traced process group, in seconds.
    ///
    /// When it runs out, the traced process group is killed and the report says
    /// `timed_out: true`. Defaults to the same 30 seconds as the library's own
    /// `TraceOptions::default`.
    #[arg(long, value_name = "N", default_value_t = default_timeout_secs())]
    timeout_secs: u64,

    /// Directory to `chdir` into before executing the program.
    ///
    /// A directory that does not exist, or cannot be entered, fails the trace before the
    /// program ever runs.
    #[arg(long, value_name = "DIR")]
    working_dir: Option<PathBuf>,

    /// Do not follow forked or cloned children; only the top-level program is traced.
    ///
    /// Forks are followed by default, because a build tool that does its real work in a
    /// child process would otherwise be invisible to the monitor.
    #[arg(long)]
    no_follow_forks: bool,

    /// The program to run, and its arguments, given after `--`.
    #[arg(required = true, num_args = 1.., last = true, value_name = "PROGRAM")]
    command: Vec<String>,
}

/// The library's own default timeout, in whole seconds, so `--timeout-secs`'s default
/// cannot silently drift away from it.
fn default_timeout_secs() -> u64 {
    TraceOptions::default().timeout.as_secs()
}

fn main() -> ExitCode {
    fmt().without_time().with_writer(std::io::stderr).init();

    let args = Args::parse();

    debug!(
        report = %args.report.display(),
        timeout_secs = args.timeout_secs,
        follow_forks = !args.no_follow_forks,
        "pm-trace starting"
    );

    if let Err(diagnostic) = monitor::preflight() {
        print_fatal(&diagnostic);
        return ExitCode::from(EXIT_PREFLIGHT_FAILED);
    }

    let options = TraceOptions {
        timeout: Duration::from_secs(args.timeout_secs),
        working_dir: args.working_dir.clone(),
        follow_forks: !args.no_follow_forks,
        ..TraceOptions::default()
    };

    // `command` is `required` and takes at least one value, so clap would already have
    // exited with code 2 before `main` ran at all if it were empty.
    let program = PathBuf::from(&args.command[0]);
    let program_args = &args.command[1..];

    info!(program = %program.display(), args = program_args.len(), "starting trace");

    let report = match monitor::trace(&program, program_args, &options) {
        Ok(report) => report,
        Err(diagnostic) => {
            let code = diagnostic
                .downcast_ref::<ChildFailure>()
                .map_or(EXIT_INTERNAL_FAILURE, exit_code_for_child_failure);
            print_fatal(&diagnostic);
            return ExitCode::from(code);
        }
    };

    if let Err(diagnostic) = write_report_atomically(&args.report, &report) {
        print_fatal(&diagnostic);
        return ExitCode::from(EXIT_REPORT_WRITE_FAILED);
    }

    if report.timed_out() {
        error!(
            report = %args.report.display(),
            "trace timed out; the report describes a killed, incomplete run"
        );
        return ExitCode::from(EXIT_TIMED_OUT);
    }

    info!(
        observations = report.observations().len(),
        exit_status = report.exit_status(),
        report = %args.report.display(),
        "trace finished"
    );
    ExitCode::from(EXIT_OK)
}

/// Print the final diagnostic a user sees before this process exits.
///
/// This is not a log line - it is the same fancy-rendered report `miette` prints
/// automatically for a `main() -> miette::Result<()>`. `pm-trace` cannot use that return
/// type because its exit code depends on *which* failure this is, so the rendering has
/// to happen here instead of at the top of the call stack.
fn print_fatal(diagnostic: &miette::Report) {
    eprintln!("{diagnostic:?}");
}

/// The exit code the CLI contract promises for each way the traced child can die before
/// its own `execve` completes.
fn exit_code_for_child_failure(failure: &ChildFailure) -> u8 {
    match failure {
        ChildFailure::Execve(_) => EXIT_EXECVE_FAILED,
        ChildFailure::Traceme(_) => EXIT_TRACEME_DENIED,
        ChildFailure::Chdir(_) | ChildFailure::SetPgid(_) => EXIT_CHILD_SETUP_FAILED,
    }
}

/// Serialise `report` to YAML and write it to `path`, atomically.
///
/// A real audit emits one observation per *permission* rather than per syscall, so a
/// thorough one produces thousands of them - the YAML can be large enough that writing
/// it in place would leave a window in which a concurrent reader sees a truncated
/// document. A temporary file is created in `path`'s own directory instead - keeping the
/// rename that follows on one filesystem, which is what makes it atomic - and is renamed
/// over `path` only once every byte has been written and flushed. A reader of `path`
/// therefore only ever observes nothing, or the complete report; never something
/// in-between.
///
/// # Errors
///
/// If `report` cannot be serialised to YAML, if a temporary file cannot be created next
/// to `path`, or if writing to or renaming that temporary file fails.
fn write_report_atomically(path: &Path, report: &TraceReport) -> miette::Result<()> {
    let yaml = serde_yaml::to_string(report)
        .into_diagnostic()
        .wrap_err("cannot serialise the trace report to YAML")?;

    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    let mut temp = tempfile::Builder::new()
        .prefix(".pm-trace-report.")
        .suffix(".tmp")
        .tempfile_in(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot create a temporary file in {}", dir.display()))?;

    temp.write_all(yaml.as_bytes())
        .into_diagnostic()
        .wrap_err("cannot write the trace report to its temporary file")?;
    temp.flush()
        .into_diagnostic()
        .wrap_err("cannot flush the trace report to disk")?;

    if let Err(error) = temp.persist(path) {
        return Err(error.error).into_diagnostic().wrap_err_with(|| {
            format!(
                "cannot rename the trace report into place at {}",
                path.display()
            )
        });
    }
    Ok(())
}
