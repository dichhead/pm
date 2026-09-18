//! Integration tests for `pm-trace`, the one-shot ptrace monitor process.
//!
//! Every test runs the real compiled binary end to end. `ptrace` binds a tracer to the
//! thread that forked its tracee, so `monitor::trace` cannot meaningfully be exercised
//! any other way here - see the module doc on `src/bin/pm-trace.rs` for why the binary
//! exists as a whole process at all.

use std::fs::{Permissions, read_dir, read_to_string, set_permissions, write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_yaml::Value;
use tempfile::tempdir;

/// A `Command` for the compiled `pm-trace` binary, provided by Cargo for integration
/// tests under this exact environment variable name.
fn pm_trace() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pm-trace"))
}

/// Parse `path` as YAML into a generic [`Value`].
///
/// The real `TraceReport` only derives `Serialize` (see `src/perms/monitor.rs`), so
/// assertions here go through a generic YAML value rather than deserialising back into
/// that type.
fn read_report(path: &Path) -> Value {
    let text = read_to_string(path).expect("read the trace report");
    serde_yaml::from_str(&text).expect("parse the trace report as YAML")
}

#[test]
fn missing_required_arguments_exit_with_claps_own_code() {
    let status = pm_trace().status().expect("run pm-trace");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn tracing_a_real_program_exits_zero_prints_its_output_and_records_an_openat() {
    let dir = tempdir().expect("temp dir");
    let report_path = dir.path().join("report.yaml");

    let output = pm_trace()
        .arg("--report")
        .arg(&report_path)
        .args(["--", "/bin/echo", "hi"])
        .output()
        .expect("run pm-trace");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim_end(), "hi");

    let report = read_report(&report_path);
    let observations = report["observations"]
        .as_sequence()
        .expect("observations is a list");
    assert!(!observations.is_empty(), "expected at least one observation");
    assert!(
        observations
            .iter()
            .any(|observation| observation["syscall"].as_str() == Some("openat")),
        "expected at least one openat observation, got {observations:?}"
    );
}

#[test]
fn an_unexecutable_program_exits_with_the_execve_code() {
    let dir = tempdir().expect("temp dir");
    let report_path = dir.path().join("report.yaml");

    let status = pm_trace()
        .arg("--report")
        .arg(&report_path)
        .args(["--", "/definitely/not/here"])
        .status()
        .expect("run pm-trace");

    let code = status.code().expect("exited normally, not on a signal");
    assert_ne!(code, 0, "a missing program must not look like success");
    assert_ne!(
        code, 127,
        "a missing program must not be confused with a tracee that itself exited 127"
    );
    assert_eq!(code, 4);
}

#[test]
fn a_missing_working_dir_exits_with_the_child_setup_code() {
    let dir = tempdir().expect("temp dir");
    let report_path = dir.path().join("report.yaml");

    let status = pm_trace()
        .arg("--report")
        .arg(&report_path)
        .args(["--working-dir", "/definitely/not/here"])
        .args(["--", "/bin/echo", "hi"])
        .status()
        .expect("run pm-trace");

    assert_eq!(status.code(), Some(6));
}

#[test]
fn a_timeout_kills_the_group_and_writes_a_timed_out_report() {
    let dir = tempdir().expect("temp dir");
    let report_path = dir.path().join("report.yaml");

    let start = Instant::now();
    let status = pm_trace()
        .arg("--report")
        .arg(&report_path)
        .args(["--timeout-secs", "1"])
        .args(["--", "/bin/sleep", "30"])
        .status()
        .expect("run pm-trace");
    let elapsed = start.elapsed();

    assert_eq!(status.code(), Some(3));
    // The 1s timeout is followed by a further 2s reap budget; this generously allows
    // for both plus scheduling noise without turning a slow CI box into a flake.
    assert!(
        elapsed < Duration::from_secs(10),
        "timeout handling took too long: {elapsed:?}"
    );

    let report = read_report(&report_path);
    assert_eq!(report["timed_out"].as_bool(), Some(true));
}

/// Prove the report is written by renaming a temporary file into place, not by
/// truncating and overwriting the target in place.
///
/// Reading the implementation is not proof - a comment can say "atomic" and still be
/// wrong - so this instead makes the two strategies behave differently and observes
/// which one actually happened. A file is seeded at the report path and then stripped
/// of every permission bit. Opening *that inode* for writing, which is what an in-place
/// `File::create` would have to do, fails with `EACCES` even for its own owner.
/// `rename(2)` does not open the old target at all: it replaces the directory entry
/// wholesale and only cares about the containing directory's permissions. So if
/// `pm-trace` still succeeds here and the file at the path is a genuine report
/// afterwards, the write can only have gone through a temporary file that was then
/// renamed over the locked-down original - the same atomic swap that guarantees a
/// concurrent reader never observes a half-written report. The directory listing at the
/// end further confirms the swap left no temporary sibling behind.
#[test]
fn the_report_replaces_a_permission_locked_target_by_rename_not_in_place_write() {
    let dir = tempdir().expect("temp dir");
    let report_path = dir.path().join("report.yaml");

    write(&report_path, "sentinel: old-content-that-must-not-survive\n")
        .expect("seed the target with old content");
    set_permissions(&report_path, Permissions::from_mode(0o000))
        .expect("lock down the pre-existing target");

    let output = pm_trace()
        .arg("--report")
        .arg(&report_path)
        .args(["--", "/bin/echo", "hi"])
        .output()
        .expect("run pm-trace");

    assert_eq!(
        output.status.code(),
        Some(0),
        "an in-place write would have failed on the locked-down target; a rename \
         would not have. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_report(&report_path);
    assert!(
        report.get("observations").is_some(),
        "the file at the target path was not replaced with a real report: {report:?}"
    );

    let leftover: Vec<_> = read_dir(dir.path())
        .expect("list the report directory")
        .map(|entry| entry.expect("directory entry").file_name())
        .filter(|name| name != report_path.file_name().expect("report has a file name"))
        .collect();
    assert!(
        leftover.is_empty(),
        "a temporary file was left behind after the rename: {leftover:?}"
    );
}
