//! RAII guards for the two resources a build owns: the staging directory it
//! writes into, and the sandboxed process it spawns out of that directory.
//!
//! # Drop order
//!
//! A [`SandboxedChild`] executes binaries that live inside a [`Workspace`].
//! Unlinking the workspace while the child is still running yanks the
//! executable, its libraries and its working directory out from under it, so
//! the child MUST be dropped first.
//!
//! Rust drops struct fields in declaration order and local variables in
//! reverse declaration order. Anything holding both therefore has to either
//!
//! - declare the `SandboxedChild` field *before* the `Workspace` field, or
//! - declare the `Workspace` local *before* the `SandboxedChild` local.
//!
//! Both spellings put the kill before the unlink. Getting it backwards is not
//! a compile error, so it is worth a comment at every site that owns the pair.

use std::fs;
use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic};
use tempfile::TempDir;
use tracing::{debug, warn};
use walkdir::WalkDir;

/// A self-deleting staging directory for one build.
///
/// The directory is removed when the guard drops. [`Workspace::keep`] flips
/// that to retaining it, so a build that failed halfway can be inspected
/// afterwards, and [`Workspace::persist`] moves a finished artifact out before
/// the teardown happens.
pub struct Workspace {
    /// `None` only after the guard has already torn down; every accessor
    /// tolerates that so no path can panic.
    dir: Option<TempDir>,
    /// Cached so [`Workspace::path`] stays infallible regardless of `dir`.
    root: PathBuf,
    label: String,
    keep: bool,
}

impl Workspace {
    /// Create a staging workspace under the system temporary directory.
    ///
    /// `label` is used in tracing output only; it is not sanitised into the
    /// directory name beyond being a prefix.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the temporary directory cannot be created, for
    /// example when `TMPDIR` is missing, unwritable or full.
    pub fn new(label: impl Into<String>) -> miette::Result<Self> {
        Self::new_in(None, label)
    }

    /// As [`Workspace::new`], created under `root` instead of the system
    /// temporary directory when `root` is `Some`.
    ///
    /// A build run on a caller's behalf may need its workspace to live
    /// somewhere other than the daemon's own `TMPDIR` - under the caller's own
    /// scratch space, say, so the finished archive's rename onto
    /// `ctx.output_dir` stays on one filesystem instead of falling back to a
    /// cross-device copy. `None` reproduces [`Workspace::new`] exactly.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the temporary directory cannot be created, for
    /// example when the target directory is missing, unwritable or full.
    pub fn new_in(root: Option<&Path>, label: impl Into<String>) -> miette::Result<Self> {
        let label = label.into();
        let prefix = format!("pm-{label}-");
        let dir = match root {
            Some(root) => TempDir::with_prefix_in(&prefix, root),
            None => TempDir::with_prefix(&prefix),
        }
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create a staging workspace for `{label}`"))?;
        let root = dir.path().to_path_buf();
        debug!(label = %label, path = %root.display(), "created workspace");
        Ok(Self {
            dir: Some(dir),
            root,
            label,
            keep: false,
        })
    }

    /// Root of the workspace. Valid for as long as the guard is alive.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Leak the directory on drop instead of deleting it, so a failed build can
    /// be inspected post-mortem. The retained path is logged at warn level when
    /// the guard drops.
    pub fn keep(&mut self) {
        self.keep = true;
    }

    /// Consume the guard, moving `src` (a path inside this workspace) to
    /// `dest`, and return `dest`.
    ///
    /// This is the fallible counterpart to [`Drop`]: use it when the artifact
    /// must outlive the workspace. `dest`'s parent directory is created if it
    /// does not exist. A plain rename is tried first; if it fails — most often
    /// `EXDEV`, because the temporary directory and the destination live on
    /// different filesystems — the contents are copied and the source removed.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if `src` cannot be read, if `dest`'s parent cannot
    /// be created, or if both the rename and the copy fallback fail.
    pub fn persist(self, src: &Path, dest: &Path) -> miette::Result<PathBuf> {
        if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create `{}`", parent.display()))?;
        }

        match fs::rename(src, dest) {
            Ok(()) => {
                debug!(
                    label = %self.label,
                    src = %src.display(),
                    dest = %dest.display(),
                    "renamed artifact out of workspace"
                );
            }
            Err(rename_err) => {
                debug!(
                    src = %src.display(),
                    dest = %dest.display(),
                    error = %rename_err,
                    "rename failed, falling back to copy"
                );
                copy_recursive(src, dest)?;
                remove_any(src)?;
            }
        }

        // `self` drops here, tearing the workspace down now that the artifact
        // has left it.
        Ok(dest.to_path_buf())
    }
}

impl Drop for Workspace {
    /// Best-effort teardown; never panics.
    ///
    /// [`TempDir`] already deletes itself, so the only thing added here is the
    /// [`Workspace::keep`] escape hatch and the tracing around either outcome.
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };

        if self.keep {
            // `TempDir::keep` is the non-deprecated spelling of `into_path`.
            let path = dir.keep();
            warn!(
                label = %self.label,
                path = %path.display(),
                "retaining workspace for inspection; delete it yourself when done"
            );
            return;
        }

        match dir.close() {
            Ok(()) => debug!(
                label = %self.label,
                path = %self.root.display(),
                "removed workspace"
            ),
            Err(error) => warn!(
                label = %self.label,
                path = %self.root.display(),
                %error,
                "failed to remove workspace"
            ),
        }
    }
}

/// A sandboxed child process that is killed and reaped if it is still running
/// when the guard drops.
///
/// [`hakoniwa::Child`] has no `Drop` impl of its own, so a spawned container
/// that is never waited on — because the caller returned early with an error,
/// say — stays alive as an orphan and leaves a zombie behind. This guard closes
/// that leak.
pub struct SandboxedChild {
    /// Declared first so the child is killed before anything else this struct
    /// owns goes away. See the module docs on drop order.
    ///
    /// `None` after [`SandboxedChild::wait`] has taken it, which makes `Drop` a
    /// no-op on the normal path.
    child: Option<hakoniwa::Child>,
    program: String,
}

impl SandboxedChild {
    /// Take ownership of a spawned container. `program` is used in diagnostics
    /// and tracing output only.
    #[must_use]
    pub fn new(child: hakoniwa::Child, program: impl Into<String>) -> Self {
        let program = program.into();
        debug!(pid = child.id(), program = %program, "supervising sandboxed child");
        Self {
            child: Some(child),
            program,
        }
    }

    /// Wait for the child and return its exit status. Consumes the guard, which
    /// is the normal path: no kill happens afterwards.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the child cannot be waited on, or if the sandbox
    /// fails to report an exit status for it.
    pub fn wait(mut self) -> miette::Result<hakoniwa::ExitStatus> {
        let Some(mut child) = self.child.take() else {
            // Unreachable while `wait` is the only consumer, but a diagnostic
            // beats an `unwrap` that outlives that assumption.
            return Err(miette::miette!(
                "sandboxed child `{}` was already waited on",
                self.program
            ));
        };

        let status = child
            .wait()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to wait for sandboxed `{}`", self.program))?;
        debug!(
            program = %self.program,
            code = status.code,
            reason = %status.reason,
            "sandboxed child exited"
        );
        Ok(status)
    }
}

impl Drop for SandboxedChild {
    /// Best-effort kill and reap; never panics.
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let pid = child.id();

        // Do not kill a child that already exited on its own; `try_wait` reaps
        // it in that case.
        match child.try_wait() {
            Ok(Some(status)) => {
                debug!(
                    pid,
                    program = %self.program,
                    code = status.code,
                    "sandboxed child had already exited at drop"
                );
                return;
            }
            Ok(None) => {}
            Err(error) => warn!(
                pid,
                program = %self.program,
                %error,
                "failed to poll sandboxed child at drop; killing it anyway"
            ),
        }

        warn!(pid, program = %self.program, "killing sandboxed child left running at drop");
        if let Err(error) = child.kill() {
            warn!(pid, program = %self.program, %error, "failed to kill sandboxed child");
        }
        if let Err(error) = child.wait() {
            warn!(pid, program = %self.program, %error, "failed to reap sandboxed child");
        }
    }
}

/// Copy `src` to `dest`, recursing when `src` is a directory.
///
/// # Errors
///
/// Returns a diagnostic if `src` cannot be read or `dest` cannot be written.
fn copy_recursive(src: &Path, dest: &Path) -> miette::Result<()> {
    let metadata = fs::symlink_metadata(src)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to stat `{}`", src.display()))?;

    if !metadata.is_dir() {
        fs::copy(src, dest)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to copy `{}` to `{}`", src.display(), dest.display()))
            .map(drop)?;
        return Ok(());
    }

    WalkDir::new(src).into_iter().try_for_each(|entry| {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to walk `{}`", src.display()))?;
        let relative = entry
            .path()
            .strip_prefix(src)
            .into_diagnostic()
            .wrap_err("workspace entry escaped the workspace root")?;
        let target = dest.join(relative);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create `{}`", target.display()))
        } else {
            fs::copy(entry.path(), &target)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "failed to copy `{}` to `{}`",
                        entry.path().display(),
                        target.display()
                    )
                })
                .map(drop)
        }
    })
}

/// Remove `src`, whether it is a file or a directory tree.
///
/// # Errors
///
/// Returns a diagnostic if the removal fails.
fn remove_any(src: &Path) -> miette::Result<()> {
    let metadata = fs::symlink_metadata(src)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to stat `{}`", src.display()))?;

    if metadata.is_dir() {
        fs::remove_dir_all(src)
    } else {
        fs::remove_file(src)
    }
    .into_diagnostic()
    .wrap_err_with(|| format!("failed to remove `{}`", src.display()))
}
