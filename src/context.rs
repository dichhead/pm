//! The caller-supplied environment a build runs against.
//!
//! Five places in this crate used to read the process's own current
//! directory, `$PATH` or `$HOME` at the moment they needed one, on the
//! assumption that "the process" and "the person who asked for the build" are
//! the same thing. They are, for `pm` run from a shell. They will not be once
//! a daemon runs a build on a caller's behalf: the daemon's cwd is not the
//! caller's, and mounting the daemon's toolchain instead of the caller's is a
//! silent wrong answer, not a crash.
//!
//! [`BuildContext`] gathers what those five places need into one value that a
//! caller can build once and pass down, instead of each site reading the
//! ambient environment on its own. [`BuildContext::from_env`] reproduces
//! today's behaviour exactly, so every existing entry point that does not
//! know about contexts yet keeps working by constructing one from the
//! process it happens to be running in.

use std::{
    env::{current_dir, var_os},
    ffi::OsString,
    path::PathBuf,
};

use miette::{IntoDiagnostic, WrapErr};

use crate::{sandbox::CONTAINER_PATH, signing::default_trust_dir};

/// Everything a build reads out of "the environment" instead of taking as an
/// explicit argument.
///
/// Marked `#[non_exhaustive]` so a caller cannot build one with a struct
/// literal - a later field added here must not silently become a required
/// part of every existing call site's construction. Build one with
/// [`BuildContext::from_env`] and adjust it with the `with_*` setters.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// The base relative dependency paths resolve against.
    pub(crate) cwd: PathBuf,
    /// Where a finished `.cpkg` lands.
    pub(crate) output_dir: PathBuf,
    /// The trust store build-file signatures verify against.
    pub(crate) trust_dir: PathBuf,
    /// The `PATH` used to resolve a step's first word and to pick toolchain
    /// mounts. Kept as [`OsString`] rather than [`String`] because a real
    /// `PATH` is not guaranteed to be valid UTF-8 and splitting it is exactly
    /// what [`std::env::split_paths`] is for.
    pub(crate) path: OsString,
    /// The `$HOME` that toolchain mounting refuses to cross. `None` means no
    /// home, and nothing is refused on that ground.
    pub(crate) home: Option<PathBuf>,
    /// The parent directory for build workspaces. `None` means the system
    /// temporary directory, which is today's behaviour.
    pub(crate) scratch_root: Option<PathBuf>,
}

impl BuildContext {
    /// Capture the ambient process environment: the current directory, the
    /// default trust store, `$PATH` and `$HOME`.
    ///
    /// This is exactly what every one of the five sites read directly before
    /// this type existed, so every entry point that has not been taught about
    /// an explicit context yet keeps its old behaviour by calling this and
    /// nothing else.
    ///
    /// # Errors
    ///
    /// Fails when the current directory cannot be determined, or when neither
    /// `$XDG_CONFIG_HOME` nor `$HOME` names a directory to keep the trust
    /// store under - see [`default_trust_dir`].
    pub fn from_env() -> miette::Result<Self> {
        let cwd = current_dir()
            .into_diagnostic()
            .wrap_err("cannot determine the current working directory")?;
        let path = var_os("PATH").unwrap_or_else(|| OsString::from(CONTAINER_PATH));
        // `HOME` is allowed to be absent or unresolvable: a caller with no
        // home directory just gets `None`, and nothing downstream refuses a
        // mount on that ground.
        let home = var_os("HOME")
            .map(PathBuf::from)
            .and_then(|home| home.canonicalize().ok());

        Ok(Self {
            output_dir: cwd.clone(),
            trust_dir: default_trust_dir()?,
            cwd,
            path,
            home,
            scratch_root: None,
        })
    }

    /// Resolve relative dependency paths against `cwd` instead.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Write a finished archive under `output_dir` instead.
    #[must_use]
    pub fn with_output_dir(mut self, output_dir: impl Into<PathBuf>) -> Self {
        self.output_dir = output_dir.into();
        self
    }

    /// Verify build-file signatures against `trust_dir` instead.
    #[must_use]
    pub fn with_trust_dir(mut self, trust_dir: impl Into<PathBuf>) -> Self {
        self.trust_dir = trust_dir.into();
        self
    }

    /// Resolve step commands and toolchain mounts against `path` instead.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<OsString>) -> Self {
        self.path = path.into();
        self
    }

    /// Treat `home` as the `$HOME` toolchain mounting refuses to cross.
    /// `None` means no home, and nothing is refused on that ground.
    #[must_use]
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    /// Place build workspaces under `scratch_root` instead. `None` means the
    /// system temporary directory.
    #[must_use]
    pub fn with_scratch_root(mut self, scratch_root: Option<PathBuf>) -> Self {
        self.scratch_root = scratch_root;
        self
    }
}
