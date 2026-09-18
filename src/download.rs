//! Fetching a build file's sources over HTTP, hashing them as they land.
//!
//! A download is the one part of a build that is *not* confined: it runs
//! in-process on the host, because it is not a child process and jailing it
//! would mean jailing `pm` itself. What keeps it honest is the hash. Every
//! `dl_urls` entry in a build file names the SHA-256 the bytes must have, and
//! [`Downloader::fetch_verified`] refuses to leave a file behind that does not
//! match it - so a compromised mirror changes the digest, not the build.
//!
//! The digest is computed **as the body streams**, not by reading the finished
//! file back. That is what lets a download report progress at all: the same
//! pass that hashes a chunk also writes it and counts it.

use std::{
    fs::{File, remove_file},
    io::{BufWriter, Read as _, Write as _},
    path::Path,
};

use miette::{IntoDiagnostic, WrapErr, miette};
use minreq::ResponseLazy;
use ring::digest::{Context, SHA256};
use tracing::{debug, warn};
use url::Url;

use crate::{cancel::Cancel, signing::to_hex};

/// How much of the body is hashed and written per pass.
///
/// 64 KiB is comfortably above the point where syscall overhead stops
/// dominating and well below the point where the buffer is worth heap-tuning.
const CHUNK: usize = 64 * 1024;

/// How many redirects are followed before the download is called a loop.
///
/// minreq's own default is 100, which is generous enough that a redirect cycle
/// looks like a hang rather than an error. Ten is more than any real mirror
/// chain needs.
const MAX_REDIRECTS: usize = 10;

/// Fetches sources named by a build file and reports what their bytes hash to.
///
/// # Timeouts
///
/// There is deliberately **no** request timeout. minreq's `with_timeout` sets
/// an absolute deadline for the whole request rather than an idle timeout, so
/// any value large enough for a slow mirror serving a 400 MB tarball is too
/// large to catch a stalled connection, and any value small enough to catch the
/// stall aborts legitimate downloads. A stalled fetch is therefore interrupted
/// by the user, not by a clock that cannot tell the two cases apart.
#[derive(Debug, Clone)]
pub struct Downloader {
    max_redirects: usize,
    /// Checked between chunks so a caller can stop a download in progress.
    /// `None`, the default, never stops one - see [`Downloader::with_cancel`].
    cancel: Option<Cancel>,
}

impl Default for Downloader {
    fn default() -> Self {
        Self::new()
    }
}

impl Downloader {
    /// A downloader with the default redirect budget and no cancellation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_redirects: MAX_REDIRECTS,
            cancel: None,
        }
    }

    /// Follow at most `max_redirects` redirects instead of the default.
    #[must_use]
    pub fn with_max_redirects(self, max_redirects: usize) -> Self {
        Self {
            max_redirects,
            ..self
        }
    }

    /// Check `cancel` after every chunk written, and stop with a diagnostic
    /// instead of writing another if it has been tripped.
    ///
    /// This is best-effort in exactly the way the rest of [`Cancel`] is: it
    /// only ever gets a chance to act between two chunks, so it does **not**
    /// interrupt a read that is already blocked in the underlying socket
    /// waiting on the network - the "no timeout" reasoning on the module doc
    /// above stays true regardless of whether a cancel token is attached.
    #[must_use]
    pub fn with_cancel(self, cancel: Cancel) -> Self {
        Self {
            cancel: Some(cancel),
            ..self
        }
    }

    /// Download `url` into `dest` and return the lowercase hex SHA-256 of what
    /// was written.
    ///
    /// `on_progress` is called once before the first byte and once per chunk
    /// afterwards, with the number of bytes written so far and the total the
    /// server declared. The total is `None` when the response carries no
    /// `Content-Length` - a chunked or connection-framed response knows its own
    /// length no better than the client does.
    ///
    /// `dest` is **truncated**, so re-downloading over a previous attempt
    /// replaces it rather than appending to it. Nothing is created until the
    /// server has answered with a success status, and a partial file is removed
    /// if the transfer fails part-way, so a failed download never leaves a
    /// truncated source for a later step to pick up.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the request cannot be made, when the response
    /// status is outside 2xx, when `dest` cannot be created or written, or when
    /// the body cannot be read to its end.
    pub fn fetch<F>(&self, url: &Url, dest: &Path, on_progress: F) -> miette::Result<String>
    where
        F: FnMut(u64, Option<u64>),
    {
        let response = minreq::get(url.as_str())
            .with_max_redirects(self.max_redirects)
            .send_lazy()
            .map_err(|e| miette!("Failed to request `{url}`: {e}"))?;

        // Check the status BEFORE creating the file, so a 404 leaves nothing
        // behind at all rather than an empty file that looks like a download.
        if !(200..300).contains(&response.status_code) {
            return Err(miette!(
                "Request for `{url}` failed with HTTP {} {}",
                response.status_code,
                response.reason_phrase
            ));
        }

        let total = content_length(&response.headers);
        debug!(%url, dest = %dest.display(), ?total, "streaming download");

        self.stream(response, dest, total, on_progress)
            .inspect_err(|_| discard(dest))
    }

    /// As [`Downloader::fetch`], but also check the digest against `expected`
    /// and remove the file if it does not match.
    ///
    /// The comparison is case-insensitive and ignores surrounding whitespace,
    /// because a hash copied out of a release page is as likely to be upper-case
    /// as lower.
    ///
    /// # Errors
    ///
    /// Everything [`Downloader::fetch`] returns, plus a diagnostic naming both
    /// digests when the bytes that arrived are not the bytes the build file
    /// asked for.
    pub fn fetch_verified<F>(
        &self,
        url: &Url,
        dest: &Path,
        expected: &str,
        on_progress: F,
    ) -> miette::Result<()>
    where
        F: FnMut(u64, Option<u64>),
    {
        let actual = self.fetch(url, dest, on_progress)?;

        let (actual, expected) = (actual.trim(), expected.trim());
        if !actual.eq_ignore_ascii_case(expected) {
            // Do not leave a corrupt file behind for a later step to pick up.
            discard(dest);
            return Err(miette!(
                "Hash mismatch for `{url}`: expected {expected}, got {actual}"
            ));
        }

        debug!(%url, "downloaded and verified");
        Ok(())
    }

    /// Write the body to `dest` while hashing and counting it in the same pass.
    fn stream<F>(
        &self,
        mut response: ResponseLazy,
        dest: &Path,
        total: Option<u64>,
        mut on_progress: F,
    ) -> miette::Result<String>
    where
        F: FnMut(u64, Option<u64>),
    {
        let mut file = BufWriter::new(
            File::create(dest)
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot create `{}`", dest.display()))?,
        );

        let mut digest = Context::new(&SHA256);
        let mut buffer = vec![0_u8; CHUNK];
        let mut written = 0_u64;

        // Report before the first read so a caller showing a progress line has
        // the total to draw against while the connection is still warming up.
        on_progress(written, total);

        loop {
            let read = response
                .read(&mut buffer)
                .into_diagnostic()
                .wrap_err("the connection failed part-way through the download")?;
            if read == 0 {
                break;
            }

            let chunk = &buffer[..read];
            digest.update(chunk);
            file.write_all(chunk)
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot write `{}`", dest.display()))?;

            written += read as u64;
            on_progress(written, total);

            // Checked right after the same `on_progress` call a caller's
            // progress line already observes, so a cancelled download stops
            // at a chunk boundary instead of writing another one it will only
            // have to discard. This cannot interrupt the `read` above once it
            // is blocked waiting on the network - see `Downloader::with_cancel`.
            if self.cancel.as_ref().is_some_and(Cancel::is_cancelled) {
                return Err(miette!(
                    "download of `{}` was cancelled after {written} bytes",
                    dest.display()
                ));
            }
        }

        file.flush()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot flush `{}`", dest.display()))?;

        Ok(to_hex(digest.finish().as_ref()))
    }
}

/// The declared body length, if the response carried one.
///
/// Header names arrive as the server sent them, so the lookup has to be
/// case-insensitive: `Content-Length`, `content-length` and `CONTENT-LENGTH`
/// are all the same header.
fn content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

/// Remove a download that must not survive, reporting rather than failing.
///
/// Called on a path that is already being abandoned, so a failure here changes
/// nothing about the outcome - but a stale file that could not be removed is
/// worth saying out loud, because the next run will find it.
fn discard(dest: &Path) {
    match remove_file(dest) {
        Ok(()) => debug!(dest = %dest.display(), "removed the abandoned download"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("Could not remove the download `{}`: {e}", dest.display()),
    }
}
