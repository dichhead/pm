//! Length-prefixed framing for the worker's socketpair.
//!
//! The daemon's public API travels over D-Bus, encoded by
//! [`crate::wire::types`]. This is the OTHER wire: what the daemon will speak
//! to its own build worker over a `socketpair(2)`, once one exists. That
//! channel has no client watching it and no bus name to register, so
//! reaching for zbus there would drag a whole codec onto a byte pipe it was
//! never meant for. This is the small alternative: one length-prefixed frame
//! at a time, dependency-free, over any `Read`/`Write`.

use std::io::{Read, Write};

use miette::{IntoDiagnostic, WrapErr, miette};

/// The largest payload [`read_frame`] will allocate for.
///
/// Once the worker is a separate process, a frame's length prefix is
/// attacker-adjacent: a corrupted or hostile prefix must fail cleanly rather
/// than turn into an attempt to allocate gigabytes for one frame. 16 MiB
/// comfortably covers a sanitised [`crate::wire::types::Diagnostic`] - see its
/// own field caps - with plenty of room to spare.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// Write `payload` as one frame: a 4-byte big-endian length, then the bytes.
///
/// # Errors
///
/// Returns an error if `payload` is longer than [`MAX_FRAME`] (or than
/// `u32::MAX`), or if a write to `writer` fails.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> miette::Result<()> {
    let len = u32::try_from(payload.len())
        .into_diagnostic()
        .wrap_err("frame payload is too large to fit its own length prefix")?;
    if len > MAX_FRAME {
        return Err(miette!(
            "frame payload is {len} bytes, over the {MAX_FRAME} byte limit"
        ));
    }

    writer
        .write_all(&len.to_be_bytes())
        .into_diagnostic()
        .wrap_err("failed to write a frame's length prefix")?;
    writer
        .write_all(payload)
        .into_diagnostic()
        .wrap_err("failed to write a frame's payload")?;
    Ok(())
}

/// Read one frame written by [`write_frame`].
///
/// # Errors
///
/// Returns an error if the declared length is over [`MAX_FRAME`], or if
/// reading the prefix or the payload from `reader` fails - including a clean
/// EOF partway through, which `read_exact` already reports as an error.
pub fn read_frame<R: Read>(reader: &mut R) -> miette::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .into_diagnostic()
        .wrap_err("failed to read a frame's length prefix")?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(miette!(
            "frame claims to be {len} bytes, over the {MAX_FRAME} byte limit"
        ));
    }

    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .into_diagnostic()
        .wrap_err("failed to read a frame's payload")?;
    Ok(payload)
}
