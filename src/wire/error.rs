//! `org.pm1.Error.*` names, and the conversion that turns an in-process
//! `miette::Report` into a [`Diagnostic`] a client without shared memory can
//! read.

use miette::Report;

use crate::{progress::sanitise, wire::types::Diagnostic};

/// Something failed for a reason the returned [`Diagnostic`] describes. The
/// fallback name when nothing more specific applies - which, today, is every
/// error in this crate: nothing here yet constructs a `miette::Report` with
/// its own `#[diagnostic(code(...))]`.
pub const FAILED: &str = "org.pm1.Error.Failed";
/// The job, package or path named in the call does not exist.
pub const NOT_FOUND: &str = "org.pm1.Error.NotFound";
/// A caller-supplied argument failed validation before any work started.
pub const INVALID_ARGUMENT: &str = "org.pm1.Error.InvalidArgument";
/// The call was cancelled by its own caller, not defeated by a failure.
pub const CANCELLED: &str = "org.pm1.Error.Cancelled";

/// Cap on [`Diagnostic::name`]. A diagnostic code is a short identifier, not
/// prose - `miette`'s own `#[diagnostic(code(...))]` convention is a handful
/// of dotted words - so this is tight compared to the other fields.
const NAME_CAP: usize = 128;
/// Cap on [`Diagnostic::message`]. Generous, and deliberately the largest cap
/// in this module: a failed build step's raw, captured stdout AND stderr
/// (`sandbox::describe_stream`) land in this exact field verbatim, via the
/// `miette!` call that becomes the report's head error, and nothing upstream
/// of this conversion bounds that text.
const MESSAGE_CAP: usize = 8192;
/// Cap on [`Diagnostic::help`]. A hint is meant to be read at a glance, but
/// still bounded rather than trusted, since a `Diagnostic` is the largest
/// untrusted channel this daemon has.
const HELP_CAP: usize = 2048;
/// Cap on each entry of [`Diagnostic::causes`]. A `wrap_err` layered on top
/// of the sandbox failure can carry the same captured command output one
/// level further up the chain, so every link gets its own cap rather than
/// inheriting `message`'s.
const CAUSE_CAP: usize = 4096;

/// The combined byte budget for `message` + `help` + every `causes` entry
/// together, per the design spec's "64 KiB total for a whole `Diagnostic`"
/// (section 5, invariant 5). `name` is excluded: the spec's own wire-types
/// table states the budget as "across message, help and causes", and `name`
/// is a short, stable key rather than untrusted prose.
///
/// `NAME_CAP`/`MESSAGE_CAP`/`HELP_CAP`/`CAUSE_CAP` above are the SHAPE: the
/// limit that applies to one field, or one `causes` entry, at a time. This
/// is the CEILING that applies once those add up regardless. It is not a
/// live hole today - the length of `causes` is fixed by how many `wrap_err`
/// calls this crate's own code makes, not by attacker input - but nothing
/// stops a future call site from wrapping a report a dozen more times, and
/// the spec's number is absolute the moment a value actually reaches the
/// wire.
const TOTAL_BUDGET: usize = 64 * 1024;

/// How many [`Diagnostic::causes`] entries survive before the rest are
/// dropped, budget or not. A count bound as well as a byte one: an
/// unbounded chain is a resource cost per entry, independent of how few
/// bytes each one holds.
const MAX_CAUSES: usize = 16;

impl From<&Report> for Diagnostic {
    /// The single place a `miette::Report` crosses onto the wire.
    ///
    /// Every string here is sanitised through [`sanitise`], the one choke
    /// point Part B of this module's design calls for: a build file is
    /// untrusted input, and a failed step's report is the largest channel its
    /// output reaches. `causes` additionally answers to [`TOTAL_BUDGET`] and
    /// [`MAX_CAUSES`] once every entry has already been sanitised and capped
    /// on its own: when either bound is the reason an entry is missing, a
    /// trailing marker says so, so a truncated chain is never mistaken for a
    /// short one. That marker is charged against [`TOTAL_BUDGET`] like any
    /// other byte - it lives INSIDE the budget, never appended on top of it.
    fn from(report: &Report) -> Self {
        let name = report.code().map_or_else(
            || FAILED.to_owned(),
            |code| sanitise(&code.to_string(), NAME_CAP),
        );
        let message = sanitise(&report.to_string(), MESSAGE_CAP);
        let help = report
            .help()
            .map_or_else(String::new, |help| sanitise(&help.to_string(), HELP_CAP));

        // `chain()` yields the head error first - the same text `message`
        // already carries - so it is skipped here rather than duplicated.
        // Only the first `MAX_CAUSES` are ever sanitised and formatted;
        // `chain()` just chases `.source()` pointers, so counting past that
        // point costs nothing even though none of it is kept.
        let mut rest = report.chain().skip(1);
        let mut causes: Vec<String> = rest
            .by_ref()
            .take(MAX_CAUSES)
            .map(|cause| sanitise(&cause.to_string(), CAUSE_CAP))
            .collect();
        let overflow = rest.count();

        // The marker's own length depends on the dropped count, which is
        // not known until the retain below decides what fits - and what
        // fits depends on how much room the marker leaves. Resolved by
        // reserving for the WORST case first: every remaining candidate
        // also getting rejected by the budget, on top of `overflow`
        // already excluded by count. The real marker, built afterwards,
        // reports a dropped count that can only be smaller or equal, so
        // it can only be shorter or equal in bytes - it fits in the space
        // reserved for it by construction, never over it.
        let spent = message.len() + help.len();
        let worst_case_dropped = overflow + causes.len();
        let reserved = drop_marker(worst_case_dropped).map_or(0, |marker| marker.len());
        let mut remaining = TOTAL_BUDGET
            .saturating_sub(spent)
            .saturating_sub(reserved);

        let mut dropped = overflow;
        causes.retain(|cause| {
            let fits = cause.len() <= remaining;
            if fits {
                remaining -= cause.len();
            } else {
                dropped += 1;
            }
            fits
        });

        if let Some(marker) = drop_marker(dropped) {
            causes.push(marker);
        }

        Self {
            name,
            message,
            help,
            causes,
        }
    }
}

/// The visible marker appended to `causes` when [`MAX_CAUSES`] or
/// [`TOTAL_BUDGET`] dropped one or more entries. `None` when nothing was
/// dropped, so a chain that fit needs no marker at all.
///
/// Factored out so [`From<&Report>`]'s budget accounting can render this
/// twice: once for a worst-case `dropped` count, to reserve its bytes ahead
/// of time, and once for real afterwards. Digit count only grows with the
/// number it represents, so the real marker - built from a `dropped` that
/// can only be smaller or equal to the worst case - is never longer than
/// what was reserved for it.
fn drop_marker(dropped: usize) -> Option<String> {
    (dropped > 0).then(|| {
        format!(
            "…{dropped} more cause(s) dropped to stay within the {TOTAL_BUDGET}-byte Diagnostic budget"
        )
    })
}
