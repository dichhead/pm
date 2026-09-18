//! Freezes the D-Bus signature of every type in [`pm::wire::types`] as a
//! string literal, and exercises [`pm::wire::frame`]'s length-prefixed
//! framing.
//!
//! A signature assertion here is the point of this module: if a field is
//! ever reordered, added or retyped, one of these fails before a client
//! mis-decodes a live message instead of after.

use std::io::Cursor;

use miette::Report;
use pm::wire::{
    frame::{MAX_FRAME, read_frame, write_frame},
    types::{CallerContext, Diagnostic, JobRow, LogLine, Observation, PackageOutcome, ProgressNode},
};
use zbus::zvariant::Type;

#[test]
fn caller_context_signature_is_frozen() {
    assert_eq!(
        <CallerContext as Type>::SIGNATURE.to_string(),
        "(sssss)",
        "CallerContext: cwd, output_dir, trust_dir, path, home, all String"
    );
}

#[test]
fn diagnostic_signature_is_frozen() {
    assert_eq!(
        <Diagnostic as Type>::SIGNATURE.to_string(),
        "(sssas)",
        "Diagnostic: name, message, help are String, causes is Vec<String>"
    );
}

#[test]
fn progress_node_signature_is_frozen() {
    // VERIFIED against a probe crate with this exact field order: u32, u32,
    // u32, String, u8, String, u64, u64, u64.
    assert_eq!(
        <ProgressNode as Type>::SIGNATURE.to_string(),
        "(uuusysttt)",
        "ProgressNode: id, parent, depth, label, kind, text, done, total, started_usec"
    );
}

#[test]
fn log_line_signature_is_frozen() {
    assert_eq!(
        <LogLine as Type>::SIGNATURE.to_string(),
        "(tys)",
        "LogLine: seq (u64), stream (u8), text (String)"
    );
}

#[test]
fn job_row_signature_is_frozen() {
    assert_eq!(
        <JobRow as Type>::SIGNATURE.to_string(),
        "(ossssxxi)",
        "JobRow: path (o), id/kind/state/subject (String), created_usec/finished_usec (i64), exit_code (i32)"
    );
}

#[test]
fn observation_signature_is_frozen() {
    assert_eq!(
        <Observation as Type>::SIGNATURE.to_string(),
        "(sisssbbs)",
        "Observation: syscall (s), pid (i), permission/label/path (s), resolved/succeeded (b), evidence (s)"
    );
}

#[test]
fn package_outcome_signature_is_frozen() {
    assert_eq!(
        <PackageOutcome as Type>::SIGNATURE.to_string(),
        "(ssss)",
        "PackageOutcome: name, outcome, archive, error, all String"
    );
}

#[test]
fn a_frame_round_trips_through_write_and_read() {
    let mut buffer = Cursor::new(Vec::new());
    write_frame(&mut buffer, b"hello, worker").expect("a small frame must write");

    buffer.set_position(0);
    let payload = read_frame(&mut buffer).expect("a frame just written must read back");

    assert_eq!(payload, b"hello, worker");
}

#[test]
fn an_empty_frame_round_trips() {
    let mut buffer = Cursor::new(Vec::new());
    write_frame(&mut buffer, b"").expect("an empty frame must write");

    buffer.set_position(0);
    let payload = read_frame(&mut buffer).expect("an empty frame must read back");

    assert!(payload.is_empty());
}

#[test]
fn a_payload_over_the_limit_is_rejected_on_write() {
    // Building an actual `MAX_FRAME + 1`-byte buffer just to prove this would
    // spend real time and memory on every test run for no extra coverage:
    // `write_frame` checks the length before ever touching `writer`, so a
    // cheap zero-filled buffer exercises the exact same branch.
    let oversized = vec![0u8; (MAX_FRAME as usize) + 1];
    let mut sink = Cursor::new(Vec::new());

    let result = write_frame(&mut sink, &oversized);

    assert!(result.is_err(), "a payload over MAX_FRAME must be rejected");
    assert!(
        sink.get_ref().is_empty(),
        "a rejected frame must not have written a partial length prefix"
    );
}

#[test]
fn a_declared_length_over_the_limit_is_rejected_on_read() {
    let mut bogus = Vec::new();
    bogus.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
    let mut reader = Cursor::new(bogus);

    let result = read_frame(&mut reader);

    assert!(
        result.is_err(),
        "a frame claiming to be over MAX_FRAME must be rejected before allocating for it"
    );
}

#[test]
fn reading_past_a_truncated_frame_is_an_error_not_a_panic() {
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&100u32.to_be_bytes());
    truncated.extend_from_slice(b"not enough bytes");
    let mut reader = Cursor::new(truncated);

    let result = read_frame(&mut reader);

    assert!(result.is_err(), "a short read must be an error, not a hang or a panic");
}

/// The combined content size a `Diagnostic` is allowed: `message`, `help`
/// and every `causes` entry together, per the design spec's 64 KiB budget.
/// `name` is deliberately excluded, matching the spec's own wording.
fn diagnostic_content_bytes(diagnostic: &Diagnostic) -> usize {
    diagnostic.message.len() + diagnostic.help.len() + diagnostic.causes.iter().map(String::len).sum::<usize>()
}

#[test]
fn a_long_chain_of_small_causes_is_capped_by_count_not_bytes() {
    // 200 layers is far past anything this crate's own `wrap_err` call
    // sites produce today - the point is a caller that adds a lot more of
    // them later, not anything reachable from a build file right now. Each
    // layer here is short, so this exercises the MAX_CAUSES count cap and
    // the drop marker's visibility, not the byte budget - see the sibling
    // tests below for that.
    let mut report = Report::msg(
        "innermost failure, padded out to a realistic build-output length so the maths in this test means something",
    );
    for layer in 0..200 {
        report = report.wrap_err(format!(
            "layer {layer} failed while wrapping the step below it with a decently long context string"
        ));
    }

    let diagnostic = Diagnostic::from(&report);

    assert!(
        diagnostic_content_bytes(&diagnostic) <= 64 * 1024,
        "message + help + causes must stay within the spec's 64 KiB Diagnostic budget: got {} bytes",
        diagnostic_content_bytes(&diagnostic)
    );
    assert!(
        diagnostic.causes.len() <= 20,
        "causes must be bounded in count, not just truncated per entry: got {} entries",
        diagnostic.causes.len()
    );
    assert!(
        diagnostic
            .causes
            .last()
            .is_some_and(|last| last.contains("dropped")),
        "dropping causes from a 200-layer chain must be visible, not silent: {:?}",
        diagnostic.causes.last()
    );
}

#[test]
fn large_causes_are_trimmed_by_the_byte_budget_even_under_the_count_cap() {
    // 16 wraps, each already at CAUSE_CAP, plus a small innermost message:
    // 17 layers total, which is AT the MAX_CAUSES count cap once the
    // outermost becomes `message` - so nothing here is excluded by count.
    // Yet 16 * 4096 bytes alone is the whole 64 KiB budget, before `help`,
    // the marker, or the small innermost cause get a single byte, so the
    // byte ceiling has to do real trimming on its own.
    let mut report = Report::msg("root cause");
    for _ in 0..16 {
        report = report.wrap_err("x".repeat(4096));
    }

    let diagnostic = Diagnostic::from(&report);

    assert!(
        diagnostic_content_bytes(&diagnostic) <= 64 * 1024,
        "message + help + causes must stay within the spec's 64 KiB Diagnostic budget: got {} bytes",
        diagnostic_content_bytes(&diagnostic)
    );
    assert!(
        diagnostic
            .causes
            .last()
            .is_some_and(|last| last.contains("dropped")),
        "large causes must be visibly trimmed by the byte budget, not silently dropped: {:?}",
        diagnostic.causes.last()
    );
}

#[test]
fn sixteen_full_causes_plus_overflow_stays_within_the_64kib_budget() {
    // The exact boundary a prior version of this conversion got wrong: an
    // empty message and help (so nothing is "spent" before causes), 16
    // causes of EXACTLY CAUSE_CAP (4096) ASCII bytes each - which
    // `sanitise` therefore returns untouched, no ellipsis, no shortening -
    // plus at least one more cause past MAX_CAUSES. 16 * 4096 is already
    // the full 64 KiB budget on its own; the dropped-cause marker then has
    // to fit INSIDE that budget rather than being appended on top of it.
    let mut report = Report::msg("root cause");
    for _ in 0..17 {
        report = report.wrap_err("x".repeat(4096));
    }
    // Empty message and help: sanitise("") is "", and nothing in this
    // chain carries a `#[diagnostic(help(...))]`, so `help` is "" already.
    report = report.wrap_err(String::new());

    let diagnostic = Diagnostic::from(&report);

    assert_eq!(diagnostic.message, "", "the empty head must sanitise to empty, not add bytes of its own");
    assert_eq!(diagnostic.help, "");
    assert!(
        diagnostic_content_bytes(&diagnostic) <= 64 * 1024,
        "16 full-cap causes plus a marker must still fit the 64 KiB budget: got {} bytes",
        diagnostic_content_bytes(&diagnostic)
    );
    // `causes.len()` alone cannot show this: dropping one full-size cause
    // and then appending one marker leaves the same COUNT. What proves the
    // budget actually trimmed something is that fewer than all 16 original
    // full-size (4096-byte) causes survive.
    let full_size_causes = diagnostic.causes.iter().filter(|cause| cause.len() == 4096).count();
    assert!(
        full_size_causes < 16,
        "fitting the marker inside the budget must cost at least one full-size cause: kept {full_size_causes} of the original 16"
    );
    assert!(
        diagnostic
            .causes
            .last()
            .is_some_and(|last| last.contains("dropped")),
        "the boundary case must still report that causes were dropped: {:?}",
        diagnostic.causes.last()
    );
}
