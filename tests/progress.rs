//! Integration tests for [`pm::progress`]: what the live region renders, and
//! what happens to a line when the work behind it ends.
//!
//! The region's whole job is to describe concurrent work truthfully, so these
//! tests are mostly about the tree staying honest: a line appears when work
//! starts, disappears when it ends, and takes its children with it when the
//! work that owned them fails.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use pm::progress::{Progress, sanitise};

/// Width every test renders against, so assertions are about content rather
/// than about whichever terminal happens to be running them.
const WIDTH: usize = 60;

/// A sink that keeps everything written to it, so a test can look at the bytes
/// the region actually emitted rather than only at its rendered lines.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the sink must not be poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn written(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the sink must not be poisoned")).into_owned()
    }
}

/// A region that renders normally but writes into `sink`.
fn region(sink: &Sink) -> Progress {
    Progress::to_writer(Box::new(sink.clone()), WIDTH)
}

#[test]
fn a_disabled_region_renders_nothing() {
    let progress = Progress::disabled();
    let _task = progress.task("zlib-1.3.1");

    assert!(
        progress.snapshot().is_empty(),
        "a disabled region must not render, however many tasks are open on it"
    );
}

#[test]
fn a_task_renders_a_line_carrying_its_label() {
    let sink = Sink::default();
    let progress = region(&sink);
    let _task = progress.task("zlib-1.3.1");

    let lines = progress.snapshot();
    assert_eq!(lines.len(), 1, "one open task is one line");
    assert!(
        lines[0].contains("zlib-1.3.1"),
        "the line must name its task: {:?}",
        lines[0]
    );
}

#[test]
fn a_child_renders_indented_under_its_parent() {
    let sink = Sink::default();
    let progress = region(&sink);
    let package = progress.task("zlib-1.3.1");
    let _command = package.child("make");

    let lines = progress.snapshot();
    assert_eq!(lines.len(), 2, "a parent and a child are two lines");
    assert!(
        !lines[0].starts_with(' '),
        "a top-level line must not be indented: {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("    "),
        "a child line must be indented under its parent: {:?}",
        lines[1]
    );
    assert!(lines[1].contains("make"));
}

/// Which of `labels` each rendered line carries, in render order.
fn labels_of(lines: &[String], labels: [&'static str; 4]) -> Vec<&'static str> {
    lines
        .iter()
        .map(|line| {
            labels
                .into_iter()
                .find(|needle| line.contains(needle))
                .unwrap_or("?")
        })
        .collect()
}

#[test]
fn a_child_renders_under_its_own_parent_not_at_the_end() {
    let sink = Sink::default();
    let progress = region(&sink);

    // The interleaving a parallel build produces: a second package opens its
    // line while the first is still running, and only then does the first
    // start a command. Appending that command to the end of the list would
    // render it under the WRONG package.
    let zlib = progress.task("zlib-1.3.1");
    let openssl = progress.task("openssl-3.5");
    let _configure = zlib.child("configure");
    let _make = openssl.child("make");

    assert_eq!(
        labels_of(
            &progress.snapshot(),
            ["zlib-1.3.1", "configure", "openssl-3.5", "make"]
        ),
        ["zlib-1.3.1", "configure", "openssl-3.5", "make"],
        "each command must render beneath the package that opened it"
    );
}

#[test]
fn a_second_child_renders_beside_the_first_not_after_a_later_package() {
    let sink = Sink::default();
    let progress = region(&sink);

    let zlib = progress.task("zlib-1.3.1");
    let _configure = zlib.child("configure");
    let openssl = progress.task("openssl-3.5");
    // zlib picks up a SECOND command after openssl already has a line. This is
    // the case that tells insertion-in-tree-order apart from appending.
    let _make = zlib.child("make");

    assert_eq!(
        labels_of(
            &progress.snapshot(),
            ["zlib-1.3.1", "configure", "make", "openssl-3.5"]
        ),
        ["zlib-1.3.1", "configure", "make", "openssl-3.5"],
        "a package's later commands must stay with it, not fall under the next package"
    );
    drop(openssl);
}

#[test]
fn dropping_a_task_removes_its_line() {
    let sink = Sink::default();
    let progress = region(&sink);
    let package = progress.task("zlib-1.3.1");
    {
        let _command = package.child("make");
        assert_eq!(progress.snapshot().len(), 2);
    }

    assert_eq!(
        progress.snapshot().len(),
        1,
        "a finished command must not keep a line on screen"
    );
}

#[test]
fn dropping_a_parent_removes_the_children_it_left_behind() {
    let sink = Sink::default();
    let progress = region(&sink);
    let command = {
        let package = progress.task("zlib-1.3.1");
        // A child that outlives its parent: the shape an early `?` leaves
        // behind when a package fails while a command is still registered.
        package.child("make")
    };

    assert!(
        progress.snapshot().is_empty(),
        "a task's children must not survive it as orphaned lines: {:?}",
        progress.snapshot()
    );
    drop(command);
}

#[test]
fn a_message_is_rendered_after_the_label() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("zlib-1.3.1");
    task.set_message("CC deflate.o");

    let line = progress.snapshot().remove(0);
    let label = line.find("zlib-1.3.1").expect("the label must be rendered");
    let message = line
        .find("CC deflate.o")
        .expect("the message must be rendered");
    assert!(message > label, "the message follows the label: {line:?}");
}

#[test]
fn a_later_message_replaces_the_one_before_it() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("zlib-1.3.1");
    task.set_message("CC deflate.o");
    task.set_message("CC inflate.o");

    let line = progress.snapshot().remove(0);
    assert!(line.contains("CC inflate.o"), "{line:?}");
    assert!(
        !line.contains("CC deflate.o"),
        "the previous message must be gone, not appended to: {line:?}"
    );
}

#[test]
fn bytes_render_against_the_total_when_one_is_known() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("source.tar.gz");
    task.set_bytes(14_200_000, Some(22_000_000));

    let line = progress.snapshot().remove(0);
    assert!(
        line.contains("13.5MiB/21.0MiB"),
        "a download with a declared length must render both halves: {line:?}"
    );
}

#[test]
fn bytes_render_alone_when_no_total_was_declared() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("source.tar.gz");
    task.set_bytes(14_200_000, None);

    let line = progress.snapshot().remove(0);
    assert!(line.contains("13.5MiB"), "{line:?}");
    assert!(
        !line.contains('/'),
        "with no declared length there is nothing to render a total against: {line:?}"
    );
}

#[test]
fn a_line_is_truncated_to_the_width_it_is_drawn_at() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("zlib-1.3.1");
    task.set_message("x".repeat(400));

    let line = progress.snapshot().remove(0);
    assert!(
        line.chars().count() <= WIDTH,
        "a line wider than the terminal wraps, and a wrapped line breaks the \
         redraw; got {} columns",
        line.chars().count()
    );
}

#[test]
fn every_line_carries_an_elapsed_time() {
    let sink = Sink::default();
    let progress = region(&sink);
    let _task = progress.task("zlib-1.3.1");

    let line = progress.snapshot().remove(0);
    assert!(
        line.trim_end().ends_with("s]"),
        "a line must say how long its work has been running: {line:?}"
    );
}

#[test]
fn the_spinner_advances_when_the_region_ticks() {
    let sink = Sink::default();
    let progress = region(&sink);
    let _task = progress.task("zlib-1.3.1");

    let before = progress.snapshot().remove(0);
    progress.tick();
    let after = progress.snapshot().remove(0);

    let frame_of = |line: &str| line.chars().next().expect("a line must have a frame");
    assert_ne!(
        frame_of(&before),
        frame_of(&after),
        "the spinner must move, or it does not read as alive"
    );
}

#[test]
fn println_writes_the_line_through_to_the_sink() {
    let sink = Sink::default();
    let progress = region(&sink);
    let _task = progress.task("zlib-1.3.1");

    progress.println("INFO building zlib version 1.3.1");

    assert!(
        sink.written().contains("INFO building zlib version 1.3.1"),
        "a log line must reach the terminal, not be swallowed by the region"
    );
}

#[test]
fn a_disabled_region_still_passes_log_lines_through() {
    let sink = Sink::default();
    let progress = Progress::passthrough(Box::new(sink.clone()));

    progress.println("WARN foo-0.1.0 is empty");

    assert!(
        sink.written().contains("WARN foo-0.1.0 is empty"),
        "turning the region off must not turn logging off"
    );
}

#[test]
fn a_handle_reports_on_a_line_it_does_not_own() {
    let sink = Sink::default();
    let progress = region(&sink);
    let package = progress.task("zlib-1.3.1");

    {
        let handle = package.handle();
        handle.set_message("building");
        assert_eq!(progress.snapshot().len(), 1, "a handle opens no new line");
    }

    let lines = progress.snapshot();
    assert_eq!(
        lines.len(),
        1,
        "dropping a handle must not close the line its owner is still using"
    );
    assert!(
        lines[0].contains("building"),
        "a handle writes to the line it refers to: {:?}",
        lines[0]
    );
}

#[test]
fn a_child_of_a_handle_nests_under_the_handles_own_line() {
    let sink = Sink::default();
    let progress = region(&sink);
    let package = progress.task("zlib-1.3.1");
    let handle = package.handle();

    let _command = handle.child("make");

    let lines = progress.snapshot();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[1].starts_with("    ") && !lines[1].starts_with("        "),
        "a handle's child sits one level down, not two: {:?}",
        lines[1]
    );
}

#[test]
fn an_empty_region_does_not_touch_the_cursor() {
    let sink = Sink::default();
    let progress = region(&sink);

    // Every `pm` subcommand builds a region, but only a build ever opens a
    // line on it. `pm run` hands the terminal to the package's own binary and
    // prompts with dialoguer; a region that hid the cursor just by existing
    // would leave that prompt invisible.
    progress.tick();
    progress.println("INFO nothing is building");

    assert!(
        !sink.written().contains("\x1b[?25l"),
        "a region with no work on it must leave the cursor alone"
    );
}

#[test]
fn the_cursor_is_hidden_only_while_there_are_lines() {
    let sink = Sink::default();
    let progress = region(&sink);

    {
        let _task = progress.task("zlib-1.3.1");
        assert!(
            sink.written().contains("\x1b[?25l"),
            "a drawing region must hide the cursor so it does not chase the redraw"
        );
    }

    assert!(
        sink.written().contains("\x1b[?25h"),
        "the cursor must come back as soon as the region has nothing left to draw"
    );
}

#[test]
fn a_thousand_messages_leave_one_node_capped_at_512_chars() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("zlib-1.3.1");

    for i in 0..1000 {
        task.set_message(format!("CC file-{i}.o with a fairly long compiler line"));
    }

    let nodes = progress.nodes();
    assert_eq!(nodes.len(), 1, "1000 updates to one node must still be one node");
    assert!(
        nodes[0].text.chars().count() <= 512,
        "the stored text must never exceed the wire cap: got {} chars",
        nodes[0].text.chars().count()
    );
}

#[test]
fn a_message_with_escape_and_carriage_return_comes_back_with_neither() {
    let sink = Sink::default();
    let progress = region(&sink);
    let task = progress.task("zlib-1.3.1");

    task.set_message("progress: 50%\rdone\x1b[2Kmore\r\nstuff");

    let nodes = progress.nodes();
    assert_eq!(nodes.len(), 1);
    assert!(
        !nodes[0].text.contains('\r') && !nodes[0].text.contains('\x1b'),
        "control characters from untrusted build output must not survive onto the wire: {:?}",
        nodes[0].text
    );
}

#[test]
fn sanitise_truncates_with_a_visible_marker_and_never_exceeds_the_cap() {
    let long = "x".repeat(50);

    let result = sanitise(&long, 10);

    assert_eq!(result.chars().count(), 10, "a truncated result stays exactly at the cap");
    assert!(
        result.ends_with('…'),
        "truncation must be visible, not silently indistinguishable from a short message: {result:?}"
    );
}

#[test]
fn sanitise_leaves_short_text_untouched() {
    assert_eq!(sanitise("CC deflate.o", 512), "CC deflate.o");
}

#[test]
fn nodes_reports_the_tree_as_wire_types() {
    let sink = Sink::default();
    let progress = region(&sink);
    let package = progress.task("zlib-1.3.1");
    let command = package.child("make");
    command.set_message("CC deflate.o");

    let nodes = progress.nodes();
    assert_eq!(nodes.len(), 2, "a package and its command are two nodes");

    let root = &nodes[0];
    assert_eq!(root.label, "zlib-1.3.1");
    assert_eq!(root.parent, 0, "a top-level node's parent is the 0 sentinel");
    assert_eq!(root.depth, 0);
    assert_ne!(root.id, 0, "0 is reserved for \"no parent\", so a real id is never 0");
    assert!(root.started_usec > 0, "started_usec must be a real wall-clock reading");

    let child = &nodes[1];
    assert_eq!(child.label, "make");
    assert_eq!(child.parent, root.id, "the command's parent must be the package's wire id");
    assert_eq!(child.depth, 1);
    assert_eq!(child.kind, 1, "kind 1 is Message");
    assert_eq!(child.text, "CC deflate.o");
    assert_eq!(child.done, 0);
    assert_eq!(child.total, 0);
}

#[test]
fn a_disabled_region_reports_no_nodes() {
    let progress = Progress::disabled();
    let _task = progress.task("zlib-1.3.1");

    assert!(
        progress.nodes().is_empty(),
        "a disabled region opens no node in the first place, so there is nothing to report"
    );
}

#[test]
fn silent_mode_is_live_so_a_build_captures_into_it() {
    let progress = Progress::silent();
    let task = progress.task("zlib-1.3.1");

    assert!(
        task.is_live(),
        "sandbox.rs branches on is_live() to decide whether to capture a build's \
         stdout instead of inheriting it onto the daemon's own stdout"
    );
}

#[test]
fn silent_mode_tracks_nodes_exactly_like_a_live_region() {
    let progress = Progress::silent();
    let package = progress.task("zlib-1.3.1");
    let command = package.child("make");
    command.set_message("CC deflate.o");
    command.set_bytes(1024, Some(2048));

    let nodes = progress.nodes();
    assert_eq!(nodes.len(), 2, "bookkeeping runs exactly as it does for a live region");
    assert_eq!(nodes[1].kind, 2, "the latest report replaces the node's detail, as in live mode");
    assert_eq!(nodes[1].done, 1024);
    assert_eq!(nodes[1].total, 2048);

    drop(command);
    assert_eq!(
        progress.nodes().len(),
        1,
        "dropping a task removes its node under silent mode too"
    );
}

#[test]
fn silent_mode_spawns_no_ticker_thread() {
    let progress = Progress::silent();
    let _task = progress.task("zlib-1.3.1");

    // The spinner frame only ever advances inside `Progress::tick`, which
    // only ever runs on its own if a ticker thread is calling it. A live
    // region's ticker (`the_spinner_advances_when_the_region_ticks`, above)
    // would move this within one `TICK` (80ms); waiting several times that
    // long and finding the frame unchanged is direct evidence no such thread
    // exists for a silent region.
    let frame_of = |progress: &Progress| progress.snapshot()[0].chars().next();

    let before = frame_of(&progress);
    std::thread::sleep(Duration::from_millis(320));
    let after = frame_of(&progress);

    assert_eq!(
        before, after,
        "a silent region must spawn no ticker, so its spinner frame never advances on its own"
    );
}
