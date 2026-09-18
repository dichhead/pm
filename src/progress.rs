//! A live, redrawable region at the bottom of the terminal.
//!
//! `pm` reports a build two ways today: `tracing` lines on stderr, and the
//! build command's own output. Neither survives concurrency - the moment two
//! packages build at once, two `make`s interleave on one terminal and the
//! result is unreadable. This module owns the bottom few lines of the screen
//! instead, and renders a tree of what is *currently* in flight: one line per
//! package, indented lines for the commands and downloads running under it.
//!
//! Everything else keeps scrolling above the region. [`Progress::println`] is
//! the seam: it clears the region, writes a line as ordinary scrollback, then
//! draws the region again underneath. Wiring that into `tracing` as a
//! [`MakeWriter`] is what lets every existing `info!` keep working untouched.
//!
//! # Lines are owned, not named
//!
//! A line is a [`Task`], and dropping the `Task` removes the line. Build code
//! is threaded with `?` and `try_for_each`, so any scheme where a line has to
//! be closed by hand leaks one the first time a step fails. Ownership makes the
//! failure path draw correctly for free - including a package's children, which
//! go when the package does.
//!
//! # Doing nothing is a supported mode
//!
//! [`Progress::disabled`] renders nothing and still forwards `println`, so
//! `--verbose`, a piped stdout and a test all take the same path through the
//! build as a live terminal does. There is no second code path to keep honest.
//!
//! # A third mode for a daemon with no terminal
//!
//! [`Progress::silent`] is neither of the above: it tracks nodes exactly as a
//! live region does - [`Task::is_live`] is true, so [`crate::sandbox`]
//! captures a build's stdout instead of inheriting it - but spawns no ticker
//! and draws nothing, ever. A daemon has no terminal to redraw and no client
//! watching every `set_message`, so it polls [`Progress::nodes`] on its own
//! schedule instead.

use std::{
    io::{self, Write},
    sync::{Arc, Mutex, MutexGuard, Weak},
    thread::{sleep, spawn},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use dialoguer::console::Term;
use tracing_subscriber::fmt::MakeWriter;

use crate::wire::types::ProgressNode;

/// Frames of the spinner, advanced once per [`Progress::tick`].
const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// How long the ticker sleeps between redraws.
///
/// A command can be silent for ten seconds while it links; the ticker is what
/// keeps its line moving in the meantime, so the region says "working" rather
/// than "hung".
const TICK: Duration = Duration::from_millis(80);

/// Columns a child line is indented by, per level of nesting.
const INDENT: usize = 4;

/// Width assumed when the terminal will not say how wide it is.
const FALLBACK_WIDTH: usize = 80;

/// Cap applied to a node's label and message text by [`sanitise`].
///
/// A build file is untrusted input and its commands' stdout reaches
/// [`Task::set_message`] verbatim, one line at a time (`sandbox::pump` reads
/// with `read_until(b'\n')`, so one newline-free line is buffered whole
/// regardless of length). Rendering used to be the only thing that bounded
/// it, truncating to terminal width at draw time - putting a node on a wire
/// deletes that cap along with the terminal, so this is now the real one.
const MESSAGE_CAP: usize = 512;

/// A live region at the bottom of the terminal.
///
/// Cloning is cheap and every clone refers to the same region, so this can be
/// handed to as many threads as there is work.
#[derive(Clone)]
pub struct Progress {
    inner: Arc<Inner>,
}

/// The shared region. Dropping the last handle clears the screen and stops the
/// ticker.
struct Inner {
    /// `None` when there is no region: `println` still writes through.
    screen: Mutex<Screen>,
    live: bool,
}

/// Everything a redraw needs, behind one lock so a draw is never interleaved.
struct Screen {
    canvas: Canvas,
    nodes: Vec<Node>,
    next_id: u64,
    frame: usize,
    /// How many lines the last draw left on screen, and therefore how many the
    /// next one has to erase.
    drawn: usize,
    /// Whether this region is the one currently hiding the cursor.
    ///
    /// Tracked rather than assumed: every `pm` subcommand builds a region but
    /// only a build ever opens a line on one, and a region that hid the cursor
    /// merely by existing would leave `pm run`'s prompt - and the package's own
    /// binary - running without one.
    cursor_hidden: bool,
}

/// Where the region is drawn, and how wide it is.
enum Canvas {
    /// A real terminal, which knows its own width and how to erase itself.
    Terminal(Term),
    /// Any writer, at a fixed width. Used by tests and by anything redirecting
    /// the region somewhere that is not a terminal.
    Writer {
        sink: Box<dyn Write + Send>,
        width: usize,
    },
    /// Nowhere. Every draw primitive is a no-op for this variant, and it
    /// holds no writer at all, so [`Progress::silent`] cannot write a byte
    /// even by accident - there is nothing here to write to.
    Silent,
}

/// One line of the region.
struct Node {
    id: u64,
    parent: Option<u64>,
    depth: usize,
    label: String,
    detail: Detail,
    /// When this line was opened, kept only for [`Screen::render_node`]'s
    /// elapsed-time column. `Instant` has no fixed epoch, so it cannot answer
    /// "when" for anything outside this process.
    started: Instant,
    /// The same moment as `started`, in `CLOCK_REALTIME` microseconds, which
    /// DOES survive a process boundary. This is what [`ProgressNode`] reports;
    /// `started` above is never sent anywhere.
    started_usec: u64,
}

/// What a line says after its label.
enum Detail {
    /// Nothing yet - the work has started but has not reported.
    Silent,
    /// The last thing the work said, usually a line of its output.
    Message(String),
    /// A transfer, with the total if the server declared one.
    Bytes { done: u64, total: Option<u64> },
}

impl Node {
    /// This node as the wire type a poller reads, sanitised and with the wall
    /// clock in place of `started`.
    ///
    /// Every string is sanitised again here even though [`Task::set_message`]
    /// already sanitised it at ingest: this is the seam that actually leaves
    /// the process, so it earns its own guarantee rather than trusting a
    /// different call site to have kept one.
    ///
    /// Ids are shifted by one: internal ids start at 0, but a
    /// [`ProgressNode`] uses `parent == 0` to mean "no parent", so a real
    /// node can never be numbered 0 on the wire.
    fn to_wire(&self) -> ProgressNode {
        let (kind, text, done, total) = match &self.detail {
            Detail::Silent => (0, String::new(), 0, 0),
            Detail::Message(message) => (1, sanitise(message, MESSAGE_CAP), 0, 0),
            Detail::Bytes { done, total } => (2, String::new(), *done, total.unwrap_or(0)),
        };

        ProgressNode {
            id: wire_id(self.id),
            parent: self.parent.map_or(0, wire_id),
            depth: u32::try_from(self.depth).unwrap_or(u32::MAX),
            label: sanitise(&self.label, MESSAGE_CAP),
            kind,
            text,
            done,
            total,
            started_usec: self.started_usec,
        }
    }
}

/// Map an internal, 0-based node id to the 1-based id [`ProgressNode`] uses,
/// so `parent == 0` is free to mean "no parent" without colliding with a
/// real node's id.
fn wire_id(id: u64) -> u32 {
    u32::try_from(id.saturating_add(1)).unwrap_or(u32::MAX)
}

impl Progress {
    /// A region on stderr, if stderr is a terminal.
    ///
    /// Falls back to [`Progress::disabled`] when it is not: a redirected or
    /// piped stderr has nobody watching it redraw, and the escape sequences
    /// would only corrupt the log someone is capturing.
    #[must_use]
    pub fn to_terminal() -> Self {
        let term = Term::stderr();
        if term.is_term() {
            Self::live(Canvas::Terminal(term))
        } else {
            Self::passthrough(Box::new(term))
        }
    }

    /// A region that draws nothing, forwarding log lines to stderr.
    ///
    /// What `--verbose` selects, and what every caller with no terminal to own
    /// should use.
    #[must_use]
    pub fn disabled() -> Self {
        Self::passthrough(Box::new(Term::stderr()))
    }

    /// A region drawn into `sink` at a fixed `width`.
    #[must_use]
    pub fn to_writer(sink: Box<dyn Write + Send>, width: usize) -> Self {
        Self::live(Canvas::Writer { sink, width })
    }

    /// A `sink` that receives log lines and no region.
    #[must_use]
    pub fn passthrough(sink: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(Inner {
                screen: Mutex::new(Screen::new(Canvas::Writer {
                    sink,
                    width: FALLBACK_WIDTH,
                })),
                live: false,
            }),
        }
    }

    /// A region that tracks nodes but draws nothing and spawns no thread.
    ///
    /// What a daemon uses. `sandbox.rs` decides whether to capture a build
    /// command's stdout by asking [`Task::is_live`], and a daemon has no
    /// terminal to inherit onto instead - the journal is the wrong place for
    /// a package's raw, unbuffered stdout to land. This gives a daemon a
    /// [`Progress`] that answers `is_live` truthfully, with a real
    /// [`Canvas::Silent`] behind it that holds no writer at all - so nothing
    /// here can draw an escape sequence into a log some other process is
    /// reading - and no ticker thread that would need to be told to stop.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: Arc::new(Inner {
                screen: Mutex::new(Screen::new(Canvas::Silent)),
                live: true,
            }),
        }
    }

    /// Build a drawing region and start the ticker that animates it.
    fn live(canvas: Canvas) -> Self {
        let progress = Self {
            inner: Arc::new(Inner {
                screen: Mutex::new(Screen::new(canvas)),
                live: true,
            }),
        };

        // The ticker holds a `Weak`: an `Arc` back to the region it animates is
        // a cycle nothing breaks, so the region would never be cleared and the
        // process would not exit. Failing to upgrade IS the shutdown signal.
        let weak = Arc::downgrade(&progress.inner);
        spawn(move || tick_until_dropped(&weak));

        progress
    }

    /// Open a top-level line, for a package.
    pub fn task(&self, label: impl Into<String>) -> Task {
        self.open(None, 0, label.into())
    }

    /// The lines the region would draw right now.
    ///
    /// Empty when the region is disabled. Exposed because it is the honest way
    /// to see what the region says without a terminal to read it off.
    #[must_use]
    pub fn snapshot(&self) -> Vec<String> {
        if !self.inner.live {
            return Vec::new();
        }
        let screen = self.lock();
        screen.render()
    }

    /// A snapshot of the current tree as wire types.
    ///
    /// What a caller polls on a schedule of its own choosing instead of
    /// receiving one event per update - the coalescing [`Progress::silent`]
    /// exists to provide, in place of the volume `set_bytes` produces on its
    /// own (once per 64 KiB of a transfer) or `set_message` (once per line of
    /// a build's output). Works on any region, live or not: an empty tree
    /// simply produces an empty `Vec`, same as [`Progress::snapshot`].
    #[must_use]
    pub fn nodes(&self) -> Vec<ProgressNode> {
        let screen = self.lock();
        screen.nodes.iter().map(Node::to_wire).collect()
    }

    /// Advance the spinner one frame and redraw.
    ///
    /// Called by the ticker; public so a caller can drive the animation itself
    /// rather than depending on a background thread's timing.
    pub fn tick(&self) {
        if !self.inner.live {
            return;
        }
        let mut screen = self.lock();
        screen.frame = screen.frame.wrapping_add(1);
        screen.draw();
    }

    /// A `tracing` writer that puts log lines above the region.
    ///
    /// Hand this to `tracing_subscriber`'s `with_writer`. It does not keep the
    /// region alive: see [`LogSink`].
    #[must_use]
    pub fn log_sink(&self) -> LogSink {
        LogSink {
            region: Arc::downgrade(&self.inner),
        }
    }

    /// Write `line` as scrollback above the region.
    ///
    /// The region is erased, the line is written where it will scroll away
    /// normally, and the region is drawn again underneath.
    pub fn println(&self, line: &str) {
        let mut screen = self.lock();
        screen.erase();
        screen.write_line(line);
        screen.draw();
    }

    /// Register a node and return the handle that owns it.
    fn open(&self, parent: Option<u64>, depth: usize, label: String) -> Task {
        if !self.inner.live {
            return Task {
                progress: self.clone(),
                id: None,
                depth,
                owns_line: true,
            };
        }

        let mut screen = self.lock();
        let id = screen.push(parent, depth, label);
        screen.draw();
        drop(screen);

        Task {
            progress: self.clone(),
            id: Some(id),
            depth,
            owns_line: true,
        }
    }

    /// Remove a node and everything nested under it.
    fn close(&self, id: u64) {
        let mut screen = self.lock();
        screen.remove(id);
        screen.draw();
    }

    /// Replace what a node says after its label.
    fn describe(&self, id: u64, detail: Detail) {
        let mut screen = self.lock();
        if let Some(node) = screen.nodes.iter_mut().find(|node| node.id == id) {
            node.detail = detail;
        }
        screen.draw();
    }

    /// Take the screen lock, surviving a poisoned mutex.
    ///
    /// A build that panics while a line is open would otherwise poison this
    /// lock and turn every later draw into a second panic, burying the first.
    /// The region is cosmetic; a torn frame is a far better outcome than losing
    /// the report of what actually went wrong.
    fn lock(&self) -> MutexGuard<'_, Screen> {
        self.inner
            .screen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        // Poisoning must not short-circuit this. A build that panicked is
        // exactly the case where the region is still on screen and the cursor
        // is still hidden, and bailing out here would hand the user back a
        // shell with an invisible cursor.
        let screen = self
            .screen
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        screen.erase();
        screen.set_cursor_hidden(false);
    }
}

/// Redraw every [`TICK`] until the region it animates is dropped.
fn tick_until_dropped(weak: &Weak<Inner>) {
    loop {
        sleep(TICK);
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let progress = Progress { inner };
        progress.tick();
    }
}

impl Screen {
    fn new(canvas: Canvas) -> Self {
        Self {
            canvas,
            nodes: Vec::new(),
            next_id: 0,
            frame: 0,
            drawn: 0,
            cursor_hidden: false,
        }
    }

    /// Add a node, keeping the flat list in tree order.
    ///
    /// A child is inserted directly after its parent's last descendant rather
    /// than at the end, so a second package opening a line does not push the
    /// first package's commands underneath it.
    fn push(&mut self, parent: Option<u64>, depth: usize, label: String) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let node = Node {
            id,
            parent,
            depth,
            label,
            detail: Detail::Silent,
            started: Instant::now(),
            started_usec: now_usec(),
        };

        match parent.and_then(|parent| self.end_of_subtree(parent)) {
            Some(index) => self.nodes.insert(index, node),
            None => self.nodes.push(node),
        }
        id
    }

    /// One past the last node nested under `parent`.
    fn end_of_subtree(&self, parent: u64) -> Option<usize> {
        let start = self.nodes.iter().position(|node| node.id == parent)?;
        let depth = self.nodes[start].depth;
        let tail = self.nodes[start + 1..]
            .iter()
            .position(|node| node.depth <= depth);
        Some(tail.map_or(self.nodes.len(), |offset| start + 1 + offset))
    }

    /// Drop `id` and every node descending from it.
    ///
    /// The descendants matter: a package whose build fails is dropped while its
    /// command lines are still registered, and leaving those behind would
    /// render commands that belong to nothing.
    fn remove(&mut self, id: u64) {
        let mut doomed = vec![id];
        let mut index = 0;
        while index < doomed.len() {
            let parent = doomed[index];
            let children = self
                .nodes
                .iter()
                .filter(|node| node.parent == Some(parent))
                .map(|node| node.id);
            doomed.extend(children.collect::<Vec<_>>());
            index += 1;
        }
        self.nodes.retain(|node| !doomed.contains(&node.id));
    }

    /// How wide a line may be before it wraps.
    fn width(&self) -> usize {
        match &self.canvas {
            Canvas::Terminal(term) => term
                .size_checked()
                .map_or(FALLBACK_WIDTH, |(_, columns)| columns as usize),
            Canvas::Writer { width, .. } => *width,
            // Nothing ever renders a `Silent` canvas, but `render` still runs
            // as a pure computation - see `Progress::nodes` and `snapshot` -
            // so this needs an answer, not a panic.
            Canvas::Silent => FALLBACK_WIDTH,
        }
    }

    /// Render every node to a line, without touching the terminal.
    fn render(&self) -> Vec<String> {
        let width = self.width();
        let now = Instant::now();
        self.nodes
            .iter()
            .map(|node| self.render_node(node, width, now))
            .collect()
    }

    /// One line: spinner, label and detail on the left, elapsed on the right.
    fn render_node(&self, node: &Node, width: usize, now: Instant) -> String {
        let frame = FRAMES[self.frame % FRAMES.len()];
        let mut left = format!("{}{frame} {}", " ".repeat(node.depth * INDENT), node.label);
        match &node.detail {
            Detail::Silent => {}
            Detail::Message(message) => left.push_str(&format!("  {message}")),
            Detail::Bytes { done, total } => {
                let transferred = match total {
                    Some(total) => format!("{}/{}", human_bytes(*done), human_bytes(*total)),
                    None => human_bytes(*done),
                };
                left.push_str(&format!("  {transferred}"));
            }
        }

        let right = format!(
            "[{}]",
            format_elapsed(now.saturating_duration_since(node.started))
        );
        let left = collapse_control(&left);

        // A line wider than the terminal wraps, and a wrapped line makes
        // `clear_last_lines` erase the wrong number of rows - the region walks
        // up the screen eating scrollback. Truncation is not cosmetic here.
        let room = width.saturating_sub(right.chars().count() + 1);
        let left: String = left.chars().take(room).collect();
        let gap = width.saturating_sub(left.chars().count() + right.chars().count());
        format!("{left}{}{right}", " ".repeat(gap))
    }

    /// Erase the region, leaving the cursor where the region started.
    fn erase(&mut self) {
        if self.drawn == 0 {
            return;
        }
        match &mut self.canvas {
            Canvas::Terminal(term) => {
                term.clear_last_lines(self.drawn).ok();
            }
            Canvas::Writer { sink, .. } => {
                // Move up one line and clear it, `drawn` times over: the same
                // thing `clear_last_lines` does, for a sink that is not a Term.
                for _ in 0..self.drawn {
                    write!(sink, "\x1b[1A\x1b[2K").ok();
                }
            }
            Canvas::Silent => {}
        }
        self.drawn = 0;
    }

    /// Erase and redraw the region in place.
    fn draw(&mut self) {
        self.erase();
        let lines = self.render();

        // The cursor is hidden only while there is a region to hide it for: it
        // would otherwise chase the redraw across the screen, but an empty
        // region has nothing to chase and no business owning it.
        self.set_cursor_hidden(!lines.is_empty());

        for line in &lines {
            self.write_line(line);
        }
        self.drawn = lines.len();
    }

    /// Hide or show the cursor, if that is not already its state.
    fn set_cursor_hidden(&mut self, hidden: bool) {
        if hidden == self.cursor_hidden {
            return;
        }
        match (&mut self.canvas, hidden) {
            (Canvas::Terminal(term), true) => {
                term.hide_cursor().ok();
            }
            (Canvas::Terminal(term), false) => {
                term.show_cursor().ok();
            }
            (Canvas::Writer { sink, .. }, true) => {
                write!(sink, "\x1b[?25l").ok();
            }
            (Canvas::Writer { sink, .. }, false) => {
                write!(sink, "\x1b[?25h").ok();
            }
            // A `Silent` canvas has no cursor to hide: this only tracks the
            // boolean so `Inner::drop`'s unconditional restore has an inert
            // no-op to call, exactly as it does for an empty live region.
            (Canvas::Silent, _) => {}
        }
        self.cursor_hidden = hidden;
    }

    /// Write one line and a newline, wherever the canvas points.
    fn write_line(&mut self, line: &str) {
        match &mut self.canvas {
            Canvas::Terminal(term) => {
                term.write_line(line).ok();
            }
            Canvas::Writer { sink, .. } => {
                writeln!(sink, "{line}").ok();
                sink.flush().ok();
            }
            Canvas::Silent => {}
        }
    }
}

/// A single line of the region, owned by whoever is doing the work.
///
/// Dropping it removes the line, along with any lines opened under it.
#[must_use = "a Task removes its line as soon as it is dropped"]
pub struct Task {
    progress: Progress,
    /// `None` when the region is disabled, which makes every method a no-op.
    id: Option<u64>,
    depth: usize,
    /// Whether dropping this removes the line. False for a [`Task::handle`],
    /// which refers to a line somebody else owns.
    owns_line: bool,
}

impl Task {
    /// A task attached to no region. Every method on it does nothing.
    ///
    /// Lets a value that may or may not be reporting progress hold a `Task`
    /// outright instead of an `Option<Task>`.
    pub fn detached() -> Self {
        Self {
            progress: Progress::disabled(),
            id: None,
            depth: 0,
            owns_line: true,
        }
    }

    /// A second reference to this same line, which does not close it.
    ///
    /// Lets a value that needs to report under an existing line - a
    /// [`crate::sandbox::BuildSandbox`] reporting under its package - hold a
    /// `Task` of its own without the line vanishing when that value is dropped
    /// or opening a redundant level of nesting under it.
    pub fn handle(&self) -> Self {
        Self {
            progress: self.progress.clone(),
            id: self.id,
            depth: self.depth,
            owns_line: false,
        }
    }

    /// Whether this task is attached to a region that is actually drawing.
    ///
    /// Callers use it to decide whether the terminal is theirs to write to.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.id.is_some()
    }

    /// Open a line nested under this one.
    pub fn child(&self, label: impl Into<String>) -> Self {
        match self.id {
            Some(parent) => self
                .progress
                .open(Some(parent), self.depth + 1, label.into()),
            None => Self::detached(),
        }
    }

    /// Say what this work is doing now, replacing whatever it said before.
    ///
    /// `message` is usually a line of a build's own output, which is
    /// untrusted input, so it is sanitised on the way in through
    /// [`sanitise`] - the same cap [`Progress::nodes`] later re-applies at
    /// the point the node actually leaves the process.
    pub fn set_message(&self, message: impl Into<String>) {
        if let Some(id) = self.id {
            let message = sanitise(&message.into(), MESSAGE_CAP);
            self.progress.describe(id, Detail::Message(message));
        }
    }

    /// Report a transfer: bytes so far, and the total if one is known.
    pub fn set_bytes(&self, done: u64, total: Option<u64>) {
        if let Some(id) = self.id {
            self.progress.describe(id, Detail::Bytes { done, total });
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let (true, Some(id)) = (self.owns_line, self.id) {
            self.progress.close(id);
        }
    }
}

/// A `tracing` writer factory that routes log lines above the region.
///
/// It holds a **weak** reference on purpose. `tracing`'s global subscriber is
/// installed for the life of the process and never dropped, so a strong one
/// here would keep the region alive past the end of `main` - the region would
/// never be erased, the cursor never restored, and the ticker thread never
/// stopped. When the region is gone, lines go straight to stderr instead.
#[derive(Clone)]
pub struct LogSink {
    region: Weak<Inner>,
}

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            region: self.region.clone(),
            buffer: Vec::new(),
        }
    }
}

/// Routes `tracing` output through [`Progress::println`] so log lines land
/// above the region instead of through it.
pub struct LogWriter {
    region: Weak<Inner>,
    buffer: Vec<u8>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit();
        Ok(())
    }
}

impl LogWriter {
    /// Hand every complete line in the buffer to the region.
    fn emit(&mut self) {
        let text = String::from_utf8_lossy(&self.buffer).into_owned();
        let lines = text.lines().filter(|line| !line.trim().is_empty());

        match self.region.upgrade() {
            Some(inner) => {
                let progress = Progress { inner };
                for line in lines {
                    progress.println(line);
                }
            }
            // The region is gone - after `main` returns, or in a `--verbose`
            // run that never had one. Logging must outlive it either way.
            None => {
                let mut stderr = io::stderr();
                for line in lines {
                    writeln!(stderr, "{line}").ok();
                }
            }
        }

        self.buffer.clear();
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        // `tracing` formats a whole event into the writer and drops it; the
        // trailing line has had no flush, so this is where it gets written.
        self.emit();
    }
}

/// The current wall-clock time, in `CLOCK_REALTIME` microseconds.
///
/// A monotonic `Instant` cannot cross a process boundary - it has no fixed
/// epoch, so two processes' clocks agree on nothing. This is what
/// [`ProgressNode::started_usec`] needs instead. Falls back to `0` rather
/// than panicking on the one system-clock error `SystemTime` can report - the
/// clock reading before the Unix epoch - since a wrong timestamp on a
/// progress line is not worth crashing a build over.
fn now_usec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Render a byte count the way a person reads one.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    const STEP: f64 = 1024.0;

    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= STEP && unit + 1 < UNITS.len() {
        size /= STEP;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes}B")
    } else {
        format!("{size:.1}{}", UNITS[unit])
    }
}

/// Render how long something has been running.
fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    }
}

/// Flatten anything that would move the cursor out of the line it is on.
///
/// A message is usually a line of a build's own output, which is free to carry
/// carriage returns, tabs and escape sequences. Any of those inside the region
/// desynchronises the redraw from what is on screen.
fn collapse_control(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' {
                ' '
            } else if c.is_control() {
                '\u{fffd}'
            } else {
                c
            }
        })
        .filter(|c| *c != '\u{fffd}')
        .collect()
}

/// The single choke point untrusted text passes through before it can reach
/// a wire type.
///
/// A build file is untrusted input, and its commands' stdout reaches these
/// strings verbatim - a package's own `make` output becomes a progress
/// message, and a failed step's captured stdout AND stderr become a
/// [`crate::wire::types::Diagnostic`]. Every wire constructor that carries
/// build-controlled text MUST pass it through here first: [`Task::set_message`]
/// does, and so does `From<&miette::Report> for Diagnostic` in
/// [`crate::wire::error`].
///
/// Two things happen, in order: control characters are collapsed by reusing
/// [`collapse_control`] - the same logic that already protects the terminal
/// render from a carriage return or an escape sequence - and the result is
/// truncated to `cap` characters. A truncated result always ends in a
/// visible `…` so a capped message is never mistaken for one that simply
/// ended there.
#[must_use]
pub fn sanitise(text: &str, cap: usize) -> String {
    let collapsed = collapse_control(text);
    if collapsed.chars().count() <= cap {
        return collapsed;
    }
    if cap == 0 {
        return String::new();
    }

    let mut truncated: String = collapsed.chars().take(cap - 1).collect();
    truncated.push('…');
    truncated
}
