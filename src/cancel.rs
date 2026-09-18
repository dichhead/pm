//! A best-effort cancellation token threaded through a build.
//!
//! Nothing in this crate spawns a build it does not wait for **today** - but a
//! daemon relaying a client's disconnect will need to ask an in-flight build
//! to stop, without anything so heavy as killing the process that runs it.
//! [`Cancel`] is that ask: a cheap flag a caller holds one end of and a
//! scheduler polls the other end of.
//!
//! # This is best-effort
//!
//! Tripping the token stops [`crate::graph::Graph`] handing out a package that
//! has not started, and stops [`crate::download::Downloader`] writing another
//! chunk of a download in progress. It does **not** reach into a package
//! that is already mid-build: a step's subprocess keeps running to whatever
//! end it was going to reach, because nothing here kills it. Say only that
//! much, everywhere this type is used.

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

/// The action [`Cancel::cancel`] runs beyond setting its flag - see the doc on
/// the `action` field of [`Cancel`] for what it is and why it has to be this
/// shape.
type Wakeup = Arc<dyn Fn() + Send + Sync>;

/// A cheap, clonable flag asking an in-flight build to stop starting new work.
///
/// Every clone refers to the same underlying flag, so a caller can keep one
/// handle to trip it while a scheduler holds another to poll it. Backed by an
/// [`AtomicBool`] rather than a `Mutex<bool>` because for a plain poller -
/// [`crate::download::Downloader`] between chunks, or anyone just asking "has
/// this fired yet" - the only operations are "set" and "read", neither of
/// which needs to observe the other's timing beyond what atomics already
/// guarantee.
///
/// A scheduler that PARKS a worker on a condvar needs more than that; see
/// [`Cancel::register_wakeup`].
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    /// An action [`Cancel::cancel`] runs in addition to setting `flag`, if a
    /// scheduler has registered one.
    ///
    /// This is deliberately opaque to `Cancel` - it does not name
    /// [`crate::graph::Graph`]'s scheduler state, and knows nothing about it.
    /// What it buys is real: [`crate::graph::Graph::build_with`] registers a
    /// closure that locks the *same* mutex its workers already hold across
    /// their whole check-then-park sequence, sets whatever the scheduler
    /// checks WHILE HOLDING that lock, then releases it and only afterwards
    /// notifies the condvar. The notify does not need to happen before the
    /// unlock - a condvar does not require that, and this one does not do
    /// it. What closes the race is that the WRITE happens under the same
    /// lock a worker's check-then-park sequence also holds throughout: by
    /// the time the write lands, a worker has either not yet checked (and
    /// will see the new value) or has already parked (and is registered as
    /// a waiter the notify will reach). There is no instant where the flag
    /// is set and a worker holds neither the lock nor a wait registration.
    /// A bare flag store outside any lock, followed by a separately locked
    /// `notify_all`, gives you no such thing: a worker can observe the flag
    /// still clear, decide to park, and only reach `Condvar::wait` after the
    /// notification already fired and was dropped on the floor, because a
    /// condvar remembers nothing. It would then sleep until some unrelated
    /// package happened to settle and notify for its own reasons - possibly
    /// the rest of that package's build time later.
    action: Arc<Mutex<Option<Wakeup>>>,
}

impl Cancel {
    /// A token that has not been tripped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the token: set the flag, and run whatever action a scheduler
    /// registered via [`Cancel::register_wakeup`].
    ///
    /// The registered action, when there is one, is what actually reaches a
    /// worker parked on a condvar promptly and correctly - see the field doc
    /// on `action`. Without one registered (nobody is scheduling against this
    /// token, or nobody has started yet), only the flag is set, which is
    /// exactly what a plain poller like [`crate::download::Downloader`] needs.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        let action = self
            .action
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(action) = action {
            action();
        }
    }

    /// Whether [`Cancel::cancel`] has been called on this token or a clone of it.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Register the action [`Cancel::cancel`] runs to reach a parked worker.
    ///
    /// Crate-private: [`crate::graph::Graph::build_with`] is the only caller.
    /// It registers a closure that locks its own scheduler mutex, sets the
    /// cancellation flag the scheduler checks WHILE HOLDING that lock, then
    /// releases it and notifies its condvar - see the `action` field for why
    /// setting the flag under that lock, not the notify's timing relative to
    /// the unlock, is what actually closes the race. Replaces whatever was
    /// registered before.
    pub(crate) fn register_wakeup<F>(&self, action: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        *self.action.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(action));
    }

    /// Forget the registered action, once the scheduler it belonged to has no
    /// more workers left to wake.
    ///
    /// Crate-private: called by [`crate::graph::Graph::build_with`] after
    /// every worker has joined, so a token kept alive past one build (a
    /// caller is free to hold and inspect it afterwards) does not keep that
    /// build's scheduler state pinned in memory, and so a later `cancel()` on
    /// an already-finished build's token is a harmless flag set rather than a
    /// call into a scheduler that no longer exists.
    pub(crate) fn clear_wakeup(&self) {
        *self.action.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl std::fmt::Debug for Cancel {
    /// The registered action has no useful `Debug` - it is an opaque
    /// closure - so this reports only what the token itself observes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cancel")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}
