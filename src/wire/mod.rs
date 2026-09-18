//! Types and framing that cross the boundary between the daemon and its
//! clients or its own worker.
//!
//! Nothing here opens a socket, binds a bus name or defines a
//! `#[zbus::interface]` - this module only freezes the shapes that will
//! travel once one exists. [`types`] is the D-Bus payload: every struct
//! derives `zbus::zvariant::Type`, and `tests/wire.rs` pins each one's
//! `SIGNATURE` as a string literal, so a field reorder here fails a test
//! instead of mis-decoding a live message on the bus. [`frame`] is the
//! unrelated length-prefixed framing the daemon will use on its own worker's
//! socketpair - not D-Bus, and carrying no such contract. [`error`] holds the
//! `org.pm1.Error.*` name constants and the conversion from an in-process
//! `miette::Report` into something a client with no shared memory can read.

/// D-Bus error names, and the conversion from a `miette::Report` into a
/// wire-safe [`types::Diagnostic`].
pub mod error;
/// Length-prefixed framing for the worker's socketpair. Not D-Bus.
pub mod frame;
/// The structs and enums that travel as D-Bus method arguments and replies.
pub mod types;
