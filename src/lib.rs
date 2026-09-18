/// Build-file parsing, building and packaging.
pub mod bf;
/// A best-effort cancellation token threaded through a build.
pub mod cancel;
/// The caller-supplied environment a build runs against, instead of the
/// process's own cwd, `$PATH` and `$HOME`.
pub mod context;
/// Fetching a build file's sources over HTTP, hashing them as they land.
pub mod download;
/// Resolving a build file's dependency graph, and building it.
pub mod graph;
/// Package metadata written into each archive.
pub mod metadata;
/// Inferring the permissions a package actually needs, from its source, its
/// built objects and a traced execution.
pub mod perms;
/// Deriving a sandbox policy from the contents of a build file.
pub mod policy;
/// A live, redrawable region that reports what a build is doing right now.
pub mod progress;
/// Extracting and running a built package inside a sandbox.
pub mod run;
/// The hakoniwa jail that build steps run inside.
pub mod sandbox;
/// Ed25519 signing and verification of build files and packages.
pub mod signing;
/// Individual build steps and their stages.
pub mod step;
/// Types and framing that cross the boundary between the daemon and its
/// clients or its own worker.
pub mod wire;
/// RAII guards that auto-close build workspaces and sandboxed child processes.
pub mod workspace;
