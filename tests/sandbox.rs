//! Tests for the RAII guards in [`pm::workspace`] and for running a package
//! inside the hakoniwa sandbox.
//!
//! The sandboxed tests need unprivileged user namespaces, which plenty of CI
//! images do not grant, so they are `#[ignore]`d and the default `cargo test`
//! run stays green everywhere. Run them with:
//!
//! ```text
//! cargo test --test sandbox -- --ignored
//! ```
//!
//! The workspace guard tests below need nothing special and always run.

use std::fs::{read, read_to_string, remove_dir_all, write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use pm::bf::{BuildFile, BuildOptions};
use pm::context::BuildContext;
use pm::progress::Progress;
use pm::run::PackageRunner;
use pm::signing::{SigningKey, TrustStore, sign_file};
use pm::workspace::Workspace;
use serde::Serialize;
use serde_yaml::to_string;
use tempfile::tempdir;

#[test]
fn a_workspace_hands_out_a_real_directory() {
    let workspace = Workspace::new("usable").expect("create a workspace");

    assert!(workspace.path().is_dir());
    let file = workspace.path().join("scratch");
    write(&file, b"work in progress").expect("the workspace must be writable");
    assert_eq!(read(&file).expect("read it back"), b"work in progress");
}

#[test]
fn two_workspaces_do_not_share_a_directory() {
    let first = Workspace::new("first").expect("create a workspace");
    let second = Workspace::new("second").expect("create a workspace");

    assert_ne!(first.path(), second.path());
}

#[test]
fn a_workspace_removes_its_directory_when_dropped() {
    let path = {
        let workspace = Workspace::new("transient").expect("create a workspace");
        let path = workspace.path().to_path_buf();
        write(path.join("leftover"), b"junk").expect("write into the workspace");
        path
    };

    assert!(
        !path.exists(),
        "a dropped workspace must take its contents with it: {}",
        path.display()
    );
}

#[test]
fn keep_leaks_the_directory_for_post_mortem_inspection() {
    let path = {
        let mut workspace = Workspace::new("kept").expect("create a workspace");
        workspace.keep();
        write(workspace.path().join("evidence"), b"why the build failed")
            .expect("write into the workspace");
        workspace.path().to_path_buf()
    };

    assert!(
        path.is_dir(),
        "keep() must retain the directory past the drop"
    );
    assert_eq!(
        read_to_string(path.join("evidence")).expect("the evidence must survive"),
        "why the build failed"
    );

    // The guard gave up ownership, so the test cleans up after itself.
    remove_dir_all(&path).expect("clean up the retained workspace");
}

#[test]
fn persist_moves_an_artifact_out_before_the_workspace_goes_away() {
    let elsewhere = tempdir().expect("destination directory");
    let destination = elsewhere.path().join("moved.cpkg");

    let workspace_path;
    let moved = {
        let workspace = Workspace::new("persisting").expect("create a workspace");
        workspace_path = workspace.path().to_path_buf();
        let artifact = workspace.path().join("artifact.cpkg");
        write(&artifact, b"archive bytes").expect("stage an artifact");
        workspace
            .persist(&artifact, &destination)
            .expect("persisting an artifact must succeed")
    };

    assert!(moved.is_file(), "persist must return a usable path");
    assert_eq!(
        read(&moved).expect("read the moved artifact"),
        b"archive bytes"
    );
    assert_eq!(
        read(&destination).expect("read the destination"),
        b"archive bytes"
    );
    assert!(
        !workspace_path.exists(),
        "persist consumes the guard, so the workspace itself must be gone"
    );
}

#[test]
fn persist_to_an_unwritable_destination_is_an_error_not_a_panic() {
    let workspace = Workspace::new("doomed-persist").expect("create a workspace");
    let artifact = workspace.path().join("artifact.cpkg");
    write(&artifact, b"archive bytes").expect("stage an artifact");

    assert!(
        workspace
            .persist(&artifact, Path::new("/pm-integration-test/nope/out.cpkg"))
            .is_err(),
        "persisting into a nonexistent directory must return a diagnostic"
    );
}

/// One step of a build file, shaped for serialisation into YAML.
#[derive(Serialize)]
struct StepSpec {
    stage: &'static str,
    dl_urls: Option<()>,
    name: &'static str,
    run: Vec<String>,
}

/// A whole build file, shaped for serialisation into YAML.
#[derive(Serialize)]
struct BuildSpec {
    name: String,
    version: Vec<String>,
    dependencies: Vec<String>,
    steps: Vec<StepSpec>,
}

/// Builds a package named `name` whose install step runs `script`, returning the
/// archive path plus the directory that owns it.
///
/// `Step` execs commands directly with no shell, so `$DESTDIR` does not expand
/// in a command string. The staging goes into a script file invoked as
/// `/bin/sh <script>` - two plain words - and the shell interpreting the script
/// expands `$DESTDIR` from the environment `Step` set for it.
fn package_staging(name: &str, script: &str) -> (tempfile::TempDir, PathBuf) {
    let work = tempdir().expect("work directory");
    let stage = work.path().join("stage.sh");
    write(&stage, script).expect("write the staging script");
    let commands = [format!("/bin/sh {}", stage.display())];
    let spec = BuildSpec {
        name: name.into(),
        version: vec!["0".into(), "1".into()],
        dependencies: Vec::new(),
        steps: vec![StepSpec {
            stage: "Install",
            dl_urls: None,
            name: "stage",
            run: commands.to_vec(),
        }],
    };

    let build_file = work.path().join("build.yaml");
    write(
        &build_file,
        to_string(&spec).expect("the build file must serialise"),
    )
    .expect("write the build file");

    let build = BuildFile::load_unverified(&build_file).expect("load the build file");
    // `output_dir` is pointed at `work` explicitly, rather than moving the
    // process's current directory there: the whole point of `BuildContext` is
    // that this test's archive lands in ITS OWN directory even while sibling
    // tests in this binary run the same build concurrently, each with their
    // own `work`.
    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_output_dir(work.path().to_path_buf());
    let archive = build
        .run_with_progress_in(&ctx, BuildOptions::default(), &Progress::disabled())
        .expect("the build must succeed");

    sign(&archive, work.path());
    (work, archive)
}

/// Config directory holding the signing key and the trust store for a test
/// package, laid out the way `pm` expects under `$XDG_CONFIG_HOME`.
fn config_dir(work: &Path) -> PathBuf {
    work.join("config")
}

/// Trust store directory for a test package.
fn trust_dir(work: &Path) -> PathBuf {
    config_dir(work).join("pm").join("trusted")
}

/// Signs `archive` with a throwaway key kept inside `work`, and trusts that key
/// in `work`'s own trust store.
///
/// `PackageRunner` verifies `<archive>.sig` before it extracts anything, so
/// every test package has to carry a real signature - which is also the only
/// way these tests exercise the verification path at all.
fn sign(archive: &Path, work: &Path) {
    let key = SigningKey::load_or_create(&config_dir(work).join("pm").join("signing.key"))
        .expect("create a throwaway signing key");
    sign_file(archive, &key).expect("sign the package");
    let dir = trust_dir(work);
    let mut trust = TrustStore::load(&dir).expect("load the trust store");
    trust
        .add(&key.public_key_hex(), &dir)
        .expect("trust the throwaway key");
}

/// Builds a package that stages a copy of `/bin/true` as `usr/bin/hello`.
fn package_with_a_runnable_binary(name: &str) -> (tempfile::TempDir, PathBuf) {
    package_staging(
        name,
        "set -eu\n\
mkdir -p \"$DESTDIR/usr/bin\"\n\
cp /bin/true \"$DESTDIR/usr/bin/hello\"\n\
chmod 755 \"$DESTDIR/usr/bin/hello\"\n",
    )
}

/// Builds a package exposing three binaries, deliberately named so that their
/// creation order is not their sorted order.
fn package_with_three_binaries(name: &str) -> (tempfile::TempDir, PathBuf) {
    package_staging(
        name,
        "set -eu\n\
mkdir -p \"$DESTDIR/usr/bin\"\n\
cp /bin/true \"$DESTDIR/usr/bin/zulu\"\n\
cp /bin/true \"$DESTDIR/usr/bin/alpha\"\n\
cp /bin/true \"$DESTDIR/usr/bin/mike\"\n\
chmod 755 \"$DESTDIR/usr/bin/zulu\" \"$DESTDIR/usr/bin/alpha\" \"$DESTDIR/usr/bin/mike\"\n",
    )
}

#[test]
#[ignore = "requires unprivileged user namespaces; run with `cargo test --test sandbox -- --ignored`"]
fn a_packaged_binary_runs_to_completion_inside_the_sandbox() {
    let (_work, archive) = package_with_a_runnable_binary("sandboxrun");

    let status = PackageRunner::new(archive)
        .trust_dir(trust_dir(_work.path()))
        .run(Some("usr/bin/hello".into()))
        .expect("running the package must succeed");

    assert!(
        status.success(),
        "the sandboxed binary exited with {}: {}",
        status.code,
        status.reason
    );
}

#[test]
#[ignore = "requires unprivileged user namespaces; run with `cargo test --test sandbox -- --ignored`"]
fn asking_for_a_binary_the_package_does_not_have_is_an_error() {
    let (_work, archive) = package_with_a_runnable_binary("sandboxmissing");

    assert!(
        PackageRunner::new(archive)
            .trust_dir(trust_dir(_work.path()))
            .run(Some("usr/bin/not-in-this-package".into()))
            .is_err(),
        "selecting an unknown entrypoint must return a diagnostic, not run something else"
    );
}

#[test]
fn running_a_package_that_does_not_exist_is_an_error_not_a_panic() {
    let dir = tempdir().expect("temporary directory");
    let missing = dir.path().join("absent.cpkg");

    assert!(
        PackageRunner::new(missing)
            .run(Some("usr/bin/hello".into()))
            .is_err(),
        "a missing archive must return a diagnostic"
    );
}

#[test]
fn running_a_file_that_is_not_an_archive_is_an_error_not_a_panic() {
    let dir = tempdir().expect("temporary directory");
    let bogus = dir.path().join("bogus.cpkg");
    write(&bogus, b"this is not a tarball").expect("write the bogus archive");

    assert!(
        PackageRunner::new(bogus)
            .run(Some("usr/bin/hello".into()))
            .is_err(),
        "a corrupt archive must return a diagnostic"
    );
}

#[test]
fn a_package_with_no_binaries_says_so_instead_of_prompting() {
    // Only a library is staged, so there is nothing to offer and nothing to
    // run. This resolves the entrypoint and fails before the sandbox is ever
    // built, so it needs no user namespaces.
    let (_work, archive) = package_staging(
        "nobinaries",
        "set -eu\n\
mkdir -p \"$DESTDIR/usr/lib\"\n\
printf 'stand-in for a shared object\\n' > \"$DESTDIR/usr/lib/libonly.so\"\n",
    );

    let error = PackageRunner::new(archive)
        .trust_dir(trust_dir(_work.path()))
        .run(None)
        .expect_err("a package with no binaries must not open an empty prompt");

    let rendered = format!("{error}\n{error:?}").to_lowercase();
    assert!(
        rendered.contains("no binary entrypoints"),
        "the diagnostic must explain that there is nothing to run, got: {rendered}"
    );
    assert!(
        rendered.contains("nobinaries"),
        "the diagnostic must name the package, got: {rendered}"
    );
}

#[test]
fn an_unknown_bin_lists_the_available_binaries_in_sorted_order() {
    let (_work, archive) = package_with_three_binaries("listing");
    let mut runner = PackageRunner::new(archive);
    runner.trust_dir(trust_dir(_work.path()));

    let rendered = |error: miette::Report| format!("{error}\n{error:?}");
    let first = rendered(
        runner
            .run(Some("not-in-this-package".into()))
            .expect_err("an unknown binary must be rejected"),
    );

    // Entrypoints live in a HashMap, so without an explicit sort this listing
    // would come out in a different order on every run.
    let alpha = first.find("usr/bin/alpha").expect("alpha must be listed");
    let mike = first.find("usr/bin/mike").expect("mike must be listed");
    let zulu = first.find("usr/bin/zulu").expect("zulu must be listed");
    assert!(
        alpha < mike && mike < zulu,
        "the available binaries must be listed in sorted order, got: {first}"
    );

    // Same package, same listing - every time.
    for _ in 0..3 {
        let again = rendered(
            runner
                .run(Some("not-in-this-package".into()))
                .expect_err("an unknown binary must be rejected"),
        );
        assert_eq!(again, first, "the listing must be stable across calls");
    }
}

#[test]
fn without_a_terminal_and_without_a_bin_the_cli_lists_what_it_could_have_run() {
    let (_work, archive) = package_with_three_binaries("noprompt");

    // The library call would prompt when the test happens to be run from a
    // terminal, so this goes through the binary with stdin closed instead -
    // which is also the shape a script or CI job would hit.
    let output = pm_command(
        &["run", &archive.display().to_string()],
        &config_dir(_work.path()),
    );

    assert!(
        !output.status.success(),
        "with nobody to answer the prompt the run must fail, not guess"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--bin"),
        "the diagnostic must say how to pick a binary, got: {stderr}"
    );

    let alpha = stderr.find("usr/bin/alpha").unwrap_or_else(|| {
        panic!("the available binaries must be listed, got: {stderr}");
    });
    let mike = stderr.find("usr/bin/mike").expect("mike must be listed");
    let zulu = stderr.find("usr/bin/zulu").expect("zulu must be listed");
    assert!(
        alpha < mike && mike < zulu,
        "the listing must be sorted, got: {stderr}"
    );
}

/// Runs the `pm` binary with stdin closed, so nothing can block on a prompt,
/// and with `$XDG_CONFIG_HOME` pointed at the test's own trust store.
fn pm_command(args: &[&str], config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pm"))
        .args(args)
        .env("XDG_CONFIG_HOME", config)
        .stdin(Stdio::null())
        .output()
        .expect("run the pm binary")
}

// ---------------------------------------------------------------------------
// Hostile packages
//
// Everything below builds a `.cpkg` by hand instead of going through
// `BuildFile`, because the point is metadata a legitimate build would never
// produce: the entrypoint table ships *inside* the package, so it says whatever
// its author wanted it to say.
// ---------------------------------------------------------------------------

/// Writes a `metadata` member declaring every path in `entrypoints` a binary.
///
/// The keys are quoted, so `..`, a leading `/` and anything else stay verbatim.
fn write_metadata(root: &Path, name: &str, entrypoints: &[&str]) {
    let mut yaml =
        format!("name: {name}\nversion:\n- '0'\n- '1'\ndependencies: []\nentrypoints:\n");
    for entrypoint in entrypoints {
        yaml.push_str(&format!("  \"{entrypoint}\": Binary\n"));
    }
    write(root.join("metadata"), yaml).expect("write the handcrafted metadata");
}

/// Tars `root` into `<work>/<name>.cpkg` and signs it with the test's own key.
fn pack(work: &Path, root: &Path, name: &str) -> PathBuf {
    let archive = work.join(format!("{name}.cpkg"));
    let status = Command::new("tar")
        .arg("-cJf")
        .arg(&archive)
        .arg("-C")
        .arg(root)
        .arg(".")
        .status()
        .expect("run tar");
    assert!(status.success(), "tar must pack the handcrafted package");
    sign(&archive, work);
    archive
}

/// Drops a marker-writing script in `work` and returns it, together with the
/// marker it writes and a `..`-spelled path that reaches it from *any* package
/// root: ten `..` components bottom out at `/`, which is where the absolute
/// path is then re-attached.
fn payload(work: &Path) -> (PathBuf, String) {
    let marker = work.join("pwned");
    let script = work.join("payload.sh");
    write(
        &script,
        format!("#!/bin/sh\nprintf owned > {}\n", marker.display()),
    )
    .expect("write the payload script");
    Command::new("chmod")
        .arg("755")
        .arg(&script)
        .status()
        .expect("chmod the payload");

    let absolute = script.display().to_string();
    let traversal = format!("{}{}", "../".repeat(10), absolute.trim_start_matches('/'));
    (marker, traversal)
}

/// A handcrafted package holding one honest binary at `usr/bin/hello`.
fn honest_tree(work: &Path) -> PathBuf {
    let root = work.join("pkg");
    std::fs::create_dir_all(root.join("usr/bin")).expect("create the package tree");
    std::fs::copy("/bin/true", root.join("usr/bin/hello")).expect("stage an honest binary");
    root
}

#[test]
fn a_traversal_entrypoint_does_not_escape_the_package() {
    let work = tempdir().expect("work directory");
    let (marker, traversal) = payload(work.path());
    let root = honest_tree(work.path());
    write_metadata(&root, "traversal", &[&traversal, "usr/bin/hello"]);
    let archive = pack(work.path(), &root, "traversal");

    let error = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .run(Some(traversal.clone()))
        .expect_err("a `..` entrypoint must be refused, not joined onto the package root");

    let rendered = format!("{error}\n{error:?}");
    assert!(
        !marker.exists(),
        "the host payload must never run, but it left {}: {rendered}",
        marker.display()
    );
    assert!(
        rendered.contains("usr/bin/hello"),
        "the diagnostic must list the entrypoints that are real, got: {rendered}"
    );
}

#[test]
fn an_absolute_entrypoint_does_not_escape_the_package() {
    let work = tempdir().expect("work directory");
    let (marker, _) = payload(work.path());
    let absolute = work.path().join("payload.sh").display().to_string();
    let root = honest_tree(work.path());
    write_metadata(&root, "absolute", &[&absolute, "usr/bin/hello"]);
    let archive = pack(work.path(), &root, "absolute");

    assert!(
        PackageRunner::new(archive)
            .trust_dir(trust_dir(work.path()))
            .run(Some(absolute))
            .is_err(),
        "an absolute entrypoint must be refused"
    );
    assert!(!marker.exists(), "the host payload must never run");
}

#[test]
fn a_symlink_entrypoint_pointing_out_of_the_package_does_not_escape_it() {
    let work = tempdir().expect("work directory");
    let (marker, _) = payload(work.path());
    let root = honest_tree(work.path());
    // Every component of this path is a plain name, so only resolving the
    // symlink can catch it.
    std::os::unix::fs::symlink(work.path().join("payload.sh"), root.join("usr/bin/sneaky"))
        .expect("plant the escaping symlink");
    write_metadata(&root, "symlinked", &["usr/bin/sneaky", "usr/bin/hello"]);
    let archive = pack(work.path(), &root, "symlinked");

    let error = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .run(Some("usr/bin/sneaky".into()))
        .expect_err("a symlinked entrypoint leaving the package must be refused");

    let rendered = format!("{error}\n{error:?}");
    assert!(
        !marker.exists(),
        "the host payload must never run, but it left {}",
        marker.display()
    );
    assert!(
        rendered.contains("usr/bin/hello") && !rendered.contains("usr/bin/sneaky, "),
        "only the usable entrypoints may be offered, got: {rendered}"
    );
}

#[test]
fn an_escaping_entrypoint_is_never_offered_in_the_listing() {
    let work = tempdir().expect("work directory");
    let (_marker, traversal) = payload(work.path());
    let root = honest_tree(work.path());
    write_metadata(&root, "listing2", &[&traversal, "usr/bin/hello"]);
    let archive = pack(work.path(), &root, "listing2");

    let error = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .run(Some("nothing-like-this".into()))
        .expect_err("an unknown binary must be rejected");

    let rendered = format!("{error}\n{error:?}");
    let available = rendered
        .split("Available:")
        .nth(1)
        .unwrap_or_else(|| panic!("the diagnostic must list what is available, got: {rendered}"));
    assert!(
        !available.contains(".."),
        "an entrypoint that escapes the package must not be offered, got: {available}"
    );
}

#[test]
fn an_unsigned_package_is_refused_before_it_is_extracted() {
    let (work, archive) = package_with_a_runnable_binary("unsigned");
    let signature = PathBuf::from(format!("{}.sig", archive.display()));
    std::fs::remove_file(&signature).expect("drop the signature");

    let error = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .run(Some("usr/bin/hello".into()))
        .expect_err("an unsigned package must not run");

    let rendered = format!("{error}\n{error:?}").to_lowercase();
    assert!(
        rendered.contains("signature") || rendered.contains(".sig"),
        "the diagnostic must blame the missing signature, got: {rendered}"
    );
}

#[test]
fn a_package_signed_by_an_untrusted_key_is_refused() {
    let (work, archive) = package_with_a_runnable_binary("untrusted");
    let empty = work.path().join("nobody-trusted");

    assert!(
        PackageRunner::new(archive)
            .trust_dir(empty)
            .run(Some("usr/bin/hello".into()))
            .is_err(),
        "a signature from a key outside the trust store must be refused"
    );
}

#[test]
#[ignore = "requires unprivileged user namespaces; run with `cargo test --test sandbox -- --ignored`"]
fn allow_unsigned_is_the_documented_escape_hatch() {
    let (work, archive) = package_with_a_runnable_binary("optout");
    let signature = PathBuf::from(format!("{}.sig", archive.display()));
    std::fs::remove_file(&signature).expect("drop the signature");

    let status = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .allow_unsigned(true)
        .run(Some("usr/bin/hello".into()))
        .expect("the opt-out must run the package anyway");

    assert!(
        status.success(),
        "the package should still run to completion"
    );
}

#[test]
#[ignore = "requires unprivileged user namespaces; run with `cargo test --test sandbox -- --ignored`"]
fn a_sandboxed_package_cannot_reach_the_network() {
    let work = tempdir().expect("work directory");
    let root = work.path().join("pkg");
    std::fs::create_dir_all(root.join("usr/bin")).expect("create the package tree");
    let prober = root.join("usr/bin/prober");
    write(
        &prober,
        "#!/bin/sh\nexec python3 -c \
         'import socket; socket.create_connection((\"1.1.1.1\", 443), 5)'\n",
    )
    .expect("write the network prober");
    Command::new("chmod")
        .arg("755")
        .arg(&prober)
        .status()
        .expect("chmod the prober");
    write_metadata(&root, "prober", &["usr/bin/prober"]);
    let archive = pack(work.path(), &root, "prober");

    let status = PackageRunner::new(archive)
        .trust_dir(trust_dir(work.path()))
        .run(Some("usr/bin/prober".into()))
        .expect("the package itself must run");

    assert!(
        !status.success(),
        "a sandboxed package must not reach the network, but the connect succeeded"
    );
}
