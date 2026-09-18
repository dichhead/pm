//! Proves the seam [`pm::context::BuildContext`] and [`pm::cancel::Cancel`]
//! open: every test here runs from a process whose own cwd, `$PATH` and
//! `$HOME` are deliberately irrelevant, and checks that the library honours
//! the context it was handed instead.
//!
//! Nothing here moves the process-wide current directory - that scaffolding
//! is exactly what this phase deleted (see `tests/common/mod.rs` history). A
//! test that still needs to chdir to pass would be proof the library is still
//! reading the process, not the context.

use std::fs::write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::channel;
use std::thread::{sleep, spawn};
use std::time::Duration;

use pm::bf::{BuildFile, BuildOptions};
use pm::cancel::Cancel;
use pm::context::BuildContext;
use pm::download::Downloader;
use pm::graph::Graph;
use pm::progress::Progress;
use pm::signing::{SigningKey, TrustStore, sign_file};
use tempfile::tempdir;

mod common;
use common::{TestServer, build_file_yaml, write_build_file};

#[test]
fn output_dir_from_the_context_places_the_archive_there() {
    let work = tempdir().expect("work directory");
    let elsewhere = tempdir().expect("scratch output directory");

    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml("outputcheck", &["0", "1"], &[], &[]),
    );
    let build = BuildFile::load_unverified(&build_file).expect("load the build file");

    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_output_dir(elsewhere.path().to_path_buf());

    let archive = build
        .run_with_progress_in(&ctx, BuildOptions::default(), &Progress::disabled())
        .expect("the build must succeed");

    assert_eq!(
        archive.parent(),
        Some(elsewhere.path()),
        "the archive must land under ctx.output_dir, got {}",
        archive.display()
    );
    assert!(
        !work.path().join("outputcheck-0.1.cpkg").exists(),
        "the archive must not also land next to the build file"
    );
    assert!(
        !std::env::current_dir()
            .expect("a current directory")
            .join("outputcheck-0.1.cpkg")
            .exists(),
        "the archive must not land in the process's own current directory either"
    );
}

#[test]
fn relative_dependency_paths_resolve_against_ctx_cwd() {
    // The dependency lives under `cwd_dir`, named only by a RELATIVE path from
    // the root build file - which itself lives somewhere else entirely, so
    // nothing here shares a directory with the process's own current one.
    let cwd_dir = tempdir().expect("the directory ctx.cwd points at");
    write_build_file(
        cwd_dir.path().join("dep.yaml"),
        &build_file_yaml("depcheck", &["1"], &[], &[]),
    );

    let root_dir = tempdir().expect("a directory unrelated to ctx.cwd");
    let root_file = write_build_file(
        root_dir.path().join("root.yaml"),
        &build_file_yaml("rootcheck", &["1"], &[Path::new("dep.yaml")], &[]),
    );
    let root = BuildFile::load_unverified(&root_file).expect("load the root build file");

    let output = tempdir().expect("output directory");
    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_cwd(cwd_dir.path().to_path_buf())
        .with_output_dir(output.path().to_path_buf());

    let archive = root
        .run_with_progress_in(&ctx, BuildOptions::default(), &Progress::disabled())
        .expect(
            "a relative dependency path must resolve against ctx.cwd, not the process's own cwd",
        );

    assert_eq!(archive.parent(), Some(output.path()));
    assert!(
        output.path().join("depcheck-1.cpkg").is_file(),
        "the dependency named by a relative path must have been resolved and built"
    );
}

#[test]
fn trust_dir_from_the_context_governs_signature_verification() {
    let work = tempdir().expect("work directory");
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml("trustcheck", &["1"], &[], &[]),
    );

    let key = SigningKey::load_or_create(&work.path().join("signing.key"))
        .expect("create a throwaway signing key");
    sign_file(&build_file, &key).expect("sign the build file");

    let trusted = work.path().join("trusted");
    let mut trust = TrustStore::load(&trusted).expect("load the (empty) trust store");
    trust
        .add(&key.public_key_hex(), &trusted)
        .expect("trust the throwaway key");

    let trusting = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_trust_dir(trusted);
    BuildFile::load_in(&trusting, &build_file)
        .expect("a signature must verify when ctx names the trust dir holding the key");

    let empty_trust_dir = work.path().join("nobody-trusted");
    let refusing = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_trust_dir(empty_trust_dir);
    assert!(
        BuildFile::load_in(&refusing, &build_file).is_err(),
        "a signature must be refused when ctx names a trust dir that does not hold the key"
    );
}

#[test]
fn a_path_supplied_through_the_context_resolves_a_steps_first_word() {
    // A program that exists ONLY under this throwaway directory - never on the
    // real process `PATH` - so a successful build proves `ctx.path` is what
    // resolved it, not the environment.
    let toolchain = tempdir().expect("toolchain directory");
    let tool = toolchain.path().join("pm-context-test-tool");
    write(&tool, "#!/bin/sh\nexit 0\n").expect("write the tool");
    let chmod = Command::new("chmod")
        .arg("755")
        .arg(&tool)
        .status()
        .expect("chmod the tool");
    assert!(chmod.success(), "chmod must succeed");

    let work = tempdir().expect("work directory");
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml("pathcheck", &["0", "1"], &[], &["pm-context-test-tool"]),
    );
    let build = BuildFile::load_unverified(&build_file).expect("load the build file");

    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_output_dir(work.path().to_path_buf())
        .with_path(toolchain.path().as_os_str().to_owned());
    // The command matches no built-in fingerprint - it is a throwaway test
    // binary, not a real build tool - so classification is relaxed. That is
    // orthogonal to what this test proves: PATH resolution.
    let options = BuildOptions {
        permissive: true,
        ..BuildOptions::default()
    };

    let archive = build
        .run_with_progress_in(&ctx, options, &Progress::disabled())
        .expect("a PATH supplied through the context must resolve the step's program");

    assert!(archive.is_file());
}

#[test]
fn a_cancelled_token_makes_a_parked_worker_return_instead_of_hang() {
    let dir = tempdir().expect("a temporary directory");

    let dep_script = dir.path().join("dep.sh");
    write(
        &dep_script,
        "set -eu\nsleep 1\necho canceldep > \"$DESTDIR/canceldep.stamp\"\n",
    )
    .expect("write the dependency's build script");
    let dep = write_build_file(
        dir.path().join("dep.yaml"),
        &build_file_yaml(
            "canceldep",
            &["1"],
            &[],
            &[&format!("/bin/sh {}", dep_script.display())],
        ),
    );
    // `top` depends on `dep` and has no step of its own: once `dep` settles,
    // `top` is the ONLY package that could still be handed out.
    let top = write_build_file(
        dir.path().join("top.yaml"),
        &build_file_yaml("canceltop", &["1"], &[&dep], &[]),
    );

    let build = BuildFile::load_unverified(&top).expect("load the root build file");
    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_output_dir(dir.path().to_path_buf());
    // Two workers, one package ready at the start: the second worker finds
    // nothing to do and parks on the very condvar `Cancel::cancel` below has
    // to reach - see the CRITICAL note on `Graph::claim`.
    let options = BuildOptions {
        jobs: NonZeroUsize::new(2),
        ..BuildOptions::default()
    };
    let graph = Graph::resolve_in(&ctx, &build, options).expect("the graph must resolve");

    let cancel = Cancel::new();
    let worker_cancel = cancel.clone();
    let (tx, rx) = channel();
    spawn(move || {
        let result = graph.build_with(&ctx, options, &Progress::disabled(), &worker_cancel);
        // The receiver is gone if the test already gave up; that is not a
        // failure of the code under test.
        let _ = tx.send(result);
    });

    // Long enough that the second worker has certainly reached `wakeup.wait`
    // before this fires, and short enough to leave most of `dep`'s one-second
    // build still ahead of it.
    sleep(Duration::from_millis(200));
    cancel.cancel();

    // A real, generous timeout: `dep` was already running when `cancel()` was
    // called and is left to finish (cancellation is best-effort and never
    // kills a package already claimed), but nothing beyond that should ever
    // run, so this must come back in about the time `dep` alone takes.
    let result = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("a cancelled build must still return rather than hang");

    assert!(
        result.is_err(),
        "the root must never be built once cancellation stopped it being handed out, got {:?}",
        result.ok()
    );
    assert!(
        dir.path().join("canceldep-1.cpkg").is_file(),
        "the package already running when cancel() was called must still finish"
    );
    assert!(
        !dir.path().join("canceltop-1.cpkg").is_file(),
        "a package that only became ready AFTER cancellation must never be built"
    );
}

#[test]
fn a_cancelled_token_stops_a_download_between_chunks() {
    // Comfortably more than one 64 KiB chunk, so the cancellation check inside
    // the read loop gets at least one chance to run before the body ends on
    // its own.
    let body = vec![b'a'; 200_000];
    let server = TestServer::serving_one(&body);
    let dir = tempdir().expect("a temporary directory");
    let dest = dir.path().join("source.tar.gz");

    let cancel = Cancel::new();
    cancel.cancel();

    let error = Downloader::new()
        .with_cancel(cancel)
        .fetch(&server.url("/source.tar.gz"), &dest, |_, _| {})
        .expect_err("a token already cancelled must stop the transfer");

    let rendered = format!("{error:?}").to_lowercase();
    assert!(
        rendered.contains("cancel"),
        "the diagnostic must say the download was cancelled, got: {rendered}"
    );
    assert!(
        !dest.exists(),
        "a cancelled download must not leave a partial file behind"
    );
}
