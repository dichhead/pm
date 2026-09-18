//! End-to-end packaging tests: run a real build and inspect the archive it
//! leaves behind.
//!
//! Every test here points a [`BuildContext`] at its own private directory
//! instead of moving the process-wide current directory: the whole crate is
//! built from having stopped `BuildFile` read that directory on its own, and a
//! test that still chdir'd to prove it would only be proving the process cwd
//! works, not that a caller-supplied one does.

use std::fs::{read, read_to_string, write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::channel;
use std::thread::spawn;
use std::time::Duration;

use pm::bf::{BuildFile, BuildOptions};
use pm::context::BuildContext;
use pm::metadata::{LibraryType, Metadata, Type};
use pm::progress::Progress;
use serde_yaml::from_str;
use tempfile::{TempDir, tempdir};

mod common;
use common::{build_file_yaml, write_build_file};

/// A [`BuildContext`] that writes its finished archive into `dir`.
fn ctx_at(dir: &Path) -> BuildContext {
    BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_output_dir(dir.to_path_buf())
}

/// Stages a binary and two libraries into `DESTDIR`.
///
/// `Step` splits commands on whitespace and execs directly - there is no shell,
/// so `$DESTDIR` does not expand in a command string. Real build files invoke a
/// build system (`make install`) that reads `DESTDIR` from the environment and
/// expands it itself; see `destdir_reaches_a_real_makefile` for that path. Here
/// a script file does the same job without depending on `make` being installed:
/// `/bin/sh <script>` is two plain words, and the shell running the script
/// expands `$DESTDIR` from its environment.
const STAGE_SCRIPT: &str = "set -eu\n\
mkdir -p \"$DESTDIR/usr/bin\" \"$DESTDIR/usr/lib\"\n\
printf '#!/bin/sh\\nexit 0\\n' > \"$DESTDIR/usr/bin/mytool\"\n\
chmod 755 \"$DESTDIR/usr/bin/mytool\"\n\
printf 'stand-in for a shared object\\n' > \"$DESTDIR/usr/lib/libfoo.so\"\n\
printf 'stand-in for an archive\\n' > \"$DESTDIR/usr/lib/libbar.a\"\n";

/// Runs `build` with its archive directed at `at`, returning the absolute path
/// it produced. `at` is always an absolute `TempDir` path, so the result
/// already is too - unlike the process cwd this used to move to, there is no
/// relative result to resolve.
fn run_in(build: &BuildFile, at: &Path) -> PathBuf {
    build
        .run_with_progress_in(&ctx_at(at), BuildOptions::default(), &Progress::disabled())
        .expect("the build must succeed")
}

/// A finished build: the archive, the directory it was extracted into, and the
/// working directory that owns the archive.
struct Built {
    _work: TempDir,
    dest: TempDir,
    archive: PathBuf,
}

/// Builds a package named `name` in a private directory and extracts it.
fn build_and_extract(name: &str) -> Built {
    let work = tempdir().expect("work directory");
    let script = work.path().join("stage.sh");
    write(&script, STAGE_SCRIPT).expect("write the staging script");
    let stage = format!("/bin/sh {}", script.display());
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml(name, &["0", "1", "0"], &[], &[stage.as_str()]),
    );

    let build = BuildFile::load_unverified(&build_file).expect("the build file must load");
    let archive = run_in(&build, work.path());

    assert!(
        archive.is_file(),
        "no archive at {}; the build produced nothing",
        archive.display()
    );

    let dest = extract(&archive);

    Built {
        _work: work,
        dest,
        archive,
    }
}

/// Extracts `archive` into a fresh temporary directory.
fn extract(archive: &Path) -> TempDir {
    let dest = tempdir().expect("extraction directory");
    let output = Command::new("tar")
        .arg("-xpf")
        .arg(archive)
        .arg("-C")
        .arg(dest.path())
        .output()
        .expect("run tar");
    assert!(
        output.status.success(),
        "tar failed to extract {}: {}",
        archive.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    dest
}

/// Looks an entrypoint up by the tail of its path, so the test does not depend
/// on whether the packager writes `usr/bin/mytool` or `./usr/bin/mytool`.
fn entrypoint_of<'a>(metadata: &'a Metadata, suffix: &str) -> Option<&'a Type> {
    metadata
        .entrypoints()
        .find(|(path, _)| path.ends_with(suffix))
        .map(|(_, ty)| ty)
}

#[test]
fn the_archive_is_named_after_the_package_and_its_version() {
    let built = build_and_extract("namecheck");

    assert_eq!(
        built.archive.file_name().and_then(|n| n.to_str()),
        Some("namecheck-0.1.0.cpkg"),
        "unexpected archive name: {}",
        built.archive.display()
    );
}

#[test]
fn the_archive_is_xz_compressed() {
    let built = build_and_extract("xzcheck");
    let bytes = read(&built.archive).expect("read the archive");

    assert!(
        bytes.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
        "the archive must carry the xz magic bytes, found {:02X?}",
        &bytes[..bytes.len().min(6)]
    );
}

#[test]
fn the_archive_contains_the_staged_files_and_its_metadata() {
    let built = build_and_extract("contentcheck");
    let root = built.dest.path();

    // The regression this pins: step output landing in a different temporary
    // directory from the one that gets packaged, yielding an empty package.
    assert!(
        root.join("usr/bin/mytool").is_file(),
        "the staged binary is missing from the archive"
    );
    assert!(
        root.join("usr/lib/libfoo.so").is_file(),
        "the staged shared library is missing from the archive"
    );
    assert!(
        root.join("usr/lib/libbar.a").is_file(),
        "the staged static library is missing from the archive"
    );
    assert!(
        root.join("metadata").is_file(),
        "metadata must sit at the root of the archive"
    );
    assert!(
        root.join("deps").is_dir(),
        "the package tree must carry a deps directory"
    );

    let staged = read_to_string(root.join("usr/lib/libfoo.so")).expect("read the staged library");
    assert_eq!(staged, "stand-in for a shared object\n");
}

#[test]
fn the_metadata_describes_the_package_it_was_built_from() {
    let built = build_and_extract("metacheck");
    let metadata: Metadata =
        from_str(&read_to_string(built.dest.path().join("metadata")).expect("read metadata"))
            .expect("metadata must be valid YAML");

    assert_eq!(metadata.name(), "metacheck");
    let version: Vec<&str> = metadata.version().iter().map(String::as_str).collect();
    assert_eq!(version, ["0", "1", "0"]);

    assert_eq!(
        entrypoint_of(&metadata, "usr/bin/mytool"),
        Some(&Type::Binary)
    );
    assert_eq!(
        entrypoint_of(&metadata, "usr/lib/libfoo.so"),
        Some(&Type::Library(LibraryType::Dynamic))
    );
    assert_eq!(
        entrypoint_of(&metadata, "usr/lib/libbar.a"),
        Some(&Type::Library(LibraryType::Static))
    );
}

#[test]
fn every_entrypoint_path_is_relative_to_the_package_root() {
    let built = build_and_extract("relcheck");
    let metadata: Metadata =
        from_str(&read_to_string(built.dest.path().join("metadata")).expect("read metadata"))
            .expect("metadata must be valid YAML");

    assert!(
        metadata.entrypoints().len() > 0,
        "the package staged files, so it must have entrypoints"
    );

    // Absolute build-time paths are meaningless once the package is extracted
    // somewhere else, so they must never make it into the metadata.
    for (path, _) in metadata.entrypoints() {
        assert!(
            path.is_relative(),
            "entrypoint {} is an absolute build-time path",
            path.display()
        );
        assert!(
            !path.components().any(|c| c.as_os_str() == "relcheck"),
            "entrypoint {} still carries the staging directory name",
            path.display()
        );
    }

    // And they must resolve against the extracted tree.
    for (path, _) in metadata.entrypoints() {
        assert!(
            built.dest.path().join(path).exists(),
            "entrypoint {} does not exist in the extracted package",
            path.display()
        );
    }
}

#[test]
fn a_build_with_no_steps_still_produces_a_valid_archive() {
    let work = tempdir().expect("work directory");
    let build_file = work.path().join("build.yaml");
    write(
        &build_file,
        "name: emptybuild\nversion:\n  - '2'\n  - '0'\ndependencies: []\nsteps: []\n",
    )
    .expect("write the build file");
    let build = BuildFile::load_unverified(&build_file).expect("load");
    let archive = run_in(&build, work.path());

    assert!(archive.is_file());
    assert_eq!(
        archive.file_name().and_then(|n| n.to_str()),
        Some("emptybuild-2.0.cpkg")
    );

    let dest = extract(&archive);
    assert!(dest.path().join("metadata").is_file());
}

#[test]
fn a_build_whose_step_fails_does_not_leave_an_archive_behind() {
    let work = tempdir().expect("work directory");
    let build_file = work.path().join("build.yaml");
    write(
        &build_file,
        "name: brokenbuild\nversion:\n  - '0'\ndependencies: []\nsteps:\n  - stage: Build\n    dl_urls: null\n    name: explode\n    run:\n      - /bin/cat /pm-integration-test-missing-file\n",
    )
    .expect("write the build file");
    let build = BuildFile::load_unverified(&build_file).expect("load");

    assert!(
        build
            .run_with_progress_in(
                &ctx_at(work.path()),
                BuildOptions::default(),
                &Progress::disabled()
            )
            .is_err(),
        "a failing build step must fail the build"
    );
    assert!(
        !work.path().join("brokenbuild-0.cpkg").exists(),
        "a failed build must not publish an archive"
    );
}

#[test]
fn a_build_that_stages_nothing_still_produces_an_archive() {
    let work = tempdir().expect("work directory");
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        // Real work, no output: the commands succeed but write nothing under
        // `$DESTDIR`. That is a suspicious package, not a broken build, so it
        // must stay a warning and still produce something installable.
        &build_file_yaml(
            "stagednothing",
            &["1", "0"],
            &[],
            &["true", "echo building > /dev/null"],
        ),
    );

    let build = BuildFile::load_unverified(&build_file).expect("load");
    let archive = run_in(&build, work.path());

    assert!(
        archive.is_file(),
        "a package that stages nothing must still be packaged"
    );
    let dest = extract(&archive);
    assert!(
        dest.path().join("metadata").is_file(),
        "the archive must still carry its metadata"
    );

    let metadata: Metadata =
        from_str(&read_to_string(dest.path().join("metadata")).expect("read metadata"))
            .expect("metadata must be valid YAML");
    assert_eq!(metadata.name(), "stagednothing");
    assert!(
        metadata.entrypoints().len() == 0,
        "nothing was staged, so there is nothing to run: {:?}",
        metadata.entrypoints().collect::<Vec<_>>()
    );
}

#[test]
fn a_dependency_that_does_not_exist_fails_the_build_and_names_the_path() {
    let work = tempdir().expect("work directory");
    let missing = work.path().join("no-such-dependency.yaml");
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml("needsmissing", &["0"], &[&missing], &[]),
    );

    let build = BuildFile::load_unverified(&build_file).expect("load");

    let error = build
        .run_with_progress_in(
            &ctx_at(work.path()),
            BuildOptions::default(),
            &Progress::disabled(),
        )
        .expect_err("a dependency that is not on disk must fail the build");

    let rendered = format!("{error}\n{error:?}");
    assert!(
        rendered.contains(&missing.display().to_string()),
        "the diagnostic must name the missing dependency, got: {rendered}"
    );
    assert!(
        !work.path().join("needsmissing-0.cpkg").exists(),
        "a build that could not resolve its dependencies must not publish an archive"
    );
}

/// Stamps the package under construction with a value no second build of the
/// same build file could ever repeat.
///
/// The build sandbox mounts the build file's own directory READ-ONLY, so a
/// build cannot leave a counter next to its build file the way this test used
/// to. What it can still do is stamp the package it produces: two builds of one
/// build file stamp two different values, one build stamps one.
const STAMP_SCRIPT: &str = "set -eu\ndate +%s%N > \"$DESTDIR/stamp\"\n";

/// Extracts `deps/<name>` out of an already-extracted package, then the
/// `shared-1.cpkg` bundled inside that, and returns the stamp it carries.
fn bundled_shared_stamp(package: &Path, name: &str) -> String {
    let intermediate = extract(&package.join("deps").join(name));
    let shared = extract(&intermediate.path().join("deps/shared-1.cpkg"));
    read_to_string(shared.path().join("stamp"))
        .expect("the shared package must carry the stamp its build wrote")
}

#[test]
fn a_diamond_dependency_builds_the_shared_package_once() {
    let work = tempdir().expect("work directory");

    // Redirection needs a shell, and commands are exec'd directly with none, so
    // the redirection lives inside a script file instead.
    let stamp = work.path().join("stamp.sh");
    write(&stamp, STAMP_SCRIPT).expect("write the stamping script");

    let shared = write_build_file(
        work.path().join("shared.yaml"),
        &build_file_yaml(
            "shared",
            &["1"],
            &[],
            &[&format!("/bin/sh {}", stamp.display())],
        ),
    );
    let left = write_build_file(
        work.path().join("left.yaml"),
        &build_file_yaml("left", &["1"], &[&shared], &[]),
    );
    let right = write_build_file(
        work.path().join("right.yaml"),
        &build_file_yaml("right", &["1"], &[&shared], &[]),
    );
    let top = write_build_file(
        work.path().join("top.yaml"),
        &build_file_yaml("top", &["1"], &[&left, &right], &[]),
    );

    let build = BuildFile::load_unverified(&top).expect("load the top of the diamond");
    let archive = run_in(&build, work.path());
    assert!(archive.is_file());

    let dest = extract(&archive);

    // Both halves of the diamond bundle a copy of the shared package. Equal
    // stamps mean one build produced both copies; a second build of `shared`
    // would have stamped a different nanosecond.
    let from_left = bundled_shared_stamp(dest.path(), "left-1.cpkg");
    let from_right = bundled_shared_stamp(dest.path(), "right-1.cpkg");
    assert!(
        !from_left.trim().is_empty(),
        "the stamping step did not run at all"
    );
    assert_eq!(
        from_left, from_right,
        "the shared dependency was built twice: {from_left:?} against {from_right:?}"
    );

    // Both intermediate packages must still be bundled under `deps/`.
    let metadata: Metadata =
        from_str(&read_to_string(dest.path().join("metadata")).expect("read metadata"))
            .expect("metadata must be valid YAML");
    let mut deps: Vec<String> = metadata
        .dependencies()
        .map(|path| path.display().to_string())
        .collect();
    deps.sort();
    assert_eq!(deps, ["deps/left-1.cpkg", "deps/right-1.cpkg"]);
}

#[test]
fn a_dependency_cycle_is_rejected_rather_than_recursing_forever() {
    let work = tempdir().expect("work directory");
    let first = work.path().join("a.yaml");
    let second = work.path().join("b.yaml");
    write_build_file(
        first.clone(),
        &build_file_yaml("cyclea", &["0"], &[&second], &[]),
    );
    write_build_file(
        second.clone(),
        &build_file_yaml("cycleb", &["0"], &[&first], &[]),
    );

    let ctx = ctx_at(work.path());

    // A regression here is an infinite recursion, which would hang the whole
    // suite. Run the build on its own thread and give up waiting on it rather
    // than letting it wedge the test binary.
    let (tx, rx) = channel();
    spawn(move || {
        let outcome = BuildFile::load_unverified(&first)
            .and_then(|build| {
                build.run_with_progress_in(&ctx, BuildOptions::default(), &Progress::disabled())
            })
            .map(|archive| archive.display().to_string())
            .map_err(|error| format!("{error}\n{error:?}"));
        // The receiver is gone if the test already gave up; that is not a failure.
        let _ = tx.send(outcome);
    });

    let outcome = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("cycle detection must terminate; the build never came back");

    let error = outcome.expect_err("a dependency cycle must be rejected");
    assert!(
        error.to_lowercase().contains("cycle"),
        "the diagnostic must say the dependencies form a cycle, got: {error}"
    );
    assert!(
        !work.path().join("cyclea-0.cpkg").exists(),
        "a cyclic dependency graph must not publish an archive"
    );
}

/// A `Makefile` whose `install` target honours `DESTDIR` the way autotools and
/// every hand-written Makefile do: the install paths are prefixed with
/// `$(DESTDIR)`, which `make` picks up from its environment.
const MAKEFILE: &str = "PREFIX ?= /usr\n\
\n\
install:\n\
\tinstall -d $(DESTDIR)$(PREFIX)/bin\n\
\tinstall -m755 mytool $(DESTDIR)$(PREFIX)/bin/mytool\n";

/// `make install` redirects its install into the staging tree via `DESTDIR`.
///
/// This is the reason `Step` passes `DESTDIR` through the environment instead of
/// substituting it into the command: the build file says nothing about where the
/// package is staged, and `make` expands `$(DESTDIR)` itself. Nothing else in
/// this suite covers that path - the other tests drive a shell script directly.
#[test]
fn destdir_reaches_a_real_makefile() {
    if Command::new("make").arg("-v").output().is_err() {
        eprintln!("skipping destdir_reaches_a_real_makefile: `make` is not installed");
        return;
    }

    let work = tempdir().expect("work directory");
    let src = work.path().join("src");
    std::fs::create_dir_all(&src).expect("create the source directory");
    write(src.join("Makefile"), MAKEFILE).expect("write the Makefile");
    write(src.join("mytool"), "#!/bin/sh\nexit 0\n").expect("write the payload");

    // `make -C <dir> install` is plain whitespace-separated words, so it runs
    // under direct exec with no shell involved.
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml(
            "makepkg",
            &["2", "0"],
            &[],
            &[&format!("make -C {} install", src.display())],
        ),
    );

    let build = BuildFile::load_unverified(&build_file).expect("the build file must load");
    let archive = run_in(&build, work.path());

    let dest = tempdir().expect("extraction directory");
    let status = Command::new("tar")
        .arg("-xpf")
        .arg(&archive)
        .arg("-C")
        .arg(dest.path())
        .status()
        .expect("tar must run");
    assert!(
        status.success(),
        "tar failed to extract {}",
        archive.display()
    );

    let staged = dest.path().join("usr/bin/mytool");
    assert!(
        staged.is_file(),
        "`make install` did not reach DESTDIR: {} is missing from the package",
        staged.display()
    );

    let metadata: Metadata =
        from_str(&read_to_string(dest.path().join("metadata")).expect("read the metadata"))
            .expect("the metadata must parse");
    assert_eq!(
        metadata
            .entrypoints()
            .find(|(p, _)| *p == Path::new("usr/bin/mytool"))
            .map(|(_, t)| t),
        Some(&Type::Binary),
        "the make-installed binary must be recorded as an entrypoint, got {:?}",
        metadata.entrypoints().collect::<Vec<_>>()
    );
}

#[test]
fn a_build_reporting_into_a_region_still_produces_its_archive() {
    let work = tempdir().expect("work directory");
    let script = work.path().join("stage.sh");
    write(&script, STAGE_SCRIPT).expect("write the staging script");
    let stage = format!("/bin/sh {}", script.display());
    let build_file = write_build_file(
        work.path().join("build.yaml"),
        &build_file_yaml("reported", &["0", "1", "0"], &[], &[stage.as_str()]),
    );
    let build = BuildFile::load_unverified(&build_file).expect("the build file must load");

    // A region that renders for real, into nothing. This is the whole stack:
    // a package line, a jailed command under it whose stdout is captured and
    // streamed into that line, and the archive at the end of it.
    let progress = Progress::to_writer(Box::new(std::io::sink()), 100);

    let archive = build
        .run_with_progress_in(&ctx_at(work.path()), BuildOptions::default(), &progress)
        .expect("the build must succeed with a region attached");

    assert!(
        archive.is_file(),
        "capturing a command's stdout must not cost us the archive: {}",
        archive.display()
    );
    assert!(
        progress.snapshot().is_empty(),
        "every line must be closed once the build is over, got {:?}",
        progress.snapshot()
    );
}
