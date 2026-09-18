//! Tests for [`pm::graph::Graph`]: what resolution accepts, what it rejects,
//! and the order it hands packages back in.
//!
//! Resolution is deliberately a separate pass from building. Everything here
//! runs without a single build step executing, which is the whole point of it:
//! a cycle, a missing build file or two packages fighting over one archive name
//! are all things you want to be told before a compiler starts.

use std::fs::write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pm::bf::{BuildFile, BuildOptions};
use pm::context::BuildContext;
use pm::graph::Graph;
use pm::progress::Progress;
use tempfile::{TempDir, tempdir};

mod common;
use common::{build_file_yaml, write_build_file};

/// Writes a build file named `name` at `<dir>/<name>.yaml` depending on `deps`.
fn package(dir: &TempDir, name: &str, deps: &[&Path]) -> PathBuf {
    write_build_file(
        dir.path().join(format!("{name}.yaml")),
        &build_file_yaml(name, &["1"], deps, &[]),
    )
}

/// Resolves the graph rooted at `path`.
fn resolve(path: &Path) -> miette::Result<Graph> {
    let root = BuildFile::load_unverified(path).expect("the root build file must load");
    Graph::resolve(&root, BuildOptions::default())
}

#[test]
fn a_build_file_with_no_dependencies_resolves_to_itself_alone() {
    let dir = tempdir().expect("a temporary directory");
    let only = package(&dir, "solo", &[]);

    let graph = resolve(&only).expect("a dependency-free build file must resolve");

    assert_eq!(graph.len(), 1);
    assert_eq!(graph.order().collect::<Vec<_>>(), ["solo"]);
}

#[test]
fn a_diamond_resolves_to_one_node_per_build_file() {
    let dir = tempdir().expect("a temporary directory");
    let shared = package(&dir, "shared", &[]);
    let left = package(&dir, "left", &[&shared]);
    let right = package(&dir, "right", &[&shared]);
    let top = package(&dir, "top", &[&left, &right]);

    let graph = resolve(&top).expect("a diamond must resolve");

    // Four build files, four nodes: the shared one is reached twice and must
    // still appear once. That identity is what stops it being built twice.
    assert_eq!(
        graph.len(),
        4,
        "the shared package was duplicated: {:?}",
        graph.order().collect::<Vec<_>>()
    );
}

#[test]
fn dependencies_come_before_the_packages_that_need_them() {
    let dir = tempdir().expect("a temporary directory");
    let shared = package(&dir, "shared", &[]);
    let left = package(&dir, "left", &[&shared]);
    let right = package(&dir, "right", &[&shared]);
    let top = package(&dir, "top", &[&left, &right]);

    let graph = resolve(&top).expect("a diamond must resolve");
    let order: Vec<&str> = graph.order().collect();

    let position = |name: &str| {
        order
            .iter()
            .position(|package| *package == name)
            .unwrap_or_else(|| panic!("{name} is missing from {order:?}"))
    };
    assert!(position("shared") < position("left"), "{order:?}");
    assert!(position("shared") < position("right"), "{order:?}");
    assert!(position("left") < position("top"), "{order:?}");
    assert!(position("right") < position("top"), "{order:?}");
}

#[test]
fn a_cycle_is_rejected_and_the_diagnostic_names_the_chain() {
    let dir = tempdir().expect("a temporary directory");
    let first = dir.path().join("cyclea.yaml");
    let second = dir.path().join("cycleb.yaml");
    write_build_file(
        first.clone(),
        &build_file_yaml("cyclea", &["0"], &[&second], &[]),
    );
    write_build_file(
        second.clone(),
        &build_file_yaml("cycleb", &["0"], &[&first], &[]),
    );

    let error = resolve(&first).expect_err("a cycle must not resolve");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains("cycle"),
        "the diagnostic must say what is wrong: {report}"
    );
    assert!(
        report.contains("cyclea.yaml") && report.contains("cycleb.yaml"),
        "the diagnostic must name both ends of the chain: {report}"
    );
}

#[test]
fn a_package_that_depends_on_itself_is_a_cycle() {
    let dir = tempdir().expect("a temporary directory");
    let path = dir.path().join("narcissus.yaml");
    write_build_file(
        path.clone(),
        &build_file_yaml("narcissus", &["0"], &[&path], &[]),
    );

    let error = resolve(&path).expect_err("a self-dependency must not resolve");
    assert!(
        format!("{error}\n{error:?}").contains("cycle"),
        "a one-node cycle is still a cycle"
    );
}

#[test]
fn a_dependency_that_is_not_a_build_file_is_rejected_by_name() {
    let dir = tempdir().expect("a temporary directory");
    let missing = dir.path().join("absent.yaml");
    let top = package(&dir, "top", &[&missing]);

    let error = resolve(&top).expect_err("a missing dependency must not resolve");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains("absent.yaml"),
        "the diagnostic must name the path that is missing: {report}"
    );
}

#[test]
fn two_packages_claiming_one_archive_name_are_rejected() {
    let dir = tempdir().expect("a temporary directory");
    // Different build files, same name and version, so both would be packaged
    // to `clash-1.cpkg` and race on one rename.
    let first = write_build_file(
        dir.path().join("first.yaml"),
        &build_file_yaml("clash", &["1"], &[], &[]),
    );
    let second = write_build_file(
        dir.path().join("second.yaml"),
        &build_file_yaml("clash", &["1"], &[], &[]),
    );
    let top = package(&dir, "top", &[&first, &second]);

    let error = resolve(&top).expect_err("two packages cannot share one archive name");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains("clash-1.cpkg") || report.contains("clash"),
        "the diagnostic must name the archive being fought over: {report}"
    );
}

#[test]
fn a_build_file_whose_commands_cannot_be_classified_is_rejected() {
    let dir = tempdir().expect("a temporary directory");
    let unclassifiable = write_build_file(
        dir.path().join("weird.yaml"),
        &build_file_yaml(
            "weird",
            &["1"],
            &[],
            &["/pm-integration-test/not-a-known-build-command --wat"],
        ),
    );
    let top = package(&dir, "top", &[&unclassifiable]);

    // Resolution derives every node's policy, so an unclassifiable command in a
    // DEPENDENCY is caught before the root starts building - not three packages
    // into the run.
    resolve(&top).expect_err("an unclassifiable command must not resolve");
}

// --- Building the resolved graph -------------------------------------------
//
// These run real builds, so they are slower than the resolution tests above.
// Each points its own `BuildContext` at its own temporary directory rather
// than moving the process-wide current directory, so they need no lock to run
// alongside each other.

/// A step that sleeps `seconds` and then stamps a file into `DESTDIR`.
///
/// The sleep is what makes concurrency observable: four of these at `-j4`
/// finish in about the time one takes, and at `-j1` in about four times that.
fn slow_package(dir: &TempDir, name: &str, seconds: &str, deps: &[&Path]) -> PathBuf {
    let script = dir.path().join(format!("{name}.sh"));
    write(
        &script,
        format!("set -eu\nsleep {seconds}\necho {name} > \"$DESTDIR/{name}.stamp\"\n"),
    )
    .expect("write the build script");
    write_build_file(
        dir.path().join(format!("{name}.yaml")),
        &build_file_yaml(
            name,
            &["1"],
            deps,
            &[&format!("/bin/sh {}", script.display())],
        ),
    )
}

/// A package whose only step fails.
fn failing_package(dir: &TempDir, name: &str, deps: &[&Path]) -> PathBuf {
    let script = dir.path().join(format!("{name}.sh"));
    write(&script, format!("echo {name} is doomed\nexit 3\n")).expect("write the build script");
    write_build_file(
        dir.path().join(format!("{name}.yaml")),
        &build_file_yaml(
            name,
            &["1"],
            deps,
            &[&format!("/bin/sh {}", script.display())],
        ),
    )
}

/// Resolves and builds `root`, with its dependencies resolved against `at` and
/// every archive it produces landing there, using `jobs` workers.
fn build_at(root: &Path, at: &Path, jobs: usize) -> miette::Result<PathBuf> {
    timed_build_at(root, at, jobs).0
}

/// As [`build_at`], also reporting how long the build itself took.
///
/// The clock starts after resolution, timing only [`Graph::build_in`] itself.
/// Nothing here moves the process's current directory - each call gets its own
/// [`BuildContext`] pointed at `at` - so, unlike when this test suite serialised
/// concurrent builds on a shared cwd, one test's timing is never inflated by a
/// sibling test's build running at the same time.
fn timed_build_at(root: &Path, at: &Path, jobs: usize) -> (miette::Result<PathBuf>, Duration) {
    let options = BuildOptions {
        jobs: NonZeroUsize::new(jobs),
        ..BuildOptions::default()
    };
    let build = BuildFile::load_unverified(root).expect("the root build file must load");
    let ctx = BuildContext::from_env()
        .expect("capture the ambient build context")
        .with_cwd(at.to_path_buf())
        .with_output_dir(at.to_path_buf());
    let graph = match Graph::resolve_in(&ctx, &build, options) {
        Ok(graph) => graph,
        Err(report) => return (Err(report), Duration::ZERO),
    };

    let started = Instant::now();
    let result = graph.build_in(&ctx, options, &Progress::disabled());
    (result, started.elapsed())
}

#[test]
fn a_graph_builds_every_package_and_returns_the_roots_archive() {
    let dir = tempdir().expect("a temporary directory");
    let left = slow_package(&dir, "gleft", "0", &[]);
    let right = slow_package(&dir, "gright", "0", &[]);
    let top = slow_package(&dir, "gtop", "0", &[&left, &right]);

    let archive = build_at(&top, dir.path(), 4).expect("the graph must build");

    assert_eq!(
        archive.file_name().expect("the archive must have a name"),
        "gtop-1.cpkg",
        "the build must hand back the ROOT's archive"
    );
    for name in ["gleft-1", "gright-1", "gtop-1"] {
        assert!(
            dir.path().join(format!("{name}.cpkg")).is_file(),
            "{name}.cpkg was not produced"
        );
    }
}

#[test]
fn independent_packages_build_at_the_same_time() {
    let dir = tempdir().expect("a temporary directory");
    let deps: Vec<PathBuf> = (0..4)
        .map(|i| slow_package(&dir, &format!("par{i}"), "2", &[]))
        .collect();
    let borrowed: Vec<&Path> = deps.iter().map(PathBuf::as_path).collect();
    let top = slow_package(&dir, "partop", "0", &borrowed);

    let (result, elapsed) = timed_build_at(&top, dir.path(), 4);
    result.expect("the graph must build");

    // Four 2-second sleeps take 8s sequentially. The margin is deliberately
    // enormous: this asserts "they overlapped", not a throughput figure.
    assert!(
        elapsed < Duration::from_secs(7),
        "four independent 2s packages took {elapsed:?} at -j4; they did not overlap"
    );
}

#[test]
fn one_job_builds_them_one_at_a_time() {
    let dir = tempdir().expect("a temporary directory");
    let deps: Vec<PathBuf> = (0..3)
        .map(|i| slow_package(&dir, &format!("seq{i}"), "1", &[]))
        .collect();
    let borrowed: Vec<&Path> = deps.iter().map(PathBuf::as_path).collect();
    let top = slow_package(&dir, "seqtop", "0", &borrowed);

    let (result, elapsed) = timed_build_at(&top, dir.path(), 1);
    result.expect("the graph must build");

    assert!(
        elapsed >= Duration::from_secs(3),
        "three 1s packages took {elapsed:?} at -j1; they must not have overlapped"
    );
}

#[test]
fn an_unrelated_package_still_builds_when_another_fails() {
    let dir = tempdir().expect("a temporary directory");
    let doomed = failing_package(&dir, "fdoomed", &[]);
    let fine = slow_package(&dir, "ffine", "0", &[]);
    let top = slow_package(&dir, "ftop", "0", &[&doomed, &fine]);

    let error =
        build_at(&top, dir.path(), 4).expect_err("a failing dependency must fail the build");

    assert!(
        dir.path().join("ffine-1.cpkg").is_file(),
        "a package unrelated to the failure must still have been built"
    );
    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains("fdoomed"),
        "the diagnostic must name what failed: {report}"
    );
}

#[test]
fn every_independent_failure_is_reported_not_just_the_first() {
    let dir = tempdir().expect("a temporary directory");
    let first = failing_package(&dir, "mfirst", &[]);
    let second = failing_package(&dir, "msecond", &[]);
    let top = slow_package(&dir, "mtop", "0", &[&first, &second]);

    let error = build_at(&top, dir.path(), 4).expect_err("both dependencies fail");

    let report = format!("{error}\n{error:?}");
    assert!(
        report.contains("mfirst") && report.contains("msecond"),
        "both independent failures must be reported, got: {report}"
    );
}

#[test]
fn a_package_whose_dependency_failed_is_never_started() {
    let dir = tempdir().expect("a temporary directory");
    let doomed = failing_package(&dir, "sdoomed", &[]);
    // `sdependent` stamps a file if its step ever runs. It must not.
    let dependent = slow_package(&dir, "sdependent", "0", &[&doomed]);
    let top = slow_package(&dir, "stop", "0", &[&dependent]);

    let error = build_at(&top, dir.path(), 4).expect_err("the build must fail");

    assert!(
        !dir.path().join("sdependent-1.cpkg").is_file(),
        "a package whose dependency failed must not be built"
    );
    assert!(
        !dir.path().join("stop-1.cpkg").is_file(),
        "the root must not be built when something under it failed"
    );
    let report = format!("{error}\n{error:?}");
    assert!(
        report.to_lowercase().contains("skip"),
        "the diagnostic must say what was skipped and why: {report}"
    );
}

#[test]
fn a_shared_dependency_is_built_once_however_many_workers_there_are() {
    let dir = tempdir().expect("a temporary directory");
    // `dshared` takes 3 seconds. Both `dleft` and `dright` need it, and at -j4
    // there are workers spare to build it twice over if the scheduler ever let
    // them. Timing is the assertion because "built once" is not visible in the
    // output: a second build would overwrite the first archive and look
    // identical. Two builds of a 3s package cannot finish in under 5s.
    let shared = slow_package(&dir, "dshared", "3", &[]);
    let left = slow_package(&dir, "dleft", "0", &[&shared]);
    let right = slow_package(&dir, "dright", "0", &[&shared]);
    let top = slow_package(&dir, "dtop", "0", &[&left, &right]);

    let (result, elapsed) = timed_build_at(&top, dir.path(), 4);
    result.expect("the diamond must build");

    assert!(
        elapsed < Duration::from_secs(5),
        "a diamond took {elapsed:?} at -j4; the shared dependency was built more than once"
    );
    assert!(
        dir.path().join("dshared-1.cpkg").is_file(),
        "the shared dependency must have been built at all"
    );
}

#[test]
fn every_dependent_of_one_package_is_built_when_it_finishes() {
    let dir = tempdir().expect("a temporary directory");
    // Five dependents of one package, and more workers than there is work.
    // All five become ready at the same instant `wshared` settles, which is
    // the moment a scheduler that released readiness badly would drop one.
    let shared = slow_package(&dir, "wshared", "1", &[]);
    let dependents: Vec<PathBuf> = (0..5)
        .map(|i| slow_package(&dir, &format!("wdep{i}"), "0", &[&shared]))
        .collect();
    let borrowed: Vec<&Path> = dependents.iter().map(PathBuf::as_path).collect();
    let top = slow_package(&dir, "wtop", "0", &borrowed);

    build_at(&top, dir.path(), 8).expect("the graph must build");

    // Deliberately not timed. Everything here is dominated by fixed
    // per-package overhead - workspaces, sandboxes, permission inference,
    // packaging - so a wall-clock budget would be measuring the machine, not
    // the scheduler. That a shared package is built once is settled
    // structurally by `a_diamond_resolves_to_one_node_per_build_file`.
    for i in 0..5 {
        assert!(
            dir.path().join(format!("wdep{i}-1.cpkg")).is_file(),
            "wdep{i} was not built, though wshared finished"
        );
    }
    assert!(
        dir.path().join("wtop-1.cpkg").is_file(),
        "the root must build once all five of its dependencies have"
    );
}
