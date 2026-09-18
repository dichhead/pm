//! Tests for [`pm::perms`]: the permission model and its three signals.
//!
//! The three signals are tested against real inputs - real source files parsed by real
//! grammars, real ELF objects off this machine, a real traced process - because every
//! interesting failure of this module is a failure of *inference*, and a mock cannot be
//! wrong in the way a grammar or an ELF header can.
//!
//! Two properties get proved in both directions on purpose. A source scanner that
//! detected nothing would pass every "must not match" test vacuously, so each language
//! has a positive test as well; and a path collapser that collapsed nothing would pass
//! the `/usr` versus `/usrlocal` test vacuously, so there is a test that a genuine
//! sub-path *is* collapsed.
//!
//! [`elf`] gets a hostile-input corpus of its own, since it is the only module here that
//! parses attacker-controlled bytes. Every fixture is asserted to produce a diagnostic
//! within a time budget: a panic fails the test, and so does a spin.

use std::{
    fs::{File, create_dir_all, write},
    io::Read as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use pm::perms::{
    Enforcement, Grant, Permission, Permissions, Provenance, elf, monitor, monitor::TraceOptions,
    source,
};
use tempfile::{TempDir, tempdir};

// ---------------------------------------------------------------------------
// The model: unification, collapsing and the refusal to collapse look-alikes.
// ---------------------------------------------------------------------------

/// Two signals asking for the same path must produce ONE grant carrying both
/// provenances. That agreement is the single most useful thing in a report, and
/// concatenating instead would hide it behind two near-identical lines.
#[test]
fn the_same_path_from_two_signals_becomes_one_grant_with_both_provenances() {
    let from_source = Permissions::from_grants([Grant::new(
        Permission::ReadPath(PathBuf::from("/etc/ssl")),
        Provenance::SourceAnalysis,
        ["src/tls.c:12: c:path-literal"],
    )]);
    let from_monitor = Permissions::from_grants([Grant::new(
        Permission::ReadPath(PathBuf::from("/etc/ssl")),
        Provenance::RuntimeMonitor,
        ["openat /etc/ssl (pid 1)"],
    )]);

    let merged = Permissions::merge([from_source, from_monitor]);

    assert_eq!(merged.len(), 1, "{}", merged.report());
    let grant = &merged.grants()[0];
    assert_eq!(
        grant.permission(),
        &Permission::ReadPath(PathBuf::from("/etc/ssl"))
    );
    assert_eq!(
        grant.provenance(),
        [Provenance::SourceAnalysis, Provenance::RuntimeMonitor],
        "both signals must survive the merge"
    );
    assert_eq!(
        grant.evidence().len(),
        2,
        "both evidence lines must survive"
    );
}

/// `/usrlocal` starts with the string `/usr` and is not under it. A `starts_with` on the
/// raw text would silently hand a package the whole of `/usr` for asking after
/// `/usrlocal` - widening the sandbox in exactly the direction that hurts.
#[test]
fn paths_that_share_a_string_prefix_are_not_collapsed_into_each_other() {
    let merged = Permissions::from_grants([
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr")),
            Provenance::ElfAnalysis,
            ["DT_NEEDED libc.so.6"],
        ),
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usrlocal")),
            Provenance::ElfAnalysis,
            ["DT_RUNPATH /usrlocal"],
        ),
    ]);

    let paths: Vec<&Path> = merged.read_paths().collect();
    assert_eq!(
        paths,
        [Path::new("/usr"), Path::new("/usrlocal")],
        "neither path covers the other"
    );
}

/// The other direction, so the test above cannot pass by collapsing nothing at all.
#[test]
fn a_real_subpath_does_collapse_into_its_ancestor() {
    let merged = Permissions::from_grants([
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr")),
            Provenance::ElfAnalysis,
            ["DT_NEEDED libc.so.6"],
        ),
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr/lib64/man-db")),
            Provenance::SourceAnalysis,
            ["src/man.c:3: c:path-literal"],
        ),
    ]);

    let paths: Vec<&Path> = merged.read_paths().collect();
    assert_eq!(paths, [Path::new("/usr")], "{}", merged.report());

    let grant = &merged.grants()[0];
    assert_eq!(
        grant.provenance(),
        [Provenance::SourceAnalysis, Provenance::ElfAnalysis],
        "the swallowed grant's provenance moves to the survivor"
    );
    assert!(
        grant
            .evidence()
            .iter()
            .any(|line| line == "covers /usr/lib64/man-db"),
        "the collapse must leave a trace: {:?}",
        grant.evidence()
    );
}

/// Collapsing is per-kind. A read of `/usr` says nothing about a write to `/usr/lib`,
/// and folding the two together would invent a write grant on all of `/usr`.
#[test]
fn a_read_grant_never_swallows_a_write_grant_below_it() {
    let merged = Permissions::from_grants([
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr")),
            Provenance::ElfAnalysis,
            ["DT_NEEDED libc.so.6"],
        ),
        Grant::new(
            Permission::WritePath(PathBuf::from("/usr/lib/cache")),
            Provenance::RuntimeMonitor,
            ["openat /usr/lib/cache (pid 1)"],
        ),
    ]);

    assert_eq!(merged.read_paths().collect::<Vec<_>>(), [Path::new("/usr")]);
    assert_eq!(
        merged.write_paths().collect::<Vec<_>>(),
        [Path::new("/usr/lib/cache")]
    );
}

/// A path holding `..` cannot be reasoned about lexically - only the run-time filesystem
/// knows what it resolves to - so it must never be treated as covered.
#[test]
fn a_parent_dir_component_blocks_collapsing() {
    let merged = Permissions::from_grants([
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr")),
            Provenance::ElfAnalysis,
            ["a"],
        ),
        Grant::new(
            Permission::ReadPath(PathBuf::from("/usr/lib/../../etc/shadow")),
            Provenance::ElfAnalysis,
            ["b"],
        ),
    ]);
    assert_eq!(merged.len(), 2, "{}", merged.report());
}

/// Nothing in the crate promotes a derived profile, so the default must be the safe one.
#[test]
fn a_fresh_profile_is_audit_only() {
    assert_eq!(Enforcement::default(), Enforcement::Audit);
    assert!(!Enforcement::default().denies());
    assert!(Enforcement::Enforce.denies());
}

/// An empty group is printed as `(none)` rather than omitted: the absence of network
/// access is a fact a reviewer needs to see stated, not inferred from a missing heading.
#[test]
fn the_report_states_the_caveat_and_every_empty_group() {
    let report = Permissions::default().report();
    assert!(report.contains("necessarily incomplete"), "{report}");
    assert!(report.contains("audit mode"), "{report}");
    for group in ["read", "write", "exec", "network", "spawn"] {
        assert!(report.contains(group), "{group} missing from:\n{report}");
    }
    assert_eq!(report.matches("(none)").count(), 5, "{report}");
}

// ---------------------------------------------------------------------------
// source: six languages, both directions.
// ---------------------------------------------------------------------------

/// Write one source file into a fresh directory and scan it.
fn scan_one(name: &str, contents: &str) -> (TempDir, Permissions) {
    let dir = tempdir().expect("temp dir");
    write(dir.path().join(name), contents).expect("write sample");
    let permissions = source::scan(dir.path()).expect("scan");
    (dir, permissions)
}

/// Whether the set holds exactly this permission.
fn holds(permissions: &Permissions, wanted: &Permission) -> bool {
    permissions
        .grants()
        .iter()
        .any(|grant| grant.permission() == wanted)
}

#[test]
fn c_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.c",
        r#"
#include <stdio.h>
#include <sys/socket.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    FILE *r = fopen("/etc/passwd", "r");
    FILE *w = fopen("/var/log/app.log", "a");
    return fd + (r != w);
}
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(
        holds(&found, &Permission::ReadPath(PathBuf::from("/etc/passwd"))),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/log/app.log"))
        ),
        "{}",
        found.report()
    );
    assert!(
        !holds(
            &found,
            &Permission::ReadPath(PathBuf::from("/var/log/app.log"))
        ),
        "the mode argument from the same call must win over the bare literal:\n{}",
        found.report()
    );
    assert!(
        found.grants()[0]
            .provenance()
            .contains(&Provenance::SourceAnalysis),
        "source grants must be attributed to source analysis"
    );
}

#[test]
fn cpp_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.cpp",
        r#"
#include <fstream>
#include <sys/socket.h>

int main() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    std::ofstream log("/var/log/cpp.log");
    return fd;
}
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/log/cpp.log"))
        ),
        "{}",
        found.report()
    );
}

#[test]
fn rust_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.rs",
        r#"
use std::net::TcpStream;
use std::process::Command;
use std::fs::File;

fn main() {
    let _ = TcpStream::connect("127.0.0.1:80");
    let _ = Command::new("/usr/bin/ls").status();
    let _ = File::create("/var/lib/app/state");
    let _ = std::fs::read("/etc/ssl/certs/ca.pem");
}
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(found.wants_spawn(), "{}", found.report());
    assert!(
        holds(&found, &Permission::ExecPath(PathBuf::from("/usr/bin/ls"))),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/lib/app/state"))
        ),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::ReadPath(PathBuf::from("/etc/ssl/certs/ca.pem"))
        ),
        "{}",
        found.report()
    );
}

#[test]
fn python_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.py",
        r#"
import socket
import subprocess

def main():
    s = socket.socket()
    subprocess.run(["/bin/true"])
    with open("/var/lib/app.db", "w") as db:
        db.write("x")
    with open("/etc/hosts", "r") as hosts:
        hosts.read()
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(found.wants_spawn(), "{}", found.report());
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/lib/app.db"))
        ),
        "{}",
        found.report()
    );
    assert!(
        holds(&found, &Permission::ReadPath(PathBuf::from("/etc/hosts"))),
        "{}",
        found.report()
    );
}

#[test]
fn go_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.go",
        r#"
package main

import (
	"net/http"
	"os"
	"os/exec"
)

func main() {
	http.Get("http://example.invalid")
	exec.Command("/bin/true").Run()
	os.OpenFile("/var/log/x.log", os.O_WRONLY|os.O_CREATE, 0644)
	os.ReadFile("/etc/resolv.conf")
}
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(found.wants_spawn(), "{}", found.report());
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/log/x.log"))
        ),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::ReadPath(PathBuf::from("/etc/resolv.conf"))
        ),
        "{}",
        found.report()
    );
}

#[test]
fn bash_calls_are_detected() {
    let (_dir, found) = scan_one(
        "net.sh",
        r#"
curl https://example.invalid/pkg.tar.gz
cat /etc/hostname
echo hello > /var/log/out.log
exec /usr/bin/true
"#,
    );
    assert!(found.wants_network(), "{}", found.report());
    assert!(found.wants_spawn(), "{}", found.report());
    assert!(
        holds(
            &found,
            &Permission::ReadPath(PathBuf::from("/etc/hostname"))
        ),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::WritePath(PathBuf::from("/var/log/out.log"))
        ),
        "{}",
        found.report()
    );
    assert!(
        holds(
            &found,
            &Permission::ExecPath(PathBuf::from("/usr/bin/true"))
        ),
        "{}",
        found.report()
    );
}

/// The five look-alikes a regex-based scanner gets wrong, in every language at once:
/// `my_socket_wrapper`, the word `connection`, a `disconnect()` call, a commented-out
/// `socket()`, and the word `system` in a comment and in a string literal. None of them
/// is a call to anything, and none is excluded by a list - they are simply different
/// nodes.
#[test]
fn look_alikes_grant_nothing_in_any_language() {
    let dir = tempdir().expect("temp dir");
    for (name, contents) in NEGATIVES {
        write(dir.path().join(name), contents).expect("write negative");
    }

    let found = source::scan(dir.path()).expect("scan");

    assert!(
        found.is_empty(),
        "look-alikes must grant nothing, got:\n{}",
        found.report()
    );
}

/// Each negative on its own, so a single language's failure is named rather than hidden
/// in the pile above.
#[test]
fn look_alikes_grant_nothing_language_by_language() {
    for (name, contents) in NEGATIVES {
        let (_dir, found) = scan_one(name, contents);
        assert!(
            found.is_empty(),
            "{name} must grant nothing, got:\n{}",
            found.report()
        );
    }
}

/// One file per language holding only the look-alikes.
const NEGATIVES: [(&str, &str); 6] = [
    (
        "quiet.c",
        r#"
/* socket(AF_INET, SOCK_STREAM, 0); is commented out here */
// system("rm -rf /") is only a comment
struct conn { int socket; };
int my_socket_wrapper(struct conn *connection);
void disconnect(void);

void go(struct conn *connection) {
    my_socket_wrapper(connection);
    disconnect();
    const char *a = "system";
    const char *b = "socket(AF_INET)";
    (void)a; (void)b;
}
"#,
    ),
    (
        "quiet.cpp",
        r#"
/* ::socket(AF_INET, SOCK_STREAM, 0); is commented out here */
// std::system("rm -rf /") is only a comment
struct conn { int socket; };
int my_socket_wrapper(conn *connection);
void disconnect();

void go(conn *connection) {
    my_socket_wrapper(connection);
    disconnect();
    const char *a = "system";
    const char *b = "socket(AF_INET)";
    (void)a; (void)b;
}
"#,
    ),
    (
        "quiet.rs",
        r#"
// use std::net::TcpStream; is commented out here
// Command::new("/bin/sh") is only a comment
struct Conn { socket: i32 }

fn my_socket_wrapper(connection: &Conn) -> i32 { connection.socket }
fn disconnect() {}

fn go(connection: &Conn) {
    let _ = my_socket_wrapper(connection);
    disconnect();
    let _ = "system";
    let _ = "socket";
}
"#,
    ),
    (
        "quiet.py",
        r#"
# import socket is commented out here
# os.system("rm -rf /") is only a comment
class Conn:
    socket = 1

def my_socket_wrapper(connection):
    return connection.socket

def disconnect():
    pass

def go(connection):
    my_socket_wrapper(connection)
    disconnect()
    a = "system"
    b = "import socket"
    return (a, b)
"#,
    ),
    (
        "quiet.go",
        r#"
package main

// import "net/http" is commented out here
// exec.Command("/bin/sh") is only a comment

type conn struct{ socket int }

func my_socket_wrapper(connection *conn) int { return connection.socket }

func disconnect() {}

func main() {
	connection := &conn{socket: 1}
	_ = my_socket_wrapper(connection)
	disconnect()
	_ = "system"
	_ = "os/exec"
}
"#,
    ),
    (
        "quiet.sh",
        r#"
# curl https://example.invalid is commented out here
# system("rm -rf /") is only a comment
my_socket_wrapper="not a command"
connection="open"
disconnect_note='disconnect() is only text here'
what="system"
"#,
    ),
];

/// The query table is public so `pm` can print what it looks for; if it ever went empty
/// every negative test above would pass vacuously.
#[test]
fn every_language_carries_queries() {
    let languages = source::languages();
    assert_eq!(languages.len(), 6);
    for rules in languages {
        assert!(
            !rules.extensions.is_empty(),
            "{} has no extensions",
            rules.name
        );
        assert!(!rules.queries.is_empty(), "{} has no queries", rules.name);
    }
}

/// Generated, vendored and version-control trees are skipped; a bait file in each proves
/// it, and the same bait at the top level proves the scan was working at all.
#[test]
fn vendored_and_generated_trees_are_skipped() {
    let dir = tempdir().expect("temp dir");
    let bait = "int main(void) { return socket(AF_INET, SOCK_STREAM, 0); }\n";
    for skipped in ["vendor", "target", ".git", "node_modules"] {
        let sub = dir.path().join(skipped);
        create_dir_all(&sub).expect("mkdir");
        write(sub.join("bait.c"), bait).expect("write bait");
    }
    assert!(source::scan(dir.path()).expect("scan").is_empty());

    write(dir.path().join("bait.c"), bait).expect("write bait");
    assert!(
        source::scan(dir.path()).expect("scan").wants_network(),
        "the same file at the top level must be seen"
    );
}

// ---------------------------------------------------------------------------
// elf: the positive case, then the hostile corpus.
// ---------------------------------------------------------------------------

/// A dynamically linked binary that is definitely on this machine: the test binary.
fn a_real_binary() -> PathBuf {
    std::env::current_exe().expect("current exe")
}

#[test]
fn a_real_binary_names_libc_and_its_loader() {
    let binary = a_real_binary();

    let needed = elf::needed_libraries(&binary).expect("needed libraries");
    assert!(
        needed.iter().any(|library| library.starts_with("libc.so")),
        "expected a libc among {needed:?}"
    );

    let interpreter = elf::interpreter(&binary).expect("interpreter");
    assert!(
        interpreter
            .as_deref()
            .is_some_and(|loader| loader.contains("ld-linux")),
        "expected a dynamic loader, got {interpreter:?}"
    );

    let permissions = elf::analyse(&binary)
        .expect("analyse")
        .expect("the test binary is an ELF");
    assert!(!permissions.is_empty(), "{}", permissions.report());
    assert!(
        permissions
            .exec_paths()
            .any(|path| path.starts_with("/lib64") || path.starts_with("/lib")),
        "the loader's directory must be executable:\n{}",
        permissions.report()
    );
    assert!(
        !permissions
            .read_paths()
            .any(|path| path == binary.as_path()),
        "the staging path of the analysed object must not enter the profile"
    );
}

/// A file that is not an ELF at all is reported as such, not as an error: a staging tree
/// is full of scripts, manuals and data, and a caller must be able to hand over every
/// regular file it finds.
#[test]
fn a_non_elf_file_is_not_an_error() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("readme.txt");
    write(&path, "this is not an ELF object\n").expect("write");

    assert!(elf::analyse(&path).expect("analyse").is_none());
    assert!(elf::needed_libraries(&path).expect("needed").is_empty());
    assert!(elf::runpath(&path).expect("runpath").is_empty());
    assert!(elf::interpreter(&path).expect("interp").is_none());
}

// --- the hostile ELF corpus ------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const HEADER_LEN: usize = 64;
const PHDR_LEN: usize = 56;
const VADDR_BASE: u64 = 0x1000;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;

/// No hostile fixture may take longer than this. A parser that spins on a crafted count
/// is as much of a denial of service as one that panics, and only a clock catches it.
const BUDGET: Duration = Duration::from_secs(5);

/// A well-formed dynamic ELF64, with one knob per way of breaking it.
///
/// Every fixture below is [`Fixture::default`] with a single field changed, so a failing
/// test names exactly which malformation got through.
struct Fixture {
    class: u8,
    endian: u8,
    phentsize: u16,
    /// `None` keeps the honest count.
    phnum: Option<u16>,
    /// `None` keeps the honest offset.
    phoff: Option<u64>,
    /// Include a `PT_LOAD` segment, without which no virtual address resolves.
    load: bool,
    /// How much of the file the `PT_LOAD` segment claims to map.
    load_filesz: Option<u64>,
    interp: Option<&'static str>,
    /// `DT_NEEDED` string-table offsets.
    needed: Vec<u64>,
    strtab: Vec<u8>,
    /// `None` computes the honest virtual address of the string table.
    strtab_addr: Option<u64>,
    /// `None` uses the honest size.
    strsz: Option<u64>,
    dynamic_offset: Option<u64>,
    dynamic_filesz: Option<u64>,
    /// Cut the assembled file down to this many bytes.
    truncate_to: Option<usize>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            class: ELFCLASS64,
            endian: ELFDATA2LSB,
            phentsize: PHDR_LEN as u16,
            phnum: None,
            phoff: None,
            load: true,
            load_filesz: None,
            interp: Some("/lib64/ld-linux-x86-64.so.2"),
            needed: vec![0],
            strtab: b"libc.so.6\0".to_vec(),
            strtab_addr: None,
            strsz: None,
            dynamic_offset: None,
            dynamic_filesz: None,
            truncate_to: None,
        }
    }
}

impl Fixture {
    /// Assemble the bytes: header, program header table, interpreter string, string
    /// table, dynamic array - in that order, each at a known offset.
    fn build(&self) -> Vec<u8> {
        let count = usize::from(self.load) + usize::from(self.interp.is_some()) + 1;
        let table_len = count * usize::from(self.phentsize);
        let interp_off = HEADER_LEN + table_len;
        let interp_len = self.interp.map_or(0, |name| name.len() + 1);
        let strtab_off = interp_off + interp_len;
        let dynamic_off = strtab_off + self.strtab.len();

        let mut dynamic: Vec<(u64, u64)> = self
            .needed
            .iter()
            .map(|offset| (DT_NEEDED, *offset))
            .collect();
        dynamic.push((
            DT_STRTAB,
            self.strtab_addr.unwrap_or(VADDR_BASE + strtab_off as u64),
        ));
        dynamic.push((DT_STRSZ, self.strsz.unwrap_or(self.strtab.len() as u64)));
        dynamic.push((DT_NULL, 0));
        let dynamic_len = dynamic.len() * 16;
        let total = dynamic_off + dynamic_len;

        let mut phdrs: Vec<(u32, u64, u64, u64)> = Vec::new();
        if self.load {
            phdrs.push((
                PT_LOAD,
                0,
                VADDR_BASE,
                self.load_filesz.unwrap_or(total as u64),
            ));
        }
        if self.interp.is_some() {
            phdrs.push((
                PT_INTERP,
                interp_off as u64,
                VADDR_BASE + interp_off as u64,
                interp_len as u64,
            ));
        }
        phdrs.push((
            PT_DYNAMIC,
            self.dynamic_offset.unwrap_or(dynamic_off as u64),
            VADDR_BASE + dynamic_off as u64,
            self.dynamic_filesz.unwrap_or(dynamic_len as u64),
        ));

        let mut out = vec![0u8; HEADER_LEN];
        out[..4].copy_from_slice(&ELF_MAGIC);
        out[4] = self.class;
        out[5] = self.endian;
        out[6] = 1; // EI_VERSION
        out[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[32..40].copy_from_slice(&self.phoff.unwrap_or(HEADER_LEN as u64).to_le_bytes());
        out[52..54].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[54..56].copy_from_slice(&self.phentsize.to_le_bytes());
        out[56..58].copy_from_slice(&self.phnum.unwrap_or(count as u16).to_le_bytes());

        for (kind, offset, vaddr, filesz) in phdrs {
            let mut entry = vec![0u8; usize::from(self.phentsize).max(PHDR_LEN)];
            entry[0..4].copy_from_slice(&kind.to_le_bytes());
            entry[8..16].copy_from_slice(&offset.to_le_bytes());
            entry[16..24].copy_from_slice(&vaddr.to_le_bytes());
            entry[32..40].copy_from_slice(&filesz.to_le_bytes());
            entry[40..48].copy_from_slice(&filesz.to_le_bytes()); // p_memsz
            entry.truncate(usize::from(self.phentsize));
            out.extend_from_slice(&entry);
        }

        if let Some(name) = self.interp {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        out.extend_from_slice(&self.strtab);
        for (tag, value) in dynamic {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        }

        if let Some(limit) = self.truncate_to {
            out.truncate(limit);
        }
        out
    }
}

/// Run all four public entry points over `bytes` and return how each one ended, timing
/// the whole thing. A panic inside any of them fails the test by unwinding; a spin fails
/// it on [`BUDGET`].
fn probe(name: &str, bytes: &[u8]) -> (Duration, miette::Result<Option<Permissions>>) {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join(name);
    write(&path, bytes).expect("write fixture");

    let started = Instant::now();
    let analysed = elf::analyse(&path);
    let _ = elf::needed_libraries(&path);
    let _ = elf::runpath(&path);
    let _ = elf::interpreter(&path);
    let elapsed = started.elapsed();

    assert!(
        elapsed < BUDGET,
        "{name} took {elapsed:?}, which is a denial of service even if it terminates"
    );
    (elapsed, analysed)
}

/// Assert `bytes` is rejected with a diagnostic, and return the message.
fn must_reject(name: &str, bytes: &[u8]) -> String {
    let (elapsed, outcome) = probe(name, bytes);
    match outcome {
        Err(report) => {
            let message = report.to_string();
            println!("{name}: rejected in {elapsed:?}: {message}");
            message
        }
        Ok(other) => panic!("{name} was accepted: {other:?}"),
    }
}

#[test]
fn the_baseline_fixture_parses_so_the_corpus_is_not_vacuous() {
    let bytes = Fixture::default().build();
    let (_, outcome) = probe("baseline", &bytes);
    let permissions = outcome
        .expect("the unmutated fixture must parse")
        .expect("it is an ELF");
    // The loader itself collapses into `/lib64`, which the bare-soname search path
    // already covers - so the grant to look for is the directory, carrying the
    // `PT_INTERP` evidence and the `covers` note the collapse leaves behind.
    let loader = permissions
        .grants()
        .iter()
        .find(|grant| grant.permission() == &Permission::ExecPath(PathBuf::from("/lib64")))
        .unwrap_or_else(|| panic!("no exec grant on /lib64:\n{}", permissions.report()));
    assert!(
        loader
            .evidence()
            .iter()
            .any(|line| line == "PT_INTERP /lib64/ld-linux-x86-64.so.2"),
        "the interpreter must be named in the evidence: {:?}",
        loader.evidence()
    );
    assert!(
        permissions
            .read_paths()
            .any(|path| path == Path::new("/lib64")),
        "libc.so.6 is searched for along the library path:\n{}",
        permissions.report()
    );
}

#[test]
fn a_truncated_elf_is_rejected() {
    let message = must_reject("stub", b"\x7fELF\x02\x01\x01");
    assert!(message.contains("too short"), "{message}");

    let whole = Fixture::default().build();
    for cut in [8, 40, 63, HEADER_LEN + 8, HEADER_LEN + PHDR_LEN + 4] {
        let message = must_reject("cut", &whole[..cut.min(whole.len())]);
        assert!(
            message.contains("malformed ELF") || message.contains("too short"),
            "{message}"
        );
    }
}

#[test]
fn a_huge_program_header_count_is_rejected() {
    let bytes = Fixture {
        phnum: Some(60_000),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("phnum", &bytes);
    assert!(message.contains("program header cap"), "{message}");
}

#[test]
fn the_pn_xnum_program_header_escape_is_rejected() {
    let bytes = Fixture {
        phnum: Some(0xffff),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("pn-xnum", &bytes);
    assert!(message.contains("PN_XNUM"), "{message}");
}

#[test]
fn a_program_header_table_past_the_end_is_rejected() {
    let bytes = Fixture {
        phoff: Some(1 << 40),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("phoff", &bytes);
    assert!(message.contains("program header table"), "{message}");
}

#[test]
fn a_dynamic_segment_past_the_end_is_rejected() {
    let bytes = Fixture {
        dynamic_offset: Some(1 << 40),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("dyn-off", &bytes);
    assert!(message.contains("PT_DYNAMIC"), "{message}");

    let bytes = Fixture {
        dynamic_filesz: Some(u64::MAX),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("dyn-size", &bytes);
    assert!(message.contains("entry cap"), "{message}");
}

#[test]
fn a_string_table_address_no_segment_covers_is_rejected() {
    let bytes = Fixture {
        strtab_addr: Some(0xdead_beef),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("strtab-vaddr", &bytes);
    assert!(message.contains("PT_LOAD"), "{message}");

    // The same thing by removing the only segment that could have covered it.
    let bytes = Fixture {
        load: false,
        ..Fixture::default()
    }
    .build();
    let message = must_reject("strtab-noload", &bytes);
    assert!(message.contains("PT_LOAD"), "{message}");
}

#[test]
fn a_string_table_past_the_end_of_the_file_is_rejected() {
    // The address resolves - a PT_LOAD claims to map a gigabyte - but the file offset it
    // translates to is far past the last byte.
    let bytes = Fixture {
        load_filesz: Some(1 << 30),
        strtab_addr: Some(VADDR_BASE + (1 << 20)),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("strtab-eof", &bytes);
    assert!(
        message.contains("runs past the end of the file"),
        "{message}"
    );
}

#[test]
fn an_absurd_string_table_size_is_rejected() {
    let bytes = Fixture {
        strsz: Some(u64::MAX),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("strsz-max", &bytes);
    assert!(message.contains("string table cap"), "{message}");
}

#[test]
fn a_string_table_with_no_terminator_is_rejected() {
    let bytes = Fixture {
        strtab: b"libc.so.6".to_vec(),
        ..Fixture::default()
    }
    .build();
    let message = must_reject("no-nul", &bytes);
    assert!(message.contains("NUL-terminated"), "{message}");

    // And a table that is all non-NUL bytes, so nothing anywhere in it terminates.
    let bytes = Fixture {
        strtab: vec![b'A'; 4096],
        needed: vec![1],
        ..Fixture::default()
    }
    .build();
    let message = must_reject("no-nul-anywhere", &bytes);
    assert!(message.contains("NUL-terminated"), "{message}");
}

#[test]
fn a_needed_offset_outside_the_string_table_is_rejected() {
    let bytes = Fixture {
        needed: vec![1 << 30],
        ..Fixture::default()
    }
    .build();
    let message = must_reject("needed-offset", &bytes);
    assert!(message.contains("DT_NEEDED"), "{message}");
}

/// An object with no program headers at all - a relocatable `.o`, where `e_phentsize` is
/// zero too - is a normal inhabitant of a staging tree, so it must parse to nothing
/// rather than fail the build that shipped it.
#[test]
fn an_object_with_zero_program_headers_yields_no_grants() {
    let mut bytes = vec![0u8; HEADER_LEN];
    bytes[..4].copy_from_slice(&ELF_MAGIC);
    bytes[4] = ELFCLASS64;
    bytes[5] = ELFDATA2LSB;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    bytes[52..54].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    // e_phoff, e_phentsize and e_phnum all stay zero, as a real `.o` has them.

    let (_, outcome) = probe("reloc.o", &bytes);
    let permissions = outcome.expect("a relocatable object is not malformed");
    assert_eq!(permissions.map(|set| set.len()), Some(0));
}

#[test]
fn a_32_bit_elf_is_rejected() {
    let bytes = Fixture {
        class: ELFCLASS32,
        ..Fixture::default()
    }
    .build();
    let message = must_reject("elf32", &bytes);
    assert!(message.contains("EI_CLASS"), "{message}");
}

#[test]
fn a_big_endian_elf_is_rejected() {
    let bytes = Fixture {
        endian: ELFDATA2MSB,
        ..Fixture::default()
    }
    .build();
    let message = must_reject("elf-be", &bytes);
    assert!(message.contains("EI_DATA"), "{message}");
}

/// A program header stride smaller than the 56-byte ELF64 header would make the table
/// overlap itself; a stride larger than that is legal and must still work.
#[test]
fn an_undersized_program_header_stride_is_rejected() {
    let bytes = Fixture {
        phentsize: 10,
        ..Fixture::default()
    }
    .build();
    let message = must_reject("phentsize", &bytes);
    assert!(message.contains("e_phentsize"), "{message}");

    let bytes = Fixture {
        phentsize: 64,
        ..Fixture::default()
    }
    .build();
    let (_, outcome) = probe("phentsize-64", &bytes);
    assert!(
        outcome.expect("a padded stride is legal").is_some(),
        "a stride larger than 56 bytes must still parse"
    );
}

/// Read `bytes` bytes of real kernel entropy.
fn urandom(bytes: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; bytes];
    File::open("/dev/urandom")
        .expect("open /dev/urandom")
        .read_exact(&mut buffer)
        .expect("read /dev/urandom");
    buffer
}

/// 4 KiB of entropy, as it comes: almost never starts with the ELF magic, so the honest
/// answer is "not an ELF".
#[test]
fn raw_random_bytes_are_not_mistaken_for_an_elf() {
    for round in 0..16 {
        let bytes = urandom(4096);
        let (_, outcome) = probe(&format!("random-{round}"), &bytes);
        match outcome {
            Ok(None) | Err(_) => {}
            Ok(Some(permissions)) => panic!("entropy parsed as an ELF:\n{}", permissions.report()),
        }
    }
}

/// The same entropy with the magic forced on, so every byte after it is fed to the real
/// parser. This is the case the module exists to survive: it may reject, it may even
/// accept, but it may not panic and it may not spin.
#[test]
fn random_bytes_behind_the_elf_magic_never_panic_or_spin() {
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let started = Instant::now();
    for round in 0..256 {
        let mut bytes = urandom(4096);
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        let (_, outcome) = probe(&format!("magic-random-{round}"), &bytes);
        match outcome {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    println!(
        "entropy behind the magic: 256 blobs, accepted={accepted} rejected={rejected} \
         panics=0 wall={:?}",
        started.elapsed()
    );
    assert_eq!(accepted + rejected, 256);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "256 random ELFs took {:?}",
        started.elapsed()
    );
}

/// Bit flips in a real binary's structural prefix: the mutations that produce *nearly*
/// valid headers, which is where a parser that trusts one field because another looked
/// sane falls over. Every mutant must terminate; a spin fails the wall-clock assertion
/// and a panic fails by unwinding.
#[test]
fn mutations_of_a_real_binary_never_panic_or_spin() {
    let original = std::fs::read("/bin/ls").expect("read /bin/ls");
    // Only the header, program header table and the segments they point at are worth
    // flipping: a bit in the middle of .text is just a different instruction.
    let structural = original.len().min(8192);
    let entropy = urandom(ROUNDS * 8);

    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("mutant");
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let started = Instant::now();

    for round in 0..ROUNDS {
        let mut bytes = original.clone();
        for step in 0..3 {
            let index = round * 8 + step * 2;
            let position =
                ((usize::from(entropy[index]) << 8) | usize::from(entropy[index + 1])) % structural;
            bytes[position] ^= entropy[index + 1] | 1;
        }
        if round % 7 == 0 {
            let cut = (usize::from(entropy[round * 8 + 7]) * 512).min(bytes.len());
            bytes.truncate(cut);
        }
        write(&path, &bytes).expect("write mutant");

        let round_started = Instant::now();
        match elf::analyse(&path) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
        let _ = elf::needed_libraries(&path);
        assert!(
            round_started.elapsed() < BUDGET,
            "mutant {round} took {:?}",
            round_started.elapsed()
        );
    }

    println!(
        "mutants: {ROUNDS} rounds, accepted={accepted} rejected={rejected} panics=0 \
         wall={:?}",
        started.elapsed()
    );
    assert_eq!(accepted + rejected, ROUNDS);
    assert!(
        rejected > 0,
        "no mutation was structural enough to be caught"
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{ROUNDS} mutants took {:?}",
        started.elapsed()
    );
}

/// Mutants per fuzzing round. Enough to hit every structural field of `/bin/ls`'s first
/// 8 KiB many times over, few enough to keep `cargo test` under a second here.
const ROUNDS: usize = 2000;

// ---------------------------------------------------------------------------
// monitor: what one real execution actually touched.
// ---------------------------------------------------------------------------

#[test]
fn tracing_cat_records_the_file_it_read() {
    let dir = tempdir().expect("temp dir");
    let target = dir.path().join("subject.txt");
    write(&target, "contents\n").expect("write subject");

    let report = monitor::trace(
        Path::new("/bin/cat"),
        &[target.display().to_string()],
        &TraceOptions {
            timeout: Duration::from_secs(20),
            ..TraceOptions::default()
        },
    )
    .expect("trace /bin/cat");

    assert!(!report.timed_out(), "cat should not need 20 seconds");
    assert_eq!(report.exit_status(), Some(0));

    let permissions = report.permissions();
    assert!(
        permissions.read_paths().any(|path| path == target),
        "the traced read of {} is missing:\n{}",
        target.display(),
        permissions.report()
    );
    assert!(
        report
            .observations()
            .iter()
            .any(|observation| observation.syscall() == "openat"),
        "an openat must have been decoded"
    );
    assert!(
        permissions
            .grants()
            .iter()
            .all(|grant| grant.provenance() == [Provenance::RuntimeMonitor]),
        "every traced grant is attributed to the monitor"
    );
    assert!(
        permissions.wants_spawn(),
        "the execve of cat itself is a spawn:\n{}",
        permissions.report()
    );
}

/// A local-socket connection is not network access. Conflating the two would put
/// `Permission::Network` - which keeps the host network namespace - on every package
/// that talks to a logging daemon.
#[test]
fn reading_a_local_file_does_not_ask_for_the_network() {
    let dir = tempdir().expect("temp dir");
    let target = dir.path().join("subject.txt");
    write(&target, "contents\n").expect("write subject");

    let report = monitor::trace(
        Path::new("/bin/cat"),
        &[target.display().to_string()],
        &TraceOptions::default(),
    )
    .expect("trace /bin/cat");

    assert!(
        !report.permissions().wants_network(),
        "cat on a local file wants no network:\n{}",
        report.permissions().report()
    );
}

/// Failed syscalls grant nothing: the loader probes a dozen paths that do not exist on
/// its way to libc, and recording those would write a profile full of fiction.
#[test]
fn a_failed_open_is_observed_but_grants_nothing() {
    let dir = tempdir().expect("temp dir");
    let missing = dir.path().join("definitely-absent.txt");

    let report = monitor::trace(
        Path::new("/bin/cat"),
        &[missing.display().to_string()],
        &TraceOptions::default(),
    )
    .expect("trace /bin/cat");

    assert!(
        !report
            .permissions()
            .read_paths()
            .any(|path| path == missing),
        "a failed open must not become a grant:\n{}",
        report.permissions().report()
    );
    assert!(
        report
            .observations()
            .iter()
            .any(|observation| !observation.succeeded()),
        "the failure must still be observable"
    );
}

/// The timeout has to fire, kill the group and still hand back the prefix it saw. A
/// monitor that hangs on a server or a `read` from a pipe would hang every build.
#[test]
fn the_timeout_fires_on_a_program_that_never_exits() {
    let started = Instant::now();
    let report = monitor::trace(
        Path::new("/bin/sleep"),
        &["30".to_owned()],
        &TraceOptions {
            timeout: Duration::from_millis(700),
            ..TraceOptions::default()
        },
    )
    .expect("trace /bin/sleep");
    let elapsed = started.elapsed();

    assert!(report.timed_out(), "the timeout must be reported");
    assert_eq!(
        report.exit_status(),
        None,
        "a killed process has no exit code"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the timeout fired after {elapsed:?}, not 700ms"
    );
    assert!(
        !report.observations().is_empty(),
        "the partial profile up to the kill is still worth returning"
    );
}

/// A program that does not exist is a diagnostic, not a panic and not a silent empty
/// report that would look like "this package needs nothing".
#[test]
fn tracing_a_missing_program_is_a_diagnostic() {
    let outcome = monitor::trace(
        Path::new("/definitely/not/here"),
        &[],
        &TraceOptions {
            timeout: Duration::from_secs(5),
            ..TraceOptions::default()
        },
    );
    match outcome {
        Err(_) => {}
        Ok(report) => assert!(
            report.exit_status().is_some_and(|code| code != 0),
            "a failed exec must not read as success"
        ),
    }
}

/// The precise regression this module exists to close: a program that never even starts
/// used to come back `Ok` with an empty observation list, which reads exactly like "this
/// package touches nothing" rather than "the exec never happened". It must now be a named
/// `ChildFailure::Execve`, not a silently clean audit.
#[test]
fn a_missing_program_is_named_as_an_execve_child_failure() {
    let outcome = monitor::trace(
        Path::new("/definitely/not/here"),
        &[],
        &TraceOptions::default(),
    );

    let error = outcome
        .expect_err("a program that never execs must not report a clean, zero-observation audit");
    let failure = error
        .downcast_ref::<monitor::ChildFailure>()
        .unwrap_or_else(|| panic!("expected a ChildFailure, got: {error}"));
    assert!(
        matches!(failure, monitor::ChildFailure::Execve(_)),
        "expected ChildFailure::Execve, got {failure:?}"
    );
}

/// The same honesty requirement for the other early failure path: a working directory
/// that does not exist must not disappear into a clean-looking report either.
#[test]
fn a_missing_working_directory_is_named_as_a_chdir_child_failure() {
    let dir = tempdir().expect("temp dir");
    let missing_working_dir = dir.path().join("does-not-exist");

    let outcome = monitor::trace(
        Path::new("/bin/true"),
        &[],
        &TraceOptions {
            working_dir: Some(missing_working_dir),
            ..TraceOptions::default()
        },
    );

    let error = outcome.expect_err("a missing working directory must not report a clean audit");
    let failure = error
        .downcast_ref::<monitor::ChildFailure>()
        .unwrap_or_else(|| panic!("expected a ChildFailure, got: {error}"));
    assert!(
        matches!(failure, monitor::ChildFailure::Chdir(_)),
        "expected ChildFailure::Chdir, got {failure:?}"
    );
}

/// `preflight` has to prove ptrace actually *works*, not merely that a child can start -
/// a probe that only calls `traceme()` and exits would report "denied" even here. This
/// task's host is documented to permit ptrace, so this must succeed.
#[test]
fn preflight_confirms_this_host_can_actually_trace() {
    let result = monitor::preflight();
    println!("monitor::preflight() on this host: {result:?}");
    result.expect("this host is documented to permit ptrace");
}

// ---------------------------------------------------------------------------
// The three signals together.
// ---------------------------------------------------------------------------

/// The shape the wiring phase will use: three independent sets folded into one profile
/// whose grants each still name where they came from.
#[test]
fn the_three_signals_merge_into_one_attributed_profile() {
    let dir = tempdir().expect("temp dir");
    write(
        dir.path().join("main.c"),
        "int main(void){ return socket(2,1,0); }\n",
    )
    .expect("write source");

    let from_source = source::scan(dir.path()).expect("scan");
    let from_elf = elf::analyse(&a_real_binary())
        .expect("analyse")
        .expect("the test binary is an ELF");

    let target = dir.path().join("subject.txt");
    write(&target, "x\n").expect("write subject");
    let from_monitor = monitor::trace(
        Path::new("/bin/cat"),
        &[target.display().to_string()],
        &TraceOptions::default(),
    )
    .expect("trace")
    .permissions()
    .clone();

    let profile = Permissions::merge([from_source, from_elf, from_monitor]);

    let seen: Vec<Provenance> = profile
        .grants()
        .iter()
        .flat_map(|grant| grant.provenance().iter().copied())
        .collect();
    for provenance in [
        Provenance::SourceAnalysis,
        Provenance::ElfAnalysis,
        Provenance::RuntimeMonitor,
    ] {
        assert!(
            seen.contains(&provenance),
            "{provenance} contributed nothing to:\n{}",
            profile.report()
        );
    }
    assert!(
        profile.wants_network(),
        "the source signal's network grant must survive the merge:\n{}",
        profile.report()
    );

    // Merging is not promotion: the profile that comes out is still audit-only.
    assert_eq!(Enforcement::default(), Enforcement::Audit);
}

// ---------------------------------------------------------------------------
// The holes, asserted on purpose.
// ---------------------------------------------------------------------------
//
// Everything below documents something these signals CANNOT see. The assertions are
// written the way they are - "this produces nothing" - so that the gaps are recorded in
// the test suite rather than in somebody's memory. If one of them starts failing, a
// signal got better and the test should be rewritten to say so; none of them should be
// deleted quietly, and none of them should be read as a reason to trust a derived
// profile enough to enforce it.

/// Source analysis matches names on the syntax tree, so anything that removes the name
/// removes the match. Each case below reaches the network or spawns a process and none
/// of them is detected.
#[test]
fn source_analysis_misses_indirection_by_construction() {
    // A libc symbol resolved at run time: there is no `socket` call node anywhere.
    let (_dir, found) = scan_one(
        "evade.c",
        r#"
#include <dlfcn.h>
int main(void) {
    int (*f)(int, int, int) = dlsym(RTLD_NEXT, "socket");
    return f(2, 1, 0);
}
"#,
    );
    assert!(
        !found.wants_network(),
        "if this ever passes, dlsym became visible - rewrite the test:\n{}",
        found.report()
    );

    // Python's dynamic import: `socket` is a string argument, not an import statement.
    let (_dir, found) = scan_one(
        "evade.py",
        r#"
mod = __import__("so" + "cket")
sock = getattr(mod, "socket")()
runner = getattr(__import__("subprocess"), "run")
runner(["/bin/sh", "-c", "true"])
"#,
    );
    assert!(!found.wants_network(), "{}", found.report());
    assert!(!found.wants_spawn(), "{}", found.report());

    // A path assembled at run time. The literal is a format string, and the module drops
    // it rather than recording a path that never existed.
    let (_dir, found) = scan_one(
        "evade2.c",
        r#"
#include <stdio.h>
int main(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s/%s", "/etc", "shadow");
    FILE *f = fopen(buf, "r");
    return f != 0;
}
"#,
    );
    assert!(
        !found
            .read_paths()
            .any(|path| path == Path::new("/etc/shadow")),
        "{}",
        found.report()
    );

    // A shell command name behind a variable: still a command, so `spawn` survives, but
    // the fact that it is `curl` does not.
    let (_dir, found) = scan_one("evade.sh", "CMD=curl\n$CMD https://example.invalid\n");
    assert!(
        !found.wants_network(),
        "the command name is an expansion, not a word:\n{}",
        found.report()
    );
}

/// The monitor sees one execution. A branch that execution did not take is simply absent
/// from the profile - which is the whole reason a derived profile ships in audit mode.
#[test]
fn the_monitor_misses_the_branch_it_did_not_run() {
    let dir = tempdir().expect("temp dir");
    let script = dir.path().join("two-paths.sh");
    let secret = dir.path().join("only-on-the-other-branch");
    write(&secret, "s\n").expect("write secret");
    let taken = dir.path().join("taken");
    write(&taken, "t\n").expect("write taken");
    write(
        &script,
        format!(
            "#!/bin/sh\nif [ -n \"$PM_UNLOCK\" ]; then cat {}; else cat {}; fi\n",
            secret.display(),
            taken.display()
        ),
    )
    .expect("write script");

    let report = monitor::trace(
        Path::new("/bin/sh"),
        &[script.display().to_string()],
        &TraceOptions::default(),
    )
    .expect("trace");

    let permissions = report.permissions();
    assert!(
        permissions.read_paths().any(|path| path == taken),
        "the branch that ran must be recorded:\n{}",
        permissions.report()
    );
    assert!(
        !permissions.read_paths().any(|path| path == secret),
        "an untaken branch cannot be seen - this is the incompleteness the model warns \
         about, not a bug:\n{}",
        permissions.report()
    );
}

/// ELF analysis reads the link-time declarations and nothing else, so a library opened by
/// name at run time leaves no `DT_NEEDED` to find.
#[test]
fn elf_analysis_misses_what_is_only_loaded_at_run_time() {
    let needed = elf::needed_libraries(Path::new("/bin/ls")).expect("needed");
    assert!(
        !needed.iter().any(|library| library.contains("nss")),
        "/bin/ls does not declare the NSS modules glibc loads for it, yet a run may need \
         them: {needed:?}"
    );
}
