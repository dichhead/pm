//! A loopback HTTP server for tests that need a real download.
//!
//! `pm` fetches sources over HTTP and nothing else - `file://` is not a scheme
//! [`pm::download::Downloader`] can speak - so a test that wants to watch a
//! download land has to serve one. This is the smallest server that makes that
//! honest: a real socket, a real request, a real `Content-Length`.
//!
//! It is not a general-purpose server and should not grow into one. It answers
//! `GET`, it knows the paths it was handed, and it 404s everything else.

#![allow(dead_code)] // Each test binary uses its own subset of this module.

use std::{
    collections::HashMap,
    fs::write,
    io::{BufRead as _, BufReader, Write as _},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{JoinHandle, sleep},
    time::Duration,
};

use serde::Serialize;
use serde_yaml::to_string;
use url::Url;

/// How long the accept loop sleeps between polls when no client is waiting.
///
/// The listener is non-blocking so the loop can notice the shutdown flag; this
/// is the price of that, paid only while idle.
const IDLE_POLL: Duration = Duration::from_millis(5);

/// How a response body is framed on the wire.
///
/// Both shapes are real and `Downloader` has to handle both: a mirror that
/// knows its file size sends `Content-Length`, and one that streams it does
/// not. Which one arrived is the difference between a progress line that can
/// show a total and one that cannot.
#[derive(Debug, Clone)]
pub enum Body {
    /// Sent with a `Content-Length` header.
    Measured(Vec<u8>),
    /// Sent with no `Content-Length`, framed by closing the connection.
    Unmeasured(Vec<u8>),
    /// A 302 pointing at another path on this same server.
    Redirect(String),
}

impl Body {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Measured(body) | Self::Unmeasured(body) => body,
            Self::Redirect(_) => &[],
        }
    }
}

/// A server bound to a loopback port for the lifetime of the value.
///
/// Dropping it stops the accept loop and joins the thread, so a test cannot
/// leak a listener into the ones that run after it.
pub struct TestServer {
    base: Url,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Serve `routes`, a map of request path (`"/source.tar.gz"`) to response body.
    ///
    /// Binds port 0 so the kernel picks a free one and tests can run in
    /// parallel without agreeing on a port beforehand.
    pub fn serving(routes: HashMap<String, Body>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port must be available");
        listener
            .set_nonblocking(true)
            .expect("the listener must be able to go non-blocking");
        let port = listener
            .local_addr()
            .expect("the socket must have an address")
            .port();

        let running = Arc::new(AtomicBool::new(true));
        let stop = Arc::clone(&running);
        let thread = std::thread::spawn(move || {
            while stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => answer(stream, &routes),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => sleep(IDLE_POLL),
                    Err(_) => break,
                }
            }
        });

        Self {
            base: Url::parse(&format!("http://127.0.0.1:{port}/"))
                .expect("the base URL must parse"),
            running,
            thread: Some(thread),
        }
    }

    /// Serve a single `Content-Length`-framed body at `/source.tar.gz`.
    pub fn serving_one(body: &[u8]) -> Self {
        Self::serving(HashMap::from([(
            "/source.tar.gz".to_string(),
            Body::Measured(body.to_vec()),
        )]))
    }

    /// Serve a single body at `/source.tar.gz` with no `Content-Length`.
    pub fn serving_one_unmeasured(body: &[u8]) -> Self {
        Self::serving(HashMap::from([(
            "/source.tar.gz".to_string(),
            Body::Unmeasured(body.to_vec()),
        )]))
    }

    /// The absolute URL of `path` on this server. `path` is absolute (`"/a/b"`).
    pub fn url(&self, path: &str) -> Url {
        self.base
            .join(path.trim_start_matches('/'))
            .expect("the route must join onto the base URL")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read one request and write the body its path maps to.
fn answer(mut stream: TcpStream, routes: &HashMap<String, Body>) {
    let Some(path) = request_path(&stream) else {
        return;
    };

    let response = match routes.get(&path) {
        Some(body) => {
            let mut head = match body {
                Body::Measured(bytes) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: \
                     application/octet-stream\r\nConnection: close\r\n\r\n",
                    bytes.len()
                ),
                Body::Unmeasured(_) => {
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Connection: close\r\n\r\n"
                        .to_string()
                }
                Body::Redirect(target) => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                ),
            }
            .into_bytes();
            head.extend_from_slice(body.bytes());
            head
        }
        None => {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
    };

    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

/// Pull the path out of the request line and drain the rest of the head.
///
/// The head must be drained either way: replying to a client that is still
/// writing its headers can land the response in a socket the peer has not
/// finished with.
fn request_path(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split_whitespace().nth(1)?.to_string();

    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    Some(path)
}

/// One step of a build file, shaped for serialisation into YAML.
///
/// `dl_urls` is always `null` here: these tests never download anything.
#[derive(Serialize)]
struct StepSpec {
    stage: &'static str,
    dl_urls: Option<()>,
    name: String,
    run: Vec<String>,
}

/// A whole build file, shaped for serialisation into YAML.
///
/// Going through `serde_yaml` rather than `format!` keeps the shell quoting in
/// the commands from having to survive a second round of YAML quoting by hand.
#[derive(Serialize)]
struct BuildSpec {
    name: String,
    version: Vec<String>,
    dependencies: Vec<String>,
    steps: Vec<StepSpec>,
}

/// Renders a build file whose single `Install` step runs `commands`.
pub fn build_file_yaml(
    name: &str,
    version: &[&str],
    dependencies: &[&Path],
    commands: &[&str],
) -> String {
    let spec = BuildSpec {
        name: name.into(),
        version: version.iter().map(|v| (*v).to_string()).collect(),
        dependencies: dependencies
            .iter()
            .map(|d| d.display().to_string())
            .collect(),
        steps: vec![StepSpec {
            stage: "Install",
            dl_urls: None,
            name: format!("stage-{name}"),
            run: commands.iter().map(|c| (*c).to_string()).collect(),
        }],
    };
    to_string(&spec).expect("a build file must serialise")
}

/// Writes a build file at `path` and hands the path back.
pub fn write_build_file(path: PathBuf, yaml: &str) -> PathBuf {
    write(&path, yaml).expect("write the build file");
    path
}
