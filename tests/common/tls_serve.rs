// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared TLS daemon startup, readiness and process ownership (#8293).

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::tls::TestTls;

/// Runner load and coverage instrumentation can delay startup (#3615, #8287).
/// Both TLS suites use this one ceiling; the plain-HTTP helper cannot probe TLS
/// (#3705). Keep this independent of a caller's first application request.
pub const SPAWN_TIMEOUT: Duration = Duration::from_mins(1);
/// Only an ephemeral-port bind collision permits a fresh startup attempt.
pub const SPAWN_BIND_RETRY_ATTEMPTS: usize = 5;
/// Interval between readiness probes, also used by the first-request retry.
pub const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const BIND_IN_USE_MARKER: &str = "Address already in use";

/// Owns the child and its pipe readers from spawn until it is reaped.
/// The public child handle also supports the graceful-shutdown integration test.
pub struct ServeChild {
    pub child: Option<Child>,
    pub port: u16,
    pub tls: TestTls,
    stderr: Arc<Mutex<String>>,
    stderr_reader: Option<JoinHandle<()>>,
    stdout_reader: Option<JoinHandle<()>>,
    _tls_dir: tempfile::TempDir,
}

impl ServeChild {
    pub fn base_url(&self) -> String {
        TestTls::base_url(self.port)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url())
    }

    pub fn stderr(&self) -> String {
        self.stderr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Stop and reap only this guard's child, then join its pipe readers.
    /// Idempotent: a caller that already waited may clear the child handle.
    pub fn stop(&mut self) -> Option<ExitStatus> {
        let status = self.child.take().and_then(|mut child| {
            let _ = child.kill();
            child.wait().ok()
        });
        for reader in [&mut self.stdout_reader, &mut self.stderr_reader] {
            if let Some(handle) = reader.take() {
                let _ = handle.join();
            }
        }
        status
    }
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Bind collisions are retryable; a startup crash or expired deadline is not.
#[derive(Debug)]
pub enum SpawnFailure {
    BindRace { stderr: String },
    Crashed { status: ExitStatus, stderr: String },
    NeverReady { stderr: String },
}

impl std::error::Error for SpawnFailure {}

impl std::fmt::Display for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindRace { stderr } => write!(
                f,
                "serve daemon lost the ephemeral-port bind race {SPAWN_BIND_RETRY_ATTEMPTS} times; child stderr:\n{stderr}"
            ),
            Self::Crashed { status, stderr } => write!(
                f,
                "serve child exited before /health became ready: {status}; child stderr:\n{stderr}"
            ),
            Self::NeverReady { stderr } => write!(
                f,
                "serve daemon did not become ready within {SPAWN_TIMEOUT:?}; child stderr:\n{stderr}"
            ),
        }
    }
}

/// Start a TLS daemon. The callback applies suite-specific child arguments and
/// environment overrides after the isolated default configuration is installed.
pub fn spawn_serve(db: &Path, configure: impl Fn(&mut Command)) -> ServeChild {
    try_spawn_serve_with_port_picker(db, configure, super::free_port)
        .unwrap_or_else(|failure| panic!("{failure}"))
}

/// Same startup path with an explicit port picker, allowing tests to reproduce
/// a bind collision without racing another process for an ephemeral port.
pub fn try_spawn_serve_with_port_picker(
    db: &Path,
    configure: impl Fn(&mut Command),
    mut pick_port: impl FnMut() -> u16,
) -> Result<ServeChild, SpawnFailure> {
    let mut last_bind_failure = SpawnFailure::BindRace {
        stderr: String::new(),
    };
    for attempt in 1..=SPAWN_BIND_RETRY_ATTEMPTS {
        match try_spawn_serve_once(db, pick_port(), &configure) {
            Err(failure @ SpawnFailure::BindRace { .. }) => {
                eprintln!(
                    "spawn_serve: bind collision on attempt {attempt}/{SPAWN_BIND_RETRY_ATTEMPTS}"
                );
                last_bind_failure = failure;
            }
            result => return result,
        }
    }
    Err(last_bind_failure)
}

fn try_spawn_serve_once(
    db: &Path,
    port: u16,
    configure: &impl Fn(&mut Command),
) -> Result<ServeChild, SpawnFailure> {
    let parent = db.parent().expect("db lives in a test directory");
    let tls_dir = tempfile::Builder::new()
        .prefix("tls-serve-8293-")
        .tempdir_in(parent)
        .expect("create per-spawn TLS directory");
    let tls = TestTls::generate(tls_dir.path());
    let keys = parent.join("keys-3198");
    std::fs::create_dir_all(&keys).expect("create test key directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("restrict test key directory");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .arg("--db")
        .arg(db)
        .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()])
        .args(tls.serve_arg_strs());
    configure(&mut cmd);
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory serve");
    // Own the child before any client or reader setup can panic.
    let mut serve = ServeChild {
        child: Some(child),
        port,
        tls,
        stderr: Arc::new(Mutex::new(String::new())),
        stderr_reader: None,
        stdout_reader: None,
        _tls_dir: tls_dir,
    };
    if let Some(stdout) = serve.child.as_mut().unwrap().stdout.take() {
        serve.stdout_reader = Some(std::thread::spawn(move || {
            for _ in BufReader::new(stdout).lines().map_while(Result::ok) {}
        }));
    }
    if let Some(stderr) = serve.child.as_mut().unwrap().stderr.take() {
        let sink = Arc::clone(&serve.stderr);
        serve.stderr_reader = Some(std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut guard = sink
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.push_str(&line);
                guard.push('\n');
            }
        }));
    }
    let client = serve.tls.client_with_timeout(READINESS_PROBE_TIMEOUT);
    let url = serve.url("/api/v1/health");
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = serve.child.as_mut().unwrap().try_wait() {
            let _ = serve.stop();
            let stderr = serve.stderr();
            return Err(if stderr.contains(BIND_IN_USE_MARKER) {
                SpawnFailure::BindRace { stderr }
            } else {
                SpawnFailure::Crashed { status, stderr }
            });
        }
        if client
            .get(&url)
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(serve);
        }
        std::thread::sleep(READINESS_POLL_INTERVAL);
    }
    let _ = serve.stop();
    Err(SpawnFailure::NeverReady {
        stderr: serve.stderr(),
    })
}
