// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 — per-source auth-failure backoff, proven on the real `serve`
//! binary so the production serve path (`axum_server` with connect info)
//! carries the peer address the backoff keys on. A router driven without a
//! TCP listener never sees a peer address and passes through, so only a
//! spawned daemon can show the control is live.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ai_memory::handlers::auth_backoff::{
    ENV_AUTH_BACKOFF_TRUSTED_PROXIES, ENV_AUTH_FAILURE_BACKOFF, ERROR_AUTH_BACKOFF, FREE_FAILURES,
};
use tempfile::TempDir;

const API_KEY: &str = "test-2502-right-key";
const WRONG_KEY: &str = "test-2502-wrong-key";
const ADMIN: &str = "ai:auth-backoff-2502";
const READY_TIMEOUT: Duration = Duration::from_secs(90);
const EXIT_TIMEOUT: Duration = Duration::from_secs(60);

struct Daemon {
    child: Child,
    url: String,
    stderr: Arc<Mutex<String>>,
    _home: TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(backoff: Option<&str>, trusted_proxies: Option<&str>) -> Daemon {
    let home = TempDir::new().expect("tempdir");
    let xdg = home.path().join(".config");
    let cfg_dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(
        cfg_dir.join("config.toml"),
        format!("api_key = \"{API_KEY}\"\n"),
    )
    .expect("config.toml");
    let port = common::free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "0")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("AI_MEMORY_DB")
        .env("AI_MEMORY_ADMIN_AGENT_IDS", ADMIN)
        .args(["--db"])
        .arg(home.path().join("ai-memory.db"))
        .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    match backoff {
        Some(v) => cmd.env(ENV_AUTH_FAILURE_BACKOFF, v),
        None => cmd.env_remove(ENV_AUTH_FAILURE_BACKOFF),
    };
    match trusted_proxies {
        Some(v) => cmd.env(ENV_AUTH_BACKOFF_TRUSTED_PROXIES, v),
        None => cmd.env_remove(ENV_AUTH_BACKOFF_TRUSTED_PROXIES),
    };
    let mut child = cmd.spawn().expect("spawn ai-memory serve");
    let stderr = Arc::new(Mutex::new(String::new()));
    if let Some(pipe) = child.stderr.take() {
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if let Ok(mut s) = sink.lock() {
                    s.push_str(&line);
                    s.push('\n');
                }
            }
        });
    }
    Daemon {
        child,
        url: format!("http://127.0.0.1:{port}"),
        stderr,
        _home: home,
    }
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client")
}

fn wait_ready(d: &mut Daemon, c: &reqwest::blocking::Client) {
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = d.child.try_wait() {
            panic!(
                "daemon exited early ({status}); stderr:\n{}",
                d.stderr.lock().unwrap()
            );
        }
        if c.get(format!("{}/api/v1/health", d.url))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "daemon never became healthy; stderr:\n{}",
        d.stderr.lock().unwrap()
    );
}

fn forwarded(
    d: &Daemon,
    c: &reqwest::blocking::Client,
    key: &str,
    xff: Option<&str>,
) -> reqwest::blocking::Response {
    let mut req = c
        .get(format!("{}/api/v1/stats", d.url))
        .header("x-api-key", key)
        .header("x-agent-id", ADMIN);
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    req.send().expect("request")
}

fn stats(d: &Daemon, c: &reqwest::blocking::Client, key: &str) -> reqwest::blocking::Response {
    forwarded(d, c, key, None)
}

/// The eleventh wrong key puts the source in backoff; while it lasts the
/// RIGHT key is refused too (so a guesser learns nothing), `/health` still
/// answers, and a success does not reset the count.
#[test]
fn repeated_wrong_keys_back_off_the_source_even_for_the_right_key_2502() {
    let c = client();
    let mut d = spawn_daemon(None, None);
    wait_ready(&mut d, &c);
    assert!(
        stats(&d, &c, API_KEY).status().is_success(),
        "right key works first"
    );
    for i in 0..=FREE_FAILURES {
        let status = stats(&d, &c, WRONG_KEY).status().as_u16();
        assert_eq!(status, 401, "wrong key #{i} is a plain 401");
    }
    let r = stats(&d, &c, API_KEY);
    assert_eq!(r.status().as_u16(), 429, "right key refused during backoff");
    let retry: u64 = r
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After seconds");
    assert!(retry >= 1, "Retry-After {retry}");
    let body: serde_json::Value = r.json().expect("json body");
    assert_eq!(body["error"], ERROR_AUTH_BACKOFF);
    let health = c
        .get(format!("{}/api/v1/health", d.url))
        .send()
        .expect("health");
    assert!(health.status().is_success(), "health is never refused");
    // No proxy is declared, so a client-written X-Forwarded-For naming some
    // other address does not move the request out of its own (loopback)
    // source: the header cannot mint a fresh budget.
    let forged = forwarded(&d, &c, API_KEY, Some("198.51.100.10"));
    assert_eq!(
        forged.status().as_u16(),
        429,
        "X-Forwarded-For from an undeclared peer is ignored"
    );

    std::thread::sleep(Duration::from_millis(retry * 1_000 + 300));
    assert!(stats(&d, &c, API_KEY).status().is_success(), "window over");
    assert_eq!(stats(&d, &c, WRONG_KEY).status().as_u16(), 401);
    let r = stats(&d, &c, API_KEY);
    assert_eq!(
        r.status().as_u16(),
        429,
        "the success did not reset the count"
    );
    assert_eq!(
        r.headers().get("retry-after").and_then(|v| v.to_str().ok()),
        Some("2"),
        "the next rejection doubled the backoff"
    );
}

/// With the loopback peer declared a proxy, the rightmost `X-Forwarded-For`
/// hop is the source: one client behind the proxy backs off without taking
/// the others (or the proxy's own source) with it.
#[test]
fn a_declared_proxy_keys_on_the_forwarded_client_2502() {
    let c = client();
    let mut d = spawn_daemon(None, Some("127.0.0.1"));
    wait_ready(&mut d, &c);
    let guesser = Some("203.0.113.5, 198.51.100.20");
    for i in 0..=FREE_FAILURES {
        let status = forwarded(&d, &c, WRONG_KEY, guesser).status().as_u16();
        assert_eq!(status, 401, "wrong key #{i} is a plain 401");
    }
    assert_eq!(
        forwarded(&d, &c, API_KEY, guesser).status().as_u16(),
        429,
        "the forwarded client is in backoff"
    );
    assert!(
        forwarded(&d, &c, API_KEY, Some("198.51.100.21"))
            .status()
            .is_success(),
        "another client behind the proxy is not"
    );
    assert!(
        forwarded(&d, &c, API_KEY, None).status().is_success(),
        "the proxy's own source is not"
    );
}

/// A falsy token switches the control off: wrong keys stay plain 401s.
#[test]
fn falsy_knob_disables_the_backoff_2502() {
    let c = client();
    let mut d = spawn_daemon(Some("off"), None);
    wait_ready(&mut d, &c);
    for _ in 0..FREE_FAILURES * 2 {
        assert_eq!(stats(&d, &c, WRONG_KEY).status().as_u16(), 401);
    }
    assert!(stats(&d, &c, API_KEY).status().is_success());
}

/// An unrecognised token is a typo, not a silent default: boot refuses and
/// names the knob (the #3200 grammar sweep).
#[test]
fn unrecognised_knob_token_refuses_boot_2502() {
    let mut d = spawn_daemon(Some("maybe"), None);
    let deadline = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = d.child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon booted with an unrecognised token"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(!status.success(), "boot must fail");
    std::thread::sleep(Duration::from_millis(200));
    let stderr = d.stderr.lock().unwrap().clone();
    assert!(
        stderr.contains(ENV_AUTH_FAILURE_BACKOFF),
        "the refusal names the knob; stderr:\n{stderr}"
    );
}
