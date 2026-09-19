// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::field_reassign_with_default)]
//! #3806 W2 — the SYNC seam's ephemeral-runtime arm: two findings, one
//! of which corrects a claim I made in the W2 handoff.
//!
//! `classify_kind` is synchronous, so it crosses
//! `llm::block_on_local_bounded`. With no ambient tokio runtime that
//! helper builds a fresh current-thread runtime per call and drops it
//! afterwards, which means the decision client's pooled connection
//! outlives the reactor that created it. I flagged that as a hazard:
//! "a pooled connection from a previous ephemeral runtime CAN fail, and
//! it degrades to an abstain". The first test below **does not
//! reproduce it** and is kept as the control that says so.
//!
//! The second test pins the property that actually matters and that IS
//! forceable: when the endpoint genuinely goes away between two calls,
//! the seam abstains with `Unavailable` — an OUTAGE — and returns no
//! verdict. That is the `Unavailable` / `Unusable` split doing its job
//! at the one place the distinction is load-bearing: "the transport
//! broke" must never arrive looking like "the model said no".
//!
//! The endpoint here is a hand-rolled blocking listener rather than
//! `wiremock`, and that is load-bearing. A `MockServer` owns a
//! background runtime this thread does not control: dropping it does
//! NOT free the port (measured — the port stayed accepting through five
//! probes), so a test that "kills" a `MockServer` and then asserts a
//! failure is asserting against a server that is still answering.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::attach_decider;
use ai_memory::llm::OllamaClient;
use ai_memory::models::MemoryKind;

/// The structured answer the decision endpoint returns.
const DECISION_BODY: &str =
    r#"{"choices":[{"message":{"role":"assistant","content":"{\"choice\":\"decision\"}"}}]}"#;

/// A decision endpoint this test can actually kill.
struct Endpoint {
    uri: String,
    port: u16,
    shutdown: Arc<AtomicBool>,
}

impl Endpoint {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let flag = Arc::clone(&flag);
                        std::thread::spawn(move || serve(stream, &flag));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            // Dropping `listener` here is what makes a later connect
            // REFUSED rather than merely unanswered.
        });
        Self {
            uri: format!("http://127.0.0.1:{port}"),
            port,
            shutdown,
        }
    }

    /// Kill it, and do not return until the port actually refuses.
    fn kill(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let addr = format!("127.0.0.1:{}", self.port)
            .parse()
            .expect("addr parses");
        for _ in 0..200 {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the endpoint never stopped accepting; the test below would prove nothing");
    }
}

/// Serve requests on one connection until the peer closes or the
/// endpoint is killed. Keep-alive, so the client POOLS this connection —
/// which is the whole point of the first test.
fn serve(mut stream: TcpStream, shutdown: &AtomicBool) {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    let mut pending = Vec::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return; // drops `stream`: the pooled connection dies here
        }
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return,
        }
        // One response per complete request head + declared body.
        while let Some(head_end) = find_head_end(&pending) {
            let head = String::from_utf8_lossy(&pending[..head_end]).to_ascii_lowercase();
            let want = content_length(&head);
            if pending.len() < head_end + want {
                break;
            }
            pending.drain(..head_end + want);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{DECISION_BODY}",
                DECISION_BODY.len()
            );
            if stream.write_all(response.as_bytes()).is_err() {
                return;
            }
            let _ = stream.flush();
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Both tests take this. The prometheus registry is process-global, so
/// the delta assertions below are exact only while nothing else in this
/// binary is recording concurrently.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialize() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn abstain_child(seam: &str, reason: &str) -> u64 {
    let needle =
        format!("ai_memory_decision_abstain_total{{reason=\"{reason}\",seam=\"{seam}\"}} ");
    ai_memory::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(needle.as_str()))
        .and_then(|r| r.trim().parse().ok())
        .unwrap_or(0)
}

/// A client whose decision endpoint is `uri`. The `[llm]` endpoint is a
/// port nothing listens on, so nothing here can reach a generative
/// model by accident.
fn client_for(uri: &str, db: &std::path::Path) -> OllamaClient {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some("http://127.0.0.1:1".to_string()),
        ..LlmSection::default()
    });
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(uri.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(DecisionFallback::Abstain),
    });
    attach_decider(
        Some(
            OllamaClient::new_with_url_no_health_check("http://127.0.0.1:1", "vendor/chat-1")
                .expect("client builds"),
        ),
        &cfg,
        db,
    )
    .expect("attach_decider returns the client it was given")
}

/// FINDING 1, and the correction: a connection pooled by one ephemeral
/// runtime and reused from the NEXT one does NOT fail.
///
/// Both calls run on this thread with no ambient tokio runtime, so each
/// takes `block_on_local_bounded`'s ephemeral arm and each drops its
/// runtime afterwards. The endpoint stays up and keeps the connection
/// alive between them. Both calls decide.
///
/// This is also the PRESENCE control for the pin below: the transport
/// works repeatedly on this code path, so an abstain there is a property
/// of the dead endpoint and not of the bridge.
#[test]
fn a_connection_pooled_across_ephemeral_runtimes_still_decides() {
    let _serialized = serialize();
    let endpoint = Endpoint::spawn();
    let db = tempfile::tempdir().expect("tempdir");
    let client = client_for(&endpoint.uri, db.path());

    let first = client
        .classify_kind("t", "c")
        .expect("call 1 is not an error");
    let second = client
        .classify_kind("t", "c")
        .expect("call 2 is not an error");

    assert_eq!(
        first,
        Some(MemoryKind::Decision),
        "the first ephemeral-runtime call decides"
    );
    assert_eq!(
        second,
        Some(MemoryKind::Decision),
        "and so does the second: the pooled-connection hazard flagged in the W2 handoff \
         does NOT reproduce — the client discards a connection whose reactor is gone and \
         opens a fresh one"
    );
    endpoint.kill();
}

/// FINDING 2, the pin: when the endpoint GOES AWAY between two calls,
/// the seam abstains as `Unavailable` and returns NO verdict.
///
/// This is the failure direction the `Unavailable` / `Unusable` split
/// exists to preserve. A broken transport must never arrive at a seam
/// looking like a model that declined: one is an outage an operator
/// pages on, the other is the feature working. Asserted on the operator
/// surface, not only on the return value.
#[test]
fn a_dead_endpoint_abstains_as_unavailable_and_never_as_a_verdict() {
    let _serialized = serialize();
    let endpoint = Endpoint::spawn();
    let db = tempfile::tempdir().expect("tempdir");
    let client = client_for(&endpoint.uri, db.path());

    // PRESENCE: it decided while the endpoint was up, so the abstain
    // below is caused by the kill and not by a client that never worked.
    assert_eq!(
        client.classify_kind("t", "c").expect("healthy call"),
        Some(MemoryKind::Decision)
    );

    let before_unavailable = abstain_child("classify_kind", "unavailable");
    let before_unusable = abstain_child("classify_kind", "unusable");
    endpoint.kill();

    let verdict = client
        .classify_kind("t", "c")
        .expect("an outage is an abstain, not an error, under `fallback = abstain`");
    assert_eq!(
        verdict, None,
        "a dead endpoint must yield NO kind — degrade, never guess"
    );
    assert_eq!(
        abstain_child("classify_kind", "unavailable"),
        before_unavailable + 1,
        "a broken transport is an OUTAGE: `unavailable`"
    );
    assert_eq!(
        abstain_child("classify_kind", "unusable"),
        before_unusable,
        "and it must NOT be reported as `unusable`, which means the model ANSWERED and \
         declined — the one confusion this split exists to prevent"
    );
}
