// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4033 (SEC, CWE-770) — every OUTBOUND federation push lane reads the
//! peer's response body through ONE byte-capped reader.
//!
//! ## The defect this pins closed
//!
//! The `/sync/since` pull reader was capped by #1928, but the push readers
//! were not: `post_once` (per-row fanout AND push-DLQ replay) buffered a 2xx
//! body with `resp.json()` and drained an error body with `resp.bytes()`, and
//! `bulk_catchup_push` did `resp.bytes()` on both arms. A faulty or
//! compromised enrolled peer could therefore make the SENDING daemon buffer an
//! unbounded body; worse, an unreadable 2xx fell through the legacy
//! "unparseable 2xx = ack" arm, so an oversize reply met quorum and retired
//! DLQ rows on a report this node never read.
//!
//! ## What is asserted (small injected cap, fake enrolled peer)
//!
//! * fanout: an oversize 2xx (no trustworthy `Content-Length`, and a declared
//!   oversize `Content-Length`) is NOT a quorum ack and lands a DLQ row;
//! * replay: an oversize 2xx does NOT retire the pending DLQ row;
//! * bulk catch-up: an oversize 2xx is a failed push for that peer;
//! * error statuses: an endless error body is abandoned at the cap — the lane
//!   returns promptly instead of reading until the client timeout.
//!
//! Dedicated binary: the cap override is a process-wide `test-support` seam.

#![cfg(feature = "sal")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ai_memory::federation::capped_body::test_cap;
use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink, replay_once};
use ai_memory::federation::sync::bulk_catchup_push;
use ai_memory::federation::{FederationConfig, PeerEndpoint, broadcast_store_quorum};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The injected push-response cap for this binary.
const CAP: usize = 4096;

/// Peer behaviours.
const MODE_OK_SMALL: u8 = 0;
/// 200, chunked (no `Content-Length`), a VALID ack-shaped JSON report padded
/// to 4x the cap — the old reader parsed it and acked.
const MODE_OK_OVERSIZE_CHUNKED: u8 = 1;
/// 200 declaring a 10 GiB `Content-Length`, then a few bytes and a hang.
const MODE_OK_DECLARED_HUGE: u8 = 2;
/// 500, chunked, an endless trickle — the old drain read until the timeout.
const MODE_ERR_ENDLESS: u8 = 3;
/// 500 with a small JSON error envelope.
const MODE_ERR_SMALL: u8 = 4;

/// Read one full HTTP/1.1 request (headers + `Content-Length` body) so the
/// response never races the client's upload.
async fn read_request(sock: &mut tokio::net::TcpStream) {
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 16 * 1024];
    loop {
        let Ok(n) = sock.read(&mut scratch).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
            let body_len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let have = buf.len() - (pos + 4);
            let mut remaining = body_len.saturating_sub(have);
            while remaining > 0 {
                let Ok(n) = sock.read(&mut scratch).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                remaining = remaining.saturating_sub(n);
            }
            return;
        }
    }
}

async fn write_chunk(sock: &mut tokio::net::TcpStream, data: &[u8]) -> std::io::Result<()> {
    sock.write_all(format!("{:x}\r\n", data.len()).as_bytes())
        .await?;
    sock.write_all(data).await?;
    sock.write_all(b"\r\n").await
}

async fn serve_one(mut sock: tokio::net::TcpStream, mode: u8) {
    Box::pin(read_request(&mut sock)).await;
    let small_ok = br#"{"applied":1,"noop":0,"skipped":0}"#;
    match mode {
        MODE_OK_SMALL => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                small_ok.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(small_ok).await;
        }
        MODE_OK_OVERSIZE_CHUNKED => {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            // A syntactically VALID ack report, padded far past the cap.
            let pad = "x".repeat(CAP * 4);
            let body = format!(r#"{{"applied":1,"noop":0,"skipped":0,"pad":"{pad}"}}"#);
            for part in body.as_bytes().chunks(1024) {
                if write_chunk(&mut sock, part).await.is_err() {
                    return;
                }
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        }
        MODE_OK_DECLARED_HUGE => {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 10737418240\r\nConnection: close\r\n\r\n{\"applied\":1",
                )
                .await;
            // Hold the socket; never finish the declared body.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        MODE_ERR_ENDLESS => {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
                      Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            // Trickle (bounded rate, so the OLD unbounded drain cannot eat the
            // host's RAM while it reads until the client timeout).
            let block = vec![b'e'; 1024];
            loop {
                if write_chunk(&mut sock, &block).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        _ => {
            let body = br#"{"error":"stub down"}"#;
            let head = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        }
    }
    let _ = sock.flush().await;
}

/// A fake enrolled peer whose behaviour is switched through `mode`.
async fn spawn_peer(mode: Arc<AtomicU8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake peer");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let m = mode.load(Ordering::SeqCst);
            tokio::spawn(serve_one(sock, m));
        }
    });
    format!("http://{addr}/api/v1/sync/push")
}

fn memory(id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: "fit/4033".to_string(),
        title: format!("push-cap probe {id}"),
        content: "the durable text of a #4033 push-cap probe".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": "ai:cap-4033"}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

fn fresh_dlq_db() -> (tempfile::TempDir, ai_memory::handlers::Db) {
    let tmp = tempfile::Builder::new()
        .prefix("fit-4033-dlq-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
    (tmp, handle)
}

/// W=2 of N=2: the single peer's ack is REQUIRED for quorum. `timeout` is
/// the per-request client timeout; the quorum ack deadline is 2 s longer, so
/// a lane that (pre-fix) acked an unreadable body after the client timeout
/// still made the deadline — the red leg is a genuine false ack.
fn config(
    peer_url: &str,
    sink: Option<Arc<dyn FederationDlqSink>>,
    timeout: Duration,
) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    test_cap::set_push_response_cap(CAP);
    FederationConfig {
        policy: QuorumPolicy::new(
            2,
            2,
            timeout + Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .expect("policy"),
        peers: vec![PeerEndpoint {
            id: "peer-cap-4033".to_string(),
            sync_push_url: peer_url.to_string(),
        }],
        client: reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("client"),
        sender_agent_id: "ai:cap-4033".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: sink,
    }
}

async fn assert_fanout_not_acked(mode: u8, id: &str) {
    let peer_mode = Arc::new(AtomicU8::new(mode));
    let url = spawn_peer(Arc::clone(&peer_mode)).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> =
        Arc::new(SqliteDlqSink::new(db.clone()).await.expect("sink"));
    let cfg = config(&url, Some(Arc::clone(&sink)), Duration::from_secs(1));
    let tracker = broadcast_store_quorum(&cfg, &memory(id))
        .await
        .expect("broadcast returns a tracker");
    assert!(
        !tracker.is_quorum_met(Instant::now()),
        "#4033: an oversize peer response (mode {mode}) must NOT count as a quorum ack"
    );
    let pending = sink.take_pending_dlq_rows(16).await.expect("take pending");
    assert_eq!(
        pending.len(),
        1,
        "#4033: the refused push must land a DLQ row (mode {mode})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_oversize_chunked_2xx_is_not_an_ack_4033() {
    assert_fanout_not_acked(MODE_OK_OVERSIZE_CHUNKED, "cap-4033-fanout-chunked").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_declared_oversize_content_length_is_not_an_ack_4033() {
    assert_fanout_not_acked(MODE_OK_DECLARED_HUGE, "cap-4033-fanout-declared").await;
}

/// Control: a small, well-formed 2xx report still acks (the cap must not
/// break the honest path).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_small_2xx_still_acks_4033() {
    let url = spawn_peer(Arc::new(AtomicU8::new(MODE_OK_SMALL))).await;
    let cfg = config(&url, None, Duration::from_secs(3));
    let tracker = broadcast_store_quorum(&cfg, &memory("cap-4033-fanout-small"))
        .await
        .expect("broadcast returns a tracker");
    assert!(
        tracker.is_quorum_met(Instant::now()),
        "a small well-formed 2xx report must still ack"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_oversize_2xx_does_not_retire_the_dlq_row_4033() {
    let peer_mode = Arc::new(AtomicU8::new(MODE_ERR_SMALL));
    let url = spawn_peer(Arc::clone(&peer_mode)).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> =
        Arc::new(SqliteDlqSink::new(db.clone()).await.expect("sink"));
    let cfg = config(&url, Some(Arc::clone(&sink)), Duration::from_secs(3));
    // A failed fanout lands the DLQ row.
    let _ = broadcast_store_quorum(&cfg, &memory("cap-4033-replay")).await;
    assert_eq!(sink.pending_dlq_count().await.expect("count"), 1);

    // The peer "recovers" into an oversize 2xx reply.
    peer_mode.store(MODE_OK_OVERSIZE_CHUNKED, Ordering::SeqCst);
    replay_once(&cfg, sink.as_ref()).await;
    assert_eq!(
        sink.pending_dlq_count().await.expect("count"),
        1,
        "#4033: an oversize 2xx on replay must NOT retire the pending DLQ row"
    );

    // Control: an honest 2xx does retire it.
    peer_mode.store(MODE_OK_SMALL, Ordering::SeqCst);
    replay_once(&cfg, sink.as_ref()).await;
    assert_eq!(sink.pending_dlq_count().await.expect("count"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_catchup_oversize_2xx_is_a_failed_push_4033() {
    for mode in [MODE_OK_OVERSIZE_CHUNKED, MODE_OK_DECLARED_HUGE] {
        let url = spawn_peer(Arc::new(AtomicU8::new(mode))).await;
        let cfg = config(&url, None, Duration::from_secs(3));
        let errors = bulk_catchup_push(&cfg, &[memory("cap-4033-bulk")]).await;
        assert_eq!(
            errors.len(),
            1,
            "#4033: an oversize 2xx (mode {mode}) must be a failed bulk push, got {errors:?}"
        );
    }
    let url = spawn_peer(Arc::new(AtomicU8::new(MODE_OK_SMALL))).await;
    let cfg = config(&url, None, Duration::from_secs(3));
    assert!(
        bulk_catchup_push(&cfg, &[memory("cap-4033-bulk-ok")])
            .await
            .is_empty()
    );
}

/// The error-arm drain is bounded: an endless error body is abandoned at the
/// cap instead of being read until the (long) client timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endless_error_body_is_abandoned_at_the_cap_4033() {
    let long = Duration::from_secs(20);

    let url = spawn_peer(Arc::new(AtomicU8::new(MODE_ERR_ENDLESS))).await;
    let cfg = config(&url, None, long);
    let started = Instant::now();
    let errors = bulk_catchup_push(&cfg, &[memory("cap-4033-err-bulk")]).await;
    let bulk_elapsed = started.elapsed();
    assert_eq!(errors.len(), 1, "a 500 is a failed bulk push");
    assert!(
        bulk_elapsed < Duration::from_secs(8),
        "#4033: the bulk error drain must stop at the cap, took {bulk_elapsed:?}"
    );

    // Replay lane (post_once error arm).
    let peer_mode = Arc::new(AtomicU8::new(MODE_ERR_SMALL));
    let url = spawn_peer(Arc::clone(&peer_mode)).await;
    let (_tmp, db) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> =
        Arc::new(SqliteDlqSink::new(db.clone()).await.expect("sink"));
    let cfg = config(&url, Some(Arc::clone(&sink)), long);
    let _ = broadcast_store_quorum(&cfg, &memory("cap-4033-err-replay")).await;
    assert_eq!(sink.pending_dlq_count().await.expect("count"), 1);
    peer_mode.store(MODE_ERR_ENDLESS, Ordering::SeqCst);
    let started = Instant::now();
    replay_once(&cfg, sink.as_ref()).await;
    let replay_elapsed = started.elapsed();
    assert_eq!(
        sink.pending_dlq_count().await.expect("count"),
        1,
        "a 500 never retires the DLQ row"
    );
    assert!(
        replay_elapsed < Duration::from_secs(8),
        "#4033: the post_once error drain must stop at the cap, took {replay_elapsed:?}"
    );
}
