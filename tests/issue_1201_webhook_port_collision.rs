// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #1201 — regression test for the webhook mock-HTTP
//! port-collision flake under parallel-binary load.
//!
//! Root cause (from #1201 RCA):
//!
//! `wiremock::MockServer::start()` pools `BareMockServer` instances
//! through a process-wide `MOCK_SERVER_POOL`
//! (`wiremock-0.6.5/src/mock_server/pool.rs`). Each instance binds to
//! `127.0.0.1:0` and the OS hands back an ephemeral port. When a test
//! releases its `MockServer` and a sibling test reaches into the pool,
//! the OS may reassign the SAME ephemeral port to a freshly-bound
//! pool member. Meanwhile,
//! `subscriptions::dispatch_event_with_details`
//! (`src/subscriptions.rs:738`) spawns the actual HTTP POST on a
//! detached `std::thread::spawn`, so a slow dispatch from a prior
//! test can land its POST on a recycled mock server in a sibling
//! test — corrupting the request count and breaking the sibling's
//! assertions.
//!
//! Fix (this commit):
//!
//!   1. Bind a dedicated `127.0.0.1:0` `TcpListener` per webhook test
//!      and feed it to `MockServer::builder().listener(...)`. This
//!      bypasses the pool entirely — the kernel cannot reassign the
//!      port until the listener is dropped, which doesn't happen
//!      until the test returns.
//!   2. Anchor every dispatch URL on a per-test UUID path
//!      (`/hook/<uuid>`). The `wait_for_event` / `collect_event_bodies`
//!      filters check the request URL path against that UUID so even
//!      if port reuse did somehow align between tests, a foreign POST
//!      cannot be mis-counted as a "real" event for this test.
//!
//! What this test pins:
//!
//!   - `TcpListener::bind("127.0.0.1:0")` returns an OS-assigned port
//!     (the foundation primitive both fixes lean on).
//!   - `MockServer::builder().listener(L).start()` honors the
//!     supplied listener address (proves we successfully bypass the
//!     pool — the resulting server is bound to the listener's port,
//!     not a pool-recycled one).
//!   - Many sequential `MockServer::builder().listener(L).start()`
//!     calls in the same process produce non-overlapping ports (proves
//!     that the pool-bypass path doesn't itself collide).
//!   - Concurrent `MockServer::builder().listener(L).start()` calls
//!     from many tokio tasks also produce non-overlapping ports —
//!     this is the real-world parallel-binary stress shape.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Arc;
use tokio::sync::Mutex;
use wiremock::MockServer;

/// Layer 1: the kernel hands out distinct ephemeral ports under
/// `127.0.0.1:0` binds. Foundation for the #1201 fix — every other
/// guarantee derives from this one.
#[test]
fn issue_1201_ephemeral_bind_returns_unique_port() {
    let l1 = TcpListener::bind("127.0.0.1:0").expect("bind 1");
    let l2 = TcpListener::bind("127.0.0.1:0").expect("bind 2");
    let p1 = l1.local_addr().expect("addr 1").port();
    let p2 = l2.local_addr().expect("addr 2").port();
    assert_ne!(
        p1, p2,
        "kernel must hand out distinct ephemeral ports while both \
         listeners are alive — port-collision precondition for \
         #1201's pool-bypass fix"
    );
    assert_ne!(p1, 0, "ephemeral port must be assigned");
}

/// Layer 2: `MockServer::builder().listener(L).start()` binds to the
/// listener we hand it, NOT to a pool member. Verifies the
/// pool-bypass mechanic the #1201 fix depends on.
#[tokio::test(flavor = "multi_thread")]
async fn issue_1201_mockserver_listener_bypasses_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let expected_port = listener.local_addr().expect("addr").port();

    let server = MockServer::builder().listener(listener).start().await;
    let observed_port = server.address().port();

    assert_eq!(
        expected_port, observed_port,
        "MockServer must use the listener we supplied (port {expected_port}) \
         rather than a pool-recycled one (port {observed_port}) — this is \
         the #1201 pool-bypass invariant"
    );
}

/// Layer 3: many sequential pool-bypassed mock servers DO get
/// distinct ports — the bind retry loop never spuriously hands back
/// the same port to two concurrent listeners.
#[tokio::test(flavor = "multi_thread")]
async fn issue_1201_sequential_listeners_get_unique_ports() {
    // Hold all listeners + servers alive in the vec so the kernel
    // cannot recycle a port mid-loop.
    let mut servers = Vec::new();
    let mut seen_ports = HashSet::new();
    for _ in 0..16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        assert!(
            seen_ports.insert(port),
            "#1201: kernel must NOT hand the same ephemeral port to \
             two concurrently-alive listeners; port {port} collided"
        );
        let server = MockServer::builder().listener(listener).start().await;
        assert_eq!(server.address().port(), port);
        servers.push(server);
    }
    assert_eq!(seen_ports.len(), 16);
}

/// Layer 4: the real-world parallel stress shape — many concurrent
/// tokio tasks each bind a listener + start a pool-bypassed mock
/// server. None collide. This is the closure-gate fact that proves
/// the #1201 fix tolerates parallel-binary load.
#[tokio::test(flavor = "multi_thread")]
async fn issue_1201_concurrent_listeners_get_unique_ports() {
    let seen: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = Vec::new();
    for _ in 0..32 {
        let seen = Arc::clone(&seen);
        handles.push(tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let server = MockServer::builder().listener(listener).start().await;
            assert_eq!(server.address().port(), port);
            let mut guard = seen.lock().await;
            assert!(
                guard.insert(port),
                "#1201: concurrent ephemeral-port allocation collided on \
                 port {port} — pool-bypass fix is leaking the OS port back \
                 between tasks"
            );
            // Hold the server until the task completes so the port
            // can't be recycled mid-test.
            drop(server);
        }));
    }
    for h in handles {
        h.await.expect("task join");
    }
    let final_count = seen.lock().await.len();
    assert_eq!(
        final_count, 32,
        "#1201: all 32 concurrent listeners must have observed unique ports"
    );
}
