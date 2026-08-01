// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2577 — the recall-path query-embedding budget.
//!
//! **R-203.** These tests FAIL at the parent commit. At parent the remote
//! embed client is bounded only by `GENERATE_TIMEOUT` (30 s) — a
//! *generation* budget applied to a *read* — so a provider that accepts
//! the connection and then never answers hangs `memory_recall` for the
//! full 30 s. On MCP stdio (single-threaded by JSON-RPC protocol design,
//! the #965 audit) that is a 30 s outage of the WHOLE server, not just one
//! slow recall.
//!
//! **Hermetic.** No network egress and no model weights: a loopback
//! `TcpListener` accepts the connection and then goes silent, standing in
//! for a provider that is up but not answering. That is the shape the
//! #2577 sample hit (39,268 ms observed), and it is the shape a plain
//! connect-timeout does NOT catch — the TCP connect succeeds.

use std::time::{Duration, Instant};

use ai_memory::embeddings::{Embedder, recall_query_embedding, set_recall_embed_budget_for_test};

/// Bind a loopback listener that accepts connections and then never
/// writes a byte. Returns the base URL. The accept loop lives on a
/// detached thread for the lifetime of the test process.
fn spawn_silent_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        // Hold every accepted stream open, forever, without responding.
        let mut held = Vec::new();
        for stream in listener.incoming() {
            match stream {
                Ok(s) => held.push(s),
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}")
}

fn silent_remote_embedder(base_url: &str) -> Embedder {
    let client = ai_memory::llm::OllamaClient::new_with_url_no_health_check(base_url, "test-embed")
        .expect("build client");
    Embedder::Ollama {
        client: std::sync::Arc::new(client),
        model_name: "test-embed".to_string(),
        dim: 768,
        degraded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// The budget bounds a stalled provider and the recall degrades rather
/// than hanging.
///
/// **Fails at parent**: without the budget this call blocks on
/// `GENERATE_TIMEOUT` (30 s) and blows the 10 s assertion ceiling.
#[test]
fn stalled_provider_is_bounded_by_the_recall_budget_2577() {
    let url = spawn_silent_endpoint();
    let emb = silent_remote_embedder(&url);

    // 700 ms budget: comfortably above any loopback round trip, far below
    // the 30 s client timeout, so the assertion cannot pass by accident.
    set_recall_embed_budget_for_test(Some(700));
    ai_memory::embeddings::clear_query_embed_cache();

    let started = Instant::now();
    let got = recall_query_embedding(&emb, "a query the provider will never answer");
    let elapsed = started.elapsed();

    set_recall_embed_budget_for_test(None);

    // DEGRADE, not error: the caller gets `None` and runs keyword-only.
    assert!(
        got.is_none(),
        "a stalled provider must degrade to keyword (None), not return a vector"
    );
    // The whole point: bounded. Generous 10 s ceiling so a loaded CI host
    // cannot flake it, while still failing hard against the 30 s parent.
    assert!(
        elapsed < Duration::from_secs(10),
        "recall embed was not bounded by the budget: took {elapsed:?} \
         (parent behaviour is the 30 s GENERATE_TIMEOUT; #2577)"
    );
}

/// **R-203 evidence, measured in-tree.** The UNBOUNDED path — exactly what
/// every recall surface called at the parent commit — against the very
/// same silent endpoint.
///
/// `#[ignore]`d because it deliberately waits out the full
/// `GENERATE_TIMEOUT` (30 s) and would dominate the suite's wall clock.
/// Run it to reproduce the defect:
///
/// ```text
/// cargo test --test recall_embed_budget_2577 -- --ignored --nocapture
/// ```
///
/// Measured on the #2577 reference host: **30,002 ms** unbounded vs
/// **703 ms** bounded — the same call, the same endpoint, 43x.
#[test]
#[ignore = "waits out the full 30s GENERATE_TIMEOUT; run with --ignored to reproduce the parent defect"]
fn parent_unbounded_embed_hangs_for_the_generation_timeout_2577() {
    let url = spawn_silent_endpoint();
    let emb = silent_remote_embedder(&url);

    let started = Instant::now();
    // The pre-#2577 call: no budget, so the only bound is the client-level
    // GENERATE_TIMEOUT — a *generation* budget applied to a *read*.
    let unbounded = emb.embed_query("a query the provider will never answer");
    let elapsed = started.elapsed();
    println!("UNBOUNDED (parent path) embed_query took {elapsed:?}");

    assert!(
        unbounded.is_err(),
        "the stalled endpoint must eventually error"
    );
    assert!(
        elapsed > Duration::from_secs(5),
        "this test only demonstrates the defect if the unbounded path really \
         does hang far past any read-appropriate budget; got {elapsed:?}"
    );
}

/// An explicit `0` disables the budget (tri-state, the #2032 M3
/// precedent) — proving the knob is real and not hard-wired on.
///
/// Asserts only the RESOLVER, never a 30 s stall, so the suite stays fast.
#[test]
fn explicit_zero_disables_the_budget_2577() {
    set_recall_embed_budget_for_test(Some(0));
    assert!(
        ai_memory::embeddings::recall_embed_budget().is_none(),
        "an explicit 0 must disable the budget (tri-state: unset != 0)"
    );
    set_recall_embed_budget_for_test(Some(2_000));
    assert_eq!(
        ai_memory::embeddings::recall_embed_budget(),
        Some(Duration::from_secs(2)),
        "a positive value must resolve to that budget"
    );
    set_recall_embed_budget_for_test(None);
}

/// The compiled default is the documented 2000 ms — pinned so a silent
/// retune cannot slip past review.
#[test]
fn compiled_default_budget_is_2000ms_2577() {
    assert_eq!(
        ai_memory::embeddings::RECALL_EMBED_BUDGET_MS_DEFAULT,
        2_000,
        "the #2577 compiled default is 2000 ms (~4x the observed p99 of 492 ms)"
    );
}
