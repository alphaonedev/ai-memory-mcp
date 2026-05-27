// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::manual_let_else)]
// Mirrors the existing `test_build_llm_client_returns_none_when_ollama_unreachable`
// pattern at `src/daemon_runtime.rs:6411` — the legacy `ollama_url`
// field still feeds the resolver via the `Legacy` precedence arm at
// v0.7.x; removal is slated for v0.8.0. Using it here keeps this
// regression test wire-shape-equivalent to the original failing
// invocation that surfaced FX-D1.
#![allow(deprecated)]
//! FX-D1 (v0.7.0, 2026-05-27) — regression test for the FX-C1 panic
//! when an `OllamaClient` sync wrapper is invoked from inside a
//! current-thread tokio runtime.
//!
//! # Lineage
//!
//! FX-C1 (PERF-9) shipped the v0.7.0 sync→async bridge in
//! `src/llm.rs::block_on_local`. The original design panicked on the
//! current-thread arm with:
//!
//! ```text
//! OllamaClient sync wrapper called from inside a current-thread
//! tokio runtime. Use the `*_async` variant or annotate the test
//! `#[tokio::test(flavor = "multi_thread")]`.
//! ```
//!
//! The rationale was "every in-repo `#[tokio::test]` is multi-thread,
//! so this branch should be unreachable in practice — make it a loud
//! panic so a regression surfaces immediately". Production hit it via
//! `daemon_runtime::build_llm_client` →
//! `tokio::task::spawn_blocking(|| OllamaClient::build_from_resolved(...))`:
//! the blocking-pool thread inherits the outer runtime handle, so when
//! the outer runtime was current-thread (the default for
//! `#[tokio::test]`), `Handle::try_current()` resolved to a
//! `CurrentThread` flavor and the panic fired.
//!
//! CI evidence post-merge on `release/v0.7.0` HEAD
//! `2a8fb45634b196d38875fa34618071d1a7b12ba9`:
//!
//! ```text
//! WARN ai_memory::daemon_runtime: L5: build_llm_client spawn_blocking
//! join failed (tier=smart): task 294 panicked with message
//! "OllamaClient sync wrapper called from inside a current-thread
//! tokio runtime. …"
//! ```
//!
//! # What this test pins
//!
//! 1. The defensive fix in `block_on_local`: spawning the sync wrapper
//!    from inside a current-thread tokio runtime no longer panics. The
//!    helper now bridges through a freshly-scoped OS thread that owns
//!    its own one-shot current-thread runtime.
//! 2. The surgical fix in `daemon_runtime::build_llm_client`: the
//!    callsite that surfaced the regression now goes through the
//!    async constructor and never re-enters `block_on_local`.
//!
//! Both fixes are exercised by the body below: every scenario builds
//! a current-thread tokio runtime (matching the original failing
//! shape) and drives the sync wrapper through `spawn_blocking`. The
//! assertion is that NO panic occurs — the wrapper either returns a
//! clean `Ok` (improbable on a closed port — usually impossible) or
//! a clean `Err`.
//!
//! Companion tests:
//! - `tests/round2_f6_llm.rs` pins the F6 circuit-breaker semantics.
//! - `src/llm.rs::tests::*` pins the multi-thread block_in_place path.

use ai_memory::llm::OllamaClient;
use std::net::TcpListener;

/// Allocate an `127.0.0.1:<port>` URL with NO listener so any TCP
/// connect against it fails immediately. The reservation listener is
/// dropped before we return so the port is left closed; this gives us
/// a deterministic "Ollama is unreachable" target without depending
/// on any OS-level firewall rule.
fn closed_local_url() -> String {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind a free 127.0.0.1 port for the test");
    let addr = listener
        .local_addr()
        .expect("local_addr resolves on a freshly-bound listener");
    drop(listener);
    format!("http://{addr}")
}

/// Driver — build a current-thread tokio runtime (matching the
/// `#[tokio::test]` default flavor that surfaced the FX-D1
/// regression), then call `spawn_blocking` to drive the sync
/// `OllamaClient` constructor. The sync constructor uses
/// `block_on_local` internally; pre-FX-D1 this combination panicked.
///
/// Asserts: the spawn_blocking join returns without a panic — either
/// `Ok(_)` (the underlying constructor returned something) or an
/// `Err`-shaped result, but never a `JoinError::is_panic()`.
fn drive_sync_constructor_under_current_thread_runtime(url: String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime builds");

    let result = rt.block_on(async move {
        // Mirror production shape: daemon_runtime::build_llm_client
        // pre-FX-D1 was `spawn_blocking(move || OllamaClient::build_from_resolved(...))`
        // and surfaced as task panicked.
        tokio::task::spawn_blocking(move || {
            // The sync constructor `new_with_url` calls into
            // `block_on_local`; this is the wrapper that panicked.
            // We aim a closed-port URL at it so the constructor
            // returns Err (Ollama unreachable) — but the LOAD-BEARING
            // assertion is no-panic, not Err-vs-Ok.
            OllamaClient::new_with_url(&url, "test-model")
        })
        .await
    });

    match result {
        Ok(Ok(_client)) => {
            // Improbable but allowed — if the connect-timeout window
            // happened to overlap with some other listener on the
            // host. The contract is "no panic".
        }
        Ok(Err(_err)) => {
            // Expected path: Ollama unreachable. Clean error envelope,
            // no panic. This is the load-bearing post-FX-D1 outcome.
        }
        Err(join_err) => {
            assert!(
                !join_err.is_panic(),
                "FX-D1 regression: spawn_blocking task panicked when sync \
                 OllamaClient wrapper was called from inside a current-thread \
                 tokio runtime. Original panic message reproduction lineage: \
                 src/llm.rs::block_on_local (FX-C1) → daemon_runtime::build_llm_client \
                 (FX-D1 surgical fix at known callsite + block_on_local defensive \
                 fix for unknown callsites). Join error: {join_err:?}"
            );
            // Cancellation is acceptable; panic is not.
        }
    }
}

#[test]
fn sync_constructor_in_current_thread_tokio_does_not_panic() {
    // Direct exercise of the original failing shape:
    //   current-thread tokio runtime  +  spawn_blocking  +  sync wrapper
    let url = closed_local_url();
    drive_sync_constructor_under_current_thread_runtime(url);
}

#[test]
fn nested_spawn_blocking_sync_constructor_does_not_panic() {
    // Double-nested exercise — spawn_blocking inside spawn_blocking.
    // Earlier FX-C1 design relied on `block_in_place` being a no-op
    // when called from outside a worker thread; this test pins that
    // the fallback path (current-thread arm of `block_on_local`) is
    // also panic-free when reached via a doubly-nested blocking
    // dispatch chain.
    let url = closed_local_url();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime builds");

    let result = rt.block_on(async move {
        tokio::task::spawn_blocking(move || {
            // Nested: build a fresh runtime *inside* this blocking
            // thread (some real-world call sites do this when
            // adapting between executors).
            let inner_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("nested current-thread tokio runtime builds");
            inner_rt.block_on(async move {
                tokio::task::spawn_blocking(move || OllamaClient::new_with_url(&url, "test-model"))
                    .await
            })
        })
        .await
    });

    match result {
        Ok(Ok(Ok(_) | Err(_))) => { /* either is fine — no panic */ }
        Ok(Err(inner_join)) => {
            assert!(
                !inner_join.is_panic(),
                "FX-D1 regression: nested spawn_blocking inner task panicked: {inner_join:?}"
            );
        }
        Err(outer_join) => {
            assert!(
                !outer_join.is_panic(),
                "FX-D1 regression: outer spawn_blocking task panicked: {outer_join:?}"
            );
        }
    }
}

#[test]
fn build_llm_client_known_callsite_does_not_panic() {
    // FX-D1 surgical fix verification: the daemon's
    // `build_llm_client` no longer wraps `build_from_resolved` in
    // `spawn_blocking`. It now calls `build_from_resolved_async`
    // directly. This test exercises that path under the same
    // current-thread runtime shape that surfaced the original
    // regression.
    //
    // The Smart tier is chosen because it has a compiled `llm_model`
    // preset, which forces `build_llm_client` past the early-return
    // gate and into the construction path. We point at a closed
    // 127.0.0.1 port so the construction fails cleanly (Ollama
    // unreachable) — but again, the load-bearing assertion is
    // no-panic, not Err-vs-None.
    use ai_memory::config::{AppConfig, FeatureTier};
    use ai_memory::daemon_runtime::build_llm_client;

    let url = closed_local_url();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime builds");

    let result = rt.block_on(async {
        let cfg = AppConfig {
            ollama_url: Some(url),
            ..AppConfig::default()
        };
        build_llm_client(FeatureTier::Smart, &cfg).await
    });

    // `build_llm_client` returns `Option<OllamaClient>` and never
    // panics post-FX-D1. Either an `Option::None` (reachability
    // failure) or `Option::Some(_)` (impossibly lucky port) is
    // acceptable; the assertion is implicit in reaching this line
    // without unwinding.
    let _ = result;
}
