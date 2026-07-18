// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2179 — DAEMON boot-maintenance wiring twin: the
//! `#[cfg(feature = "sal-postgres")]` block in
//! [`ai_memory::daemon_runtime::bootstrap_serve`] that, on a POSTGRES-backed
//! daemon WITH a configured embedder, downcasts the typed store handle and runs
//! `PostgresStore::embedding_space_boot_maintenance(active_fp, dim)` against the
//! ACTUAL pg corpus (adopt→census). Without this wiring a v84 upgrade leaves
//! every legacy pg row `embedding_space NULL`, permanently excluded from
//! semantic recall (#2179).
//!
//! The unit-level pg twins live in `tests/embedding_space_provenance_2167_pg.rs`
//! (they call `embedding_space_boot_maintenance` directly). This file drives the
//! DAEMON `bootstrap_serve` path itself so the downcast + call SITE in
//! `daemon_runtime.rs` executes — the coverage job otherwise never reaches it
//! (no in-process `bootstrap_serve` test booted a pg store with an embedder).
//!
//! ## Gating
//!
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`. Without the env
//! var the test prints a skip line and returns (the shipped `pg_*` convention),
//! so a plain `cargo test` stays green and the coverage job (which sets the URL)
//! executes it.
//!
//! The embedder is an OFFLINE `openai-compatible` remote embedder: it is built
//! `new_remote` at boot with NO network round-trip, so `emb.dim()` /
//! `emb.space_fingerprint()` (the only methods the boot block calls) are pure —
//! no model download, no live vendor.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

use ai_memory::config::{AppConfig, EmbeddingsSection};
use ai_memory::daemon_runtime::{ServeArgs, bootstrap_serve};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A loopback `ServeArgs` pointed at the live postgres store. Loopback + no
/// api_key boots with a WARN (the single-tenant dev convention pinned by
/// `tests/v070_a1_authn.rs`), so bootstrap returns `Ok` without binding.
fn serve_args(url: &str) -> ServeArgs {
    ServeArgs {
        host: "127.0.0.1".to_string(),
        port: 0,
        tls_cert: None,
        tls_key: None,
        mtls_allowlist: None,
        shutdown_grace_secs: 30,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 30,
        federation_identity: None,
        store_url: Some(url.to_string()),
    }
}

/// An `AppConfig` whose resolved embedder is an OFFLINE `openai-compatible`
/// remote embedder (built `new_remote`, no model load / no network at boot).
/// `tier = semantic` enables the embedder; the explicit `dim` is required for an
/// API backend whose model is not in the known-dims table.
fn app_config_with_offline_api_embedder() -> AppConfig {
    AppConfig {
        tier: Some("semantic".to_string()),
        embeddings: Some(EmbeddingsSection {
            backend: Some("openai-compatible".to_string()),
            base_url: Some("http://127.0.0.1:1".to_string()),
            model: Some("test-embed-boot-2167".to_string()),
            dim: Some(768),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A default `AppConfig` (no `tier`, no `[embeddings]` section) — the
/// keyword-only posture. `build_embedder` resolves NO model in this shape
/// (`resolve_embedder_model` / the tier preset both come back `None`), so
/// `embedder_arc.as_ref()` is `None` at the `#2179` boot-maintenance guard.
fn app_config_keyword_only() -> AppConfig {
    AppConfig::default()
}

/// The daemon boot block runs `embedding_space_boot_maintenance` against the pg
/// corpus when the store is Postgres AND an embedder is configured. Booting the
/// full `bootstrap_serve` path with both conditions true executes the downcast +
/// call site in `daemon_runtime.rs`. A clean `Ok(_)` (the census is
/// fire-and-forget, never fails the boot) proves the block ran without
/// disturbing startup.
#[tokio::test]
async fn daemon_bootstrap_runs_pg_embedding_space_boot_maintenance_2179() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    // A throwaway sqlite db path for the (unused-by-pg) local handle; the store
    // is the postgres one selected by `store_url`.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for local db");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    let args = serve_args(&url);
    let cfg = app_config_with_offline_api_embedder();

    let result = bootstrap_serve(&path, &args, &cfg).await;

    let boot = result.expect(
        "bootstrap_serve must boot a postgres-backed loopback daemon with an offline embedder \
         and run the #2179 embedding-space boot maintenance without error",
    );
    assert!(
        matches!(
            boot.app_state.storage_backend,
            ai_memory::handlers::StorageBackend::Postgres
        ),
        "the daemon must be postgres-backed so the #2179 boot-maintenance block executes"
    );

    // Stop the spawned background workers so the test tears down cleanly.
    for handle in boot.task_handles {
        handle.abort();
    }
}

/// Guard-false arm (b): the store IS Postgres but NO embedder is configured
/// (`embedder_arc.as_ref()` is `None`). The `#2179` boot-maintenance `if`
/// short-circuits on the second `let`-chain condition and the block is
/// SKIPPED — no downcast, no `embedding_space_boot_maintenance` call. Boot
/// must still succeed cleanly (keyword-only postgres daemon is a supported
/// posture) so this exercises the guard's false branch without disturbing
/// startup.
#[tokio::test]
async fn daemon_bootstrap_skips_pg_boot_maintenance_when_no_embedder_configured() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };

    let tmp = tempfile::NamedTempFile::new().expect("tempfile for local db");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    let args = serve_args(&url);
    let cfg = app_config_keyword_only();

    let result = bootstrap_serve(&path, &args, &cfg).await;

    let boot = result.expect(
        "bootstrap_serve must boot a postgres-backed loopback daemon with NO embedder \
         configured (keyword-only posture) — the #2179 boot-maintenance block must be \
         skipped, not error, on the embedder-absent guard arm",
    );
    assert!(
        matches!(
            boot.app_state.storage_backend,
            ai_memory::handlers::StorageBackend::Postgres
        ),
        "the daemon must still be postgres-backed — only the embedder is absent"
    );
    assert!(
        boot.app_state.embedder.is_none(),
        "keyword-only AppConfig must resolve to no embedder, so the #2179 guard's \
         `let Some(emb) = embedder_arc.as_ref()` arm is FALSE"
    );

    for handle in boot.task_handles {
        handle.abort();
    }
}

/// Guard-false arm (a): the daemon is SQLITE-backed (no `store_url`) even
/// though an embedder IS configured. `matches!(storage_backend, Postgres)`
/// is false, so the `#2179` boot-maintenance `if` short-circuits on the
/// FIRST condition and the block is skipped — no downcast attempted at all
/// (the sqlite `store_handle` is not a `PostgresStore`). Requires
/// `AI_MEMORY_TEST_POSTGRES_URL` only because this file is gated
/// `#[cfg(feature = "sal-postgres")]` at the module level; the test itself
/// does not touch postgres.
#[tokio::test]
async fn daemon_bootstrap_skips_pg_boot_maintenance_on_sqlite_backend() {
    if pg_url().is_none() {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    }

    let tmp = tempfile::NamedTempFile::new().expect("tempfile for local db");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    let args = ServeArgs {
        host: "127.0.0.1".to_string(),
        port: 0,
        tls_cert: None,
        tls_key: None,
        mtls_allowlist: None,
        shutdown_grace_secs: 30,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 30,
        federation_identity: None,
        store_url: None,
    };
    let cfg = app_config_with_offline_api_embedder();

    let result = bootstrap_serve(&path, &args, &cfg).await;

    let boot = result.expect(
        "bootstrap_serve must boot a sqlite-backed loopback daemon with an embedder \
         configured — the #2179 boot-maintenance block must be skipped (not error) on \
         the non-postgres guard arm",
    );
    assert!(
        matches!(
            boot.app_state.storage_backend,
            ai_memory::handlers::StorageBackend::Sqlite
        ),
        "no store_url must resolve to the sqlite backend, so the #2179 guard's \
         `matches!(storage_backend, Postgres)` arm is FALSE"
    );

    for handle in boot.task_handles {
        handle.abort();
    }
}
