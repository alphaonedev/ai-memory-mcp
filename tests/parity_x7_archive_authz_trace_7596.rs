// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7596 - the sqlite `archive_by_ids` foreign-row refusal reaches the AUTHZ
//! trace with owner, caller and row id, as the postgres twin does (#3426).
//!
//! ONE test per binary: the `tracing` callsite-interest cache is
//! process-global (see `tests/authz_refusal_trace_3426.rs`).

#![cfg(feature = "sal")]

mod common;

use std::sync::{Arc, Mutex};

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const OWNER: &str = "ai:owner-7596";
const INTRUDER: &str = "ai:intruder-7596";
const ID: &str = "x7-trace-row";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn sqlite_archive_foreign_refusal_emits_authz_trace_7596() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("trace.db")).expect("open");
    let admin = CallerContext::for_admin("operator:trace-7596");
    let ts = "2026-09-01T00:00:00+00:00".to_string();
    let mem = Memory {
        id: ID.to_string(),
        tier: Tier::Long,
        namespace: "x7/trace".to_string(),
        title: "trace row".to_string(),
        content: "trace row body".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "x7".to_string(),
        created_at: ts.clone(),
        updated_at: ts,
        metadata: serde_json::json!({ "agent_id": OWNER }),
        ..Default::default()
    };
    store.store(&admin, &mem).await.expect("store");

    let sink = Capture::default();
    let sink_for_writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink_for_writer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let err = {
        let _default = tracing::subscriber::set_default(subscriber);
        store
            .archive_by_ids(&CallerContext::for_agent(INTRUDER), &[ID.to_string()], None)
            .await
            .expect_err("a foreign row must refuse")
    };
    let StoreError::PermissionDenied { reason, .. } = err else {
        panic!("expected PermissionDenied, got {err:?}");
    };
    assert!(
        !reason.contains(OWNER),
        "the wire reason never names the owner"
    );

    let logs = String::from_utf8_lossy(
        &sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .to_string();
    assert!(
        logs.contains(ai_memory::handlers::AUTHZ_TRACE_TARGET),
        "refusal must use the AUTHZ trace target; got:\n{logs}"
    );
    assert!(
        logs.contains(OWNER) && logs.contains(INTRUDER) && logs.contains(ID),
        "trace must carry owner, caller and id; got:\n{logs}"
    );
}
