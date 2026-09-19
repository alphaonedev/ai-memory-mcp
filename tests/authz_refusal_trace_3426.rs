// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #3426 — the OPERATOR half of the owner-gate refusal contract.
//!
//! `tests/authz_refusal_leak_3426.rs` pins that the wire never names the
//! owning agent. This binary pins the other direction: the owner the wire
//! dropped still reaches the server-side `ai_memory::authz` trace line, so
//! operators keep full attribution of every cross-owner refusal. Without
//! this pin a future "tidy-up" could delete the WARN and the refusal would
//! become anonymous everywhere — the leak fix would have quietly become
//! an audit gap.
//!
//! ONE test per binary: the `tracing` callsite-interest cache is
//! process-global, and a sibling test in the same binary running with no
//! subscriber installed can pin the shared callsite to `never`, making
//! this assertion flaky in the direction of a false PASS-through.

#![cfg(feature = "sal")]

use std::sync::{Arc, Mutex};

use ai_memory::models::{Memory, MemoryScope, Tier};
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use tempfile::NamedTempFile;

const OWNER: &str = "ai:alice-3426-trace";
const INTRUDER: &str = "ai:bob-3426-trace";

/// In-memory `tracing` writer (the `tests/agent_api_key_admin_route_3474.rs`
/// idiom) so the assertion reads what the subscriber actually emitted.
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
async fn cross_owner_refusal_reaches_authz_trace_with_owner_3426() {
    let tmp = NamedTempFile::new().expect("tempfile");
    let id = {
        let conn = ai_memory::db::open(tmp.path()).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "trace-3426".to_string(),
            title: "trace-3426".to_string(),
            content: "body".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({
                "agent_id": OWNER,
                "scope": MemoryScope::Collective.as_str(),
            }),
            version: 1,
            ..Memory::default()
        };
        ai_memory::db::insert(&conn, &mem).expect("db::insert");
        mem.id
    };
    let store = ai_memory::store::sqlite::SqliteStore::open(tmp.path()).expect("open");

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
            .update(
                &CallerContext::for_agent(INTRUDER),
                &id,
                UpdatePatch {
                    content: Some("hijacked".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect_err("#3426: a cross-owner update must be refused")
    };
    let StoreError::PermissionDenied { reason, .. } = err else {
        panic!("#3426: expected PermissionDenied, got {err:?}");
    };
    assert!(
        !reason.contains(OWNER),
        "#3426: the caller-facing reason must not name the owner: {reason}"
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
        "#3426: the refusal must be emitted under the AUTHZ trace target; got:\n{logs}"
    );
    assert!(
        logs.contains(OWNER) && logs.contains(INTRUDER) && logs.contains(&id),
        "#3426: the AUTHZ trace line must carry owner, caller and row id; got:\n{logs}"
    );
}
