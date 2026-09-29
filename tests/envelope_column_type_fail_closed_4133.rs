// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4133 — a non-NULL `encrypted_envelope` that is not a valid BLOB envelope
//! must fail CLOSED, never fall back to the plaintext `content` column.
//!
//! The row mapper read the envelope as `Option<Vec<u8>>` with
//! `.unwrap_or(None)`, so a column TYPE error (a TEXT or INTEGER value, from
//! corruption or tampering) was treated as "no envelope" and the row's raw
//! `content` column was returned as if the row were unencrypted.
//!
//! Cells (SQLite, driven through a real `ai-memory mcp` child plus the
//! storage read lanes), for TEXT, INTEGER and truncated-BLOB envelopes:
//!   * `memory_get` (targeted read) refuses the row; the plaintext never
//!     appears. RED on the untouched tip for TEXT / INTEGER.
//!   * `memory_recall` and `memory_skill_compositional_context` (scan reads)
//!     omit the row and still return the healthy sibling. RED for TEXT /
//!     INTEGER.
//!   * truncated BLOB is the control: it already failed closed.
//!
//! PostgreSQL (`--features sal-postgres`, `#[ignore]`, needs
//! `AI_MEMORY_TEST_POSTGRES_URL`): the column is `BYTEA`, so a TEXT or
//! INTEGER value cannot be stored (the INTEGER write is refused by the
//! schema, a text literal is coerced to bytes); every corrupt envelope the
//! column CAN hold must fail closed on `get` and be omitted by `list` /
//! `search`.

use ai_memory::models::{Memory, MemoryKind, Tier};
use rusqlite::types::Value as Sql;
use serde_json::json;

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

const NS: &str = "env4133";
const SECRET: &str = "SECRET-PLAINTEXT-4133";
const HEALTHY: &str = "HEALTHY-4133";
const NEEDLE: &str = "needle4133";
const OWNER: &str = "ai:owner-4133";

/// The corrupt envelope cells under test: (label, value).
fn corrupt_envelopes() -> [(&'static str, Sql); 3] {
    [
        ("text", Sql::Text("truncated-envelope".to_string())),
        ("integer", Sql::Integer(17)),
        ("truncated-blob", Sql::Blob(vec![3, 1, 2])),
    ]
}

fn seed(conn: &rusqlite::Connection, marker: &str, kind: MemoryKind) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: format!("{marker} {NEEDLE}"),
        content: format!("{marker} {NEEDLE} body"),
        namespace: NS.to_string(),
        tier: Tier::Long,
        memory_kind: kind,
        reflection_depth: i32::from(kind == MemoryKind::Reflection),
        metadata: json!({"agent_id": OWNER, "scope": "collective"}),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed")
}

/// Fresh store: one healthy + one poisoned row of `kind`; returns the
/// poisoned id.
fn fixture_with_poison(kind: MemoryKind, envelope: &Sql) -> (Fixture, String) {
    let fixture = Fixture::new();
    let conn = rusqlite::Connection::open(&fixture.db).expect("open");
    let _healthy = seed(&conn, HEALTHY, kind);
    let poisoned = seed(&conn, SECRET, kind);
    let n = conn
        .execute(
            "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
            rusqlite::params![envelope, poisoned],
        )
        .expect("poison envelope");
    assert_eq!(n, 1);
    (fixture, poisoned)
}

#[test]
fn targeted_read_fails_closed_on_a_non_blob_envelope_4133() {
    for (label, envelope) in corrupt_envelopes() {
        let (fixture, poisoned) = fixture_with_poison(MemoryKind::Observation, &envelope);
        // Storage targeted read: an error, never the plaintext column.
        let conn = ai_memory::db::open(&fixture.db).expect("open");
        match ai_memory::db::get(&conn, &poisoned) {
            Err(_) => {}
            Ok(row) => panic!("{label}: targeted read must fail closed, got {row:?}"),
        }
        // Scan read lane: the row is omitted.
        let got = ai_memory::db::get_many(&conn, std::slice::from_ref(&poisoned)).expect("scan");
        assert!(got.is_empty(), "{label}: scan read must omit the row");
        drop(conn);

        // MCP memory_get.
        let mut mcp = Mcp::start(&fixture, Some(OWNER));
        let result = mcp.call("memory_get", &json!({"id": poisoned}));
        assert_eq!(
            result["isError"], true,
            "{label}: memory_get must refuse a corrupt envelope: {result}"
        );
        assert!(
            !result.to_string().contains(SECRET),
            "{label}: the plaintext column must never be returned: {result}"
        );
    }
}

#[test]
fn recall_omits_a_non_blob_envelope_row_4133() {
    for (label, envelope) in corrupt_envelopes() {
        let (fixture, _poisoned) = fixture_with_poison(MemoryKind::Observation, &envelope);
        let mut mcp = Mcp::start(&fixture, Some(OWNER));
        let result = mcp.call(
            "memory_recall",
            &json!({"context": NEEDLE, "namespace": NS, "limit": 10, "format": "json"}),
        );
        assert_ne!(
            result["isError"], true,
            "{label}: recall must not fail: {result}"
        );
        let text = Mcp::text(&result);
        assert!(
            text.contains(HEALTHY),
            "{label}: healthy row recalled: {text}"
        );
        assert!(
            !text.contains(SECRET),
            "{label}: the corrupt-envelope row is omitted, never its plaintext: {text}"
        );
    }
}

#[test]
fn composition_omits_a_non_blob_envelope_reflection_4133() {
    for (label, envelope) in corrupt_envelopes() {
        let (fixture, _poisoned) = fixture_with_poison(MemoryKind::Reflection, &envelope);
        let skill_id = {
            let mut mcp = Mcp::start(&fixture, None);
            let md = format!(
                "---\nnamespace: skills4133\nname: composer-4133\ndescription: Composes {NS}.\n\
                 composes_with_reflections:\n  - namespace: {NS}\n    min_depth: 0\n---\n\nCompose.\n"
            );
            let reg = mcp.call_ok("memory_skill_register", &json!({"inline_skill": md}));
            reg["id"].as_str().expect("skill id").to_string()
        };
        for caller in [Some(OWNER), Some("ai:outsider-4133"), None] {
            let mut mcp = Mcp::start(&fixture, caller);
            let result = mcp.call(
                "memory_skill_compositional_context",
                &json!({"skill_id": skill_id}),
            );
            assert_ne!(
                result["isError"], true,
                "{label}/{caller:?}: composition must not fail: {result}"
            );
            let text = Mcp::text(&result);
            assert!(
                text.contains(HEALTHY),
                "{label}/{caller:?}: healthy composed: {text}"
            );
            assert!(
                !text.contains(SECRET),
                "{label}/{caller:?}: corrupt-envelope reflection omitted: {text}"
            );
        }
    }
}

#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{HEALTHY, NEEDLE, SECRET};
    use ai_memory::models::{Memory, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, Filter, MemoryStore};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        PostgresStore::connect(&url).await.ok()
    }

    fn mem(ns: &str, marker: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("{marker} {NEEDLE}"),
            content: format!("{marker} {NEEDLE} body"),
            namespace: ns.to_string(),
            tier: Tier::Long,
            metadata: serde_json::json!({"agent_id": "ai:pg-4133", "scope": "collective"}),
            created_at: now.clone(),
            updated_at: now,
            ..Memory::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_corrupt_envelope_fails_closed_4133() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("pg-4133");
        // The BYTEA column refuses an INTEGER outright (schema-level).
        let ns = format!("pg4133-{}", uuid::Uuid::new_v4().simple());
        let healthy = MemoryStore::store_with_embedding(&pg, &ctx, &mem(&ns, HEALTHY), None, None)
            .await
            .expect("store healthy");
        let poisoned = MemoryStore::store_with_embedding(&pg, &ctx, &mem(&ns, SECRET), None, None)
            .await
            .expect("store poisoned");
        let int_write = sqlx::query("UPDATE memories SET encrypted_envelope = 17 WHERE id = $1")
            .bind(&poisoned)
            .execute(pg.pool())
            .await;
        assert!(int_write.is_err(), "BYTEA must refuse an INTEGER envelope");

        for (label, sql) in [
            (
                "text-literal",
                "UPDATE memories SET encrypted_envelope = 'truncated-envelope' WHERE id = $1",
            ),
            (
                "truncated-blob",
                "UPDATE memories SET encrypted_envelope = decode('030102', 'hex') WHERE id = $1",
            ),
        ] {
            sqlx::query(sql)
                .bind(&poisoned)
                .execute(pg.pool())
                .await
                .expect("poison envelope");
            let got = MemoryStore::get(&pg, &ctx, &poisoned).await;
            assert!(
                got.as_ref().map_or(true, |m| !m.content.contains(SECRET)) && got.is_err(),
                "{label}: pg get must fail closed, got {got:?}"
            );
            // `Filter` is `#[non_exhaustive]`: build from Default.
            let mut filter = Filter::default();
            filter.namespace = Some(ns.clone());
            filter.limit = 50;
            let listed = MemoryStore::list(&pg, &ctx, &filter).await.expect("list");
            assert!(
                listed.iter().any(|m| m.id == healthy),
                "{label}: healthy listed"
            );
            assert!(
                listed
                    .iter()
                    .all(|m| m.id != poisoned && !m.content.contains(SECRET)),
                "{label}: pg list omits the corrupt row"
            );
            let found = MemoryStore::search(&pg, &ctx, NEEDLE, &filter)
                .await
                .expect("search");
            assert!(
                found
                    .iter()
                    .all(|m| m.id != poisoned && !m.content.contains(SECRET)),
                "{label}: pg search omits the corrupt row"
            );
        }
        let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
            .bind(&ns)
            .execute(pg.pool())
            .await;
    }
}
