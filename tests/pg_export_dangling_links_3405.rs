// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #1986: crate-level `//!` docs are still linted when `#![cfg(feature =
// "sal-postgres")]` is false (the allow below that cfg is configured out).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3405 — POSTGRES parity for the export bundle's referential-integrity
//! funnel.
//!
//! `handlers::admin::export_memories` composes its bundle from two independent
//! SAL reads on BOTH backends. On postgres, `export_memories()` walks a keyset
//! reader that applies the expiry predicate AND the #1948 lifecycle allow-list
//! (see `store::postgres_parity::export_memories_keyset`), while
//! `export_links()` delegates to the uncapped `list_links(None)` with no
//! lifecycle predicate at all — the exact asymmetry the sqlite lane has. So a
//! `tombstoned` row is withheld from `memories[]` while every edge naming it
//! still rides `links[]`, and the wire bundle names memories it does not
//! carry. `memory_links` carries a `REFERENCES memories(id)` foreign key on
//! both backends, so neither `POST /api/v1/import` nor `ai-memory import` can
//! materialise such an edge.
//!
//! This test drives the postgres SAL reads DIRECTLY (the same two calls the
//! handler makes, in the same order) and asserts:
//!
//! 1. **the defect is real on postgres** — the raw `export_links()` result DOES
//!    name the tombstoned endpoint, so the funnel is not filtering a case that
//!    cannot occur here; and
//! 2. **the control holds on postgres** — `export_scope::retain_resolvable_links`
//!    drops exactly that edge, keeps the intact one (the ALLOWED path), and
//!    reports the drop rather than swallowing it.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset), and
//! confined to a uuid-suffixed probe namespace that is dropped at the end.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::similar_names)]

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn mem(id: &str, ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        created_at: now.clone(),
        updated_at: now,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("content of {title}"),
        source: "import".to_string(),
        metadata: serde_json::json!({ "agent_id": "ai:3405" }),
        ..Memory::default()
    }
}

fn edge(source_id: &str, target_id: &str) -> MemoryLink {
    MemoryLink {
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

#[tokio::test]
async fn pg_export_never_emits_an_edge_whose_endpoint_it_withheld_3405() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-3405-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:3405");

    let live_a = format!("m3405-a-{}", uuid::Uuid::new_v4());
    let live_b = format!("m3405-b-{}", uuid::Uuid::new_v4());
    let doomed = format!("m3405-t-{}", uuid::Uuid::new_v4());
    for (id, title) in [
        (&live_a, "live a"),
        (&live_b, "live b"),
        (&doomed, "to be tombstoned"),
    ] {
        store
            .store(&ctx, &mem(id, &ns, title))
            .await
            .expect("seed row");
    }
    // The ALLOWED edge (both endpoints stay live) and the edge that will point
    // at a withheld row — the shape consolidation mints in production
    // (`storage::consolidate` writes `derived_from` to each source, then
    // tombstones it).
    store
        .link(&ctx, &edge(&live_a, &live_b))
        .await
        .expect("intact edge");
    store
        .link(&ctx, &edge(&live_a, &doomed))
        .await
        .expect("doomed edge");

    // Retain the row and move it to the terminal `tombstoned` lifecycle state,
    // exactly as the consolidation path does. Raw SQL: this is a system
    // transition, not a caller-reachable transition.
    sqlx::query("UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = $1")
        .bind(&doomed)
        .execute(store.pool())
        .await
        .expect("tombstone the source row");

    // ── the two reads the HTTP admin export performs, in order ────────────
    let memories = store.export_memories().await.expect("export_memories");
    let links = store.export_links().await.expect("export_links");

    let mine: Vec<Memory> = memories.into_iter().filter(|m| m.namespace == ns).collect();
    assert_eq!(
        mine.len(),
        2,
        "the postgres export withholds the tombstoned row (the #1948 lifecycle allow-list)"
    );
    let mine_links: Vec<MemoryLink> = links
        .into_iter()
        .filter(|l| l.source_id == live_a)
        .collect();

    // (1) The defect is REAL on postgres: `export_links` has no lifecycle
    //     predicate, so the raw edge set still names the withheld row.
    assert!(
        mine_links.iter().any(|l| l.target_id == doomed),
        "#3405 precondition: the raw postgres edge read must still name the \
         tombstoned endpoint — otherwise this test would be vacuous"
    );

    // (2) The control holds on postgres: the shared funnel keeps the intact
    //     edge and drops exactly the unresolvable one, reporting it.
    let (kept, dangling) = ai_memory::export_scope::retain_resolvable_links(&mine, mine_links);
    assert_eq!(
        kept.len(),
        1,
        "only the edge whose BOTH endpoints ride the bundle survives"
    );
    assert_eq!(kept[0].target_id, live_b, "the intact edge is preserved");
    assert_eq!(
        dangling,
        vec![format!("{live_a}->{doomed}")],
        "the withheld edge is REPORTED on the operator channel, never swallowed"
    );

    // ── cleanup: confine every artifact to the probe namespace ────────────
    sqlx::query("DELETE FROM memory_links WHERE source_id = $1")
        .bind(&live_a)
        .execute(store.pool())
        .await
        .expect("cleanup links");
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("cleanup memories");
}
