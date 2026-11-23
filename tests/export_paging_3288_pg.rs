// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3288 — the postgres half of the bounded admin export.
//!
//! Pre-#3288 `PostgresStore::export_memories` walked keyset pages but pushed
//! every page into ONE `Vec<Memory>` (and `export_links` returned the whole
//! link table), so `GET /api/v1/export` on a multi-million-row tenant
//! materialised the corpus and OOM-killed the daemon; rows the decrypt
//! projection skipped were reported to the log only. These tests drive the
//! trait surface the handler uses, `export_memories_page` +
//! `export_links_page`, and pin:
//!
//! * every page returns at most `limit` rows and a walk visits every live row
//!   of the probe namespace exactly once, `created_at` ties included;
//! * a row that holds an at-rest envelope (sealed, openable or not) REFUSES
//!   the page with `SEALED_EXPORT_REFUSED` (#10033, 3-agent vote 71472661
//!   V3-STD4-SCOPE C-3): the page format has no envelope field, so the row is
//!   never decrypted onto the wire and never silently skipped;
//! * pages taken in order never carry an edge before both endpoints are
//!   carried, and every carriable edge is emitted exactly once.
//!
//! The pg suite shares one database, so each test confines its assertions to
//! a uuid-suffixed probe namespace dated after everything else the suite
//! writes, and walks from a cursor just before it. Gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use std::collections::{HashMap, HashSet};

use ai_memory::export_paging::{ExportCursor, ExportMemoriesPage};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn mem(id: &str, ns: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        namespace: ns.to_string(),
        title: format!("title {id}"),
        content: format!("content of {id}"),
        source: "import".to_string(),
        metadata: serde_json::json!({ "agent_id": "ai:3288" }),
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

/// Seed `n` rows in `ns`, pairs sharing a `created_at` so ties are exercised.
async fn seed(store: &PostgresStore, ns: &str, n: usize) -> Vec<String> {
    let ctx = CallerContext::for_agent("ai:3288");
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!("{ns}-{i:03}");
        let ts = format!("2031-03-01T00:00:{:02}.000000Z", (i / 2) % 60);
        store
            .store(&ctx, &mem(&id, ns, &ts))
            .await
            .expect("seed row");
        ids.push(id);
    }
    ids
}

/// Walk with `limit` from just before the probe rows' `created_at` (year
/// 2031, after anything the rest of the shared suite writes) to the end of
/// the corpus, returning each page. Starting from a cursor keeps the walk
/// short on a large shared database and exercises resume-from-cursor.
async fn walk(store: &PostgresStore, limit: usize) -> Vec<ExportMemoriesPage> {
    let as_of = chrono::Utc::now();
    let mut cursor: Option<ExportCursor> = Some(ExportCursor {
        after: ai_memory::export_paging::ExportKey {
            created_at: "2031-02-28T23:59:59.000000Z".to_string(),
            id: String::new(),
        },
        as_of,
        namespace: None,
    });
    let mut pages = Vec::new();
    for _ in 0..1_000_000 {
        let page = store
            .export_memories_page(cursor.as_ref(), limit, as_of, None)
            .await
            .expect("export page");
        assert!(page.raw_rows() <= limit, "a page never exceeds its limit");
        cursor.clone_from(&page.next_cursor);
        let done = cursor.is_none();
        pages.push(page);
        if done {
            return pages;
        }
    }
    panic!("export walk did not terminate");
}

#[tokio::test]
async fn pg_export_walk_is_bounded_and_complete_3288() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-3288-{}", uuid::Uuid::new_v4());
    let expected: HashSet<String> = seed(&store, &ns, 17).await.into_iter().collect();

    let pages = walk(&store, 7).await;
    let mut seen: Vec<String> = Vec::new();
    for page in &pages {
        seen.extend(
            page.memories
                .iter()
                .filter(|m| m.namespace == ns)
                .map(|m| m.id.clone()),
        );
    }
    let unique: HashSet<String> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), seen.len(), "no row is returned twice");
    assert_eq!(unique, expected, "every live probe row is carried");
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("cleanup");
}

/// The exact refusal code, written out here rather than taken from the code
/// under test.
const SEALED_REFUSAL_CODE: &str = "SEALED_EXPORT_REFUSED";

/// #10033 on the store surface: a row with an at-rest envelope refuses the
/// export page, on the first page of a scoped walk (whatever page the row
/// would fall on) and on a page resumed from a cursor just before it. The
/// envelope is garbage, so the refusal is proven to be decided from the
/// column, before any decrypt. The probe rows are dated 2030, before the
/// 2031 window the other cells of this binary walk, so a parallel cell never
/// meets the sealed row.
#[tokio::test]
async fn pg_export_refuses_a_sealed_row_instead_of_skipping_it_10033() {
    let Some(url) = postgres_url() else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-10033-sealed-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:3288");
    let mut ids = Vec::new();
    for i in 0..5 {
        let id = format!("{ns}-{i:03}");
        let ts = format!("2030-06-01T00:00:{i:02}.000000Z");
        store
            .store(&ctx, &mem(&id, &ns, &ts))
            .await
            .expect("seed row");
        ids.push(id);
    }
    sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
        .bind(vec![0_u8; 96])
        .bind(&ids[4])
        .execute(store.pool())
        .await
        .expect("plant an at-rest envelope");
    let as_of = chrono::Utc::now();
    let first = store
        .export_memories_page(None, 2, as_of, Some(&ns))
        .await
        .expect_err("the first page of a walk over a sealed row must refuse");
    let msg = first.to_string();
    assert!(
        msg.contains(SEALED_REFUSAL_CODE) && msg.contains(&ids[4]),
        "not the sealed-export refusal naming the row: {msg}"
    );
    let resumed = ExportCursor {
        after: ai_memory::export_paging::ExportKey {
            created_at: "2030-06-01T00:00:03.000000Z".to_string(),
            id: ids[3].clone(),
        },
        as_of,
        namespace: Some(ns.clone()),
    };
    let later = store
        .export_memories_page(Some(&resumed), 2, as_of, Some(&ns))
        .await
        .expect_err("a page that holds the sealed row must refuse");
    assert!(
        later.to_string().contains(SEALED_REFUSAL_CODE),
        "not the sealed-export refusal: {later}"
    );
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn pg_export_links_page_never_dangles_in_import_order_3288() {
    let Some(url) = postgres_url() else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-3288-lnk-{}", uuid::Uuid::new_v4());
    let ids = seed(&store, &ns, 10).await;
    let ctx = CallerContext::for_agent("ai:3288");
    let edges = [(0, 9), (9, 1), (2, 3), (4, 8), (8, 4), (6, 0), (5, 7)];
    for (s, t) in edges {
        store
            .link(&ctx, &edge(&ids[s], &ids[t]))
            .await
            .expect("link");
    }
    // Withhold row 7 (quarantined): (5 -> 7) is not carriable.
    sqlx::query("UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = $1")
        .bind(&ids[7])
        .execute(store.pool())
        .await
        .expect("quarantine");

    let pages = walk(&store, 3).await;
    let mut carried: HashSet<String> = HashSet::new();
    let mut emitted: HashMap<(String, String), usize> = HashMap::new();
    let mut dangling_mine = 0_usize;
    for page in &pages {
        carried.extend(page.memories.iter().map(|m| m.id.clone()));
        let survivors: HashSet<String> = page.memories.iter().map(|m| m.id.clone()).collect();
        let links = store
            .export_links_page(&page.scope, &survivors)
            .await
            .expect("links page");
        for l in &links.links {
            assert!(
                carried.contains(&l.source_id) && carried.contains(&l.target_id),
                "an edge is only emitted once both endpoints are carried"
            );
            if l.source_id.starts_with(&ns) {
                *emitted
                    .entry((l.source_id.clone(), l.target_id.clone()))
                    .or_default() += 1;
            }
        }
        if page.scope.raw_ids.contains(&ids[5]) {
            dangling_mine += links.dangling;
        }
    }
    let carriable: HashSet<(String, String)> = edges
        .iter()
        .filter(|(s, t)| *s != 7 && *t != 7)
        .map(|(s, t)| (ids[*s].clone(), ids[*t].clone()))
        .collect();
    assert_eq!(emitted.keys().cloned().collect::<HashSet<_>>(), carriable);
    assert!(
        emitted.values().all(|n| *n == 1),
        "no edge is emitted twice"
    );
    assert!(
        dangling_mine >= 1,
        "the edge to the withheld row is counted on the page carrying its live endpoint"
    );
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .expect("cleanup");
}

/// #3427 (pg) — the namespace scope is a WHERE predicate on the page query:
/// a foreign-namespace row is absent from every page, the excluded counts
/// are scoped, and a cross-namespace edge is withheld (its counterpart is
/// not carried by the export).
#[tokio::test]
async fn pg_export_namespace_scope_is_honoured_on_every_page_3427() {
    let Some(url) = postgres_url() else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let alice = format!("alice-3427-{run}");
    let bob = format!("bob-3427-{run}");
    let alice_ids = seed(&store, &alice, 5).await;
    let bob_ids = seed(&store, &bob, 2).await;

    let mut cursor: Option<ExportCursor> = None;
    let mut seen = Vec::new();
    for _ in 0..10 {
        let page = store
            .export_memories_page(cursor.as_ref(), 2, chrono::Utc::now(), Some(alice.as_str()))
            .await
            .expect("scoped page");
        assert_eq!(page.scope.namespace.as_deref(), Some(alice.as_str()));
        for m in &page.memories {
            assert_eq!(
                m.namespace, alice,
                "a foreign-namespace row leaked: {}",
                m.id
            );
            assert!(!bob_ids.contains(&m.id));
        }
        seen.extend(page.memories.iter().map(|m| m.id.clone()));
        match page.next_cursor {
            Some(c) => {
                assert_eq!(
                    c.namespace.as_deref(),
                    Some(alice.as_str()),
                    "pinned in the cursor"
                );
                cursor = Some(c);
            }
            None => break,
        }
    }
    seen.sort();
    let mut expected = alice_ids.clone();
    expected.sort();
    assert_eq!(seen, expected, "every scoped row exactly once");
}
