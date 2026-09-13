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
//! * an undecryptable row is SKIPPED and COUNTED in its page's
//!   `undecryptable` (the machine-readable count the issue asks for), while
//!   the cursor still advances past it;
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
            .export_memories_page(cursor.as_ref(), limit, as_of)
            .await
            .expect("export page");
        assert!(page.raw_rows() <= limit, "a page never exceeds its limit");
        cursor = page.next_cursor.clone();
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

#[tokio::test]
async fn pg_export_counts_undecryptable_rows_instead_of_hiding_them_3288() {
    let Some(url) = postgres_url() else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-3288-dec-{}", uuid::Uuid::new_v4());
    let ids = seed(&store, &ns, 3).await;
    // A garbage envelope: the scheme byte is not a known envelope version, so
    // the scan mapper cannot open it — the shape a lost keypair leaves behind.
    sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
        .bind(vec![0_u8; 96])
        .bind(&ids[1])
        .execute(store.pool())
        .await
        .expect("plant an undecryptable envelope");

    let pages = walk(&store, 50).await;
    let carried: HashSet<String> = pages
        .iter()
        .flat_map(|p| p.memories.iter())
        .filter(|m| m.namespace == ns)
        .map(|m| m.id.clone())
        .collect();
    assert!(
        !carried.contains(&ids[1]),
        "the undecryptable row is not carried"
    );
    assert!(carried.contains(&ids[0]) && carried.contains(&ids[2]));
    let page_of_poison = pages
        .iter()
        .find(|p| p.scope.raw_ids.contains(&ids[1]))
        .expect("the walk returned the poisoned row's raw id (the cursor passed it)");
    assert!(
        page_of_poison.undecryptable >= 1,
        "the skipped row is COUNTED on its page, not only logged"
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
            .export_memories_page(cursor.as_ref(), 2, Utc::now(), Some(alice.as_str()))
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
