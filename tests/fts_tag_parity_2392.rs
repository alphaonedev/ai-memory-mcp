// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2392 — cross-backend FTS parity: a tag-only-hit `search` query returns
//! the row on BOTH `SQLite` and Postgres.
//!
//! ## The defect this pins
//!
//! `SQLite`'s `memories_fts` FTS5 virtual table has always indexed
//! `(title, content, tags)`, but the Postgres stored generated `tsv`
//! tsvector (schema v57, #1579 B2) folded ONLY `title + content` — it
//! omitted `tags`. So the SAME wire query — an FTS `search` (and, by the
//! same `tsv` column, recall / contradiction / list) whose ONLY matching
//! token is a TAG word — returned the row on `SQLite` but ZERO rows on the
//! enterprise (Postgres) tier. Schema v89 (#2392,
//! `PostgresStore::migrate_v89` + `migrations/postgres/0046_v89_tsv_include_tags.sql`)
//! redefines the generated column to fold `coalesce(tags::text, '')`, so
//! both backends now agree.
//!
//! ## Tag-token choice
//!
//! The probe tag `zparitytagfts2392` is a coined, lowercase-ASCII,
//! non-stopword, stem-invariant nonce that appears NOWHERE in the title or
//! content — so a hit can ONLY come from the tags fold. Being stem-invariant
//! (no english-snowball suffix) it tokenizes to the identical lexeme on both
//! backends (Postgres `to_tsvector`/`plainto_tsquery('english', …)` and
//! `SQLite` FTS5 `unicode61`), so the parity assertion compares like with like
//! and is immune to the (pre-existing, cross-backend) stemming/stopword
//! asymmetry that the `'english'` config applies to title + content.
//!
//! ## How to run (Postgres leg)
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test \
//!   cargo test --features sal,sal-postgres --test fts_tag_parity_2392
//! ```
//!
//! The Postgres leg self-skips (eprintln) when the URL is unset so a plain
//! `cargo test` stays green on nodes without postgres routing — the
//! skip-if-url convention of the shipped `pg_*` suite
//! (`tests/embedding_space_provenance_2167_pg.rs`).

#![cfg(feature = "sal")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::{CallerContext, Filter, MemoryStore};

/// The tag-only probe token — present ONLY in `tags`, never in title/content.
const PROBE_TAG: &str = "zparitytagfts2392";

/// Build a memory whose ONLY occurrence of [`PROBE_TAG`] is in `tags`.
fn tagged_memory(id: &str, namespace: &str, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: "quarterly planning notes".to_string(),
        content: "the finance review body has no probe token in it".to_string(),
        tags: vec![PROBE_TAG.to_string(), "unrelated".to_string()],
        priority: 5,
        confidence: 0.9,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

/// Store the probe row, then run a `search` whose query is EXACTLY the tag
/// token, and return the matching ids. The tag word is absent from title +
/// content, so a hit proves the FTS index folds `tags`.
async fn tag_only_hit_ids(store: &dyn MemoryStore, namespace: &str, owner: &str) -> Vec<String> {
    let ctx = CallerContext::for_agent(owner);
    let id = uuid::Uuid::new_v4().to_string();
    store
        .store(&ctx, &tagged_memory(&id, namespace, owner))
        .await
        .expect("store probe row");

    let filter = Filter {
        namespace: Some(namespace.to_string()),
        limit: 50,
        ..Filter::default()
    };
    let hits = store
        .search(&ctx, PROBE_TAG, &filter)
        .await
        .expect("search tag token");
    hits.into_iter().map(|m| m.id).collect()
}

#[tokio::test]
async fn sqlite_tag_only_hit_returns_row_2392() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("fts-tag-parity.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore");

    let owner = "ai:2392-sqlite";
    let ns = format!("fts2392-{}", uuid::Uuid::new_v4());
    let ids = tag_only_hit_ids(&store, &ns, owner).await;

    assert_eq!(
        ids.len(),
        1,
        "#2392 SQLite: a tag-only-hit FTS search must return the row (FTS5 indexes \
         (title, content, tags)); got ids={ids:?}",
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_tag_only_hit_returns_row_2392() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return;
        }
    };

    let owner = "ai:2392-postgres";
    let ns = format!("fts2392-{}", uuid::Uuid::new_v4());
    let ids = tag_only_hit_ids(&store, &ns, owner).await;

    assert_eq!(
        ids.len(),
        1,
        "#2392 Postgres: a tag-only-hit FTS search must return the row — schema v89 \
         folds `tags` into the stored generated `tsv` tsvector, matching the SQLite \
         `memories_fts(title, content, tags)` scope. A ZERO result here is the \
         pre-v89 cross-backend divergence (the enterprise tier under-returning tag \
         matches); got ids={ids:?}",
    );
}
