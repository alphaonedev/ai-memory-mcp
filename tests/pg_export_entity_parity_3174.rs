// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #1986: crate-level `//!` docs are still linted when `#![cfg(feature =
// "sal-postgres")]` is false (the allow below that cfg is configured out).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3174 — postgres admin-export + `entity_register` parity.
//!
//! Three proofs, all against a corpus deliberately LARGER than
//! `crate::storage::LIST_MAX_LIMIT` (1000), which is exactly the size at which
//! the pre-fix code started losing data silently:
//!
//! 1. `export_memories()` returns EVERY seeded row. Pre-#3174 the pg export
//!    built `Filter { limit: 100_000 }` and delegated to `list`, whose first
//!    statement clamps to `LIST_MAX_LIMIT` — so the "complete" backup bundle
//!    carried at most 1000 rows with no error and no truncation flag.
//! 2. Re-registering an entity whose row sits beyond that window returns
//!    `created == false`. Pre-fix the prior-entity lookup was a clamped `list`
//!    scan, so the prior row fell outside the window and a DUPLICATE entity
//!    landed.
//! 3. `entity_get_by_alias(canonical_name)` resolves. Pre-fix the pg twin
//!    built its `entity_aliases` rows from `prior_aliases + aliases` only, so
//!    the canonical name was never an alias row — `Some` on sqlite, `None` on
//!    postgres for the identical registration.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

/// Rows seeded into the probe namespace: comfortably past `LIST_MAX_LIMIT`.
const SEEDED: i64 = 1_500;

#[tokio::test]
async fn pg_export_and_entity_register_survive_past_list_max_limit_3174() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ns = format!("export-3174-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent("ai:3174");

    // Seed 1500 rows in ONE statement (generate_series) — the SAL write funnel
    // is not under test here, the read cap is.
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, metadata) \
         SELECT $1 || '-' || lpad(i::text, 5, '0'), 'long', $2, \
                'export probe ' || i, 'body ' || i, 'test', \
                jsonb_build_object('agent_id', 'ai:3174') \
         FROM generate_series(1, $3) AS g(i)",
    )
    .bind(&ns)
    .bind(&ns)
    .bind(SEEDED)
    .execute(store.pool())
    .await
    .expect("seed 1500 rows");

    // ---- (1) export_memories returns ALL of them, not the first 1000. ----
    let exported = store.export_memories().await.expect("export_memories");
    let mine = exported.iter().filter(|m| m.namespace == ns).count();
    assert_eq!(
        i64::try_from(mine).unwrap_or(-1),
        SEEDED,
        "#3174: the admin export must carry the FULL corpus — got {mine} of \
         {SEEDED} rows from the probe namespace (a LIST_MAX_LIMIT clamp would \
         cap this at 1000)"
    );
    // Distinct ids: a paging bug that re-reads a page would inflate the count.
    let distinct: std::collections::BTreeSet<&str> = exported
        .iter()
        .filter(|m| m.namespace == ns)
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(
        i64::try_from(distinct.len()).unwrap_or(-1),
        SEEDED,
        "#3174: the keyset walk must not duplicate rows across pages"
    );

    // ---- (2) entity_register dedupes over a >1000-row namespace. ----
    let canonical = format!("Acme-3174-{}", uuid::Uuid::new_v4());
    let extra = serde_json::json!({});
    let first = store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            &["acme-3174".to_string()],
            &extra,
            Some("ai:3174"),
        )
        .await
        .expect("entity_register first");
    assert!(first.created, "first registration creates the entity");

    let second = store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            &["acme-inc-3174".to_string()],
            &extra,
            Some("ai:3174"),
        )
        .await
        .expect("entity_register re-register");
    assert!(
        !second.created,
        "#3174: re-registering an entity in a namespace with more than \
         LIST_MAX_LIMIT rows must find the prior row (created=false), not mint \
         a duplicate"
    );
    assert_eq!(
        second.entity_id, first.entity_id,
        "#3174: the re-register must resolve to the SAME entity id"
    );

    // ---- (3) the canonical name is alias-resolvable (sqlite parity). ----
    let by_canonical = store
        .entity_get_by_alias(&canonical, Some(&ns))
        .await
        .expect("entity_get_by_alias canonical")
        .expect(
            "#3174: entity_get_by_alias(canonical_name) must resolve on \
             postgres as it does on sqlite — without the canonical alias row \
             an entity registered with no aliases is unreachable by name",
        );
    assert_eq!(by_canonical.entity_id, first.entity_id);
    assert!(
        second.aliases.iter().any(|a| a == &canonical),
        "#3174: the returned alias set is the entity_aliases table read (the \
         sqlite `list_entity_aliases` shape), so it includes the canonical \
         name: {:?}",
        second.aliases
    );

    // Cleanup — test-scoped rows only.
    sqlx::query("DELETE FROM entity_aliases WHERE entity_id = $1")
        .bind(&first.entity_id)
        .execute(store.pool())
        .await
        .ok();
    sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(store.pool())
        .await
        .ok();
}
