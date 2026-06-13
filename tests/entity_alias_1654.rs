// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1654 regression — `PostgresStore::entity_register` must populate the
//! `entity_aliases` join table so `entity_get_by_alias` (which resolves
//! via that table, NOT `metadata.aliases`) can find a SAL-trait-registered
//! entity. Pre-fix: register-then-get-by-alias returned `None`.
//!
//! Live-postgres gated (skip-if-`AI_MEMORY_TEST_POSTGRES_URL`-unset), the
//! same pattern as `tests/cov_postgres_kg.rs`. uuid-randomized namespace
//! so it never collides with co-resident suites on the shared CI DB.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

#[tokio::test]
async fn entity_register_then_get_by_alias_resolves_1654() {
    let Some(url) = pg_url() else {
        eprintln!(
            "skip entity_register_then_get_by_alias_resolves_1654: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_agent("entity-1654-owner");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("ent-1654-{run}");
    let canonical = format!("Canonical Entity {run}");
    let alias_a = format!("alias-a-{run}");
    let alias_b = format!("alias-b-{run}");

    // Register via the SAL trait with two aliases.
    let reg = store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            &[alias_a.clone(), alias_b.clone()],
            &serde_json::json!({}),
            Some("entity-1654-owner"),
        )
        .await
        .expect("entity_register");
    assert!(!reg.entity_id.is_empty(), "registration returns an id");

    // #1654: each alias must resolve back to the same entity via
    // entity_get_by_alias (which reads the entity_aliases join table).
    for alias in [&alias_a, &alias_b] {
        let got = store
            .entity_get_by_alias(alias, Some(&ns))
            .await
            .expect("entity_get_by_alias ok")
            .unwrap_or_else(|| panic!("alias '{alias}' must resolve (pre-#1654 returned None)"));
        assert_eq!(
            got.entity_id, reg.entity_id,
            "alias '{alias}' resolves to the registered entity id"
        );
    }

    // Re-register unioning a third alias is idempotent (ON CONFLICT) and
    // the new alias also resolves.
    let alias_c = format!("alias-c-{run}");
    store
        .entity_register(
            &ctx,
            &canonical,
            &ns,
            std::slice::from_ref(&alias_c),
            &serde_json::json!({}),
            Some("entity-1654-owner"),
        )
        .await
        .expect("entity_register re-register");
    let got_c = store
        .entity_get_by_alias(&alias_c, Some(&ns))
        .await
        .expect("get_by_alias c ok")
        .expect("third alias resolves after union re-register");
    assert_eq!(
        got_c.entity_id, reg.entity_id,
        "re-register keeps the same entity id"
    );
}
