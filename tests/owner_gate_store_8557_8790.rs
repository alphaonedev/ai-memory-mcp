// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8557 / #8790 — the store-layer owner gate on `entity_register` (alias
//! merge into an existing entity) and `action_add_edge` (a DAG edge between
//! two actions), on BOTH backends through the `MemoryStore` trait.
//!
//! Invariant: a mutation of an existing object succeeds only when the
//! resolved caller is its recorded owner (or holds the governance bypass);
//! otherwise the store returns ONE refusal,
//! `PermissionDenied { action: OWNER_GATE_ACTION, reason:
//! CALLER_DOES_NOT_OWN_OBJECT }`, and the owner's rows are unchanged. The
//! sqlite and postgres transcripts must be equal, and the HTTP mapping of
//! that refusal is the shared `403 NOT_OWNER` body.
//!
//! The sqlite cells run on every `--features sal` build; the postgres cell
//! is `sal-postgres` and skips without `AI_MEMORY_TEST_POSTGRES_URL`.
#![cfg(feature = "sal")]

use ai_memory::errors::error_codes::NOT_OWNER;
use ai_memory::errors::msg::CALLER_DOES_NOT_OWN_OBJECT;
use ai_memory::identity::object_owner::OWNER_GATE_ACTION;
use ai_memory::models::{Action, ActionState, EdgeType};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::json;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// The recorded owner of every probe object.
const OWNER: &str = "ai:owner-8557";
/// A second, authenticated agent that owns none of them.
const INTRUDER: &str = "ai:intruder-8557";
/// Canonical name of the probe entity.
const ENTITY_NAME: &str = "Entity 8557";
/// The alias the owner registers first.
const OWNER_ALIAS: &str = "owner-alias-8557";
/// The alias the intruder tries to merge in.
const INTRUDER_ALIAS: &str = "intruder-alias-8557";
/// The alias the owner adds later (the owner path still succeeds).
const OWNER_SECOND_ALIAS: &str = "owner-alias-2-8557";
/// Action kind of every probe action.
const ACTION_KIND: &str = "work";
/// Fixed timestamp for edges and actions, so transcripts are stable.
const PROBE_NOW: i64 = 1_700_000_000;
/// Scratch database prefix for the postgres cell.
#[cfg(feature = "sal-postgres")]
const SCRATCH_PREFIX: &str = "ai_memory_8557";

fn unique(tag: &str) -> String {
    format!("{tag}-{}", uuid::Uuid::new_v4().simple())
}

fn action(id: &str, ns: &str, owner: &str) -> Action {
    Action {
        id: id.to_string(),
        namespace: ns.to_string(),
        kind: ACTION_KIND.to_string(),
        state: ActionState::Pending,
        title: id.to_string(),
        payload: json!({}),
        priority: 5,
        agent_id: Some(owner.to_string()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: PROBE_NOW,
        updated_at: PROBE_NOW,
    }
}

/// Render a store result as a backend-neutral line. A refusal is only
/// `refused` when it is EXACTLY the owner-gate refusal on `target`.
fn describe<T>(label: &str, r: &Result<T, StoreError>, target: &str) -> String {
    match r {
        Ok(_) => format!("{label}: ok"),
        Err(StoreError::PermissionDenied {
            action,
            target: t,
            reason,
        }) if action == OWNER_GATE_ACTION
            && t == target
            && reason == CALLER_DOES_NOT_OWN_OBJECT =>
        {
            format!("{label}: refused")
        }
        Err(other) => format!("{label}: unexpected {other:?}"),
    }
}

/// Number of edges touching `id`, or `None` when the read fails.
async fn edge_count(store: &dyn MemoryStore, ctx: &CallerContext, id: &str) -> Option<usize> {
    store.action_edges_for(ctx, id).await.ok().map(|e| e.len())
}

/// Drive the #8557 and #8790 cells against `store`.
async fn transcript(store: &dyn MemoryStore) -> Vec<String> {
    let owner = CallerContext::for_agent(OWNER);
    let intruder = CallerContext::for_agent(INTRUDER);
    let ns = unique("ns-8557");
    let mut out = Vec::new();

    // ---- #8557: alias merge into another agent's entity ----
    let created = store
        .entity_register(
            &owner,
            ENTITY_NAME,
            &ns,
            &[OWNER_ALIAS.into()],
            &json!({}),
            Some(OWNER),
        )
        .await
        .expect("owner registers the entity");
    out.push(format!("entity created: {}", created.created));
    let before = store
        .get(&owner, &created.entity_id)
        .await
        .expect("owner reads entity");
    let merge = store
        .entity_register(
            &intruder,
            ENTITY_NAME,
            &ns,
            &[INTRUDER_ALIAS.into()],
            &json!({}),
            Some(INTRUDER),
        )
        .await;
    out.push(describe("intruder alias merge", &merge, &ns));
    let after = store
        .get(&owner, &created.entity_id)
        .await
        .expect("owner rereads entity");
    out.push(format!(
        "entity row unchanged: {}",
        serde_json::to_string(&before).ok() == serde_json::to_string(&after).ok()
    ));
    let leaked = store
        .entity_get_by_alias(INTRUDER_ALIAS, Some(&ns))
        .await
        .expect("alias lookup");
    out.push(format!("intruder alias resolves: {}", leaked.is_some()));
    let again = store
        .entity_register(
            &owner,
            ENTITY_NAME,
            &ns,
            &[OWNER_SECOND_ALIAS.into()],
            &json!({}),
            Some(OWNER),
        )
        .await;
    out.push(describe("owner alias merge", &again, &ns));

    // ---- #8790: a DAG edge between another agent's actions ----
    let (a, b, own) = (unique("act-a"), unique("act-b"), unique("act-own"));
    for (id, who, ctx) in [
        (&a, OWNER, &owner),
        (&b, OWNER, &owner),
        (&own, INTRUDER, &intruder),
    ] {
        store
            .action_create(ctx, &action(id, &ns, who))
            .await
            .expect("action_create");
    }
    let a_before = store.action_get(&owner, &a).await.expect("action_get");
    let foreign = store
        .action_add_edge(&intruder, &a, &b, EdgeType::Requires, PROBE_NOW)
        .await;
    out.push(describe(
        "intruder edge between owner actions",
        &foreign,
        &a,
    ));
    let into_owner = store
        .action_add_edge(&intruder, &own, &a, EdgeType::Requires, PROBE_NOW)
        .await;
    out.push(describe(
        "intruder edge into owner action",
        &into_owner,
        &own,
    ));
    let a_after = store.action_get(&owner, &a).await.expect("action_get");
    out.push(format!(
        "action row unchanged: {}",
        serde_json::to_string(&a_before).ok() == serde_json::to_string(&a_after).ok()
    ));
    out.push(format!(
        "edges on a after refusal: {:?}",
        edge_count(store, &owner, &a).await
    ));
    out.push(format!(
        "edges on own after refusal: {:?}",
        edge_count(store, &owner, &own).await
    ));
    let by_owner = store
        .action_add_edge(&owner, &a, &b, EdgeType::Requires, PROBE_NOW)
        .await;
    out.push(describe("owner edge", &by_owner, &a));
    out.push(format!(
        "edges on a after owner edge: {:?}",
        edge_count(store, &owner, &a).await
    ));
    out
}

fn expected() -> Vec<String> {
    [
        "entity created: true",
        "intruder alias merge: refused",
        "entity row unchanged: true",
        "intruder alias resolves: false",
        "owner alias merge: ok",
        "intruder edge between owner actions: refused",
        "intruder edge into owner action: refused",
        "action row unchanged: true",
        "edges on a after refusal: Some(0)",
        "edges on own after refusal: Some(0)",
        "owner edge: ok",
        "edges on a after owner edge: Some(1)",
    ]
    .map(str::to_string)
    .to_vec()
}

#[tokio::test]
async fn sqlite_store_refuses_non_owner_alias_merge_and_edge_8557_8790() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let store = ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open");
    assert_eq!(transcript(&store).await, expected());
}

/// The HTTP rendering of the store refusal (the PostgreSQL route path) is the
/// shared `403 NOT_OWNER` body with the exact message.
#[tokio::test]
async fn store_owner_refusal_renders_as_403_not_owner_8557() {
    let ns = unique("ns-8557-http");
    let resp =
        ai_memory::handlers::postgres_gate::store_err_to_response(StoreError::PermissionDenied {
            action: OWNER_GATE_ACTION.to_string(),
            target: ns.clone(),
            reason: CALLER_DOES_NOT_OWN_OBJECT.to_string(),
        });
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    assert_eq!(body["code"], NOT_OWNER, "body={body}");
    assert_eq!(body["error"], CALLER_DOES_NOT_OWN_OBJECT, "body={body}");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_store_refuses_non_owner_alias_merge_and_edge_8557_8790() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip pg_store_refuses_non_owner_alias_merge_and_edge_8557_8790: URL unset");
        return;
    };
    let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let pg = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    let pg_transcript = transcript(&pg).await;
    assert_eq!(pg_transcript, expected(), "postgres cells");

    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let sqlite = ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open");
    assert_eq!(
        transcript(&sqlite).await,
        pg_transcript,
        "sqlite and postgres must agree"
    );
}
