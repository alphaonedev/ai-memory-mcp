// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3282 — MCP `handle_reflect` must scope its SOURCE READ by the
//! read-visibility caller (`resolve_read_visibility_caller`), NOT the
//! write-ladder governance subject (`resolve_governance_subject` /
//! `input.agent_id`).
//!
//! ## The regression (#3237 M3, item 4)
//!
//! #3176 / #3237-item-4 threaded the caller principal into the reflect
//! source read so a tenant could not pull another agent's `scope=private`
//! source into a reflection. But it bound that READ to the WRITE subject
//! `input.agent_id`. In the DEFAULT single-operator config
//! (`AI_MEMORY_AGENT_ID` unset), the write subject resolves to a
//! synthesized `host:<hostname>` / `ai:<client>@<host>` principal, so
//! `handle_reflect` began folding any source WRITTEN BY A DIFFERENT
//! principal (CLI, HTTP, curator, federation, a second MCP client) to
//! `source memory not found` — even though recall / list / search / get on
//! the same session apply NO filter and still show the row. A read was
//! being gated as if it were a write. Severity MEDIUM (default-config
//! functional regression), v1.0.0 GA blocker.
//!
//! ## The fix
//!
//! The source read now resolves `resolve_read_visibility_caller()` — the
//! same resolver recall/list/search/get and the #2988 recall ledger use.
//! It is `None` when `AI_MEMORY_AGENT_ID` is unset (trust-all read, matching
//! every other read surface) and `Some(enforced)` under the multi-tenant
//! opt-in, where it gates each source exactly like the recall path. The
//! WRITE owner stays `input.agent_id` — writes remain on the write ladder.
//!
//! ## What this pins (all against MCP `handle_reflect`, sqlite)
//!
//! 1. `default_config_reflect_over_cross_principal_source_succeeds` — the
//!    regression proof. `AI_MEMORY_AGENT_ID` unset, source owned by another
//!    principal with default (private) scope: reflect SUCCEEDS. FAILS at the
//!    parent commit with `source memory not found` (read gated to the
//!    synthesized self, which is not the owner).
//! 2. `enforced_non_owner_tenant_still_refused` — the CONTROL proving the
//!    fix did not just disable the gate. `AI_MEMORY_AGENT_ID` set to a
//!    non-owner tenant: reflect still fail-closes with `source memory not
//!    found` (the multi-tenant read gate fires, byte-identical to a missing
//!    id — no existence leak).
//! 3. `enforced_owner_tenant_can_reflect` — the CONTROL proving the enforced
//!    gate lets the OWNER through. `AI_MEMORY_AGENT_ID` set to the owner:
//!    reflect SUCCEEDS.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::mcp::handle_reflect;
use ai_memory::models::{Memory, MemoryKind, Tier};
use rusqlite::Connection;
use serde_json::json;

mod common;

/// Serialises the three tests in this binary that read / mutate the
/// process-global `AI_MEMORY_AGENT_ID`, mirroring the crate-wide
/// `identity::env_var_lock` discipline (#1772) for the integration-test
/// surface (which cannot reach that `pub(crate)` guard).
static ENV_GUARD: Mutex<()> = Mutex::new(());

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

/// Hermetic file-backed DB under `.local-runs/` (never `/tmp`, per project
/// rule; a real path so `handle_reflect`'s post-write dispatch has a db to
/// open). Returns the `TempDir` guard (kept alive by the caller) + path.
fn fresh_db() -> (tempfile::TempDir, PathBuf, Connection) {
    common::permissive_attestation_for_tests();
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("reflect-read-visibility-3282");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    let conn = db::open(&path).expect("db::open");
    (dir, path, conn)
}

/// Seed a `scope=private` observation OWNED BY `owner`. With the default
/// (owner-keyed) private scope, this row is visible to a `None` caller
/// (trust-all) and to `owner`, but invisible to any other enforced caller.
fn seed_private_source(conn: &Connection, namespace: &str, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: "cross-principal source".to_string(),
        content: "source body owned by another principal".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test-3282".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner, "scope": "private" }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert private source")
}

/// SAFETY helper: set `AI_MEMORY_AGENT_ID` (env mutation serialised by the
/// caller holding `ENV_GUARD`).
fn set_agent_id(value: &str) {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::set_var(ENV_AGENT_ID, value) };
}

/// SAFETY helper: clear `AI_MEMORY_AGENT_ID` (env mutation serialised by the
/// caller holding `ENV_GUARD`).
fn clear_agent_id() {
    // SAFETY: env mutation is serialised by `ENV_GUARD`, held by the caller.
    unsafe { std::env::remove_var(ENV_AGENT_ID) };
}

fn reflect_params(source_id: &str, namespace: &str) -> serde_json::Value {
    json!({
        "source_ids": [source_id],
        "title": "reflection over a cross-principal source",
        "content": "a synthesised insight drawn from another principal's memory",
        "namespace": namespace,
    })
}

fn call_reflect(
    conn: &Connection,
    db_path: &Path,
    source_id: &str,
    namespace: &str,
) -> Result<serde_json::Value, String> {
    handle_reflect(
        conn,
        db_path,
        &reflect_params(source_id, namespace),
        None, // embedder
        None, // vector_index
        None, // mcp_client
        None, // active_keypair
    )
}

/// #3282 regression proof — default config, cross-principal private source,
/// reflect SUCCEEDS. Fails at the parent commit with `source memory not
/// found` because the read was scoped to the synthesized write subject.
#[test]
fn default_config_reflect_over_cross_principal_source_succeeds() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_agent_id(); // default single-operator config: no enforced caller.

    let (_dir, path, conn) = fresh_db();
    let ns = "team/3282-default";
    let src = seed_private_source(&conn, ns, "ai:some-other-principal");

    let out = call_reflect(&conn, &path, &src, ns);

    clear_agent_id();
    let out = out.expect(
        "default-config reflect over a cross-principal source must succeed \
         (read gated by resolve_read_visibility_caller = None => trust-all)",
    );
    assert!(
        out.get("id").and_then(serde_json::Value::as_str).is_some(),
        "successful reflect must return the new reflection id, got {out}"
    );
    // Wire key is the stable MCP `memory_reflect` response field (the const
    // itself is `pub(crate)`; the wire string is the public contract).
    let reflects_on = out
        .get("reflects_on")
        .and_then(serde_json::Value::as_array)
        .expect("reflects_on array");
    assert!(
        reflects_on.iter().any(|v| v.as_str() == Some(src.as_str())),
        "the reflection must link back to the seeded source {src}, got {out}"
    );
}

/// CONTROL — enforced multi-tenant caller that does NOT own the source is
/// still refused (the read gate fires; no existence leak). Proves the fix
/// did not simply disable source-read visibility.
#[test]
fn enforced_non_owner_tenant_still_refused() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let (_dir, path, conn) = fresh_db();
    let ns = "team/3282-tenant";
    let src = seed_private_source(&conn, ns, "ai:owner-alpha");

    set_agent_id("ai:tenant-beta"); // enforced caller, NOT the owner.
    let out = call_reflect(&conn, &path, &src, ns);
    clear_agent_id();

    let err = out.expect_err("a non-owner enforced tenant must NOT reflect on a private source");
    assert!(
        err.contains("source memory not found"),
        "refusal must fold to the honest missing-source string (no existence \
         leak), got: {err}"
    );
}

/// CONTROL — enforced caller that OWNS the source can reflect. Proves the
/// enforced gate lets the legitimate owner through (it is not a blanket
/// refuse-when-set).
#[test]
fn enforced_owner_tenant_can_reflect() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let (_dir, path, conn) = fresh_db();
    let ns = "team/3282-owner";
    let owner = "ai:owner-gamma";
    let src = seed_private_source(&conn, ns, owner);

    set_agent_id(owner); // enforced caller IS the owner.
    let out = call_reflect(&conn, &path, &src, ns);
    clear_agent_id();

    let out = out.expect("the source owner must be able to reflect on its own private source");
    assert!(
        out.get("id").and_then(serde_json::Value::as_str).is_some(),
        "owner reflect must return the new reflection id, got {out}"
    );
}
