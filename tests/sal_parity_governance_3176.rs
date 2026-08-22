// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Test scaffolding: pedantic lints on the narrative header / fixtures have no
// behavioural impact (mirrors `tests/parity_write_funnels.rs`).
#![allow(clippy::doc_markdown, clippy::missing_panics_doc, clippy::too_many_lines)]
// The whole harness threads the SAL `MemoryStore` trait, which only exists
// under `sal`.
#![cfg(feature = "sal")]

//! #3176 — the sqlite SAL adapter must enforce the SAME authorization the
//! postgres adapter enforces.
//!
//! Four result-changing divergences, all in the direction "sqlite permits what
//! postgres refuses":
//!
//! 1. **`clear_namespace_standard` had NO owner gate and no #2545
//!    severed-standard refusal.** The sqlite adapter discarded `ctx` and went
//!    straight to `DELETE FROM namespace_meta`, so a trait-routed tenant could
//!    DISARM the governance standard protecting every memory in another
//!    tenant's namespace — an un-bind primitive. postgres enforced both arms.
//! 2. **`verify` discarded `ctx`** and read through the raw `db::get`, so a
//!    caller could confirm the EXISTENCE of another agent's `scope=private`
//!    memory and read its integrity/CID findings. postgres routes through the
//!    #910-gated `self.get(ctx, id)`.
//! 3. **`enforce_governance` owner selection.** sqlite used
//!    `memory_owner.or(namespace_owner)` for EVERY action; postgres uses
//!    `Store => ns_owner`. A `Store` with `memory_owner == agent != ns_owner`
//!    was ALLOW on sqlite, DENY on postgres.
//! 4. **`reflect` read its sources unscoped**, so a tenant could pull another
//!    agent's `scope=private` content into its own reflection. postgres loads
//!    each source through the gated `MemoryStore::get(ctx, id)`.
//!
//! **R-203.** Every cell below fails at the parent commit, for the right
//! reason:
//!
//! | cell | parent behaviour |
//! |---|---|
//! | `sqlite_non_owner_cannot_clear_namespace_standard_3176` | `Ok(true)` — the standard is DELETED |
//! | `sqlite_severed_standard_clear_is_refused_3176` | `Ok(true)` — governance disarmed |
//! | `sqlite_verify_folds_foreign_private_row_to_not_found_3176` | `Ok(VerifyReport{..})` for bob |
//! | `sqlite_reflect_cannot_read_foreign_private_source_3176` | reflection CREATED over alice's private row |
//! | `governance_store_owner_is_namespace_owner_not_caller_claim_3176` | `Allow` |
//!
//! CONTROL cells pin that the new refusals are not passing for a trivial
//! reason: the OWNER and the admin/bypass context still succeed on every path.
//!
//! The postgres twins soft-skip without `AI_MEMORY_TEST_POSTGRES_URL`
//! (deliberately NOT `#[ignore]`, so the PR-gating `postgres-feature` job —
//! which runs without `--include-ignored` — can see them).

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::json;

/// The two wire-pinned refusal strings, spelled out HERE so the test is an
/// independent pin on the bytes both adapters must emit (the consts
/// themselves are `pub(crate)`).
const REASON_UNRESOLVABLE: &str =
    "cannot clear namespace standard: the bound standard memory is unresolvable \
     (severed or dangling). Re-point the standard first, then clear — or use an \
     admin/bypass surface.";

fn reason_not_owner(owner: &str) -> String {
    format!("caller does not own this namespace standard (owner: {owner})")
}

/// #1751 — pin this binary to the permissive agent-attestation opt-out; the
/// v0.9 default is REQUIRED and would reject the unsigned fixtures before any
/// of the authorization under test runs.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

/// Hermetic DB path under `.local-runs/` (never `/tmp`, per project rule).
fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sal-parity-3176");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn fresh_store() -> (tempfile::TempDir, PathBuf, SqliteStore) {
    permissive_attestation_for_tests();
    let (dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    (dir, path, store)
}

fn memory(ns: &str, title: &str, owner: &str, private: bool) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut meta = json!({ "agent_id": owner });
    if private {
        meta["scope"] = json!("private");
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "parity-3176".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: meta,
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn permission_denied_reason(e: &StoreError) -> String {
    match e {
        StoreError::PermissionDenied { reason, .. } => reason.clone(),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// 1 — clear_namespace_standard owner gate (#1777) at the SAL layer.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_non_owner_cannot_clear_namespace_standard_3176() {
    let (_dir, _path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let bob = CallerContext::for_agent("bob");
    let ns = "tenant/alice/private-ns";

    let std_id = store
        .store(&alice, &memory(ns, "alice-standard", "alice", false))
        .await
        .expect("store standard");
    store
        .set_namespace_standard(&alice, ns, &std_id, None)
        .await
        .expect("set standard");

    // PRE-FIX: `Ok(true)` — bob deleted alice's namespace_meta row.
    let err = store
        .clear_namespace_standard(&bob, ns)
        .await
        .expect_err("bob must not clear alice's standard");
    assert_eq!(permission_denied_reason(&err), reason_not_owner("alice"));

    // The binding must still be there — a refused clear writes nothing.
    let still = store
        .get_namespace_standard(&bob, ns)
        .await
        .expect("get standard");
    assert_eq!(
        still.as_ref().map(|(s, _)| s.as_str()),
        Some(std_id.as_str()),
        "a refused clear must leave the governance binding intact"
    );

    // CONTROL — the OWNER can still clear (the gate is not a blanket refusal).
    assert!(
        store
            .clear_namespace_standard(&alice, ns)
            .await
            .expect("alice clears her own standard")
    );
}

#[tokio::test]
async fn sqlite_admin_bypass_can_clear_namespace_standard_3176() {
    let (_dir, _path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let admin = CallerContext::for_admin("ai:operator");
    let ns = "tenant/alice/admin-clearable";

    let std_id = store
        .store(&alice, &memory(ns, "alice-standard-2", "alice", false))
        .await
        .expect("store standard");
    store
        .set_namespace_standard(&alice, ns, &std_id, None)
        .await
        .expect("set standard");

    // CONTROL — `bypass_visibility` skips the gate, exactly as on postgres.
    assert!(
        store
            .clear_namespace_standard(&admin, ns)
            .await
            .expect("admin clears")
    );
}

#[tokio::test]
async fn sqlite_unowned_standard_stays_clearable_3176() {
    // #2704-F2 — an UNOWNED standard (no `metadata.agent_id`) must remain
    // clearable by a named caller; collapsing "unowned" into "unresolvable"
    // was the regression that fix closed on postgres, and the sqlite mirror
    // must not reintroduce it.
    let (_dir, _path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let bob = CallerContext::for_agent("bob");
    let ns = "legacy/unowned-standard";

    let mut mem = memory(ns, "legacy-standard", "", false);
    mem.metadata = json!({});
    let std_id = store.store(&alice, &mem).await.expect("store standard");
    store
        .set_namespace_standard(&alice, ns, &std_id, None)
        .await
        .expect("set standard");

    assert!(
        store
            .clear_namespace_standard(&bob, ns)
            .await
            .expect("an unowned standard is the documented unowned-PASS")
    );
}

// ─────────────────────────────────────────────────────────────────────
// 2 — #2545 severed/dangling standard is fail-closed refused.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_severed_standard_clear_is_refused_3176() {
    let (_dir, path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let admin = CallerContext::for_admin("ai:operator");
    let ns = "tenant/alice/severed";

    let std_id = store
        .store(&alice, &memory(ns, "to-be-severed", "alice", false))
        .await
        .expect("store standard");
    store
        .set_namespace_standard(&alice, ns, &std_id, None)
        .await
        .expect("set standard");

    // Deleting the standard memory SEVERS the binding (#2503): the
    // `namespace_meta` row survives with a NULL `standard_id`.
    {
        let conn = ai_memory::db::open(&path).expect("reopen for sever");
        ai_memory::db::delete(&conn, &std_id).expect("delete standard memory");
    }

    // PRE-FIX: `Ok(true)` — the last evidence of governance was deleted and
    // the namespace fell back to permissive allow-on-silence.
    let err = store
        .clear_namespace_standard(&alice, ns)
        .await
        .expect_err("a severed standard must not be clearable by a tenant");
    assert_eq!(permission_denied_reason(&err), REASON_UNRESOLVABLE);

    // CONTROL — the documented remedy: an admin/bypass surface can clear it.
    assert!(
        store
            .clear_namespace_standard(&admin, ns)
            .await
            .expect("admin clears a severed binding")
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3 — verify honours the #910 scope=private gate.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_verify_folds_foreign_private_row_to_not_found_3176() {
    let (_dir, _path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let bob = CallerContext::for_agent("bob");
    let admin = CallerContext::for_admin("ai:operator");

    let id = store
        .store(
            &alice,
            &memory("tenant/alice", "alice-secret", "alice", true),
        )
        .await
        .expect("store private memory");

    // PRE-FIX: `Ok(VerifyReport { .. })` — bob learned the row EXISTS and
    // read its integrity findings + CID verdict.
    match store.verify(&bob, &id).await {
        Err(StoreError::NotFound { id: got }) => assert_eq!(got, id),
        other => panic!("bob must get NotFound for alice's private row, got {other:?}"),
    }

    // CONTROL — the owner and an admin context still verify it.
    let owner_report = store.verify(&alice, &id).await.expect("alice verifies");
    assert_eq!(owner_report.memory_id, id);
    let admin_report = store.verify(&admin, &id).await.expect("admin verifies");
    assert_eq!(admin_report.memory_id, id);
}

// ─────────────────────────────────────────────────────────────────────
// 4 — reflect scopes its SOURCE read to the caller.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_reflect_cannot_read_foreign_private_source_3176() {
    use ai_memory::storage::{ReflectError, ReflectInput};

    let (_dir, _path, store) = fresh_store();
    let alice = CallerContext::for_agent("alice");
    let bob = CallerContext::for_agent("bob");

    let alice_id = store
        .store(
            &alice,
            &memory("tenant/alice", "alice-reflect-source", "alice", true),
        )
        .await
        .expect("store private source");

    let input = ReflectInput {
        source_ids: vec![alice_id.clone()],
        title: "bob's reflection".to_string(),
        content: "a synthesis over a source bob may not read".to_string(),
        namespace: Some("tenant/bob".to_string()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "parity-3176".to_string(),
        agent_id: "bob".to_string(),
        metadata: json!({}),
    };

    // PRE-FIX: the reflection was CREATED over alice's private row.
    match store.reflect(&bob, &input, None).await {
        Err(ReflectError::SourceNotFound(got)) => assert_eq!(got, alice_id),
        other => panic!("bob must not reflect on alice's private row, got {other:?}"),
    }

    // CONTROL — the OWNER can reflect on her own private row.
    let mut owner_input = input;
    owner_input.agent_id = "alice".to_string();
    owner_input.namespace = Some("tenant/alice".to_string());
    owner_input.title = "alice's reflection".to_string();
    store
        .reflect(&alice, &owner_input, None)
        .await
        .expect("alice reflects on her own source");
}

// ─────────────────────────────────────────────────────────────────────
// 5 — governance Owner-level Store resolves the NAMESPACE owner.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn governance_store_owner_is_namespace_owner_not_caller_claim_3176() {
    use ai_memory::models::GovernanceDecision;
    use ai_memory::models::GovernedAction;

    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let conn = ai_memory::db::open(&path).expect("db::open");

    let ns = "tenant/alice/owner-write";
    // A standard memory OWNED BY ALICE carrying `governance.write = owner`.
    let mut std_mem = memory(ns, "owner-policy-standard", "alice", false);
    std_mem.metadata = json!({
        "agent_id": "alice",
        "governance": { "write": "owner" },
    });
    let std_id = ai_memory::db::insert(&conn, &std_mem).expect("insert standard");
    ai_memory::db::set_namespace_standard(&conn, ns, &std_id, None).expect("set standard");

    // bob asserts he is the memory owner on a STORE. postgres has always read
    // the NAMESPACE owner here and denied; sqlite let bob's own claim win.
    // PRE-FIX: `Allow`.
    let decision = ai_memory::db::enforce_governance(
        &conn,
        GovernedAction::Store,
        ns,
        "bob",
        None,
        Some("bob"),
        &json!({}),
        None,
    )
    .expect("enforce_governance");
    assert!(
        matches!(decision, GovernanceDecision::Deny(_)),
        "a Store under an owner-level policy must resolve the NAMESPACE owner, \
         not the caller's own memory_owner claim; got {decision:?}"
    );

    // CONTROL — the real namespace owner is still allowed.
    let allowed = ai_memory::db::enforce_governance(
        &conn,
        GovernedAction::Store,
        ns,
        "alice",
        None,
        Some("alice"),
        &json!({}),
        None,
    )
    .expect("enforce_governance");
    assert!(
        matches!(allowed, GovernanceDecision::Allow),
        "the namespace owner must still be allowed; got {allowed:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// postgres twins — the same authorization, byte-identical refusals.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{REASON_UNRESOLVABLE, memory, permission_denied_reason, reason_not_owner};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    async fn store_or_skip() -> Option<PostgresStore> {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    fn unique_ns(prefix: &str) -> String {
        format!("{prefix}/{}", uuid::Uuid::new_v4())
    }

    #[tokio::test]
    async fn pg_non_owner_cannot_clear_namespace_standard_3176() {
        let Some(store) = store_or_skip().await else {
            return;
        };
        let alice = CallerContext::for_agent("alice");
        let bob = CallerContext::for_agent("bob");
        let ns = unique_ns("parity3176/owner");

        let std_id = store
            .store(&alice, &memory(&ns, "pg-alice-standard", "alice", false))
            .await
            .expect("store standard");
        store
            .set_namespace_standard(&alice, &ns, &std_id, None)
            .await
            .expect("set standard");

        let err = store
            .clear_namespace_standard(&bob, &ns)
            .await
            .expect_err("bob must not clear alice's standard");
        // BYTE-IDENTICAL to the sqlite twin — the refusal string is shared.
        assert_eq!(permission_denied_reason(&err), reason_not_owner("alice"));

        assert!(
            store
                .clear_namespace_standard(&alice, &ns)
                .await
                .expect("alice clears her own standard")
        );
    }

    #[tokio::test]
    async fn pg_severed_standard_clear_is_refused_3176() {
        let Some(store) = store_or_skip().await else {
            return;
        };
        let alice = CallerContext::for_agent("alice");
        let admin = CallerContext::for_admin("ai:operator");
        let ns = unique_ns("parity3176/severed");

        let std_id = store
            .store(&alice, &memory(&ns, "pg-to-be-severed", "alice", false))
            .await
            .expect("store standard");
        store
            .set_namespace_standard(&alice, &ns, &std_id, None)
            .await
            .expect("set standard");
        store
            .delete(&alice, &std_id)
            .await
            .expect("delete standard memory (severs the binding)");

        let err = store
            .clear_namespace_standard(&alice, &ns)
            .await
            .expect_err("a severed standard must not be clearable by a tenant");
        assert_eq!(permission_denied_reason(&err), REASON_UNRESOLVABLE);

        assert!(
            store
                .clear_namespace_standard(&admin, &ns)
                .await
                .expect("admin clears a severed binding")
        );
    }

    #[tokio::test]
    async fn pg_verify_folds_foreign_private_row_to_not_found_3176() {
        let Some(store) = store_or_skip().await else {
            return;
        };
        let alice = CallerContext::for_agent("alice");
        let bob = CallerContext::for_agent("bob");
        let ns = unique_ns("parity3176/verify");

        let id = store
            .store(&alice, &memory(&ns, "pg-alice-secret", "alice", true))
            .await
            .expect("store private memory");

        match store.verify(&bob, &id).await {
            Err(ai_memory::store::StoreError::NotFound { .. }) => {}
            other => panic!("bob must get NotFound for alice's private row, got {other:?}"),
        }
        let owner_report = store.verify(&alice, &id).await.expect("alice verifies");
        assert_eq!(owner_report.memory_id, id);
    }
}
