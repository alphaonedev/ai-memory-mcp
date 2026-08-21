// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v1.0.0 #2542 — namespace-standard chain grafting (tenant-isolation +
//! approval-bypass). Regression pins for the two ratified routes; verified to
//! REPRODUCE at `release/v1.0.0` before the fix.
//!
//! **Route 1 — the authorization edge (bind).** A namespace-standard bind now
//! authorizes the DECLARED `parent` too: the bind is refused unless the parent
//! namespace is UNOWNED (no standard bound) or its standard is owned by the SAME
//! principal as the caller. Pre-fix, `set_standard { parent: victim-ns }`
//! spliced any victim namespace above the caller's in the chain that
//! `resolve_governance_policy` layers governance over, with no check on the
//! parent (`#929` only checked the bound memory). Driven end-to-end through the
//! MCP funnel `handle_namespace_set_standard` (which the HTTP sqlite path also
//! delegates to).
//!
//! **Route 2 — CROSS-TENANT parent links vs governance.** The governance view of
//! the chain follows each `child → parent` link ONLY when ENTITLED, checked
//! PER-HOP: parent unowned, or same-principal as `child` — the namespace that
//! DECLARED the link (NOT the leaf; a `/`-child inherits its `/`-parent's entitled
//! links structurally). This is the Route-1 bind rule re-checked at resolution. A
//! cross-tenant parent (inferred, explicit-legacy, or a TOCTOU-bound-later one) is
//! dropped with a WARN; a legitimate same-owner parent — INCLUDING a flat `-`
//! hierarchy that coincides with the auto-detect pattern, AND a federation-pushed
//! in-scope parent whose declarer shares its owner (#2479) — keeps its layer.
//! Driven at the resolver (`db::resolve_governance_policy` /
//! `db::resolve_require_approval_above_depth`).

use ai_memory::config::ResolvedTtl;
use ai_memory::db;
use ai_memory::models::{
    ApproverType, ConfidenceSource, GovernanceLevel, Memory, Tier, default_metadata,
};
use rusqlite::Connection;
use serde_json::{Value, json};

const ALICE: &str = "ai:alice-2542";
const BOB: &str = "ai:bob-2542";

/// v1.0.0 store-path attestation default is REQUIRED; the MCP store fixtures
/// here are unsigned, so pin the permissive opt-out for this process.
fn permissive_attestation() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, set before any store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn open_db() -> (Connection, tempfile::NamedTempFile) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = db::open(f.path()).expect("db::open");
    (conn, f)
}

/// Seed a memory owned by `owner` via the MCP store path (so its stored
/// `metadata.agent_id` is the RESOLVED principal the funnel's ownership gate
/// compares against). Returns the memory id.
fn seed_owned(
    conn: &Connection,
    db_path: &std::path::Path,
    namespace: &str,
    owner: &str,
) -> String {
    permissive_attestation();
    let ttl = ResolvedTtl::default();
    let v = ai_memory::mcp::tools::handle_store_for_tests(
        conn,
        db_path,
        &json!({
            "tier": "long",
            "namespace": namespace,
            "title": format!("std-{owner}"),
            "content": "2542 standard anchor",
            "priority": 5,
            "agent_id": owner,
        }),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("seed memory store");
    v["id"].as_str().expect("seed id").to_string()
}

/// Drive the MCP set-standard funnel as `caller`, optionally declaring `parent`.
fn set_standard(
    conn: &Connection,
    namespace: &str,
    id: &str,
    caller: &str,
    parent: Option<&str>,
) -> Result<Value, String> {
    let mut params = json!({ "namespace": namespace, "id": id, "agent_id": caller });
    if let Some(p) = parent {
        params["parent"] = json!(p);
    }
    ai_memory::mcp::handle_namespace_set_standard(conn, &params)
}

// ===========================================================================
// Route 1 — declared-parent entitlement on the bind.
// ===========================================================================

#[test]
fn r1_unowned_parent_graft_allowed() {
    // The declared parent has NO standard bound → UNOWNED → the graft is allowed.
    let (conn, f) = open_db();
    let bob_std = seed_owned(&conn, f.path(), "bob-ns-unowned", BOB);
    let res = set_standard(
        &conn,
        "bob-ns-unowned",
        &bob_std,
        BOB,
        Some("victim-has-no-standard-2542"),
    );
    assert!(
        res.is_ok(),
        "#2542 Route 1: a parent with no standard is unowned and must be allowed; got {res:?}"
    );
}

#[test]
fn r1_same_principal_parent_allowed() {
    // Alice owns the parent namespace's standard; alice may graft under it.
    let (conn, f) = open_db();
    let parent_std = seed_owned(&conn, f.path(), "alice-parent-2542", ALICE);
    set_standard(&conn, "alice-parent-2542", &parent_std, ALICE, None)
        .expect("alice binds her own parent standard");

    let child_std = seed_owned(&conn, f.path(), "alice-child-2542", ALICE);
    let res = set_standard(
        &conn,
        "alice-child-2542",
        &child_std,
        ALICE,
        Some("alice-parent-2542"),
    );
    assert!(
        res.is_ok(),
        "#2542 Route 1: same-principal parent graft must be allowed; got {res:?}"
    );
}

#[test]
fn r1_cross_principal_parent_graft_refused_loudly() {
    // Alice owns the parent standard; BOB tries to graft his namespace under it.
    let (conn, f) = open_db();
    let alice_parent_std = seed_owned(&conn, f.path(), "graft-victim-2542", ALICE);
    set_standard(&conn, "graft-victim-2542", &alice_parent_std, ALICE, None)
        .expect("alice binds her victim-namespace standard");

    // Bob owns his OWN bound standard (so the #929 bound-owner gate passes and
    // we isolate the #2542 declared-parent gate).
    let bob_std = seed_owned(&conn, f.path(), "bob-ns-2542", BOB);
    let res = set_standard(
        &conn,
        "bob-ns-2542",
        &bob_std,
        BOB,
        Some("graft-victim-2542"),
    );
    let err = res.expect_err("#2542 Route 1: cross-principal parent graft MUST be refused");
    assert!(
        err.contains("declared parent namespace standard"),
        "#2542 Route 1: refusal must name the declared parent, fail-closed and loud; got {err:?}"
    );
}

// ===========================================================================
// Route 2 — CROSS-TENANT parent links excluded from governance layering.
//
// The exclusion is OWNERSHIP-based (review Finding 1): a `parent_namespace` link
// layers governance ONLY when the parent is UNOWNED or owned by the SAME
// principal as the namespace being resolved — the exact Route-1 bind rule,
// re-checked at resolution. This keeps a legitimately-declared same-owner parent
// (which the pre-review Route 2 wrongly stripped whenever it coincided with the
// `-`-prefix pattern — an approval BYPASS) while excluding cross-tenant grafts,
// whether they arrived by `-`-inference, an explicit legacy declaration, or a
// TOCTOU window where the parent was unowned at bind time.
// ===========================================================================

const ATTACKER: &str = "ai:attacker-2542";
const OP: &str = "ai:operator-2542";
const VICTIM: &str = "ai:victim-2542";

/// Approve/Human governance blob, optionally carrying `require_approval_above_depth`
/// (which lives OUTSIDE the typed `GovernancePolicy` struct, so it is expressed
/// as raw JSON).
fn approve_gov(require_approval_above_depth: Option<u64>) -> Value {
    let mut g = json!({
        "write": "approve",
        "promote": "any",
        "delete": "owner",
        "approver": "human",
        "inherit": true,
    });
    if let Some(d) = require_approval_above_depth {
        g["require_approval_above_depth"] = json!(d);
    }
    g
}

/// Insert a namespace standard directly (resolver-level), optionally carrying a
/// governance blob and an explicit `parent`. `parent = None` triggers the
/// storage-side `-`-prefix `auto_detect_parent` inference, exactly as a bind
/// with no declared parent does.
fn seed_standard_row(
    conn: &Connection,
    namespace: &str,
    owner: &str,
    governance: Option<Value>,
    parent: Option<&str>,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".to_string(), json!(owner));
        if let Some(g) = governance {
            obj.insert("governance".to_string(), g);
        }
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{namespace}"),
        title: format!("standard for {namespace}"),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        confidence_source: ConfidenceSource::CallerProvided,
        ..Memory::default()
    };
    let id = db::insert(conn, &standard).unwrap();
    db::set_namespace_standard(conn, namespace, &id, parent).unwrap();
}

#[test]
fn r2_inferred_cross_tenant_graft_excluded_from_governance() {
    // THE #2542 attack via `-`-inference: the attacker owns the short prefix
    // `acme`; the victim's `acme-sub` (no declared parent) `-`-auto-detects it.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_standard_row(&conn, "acme", ATTACKER, Some(approve_gov(None)), None);
    seed_standard_row(&conn, "acme-sub", ALICE, None, None); // auto-detects `acme`

    // The inference is KEPT for LOOKUP — `acme` is still in the display chain.
    let chain = db::build_namespace_chain(&conn, "acme-sub");
    assert!(
        chain.iter().any(|s| s == "acme"),
        "#2542 Route 2: the `-`-prefix inference must survive for LOOKUP; got {chain:?}"
    );

    // But the attacker's `acme` policy must NOT govern the victim's `acme-sub`.
    let resolved = db::resolve_governance_policy(&conn, "acme-sub");
    assert!(
        resolved.is_none(),
        "#2542 Route 2: a CROSS-TENANT inferred ancestor must not layer governance; got {resolved:?}"
    );
}

#[test]
fn r2_same_owner_inferred_hierarchy_keeps_governance() {
    // Same principal owns both — NOT a tenant violation, and an ancestor layer
    // can only ADD a restriction (fail-safe), never bypass one. Kept.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_standard_row(&conn, "acme", ALICE, Some(approve_gov(None)), None);
    seed_standard_row(&conn, "acme-sub", ALICE, None, None); // auto-detects `acme`

    let resolved = db::resolve_governance_policy(&conn, "acme-sub").expect(
        "#2542 Route 2: a SAME-OWNER inferred ancestor keeps governance (operator's own hierarchy)",
    );
    assert_eq!(resolved.core.write, GovernanceLevel::Approve);
}

#[test]
fn r2_explicit_same_owner_flat_hierarchy_inherits_approval_gate() {
    // REVIEW FINDING 1 REGRESSION — the exact bypass the review caught: an
    // operator explicitly declares `parent: acme-corp` on `acme-corp-frontend`
    // (a flat `-` hierarchy that COINCIDES with the auto-detect pattern). The
    // child MUST inherit acme-corp's Approve + require_approval gate. The
    // pre-review Route 2 stripped it (writes that should require Human approval
    // proceeded UNGATED).
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_standard_row(&conn, "acme-corp", OP, Some(approve_gov(Some(1))), None);
    seed_standard_row(&conn, "acme-corp-frontend", OP, None, Some("acme-corp"));

    let resolved = db::resolve_governance_policy(&conn, "acme-corp-frontend").expect(
        "#2542 Finding 1: an explicitly-declared same-owner parent MUST layer its governance",
    );
    assert_eq!(
        resolved.core.write,
        GovernanceLevel::Approve,
        "#2542 Finding 1: the child must inherit the parent's Approve write gate"
    );
    assert_eq!(resolved.core.approver, ApproverType::Human);
    // The approval-DEPTH gate (a separate resolver over the same governance
    // chain) must inherit too.
    assert_eq!(
        db::resolve_require_approval_above_depth(&conn, "acme-corp-frontend"),
        Some(1),
        "#2542 Finding 1: the child must inherit the parent's require_approval_above_depth gate"
    );
}

#[test]
fn r2_explicit_non_coincident_same_owner_parent_inherits() {
    // Explicit parent whose name does NOT share a `-`-prefix with the child —
    // unambiguously explicit; inherits (control for the coincident case above).
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_standard_row(&conn, "orgpolicy", ALICE, Some(approve_gov(None)), None);
    seed_standard_row(&conn, "teamspace", ALICE, None, Some("orgpolicy"));

    let resolved = db::resolve_governance_policy(&conn, "teamspace").expect(
        "#2542 Route 2: an explicitly-declared same-owner parent MUST layer its governance",
    );
    assert_eq!(resolved.core.write, GovernanceLevel::Approve);
    assert_eq!(resolved.core.approver, ApproverType::Human);
}

#[test]
fn r2_explicit_cross_tenant_parent_excluded_from_governance() {
    // A cross-tenant EXPLICIT parent link (a pre-#2542 graft, or a pre-Route-1
    // declaration) is dropped from governance layering with a WARN.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_standard_row(&conn, "victimns", ATTACKER, Some(approve_gov(None)), None);
    seed_standard_row(&conn, "childns", ALICE, None, Some("victimns"));

    let resolved = db::resolve_governance_policy(&conn, "childns");
    assert!(
        resolved.is_none(),
        "#2542 Route 2: a cross-tenant explicit parent must not layer governance; got {resolved:?}"
    );
}

#[test]
fn r2_toctou_unowned_parent_bound_later_is_excluded() {
    // REVIEW FINDING 2 (TOCTOU) — the attacker grafts `parent: victimns` while
    // victimns has NO standard (so Route 1's bind gate treats it as unowned and
    // ALLOWS the declaration). When the victim LATER binds a governed standard,
    // the resolution-time ownership re-check excludes the now-cross-tenant link.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // Attacker's namespace declares the (currently unowned) victim as parent.
    seed_standard_row(&conn, "attackerns", ATTACKER, None, Some("victimns"));
    // Later: the victim binds a governed standard at victimns.
    seed_standard_row(&conn, "victimns", ALICE, Some(approve_gov(None)), None);

    let resolved = db::resolve_governance_policy(&conn, "attackerns");
    assert!(
        resolved.is_none(),
        "#2542 Finding 2: a parent bound by another tenant AFTER the graft must not \
         couple its governance onto the attacker's namespace; got {resolved:?}"
    );
}

#[test]
fn r2_federation_in_scope_same_owner_parent_applies_through_unowned_leaf() {
    // REGRESSION for the CI-caught #2479 break: the governance entitlement is
    // PER-HOP against the DECLARER of each link, not the leaf. `alpha` (federated
    // in-scope, declaring `parent: victim`) and `victim` share an owner; the leaf
    // `alpha/sub` is UNOWNED (no standard). A leaf-based check wrongly dropped
    // `victim` because the unowned leaf did not own it; the per-hop check keeps it
    // because `alpha` (the declarer) does — so `victim`'s policy governs
    // `alpha/sub`, exactly what `federation_ns_meta_scope_2479`'s
    // `control_parent_in_scope_applies_and_takes_effect` asserts.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let permissive = json!({"write": "any", "promote": "any", "delete": "owner"});
    seed_standard_row(&conn, "victim", VICTIM, Some(permissive), None);
    // `alpha` shares victim's owner and declares `victim` as its parent (the
    // federation #2479 in-scope link, minted same-owner at the receiver).
    seed_standard_row(&conn, "alpha", VICTIM, None, Some("victim"));
    // `alpha/sub` has NO standard of its own — an unowned `/`-child.

    assert_eq!(
        db::resolve_governance_policy(&conn, "alpha/sub").map(|p| p.core.write),
        Some(GovernanceLevel::Any),
        "#2542/#2479: a same-owner in-scope parent must govern an unowned `/`-child \
         (per-hop entitlement against the declarer, not the leaf)"
    );
}
