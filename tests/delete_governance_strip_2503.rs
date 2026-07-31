// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2503 (CWE-284 / data-integrity) — a CORRECTLY-AUTHORIZED delete must not
//! strip the governance binding of a namespace it has no authority over.
//!
//! ## The hole
//!
//! Every reap funnel ran an UNQUALIFIED
//! `DELETE FROM namespace_meta WHERE standard_id = ?1`. `set_namespace_standard`
//! deliberately permits CROSS-NAMESPACE binding ("allow cross-namespace —
//! shared policy"), so deleting an in-scope memory destroyed the binding ROW of
//! every namespace that pointed at it — anywhere in the tree — and
//! `resolve_governance_policy` then failed OPEN (allow-on-silence, #1569).
//! Through the global `*` standard, one in-scope delete disarmed policy
//! resolution for the whole node.
//!
//! ## What these cells pin, precisely
//!
//! Two distinct properties, and the distinction matters because only one of
//! them is achievable:
//!
//! 1. **The binding ROW survives** with `standard_id` severed to NULL, so the
//!    operator's `parent_namespace` inheritance link — configuration that has
//!    NOTHING to do with the deleted memory — is not collateral damage.
//! 2. **Resolution fails CLOSED**, not open. The victim's POLICY is genuinely
//!    unrecoverable (it lived in the deleted memory's `metadata.governance`);
//!    no fix can resurrect it. What is achievable, and what these cells
//!    assert, is that the deletion cannot silently WIDEN the victim's
//!    authority.
//!
//! ## Traps these cells are shaped to avoid
//!
//! - **Row state MUST be asserted via RAW SQL.** `db::get_namespace_standard`
//!   collapses a NULL `standard_id` into `None` (deliberately — that is the
//!   #1642 observable), so asserting through it cannot distinguish "row
//!   deleted" from "row severed" and would pass at the parent commit.
//! - **Resolved policy MUST be asserted too.** A row-state-only test passes
//!   while the attacker still writes ungoverned, since severing alone does not
//!   change the resolver.
//! - **A control must prove the fix did not degenerate into "never clean".**
//!   `control_same_namespace_reap_still_prevents_the_1642_dangle` pins the
//!   #1642 invariant the unqualified DELETE existed to enforce.
//! - **A control must prove an unrelated delete is byte-identical**, because
//!   the sever writes `updated_at` and could otherwise churn every row.

use ai_memory::db;
use ai_memory::models::{
    ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier, default_metadata,
};
use rusqlite::Connection;

const OWNER: &str = "ai:operator-2503";

fn open() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Insert a policy-bearing memory INTO `standard_ns` and return its id. The
/// caller decides which namespace(s) then BIND it, which is the whole point —
/// the standard lives in one namespace while governing another.
fn seed_standard_memory(conn: &Connection, standard_ns: &str, policy: &GovernancePolicy) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(OWNER.to_string()),
        );
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(policy).unwrap(),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: standard_ns.to_string(),
        // UNIQUE title per call. `db::insert` upserts on `(title, namespace)`,
        // so a fixed title would silently collapse two standards seeded into
        // the same namespace into ONE row — making an "ancestor vs child"
        // fixture secretly share a single standard, and any assertion built on
        // the pair vacuous. Caught by
        // `control_severed_child_does_not_downgrade_governed_ancestor_2503`.
        title: format!("standard living in {standard_ns} {}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &standard).expect("insert standard memory")
}

fn plain_memory(conn: &Connection, ns: &str, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "ordinary content".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: default_metadata(),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert plain memory")
}

fn approve_write_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    }
}

/// RAW row state — deliberately NOT routed through `db::get_namespace_standard`
/// (see the file header). Returns `(row_exists, standard_id, parent_namespace)`.
fn raw_meta_row(conn: &Connection, namespace: &str) -> (bool, Option<String>, Option<String>) {
    use rusqlite::OptionalExtension;
    let row: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT standard_id, parent_namespace FROM namespace_meta WHERE namespace = ?1",
            rusqlite::params![namespace],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .expect("raw namespace_meta probe");
    match row {
        Some((sid, parent)) => (true, sid, parent),
        None => (false, None, None),
    }
}

fn raw_updated_at(conn: &Connection, namespace: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT updated_at FROM namespace_meta WHERE namespace = ?1",
        rusqlite::params![namespace],
        |r| r.get::<_, Option<String>>(0),
    )
    .optional()
    .expect("raw updated_at probe")
    .flatten()
}

// ─────────────────────────────────────────────────────────────────────
// EXPLOIT cells — RED at the parent commit on BOTH row state and policy
// ─────────────────────────────────────────────────────────────────────

/// The headline #2503 shape: the deleter is authorized for `public/ok` and the
/// victim is `secure/ops`, a namespace it may not touch at all.
#[test]
fn exploit_delete_strips_out_of_scope_victim_binding_2503() {
    let conn = open();
    // The standard memory lives in the namespace the deleter IS authorized for.
    let standard_id = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    // ...but governs a namespace the deleter is NOT authorized for, and carries
    // an operator-configured parent link that has nothing to do with the memory.
    db::set_namespace_standard(&conn, "secure/ops", &standard_id, Some("secure"))
        .expect("bind victim namespace");

    // Precondition: the victim really is governed, and the standard really
    // exists (a #2479-class trap — `set_namespace_standard` refuses an absent
    // standard, and that refusal is observationally identical to a scope
    // refusal, so the exploit must positively assert the seed took).
    let before = db::resolve_governance_policy(&conn, "secure/ops");
    assert_eq!(
        before.as_ref().map(|p| p.core.write.clone()),
        Some(GovernanceLevel::Approve),
        "precondition: the victim namespace must be governed before the delete"
    );
    assert!(
        db::get(&conn, &standard_id).unwrap().is_some(),
        "precondition: the standard memory must exist"
    );

    // The delete the namespace gates CORRECTLY ALLOW.
    assert!(db::delete(&conn, &standard_id).expect("delete standard memory"));

    // (1) ROW STATE — the victim's binding row must SURVIVE, severed, with its
    // operator-configured parent link intact. At the parent commit the row is
    // GONE (`row_exists == false`) and the parent link is destroyed with it.
    let (row_exists, standard, parent) = raw_meta_row(&conn, "secure/ops");
    assert!(
        row_exists,
        "#2503: the victim's namespace_meta row must SURVIVE the delete — \
         destroying it also destroys the operator's parent_namespace link, \
         which has nothing to do with the deleted memory"
    );
    assert_eq!(
        standard, None,
        "#1642: the severed row must not name a memory that no longer exists"
    );
    assert_eq!(
        parent.as_deref(),
        Some("secure"),
        "#2503: the parent_namespace inheritance link must be preserved"
    );

    // (2) RESOLVED POLICY — must NOT fall through to allow-on-silence. At the
    // parent commit this is `None`, i.e. the deletion silently widened the
    // victim's authority from `write: approve` to the permissive default.
    let after = db::resolve_governance_policy(&conn, "secure/ops")
        .expect("#2503: a severed binding must resolve to the floor, never to None");
    assert_eq!(
        after.core.write,
        GovernanceLevel::Owner,
        "#2503: severed governance must fail CLOSED to the owner floor"
    );
    assert_eq!(after.core.promote, GovernanceLevel::Owner);
    assert_eq!(after.core.delete, GovernanceLevel::Owner);
}

/// Blast radius: a single `*`-bound standard sits in EVERY namespace's chain,
/// so one in-scope delete used to disarm policy resolution node-wide.
#[test]
fn exploit_global_standard_delete_disarms_whole_tree_2503() {
    let conn = open();
    let standard_id = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "*", &standard_id, None).expect("bind global standard");

    for probe in ["secure/ops/deep", "unrelated", "other/tree/leaf"] {
        assert_eq!(
            db::resolve_governance_policy(&conn, probe).map(|p| p.core.write),
            Some(GovernanceLevel::Approve),
            "precondition: {probe} inherits the global standard"
        );
    }

    assert!(db::delete(&conn, &standard_id).expect("delete the global standard memory"));

    let (row_exists, standard, _) = raw_meta_row(&conn, "*");
    assert!(row_exists, "#2503: the global binding row must survive");
    assert_eq!(standard, None, "#1642: severed, not dangling");

    for probe in ["secure/ops/deep", "unrelated", "other/tree/leaf"] {
        let after = db::resolve_governance_policy(&conn, probe)
            .unwrap_or_else(|| panic!("#2503: {probe} must not fall back to allow-on-silence"));
        assert_eq!(
            after.core.write,
            GovernanceLevel::Owner,
            "#2503: {probe} must fail closed to the floor"
        );
    }
}

/// The SECURITY half in isolation. Deliberately asserts NOTHING about row
/// state, so at the parent commit it fails on the RESOLVED POLICY rather than
/// on the binding row — proving the fail-open is closed and not merely that
/// the row layout changed. (The combined exploit cells above assert row state
/// first, so their parent failure lands on the row and would leave the
/// authorization outcome unproven.)
#[test]
fn exploit_delete_fails_open_on_resolved_policy_2503() {
    let conn = open();
    let standard_id = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "secure/ops", &standard_id, None).expect("bind victim");
    assert_eq!(
        db::resolve_governance_policy(&conn, "secure/ops").map(|p| p.core.write),
        Some(GovernanceLevel::Approve)
    );

    assert!(db::delete(&conn, &standard_id).expect("delete standard memory"));

    // At the parent commit this is `None` — allow-on-silence — so a caller the
    // operator gated behind `write: approve` writes freely.
    let after = db::resolve_governance_policy(&conn, "secure/ops").expect(
        "#2503 SECURITY: an in-scope delete must not leave the out-of-scope \
         victim resolving to None (allow-on-silence); that is the privilege \
         widening this issue is about",
    );
    assert_eq!(after.core.write, GovernanceLevel::Owner);
}

/// The archive funnels share the primitive, so they share the defect.
#[test]
fn exploit_archive_strips_out_of_scope_victim_binding_2503() {
    let conn = open();
    let standard_id = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "secure/ops", &standard_id, Some("secure"))
        .expect("bind victim namespace");
    assert!(db::resolve_governance_policy(&conn, "secure/ops").is_some());

    assert!(db::archive_memory(&conn, &standard_id, Some("manual")).expect("archive standard"));

    let (row_exists, standard, parent) = raw_meta_row(&conn, "secure/ops");
    assert!(
        row_exists,
        "#2503: archiving a standard must SEVER, not destroy, the victim's row"
    );
    assert_eq!(standard, None);
    assert_eq!(parent.as_deref(), Some("secure"));
    assert_eq!(
        db::resolve_governance_policy(&conn, "secure/ops").map(|p| p.core.write),
        Some(GovernanceLevel::Owner),
        "#2503: archive must fail closed to the floor too"
    );
}

// ─────────────────────────────────────────────────────────────────────
// CONTROL cells — the fix must not over-reach
// ─────────────────────────────────────────────────────────────────────

/// The #1642 invariant the unqualified DELETE existed to enforce: after
/// reaping a standard memory, nothing may still resolve a standard whose
/// backing memory is gone. Severing satisfies this LITERALLY, and the
/// OBSERVABLE #1642's own regression test pins is byte-identical.
#[test]
fn control_same_namespace_reap_still_prevents_the_1642_dangle() {
    let conn = open();
    let standard_id = seed_standard_memory(&conn, "team/eng", &approve_write_policy());
    db::set_namespace_standard(&conn, "team/eng", &standard_id, Some("team"))
        .expect("bind own namespace");

    assert!(db::delete(&conn, &standard_id).expect("delete standard"));

    // The #1642 observable, unchanged: no standard resolves.
    assert_eq!(
        db::get_namespace_standard(&conn, "team/eng").expect("get standard"),
        None,
        "#1642: a reaped standard must not keep resolving"
    );
    // And there is genuinely no dangling pointer — the column is NULL, so no
    // row names a memory that does not exist.
    let (row_exists, standard, parent) = raw_meta_row(&conn, "team/eng");
    assert!(row_exists, "#2503: the row itself survives");
    assert_eq!(
        standard, None,
        "#1642: the pointer is severed, not left dangling"
    );
    assert_eq!(
        parent.as_deref(),
        Some("team"),
        "#2503: even an own-namespace reap preserves the parent link"
    );
}

/// An ordinary delete of a memory that is nobody's standard must be
/// byte-identical to the pre-fix behaviour — no UPDATE, no `updated_at` churn,
/// no row touched. This is what proves the sever is scoped to the pointer and
/// does not sweep the table.
#[test]
fn control_delete_of_non_standard_memory_is_byte_identical_2503() {
    let conn = open();
    let standard_id = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "secure/ops", &standard_id, Some("secure"))
        .expect("bind victim");
    let unrelated = plain_memory(&conn, "public/ok", "not a standard");

    let before_row = raw_meta_row(&conn, "secure/ops");
    let before_updated = raw_updated_at(&conn, "secure/ops");
    let before_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM namespace_meta", [], |r| r.get(0))
        .unwrap();

    assert!(db::delete(&conn, &unrelated).expect("delete unrelated memory"));

    assert_eq!(
        raw_meta_row(&conn, "secure/ops"),
        before_row,
        "#2503: deleting a non-standard memory must not touch any binding"
    );
    assert_eq!(
        raw_updated_at(&conn, "secure/ops"),
        before_updated,
        "#2503: no updated_at churn on an unrelated delete"
    );
    let after_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM namespace_meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before_count, after_count);
    // The victim is still fully governed — nothing was severed.
    assert_eq!(
        db::resolve_governance_policy(&conn, "secure/ops").map(|p| p.core.write),
        Some(GovernanceLevel::Approve),
        "#2503: an unrelated delete must leave the policy exactly as it was"
    );
}

/// The floor composes OVER inheritance, it does not replace it. A severed
/// CHILD must never DOWNGRADE a governed ANCESTOR — that would invert the fix
/// and break the feature `parent_namespace` exists for.
#[test]
fn control_severed_child_does_not_downgrade_governed_ancestor_2503() {
    let conn = open();
    // Ancestor: intact, strict.
    let ancestor_std = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "corp", &ancestor_std, None).expect("bind ancestor");
    // Child: its own standard, which we then reap.
    let child_std = seed_standard_memory(&conn, "public/ok", &approve_write_policy());
    db::set_namespace_standard(&conn, "corp/team", &child_std, None).expect("bind child");

    assert!(db::delete(&conn, &child_std).expect("reap the child's standard"));

    let resolved = db::resolve_governance_policy(&conn, "corp/team")
        .expect("must resolve through the intact ancestor");
    assert_eq!(
        resolved.core.write,
        GovernanceLevel::Approve,
        "#2503: the severed child must NOT downgrade the ancestor's \
         write:approve to the owner floor — the floor may only tighten"
    );
    // The ancestor is untouched and still governs on its own.
    assert_eq!(
        db::resolve_governance_policy(&conn, "corp").map(|p| p.core.write),
        Some(GovernanceLevel::Approve)
    );
}

/// gc must HEAL a legacy dangling pointer into the severed state, never DELETE
/// it. Pre-#2503 the sweep was the back door onto the reap-path confinement: a
/// preserved severance was erased on the next tick, silently restoring
/// allow-on-silence ~30 minutes later.
#[test]
fn control_gc_heals_dangling_pointer_to_severed_not_absent_2503() {
    let conn = open();
    // A legacy dangle: a binding naming a memory that does not exist. Written
    // by raw SQL because no production path can produce one post-#2503.
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
         VALUES ('legacy/ns', 'ghost-id-that-does-not-exist', ?1, 'legacy')",
        rusqlite::params![chrono::Utc::now().to_rfc3339()],
    )
    .expect("seed a legacy dangling binding");

    db::gc(&conn, false).expect("gc sweep");

    let (row_exists, standard, parent) = raw_meta_row(&conn, "legacy/ns");
    assert!(
        row_exists,
        "#2503: gc must HEAL the dangle, not DELETE the row — deleting it is \
         the back door that silently restores allow-on-silence"
    );
    assert_eq!(standard, None, "#2503: healed into the severed state");
    assert_eq!(parent.as_deref(), Some("legacy"));
    // And the healed state still fails closed.
    assert_eq!(
        db::resolve_governance_policy(&conn, "legacy/ns").map(|p| p.core.write),
        Some(GovernanceLevel::Owner)
    );

    // MONOTONE: a second sweep must not re-touch the already-severed row.
    // `standard_id IS NOT NULL` is what guarantees no per-tick updated_at churn
    // (and, on sqlite specifically, what stops `NOT EXISTS (… = NULL)` — which
    // is TRUE — from matching every severed row).
    let after_first = raw_updated_at(&conn, "legacy/ns");
    db::gc(&conn, false).expect("second gc sweep");
    assert_eq!(
        raw_updated_at(&conn, "legacy/ns"),
        after_first,
        "#2503: the heal must be monotone — an already-severed row is never \
         re-touched, so there is no per-tick churn or fanout storm"
    );
}

/// A namespace that was NEVER governed keeps allow-on-silence (#1569). The
/// floor must fire only where an operator actually configured a standard.
#[test]
fn control_ungoverned_namespace_keeps_allow_on_silence_2503() {
    let conn = open();
    let _ = plain_memory(&conn, "wide/open", "ordinary");
    assert_eq!(
        db::resolve_governance_policy(&conn, "wide/open"),
        None,
        "#1569: a namespace with no standard anywhere in its chain must still \
         resolve to None — #2503 must not tighten the never-configured case"
    );
}

/// The floor is a FLOOR: stricter levels survive, looser ones are raised, and
/// nothing outside {write, promote, delete} is touched.
#[test]
fn severed_floor_only_ever_tightens_2503() {
    let strict = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Registered,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    };
    let floored = strict.clone().with_severed_standard_floor();
    assert_eq!(
        floored.core.write,
        GovernanceLevel::Approve,
        "a stricter level must survive the floor untouched"
    );
    assert_eq!(floored.core.promote, GovernanceLevel::Owner);
    assert_eq!(floored.core.delete, GovernanceLevel::Owner);
    assert_eq!(
        floored.core.inherit, strict.core.inherit,
        "the floor must not disturb any field outside write/promote/delete"
    );

    // The documented strictness order the floor relies on.
    assert!(GovernanceLevel::Any.strictness() < GovernanceLevel::Registered.strictness());
    assert!(GovernanceLevel::Registered.strictness() < GovernanceLevel::Owner.strictness());
    assert!(GovernanceLevel::Owner.strictness() < GovernanceLevel::Approve.strictness());
}
