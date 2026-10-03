// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4043 — an UNREADABLE namespace governance policy must refuse the governed
//! write, never fall through to allow-on-silence. A child module of `storage`
//! so it reaches the private gate; kept out of `storage/mod.rs` (no ceiling
//! bump, QUAL-10).

use super::*;
use crate::models::{Memory, Tier};

fn test_db() -> Connection {
    open(std::path::Path::new(":memory:")).unwrap()
}

fn make_memory(title: &str, ns: &str, tier: Tier, priority: i32) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("Content for {title}"),
        priority,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

// ---- #4043 — an UNREADABLE namespace policy must refuse, never allow ----

/// An Owner-gated namespace whose standard belongs to `ai:owner-4043`.
fn owner_gated_conn_4043(ns: &str) -> Connection {
    use crate::models::{ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy};
    let conn = test_db();
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Owner,
            promote: GovernanceLevel::Owner,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        ..Default::default()
    };
    let mut standard = make_memory("std-4043", &format!("_standards-{ns}"), Tier::Long, 9);
    standard.metadata = serde_json::json!({"governance": policy, "agent_id": "ai:owner-4043"});
    let sid = insert(&conn, &standard).unwrap();
    set_namespace_standard(&conn, ns, &sid, None).unwrap();
    conn
}

/// Make every read of `table` on THIS connection fail, the way a
/// storage/decrypt fault would: a TEMP view shadows the table and calls a
/// scalar function that always errors.
fn inject_read_fault_4043(conn: &Connection, table: &str) {
    conn.create_scalar_function(
        "fault_4043",
        0,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8,
        |_| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::UserFunctionError(
                "injected #4043 read fault".into(),
            ))
        },
    )
    .unwrap();
    conn.execute_batch(&format!(
        "CREATE TEMP VIEW {table} AS SELECT * FROM main.{table} WHERE fault_4043() = 1"
    ))
    .unwrap();
}

fn enforce_store_4043(conn: &Connection, ns: &str) -> Result<crate::models::GovernanceDecision> {
    enforce_governance(
        conn,
        crate::models::GovernedAction::Store,
        ns,
        "ai:intruder-4043",
        None,
        None,
        &serde_json::json!({"title": "x"}),
        None,
    )
}

/// #4043 red-first — control: the policy is readable and a non-owner is
/// refused; then a `namespace_meta` read fault must REFUSE (error), not
/// fall through to allow-on-silence.
#[test]
fn issue_4043_namespace_meta_read_fault_refuses_under_enforce() {
    use crate::config::{
        PermissionsMode, lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
    };
    use crate::models::GovernanceDecision;
    let gate = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Enforce);
    let ns = "gov4043/meta";
    let conn = owner_gated_conn_4043(ns);

    let control = enforce_store_4043(&conn, ns).expect("readable policy decides");
    assert!(
        matches!(control, GovernanceDecision::Deny(_)),
        "control: an Owner policy refuses a non-owner, got {control:?}"
    );

    inject_read_fault_4043(&conn, "namespace_meta");
    match enforce_store_4043(&conn, ns) {
        Err(_) | Ok(GovernanceDecision::Deny(_)) => {}
        Ok(other) => {
            panic!("#4043: an unreadable namespace policy must refuse the write, got {other:?}")
        }
    }
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Advisory);
}

/// #4043 red-first — the bound standard itself is unreadable (the
/// selective-key-loss / decrypt-fault shape): refuse, never allow.
#[test]
fn issue_4043_standard_read_fault_refuses_under_enforce() {
    use crate::config::{
        PermissionsMode, lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
    };
    use crate::models::GovernanceDecision;
    let gate = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Enforce);
    let ns = "gov4043/standard";
    let conn = owner_gated_conn_4043(ns);

    inject_read_fault_4043(&conn, "memories");
    match enforce_store_4043(&conn, ns) {
        Err(_) | Ok(GovernanceDecision::Deny(_)) => {}
        Ok(other) => {
            panic!("#4043: an unreadable namespace standard must refuse the write, got {other:?}")
        }
    }
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Advisory);
}

/// #4043 red-first — the realistic fault: the standard's at-rest envelope
/// cannot be opened (selective key loss / corrupted ciphertext). Refuse.
#[test]
fn issue_4043_undecryptable_standard_refuses_under_enforce() {
    use crate::config::{
        PermissionsMode, lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
    };
    use crate::models::GovernanceDecision;
    let gate = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Enforce);
    let ns = "gov4043/envelope";
    let conn = owner_gated_conn_4043(ns);
    let sid: String = conn
        .query_row(
            "SELECT standard_id FROM namespace_meta WHERE namespace = ?1",
            params![ns],
            |r| r.get(0),
        )
        .unwrap();
    let changed = conn
        .execute(
            "UPDATE memories SET encrypted_envelope = x'00ff00ff' WHERE id = ?1",
            params![sid],
        )
        .unwrap();
    assert_eq!(changed, 1);
    match enforce_store_4043(&conn, ns) {
        Err(_) | Ok(GovernanceDecision::Deny(_)) => {}
        Ok(other) => panic!(
            "#4043: an undecryptable namespace standard must refuse the write, got {other:?}"
        ),
    }
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Advisory);
}

/// #4043 — a read fault on a PARENT link of the governance chain must
/// refuse: the leaf has no policy, the governed parent is reachable only
/// through `namespace_meta.parent_namespace`, and that read fails.
#[test]
fn issue_4043_parent_link_read_fault_refuses_under_enforce() {
    use crate::config::{
        PermissionsMode, lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
    };
    use crate::models::GovernanceDecision;
    let gate = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Enforce);
    let parent = "gov4043parent";
    let conn = owner_gated_conn_4043(parent);
    let leaf = "gov4043leaf";
    // The leaf's own standard carries NO governance (contributes nothing),
    // owned by the same principal so the parent link is entitled (#2542).
    let mut plain = make_memory("leaf-std-4043", "_standards-gov4043leaf", Tier::Long, 5);
    plain.metadata = serde_json::json!({"agent_id": "ai:owner-4043"});
    let plain_id = insert(&conn, &plain).unwrap();
    set_namespace_standard(&conn, leaf, &plain_id, Some(parent)).unwrap();
    // Control: the leaf inherits the parent's Owner gate (severed-floor
    // aside, a non-owner is refused).
    let control = enforce_store_4043(&conn, leaf).expect("readable chain decides");
    assert!(
        matches!(control, GovernanceDecision::Deny(_)),
        "control: the inherited Owner policy refuses a non-owner, got {control:?}"
    );
    inject_read_fault_4043(&conn, "namespace_meta");
    match enforce_store_4043(&conn, leaf) {
        Err(_) | Ok(GovernanceDecision::Deny(_)) => {}
        Ok(other) => {
            panic!("#4043: an unreadable parent link must refuse the write, got {other:?}")
        }
    }
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Advisory);
}

/// #4043 — Advisory never blocks by contract, including on a read fault.
#[test]
fn issue_4043_read_fault_under_advisory_allows() {
    use crate::config::{
        PermissionsMode, lock_permissions_mode_for_test, override_active_permissions_mode_for_test,
    };
    use crate::models::GovernanceDecision;
    let gate = lock_permissions_mode_for_test();
    override_active_permissions_mode_for_test(&gate, PermissionsMode::Advisory);
    let ns = "gov4043/advisory";
    let conn = owner_gated_conn_4043(ns);
    inject_read_fault_4043(&conn, "namespace_meta");
    let d = enforce_store_4043(&conn, ns).expect("advisory never errors");
    assert!(
        matches!(d, GovernanceDecision::Allow),
        "advisory allows, got {d:?}"
    );
}
