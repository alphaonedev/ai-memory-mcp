// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4285 (5-agent vote 4d3ea1c5, memory 1c3e2889; reverses #1384) — a namespace
//! governance standard whose `metadata.governance` does NOT deserialize is a
//! SEVERED level (#2503), at every level of the chain, on BOTH backends.
//!
//! Pre-fix the parse failure was `NoPolicy`: the walk continued past the
//! corrupt level as if no policy were set, so a corrupt stricter child (or a
//! corrupt `*`) silently resolved to allow-on-silence. The fix is neither a
//! hard refusal (a corrupt `*` would be a substrate-wide write outage) nor
//! `NoPolicy`: the walk continues and `with_severed_standard_floor` raises
//! write/promote/delete to at least Owner.
//!
//! Documented limit: a corrupt policy that MEANT something stricter than Owner
//! (Approve / consensus) degrades to the Owner floor; the doctor Critical is
//! the operator's signal.

use ai_memory::config::{PermissionsMode, set_active_permissions_mode};
use ai_memory::models::{
    ConfidenceSource, CorePolicy, GovernanceDecision, GovernanceLevel, GovernancePolicy,
    GovernedAction, Memory, Tier, default_metadata,
};

const OWNER: &str = "ai:owner-4285";
const STRANGER: &str = "ai:stranger-4285";

/// A `metadata.governance` blob that cannot deserialize (unknown enum variant,
/// the `#1384` shape: a typo or an out-of-band edit).
fn corrupt_governance_json() -> serde_json::Value {
    serde_json::json!({ "write": "approval-typo-4285" })
}

fn strict_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    }
}

fn standard_memory(ns: &str, governance: serde_json::Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".into(), serde_json::json!(OWNER));
        obj.insert("governance".into(), governance);
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("standard-{}", uuid::Uuid::new_v4()),
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
    }
}

#[test]
fn fixture_is_really_a_parse_failure_4285() {
    let m = standard_memory("x", corrupt_governance_json());
    assert!(
        matches!(GovernancePolicy::from_metadata(&m.metadata), Some(Err(_))),
        "the corrupt fixture must be a typed-deserialise failure, not absent governance"
    );
}

mod sqlite {
    use super::*;
    use ai_memory::db;
    use rusqlite::Connection;

    fn open() -> Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn bind(conn: &Connection, ns: &str, governance: serde_json::Value) -> String {
        let sid = db::insert(conn, &standard_memory("std-home", governance)).expect("insert");
        db::set_namespace_standard(conn, ns, &sid, None).expect("bind");
        sid
    }

    fn store_decision(conn: &Connection, ns: &str, agent: &str) -> GovernanceDecision {
        set_active_permissions_mode(PermissionsMode::Enforce);
        db::enforce_governance(
            conn,
            GovernedAction::Store,
            ns,
            agent,
            None,
            None,
            &serde_json::json!({}),
            None,
        )
        .expect("enforce_governance")
    }

    /// A corrupt `*` standard resolves to the Owner floor, never `None`.
    #[test]
    fn corrupt_star_resolves_to_owner_floor_not_none_4285() {
        let conn = open();
        bind(&conn, "*", corrupt_governance_json());
        let p = db::resolve_governance_policy(&conn, "corp/team")
            .expect("resolve")
            .expect("#4285: a corrupt standard must resolve to the severed floor, never None");
        assert_eq!(p.core.write, GovernanceLevel::Owner);
        assert_eq!(p.core.promote, GovernanceLevel::Owner);
        assert_eq!(p.core.delete, GovernanceLevel::Owner);
    }

    /// The OWNER of the corrupt `*` standard is not locked out.
    #[test]
    fn corrupt_star_does_not_lock_out_owner_write_4285() {
        let conn = open();
        bind(&conn, "*", corrupt_governance_json());
        assert!(matches!(
            store_decision(&conn, "corp/team", OWNER),
            GovernanceDecision::Allow
        ));
    }

    /// A non-owner write under a corrupt ancestor is refused (Owner floor).
    #[test]
    fn non_owner_write_under_corrupt_ancestor_refused_4285() {
        let conn = open();
        bind(&conn, "corp", corrupt_governance_json());
        let d = store_decision(&conn, "corp/team", STRANGER);
        assert!(
            !matches!(d, GovernanceDecision::Allow),
            "#4285: a non-owner write under a corrupt ancestor must hit the Owner floor; got {d:?}"
        );
    }

    /// The operator repairs by re-binding a valid standard.
    #[test]
    fn operator_repairs_corrupt_standard_via_set_standard_4285() {
        let conn = open();
        bind(&conn, "corp", corrupt_governance_json());
        bind(
            &conn,
            "corp",
            serde_json::to_value(strict_policy()).expect("ser"),
        );
        let p = db::resolve_governance_policy(&conn, "corp/team")
            .expect("resolve")
            .expect("governed");
        assert_eq!(
            p.core.write,
            GovernanceLevel::Approve,
            "after repair the intact policy governs with no severed floor applied"
        );
    }

    /// The census (doctor Critical + boot WARN source) lists EVERY corrupt
    /// standard, sorted, and is empty once repaired.
    #[test]
    fn census_lists_every_corrupt_standard_4285() {
        let conn = open();
        assert!(
            db::list_corrupt_governance_standards(&conn)
                .expect("census")
                .is_empty()
        );
        bind(&conn, "zeta", corrupt_governance_json());
        bind(&conn, "alpha", corrupt_governance_json());
        bind(
            &conn,
            "intact",
            serde_json::to_value(strict_policy()).expect("ser"),
        );
        let c = db::list_corrupt_governance_standards(&conn).expect("census");
        assert_eq!(
            c.iter().map(|x| x.namespace.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        bind(
            &conn,
            "alpha",
            serde_json::to_value(strict_policy()).expect("ser"),
        );
        let c = db::list_corrupt_governance_standards(&conn).expect("census");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].namespace, "zeta");
    }

    /// Parity with the #2503 severed shape: a corrupt-JSON leaf resolves
    /// IDENTICALLY to a leaf whose standard was reaped (dangling/severed),
    /// with and without an intact ancestor.
    #[test]
    fn corrupt_json_resolves_identically_to_severed_4285() {
        for ancestor in [false, true] {
            let corrupt = open();
            let severed = open();
            for conn in [&corrupt, &severed] {
                if ancestor {
                    bind(
                        conn,
                        "corp",
                        serde_json::to_value(strict_policy()).expect("ser"),
                    );
                }
            }
            bind(&corrupt, "corp/team", corrupt_governance_json());
            let sid = bind(
                &severed,
                "corp/team",
                serde_json::to_value(strict_policy()).expect("ser"),
            );
            assert!(db::delete(&severed, &sid).expect("reap"));
            let a = db::resolve_governance_policy(&corrupt, "corp/team").expect("resolve");
            let b = db::resolve_governance_policy(&severed, "corp/team").expect("resolve");
            assert_eq!(
                serde_json::to_value(&a).expect("ser"),
                serde_json::to_value(&b).expect("ser"),
                "#4285: corrupt JSON must equal the #2503 severed outcome (ancestor={ancestor})"
            );
            assert!(a.is_some(), "never NoPolicy (ancestor={ancestor})");
        }
    }
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, GovernedAction as StoreAction, MemoryStore};

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    async fn live() -> Option<PostgresStore> {
        let url = pg_url()?;
        // #4285 F5 — a URL that IS set must connect: a stale tunnel or wrong
        // server may never turn a pg cell into a vacuous green skip. Only an
        // UNSET URL skips (reported on stderr, per the repo convention).
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                panic!("AI_MEMORY_TEST_POSTGRES_URL is set but PostgresStore::connect failed: {e}")
            }
        }
    }

    fn uniq(p: &str) -> String {
        format!("{p}-{}", &uuid::Uuid::new_v4().to_string()[..8])
    }

    async fn bind(store: &PostgresStore, ns: &str, governance: serde_json::Value) -> String {
        let ctx = CallerContext::for_agent(OWNER.to_string());
        let sid = store
            .store(&ctx, &standard_memory(&uniq("std-home-4285"), governance))
            .await
            .expect("store standard");
        store
            .set_namespace_standard(&ctx, ns, &sid, None)
            .await
            .expect("bind");
        sid
    }

    async fn store_decision(store: &PostgresStore, ns: &str, agent: &str) -> GovernanceDecision {
        set_active_permissions_mode(PermissionsMode::Enforce);
        store
            .enforce_governance_action(
                StoreAction::Store,
                ns,
                agent,
                None,
                None,
                &serde_json::json!({}),
                None,
            )
            .await
            .expect("enforce_governance_action")
    }

    #[tokio::test]
    async fn pg_corrupt_ancestor_resolves_to_owner_floor_not_none_4285() {
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let parent = uniq("corp-4285");
        bind(&store, &parent, corrupt_governance_json()).await;
        let p = store
            .resolve_governance_policy(&format!("{parent}/team"))
            .await
            .expect("resolve")
            .expect("#4285: corrupt standard must resolve to the severed floor, never None");
        assert_eq!(p.core.write, GovernanceLevel::Owner);
        assert_eq!(p.core.promote, GovernanceLevel::Owner);
        assert_eq!(p.core.delete, GovernanceLevel::Owner);
    }

    #[tokio::test]
    async fn pg_owner_write_not_locked_out_and_non_owner_refused_4285() {
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let parent = uniq("corp-4285");
        bind(&store, &parent, corrupt_governance_json()).await;
        let ns = format!("{parent}/team");
        assert!(matches!(
            store_decision(&store, &ns, OWNER).await,
            GovernanceDecision::Allow
        ));
        let d = store_decision(&store, &ns, STRANGER).await;
        assert!(
            !matches!(d, GovernanceDecision::Allow),
            "#4285: non-owner under a corrupt ancestor must hit the Owner floor; got {d:?}"
        );
    }

    /// A corrupt GLOBAL `*` standard: serialised + restored so it cannot leak
    /// into sibling cells sharing the database.
    #[tokio::test]
    async fn pg_corrupt_star_does_not_lock_out_owner_4285() {
        static STAR: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _g = STAR.lock().await;
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let url = pg_url().expect("url");
        let pool = sqlx::PgPool::connect(&url).await.expect("probe pool");
        let prior: Option<(Option<String>,)> =
            sqlx::query_as("SELECT standard_id FROM namespace_meta WHERE namespace = '*'")
                .fetch_optional(&pool)
                .await
                .expect("prior");
        bind(&store, "*", corrupt_governance_json()).await;
        let ns = uniq("star-child-4285");
        let owner_ok = store_decision(&store, &ns, OWNER).await;
        let stranger = store_decision(&store, &ns, STRANGER).await;
        match prior {
            Some((sid,)) => {
                let _ =
                    sqlx::query("UPDATE namespace_meta SET standard_id = $1 WHERE namespace = '*'")
                        .bind(sid)
                        .execute(&pool)
                        .await;
            }
            None => {
                let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = '*'")
                    .execute(&pool)
                    .await;
            }
        }
        assert!(matches!(owner_ok, GovernanceDecision::Allow));
        assert!(
            !matches!(stranger, GovernanceDecision::Allow),
            "{stranger:?}"
        );
    }

    #[tokio::test]
    async fn pg_census_lists_corrupt_standards_4285() {
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let bad = uniq("census-bad-4285");
        let good = uniq("census-good-4285");
        bind(&store, &bad, corrupt_governance_json()).await;
        bind(
            &store,
            &good,
            serde_json::to_value(strict_policy()).expect("ser"),
        )
        .await;
        let c = store.corrupt_governance_standards().await.expect("census");
        assert!(c.iter().any(|x| x.namespace == bad), "{c:?}");
        assert!(!c.iter().any(|x| x.namespace == good), "{c:?}");
    }

    #[tokio::test]
    async fn pg_operator_repairs_via_set_standard_4285() {
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let parent = uniq("corp-4285");
        bind(&store, &parent, corrupt_governance_json()).await;
        bind(
            &store,
            &parent,
            serde_json::to_value(strict_policy()).expect("ser"),
        )
        .await;
        let p = store
            .resolve_governance_policy(&format!("{parent}/team"))
            .await
            .expect("resolve")
            .expect("governed");
        assert_eq!(p.core.write, GovernanceLevel::Approve);
    }

    #[tokio::test]
    async fn pg_corrupt_json_resolves_identically_to_severed_4285() {
        let Some(store) = live().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_agent(OWNER.to_string());
        for ancestor in [false, true] {
            let root_c = uniq("pc-4285");
            let root_s = uniq("ps-4285");
            if ancestor {
                for r in [&root_c, &root_s] {
                    bind(
                        &store,
                        r,
                        serde_json::to_value(strict_policy()).expect("ser"),
                    )
                    .await;
                }
            }
            let leaf_c = format!("{root_c}/team");
            let leaf_s = format!("{root_s}/team");
            bind(&store, &leaf_c, corrupt_governance_json()).await;
            let sid = bind(
                &store,
                &leaf_s,
                serde_json::to_value(strict_policy()).expect("ser"),
            )
            .await;
            store.delete(&ctx, &sid).await.expect("reap");
            let a = store.resolve_governance_policy(&leaf_c).await.expect("a");
            let b = store.resolve_governance_policy(&leaf_s).await.expect("b");
            assert_eq!(
                serde_json::to_value(&a).expect("ser"),
                serde_json::to_value(&b).expect("ser"),
                "#4285: corrupt JSON must equal the #2503 severed outcome (ancestor={ancestor})"
            );
            assert!(a.is_some());
        }
    }
}
