// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4285 CHANGES-REQUESTED follow-up (v2): the corrupt-standard class closed
//! at every governance reader, not only the policy walk.
//!
//! * F1 — sqlite whole-`metadata` corruption (invalid JSON / array / string) of
//!   a standard is a SEVERED level, never `NoPolicy`; the census names it.
//! * F2 — the sibling walkers (`resolve_require_approval_above_depth`,
//!   `resolve_skill_promotion_min_depth`) treat a corrupt level as severed: the
//!   walk CONTINUES to the ancestor and the corrupt level contributes no key.
//! * F3 — no stored value is echoed into a log line, the census text or the
//!   get-standard response (serde's own error text echoes the offending token).
//! * F4 — get-standard / the capabilities rule summary report the effective
//!   (severed, Owner-floored) policy, not the permissive default.
//! * F5 — the pg cells fail loudly when a URL is set but unreachable.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ai_memory::config::{PermissionsMode, set_active_permissions_mode};
use ai_memory::models::{
    ConfidenceSource, GovernanceDecision, GovernanceLevel, GovernedAction, Memory, Tier,
    default_metadata,
};

const OWNER: &str = "ai:owner-4285v2";
const STRANGER: &str = "ai:stranger-4285v2";
/// A stand-in for a secret that must never be echoed.
const MARKER: &str = "sk-live-SECRETMARKER-4285";

fn standard_memory(governance: serde_json::Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".into(), serde_json::json!(OWNER));
        obj.insert("governance".into(), governance);
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "std-home".to_string(),
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

/// A `Write` sink the tracing subscriber can share; read back as a string.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut g) = self.0.lock() {
            g.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Capture {
    fn text(&self) -> String {
        self.0
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish()
    }
}

mod sqlite {
    use super::*;
    use ai_memory::db;
    use rusqlite::{Connection, params};

    fn open() -> Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn bind(
        conn: &Connection,
        ns: &str,
        parent: Option<&str>,
        governance: serde_json::Value,
    ) -> String {
        let sid = db::insert(conn, &standard_memory(governance)).expect("insert");
        db::set_namespace_standard(conn, ns, &sid, parent).expect("bind");
        sid
    }

    fn corrupt_raw(conn: &Connection, sid: &str, raw: &str) {
        conn.execute(
            "UPDATE memories SET metadata = ?1 WHERE id = ?2",
            params![raw, sid],
        )
        .expect("raw corrupt");
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

    /// The three whole-`metadata` corruption shapes the lenient row mapper
    /// folds into `{}`.
    const WHOLE_METADATA: [&str; 3] = ["{not json", "[1,2,3]", "\"just a string\""];

    // ---------------- F1 ----------------

    /// An intact `write: approve` standard whose WHOLE metadata cell is then
    /// corrupted must NOT read as "no policy": a stranger is not allowed and
    /// the severed floor applies. (Whole-metadata corruption also loses the stored owner id, so no
    /// agent is the owner: fail closed until an operator repairs the binding.)
    #[test]
    fn f1_whole_metadata_corruption_is_severed_not_nopolicy_4285() {
        for raw in WHOLE_METADATA {
            let conn = open();
            let sid = bind(&conn, "corp", None, serde_json::json!({"write": "approve"}));
            corrupt_raw(&conn, &sid, raw);
            let p = db::resolve_governance_policy(&conn, "corp/team")
                .expect("resolve")
                .unwrap_or_else(|| panic!("#4285 F1: metadata {raw:?} resolved to NoPolicy"));
            assert_eq!(p.core.write, GovernanceLevel::Owner, "raw={raw}");
            assert!(
                !matches!(
                    store_decision(&conn, "corp/team", STRANGER),
                    GovernanceDecision::Allow
                ),
                "#4285 F1: stranger must not be allowed under whole-metadata corruption ({raw})"
            );
        }
    }

    /// The census names a whole-metadata-corrupt standard instead of erroring
    /// ("census could not be read") or skipping it.
    #[test]
    fn f1_census_names_whole_metadata_corruption_4285() {
        let conn = open();
        for (i, raw) in WHOLE_METADATA.iter().enumerate() {
            let sid = bind(&conn, &format!("ns{i}"), None, serde_json::json!({}));
            corrupt_raw(&conn, &sid, raw);
        }
        let census = db::list_corrupt_governance_standards(&conn)
            .expect("#4285 F1: census must not error on invalid-JSON metadata");
        assert_eq!(census.len(), WHOLE_METADATA.len(), "{census:?}");
    }

    /// The reusable classifier (#4356 reuses it): non-object metadata is
    /// Corrupt, an object without `governance` is not.
    #[test]
    fn f1_classifier_is_total_over_metadata_shapes_4285() {
        use ai_memory::db::{StandardMetadata, classify_standard_metadata_text};
        for raw in ["{not json", "[1]", "\"s\"", "7", "true", "null"] {
            assert!(
                matches!(
                    classify_standard_metadata_text(raw),
                    StandardMetadata::Corrupt(_)
                ),
                "{raw}"
            );
        }
        assert!(matches!(
            classify_standard_metadata_text("{}"),
            StandardMetadata::NoGovernance
        ));
        assert!(matches!(
            classify_standard_metadata_text(r#"{"governance":{"write":"owner"}}"#),
            StandardMetadata::Policy(..)
        ));
        assert!(matches!(
            classify_standard_metadata_text(r#"{"governance":{"write":"bogus"}}"#),
            StandardMetadata::Corrupt(_)
        ));
    }

    // ---------------- F2 ----------------

    fn gate_chain(
        leaf_governance: serde_json::Value,
        parent_governance: serde_json::Value,
    ) -> Connection {
        let conn = open();
        bind(&conn, "gate", None, parent_governance);
        bind(&conn, "gate/leaf", Some("gate"), leaf_governance);
        conn
    }

    /// Parent gate + a corrupt leaf: the parent's gate is NOT dropped.
    #[test]
    fn f2_approval_depth_corrupt_leaf_continues_to_parent_4285() {
        let conn = gate_chain(
            serde_json::json!({"write": "bogus-4285"}),
            serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            Some(1),
            "#4285 F2: a corrupt leaf must not drop the parent's approval-depth gate"
        );
    }

    /// A corrupt leaf's OWN raw key is not honoured over the parent's.
    #[test]
    fn f2_approval_depth_corrupt_leaf_key_not_honoured_4285() {
        let conn = gate_chain(
            serde_json::json!({"write": "bogus-4285", "require_approval_above_depth": 99}),
            serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            Some(1),
            "#4285 F2: a field of an UNPARSEABLE policy must not be honoured"
        );
    }

    /// Whole-metadata corruption of the leaf behaves the same.
    #[test]
    fn f2_approval_depth_whole_metadata_corrupt_leaf_4285() {
        for raw in WHOLE_METADATA {
            let conn = open();
            bind(
                &conn,
                "gate",
                None,
                serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
            );
            let sid = bind(&conn, "gate/leaf", Some("gate"), serde_json::json!({}));
            corrupt_raw(&conn, &sid, raw);
            assert_eq!(
                db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
                Some(1),
                "raw={raw}"
            );
        }
    }

    /// GOD FINAL ruling (leaf-first-wins, #2542): a well-formed policy that
    /// OMITS the key means no gate and the walk STOPS; an explicit value at the
    /// nearest level decides; an explicit null keeps walking; a corrupt leaf
    /// under an omitting parent fails closed to 0.
    #[test]
    fn f2_approval_depth_omitted_key_stops_the_walk_4285() {
        let conn = gate_chain(
            serde_json::json!({"write": "owner"}),
            serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            None,
            "an omitting child is no gate and stops the walk"
        );
        let conn = gate_chain(
            serde_json::json!({"write": "any", "require_approval_above_depth": null}),
            serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            Some(1),
            "an explicit null keeps walking"
        );
        let conn = gate_chain(
            serde_json::json!({"write": "any", "require_approval_above_depth": 3}),
            serde_json::json!({"write": "any", "require_approval_above_depth": 1}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            Some(3)
        );
        let conn = gate_chain(
            serde_json::json!({"write": "bogus-4285"}),
            serde_json::json!({"write": "any"}),
        );
        assert_eq!(
            db::resolve_require_approval_above_depth(&conn, "gate/leaf").expect("resolve"),
            Some(0),
            "corrupt leaf under an omitting parent: rule 5 then rule 3"
        );
    }

    /// Sibling parity: an omitting child stops the skill-floor walk; null
    /// continues; a corrupt leaf under an omitting parent is u32::MAX.
    #[test]
    fn f2_skill_promotion_omitted_key_stops_the_walk_4285() {
        let conn = gate_chain(
            serde_json::json!({"write": "owner"}),
            serde_json::json!({"write": "any", "skill_promotion_min_depth": 5}),
        );
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn, "gate/leaf").expect("resolve"),
            None
        );
        let conn = gate_chain(
            serde_json::json!({"write": "any", "skill_promotion_min_depth": null}),
            serde_json::json!({"write": "any", "skill_promotion_min_depth": 5}),
        );
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn, "gate/leaf").expect("resolve"),
            Some(5)
        );
        let conn = gate_chain(
            serde_json::json!({"write": "bogus-4285"}),
            serde_json::json!({"write": "any"}),
        );
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn, "gate/leaf").expect("resolve"),
            Some(u32::MAX)
        );
    }

    #[test]
    fn f2_skill_promotion_corrupt_leaf_continues_to_parent_4285() {
        let conn = gate_chain(
            serde_json::json!({"write": "bogus-4285", "skill_promotion_min_depth": 0}),
            serde_json::json!({"write": "any", "skill_promotion_min_depth": 5}),
        );
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn, "gate/leaf").expect("resolve"),
            Some(5),
            "#4285 F2: corrupt leaf must neither drop the parent's floor nor override it"
        );
        let conn2 = open();
        bind(
            &conn2,
            "gate",
            None,
            serde_json::json!({"write": "any", "skill_promotion_min_depth": 5}),
        );
        let sid = bind(&conn2, "gate/leaf", Some("gate"), serde_json::json!({}));
        corrupt_raw(&conn2, &sid, "[1]");
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn2, "gate/leaf").expect("resolve"),
            Some(5)
        );
    }

    /// A corrupt (knob-only, untyped) level with NO explicit ancestor value is
    /// not silence: the promotion floor fails closed until repaired.
    #[test]
    fn f2_skill_promotion_corrupt_level_without_ancestor_fails_closed_4285() {
        let conn = open();
        bind(
            &conn,
            "solo",
            None,
            serde_json::json!({"skill_promotion_min_depth": 2}),
        );
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&conn, "solo").expect("resolve"),
            Some(u32::MAX)
        );
        // An unconfigured chain keeps the default (None).
        assert_eq!(
            db::resolve_skill_promotion_min_depth(&open(), "nothing").expect("resolve"),
            None
        );
    }

    // ---------------- F3 ----------------

    fn marker_governance() -> serde_json::Value {
        serde_json::json!({ "write": MARKER })
    }

    /// The stored value is in neither the WARN, the census text, nor the
    /// get-standard response; a 2 MB value does not amplify the log.
    #[test]
    fn f3_no_stored_value_echo_4285() {
        let conn = open();
        let big = "A".repeat(2_000_000);
        bind(&conn, "leak", None, marker_governance());
        bind(&conn, "big", None, serde_json::json!({ "write": big }));
        let cap = Capture::default();
        let (resolved, census, got) = tracing::subscriber::with_default(cap.subscriber(), || {
            let r1 = db::resolve_governance_policy(&conn, "leak/x").expect("resolve");
            let r2 = db::resolve_governance_policy(&conn, "big/x").expect("resolve");
            let census = db::list_corrupt_governance_standards(&conn).expect("census");
            let got = ai_memory::mcp::handle_namespace_get_standard(
                &conn,
                &serde_json::json!({"namespace": "leak"}),
                None,
            )
            .expect("get");
            ((r1, r2), census, got)
        });
        assert!(resolved.0.is_some() && resolved.1.is_some());
        let logs = cap.text();
        assert!(!logs.contains(MARKER), "#4285 F3: marker echoed into logs");
        assert!(
            logs.len() < 20_000,
            "#4285 F3: unbounded log amplification ({} bytes)",
            logs.len()
        );
        let census_text = format!("{census:?}");
        assert!(!census_text.contains(MARKER) && census_text.len() < 20_000);
        assert!(!got.to_string().contains(MARKER), "get-standard echoed it");
        assert!(got.to_string().len() < 20_000);
    }

    // ---------------- F4 ----------------

    /// get-standard on a corrupt standard reports the EFFECTIVE (floored)
    /// policy and `corrupt: true`, not `write: any`.
    #[test]
    fn f4_get_standard_reports_effective_floor_4285() {
        let conn = open();
        bind(&conn, "ns-gov", None, serde_json::json!({"write": "bogus"}));
        let r = ai_memory::mcp::handle_namespace_get_standard(
            &conn,
            &serde_json::json!({"namespace": "ns-gov"}),
            None,
        )
        .expect("get");
        assert_eq!(r["governance"]["write"], "owner", "{r}");
        assert_eq!(r["governance"]["corrupt"], true, "{r}");
    }

    #[test]
    fn f4_get_standard_whole_metadata_corrupt_reports_floor_4285() {
        for raw in WHOLE_METADATA {
            let conn = open();
            let sid = bind(&conn, "ns-whole", None, serde_json::json!({"write": "any"}));
            corrupt_raw(&conn, &sid, raw);
            let r = ai_memory::mcp::handle_namespace_get_standard(
                &conn,
                &serde_json::json!({"namespace": "ns-whole"}),
                None,
            )
            .expect("get");
            assert_eq!(r["governance"]["write"], "owner", "raw={raw} {r}");
            assert_eq!(r["governance"]["corrupt"], true, "raw={raw} {r}");
        }
    }

    /// The capabilities rule summary does not silently drop a corrupt
    /// standard (nor error on invalid-JSON metadata): it lists the floored
    /// effective policy.
    #[test]
    fn f4_rule_summary_lists_corrupt_standard_floored_4285() {
        let conn = open();
        bind(&conn, "a-bad", None, serde_json::json!({"write": "bogus"}));
        let sid = bind(&conn, "b-bad", None, serde_json::json!({}));
        corrupt_raw(&conn, &sid, "{not json");
        bind(&conn, "c-ok", None, serde_json::json!({"write": "approve"}));
        let rules = db::list_active_governance_policies(&conn)
            .expect("#4285: invalid-JSON metadata must not error the summary");
        let by_ns: std::collections::BTreeMap<_, _> = rules.into_iter().collect();
        assert_eq!(by_ns["a-bad"].core.write, GovernanceLevel::Owner);
        assert_eq!(by_ns["b-bad"].core.write, GovernanceLevel::Owner);
        assert_eq!(by_ns["c-ok"].core.write, GovernanceLevel::Approve);
    }
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    /// F5 — an UNSET url is an explicit, reported skip; a SET url that cannot
    /// connect is a hard failure, never a vacuous pass.
    async fn live() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let Some(url) = url else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => panic!("AI_MEMORY_TEST_POSTGRES_URL is set but connect failed: {e}"),
        }
    }

    fn uniq(p: &str) -> String {
        format!("{p}-{}", &uuid::Uuid::new_v4().to_string()[..8])
    }

    /// F3 on pg: neither the resolve WARN nor the census carries the value.
    #[tokio::test]
    async fn pg_f3_no_stored_value_echo_4285() {
        let Some(store) = live().await else {
            return;
        };
        let ctx = CallerContext::for_agent(OWNER.to_string());
        let ns = uniq("leak-4285");
        let sid = store
            .store(
                &ctx,
                &standard_memory(serde_json::json!({ "write": MARKER })),
            )
            .await
            .expect("store");
        store
            .set_namespace_standard(&ctx, &ns, &sid, None)
            .await
            .expect("bind");
        let cap = Capture::default();
        let _g = tracing::subscriber::set_default(cap.subscriber());
        let p = store
            .resolve_governance_policy(&format!("{ns}/x"))
            .await
            .expect("resolve")
            .expect("severed floor");
        assert_eq!(p.core.write, GovernanceLevel::Owner);
        let census = store.corrupt_governance_standards().await.expect("census");
        let mine: Vec<_> = census.iter().filter(|c| c.namespace == ns).collect();
        assert!(matches!(mine.as_slice(), [_]), "{census:?}");
        assert!(!format!("{mine:?}").contains(MARKER));
        assert!(
            !cap.text().contains(MARKER),
            "#4285 F3: pg WARN echoed value"
        );
    }
}
