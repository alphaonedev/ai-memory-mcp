// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8850: the curator reflection pass never republishes an observation to a
//! reader who could not read it.
//!
//! The pass read every source row with an operator context that bypassed the
//! scope filter, summarised whatever clustered, and stamped every reflection
//! `collective`. A `private` or `team` observation therefore reached every
//! agent in the deployment as the content of a curator reflection.
//!
//! Invariant, for every source scope and every reader, on both backends:
//!
//! 1. every reflection a reader can list cites only sources that reader can
//!    read itself;
//! 2. a source the curator identity cannot read never reaches the LLM;
//! 3. a reflection carries the most restrictive scope of its sources, so a
//!    cluster that includes a `private` row the curator owns yields a
//!    `private` reflection, not a `collective` one;
//! 4. a fully `collective` cluster still reflects (the fix is not a blanket
//!    refusal).
//!
//! The table is (source scope x reader); each scope case runs in its own
//! namespace so the cases cannot cluster together.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::sync::Mutex;

use ai_memory::autonomy::AutonomyLlm;
use ai_memory::curator::reflection_pass::{ReflectionPassReport, run_reflection_pass};
use ai_memory::identity::sentinels::AI_CURATOR;
use ai_memory::models::{Memory, MemoryKind, MemoryLinkRelation, Tier};
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError};

/// Owner of the non-curator sources. The `/` segments give it a team
/// ancestor (`acme/eng`), so a `team` row in that namespace is readable by
/// the owner and by nobody outside the subtree.
const OWNER: &str = "acme/eng/alice";
/// A reader outside the owner's subtree.
const OTHER: &str = "zeta/ops/bob";
/// Team namespace of [`OWNER`]; every case namespace is nested under it.
const TEAM_NS: &str = "acme/eng";
/// Shared token bag: every row of a case clusters with every other.
const TOPIC: &str = "kubernetes rolling deploy canary rollout strategy";
/// Rows per case, above the pass's three-member cluster floor.
const CLUSTER_ROWS: usize = 4;
/// `access_count` above the pass's co-recall floor, so every row is eligible.
const CO_RECALLED: i64 = 2;
/// Canned LLM summary.
const SUMMARY: &str = "pattern summary 8850";
/// Upper bound on rows read back per reader listing.
const READBACK_LIMIT: usize = 100;

/// One row of the scope table.
#[derive(Clone, Copy)]
struct Case {
    /// Case label, also the namespace leaf and the content marker.
    label: &'static str,
    /// `(owner, scope)` per seeded row, in seed order.
    rows: [(&'static str, &'static str); CLUSTER_ROWS],
    /// Reflections the pass must persist.
    persisted: usize,
    /// Scope stamped on the persisted reflection, when one is expected.
    reflection_scope: Option<&'static str>,
    /// Whether the content of the non-collective rows may reach the LLM
    /// (only when the curator identity itself can read them).
    llm_may_see_restricted: bool,
}

const CASES: [Case; 4] = [
    Case {
        label: "private-8850",
        rows: [(OWNER, "private"); CLUSTER_ROWS],
        persisted: 0,
        reflection_scope: None,
        llm_may_see_restricted: false,
    },
    Case {
        label: "team-8850",
        rows: [(OWNER, "team"); CLUSTER_ROWS],
        persisted: 0,
        reflection_scope: None,
        llm_may_see_restricted: false,
    },
    Case {
        label: "collective-8850",
        rows: [(OWNER, "collective"); CLUSTER_ROWS],
        persisted: 1,
        reflection_scope: Some("collective"),
        llm_may_see_restricted: true,
    },
    Case {
        label: "curator-private-mix-8850",
        rows: [
            (OWNER, "collective"),
            (AI_CURATOR, "private"),
            (OWNER, "collective"),
            (AI_CURATOR, "private"),
        ],
        persisted: 1,
        reflection_scope: Some("private"),
        llm_may_see_restricted: true,
    },
];

/// Records every `(title, content)` the pass hands to the LLM.
struct StubLlm {
    seen: Mutex<Vec<(String, String)>>,
}

impl StubLlm {
    fn new() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().expect("stub llm lock").clone()
    }
}

impl AutonomyLlm for StubLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> anyhow::Result<String> {
        self.seen
            .lock()
            .expect("stub llm lock")
            .extend(memories.iter().cloned());
        Ok(SUMMARY.to_string())
    }
}

/// Content marker of a row that is NOT collective, so a leak is greppable.
fn restricted_marker(label: &str) -> String {
    format!("restricted-{label}")
}

/// The seeded observations of `case` in namespace `ns`.
fn case_rows(case: &Case, ns: &str) -> Vec<Memory> {
    let now = chrono::Utc::now().to_rfc3339();
    case.rows
        .iter()
        .enumerate()
        .map(|(idx, (owner, scope))| {
            let marker = if *scope == "collective" {
                format!("open-{}", case.label)
            } else {
                restricted_marker(case.label)
            };
            // `Memory` is `#[non_exhaustive]`: build from the default.
            let mut row = Memory::default();
            row.id = uuid::Uuid::new_v4().to_string();
            row.tier = Tier::Long;
            row.namespace = ns.to_string();
            row.title = format!("observation {TOPIC} {} #{idx}", case.label);
            row.content = format!("{TOPIC} {TOPIC} {TOPIC} {marker} row {idx}");
            row.priority = 5;
            row.confidence = 1.0;
            row.source = "api".to_string();
            row.access_count = CO_RECALLED;
            row.created_at.clone_from(&now);
            row.updated_at.clone_from(&now);
            row.metadata = serde_json::json!({"agent_id": owner, "scope": scope});
            row.memory_kind = MemoryKind::Observation;
            row
        })
        .collect()
}

/// Every reader of a case: the two tenant agents and the curator itself.
const READERS: [&str; 3] = [OWNER, OTHER, AI_CURATOR];

/// Assert the #8850 invariant for one case after the pass ran.
async fn assert_case(
    store: &dyn MemoryStore,
    case: &Case,
    ns: &str,
    llm: &StubLlm,
    report: &ReflectionPassReport,
    backend: &str,
) {
    let where_ = format!("#8850 [{backend}] case {}", case.label);

    // (2) a source the curator could not read never reached the LLM.
    if !case.llm_may_see_restricted {
        let marker = restricted_marker(case.label);
        let leaked: Vec<String> = llm
            .seen()
            .into_iter()
            .filter(|(_, content)| content.contains(&marker))
            .map(|(title, _)| title)
            .collect();
        assert!(
            leaked.is_empty(),
            "{where_}: rows the curator cannot read were sent to the LLM: {leaked:?}"
        );
    }

    assert_eq!(
        report.reflections_persisted, case.persisted,
        "{where_}: reflections persisted (report errors: {:?})",
        report.errors
    );

    // `Filter` is `#[non_exhaustive]`: build from the constructor twin.
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    filter.limit = READBACK_LIMIT;
    for reader in READERS {
        let ctx = CallerContext::for_agent(reader);
        let listed = store.list(&ctx, &filter).await.expect("reader list");
        for reflection in listed
            .iter()
            .filter(|m| m.memory_kind == MemoryKind::Reflection)
        {
            // (3) the stamped scope is the narrowest source scope.
            let stamped = reflection
                .metadata
                .get("scope")
                .and_then(serde_json::Value::as_str);
            assert_eq!(
                stamped, case.reflection_scope,
                "{where_}: reflection {} scope as listed by {reader}",
                reflection.id
            );
            // (1) every cited source is readable by this reader.
            let links = store
                .get_links_for_anchor(&reflection.id)
                .await
                .expect("reflection links");
            let sources: Vec<&str> = links
                .iter()
                .filter(|l| {
                    l.source_id == reflection.id && l.relation == MemoryLinkRelation::ReflectsOn
                })
                .map(|l| l.target_id.as_str())
                .collect();
            assert!(
                !sources.is_empty(),
                "{where_}: reflection {} has no reflects_on edge",
                reflection.id
            );
            for source in sources {
                match store.get(&ctx, source).await {
                    Ok(_) => {}
                    Err(StoreError::NotFound { .. }) => panic!(
                        "{where_}: reader {reader} can list reflection {} but cannot read its \
                         source {source}: the reflection republishes a row the reader may not see",
                        reflection.id
                    ),
                    Err(e) => panic!("{where_}: get source {source} as {reader}: {e}"),
                }
            }
        }
    }

    // (4) liveness: a persisted reflection is visible to the curator, and a
    // collective one to every reader.
    if case.persisted > 0 {
        let curator_view = store
            .list(&CallerContext::for_agent(AI_CURATOR), &filter)
            .await
            .expect("curator list");
        let reflections = curator_view
            .iter()
            .filter(|m| m.memory_kind == MemoryKind::Reflection)
            .count();
        assert_eq!(
            reflections, case.persisted,
            "{where_}: reflections the curator can read back"
        );
    }
    if case.reflection_scope == Some("private") {
        let other_view = store
            .list(&CallerContext::for_agent(OTHER), &filter)
            .await
            .expect("other list");
        assert!(
            other_view
                .iter()
                .all(|m| m.memory_kind != MemoryKind::Reflection),
            "{where_}: a reflection over a private source is listed to {OTHER}"
        );
    }
}

/// Run the pass over one namespace as the default (keyless) curator.
async fn run_pass(store: &dyn MemoryStore, ns: &str, llm: &StubLlm) -> ReflectionPassReport {
    run_reflection_pass(store, llm, None, Some(ns), None, false, |_| true)
        .await
        .expect("run_reflection_pass")
}

#[tokio::test]
async fn reflection_never_widens_source_visibility_sqlite_8850() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("reflection-visibility-8850.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        for case in &CASES {
            let ns = format!("{TEAM_NS}/{}", case.label);
            for row in case_rows(case, &ns) {
                ai_memory::db::insert(&conn, &row).expect("seed observation");
            }
        }
    }
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    for case in &CASES {
        let ns = format!("{TEAM_NS}/{}", case.label);
        let llm = StubLlm::new();
        let report = run_pass(&store, &ns, &llm).await;
        assert_case(&store, case, &ns, &llm, &report, "sqlite").await;
    }
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{CASES, StubLlm, TEAM_NS, assert_case, case_rows, run_pass};
    use ai_memory::store::postgres::PostgresStore;

    /// Insert a seeded row directly so `access_count` and the owner metadata
    /// land exactly as given (the write funnel resets the former).
    async fn raw_insert(store: &PostgresStore, row: &ai_memory::models::Memory) {
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, source, priority, \
                                   confidence, access_count, created_at, updated_at, metadata) \
             VALUES ($1, 'long', $2, $3, $4, $5, $6, $7, $8, now(), now(), $9::jsonb)",
        )
        .bind(&row.id)
        .bind(&row.namespace)
        .bind(&row.title)
        .bind(&row.content)
        .bind(&row.source)
        .bind(row.priority)
        .bind(row.confidence)
        .bind(row.access_count)
        .bind(row.metadata.to_string())
        .execute(store.pool())
        .await
        .expect("raw insert");
    }

    async fn cleanup(store: &PostgresStore, ns_root: &str) {
        let _ = sqlx::query(
            "DELETE FROM memory_links WHERE source_id IN \
             (SELECT id FROM memories WHERE namespace LIKE $1) \
             OR target_id IN (SELECT id FROM memories WHERE namespace LIKE $1)",
        )
        .bind(format!("{ns_root}/%"))
        .execute(store.pool())
        .await;
        let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
            .bind(format!("{ns_root}/%"))
            .execute(store.pool())
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reflection_never_widens_source_visibility_pg_8850() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #8850 live-pg cell");
        };
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        // A uuid leaf keeps concurrent lanes on one cluster apart while every
        // case namespace stays inside the owner's team subtree.
        let ns_root = format!("{TEAM_NS}/{}", uuid::Uuid::new_v4().simple());
        for case in &CASES {
            let ns = format!("{ns_root}/{}", case.label);
            for row in case_rows(case, &ns) {
                raw_insert(&store, &row).await;
            }
        }
        for case in &CASES {
            let ns = format!("{ns_root}/{}", case.label);
            let llm = StubLlm::new();
            let report = run_pass(&store, &ns, &llm).await;
            assert_case(&store, case, &ns, &llm, &report, "postgres").await;
        }
        cleanup(&store, &ns_root).await;
    }
}
