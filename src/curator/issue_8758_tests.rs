// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8758 — no autonomous curator pass combines rows that differ in
//! `(namespace, owner, scope)` in one cluster, one LLM prompt or one derived
//! record, and every derived or rollback row is never wider than its
//! narrowest source.
//!
//! The tables below are driven over owner x scope x namespace with a
//! recording stub LLM (no network, no keys). The scope oracle here is written
//! independently of `crate::visibility` so the test does not share a bug with
//! the code it checks: an absent scope, `private` and an unknown token are one
//! arm, `collective` and the legacy `shared` are one arm, and `team` / `unit` /
//! `org` are three distinct arms.

use crate::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

use super::cluster::ConsolidationClustering;

/// Two owners that share a namespace in the audit scenario.
pub(crate) const OWNERS: [&str; 2] = ["ai:alice-8758", "ai:bob-8758"];
/// Every scope arm, plus the two spellings that alias an arm.
pub(crate) const SCOPES: [Option<&str>; 7] = [
    None,
    Some("private"),
    Some("team"),
    Some("unit"),
    Some("org"),
    Some("collective"),
    Some("shared"),
];
/// Two sibling namespaces (cross-namespace merging was already refused).
pub(crate) const NAMESPACES: [&str; 2] = ["proj8758/app", "proj8758/other"];
/// One body for every row, so content similarity never separates them: only
/// the partition may.
const BODY: &str = "kubernetes rolling canary deploy strategy notes for the payments service";
/// Embedding width for the pure clustering table.
const DIM: usize = 8;
/// The canonical private token stamped on curator-written rows.
pub(crate) const PRIVATE: &str = "private";

/// Independent scope oracle: the visibility arm a raw scope token selects.
fn arm(scope: Option<&str>) -> u8 {
    match scope {
        Some("team") => 1,
        Some("unit") => 2,
        Some("org") => 3,
        Some("collective" | "shared") => 9,
        // Absent, `private`, or an unknown token: owner-private.
        _ => 0,
    }
}

/// One cell of the owner x scope x namespace grid.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cell {
    pub(crate) owner: &'static str,
    pub(crate) scope: Option<&'static str>,
    pub(crate) namespace: &'static str,
}

impl Cell {
    fn same_partition(self, other: Self) -> bool {
        self.namespace == other.namespace
            && self.owner == other.owner
            && arm(self.scope) == arm(other.scope)
    }

    fn label(self) -> String {
        format!(
            "{}|{}|{}",
            self.namespace,
            self.owner,
            self.scope.unwrap_or("<absent>")
        )
    }
}

pub(crate) fn grid() -> Vec<Cell> {
    let mut cells = Vec::new();
    for namespace in NAMESPACES {
        for owner in OWNERS {
            for scope in SCOPES {
                cells.push(Cell {
                    owner,
                    scope,
                    namespace,
                });
            }
        }
    }
    cells
}

pub(crate) fn memory(
    id: &str,
    title: &str,
    cell: Cell,
    kind: MemoryKind,
    access_count: i64,
) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::json!({ crate::META_KEY_AGENT_ID: cell.owner });
    if let Some(scope) = cell.scope {
        metadata[crate::META_KEY_SCOPE] = serde_json::Value::String(scope.to_string());
    }
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Long,
        namespace: cell.namespace.to_string(),
        title: title.to_string(),
        content: format!("{BODY} [{title}]"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: kind,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

#[cfg(feature = "sal")]
pub(crate) fn scope_of(m: &Memory) -> Option<&str> {
    m.metadata
        .get(crate::META_KEY_SCOPE)
        .and_then(serde_json::Value::as_str)
}

/// Assert every pair of grid cells clusters iff the pair shares a partition.
/// `clusters_pair` runs the clustering site under test over `[a, a2, b]`
/// (`a2` is a second row in `a`'s cell so a pass with a 3-member floor can
/// still form a cluster) and reports whether `a` and `b` landed together.
pub(crate) fn assert_pair_table(site: &str, mut clusters_pair: impl FnMut(Cell, Cell) -> bool) {
    let cells = grid();
    let mut wrong = Vec::new();
    let mut together = 0_usize;
    for (i, &a) in cells.iter().enumerate() {
        for &b in &cells[i + 1..] {
            let merged = clusters_pair(a, b);
            if merged {
                together += 1;
            }
            if merged != a.same_partition(b) {
                wrong.push(format!("{} + {} merged={merged}", a.label(), b.label()));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "#8758 {site}: {} of the owner x scope x namespace pairs broke the \
         partition invariant; first: {:?}",
        wrong.len(),
        &wrong[..wrong.len().min(6)]
    );
    // Positive control: same-partition pairs (absent + private, collective +
    // shared) still merge, so the table cannot pass by never clustering.
    assert!(together > 0, "#8758 {site}: no pair ever clustered");
}

#[test]
fn issue_8758_cluster_memories_never_crosses_owner_or_scope() {
    let clustering = ConsolidationClustering::new();
    assert_pair_table("cluster_memories", |a, b| {
        let rows = [
            memory("a", "a", a, MemoryKind::Observation, 0),
            memory("a2", "a2", a, MemoryKind::Observation, 0),
            memory("b", "b", b, MemoryKind::Observation, 0),
        ];
        let embeddings = vec![Some(vec![1.0_f32; DIM]); rows.len()];
        let spaces = vec![Some("space-8758".to_string()); rows.len()];
        clustering
            .cluster_memories(&rows, &embeddings, &spaces)
            .iter()
            .any(|c| c.iter().any(|id| id == "a") && c.iter().any(|id| id == "b"))
    });
}

#[test]
fn issue_8758_contradiction_sibling_is_same_partition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = crate::db::open(&dir.path().join("t.db")).expect("db::open");
    let ns = "proj8758/contradiction";
    let alice_private = Cell {
        owner: OWNERS[0],
        scope: Some(PRIVATE),
        namespace: ns,
    };
    let bob_collective = Cell {
        owner: OWNERS[1],
        scope: Some("collective"),
        namespace: ns,
    };
    let target = memory(
        "target-8758",
        "alice target",
        alice_private,
        MemoryKind::Observation,
        0,
    );
    crate::db::insert(&conn, &target).expect("insert target");
    crate::db::insert(
        &conn,
        &memory(
            "bob-8758",
            "bob collective",
            bob_collective,
            MemoryKind::Observation,
            0,
        ),
    )
    .expect("insert bob");
    let sibling = super::candidates::adjacent_memory(&conn, &target).expect("adjacent_memory");
    assert!(
        sibling.is_none(),
        "#8758: the contradiction pair must never join another owner's or \
         scope's row; got {:?}",
        sibling.map(|m| m.id)
    );
    // Positive control: a row in the target's own partition is still found.
    crate::db::insert(
        &conn,
        &memory(
            "alice2-8758",
            "alice second",
            alice_private,
            MemoryKind::Observation,
            0,
        ),
    )
    .expect("insert alice2");
    let sibling = super::candidates::adjacent_memory(&conn, &target).expect("adjacent_memory");
    assert_eq!(sibling.map(|m| m.id).as_deref(), Some("alice2-8758"));
}

#[test]
fn issue_8758_rollback_rows_are_explicitly_private() {
    for scope in SCOPES {
        let cell = Cell {
            owner: OWNERS[0],
            scope,
            namespace: NAMESPACES[0],
        };
        let originals = [
            memory("r1", "r1", cell, MemoryKind::Observation, 0),
            memory("r2", "r2", cell, MemoryKind::Observation, 0),
        ];
        let write_ahead = crate::autonomy::build_write_ahead_memory(&originals).expect("wa");
        let (_, committed) =
            crate::autonomy::commit_write_ahead_patch(&originals, "result").expect("commit");
        let forget =
            crate::autonomy::build_rollback_memory(&crate::autonomy::RollbackEntry::Forget {
                snapshot: originals[0].clone(),
            })
            .expect("forget");
        for (what, meta) in [
            ("write-ahead", &write_ahead.metadata),
            ("commit", &committed),
            ("forget", &forget.metadata),
        ] {
            assert_eq!(
                meta.get(crate::META_KEY_SCOPE)
                    .and_then(serde_json::Value::as_str),
                Some(PRIVATE),
                "#8758: a {what} rollback row from a {:?} source must carry an \
                 explicit private scope, never NULL and never wider",
                scope
            );
        }
    }
}

/// Recording stub: every summarise prompt is kept as the titles it carried.
#[cfg(feature = "sal")]
#[derive(Default)]
pub(crate) struct RecordingLlm {
    prompts: std::sync::Mutex<Vec<Vec<String>>>,
}

#[cfg(feature = "sal")]
impl RecordingLlm {
    pub(crate) fn prompts(&self) -> Vec<Vec<String>> {
        self.prompts.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

#[cfg(feature = "sal")]
impl crate::autonomy::AutonomyLlm for RecordingLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
    fn detect_contradiction(&self, a: &str, b: &str) -> anyhow::Result<bool> {
        if let Ok(mut p) = self.prompts.lock() {
            p.push(vec![a.to_string(), b.to_string()]);
        }
        Ok(false)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> anyhow::Result<String> {
        if let Ok(mut p) = self.prompts.lock() {
            p.push(memories.iter().map(|(t, _)| t.clone()).collect());
        }
        Ok("synthesised summary for issue 8758".to_string())
    }
}

#[cfg(feature = "sal")]
mod sal {
    use super::*;

    use crate::curator::compaction::ConsolidationPass;
    use crate::store::{CallerContext, MemoryStore};

    fn open_store() -> (crate::store::sqlite::SqliteStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            crate::store::sqlite::SqliteStore::open(&dir.path().join("t.db")).expect("open");
        (store, dir)
    }

    /// Seed `rows` through the SAL with a shared embedding and return them as
    /// read back. The owner precondition is checked so a store that rewrote
    /// `metadata.agent_id` cannot make the table vacuous.
    async fn seed(store: &dyn MemoryStore, rows: &[Memory]) -> Vec<Memory> {
        let ctx = CallerContext::for_admin(crate::identity::sentinels::AI_CURATOR);
        let space = crate::embeddings::embedding_space_fingerprint("space-8758");
        let mut out = Vec::new();
        for row in rows {
            store.store(&ctx, row).await.expect("store");
            store
                .update_embedding(&ctx, &row.id, Some(&vec![1.0; 384]), &space)
                .await
                .expect("embedding");
            let back = store.get(&ctx, &row.id).await.expect("get");
            assert_eq!(
                back.metadata.get(crate::META_KEY_AGENT_ID),
                row.metadata.get(crate::META_KEY_AGENT_ID),
                "precondition: the store kept the seeded owner"
            );
            out.push(back);
        }
        out
    }

    /// Fail when any recorded prompt carries titles from two partitions.
    fn assert_prompts_single_partition(prompts: &[Vec<String>], partition_of: &[(String, String)]) {
        for prompt in prompts {
            let parts: std::collections::BTreeSet<&str> = prompt
                .iter()
                .filter_map(|t| {
                    partition_of
                        .iter()
                        .find(|(title, _)| t == title || t.ends_with(&format!("[{title}]")))
                        .map(|(_, p)| p.as_str())
                })
                .collect();
            assert!(
                parts.len() <= 1,
                "#8758: one LLM prompt mixed partitions {parts:?}"
            );
        }
    }

    /// The audit scenario (#8758): one owner's private row and another
    /// owner's collective row in one namespace with identical bodies and
    /// vectors. Then a same-partition positive control that must still merge
    /// and must write an explicitly private rollback row.
    async fn audit_matrix(store: &dyn MemoryStore) {
        let ns: &'static str =
            Box::leak(format!("audit8758/{}", uuid::Uuid::new_v4()).into_boxed_str());
        let alice = Cell {
            owner: OWNERS[0],
            scope: Some(PRIVATE),
            namespace: ns,
        };
        let bob = Cell {
            owner: OWNERS[1],
            scope: Some("collective"),
            namespace: ns,
        };
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let a_title = format!("alice private {tag}");
        let b_title = format!("bob collective {tag}");
        let rows = [
            memory(
                &uuid::Uuid::new_v4().to_string(),
                &a_title,
                alice,
                MemoryKind::Observation,
                0,
            ),
            memory(
                &uuid::Uuid::new_v4().to_string(),
                &b_title,
                bob,
                MemoryKind::Observation,
                0,
            ),
        ];
        let candidates = seed(store, &rows).await;
        let llm = RecordingLlm::default();
        let report = ConsolidationPass::new(store, &llm, false)
            .run(&candidates)
            .await
            .expect("run");
        let partition_of = vec![
            (a_title.clone(), "alice-private".to_string()),
            (b_title.clone(), "bob-collective".to_string()),
        ];
        assert_prompts_single_partition(&llm.prompts(), &partition_of);
        assert_eq!(
            report.memories_consolidated, 0,
            "#8758: rows of two owners and scopes must never be merged"
        );
        assert_eq!(report.rollback_entries_written, 0, "#8758: no rollback row");

        // Positive control: two rows of one partition still consolidate.
        let a2_title = format!("alice private second {tag}");
        let more = [memory(
            &uuid::Uuid::new_v4().to_string(),
            &a2_title,
            alice,
            MemoryKind::Observation,
            0,
        )];
        let mut same = vec![candidates[0].clone()];
        same.extend(seed(store, &more).await);
        let report = ConsolidationPass::new(store, &llm, false)
            .run(&same)
            .await
            .expect("run");
        assert_eq!(report.memories_consolidated, 2, "same partition merges");
        let ctx = CallerContext::for_admin(crate::identity::sentinels::AI_CURATOR);
        let filter = crate::store::Filter {
            namespace: Some("_curator/rollback".to_string()),
            limit: 1000,
            ..crate::store::Filter::default()
        };
        let rollback: Vec<Memory> = store
            .list(&ctx, &filter)
            .await
            .expect("list rollback")
            .into_iter()
            .filter(|m| m.content.contains(&tag))
            .collect();
        assert!(!rollback.is_empty(), "the merge wrote its rollback row");
        for row in &rollback {
            assert!(
                !row.content.contains(&b_title),
                "#8758: a rollback row carries another owner's row"
            );
            assert_eq!(scope_of(row), Some(PRIVATE), "#8758: rollback scope");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issue_8758_audit_private_and_collective_never_share_a_prompt_sqlite() {
        let _dag = crate::test_support::no_lineage_dag_guard();
        let (store, _dir) = open_store();
        audit_matrix(&store).await;
    }

    /// Skips only when the URL is unset; a set but unreachable URL fails.
    #[cfg(feature = "sal-postgres")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issue_8758_audit_private_and_collective_never_share_a_prompt_postgres() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            return;
        };
        let _dag = crate::test_support::no_lineage_dag_guard();
        let store = crate::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect");
        audit_matrix(&store).await;
    }

    /// The sqlite autonomy Pass-1 (`run_autonomy_passes`) on the same scenario.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issue_8758_audit_autonomy_pass_never_mixes_partitions() {
        let _dag = crate::test_support::no_lineage_dag_guard();
        let (store, dir) = open_store();
        let ns = "audit8758/autonomy";
        let a = Cell {
            owner: OWNERS[0],
            scope: Some(PRIVATE),
            namespace: ns,
        };
        let b = Cell {
            owner: OWNERS[1],
            scope: Some("collective"),
            namespace: ns,
        };
        let rows = [
            memory(
                "auto-a",
                "alice private auto",
                a,
                MemoryKind::Observation,
                0,
            ),
            memory(
                "auto-b",
                "bob collective auto",
                b,
                MemoryKind::Observation,
                0,
            ),
        ];
        let candidates = seed(&store, &rows).await;
        let conn = crate::db::open(&dir.path().join("t.db")).expect("db::open");
        let llm = RecordingLlm::default();
        let report =
            crate::autonomy::run_autonomy_passes(&conn, &llm, &candidates, false, false, 64, None);
        let partition_of = vec![
            ("alice private auto".to_string(), "a".to_string()),
            ("bob collective auto".to_string(), "b".to_string()),
        ];
        assert_prompts_single_partition(&llm.prompts(), &partition_of);
        assert_eq!(
            report.memories_consolidated, 0,
            "#8758: no cross-owner merge"
        );
        let found = crate::autonomy::find_consolidation_clusters(&conn, &candidates);
        assert!(found.is_empty(), "#8758: no cross-owner cluster: {found:?}");
    }
}
