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
// `Memory` is `#[non_exhaustive]`, so rows are built from the default and
// assigned in place (precedent: tests/inbox_unread_pushdown_3463.rs).
#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use std::sync::Mutex;

use ai_memory::autonomy::AutonomyLlm;
use ai_memory::curator::reflection_pass::{
    ReflectionPassReport, VISIBILITY_SKIPPED_LOG, run_reflection_pass,
};
use ai_memory::db::{DERIVED_REFUSAL_PREFIX, ReflectError, ReflectInput};
use ai_memory::identity::keypair::DAEMON_KEYPAIR_LABEL;
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
            observation_row(
                ns,
                case.label,
                idx,
                &marker,
                serde_json::json!({"agent_id": owner, "scope": scope}),
                &now,
            )
        })
        .collect()
}

/// One clustering observation in `ns` with the given `metadata`.
fn observation_row(
    ns: &str,
    label: &str,
    idx: usize,
    marker: &str,
    metadata: serde_json::Value,
    now: &str,
) -> Memory {
    // `Memory` is `#[non_exhaustive]`: build from the default.
    let mut row = Memory::default();
    row.id = uuid::Uuid::new_v4().to_string();
    row.tier = Tier::Long;
    row.namespace = ns.to_string();
    row.title = format!("observation {TOPIC} {label} #{idx}");
    row.content = format!("{TOPIC} {TOPIC} {TOPIC} {marker} row {idx}");
    row.priority = 5;
    row.confidence = 1.0;
    row.source = "api".to_string();
    row.access_count = CO_RECALLED;
    row.created_at = now.to_string();
    row.updated_at = now.to_string();
    row.metadata = metadata;
    row.memory_kind = MemoryKind::Observation;
    row
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

/// One row of the `narrowest_scope` table: the `metadata.scope` value of each
/// source (`None` = the key is absent) and the scope a derived row must carry.
type ScopeRow = (&'static [Option<&'static str>], &'static str);

/// Every scope, the absent key, an unrecognised token, a legacy broad token,
/// and the empty set, each against the narrowest result the read path implies.
const NARROWEST_TABLE: [ScopeRow; 12] = [
    (&[], "private"),
    (&[None], "private"),
    (&[Some("not-a-scope-8850")], "private"),
    (&[Some("collective")], "collective"),
    (&[Some("shared")], "collective"),
    (&[Some("org"), Some("collective")], "org"),
    (&[Some("collective"), Some("unit"), Some("org")], "unit"),
    (&[Some("org"), Some("team"), Some("unit")], "team"),
    (&[Some("collective"), Some("team")], "team"),
    (&[Some("collective"), None], "private"),
    (
        &[Some("team"), Some("private"), Some("collective")],
        "private",
    ),
    (&[Some("collective"), Some("bogus-8850")], "private"),
];

/// Upper bound on the large-input row count for the linear-cost check.
const LARGE_SOURCE_ROWS: usize = 100_000;

/// Wall-clock ceiling for classifying [`LARGE_SOURCE_ROWS`] sources.
const LARGE_SOURCE_CEILING: std::time::Duration = std::time::Duration::from_secs(5);

fn scoped_row(scope: Option<&str>) -> Memory {
    let mut row = Memory::default();
    row.id = uuid::Uuid::new_v4().to_string();
    row.namespace = format!("{TEAM_NS}/narrowest-8850");
    row.metadata = match scope {
        Some(s) => serde_json::json!({"agent_id": OWNER, "scope": s}),
        None => serde_json::json!({"agent_id": OWNER}),
    };
    row
}

#[test]
fn narrowest_scope_table_8850() {
    for (scopes, expected) in NARROWEST_TABLE {
        let rows: Vec<Memory> = scopes.iter().map(|s| scoped_row(*s)).collect();
        assert_eq!(
            ai_memory::visibility::narrowest_scope(&rows).as_str(),
            expected,
            "#8850: narrowest scope of {scopes:?}"
        );
        // Order never matters.
        let reversed: Vec<Memory> = rows.into_iter().rev().collect();
        assert_eq!(
            ai_memory::visibility::narrowest_scope(&reversed).as_str(),
            expected,
            "#8850: narrowest scope of reversed {scopes:?}"
        );
    }
}

#[test]
fn narrowest_scope_is_linear_on_large_input_8850() {
    let mut rows: Vec<Memory> = (0..LARGE_SOURCE_ROWS)
        .map(|_| scoped_row(Some("collective")))
        .collect();
    rows.push(scoped_row(Some("team")));
    let started = std::time::Instant::now();
    let scope = ai_memory::visibility::narrowest_scope(&rows);
    assert!(
        started.elapsed() < LARGE_SOURCE_CEILING,
        "#8850: {} rows took {:?}",
        rows.len(),
        started.elapsed()
    );
    assert_eq!(
        scope.as_str(),
        "team",
        "#8850: one team row narrows the set"
    );
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

// ---------------------------------------------------------------------------
// #9185 round 1: Y-8 + Y-9 (default-scope negative + skipped count), L-F
// (write-time re-verify inside the reflect transaction), M-D (persist refusal
// for a source narrowed or moved between summarize and persist), L-G (the
// pass with the daemon keypair loaded). Each runs on sqlite and postgres.
// ---------------------------------------------------------------------------

/// In-memory tracing sink (precedent: the `WarnSink9185` capture in
/// src/forensic/bundle.rs). Scoped to one future with `with_subscriber`, so no
/// process-global subscriber is installed.
#[derive(Clone, Default)]
struct LogSink(std::sync::Arc<Mutex<Vec<u8>>>);

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log sink lock")).into_owned()
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log sink lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run the pass over `ns` with an INFO capture scoped to that one future.
async fn run_pass_captured(
    store: &dyn MemoryStore,
    ns: &str,
    llm: &dyn AutonomyLlm,
) -> (ReflectionPassReport, String) {
    use tracing::instrument::WithSubscriber;
    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let report = run_reflection_pass(store, llm, None, Some(ns), None, false, |_| true)
        .with_subscriber(subscriber)
        .await
        .expect("run_reflection_pass");
    (report, sink.text())
}

/// Content marker of the Y-8 default-scope rows, so a leak is greppable.
const DEFAULT_SCOPE_MARKER: &str = "default-scope-9185";

/// Y-8 fixtures: [`OWNER`]'s rows with NO `scope` key (the default
/// deployment shape: owner-private), never stamped collective.
fn default_scope_rows(ns: &str) -> Vec<Memory> {
    let now = chrono::Utc::now().to_rfc3339();
    (0..CLUSTER_ROWS)
        .map(|idx| {
            observation_row(
                ns,
                "default-scope-9185",
                idx,
                DEFAULT_SCOPE_MARKER,
                serde_json::json!({"agent_id": OWNER}),
                &now,
            )
        })
        .collect()
}

/// Reflections in `ns` listed by any reader (the curator, the owner, another
/// tenant). A reflection the pass writes is owned by the curator, so the
/// curator listing finds it whatever scope it carries.
async fn reflections_in(store: &dyn MemoryStore, ns: &str) -> usize {
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    filter.limit = READBACK_LIMIT;
    let mut ids = std::collections::BTreeSet::new();
    for reader in READERS {
        let listed = store
            .list(&CallerContext::for_agent(reader), &filter)
            .await
            .expect("reader list");
        ids.extend(
            listed
                .into_iter()
                .filter(|m| m.memory_kind == MemoryKind::Reflection)
                .map(|m| m.id),
        );
    }
    ids.len()
}

/// Y-8 + Y-9: default owner-private rows of another owner yield no
/// reflection, reach no LLM, raise no error, and the pass logs how many rows
/// it could not see.
async fn assert_default_scope_yields_nothing(store: &dyn MemoryStore, ns: &str, backend: &str) {
    let where_ = format!("#9185 Y-8 [{backend}] {ns}");
    let llm = StubLlm::new();
    let (report, log) = run_pass_captured(store, ns, &llm).await;
    assert_eq!(report.reflections_persisted, 0, "{where_}: {report:?}");
    assert!(
        report.errors.is_empty(),
        "{where_}: errors {:?}",
        report.errors
    );
    assert_eq!(
        report.observations_scanned, 0,
        "{where_}: rows the curator listed"
    );
    assert!(
        llm.seen().is_empty(),
        "{where_}: another owner's private rows reached the LLM: {:?}",
        llm.seen()
    );
    assert_eq!(reflections_in(store, ns).await, 0, "{where_}: reflections");
    // Y-9: the skipped count is logged, so the empty result is observable.
    let line = log
        .lines()
        .find(|l| l.contains(VISIBILITY_SKIPPED_LOG))
        .unwrap_or_else(|| panic!("{where_}: no skipped-count log line in {log:?}"));
    for field in [
        format!("namespace={ns}"),
        format!("skipped={CLUSTER_ROWS}"),
        "visible=0".to_string(),
        format!("curator={AI_CURATOR}"),
    ] {
        assert!(
            line.contains(&field),
            "{where_}: {field} missing from {line:?}"
        );
    }
}

/// The curator's write context as the pass builds it: admin bypass naming
/// the principal the sources were read as (a DERIVED write).
fn curator_derived_ctx() -> CallerContext {
    CallerContext {
        as_agent: Some(AI_CURATOR.to_string()),
        ..CallerContext::for_admin(AI_CURATOR)
    }
}

/// One L-F cell: a direct derived `reflect` and its exact outcome.
struct LfCell {
    label: &'static str,
    namespace: String,
    source_ids: Vec<String>,
    stamped: &'static str,
    /// The reflection's `agent_id` (the derived principal is `ai:curator`).
    author: &'static str,
    /// `None` = the reflect must succeed (positive control).
    refusal: Option<String>,
}

/// L-F fixtures under `ns_root`: the rows to seed and the cells to run.
fn lf_fixture(ns_root: &str) -> (Vec<Memory>, Vec<LfCell>) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut rows = Vec::new();
    let mut cells = Vec::new();
    let mut seed = |ns: &str, label: &'static str, meta: Vec<(&str, &str)>| -> Vec<String> {
        meta.into_iter()
            .enumerate()
            .map(|(idx, (owner, scope))| {
                let row = observation_row(
                    ns,
                    label,
                    idx,
                    label,
                    serde_json::json!({"agent_id": owner, "scope": scope}),
                    &now,
                );
                let id = row.id.clone();
                rows.push(row);
                id
            })
            .collect()
    };

    // (a) a source the curator may not read (another owner's private row).
    let ns_a = format!("{ns_root}/lf-unreadable-9185");
    let ids_a = seed(
        &ns_a,
        "lf-unreadable-9185",
        vec![
            (OWNER, "collective"),
            (OWNER, "private"),
            (OWNER, "collective"),
        ],
    );
    let refusal_a = format!(
        "{DERIVED_REFUSAL_PREFIX}: source {} is not readable by {AI_CURATOR}",
        ids_a[1]
    );
    // (b) a readable source in another namespace than the target.
    let ns_b = format!("{ns_root}/lf-namespace-9185");
    let ns_b_other = format!("{ns_root}/lf-namespace-other-9185");
    let mut ids_b = seed(
        &ns_b,
        "lf-namespace-9185",
        vec![(OWNER, "collective"), (OWNER, "collective")],
    );
    let moved = seed(
        &ns_b_other,
        "lf-namespace-9185",
        vec![(OWNER, "collective")],
    );
    let refusal_b = format!(
        "{DERIVED_REFUSAL_PREFIX}: source {} is in namespace '{ns_b_other}', not '{ns_b}'",
        moved[0]
    );
    ids_b.extend(moved);
    // (c) a stamp wider than the narrowest source scope.
    let ns_c = format!("{ns_root}/lf-scope-9185");
    let ids_c = seed(
        &ns_c,
        "lf-scope-9185",
        vec![
            (OWNER, "collective"),
            (AI_CURATOR, "private"),
            (OWNER, "collective"),
        ],
    );
    let refusal_c = format!(
        "{DERIVED_REFUSAL_PREFIX}: the sources narrow to scope 'private', the reflection \
         carries 'collective'"
    );
    // (d) positive control: collective sources, collective stamp.
    let ns_d = format!("{ns_root}/lf-ok-9185");
    let ids_d = seed(
        &ns_d,
        "lf-ok-9185",
        vec![
            (OWNER, "collective"),
            (OWNER, "collective"),
            (OWNER, "collective"),
        ],
    );

    cells.push(LfCell {
        label: "unreadable",
        author: AI_CURATOR,
        namespace: ns_a,
        source_ids: ids_a,
        stamped: "collective",
        refusal: Some(refusal_a),
    });
    cells.push(LfCell {
        label: "namespace",
        author: AI_CURATOR,
        namespace: ns_b,
        source_ids: ids_b,
        stamped: "collective",
        refusal: Some(refusal_b),
    });
    cells.push(LfCell {
        label: "scope",
        author: AI_CURATOR,
        namespace: ns_c,
        source_ids: ids_c,
        stamped: "collective",
        refusal: Some(refusal_c),
    });
    // (e) L-G: a derived write whose author is NOT the principal it read as
    // keeps the full #977 reserved-name reject (runs before the control, on
    // the control's sources, so a wrongly accepted write shows as a row).
    cells.push(LfCell {
        label: "reserved-author",
        namespace: ns_d.clone(),
        source_ids: ids_d.clone(),
        stamped: "collective",
        author: DAEMON_KEYPAIR_LABEL,
        refusal: Some(format!(
            "agent_id '{DAEMON_KEYPAIR_LABEL}' is reserved for internal use and cannot be \
             supplied by wire callers"
        )),
    });
    cells.push(LfCell {
        label: "ok",
        namespace: ns_d,
        source_ids: ids_d,
        stamped: "collective",
        author: AI_CURATOR,
        refusal: None,
    });
    (rows, cells)
}

/// L-F: every derived-reflection drift refuses inside the write transaction
/// with the exact error and writes no row; the positive control writes one.
async fn assert_lf_cells(store: &dyn MemoryStore, cells: &[LfCell], backend: &str) {
    for cell in cells {
        let where_ = format!("#9185 L-F [{backend}] cell {}", cell.label);
        let input = ReflectInput {
            source_ids: cell.source_ids.clone(),
            title: format!("derived reflection {} 9185", cell.label),
            content: format!("derived reflection content {} 9185", cell.label),
            namespace: Some(cell.namespace.clone()),
            tier: Tier::Long,
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
            agent_id: cell.author.to_string(),
            metadata: serde_json::json!({"agent_id": cell.author, "scope": cell.stamped}),
        };
        let outcome = store.reflect(&curator_derived_ctx(), &input, None).await;
        match (&cell.refusal, outcome) {
            (Some(expected), Err(ReflectError::Validation(msg))) => {
                assert_eq!(&msg, expected, "{where_}: refusal text");
                assert_eq!(
                    reflections_in(store, &cell.namespace).await,
                    0,
                    "{where_}: a refused derived reflection left a row"
                );
            }
            (Some(expected), other) => {
                panic!("{where_}: expected refusal {expected:?}, got {other:?}")
            }
            (None, Ok(_)) => assert_eq!(
                reflections_in(store, &cell.namespace).await,
                1,
                "{where_}: positive control"
            ),
            (None, Err(e)) => panic!("{where_}: positive control refused: {e}"),
        }
    }
}

/// The mutation an [`MutatingLlm`] fires between `summarize` and `persist`.
type Mutation = Box<dyn FnOnce() + Send>;

/// Stub LLM that fires one store mutation inside `summarize_memories`, i.e.
/// after the pass read the cluster and before `persist` re-reads it.
struct MutatingLlm {
    mutation: Mutex<Option<Mutation>>,
}

impl MutatingLlm {
    fn new(mutation: Mutation) -> Self {
        Self {
            mutation: Mutex::new(Some(mutation)),
        }
    }
}

impl AutonomyLlm for MutatingLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, _memories: &[(String, String)]) -> anyhow::Result<String> {
        if let Some(mutate) = self.mutation.lock().expect("mutation lock").take() {
            mutate();
        }
        Ok(SUMMARY.to_string())
    }
}

/// M-D fixtures: a fully collective cluster of [`OWNER`]'s rows in `ns`.
fn collective_cluster(ns: &str, label: &str) -> Vec<Memory> {
    let now = chrono::Utc::now().to_rfc3339();
    (0..CLUSTER_ROWS)
        .map(|idx| {
            observation_row(
                ns,
                label,
                idx,
                label,
                serde_json::json!({"agent_id": OWNER, "scope": "collective"}),
                &now,
            )
        })
        .collect()
}

/// M-D exact persist refusal for a source narrowed after `summarize`.
fn narrowed_refusal(ns: &str, id: &str) -> String {
    format!(
        "namespace '{ns}': persist failed: ReflectionPass::persist: source {id} is not readable \
         by curator {AI_CURATOR}; the reflection is not written"
    )
}

/// M-D exact persist refusal for a source moved after `summarize`.
fn moved_refusal(ns: &str, id: &str, moved_to: &str) -> String {
    format!(
        "namespace '{ns}': persist failed: ReflectionPass::persist: source {id} is in namespace \
         '{moved_to}', not '{ns}'; the reflection is not written"
    )
}

/// M-D: the pass refused with exactly `expected` and wrote no reflection.
async fn assert_persist_refused(
    store: &dyn MemoryStore,
    ns: &str,
    report: &ReflectionPassReport,
    expected: &str,
    backend: &str,
) {
    let where_ = format!("#9185 M-D [{backend}] {ns}");
    assert_eq!(
        report.errors,
        vec![expected.to_string()],
        "{where_}: errors"
    );
    assert_eq!(report.reflections_persisted, 0, "{where_}: persisted");
    assert_eq!(reflections_in(store, ns).await, 0, "{where_}: reflections");
}

/// L-G: the pass with the daemon keypair loaded signs and attributes as the
/// daemon principal, and the #8850 invariant still holds.
async fn assert_daemon_keyed_cell(store: &dyn MemoryStore, ns: &str, backend: &str) {
    let where_ = format!("#9185 L-G [{backend}] {ns}");
    let keypair = ai_memory::identity::keypair::generate(DAEMON_KEYPAIR_LABEL)
        .expect("generate daemon keypair");
    let llm = StubLlm::new();
    let report = run_reflection_pass(store, &llm, Some(&keypair), Some(ns), None, false, |_| true)
        .await
        .expect("run_reflection_pass");
    assert_eq!(
        report.reflections_persisted, 1,
        "{where_}: {:?}",
        report.errors
    );
    assert!(
        report.errors.is_empty(),
        "{where_}: errors {:?}",
        report.errors
    );

    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    filter.limit = READBACK_LIMIT;
    let daemon_view = store
        .list(&CallerContext::for_agent(DAEMON_KEYPAIR_LABEL), &filter)
        .await
        .expect("daemon list");
    let reflections: Vec<&Memory> = daemon_view
        .iter()
        .filter(|m| m.memory_kind == MemoryKind::Reflection)
        .collect();
    assert_eq!(
        reflections.len(),
        1,
        "{where_}: reflections the daemon reads back"
    );
    let reflection = reflections[0];
    assert_eq!(
        reflection
            .metadata
            .get("agent_id")
            .and_then(serde_json::Value::as_str),
        Some(DAEMON_KEYPAIR_LABEL),
        "{where_}: the reflection is owned by the daemon principal"
    );
    assert_eq!(
        reflection
            .metadata
            .get("scope")
            .and_then(serde_json::Value::as_str),
        Some("private"),
        "{where_}: a daemon-private source narrows the reflection"
    );
    let links = store
        .get_links_for_anchor(&reflection.id)
        .await
        .expect("reflection links");
    let edges: Vec<_> = links
        .iter()
        .filter(|l| l.source_id == reflection.id && l.relation == MemoryLinkRelation::ReflectsOn)
        .collect();
    assert_eq!(edges.len(), CLUSTER_ROWS, "{where_}: reflects_on edges");
    for edge in edges {
        assert_eq!(
            edge.attest_level.as_deref(),
            Some("self_signed"),
            "{where_}: edge {} -> {} is not signed by the daemon key",
            edge.source_id,
            edge.target_id
        );
    }
    // Nobody but the daemon reads the private reflection, the keyless curator
    // identity included.
    for reader in READERS {
        let listed = store
            .list(&CallerContext::for_agent(reader), &filter)
            .await
            .expect("reader list");
        assert!(
            listed
                .iter()
                .all(|m| m.memory_kind != MemoryKind::Reflection),
            "{where_}: the daemon-private reflection is listed to {reader}"
        );
    }
}

/// L-G fixtures: two collective rows of [`OWNER`] and two private rows of the
/// daemon principal, so the keyed curator reads all four.
fn daemon_mix_rows(ns: &str) -> Vec<Memory> {
    let now = chrono::Utc::now().to_rfc3339();
    [
        (OWNER, "collective"),
        (DAEMON_KEYPAIR_LABEL, "private"),
        (OWNER, "collective"),
        (DAEMON_KEYPAIR_LABEL, "private"),
    ]
    .into_iter()
    .enumerate()
    .map(|(idx, (owner, scope))| {
        observation_row(
            ns,
            "daemon-mix-9185",
            idx,
            "daemon-mix-9185",
            serde_json::json!({"agent_id": owner, "scope": scope}),
            &now,
        )
    })
    .collect()
}

/// Seed `rows` into the sqlite file at `db_path` through the legacy funnel.
fn sqlite_seed(db_path: &std::path::Path, rows: &[Memory]) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    for row in rows {
        ai_memory::db::insert(&conn, row).expect("seed observation");
    }
}

/// A raw sqlite UPDATE on its own connection (the store's is untouched).
fn sqlite_update(db_path: &std::path::Path, sql: &'static str, value: &str, id: &str) {
    let conn = ai_memory::db::open(db_path).expect("db::open");
    conn.execute(sql, rusqlite::params![value, id])
        .expect("toctou update");
}

/// Narrow one source to owner-private (the generated `scope_idx` column
/// follows `metadata`).
const SQL_SET_METADATA: &str = "UPDATE memories SET metadata = ?1 WHERE id = ?2";
/// Move one source to another namespace.
const SQL_SET_NAMESPACE: &str = "UPDATE memories SET namespace = ?1 WHERE id = ?2";

#[tokio::test]
async fn default_scope_rows_yield_no_reflection_and_log_skipped_sqlite_9185() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("default-scope-9185.db");
    let ns = format!("{TEAM_NS}/default-scope-9185");
    sqlite_seed(&db_path, &default_scope_rows(&ns));
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    assert_default_scope_yields_nothing(&store, &ns, "sqlite").await;
}

#[tokio::test]
async fn derived_reflect_reverifies_in_txn_sqlite_9185() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("derived-reflect-9185.db");
    let (rows, cells) = lf_fixture(TEAM_NS);
    sqlite_seed(&db_path, &rows);
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    assert_lf_cells(&store, &cells, "sqlite").await;
}

#[tokio::test]
async fn persist_refuses_source_narrowed_after_summarize_sqlite_9185() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("persist-narrowed-9185.db");
    let ns = format!("{TEAM_NS}/persist-narrowed-9185");
    let rows = collective_cluster(&ns, "persist-narrowed-9185");
    sqlite_seed(&db_path, &rows);
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    let target = rows[0].id.clone();
    let (path, id) = (db_path.clone(), target.clone());
    let llm = MutatingLlm::new(Box::new(move || {
        let narrowed = serde_json::json!({"agent_id": OWNER, "scope": "private"}).to_string();
        sqlite_update(&path, SQL_SET_METADATA, &narrowed, &id);
    }));
    let report = run_reflection_pass(&store, &llm, None, Some(&ns), None, false, |_| true)
        .await
        .expect("run_reflection_pass");
    assert_persist_refused(
        &store,
        &ns,
        &report,
        &narrowed_refusal(&ns, &target),
        "sqlite",
    )
    .await;
}

#[tokio::test]
async fn persist_refuses_source_moved_after_summarize_sqlite_9185() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("persist-moved-9185.db");
    let ns = format!("{TEAM_NS}/persist-moved-9185");
    let moved_to = format!("{TEAM_NS}/persist-moved-elsewhere-9185");
    let rows = collective_cluster(&ns, "persist-moved-9185");
    sqlite_seed(&db_path, &rows);
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    let target = rows[0].id.clone();
    let (path, id, to) = (db_path.clone(), target.clone(), moved_to.clone());
    let llm = MutatingLlm::new(Box::new(move || {
        sqlite_update(&path, SQL_SET_NAMESPACE, &to, &id);
    }));
    let report = run_reflection_pass(&store, &llm, None, Some(&ns), None, false, |_| true)
        .await
        .expect("run_reflection_pass");
    assert_persist_refused(
        &store,
        &ns,
        &report,
        &moved_refusal(&ns, &target, &moved_to),
        "sqlite",
    )
    .await;
}

#[tokio::test]
async fn daemon_keyed_pass_signs_and_attributes_as_daemon_sqlite_9185() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let db_path = tmp.path().join("daemon-keyed-9185.db");
    let ns = format!("{TEAM_NS}/daemon-keyed-9185");
    sqlite_seed(&db_path, &daemon_mix_rows(&ns));
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore::open");
    assert_daemon_keyed_cell(&store, &ns, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        CASES, MutatingLlm, OWNER, StubLlm, TEAM_NS, assert_case, assert_daemon_keyed_cell,
        assert_default_scope_yields_nothing, assert_lf_cells, assert_persist_refused, case_rows,
        collective_cluster, daemon_mix_rows, default_scope_rows, lf_fixture, moved_refusal,
        narrowed_refusal, run_pass, run_reflection_pass,
    };
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

    /// Connect to the minted test database and give the cell its own
    /// namespace root inside the owner's team subtree.
    async fn connect() -> (PostgresStore, String) {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #9185 live-pg cells");
        };
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        let ns_root = format!("{TEAM_NS}/{}", uuid::Uuid::new_v4().simple());
        (store, ns_root)
    }

    /// A raw UPDATE on the store's pool, run from inside the synchronous LLM
    /// callback (`block_in_place` needs the multi-thread runtime).
    fn pg_update(
        store: &PostgresStore,
        sql: &'static str,
        value: String,
        id: String,
    ) -> super::Mutation {
        let pool = store.pool().clone();
        let handle = tokio::runtime::Handle::current();
        Box::new(move || {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    sqlx::query(sql)
                        .bind(value)
                        .bind(id)
                        .execute(&pool)
                        .await
                        .expect("toctou update");
                });
            });
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn default_scope_rows_yield_no_reflection_and_log_skipped_pg_9185() {
        let (store, ns_root) = connect().await;
        let ns = format!("{ns_root}/default-scope-9185");
        for row in default_scope_rows(&ns) {
            raw_insert(&store, &row).await;
        }
        assert_default_scope_yields_nothing(&store, &ns, "postgres").await;
        cleanup(&store, &ns_root).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn derived_reflect_reverifies_in_txn_pg_9185() {
        let (store, ns_root) = connect().await;
        let (rows, cells) = lf_fixture(&ns_root);
        for row in &rows {
            raw_insert(&store, row).await;
        }
        assert_lf_cells(&store, &cells, "postgres").await;
        cleanup(&store, &ns_root).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persist_refuses_source_narrowed_after_summarize_pg_9185() {
        let (store, ns_root) = connect().await;
        let ns = format!("{ns_root}/persist-narrowed-9185");
        let rows = collective_cluster(&ns, "persist-narrowed-9185");
        for row in &rows {
            raw_insert(&store, row).await;
        }
        let target = rows[0].id.clone();
        let narrowed = serde_json::json!({"agent_id": OWNER, "scope": "private"}).to_string();
        let llm = MutatingLlm::new(pg_update(
            &store,
            "UPDATE memories SET metadata = $1::jsonb WHERE id = $2",
            narrowed,
            target.clone(),
        ));
        let report = run_reflection_pass(&store, &llm, None, Some(&ns), None, false, |_| true)
            .await
            .expect("run_reflection_pass");
        assert_persist_refused(
            &store,
            &ns,
            &report,
            &narrowed_refusal(&ns, &target),
            "postgres",
        )
        .await;
        cleanup(&store, &ns_root).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persist_refuses_source_moved_after_summarize_pg_9185() {
        let (store, ns_root) = connect().await;
        let ns = format!("{ns_root}/persist-moved-9185");
        let moved_to = format!("{ns_root}/persist-moved-elsewhere-9185");
        let rows = collective_cluster(&ns, "persist-moved-9185");
        for row in &rows {
            raw_insert(&store, row).await;
        }
        let target = rows[0].id.clone();
        let llm = MutatingLlm::new(pg_update(
            &store,
            "UPDATE memories SET namespace = $1 WHERE id = $2",
            moved_to.clone(),
            target.clone(),
        ));
        let report = run_reflection_pass(&store, &llm, None, Some(&ns), None, false, |_| true)
            .await
            .expect("run_reflection_pass");
        assert_persist_refused(
            &store,
            &ns,
            &report,
            &moved_refusal(&ns, &target, &moved_to),
            "postgres",
        )
        .await;
        cleanup(&store, &ns_root).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn daemon_keyed_pass_signs_and_attributes_as_daemon_pg_9185() {
        let (store, ns_root) = connect().await;
        let ns = format!("{ns_root}/daemon-keyed-9185");
        for row in daemon_mix_rows(&ns) {
            raw_insert(&store, &row).await;
        }
        assert_daemon_keyed_cell(&store, &ns, "postgres").await;
        cleanup(&store, &ns_root).await;
    }
}
