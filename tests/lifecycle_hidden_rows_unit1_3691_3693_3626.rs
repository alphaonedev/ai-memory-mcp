// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 — the three sqlite lanes that consulted
//! `lifecycle_state` in the OTHER directions (#3691 write, #3693 read) and
//! the owner-stamp half that lives in the same upsert literals (#3626).
//!
//!  * #3691 — the consolidation tombstone UPDATE is GUARDED by the visible
//!    allow-list and checks its affected-row count: a source that was
//!    quarantined between the curator's snapshot read and the write keeps
//!    its security state and the WHOLE cluster aborts (no summary row).
//!  * #3693 — `find_contradictions` / `find_synthesis_candidates`, the
//!    proactive conflict scan, and both persona reflection loaders apply the
//!    fail-closed `lifecycle_visible_clause`: a hidden row is neither
//!    reported, merged, nor used as persona source material.
//!  * #3626 — a dedup / upsert / synthesis merge onto an UNSTAMPED row leaves
//!    it unstamped: the caller's `metadata.agent_id` never claims it
//!    (claiming stays `ai-memory reown`), on the SQL arm AND the Rust helper.
//!
//! Every cell is RED on the pre-fix tree (1ec64196b).

#![allow(clippy::too_many_lines)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ai_memory::autonomy::AutonomyLlm;
use ai_memory::db;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::persona::{PersonaConfig, PersonaGenerator};
use serde_json::{Value, json};

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["unit1".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-unit1".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": "ai:tester-unit1" }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
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

fn open() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("m.db")).expect("open");
    (dir, conn)
}

fn set_state(conn: &rusqlite::Connection, id: &str, state: &str) {
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?2 WHERE id = ?1",
        rusqlite::params![id, state],
    )
    .expect("set lifecycle_state");
}

fn state_of(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row(
        "SELECT lifecycle_state FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("row resident")
}

fn count_title(conn: &rusqlite::Connection, title: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1",
        rusqlite::params![title],
        |r| r.get(0),
    )
    .expect("count")
}

static FLAG_LOCK: Mutex<()> = Mutex::new(());

// ───────────────────────────────────────────────────────────────────
// #3691 — guarded tombstone
// ───────────────────────────────────────────────────────────────────

/// A source quarantined AFTER the curator's snapshot read but BEFORE the
/// tombstone write (simulated by an AFTER-INSERT trigger on the summary row,
/// which fires inside consolidate's own transaction, between its `get`
/// snapshot and its tombstone loop) keeps `quarantined`; the cluster aborts
/// with the typed transition conflict and NO summary row is committed.
#[test]
fn consolidate_aborts_the_cluster_when_a_source_is_quarantined_after_snapshot_3691() {
    let _guard = FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
    let (_dir, conn) = open();
    db::insert(&conn, &mem("src-a", "team/ops", "a-3691", "alpha")).expect("seed a");
    db::insert(&conn, &mem("src-b", "team/ops", "b-3691", "beta")).expect("seed b");
    conn.execute_batch(
        "CREATE TRIGGER quarantine_b_mid_consolidate AFTER INSERT ON memories
         WHEN NEW.title = 'C-3691'
         BEGIN
             UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = 'src-b';
         END;",
    )
    .expect("install the race trigger");

    let err = db::consolidate(
        &conn,
        &["src-a".to_string(), "src-b".to_string()],
        "C-3691",
        "merged",
        "team/ops",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .expect_err("a source that went hidden mid-consolidation aborts the cluster");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("illegal lifecycle transition") && rendered.contains("src-b"),
        "typed transition conflict naming the source, got: {rendered}"
    );
    // The simulated quarantine rode consolidate's own transaction, so the
    // rollback that protected it also reverted it: what the guard proves is
    // that NEITHER source was tombstoned over a hidden state.
    assert_ne!(
        state_of(&conn, "src-b"),
        "tombstoned",
        "the hidden source was never tombstoned"
    );
    assert_eq!(
        state_of(&conn, "src-a"),
        "open",
        "the cluster rolled back: a is NOT tombstoned"
    );
    assert_eq!(
        count_title(&conn, "C-3691"),
        0,
        "no summary row was committed"
    );
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
}

/// Control: with no interference the same cluster consolidates and both
/// sources are tombstoned (the guard admits every visible source).
#[test]
fn consolidate_still_tombstones_visible_sources_3691() {
    let _guard = FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
    let (_dir, conn) = open();
    db::insert(&conn, &mem("src-a", "team/ops", "a-3691", "alpha")).expect("seed a");
    db::insert(&conn, &mem("src-b", "team/ops", "b-3691", "beta")).expect("seed b");
    let c = db::consolidate(
        &conn,
        &["src-a".to_string(), "src-b".to_string()],
        "C-3691",
        "merged",
        "team/ops",
        &Tier::Long,
        "consolidation",
        "ai:consolidator",
        false,
    )
    .expect("consolidates");
    assert_eq!(state_of(&conn, "src-a"), "tombstoned");
    assert_eq!(state_of(&conn, "src-b"), "tombstoned");
    assert!(
        db::get(&conn, &c).expect("get").is_some(),
        "the summary is visible"
    );
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
}

// ───────────────────────────────────────────────────────────────────
// #3693 — read lanes
// ───────────────────────────────────────────────────────────────────

/// A hidden row with a similar title is neither a contradiction candidate
/// nor a synthesis candidate; a visible sibling still is.
#[test]
fn contradiction_and_synthesis_lanes_skip_hidden_rows_3693() {
    for hidden in ["quarantined", "contaminated", "tombstoned"] {
        let (_dir, conn) = open();
        db::insert(
            &conn,
            &mem("hid", "team/ops", "deploy strategy canary", "peer text"),
        )
        .expect("seed hidden");
        db::insert(
            &conn,
            &mem("vis", "team/ops", "deploy strategy rollback", "ours"),
        )
        .expect("seed visible");
        set_state(&conn, "hid", hidden);
        let contradictions = db::find_contradictions(&conn, "deploy strategy", "team/ops", None)
            .expect("contradictions");
        let ids: Vec<&str> = contradictions.iter().map(|m| m.id.as_str()).collect();
        assert!(
            !ids.contains(&"hid"),
            "{hidden}: a hidden row is never a contradiction candidate: {ids:?}"
        );
        assert!(
            ids.contains(&"vis"),
            "{hidden}: the visible sibling still is: {ids:?}"
        );
        let synthesis =
            db::find_synthesis_candidates(&conn, "deploy strategy", "team/ops").expect("synthesis");
        let ids: Vec<&str> = synthesis.iter().map(|m| m.id.as_str()).collect();
        assert!(
            !ids.contains(&"hid"),
            "{hidden}: a hidden row is never merged by synthesis: {ids:?}"
        );
        assert!(
            ids.contains(&"vis"),
            "{hidden}: the visible sibling still is: {ids:?}"
        );
    }
}

/// The proactive (embedding) conflict scan never names a hidden row: with
/// only the hidden near-duplicate present there is NO conflict; a visible
/// twin is still reported.
#[test]
fn proactive_conflict_scan_skips_hidden_rows_3693() {
    let (_dir, conn) = open();
    let emb: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
    let claim = "the deploy uses canary health checks before traffic shifts to the new replica set";
    db::insert(&conn, &mem("hid", "team/ops", "conflict-hid", claim)).expect("seed");
    db::set_embedding(&conn, "hid", &emb, "test#none").expect("embed");
    set_state(&conn, "hid", "quarantined");
    let probe = mem(
        "probe",
        "team/ops",
        "probe",
        &format!("{claim} and rolls back on failure"),
    );
    let ids = ["hid".to_string(), "vis".to_string()];
    assert!(
        db::proactive_conflict_check(&conn, &probe, &emb, None)
            .expect("scan")
            .is_none(),
        "a hidden row is never the subject of a conflict advisory"
    );
    assert!(
        db::proactive_conflict_check_candidates(&conn, &probe, &emb, &ids, None)
            .expect("ann")
            .is_none(),
        "the ANN-routed lane never names a hidden row"
    );
    db::insert(&conn, &mem("vis", "team/ops", "conflict-vis", claim)).expect("seed");
    db::set_embedding(&conn, "vis", &emb, "test#none").expect("embed");
    let hit = db::proactive_conflict_check(&conn, &probe, &emb, None)
        .expect("scan")
        .expect("visible twin conflicts");
    assert_eq!(hit.existing_id, "vis");
    let hit = db::proactive_conflict_check_candidates(&conn, &probe, &emb, &ids, None)
        .expect("ann")
        .expect("visible twin conflicts");
    assert_eq!(hit.existing_id, "vis");
}

/// Records what the persona curator was handed.
struct RecordingLlm {
    seen: Mutex<Vec<String>>,
}

impl AutonomyLlm for RecordingLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> anyhow::Result<String> {
        self.seen
            .lock()
            .expect("lock")
            .extend(memories.iter().map(|(_, content)| content.clone()));
        Ok("alice is composed.".to_string())
    }
}

fn reflection(id: &str, ns: &str, entity: &str, content: &str) -> Memory {
    let mut m = mem(id, ns, &format!("reflection {id}"), content);
    m.memory_kind = MemoryKind::Reflection;
    m.reflection_depth = 1;
    m.metadata = json!({ "agent_id": "ai:tester-unit1", "entity_id": entity });
    m
}

/// Both persona loaders (namespaced + cross-namespace) skip hidden
/// reflections: a quarantined reflection's text never reaches the persona
/// curator, while the visible one does.
#[test]
fn persona_loaders_skip_hidden_reflections_3693() {
    for (cross_namespace, hidden) in [
        (false, "quarantined"),
        (false, "contaminated"),
        (true, "quarantined"),
    ] {
        let (_dir, conn) = open();
        db::insert(
            &conn,
            &reflection("r-hid", "team/alpha", "alice", "HIDDEN-REFLECTION-TEXT"),
        )
        .expect("seed");
        db::insert(
            &conn,
            &reflection("r-vis", "team/alpha", "alice", "visible reflection text"),
        )
        .expect("seed");
        set_state(&conn, "r-hid", hidden);
        let llm = RecordingLlm {
            seen: Mutex::new(Vec::new()),
        };
        let generator = PersonaGenerator::new(&conn, &llm, None, PersonaConfig::default());
        let generated = if cross_namespace {
            generator.generate_cross_namespace("alice", "team/alpha")
        } else {
            generator.generate("alice", "team/alpha")
        };
        generated.expect("the visible reflection is enough source material");
        let seen = llm.seen.lock().expect("lock").clone();
        assert!(
            !seen.iter().any(|c| c.contains("HIDDEN-REFLECTION-TEXT")),
            "{hidden} (cross={cross_namespace}): a hidden reflection reached the persona curator: {seen:?}"
        );
        assert!(
            seen.iter().any(|c| c.contains("visible reflection text")),
            "{hidden} (cross={cross_namespace}): the visible reflection is still source material"
        );
    }
}

// ───────────────────────────────────────────────────────────────────
// #3626 — an unstamped row is never claimed by a merge
// ───────────────────────────────────────────────────────────────────

fn agent_id_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("row")
}

/// The SQL upsert arm: a `(title, namespace)` merge onto a row with NO
/// `metadata.agent_id` (missing, JSON null, or "") leaves it unowned; the
/// caller's id is dropped. A STAMPED row keeps its owner as before.
#[test]
fn upsert_merge_onto_an_unstamped_row_leaves_it_unstamped_3626() {
    for unstamped in [
        json!({}),
        json!({"agent_id": null}),
        json!({"agent_id": ""}),
    ] {
        let (_dir, conn) = open();
        let mut legacy = mem("legacy", "team/ops", "slot", "legacy text");
        legacy.metadata = unstamped.clone();
        db::insert(&conn, &legacy).expect("seed unstamped");
        let id =
            db::insert(&conn, &mem("claimer", "team/ops", "slot", "claimed text")).expect("merge");
        assert_eq!(id, "legacy");
        assert_eq!(
            agent_id_of(&conn, "legacy").filter(|s| !s.is_empty()),
            None,
            "seed {unstamped}: the merging caller must not become the owner"
        );
        let content: String = conn
            .query_row(
                "SELECT content FROM memories WHERE id = 'legacy'",
                [],
                |r| r.get(0),
            )
            .expect("content");
        assert_eq!(content, "claimed text", "the merge itself still happened");
    }
    // stamped control
    let (_dir, conn) = open();
    db::insert(&conn, &mem("owned", "team/ops", "slot", "owned text")).expect("seed");
    let mut other = mem("other", "team/ops", "slot", "x");
    other.metadata = json!({ "agent_id": "ai:someone-else" });
    db::insert(&conn, &other).expect("merge");
    assert_eq!(
        agent_id_of(&conn, "owned").as_deref(),
        Some("ai:tester-unit1"),
        "existing owner wins"
    );
}

/// The Rust merge helper the MCP dedup update and the synthesis merge use.
#[test]
fn preserve_provenance_keys_for_merge_drops_a_claim_on_an_unstamped_row_3626() {
    let incoming = json!({ "agent_id": "ai:claimer", "note": "x" });
    let merged = ai_memory::identity::preserve_provenance_keys_for_merge(&json!({}), &incoming);
    assert!(merged.get("agent_id").is_none(), "claim dropped: {merged}");
    assert_eq!(merged["note"], "x");
    let merged = ai_memory::identity::preserve_provenance_keys_for_merge(
        &json!({ "agent_id": "ai:owner" }),
        &incoming,
    );
    assert_eq!(merged["agent_id"], "ai:owner", "existing owner preserved");
}

/// End to end through the MCP `memory_store` dedup path (the real binary,
/// `AI_MEMORY_AGENT_ID` set): a second store of the same title by a named
/// caller merges into the legacy unowned row and leaves it unowned.
#[test]
fn mcp_store_dedup_onto_an_unstamped_row_leaves_it_unstamped_3626() {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch");
    let db_path = dir.path().join("dedup.db");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    {
        let conn = db::open(&db_path).expect("open");
        let mut legacy = mem("legacy", "team/ops", "slot-3626", "legacy text");
        legacy.metadata = json!({});
        db::insert(&conn, &legacy).expect("seed unstamped");
    }
    let stored = mcp(
        &db_path,
        &home,
        "ai:claimer-3626",
        "memory_store",
        &json!({"title": "slot-3626", "content": "claimed text", "namespace": "team/ops", "tier": "long"}),
    );
    assert_eq!(
        stored["id"], "legacy",
        "dedup merged into the legacy row: {stored}"
    );
    let conn = db::open(&db_path).expect("reopen");
    assert_eq!(
        agent_id_of(&conn, "legacy").filter(|s| !s.is_empty()),
        None,
        "the MCP dedup update must not stamp the caller as owner"
    );
}

fn mcp(
    db: &std::path::Path,
    home: &std::path::Path,
    caller: &str,
    tool: &str,
    args: &Value,
) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", caller)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args([
            "--db",
            db.to_str().expect("db path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mcp child");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}});
    writeln!(child.stdin.take().expect("stdin"), "{request}").expect("request");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("poll").is_none() {
        assert!(Instant::now() < deadline, "MCP child timed out on {tool}");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("output");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let response = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 1)
        .unwrap_or_else(|| {
            panic!(
                "no response for {caller} {tool}: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    if let Some(text) = response["result"]["content"][0]["text"].as_str() {
        if response["result"]["isError"].as_bool() == Some(true) {
            return json!({"error": text});
        }
        return serde_json::from_str(text).unwrap_or_else(|_| json!({"text": text}));
    }
    json!({"error": response["error"].clone()})
}
