// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_update,
    clippy::similar_names
)]

//! v0.9.0 G7 (#1824) — the contradiction-CONSERVE behavioral suite.
//!
//! The curator no longer HARD-DELETES the loser of a confirmed
//! contradiction. It CONSERVES the pair: retain BOTH memories, write ONE
//! canonical signed `contradicts` edge, emit EXACTLY ONE identity-only
//! SUPERSEDE revision leaf (flag-gated, reusing the shipped G6 spine), and
//! mark the loser with a reversible node-local soft down-weight.
//!
//! These tests pin, end to end:
//!
//!  a. both memories survive the pass,
//!  b. exactly ONE canonical `contradicts` edge — signed when a keypair
//!     is configured, unsigned otherwise,
//!  c. EXACTLY ONE `memory_revisions` SUPERSEDE leaf for the loser
//!     (prior_version == loser.version), identity-only (no content / no
//!     winner id in the leaf bytes),
//!  d. the loser's `updated_at` is byte-unchanged and it carries
//!     `contradiction_conserved == true`,
//!  e. a second pass (fresh DB re-read) writes ZERO new links / leaves —
//!     the re-entry gate is idempotent,
//!  f. with the append-only flag OFF: retained + linked + marker, but ZERO
//!     revision leaves,
//!  g. the reversal removes the edge and clears the markers, leaving BOTH
//!     rows intact and appending NO compensating leaf,
//!  h. a MUTUAL contradiction (both rows flag each other) is conserved
//!     exactly ONCE — the winner's pass returns `Ok(None)`.
//!
//! ## Concurrency
//!
//! `append_only` and the daemon audit key are process-wide, so the tests
//! serialize on a file-local `Mutex` and install the audit key once.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ai_memory::autonomy::{self, AutonomyLlm, RollbackEntry};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::models::field_names;
use ai_memory::models::{AttestLevel, Memory, MemoryLinkRelation, Tier};
use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};

// ---------------------------------------------------------------------------
// Process-wide fixtures (the flag + audit key are global singletons)
// ---------------------------------------------------------------------------

static FLAG_LOCK: Mutex<()> = Mutex::new(());
static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install a process-wide daemon audit signing key exactly once so the
/// flag-ON SUPERSEDE leaves carry a real signature.
fn ensure_audit_key() {
    AUDIT_DIR.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("ai-memory-g7-conserve-")
            .tempdir()
            .expect("tempdir for audit sink");
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        ai_memory::governance::audit::init(dir.path(), Some(signing))
            .expect("install daemon audit key");
        dir
    });
}

// ---------------------------------------------------------------------------
// A minimal no-op curator LLM — the conserve pass (pass 2) never touches it,
// and we always run with `skip_consolidation = true`.
// ---------------------------------------------------------------------------

struct NoopLlm;

impl AutonomyLlm for NoopLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, _memories: &[(String, String)]) -> Result<String> {
        Ok(String::new())
    }
}

// ---------------------------------------------------------------------------
// Builders + probes
// ---------------------------------------------------------------------------

fn open_mem_db() -> rusqlite::Connection {
    ai_memory::db::open(Path::new(":memory:")).expect("open in-memory db")
}

/// A seed memory. `updated_at` drives the recency tie-break; `created_at`
/// is pinned to "now" so the priority-feedback pass never fires (its −1
/// rule needs `created_at` older than 30d, which would emit an unrelated
/// SUPERSEDE leaf and pollute the leaf-count assertions).
fn seed_mem(
    id: &str,
    content: &str,
    confidence: f64,
    updated_at: &str,
    contradicts: &str,
) -> Memory {
    Memory {
        id: id.to_string(),
        title: format!("title-{id}"),
        content: content.to_string(),
        namespace: "facts".to_string(),
        tier: Tier::Long,
        confidence,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: updated_at.to_string(),
        version: 1,
        metadata: serde_json::json!({
            "agent_id": "ai:test",
            field_names::CONFIRMED_CONTRADICTIONS: [contradicts],
        }),
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
struct Leaf {
    memory_id: String,
    kind: String,
    prior_version: Option<i64>,
    namespace: String,
    agent_id: Option<String>,
    created_at: String,
    signature: Option<Vec<u8>>,
}

fn read_leaves(conn: &rusqlite::Connection) -> Vec<Leaf> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, kind, prior_version, namespace, agent_id, created_at, signature \
             FROM memory_revisions ORDER BY sequence",
        )
        .expect("prepare leaf read");
    let rows = stmt
        .query_map([], |r| {
            Ok(Leaf {
                memory_id: r.get(0)?,
                kind: r.get(1)?,
                prior_version: r.get(2)?,
                namespace: r.get(3)?,
                agent_id: r.get(4)?,
                created_at: r.get(5)?,
                signature: r.get(6)?,
            })
        })
        .expect("query leaves");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect leaves")
}

fn leaf_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
        .expect("count leaves")
}

/// Count of `contradicts` edges between the ordered pair (a, b).
fn contradicts_edges(
    conn: &rusqlite::Connection,
    a: &str,
    b: &str,
) -> Vec<ai_memory::models::MemoryLink> {
    let (src, tgt) = ai_memory::db::canonical_contradiction_pair(a, b);
    ai_memory::db::get_links(conn, src)
        .expect("get_links")
        .into_iter()
        .filter(|l| {
            l.source_id == src
                && l.target_id == tgt
                && l.relation == MemoryLinkRelation::Contradicts
        })
        .collect()
}

fn marker_bool(conn: &rusqlite::Connection, id: &str, key: &str) -> Option<bool> {
    let mem = ai_memory::db::get(conn, id)
        .expect("get")
        .expect("row present");
    mem.metadata.get(key).and_then(serde_json::Value::as_bool)
}

/// Build an in-memory signing keypair (no disk, no key-dir activation).
fn signing_keypair() -> AgentKeypair {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let vk: VerifyingKey = (&sk).into();
    AgentKeypair {
        agent_id: "ai:g7-curator".to_string(),
        public: vk,
        private: Some(sk),
    }
}

const OLD_TS: &str = "2020-01-01T00:00:00Z";
const NEW_TS: &str = "2025-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// a + c + d + e + h — the full conserve pass, flag ON, via run_autonomy_passes
// ---------------------------------------------------------------------------

#[test]
fn conserve_pass_flag_on_retains_both_and_is_idempotent() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    // loser is OLDER; winner is NEWER with >= confidence. They flag EACH
    // OTHER (mutual) so we also exercise the winner's `Ok(None)` path (h).
    let loser = seed_mem("loser", "the sky is green", 0.8, OLD_TS, "winner");
    let winner = seed_mem("winner", "the sky is blue", 0.9, NEW_TS, "loser");
    ai_memory::db::insert(&conn, &loser).expect("insert loser");
    ai_memory::db::insert(&conn, &winner).expect("insert winner");
    assert_eq!(leaf_count(&conn), 0, "plain inserts emit no leaves");

    let report = autonomy::run_autonomy_passes(
        &conn,
        &NoopLlm,
        &[loser.clone(), winner.clone()],
        false,
        true,
    );
    assert!(report.errors.is_empty(), "pass errors: {:?}", report.errors);
    // (h) mutual contradiction conserved exactly once (winner → Ok(None)).
    assert_eq!(
        report.memories_forgotten, 1,
        "exactly one conserve per pair"
    );

    // (a) both rows survive.
    assert!(ai_memory::db::get(&conn, "loser").unwrap().is_some());
    assert!(ai_memory::db::get(&conn, "winner").unwrap().is_some());

    // (b) exactly one canonical contradicts edge.
    assert_eq!(
        contradicts_edges(&conn, "loser", "winner").len(),
        1,
        "exactly one canonical contradicts edge"
    );

    // (c) exactly one SUPERSEDE leaf for the loser, identity-only.
    let leaves = read_leaves(&conn);
    assert_eq!(
        leaves.len(),
        1,
        "exactly one revision leaf for the conserve"
    );
    let leaf = &leaves[0];
    assert_eq!(leaf.kind, "SUPERSEDE");
    assert_eq!(leaf.memory_id, "loser", "the leaf is for the loser");
    assert_eq!(
        leaf.prior_version,
        Some(1),
        "prior_version == loser.version"
    );
    assert_eq!(leaf.namespace, "facts");
    assert_eq!(leaf.agent_id.as_deref(), Some("ai:curator"));
    assert!(
        leaf.signature.is_some(),
        "flag-ON leaf is signed under the audit key"
    );
    // identity-only: neither content nor the winner id is in the leaf.
    for needle in ["the sky is green", "the sky is blue", "winner"] {
        assert!(
            !leaf.created_at.contains(needle)
                && !leaf.memory_id.contains(needle)
                && !leaf.namespace.contains(needle),
            "the leaf must be identity-only (no {needle})"
        );
    }

    // (d) loser.updated_at byte-unchanged + conserved marker true; winner NOT flagged.
    let loser_row = ai_memory::db::get(&conn, "loser").unwrap().unwrap();
    assert_eq!(
        loser_row.updated_at, OLD_TS,
        "updated_at preserved byte-for-byte"
    );
    assert_eq!(
        marker_bool(&conn, "loser", field_names::CONTRADICTION_CONSERVED),
        Some(true)
    );
    assert_eq!(
        marker_bool(&conn, "loser", field_names::CONTRADICTION_SOFT_LOSER),
        Some(true)
    );
    assert_eq!(
        loser_row
            .metadata
            .get(field_names::CONTRADICTION_WINNER_ID)
            .and_then(serde_json::Value::as_str),
        Some("winner")
    );
    assert_eq!(
        marker_bool(&conn, "winner", field_names::CONTRADICTION_CONSERVED),
        None,
        "the winner is never flagged (h)"
    );

    // (e) second pass, re-reading the (now-marked) rows from the DB: the
    // re-entry gate fires → ZERO new links, ZERO new leaves.
    let loser_fresh = ai_memory::db::get(&conn, "loser").unwrap().unwrap();
    let winner_fresh = ai_memory::db::get(&conn, "winner").unwrap().unwrap();
    let report2 =
        autonomy::run_autonomy_passes(&conn, &NoopLlm, &[loser_fresh, winner_fresh], false, true);
    assert_eq!(
        report2.memories_forgotten, 0,
        "re-entry gate: nothing re-conserved"
    );
    assert_eq!(leaf_count(&conn), 1, "no second leaf");
    assert_eq!(
        contradicts_edges(&conn, "loser", "winner").len(),
        1,
        "no duplicate edge"
    );
}

// ---------------------------------------------------------------------------
// b — the canonical edge is SIGNED when a keypair is configured, else not
// ---------------------------------------------------------------------------

#[test]
fn conserve_signs_edge_when_keypair_configured() {
    let _g = flag_guard();
    ai_memory::config::set_append_only(false); // leaf state irrelevant here

    // Signed variant.
    {
        let conn = open_mem_db();
        let loser = seed_mem("loser", "green", 0.8, OLD_TS, "winner");
        let winner = seed_mem("winner", "blue", 0.9, NEW_TS, "loser");
        ai_memory::db::insert(&conn, &loser).unwrap();
        ai_memory::db::insert(&conn, &winner).unwrap();
        let kp = signing_keypair();
        ai_memory::db::conserve_contradiction(&conn, &loser, "winner", Some(&kp))
            .expect("conserve");
        let edges = contradicts_edges(&conn, "loser", "winner");
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].attest_level.as_deref(),
            Some(AttestLevel::SelfSigned.as_str()),
            "a configured keypair signs the edge"
        );
    }

    // Unsigned variant.
    {
        let conn = open_mem_db();
        let loser = seed_mem("loser", "green", 0.8, OLD_TS, "winner");
        let winner = seed_mem("winner", "blue", 0.9, NEW_TS, "loser");
        ai_memory::db::insert(&conn, &loser).unwrap();
        ai_memory::db::insert(&conn, &winner).unwrap();
        ai_memory::db::conserve_contradiction(&conn, &loser, "winner", None).expect("conserve");
        let edges = contradicts_edges(&conn, "loser", "winner");
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].attest_level.as_deref(),
            Some(AttestLevel::Unsigned.as_str()),
            "no keypair → unsigned edge"
        );
    }
}

// ---------------------------------------------------------------------------
// f — flag OFF: retained + linked + marker, but ZERO revision leaves
// ---------------------------------------------------------------------------

#[test]
fn conserve_flag_off_marks_and_links_but_emits_no_leaf() {
    let _g = flag_guard();
    ai_memory::config::set_append_only(false);

    let conn = open_mem_db();
    let loser = seed_mem("loser", "green", 0.8, OLD_TS, "winner");
    let winner = seed_mem("winner", "blue", 0.9, NEW_TS, "loser");
    ai_memory::db::insert(&conn, &loser).unwrap();
    ai_memory::db::insert(&conn, &winner).unwrap();

    ai_memory::db::conserve_contradiction(&conn, &loser, "winner", None).expect("conserve");

    assert!(ai_memory::db::get(&conn, "loser").unwrap().is_some());
    assert!(ai_memory::db::get(&conn, "winner").unwrap().is_some());
    assert_eq!(
        contradicts_edges(&conn, "loser", "winner").len(),
        1,
        "linked"
    );
    assert_eq!(
        marker_bool(&conn, "loser", field_names::CONTRADICTION_CONSERVED),
        Some(true),
        "marker set even with the flag OFF"
    );
    assert_eq!(leaf_count(&conn), 0, "flag OFF emits ZERO revision leaves");
}

// ---------------------------------------------------------------------------
// g — reversal removes the edge + clears the markers, both rows intact,
//     and appends NO compensating leaf
// ---------------------------------------------------------------------------

#[test]
fn reverse_conserve_removes_edge_and_clears_marker() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    let loser = seed_mem("loser", "green", 0.8, OLD_TS, "winner");
    let winner = seed_mem("winner", "blue", 0.9, NEW_TS, "loser");
    ai_memory::db::insert(&conn, &loser).unwrap();
    ai_memory::db::insert(&conn, &winner).unwrap();

    ai_memory::db::conserve_contradiction(&conn, &loser, "winner", None).expect("conserve");
    assert_eq!(contradicts_edges(&conn, "loser", "winner").len(), 1);
    assert_eq!(leaf_count(&conn), 1, "conserve wrote its one leaf");

    let (src, tgt) = ai_memory::db::canonical_contradiction_pair("loser", "winner");
    let entry = RollbackEntry::ConserveContradiction {
        loser_id: "loser".to_string(),
        winner_id: "winner".to_string(),
        canonical_src: src.to_string(),
        canonical_tgt: tgt.to_string(),
    };
    let applied = autonomy::reverse_rollback_entry(&conn, &entry).expect("reverse");
    assert!(applied, "reversal reports it acted");

    // edge gone, markers cleared, BOTH rows intact.
    assert_eq!(
        contradicts_edges(&conn, "loser", "winner").len(),
        0,
        "edge removed"
    );
    let loser_row = ai_memory::db::get(&conn, "loser")
        .unwrap()
        .expect("loser intact");
    assert!(
        ai_memory::db::get(&conn, "winner").unwrap().is_some(),
        "winner intact"
    );
    assert!(
        loser_row
            .metadata
            .get(field_names::CONTRADICTION_CONSERVED)
            .is_none()
    );
    assert!(
        loser_row
            .metadata
            .get(field_names::CONTRADICTION_SOFT_LOSER)
            .is_none()
    );
    assert!(
        loser_row
            .metadata
            .get(field_names::CONTRADICTION_WINNER_ID)
            .is_none()
    );
    assert_eq!(loser_row.updated_at, OLD_TS, "updated_at still preserved");

    // NO compensating leaf — the one SUPERSEDE from conserve time stands.
    assert_eq!(
        leaf_count(&conn),
        1,
        "reversal appends no compensating leaf"
    );
}
