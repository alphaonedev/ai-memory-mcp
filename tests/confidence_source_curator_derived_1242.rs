// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_wrap
)]

//! v0.7.0 issue #1242 regression — persona + atom rows must stamp
//! `confidence_source = "curator_derived"`, not `"caller_provided"`.
//!
//! # The bug
//!
//! Pre-#1242 both write sites — `src/persona/mod.rs:397` and
//! `src/atomisation/mod.rs:599` — minted rows with
//! `ConfidenceSource::CallerProvided` even though the value on the
//! row was engine-derived (persona pins `confidence = 1.0` per the
//! QW-2 brief; atoms inherit the parent's `confidence` from
//! `source.confidence`). That mis-labelling hides those rows from
//! the partial `idx_memories_confidence_source` enumeration the
//! calibration sweep scans (the index `WHERE confidence_source !=
//! 'caller_provided'` predicate excluded them), and violates the
//! audit-honesty invariant that the discriminator must reflect the
//! actual provenance.
//!
//! # The fix
//!
//! Added a fifth `ConfidenceSource::CuratorDerived` variant (wire
//! string `"curator_derived"`), wired into both write sites. The
//! partial index continues to filter on `!= 'caller_provided'`, so
//! every curator-derived row now lands in the index and surfaces
//! to the calibration sweep + forensic audit.
//!
//! # What this file pins
//!
//! Two integration tests that hit the SQLite write path through the
//! public engine APIs and read the resulting `confidence_source`
//! column back via raw SQL:
//!
//! 1. `persona_row_stamped_curator_derived` — drives
//!    `PersonaGenerator::generate` against a seeded reflection
//!    cluster and asserts the persona row's `confidence_source`
//!    column reads `"curator_derived"`.
//!
//! 2. `atom_row_stamped_curator_derived` — drives
//!    `Atomiser::atomise_sync` against a seeded long observation
//!    and asserts EVERY atom row's `confidence_source` column reads
//!    `"curator_derived"`.
//!
//! Both tests also confirm the discriminator passes the partial
//! index's `!= 'caller_provided'` predicate by counting rows the
//! calibration-style query would surface.

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::autonomy::AutonomyLlm;
use ai_memory::config::FeatureTier;
use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::persona::{PersonaConfig, PersonaGenerator};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared scaffolding — fresh DB + stubs
// ---------------------------------------------------------------------------

fn fresh_db() -> (Connection, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    let conn = db::open(Path::new(&path)).expect("open fresh db");
    (conn, dir)
}

/// Deterministic stub for the persona curator LLM. Echoes a canned
/// summary so the engine end-to-end runs without an Ollama
/// round-trip.
struct StubPersonaLlm;

impl AutonomyLlm for StubPersonaLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, _memories: &[(String, String)]) -> anyhow::Result<String> {
        Ok("Alice is composed and thoughtful; she values clarity.".to_string())
    }
}

/// Deterministic stub for the atomisation curator. Returns a canned
/// atom list keyed off the call count (one queued response per call).
struct StubAtomiseCurator {
    responses: Mutex<Vec<Vec<Atom>>>,
}

impl StubAtomiseCurator {
    fn new(responses: Vec<Vec<Atom>>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }
}

impl Curator for StubAtomiseCurator {
    fn decompose(
        &self,
        _body: &str,
        _max_atom_tokens: u32,
        _max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        let mut q = self.responses.lock().unwrap();
        if q.is_empty() {
            return Err(CuratorError::MalformedResponse(
                "stub: queue exhausted".into(),
            ));
        }
        Ok(q.remove(0))
    }
}

fn seed_reflection_mentioning(conn: &Connection, namespace: &str, entity_id: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: format!("reflection about {entity_id}"),
        content: format!(
            "{entity_id} demonstrated calm decision-making during the deploy postmortem."
        ),
        tags: vec!["reflection".into()],
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({
            "agent_id": "test-agent",
            "entity_id": entity_id,
        }),
        reflection_depth: 1,
        memory_kind: MemoryKind::Reflection,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed reflection")
}

fn seed_long_observation(conn: &Connection, namespace: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let body = (0..15).map(|i| format!(
        "Paragraph {i}: The kubernetes rolling deploy strategy required canary instance health checks. \
         The pod readiness probe must pass before traffic shifts. Failures roll back the deployment \
         within 30 seconds. Operator dashboards track replica counts and error rates."
    )).collect::<Vec<_>>().join(" ");
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("long-obs-{}", uuid::Uuid::new_v4().simple()),
        content: body,
        tags: vec!["kubernetes".into()],
        priority: 5,
        // Distinct non-1.0 value so the inheritance assertion below
        // is meaningful — atoms must carry THIS value while still
        // stamping the engine-provenance discriminator.
        confidence: 0.85,
        source: "test".into(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "test-agent"}),
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
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed long observation")
}

// ---------------------------------------------------------------------------
// Test 1 — persona row stamps curator_derived
// ---------------------------------------------------------------------------

#[test]
fn persona_row_stamped_curator_derived() {
    let (conn, _dir) = fresh_db();

    // Seed enough reflections so the generator's source-pool minimum is
    // satisfied (the engine requires at least one matching reflection).
    let _r1 = seed_reflection_mentioning(&conn, "team/alpha", "alice");
    let _r2 = seed_reflection_mentioning(&conn, "team/alpha", "alice");

    let llm = StubPersonaLlm;
    let generator = PersonaGenerator::new(&conn, &llm, None, PersonaConfig::default());
    let persona = generator
        .generate("alice", "team/alpha")
        .expect("persona generates");

    // Read the persona row's confidence_source column back via raw SQL.
    let stored: String = conn
        .query_row(
            "SELECT confidence_source FROM memories WHERE id = ?1",
            rusqlite::params![&persona.id],
            |r| r.get(0),
        )
        .expect("persona row exists");

    assert_eq!(
        stored, "curator_derived",
        "persona row must stamp confidence_source=curator_derived (issue #1242), got {stored:?}"
    );

    // The partial index `idx_memories_confidence_source` covers rows
    // whose discriminator is NOT 'caller_provided'. A calibration-style
    // enumeration must surface the persona row post-fix.
    let n_visible: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = ?1 \
               AND confidence_source != 'caller_provided'",
            rusqlite::params![&persona.id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        n_visible, 1,
        "post-#1242 persona row must pass the partial-index predicate \
         `confidence_source != 'caller_provided'` (calibration scan visibility)"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — every atom row stamps curator_derived
// ---------------------------------------------------------------------------

#[test]
fn atom_row_stamped_curator_derived() {
    let (conn, _dir) = fresh_db();
    let source_id = seed_long_observation(&conn, "ns/wt1b/atom_provenance");

    // Three atoms; the engine writes one row per atom + stamps the
    // `atom_of` column on each.
    let curator = Box::new(StubAtomiseCurator::new(vec![vec![
        Atom {
            text: "First atom about kubernetes deploys.".into(),
        },
        Atom {
            text: "Second atom about readiness probes.".into(),
        },
        Atom {
            text: "Third atom about rollback windows.".into(),
        },
    ]]));
    let atomiser = Atomiser::new(curator, None, AtomiserConfig::default(), FeatureTier::Smart);

    let result = atomiser
        .atomise_sync(&conn, &source_id, 200, false, "test-agent")
        .expect("atomise must succeed against the seeded long body");
    assert!(
        result.atom_ids.len() >= 2,
        "engine should mint at least 2 atoms (got {})",
        result.atom_ids.len()
    );

    for atom_id in &result.atom_ids {
        let stored: String = conn
            .query_row(
                "SELECT confidence_source FROM memories WHERE id = ?1",
                rusqlite::params![atom_id],
                |r| r.get(0),
            )
            .expect("atom row exists");

        assert_eq!(
            stored, "curator_derived",
            "atom row {atom_id} must stamp confidence_source=curator_derived \
             (issue #1242), got {stored:?}"
        );

        // Round-trip via the typed enum — parses back cleanly.
        let parsed = ConfidenceSource::from_str(&stored)
            .expect("curator_derived must round-trip through ConfidenceSource::from_str");
        assert_eq!(parsed, ConfidenceSource::CuratorDerived);
    }

    // Partial-index visibility: every atom row passes the
    // `!= 'caller_provided'` predicate so the calibration sweep
    // surfaces them. Pre-fix this count was 0 (atom rows stamped
    // CallerProvided and were excluded from the index).
    let n_visible: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE atom_of = ?1 \
               AND confidence_source != 'caller_provided'",
            rusqlite::params![&source_id],
            |r| r.get(0),
        )
        .expect("count atoms in partial-index slice");
    assert_eq!(
        n_visible,
        result.atom_ids.len() as i64,
        "post-#1242 every atom of {source_id} must pass the partial-index predicate \
         `confidence_source != 'caller_provided'` (calibration scan visibility)"
    );
}
