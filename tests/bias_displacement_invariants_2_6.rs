// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value
)]

//! FX-9 / ARCH-4 — §2.6 bias-displacement substrate-level invariant pins.
//!
//! # Why this file exists
//!
//! `docs/strategy/moonshot-synthesis.md` §2.6 declares the substrate's
//! bias-displacement property — the federalist-papers move applied to AI
//! cognition: "the substrate does not trust any single cognition; it
//! trusts only the intersection of cognitions with decorrelated errors."
//! Pre-FX-9 the principle was documentation-only — no mechanical
//! invariant pinned the substrate-level behaviour that operationalises
//! it. The ARCH-4 review surfaced this as a drift risk: doc text without
//! a substrate-level test is a property held by operator discipline, not
//! by architecture.
//!
//! This file pins four mechanical invariants that ARE testable today
//! AND are load-bearing for §2.6 to actually hold at the substrate
//! layer:
//!
//! ## Invariant 1 — Recall determinism over identical memory set + query
//!
//! Two `db::recall` calls against the same memory set, in the same
//! process, with the same query, MUST return the same MEMORIES in the
//! same ORDER (id ranking byte-equal). Absolute score floats are
//! permitted to drift because the substrate's scoring formula
//! includes a wall-clock-dependent recency factor
//! (`julianday('now') - julianday(updated_at)`); the load-bearing
//! property for §2.6 is ranking stability, not score-value stability.
//!
//! Why this is §2.6-relevant: a non-deterministic recall RANKING
//! would mean "the substrate's view of itself" varies on identical
//! inputs — there would be no stable "production" for a reflector to
//! reflect, so the bias-displacement composition `producer × reflector`
//! is meaningless. Ranking determinism is the substrate-side
//! precondition for reflection to be a meaningful operation.
//!
//! ## Invariant 2 — Confidence source attribution preservation
//!
//! When `db::insert` stores a memory with `confidence_source = X`, the
//! row's `confidence_source` column reads back exactly `X` for every
//! variant of [`ConfidenceSource`]. The discriminator that says "where
//! did this confidence number come from" is not silently rewritten by
//! the substrate.
//!
//! Why this is §2.6-relevant: the bias-displacement audit trail
//! requires the substrate to honestly report the provenance of every
//! confidence score. If `CallerProvided` and `AutoDerived` are
//! interchangeable on the wire, a reflector cannot tell whose bias the
//! number reflects, and the §2.6 composition collapses.
//!
//! ## Invariant 3 — V-4 chain coverage for substrate writes
//!
//! After a `create_link` write, `signed_events` has an entry with the
//! correct `prev_hash` linkage: `current.prev_hash ==
//! sha256(canonical_chain_bytes(prior_row))`. The V-4 cross-row hash
//! chain holds end-to-end across substrate-attested writes.
//!
//! Why this is §2.6-relevant: bias-displacement requires that every
//! claim about a substrate write is cryptographically anchored. The
//! V-4 chain is the substrate's tamper-evidence — a §2.6 reflector
//! can only meaningfully reflect on a producer's actions if those
//! actions are anchored to an immutable chain the reflector can
//! independently verify.
//!
//! ## Invariant 4 — Recall blindness to LLM vendor backend (HEADLINE)
//!
//! THE §2.6 HEADLINE INVARIANT. The same memory set + the same recall
//! query MUST yield the same RANKING (id order byte-equal) regardless
//! of which value `AI_MEMORY_LLM_BACKEND` holds. (Score floats drift
//! with wall-clock per Invariant 1's caveat; the ranking is the
//! load-bearing property.) The substrate's recall path is
//! structurally independent of vendor — recall reads FTS5 + the
//! `memories` table, never the LLM client — so swapping the LLM
//! backend env var between `ollama` and `xai` MUST be a no-op on
//! recall output.
//!
//! Why this is §2.6-relevant: bias-displacement requires the substrate
//! itself to be neutral to which cognition operates through it. If
//! recall results varied with vendor, the substrate would have a hidden
//! preference — same-vendor reflection would look more coherent than
//! cross-vendor reflection, and the §2.6 composition would be biased
//! at the substrate layer. The substrate IS vendor-neutral at the
//! recall surface by construction (the recall code path reads no LLM
//! env vars), and this test pins that property mechanically so a
//! future change that introduces vendor-dependent behaviour in recall
//! trips a hard test failure.
//!
//! # What this file does NOT test
//!
//! - Anything about "fairness" or "neutrality" abstractly — those are
//!   not mechanical properties.
//! - Whether the producer/reflector models are themselves decorrelated
//!   — that is the unresolved §2.6 gap explicitly named in the doc
//!   (deferred for operator discussion; tracked separately).
//! - Whether reflection synthesis is unbiased — that is a property of
//!   the reflector LLM, not of the substrate.
//!
//! The invariants here pin the substrate-side preconditions for §2.6.
//! The reflector-side gap (cryptographic family-attestation) stays a
//! documented future-commitment per the §2.6 doc.

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::signed_events::{canonical_chain_bytes, list_signed_events};
use ai_memory::storage;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tempfile::TempDir;

mod common;
use common::EnvVarGuard;

// ---------------------------------------------------------------------------
// Shared scaffolding
// ---------------------------------------------------------------------------

/// Process-wide lock so the env-mutating Invariant-4 test doesn't race
/// the determinism / confidence / chain tests that don't touch env.
/// Mirrors the pattern in `tests/form_4_provenance.rs`.
fn test_serial() -> &'static Mutex<()> {
    static M: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

fn fresh_db() -> (Connection, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    let conn = db::open(&path).expect("open fresh db");
    (conn, dir)
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn mem_with_source(
    ns: &str,
    title: &str,
    content: &str,
    confidence_source: ConfidenceSource,
) -> Memory {
    let now = now();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: Vec::new(),
        priority: 5,
        confidence: 0.7,
        source: "test".to_string(),
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
        confidence_source,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Recall against the standard substrate path with default TTL
/// parameters and no filters. Wraps the long parameter list so the
/// invariant-test bodies stay focused on the comparison.
fn recall_default(conn: &Connection, ns: &str, query: &str) -> Vec<(String, f64)> {
    let resolved_ttl = ai_memory::config::ResolvedTtl::default();
    let (results, _outcome) = db::recall(
        conn,
        query,
        Some(ns),
        20,
        None,
        None,
        None,
        resolved_ttl.short_extend_secs,
        resolved_ttl.mid_extend_secs,
        None,
        None,
        false,
        None,
    )
    .expect("recall");
    results.into_iter().map(|(m, s)| (m.id, s)).collect()
}

// ---------------------------------------------------------------------------
// Invariant 1 — Recall determinism over identical memory set + query
// ---------------------------------------------------------------------------

#[test]
fn invariant_1_recall_is_deterministic_over_identical_memory_set_and_query() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (conn, _dir) = fresh_db();
    let ns = "fx9/invariant1";

    // Seed N memories spanning content variation so the FTS5 scoring
    // has a non-trivial ordering to produce.
    let titles_and_bodies = [
        ("alpha doc", "kubernetes pod rolling deploy strategy"),
        ("beta doc", "kubernetes service mesh sidecar injection"),
        (
            "gamma doc",
            "kubernetes operator pattern custom resource definitions",
        ),
        ("delta doc", "kubernetes namespace isolation rbac roles"),
        ("epsilon doc", "postgres replication streaming hot standby"),
        ("zeta doc", "postgres autovacuum tuning bloat reclaim"),
    ];
    for (title, body) in titles_and_bodies {
        let mem = mem_with_source(ns, title, body, ConfidenceSource::CallerProvided);
        storage::insert(&conn, &mem).expect("insert seed");
    }

    // First recall pass — establishes the substrate's "view" of itself
    // under this query.
    let first = recall_default(&conn, ns, "kubernetes");
    assert!(
        !first.is_empty(),
        "seed should produce non-empty recall result so the determinism \
         check carries real load (substrate returned no rows for the \
         'kubernetes' FTS query — fixture drift)"
    );

    // Second recall pass — must be byte-identical in ID ORDER. The
    // substrate's "view of itself" must not vary on identical inputs.
    //
    // Note on scores: the recall scoring formula in
    // `src/storage/mod.rs::recall` includes a recency factor
    // `1.0 / (1.0 + (julianday('now') - julianday(m.updated_at)) * 0.1)`
    // whose absolute value DOES legitimately drift with wall-clock
    // between calls, even on the same memory set. The load-bearing
    // §2.6 invariant is that the RANKING (id order) is stable on
    // identical inputs — same memories returned in the same order —
    // not that the absolute score float is byte-equal. We pin the
    // ranking; we accept the recency-induced numeric drift as
    // documented substrate behaviour, not non-determinism.
    let second = recall_default(&conn, ns, "kubernetes");
    assert_eq!(
        first.len(),
        second.len(),
        "Invariant 1 violated: recall result LEN differs across two \
         identical calls: first={} second={}",
        first.len(),
        second.len(),
    );
    let first_ids: Vec<&str> = first.iter().map(|(id, _)| id.as_str()).collect();
    let second_ids: Vec<&str> = second.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        first_ids, second_ids,
        "Invariant 1 violated: recall result ID order differs across \
         two identical calls. The substrate's ranking under a given \
         query must be deterministic for §2.6 reflection to operate \
         on a stable production."
    );
}

// ---------------------------------------------------------------------------
// Invariant 2 — Confidence source attribution preservation
// ---------------------------------------------------------------------------

#[test]
fn invariant_2_confidence_source_attribution_is_preserved_for_every_variant() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (conn, _dir) = fresh_db();
    let ns = "fx9/invariant2";

    // Enumerate every ConfidenceSource variant so a future variant
    // addition without a corresponding write-path wiring fails this
    // test instead of silently mis-attributing.
    let variants = [
        (ConfidenceSource::CallerProvided, "caller_provided"),
        (ConfidenceSource::AutoDerived, "auto_derived"),
        (ConfidenceSource::Calibrated, "calibrated"),
        (ConfidenceSource::Decayed, "decayed"),
        (ConfidenceSource::CuratorDerived, "curator_derived"),
    ];

    // The enum's compiler-derived as_str() is the canonical
    // serialisation; double-check it matches the column-wire strings
    // we're about to assert against, so a rename of the enum's
    // wire-string output would surface here rather than as a
    // mysterious row-level discrepancy.
    for (variant, expected_wire) in variants {
        assert_eq!(
            variant.as_str(),
            expected_wire,
            "Invariant 2 pre-condition: ConfidenceSource::as_str() drift \
             for variant {variant:?} — expected {expected_wire:?}"
        );
    }

    for (variant, expected_wire) in variants {
        let title = format!("{expected_wire}-row");
        let mem = mem_with_source(ns, &title, "attribution-test-body", variant);
        let id = storage::insert(&conn, &mem).expect("insert variant row");

        // Read the column back via raw SQL — bypasses any
        // Memory-struct-level coercion so the test pins the actual
        // on-disk discriminator.
        let stored: String = conn
            .query_row(
                "SELECT confidence_source FROM memories WHERE id = ?1",
                rusqlite::params![&id],
                |r| r.get(0),
            )
            .expect("row exists");
        assert_eq!(
            stored, expected_wire,
            "Invariant 2 violated: caller-supplied ConfidenceSource::{variant:?} \
             (wire {expected_wire:?}) was rewritten to {stored:?} on the row's \
             confidence_source column. The discriminator must round-trip exactly \
             — bias-displacement audit requires honest provenance reporting."
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 3 — V-4 chain coverage for substrate writes
// ---------------------------------------------------------------------------

#[test]
fn invariant_3_v4_chain_holds_across_substrate_attested_writes() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (conn, _dir) = fresh_db();
    let ns = "fx9/invariant3";

    // Seed three memories whose pairwise links will produce three
    // signed_events rows (one per link.created event). Three is the
    // minimum to verify chain LINKAGE (first row's prev_hash is
    // ZERO_HASH per definition; the property we want to pin is that
    // EACH SUBSEQUENT row's prev_hash chains to the canonical-bytes
    // digest of the PREVIOUS row).
    let m1 = mem_with_source(
        ns,
        "source-1",
        "alpha body",
        ConfidenceSource::CallerProvided,
    );
    let m2 = mem_with_source(
        ns,
        "source-2",
        "beta body",
        ConfidenceSource::CallerProvided,
    );
    let m3 = mem_with_source(
        ns,
        "source-3",
        "gamma body",
        ConfidenceSource::CallerProvided,
    );
    let id1 = storage::insert(&conn, &m1).expect("insert m1");
    let id2 = storage::insert(&conn, &m2).expect("insert m2");
    let id3 = storage::insert(&conn, &m3).expect("insert m3");

    // Three link writes — each appends a signed_events row with
    // event_type = "memory_link.created". The chain MUST hold.
    storage::create_link(&conn, &id1, &id2, "related_to").expect("link 1->2");
    storage::create_link(&conn, &id2, &id3, "related_to").expect("link 2->3");
    storage::create_link(&conn, &id1, &id3, "related_to").expect("link 1->3");

    // Pull every signed_events row in chain order.
    let events = list_signed_events(&conn, None, 100, 0).expect("list signed_events");
    assert!(
        events.len() >= 3,
        "Invariant 3 pre-condition: expected at least 3 signed_events rows \
         for the three create_link writes; got {}",
        events.len()
    );

    // Filter to the memory_link.created subset and verify the chain
    // linkage row-to-row. Sequence numbers must be monotonically
    // increasing and prev_hash must chain to the canonical-bytes
    // SHA-256 of the preceding row.
    let link_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "memory_link.created")
        .collect();
    assert_eq!(
        link_events.len(),
        3,
        "Invariant 3 pre-condition: expected exactly 3 \
         memory_link.created rows; got {}",
        link_events.len()
    );

    // The events come back in sequence order (list_signed_events
    // orders by sequence ASC for stable replay). Verify each row's
    // prev_hash matches sha256(canonical_chain_bytes(prior_event)).
    // We walk the full event list (not just the link-events subset)
    // because the chain is global across all event types.
    for i in 1..events.len() {
        let prior = &events[i - 1];
        let current = &events[i];
        assert_eq!(
            current.sequence,
            prior.sequence + 1,
            "Invariant 3 violated: signed_events sequence non-contiguous \
             at index {i}: prior.sequence={}, current.sequence={}",
            prior.sequence,
            current.sequence,
        );
        let expected_prev = {
            let mut h = Sha256::new();
            h.update(canonical_chain_bytes(prior));
            h.finalize().to_vec()
        };
        assert_eq!(
            current.prev_hash, expected_prev,
            "Invariant 3 violated: signed_events row at sequence={} has \
             prev_hash that does NOT match sha256(canonical_bytes(prior)). \
             V-4 cross-row hash chain is broken — bias-displacement audit \
             trail is no longer tamper-evident.",
            current.sequence,
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 4 — Recall blindness to LLM vendor backend (HEADLINE)
// ---------------------------------------------------------------------------

/// HEADLINE §2.6 invariant.
///
/// The substrate's recall path reads NO `AI_MEMORY_LLM_*` env var
/// (verified by inspection of `src/storage/mod.rs::recall` — no env
/// lookups appear in the function body or its dependency closure for
/// vendor-affecting decisions). So flipping `AI_MEMORY_LLM_BACKEND`
/// between `ollama` and `xai` MUST be a no-op on recall output, byte
/// for byte. This test pins that as a mechanical property so a future
/// change that introduces vendor-dependent behaviour in recall trips
/// here rather than landing silently.
///
/// We do not need to actually call out to either LLM — recall doesn't
/// invoke an LLM unless the caller routes through the reflector. The
/// invariant under test is exactly that recall is vendor-blind at the
/// substrate layer.
#[test]
fn invariant_4_recall_results_are_blind_to_llm_vendor_backend() {
    let _g = test_serial()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (conn, _dir) = fresh_db();
    let ns = "fx9/invariant4";

    // Seed a memory set whose top-K under the query has enough
    // structure that a hidden vendor-dependent ranking shift would
    // surface as a visible reorder.
    let seed = [
        ("alpha", "kubernetes pod rolling deploy strategy"),
        ("beta", "kubernetes service mesh sidecar injection"),
        ("gamma", "kubernetes operator pattern custom resource"),
        ("delta", "kubernetes namespace isolation rbac roles"),
        ("epsilon", "kubernetes ingress controller tls termination"),
        ("zeta", "kubernetes horizontal pod autoscaler"),
    ];
    for (title, body) in seed {
        let mem = mem_with_source(ns, title, body, ConfidenceSource::CallerProvided);
        storage::insert(&conn, &mem).expect("insert seed");
    }

    // Snapshot result under backend=ollama.
    let under_ollama = {
        let _g_env = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", "ollama".to_string());
        recall_default(&conn, ns, "kubernetes")
    };

    // Snapshot result under backend=xai. EnvVarGuard restores on drop
    // so subsequent tests see the original env state.
    let under_xai = {
        let _g_env = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", "xai".to_string());
        recall_default(&conn, ns, "kubernetes")
    };

    // Both passes must produce non-empty results so the comparison
    // carries real load.
    assert!(
        !under_ollama.is_empty(),
        "Invariant 4 pre-condition: recall under backend=ollama produced \
         empty results — fixture drift"
    );
    assert!(
        !under_xai.is_empty(),
        "Invariant 4 pre-condition: recall under backend=xai produced \
         empty results — fixture drift"
    );

    // THE invariant. Same RANKING (id order) across vendor backends.
    //
    // Note on scores: the recall scoring formula in
    // `src/storage/mod.rs::recall` includes a recency factor that
    // drifts with wall-clock between calls. The load-bearing §2.6
    // invariant is that the SAME memories come back in the SAME
    // ORDER regardless of vendor — not that the absolute score float
    // is byte-equal. We pin the ranking; wall-clock-induced numeric
    // drift is documented substrate behaviour. A regression that
    // makes ranking depend on the LLM vendor would shift IDs across
    // these snapshots and trip the assertion here.
    assert_eq!(
        under_ollama.len(),
        under_xai.len(),
        "Invariant 4 violated: recall result LEN differs across LLM \
         backends: ollama={} xai={}. The substrate's recall path MUST \
         be vendor-blind for §2.6 to hold at the substrate layer.",
        under_ollama.len(),
        under_xai.len(),
    );
    let ollama_ids: Vec<&str> = under_ollama.iter().map(|(id, _)| id.as_str()).collect();
    let xai_ids: Vec<&str> = under_xai.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ollama_ids, xai_ids,
        "Invariant 4 violated: recall result ID order differs across \
         LLM backends (ollama vs xai). The substrate's recall ordering \
         MUST NOT depend on the LLM vendor — §2.6 bias-displacement \
         requires the substrate itself to be vendor-neutral."
    );

    // Defense-in-depth: a third backend value (the generic vendor
    // alias) must also produce the same ranking, so the invariant
    // catches a regression that special-cases a specific pair of
    // backends while still varying on a third.
    let under_openai = {
        let _g_env = EnvVarGuard::set("AI_MEMORY_LLM_BACKEND", "openai".to_string());
        recall_default(&conn, ns, "kubernetes")
    };
    assert_eq!(
        under_ollama.len(),
        under_openai.len(),
        "Invariant 4 (defense-in-depth) violated: recall result LEN \
         under backend=openai diverged from ollama"
    );
    let openai_ids: Vec<&str> = under_openai.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ollama_ids, openai_ids,
        "Invariant 4 (defense-in-depth) violated: recall result ID \
         order under backend=openai diverged from ollama"
    );
}
