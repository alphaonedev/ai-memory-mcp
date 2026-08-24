// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2395 / #2394 — MERGE FIELD-SET COHERENCE on both sqlite upsert
//! funnels.
//!
//! Two independent instances of one defect class: a merged row whose
//! surviving VALUE and the metadata that DESCRIBES that value were selected
//! by DIFFERENT rules, so the durable row ended up attesting a fact about an
//! operand the merge had already thrown away.
//!
//! * **#2395** — `confidence` merged by `MAX(...)` while `confidence_source`
//!   / `confidence_signals` / `confidence_decayed_at` merged by "explicit
//!   non-default replaces / COALESCE" (local upsert) or by the `updated_at`/`id`
//!   newer-wins tiebreak (federation). Merging a stored `(0.9, auto_derived,
//!   S1)` with an incoming `(0.4, calibrated, S2)` produced the durable row
//!   `confidence = 0.9` labelled `calibrated` carrying `S2`.
//! * **#2394** — `memory_kind` is STICKY (a stored `reflection` / `persona`
//!   is never downgraded) while `kind_provenance` merged by a bare
//!   `COALESCE(excluded, memories)`, so the surviving kind was relabelled
//!   with the REJECTED write's provenance.
//!
//! Both are durable-metadata corruption, not display skew: every downstream
//! consumer (calibration review, decorrelation, typed-cognition analytics)
//! reads the stored pair as fact. The fix makes each field-set ATOMIC — one
//! selector picks the winning operand's WHOLE tuple.
//!
//! The postgres twins carry the identical SQL and are covered by
//! `tests/pg_merge_field_set_coherence_2394_2395.rs` (live-PG gated).

use ai_memory::db;
use ai_memory::models::{
    ConfidenceSignals, ConfidenceSource, KindProvenance, Memory, MemoryKind, Tier, default_metadata,
};
use rusqlite::{Connection, params};

fn open_db() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

const NS: &str = "merge-coherence-2394-2395";

fn signals(age_days: f64) -> ConfidenceSignals {
    ConfidenceSignals {
        source_age_days: age_days,
        atom_derivation: false,
        prior_corroboration_count: 0,
        freshness_factor: 1.0,
        baseline_per_source: 0.5,
    }
}

fn memory(title: &str, updated_at: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "merge coherence content".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: updated_at.to_string(),
        metadata: default_metadata(),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    }
}

/// Seed the EXACT stored tuple the merge is about to run against, bypassing
/// every write-funnel normalisation so the assertion isolates the `ON
/// CONFLICT DO UPDATE` selector under test.
#[allow(clippy::too_many_arguments)]
fn seed_stored_tuple(
    conn: &Connection,
    title: &str,
    confidence: f64,
    source: ConfidenceSource,
    signals_json: Option<&str>,
    decayed_at: Option<&str>,
) -> String {
    let mem = memory(title, "2026-02-01T00:00:00+00:00");
    let id = ai_memory::storage::insert(conn, &mem).expect("seed insert");
    conn.execute(
        "UPDATE memories SET confidence = ?1, confidence_source = ?2, \
         confidence_signals = ?3, confidence_decayed_at = ?4 WHERE id = ?5",
        params![confidence, source.as_str(), signals_json, decayed_at, id],
    )
    .expect("seed confidence tuple");
    id
}

fn read_confidence_tuple(
    conn: &Connection,
    title: &str,
) -> (f64, String, Option<String>, Option<String>) {
    conn.query_row(
        "SELECT confidence, confidence_source, confidence_signals, confidence_decayed_at \
         FROM memories WHERE title = ?1 AND namespace = ?2",
        params![title, NS],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .expect("read merged confidence tuple")
}

fn read_kind_pair(conn: &Connection, title: &str) -> (String, Option<String>) {
    conn.query_row(
        "SELECT memory_kind, kind_provenance FROM memories \
         WHERE title = ?1 AND namespace = ?2",
        params![title, NS],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("read merged kind pair")
}

// ---------------------------------------------------------------------------
// #2395 — local upsert funnel (`storage::insert` -> `upsert_sql`)
// ---------------------------------------------------------------------------

/// The stored row WINS the `MAX(confidence)`, so its calibration record must
/// survive INTACT. Pre-#2395 the incoming non-default `confidence_source`
/// replaced the label and the incoming `confidence_signals` /
/// `confidence_decayed_at` replaced the evidence — the durable row then said
/// "0.9, calibrated, S2" when 0.9 was
/// the auto-derived operand's number and S2 described the 0.4 that lost.
#[test]
fn upsert_losing_operand_cannot_relabel_the_surviving_confidence_2395() {
    let conn = open_db();
    let title = "coherence-lower-loses";
    seed_stored_tuple(
        &conn,
        title,
        0.9,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        Some("2026-03-01T00:00:00+00:00"),
    );

    let mut incoming = memory(title, "2026-04-01T00:00:00+00:00");
    incoming.confidence = 0.4;
    incoming.confidence_source = ConfidenceSource::Calibrated;
    incoming.confidence_signals = Some(signals(99.0));
    incoming.confidence_decayed_at = Some("2026-04-01T00:00:00+00:00".to_string());
    ai_memory::storage::insert(&conn, &incoming).expect("upsert merge");

    let (confidence, source, sig, decayed) = read_confidence_tuple(&conn, title);
    assert!(
        (confidence - 0.9).abs() < f64::EPSILON,
        "MAX must keep the higher stored confidence, got {confidence}"
    );
    assert_eq!(
        source,
        ConfidenceSource::AutoDerived.as_str(),
        "#2395: the surviving confidence must keep ITS OWN source label"
    );
    assert_eq!(
        sig.as_deref(),
        Some(r#"{"source_age_days":1.0}"#),
        "#2395: signals must ride the operand that won the MAX"
    );
    assert_eq!(
        decayed.as_deref(),
        Some("2026-03-01T00:00:00+00:00"),
        "#2395: confidence_decayed_at must ride the operand that won the MAX"
    );
}

/// The INCOMING row wins the `MAX(confidence)`, so its calibration record —
/// including a `caller_provided` label and ABSENT signals — must be adopted
/// wholesale. Pre-#2395 a `caller_provided` incoming source kept the stored
/// `auto_derived` label and the `COALESCE` kept the stored signals, so the
/// row attested auto-derivation for a number the caller simply asserted.
#[test]
fn upsert_winning_operand_carries_its_own_calibration_record_2395() {
    let conn = open_db();
    let title = "coherence-higher-wins";
    seed_stored_tuple(
        &conn,
        title,
        0.4,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        Some("2026-03-01T00:00:00+00:00"),
    );

    let mut incoming = memory(title, "2026-04-01T00:00:00+00:00");
    incoming.confidence = 0.9;
    incoming.confidence_source = ConfidenceSource::CallerProvided;
    incoming.confidence_signals = None;
    incoming.confidence_decayed_at = None;
    ai_memory::storage::insert(&conn, &incoming).expect("upsert merge");

    let (confidence, source, sig, decayed) = read_confidence_tuple(&conn, title);
    assert!(
        (confidence - 0.9).abs() < f64::EPSILON,
        "MAX must take the higher incoming confidence, got {confidence}"
    );
    assert_eq!(
        source,
        ConfidenceSource::CallerProvided.as_str(),
        "#2395: a caller-asserted value must not wear the stored auto_derived label"
    );
    assert_eq!(
        sig, None,
        "#2395: the winner carried no signals, so no signals may survive"
    );
    assert_eq!(
        decayed, None,
        "#2395: the winner carried no decay stamp, so none may survive"
    );
}

/// On an EXACT tie the pre-#2395 #1629 rule is preserved byte-for-byte — an
/// explicit non-`caller_provided` source replaces, a default one keeps the
/// stored provenance — except that it now moves the WHOLE tuple, which is
/// the fix.
#[test]
fn upsert_equal_confidence_keeps_the_1629_tie_rule_as_a_tuple_2395() {
    let conn = open_db();

    // Default `caller_provided` incoming: the stored provenance is kept.
    let keep = "coherence-tie-keeps-stored";
    seed_stored_tuple(
        &conn,
        keep,
        0.7,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        None,
    );
    let mut plain = memory(keep, "2026-04-01T00:00:00+00:00");
    plain.confidence = 0.7;
    plain.confidence_source = ConfidenceSource::CallerProvided;
    ai_memory::storage::insert(&conn, &plain).expect("tie upsert (default source)");
    let (_, source, sig, _) = read_confidence_tuple(&conn, keep);
    assert_eq!(source, ConfidenceSource::AutoDerived.as_str());
    assert_eq!(sig.as_deref(), Some(r#"{"source_age_days":1.0}"#));

    // Explicit non-default incoming: the WHOLE incoming tuple replaces.
    let take = "coherence-tie-takes-incoming";
    seed_stored_tuple(
        &conn,
        take,
        0.7,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        None,
    );
    let mut calibrated = memory(take, "2026-04-01T00:00:00+00:00");
    calibrated.confidence = 0.7;
    calibrated.confidence_source = ConfidenceSource::Calibrated;
    calibrated.confidence_signals = Some(signals(42.0));
    ai_memory::storage::insert(&conn, &calibrated).expect("tie upsert (explicit source)");
    let (_, source, sig, _) = read_confidence_tuple(&conn, take);
    assert_eq!(source, ConfidenceSource::Calibrated.as_str());
    assert!(
        sig.as_deref()
            .is_some_and(|s| s.contains("\"source_age_days\":42.0")),
        "the explicit-source winner's OWN signals must land, got {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// #2395 — federation newer-wins funnel (`storage::insert_if_newer`)
// ---------------------------------------------------------------------------

/// A peer that LOSES the `MAX(confidence)` but WINS the `updated_at` tiebreak
/// must not relabel the surviving number. Pre-#2395 the two selectors
/// disagreed and every replica converged on the inconsistent tuple, making
/// the corruption permanent rather than transient.
#[test]
fn federation_merge_confidence_tuple_rides_the_max_winner_2395() {
    let conn = open_db();
    let title = "coherence-fed-stale-peer";
    seed_stored_tuple(
        &conn,
        title,
        0.9,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        Some("2026-03-01T00:00:00+00:00"),
    );

    // Peer row is STRICTLY NEWER by updated_at but carries a LOWER confidence.
    let mut peer = memory(title, "2026-12-01T00:00:00+00:00");
    peer.confidence = 0.4;
    peer.confidence_source = ConfidenceSource::Decayed;
    peer.confidence_signals = Some(signals(99.0));
    peer.confidence_decayed_at = Some("2026-12-01T00:00:00+00:00".to_string());
    ai_memory::storage::insert_if_newer(&conn, &peer).expect("federation merge");

    let (confidence, source, sig, decayed) = read_confidence_tuple(&conn, title);
    assert!(
        (confidence - 0.9).abs() < f64::EPSILON,
        "MAX keeps the local confidence, got {confidence}"
    );
    assert_eq!(
        source,
        ConfidenceSource::AutoDerived.as_str(),
        "#2395: a stale peer that lost the MAX must not relabel the survivor"
    );
    assert_eq!(sig.as_deref(), Some(r#"{"source_age_days":1.0}"#));
    assert_eq!(decayed.as_deref(), Some("2026-03-01T00:00:00+00:00"));
}

/// The federation selector must stay a total order whose first component IS
/// the `MAX`: a peer with a STRICTLY HIGHER confidence wins the whole tuple
/// even when it LOSES the `updated_at` tiebreak.
#[test]
fn federation_merge_higher_confidence_wins_the_whole_tuple_2395() {
    let conn = open_db();
    let title = "coherence-fed-older-but-higher";
    seed_stored_tuple(
        &conn,
        title,
        0.4,
        ConfidenceSource::AutoDerived,
        Some(r#"{"source_age_days":1.0}"#),
        None,
    );

    // Peer is OLDER by updated_at (the seed row was stored at 2026-02-01)
    // but carries a strictly higher confidence.
    let mut peer = memory(title, "2026-01-15T00:00:00+00:00");
    peer.confidence = 0.9;
    peer.confidence_source = ConfidenceSource::Calibrated;
    peer.confidence_signals = Some(signals(7.0));
    ai_memory::storage::insert_if_newer(&conn, &peer).expect("federation merge");

    let (confidence, source, sig, _) = read_confidence_tuple(&conn, title);
    assert!((confidence - 0.9).abs() < f64::EPSILON);
    assert_eq!(
        source,
        ConfidenceSource::Calibrated.as_str(),
        "#2395: the MAX winner's label must ride its own number"
    );
    assert!(
        sig.as_deref()
            .is_some_and(|s| s.contains("\"source_age_days\":7.0")),
        "got {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// #2394 — kind_provenance must follow the kind that actually won
// ---------------------------------------------------------------------------

fn seed_kind(conn: &Connection, title: &str, kind: &str, provenance: Option<&str>) {
    let mem = memory(title, "2026-02-01T00:00:00+00:00");
    let id = ai_memory::storage::insert(conn, &mem).expect("seed insert");
    conn.execute(
        "UPDATE memories SET memory_kind = ?1, kind_provenance = ?2 WHERE id = ?3",
        params![kind, provenance, id],
    )
    .expect("seed kind pair");
}

fn incoming_with_kind(title: &str, kind: MemoryKind, provenance: Option<KindProvenance>) -> Memory {
    let mut mem = memory(title, "2026-04-01T00:00:00+00:00");
    mem.memory_kind = kind;
    if let Some(p) = provenance {
        p.stamp(&mut mem.metadata);
    }
    mem
}

/// The stored `reflection` kind is STICKY, so the merge REJECTS the incoming
/// `observation`. Pre-#2394 the bare COALESCE still adopted that rejected
/// write's `llm` provenance, leaving the row claiming an LLM classifier
/// assigned a kind the classifier never produced.
#[test]
fn upsert_sticky_kind_keeps_its_own_provenance_2394() {
    let conn = open_db();
    let title = "kind-sticky-reflection";
    seed_kind(&conn, title, "reflection", Some("declared"));

    let incoming = incoming_with_kind(title, MemoryKind::Observation, Some(KindProvenance::Llm));
    ai_memory::storage::insert(&conn, &incoming).expect("upsert merge");

    let (kind, provenance) = read_kind_pair(&conn, title);
    assert_eq!(kind, "reflection", "L1-1 stickiness must hold");
    assert_eq!(
        provenance.as_deref(),
        Some("declared"),
        "#2394: provenance must describe the kind that SURVIVED, not the rejected one"
    );
}

/// When the INCOMING kind IS adopted, its provenance must be taken verbatim
/// — NULL included. Pre-#2394 the COALESCE fell back to the stored value, so
/// a kind change carrying no provenance inherited a marker minted for the
/// SUPERSEDED kind.
#[test]
fn upsert_adopted_kind_takes_the_incoming_provenance_verbatim_2394() {
    let conn = open_db();
    let title = "kind-adopted-null-provenance";
    seed_kind(&conn, title, "observation", Some("declared"));

    // No provenance stamped: the incoming carrier is absent (NULL).
    let incoming = incoming_with_kind(title, MemoryKind::Concept, None);
    ai_memory::storage::insert(&conn, &incoming).expect("upsert merge");

    let (kind, provenance) = read_kind_pair(&conn, title);
    assert_eq!(kind, "concept", "the incoming kind was adopted");
    assert_eq!(
        provenance, None,
        "#2394: a provenance minted for the SUPERSEDED kind must not be inherited"
    );
}

/// The #1945 COALESCE rule is preserved verbatim when the kind does NOT
/// change: an incoming write that omits the carrier must never blank an
/// existing marker.
#[test]
fn upsert_unchanged_kind_keeps_the_1945_coalesce_rule_2394() {
    let conn = open_db();
    let title = "kind-unchanged-coalesce";
    seed_kind(&conn, title, "observation", Some("regex"));

    let incoming = incoming_with_kind(title, MemoryKind::Observation, None);
    ai_memory::storage::insert(&conn, &incoming).expect("upsert merge");

    let (kind, provenance) = read_kind_pair(&conn, title);
    assert_eq!(kind, "observation");
    assert_eq!(
        provenance.as_deref(),
        Some("regex"),
        "#1945: an omitted carrier must not blank the stored marker"
    );
}

/// Federation twin: a peer that loses the sticky-kind merge must not
/// relabel the surviving kind's provenance either.
#[test]
fn federation_sticky_kind_keeps_its_own_provenance_2394() {
    let conn = open_db();
    let title = "kind-fed-sticky-persona";
    seed_kind(&conn, title, "persona", Some("declared"));

    let mut peer = incoming_with_kind(title, MemoryKind::Observation, Some(KindProvenance::Llm));
    peer.updated_at = "2026-12-01T00:00:00+00:00".to_string();
    ai_memory::storage::insert_if_newer(&conn, &peer).expect("federation merge");

    let (kind, provenance) = read_kind_pair(&conn, title);
    assert_eq!(kind, "persona", "QW-2 persona stickiness must hold");
    assert_eq!(
        provenance.as_deref(),
        Some("declared"),
        "#2394: a newer peer that lost the kind merge must not relabel the survivor"
    );
}
