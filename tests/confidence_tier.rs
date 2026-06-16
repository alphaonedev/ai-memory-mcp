// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Gap 4 (issue #887) — derived `ConfidenceTier` enum
//! regression suite.
//!
//! Acceptance criteria from the playbook:
//!
//! 1. `Memory::confidence_tier()` returns `Confirmed` (>=0.95),
//!    `Likely` (0.7..0.95), `Ambiguous` (<0.7) for three sample
//!    rows at 0.99 / 0.85 / 0.5.
//! 2. `memory_recall(confidence_tier="ambiguous")` returns only the
//!    0.5-confidence row.
//! 3. `memory_capabilities` surfaces the threshold map under the
//!    `confidence_calibration.tier_thresholds` block so callers can
//!    filter without re-deriving the breakpoints.

#![allow(clippy::needless_update)]

use ai_memory::config::CapabilityConfidenceCalibration;
use ai_memory::models::{ConfidenceTier, Memory};
use rusqlite::params;

fn fresh_db() -> rusqlite::Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

#[test]
fn gap4_confidence_tier_thresholds_pinned() {
    // The substrate-side mapping is load-bearing. Pin all three
    // boundary cases — anything below `LIKELY_MIN` is ambiguous,
    // anything at-or-above `CONFIRMED_MIN` is confirmed, the rest
    // is likely.
    let confirmed = Memory {
        confidence: 0.99,
        ..Memory::default()
    };
    let likely = Memory {
        confidence: 0.85,
        ..Memory::default()
    };
    let ambiguous = Memory {
        confidence: 0.5,
        ..Memory::default()
    };
    assert_eq!(confirmed.confidence_tier(), ConfidenceTier::Confirmed);
    assert_eq!(likely.confidence_tier(), ConfidenceTier::Likely);
    assert_eq!(ambiguous.confidence_tier(), ConfidenceTier::Ambiguous);

    // Boundary cases — exclusive vs inclusive matter.
    assert_eq!(
        Memory {
            confidence: 0.95,
            ..Memory::default()
        }
        .confidence_tier(),
        ConfidenceTier::Confirmed,
        "0.95 is inclusive lower bound of confirmed"
    );
    assert_eq!(
        Memory {
            confidence: 0.7,
            ..Memory::default()
        }
        .confidence_tier(),
        ConfidenceTier::Likely,
        "0.7 is inclusive lower bound of likely"
    );
    // NaN ⇒ Ambiguous (conservative fallback for corrupt input).
    assert_eq!(
        ConfidenceTier::from_confidence(f64::NAN),
        ConfidenceTier::Ambiguous,
    );
}

#[test]
fn gap4_confidence_tier_parse_roundtrips_via_str() {
    for tier in [
        ConfidenceTier::Confirmed,
        ConfidenceTier::Likely,
        ConfidenceTier::Ambiguous,
    ] {
        let s = tier.as_str();
        assert_eq!(ConfidenceTier::parse(s), Some(tier));
    }
    assert_eq!(
        ConfidenceTier::parse("  CONFIRMED  "),
        Some(ConfidenceTier::Confirmed),
        "case-insensitive + whitespace-trimming"
    );
    assert_eq!(ConfidenceTier::parse("bogus"), None);
}

#[test]
fn gap4_capabilities_carry_tier_threshold_block() {
    // The `memory_capabilities` v3 calibration surface MUST carry
    // the threshold map so external callers can filter / score
    // against the substrate's official breakpoints.
    let surface = CapabilityConfidenceCalibration::current();
    let thresholds = &surface.tier_thresholds;
    assert!(
        (thresholds.confirmed - ConfidenceTier::CONFIRMED_MIN).abs() < f64::EPSILON,
        "confirmed threshold matches model constant"
    );
    assert!(
        (thresholds.likely - ConfidenceTier::LIKELY_MIN).abs() < f64::EPSILON,
        "likely threshold matches model constant"
    );
    assert!(
        (thresholds.ambiguous - 0.0).abs() < f64::EPSILON,
        "ambiguous is the implicit floor"
    );
}

#[test]
fn gap4_boundary_values_at_likely_min_and_below() {
    // AC pin: boundary semantics are inclusive at lower bounds.
    // 0.7 (inclusive) ⇒ Likely. 0.699… ⇒ Ambiguous. 0.0 ⇒ Ambiguous.
    assert_eq!(
        ConfidenceTier::from_confidence(0.7),
        ConfidenceTier::Likely,
        "0.7 inclusive lower bound of Likely"
    );
    assert_eq!(
        ConfidenceTier::from_confidence(0.699_999_999),
        ConfidenceTier::Ambiguous,
        "just below 0.7 ⇒ Ambiguous"
    );
    assert_eq!(
        ConfidenceTier::from_confidence(0.0),
        ConfidenceTier::Ambiguous,
        "0.0 ⇒ Ambiguous"
    );
    // And just below confirmed.
    assert_eq!(
        ConfidenceTier::from_confidence(0.949_999_999),
        ConfidenceTier::Likely,
        "just below 0.95 ⇒ Likely"
    );
}

#[test]
fn gap4_tier_serde_roundtrip_through_json() {
    // AC pin: serde roundtrip — the JSON wire shape uses
    // snake_case-renamed variants ("confirmed" / "likely" / "ambiguous").
    for (tier, wire) in [
        (ConfidenceTier::Confirmed, "\"confirmed\""),
        (ConfidenceTier::Likely, "\"likely\""),
        (ConfidenceTier::Ambiguous, "\"ambiguous\""),
    ] {
        let s = serde_json::to_string(&tier).expect("ser");
        assert_eq!(s, wire, "serialization shape");
        let back: ConfidenceTier = serde_json::from_str(wire).expect("de");
        assert_eq!(back, tier, "roundtrip");
    }
}

#[test]
fn gap4_tier_thresholds_block_serialises_to_capability_json() {
    // AC pin: the threshold block lives inside the v3 capabilities
    // JSON envelope. A downstream caller filtering against the
    // canonical thresholds reads them from this JSON, not from a
    // compile-time constant.
    let surface = CapabilityConfidenceCalibration::current();
    let json = serde_json::to_value(&surface).expect("ser");
    let thresholds = &json["tier_thresholds"];
    assert!(
        thresholds.is_object(),
        "tier_thresholds is a JSON object: {json}"
    );
    assert!((thresholds["confirmed"].as_f64().expect("confirmed") - 0.95).abs() < f64::EPSILON);
    assert!((thresholds["likely"].as_f64().expect("likely") - 0.7).abs() < f64::EPSILON);
    assert!((thresholds["ambiguous"].as_f64().expect("ambiguous") - 0.0).abs() < f64::EPSILON);
}

#[test]
fn gap4_unknown_tier_filter_falls_through_to_no_filter() {
    // AC pin: when an unknown string lands on the `confidence_tier`
    // recall filter (a client typo, future enum value), the recall
    // path falls through to "no filter" rather than returning zero
    // rows. ConfidenceTier::parse returns None on unknown input; the
    // recall handler then treats None as no-filter.
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};
    let conn = fresh_db();
    let now = chrono::Utc::now().to_rfc3339();
    for (id, conf) in &[("u-conf", 0.99_f64), ("u-amb", 0.5)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
             VALUES (?1, 'long', 'g4unk', ?2, ?3, ?4, ?5, ?5)",
            params![id, format!("title-{id}"), format!("payload {id}"), conf, now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'g4unk'",
        [],
    )
    .ok();
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4unk",
            "confidence_tier": "this-is-not-a-tier",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    let memories = resp["memories"].as_array().expect("array");
    assert_eq!(
        memories.len(),
        2,
        "unknown tier filter falls through, returns both rows"
    );
}

#[test]
fn gap4_tier_filter_likely_returns_only_likely_row() {
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};
    let conn = fresh_db();
    let now = chrono::Utc::now().to_rfc3339();
    for (id, conf) in &[("g4l-conf", 0.99_f64), ("g4l-lik", 0.85), ("g4l-amb", 0.5)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
             VALUES (?1, 'long', 'g4l', ?2, ?3, ?4, ?5, ?5)",
            params![id, format!("title-{id}"), format!("payload {id}"), conf, now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'g4l'",
        [],
    )
    .ok();
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4l",
            "confidence_tier": "likely",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    let memories = resp["memories"].as_array().unwrap();
    assert_eq!(memories.len(), 1);
    assert_eq!(memories[0]["id"].as_str(), Some("g4l-lik"));
}

#[test]
fn gap4_recall_confidence_tier_filter_returns_only_ambiguous() {
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};

    let conn = fresh_db();
    // Seed three memories at the canonical 0.99 / 0.85 / 0.5 marks.
    let now = chrono::Utc::now().to_rfc3339();
    for (id, conf) in &[("m-conf", 0.99_f64), ("m-likely", 0.85), ("m-amb", 0.5)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
             VALUES (?1, 'long', 'g4', ?2, ?3, ?4, ?5, ?5)",
            params![id, format!("title-{id}"), format!("payload {id}"), conf, now],
        )
        .unwrap();
    }
    // FTS5 sync.
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'g4'",
        [],
    )
    .ok();

    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();

    // Filter by `ambiguous` ⇒ only the 0.5-confidence row should
    // survive.
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4",
            "confidence_tier": "ambiguous",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    let memories = resp["memories"]
        .as_array()
        .expect("recall response carries memories array");
    assert_eq!(
        memories.len(),
        1,
        "ambiguous filter must return exactly the 0.5 row"
    );
    assert_eq!(memories[0]["id"].as_str(), Some("m-amb"));
    assert_eq!(
        memories[0]["confidence_tier"].as_str(),
        Some("ambiguous"),
        "row carries the derived tier when verbose_provenance=true (default)"
    );

    // Filter by `confirmed` ⇒ only the 0.99 row.
    let resp_conf = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4",
            "confidence_tier": "confirmed",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    let conf_memories = resp_conf["memories"].as_array().unwrap();
    assert_eq!(conf_memories.len(), 1);
    assert_eq!(conf_memories[0]["id"].as_str(), Some("m-conf"));
}

/// v0.8.0 #1709 §2.5 T3 (A2) — helper: seed the canonical 0.99 / 0.85 /
/// 0.5 trio under namespace `g4` and FTS-sync, mirroring the
/// `gap4_recall_confidence_tier_filter_returns_only_ambiguous` setup.
fn seed_tier_trio(conn: &rusqlite::Connection) {
    let now = chrono::Utc::now().to_rfc3339();
    for (id, conf) in &[("m-conf", 0.99_f64), ("m-likely", 0.85), ("m-amb", 0.5)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
             VALUES (?1, 'long', 'g4', ?2, ?3, ?4, ?5, ?5)",
            params![id, format!("title-{id}"), format!("payload {id}"), conf, now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'g4'",
        [],
    )
    .ok();
}

/// v0.8.0 #1709 §2.5 T3 (A2) — a tier filter that drops at least one
/// candidate surfaces `confidence_filtered_out > 0` AND
/// `had_filtered_candidates == true` in the response `meta`. Includes
/// the `count:0`-but-candidates-existed case: requesting `confirmed`
/// against a corpus whose matching rows are all below the bar must report
/// that the drop happened rather than silently returning an empty set.
#[test]
fn t3_a2_confidence_filter_meta_surfaces_dropped_candidates() {
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};

    let conn = fresh_db();
    seed_tier_trio(&conn);
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();

    // `confirmed` ⇒ keeps the 0.99 row, drops the 0.85 + 0.5 rows.
    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4",
            "confidence_tier": "confirmed",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    assert_eq!(resp["count"].as_u64(), Some(1));
    assert_eq!(
        resp["meta"]["confidence_filtered_out"].as_u64(),
        Some(2),
        "two below-bar candidates were dropped"
    );
    assert_eq!(
        resp["meta"]["had_filtered_candidates"].as_bool(),
        Some(true)
    );

    // count:0-but-candidates-existed — a corpus with NO confirmed row.
    // Seed two more ambiguous/likely rows under a distinct namespace and
    // request `confirmed`: every matching candidate is below the bar, so
    // count is 0 yet the meta proves candidates existed and were dropped.
    let now = chrono::Utc::now().to_rfc3339();
    for (id, conf) in &[("b-amb", 0.4_f64), ("b-likely", 0.8)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
             VALUES (?1, 'long', 'belowbar', ?2, ?3, ?4, ?5, ?5)",
            params![id, format!("title-{id}"), format!("belowpayload {id}"), conf, now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'belowbar'",
        [],
    )
    .ok();

    let resp_zero = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "belowpayload",
            "namespace": "belowbar",
            "confidence_tier": "confirmed",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    assert_eq!(
        resp_zero["count"].as_u64(),
        Some(0),
        "no confirmed row exists in this namespace"
    );
    assert_eq!(
        resp_zero["meta"]["confidence_filtered_out"].as_u64(),
        Some(2),
        "both candidates were dropped for being below the confirmed bar"
    );
    assert_eq!(
        resp_zero["meta"]["had_filtered_candidates"].as_bool(),
        Some(true),
        "count:0 with candidates that existed must be distinguishable from no-match"
    );
}

/// v0.8.0 #1709 §2.5 T3 (A2) — a tier filter that drops nothing reports
/// `confidence_filtered_out == 0` AND `had_filtered_candidates == false`.
#[test]
fn t3_a2_confidence_filter_meta_zero_when_nothing_dropped() {
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};

    let conn = fresh_db();
    // Seed a single confirmed row so a `confirmed` filter drops nothing.
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, confidence, created_at, updated_at) \
         VALUES ('only-conf', 'long', 'g4', 'title-only', 'payload only', 0.99, ?1, ?1)",
        params![now],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO memories_fts(rowid, title, content) \
         SELECT rowid, title, content FROM memories WHERE namespace = 'g4'",
        [],
    )
    .ok();
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();

    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4",
            "confidence_tier": "confirmed",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    assert_eq!(resp["count"].as_u64(), Some(1));
    assert_eq!(
        resp["meta"]["confidence_filtered_out"].as_u64(),
        Some(0),
        "nothing was below the bar"
    );
    assert_eq!(
        resp["meta"]["had_filtered_candidates"].as_bool(),
        Some(false)
    );
}

/// v0.8.0 #1709 §2.5 T3 (A2) — an UNFILTERED recall (no
/// `confidence_tier`) gets NO new meta keys — zero noise. The fields are
/// absent (not merely zero) so a caller can tell the filter was never
/// requested.
#[test]
fn t3_a2_unfiltered_recall_has_no_confidence_filter_meta() {
    use ai_memory::config::{ResolvedScoring, ResolvedTtl};

    let conn = fresh_db();
    seed_tier_trio(&conn);
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();

    let resp = ai_memory::mcp::handle_recall(
        &conn,
        &serde_json::json!({
            "context": "payload",
            "namespace": "g4",
        }),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
    )
    .expect("recall ok");
    // All three rows surface — no tier filter applied.
    assert_eq!(resp["count"].as_u64(), Some(3));
    assert!(
        resp["meta"].get("confidence_filtered_out").is_none(),
        "unfiltered recall must NOT carry confidence_filtered_out"
    );
    assert!(
        resp["meta"].get("had_filtered_candidates").is_none(),
        "unfiltered recall must NOT carry had_filtered_candidates"
    );
}
