// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::needless_update,
    clippy::doc_overindented_list_items
)]

//! v0.7.x QUAL-3 (FX-5) — governance metadata `u64 → u32` truncation regression.
//!
//! Background
//! ----------
//!
//! `src/storage/mod.rs:7865` and `src/storage/mod.rs:7917` (pre-fix line
//! numbers) used silent `n as u32` truncation on values pulled from the
//! `metadata.governance` JSON blob (`require_approval_above_depth` and
//! `skill_promotion_min_depth` respectively). The `metadata.governance`
//! blob is operator-controlled — every `memory_store` write path can
//! supply it — so a hostile or careless operator could set
//! `require_approval_above_depth = 2^32` and have it silently land as
//! `0` after the truncation. The depth-comparison check
//! (`proposed_depth > threshold`) then evaluates `depth > 0` instead of
//! the intended `depth > 2^32`, which is the OPPOSITE of the operator's
//! stated policy (`> 2^32` would never fire because reflection depth is
//! an `i32` capped well below 2^31). For values whose `low_32` bits are
//! also zero (e.g. `2^32`, `2^33`, `2^32 + 2^32`, `5 * 2^32`, etc.) the
//! approval gate is effectively DISABLED.
//!
//! The companion site at `skill_promotion_min_depth` has the dual risk:
//! a value of `2^32 + k` lands as `k` post-truncation; with `k == 0`
//! every reflection becomes promotable to a skill regardless of depth.
//!
//! Fix-Closed Semantics
//! --------------------
//!
//! Per K3/K9 substrate discipline (CLAUDE.md §"AI_MEMORY_PERMISSIONS_MODE"
//! / pm-v3 fail-CLOSED posture), overflow values are treated as
//! operator misconfiguration and saturate to the SECURE extreme:
//!
//!  - `require_approval_above_depth` → `Some(0)` on overflow
//!     (every depth requires approval).
//!  - `skill_promotion_min_depth` → `Some(u32::MAX)` on overflow
//!     (no reflection can be promoted).
//!
//! The fix uses `u32::try_from(n).unwrap_or(<fail-closed-sentinel>)` at
//! each site so a re-introduction of the silent `as` cast trips this
//! regression test mechanically.

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, Tier};
use chrono::Utc;

/// Build a namespace standard memory carrying the supplied raw
/// `governance` blob and register it as the namespace standard. Mirrors
/// the helper in `tests/approval_reflect.rs`.
fn seed_governance_json(
    conn: &rusqlite::Connection,
    namespace: &str,
    governance: &serde_json::Value,
) {
    let now = Utc::now().to_rfc3339();
    let metadata = serde_json::json!({
        "agent_id": "test-agent-qual-3",
        "governance": governance,
    });
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{namespace}"),
        title: format!("standard for {namespace}"),
        content: "QUAL-3 fail-closed regression fixture".to_string(),
        tags: vec![],
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
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
    let std_id = db::insert(conn, &standard).unwrap();
    db::set_namespace_standard(conn, namespace, &std_id, None).unwrap();
}

// ─────────────────────────────────────────────────────────────────────
// (1) require_approval_above_depth — overflow saturates to 0 (fail-closed).
//     `low_32(2^32) == 0`. Pre-fix: `2^32 as u32 == 0` — approval gate
//     effectively disabled (depth > 0 is the operator's "block-everything"
//     intent, but the operator wrote 2^32 expecting "block nothing"; the
//     truncation flips the meaning AND happens silently).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn require_approval_above_depth_overflow_saturates_fail_closed() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // 2^32 — the canonical truncation-to-0 payload.
    let overflow_value: u64 = 1u64 << 32;
    seed_governance_json(
        &conn,
        "qual-3-approval-overflow",
        &serde_json::json!({
            "write": "any",
            "require_approval_above_depth": overflow_value,
        }),
    );
    let resolved = db::resolve_require_approval_above_depth(&conn, "qual-3-approval-overflow");
    assert_eq!(
        resolved,
        Some(0),
        "QUAL-3: u64→u32 overflow on require_approval_above_depth must saturate \
         to 0 (fail-CLOSED: every depth triggers approval), NOT silently truncate \
         to low_32 bits which would be 0 here too but for the WRONG reason — the \
         caller MUST see the safe sentinel, not the truncated low bits"
    );
}

#[test]
fn require_approval_above_depth_u64_max_saturates_fail_closed() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_governance_json(
        &conn,
        "qual-3-approval-u64max",
        &serde_json::json!({
            "write": "any",
            "require_approval_above_depth": u64::MAX,
        }),
    );
    let resolved = db::resolve_require_approval_above_depth(&conn, "qual-3-approval-u64max");
    assert_eq!(
        resolved,
        Some(0),
        "QUAL-3: u64::MAX must saturate to 0 (fail-CLOSED). Pre-fix the cast \
         would yield u32::MAX (≈4B) which the proposed_depth > threshold check \
         would never trigger — effectively DISABLING the gate."
    );
}

#[test]
fn require_approval_above_depth_just_over_u32_max_saturates_fail_closed() {
    // u32::MAX + 1 — the minimal overflow case. Pre-fix this lands as 0.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let overflow_value: u64 = u64::from(u32::MAX) + 1;
    seed_governance_json(
        &conn,
        "qual-3-approval-edge",
        &serde_json::json!({
            "write": "any",
            "require_approval_above_depth": overflow_value,
        }),
    );
    let resolved = db::resolve_require_approval_above_depth(&conn, "qual-3-approval-edge");
    assert_eq!(
        resolved,
        Some(0),
        "QUAL-3: u32::MAX + 1 must saturate to fail-CLOSED 0, not silently \
         truncate to 0 via low-32-bit extraction (different bug, same number)"
    );
}

#[test]
fn require_approval_above_depth_in_range_value_round_trips() {
    // Non-regression: in-range values continue to pass through verbatim.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_governance_json(
        &conn,
        "qual-3-approval-inrange",
        &serde_json::json!({
            "write": "any",
            "require_approval_above_depth": 7_u32,
        }),
    );
    let resolved = db::resolve_require_approval_above_depth(&conn, "qual-3-approval-inrange");
    assert_eq!(
        resolved,
        Some(7),
        "QUAL-3 non-regression: a value that fits in u32 must round-trip verbatim",
    );
}

// ─────────────────────────────────────────────────────────────────────
// (2) skill_promotion_min_depth — overflow saturates to u32::MAX
//     (fail-closed: no reflection can be promoted).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn skill_promotion_min_depth_overflow_saturates_fail_closed() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // 2^32 — `n as u32` would yield 0; that would mean "every reflection
    // can be promoted to a skill". Fail-CLOSED is u32::MAX (no promotion).
    let overflow_value: u64 = 1u64 << 32;
    seed_governance_json(
        &conn,
        "qual-3-promote-overflow",
        &serde_json::json!({
            "write": "any",
            "skill_promotion_min_depth": overflow_value,
        }),
    );
    let resolved = db::resolve_skill_promotion_min_depth(&conn, "qual-3-promote-overflow");
    assert_eq!(
        resolved,
        Some(u32::MAX),
        "QUAL-3: u64→u32 overflow on skill_promotion_min_depth must saturate to \
         u32::MAX (fail-CLOSED: blocks all promotions). Pre-fix the cast would \
         yield 0 — letting every reflection promote regardless of depth, which \
         is the substrate's most-permissive posture for this gate."
    );
}

#[test]
fn skill_promotion_min_depth_u64_max_saturates_fail_closed() {
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_governance_json(
        &conn,
        "qual-3-promote-u64max",
        &serde_json::json!({
            "write": "any",
            "skill_promotion_min_depth": u64::MAX,
        }),
    );
    let resolved = db::resolve_skill_promotion_min_depth(&conn, "qual-3-promote-u64max");
    assert_eq!(
        resolved,
        Some(u32::MAX),
        "QUAL-3: u64::MAX skill_promotion_min_depth must saturate to u32::MAX \
         (fail-CLOSED). Pre-fix: `u64::MAX as u32 == u32::MAX` happened to be the \
         same value here, but only by coincidence — the next test pins the \
         load-bearing case where the truncation and the fix-closed value differ."
    );
}

#[test]
fn skill_promotion_min_depth_just_over_u32_max_saturates_fail_closed() {
    // u32::MAX + 1 — pre-fix truncates to 0 (every reflection promotable).
    // Post-fix saturates to u32::MAX (nothing promotable).
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let overflow_value: u64 = u64::from(u32::MAX) + 1;
    seed_governance_json(
        &conn,
        "qual-3-promote-edge",
        &serde_json::json!({
            "write": "any",
            "skill_promotion_min_depth": overflow_value,
        }),
    );
    let resolved = db::resolve_skill_promotion_min_depth(&conn, "qual-3-promote-edge");
    assert_eq!(
        resolved,
        Some(u32::MAX),
        "QUAL-3: u32::MAX + 1 promotion-min-depth must saturate to u32::MAX. \
         Pre-fix it would silently land as 0 — every reflection promotable. \
         This is the load-bearing assertion: pre-fix returns 0, post-fix \
         returns u32::MAX, and the two values are observably different."
    );
}

#[test]
fn skill_promotion_min_depth_in_range_value_round_trips() {
    // Non-regression: in-range values continue to pass through verbatim.
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    seed_governance_json(
        &conn,
        "qual-3-promote-inrange",
        &serde_json::json!({
            "write": "any",
            "skill_promotion_min_depth": 3_u32,
        }),
    );
    let resolved = db::resolve_skill_promotion_min_depth(&conn, "qual-3-promote-inrange");
    assert_eq!(
        resolved,
        Some(3),
        "QUAL-3 non-regression: a value that fits in u32 must round-trip verbatim",
    );
}
