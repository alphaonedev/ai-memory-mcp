// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Form 5 — freshness-decay updater.
//!
//! The [`decayed`] function returns an exponentially decayed copy of
//! the input confidence value. Recall paths can call it on touch to
//! soft-floor stale rows; the actual write back into
//! `memories.confidence` happens only when
//! `AI_MEMORY_CONFIDENCE_DECAY=1` or the namespace policy carries
//! `confidence_decay_half_life_days`.
//!
//! The recall-time substrate touch lives in [`apply_decay_touch`]:
//! when `AI_MEMORY_CONFIDENCE_DECAY=1` and a memory is recalled,
//! `crate::store::sqlite::touch_after_recall` calls this helper to
//! UPDATE the row in place, stamp `confidence_decayed_at`, overwrite
//! `confidence` with the decayed value, and flip `confidence_source`
//! to [`crate::models::ConfidenceSource::Decayed`].
//!
//! Audit-honest contract: this module is pure (the math) plus one
//! tightly-scoped substrate writer ([`apply_decay_touch`]) that lives
//! here — not in `src/storage/mod.rs` — so the Cluster F recall SQL
//! stays untouched.

use rusqlite::{Connection, params};

/// Environment-variable opt-in for the recall-time decay updater.
pub const ENV_DECAY: &str = "AI_MEMORY_CONFIDENCE_DECAY";

/// Returns true when [`ENV_DECAY`] is set to `"1"`.
#[must_use]
pub fn decay_enabled() -> bool {
    std::env::var(ENV_DECAY).is_ok_and(|v| v == "1")
}

/// n15 — process-global per-namespace confidence-decay half-life
/// overrides (days), seeded once at boot from
/// `[curator.confidence_decay_half_life_days]`
/// (`AppConfig::confidence_decay_half_life_overrides`). `apply_decay_touch`
/// is a `&Connection`-bound free fn with no `AppConfig` in scope, so the
/// override is resolved through this global rather than threaded through
/// every recall-touch caller — the same boot-seeded-global pattern as
/// `crate::reranker::set_rerank_max_seq` and the quota defaults.
static NAMESPACE_HALF_LIFE: std::sync::OnceLock<std::collections::HashMap<String, f64>> =
    std::sync::OnceLock::new();

/// n15 — seed the per-namespace half-life overrides once at boot.
/// First-writer-wins (`OnceLock`); a re-seed is silently ignored.
pub fn set_namespace_half_life_overrides(overrides: std::collections::HashMap<String, f64>) {
    let _ = NAMESPACE_HALF_LIFE.set(overrides);
}

/// n15 — borrow the boot-seeded per-namespace half-life overrides when
/// any were configured (and non-empty). The sqlite per-id decay path
/// uses [`half_life_for_namespace`]; the postgres bulk-decay path uses
/// this to build a per-namespace `CASE` so both backends apply the same
/// override. `None` (the common case) → both backends use the compiled
/// default and the simple single-half-life path.
#[must_use]
pub fn namespace_half_life_overrides() -> Option<&'static std::collections::HashMap<String, f64>> {
    NAMESPACE_HALF_LIFE.get().filter(|m| !m.is_empty())
}

/// n15 — resolve the half-life (days) for `namespace`: the boot-seeded
/// override when present + finite + `> 0`, else
/// [`crate::confidence::DEFAULT_HALF_LIFE_DAYS`].
#[must_use]
pub fn half_life_for_namespace(namespace: &str) -> f64 {
    NAMESPACE_HALF_LIFE
        .get()
        .and_then(|m| m.get(namespace))
        .copied()
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(crate::confidence::DEFAULT_HALF_LIFE_DAYS)
}

/// Compute a decayed confidence value.
///
/// `base` is the stored value; `age_days` is the time elapsed since
/// the value was last written (typically `now - max(created_at,
/// confidence_decayed_at)`); `half_life_days` is the namespace-policy
/// override or [`crate::confidence::DEFAULT_HALF_LIFE_DAYS`].
///
/// Formula: `base * 2^(-age / half_life)`, i.e.
/// `base * exp(-age * ln(2) / half_life)`. Honours the standard
/// half-life convention: at `age = half_life`, the value collapses to
/// `0.5 * base`. Clamped to `[0.0, 1.0]`. Negative `age_days` is
/// treated as `0.0` (no future-dated decay). `half_life_days <= 0`
/// is treated as `f64::EPSILON` so the divisor never goes to zero
/// (the value collapses to 0 in that case, which is the documented
/// degenerate-input contract).
#[must_use]
pub fn decayed(base: f64, age_days: f64, half_life_days: f64) -> f64 {
    let age = age_days.max(0.0);
    let half_life = half_life_days.max(f64::EPSILON);
    let factor = (-age * std::f64::consts::LN_2 / half_life).exp();
    (base * factor).clamp(0.0, 1.0)
}

/// Substrate-side decay touch fired from `touch_after_recall` when
/// `AI_MEMORY_CONFIDENCE_DECAY=1`. Reads the row's current
/// `confidence`, `created_at`, `confidence_decayed_at`, and
/// `namespace`, computes the decayed value via [`decayed`] using the
/// per-namespace half-life resolved by [`half_life_for_namespace`]
/// (n15 — `[curator.confidence_decay_half_life_days]` override >
/// [`crate::confidence::DEFAULT_HALF_LIFE_DAYS`]), and writes back the
/// new value, the `'decayed'` source marker, and a fresh
/// `confidence_decayed_at` timestamp.
///
/// Idempotent — re-running on a row that has already been decayed
/// uses the most recent `confidence_decayed_at` as the age anchor, so
/// repeated touches converge rather than collapsing the value to zero.
/// Returns `Ok(true)` when a row was updated, `Ok(false)` when no row
/// matched the id (silently swallowed by the caller).
///
/// # Errors
///
/// Returns the underlying `rusqlite` error on SQL failure.
pub fn apply_decay_touch(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    use chrono::{DateTime, Utc};
    // Read the row's age anchor + current confidence in one shot. The
    // anchor is `confidence_decayed_at` when present (subsequent
    // decays compute from the last decay timestamp, not creation),
    // falling back to `created_at` for first-touch rows.
    // n15 — read `namespace` too so the per-namespace half-life override
    // (boot-seeded from `[curator.confidence_decay_half_life_days]`) can
    // be resolved per row instead of always using the compiled default.
    // #1906 — `.ok()` used to collapse EVERY `rusqlite::Error` into
    // `None`, indistinguishable from the legitimate "no such id"
    // outcome. That swallowed real faults (a missing/renamed column
    // after a partial migration, a locked DB, corruption) silently:
    // `touch_after_recall` treats `Ok(false)` as "nothing to do", so a
    // persistent read fault made confidence-decay look enabled while
    // doing nothing, with zero telemetry. Only `QueryReturnedNoRows`
    // (the genuine "no such id" case) maps to `Ok(false)`; every other
    // error now propagates via `?`, matching this function's own write
    // path (`conn.execute` below) and its documented `Result<bool>`
    // contract.
    let row: (f64, String, Option<String>, String) = match conn.query_row(
        "SELECT confidence, created_at, confidence_decayed_at, namespace
         FROM memories WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ) {
        Ok(row) => row,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
        Err(e) => return Err(e),
    };
    let (current_confidence, created_at, decayed_at, namespace) = row;

    let now = Utc::now();
    let anchor_str = decayed_at.unwrap_or(created_at);
    let anchor = DateTime::parse_from_rfc3339(&anchor_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(now);
    let age_days = (now - anchor).num_seconds() as f64 / crate::SECS_PER_DAY as f64;
    // n15 — per-namespace half-life override > compiled default.
    let new_value = decayed(
        current_confidence,
        age_days,
        half_life_for_namespace(&namespace),
    );
    let stamp = now.to_rfc3339();
    // v0.7.0 #1036 (Agent-3 #7) — intentionally non-version-bumping
    // write. This is a periodic system sweep updating confidence
    // calibration metadata, NOT a user-initiated content edit. The
    // optimistic-concurrency contract (Gap-1 #884) protects against
    // concurrent USER edits via `memories.version`. Bumping version
    // here would cause spurious VersionConflict on the next user
    // `update_with_expected_version` call (the user's stale `version`
    // would diverge from the row's decay-bumped value), breaking
    // the user-facing concurrency story without protecting any
    // real cross-edit race (the decay sweep is monotonic + idempotent
    // — re-running on the same row converges to the same value
    // modulo the slow time decay).
    //
    // Pinned by `tests/non_version_bumping_sites_1036.rs` —
    // a fresh `version` MUST equal the pre-decay `version` post-call.
    let n = conn.execute(
        "UPDATE memories
         SET confidence = ?1,
             confidence_source = 'decayed',
             confidence_decayed_at = ?2
         WHERE id = ?3",
        params![new_value, stamp, id],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_age_returns_base() {
        assert!((decayed(0.9, 0.0, 30.0) - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn half_life_halves_value() {
        // base=1.0, age=half_life ⇒ ~0.5
        let v = decayed(1.0, 30.0, 30.0);
        assert!((v - 0.5).abs() < 1e-6, "expected ~0.5 got {v}");
    }

    #[test]
    fn very_old_collapses_toward_zero() {
        let v = decayed(0.9, 365.0, 30.0);
        assert!(v < 0.05, "expected near-zero got {v}");
    }

    #[test]
    fn negative_age_treated_as_zero() {
        assert!((decayed(0.7, -5.0, 30.0) - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn n15_half_life_for_unseeded_namespace_is_default() {
        // n15 — a namespace with no seeded override resolves to the
        // compiled default. Uses a sentinel namespace no other test
        // seeds, so the assertion is order-independent against the
        // process-global OnceLock (the seed→read value logic is covered
        // deterministically by the AppConfig resolver tests).
        let hl = half_life_for_namespace("__n15_definitely_unseeded_namespace__");
        assert!((hl - crate::confidence::DEFAULT_HALF_LIFE_DAYS).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_half_life_collapses_to_zero() {
        // Degenerate input: half_life=0 ⇒ value collapses to 0
        // immediately (no future-dated decay; this is the contract).
        let v = decayed(0.9, 1.0, 0.0);
        assert!(v < 1e-6, "expected ~0 got {v}");
    }

    #[test]
    fn output_clamped_to_unit_interval() {
        // base > 1.0 is a bug elsewhere but the function must not
        // propagate it.
        let v = decayed(2.0, 0.0, 30.0);
        assert!((v - 1.0).abs() < f64::EPSILON);
        let v = decayed(-0.5, 0.0, 30.0);
        assert!((v - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn monotonic_in_age() {
        let a = decayed(1.0, 0.0, 30.0);
        let b = decayed(1.0, 10.0, 30.0);
        let c = decayed(1.0, 30.0, 30.0);
        assert!(a > b && b > c, "should decay monotonically: {a} {b} {c}");
    }

    #[test]
    fn apply_decay_touch_missing_id_returns_ok_false() {
        // The legitimate "no such id" contract must still hold after
        // #1906 narrowed the swallowed-error case to
        // `QueryReturnedNoRows` specifically.
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("t.db");
        let _ = crate::storage::open(&path).expect("open storage");
        let conn = Connection::open(&path).expect("open conn");
        let found = apply_decay_touch(&conn, "does-not-exist").expect("must not error");
        assert!(!found, "unknown id must yield Ok(false), not an error");
    }

    #[test]
    fn apply_decay_touch_propagates_real_sql_errors_instead_of_swallowing_them() {
        // #1906 — before the fix, `.ok()` collapsed EVERY
        // `rusqlite::Error` (not just "no rows") into `None`, which
        // `let ... else` then turned into the same `Ok(false)` as a
        // legitimate "no such id". A real fault — here, the `memories`
        // table not existing at all (e.g. a partial/failed migration)
        // — must propagate as `Err`, not silently report "nothing to
        // decay".
        let conn = Connection::open_in_memory().expect("open in-memory conn");
        let err = apply_decay_touch(&conn, "any-id")
            .expect_err("a missing table is a real SQL fault, not a benign not-found");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("no such table"),
            "expected a real rusqlite error surfaced to the caller, got: {msg}"
        );
    }

    #[test]
    fn decay_env_gating_default_off() {
        unsafe { std::env::remove_var(ENV_DECAY) };
        assert!(!decay_enabled());
        unsafe { std::env::set_var(ENV_DECAY, "1") };
        assert!(decay_enabled());
        unsafe { std::env::remove_var(ENV_DECAY) };
    }
}
