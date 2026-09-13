// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3660 — read-audit delivery evidence (audit #3645 F14).
//!
//! `gate_read` evaluates `read_action` rules and appends a
//! `governance.check` row for every ENGAGED decision through
//! `emit_check_event` → `append_signed_event` — a direct, synchronous
//! `signed_events` INSERT in its own IMMEDIATE transaction. Pre-#3660 the
//! gate's comments and its WARN line claimed that an append failure was
//! "DLQ-backed" / "the deferred-audit DLQ keeps the trail recoverable".
//! **That claim was false on this call path.** The deferred-audit queue
//! (`governance::deferred_audit`) is the substrate pre-WRITE hook's
//! mechanism: it admits blocking refusals only (`from_refusal` returns
//! `None` for an allow/warn decision) and is not reachable from
//! `gate_read`, which holds nothing but a `Connection`. A read decision
//! whose append fails is not queued, not spooled and not retried; its only
//! residence is the best-effort forensic file (when that sink is enabled)
//! — and that file is rotated and unsigned-by-default.
//!
//! This module makes the gap MEASURED instead of wished away:
//!
//! * process-wide counters of engaged read decisions, chain appends, and
//!   append failures split by where the evidence ended up
//!   (`forensic_only` / `none`);
//! * the same counters on `/metrics` (`ai_memory_governance_read_audit_*`,
//!   closed `residence` label set) and on `/health` as the
//!   `governance.read_audit_delivery` signal object (#3646 shape);
//! * an ENTERPRISE policy knob, [`ENV_READ_AUDIT_STRICT`]: when armed, a
//!   read whose decision cannot be chain-logged is REFUSED instead of
//!   proceeding. Default stays the documented best-effort posture (read
//!   availability is never coupled to audit-sink liveness) — the knob is
//!   how a deployment whose compliance requirements outrank read
//!   availability selects the stricter behaviour.
//!
//! What this module deliberately does NOT do: build a second spool for
//! read decisions. The write-side journal exists because a refusal MUST
//! reach the chain; the read side's documented policy is availability
//! first. Inventing durable machinery to satisfy a comment would have
//! added a spool nobody asked for; correcting the comment and counting the
//! loss is the honest fix.

use std::sync::atomic::{AtomicU64, Ordering};

/// Enterprise policy knob: `1` / `true` (same grammar as
/// `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR`) makes `gate_read` REFUSE a
/// read whose engaged decision could not be appended to `signed_events`.
/// Unset / any other value = best-effort (read proceeds, gap counted).
pub const ENV_READ_AUDIT_STRICT: &str = "AI_MEMORY_READ_AUDIT_STRICT";

/// Refusal reason surfaced to the caller under the strict policy.
pub const STRICT_REFUSAL_REASON: &str = "read audit unavailable: the governance decision could not be chain-logged and \
     AI_MEMORY_READ_AUDIT_STRICT refuses reads without durable audit evidence";

/// The surface these counters cover. HTTP/postgres reads route through the
/// SAL store and are NOT gated by `gate_read` (documented since #1730), so
/// a daemon that serves only HTTP reads reports `evaluated_total = 0`
/// honestly rather than implying coverage it does not have.
pub const SCOPE: &str = "mcp_sqlite_read_gate";

/// Where an engaged read decision's evidence ended up after its chain
/// append failed. Closed set — the `residence` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapResidence {
    /// The forensic sink accepted the row: the decision exists ONLY in a
    /// rotated, best-effort file and cannot be reconstructed from
    /// `signed_events`.
    ForensicOnly,
    /// Neither the chain nor the forensic sink holds it: the decision is
    /// gone.
    None,
}

impl GapResidence {
    /// Stable label / JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForensicOnly => "forensic_only",
            Self::None => "none",
        }
    }

    /// Every residence, for pre-touching the labelled metric family.
    pub const ALL: [Self; 2] = [Self::ForensicOnly, Self::None];
}

/// Process-wide counters. Atomics only: the read gate is on the recall
/// hot path and takes no lock here.
#[derive(Debug, Default)]
pub struct ReadAuditCounters {
    evaluated: AtomicU64,
    chain_appended: AtomicU64,
    gap_forensic_only: AtomicU64,
    gap_none: AtomicU64,
    strict_refusals: AtomicU64,
    last_chain_append_unix: AtomicU64,
    last_gap_unix: AtomicU64,
}

static COUNTERS: ReadAuditCounters = ReadAuditCounters {
    evaluated: AtomicU64::new(0),
    chain_appended: AtomicU64::new(0),
    gap_forensic_only: AtomicU64::new(0),
    gap_none: AtomicU64::new(0),
    strict_refusals: AtomicU64::new(0),
    last_chain_append_unix: AtomicU64::new(0),
    last_gap_unix: AtomicU64::new(0),
};

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One engaged read decision was evaluated (rules present; the zero-rule
/// fast path does not count — it emits no audit by design).
pub fn record_evaluated() {
    COUNTERS.evaluated.fetch_add(1, Ordering::Relaxed);
    crate::metrics::registry()
        .governance_read_audit_evaluated_total
        .inc();
}

/// The decision's `governance.check` row reached `signed_events`.
pub fn record_chain_appended() {
    COUNTERS.chain_appended.fetch_add(1, Ordering::Relaxed);
    COUNTERS
        .last_chain_append_unix
        .store(unix_now_secs(), Ordering::Relaxed);
    crate::metrics::registry()
        .governance_read_audit_chain_appended_total
        .inc();
}

/// The chain append FAILED. `forensic_accepted` says whether the
/// best-effort forensic sink took the row (false when the sink is
/// disabled or its write failed). Returns the residence recorded.
#[must_use = "the residence names where the evidence lives; log it"]
pub fn record_chain_append_failed(forensic_accepted: bool) -> GapResidence {
    let residence = if forensic_accepted {
        COUNTERS.gap_forensic_only.fetch_add(1, Ordering::Relaxed);
        GapResidence::ForensicOnly
    } else {
        COUNTERS.gap_none.fetch_add(1, Ordering::Relaxed);
        GapResidence::None
    };
    let now = unix_now_secs();
    COUNTERS.last_gap_unix.store(now, Ordering::Relaxed);
    let m = crate::metrics::registry();
    m.governance_read_audit_evidence_gap_total
        .with_label_values(&[residence.as_str()])
        .inc();
    #[allow(clippy::cast_possible_wrap)]
    m.governance_read_audit_last_gap_at_seconds.set(now as i64);
    residence
}

/// A read was refused under [`ENV_READ_AUDIT_STRICT`] because its
/// decision could not be chain-logged.
pub fn record_strict_refusal() {
    COUNTERS.strict_refusals.fetch_add(1, Ordering::Relaxed);
    crate::metrics::registry()
        .governance_read_audit_strict_refusals_total
        .inc();
}

/// Live policy: is [`ENV_READ_AUDIT_STRICT`] armed?
#[must_use]
pub fn strict_policy_from_env() -> bool {
    std::env::var(ENV_READ_AUDIT_STRICT)
        .map(|v| strict_value_enabled(&v))
        .unwrap_or(false)
}

/// Value grammar — exact `"1"` or case-insensitive `"true"`, the same
/// grammar as `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` so the two
/// governance-posture knobs cannot drift.
#[must_use]
pub fn strict_value_enabled(v: &str) -> bool {
    crate::daemon_runtime::governance_fail_open_value_enabled(v)
}

/// A fully measured snapshot of read-audit delivery for this process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReadAuditDelivery {
    /// [`SCOPE`].
    pub scope: &'static str,
    /// `best_effort` or `strict` — the policy in force when the snapshot
    /// was taken.
    pub policy: &'static str,
    /// Engaged read decisions evaluated since boot.
    pub evaluated_total: u64,
    /// Decisions whose row reached `signed_events`.
    pub chain_appended_total: u64,
    /// Decisions whose row did NOT reach the chain, by residence.
    pub evidence_gap_by_residence: Vec<(&'static str, u64)>,
    /// Sum of the gaps: decisions that cannot be reconstructed from
    /// `signed_events`. Never decreases within a process lifetime — lost
    /// evidence does not come back.
    pub evidence_gap_total: u64,
    /// Reads refused under the strict policy.
    pub strict_refusals_total: u64,
    /// Unix seconds of the last successful chain append (`None` = none
    /// since boot).
    pub last_chain_append_at_seconds: Option<u64>,
    /// Unix seconds of the last gap (`None` = none since boot).
    pub last_gap_at_seconds: Option<u64>,
    /// `true` while the most recent outcome was a gap (the sink is failing
    /// NOW), `false` once a later append succeeded or no gap occurred.
    pub gap_open: bool,
    /// `true` once ANY evidence has been lost this process lifetime: an
    /// operator has to know that `signed_events` is incomplete for reads.
    pub actionable: bool,
    /// The unix second this snapshot was taken at.
    pub observed_at_seconds: u64,
}

impl ReadAuditDelivery {
    /// The #3646 signal-object rendering (`state: "available"` plus
    /// additive `value` / freshness fields; never a bare number).
    #[must_use]
    pub fn to_signal_json(&self) -> serde_json::Value {
        let gaps: serde_json::Map<String, serde_json::Value> = self
            .evidence_gap_by_residence
            .iter()
            .map(|(k, n)| ((*k).to_string(), serde_json::Value::from(*n)))
            .collect();
        serde_json::json!({
            "state": "available",
            "observed_at_seconds": self.observed_at_seconds,
            "value": {
                "scope": self.scope,
                "policy": self.policy,
                "evaluated_total": self.evaluated_total,
                "chain_appended_total": self.chain_appended_total,
                "evidence_gap_by_residence": gaps,
                "evidence_gap_total": self.evidence_gap_total,
                "strict_refusals_total": self.strict_refusals_total,
                "last_chain_append_at_seconds": self.last_chain_append_at_seconds,
                "last_gap_at_seconds": self.last_gap_at_seconds,
                "gap_open": self.gap_open,
                "actionable": self.actionable,
            },
        })
    }
}

/// Snapshot at `now_unix` under an explicit `strict` policy (injected so
/// the rendering is testable without touching the process environment).
#[must_use]
pub fn delivery_at(now_unix: u64, strict: bool) -> ReadAuditDelivery {
    let nz = |v: u64| if v == 0 { None } else { Some(v) };
    let forensic_only = COUNTERS.gap_forensic_only.load(Ordering::Relaxed);
    let none = COUNTERS.gap_none.load(Ordering::Relaxed);
    let last_ok = COUNTERS.last_chain_append_unix.load(Ordering::Relaxed);
    let last_gap = COUNTERS.last_gap_unix.load(Ordering::Relaxed);
    let gap_total = forensic_only + none;
    ReadAuditDelivery {
        scope: SCOPE,
        policy: if strict { "strict" } else { "best_effort" },
        evaluated_total: COUNTERS.evaluated.load(Ordering::Relaxed),
        chain_appended_total: COUNTERS.chain_appended.load(Ordering::Relaxed),
        evidence_gap_by_residence: vec![
            (GapResidence::ForensicOnly.as_str(), forensic_only),
            (GapResidence::None.as_str(), none),
        ],
        evidence_gap_total: gap_total,
        strict_refusals_total: COUNTERS.strict_refusals.load(Ordering::Relaxed),
        last_chain_append_at_seconds: nz(last_ok),
        last_gap_at_seconds: nz(last_gap),
        gap_open: last_gap != 0 && last_gap >= last_ok,
        actionable: gap_total > 0,
        observed_at_seconds: now_unix,
    }
}

/// [`delivery_at`] at the wall clock under the live env policy.
#[must_use]
pub fn delivery() -> ReadAuditDelivery {
    delivery_at(unix_now_secs(), strict_policy_from_env())
}

#[cfg(test)]
mod tests {
    use super::{GapResidence, delivery_at, strict_value_enabled};

    #[test]
    fn strict_value_grammar_matches_fail_open_knob_3660() {
        assert!(strict_value_enabled("1"));
        assert!(strict_value_enabled("true"));
        assert!(strict_value_enabled("TRUE"));
        assert!(!strict_value_enabled("yes"));
        assert!(!strict_value_enabled("on"));
        assert!(!strict_value_enabled("0"));
        assert!(!strict_value_enabled(""));
    }

    #[test]
    fn residence_labels_are_closed_and_stable_3660() {
        let labels: Vec<&str> = GapResidence::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels, ["forensic_only", "none"]);
    }

    #[test]
    fn signal_json_is_a_signal_object_not_a_bare_number_3660() {
        let j = delivery_at(7, true).to_signal_json();
        assert_eq!(j["state"], "available");
        assert_eq!(j["observed_at_seconds"], 7);
        assert_eq!(j["value"]["scope"], super::SCOPE);
        assert_eq!(j["value"]["policy"], "strict");
        assert!(j["value"]["evidence_gap_by_residence"]["forensic_only"].is_u64());
        assert!(j["value"]["evidence_gap_by_residence"]["none"].is_u64());
        assert!(j["value"]["actionable"].is_boolean());
        assert_eq!(delivery_at(7, false).policy, "best_effort");
    }
}
