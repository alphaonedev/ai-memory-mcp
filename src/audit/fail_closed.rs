// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4400 — opt-in fail-closed mode for the flat audit trail (the #3975 T3
//! item).
//!
//! By default the flat trail never fails a memory operation: a lost event is
//! counted (`ai_memory_audit_write_failures_total`), reported on stderr and in
//! `doctor` (#3975), and the write goes ahead. With
//! [`REQUIRE_AUDIT_TRAIL_ENV`] set, a failed append or flush LATCHES this
//! process: every later mutating record-plane operation is refused, through the
//! same chokepoints the record-stop actuator (#1955) already gates, until the
//! trail is writable again. Reads stay live.
//!
//! Decision: 5-agent vote, `handoff/4400-VOTE-RULING-f2h.md` (memory
//! `88fe83b7`): option B, built on the record-stop gate, default OFF, not
//! pinned by `asi-hard`.
//!
//! # What it does NOT promise
//! - Every `audit::emit` runs after its durable write, so a write that was
//!   already past the gate when the trail failed still commits and fails its
//!   own append. That is at most one unaudited write per write IN FLIGHT when
//!   the trail fails (one for a sequential caller; up to the number of
//!   concurrent requests on `serve`), each counted.
//! - A failed retry (see below) is itself a failed append: it consumes a
//!   sequence number and is counted in `ai_memory_audit_write_failures_total`.
//!   During a latched outage the lost-event count and the `audit verify`
//!   sequence gaps therefore grow by about one per second from retries alone,
//!   not from client events.
//! - A one-shot CLI process cannot latch before its single write; it relies on
//!   the #3651 boot refusal when the trail cannot initialise.
//! - This guards the flat SIEM trail (`src/audit.rs`), not the `signed_events`
//!   or forensic chains. But it refuses through the record-stop gate, so a
//!   latched process also refuses the signed `governance.check` rows it would
//!   append (#4465; each counted, the verdict still returned).
//! - `doctor` reports the latch of the `doctor` process itself. For a running
//!   daemon, watch its `/metrics` gauge [`AUDIT_TRAIL_LATCHED_GAUGE`].
//!
//! # Clearing the latch
//! A gated write that finds the latch set first appends a real
//! [`super::AuditAction::TrailResumed`] record. If that append succeeds the
//! trail is writable, the latch clears and the write proceeds; the record also
//! marks in the trail itself where recording resumed. If it fails the write is
//! refused. Retries are rate-limited to one per [`PROBE_INTERVAL_MS`] so a
//! burst of refused writes does not turn into a burst of failed appends (each
//! failed append consumes a sequence number and counts as a lost event).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// #4400 — the knob. Truthy (the shared `1`/`true`/`yes`/`on` grammar) turns
/// the fail-closed latch on. Unset or anything else: the default count-and-
/// report behaviour, byte-identical to pre-#4400.
pub const REQUIRE_AUDIT_TRAIL_ENV: &str = "AI_MEMORY_REQUIRE_AUDIT_TRAIL";

/// #4400 — the least time between two retries of a latched trail.
pub const PROBE_INTERVAL_MS: u64 = 1_000;

/// #4400 — the gauge an operator watches: 1 while this process refuses
/// mutating operations because its audit trail failed.
pub const AUDIT_TRAIL_LATCHED_GAUGE: &str = "ai_memory_audit_trail_latched";

/// Set when a failed append or flush latched this process. Process-local and
/// never persisted: an audit outage is a health condition of this process's
/// sink, not an operator decision (contrast the signed, persisted record-stop).
static LATCHED: AtomicBool = AtomicBool::new(false);

/// Wall-clock milliseconds of the last retry; 0 = never.
static LAST_PROBE_MS: AtomicU64 = AtomicU64::new(0);

/// #4464 — bumped by every counted failure while the mode is on, BEFORE the
/// latch is set. A retry that succeeded clears the latch only if no failure
/// landed meanwhile: otherwise that failure's `swap(true)` was a no-op on the
/// still-set latch and the clear would erase it.
static FAILURE_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Whether the fail-closed mode is on (read per call, like the other
/// direct-read `AI_MEMORY_REQUIRE_*` knobs).
#[must_use]
pub fn require_audit_trail_enabled() -> bool {
    #[cfg(test)]
    if FORCE_ON_FOR_TEST.load(Ordering::SeqCst) {
        return true;
    }
    std::env::var(REQUIRE_AUDIT_TRAIL_ENV).is_ok_and(|v| crate::security_profile::is_truthy(&v))
}

/// Test-only: turn the mode on without touching the process environment.
#[cfg(test)]
static FORCE_ON_FOR_TEST: AtomicBool = AtomicBool::new(false);

/// Test-only: force the mode on (or back to the environment) and reset the
/// latch and retry clock. Callers hold `audit::sink_test_lock`.
#[cfg(test)]
pub(crate) fn force_on_for_test(on: bool) {
    FORCE_ON_FOR_TEST.store(on, Ordering::SeqCst);
    reset_for_test();
}

/// Whether this process is currently refusing mutations because its audit
/// trail failed.
#[must_use]
pub fn audit_trail_latched() -> bool {
    LATCHED.load(Ordering::SeqCst)
}

/// Called on every counted emit failure: latch when the mode is on.
pub(super) fn note_failure_for_latch() {
    if !require_audit_trail_enabled() {
        return;
    }
    FAILURE_EPOCH.fetch_add(1, Ordering::SeqCst);
    if !LATCHED.swap(true, Ordering::SeqCst) {
        let line = format!(
            "ai-memory: the audit trail failed and {REQUIRE_AUDIT_TRAIL_ENV} is set: \
             mutating operations are refused until the trail records again (reads \
             stay live); see {AUDIT_TRAIL_LATCHED_GAUGE} (#4400)"
        );
        tracing::error!("{line}");
        // Nothing is left to report a failing stderr to.
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("{line}\n").as_bytes());
    }
}

/// Why a mutating operation was refused: the reason text the storage and
/// store error variants carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrailUnavailable {
    /// Caller-safe description (no paths, no sink internals).
    pub reason: String,
}

impl std::fmt::Display for AuditTrailUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// #4400 — the check every record-stop chokepoint runs before a mutating
/// operation. `Ok` when the mode is off, when the trail is not latched, or
/// when a retry shows it is writable again (which clears the latch).
///
/// # Errors
/// [`AuditTrailUnavailable`] while the trail is latched and the retry (or the
/// rate limit) says it is still not recording.
pub fn audit_trail_gate() -> Result<(), AuditTrailUnavailable> {
    if !LATCHED.load(Ordering::SeqCst) {
        // The common path: one atomic load, no environment read.
        return Ok(());
    }
    gate_with(
        require_audit_trail_enabled(),
        super::now_unix_ms(),
        probe_trail,
    )
}

/// The whole gate decision against an explicit mode, clock and retry, so the
/// cells never touch the process environment.
fn gate_with(
    enabled: bool,
    now_ms: u64,
    probe: impl FnOnce() -> bool,
) -> Result<(), AuditTrailUnavailable> {
    if !LATCHED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if !enabled {
        // The operator turned the mode off: stop refusing.
        LATCHED.store(false, Ordering::SeqCst);
        return Ok(());
    }
    let last = LAST_PROBE_MS.load(Ordering::SeqCst);
    let due = last == 0 || now_ms.saturating_sub(last) >= PROBE_INTERVAL_MS;
    let epoch = FAILURE_EPOCH.load(Ordering::SeqCst);
    if due
        && LAST_PROBE_MS
            .compare_exchange(last, now_ms.max(1), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        && probe()
    {
        // #4464 — clear, then re-check: a failure either set the latch after
        // this store (still latched), or bumped the epoch before it (re-latch
        // here). Either way it is never erased.
        LATCHED.store(false, Ordering::SeqCst);
        if FAILURE_EPOCH.load(Ordering::SeqCst) == epoch {
            return Ok(());
        }
        LATCHED.store(true, Ordering::SeqCst);
    }
    Err(AuditTrailUnavailable {
        reason: refusal_message(),
    })
}

/// #4400 — THE caller-facing refusal text: names the knob and nothing else
/// (no path, no errno, no sink internals). Every surface renders this one
/// string, so they cannot drift (#3707: the HTTP body never shows an error's
/// `Display`).
#[must_use]
pub fn refusal_message() -> String {
    format!(
        "the audit trail is not recording and {REQUIRE_AUDIT_TRAIL_ENV} is set; \
         mutating operations are refused until it records again (reads stay live)"
    )
}

/// Append a real `trail_resumed` record. `true` when it reached the trail, or
/// when no trail is installed any more (nothing to protect).
fn probe_trail() -> bool {
    let event = super::EventBuilder::new(
        super::AuditAction::TrailResumed,
        super::actor(
            crate::identity::sentinels::DAEMON_PRINCIPAL,
            super::synthesis_sources::SUBSTRATE,
            None,
        ),
        super::target_sweep("*"),
    );
    super::try_emit(event).is_ok()
}

/// Test-only: latch this process now (mode forced on), with the retry not
/// due for [`PROBE_INTERVAL_MS`], so a surface test sees the refusal without
/// installing a failing sink. Callers hold `audit::sink_test_lock` and call
/// [`force_on_for_test`]`(false)` afterwards.
#[cfg(test)]
pub(crate) fn latch_for_test() {
    FORCE_ON_FOR_TEST.store(true, Ordering::SeqCst);
    LATCHED.store(true, Ordering::SeqCst);
    LAST_PROBE_MS.store(super::now_unix_ms().max(1), Ordering::SeqCst);
}

/// Test-only: let the next latched gate retry at once.
#[cfg(test)]
pub(crate) fn reset_probe_clock_for_test() {
    LAST_PROBE_MS.store(0, Ordering::SeqCst);
}

/// Test-only: reset the process-global latch state.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    LATCHED.store(false, Ordering::SeqCst);
    LAST_PROBE_MS.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The latch is process-global and the end-to-end cells in
    /// `fail_closed_4400_tests` also set and reset it, so every cell holds the
    /// ONE audit sink lock (a private lock here raced them).
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        super::super::sink_test_lock()
    }

    /// Unlatched: allowed, and the retry never runs.
    #[test]
    fn an_unlatched_gate_allows_without_a_retry_4400() {
        let _g = lock();
        reset_for_test();
        assert!(gate_with(true, 5, || panic!("no retry when not latched")).is_ok());
    }

    /// Latched with the mode on: refused while the retry fails; the retry is
    /// rate-limited to one per interval; a successful retry clears the latch.
    #[test]
    fn a_latched_gate_retries_at_most_once_per_interval_4400() {
        let _g = lock();
        reset_for_test();
        LATCHED.store(true, Ordering::SeqCst);
        let mut probes = 0;
        let refused = gate_with(true, 10_000, || {
            probes += 1;
            false
        });
        assert!(refused.is_err(), "a failed retry keeps refusing");
        assert!(
            refused
                .unwrap_err()
                .reason
                .contains(REQUIRE_AUDIT_TRAIL_ENV),
            "the refusal names the knob"
        );
        let inside = gate_with(true, 10_500, || {
            probes += 1;
            true
        });
        assert!(inside.is_err(), "inside the interval: refused, no retry");
        assert_eq!(probes, 1);
        assert!(
            gate_with(true, 11_000, || {
                probes += 1;
                true
            })
            .is_ok()
        );
        assert_eq!(probes, 2);
        assert!(
            !audit_trail_latched(),
            "a successful retry clears the latch"
        );
        reset_for_test();
    }

    /// #4464 — a failure that lands while the retry is appending (another
    /// request's emit failing concurrently) is not erased by the retry's
    /// success: the process stays latched and this request is refused.
    /// Red before the fix: the clear was unconditional.
    #[test]
    fn a_failure_during_a_successful_retry_keeps_the_latch_4464() {
        let _g = lock();
        force_on_for_test(true);
        LATCHED.store(true, Ordering::SeqCst);
        let r = gate_with(true, 50_000, || {
            // A concurrent emit failure, landing while the retry appends.
            note_failure_for_latch();
            true
        });
        assert!(r.is_err(), "the concurrent failure must keep refusing");
        assert!(audit_trail_latched(), "the latch survives the retry");
        force_on_for_test(false);
    }

    /// Latched but the mode was turned off: allowed, latch cleared, no retry.
    #[test]
    fn turning_the_mode_off_clears_the_latch_4400() {
        let _g = lock();
        reset_for_test();
        LATCHED.store(true, Ordering::SeqCst);
        assert!(gate_with(false, 1, || panic!("no retry when the mode is off")).is_ok());
        assert!(!audit_trail_latched());
        reset_for_test();
    }
}
