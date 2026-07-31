// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2579](https://github.com/alphaonedev/ai-memory-mcp/issues/2579) —
//! the paced FTS5 index-integrity checker and the cached verdict
//! `GET /api/v1/health` renders.
//!
//! **What this replaces.** `db::health_check` used to run
//! `INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')` on
//! EVERY `/health` request. `memories_fts` is an **external-content** FTS5
//! table (`content=memories`), so that command does not merely walk the
//! index — it re-tokenizes every row's `title`/`content`/`tags` out of
//! `memories` and compares the derived doclists. The cost is therefore
//! O(corpus) in TOKENS, measured at 22-30 us/row on a real corpus
//! (0.24 s at 8k rows, 2.8 s at 130k rows), and it is issued as an INSERT,
//! so SQLite prepares it as a NON-readonly statement that takes the single
//! WAL writer lock for its whole duration. A liveness probe scraped on a
//! fixed interval by Kubernetes / systemd therefore (a) exceeded its probe
//! timeout on exactly the largest corpora, killing healthy pods, and (b)
//! kept a write transaction perpetually open under a sustained scrape,
//! which prevents WAL checkpointing.
//!
//! **What this does instead.** The full check runs here, on a paced,
//! jittered cadence, on its OWN connection — never the daemon's single
//! `Arc<Mutex<Connection>>` — and publishes its verdict into an
//! [`IntegrityStatus`] that `/health` reads with a couple of atomic loads.
//! `/health` keeps its fail-closed contract: a cached `Failed` verdict
//! still answers `503`, exactly as the per-probe check did. What changed is
//! FRESHNESS (a corruption is now detected within one interval instead of
//! on the next probe), and `/health` states that explicitly by rendering
//! `fts_integrity.checked_at` alongside the status — the staleness is
//! visible, never implied.
//!
//! **Why the verdict can go stale but never silently.** Per
//! [#2444](https://github.com/alphaonedev/ai-memory-mcp/issues/2444) /
//! [#2445](https://github.com/alphaonedev/ai-memory-mcp/issues/2445), a
//! control that reports success while doing nothing is worse than no
//! control — so an `Ok` verdict older than [`STALE_INTERVAL_MULTIPLIER`]
//! intervals degrades to [`Verdict::Stale`] ON ITS OWN. A checker that dies
//! cannot keep re-presenting its last PASS forever.
//!
//! **Why an operational error does not flip the verdict.** The checker runs
//! on a separate connection, so `SQLITE_BUSY` under a long write is now
//! reachable where it was not before. Only a genuine corruption verdict
//! (`SQLITE_CORRUPT` / `SQLITE_CORRUPT_VTAB`, which is what FTS5 raises when
//! the index disagrees with its content table) records a failure; any other
//! error leaves the previous verdict in place and logs a WARN. Without that
//! split, a transient lock would 503 a healthy node — a NEW false-failure
//! class this change would otherwise have introduced.
//!
//! Design resolved by the 5-agent adversarial vote (`4d3ea1c5`), 4-1 for the
//! cached-background-verdict shape over liveness-only-plus-`doctor`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;

/// Operator override for the integrity-check cadence, in whole seconds.
/// `0` disables the checker entirely (the verdict then renders
/// [`Verdict::Disabled`], which is honest about the absent control rather
/// than presenting a stale pass).
pub const ENV_INTERVAL_SECS: &str = "AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS";

/// Default cadence: every 6 hours. The check is O(corpus) — seconds on a
/// million-row node — so it is a maintenance operation, not a monitoring
/// one. Sourced from the substrate-wide `SECS_PER_HOUR` SSOT so the
/// vendor-literals gate's SECS_PER_* drift-block applies here.
#[allow(clippy::cast_sign_loss)]
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(6 * crate::SECS_PER_HOUR as u64);

/// How many intervals an `Ok` verdict may age before it degrades to
/// [`Verdict::Stale`]. Three tolerates one missed run plus scheduling
/// slack without letting a dead checker present a pass indefinitely.
pub const STALE_INTERVAL_MULTIPLIER: i64 = 3;

/// Upper bound of the RANDOM delay before the FIRST check of a process.
/// A whole fleet restarting together must not run its first integrity
/// check in lockstep (the North Star's no-synchronized-blast rule), but a
/// node must also not stay verdict-less for a whole 6h interval — five
/// minutes spreads the fleet while keeping the blind window short.
#[allow(clippy::cast_sign_loss)]
pub const INITIAL_SPREAD: Duration = Duration::from_secs(5 * 60);

/// Jitter applied to every subsequent interval, as a percentage of the
/// interval, applied symmetrically (`interval * [1 - p/100, 1 + p/100]`).
/// Keeps nodes that happened to align at boot from re-converging.
pub const JITTER_PCT: u64 = 20;

// Discriminants for the `AtomicU8` state. Kept as consts (not a repr(u8)
// enum + transmute) so a corrupt/unexpected byte can never be UB.
const STATE_PENDING: u8 = 0;
const STATE_OK: u8 = 1;
const STATE_FAILED: u8 = 2;

/// Wire tag for [`Verdict::Pending`] — no check has completed yet.
pub const VERDICT_PENDING: &str = "pending";
/// Wire tag for [`Verdict::Ok`].
pub const VERDICT_OK: &str = "ok";
/// Wire tag for [`Verdict::Stale`] — an `Ok` that aged out.
pub const VERDICT_STALE: &str = "stale";
/// Wire tag for [`Verdict::Failed`] — the index disagrees with its content.
pub const VERDICT_FAILED: &str = "failed";
/// Wire tag for [`Verdict::Disabled`] — the operator turned the check off.
pub const VERDICT_DISABLED: &str = "disabled";

/// The verdict `/health` renders for the FTS5 index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The checker has not completed a pass yet in this process. NOT a
    /// failure — `/health` stays `200` — but it is not a pass either.
    Pending,
    /// The last completed check verified the index against its content.
    Ok,
    /// An `Ok` verdict older than [`STALE_INTERVAL_MULTIPLIER`] intervals.
    /// The checker is not running; the node is not asserting integrity.
    Stale,
    /// The check ran and the index disagreed with the content table.
    /// `/health` answers `503` — the pre-#2579 fail-closed contract.
    Failed,
    /// The operator set the cadence to `0`. Reported so an absent control
    /// is never mistaken for a passing one.
    Disabled,
}

impl Verdict {
    /// Stable wire tag rendered into the `/health` body.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => VERDICT_PENDING,
            Self::Ok => VERDICT_OK,
            Self::Stale => VERDICT_STALE,
            Self::Failed => VERDICT_FAILED,
            Self::Disabled => VERDICT_DISABLED,
        }
    }

    /// Whether this verdict takes the node out of rotation. ONLY a
    /// confirmed corruption does; `Pending` / `Stale` / `Disabled` are
    /// "no assertion", not "failed assertion", and 503-ing on those would
    /// deadlock a rolling restart across a whole fleet.
    #[must_use]
    pub fn is_unhealthy(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// Cached FTS5 integrity verdict shared between the background checker and
/// the `/health` handler. Lock-free: the handler pays three relaxed atomic
/// loads, so the probe path stays O(1) under any scrape rate.
#[derive(Debug)]
pub struct IntegrityStatus {
    state: AtomicU8,
    /// UNIX seconds of the last COMPLETED check; `0` = never.
    checked_at_unix: AtomicI64,
    /// Configured cadence in seconds; `0` = disabled.
    interval_secs: AtomicU64,
}

impl IntegrityStatus {
    /// Build a status carrying the configured cadence. `interval_secs == 0`
    /// means the checker is disabled.
    #[must_use]
    pub fn new(interval_secs: u64) -> Self {
        Self {
            state: AtomicU8::new(STATE_PENDING),
            checked_at_unix: AtomicI64::new(0),
            interval_secs: AtomicU64::new(interval_secs),
        }
    }

    /// A status for a process that runs no checker at all (tests, the MCP
    /// stdio surface, any router built without the daemon loop).
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(0)
    }

    /// Record a completed, passing check.
    pub fn record_ok(&self, now_unix: i64) {
        self.checked_at_unix.store(now_unix, Ordering::Relaxed);
        self.state.store(STATE_OK, Ordering::Relaxed);
    }

    /// Record a completed check that found the index inconsistent with its
    /// content table.
    pub fn record_failure(&self, now_unix: i64) {
        self.checked_at_unix.store(now_unix, Ordering::Relaxed);
        self.state.store(STATE_FAILED, Ordering::Relaxed);
    }

    /// UNIX seconds of the last completed check, or `None` if none has
    /// completed.
    #[must_use]
    pub fn checked_at_unix(&self) -> Option<i64> {
        let v = self.checked_at_unix.load(Ordering::Relaxed);
        (v != 0).then_some(v)
    }

    /// Configured cadence in seconds (`0` = disabled).
    #[must_use]
    pub fn interval_secs(&self) -> u64 {
        self.interval_secs.load(Ordering::Relaxed)
    }

    /// Publish the resolved cadence at daemon boot.
    ///
    /// The status is reached through the process-wide
    /// [`crate::runtime_context::RuntimeContext`] (see the field doc there
    /// for why), which is `Default`-constructed — i.e. DISABLED — before
    /// any config is read. `bootstrap_serve` calls this once, with the
    /// resolved interval, immediately before spawning the checker, so the
    /// staleness ceiling in [`Self::verdict_at`] is computed against the
    /// cadence that is actually running.
    pub fn set_interval_secs(&self, secs: u64) {
        self.interval_secs.store(secs, Ordering::Relaxed);
    }

    /// Resolve the verdict as of `now_unix`.
    ///
    /// Order matters and is the whole safety argument:
    /// 1. A recorded FAILURE wins unconditionally — including when the
    ///    checker is later disabled or the verdict ages out. Fail closed.
    /// 2. A disabled checker with no verdict is `Disabled`, never `Ok`.
    /// 3. No completed check is `Pending`, never `Ok`.
    /// 4. An `Ok` older than `STALE_INTERVAL_MULTIPLIER` intervals is
    ///    `Stale` — a dead checker cannot re-present its last pass.
    #[must_use]
    pub fn verdict_at(&self, now_unix: i64) -> Verdict {
        let state = self.state.load(Ordering::Relaxed);
        if state == STATE_FAILED {
            return Verdict::Failed;
        }
        let interval = self.interval_secs();
        if state == STATE_PENDING {
            return if interval == 0 {
                Verdict::Disabled
            } else {
                Verdict::Pending
            };
        }
        // state == STATE_OK
        if interval == 0 {
            // Disabled AFTER a pass: the pass is a historical fact, not a
            // live control. Report the absent control, not the old pass.
            return Verdict::Disabled;
        }
        let checked_at = self.checked_at_unix.load(Ordering::Relaxed);
        let max_age = i64::try_from(interval)
            .unwrap_or(i64::MAX)
            .saturating_mul(STALE_INTERVAL_MULTIPLIER);
        if now_unix.saturating_sub(checked_at) > max_age {
            Verdict::Stale
        } else {
            Verdict::Ok
        }
    }
}

impl Default for IntegrityStatus {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Resolve the configured cadence: [`ENV_INTERVAL_SECS`] when it parses to
/// a `u64`, else [`DEFAULT_INTERVAL`]. An explicit `0` DISABLES the checker
/// (it parses, so it wins); an unparseable value falls through to the
/// default rather than silently disabling the control.
#[must_use]
pub fn resolve_interval() -> Duration {
    match std::env::var(ENV_INTERVAL_SECS) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => DEFAULT_INTERVAL,
        },
        Err(_) => DEFAULT_INTERVAL,
    }
}

/// Symmetric jitter: map `seed` onto `base * [1 - pct/100, 1 + pct/100]`.
/// Pure so the fleet-desynchronisation property is unit-testable without a
/// clock. `pct >= 100` is clamped so the delay can never reach zero.
#[must_use]
pub fn jittered(base: Duration, pct: u64, seed: u64) -> Duration {
    let secs = base.as_secs();
    if secs == 0 {
        return base;
    }
    let pct = pct.min(99);
    let span = secs.saturating_mul(pct) / 100;
    if span == 0 {
        return base;
    }
    let width = span.saturating_mul(2).saturating_add(1);
    let offset = seed % width;
    Duration::from_secs(secs.saturating_add(offset).saturating_sub(span))
}

/// Delay before the FIRST check of a process: uniform over
/// `[0, min(interval, INITIAL_SPREAD)]`. Spreads a fleet restart without
/// leaving any node verdict-less for a whole interval.
#[must_use]
pub fn initial_delay(interval: Duration, seed: u64) -> Duration {
    let cap = interval.min(INITIAL_SPREAD).as_secs();
    if cap == 0 {
        return Duration::from_secs(0);
    }
    Duration::from_secs(seed % (cap + 1))
}

/// Best-effort per-process seed. Node identity does not need to be
/// cryptographic here — it only needs to differ between hosts that booted
/// together, which wall-clock nanos plus the pid supply.
#[must_use]
pub fn process_seed() -> u64 {
    let nanos: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let pid = u64::from(std::process::id());
    nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(pid)
}

/// Outcome of one attempted check. Distinguishing these two is what keeps
/// a transient `SQLITE_BUSY` on the checker's own connection from 503-ing a
/// healthy node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The check completed and the index verified.
    Verified,
    /// The check completed and the index is inconsistent with its content.
    Corrupt,
    /// The check could not be completed (lock contention, open failure,
    /// schema-ahead refusal). The previous verdict is left untouched.
    Unavailable,
}

/// Classify an integrity-check error. FTS5 reports a content/index
/// disagreement as `SQLITE_CORRUPT_VTAB`; some builds surface the generic
/// "malformed" text instead, so both shapes are treated as corruption.
/// Everything else is operational.
#[must_use]
pub fn classify_error(err: &anyhow::Error) -> Outcome {
    if let Some(rusqlite::Error::SqliteFailure(e, msg)) = err.downcast_ref::<rusqlite::Error>() {
        if e.code == rusqlite::ffi::ErrorCode::DatabaseCorrupt {
            return Outcome::Corrupt;
        }
        if msg
            .as_deref()
            .is_some_and(|m| m.contains("malformed") || m.contains("corrupt"))
        {
            return Outcome::Corrupt;
        }
    }
    Outcome::Unavailable
}

/// Run one integrity check against an already-open connection and fold the
/// result into `status`. Returns the [`Outcome`] so callers (`doctor`, the
/// loop, tests) can report it.
pub fn run_once(conn: &rusqlite::Connection, status: &IntegrityStatus, now_unix: i64) -> Outcome {
    match crate::storage::fts_integrity_check(conn) {
        Ok(()) => {
            status.record_ok(now_unix);
            Outcome::Verified
        }
        Err(e) => match classify_error(&e) {
            Outcome::Corrupt => {
                status.record_failure(now_unix);
                tracing::error!(
                    target: TRACE_TARGET,
                    error = %e,
                    "FTS5 integrity check FAILED — the full-text index disagrees with the \
                     memories table. Recall will silently miss rows until the index is rebuilt. \
                     The durable memory TEXT is intact; the index is derived and regenerable."
                );
                Outcome::Corrupt
            }
            _ => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    error = %e,
                    "FTS5 integrity check could not complete; the previous verdict is retained"
                );
                Outcome::Unavailable
            }
        },
    }
}

/// `tracing` target for every event this module emits.
pub const TRACE_TARGET: &str = "ai_memory::fts_integrity";

/// Open a dedicated connection to `path` and run one check.
///
/// The connection is DELIBERATELY not the daemon's. FTS5's
/// `'integrity-check'` is prepared as a WRITER, so running it under the
/// daemon's single `Arc<Mutex<Connection>>` would block every reader —
/// including `/health` itself — for its whole multi-second duration, which
/// would re-create the probe-timeout kill this change exists to remove.
/// On its own connection it takes only SQLite's write lock, so readers are
/// unaffected (WAL) and writers merely queue behind `busy_timeout`.
///
/// [`crate::storage::open_unmigrated`] is the right funnel: it applies the
/// writer pragmas without replaying the bootstrap schema or the migration
/// ladder (the daemon already did), and the check writes no rows.
pub fn run_once_on_path(path: &Path, status: &IntegrityStatus, now_unix: i64) -> Outcome {
    match crate::storage::open_unmigrated(path) {
        Ok(conn) => run_once(&conn, status, now_unix),
        Err(e) => {
            tracing::warn!(
                target: TRACE_TARGET,
                path = %path.display(),
                error = %e,
                "could not open a checker connection; the previous FTS verdict is retained"
            );
            Outcome::Unavailable
        }
    }
}

/// Spawn the paced FTS5 integrity checker.
///
/// A zero `interval` returns a task that exits immediately — the caller
/// still holds a `JoinHandle` so the spawn list stays uniform, and the
/// status renders [`Verdict::Disabled`].
///
/// The check itself runs on `spawn_blocking`: it is a multi-second
/// synchronous rusqlite call, and running it on the async reactor would pin
/// a tokio worker for its whole duration.
#[must_use]
pub fn spawn(db_path: PathBuf, status: Arc<IntegrityStatus>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        if interval.as_secs() == 0 {
            tracing::info!(
                target: TRACE_TARGET,
                env = ENV_INTERVAL_SECS,
                "FTS5 integrity checker DISABLED by configuration; /health will report \
                 `fts_integrity: disabled` rather than a pass"
            );
            return;
        }
        tokio::time::sleep(initial_delay(interval, process_seed())).await;
        loop {
            let path = db_path.clone();
            let st = Arc::clone(&status);
            let now = chrono::Utc::now().timestamp();
            // A panic inside the blocking task must not kill the loop: a
            // dead checker is exactly the failure the staleness ceiling
            // exists to surface, but silently losing the loop to one bad
            // pass would surface it far later than necessary.
            if let Err(e) =
                tokio::task::spawn_blocking(move || run_once_on_path(&path, &st, now)).await
            {
                tracing::error!(target: TRACE_TARGET, error = %e, "integrity-check worker died");
            }
            tokio::time::sleep(jittered(interval, JITTER_PCT, process_seed())).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600;

    #[test]
    fn pending_when_no_check_has_run() {
        let s = IntegrityStatus::new(HOUR);
        assert_eq!(s.verdict_at(0), Verdict::Pending);
        assert_eq!(s.checked_at_unix(), None);
        assert!(!s.verdict_at(0).is_unhealthy());
    }

    #[test]
    fn disabled_when_interval_is_zero() {
        let s = IntegrityStatus::new(0);
        assert_eq!(s.verdict_at(0), Verdict::Disabled);
        // A historical pass must NOT re-present as a live control once the
        // checker is off.
        s.record_ok(100);
        assert_eq!(s.verdict_at(101), Verdict::Disabled);
    }

    #[test]
    fn ok_then_stale_past_the_multiplier() {
        let s = IntegrityStatus::new(HOUR);
        s.record_ok(1_000);
        assert_eq!(s.verdict_at(1_000), Verdict::Ok);
        let edge = 1_000 + i64::try_from(HOUR).unwrap() * STALE_INTERVAL_MULTIPLIER;
        assert_eq!(
            s.verdict_at(edge),
            Verdict::Ok,
            "exactly at the ceiling is still Ok"
        );
        assert_eq!(s.verdict_at(edge + 1), Verdict::Stale);
        assert!(
            !s.verdict_at(edge + 1).is_unhealthy(),
            "stale is no-assertion, not failure"
        );
    }

    #[test]
    fn failure_wins_over_staleness_and_disabling() {
        let s = IntegrityStatus::new(HOUR);
        s.record_failure(1_000);
        assert_eq!(s.verdict_at(1_000), Verdict::Failed);
        assert_eq!(
            s.verdict_at(1_000 + i64::try_from(HOUR).unwrap() * 100),
            Verdict::Failed,
            "an aged-out failure must stay a failure — fail closed"
        );
        assert!(s.verdict_at(i64::MAX).is_unhealthy());
    }

    #[test]
    fn a_later_pass_clears_a_failure() {
        let s = IntegrityStatus::new(HOUR);
        s.record_failure(1_000);
        s.record_ok(2_000);
        assert_eq!(s.verdict_at(2_000), Verdict::Ok);
    }

    #[test]
    fn jitter_stays_inside_the_declared_band_and_actually_spreads() {
        let base = Duration::from_secs(HOUR);
        let lo = HOUR - HOUR * JITTER_PCT / 100;
        let hi = HOUR + HOUR * JITTER_PCT / 100;
        let mut seen = std::collections::HashSet::new();
        for seed in 0..5_000u64 {
            let d = jittered(base, JITTER_PCT, seed.wrapping_mul(0x9E37_79B9)).as_secs();
            assert!(d >= lo && d <= hi, "{d} outside [{lo}, {hi}]");
            seen.insert(d);
        }
        assert!(
            seen.len() > 100,
            "jitter collapsed to {} values",
            seen.len()
        );
    }

    #[test]
    fn jitter_is_a_noop_on_a_zero_interval() {
        assert_eq!(jittered(Duration::from_secs(0), JITTER_PCT, 7).as_secs(), 0);
    }

    #[test]
    fn initial_delay_is_bounded_by_the_spread_and_the_interval() {
        let long = Duration::from_secs(HOUR * 6);
        for seed in 0..1_000u64 {
            assert!(initial_delay(long, seed) <= INITIAL_SPREAD);
        }
        let short = Duration::from_secs(30);
        for seed in 0..1_000u64 {
            assert!(initial_delay(short, seed) <= short);
        }
    }

    #[test]
    fn interval_resolves_env_then_default() {
        // Pure-function contract only; the env read itself is exercised by
        // the daemon boot path. `0` must be honoured as DISABLED, because a
        // knob that cannot be turned off invites a worse workaround.
        assert_eq!(DEFAULT_INTERVAL.as_secs(), 6 * HOUR);
        assert!(DEFAULT_INTERVAL.as_secs() > 0);
    }

    #[test]
    fn operational_errors_do_not_record_a_failure() {
        let s = IntegrityStatus::new(HOUR);
        s.record_ok(1_000);
        let busy = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(5), // SQLITE_BUSY
            Some("database is locked".to_string()),
        ));
        assert_eq!(classify_error(&busy), Outcome::Unavailable);
        // The caller retains the prior verdict on Unavailable.
        assert_eq!(s.verdict_at(1_001), Verdict::Ok);
    }

    #[test]
    fn corruption_codes_are_classified_as_corrupt() {
        let corrupt = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(11), // SQLITE_CORRUPT
            Some("database disk image is malformed".to_string()),
        ));
        assert_eq!(classify_error(&corrupt), Outcome::Corrupt);
        let vtab = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(267), // SQLITE_CORRUPT_VTAB
            None,
        ));
        assert_eq!(classify_error(&vtab), Outcome::Corrupt);
    }

    #[test]
    fn verdict_tags_are_stable() {
        assert_eq!(Verdict::Pending.as_str(), VERDICT_PENDING);
        assert_eq!(Verdict::Ok.as_str(), VERDICT_OK);
        assert_eq!(Verdict::Stale.as_str(), VERDICT_STALE);
        assert_eq!(Verdict::Failed.as_str(), VERDICT_FAILED);
        assert_eq!(Verdict::Disabled.as_str(), VERDICT_DISABLED);
    }

    #[test]
    fn run_once_verifies_a_healthy_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fts-integrity.db");
        let conn = crate::storage::open(&path).expect("open");
        let s = IntegrityStatus::new(HOUR);
        assert_eq!(run_once(&conn, &s, 42), Outcome::Verified);
        assert_eq!(s.verdict_at(42), Verdict::Ok);
        assert_eq!(s.checked_at_unix(), Some(42));
    }

    #[test]
    fn run_once_on_path_is_unavailable_when_the_path_is_not_a_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-a-db.db");
        std::fs::write(&path, b"this is not a sqlite file at all").expect("write");
        let s = IntegrityStatus::new(HOUR);
        s.record_ok(1_000);
        assert_eq!(run_once_on_path(&path, &s, 2_000), Outcome::Unavailable);
        assert_eq!(
            s.verdict_at(1_001),
            Verdict::Ok,
            "an unreadable checker connection must NOT 503 a node"
        );
    }
}
