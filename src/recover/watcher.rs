// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! L3 substrate watcher — continuous, std-only poll-based filesystem
//! capture daemon (issue [#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978),
//! the L3 layer of the #1389 layered-capture architecture).
//!
//! ## Why polling, not `notify`
//!
//! The canonical L3 design (policy memory `f62cb182`, #1389 design
//! comment) describes "a daemon thread subscribing to filesystem
//! notifications (the `notify` crate: inotify / `FSEvents` /
//! `ReadDirectoryChangesW`)". Adding `notify` is a new external
//! dependency, which is operator-gated under the sole-authority
//! no-external-injection rule (CLAUDE.md §"Sole-authority operator") —
//! an AI NHI agent cannot add a dependency. This module satisfies the
//! SAME architectural contract — continuous, bounded, backend-agnostic
//! capture across every known host transcript directory, feeding the
//! shared L2 parser pipeline with L2-identical idempotency — using a
//! **std-only bounded poll loop** (`std::fs::metadata` mtime/size
//! diffing) instead of OS-level filesystem notifications. No new
//! crate; the dependency-add blocker recorded against #1978 does not
//! apply to this design.
//!
//! ## Mechanism
//!
//! [`run_watch_daemon`] ticks every `poll_interval` (operator-clamped
//! to [`MIN_POLL_INTERVAL_SECS`]..=[`MAX_POLL_INTERVAL_SECS`]). Each
//! tick, for every watched [`HostKind`] it resolves that host's current
//! most-recently-modified transcript candidate via
//! [`transcript_paths::resolve_transcript`] — the SAME resolver L2
//! (`recover_from_transcript`) uses — reads that file's `(mtime, len)`
//! via `std::fs::metadata`, and compares against the last-observed
//! state for that host ([`poll_once`]). On a detected change (new
//! file, size growth, or mtime advance) it calls
//! [`super::recover_from_transcript`] with that exact path pinned as
//! `transcript_override`, so the new lines are parsed via the shared L2
//! parser table, deduped through `transcript_line_dedup` (the same
//! idempotency L2 and L4 share), and atomised — identical semantics to
//! a manual `ai-memory recover-previous-session` run, just triggered by
//! the poll tick instead of a session boundary.
//!
//! An unchanged host costs one directory-listing + a handful of
//! `stat(2)`-class calls per tick (no DB touch at all); a changed host
//! additionally pays one `recover_from_transcript` call (parse + dedup
//! + write, bounded by `--limit` exactly as the L2 CLI/MCP surfaces
//! are). A stat/parse failure on one host never affects the others
//! (graceful per-host degradation — the same "never wedge the caller"
//! contract L2 documents).
//!
//! ## Shutdown
//!
//! [`run_watch_daemon`] is a synchronous, blocking function (mirrors
//! [`crate::curator::run_daemon`]) driven by an `Arc<AtomicBool>`
//! checked every [`SHUTDOWN_POLL_TICK`]. The CLI async wrapper
//! (`cli::watch::run_watch_daemon_with_primitives`) bridges a
//! `tokio::sync::Notify` (fired on SIGINT, or — on unix — SIGTERM; see
//! `crate::cli::watch::run`) into that flag via `spawn_blocking` — the
//! identical bridge the curator daemon uses.
//!
//! ## Opt-in
//!
//! The watcher never runs unless an operator explicitly invokes
//! `ai-memory watch --once` or `ai-memory watch --daemon`. There is no
//! implicit activation from `serve`, `mcp`, or any other surface.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::transcript_paths::{self, HostKind};
use super::{DEFAULT_RECOVER_LIMIT, RecoverOpts, RecoverReport, recover_from_transcript};

/// Floor on the operator-configurable poll interval. Below this the
/// watcher would busy-poll the filesystem for no practical benefit —
/// host transcripts are written per-turn, not sub-second.
pub const MIN_POLL_INTERVAL_SECS: u64 = 1;

/// Ceiling on the operator-configurable poll interval. Above this the
/// L3 backstop stops being meaningfully "continuous"; the L2
/// recover-on-boot backstop already covers unbounded session-boundary
/// gaps.
pub const MAX_POLL_INTERVAL_SECS: u64 = 3600;

/// Default poll interval when the operator doesn't override it.
/// Bridges the gap between L1 (per-turn, if the agent behaves) and L2
/// (session-boundary) without materially increasing DB load — an
/// unchanged-host tick costs zero DB opens.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Shutdown-flag check granularity for the blocking daemon loop.
/// Mirrors `curator::run_daemon`'s 500ms tick.
const SHUTDOWN_POLL_TICK: Duration = Duration::from_millis(500);

/// Default per-host, per-tick atomisation cap. Mirrors
/// [`DEFAULT_RECOVER_LIMIT`] so the watcher's FIRST tick against a
/// pre-existing, never-recovered transcript can't blow past a sane
/// bound in one call — the remainder is picked up on later ticks since
/// the dedup table + fast-path watermark only ever advance forward.
pub const DEFAULT_WATCH_LIMIT: usize = DEFAULT_RECOVER_LIMIT;

/// Max number of extra re-parse attempts the `Ok`-arm bounded-retry
/// (issue #2150) makes for a single `(mtime, len)` delta whose recovery
/// returned `Ok(report)` with `report.errors` set — a per-turn write
/// that failed *transiently* (e.g. `SQLITE_BUSY` on the per-turn
/// `BEGIN IMMEDIATE` while a live MCP session holds the write lock) but
/// rolled back atomically, so it is retryable. The `#2134` Err-arm
/// retry only covers the hard `Err` case; this bounds the
/// `Ok`-with-embedded-errors case so the failed turn is retried across
/// ticks instead of being stranded once the transcript goes static.
///
/// The bound is what makes this CONVERGE (issue #2126): a
/// *persistently*-erroring turn (a validation reject / quota that never
/// clears) is re-parsed at most `WATCH_RECOVERY_MAX_RETRIES` times per
/// delta, then the watermark advances and re-parsing stops — never the
/// unbounded busy-loop #2126 case (b) forbids (M-DOCUMENTED-MAGIC:
/// documented magic value).
pub const WATCH_RECOVERY_MAX_RETRIES: u8 = 3;

/// Clamp an operator-supplied poll interval (seconds) into the sane
/// `[MIN_POLL_INTERVAL_SECS, MAX_POLL_INTERVAL_SECS]` band.
#[must_use]
pub fn clamp_poll_interval(secs: u64) -> Duration {
    Duration::from_secs(secs.clamp(MIN_POLL_INTERVAL_SECS, MAX_POLL_INTERVAL_SECS))
}

/// Hosts the watcher polls when the operator doesn't restrict via
/// `--host`. Deliberately excludes [`HostKind::Auto`] — the watcher
/// tracks each concrete host's candidate independently (rather than
/// `Auto`'s cross-host "most-recent wins" union) so a Claude Code
/// session and a concurrent Codex session are BOTH captured, not just
/// whichever one most recently touched disk.
#[must_use]
pub fn default_watch_hosts() -> Vec<HostKind> {
    vec![HostKind::ClaudeCode, HostKind::Codex, HostKind::Gemini]
}

/// Per-host last-observed file identity + freshness. `None`/default
/// means "no transcript resolved for this host as of the last tick" —
/// a legitimate steady state (no agent of that kind has written here
/// yet).
#[derive(Debug, Clone, Default)]
pub struct HostPollState {
    path: Option<PathBuf>,
    mtime: Option<SystemTime>,
    len: u64,
    /// `true` when the LAST recovery for this host hit the per-tick
    /// `--limit` cap (`RecoverReport.lines_skipped_limit > 0`), leaving
    /// an un-drained tail. The next tick MUST re-run recovery even when
    /// the file's `(mtime, len)` are unchanged, or the remainder of an
    /// oversized transcript that then goes static is never recovered
    /// (issue #2117 — contradicting the module doc "the remainder is
    /// picked up on later ticks"). Dedup keeps the re-poll idempotent:
    /// already-atomised lines are skipped, only the tail advances.
    pending_drain: bool,
    /// Bounded-retry budget spent on the CURRENTLY-armed `(mtime, len)`
    /// watermark (issue #2150). `0` = not retrying (the steady state);
    /// `> 0` = a prior tick's recovery returned `Ok(report)` with
    /// `report.errors` set (a *transient* per-turn write failure that
    /// rolled back), so the same delta is being re-parsed to retry the
    /// failed turn. Acts as the "armed" signal for change-detection the
    /// same way [`pending_drain`](Self::pending_drain) does: while it is
    /// `> 0`, [`decide_poll`] forces `Recover` even on a byte-identical
    /// static file, so the failed turn is retried instead of stranded.
    /// Capped at [`WATCH_RECOVERY_MAX_RETRIES`] then RESET to `0` (with
    /// the watermark advanced) so a permanently-erroring turn CONVERGES
    /// (issue #2126) rather than busy-looping. Also reset to `0` whenever
    /// a genuine new `(mtime, len)` delta is observed — a fresh capture
    /// opportunity gets a fresh budget.
    retry_attempts: u8,
}

/// The per-host diff decision for a single poll tick — the PURE core of
/// [`poll_once`]'s change detection, split out so the new-file /
/// unchanged / grown / limit-tail branches are directly unit-testable
/// without a real `$HOME`-rooted resolver walk (issue #2118). Given the
/// prior [`HostPollState`] plus this tick's freshly-observed candidate
/// path + `(mtime, len)`, it decides whether recovery must run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDecision {
    /// No transcript candidate resolved this tick — a benign steady
    /// state. `poll_once` clears any prior state and does not touch the
    /// DB.
    NoCandidate,
    /// A candidate resolved but it is byte-identical to the last
    /// observation (same path, `mtime`, and `len`) AND no prior tick
    /// left an un-drained limit-tail — skip recovery for this tick.
    Unchanged,
    /// Recovery must run: a new path, a grown / mtime-advanced file, OR
    /// an identical-but-still-draining file whose prior tick capped out
    /// on `--limit` (`pending_drain`, issue #2117).
    Recover,
}

/// Pure change-detection decision for one host-tick. See
/// [`PollDecision`]. Deliberately free of any filesystem / DB / resolver
/// side effect so every branch is covered by fast unit tests.
#[must_use]
pub fn decide_poll(
    prev: &HostPollState,
    candidate: Option<&std::path::Path>,
    observed_mtime: Option<SystemTime>,
    observed_len: u64,
) -> PollDecision {
    let Some(path) = candidate else {
        return PollDecision::NoCandidate;
    };
    let identical = prev.path.as_deref() == Some(path)
        && prev.mtime == observed_mtime
        && prev.len == observed_len;
    // An armed retry budget (`retry_attempts > 0`, issue #2150) forces
    // `Recover` on a byte-identical static file exactly as an un-drained
    // limit-tail (`pending_drain`, #2117) does: a prior tick's recovery
    // returned `Ok(report)` with a *transient* per-turn write failure, so
    // the same delta must be re-parsed to retry the failed turn (dedup
    // keeps it idempotent). The budget is bounded (#2126), so this cannot
    // busy-loop.
    if identical && !prev.pending_drain && prev.retry_attempts == 0 {
        PollDecision::Unchanged
    } else {
        PollDecision::Recover
    }
}

/// Compose the operator-facing WARN emitted when the issue #2150 bounded
/// retry gives up on a delta whose recovery keeps returning embedded
/// per-turn errors ([`WATCH_RECOVERY_MAX_RETRIES`] attempts exhausted).
/// Extracted as a pure function (M-REGULAR-FN) so the stranded-turn count
/// + remediation text are unit-testable without a `tracing` subscriber.
/// Names the stranded-turn count and the two remediations the operator
/// has: `touch` the transcript so its `(mtime, len)` changes and the
/// watcher re-detects the delta, or re-run the in-session L2 rehydrator.
#[must_use]
fn exhaustion_warning(host: HostKind, transcript: &std::path::Path, stranded: usize) -> String {
    let transcript = transcript.display();
    format!(
        "L3 watch [{host}]: bounded recovery retry exhausted after \
         {WATCH_RECOVERY_MAX_RETRIES} attempt(s) — {stranded} turn(s) still failing \
         capture on {transcript} and will NOT be retried further; remediation: \
         `touch {transcript}` to re-detect the delta, or re-run \
         `ai-memory recover-previous-session`",
        host = host.as_str(),
    )
}

/// Poll-loop configuration. Built once at CLI dispatch time and moved
/// into the blocking daemon body.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Hosts to poll every tick. See [`default_watch_hosts`].
    pub hosts: Vec<HostKind>,
    /// Interval between ticks. Always pre-clamped via
    /// [`clamp_poll_interval`] by the CLI surface.
    pub poll_interval: Duration,
    /// agent_id to attribute captured memories to.
    pub agent_id: String,
    /// Namespace override; `None` defers to `RecoverOpts`'s own
    /// default-namespace resolution.
    pub namespace: Option<String>,
    /// Max lines atomised per host, per tick.
    pub limit: usize,
    /// Parse + report only, no writes.
    pub dry_run: bool,
}

impl WatchConfig {
    /// Sensible defaults for a given agent_id; callers override any
    /// field that diverges (mirrors `RecoverOpts::for_session_start_hook`).
    #[must_use]
    pub fn new(agent_id: String) -> Self {
        Self {
            hosts: default_watch_hosts(),
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            agent_id,
            namespace: None,
            limit: DEFAULT_WATCH_LIMIT,
            dry_run: false,
        }
    }
}

/// Outcome of a single per-host poll attempt this tick. Serialized for
/// `--once`/`--json` reporting and for the periodic daemon-mode
/// tracing summary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostTickOutcome {
    /// Which host this outcome is for.
    pub host: HostKind,
    /// `true` when this tick detected a change (new/modified/grown
    /// transcript) and ran a recovery parse.
    pub changed: bool,
    /// Populated only when `changed` — the recovery report from the
    /// shared L2 pipeline.
    pub recover_report: Option<RecoverReport>,
    /// Best-effort error (e.g. a recovery DB-open failure). A per-host
    /// error never aborts the tick for the remaining hosts.
    pub error: Option<String>,
}

impl HostTickOutcome {
    fn unchanged(host: HostKind) -> Self {
        Self {
            host,
            changed: false,
            recover_report: None,
            error: None,
        }
    }
}

/// Cumulative report across one or more ticks — the `--once`/`--json`
/// wire shape and the daemon-mode periodic tracing-summary source.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchReport {
    /// Total ticks run so far (1 for `--once`).
    pub ticks: u64,
    /// Total host-ticks across all ticks where a change was detected.
    pub changes_detected: u64,
    /// Total new memories atomised across every tick.
    pub memories_captured: u64,
    /// Total per-host errors across every tick.
    pub errors: u64,
    /// Per-host outcomes for the MOST RECENT tick only (bounds the
    /// JSON payload for long-running `--daemon` reporting; the
    /// cumulative counters above cover the full run).
    pub last_tick: Vec<HostTickOutcome>,
}

impl WatchReport {
    /// Fold one tick's outcomes into the cumulative counters and
    /// replace `last_tick`.
    pub fn absorb_tick(&mut self, outcomes: Vec<HostTickOutcome>) {
        self.ticks += 1;
        for o in &outcomes {
            if o.changed {
                self.changes_detected += 1;
            }
            if let Some(r) = &o.recover_report {
                // Count the REAL number of lines atomised this tick, NOT
                // `memories_created.len()` — the latter is truncated to
                // `QUIET_MEMORY_ID_PREVIEW_CAP` (10) because `poll_once`
                // runs recovery in `quiet` mode, and DEFAULT_WATCH_LIMIT
                // (100) ≫ 10, so the headline metric would under-report
                // by up to 10× in the common case (issue #2116).
                // `lines_atomised` is the untruncated count (and, in
                // `--dry-run`, the would-be-written count).
                self.memories_captured += u64::from(r.lines_atomised);
                // Surface errors EMBEDDED in an otherwise-successful
                // `RecoverReport` (a transcript parse failure returns
                // `Ok(report)` with `report.errors` set — the deliberate
                // never-wedge contract in `recover_from_transcript`; per-turn
                // `write_recovered_turn` failures land here too). Without
                // this a parse-failed tick counted these as zero and the
                // `errors_total` metric lied (issue #2136). The `Ok` arm sets
                // `o.error = None`, so this never double-counts with the
                // outcome-level bump below.
                self.errors += u64::try_from(r.errors.len()).unwrap_or(u64::MAX);
            }
            if o.error.is_some() {
                self.errors += 1;
            }
        }
        self.last_tick = outcomes;
    }
}

/// Run exactly one poll tick against every configured host, mutating
/// `states` with the freshly observed `(path, mtime, len)` per host and
/// returning the per-host outcome. Deliberately free of any sleep/loop
/// concern so it is directly unit-testable — [`run_watch_daemon`] is a
/// thin sleep-and-repeat wrapper around this function. The pure
/// new/unchanged/grown/limit-tail branch decision lives in
/// [`decide_poll`] (issue #2118).
///
/// Each tick resolves each host's transcript candidate against the
/// process working directory. The daemon deliberately tracks the
/// project rooted at the directory it was launched from; that directory
/// is invariant for the process's lifetime, so re-reading it every tick
/// (rather than capturing it once) is a harmless equivalent — a
/// `watch --daemon` started from a given cwd watches THAT cwd's session
/// transcripts for its whole run.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn poll_once(
    db_path: &std::path::Path,
    cfg: &WatchConfig,
    states: &mut HashMap<HostKind, HostPollState>,
) -> Vec<HostTickOutcome> {
    poll_once_with_resolver(db_path, cfg, states, transcript_paths::resolve_transcript)
}

/// [`poll_once`] with an injectable transcript resolver. The production
/// entry point [`poll_once`] passes [`transcript_paths::resolve_transcript`]
/// (which walks the real `$HOME`-rooted host directories); unit tests
/// inject a pure resolver so they can drive the change-detection +
/// recovery wiring hermetically instead of depending on the ambient
/// filesystem (M-MOCKABLE-SYSCALLS; issue #2118).
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn poll_once_with_resolver<R>(
    db_path: &std::path::Path,
    cfg: &WatchConfig,
    states: &mut HashMap<HostKind, HostPollState>,
    resolve: R,
) -> Vec<HostTickOutcome>
where
    R: Fn(HostKind, &std::path::Path) -> Result<Option<PathBuf>, transcript_paths::ResolveError>,
{
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut outcomes = Vec::with_capacity(cfg.hosts.len());

    for &host in &cfg.hosts {
        let candidate = match resolve(host, &cwd) {
            Ok(p) => p,
            Err(e) => {
                outcomes.push(HostTickOutcome {
                    host,
                    changed: false,
                    recover_report: None,
                    error: Some(format!("resolve_transcript: {e}")),
                });
                continue;
            }
        };

        let entry = states.entry(host).or_default();

        // Observe this tick's freshness (a no-candidate tick observes
        // nothing), then let the pure decider pick the branch.
        let metadata = candidate.as_ref().and_then(|p| std::fs::metadata(p).ok());
        let mtime = metadata.as_ref().and_then(|m| m.modified().ok());
        let len = metadata.as_ref().map_or(0, std::fs::Metadata::len);

        match decide_poll(entry, candidate.as_deref(), mtime, len) {
            PollDecision::NoCandidate => {
                // No transcript for this host as of this tick — clear any
                // prior state (a previously-resolved file may have been
                // deleted / rotated away) and move on; benign steady
                // state.
                *entry = HostPollState::default();
                outcomes.push(HostTickOutcome::unchanged(host));
            }
            PollDecision::Unchanged => {
                outcomes.push(HostTickOutcome::unchanged(host));
            }
            PollDecision::Recover => {
                // `candidate` is `Some` on this branch (decide_poll only
                // returns `Recover`/`Unchanged` when a candidate
                // resolved).
                let path = candidate.expect("Recover implies a resolved candidate");

                // Issue #2150 counter-reset: a Recover driven by a GENUINE
                // new `(mtime, len)` delta (distinct from the currently-armed
                // retry watermark) is a fresh capture opportunity, so it gets
                // a fresh retry budget. Only a re-poll of the SAME armed
                // watermark (a `retry_attempts > 0` re-detection of a static
                // file) keeps its running count. Computed BEFORE the watermark
                // is advanced below so a flaky-but-progressing transcript
                // never exhausts its budget prematurely.
                let same_as_armed_watermark = entry.path.as_deref() == Some(path.as_path())
                    && entry.mtime == mtime
                    && entry.len == len;
                if !same_as_armed_watermark {
                    entry.retry_attempts = 0;
                }

                // Detected: a new path, the same path grew / its mtime
                // advanced, OR a prior tick left an un-drained limit-tail
                // (issue #2117). Feed the change into the shared L2
                // recovery pipeline, pinning the exact path this tick
                // observed (bypassing the resolver's own re-walk since
                // we've already picked the winner for this tick).
                //
                // `bypass_fast_path` is set: the watcher has already made
                // its own `(mtime, len)` change decision above, so the L2
                // watermark short-circuit is redundant here — and, on a
                // `pending_drain` re-drain whose watermark advanced past
                // the now-static file's mtime, it would fast-path past the
                // un-drained tail and silently strand it (issue #2126,
                // re-opening the #2117 loss). Bypassing makes recovery
                // actually parse so the tail drains across ticks; dedup
                // keeps every re-parse idempotent.
                let opts = RecoverOpts {
                    host,
                    transcript_override: Some(path.clone()),
                    since_iso: None,
                    namespace: cfg.namespace.clone(),
                    limit: cfg.limit,
                    dry_run: cfg.dry_run,
                    quiet: true,
                    agent_id: cfg.agent_id.clone(),
                    bypass_fast_path: true,
                };

                match recover_from_transcript(db_path, &opts) {
                    Ok(report) => {
                        // Issue #2150 — bounded retry of the `Ok`-with-
                        // embedded-errors case. A recovery that returns
                        // `Ok(report)` with `report.errors` set had a per-turn
                        // write fail TRANSIENTLY (e.g. `SQLITE_BUSY` on the
                        // per-turn `BEGIN IMMEDIATE` while a live MCP session
                        // holds the write lock) and roll back atomically — no
                        // dedup row, so the turn is retryable. The #2134
                        // Err-arm retry does NOT cover this (it is `Ok`, not
                        // `Err`); left unhandled the watermark would advance
                        // and, if the transcript then went static, the failed
                        // turn would be stranded forever (the L2 boot backstop
                        // is fast-path-gated, src/recover/mod.rs:373-385).
                        //
                        // So when a non-dry-run tick returns embedded errors
                        // and the retry budget is not spent, ADVANCE the
                        // watermark (so a later genuine delta is
                        // distinguishable for the counter-reset above) but ARM
                        // the retry (`retry_attempts > 0`), which forces
                        // `decide_poll` to `Recover` the SAME static delta next
                        // tick — dedup keeps the re-parse idempotent, exactly
                        // like the #2134 Err lane. The budget is BOUNDED to
                        // `WATCH_RECOVERY_MAX_RETRIES`: a permanently-erroring
                        // turn (validation reject, quota — errors that never
                        // clear) is re-parsed at most that many times per delta
                        // and then CONVERGES (watermark advances, counter
                        // resets, re-parsing stops), never the unbounded
                        // busy-loop #2126 case (b) forbids. `--dry-run` never
                        // arms a retry (no dedup rows ⇒ no progress ⇒ it would
                        // busy-loop, the same guard as `pending_drain`).
                        let retry_armed = !cfg.dry_run
                            && !report.errors.is_empty()
                            && entry.retry_attempts < WATCH_RECOVERY_MAX_RETRIES;

                        // Advance the `(path, mtime, len)` watermark (issue
                        // #2134 committed it only on the `Ok` arm; that still
                        // holds — a hard `Err` leaves it unadvanced below). On
                        // the retry path advancing is safe *because* the armed
                        // counter re-detects the delta regardless.
                        entry.path = Some(path);
                        entry.mtime = mtime;
                        entry.len = len;

                        if retry_armed {
                            // M-DOCUMENTED-MAGIC / num-overflow-explicit: the
                            // `< WATCH_RECOVERY_MAX_RETRIES` guard bounds the
                            // `u8` so `+ 1` cannot overflow.
                            entry.retry_attempts += 1;
                        } else {
                            // Success, OR the retry budget is exhausted. On
                            // EXHAUSTION with errors still present, emit a WARN
                            // naming the stranded-turn count + remediation so
                            // the loss is loud, not silent (issue #2136 made it
                            // visible; this makes the give-up explicit).
                            if !cfg.dry_run
                                && !report.errors.is_empty()
                                && entry.retry_attempts >= WATCH_RECOVERY_MAX_RETRIES
                            {
                                // obs-error-chain / M-LOG-STRUCTURED: surfaced
                                // once, at the give-up boundary, with the
                                // actionable remediation. `entry.path` was just
                                // set to the observed path above.
                                if let Some(stranded_path) = entry.path.as_deref() {
                                    tracing::warn!(
                                        "{}",
                                        exhaustion_warning(
                                            host,
                                            stranded_path,
                                            report.errors.len()
                                        )
                                    );
                                }
                            }
                            entry.retry_attempts = 0;
                        }

                        // Carry an un-drained limit-tail forward so the
                        // next tick re-runs recovery on the (now static)
                        // file until every deduped line is consumed
                        // (issue #2117). In `--dry-run` NO dedup rows are
                        // written, so a re-drain can never make progress —
                        // every tick would re-parse the same first `limit`
                        // lines forever (a busy-loop). So dry-run never
                        // arms `pending_drain`: one inspection parse per
                        // detected `(mtime, len)` change, then the next
                        // identical tick short-circuits to `Unchanged`
                        // (issue #2126 case (b)).
                        entry.pending_drain = !cfg.dry_run && report.lines_skipped_limit > 0;
                        outcomes.push(HostTickOutcome {
                            host,
                            changed: true,
                            recover_report: Some(report),
                            error: None,
                        });
                    }
                    Err(e) => {
                        // Recovery failed (a transient DB-open error while a
                        // live MCP session shares the DB, or a partial
                        // write). Leave the prior `(path, mtime, len)`
                        // watermark UNADVANCED and `pending_drain` UNTOUCHED
                        // (issue #2134): the next tick then re-detects the
                        // SAME `(mtime, len)` delta — or the still-armed
                        // `pending_drain` for a failed drain re-run — and
                        // retries recovery even on a now-static transcript.
                        // Dedup keeps the retry idempotent; it is bounded to
                        // one attempt per `--interval-secs` tick and
                        // CONVERGES once the transient failure clears (unlike
                        // the non-converging dry-run re-parse #2126 case (b)
                        // guards against), so it is not a busy-loop of that
                        // kind. Embedded per-turn `RecoverReport.errors` on
                        // the `Ok` arm are surfaced separately (issue #2136).
                        outcomes.push(HostTickOutcome {
                            host,
                            changed: true,
                            recover_report: None,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
    }

    outcomes
}

/// Blocking L3 daemon body. Loops until `shutdown` flips, sleeping in
/// [`SHUTDOWN_POLL_TICK`] increments between full `cfg.poll_interval`
/// ticks (mirrors [`crate::curator::run_daemon`]'s shutdown-check
/// granularity). Never panics on a per-host recovery failure — see
/// [`poll_once`]'s per-host error handling.
pub fn run_watch_daemon(db_path: PathBuf, cfg: WatchConfig, shutdown: Arc<AtomicBool>) {
    run_watch_daemon_with_resolver(db_path, cfg, shutdown, transcript_paths::resolve_transcript);
}

/// [`run_watch_daemon`] with an injectable transcript resolver, so the
/// shutdown-latency test can drive the loop without walking the real
/// `$HOME`-rooted host directories (M-MOCKABLE-SYSCALLS; issue #2118).
/// Production uses [`run_watch_daemon`].
pub fn run_watch_daemon_with_resolver<R>(
    db_path: PathBuf,
    cfg: WatchConfig,
    shutdown: Arc<AtomicBool>,
    resolve: R,
) where
    R: Fn(HostKind, &std::path::Path) -> Result<Option<PathBuf>, transcript_paths::ResolveError>,
{
    let mut states: HashMap<HostKind, HostPollState> = HashMap::new();
    let mut report = WatchReport::default();
    let hosts_str: Vec<&str> = cfg.hosts.iter().map(|h| h.as_str()).collect();
    tracing::info!(
        "L3 watch daemon started (hosts={:?}, interval={}s, dry_run={})",
        hosts_str,
        cfg.poll_interval.as_secs(),
        cfg.dry_run,
    );

    while !shutdown.load(Ordering::Relaxed) {
        let outcomes = poll_once_with_resolver(&db_path, &cfg, &mut states, &resolve);
        for o in outcomes.iter().filter(|o| o.changed) {
            if let Some(e) = &o.error {
                tracing::warn!("L3 watch: {} tick error: {e}", o.host.as_str());
            } else if let Some(r) = &o.recover_report {
                tracing::info!(
                    "L3 watch: {} captured {} new memories \
                     (skipped_dedup={}, skipped_limit={}, errors={})",
                    o.host.as_str(),
                    // `lines_atomised`, not the quiet-truncated
                    // `memories_created.len()` (issue #2116).
                    r.lines_atomised,
                    r.lines_skipped_dedup,
                    r.lines_skipped_limit,
                    r.errors.len(),
                );
            }
        }
        report.absorb_tick(outcomes);

        let deadline = Instant::now() + cfg.poll_interval;
        while Instant::now() < deadline {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(SHUTDOWN_POLL_TICK.min(cfg.poll_interval));
        }
    }
    tracing::info!(
        "L3 watch daemon shutdown (ticks={}, changes_detected={}, memories_captured={}, errors={})",
        report.ticks,
        report.changes_detected,
        report.memories_captured,
        report.errors,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// In-tree scratch root honoring the project no-`/tmp` HARD RULE.
    fn fresh_dir() -> tempfile::TempDir {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".local-runs")
            .join("issue-1978-poll-watcher-unit-test");
        std::fs::create_dir_all(&root).ok();
        tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
    }

    fn write_transcript(dir: &std::path::Path, lines: &[&str]) -> PathBuf {
        let p = dir.join("session.jsonl");
        let mut f = std::fs::File::create(&p).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        f.flush().unwrap();
        p
    }

    const USER_LINE_1: &str = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":[{"type":"text","text":"first directive"}]}}"#;

    /// One distinct Claude-Code JSONL user turn per `n` (distinct text +
    /// timestamp → distinct dedup key → each atomises separately). Used
    /// to build oversized transcripts for the `--limit` drain tests.
    fn turn_line(n: u32) -> String {
        format!(
            r#"{{"timestamp":"2026-05-28T12:{n:02}:00Z","type":"user","message":{{"content":[{{"type":"text","text":"directive {n}"}}]}}}}"#
        )
    }

    fn base_config(agent_id: &str) -> WatchConfig {
        WatchConfig {
            hosts: vec![HostKind::ClaudeCode],
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            agent_id: agent_id.to_string(),
            namespace: Some("test-watch".to_string()),
            limit: DEFAULT_WATCH_LIMIT,
            dry_run: false,
        }
    }

    #[test]
    fn clamp_poll_interval_bounds_low_and_high() {
        assert_eq!(
            clamp_poll_interval(0),
            Duration::from_secs(MIN_POLL_INTERVAL_SECS)
        );
        assert_eq!(
            clamp_poll_interval(u64::MAX),
            Duration::from_secs(MAX_POLL_INTERVAL_SECS)
        );
        assert_eq!(clamp_poll_interval(30), Duration::from_secs(30));
    }

    #[test]
    fn default_watch_hosts_excludes_auto() {
        let hosts = default_watch_hosts();
        assert!(!hosts.contains(&HostKind::Auto));
        assert!(hosts.contains(&HostKind::ClaudeCode));
        assert!(hosts.contains(&HostKind::Codex));
        assert!(hosts.contains(&HostKind::Gemini));
    }

    #[test]
    fn no_transcript_is_unchanged_and_benign() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let cfg = base_config("ai:test:no-transcript");
        // Hermetic: inject a resolver that reports NO candidate for this
        // host (the steady state on a fresh box) rather than walking the
        // real `$HOME`-rooted host directories (M-MOCKABLE-SYSCALLS;
        // issue #2118). A no-candidate tick must not touch the DB — a
        // hard failure here would mean we opened a connection for a
        // no-op tick.
        let mut states = HashMap::new();
        let outcomes = poll_once_with_resolver(&db, &cfg, &mut states, |_host, _cwd| Ok(None));
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].changed);
        assert!(outcomes[0].error.is_none());
        assert!(
            !db.exists(),
            "a no-candidate tick must not create the db file"
        );
    }

    /// Renamed from the misleading `detects_new_transcript_*` (issue
    /// #2118): the old test only called `recover_from_transcript`
    /// directly and never exercised `poll_once`'s change detection. With
    /// the injectable resolver seam this now genuinely drives `poll_once`
    /// end-to-end — first tick detects the fresh transcript + captures
    /// via the shared L2 pipeline, second tick short-circuits to
    /// `Unchanged` (belt-and-suspenders dedup keeps it idempotent).
    #[test]
    fn poll_once_detects_new_transcript_then_skips_unchanged() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        let cfg = base_config("ai:test:detect");
        let resolve = |_host: HostKind, _cwd: &std::path::Path| Ok(Some(transcript.clone()));

        let mut states = HashMap::new();

        // First tick: fresh transcript → detect + capture.
        let outcomes = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].changed, "fresh transcript must be detected");
        let r1 = outcomes[0].recover_report.as_ref().expect("report");
        assert_eq!(r1.lines_atomised, 1);
        assert!(r1.errors.is_empty(), "errors: {:?}", r1.errors);

        // Second tick: same `(path, mtime, len)`, no pending-drain → the
        // pure `decide_poll` short-circuits to `Unchanged`, so recovery
        // does not even run (no DB touch).
        let outcomes2 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        assert!(!outcomes2[0].changed, "unchanged file must skip recovery");
        assert!(outcomes2[0].recover_report.is_none());
    }

    #[test]
    fn watch_report_absorb_tick_accumulates_counters() {
        let mut report = WatchReport::default();
        let mut rr = RecoverReport::new(HostKind::ClaudeCode, 82);
        rr.lines_atomised = 2;
        rr.memories_created = vec!["a".to_string(), "b".to_string()];
        report.absorb_tick(vec![
            HostTickOutcome {
                host: HostKind::ClaudeCode,
                changed: true,
                recover_report: Some(rr),
                error: None,
            },
            HostTickOutcome::unchanged(HostKind::Codex),
            HostTickOutcome {
                host: HostKind::Gemini,
                changed: true,
                recover_report: None,
                error: Some("boom".to_string()),
            },
        ]);
        assert_eq!(report.ticks, 1);
        assert_eq!(report.changes_detected, 2);
        assert_eq!(report.memories_captured, 2);
        assert_eq!(report.errors, 1);
        assert_eq!(report.last_tick.len(), 3);

        // A second tick REPLACES last_tick but keeps accumulating the
        // cumulative counters.
        report.absorb_tick(vec![HostTickOutcome::unchanged(HostKind::ClaudeCode)]);
        assert_eq!(report.ticks, 2);
        assert_eq!(report.changes_detected, 2);
        assert_eq!(report.last_tick.len(), 1);
    }

    /// Issue #2116 — the headline `memories_captured` metric must be
    /// driven by `lines_atomised`, NOT the quiet-truncated
    /// `memories_created` preview vec (capped at
    /// `QUIET_MEMORY_ID_PREVIEW_CAP` = 10). A tick that atomised more
    /// than the preview cap must report the full count.
    #[test]
    fn absorb_tick_counts_lines_atomised_not_truncated_preview() {
        use crate::recover::QUIET_MEMORY_ID_PREVIEW_CAP;
        let mut report = WatchReport::default();
        let mut rr = RecoverReport::new(HostKind::ClaudeCode, 82);
        // 42 lines atomised this tick, but `quiet` mode truncated the
        // echoed-ID vec to the 10-id preview cap (exactly what
        // `poll_once` produces).
        rr.lines_atomised = 42;
        rr.memories_created = (0..QUIET_MEMORY_ID_PREVIEW_CAP)
            .map(|i| format!("id-{i}"))
            .collect();
        assert_eq!(rr.memories_created.len(), QUIET_MEMORY_ID_PREVIEW_CAP);
        report.absorb_tick(vec![HostTickOutcome {
            host: HostKind::ClaudeCode,
            changed: true,
            recover_report: Some(rr),
            error: None,
        }]);
        assert_eq!(
            report.memories_captured, 42,
            "must count lines_atomised (42), not the 10-id truncated preview"
        );
    }

    /// Issue #2118 — pure change-detection: a fresh host (default state)
    /// with a resolved candidate must decide to recover.
    #[test]
    fn decide_poll_new_transcript_recovers() {
        let prev = HostPollState::default();
        let path = std::path::Path::new("/x/session.jsonl");
        let decision = decide_poll(&prev, Some(path), Some(SystemTime::UNIX_EPOCH), 100);
        assert_eq!(decision, PollDecision::Recover);
    }

    /// Issue #2118 — an identical `(path, mtime, len)` with no pending
    /// limit-tail is unchanged (skip recovery).
    #[test]
    fn decide_poll_unchanged_skips() {
        let path = PathBuf::from("/x/session.jsonl");
        let mtime = Some(SystemTime::UNIX_EPOCH);
        let prev = HostPollState {
            path: Some(path.clone()),
            mtime,
            len: 100,
            pending_drain: false,
            retry_attempts: 0,
        };
        assert_eq!(
            decide_poll(&prev, Some(&path), mtime, 100),
            PollDecision::Unchanged
        );
    }

    /// Issue #2118 — the same path that GREW (larger `len`) must
    /// recover, as must an mtime-advanced file.
    #[test]
    fn decide_poll_grown_or_mtime_advanced_recovers() {
        let path = PathBuf::from("/x/session.jsonl");
        let prev = HostPollState {
            path: Some(path.clone()),
            mtime: Some(SystemTime::UNIX_EPOCH),
            len: 100,
            pending_drain: false,
            retry_attempts: 0,
        };
        // Grew.
        assert_eq!(
            decide_poll(&prev, Some(&path), Some(SystemTime::UNIX_EPOCH), 200),
            PollDecision::Recover
        );
        // mtime advanced (same len).
        assert_eq!(
            decide_poll(
                &prev,
                Some(&path),
                Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                100
            ),
            PollDecision::Recover
        );
    }

    /// Issue #2118 — no candidate resolved this tick is `NoCandidate`
    /// regardless of prior state.
    #[test]
    fn decide_poll_no_candidate() {
        let prev = HostPollState {
            path: Some(PathBuf::from("/x/session.jsonl")),
            mtime: Some(SystemTime::UNIX_EPOCH),
            len: 100,
            pending_drain: false,
            retry_attempts: 0,
        };
        assert_eq!(decide_poll(&prev, None, None, 0), PollDecision::NoCandidate);
    }

    /// Issue #2117 — the limit-tail case: a file whose `(mtime, len)` are
    /// byte-identical to the last observation but whose prior recovery
    /// hit the `--limit` cap (`pending_drain`) MUST re-run recovery so
    /// the un-drained tail of an oversized-then-static transcript is
    /// eventually recovered (module doc "remainder is picked up on later
    /// ticks").
    #[test]
    fn decide_poll_pending_drain_forces_recover_on_static_file() {
        let path = PathBuf::from("/x/session.jsonl");
        let mtime = Some(SystemTime::UNIX_EPOCH);
        let prev = HostPollState {
            path: Some(path.clone()),
            mtime,
            len: 100,
            pending_drain: true,
            retry_attempts: 0,
        };
        // Identical freshness, yet the un-drained tail forces a re-poll.
        assert_eq!(
            decide_poll(&prev, Some(&path), mtime, 100),
            PollDecision::Recover
        );
    }

    #[test]
    fn run_watch_daemon_stops_promptly_on_shutdown_signal() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let mut cfg = base_config("ai:test:daemon-shutdown");
        // Hermetic: inject a resolver that never resolves a candidate so
        // the loop does no DB work and never walks the real `$HOME`
        // (M-MOCKABLE-SYSCALLS; issue #2118). A short interval keeps the
        // test quick even absent the shutdown signal.
        cfg.poll_interval = Duration::from_secs(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::spawn(move || {
            run_watch_daemon_with_resolver(db, cfg, shutdown_for_thread, |_host, _cwd| Ok(None));
        });
        // Give it a moment to enter the loop, then signal shutdown.
        std::thread::sleep(Duration::from_millis(50));
        shutdown.store(true, Ordering::Relaxed);
        let start = Instant::now();
        handle.join().expect("daemon thread joins cleanly");
        // Shutdown must be observed within one SHUTDOWN_POLL_TICK
        // (500ms) plus scheduling slack — well under the 1s poll
        // interval, proving the daemon isn't just sleeping the full
        // interval before checking the flag.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "daemon took too long to shut down: {:?}",
            start.elapsed()
        );
    }

    /// Issue #2126 (a) — the un-drained `pending_drain` tail of an
    /// oversized-then-static transcript MUST still drain on later ticks
    /// even after the agent's `MAX(created_at)` watermark advances PAST
    /// the file's mtime (a same-agent wall-clock L1 write mid-drain). The
    /// #2117 fix armed `pending_drain`, but `poll_once` fed recovery a
    /// fast-path-eligible `RecoverOpts` — so once the watermark passed the
    /// mtime the drain tick fast-pathed, reported `lines_skipped_limit=0`,
    /// cleared `pending_drain`, and SILENTLY stranded the tail (re-opening
    /// the exact #2117 loss). The fix is `bypass_fast_path` on the
    /// watcher's recovery so it actually parses.
    #[test]
    fn pending_drain_tail_drains_even_after_watermark_advances_2126() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let lines = [turn_line(1), turn_line(2), turn_line(3)];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let transcript = write_transcript(dir.path(), &refs);
        let mut cfg = base_config("ai:test:2126");
        cfg.limit = 1; // one turn/tick → a two-tick tail to drain
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Tick 1: capture turn 1, skip the rest → pending_drain armed.
        let o1 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        let r1 = o1[0].recover_report.as_ref().expect("report");
        assert_eq!(r1.lines_atomised, 1);
        assert!(r1.lines_skipped_limit >= 1);
        assert!(states[&HostKind::ClaudeCode].pending_drain);

        // Advance the agent watermark PAST the static file's mtime — the
        // exact #2126 trigger (a same-agent wall-clock L1 write mid-drain).
        {
            let conn = crate::storage::open(&db).expect("open");
            conn.execute(
                "UPDATE memories SET created_at = '2999-01-01T00:00:00Z' WHERE agent_id_idx = ?1",
                rusqlite::params![&cfg.agent_id],
            )
            .expect("advance watermark");
        }

        // Tick 2: watermark now far in the future, yet the drain MUST
        // parse (bypass_fast_path) and capture the tail — never fast-path.
        let o2 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        let r2 = o2[0].recover_report.as_ref().expect("report");
        assert!(
            !r2.fast_path_hit,
            "watcher must bypass the L2 watermark fast-path (#2126)"
        );
        assert_eq!(
            r2.lines_atomised, 1,
            "the tail turn must be captured, not silently stranded"
        );

        // Tick 3: last turn drains, pending_drain clears — no busy-loop.
        let o3 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        let r3 = o3[0].recover_report.as_ref().expect("report");
        assert_eq!(r3.lines_atomised, 1);
        assert_eq!(r3.lines_skipped_limit, 0);
        assert!(
            !states[&HostKind::ClaudeCode].pending_drain,
            "pending_drain must clear once the tail is fully drained"
        );

        // Tick 4: fully drained + static → Unchanged, no re-parse.
        let o4 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        assert!(
            !o4[0].changed,
            "a fully-drained static file must be Unchanged"
        );
    }

    /// Issue #2126 (b) — a `--dry-run` watch over an oversized static
    /// transcript must NOT busy-loop. Dry-run writes no dedup rows, so a
    /// re-drain can never make progress; arming `pending_drain` would
    /// re-parse the same first `limit` lines every tick forever. Dry-run
    /// therefore does exactly ONE inspection parse per detected change,
    /// then short-circuits to `Unchanged`.
    #[test]
    fn dry_run_oversized_transcript_does_not_busy_loop_2126() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let lines = [turn_line(1), turn_line(2), turn_line(3)];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let transcript = write_transcript(dir.path(), &refs);
        let mut cfg = base_config("ai:test:2126-dry");
        cfg.limit = 1;
        cfg.dry_run = true;
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Tick 1: inspect (count a would-be write + a skipped tail) but
        // MUST NOT arm pending_drain.
        let o1 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        let r1 = o1[0].recover_report.as_ref().expect("report");
        assert_eq!(r1.lines_atomised, 1);
        assert!(r1.lines_skipped_limit >= 1);
        assert!(
            !states[&HostKind::ClaudeCode].pending_drain,
            "dry-run must never arm pending_drain (busy-loop guard, #2126 (b))"
        );

        // Tick 2: same `(path, mtime, len)` + pending_drain=false → the
        // static file short-circuits to Unchanged (no perpetual re-parse).
        let o2 = poll_once_with_resolver(&db, &cfg, &mut states, resolve);
        assert!(
            !o2[0].changed,
            "dry-run over a static oversized transcript must not re-parse every tick"
        );
        assert!(o2[0].recover_report.is_none());
    }

    /// Issue #2134 — a change whose recovery fails transiently (e.g. a
    /// DB-open error while a live MCP session shares the DB) MUST be
    /// retried on a later tick even when the transcript has since gone
    /// static. The fix advances the per-host `(mtime, len)` watermark
    /// ONLY after a successful recovery, so a failed tick leaves the same
    /// delta re-detectable. Drives the real `poll_once` change-detection
    /// end-to-end (NOT a `decide_poll`-only check) per the audit's
    /// "do not bypass poll_once" requirement.
    #[test]
    fn poll_once_retries_after_transient_recovery_failure_on_static_file_2134() {
        let dir = fresh_dir();
        // A directory is not an openable sqlite file → RecoverError::DbOpen,
        // a hermetic stand-in for the transient DB-open failure #2134
        // describes (a live session holding the write lock, a disk blip).
        let bad_db = dir.path().join("unopenable-db-dir");
        std::fs::create_dir_all(&bad_db).unwrap();
        let good_db = dir.path().join("mem.db");
        // Static transcript: written ONCE, never modified between ticks, so
        // the ONLY thing that can drive a tick-2 recover is an unadvanced
        // watermark (the bug: tick 1 advanced it despite failing).
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        let cfg = base_config("ai:test:2134");
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Tick 1: change detected, but recovery fails (DB-open) → `changed`
        // with an error and NO report. The watermark must stay UNADVANCED.
        let o1 = poll_once_with_resolver(&bad_db, &cfg, &mut states, resolve);
        assert!(o1[0].changed, "a fresh transcript is a detected change");
        assert!(
            o1[0].error.is_some(),
            "recovery must fail against an unopenable db path"
        );
        assert!(o1[0].recover_report.is_none());

        // Tick 2: SAME static transcript, now a good db. Because tick 1 left
        // the watermark unadvanced, the same `(mtime, len)` delta is
        // re-detected and recovery runs — the un-captured line is finally
        // atomised instead of stranded (pre-fix this tick was `Unchanged`).
        let o2 = poll_once_with_resolver(&good_db, &cfg, &mut states, resolve);
        assert!(
            o2[0].changed,
            "the failed change must be retried on a static file, not stranded"
        );
        let r2 = o2[0].recover_report.as_ref().expect("report");
        assert_eq!(
            r2.lines_atomised, 1,
            "the previously-failed line is captured on retry"
        );

        // Tick 3: recovery having succeeded, the watermark advanced, so the
        // still-static file short-circuits to Unchanged (no busy re-parse).
        let o3 = poll_once_with_resolver(&good_db, &cfg, &mut states, resolve);
        assert!(
            !o3[0].changed,
            "a successfully-drained static file must be Unchanged (no busy-loop)"
        );
    }

    /// Build a migrated sqlite DB at `name` under `dir`, then install a
    /// `BEFORE INSERT` trigger on `memories` that `RAISE(ABORT)`s — so
    /// every L2 per-turn `insert` fails with `MEMORY_INSERT_FAILED`, which
    /// `recover_from_transcript` surfaces as `Ok(report)` with
    /// `report.errors` set (the never-wedge contract; a rolled-back per-turn
    /// write ⇒ no dedup row ⇒ retryable). A hermetic, fast, deterministic
    /// stand-in for the #2150 TRANSIENT per-turn write failure (the issue
    /// names `SQLITE_BUSY` on the per-turn `BEGIN IMMEDIATE`; any
    /// Ok-embedded per-turn write error drives the IDENTICAL `poll_once`
    /// retry logic). The bootstrap `SCHEMA` re-run on the next `open()`
    /// uses `CREATE ... IF NOT EXISTS`, so this custom-named trigger
    /// survives every subsequent open.
    fn poison_write_db(dir: &std::path::Path, name: &str) -> PathBuf {
        let db = dir.join(name);
        let conn = crate::storage::open(&db).expect("open+migrate db");
        conn.execute_batch(
            "CREATE TRIGGER ai_memory_2150_poison_insert \
             BEFORE INSERT ON memories \
             BEGIN SELECT RAISE(ABORT, 'poisoned-write-2150'); END;",
        )
        .expect("install poison trigger");
        db
    }

    /// Issue #2150 (transient lane) — a recovery that returns `Ok(report)`
    /// with `report.errors` set (a per-turn write that failed TRANSIENTLY
    /// and rolled back, e.g. `SQLITE_BUSY` on the per-turn `BEGIN
    /// IMMEDIATE`) MUST be retried on a later tick even when the transcript
    /// has since gone static — the `Ok`-arm sibling of the #2134 Err lane.
    /// The #2134 fix only covers the hard `Err`; without this, the failed
    /// turn advances the watermark and is stranded forever (the L2 boot
    /// backstop is fast-path-gated). Drives the real `poll_once`
    /// change-detection end-to-end per the audit's "do not bypass
    /// poll_once" requirement.
    #[test]
    fn poll_once_retries_after_transient_embedded_error_on_static_file_2150() {
        let dir = fresh_dir();
        let poisoned = poison_write_db(dir.path(), "poisoned.db");
        // A distinct, initially-nonexistent good db (recover's `open` creates
        // it) — the environment change that clears the transient error, the
        // #2134 bad→good db-swap shape but producing an Ok-embedded error.
        let good = dir.path().join("good.db");
        // Static transcript: written ONCE, never modified, so the ONLY thing
        // that can drive a tick-2 recover is the armed retry budget.
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        let cfg = base_config("ai:test:2150-transient");
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Tick 1: poisoned db → the per-turn write fails → `Ok(report)` with
        // embedded errors (NOT an outcome-level `Err`) and NOTHING captured.
        // The retry budget is armed so the delta is not stranded.
        let o1 = poll_once_with_resolver(&poisoned, &cfg, &mut states, resolve);
        assert!(o1[0].changed, "a fresh transcript is a detected change");
        assert!(
            o1[0].error.is_none(),
            "an embedded per-turn error is Ok, not an outcome-level Err"
        );
        let r1 = o1[0].recover_report.as_ref().expect("Ok(report), not Err");
        assert!(
            !r1.errors.is_empty(),
            "the failed per-turn write lands in report.errors (#2136)"
        );
        assert_eq!(r1.lines_atomised, 0, "the failed turn is NOT captured");
        assert_eq!(
            states[&HostKind::ClaudeCode].retry_attempts,
            1,
            "the transient-embedded-error tick arms the retry budget"
        );

        // Tick 2: SAME static transcript, now a GOOD db. The armed retry
        // forces Recover on the byte-identical file, and the previously-failed
        // turn is finally captured (pre-#2150 this tick was `Unchanged` — the
        // permanent-loss lane).
        let o2 = poll_once_with_resolver(&good, &cfg, &mut states, resolve);
        assert!(
            o2[0].changed,
            "the armed retry re-detects the static delta (#2150 lane closed)"
        );
        let r2 = o2[0].recover_report.as_ref().expect("report");
        assert!(
            r2.errors.is_empty(),
            "the transient error cleared on retry: {:?}",
            r2.errors
        );
        assert_eq!(
            r2.lines_atomised, 1,
            "the previously-failed turn is captured on retry"
        );
        assert_eq!(
            states[&HostKind::ClaudeCode].retry_attempts,
            0,
            "a successful capture resets the retry budget"
        );

        // Tick 3: captured + watermark advanced → Unchanged (no busy re-parse).
        let o3 = poll_once_with_resolver(&good, &cfg, &mut states, resolve);
        assert!(
            !o3[0].changed,
            "a captured static file must be Unchanged (no busy-loop)"
        );
    }

    /// Issue #2150 convergence invariant (the #2126 guard for the new lane)
    /// — a PERSISTENTLY-erroring turn on a static transcript (an error that
    /// never clears: validation reject, quota) MUST converge: exactly
    /// [`WATCH_RECOVERY_MAX_RETRIES`]`+ 1` re-parses (the initial parse plus
    /// the bounded retries), then the watermark advances, the counter
    /// resets, and re-parsing stops. It must NOT reintroduce the #2126
    /// unbounded busy-loop.
    #[test]
    fn poll_once_persistent_embedded_error_converges_bounded_2150_2126() {
        let dir = fresh_dir();
        // The SAME poisoned db every tick → the per-turn write ALWAYS fails
        // (an error that never clears — the non-convergence hazard).
        let poisoned = poison_write_db(dir.path(), "poisoned.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        let cfg = base_config("ai:test:2150-persistent");
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Run well past the budget; record which ticks re-parsed (changed).
        let total_ticks = u32::from(WATCH_RECOVERY_MAX_RETRIES) + 5;
        let mut changed_ticks = Vec::new();
        for _ in 0..total_ticks {
            let o = poll_once_with_resolver(&poisoned, &cfg, &mut states, resolve);
            // The write never succeeds, so nothing is ever captured.
            if let Some(r) = &o[0].recover_report {
                assert_eq!(r.lines_atomised, 0, "a poisoned write never captures");
            }
            changed_ticks.push(o[0].changed);
        }

        // Exactly (initial parse + N retries) re-parses, then convergence.
        let reparses = changed_ticks.iter().filter(|c| **c).count();
        assert_eq!(
            reparses,
            usize::from(WATCH_RECOVERY_MAX_RETRIES) + 1,
            "a persistent embedded error is bounded to the initial parse + \
             WATCH_RECOVERY_MAX_RETRIES retries, then converges"
        );
        // The re-parses are the LEADING ticks; every later tick is Unchanged
        // (no busy-loop) — the #2126 non-convergence guard for the new lane.
        for (i, changed) in changed_ticks.iter().enumerate() {
            let expected = i <= usize::from(WATCH_RECOVERY_MAX_RETRIES);
            assert_eq!(
                *changed, expected,
                "tick {i}: convergence — leading ticks re-parse, the rest are Unchanged"
            );
        }
        assert_eq!(
            states[&HostKind::ClaudeCode].retry_attempts,
            0,
            "the budget is reset to 0 on give-up (armed state cleared)"
        );
    }

    /// Issue #2150 counter-reset — an embedded-error tick arms the retry
    /// budget; a subsequent GENUINE `(mtime, len)` delta (the transcript
    /// legitimately grew) is a FRESH capture opportunity and MUST reset the
    /// budget rather than continue the old count, so a flaky-but-progressing
    /// transcript never exhausts its budget prematurely.
    #[test]
    fn poll_once_retry_budget_resets_on_fresh_delta_2150() {
        let dir = fresh_dir();
        let poisoned = poison_write_db(dir.path(), "poisoned.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        let cfg = base_config("ai:test:2150-reset");
        let resolve = |_h: HostKind, _c: &std::path::Path| Ok(Some(transcript.clone()));
        let mut states = HashMap::new();

        // Tick 1 on delta A → embedded error → retry budget armed at 1.
        let o1 = poll_once_with_resolver(&poisoned, &cfg, &mut states, resolve);
        assert!(!o1[0].recover_report.as_ref().unwrap().errors.is_empty());
        assert_eq!(
            states[&HostKind::ClaudeCode].retry_attempts,
            1,
            "delta A arms the retry budget at 1"
        );

        // The transcript legitimately CHANGES (append a distinct line → the
        // (mtime, len) grows) — a fresh capture opportunity, NOT a
        // continuation of delta A's budget. It STILL errors (same poisoned
        // db), so the ONLY reason the counter is back at 1 (not 2) is the
        // fresh-delta reset.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(f, "{}", turn_line(2)).unwrap();
            f.flush().unwrap();
        }

        let o2 = poll_once_with_resolver(&poisoned, &cfg, &mut states, resolve);
        assert!(o2[0].changed, "the grown transcript is a detected delta");
        assert!(
            !o2[0].recover_report.as_ref().unwrap().errors.is_empty(),
            "the fresh delta still errors (same poisoned db)"
        );
        assert_eq!(
            states[&HostKind::ClaudeCode].retry_attempts,
            1,
            "a fresh (mtime, len) delta RESETS the budget (would be 2 without the reset)"
        );
    }

    /// Issue #2150 — the exhaustion WARN names the stranded-turn count and
    /// both remediations (`touch` / re-run `recover-previous-session`), so
    /// the give-up is loud + actionable. Asserted on the pure composer so no
    /// `tracing` subscriber is needed.
    #[test]
    fn exhaustion_warning_names_stranded_count_and_remediation_2150() {
        let w = exhaustion_warning(
            HostKind::ClaudeCode,
            std::path::Path::new("/x/session.jsonl"),
            3,
        );
        assert!(
            w.contains("3 turn(s)"),
            "names the stranded-turn count: {w}"
        );
        assert!(w.contains("/x/session.jsonl"), "names the transcript: {w}");
        assert!(w.contains("touch"), "names the touch remediation: {w}");
        assert!(
            w.contains("recover-previous-session"),
            "names the recover-previous-session remediation: {w}"
        );
    }

    /// Issue #2136 — errors EMBEDDED in an otherwise-successful
    /// `RecoverReport` (a transcript parse failure returns `Ok(report)`
    /// with `report.errors` set — the never-wedge contract; per-turn
    /// `write_recovered_turn` failures land there too) MUST reach the
    /// cumulative `WatchReport.errors` (`errors_total`), else a
    /// parse-failed tick reports `errors_total: 0`.
    #[test]
    fn absorb_tick_surfaces_embedded_recover_errors_2136() {
        let mut report = WatchReport::default();
        let mut rr = RecoverReport::new(HostKind::ClaudeCode, 82);
        rr.lines_atomised = 0; // parse failed → nothing captured this tick
        rr.errors = vec![
            "parse failed: unexpected end of input".to_string(),
            "skipping turn with malformed sha256: zz".to_string(),
        ];
        report.absorb_tick(vec![HostTickOutcome {
            host: HostKind::ClaudeCode,
            changed: true,
            recover_report: Some(rr),
            error: None,
        }]);
        assert_eq!(
            report.errors, 2,
            "embedded RecoverReport.errors must reach the errors_total counter"
        );
        assert_eq!(report.memories_captured, 0);

        // A mixed second tick: an outcome-level error (report `None`) plus
        // an embedded-error report — both count, no double-count (the `Ok`
        // arm always sets `error = None`).
        let mut rr2 = RecoverReport::new(HostKind::Codex, 82);
        rr2.errors = vec!["parse failed: x".to_string()];
        report.absorb_tick(vec![
            HostTickOutcome {
                host: HostKind::ClaudeCode,
                changed: true,
                recover_report: None,
                error: Some("db-open boom".to_string()),
            },
            HostTickOutcome {
                host: HostKind::Codex,
                changed: true,
                recover_report: Some(rr2),
                error: None,
            },
        ]);
        assert_eq!(
            report.errors, 4,
            "outcome-level (+1) and embedded (+1) both accrue, no double-count"
        );
    }
}
