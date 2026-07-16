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
    if identical && !prev.pending_drain {
        PollDecision::Unchanged
    } else {
        PollDecision::Recover
    }
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

                entry.path = Some(path.clone());
                entry.mtime = mtime;
                entry.len = len;

                match recover_from_transcript(db_path, &opts) {
                    Ok(report) => {
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
                        // A recovery error is not evidence of an
                        // un-drained tail — clear the flag so a
                        // persistently-failing host doesn't busy-poll.
                        entry.pending_drain = false;
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
}
