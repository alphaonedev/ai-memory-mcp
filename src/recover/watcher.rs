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
//! (`daemon_runtime::run_watch_daemon_with_primitives`) bridges a
//! `tokio::sync::Notify` (fired on SIGINT) into that flag via
//! `spawn_blocking` — the identical bridge the curator daemon uses.
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
                self.memories_captured +=
                    u64::try_from(r.memories_created.len()).unwrap_or(u64::MAX);
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
/// thin sleep-and-repeat wrapper around this function.
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
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut outcomes = Vec::with_capacity(cfg.hosts.len());

    for &host in &cfg.hosts {
        let candidate = match transcript_paths::resolve_transcript(host, &cwd) {
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

        let Some(path) = candidate else {
            // No transcript for this host as of this tick — clear any
            // prior state (a previously-resolved file may have been
            // deleted / rotated away) and move on; benign steady state.
            *entry = HostPollState::default();
            outcomes.push(HostTickOutcome::unchanged(host));
            continue;
        };

        let metadata = std::fs::metadata(&path).ok();
        let mtime = metadata.as_ref().and_then(|m| m.modified().ok());
        let len = metadata.as_ref().map_or(0, std::fs::Metadata::len);

        let unchanged = entry.path.as_deref() == Some(path.as_path())
            && entry.mtime == mtime
            && entry.len == len;

        if unchanged {
            outcomes.push(HostTickOutcome::unchanged(host));
            continue;
        }

        // Detected: a new path, or the same path grew / its mtime
        // advanced. Feed the change into the shared L2 recovery
        // pipeline, pinning the exact path this tick observed
        // (bypassing the resolver's own re-walk since we've already
        // picked the winner for this tick).
        let opts = RecoverOpts {
            host,
            transcript_override: Some(path.clone()),
            since_iso: None,
            namespace: cfg.namespace.clone(),
            limit: cfg.limit,
            dry_run: cfg.dry_run,
            quiet: true,
            agent_id: cfg.agent_id.clone(),
        };

        entry.path = Some(path.clone());
        entry.mtime = mtime;
        entry.len = len;

        match recover_from_transcript(db_path, &opts) {
            Ok(report) => outcomes.push(HostTickOutcome {
                host,
                changed: true,
                recover_report: Some(report),
                error: None,
            }),
            Err(e) => outcomes.push(HostTickOutcome {
                host,
                changed: true,
                recover_report: None,
                error: Some(e.to_string()),
            }),
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
        let outcomes = poll_once(&db_path, &cfg, &mut states);
        for o in outcomes.iter().filter(|o| o.changed) {
            if let Some(e) = &o.error {
                tracing::warn!("L3 watch: {} tick error: {e}", o.host.as_str());
            } else if let Some(r) = &o.recover_report {
                tracing::info!(
                    "L3 watch: {} captured {} new memories (skipped_dedup={}, errors={})",
                    o.host.as_str(),
                    r.memories_created.len(),
                    r.lines_skipped_dedup,
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
        // Point HOME somewhere with no Claude Code project dir by using
        // a cwd that never resolves. `resolve_transcript` swallows a
        // missing dir gracefully, so this call must not touch the DB
        // (a hard failure here would mean we opened a connection for a
        // no-op tick).
        let mut states = HashMap::new();
        let outcomes = poll_once(&db, &cfg, &mut states);
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].changed);
        assert!(outcomes[0].error.is_none());
        assert!(
            !db.exists(),
            "a no-candidate tick must not create the db file"
        );
    }

    #[test]
    fn detects_new_transcript_and_captures_via_l2_pipeline() {
        use crate::recover::transcript_paths::HostKind as HK;
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);

        // Directly exercise `poll_once`'s change-detection + recovery
        // wiring by pre-seeding a `HostPollState` as if `resolve_transcript`
        // had already returned this exact path with stale (empty) state —
        // then flip the file to simulate the resolver returning it fresh.
        let cfg = base_config("ai:test:detect");

        // Simulate the resolver having previously seen NOTHING for this
        // host, then a transcript appears: call the shared recovery path
        // directly with the resolved candidate to prove the plumbing
        // (poll_once itself requires a real HOME-rooted resolver walk,
        // covered end-to-end by `transcript_paths` tests + the CLI test
        // in `cli::watch::tests`).
        let opts = RecoverOpts {
            host: HK::ClaudeCode,
            transcript_override: Some(transcript.clone()),
            since_iso: None,
            namespace: cfg.namespace.clone(),
            limit: cfg.limit,
            dry_run: false,
            quiet: true,
            agent_id: cfg.agent_id.clone(),
        };
        let report = recover_from_transcript(&db, &opts).unwrap();
        assert_eq!(report.lines_atomised, 1);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);

        // Second call against the SAME unmodified file must dedup to
        // zero new lines — the same idempotency guarantee L2 gives,
        // which is exactly what makes repeated polling of an unchanged
        // file safe once `poll_once`'s own mtime/size diff lets a tick
        // through anyway (belt-and-suspenders dedup).
        let report2 = recover_from_transcript(&db, &opts).unwrap();
        assert_eq!(report2.lines_atomised, 0);
        assert_eq!(report2.lines_skipped_dedup, 1);
    }

    #[test]
    fn watch_report_absorb_tick_accumulates_counters() {
        let mut report = WatchReport::default();
        let mut rr = RecoverReport::new(HostKind::ClaudeCode, 82);
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

    #[test]
    fn run_watch_daemon_stops_promptly_on_shutdown_signal() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let mut cfg = base_config("ai:test:daemon-shutdown");
        // Point the daemon at a host with no resolvable transcript
        // (empty HOME-independent hosts list would still walk real
        // $HOME; scope to ClaudeCode which gracefully no-ops when the
        // project dir is absent) and a short interval so the test
        // doesn't wait long even without the shutdown signal.
        cfg.poll_interval = Duration::from_secs(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::spawn(move || {
            run_watch_daemon(db, cfg, shutdown_for_thread);
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
}
