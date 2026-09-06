// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3470 (EPIC #3466) — the wake-hub CLIENT: one long-lived session
//! that turns a content-free hint into "read your inbox now".
//!
//! # What this module decides, and what it deliberately does not
//!
//! It decides WHEN an agent should read its inbox. It never decides WHAT is in
//! the inbox: no frame it handles carries a body, and the durable ai-memory
//! row remains the only record. Everything here is therefore a LATENCY
//! optimisation over the poll that was always the guarantee, which is why
//! every failure mode below degrades to "read a little later" and none of them
//! can lose a committed notify.
//!
//! # The state machine
//!
//! ```text
//!            ┌──────────── connect + hello + welcome ────────────┐
//!            │                                                   v
//!    Disconnected  <── error / EOF / refusal ──────────────────  Live
//!            ^                                                   │
//!            └── jittered exponential backoff, capped at ────────┘
//!                wake_sink::BACKSTOP_POLL_MAX (60 s)
//!
//!    welcome                 -> ONE catch-up read (`Welcome`),
//!                               or `Lagged` when the hub's offline set
//!                               stopped retaining ids
//!    wake frame              -> ONE catch-up read (`Wake`)
//!    wake with a seq gap     -> ONE catch-up read (`Gap`)
//!    backstop tick           -> ONE catch-up read (`Backstop`)
//! ```
//!
//! Exactly ONE catch-up inbox read per signal — never a burst, never a read
//! per queued hint. `seq_high_watermark` is read as "wakes happened that you
//! did not see", so a gap costs one extra read and can never be mistaken for
//! "nothing was missed".
//!
//! # The backstop is always armed
//!
//! The `<= 60 s` poll runs whether or not a hub is reachable, and its clock is
//! reset by every catch-up read (hub-driven or not) rather than by a fixed
//! wall-clock schedule. So:
//!
//! * a hub that is down, refusing, or was never configured costs LATENCY only,
//!   bounded by [`crate::wake_sink::BACKSTOP_POLL_MAX`];
//! * a healthy hub costs at most one idle read per minute per agent, not one
//!   per wake plus one per minute;
//! * reconnects are jittered and capped at the same bound, so a hub restart
//!   cannot produce a synchronised reconnect blast across a fleet.
//!
//! # Bounded hand-off
//!
//! Signals cross to the consumer through a BOUNDED channel using `try_send`.
//! A full channel means a catch-up read is already queued and has not run yet
//! — and that queued read will see every row a dropped signal referred to — so
//! the drop is coalescing, not loss. It is counted, because a listener that
//! silently stopped reading must not look like a quiet inbox.

pub mod bundle;
pub mod session;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use rand_core::RngCore as _;
use tokio::sync::{Notify, mpsc};

pub use bundle::{BUNDLE_MODE, HubJoinBundle, SignedHello};
pub use session::{Session, SessionConfig, SessionEvent, assert_socket_is_owner_only};

use crate::wake_hub::frame::WakeMeta;
use crate::wake_sink::BACKSTOP_POLL_MAX;
use crate::wake_sink::uds::backoff_for;

/// Depth of the bounded signal hand-off.
///
/// Small on purpose: every entry means "do one catch-up read", and reads
/// collapse. A deep queue would only buy a longer backlog of reads that all
/// return the same rows.
pub const SIGNAL_QUEUE_DEPTH: usize = 8;

/// How long a session must LAST before the reconnect ladder resets.
///
/// The same rule the #3469 forwarder uses, for the same reason: resetting on
/// every successful connect turns a hub that accepts and instantly drops into
/// a reconnect hot loop, and never resetting leaves a long-lived listener
/// pinned at the cap after one long outage.
pub const HEALTHY_SESSION: Duration = Duration::from_secs(30);

/// Why a catch-up inbox read is due.
///
/// The variants exist to be REPORTED — an operator reading a listener's log or
/// a hook's `AI_MEMORY_WAKE_REASON` must be able to tell "the hub told me" from
/// "the backstop fired", because the second one silently replacing the first
/// is exactly what a broken wake plane looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    /// A session was just admitted; read once in case mail arrived offline.
    Welcome,
    /// The hub's offline set stopped retaining ids for this agent, so its
    /// pending id list cannot be trusted and a full read is required.
    Lagged,
    /// A wake hint arrived.
    Wake,
    /// A wake hint arrived whose `seq_high_watermark` skipped: wakes happened
    /// that this listener did not see.
    Gap,
    /// The bounded poll fallback fired. With a healthy hub this is the idle
    /// heartbeat; with no hub it is the whole delivery mechanism.
    Backstop,
}

impl WakeReason {
    /// The stable slug reported in JSON output and in the hook environment.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::Lagged => "lagged",
            Self::Wake => "wake",
            Self::Gap => "gap",
            Self::Backstop => "backstop",
        }
    }

    /// `true` when this signal came from the hub rather than from the poll.
    #[must_use]
    pub const fn is_hub_driven(self) -> bool {
        !matches!(self, Self::Backstop)
    }
}

impl std::fmt::Display for WakeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One "read your inbox now" signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeSignal {
    /// Why the read is due.
    pub reason: WakeReason,
    /// The hint, when the hub supplied one. `None` for `Welcome`, `Lagged` and
    /// `Backstop`, which name no single row.
    pub meta: Option<WakeMeta>,
    /// Wakes the hub coalesced while this agent was offline, from the welcome.
    pub pending_count: u64,
    /// Wakes this listener demonstrably did not see, from a watermark gap.
    pub missed: u64,
}

impl WakeSignal {
    /// A signal that names no row.
    #[must_use]
    pub const fn bare(reason: WakeReason) -> Self {
        Self {
            reason,
            meta: None,
            pending_count: 0,
            missed: 0,
        }
    }
}

/// Tracks `seq_high_watermark` so a gap becomes exactly one extra read.
///
/// Deliberately fail-safe in one direction only: it may report a gap that was
/// not one (after a producer restart, say), costing one redundant read; it can
/// never report contiguity across a real gap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeqTracker {
    last: Option<u64>,
}

impl SeqTracker {
    /// Fold one observed watermark in and report how many wakes were missed.
    pub fn observe(&mut self, seq: u64) -> u64 {
        let missed = match self.last {
            // The first wake of a session establishes the baseline. The
            // session's own welcome already forced a catch-up read, so there
            // is nothing to recover here.
            None => 0,
            Some(prev) => seq.saturating_sub(prev).saturating_sub(1),
        };
        self.last = Some(self.last.map_or(seq, |prev| prev.max(seq)));
        missed
    }

    /// The highest watermark seen on this session.
    #[must_use]
    pub const fn last(&self) -> Option<u64> {
        self.last
    }
}

/// Counters an operator needs to tell a quiet inbox from a broken listener.
#[derive(Debug, Default)]
pub struct ClientMetrics {
    signals: AtomicU64,
    coalesced: AtomicU64,
    sessions: AtomicU64,
    reconnects: AtomicU64,
}

/// A point-in-time copy of [`ClientMetrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientMetricsSnapshot {
    /// Signals handed to the consumer.
    pub signals: u64,
    /// Signals dropped because a catch-up read was already queued.
    pub coalesced: u64,
    /// Sessions successfully admitted by the hub.
    pub sessions: u64,
    /// Reconnect attempts made after a failed or lost session.
    pub reconnects: u64,
}

impl ClientMetrics {
    /// Read every counter.
    #[must_use]
    pub fn snapshot(&self) -> ClientMetricsSnapshot {
        ClientMetricsSnapshot {
            signals: self.signals.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            sessions: self.sessions.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
        }
    }
}

/// Operator-tunable listener parameters. Every default is bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeClientConfig {
    /// Longest gap between catch-up reads, hub or no hub. Clamped by
    /// [`WakeClientConfig::validate`] to `1 s ..= BACKSTOP_POLL_MAX`.
    pub poll_interval: Duration,
    /// First reconnect delay; doubles per consecutive failure, capped at
    /// [`BACKSTOP_POLL_MAX`].
    pub reconnect_base: Duration,
    /// Random span added to every reconnect delay.
    pub reconnect_jitter: Duration,
}

impl Default for WakeClientConfig {
    fn default() -> Self {
        Self {
            poll_interval: BACKSTOP_POLL_MAX,
            reconnect_base: Duration::from_millis(u64::from(
                crate::wake_hub::limits::DEFAULT_RECONNECT_BASE_MS,
            )),
            reconnect_jitter: Duration::from_millis(u64::from(
                crate::wake_hub::limits::DEFAULT_RECONNECT_JITTER_MS,
            )),
        }
    }
}

impl WakeClientConfig {
    /// Refuse a configuration that would break the normative bound.
    ///
    /// # Errors
    ///
    /// When `poll_interval` is zero or longer than
    /// [`BACKSTOP_POLL_MAX`]. The ceiling is REFUSED rather than clamped: a
    /// listener that silently polled less often than the plane's contract
    /// promises would be reporting a guarantee it does not provide.
    pub fn validate(&self) -> Result<()> {
        if self.poll_interval.is_zero() {
            bail!("the backstop poll interval must be at least one second");
        }
        if self.poll_interval > BACKSTOP_POLL_MAX {
            bail!(
                "the backstop poll interval {:?} exceeds the normative maximum {BACKSTOP_POLL_MAX:?}. \
                 A wake-plane client MUST read its inbox at least that often; the ceiling is \
                 refused rather than clamped so nothing silently runs slower than the contract.",
                self.poll_interval
            );
        }
        Ok(())
    }
}

/// The consumer side: a stream of "read your inbox now" signals.
///
/// Dropping it stops both background tasks.
pub struct WakeStream {
    rx: mpsc::Receiver<WakeSignal>,
    read_done: Arc<Notify>,
    metrics: Arc<ClientMetrics>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for WakeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeStream")
            .field("metrics", &self.metrics.snapshot())
            .field("tasks", &self.tasks.len())
            .finish()
    }
}

impl Drop for WakeStream {
    fn drop(&mut self) {
        // Abort rather than detach: a listener that went away must not leave a
        // reconnect ladder running in a long-lived process.
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl WakeStream {
    /// Start the listener.
    ///
    /// `hub` is `None` for a host with no wake-hub configured: the backstop
    /// poll then IS the delivery mechanism, which is the documented degraded
    /// mode and not an error.
    ///
    /// # Errors
    ///
    /// An invalid configuration, or no Tokio runtime on this thread.
    pub fn start(
        cfg: WakeClientConfig,
        hub: Option<(SessionConfig, Arc<HubJoinBundle>)>,
    ) -> Result<Self> {
        cfg.validate()?;
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            anyhow::anyhow!("no Tokio runtime on this thread to host the wake listener")
        })?;
        let (tx, rx) = mpsc::channel::<WakeSignal>(SIGNAL_QUEUE_DEPTH);
        let read_done = Arc::new(Notify::new());
        let metrics = Arc::new(ClientMetrics::default());

        let mut tasks = Vec::with_capacity(2);
        {
            let tx = tx.clone();
            let read_done = Arc::clone(&read_done);
            let metrics = Arc::clone(&metrics);
            let interval = cfg.poll_interval;
            tasks.push(handle.spawn(async move {
                backstop_loop(interval, tx, read_done, metrics).await;
            }));
        }
        if let Some((session_cfg, bundle)) = hub {
            let metrics = Arc::clone(&metrics);
            tasks.push(handle.spawn(async move {
                hub_loop(cfg, session_cfg, bundle, tx, metrics).await;
            }));
        } else {
            tracing::info!(
                "wake listener: no wake-hub configured; the bounded backstop poll is the \
                 delivery mechanism (at most {BACKSTOP_POLL_MAX:?} of latency)"
            );
        }
        Ok(Self {
            rx,
            read_done,
            metrics,
            tasks,
        })
    }

    /// This listener's live counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<ClientMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Await the next signal. `None` only when every producer has stopped.
    pub async fn next(&mut self) -> Option<WakeSignal> {
        self.rx.recv().await
    }

    /// Tell the backstop a catch-up read just completed, so its clock restarts.
    ///
    /// Calling this is what makes the poll "at most `poll_interval` since the
    /// last read" rather than a fixed schedule that fires right after a wake.
    pub fn note_read(&self) {
        self.read_done.notify_one();
    }
}

/// The bounded poll fallback. Always armed, hub or no hub.
async fn backstop_loop(
    interval: Duration,
    tx: mpsc::Sender<WakeSignal>,
    read_done: Arc<Notify>,
    metrics: Arc<ClientMetrics>,
) {
    loop {
        tokio::select! {
            // A catch-up read just happened for some other reason; the
            // backstop's whole job is "at most `interval` since the last
            // read", so restart the clock rather than firing on schedule.
            () = read_done.notified() => {}
            () = tokio::time::sleep(interval) => {
                if !offer(&tx, WakeSignal::bare(WakeReason::Backstop), &metrics) {
                    return;
                }
            }
        }
    }
}

/// Connect, serve, back off, repeat — until the consumer goes away.
async fn hub_loop(
    cfg: WakeClientConfig,
    session_cfg: SessionConfig,
    bundle: Arc<HubJoinBundle>,
    tx: mpsc::Sender<WakeSignal>,
    metrics: Arc<ClientMetrics>,
) {
    let mut attempt: u32 = 0;
    loop {
        if tx.is_closed() {
            return;
        }
        let started = tokio::time::Instant::now();
        match run_session(&session_cfg, &bundle, &tx, &metrics).await {
            Ok(()) => {
                tracing::info!("wake listener: stopping because the consumer went away");
                return;
            }
            Err(e) => {
                if started.elapsed() >= HEALTHY_SESSION {
                    attempt = 0;
                }
                attempt = attempt.saturating_add(1);
                metrics.reconnects.fetch_add(1, Ordering::Relaxed);
                let wait = backoff_for(cfg.reconnect_base, attempt) + jitter(cfg.reconnect_jitter);
                tracing::warn!(
                    attempt,
                    wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "wake listener: hub session ended ({e:#}); retrying with jittered backoff \
                     — the backstop poll keeps delivering meanwhile"
                );
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// One session's lifetime. `Ok(())` means the CONSUMER went away.
async fn run_session(
    session_cfg: &SessionConfig,
    bundle: &HubJoinBundle,
    tx: &mpsc::Sender<WakeSignal>,
    metrics: &ClientMetrics,
) -> Result<()> {
    // An expired credential is a configuration problem, not a network one.
    // Say so before dialling, so the operator sees the remediation instead of
    // a ladder of 401s.
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    if !bundle.is_valid_at(&now) {
        bail!(
            "the a2a-hub delegation for {} expired at {}; mint a fresh one with \
             `ai-memory identity delegate --scope a2a-hub`",
            bundle.agent_id(),
            bundle.not_after()
        );
    }

    let mut session = session::connect(session_cfg, bundle).await?;
    metrics.sessions.fetch_add(1, Ordering::Relaxed);
    let welcome = *session.welcome();
    tracing::info!(
        agent = bundle.agent_id(),
        hub = bundle.hub_id(),
        pending = welcome.pending_count,
        lagged = welcome.lagged,
        "wake listener: admitted to the wake-hub"
    );
    let signal = WakeSignal {
        reason: if welcome.lagged {
            WakeReason::Lagged
        } else {
            WakeReason::Welcome
        },
        meta: None,
        pending_count: welcome.pending_count,
        missed: 0,
    };
    if !offer(tx, signal, metrics) {
        return Ok(());
    }

    let mut seq = SeqTracker::default();
    loop {
        match session.next_event().await? {
            SessionEvent::Wake(meta) => {
                let missed = seq.observe(meta.seq_high_watermark);
                let signal = WakeSignal {
                    reason: if missed > 0 {
                        WakeReason::Gap
                    } else {
                        WakeReason::Wake
                    },
                    meta: Some(*meta),
                    pending_count: 0,
                    missed,
                };
                if !offer(tx, signal, metrics) {
                    return Ok(());
                }
            }
            SessionEvent::Idle => {}
        }
    }
}

/// Hand one signal to the consumer without ever blocking the reader.
///
/// Returns `false` only when the consumer is GONE. A full channel is not a
/// loss: a catch-up read is already queued and will see every row the dropped
/// signal referred to, so the drop coalesces reads that would have returned
/// the same rows. It is counted all the same.
fn offer(tx: &mpsc::Sender<WakeSignal>, signal: WakeSignal, metrics: &ClientMetrics) -> bool {
    match tx.try_send(signal) {
        Ok(()) => {
            metrics.signals.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(mpsc::error::TrySendError::Full(dropped)) => {
            metrics.coalesced.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                reason = dropped.reason.label(),
                "wake listener: a catch-up read is already queued; coalescing this signal"
            );
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// A uniformly random delay in `0..=span`, so a fleet's reconnects spread.
fn jitter(span: Duration) -> Duration {
    let span_ms = u32::try_from(span.as_millis()).unwrap_or(u32::MAX);
    if span_ms == 0 {
        return Duration::ZERO;
    }
    let draw = rand_core::OsRng.next_u32() % (span_ms.saturating_add(1));
    Duration::from_millis(u64::from(draw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A watermark gap costs exactly one extra read, and contiguity is never
    /// claimed across a real gap.
    #[test]
    fn the_seq_tracker_reports_a_gap_but_never_false_contiguity_3470() {
        let mut t = SeqTracker::default();
        // The session's welcome already forced a read, so the first wake
        // establishes a baseline rather than claiming a gap of `seq`.
        assert_eq!(t.observe(100), 0);
        assert_eq!(t.observe(101), 0, "contiguous wakes need no extra read");
        assert_eq!(t.observe(105), 3, "three wakes were demonstrably missed");
        assert_eq!(t.last(), Some(105));
        // A reordered or duplicated watermark must never rewind the baseline
        // into claiming a later gap that is not one.
        assert_eq!(t.observe(103), 0);
        assert_eq!(t.last(), Some(105));
        assert_eq!(t.observe(106), 0);
    }

    /// The normative ceiling is REFUSED, not clamped: a client that silently
    /// polled slower than the plane's contract would be reporting a guarantee
    /// it does not provide.
    #[test]
    fn a_poll_interval_over_the_backstop_is_refused_3470() {
        let mut cfg = WakeClientConfig::default();
        cfg.validate().expect("the default is the ceiling itself");
        assert_eq!(cfg.poll_interval, BACKSTOP_POLL_MAX);

        cfg.poll_interval = BACKSTOP_POLL_MAX + Duration::from_secs(1);
        let err = cfg.validate().expect_err("over the normative bound");
        assert!(format!("{err:#}").contains("normative maximum"), "{err:#}");

        cfg.poll_interval = Duration::ZERO;
        assert!(cfg.validate().is_err(), "a zero interval is a hot loop");

        cfg.poll_interval = Duration::from_secs(1);
        cfg.validate().expect("a tighter poll is always allowed");
    }

    /// The reconnect ladder is bounded by the backstop: waiting longer than
    /// the interval a client polls at anyway buys nothing.
    #[test]
    fn the_reconnect_ladder_is_capped_at_the_backstop_3470() {
        let base = WakeClientConfig::default().reconnect_base;
        assert!(backoff_for(base, 1) < BACKSTOP_POLL_MAX);
        assert_eq!(backoff_for(base, 30), BACKSTOP_POLL_MAX);
        assert!(
            HEALTHY_SESSION < BACKSTOP_POLL_MAX,
            "a session must be able to count as healthy inside one backstop window"
        );
        for _ in 0..32 {
            assert!(jitter(Duration::from_millis(50)) <= Duration::from_millis(50));
        }
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    /// A full channel coalesces rather than loses: the queued read will see
    /// every row the dropped signal referred to, and the drop is counted.
    #[tokio::test]
    async fn a_full_hand_off_coalesces_and_is_counted_3470() {
        let metrics = ClientMetrics::default();
        let (tx, rx) = mpsc::channel::<WakeSignal>(1);
        assert!(offer(&tx, WakeSignal::bare(WakeReason::Wake), &metrics));
        assert!(offer(&tx, WakeSignal::bare(WakeReason::Wake), &metrics));
        let snap = metrics.snapshot();
        assert_eq!(snap.signals, 1);
        assert_eq!(snap.coalesced, 1, "the drop must be visible to an operator");
        drop(rx);
        assert!(
            !offer(&tx, WakeSignal::bare(WakeReason::Wake), &metrics),
            "a departed consumer stops the listener rather than spinning"
        );
    }

    /// Reasons are reported, and the hub-driven / poll-driven split is
    /// legible: a backstop silently replacing hub delivery is exactly what a
    /// broken wake plane looks like.
    #[test]
    fn every_reason_has_a_stable_label_3470() {
        for (reason, label, hub_driven) in [
            (WakeReason::Welcome, "welcome", true),
            (WakeReason::Lagged, "lagged", true),
            (WakeReason::Wake, "wake", true),
            (WakeReason::Gap, "gap", true),
            (WakeReason::Backstop, "backstop", false),
        ] {
            assert_eq!(reason.label(), label);
            assert_eq!(reason.to_string(), label);
            assert_eq!(reason.is_hub_driven(), hub_driven);
        }
    }

    /// With no hub configured the backstop IS the delivery mechanism, and it
    /// still fires — the documented degraded mode, not an error.
    #[tokio::test(start_paused = true)]
    async fn with_no_hub_the_backstop_still_delivers_3470() {
        let cfg = WakeClientConfig {
            poll_interval: Duration::from_secs(5),
            ..WakeClientConfig::default()
        };
        let mut stream = WakeStream::start(cfg, None).expect("start");
        let signal = stream.next().await.expect("the backstop must fire");
        assert_eq!(signal.reason, WakeReason::Backstop);
        assert!(signal.meta.is_none(), "a poll names no single row");

        // A catch-up read restarts the clock rather than leaving a fixed
        // schedule that fires again immediately.
        stream.note_read();
        let again = stream.next().await.expect("and keeps firing");
        assert_eq!(again.reason, WakeReason::Backstop);
        assert!(stream.metrics().snapshot().signals >= 2);
    }
}
