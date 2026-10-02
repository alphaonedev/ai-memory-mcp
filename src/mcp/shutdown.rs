// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4347 — graceful stop of `ai-memory mcp` on a signal.
//!
//! `mcp` keeps the background forensic writer (#1472) and drains it at exit
//! (#4319). A process that dies by a signal's default disposition never
//! reaches that drain, so SIGTERM, SIGINT and SIGHUP lost every row still
//! queued. This module routes those three signals (Ctrl-C only on a non-unix
//! build) into a graceful stop:
//!
//! 1. The signal is received on the tokio runtime, never in a raw handler
//!    (CONCURRENCY-22): the handler only wakes an async task.
//! 2. The stdio loop stops accepting requests: [`ShutdownGate`] refuses to
//!    begin a request once a stop was claimed.
//! 3. A request already in flight is allowed to finish, bounded by
//!    [`IN_FLIGHT_BUDGET`]. An acknowledged write is durable (SQLite commits
//!    before the response is written); a request cut off at the bound was
//!    never acknowledged.
//! 4. The forensic drain runs on a blocking thread, once, through
//!    `governance::audit::drain_at_exit_once`, which the `atexit` hook shares,
//!    so both paths firing is one drain.
//! 5. The process exits with the conventional `128 + signal number` through
//!    [`SignalExit`], which `main` maps to `process::exit` before the runtime
//!    is dropped (the stdin reader is an uncancellable blocking read).
//!
//! SIGHUP is a stop here, not a reload: the stdio child's default disposition
//! for it is already "terminate" (terminal hang-up, session leader exit), the
//! `[llm]` hot-reload on this surface is driven by config mtime (#2166), and
//! `serve`'s SIGHUP reload does not apply to a stdio child.

use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;

/// How long an in-flight request may take to finish after a stop signal
/// before the stop proceeds without it.
pub const IN_FLIGHT_BUDGET: Duration = Duration::from_secs(10);

const IDLE: u8 = 0;
const BUSY: u8 = 1;
/// A stop was claimed while a request was in flight: the request finishes,
/// then no further request begins.
const STOP_AFTER_REQUEST: u8 = 2;
/// A stop was claimed: no request begins.
const STOPPED: u8 = 3;

/// What a stop claim found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopClaim {
    /// The loop was between requests: nothing to wait for.
    Idle,
    /// A request is in flight and will finish before the loop stops.
    InFlight,
    /// A stop was already claimed.
    AlreadyStopping,
}

/// Coordinates the signal task with the stdio loop. Lock-free: the loop owns
/// the `BUSY` transitions and the signal task owns the stop transitions, so
/// every change is one compare-exchange (CONCURRENCY-08).
#[derive(Debug)]
pub struct ShutdownGate {
    state: AtomicU8,
}

/// Held for the duration of one request; releases the gate when dropped, on
/// every exit path of the loop body (including `continue`).
#[derive(Debug)]
pub struct RequestGuard<'a> {
    gate: &'a ShutdownGate,
}

impl ShutdownGate {
    /// A gate in the running state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(IDLE),
        }
    }

    /// Begin one request. `None` when a stop was claimed: the caller must not
    /// process the request it just read.
    pub fn begin_request(&self) -> Option<RequestGuard<'_>> {
        self.state
            .compare_exchange(IDLE, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| RequestGuard { gate: self })
    }

    /// Whether a stop was claimed (the loop returns instead of reading on).
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            STOP_AFTER_REQUEST | STOPPED
        )
    }

    /// Claim the stop. Idempotent: later claims report `AlreadyStopping`.
    pub fn request_stop(&self) -> StopClaim {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            let (next, claim) = match current {
                IDLE => (STOPPED, StopClaim::Idle),
                BUSY => (STOP_AFTER_REQUEST, StopClaim::InFlight),
                _ => return StopClaim::AlreadyStopping,
            };
            match self
                .state
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return claim,
                Err(actual) => current = actual,
            }
        }
    }

    fn end_request(&self) {
        // Only the loop leaves `BUSY`/`STOP_AFTER_REQUEST`, so a failed first
        // exchange means the signal task moved the state to the second.
        if self
            .state
            .compare_exchange(BUSY, IDLE, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            let _ = self.state.compare_exchange(
                STOP_AFTER_REQUEST,
                STOPPED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

impl Default for ShutdownGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        self.gate.end_request();
    }
}

static GATE: ShutdownGate = ShutdownGate::new();

/// The process-wide gate the stdio loop and the signal task share.
#[must_use]
pub fn gate() -> &'static ShutdownGate {
    &GATE
}

/// The signals that stop the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSignal {
    Term,
    Int,
    #[cfg(unix)]
    Hup,
}

impl StopSignal {
    /// The conventional shell exit code for death by this signal.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Term => 128 + 15,
            Self::Int => 128 + 2,
            #[cfg(unix)]
            Self::Hup => 128 + 1,
        }
    }

    /// The signal's conventional name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Int => "SIGINT",
            #[cfg(unix)]
            Self::Hup => "SIGHUP",
        }
    }
}

/// The error `serve_until_stopped` returns once a signal stopped the server
/// gracefully. `main` exits the process with [`SignalExit::code`].
#[derive(Debug)]
pub struct SignalExit {
    pub signal: StopSignal,
}

impl SignalExit {
    /// The process exit code.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.signal.exit_code()
    }
}

impl std::fmt::Display for SignalExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mcp stopped by {}", self.signal.name())
    }
}

impl std::error::Error for SignalExit {}

/// The installed stop-signal listeners. Install before the stdio loop starts
/// so no signal can reach the default disposition once the server is up.
#[derive(Debug)]
pub struct StopSignals {
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    hup: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
fn install_one(
    kind: tokio::signal::unix::SignalKind,
    name: &str,
) -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            // Degrade, loudly: the server still runs, but this signal keeps
            // its default disposition and the exit drain does not run on it.
            eprintln!(
                "ai-memory: could not install the {name} handler ({e}); the forensic exit \
                 drain will not run when that signal stops mcp (#4347)"
            );
            None
        }
    }
}

#[cfg(unix)]
async fn wait_one(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig.as_mut() {
        Some(s) => {
            // `None` means the runtime is shutting down, not that a signal
            // arrived: never read it as a stop.
            if s.recv().await.is_some() {
                return;
            }
            std::future::pending::<()>().await;
        }
        None => std::future::pending::<()>().await,
    }
}

impl StopSignals {
    /// Install the listeners. Must run inside the tokio runtime.
    #[cfg(unix)]
    #[must_use]
    pub fn install() -> Self {
        use tokio::signal::unix::SignalKind;
        Self {
            term: install_one(SignalKind::terminate(), "SIGTERM"),
            int: install_one(SignalKind::interrupt(), "SIGINT"),
            hup: install_one(SignalKind::hangup(), "SIGHUP"),
        }
    }

    /// Install the listeners (Ctrl-C only: there is no SIGTERM here).
    #[cfg(not(unix))]
    #[must_use]
    pub fn install() -> Self {
        Self {}
    }

    /// Resolve with the first stop signal.
    #[cfg(unix)]
    pub async fn recv(&mut self) -> StopSignal {
        tokio::select! {
            () = wait_one(&mut self.term) => StopSignal::Term,
            () = wait_one(&mut self.int) => StopSignal::Int,
            () = wait_one(&mut self.hup) => StopSignal::Hup,
        }
    }

    /// Resolve on Ctrl-C.
    #[cfg(not(unix))]
    pub async fn recv(&mut self) -> StopSignal {
        let _ = tokio::signal::ctrl_c().await;
        StopSignal::Int
    }
}

/// Supervise the blocking stdio loop with the process-wide gate and the
/// shared exit drain.
///
/// # Errors
/// The loop's own error, or [`SignalExit`] after a signal stopped it.
pub async fn supervise(
    handle: JoinHandle<anyhow::Result<()>>,
    mut signals: StopSignals,
) -> anyhow::Result<()> {
    serve_until_stopped(
        handle,
        gate(),
        async move { signals.recv().await },
        IN_FLIGHT_BUDGET,
        || {
            let outcome = crate::governance::audit::drain_at_exit_once();
            eprintln!("ai-memory: mcp forensic exit drain: {outcome:?} (#4347)");
        },
    )
    .await
}

/// Wait for the stdio loop to end on its own or for a stop signal. On a
/// signal: claim the stop, let an in-flight request finish (bounded by
/// `budget`), run `drain` on a blocking thread, then return [`SignalExit`].
///
/// # Errors
/// The loop's own error, or [`SignalExit`] after a signal stopped it.
pub async fn serve_until_stopped<S, D>(
    mut handle: JoinHandle<anyhow::Result<()>>,
    gate: &ShutdownGate,
    stop: S,
    budget: Duration,
    drain: D,
) -> anyhow::Result<()>
where
    S: Future<Output = StopSignal>,
    D: FnOnce() + Send + 'static,
{
    let signal = tokio::select! {
        joined = &mut handle => {
            return joined.map_err(|e| anyhow::anyhow!("mcp join: {e}"))?;
        }
        signal = stop => signal,
    };
    let claim = gate.request_stop();
    eprintln!(
        "ai-memory: {} received; stopping the mcp server ({claim:?}) (#4347)",
        signal.name()
    );
    if claim != StopClaim::Idle {
        match tokio::time::timeout(budget, &mut handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => eprintln!("ai-memory: mcp loop ended with an error: {e}"),
            Ok(Err(e)) => eprintln!("ai-memory: mcp loop did not join: {e}"),
            Err(_) => eprintln!(
                "ai-memory: the in-flight request did not finish within {budget:?}; \
                 stopping without it (it was never acknowledged)"
            ),
        }
    }
    if let Err(e) = tokio::task::spawn_blocking(drain).await {
        eprintln!("ai-memory: the mcp exit drain did not complete: {e}");
    }
    Err(anyhow::Error::new(SignalExit { signal }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_stop_while_idle_refuses_the_next_request_4347() {
        let gate = ShutdownGate::new();
        assert!(!gate.is_stopping());
        assert_eq!(gate.request_stop(), StopClaim::Idle);
        assert!(gate.is_stopping());
        assert!(
            gate.begin_request().is_none(),
            "no new request after a stop"
        );
        assert_eq!(gate.request_stop(), StopClaim::AlreadyStopping);
    }

    #[test]
    fn a_stop_during_a_request_lets_it_finish_then_refuses_the_next_4347() {
        let gate = ShutdownGate::new();
        let request = gate.begin_request().expect("a running gate accepts");
        assert_eq!(gate.request_stop(), StopClaim::InFlight);
        assert!(gate.is_stopping());
        drop(request);
        assert!(gate.begin_request().is_none(), "stopped after the request");
        assert_eq!(gate.request_stop(), StopClaim::AlreadyStopping);
    }

    #[test]
    fn a_request_that_ends_normally_returns_the_gate_to_idle_4347() {
        let gate = ShutdownGate::new();
        drop(gate.begin_request().expect("accepts"));
        assert!(!gate.is_stopping());
        assert!(gate.begin_request().is_some());
    }

    #[test]
    fn exit_codes_are_the_conventional_128_plus_signal_4347() {
        assert_eq!(StopSignal::Term.exit_code(), 143);
        assert_eq!(StopSignal::Int.exit_code(), 130);
        #[cfg(unix)]
        assert_eq!(StopSignal::Hup.exit_code(), 129);
    }

    /// A stop with a request in flight waits for that request, then drains
    /// once, then reports the signal exit.
    #[tokio::test]
    async fn an_in_flight_request_finishes_before_the_drain_4347() {
        static GATE_UNDER_TEST: ShutdownGate = ShutdownGate::new();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (busy_tx, busy_rx) = std::sync::mpsc::channel::<()>();
        let finished = Arc::new(AtomicUsize::new(0));
        let finished_in_loop = Arc::clone(&finished);
        let handle = tokio::task::spawn_blocking(move || {
            let req = GATE_UNDER_TEST.begin_request().expect("accepts");
            busy_tx.send(()).expect("announce busy");
            release_rx.recv().expect("released");
            finished_in_loop.store(1, Ordering::SeqCst);
            drop(req);
            Ok(())
        });
        busy_rx.recv().expect("loop is busy");
        let drains = Arc::new(AtomicUsize::new(0));
        let drains_seen = Arc::clone(&drains);
        let finished_at_drain = Arc::new(AtomicUsize::new(0));
        let finished_probe = Arc::clone(&finished_at_drain);
        let finished_src = Arc::clone(&finished);
        let release = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(100));
            release_tx.send(()).expect("release the request");
        });
        let result = serve_until_stopped(
            handle,
            &GATE_UNDER_TEST,
            async { StopSignal::Term },
            Duration::from_secs(10),
            move || {
                finished_probe.store(finished_src.load(Ordering::SeqCst), Ordering::SeqCst);
                drains_seen.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        release.await.expect("release task");
        let err = result.expect_err("a signal stop is an error carrying the exit code");
        assert_eq!(
            err.downcast_ref::<SignalExit>().map(SignalExit::code),
            Some(143)
        );
        assert_eq!(
            finished_at_drain.load(Ordering::SeqCst),
            1,
            "drain ran after the request"
        );
        assert_eq!(drains.load(Ordering::SeqCst), 1, "exactly one drain");
    }

    /// A request that never finishes is abandoned at the budget: the stop
    /// still drains and exits instead of hanging.
    #[tokio::test]
    async fn a_stuck_request_is_abandoned_at_the_budget_4347() {
        static GATE_STUCK: ShutdownGate = ShutdownGate::new();
        let (busy_tx, busy_rx) = std::sync::mpsc::channel::<()>();
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let handle = tokio::task::spawn_blocking(move || {
            let _req = GATE_STUCK.begin_request().expect("accepts");
            busy_tx.send(()).expect("announce busy");
            let _ = hold_rx.recv();
            Ok(())
        });
        busy_rx.recv().expect("busy");
        let drains = Arc::new(AtomicUsize::new(0));
        let drains_seen = Arc::clone(&drains);
        let started = std::time::Instant::now();
        let result = serve_until_stopped(
            handle,
            &GATE_STUCK,
            async { StopSignal::Int },
            Duration::from_millis(100),
            move || {
                drains_seen.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded by the budget"
        );
        assert_eq!(
            result
                .expect_err("signal exit")
                .downcast_ref::<SignalExit>()
                .map(SignalExit::code),
            Some(130)
        );
        assert_eq!(drains.load(Ordering::SeqCst), 1);
        drop(hold_tx);
    }

    /// The loop ending on its own (stdin EOF) wins: no stop, no signal drain.
    #[tokio::test]
    async fn the_loop_ending_on_its_own_is_not_a_signal_stop_4347() {
        let gate = ShutdownGate::new();
        let handle = tokio::task::spawn_blocking(|| Ok(()));
        let drains = Arc::new(AtomicUsize::new(0));
        let drains_seen = Arc::clone(&drains);
        let result = serve_until_stopped(
            handle,
            &gate,
            std::future::pending::<StopSignal>(),
            Duration::from_secs(1),
            move || {
                drains_seen.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(drains.load(Ordering::SeqCst), 0);
        assert!(!gate.is_stopping());
    }
}
