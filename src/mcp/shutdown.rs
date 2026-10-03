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
//! 1. The listeners are installed before the server serves anything; if any
//!    cannot be installed, `mcp` REFUSES TO START ([`StopInstallError`]): a
//!    server that cannot be stopped gracefully must not acknowledge writes it
//!    could lose rows for (fail closed).
//! 2. The signal is received on the tokio runtime, never in a raw handler
//!    (CONCURRENCY-22): the handler only wakes an async task.
//! 3. The stdio loop stops accepting requests: [`ShutdownGate`] refuses to
//!    begin a request once a stop was claimed.
//! 4. A request already in flight is allowed to finish, bounded by
//!    [`IN_FLIGHT_BUDGET`]. When the budget expires the request is FENCED: it
//!    is never acknowledged ([`ShutdownGate::commit_ack`] refuses), so no
//!    acknowledged request can have its forensic row queued after the drain.
//!    A request that committed its ack before the fence has its row queued
//!    already (rows are queued by `handle_request`, before the ack), so the
//!    drain below covers it.
//! 5. The forensic drain runs on a blocking thread, once, through
//!    `governance::audit::drain_at_exit_once`, which the `atexit` hook shares.
//! 6. The process exits with the conventional `128 + signal number` through
//!    [`SignalExit`], which `main` maps to `process::exit` before the runtime
//!    is dropped (the stdio reader is an uncancellable blocking read).
//!
//! A second signal during the drain does NOT abort it: the listener swallows
//! it, so queued rows are not cut off. Shutdown stays bounded (in-flight
//! budget plus the 5 s drain), and SIGKILL remains the operator's hard stop.
//!
//! A SIGHUP or SIGINT the parent left IGNORED (`nohup`, a background job) stays
//! ignored (#4473): that is the operator's explicit intent. SIGTERM always
//! installs.
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
/// before it is fenced (never acknowledged) and the stop proceeds.
pub const IN_FLIGHT_BUDGET: Duration = Duration::from_secs(10);

/// The in-flight budget in force. Debug and test builds read
/// [`TEST_IN_FLIGHT_BUDGET_ENV`] so a cell can reach the expiry path quickly.
#[must_use]
pub fn in_flight_budget() -> Duration {
    #[cfg(any(test, debug_assertions))]
    if let Some(ms) = std::env::var(TEST_IN_FLIGHT_BUDGET_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
    {
        return Duration::from_millis(ms);
    }
    IN_FLIGHT_BUDGET
}

/// #4347 — test seam: the in-flight budget in milliseconds (debug builds).
pub const TEST_IN_FLIGHT_BUDGET_ENV: &str = "AI_MEMORY_TEST_IN_FLIGHT_BUDGET_MS";

/// #4347 — test seam: `<request id>:<directory>`. The loop holds the finished
/// request with that id before its acknowledgement: it creates
/// `<directory>/entered`, then waits (bounded) for `<directory>/release`.
/// Debug and test builds only.
pub const TEST_HOLD_IN_FLIGHT_ENV: &str = "AI_MEMORY_TEST_HOLD_IN_FLIGHT";

/// #4347 — test seam: name a signal (`SIGTERM`, `SIGINT`, `SIGHUP`) whose
/// handler installation must fail, or `any`. Debug and test builds only.
pub const TEST_FAIL_STOP_INSTALL_ENV: &str = "AI_MEMORY_TEST_FAIL_STOP_SIGNAL_INSTALL";

/// Longest the test hold waits for its release file.
#[cfg(any(test, debug_assertions))]
const TEST_HOLD_BOUND: Duration = Duration::from_secs(30);

const IDLE: u8 = 0;
/// A request is in flight; its ack is not yet committed.
const BUSY: u8 = 1;
/// A stop was claimed while a request was in flight: the request finishes,
/// then no further request begins.
const STOP_AFTER_REQUEST: u8 = 2;
/// A stop was claimed: no request begins.
const STOPPED: u8 = 3;
/// The in-flight request committed to acknowledging itself.
const ACKING: u8 = 4;
/// A stop was claimed after the in-flight request committed its ack.
const STOP_ACKING: u8 = 5;
/// A stop was claimed and the in-flight request ran past its budget: it must
/// not be acknowledged.
const FENCED: u8 = 6;

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

/// What fencing the in-flight request found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceOutcome {
    /// The request will never be acknowledged.
    Fenced,
    /// The request had already committed its ack (its row is queued, so the
    /// drain covers it).
    AckCommitted,
    /// No request was in flight to fence.
    NoRequest,
}

/// Coordinates the signal task with the stdio loop. Lock-free: every change
/// is one compare-exchange (CONCURRENCY-08), and the loop and the signal task
/// each own a disjoint set of transitions.
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

    fn transition(&self, from: u8, to: u8) -> bool {
        self.state
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Begin one request. `None` when a stop was claimed: the caller must not
    /// process the request it just read.
    pub fn begin_request(&self) -> Option<RequestGuard<'_>> {
        self.transition(IDLE, BUSY)
            .then_some(RequestGuard { gate: self })
    }

    /// Commit to acknowledging the in-flight request. Call after the request
    /// ran (its forensic row is queued) and before writing its response.
    /// `false` when the stop fenced the request: do not acknowledge it.
    #[must_use]
    pub fn commit_ack(&self) -> bool {
        self.transition(BUSY, ACKING) || self.transition(STOP_AFTER_REQUEST, STOP_ACKING)
    }

    /// Whether a stop was claimed (the loop returns instead of reading on).
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            STOP_AFTER_REQUEST | STOPPED | STOP_ACKING | FENCED
        )
    }

    /// Claim the stop. Idempotent: later claims report `AlreadyStopping`.
    pub fn request_stop(&self) -> StopClaim {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            let (next, claim) = match current {
                IDLE => (STOPPED, StopClaim::Idle),
                BUSY => (STOP_AFTER_REQUEST, StopClaim::InFlight),
                ACKING => (STOP_ACKING, StopClaim::InFlight),
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

    /// Fence the in-flight request after its budget expired: it will never
    /// be acknowledged. Call only after [`Self::request_stop`].
    pub fn fence(&self) -> FenceOutcome {
        loop {
            let current = self.state.load(Ordering::Acquire);
            match current {
                STOP_AFTER_REQUEST => {
                    if self.transition(STOP_AFTER_REQUEST, FENCED) {
                        return FenceOutcome::Fenced;
                    }
                }
                STOP_ACKING | STOPPED | FENCED => {
                    return if current == FENCED {
                        FenceOutcome::Fenced
                    } else if current == STOP_ACKING {
                        FenceOutcome::AckCommitted
                    } else {
                        FenceOutcome::NoRequest
                    };
                }
                _ => return FenceOutcome::NoRequest,
            }
        }
    }

    fn end_request(&self) {
        // Only the loop leaves its own states, so a failed exchange means the
        // signal task moved the state; try each stop-side successor.
        let _ = self.transition(BUSY, IDLE)
            || self.transition(ACKING, IDLE)
            || self.transition(STOP_AFTER_REQUEST, STOPPED)
            || self.transition(STOP_ACKING, STOPPED)
            || self.transition(FENCED, STOPPED);
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
    signal: StopSignal,
}

impl SignalExit {
    /// The process exit code.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.signal.exit_code()
    }

    /// The signal that stopped the server.
    #[must_use]
    pub const fn signal(&self) -> StopSignal {
        self.signal
    }
}

impl std::fmt::Display for SignalExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mcp stopped by {}", self.signal.name())
    }
}

impl std::error::Error for SignalExit {}

/// A stop listener could not be installed: `mcp` refuses to start.
#[derive(Debug)]
pub struct StopInstallError {
    signal: &'static str,
    source: std::io::Error,
}

impl std::fmt::Display for StopInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ai-memory mcp: cannot install the {} handler, refusing to start: a stop by that \
             signal would lose queued forensic audit rows (#4347)",
            self.signal
        )
    }
}

impl std::error::Error for StopInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The seam's injected failure for `name`, if armed (debug and test builds).
#[cfg(any(test, debug_assertions))]
fn injected_install_failure(name: &str) -> Option<std::io::Error> {
    let armed = std::env::var(TEST_FAIL_STOP_INSTALL_ENV).ok()?;
    let armed = armed.trim();
    (armed.eq_ignore_ascii_case("any") || armed.eq_ignore_ascii_case(name))
        .then(|| std::io::Error::other("injected stop-signal install failure (test seam)"))
}

/// The installed stop-signal listeners. Install before the stdio loop starts
/// so no signal can reach the default disposition once the server is up.
#[cfg_attr(unix, derive(Debug))]
pub struct StopSignals {
    /// Always `Some` once installed; an `Option` so the three share a waiter.
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    /// `None` when SIGINT was inherited as ignored (#4473): honoured.
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
    /// `None` when SIGHUP was inherited as ignored (#4473): honoured.
    #[cfg(unix)]
    hup: Option<tokio::signal::unix::Signal>,
    #[cfg(not(unix))]
    ctrl_c: Option<std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>>,
    /// The listener already completed with `Ok`: the future is dropped and
    /// never polled again (a finished async future panics when re-polled).
    #[cfg(not(unix))]
    fired: bool,
}

#[cfg(unix)]
fn install_one(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> Result<tokio::signal::unix::Signal, StopInstallError> {
    #[cfg(any(test, debug_assertions))]
    if let Some(source) = injected_install_failure(name) {
        return Err(StopInstallError {
            signal: name,
            source,
        });
    }
    tokio::signal::unix::signal(kind).map_err(|source| StopInstallError {
        signal: name,
        source,
    })
}

/// Whether the parent left `signum` ignored (`nohup`, a background job).
/// An ignored disposition is the operator's explicit intent; installing a
/// tokio listener would replace it (#4473).
#[cfg(unix)]
fn inherited_ignored(signum: libc::c_int, name: &'static str) -> Result<bool, StopInstallError> {
    // SAFETY: a zeroed `sigaction` is a valid value, and `sigaction` with a
    // null `act` only reads the current disposition into `old`.
    let (rc, old) = unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        let rc = libc::sigaction(signum, std::ptr::null(), &raw mut old);
        (rc, old)
    };
    if rc != 0 {
        return Err(StopInstallError {
            signal: name,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(old.sa_sigaction == libc::SIG_IGN)
}

/// Install the listener unless the parent ignored the signal.
#[cfg(unix)]
fn install_unless_ignored(
    signum: libc::c_int,
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> Result<Option<tokio::signal::unix::Signal>, StopInstallError> {
    if inherited_ignored(signum, name)? {
        return Ok(None);
    }
    install_one(kind, name).map(Some)
}

#[cfg(unix)]
async fn wait_one(sig: &mut Option<tokio::signal::unix::Signal>) {
    // An ignored signal (`None`) never stops the server. `recv() == None`
    // means the runtime is shutting down, not that a signal arrived: never
    // read it as a stop.
    if let Some(sig) = sig.as_mut()
        && sig.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
}

impl StopSignals {
    /// Install the listeners. Must run inside the tokio runtime.
    ///
    /// # Errors
    /// [`StopInstallError`] when any listener cannot be installed: the caller
    /// must not start serving.
    #[cfg(unix)]
    #[allow(clippy::unused_async)] // one signature for unix and non-unix
    pub async fn install() -> Result<Self, StopInstallError> {
        use tokio::signal::unix::SignalKind;
        Ok(Self {
            // SIGTERM always installs: nothing ignores the stop signal of
            // systemd, Docker and `kill` on purpose.
            term: Some(install_one(SignalKind::terminate(), "SIGTERM")?),
            int: install_unless_ignored(libc::SIGINT, SignalKind::interrupt(), "SIGINT")?,
            hup: install_unless_ignored(libc::SIGHUP, SignalKind::hangup(), "SIGHUP")?,
        })
    }

    /// Install the Ctrl-C listener (no SIGTERM here). The registration
    /// happens on first poll, so poll once now: a registration error refuses
    /// to start instead of being read later as a stop.
    ///
    /// # Errors
    /// [`StopInstallError`] when the listener cannot be registered.
    #[cfg(not(unix))]
    pub async fn install() -> Result<Self, StopInstallError> {
        #[cfg(any(test, debug_assertions))]
        if let Some(source) = injected_install_failure("SIGINT") {
            return Err(StopInstallError {
                signal: "SIGINT",
                source,
            });
        }
        let mut ctrl_c: std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> =
            Box::pin(tokio::signal::ctrl_c());
        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(ctrl_c.as_mut().poll(cx))).await;
        match first {
            std::task::Poll::Ready(Err(source)) => Err(StopInstallError {
                signal: "SIGINT",
                source,
            }),
            // A Ctrl-C inside the registering poll is an immediate stop; the
            // finished future is dropped, never polled again.
            std::task::Poll::Ready(Ok(())) => Ok(Self {
                ctrl_c: None,
                fired: true,
            }),
            std::task::Poll::Pending => Ok(Self {
                ctrl_c: Some(ctrl_c),
                fired: false,
            }),
        }
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

    /// Resolve on Ctrl-C. A listener error is logged and never read as a
    /// signal (ERRORS-19).
    #[cfg(not(unix))]
    pub async fn recv(&mut self) -> StopSignal {
        if self.fired {
            return StopSignal::Int;
        }
        let Some(listener) = self.ctrl_c.as_mut() else {
            return std::future::pending::<StopSignal>().await;
        };
        let outcome = listener.await;
        // Ready: the future is finished, so drop it before anything can poll
        // it again (CONCURRENCY-23, ERRORS-19).
        self.ctrl_c = None;
        match outcome {
            Ok(()) => {
                self.fired = true;
                StopSignal::Int
            }
            Err(e) => {
                eprintln!("ai-memory: the Ctrl-C listener failed: {e}; it will not stop mcp");
                std::future::pending::<StopSignal>().await
            }
        }
    }
}

/// #4347 — test seam: hold the finished request before its ack (see
/// [`TEST_HOLD_IN_FLIGHT_ENV`]). A no-op in release builds.
#[cfg(any(test, debug_assertions))]
pub fn hold_before_ack_for_test(request_id: Option<&serde_json::Value>) {
    use std::sync::OnceLock;
    static SPEC: OnceLock<Option<(u64, std::path::PathBuf)>> = OnceLock::new();
    let spec = SPEC.get_or_init(|| {
        let raw = std::env::var(TEST_HOLD_IN_FLIGHT_ENV).ok()?;
        let (id, dir) = raw.split_once(':')?;
        Some((id.trim().parse().ok()?, std::path::PathBuf::from(dir)))
    });
    let Some((id, dir)) = spec else { return };
    if request_id.and_then(serde_json::Value::as_u64) != Some(*id) {
        return;
    }
    let _ = std::fs::write(dir.join("entered"), b"");
    let release = dir.join("release");
    let started = std::time::Instant::now();
    while !release.exists() && started.elapsed() < TEST_HOLD_BOUND {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Release builds hold nothing.
#[cfg(not(any(test, debug_assertions)))]
#[inline]
pub fn hold_before_ack_for_test(_request_id: Option<&serde_json::Value>) {}

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
        in_flight_budget(),
        || {
            let outcome = crate::governance::audit::drain_at_exit_once();
            eprintln!("ai-memory: mcp forensic exit drain: {outcome:?} (#4347)");
        },
    )
    .await
}

/// Wait for the stdio loop to end on its own or for a stop signal. On a
/// signal: claim the stop, let an in-flight request finish (bounded by
/// `budget`, then fence it), run `drain` on a blocking thread, then return
/// [`SignalExit`].
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
            Err(_) => {
                let outcome = gate.fence();
                eprintln!(
                    "ai-memory: the in-flight request did not finish within {budget:?} \
                     ({outcome:?}); it is not acknowledged"
                );
            }
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
        assert!(
            gate.commit_ack(),
            "within budget the request may be acknowledged"
        );
        drop(request);
        assert!(gate.begin_request().is_none(), "stopped after the request");
        assert_eq!(gate.request_stop(), StopClaim::AlreadyStopping);
    }

    #[test]
    fn a_request_that_ends_normally_returns_the_gate_to_idle_4347() {
        let gate = ShutdownGate::new();
        let request = gate.begin_request().expect("accepts");
        assert!(gate.commit_ack());
        drop(request);
        assert!(!gate.is_stopping());
        assert!(gate.begin_request().is_some());
    }

    /// F2 — a request fenced after its budget is never acknowledged.
    #[test]
    fn a_fenced_request_is_never_acknowledged_4347() {
        let gate = ShutdownGate::new();
        let request = gate.begin_request().expect("accepts");
        assert_eq!(gate.request_stop(), StopClaim::InFlight);
        assert_eq!(gate.fence(), FenceOutcome::Fenced);
        assert!(
            !gate.commit_ack(),
            "a fenced request must not be acknowledged"
        );
        drop(request);
        assert!(gate.begin_request().is_none());
    }

    /// F2 — a request that committed its ack before the fence keeps it: its
    /// row was queued before the commit, so the drain covers it.
    #[test]
    fn an_ack_committed_before_the_fence_stands_4347() {
        let gate = ShutdownGate::new();
        let request = gate.begin_request().expect("accepts");
        assert!(gate.commit_ack());
        assert_eq!(gate.request_stop(), StopClaim::InFlight);
        assert_eq!(gate.fence(), FenceOutcome::AckCommitted);
        drop(request);
        assert!(gate.is_stopping());
    }

    #[test]
    fn fencing_with_nothing_in_flight_is_a_no_op_4347() {
        let gate = ShutdownGate::new();
        assert_eq!(gate.fence(), FenceOutcome::NoRequest);
        assert_eq!(gate.request_stop(), StopClaim::Idle);
        assert_eq!(gate.fence(), FenceOutcome::NoRequest);
    }

    #[test]
    fn exit_codes_are_the_conventional_128_plus_signal_4347() {
        assert_eq!(StopSignal::Term.exit_code(), 143);
        assert_eq!(StopSignal::Int.exit_code(), 130);
        #[cfg(unix)]
        assert_eq!(StopSignal::Hup.exit_code(), 129);
    }

    /// B1 — an install failure is an error, not a degraded start.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_install_failure_is_an_error_not_a_degraded_start_4347() {
        let err = install_one(tokio::signal::unix::SignalKind::terminate(), "SIGTERM");
        assert!(err.is_ok(), "a real install works in a runtime");
        let failure = StopInstallError {
            signal: "SIGHUP",
            source: std::io::Error::other("boom"),
        };
        let shown = failure.to_string();
        assert!(shown.contains("refusing to start"), "{shown}");
        assert!(shown.contains("SIGHUP"), "{shown}");
        assert!(std::error::Error::source(&failure).is_some());
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
            assert!(GATE_UNDER_TEST.commit_ack(), "finished within budget");
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

    /// A request that never finishes is fenced at the budget: the stop still
    /// drains and exits instead of hanging, and the late request cannot ack.
    #[tokio::test]
    async fn a_stuck_request_is_fenced_at_the_budget_4347() {
        static GATE_STUCK: ShutdownGate = ShutdownGate::new();
        let (busy_tx, busy_rx) = std::sync::mpsc::channel::<()>();
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<bool>();
        let handle = tokio::task::spawn_blocking(move || {
            let _req = GATE_STUCK.begin_request().expect("accepts");
            busy_tx.send(()).expect("announce busy");
            let _ = hold_rx.recv();
            // The request finished after the budget: it must not ack.
            ack_tx
                .send(GATE_STUCK.commit_ack())
                .expect("report the ack");
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
        // Let the held request finish AFTER the drain: it observes the fence.
        drop(hold_tx);
        assert_eq!(
            ack_rx.recv_timeout(Duration::from_secs(5)),
            Ok(false),
            "the late request must be refused its ack"
        );
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
