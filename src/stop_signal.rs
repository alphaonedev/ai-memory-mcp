// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8193 - the one shutdown primitive for every long-running verb.
//!
//! `serve`, `wake-hub`, `wake-listen`, `watch --daemon`, `curator --daemon`
//! and `sync-daemon` all stop on SIGINT and SIGTERM (unix) or Ctrl-C
//! (elsewhere) through [`StopListener`]. A signal registration that fails is
//! an error: it is logged at `error` level and the matching arm parks, so a
//! failed registration is never read as a received stop (ERRORS-19, #6385,
//! #6869). The `mcp` stdio server keeps its own fail-closed listeners in
//! [`crate::mcp::shutdown`] (it refuses to start rather than run unstoppable).

use std::io;

/// Name of the interrupt signal in log lines and the test seam.
pub const SIGNAL_NAME_INT: &str = "SIGINT";

/// Name of the terminate signal in log lines and the test seam.
pub const SIGNAL_NAME_TERM: &str = "SIGTERM";

/// Test seam (debug and test builds only): the listed signal name, or `any`,
/// fails its registration with an injected error. Shares the variable the
/// `mcp` listeners use, so one switch drives every verb.
#[cfg(any(test, debug_assertions))]
pub const TEST_FAIL_REGISTER_ENV: &str = crate::mcp::shutdown::TEST_FAIL_STOP_INSTALL_ENV;

/// Value of [`TEST_FAIL_REGISTER_ENV`] that fails every registration.
#[cfg(any(test, debug_assertions))]
const TEST_FAIL_ANY: &str = "any";

/// The outcome of waiting for an interrupt registration.
#[cfg(any(test, not(unix)))]
#[derive(Debug)]
pub enum InterruptWait {
    /// An interrupt was delivered.
    Received,
    /// The handler could not be registered: no interrupt will ever arrive.
    RegistrationFailed(io::Error),
}

/// Classify the result of `tokio::signal::ctrl_c()`: an `Err` is a failed
/// registration, never a received interrupt (ERRORS-19).
#[cfg(any(test, not(unix)))]
#[must_use]
pub fn classify_interrupt(result: io::Result<()>) -> InterruptWait {
    match result {
        Ok(()) => InterruptWait::Received,
        Err(error) => InterruptWait::RegistrationFailed(error),
    }
}

/// Log a failed registration and yield `None`; yield the handle otherwise.
fn armed<T>(name: &'static str, result: io::Result<T>) -> Option<T> {
    match result {
        Ok(handle) => Some(handle),
        Err(error) => {
            tracing::error!(
                signal = name,
                %error,
                "#8193: stop-signal registration failed; this signal will NOT stop the \
                 daemon (it keeps running) - stop it with another signal or fix the host"
            );
            None
        }
    }
}

/// The injected registration failure for `name`, if the seam is armed.
#[cfg(any(test, debug_assertions))]
fn injected_failure(name: &str) -> Option<io::Error> {
    let value = std::env::var(TEST_FAIL_REGISTER_ENV).ok()?;
    let value = value.trim();
    (value.eq_ignore_ascii_case(TEST_FAIL_ANY) || value.eq_ignore_ascii_case(name))
        .then(|| io::Error::other("injected stop-signal registration failure (test seam)"))
}

/// Registered stop-signal listeners. Install once, before the daemon starts
/// serving, so no stop signal can reach the default disposition afterwards.
#[derive(Debug)]
pub struct StopListener {
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
fn register(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> Option<tokio::signal::unix::Signal> {
    #[cfg(any(test, debug_assertions))]
    if let Some(error) = injected_failure(name) {
        return armed(name, Err(error));
    }
    armed(name, tokio::signal::unix::signal(kind))
}

/// Resolve when `slot` receives its signal. A missing slot (failed
/// registration) and a closed stream (`recv() == None`, the runtime going
/// away) both park: neither is a received stop.
#[cfg(unix)]
async fn wait_one(slot: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = slot.as_mut()
        && signal.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
}

impl StopListener {
    /// Register SIGINT and SIGTERM (unix) or arm the Ctrl-C wait (elsewhere).
    /// Must run inside the tokio runtime. A failed registration is logged and
    /// leaves that signal parked; see [`Self::fully_installed`].
    #[must_use]
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::SignalKind;
            Self {
                int: register(SignalKind::interrupt(), SIGNAL_NAME_INT),
                term: register(SignalKind::terminate(), SIGNAL_NAME_TERM),
            }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    /// Whether every stop signal this platform supports is registered.
    #[must_use]
    pub fn fully_installed(&self) -> bool {
        #[cfg(unix)]
        {
            self.int.is_some() && self.term.is_some()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// Resolve when a stop signal is received. Never resolves because of a
    /// failed registration.
    pub async fn wait(&mut self) {
        #[cfg(unix)]
        {
            let Self { int, term } = self;
            tokio::select! {
                () = wait_one(int) => {}
                () = wait_one(term) => {}
            }
        }
        #[cfg(not(unix))]
        {
            match classify_interrupt(tokio::signal::ctrl_c().await) {
                InterruptWait::Received => {}
                InterruptWait::RegistrationFailed(error) => {
                    let _ = armed::<()>(SIGNAL_NAME_INT, Err(error));
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// Install the listeners and wait for the first stop signal.
pub async fn stop_signal() {
    StopListener::install().wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bound a parked wait must outlast to count as "did not resolve".
    const PARK_PROBE: std::time::Duration = std::time::Duration::from_millis(300);

    /// Bound for a delivered signal to resolve the wait.
    const DELIVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn a_failed_ctrl_c_registration_is_not_a_received_interrupt_6385() {
        assert!(matches!(
            classify_interrupt(Ok(())),
            InterruptWait::Received
        ));
        assert!(matches!(
            classify_interrupt(Err(io::Error::other("no handler"))),
            InterruptWait::RegistrationFailed(_)
        ));
    }

    #[test]
    fn armed_returns_none_for_an_error_and_the_handle_for_ok_6385() {
        assert_eq!(armed(SIGNAL_NAME_INT, Ok(7_u8)), Some(7));
        assert_eq!(
            armed::<u8>(SIGNAL_NAME_INT, Err(io::Error::other("x"))),
            None
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_missing_listener_stays_pending_6869() {
        let mut slot: Option<tokio::signal::unix::Signal> = None;
        let outcome = tokio::time::timeout(PARK_PROBE, wait_one(&mut slot)).await;
        assert!(
            outcome.is_err(),
            "a failed registration must park, not stop"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_all_failed_listener_never_resolves_6869() {
        let mut listener = StopListener {
            int: None,
            term: None,
        };
        assert!(!listener.fully_installed());
        let outcome = tokio::time::timeout(PARK_PROBE, listener.wait()).await;
        assert!(outcome.is_err(), "no registered signal must mean no stop");
    }

    /// Raise `signal` on this process once the listener is installed.
    #[cfg(unix)]
    async fn stops_on(signal: libc::c_int) {
        let mut listener = StopListener::install();
        assert!(listener.fully_installed(), "both stop signals register");
        // SAFETY: raising a signal on our own process whose handler is installed.
        unsafe {
            libc::raise(signal);
        }
        tokio::time::timeout(DELIVER_DEADLINE, listener.wait())
            .await
            .expect("an installed stop signal must resolve the wait");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sigint_and_sigterm_resolve_the_same_wait_8193() {
        // A raised signal reaches every listener in the process, so run alone
        // in a child (the curator tests kick the same signals).
        if crate::config::run_env_isolated_child_or_spawn(
            "stop_signal::tests::sigint_and_sigterm_resolve_the_same_wait_8193",
        ) {
            return;
        }
        stops_on(libc::SIGINT).await;
        stops_on(libc::SIGTERM).await;
    }
}
