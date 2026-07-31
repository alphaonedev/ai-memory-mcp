// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared MCP-stdio subprocess response wait for the integration
//! suites that drive a real `ai-memory mcp` child (issue #2525).
//!
//! ## Usage
//!
//! This is a LEAF helper module, deliberately dependency-free beyond
//! `std`, pulled in by the `#[path]` submodule idiom already used by
//! `tests/atomisation.rs` / `tests/cli.rs`:
//!
//! ```ignore
//! #[path = "common/mcp_wait.rs"]
//! mod mcp_wait;
//! ```
//!
//! It is deliberately NOT re-exported from `tests/common/mod.rs`: that
//! module pulls `reqwest` + `ed25519_dalek` + `rusqlite` into every
//! binary that declares `mod common;`, and per-binary link weight in
//! this repo has already caused a real CI failure once (the #1381
//! `postgres_env` doctest-link `Bus error`). The MCP suites need none
//! of those, so they take the leaf module instead of the whole bag.
//!
//! ## Why this exists (issue #2525, precedent #1713 / #1194)
//!
//! Six integration binaries each hand-rolled the same shape: spawn
//! `ai-memory mcp`, feed the child's stdout into an `mpsc` channel on a
//! reader thread, then pop each JSON-RPC response with a single
//! blocking `recv_timeout(READ_TIMEOUT)` against a FIXED per-file
//! constant (10 s / 15 s / 20 s). On a loaded `ubuntu-latest` runner
//! the `initialize` handshake — cold `fork+exec` of a freshly-linked
//! test binary plus schema bootstrap — can legitimately exceed that
//! window, which is exactly what #2525 observed on PR #2522: a
//! workflow-trigger-only diff, the sibling test in the same binary
//! passing, and a full re-run green. Timing, not logic.
//!
//! ### Why this is not just a bigger constant
//!
//! 1. **The budget is no longer a constant.** It is
//!    `MCP_RESPONSE_BASE_TIMEOUT × AI_MEMORY_TEST_TIMING_BUDGET_MULT`
//!    (env row #68 in `CLAUDE.md` — the repo's existing knob for slow
//!    CI hosts). A host that needs more headroom sets one env var in
//!    its job definition; it does not need a code change and a fresh
//!    round of constant-negotiation.
//!
//! 2. **Raising the base is now free, which is why the base could be
//!    raised at all.** The old 10 s had to stay small because a large
//!    window also made *genuine* breakage slow to surface — the
//!    "fail fast" half of the #1713 fix. [`recv_mcp_response`] severs
//!    that coupling by discriminating the two `RecvTimeoutError`
//!    variants: when the child dies, exits early, or closes stdout,
//!    the reader thread's `Sender` drops and the channel reports
//!    `Disconnected` in MILLISECONDS regardless of the budget. So the
//!    budget's only remaining job is bounding a genuinely-wedged
//!    BUT-ALIVE child (#1713's orphaned-subprocess shape) — where a
//!    generous bound costs a green run nothing.
//!
//! 3. **The base is derived, not guessed.** It matches this repo's own
//!    generous-bounded-wait precedents for subprocess work that should
//!    take well under a second: `GOVERNANCE_CLI_DEADLINE_SECS = 60`
//!    (`tests/integration.rs`, #1522) and `FANOUT_OBSERVED_TIMEOUT =
//!    1 min` (`tests/common/mod.rs`, #1853). Against the ~2-3 s
//!    observed cold-spawn `initialize` latency that is ~20-30×
//!    headroom, versus the ~3× the per-file constants carried.
//!
//! ### Why not poll-until-deadline (#2525 option (b)) on its own
//!
//! `std::sync::mpsc::Receiver::recv_timeout` already wakes the instant
//! a line arrives AND the instant the sender is dropped, and a single
//! JSON-RPC response exposes no observable intermediate progress to
//! poll for. A slice-polling loop over the same channel would be
//! behaviourally identical with extra wakeups. The SUBSTANCE of option
//! (b) — a generous overall budget that still fails fast on real
//! breakage — is delivered by points 2 and 3 above, which is why this
//! module implements option (c) as "(a) + fail-fast liveness" rather
//! than "(a) + a redundant loop".

#![allow(dead_code)]

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Test-only timing-budget multiplier env var (`CLAUDE.md` env row #68).
///
/// Mirrors the production SSOT `src/hooks/timeouts.rs::
/// test_timing_budget_mult`, which is private to that module and so
/// cannot be called from an integration binary. The parse + clamp
/// below is kept byte-identical in behaviour to it on purpose.
pub const ENV_TEST_TIMING_BUDGET_MULT: &str = "AI_MEMORY_TEST_TIMING_BUDGET_MULT";

/// Accepted multiplier range, mirroring `src/hooks/timeouts.rs`.
const BUDGET_MULT_MIN: u64 = 1;
const BUDGET_MULT_MAX: u64 = 100;

/// Unscaled per-response budget for an `ai-memory mcp` stdio child.
///
/// See the module docs for the derivation. This is the ONE value the
/// six MCP suites share; before #2525 they carried three different
/// hand-picked constants (10 s / 15 s / 20 s) with no stated basis for
/// the spread.
/// Spelled `from_mins(1)` rather than `from_secs(60)` to satisfy
/// `clippy::duration_suboptimal_units`, and matching
/// `tests/common/mod.rs::FANOUT_OBSERVED_TIMEOUT`'s spelling of the
/// same one-minute generous bound.
pub const MCP_RESPONSE_BASE_TIMEOUT: Duration = Duration::from_mins(1);

/// Pure multiplier resolution, factored out so the clamp is unit
/// testable WITHOUT mutating process-global env (`std::env::set_var`
/// is unsound under concurrent test threads — see the `#1998 → #2115 →
/// #2127 → #2146` lineage and `scripts/check-test-env-lock.sh`).
fn budget_mult_from(raw: Option<&str>) -> u64 {
    raw.and_then(|s| s.parse::<u64>().ok())
        .filter(|n| (BUDGET_MULT_MIN..=BUDGET_MULT_MAX).contains(n))
        .unwrap_or(BUDGET_MULT_MIN)
}

/// Resolved [`ENV_TEST_TIMING_BUDGET_MULT`] value; `1` when unset,
/// unparseable, or out of the documented `1..=100` range.
#[must_use]
pub fn timing_budget_mult() -> u64 {
    budget_mult_from(std::env::var(ENV_TEST_TIMING_BUDGET_MULT).ok().as_deref())
}

/// Elastic per-response budget: base × the resolved multiplier.
#[must_use]
pub fn mcp_response_timeout() -> Duration {
    // `timing_budget_mult` is clamped to `1..=100`, so the conversion
    // never actually saturates; the fallback keeps the arithmetic total.
    let mult = u32::try_from(timing_budget_mult()).unwrap_or(u32::MAX);
    MCP_RESPONSE_BASE_TIMEOUT.saturating_mul(mult)
}

/// Pop the next MCP JSON-RPC response line from `rx`, bounded by
/// [`mcp_response_timeout`].
///
/// `ctx` names the in-flight request (e.g. `"initialize"`,
/// `"tools/call memory_reflect"`) so a failure says WHICH exchange
/// stalled rather than only that one did.
///
/// # Panics
///
/// * Immediately (millisecond scale, independent of the budget) when
///   the channel is `Disconnected` — the reader thread ended because
///   the child exited or closed stdout. That is a REAL failure, and
///   the panic says so, so it is never mistaken for a timing flake.
/// * On budget expiry, naming the elapsed wall time, the resolved
///   budget, and the env knob that widens it. The legacy substring
///   `mcp response did not arrive within READ_TIMEOUT` is preserved
///   verbatim so operators (and issue #2525) grepping CI logs for the
///   old signature still match — the same panic-shape-continuity
///   discipline `tests/common/mod.rs::WaitForReadyError` follows for
///   #1194.
pub fn recv_mcp_response(rx: &Receiver<String>, ctx: &str) -> String {
    let budget = mcp_response_timeout();
    let started = Instant::now();
    match rx.recv_timeout(budget) {
        Ok(line) => line,
        Err(RecvTimeoutError::Disconnected) => panic!(
            "mcp child closed stdout without answering {ctx} after {elapsed:?} \
             (budget {budget:?}) — the subprocess exited or died early. This is \
             a real failure, NOT a timing flake: the channel reports \
             Disconnected the moment the stdout reader thread ends, so the \
             budget was never consumed.",
            elapsed = started.elapsed(),
        ),
        Err(RecvTimeoutError::Timeout) => panic!(
            "mcp response did not arrive within READ_TIMEOUT: Timeout \
             (request={ctx}, waited {elapsed:?}, budget {budget:?} = \
             {base:?} x {mult}). The child was still alive and holding stdout \
             open the whole time — either it is genuinely wedged (see #1713), \
             or this host needs a wider budget: set \
             {ENV_TEST_TIMING_BUDGET_MULT}=<2..=100> (CLAUDE.md env row #68).",
            elapsed = started.elapsed(),
            base = MCP_RESPONSE_BASE_TIMEOUT,
            mult = timing_budget_mult(),
        ),
    }
}

#[cfg(test)]
mod mcp_wait_tests {
    use super::{
        BUDGET_MULT_MAX, MCP_RESPONSE_BASE_TIMEOUT, budget_mult_from, mcp_response_timeout,
        recv_mcp_response,
    };

    /// Unset / garbage / out-of-range all fall through to `1`, and an
    /// in-range value is honoured — byte-identical to the clamp in
    /// `src/hooks/timeouts.rs::test_timing_budget_mult`.
    #[test]
    fn budget_mult_clamp_matches_production_ladder() {
        assert_eq!(budget_mult_from(None), 1, "unset");
        assert_eq!(budget_mult_from(Some("")), 1, "empty");
        assert_eq!(budget_mult_from(Some("nope")), 1, "unparseable");
        assert_eq!(budget_mult_from(Some("0")), 1, "below range");
        assert_eq!(budget_mult_from(Some("101")), 1, "above range");
        assert_eq!(budget_mult_from(Some("1")), 1, "floor");
        assert_eq!(budget_mult_from(Some("7")), 7, "in range");
        assert_eq!(budget_mult_from(Some("100")), BUDGET_MULT_MAX, "ceiling");
    }

    /// The shipped budget is at least the base — a regression that
    /// tightened it below the pre-#2525 20 s maximum would re-open the
    /// flake for the suites that carried 15 s / 20 s constants.
    #[test]
    fn resolved_budget_is_never_below_the_base() {
        assert!(mcp_response_timeout() >= MCP_RESPONSE_BASE_TIMEOUT);
        assert!(MCP_RESPONSE_BASE_TIMEOUT.as_secs() >= 20);
    }

    /// A dead child (dropped sender) must surface as the fail-FAST
    /// disconnect panic, far inside the 60 s budget — this is the
    /// property that makes the generous budget affordable.
    #[test]
    fn dropped_sender_fails_fast_not_after_the_budget() {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        drop(tx);
        let started = std::time::Instant::now();
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recv_mcp_response(&rx, "initialize");
        }))
        .expect_err("disconnected channel must panic");
        let msg = err
            .downcast_ref::<String>()
            .map_or_else(String::new, Clone::clone);
        assert!(
            msg.contains("closed stdout"),
            "disconnect must be distinguishable from a timeout: {msg}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "disconnect must not wait out the budget (took {:?})",
            started.elapsed()
        );
    }
}
