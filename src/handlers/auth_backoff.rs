// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 — per-source auth-failure backoff for the HTTP transport-auth gate.
//!
//! [`super::transport::api_key_auth`] is the one transport-auth chokepoint
//! for every authenticated HTTP route. Before #2502 it recorded nothing: a
//! single source could present wrong keys forever at whatever rate the
//! daemon completed them. Admission control
//! (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`) bounds how many requests run AT ONCE,
//! not how many attempts one source makes over time.
//!
//! [`AuthFailurePolicy`] is the ONE predicate governing this (ruling 2):
//! the middleware consults it at every auth-failure site (missing key and
//! unknown key alike, shared-key and per-agent-key paths) and at the success
//! site (a success resets the source). No second copy of the decision
//! exists anywhere.
//!
//! * Source identity is the TCP peer IP (`ConnectInfo<SocketAddr>`,
//!   `transport.rs`), NEVER a client header: a header-derived source lets an
//!   attacker lock someone else out with a forged header. The tree has no
//!   trusted-proxy setting, so headers are not read at all.
//! * After [`FREE_FAILURES`] failures a source is refused with `429` +
//!   `Retry-After` BEFORE its key is looked at (a correct key presented
//!   during backoff is still refused, so the refusal is not a key oracle).
//!   The backoff doubles per further failure, capped at
//!   [`MAX_BACKOFF_SECS`]. A success removes the source, restarting its
//!   budget.
//! * The table is bounded at [`MAX_TRACKED_SOURCES`] entries in the shape of
//!   the federation replay LRU (`FEDERATION_NONCE_CAPACITY_PER_PEER`,
//!   `src/identity/replay.rs`): a constant cap with oldest-first eviction,
//!   so the counter cannot itself become a memory-exhaustion surface.
//! * Fail-open (issue item 3): a broken counter admits and logs at WARN —
//!   degrade, never deny. Pinned by the [`FailingStore`] seam.
//! * Observability: `ai_memory_auth_failures_total` (no per-source label —
//!   unbounded cardinality is forbidden) plus
//!   `ai_memory_auth_backoff_episodes_total` (backoff episodes begun since
//!   boot, incremented exactly on the crossing edge — amend F5: a gauge of
//!   "currently refused" would lie, because a source that crosses and never
//!   returns keeps the gauge non-zero after its window expires while the
//!   render path cannot recompute it), and one WARN edge-triggered on
//!   crossing the threshold, never per failure.
//!
//! Constants only, no env knob (ruling 7): nothing in the row-130 class
//! requires operator tuning here, so no `CLAUDE.md` env-table row and no
//! docs SSOT gate is touched.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Failures a source may accumulate before backoff starts. The first
/// [`FREE_FAILURES`] failures still answer the pre-existing `401`; the next
/// attempt is refused with `429`.
pub const FREE_FAILURES: u32 = 5;

/// Backoff after the first failure past [`FREE_FAILURES`]; doubles per
/// further failure while the source keeps guessing.
pub const BASE_BACKOFF_SECS: u64 = 1;

/// Longest single backoff: a persistently guessing source settles at one
/// attempt per five minutes.
pub const MAX_BACKOFF_SECS: u64 = 300;

/// Most sources tracked at once. 1024 entries of `(IpAddr, u32, Instant)`
/// plus recency links is tens of kilobytes — bounded by construction, so a
/// guessing fleet cannot grow the daemon.
pub const MAX_TRACKED_SOURCES: usize = 1024;

/// Closed-vocabulary `error` field of the `429` refusal body. Rendered only
/// through [`refusal_response`], so the shared-key and per-agent-key paths
/// are byte-identical and the body never says whether the key exists or
/// which path failed.
pub const AUTH_BACKOFF_ERROR: &str = "auth_backoff";

/// Doublings past which the backoff is already at [`MAX_BACKOFF_SECS`];
/// bounds the shift so it can never overflow (`PERF-01`).
const MAX_DOUBLINGS: u32 = 16;

/// Operator-log target for backoff transitions. Matches the auth
/// middleware's existing target.
const TRACE_TARGET: &str = "http::auth";

/// Operator-log operation names for the fail-open paths: ONE const per
/// operation, referenced by name (the hardcoded-literals gate forbids
/// scattering the same string across the three fail-open sites).
const OP_PRE_CHECK: &str = "pre_check";
const OP_RECORD_FAILURE: &str = "record_failure";

/// The one predicate's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// The attempt may proceed to normal authentication.
    Admit,
    /// The source is in backoff: refuse with `429` and this `Retry-After`
    /// (whole seconds).
    Refuse { retry_after_secs: u64 },
}

/// What the policy records per source.
#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    backoff_until: Option<Instant>,
}

/// Error from the failure store. Unit by design: the caller-facing refusal
/// is rendered from the closed vocabulary ([`AUTH_BACKOFF_ERROR`]), never
/// from a foreign error chain; the detail stays in the operator log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreError;

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("auth failure store unavailable")
    }
}

impl std::error::Error for StoreError {}

/// The counter seam. The production implementation is [`LruAuthFailureStore`];
/// tests inject doubles through
/// [`AuthFailurePolicy::with_store_for_test`](AuthFailurePolicy::with_store_for_test).
pub trait AuthFailureStore: Send {
    /// Record one auth failure from `source`. Returns the verdict for THIS
    /// attempt plus whether the source just crossed into backoff (the WARN
    /// + gauge edge — true exactly once per episode, when the failure count
    /// reaches `FREE_FAILURES + 1`).
    fn record_failure(
        &mut self,
        source: IpAddr,
        now: Instant,
    ) -> Result<(AuthDecision, bool), StoreError>;
    /// Read-only verdict for `source` without recording: used BEFORE the key
    /// is looked at so a backed-off source (correct key included) is refused
    /// without the refusal becoming a key oracle.
    fn check(&mut self, source: IpAddr, now: Instant) -> Result<AuthDecision, StoreError>;
    /// A successful authentication resets the source. Returns whether a
    /// backed-off source was cleared.
    fn record_success(&mut self, source: IpAddr) -> Result<bool, StoreError>;
    /// Sources currently refused at `now` (the gauge value).
    fn backed_off_count(&self, now: Instant) -> usize;
}

/// Backoff for a failure count past the threshold: `BASE * 2^n` capped at
/// `MAX`, with the shift bounded so it cannot overflow.
fn backoff_for(failures_past_free: u32) -> Duration {
    let shift = failures_past_free.min(MAX_DOUBLINGS);
    let secs = BASE_BACKOFF_SECS
        .saturating_mul(1u64 << shift)
        .min(MAX_BACKOFF_SECS);
    Duration::from_secs(secs.max(1))
}

/// Bounded per-source failure table: `HashMap` plus a recency queue, cap +
/// oldest-first eviction — the in-memory shape of the federation replay LRU
/// (`FEDERATION_NONCE_CAPACITY_PER_PEER`, `src/identity/replay.rs`).
pub struct LruAuthFailureStore {
    entries: HashMap<IpAddr, Entry>,
    recency: VecDeque<IpAddr>,
    cap: usize,
}

impl LruAuthFailureStore {
    /// Production table at [`MAX_TRACKED_SOURCES`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            recency: VecDeque::new(),
            cap: MAX_TRACKED_SOURCES,
        }
    }

    fn touch(&mut self, source: IpAddr) {
        self.recency.retain(|s| *s != source);
        self.recency.push_back(source);
        while self.entries.len() > self.cap {
            if let Some(oldest) = self.recency.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn is_backed_off(entry: &Entry, now: Instant) -> bool {
        entry.failures > FREE_FAILURES && entry.backoff_until.is_some_and(|until| now < until)
    }
}

impl Default for LruAuthFailureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthFailureStore for LruAuthFailureStore {
    fn record_failure(
        &mut self,
        source: IpAddr,
        now: Instant,
    ) -> Result<(AuthDecision, bool), StoreError> {
        let verdict = {
            let entry = self.entries.entry(source).or_insert(Entry {
                failures: 0,
                backoff_until: None,
            });
            entry.failures = entry.failures.saturating_add(1);
            if entry.failures > FREE_FAILURES {
                let backoff = backoff_for(entry.failures - FREE_FAILURES - 1);
                entry.backoff_until = Some(now + backoff);
                let crossed = entry.failures == FREE_FAILURES + 1;
                (
                    AuthDecision::Refuse {
                        retry_after_secs: backoff.as_secs().max(1),
                    },
                    crossed,
                )
            } else {
                (AuthDecision::Admit, false)
            }
        };
        self.touch(source);
        Ok(verdict)
    }

    fn check(&mut self, source: IpAddr, now: Instant) -> Result<AuthDecision, StoreError> {
        match self.entries.get(&source) {
            Some(entry) if Self::is_backed_off(entry, now) => {
                let remaining = entry
                    .backoff_until
                    .map(|until| until.saturating_duration_since(now).as_secs().max(1))
                    .unwrap_or(1);
                Ok(AuthDecision::Refuse {
                    retry_after_secs: remaining,
                })
            }
            _ => Ok(AuthDecision::Admit),
        }
    }

    fn record_success(&mut self, source: IpAddr) -> Result<bool, StoreError> {
        let was_backed_off = self
            .entries
            .remove(&source)
            .is_some_and(|entry| entry.failures > FREE_FAILURES);
        // Amend F3: recency shrinks with entries on EVERY success, not only
        // for backed-off sources — otherwise each fail-a-few-times-then-succeed
        // client leaks one recency element forever while entries stays capped.
        self.recency.retain(|s| *s != source);
        Ok(was_backed_off)
    }

    fn backed_off_count(&self, now: Instant) -> usize {
        self.entries
            .values()
            .filter(|entry| Self::is_backed_off(entry, now))
            .count()
    }
}

struct PolicyInner {
    store: Box<dyn AuthFailureStore>,
    broken: bool,
}

/// The ONE predicate (ruling 2): per-source auth-failure backoff consulted
/// at every auth-failure site and at the success site. `Clone` shares the
/// table, so every middleware copy (and every `ApiKeyState` copy) decides
/// from the same counters.
#[derive(Clone)]
pub struct AuthFailurePolicy {
    shared: Arc<Mutex<PolicyInner>>,
}

impl AuthFailurePolicy {
    /// Production policy: bounded LRU table, fail-open on counter error.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(PolicyInner {
                store: Box::new(LruAuthFailureStore::new()),
                broken: false,
            })),
        }
    }

    /// Test seam: drive the policy with an injected store. Production code
    /// never calls this.
    #[doc(hidden)]
    #[must_use]
    pub fn with_store_for_test(store: impl AuthFailureStore + 'static) -> Self {
        Self {
            shared: Arc::new(Mutex::new(PolicyInner {
                store: Box::new(store),
                broken: false,
            })),
        }
    }

    /// Test seam: break the counter so every operation takes the fail-open
    /// path (ruling 6 / pin (e)). The `Clone` shares the flag, so breaking
    /// one handle breaks the middleware's copy too.
    #[doc(hidden)]
    pub fn break_for_test(&self) {
        if let Ok(mut inner) = self.shared.lock() {
            inner.broken = true;
        }
    }

    fn fail_open(source: IpAddr, what: &'static str) -> AuthDecision {
        tracing::warn!(
            target: TRACE_TARGET,
            ip = %source,
            op = what,
            "auth-failure counter unavailable — admitting (fail-open)"
        );
        AuthDecision::Admit
    }

    /// Pre-key verdict for `source`: refuse BEFORE the presented key is
    /// compared, so a correct key during backoff is still refused.
    #[must_use]
    pub fn pre_check(&self, source: IpAddr, now: Instant) -> AuthDecision {
        let mut inner = match self.shared.lock() {
            Ok(inner) => inner,
            Err(_) => return Self::fail_open(source, OP_PRE_CHECK),
        };
        if inner.broken {
            return Self::fail_open(source, OP_PRE_CHECK);
        }
        match inner.store.check(source, now) {
            Ok(decision) => decision,
            Err(_) => Self::fail_open(source, OP_PRE_CHECK),
        }
    }

    /// Record one auth failure from `source` and return the verdict for this
    /// attempt. Fails open to [`AuthDecision::Admit`] when the counter
    /// errors.
    #[must_use]
    pub fn on_failure(&self, source: IpAddr, now: Instant) -> AuthDecision {
        // Amend F4: the mutex is held only for the store call. The WARN edge
        // and both metric increments happen AFTER the guard drops, so a slow
        // log/metrics sink can never stall the auth hot path; `backed_off_count`
        // (an O(entries) scan) is nowhere near it (F5 removed the sampling).
        let outcome: Option<(AuthDecision, bool)> = {
            let mut inner = match self.shared.lock() {
                Ok(inner) => inner,
                Err(_) => return Self::fail_open(source, OP_RECORD_FAILURE),
            };
            if inner.broken {
                return Self::fail_open(source, OP_RECORD_FAILURE);
            }
            match inner.store.record_failure(source, now) {
                Ok((decision, crossed)) => Some((decision, crossed)),
                Err(_) => None,
            }
        };
        let Some((decision, crossed)) = outcome else {
            return Self::fail_open(source, OP_RECORD_FAILURE);
        };
        let metrics = crate::metrics::registry();
        metrics.auth_failures_total.inc();
        if crossed {
            tracing::warn!(
                target: TRACE_TARGET,
                ip = %source,
                failures = FREE_FAILURES + 1,
                "auth failures from one source crossed the backoff threshold — \
                 refusing further attempts with 429 (edge-triggered)"
            );
            // Amend F5: episodes-since-boot, incremented exactly on the
            // crossing edge — the same place the WARN fires.
            metrics.auth_backoff_episodes_total.inc();
        }
        decision
    }

    /// A successful authentication resets the source.
    pub fn on_success(&self, source: IpAddr) {
        // Amend F4: no metric sample under the guard — F5 moved the gauge to
        // an episodes counter incremented on the crossing edge only, so the
        // success path needs no scan at all.
        let mut inner = match self.shared.lock() {
            Ok(inner) => inner,
            Err(_) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    ip = %source,
                    "auth-failure counter unavailable on success — continuing (fail-open)"
                );
                return;
            }
        };
        if inner.broken {
            return;
        }
        if inner.store.record_success(source).is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                ip = %source,
                "auth-failure counter unavailable on success — continuing (fail-open)"
            );
        }
    }
}

impl Default for AuthFailurePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AuthFailurePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthFailurePolicy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct FailingStore;

    impl AuthFailureStore for FailingStore {
        fn record_failure(
            &mut self,
            _source: IpAddr,
            _now: Instant,
        ) -> Result<(AuthDecision, bool), StoreError> {
            Err(StoreError)
        }

        fn check(&mut self, _source: IpAddr, _now: Instant) -> Result<AuthDecision, StoreError> {
            Err(StoreError)
        }

        fn record_success(&mut self, _source: IpAddr) -> Result<bool, StoreError> {
            Err(StoreError)
        }

        fn backed_off_count(&self, _now: Instant) -> usize {
            0
        }
    }

    fn test_store(cap: usize) -> LruAuthFailureStore {
        LruAuthFailureStore {
            entries: HashMap::new(),
            recency: VecDeque::new(),
            cap,
        }
    }

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    /// (e) a broken counter admits everywhere: pre-check, failure, and
    /// success paths all fail open.
    #[test]
    fn fail_open_on_counter_error() {
        let policy = AuthFailurePolicy::with_store_for_test(FailingStore);
        let now = Instant::now();
        assert_eq!(policy.pre_check(SRC, now), AuthDecision::Admit);
        assert_eq!(policy.on_failure(SRC, now), AuthDecision::Admit);
        policy.on_success(SRC);
        let broken = AuthFailurePolicy::new();
        broken.break_for_test();
        assert_eq!(broken.pre_check(SRC, now), AuthDecision::Admit);
        assert_eq!(broken.on_failure(SRC, now), AuthDecision::Admit);
        broken.on_success(SRC);
    }

    /// The threshold and the doubling schedule: FREE admits, then 1s, 2s,
    /// 4s … capped at MAX.
    #[test]
    fn threshold_then_doubling_backoff_capped() {
        let mut store = test_store(64);
        let now = Instant::now();
        for _ in 0..FREE_FAILURES {
            assert_eq!(
                store.record_failure(SRC, now).expect("record").0,
                AuthDecision::Admit
            );
        }
        let (decision, crossed) = store.record_failure(SRC, now).expect("record");
        assert_eq!(
            decision,
            AuthDecision::Refuse {
                retry_after_secs: 1
            }
        );
        assert!(crossed, "WARN edge fires exactly on crossing");
        let (decision, crossed) = store.record_failure(SRC, now).expect("record");
        assert_eq!(
            decision,
            AuthDecision::Refuse {
                retry_after_secs: 2
            }
        );
        assert!(!crossed, "no second edge while in backoff");
        let (decision, _) = store.record_failure(SRC, now).expect("record");
        assert_eq!(
            decision,
            AuthDecision::Refuse {
                retry_after_secs: 4
            }
        );
        for _ in 0..40 {
            let _ = store.record_failure(SRC, now).expect("record");
        }
        let (decision, _) = store.record_failure(SRC, now).expect("record");
        assert_eq!(
            decision,
            AuthDecision::Refuse {
                retry_after_secs: MAX_BACKOFF_SECS
            },
            "backoff caps, never overflows"
        );
    }

    /// A success resets the source to a fresh budget.
    #[test]
    fn success_resets_the_source() {
        let mut store = test_store(64);
        let now = Instant::now();
        for _ in 0..=FREE_FAILURES {
            let _ = store.record_failure(SRC, now).expect("record");
        }
        assert!(matches!(
            store.check(SRC, now).expect("check"),
            AuthDecision::Refuse { .. }
        ));
        assert!(store.record_success(SRC).expect("reset"));
        for _ in 0..FREE_FAILURES {
            assert_eq!(
                store.record_failure(SRC, now).expect("record").0,
                AuthDecision::Admit
            );
        }
    }

    /// Success on an unknown source is a no-op (no gauge edge).
    #[test]
    fn success_on_unknown_source_is_a_noop() {
        let mut store = test_store(64);
        assert!(!store.record_success(SRC).expect("noop"));
    }

    /// The cap evicts the oldest source; recency is refreshed by failure.
    #[test]
    fn lru_cap_evicts_the_oldest_source() {
        let mut store = test_store(2);
        let now = Instant::now();
        let a = IpAddr::from([10, 0, 0, 1]);
        let b = IpAddr::from([10, 0, 0, 2]);
        let c = IpAddr::from([10, 0, 0, 3]);
        let _ = store.record_failure(a, now).expect("record");
        let _ = store.record_failure(b, now).expect("record");
        let _ = store.record_failure(c, now).expect("record");
        assert!(!store.entries.contains_key(&a), "oldest evicted");
        assert!(store.entries.contains_key(&b));
        assert!(store.entries.contains_key(&c));
    }

    /// An expired backoff admits again without recording.
    #[test]
    fn expired_backoff_admits_on_check() {
        let mut store = test_store(64);
        let now = Instant::now();
        for _ in 0..=FREE_FAILURES {
            let _ = store.record_failure(SRC, now).expect("record");
        }
        assert!(matches!(
            store.check(SRC, now),
            Ok(AuthDecision::Refuse { .. })
        ));
        assert_eq!(
            store.check(SRC, now + Duration::from_secs(MAX_BACKOFF_SECS + 1)),
            Ok(AuthDecision::Admit),
            "after the window the source is admittable again"
        );
    }

    /// `check` refuses a backed-off source with the remaining window, and a
    /// correct key presented during backoff is still refused (no oracle).
    #[test]
    fn check_refuses_during_backoff_with_remaining_window() {
        let mut store = test_store(64);
        let now = Instant::now();
        for _ in 0..=FREE_FAILURES {
            let _ = store.record_failure(SRC, now).expect("record");
        }
        match store.check(SRC, now).expect("check") {
            AuthDecision::Refuse { retry_after_secs } => {
                assert_eq!(retry_after_secs, 1, "first backoff step is the 1s base");
            }
            AuthDecision::Admit => panic!("backed-off source must be refused"),
        }
    }

    /// Amend F3 pin: `recency` must shrink with `entries`. 2000 distinct
    /// sources each fail once then succeed -> `recency.len() <=
    /// entries.len() <= 1024`. Before the fix `record_success` pruned
    /// `recency` only for backed-off sources, so every client that failed
    /// 1-5 times then succeeded leaked one `recency` element forever.
    #[test]
    fn recency_shrinks_with_entries_on_success() {
        let mut store = LruAuthFailureStore::new();
        let now = Instant::now();
        let mut sources = Vec::with_capacity(2000);
        for i in 0..2000u32 {
            let source = IpAddr::from([10, 200, (i >> 8) as u8, (i & 0xff) as u8]);
            sources.push(source);
            let _ = store.record_failure(source, now).expect("record");
        }
        assert!(
            store.entries.len() <= MAX_TRACKED_SOURCES,
            "entries bounded: {}",
            store.entries.len()
        );
        for source in sources {
            let _ = store.record_success(source).expect("reset");
        }
        assert!(
            store.recency.len() <= store.entries.len(),
            "recency must shrink with entries: recency {} > entries {}",
            store.recency.len(),
            store.entries.len()
        );
        assert!(
            store.recency.len() <= MAX_TRACKED_SOURCES,
            "recency bounded: {}",
            store.recency.len()
        );
    }
}
