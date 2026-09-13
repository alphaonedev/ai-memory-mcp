// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 — per-source auth-failure backoff for the HTTP transport-auth gate.
//!
//! [`super::transport::api_key_auth`] is the one transport-auth chokepoint for
//! every authenticated HTTP route. Before #2502 it recorded nothing: a single
//! source could present wrong keys forever at whatever rate the daemon
//! completed them. Admission control (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`)
//! bounds how many requests run AT ONCE, not how many attempts one source
//! makes over time.
//!
//! This layer sits directly OUTSIDE `api_key_auth`:
//!
//! * `api_key_auth` stamps [`AuthRejected`] on its two `401` returns (no
//!   key, or a key that is neither the shared key nor an enrolled per-agent
//!   key). Nothing else is counted: `/health`, a daemon with no key
//!   configured, the mTLS `/sync/*` bypass, a `403` identity mismatch (the
//!   key was valid) and handler-level refusals carry no stamp.
//! * The source is the TCP peer address (`ConnectInfo<SocketAddr>`), IPv6
//!   collapsed to its /48 (one customer allocation, so an attacker cannot
//!   mint a fresh source per address). `X-Forwarded-For` is read ONLY when
//!   the peer is in the operator-declared set
//!   [`ENV_AUTH_BACKOFF_TRUSTED_PROXIES`] (empty by default): the client
//!   writes that header, and "the peer is loopback" is not "the peer is our
//!   proxy" on a host other local processes share, so trusting it anywhere
//!   else would let a guesser name a fresh source per request, or name
//!   another client's address to lock it out. From a declared proxy the
//!   source is the rightmost hop that is not itself a declared proxy.
//! * After [`FREE_FAILURES`] rejections, each further rejection puts the
//!   source in backoff for `1 s * 2^(k-1)`, capped at [`MAX_BACKOFF`]. A
//!   source in backoff gets `429` + `Retry-After` BEFORE its key is looked
//!   at, correct key included: answering a correct key during backoff would
//!   tell the guesser which key was right, and the guessing would not slow.
//! * A successful authentication does NOT clear the source: otherwise a
//!   caller holding one valid key could interleave valid requests with
//!   guesses at another key and never reach backoff. The count decays by
//!   time only: a source with no rejection for [`IDLE_RESET`] starts over.
//! * The table is bounded at [`MAX_TRACKED_SOURCES`], so it cannot itself
//!   exhaust memory. At capacity the least-recently-failed source is dropped,
//!   but never one in backoff: dropping it would let a guesser clear its own
//!   backoff by failing from other addresses. When every candidate is in
//!   backoff the new source is not counted (one WARN per process).
//! * A request with no peer address (a router driven without a TCP listener)
//!   passes untouched; a poisoned lock is recovered. The layer degrades to
//!   "no backoff", never to "deny".
//!
//! `AI_MEMORY_AUTH_FAILURE_BACKOFF` (default ON; pinned by `asi-hard`)
//! switches the layer off with a falsy token. Known trade-off: behind a proxy
//! that is not declared (or one that does not append its hop) every client
//! shares the proxy's source, so one client presenting wrong keys puts all of
//! them in backoff for at most [`MAX_BACKOFF`]; the WARN names that source.
//! The guessing bound is [`FREE_FAILURES`] per source, not a global total.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// The env knob. Registered in [`crate::env_flag::knobs::AUTH_FAILURE_BACKOFF`].
pub const ENV_AUTH_FAILURE_BACKOFF: &str = "AI_MEMORY_AUTH_FAILURE_BACKOFF";

/// Comma-separated IP addresses of the reverse proxies whose
/// `X-Forwarded-For` is read. Unset or empty: none, every peer is its own
/// source.
pub const ENV_AUTH_BACKOFF_TRUSTED_PROXIES: &str = "AI_MEMORY_AUTH_BACKOFF_TRUSTED_PROXIES";

/// Rejections a source may accumulate before backoff starts.
pub const FREE_FAILURES: u32 = 10;

/// Backoff after the first rejection past [`FREE_FAILURES`]; doubles per
/// further rejection.
pub const BASE_BACKOFF: Duration = Duration::from_secs(1);

/// Longest single backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(5 * SECS_PER_MINUTE);

/// A source with no rejection for this long starts over.
pub const IDLE_RESET: Duration = Duration::from_secs(15 * SECS_PER_MINUTE);

/// Most sources tracked at once.
pub const MAX_TRACKED_SOURCES: usize = 10_000;

/// `error` field of the `429` body.
pub const ERROR_AUTH_BACKOFF: &str = "auth_backoff";

const SECS_PER_MINUTE: u64 = crate::SECS_PER_MINUTE.unsigned_abs();

/// Doublings past which the backoff is already at [`MAX_BACKOFF`]; bounds the
/// shift so it can never overflow.
const MAX_DOUBLINGS: u32 = 16;

const TRACE_TARGET: &str = "http::auth";

/// Header a reverse proxy appends the client address to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// `X-Forwarded-For` hops examined from the right before giving up and
/// keying on the last declared proxy seen.
const MAX_FORWARDED_HOPS: usize = 32;

/// Live records examined per eviction before the new source is left
/// untracked; bounds the work done under the lock.
const EVICTION_SCAN: usize = 64;

/// Leading bytes of an IPv6 address that form one source (/48).
const V6_SOURCE_PREFIX_BYTES: usize = 6;

/// Response extension `api_key_auth` puts on its `401`s: the credential was
/// missing or unknown. The backoff layer counts exactly these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRejected;

impl AuthRejected {
    /// Mark `response` as a transport-auth rejection.
    #[must_use]
    pub fn stamp(mut response: Response) -> Response {
        response.extensions_mut().insert(Self);
        response
    }
}

/// One source: an IPv4 address, or an IPv6 /48 (an IPv4-mapped IPv6 address
/// counts as its IPv4 address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// An IPv4 peer.
    V4(Ipv4Addr),
    /// The first 48 bits of an IPv6 peer.
    V6Net([u8; V6_SOURCE_PREFIX_BYTES]),
}

impl SourceKey {
    /// The source a peer address belongs to.
    #[must_use]
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4),
                None => {
                    let mut net = [0_u8; V6_SOURCE_PREFIX_BYTES];
                    net.copy_from_slice(&v6.octets()[..V6_SOURCE_PREFIX_BYTES]);
                    Self::V6Net(net)
                }
            },
        }
    }
}

/// The reverse proxies whose `X-Forwarded-For` the layer reads
/// ([`ENV_AUTH_BACKOFF_TRUSTED_PROXIES`]). A trust boundary is something an
/// operator declares, never something inferred from an address class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Arc<[IpAddr]>);

impl TrustedProxies {
    /// Parse a comma-separated address list. Returns the set and the entries
    /// that did not parse; a rejected entry is simply not trusted, so a typo
    /// can only narrow what is trusted, never widen it.
    #[must_use]
    pub fn parse(raw: &str) -> (Self, Vec<String>) {
        let mut trusted = Vec::new();
        let mut rejected = Vec::new();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            match entry.parse::<IpAddr>() {
                Ok(ip) => trusted.push(ip.to_canonical()),
                Err(_) => rejected.push(entry.to_owned()),
            }
        }
        (Self(trusted.into()), rejected)
    }

    /// The set from [`ENV_AUTH_BACKOFF_TRUSTED_PROXIES`]; each rejected entry
    /// is logged at WARN.
    #[must_use]
    pub fn from_env() -> Self {
        let raw = match std::env::var(ENV_AUTH_BACKOFF_TRUSTED_PROXIES) {
            Ok(raw) => raw,
            Err(std::env::VarError::NotPresent) => return Self::default(),
            Err(std::env::VarError::NotUnicode(_)) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    "{ENV_AUTH_BACKOFF_TRUSTED_PROXIES} is not UTF-8; no proxy is trusted (#2502)"
                );
                return Self::default();
            }
        };
        let (trusted, rejected) = Self::parse(&raw);
        for entry in rejected {
            tracing::warn!(
                target: TRACE_TARGET,
                entry = %entry,
                "{ENV_AUTH_BACKOFF_TRUSTED_PROXIES} entry is not an IP address; it is \
                 not trusted (#2502)"
            );
        }
        trusted
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }

    /// No proxy is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The source a request belongs to. The peer, unless the peer is a declared
/// proxy: then the rightmost `X-Forwarded-For` hop that is not itself a
/// declared proxy. An absent or unparseable hop stops the walk and the last
/// declared proxy seen is the source, which only ever widens a bucket.
#[must_use]
pub fn source_for(peer: SocketAddr, headers: &HeaderMap, trusted: &TrustedProxies) -> SourceKey {
    let mut candidate = peer.ip().to_canonical();
    if !trusted.contains(candidate) {
        return SourceKey::from_ip(candidate);
    }
    let mut seen = 0_usize;
    // Several header lines form one list in order, so walk the last line
    // first and each line from its right end.
    for line in headers.get_all(X_FORWARDED_FOR).iter().rev() {
        let Ok(line) = line.to_str() else {
            return SourceKey::from_ip(candidate);
        };
        for hop in line.rsplit(',') {
            seen += 1;
            if seen > MAX_FORWARDED_HOPS {
                return SourceKey::from_ip(candidate);
            }
            let Some(ip) = parse_hop(hop.trim()) else {
                return SourceKey::from_ip(candidate);
            };
            if !trusted.contains(ip) {
                return SourceKey::from_ip(ip);
            }
            candidate = ip;
        }
    }
    SourceKey::from_ip(candidate)
}

/// One `X-Forwarded-For` hop as an address: a bare IP, or `host:port`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|s| s.ip()))
        .map(|ip| ip.to_canonical())
}

impl fmt::Display for SourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{v4}"),
            Self::V6Net(net) => {
                let word = |i: usize| u16::from_be_bytes([net[i], net[i + 1]]);
                write!(f, "{:x}:{:x}:{:x}::/48", word(0), word(2), word(4))
            }
        }
    }
}

/// What one recorded rejection did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureEffect {
    /// Counted; the source is still within [`FREE_FAILURES`].
    Counted,
    /// The source is now in backoff for `backoff`. `first` is true on the
    /// rejection that crossed [`FREE_FAILURES`] (the edge the WARN fires on).
    Backoff {
        /// Rejections recorded for the source, this one included.
        failures: u32,
        /// How long the source is refused.
        backoff: Duration,
        /// This rejection crossed the threshold.
        first: bool,
    },
    /// Not counted: the table is full and every eviction candidate is in
    /// backoff.
    Untracked,
}

#[derive(Debug)]
struct Record {
    failures: u32,
    last_failure: Instant,
    blocked_until: Option<Instant>,
    seq: u64,
}

impl Record {
    fn is_blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|until| until > now)
    }
}

#[derive(Debug)]
struct Table {
    records: HashMap<SourceKey, Record>,
    /// Least-recently-failed first: every rejection re-queues its source
    /// with a fresh `seq`, and entries whose `seq` no longer matches the live
    /// record are stale and skipped.
    order: VecDeque<(SourceKey, u64)>,
    next_seq: u64,
    capacity: usize,
}

/// The per-source rejection table.
#[derive(Debug)]
pub struct AuthBackoff {
    table: Mutex<Table>,
}

impl Default for AuthBackoff {
    fn default() -> Self {
        Self::with_capacity(MAX_TRACKED_SOURCES)
    }
}

/// Backoff for the `k`-th rejection past [`FREE_FAILURES`] (`k >= 1`).
#[must_use]
pub fn backoff_for(k: u32) -> Duration {
    let doublings = k.saturating_sub(1).min(MAX_DOUBLINGS);
    BASE_BACKOFF
        .saturating_mul(1_u32 << doublings)
        .min(MAX_BACKOFF)
}

impl AuthBackoff {
    /// A table tracking at most `capacity` sources (at least one).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            table: Mutex::new(Table {
                records: HashMap::new(),
                order: VecDeque::new(),
                next_seq: 0,
                capacity: capacity.max(1),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        // The table holds counters and deadlines only; a panic mid-update can
        // leave at worst one stale count, so recovering keeps the control on.
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remaining backoff for `source` at `now`, or `None` when it may try.
    #[must_use]
    pub fn blocked_for(&self, source: SourceKey, now: Instant) -> Option<Duration> {
        let table = self.lock();
        let until = table.records.get(&source)?.blocked_until?;
        let remaining = until.saturating_duration_since(now);
        (!remaining.is_zero()).then_some(remaining)
    }

    /// Record one rejection for `source` at `now`.
    pub fn record_failure(&self, source: SourceKey, now: Instant) -> FailureEffect {
        let mut table = self.lock();
        let idle = table
            .records
            .get(&source)
            .is_some_and(|r| now.saturating_duration_since(r.last_failure) >= IDLE_RESET);
        if idle {
            table.records.remove(&source);
        }
        if !table.records.contains_key(&source) {
            if !table.make_room(now) {
                return FailureEffect::Untracked;
            }
            table.records.insert(
                source,
                Record {
                    failures: 0,
                    last_failure: now,
                    blocked_until: None,
                    seq: 0,
                },
            );
        }
        let seq = table.next_seq;
        table.next_seq = table.next_seq.wrapping_add(1);
        let Some(record) = table.records.get_mut(&source) else {
            return FailureEffect::Untracked;
        };
        record.seq = seq;
        record.failures = record.failures.saturating_add(1);
        record.last_failure = now;
        let past = record.failures.saturating_sub(FREE_FAILURES);
        let effect = if past == 0 {
            FailureEffect::Counted
        } else {
            let backoff = backoff_for(past);
            record.blocked_until = now.checked_add(backoff);
            FailureEffect::Backoff {
                failures: record.failures,
                backoff,
                first: past == 1,
            }
        };
        table.order.push_back((source, seq));
        table.compact();
        effect
    }

    /// Sources currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.lock().records.len()
    }
}

impl Table {
    /// Make room for one more record by dropping the least-recently-failed
    /// source that is not in backoff at `now`. A source in backoff is kept
    /// and re-queued: dropping it would clear its backoff. Returns `false`
    /// when [`EVICTION_SCAN`] live candidates were all in backoff.
    fn make_room(&mut self, now: Instant) -> bool {
        let mut scanned = 0_usize;
        while self.records.len() >= self.capacity {
            if scanned == EVICTION_SCAN {
                return false;
            }
            let Some((key, seq)) = self.order.pop_front() else {
                return false;
            };
            let blocked = match self.records.get(&key) {
                Some(record) if record.seq == seq => record.is_blocked(now),
                _ => continue,
            };
            scanned += 1;
            if blocked {
                self.order.push_back((key, seq));
            } else {
                self.records.remove(&key);
            }
        }
        true
    }

    /// Drop stale order entries once they outnumber the live records, so the
    /// order queue stays within twice the capacity.
    fn compact(&mut self) {
        if self.order.len() > self.capacity.saturating_mul(2) {
            let records = &self.records;
            self.order
                .retain(|(key, seq)| records.get(key).is_some_and(|r| r.seq == *seq));
        }
    }
}

/// Router state for [`auth_backoff_layer`]. `table` is `None` when the knob
/// is off; `mtls_enforced` mirrors [`super::transport::ApiKeyState`] so the
/// layer skips exactly the requests `api_key_auth` does not judge.
#[derive(Debug, Clone, Default)]
pub struct AuthBackoffState {
    table: Option<Arc<AuthBackoff>>,
    mtls_enforced: bool,
    trusted: TrustedProxies,
}

impl AuthBackoffState {
    /// State from `AI_MEMORY_AUTH_FAILURE_BACKOFF` (default ON) and
    /// [`ENV_AUTH_BACKOFF_TRUSTED_PROXIES`]: a fresh table per router, so each
    /// daemon (and each test router) counts on its own.
    #[must_use]
    pub fn from_env(mtls_enforced: bool) -> Self {
        let enabled = crate::env_flag::knobs::AUTH_FAILURE_BACKOFF.enabled();
        Self {
            table: enabled.then(|| Arc::new(AuthBackoff::default())),
            mtls_enforced,
            trusted: if enabled {
                TrustedProxies::from_env()
            } else {
                TrustedProxies::default()
            },
        }
    }

    /// State over an explicit table, trusting no proxy.
    #[must_use]
    pub fn with_table(table: Arc<AuthBackoff>, mtls_enforced: bool) -> Self {
        Self {
            table: Some(table),
            mtls_enforced,
            trusted: TrustedProxies::default(),
        }
    }

    /// The same state, reading `X-Forwarded-For` from `trusted` proxies.
    #[must_use]
    pub fn trusting(self, trusted: TrustedProxies) -> Self {
        Self { trusted, ..self }
    }
}

fn refusal(remaining: Duration) -> Response {
    let secs = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0))
        .max(1);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": ERROR_AUTH_BACKOFF,
            "message": "too many failed authentication attempts from this address; \
                        retry after the Retry-After interval",
            "retry_after_secs": secs,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(secs));
    response
}

/// The backoff layer. Composed directly outside `api_key_auth`.
pub async fn auth_backoff_layer(
    State(state): State<AuthBackoffState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(table) = state.table else {
        return next.run(req).await;
    };
    if super::transport::auth_exempt(req.uri().path(), state.mtls_enforced) {
        return next.run(req).await;
    }
    let Some(source) = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| source_for(*addr, req.headers(), &state.trusted))
    else {
        static NO_PEER_ONCE: std::sync::Once = std::sync::Once::new();
        NO_PEER_ONCE.call_once(|| {
            tracing::warn!(
                target: TRACE_TARGET,
                "auth-failure backoff (#2502) is inactive for requests without a \
                 peer address; the router is being served without connect info"
            );
        });
        return next.run(req).await;
    };
    if let Some(remaining) = table.blocked_for(source, Instant::now()) {
        crate::metrics::registry().auth_backoff_refusals_total.inc();
        return refusal(remaining);
    }
    let response = next.run(req).await;
    if response.extensions().get::<AuthRejected>().is_some() {
        crate::metrics::registry().auth_failures_total.inc();
        match table.record_failure(source, Instant::now()) {
            FailureEffect::Backoff {
                failures,
                backoff,
                first: true,
            } => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    %source,
                    failures,
                    backoff_secs = backoff.as_secs(),
                    "source exceeded {FREE_FAILURES} failed authentication attempts; \
                     refusing it with 429 for a doubling interval (#2502). Set \
                     {ENV_AUTH_FAILURE_BACKOFF}=0 to disable"
                );
            }
            FailureEffect::Untracked => {
                static FULL_ONCE: std::sync::Once = std::sync::Once::new();
                FULL_ONCE.call_once(|| {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        %source,
                        capacity = MAX_TRACKED_SOURCES,
                        "auth-failure table is full of sources in backoff; new \
                         sources are not counted until one expires (#2502)"
                    );
                });
            }
            FailureEffect::Counted | FailureEffect::Backoff { .. } => {}
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(last: u8) -> SourceKey {
        SourceKey::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn fail_n(t: &AuthBackoff, s: SourceKey, n: u32, now: Instant) -> FailureEffect {
        let mut last = FailureEffect::Counted;
        for _ in 0..n {
            last = t.record_failure(s, now);
        }
        last
    }

    #[test]
    fn free_failures_then_doubling_backoff_capped_2502() {
        let t = AuthBackoff::default();
        let now = Instant::now();
        assert_eq!(
            fail_n(&t, v4(1), FREE_FAILURES, now),
            FailureEffect::Counted
        );
        assert_eq!(t.blocked_for(v4(1), now), None);
        assert_eq!(
            t.record_failure(v4(1), now),
            FailureEffect::Backoff {
                failures: FREE_FAILURES + 1,
                backoff: BASE_BACKOFF,
                first: true,
            }
        );
        assert_eq!(t.blocked_for(v4(1), now), Some(BASE_BACKOFF));
        assert_eq!(backoff_for(2), Duration::from_secs(2));
        assert_eq!(backoff_for(9), Duration::from_secs(256));
        assert_eq!(backoff_for(10), MAX_BACKOFF);
        assert_eq!(backoff_for(u32::MAX), MAX_BACKOFF);
        let FailureEffect::Backoff { backoff, first, .. } = t.record_failure(v4(1), now) else {
            panic!("the twelfth rejection must extend the backoff");
        };
        assert_eq!((backoff, first), (Duration::from_secs(2), false));
    }

    #[test]
    fn backoff_expires_but_the_count_is_kept_2502() {
        let t = AuthBackoff::default();
        let now = Instant::now();
        fail_n(&t, v4(2), FREE_FAILURES + 1, now);
        let later = now + BASE_BACKOFF;
        assert_eq!(
            t.blocked_for(v4(2), later),
            None,
            "backoff over at its deadline"
        );
        let FailureEffect::Backoff { backoff, .. } = t.record_failure(v4(2), later) else {
            panic!("the count survives the window: the next rejection doubles");
        };
        assert_eq!(backoff, Duration::from_secs(2));
    }

    #[test]
    fn idle_source_starts_over_2502() {
        let t = AuthBackoff::default();
        let now = Instant::now();
        fail_n(&t, v4(3), FREE_FAILURES, now);
        assert_eq!(
            t.record_failure(v4(3), now + IDLE_RESET),
            FailureEffect::Counted
        );
    }

    #[test]
    fn sources_are_independent_2502() {
        let t = AuthBackoff::default();
        let now = Instant::now();
        fail_n(&t, v4(4), FREE_FAILURES + 1, now);
        assert!(t.blocked_for(v4(4), now).is_some());
        assert_eq!(t.blocked_for(v4(5), now), None);
    }

    fn failures(t: &AuthBackoff, s: SourceKey) -> Option<u32> {
        t.lock().records.get(&s).map(|r| r.failures)
    }

    #[test]
    fn table_drops_the_least_recently_failed_source_2502() {
        let t = AuthBackoff::with_capacity(3);
        let now = Instant::now();
        for i in 0..3 {
            t.record_failure(v4(i), now);
        }
        // v4(0) fails again, so v4(1) is now the least recently failed.
        t.record_failure(v4(0), now);
        t.record_failure(v4(3), now);
        assert_eq!(t.tracked(), 3);
        assert_eq!(failures(&t, v4(0)), Some(2), "a recent failure is kept");
        assert_eq!(failures(&t, v4(1)), None, "the least recent is dropped");
        for i in 10..60 {
            t.record_failure(v4(i), now + IDLE_RESET);
        }
        assert_eq!(t.tracked(), 3);
        assert!(t.lock().order.len() <= 6, "the order queue stays bounded");
    }

    #[test]
    fn a_source_in_backoff_is_never_evicted_2502() {
        let t = AuthBackoff::with_capacity(2);
        let now = Instant::now();
        fail_n(&t, v4(0), FREE_FAILURES + 1, now);
        // Pre-fix, one cheap failure each from other addresses flushed the
        // blocked source and handed it a fresh free budget.
        for i in 10..60 {
            t.record_failure(v4(i), now);
        }
        assert_eq!(t.blocked_for(v4(0), now), Some(BASE_BACKOFF));
        assert_eq!(failures(&t, v4(0)), Some(FREE_FAILURES + 1));
        assert_eq!(t.tracked(), 2);
    }

    #[test]
    fn a_table_full_of_blocked_sources_leaves_new_ones_untracked_2502() {
        let t = AuthBackoff::with_capacity(2);
        let now = Instant::now();
        fail_n(&t, v4(0), FREE_FAILURES + 1, now);
        fail_n(&t, v4(1), FREE_FAILURES + 1, now);
        assert_eq!(t.record_failure(v4(2), now), FailureEffect::Untracked);
        assert_eq!(t.tracked(), 2);
        assert!(t.blocked_for(v4(0), now).is_some());
        assert!(t.blocked_for(v4(1), now).is_some());
        let later = now + BASE_BACKOFF;
        assert_eq!(
            t.record_failure(v4(2), later),
            FailureEffect::Counted,
            "once a backoff ends that source may be dropped"
        );
    }

    #[test]
    fn ipv6_collapses_to_48_and_mapped_v4_is_v4_2502() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 1, 0xffff, 0xffff, 1, 2, 3);
        let c = Ipv6Addr::new(0x2001, 0xdb8, 2, 2, 0, 0, 0, 1);
        let ka = SourceKey::from_ip(IpAddr::V6(a));
        assert_eq!(ka, SourceKey::from_ip(IpAddr::V6(b)), "same /48");
        assert_ne!(ka, SourceKey::from_ip(IpAddr::V6(c)));
        assert_eq!(ka.to_string(), "2001:db8:1::/48");
        let mapped = Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped();
        assert_eq!(
            SourceKey::from_ip(IpAddr::V6(mapped)),
            SourceKey::V4(Ipv4Addr::new(198, 51, 100, 7))
        );
    }

    #[test]
    fn trusted_proxies_parse_and_reject_2502() {
        let (t, rejected) = TrustedProxies::parse(" 127.0.0.1, ::1, bogus, , ::ffff:10.0.0.6 ");
        assert_eq!(rejected, vec!["bogus".to_owned()]);
        assert!(t.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(t.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(
            t.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))),
            "a mapped address is stored as its IPv4 form"
        );
        assert!(TrustedProxies::parse("").0.is_empty());
    }

    #[test]
    fn forwarded_for_is_read_only_from_a_declared_proxy_2502() {
        let mut h = HeaderMap::new();
        h.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("203.0.113.9, 198.51.100.2"),
        );
        let remote: SocketAddr = "192.0.2.50:4000".parse().expect("addr");
        let local: SocketAddr = "127.0.0.1:4000".parse().expect("addr");
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:4000".parse().expect("addr");
        let loopback = SourceKey::V4(Ipv4Addr::LOCALHOST);
        let none = TrustedProxies::default();
        assert_eq!(
            source_for(local, &h, &none),
            loopback,
            "a loopback peer is not a proxy unless declared"
        );
        let (proxy, _) = TrustedProxies::parse("127.0.0.1");
        assert_eq!(
            source_for(remote, &h, &proxy),
            SourceKey::V4(Ipv4Addr::new(192, 0, 2, 50)),
            "an undeclared peer's header is client-written and ignored"
        );
        let hop = SourceKey::V4(Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(
            source_for(local, &h, &proxy),
            hop,
            "rightmost hop, not the first"
        );
        assert_eq!(
            source_for(mapped, &h, &proxy),
            hop,
            "an IPv4-mapped peer matches its IPv4 declaration"
        );
        let (chain, _) = TrustedProxies::parse("127.0.0.1, 198.51.100.2");
        assert_eq!(
            source_for(local, &h, &chain),
            SourceKey::V4(Ipv4Addr::new(203, 0, 113, 9)),
            "a declared proxy hop is skipped"
        );
        h.append(
            X_FORWARDED_FOR,
            HeaderValue::from_static("[2001:db8:9::1]:443"),
        );
        assert_eq!(
            source_for(local, &h, &proxy),
            SourceKey::from_ip("2001:db8:9::1".parse().expect("ip")),
            "the last line is the right end; a bracketed host:port parses"
        );
        let mut junk = HeaderMap::new();
        junk.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.2, unknown"),
        );
        assert_eq!(
            source_for(local, &junk, &proxy),
            loopback,
            "an unparseable hop falls back to the proxy"
        );
        let mut all_proxies = HeaderMap::new();
        all_proxies.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.2"));
        assert_eq!(
            source_for(local, &all_proxies, &chain),
            hop,
            "only proxies: the last proxy seen is the source"
        );
        assert_eq!(source_for(local, &HeaderMap::new(), &proxy), loopback);
        let long = std::iter::repeat_n("127.0.0.1", MAX_FORWARDED_HOPS + 1)
            .collect::<Vec<_>>()
            .join(", ");
        let mut deep = HeaderMap::new();
        deep.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_str(&format!("203.0.113.9, {long}")).expect("header"),
        );
        assert_eq!(
            source_for(local, &deep, &proxy),
            loopback,
            "the walk stops after MAX_FORWARDED_HOPS"
        );
    }

    #[test]
    fn refusal_carries_retry_after_rounded_up_2502() {
        let r = refusal(Duration::from_millis(1_500));
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from(2_u64))
        );
        let r = refusal(Duration::from_millis(1));
        assert_eq!(
            r.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from(1_u64))
        );
    }

    #[test]
    fn knob_is_default_on_with_the_shared_grammar_2502() {
        let knob = &crate::env_flag::knobs::AUTH_FAILURE_BACKOFF;
        assert_eq!(knob.env, ENV_AUTH_FAILURE_BACKOFF);
        assert!(knob.value_enabled(""), "unset keeps the default ON");
        assert!(knob.value_enabled("yes"));
        assert!(!knob.value_enabled("0"));
        assert!(!knob.value_enabled("OFF"));
        assert!(
            knob.value_enabled("maybe"),
            "an unrecognised token reads the secure side (the boot sweep refuses it)"
        );
    }

    /// Router whose one route answers like `api_key_auth`: `401` stamped
    /// [`AuthRejected`] unless the `ok` header is present.
    fn layered(table: &Arc<AuthBackoff>) -> axum::Router {
        use axum::routing::get;
        async fn gate(headers: axum::http::HeaderMap) -> Response {
            if headers.contains_key("ok") {
                StatusCode::OK.into_response()
            } else {
                AuthRejected::stamp(StatusCode::UNAUTHORIZED.into_response())
            }
        }
        axum::Router::new()
            .route("/x", get(gate))
            .route(super::super::routes::HEALTH, get(gate))
            .route("/plain", get(|| async { StatusCode::UNAUTHORIZED }))
            .layer(axum::middleware::from_fn_with_state(
                AuthBackoffState::with_table(Arc::clone(table), false),
                auth_backoff_layer,
            ))
    }

    async fn call(router: &axum::Router, path: &str, peer: Option<[u8; 4]>, ok: bool) -> Response {
        use tower::ServiceExt as _;
        let mut builder = axum::http::Request::builder().uri(path);
        if ok {
            builder = builder.header("ok", "1");
        }
        let mut req = builder.body(axum::body::Body::empty()).expect("request");
        if let Some(ip) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((ip, 40_000))));
        }
        router
            .clone()
            .oneshot(req)
            .await
            .expect("infallible router")
    }

    #[tokio::test]
    async fn layer_refuses_the_right_key_while_a_source_is_in_backoff_2502() {
        let table = Arc::new(AuthBackoff::default());
        let router = layered(&table);
        let attacker = Some([192, 0, 2, 7]);
        for _ in 0..=FREE_FAILURES {
            let r = call(&router, "/x", attacker, false).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        let r = call(&router, "/x", attacker, true).await;
        assert_eq!(
            r.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "right key refused too"
        );
        assert_eq!(
            r.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from(1_u64))
        );
        let other = call(&router, "/x", Some([192, 0, 2, 8]), true).await;
        assert_eq!(
            other.status(),
            StatusCode::OK,
            "another source is unaffected"
        );
        let health = call(&router, super::super::routes::HEALTH, attacker, true).await;
        assert_eq!(
            health.status(),
            StatusCode::OK,
            "the auth-exempt path is never refused"
        );
        let no_peer = call(&router, "/x", None, true).await;
        assert_eq!(
            no_peer.status(),
            StatusCode::OK,
            "no peer address: pass through"
        );
    }

    #[tokio::test]
    async fn only_stamped_rejections_count_2502() {
        let table = Arc::new(AuthBackoff::default());
        let router = layered(&table);
        let peer = Some([198, 51, 100, 1]);
        // A handler-level 401 that is not the transport-auth gate's is not
        // counted, and neither is anything on the auth-exempt path.
        for _ in 0..=FREE_FAILURES {
            call(&router, "/plain", peer, false).await;
            call(&router, super::super::routes::HEALTH, peer, false).await;
        }
        assert_eq!(table.tracked(), 0);
        assert_eq!(
            call(&router, "/x", peer, true).await.status(),
            StatusCode::OK
        );
    }

    #[test]
    fn poisoned_lock_is_recovered_2502() {
        let t = Arc::new(AuthBackoff::default());
        let t2 = Arc::clone(&t);
        let _ = std::thread::spawn(move || {
            let _guard = t2.table.lock();
            panic!("poison the table");
        })
        .join();
        assert!(t.table.is_poisoned());
        assert_eq!(
            t.record_failure(v4(9), Instant::now()),
            FailureEffect::Counted
        );
        assert_eq!(t.tracked(), 1);
    }
}
