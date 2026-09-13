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
//!   collapsed to its /64. A non-loopback peer's `X-Forwarded-For` is never
//!   read: the client writes it, so trusting it would let a guesser name a
//!   fresh source per request. A LOOPBACK peer is the same-host proxy
//!   `docs/ADMIN_GUIDE.md` recommends; keying on it would put every client
//!   behind it in one bucket, so its RIGHTMOST `X-Forwarded-For` hop (the
//!   one the proxy appended, which a client cannot replace) names the source.
//! * After [`FREE_FAILURES`] rejections, each further rejection puts the
//!   source in backoff for `1 s * 2^(k-1)`, capped at [`MAX_BACKOFF`]. A
//!   source in backoff gets `429` + `Retry-After` BEFORE its key is looked
//!   at, correct key included: answering a correct key during backoff would
//!   tell the guesser which key was right, and the guessing would not slow.
//! * A successful authentication does NOT clear the source: otherwise a
//!   caller holding one valid key could interleave valid requests with
//!   guesses at another key and never reach backoff. A source with no
//!   rejection for [`IDLE_RESET`] starts over. The table is bounded at
//!   [`MAX_TRACKED_SOURCES`]; the oldest-tracked source is dropped first, so
//!   the table cannot itself exhaust memory.
//! * A request with no peer address (a router driven without a TCP listener)
//!   passes untouched; a poisoned lock is recovered. The layer degrades to
//!   "no backoff", never to "deny".
//!
//! `AI_MEMORY_AUTH_FAILURE_BACKOFF` (default ON) switches the layer off with
//! a falsy token. Known trade-off: behind a proxy on ANOTHER host (or a same-
//! host proxy that does not append its hop) every client shares one source,
//! so one client presenting wrong keys puts all of them in backoff for at
//! most [`MAX_BACKOFF`].

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

/// Header a same-host proxy appends the client address to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

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

/// One source: an IPv4 address, or an IPv6 /64 (an IPv4-mapped IPv6 address
/// counts as its IPv4 address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// An IPv4 peer.
    V4(Ipv4Addr),
    /// The upper 64 bits of an IPv6 peer.
    V6Net(u64),
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
                    let mut net = [0_u8; 8];
                    net.copy_from_slice(&v6.octets()[..8]);
                    Self::V6Net(u64::from_be_bytes(net))
                }
            },
        }
    }
}

/// The source a request belongs to: the peer, or, for a loopback peer (a
/// same-host proxy), the rightmost `X-Forwarded-For` hop when it parses.
#[must_use]
pub fn source_for(peer: SocketAddr, headers: &HeaderMap) -> SourceKey {
    let ip = peer.ip().to_canonical();
    let forwarded = if ip.is_loopback() {
        rightmost_forwarded_hop(headers)
    } else {
        None
    };
    SourceKey::from_ip(forwarded.unwrap_or(ip))
}

/// The last hop of the last `X-Forwarded-For` line (several lines form one
/// list in order), as an address. `None` when absent or unparseable.
fn rightmost_forwarded_hop(headers: &HeaderMap) -> Option<IpAddr> {
    let line = headers.get_all(X_FORWARDED_FOR).iter().next_back()?;
    let hop = line.to_str().ok()?.rsplit(',').next()?.trim();
    hop.parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|s| s.ip()))
}

impl fmt::Display for SourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{v4}"),
            Self::V6Net(net) => {
                let [a, b, c, d] = [net >> 48, net >> 32, net >> 16, *net].map(|w| w & 0xffff);
                write!(f, "{a:x}:{b:x}:{c:x}:{d:x}::/64")
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
}

#[derive(Debug)]
struct Record {
    failures: u32,
    last_failure: Instant,
    blocked_until: Option<Instant>,
    seq: u64,
}

#[derive(Debug)]
struct Table {
    records: HashMap<SourceKey, Record>,
    /// Insertion order for eviction; entries whose `seq` no longer matches
    /// the live record are stale and skipped.
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
            table.insert_new(source, now);
        }
        let Some(record) = table.records.get_mut(&source) else {
            return FailureEffect::Counted;
        };
        record.failures = record.failures.saturating_add(1);
        record.last_failure = now;
        let past = record.failures.saturating_sub(FREE_FAILURES);
        if past == 0 {
            return FailureEffect::Counted;
        }
        let backoff = backoff_for(past);
        record.blocked_until = now.checked_add(backoff);
        FailureEffect::Backoff {
            failures: record.failures,
            backoff,
            first: past == 1,
        }
    }

    /// Sources currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.lock().records.len()
    }
}

impl Table {
    fn insert_new(&mut self, source: SourceKey, now: Instant) {
        while self.records.len() >= self.capacity {
            let Some((key, seq)) = self.order.pop_front() else {
                break;
            };
            if self.records.get(&key).is_some_and(|r| r.seq == seq) {
                self.records.remove(&key);
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.records.insert(
            source,
            Record {
                failures: 0,
                last_failure: now,
                blocked_until: None,
                seq,
            },
        );
        self.order.push_back((source, seq));
        self.compact();
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
}

impl AuthBackoffState {
    /// State from `AI_MEMORY_AUTH_FAILURE_BACKOFF` (default ON): a fresh table
    /// per router, so each daemon (and each test router) counts on its own.
    #[must_use]
    pub fn from_env(mtls_enforced: bool) -> Self {
        let table = crate::env_flag::knobs::AUTH_FAILURE_BACKOFF
            .enabled()
            .then(|| Arc::new(AuthBackoff::default()));
        Self {
            table,
            mtls_enforced,
        }
    }

    /// State over an explicit table.
    #[must_use]
    pub fn with_table(table: Arc<AuthBackoff>, mtls_enforced: bool) -> Self {
        Self {
            table: Some(table),
            mtls_enforced,
        }
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
        .map(|ConnectInfo(addr)| source_for(*addr, req.headers()))
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
        if let FailureEffect::Backoff {
            failures,
            backoff,
            first: true,
        } = table.record_failure(source, Instant::now())
        {
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

    #[test]
    fn table_is_bounded_oldest_dropped_first_2502() {
        let t = AuthBackoff::with_capacity(3);
        let now = Instant::now();
        fail_n(&t, v4(0), FREE_FAILURES, now);
        for i in 1..=3 {
            t.record_failure(v4(i), now);
        }
        assert_eq!(t.tracked(), 3, "the fourth source evicted the oldest");
        assert_eq!(
            t.record_failure(v4(0), now),
            FailureEffect::Counted,
            "an evicted source starts over"
        );
        for i in 10..60 {
            t.record_failure(v4(i), now + IDLE_RESET);
        }
        assert_eq!(t.tracked(), 3);
        assert!(t.lock().order.len() <= 6, "the order queue stays bounded");
    }

    #[test]
    fn ipv6_collapses_to_64_and_mapped_v4_is_v4_2502() {
        let a = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 1, 2, 3);
        let c = Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1);
        let ka = SourceKey::from_ip(IpAddr::V6(a));
        assert_eq!(ka, SourceKey::from_ip(IpAddr::V6(b)));
        assert_ne!(ka, SourceKey::from_ip(IpAddr::V6(c)));
        assert_eq!(ka.to_string(), "2001:db8:1:2::/64");
        let mapped = Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped();
        assert_eq!(
            SourceKey::from_ip(IpAddr::V6(mapped)),
            SourceKey::V4(Ipv4Addr::new(198, 51, 100, 7))
        );
    }

    #[test]
    fn forwarded_for_is_read_only_from_a_loopback_peer_2502() {
        let mut h = HeaderMap::new();
        h.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("203.0.113.9, 198.51.100.2"),
        );
        let remote: SocketAddr = "192.0.2.50:4000".parse().expect("addr");
        let local: SocketAddr = "127.0.0.1:4000".parse().expect("addr");
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:4000".parse().expect("addr");
        assert_eq!(
            source_for(remote, &h),
            SourceKey::V4(Ipv4Addr::new(192, 0, 2, 50)),
            "a remote peer's header is client-written and ignored"
        );
        let hop = SourceKey::V4(Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(source_for(local, &h), hop, "rightmost hop, not the first");
        assert_eq!(
            source_for(mapped, &h),
            hop,
            "an IPv4-mapped loopback peer too"
        );
        h.append(
            X_FORWARDED_FOR,
            HeaderValue::from_static("[2001:db8:9::1]:443"),
        );
        assert_eq!(
            source_for(local, &h),
            SourceKey::from_ip("2001:db8:9::1".parse().expect("ip")),
            "the last line wins; a bracketed host:port parses"
        );
        let mut junk = HeaderMap::new();
        junk.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.2, unknown"),
        );
        assert_eq!(
            source_for(local, &junk),
            SourceKey::V4(Ipv4Addr::LOCALHOST),
            "an unparseable hop falls back to the peer"
        );
        assert_eq!(
            source_for(local, &HeaderMap::new()),
            SourceKey::V4(Ipv4Addr::LOCALHOST)
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
