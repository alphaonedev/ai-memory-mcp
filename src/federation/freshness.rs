// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3654 — per-peer federation freshness.
//!
//! Before #3654 the federation lane counted retries, drops, partial quorums
//! and aggregate DLQ depth, but nothing said WHICH peer had stopped
//! converging. Every catch-up failure (non-2xx, unreachable) went to a DEBUG
//! line, so an unreachable or rejecting peer could fall behind for days
//! without one INFO-level event or one alertable series. A quiet peer, a dead
//! worker, a partition and a peer that silently rejects our pushes all looked
//! the same.
//!
//! This module is the one place that remembers, per configured peer and per
//! direction (`pull` = our catch-up of the peer, `push` = our writes to the
//! peer):
//!
//! - when we last ATTEMPTED an exchange and when one last SUCCEEDED,
//! - how many attempts in a row have failed, and the class of the last one,
//! - the peer's clock offset as seen in its HTTP `Date` header,
//! - the per-peer push-DLQ backlog (depth and the oldest pending failure).
//!
//! Every timestamp is taken from THIS node's clock at the moment it observed
//! the outcome. Nothing a peer sends is used as a freshness timestamp, so a
//! peer with a skewed clock cannot make itself look fresh (or stale); its skew
//! is reported separately as a measurement.
//!
//! ## Telling the failure modes apart
//!
//! - quiet but healthy: pull attempts and successes keep advancing every
//!   catch-up interval; push attempts only advance when there is something to
//!   push, and every attempt succeeds.
//! - stopped accepting pushes: `last_attempt{direction="push"}` is newer than
//!   `last_success{direction="push"}` and `consecutive_failures` climbs.
//! - unreachable / partitioned: the same shape on `pull`, class `unreachable`.
//! - dead catch-up worker: `last_attempt{direction="pull"}` stops advancing;
//!   alert when its age exceeds a few multiples of
//!   `ai_memory_federation_catchup_interval_seconds`.
//!
//! ## Never a number we did not measure
//!
//! A series is only emitted after its first observation. A peer we have never
//! pushed to has NO push timestamp series, rather than a `0` that would read
//! as "failed in 1970" or, worse, be averaged into a healthy fleet.
//!
//! ## Logging
//!
//! A single failed attempt stays at the existing DEBUG level (transients are
//! normal). When a peer reaches [`ESCALATE_AFTER_CONSECUTIVE_FAILURES`]
//! failures in a row the registry emits a WARN, then again each time the
//! streak doubles (3, 6, 12, 24, …), so a peer that is down for a day costs a
//! dozen lines, not one per tick. The first success after an escalated streak
//! emits one INFO naming how long the peer was failing.
//!
//! ## Labels
//!
//! Series are labelled by [`peer_label`]: the minted `peer-h1…` id (fixed
//! width, bounded by configured membership, and the same key the DLQ and the
//! boot `registered peer` log line use, so operators can correlate), or a
//! legacy positional `peer-N`. Any other id is hashed first, because legacy
//! and test configurations have used the peer URL itself as the id and a URL
//! can carry credentials (#3667 is the same leak class).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::PeerEndpoint;

/// `tracing` target for every freshness escalation / recovery line.
pub const FRESHNESS_TRACE_TARGET: &str = "federation.peer_freshness";

/// Consecutive failed attempts in one direction before the registry escalates
/// from DEBUG to WARN. Three attempts rides out a restart or a single network
/// flap without paging anyone, and on the default catch-up cadence is still
/// well under a minute.
pub const ESCALATE_AFTER_CONSECUTIVE_FAILURES: u64 = 3;

/// Prefix of the label minted for a peer id that is not already a safe,
/// fixed-width identifier (see [`peer_label`]).
const HASHED_PEER_LABEL_PREFIX: &str = "peer-x";

/// Domain separator for the hashed label, so it can never collide with the
/// `peer-h1` derivation in `peer.rs`.
const HASHED_PEER_LABEL_DOMAIN: &[u8] = b"ai-memory:peer-label:v1\0";

/// Hex nibbles kept from the hashed label digest. 64 bits is ample for a
/// label space bounded by configured membership.
const HASHED_PEER_LABEL_NIBBLES: usize = 16;

/// Which way the exchange went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Our catch-up `GET /sync/since` against the peer.
    Pull,
    /// Our `POST /sync/push` to the peer (fan-out, DLQ replay or bulk catch-up).
    Push,
}

impl Direction {
    /// Closed-set Prometheus label value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Direction::Pull => "pull",
            Direction::Push => "push",
        }
    }
}

/// Closed set of failure classes (bounded label cardinality).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// HTTP 401 / 403: the peer does not accept our identity or key.
    Unauthorized,
    /// HTTP 429: a quota window on the peer.
    Throttled,
    /// Any other 4xx: the peer refused the request as malformed.
    Rejected,
    /// HTTP 5xx.
    ServerError,
    /// No HTTP response at all: connect, TLS or timeout failure.
    Unreachable,
    /// A 2xx whose body could not be read as the expected envelope.
    BadResponse,
    /// A 2xx whose own report says the items were NOT applied (#2341), or an
    /// id drift.
    NotApplied,
    /// The fan-out task itself failed (panicked or was cancelled).
    TaskFailed,
    /// Anything else, including a local refusal before the request was sent.
    Other,
}

impl FailureClass {
    /// Closed-set Prometheus label value.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            FailureClass::Unauthorized => "unauthorized",
            FailureClass::Throttled => "throttled",
            FailureClass::Rejected => "rejected",
            FailureClass::ServerError => "server_error",
            FailureClass::Unreachable => "unreachable",
            FailureClass::BadResponse => "bad_response",
            FailureClass::NotApplied => "not_applied",
            FailureClass::TaskFailed => "task_failed",
            FailureClass::Other => "other",
        }
    }

    /// Class of a non-2xx response, from its REAL status code.
    #[must_use]
    pub fn from_http_status(status: u16) -> Self {
        match status {
            401 | 403 => FailureClass::Unauthorized,
            429 => FailureClass::Throttled,
            500..=599 => FailureClass::ServerError,
            400..=499 => FailureClass::Rejected,
            _ => FailureClass::Other,
        }
    }

    /// Class of a push failure from the typed `AckOutcome` reason.
    ///
    /// Reads the #2672 leading class tag (a local, typed discriminant), never
    /// peer-supplied prose. The one refinement is 5xx: the DLQ taxonomy folds
    /// it into `other`, but the tag's detail is the locally formatted
    /// `http <status>` line built from the real status code, so a server error
    /// is still told apart from a client-side refusal here.
    #[must_use]
    pub(super) fn from_push_reason(reason: &str) -> Self {
        use super::dlq_class::DlqErrorClass;
        match super::dlq_class::class_of(reason) {
            DlqErrorClass::Network => FailureClass::Unreachable,
            DlqErrorClass::UnenrolledPeer => FailureClass::Unauthorized,
            DlqErrorClass::Throttle => FailureClass::Throttled,
            DlqErrorClass::Permanent => FailureClass::Rejected,
            DlqErrorClass::PeerRefused
            | DlqErrorClass::PeerUnsupported
            | DlqErrorClass::IdDrift => FailureClass::NotApplied,
            DlqErrorClass::PeerRemoved | DlqErrorClass::Queued | DlqErrorClass::Other => {
                if super::dlq_class::detail_of(reason).starts_with("http 5") {
                    FailureClass::ServerError
                } else {
                    FailureClass::Other
                }
            }
        }
    }
}

/// One observed outcome of an exchange with a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    /// The peer answered and (for pushes) applied what we sent.
    Success,
    /// The exchange failed.
    Failure(FailureClass),
}

/// What the registry knows about one direction of one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct DirectionFreshness {
    /// Unix seconds (local clock) of the last attempt, success or not.
    pub last_attempt_unix: Option<i64>,
    /// Unix seconds (local clock) of the last successful exchange.
    pub last_success_unix: Option<i64>,
    /// Failed attempts since the last success (0 after a success).
    pub consecutive_failures: u64,
    /// Class of the most recent failure, if the last attempt failed.
    pub last_failure_class: Option<&'static str>,
    /// Unix seconds (local clock) of the first failure of the current streak.
    pub failing_since_unix: Option<i64>,
}

/// What the registry knows about one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct PeerFreshness {
    /// Safe metric label for the peer (see [`peer_label`]).
    pub peer_label: String,
    /// True when the peer is part of this node's configured membership.
    pub configured: bool,
    /// Our catch-up of the peer.
    pub pull: DirectionFreshness,
    /// Our pushes to the peer.
    pub push: DirectionFreshness,
    /// Peer clock minus local clock, in whole seconds, from the peer's last
    /// HTTP `Date` header. `None` until a response carried a parseable one.
    pub clock_skew_seconds: Option<i64>,
    /// Pending push-DLQ rows for the peer, as of the last replay tick.
    pub push_dlq_depth: Option<i64>,
    /// Unix seconds of the oldest pending push-DLQ failure for the peer.
    /// `None` when the backlog is empty or has not been measured.
    pub push_dlq_oldest_failed_unix: Option<i64>,
}

impl PeerFreshness {
    fn direction_mut(&mut self, direction: Direction) -> &mut DirectionFreshness {
        match direction {
            Direction::Pull => &mut self.pull,
            Direction::Push => &mut self.push,
        }
    }
}

/// Per-peer DLQ backlog as read from the sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerDlqBacklog {
    /// `federation_push_dlq.peer_id`.
    pub peer_id: String,
    /// Pending rows for the peer.
    pub pending: i64,
    /// Unix seconds of the oldest pending row's `failed_at`, when parseable.
    pub oldest_failed_unix: Option<i64>,
}

fn table() -> MutexGuard<'static, HashMap<String, PeerFreshness>> {
    static TABLE: OnceLock<Mutex<HashMap<String, PeerFreshness>>> = OnceLock::new();
    // A panic while holding this lock can only leave a half-updated
    // bookkeeping entry, never corrupt durable state, so recover the guard
    // rather than take the whole federation lane down (CONCURRENCY-18).
    TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The metric / log label for `peer_id`.
///
/// A minted `peer-h1…` id or a legacy positional `peer-N` is returned
/// verbatim: both are short, fixed-shape and credential-free, and the minted
/// form is the key operators already use for DLQ triage. Anything else is
/// replaced by a domain-separated SHA-256 prefix, because an id of unknown
/// shape may be a URL and a URL may embed credentials.
#[must_use]
pub fn peer_label(peer_id: &str) -> String {
    if super::peer::is_minted_peer_id(peer_id) || super::peer::is_legacy_positional_peer_id(peer_id)
    {
        return peer_id.to_string();
    }
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(HASHED_PEER_LABEL_DOMAIN);
    hasher.update(peer_id.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let mut label =
        String::with_capacity(HASHED_PEER_LABEL_PREFIX.len() + HASHED_PEER_LABEL_NIBBLES);
    label.push_str(HASHED_PEER_LABEL_PREFIX);
    label.push_str(&digest[..HASHED_PEER_LABEL_NIBBLES]);
    label
}

/// True when a streak of `failures` consecutive failures should be logged at
/// WARN: at the threshold, then each time the streak doubles.
#[must_use]
pub fn is_escalation_point(failures: u64) -> bool {
    failures >= ESCALATE_AFTER_CONSECUTIVE_FAILURES
        && failures % ESCALATE_AFTER_CONSECUTIVE_FAILURES == 0
        && (failures / ESCALATE_AFTER_CONSECUTIVE_FAILURES).is_power_of_two()
}

/// Record the configured membership (the census). Called once per
/// `FederationConfig::build`.
pub fn note_configured(peers: &[PeerEndpoint]) {
    let metrics = crate::metrics::registry();
    let mut table = table();
    for peer in peers {
        let label = peer_label(&peer.id);
        let entry = table.entry(label.clone()).or_default();
        entry.peer_label.clone_from(&label);
        entry.configured = true;
        metrics
            .federation_peer_configured
            .with_label_values(&[label.as_str()])
            .set(1);
    }
}

/// Publish the catch-up cadence so a stalled catch-up worker is alertable
/// (`time() - last_attempt{direction="pull"}` against a multiple of it).
pub fn note_catchup_interval(interval: Duration) {
    crate::metrics::registry()
        .federation_catchup_interval_seconds
        .set(i64::try_from(interval.as_secs()).unwrap_or(i64::MAX));
}

/// Record one outcome of an exchange with `peer_id`.
pub fn record(peer_id: &str, direction: Direction, observation: Observation) {
    record_at(peer_id, direction, observation, now_unix());
}

fn record_at(peer_id: &str, direction: Direction, observation: Observation, now: i64) {
    let label = peer_label(peer_id);
    let (after, previous_failures, previous_failing_since) = {
        let mut table = table();
        let entry = table.entry(label.clone()).or_default();
        entry.peer_label.clone_from(&label);
        let state = entry.direction_mut(direction);
        let previous_failures = state.consecutive_failures;
        let previous_failing_since = state.failing_since_unix;
        state.last_attempt_unix = Some(now);
        match observation {
            Observation::Success => {
                state.last_success_unix = Some(now);
                state.consecutive_failures = 0;
                state.last_failure_class = None;
                state.failing_since_unix = None;
            }
            Observation::Failure(class) => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.last_failure_class = Some(class.as_label());
                if state.failing_since_unix.is_none() {
                    state.failing_since_unix = Some(now);
                }
            }
        }
        (state.clone(), previous_failures, previous_failing_since)
    };

    let metrics = crate::metrics::registry();
    let labels = [label.as_str(), direction.as_label()];
    metrics
        .federation_peer_last_attempt_timestamp_seconds
        .with_label_values(&labels)
        .set(now);
    metrics
        .federation_peer_consecutive_failures
        .with_label_values(&labels)
        .set(i64::try_from(after.consecutive_failures).unwrap_or(i64::MAX));

    match observation {
        Observation::Success => {
            metrics
                .federation_peer_last_success_timestamp_seconds
                .with_label_values(&labels)
                .set(now);
            if previous_failures >= ESCALATE_AFTER_CONSECUTIVE_FAILURES {
                let failing_for =
                    previous_failing_since.map_or(0, |since| now.saturating_sub(since));
                tracing::info!(
                    target: FRESHNESS_TRACE_TARGET,
                    peer = %label,
                    direction = direction.as_label(),
                    recovered_after_failures = previous_failures,
                    failing_for_seconds = failing_for,
                    "federation: peer {label} {dir} recovered after {previous_failures} consecutive \
                     failed attempts ({failing_for}s) (#3654)",
                    dir = direction.as_label(),
                );
            }
        }
        Observation::Failure(class) => {
            metrics
                .federation_peer_failures_total
                .with_label_values(&[label.as_str(), direction.as_label(), class.as_label()])
                .inc();
            if is_escalation_point(after.consecutive_failures) {
                let failing_for = after
                    .failing_since_unix
                    .map_or(0, |since| now.saturating_sub(since));
                tracing::warn!(
                    target: FRESHNESS_TRACE_TARGET,
                    peer = %label,
                    direction = direction.as_label(),
                    consecutive_failures = after.consecutive_failures,
                    class = class.as_label(),
                    failing_for_seconds = failing_for,
                    "federation: peer {label} {dir} has failed {n} consecutive attempts over \
                     {failing_for}s (last: {cls}); replication with this peer is not converging \
                     (#3654)",
                    dir = direction.as_label(),
                    n = after.consecutive_failures,
                    cls = class.as_label(),
                );
            }
        }
    }
}

/// Record a push outcome from the typed fan-out result.
pub(super) fn record_push_outcome(peer_id: &str, outcome: &super::sync::AckOutcome) {
    use super::sync::AckOutcome;
    let observation = match outcome {
        AckOutcome::Ack => Observation::Success,
        AckOutcome::IdDrift => Observation::Failure(FailureClass::NotApplied),
        AckOutcome::Throttled(_) => Observation::Failure(FailureClass::Throttled),
        AckOutcome::Fail(reason) => Observation::Failure(FailureClass::from_push_reason(reason)),
    };
    record(peer_id, Direction::Push, observation);
}

/// Peer clock minus `local_unix`, from an HTTP `Date` header value
/// (IMF-fixdate, one-second resolution). `None` when absent or unparseable.
#[must_use]
pub fn clock_skew_from_date_header(date: Option<&str>, local_unix: i64) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc2822(date?.trim()).ok()?;
    Some(parsed.timestamp().saturating_sub(local_unix))
}

/// Record the peer's clock offset from a response's `Date` header, measured
/// against the local clock when the response arrived.
pub fn record_response_clock(peer_id: &str, headers: &reqwest::header::HeaderMap) {
    let date = headers
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok());
    let Some(skew) = clock_skew_from_date_header(date, now_unix()) else {
        return;
    };
    let label = peer_label(peer_id);
    {
        let mut table = table();
        let entry = table.entry(label.clone()).or_default();
        entry.peer_label.clone_from(&label);
        entry.clock_skew_seconds = Some(skew);
    }
    crate::metrics::registry()
        .federation_peer_clock_skew_seconds
        .with_label_values(&[label.as_str()])
        .set(skew);
}

/// Publish the per-peer push-DLQ backlog read on a replay tick.
///
/// Every peer the registry knows about that is absent from `backlog` has an
/// empty backlog: its depth is set to 0 (a measurement) and its oldest-failure
/// series is removed (there is no oldest pending row, so no number).
pub fn record_push_dlq_backlog(backlog: &[PeerDlqBacklog]) {
    let metrics = crate::metrics::registry();
    let mut table = table();
    let mut seen: Vec<String> = Vec::with_capacity(backlog.len());
    for row in backlog {
        let label = peer_label(&row.peer_id);
        let entry = table.entry(label.clone()).or_default();
        entry.peer_label.clone_from(&label);
        entry.push_dlq_depth = Some(row.pending);
        entry.push_dlq_oldest_failed_unix = row.oldest_failed_unix;
        metrics
            .federation_peer_push_dlq_depth
            .with_label_values(&[label.as_str()])
            .set(row.pending);
        match row.oldest_failed_unix {
            Some(ts) => metrics
                .federation_peer_push_dlq_oldest_failed_timestamp_seconds
                .with_label_values(&[label.as_str()])
                .set(ts),
            None => {
                let _ = metrics
                    .federation_peer_push_dlq_oldest_failed_timestamp_seconds
                    .remove_label_values(&[label.as_str()]);
            }
        }
        seen.push(label);
    }
    for (label, entry) in table.iter_mut() {
        if seen.iter().any(|s| s == label) {
            continue;
        }
        entry.push_dlq_depth = Some(0);
        entry.push_dlq_oldest_failed_unix = None;
        metrics
            .federation_peer_push_dlq_depth
            .with_label_values(&[label.as_str()])
            .set(0);
        // Absent series is the expected state for an empty backlog; the
        // `Err` only means there was nothing to remove.
        let _ = metrics
            .federation_peer_push_dlq_oldest_failed_timestamp_seconds
            .remove_label_values(&[label.as_str()]);
    }
}

/// Snapshot of every peer the registry has seen, sorted by label.
#[must_use]
pub fn snapshot() -> Vec<PeerFreshness> {
    let mut peers: Vec<PeerFreshness> = table().values().cloned().collect();
    peers.sort_by(|a, b| a.peer_label.cmp(&b.peer_label));
    peers
}

/// Snapshot of one peer, by its (unlabelled) id.
#[must_use]
pub fn snapshot_for(peer_id: &str) -> Option<PeerFreshness> {
    table().get(&peer_label(peer_id)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique(tag: &str) -> String {
        format!("test-3654-{tag}-{}", uuid::Uuid::new_v4())
    }

    #[test]
    fn escalation_points_double_from_the_threshold() {
        let points: Vec<u64> = (0..=50).filter(|n| is_escalation_point(*n)).collect();
        assert_eq!(points, vec![3, 6, 12, 24, 48]);
    }

    #[test]
    fn minted_and_positional_ids_are_labelled_verbatim() {
        let minted = format!("peer-h1{}", "0123456789abcdef".repeat(2));
        assert_eq!(peer_label(&minted), minted);
        assert_eq!(peer_label("peer-7"), "peer-7");
    }

    #[test]
    fn url_shaped_ids_never_reach_a_label() {
        let id = "peer-0:https://admin:hunter2@peer.example:9077";
        let label = peer_label(id);
        assert!(label.starts_with(HASHED_PEER_LABEL_PREFIX), "{label}");
        assert_eq!(
            label.len(),
            HASHED_PEER_LABEL_PREFIX.len() + HASHED_PEER_LABEL_NIBBLES
        );
        assert!(!label.contains("hunter2") && !label.contains("peer.example"));
        assert_eq!(peer_label(id), label, "label must be stable");
    }

    #[test]
    fn failure_streak_resets_on_success_and_keeps_local_timestamps() {
        let peer = unique("streak");
        record_at(
            &peer,
            Direction::Pull,
            Observation::Failure(FailureClass::Unreachable),
            100,
        );
        record_at(
            &peer,
            Direction::Pull,
            Observation::Failure(FailureClass::ServerError),
            160,
        );
        let mid = snapshot_for(&peer).expect("peer recorded");
        assert_eq!(mid.pull.consecutive_failures, 2);
        assert_eq!(mid.pull.failing_since_unix, Some(100));
        assert_eq!(mid.pull.last_attempt_unix, Some(160));
        assert_eq!(
            mid.pull.last_success_unix, None,
            "never succeeded: no number"
        );
        assert_eq!(mid.pull.last_failure_class, Some("server_error"));
        assert_eq!(mid.push, DirectionFreshness::default(), "push untouched");

        record_at(&peer, Direction::Pull, Observation::Success, 220);
        let after = snapshot_for(&peer).expect("peer recorded");
        assert_eq!(after.pull.consecutive_failures, 0);
        assert_eq!(after.pull.last_success_unix, Some(220));
        assert_eq!(after.pull.failing_since_unix, None);
        assert_eq!(after.pull.last_failure_class, None);
    }

    #[test]
    fn http_status_classes_are_distinct() {
        assert_eq!(
            FailureClass::from_http_status(401),
            FailureClass::Unauthorized
        );
        assert_eq!(
            FailureClass::from_http_status(403),
            FailureClass::Unauthorized
        );
        assert_eq!(FailureClass::from_http_status(429), FailureClass::Throttled);
        assert_eq!(FailureClass::from_http_status(404), FailureClass::Rejected);
        assert_eq!(
            FailureClass::from_http_status(500),
            FailureClass::ServerError
        );
        assert_eq!(
            FailureClass::from_http_status(503),
            FailureClass::ServerError
        );
        assert_eq!(FailureClass::from_http_status(302), FailureClass::Other);
    }

    #[test]
    fn push_reasons_map_from_the_typed_tag() {
        use super::super::dlq_class::DlqErrorClass;
        let network = DlqErrorClass::Network.stamp("connection refused");
        assert_eq!(
            FailureClass::from_push_reason(&network),
            FailureClass::Unreachable
        );
        let server = DlqErrorClass::from_http_status(500).stamp("http 500 Internal Server Error");
        assert_eq!(
            FailureClass::from_push_reason(&server),
            FailureClass::ServerError
        );
        let unauthorized = DlqErrorClass::from_http_status(401).stamp("http 401 Unauthorized");
        assert_eq!(
            FailureClass::from_push_reason(&unauthorized),
            FailureClass::Unauthorized
        );
        let refused = DlqErrorClass::PeerRefused.stamp("peer skipped 1 item(s)");
        assert_eq!(
            FailureClass::from_push_reason(&refused),
            FailureClass::NotApplied
        );
        // An untagged reason whose prose mentions a 5xx is NOT trusted.
        assert_eq!(
            FailureClass::from_push_reason("peer said http 500"),
            FailureClass::Other
        );
    }

    #[test]
    fn clock_skew_is_peer_minus_local_and_tolerates_garbage() {
        // 2026-09-12T20:00:00Z
        let local = 1_789_243_200;
        let ahead = "Sat, 12 Sep 2026 20:01:30 GMT";
        assert_eq!(clock_skew_from_date_header(Some(ahead), local), Some(90));
        let behind = "Sat, 12 Sep 2026 19:59:00 GMT";
        assert_eq!(clock_skew_from_date_header(Some(behind), local), Some(-60));
        assert_eq!(clock_skew_from_date_header(Some("not a date"), local), None);
        assert_eq!(clock_skew_from_date_header(None, local), None);
    }

    #[test]
    fn empty_backlog_measures_zero_depth_and_drops_the_oldest_series() {
        let busy = unique("dlq-busy");
        let idle = unique("dlq-idle");
        record_at(&idle, Direction::Push, Observation::Success, 10);
        record_push_dlq_backlog(&[
            PeerDlqBacklog {
                peer_id: busy.clone(),
                pending: 4,
                oldest_failed_unix: Some(1_000),
            },
            PeerDlqBacklog {
                peer_id: idle.clone(),
                pending: 1,
                oldest_failed_unix: Some(2_000),
            },
        ]);
        assert_eq!(snapshot_for(&idle).unwrap().push_dlq_depth, Some(1));
        record_push_dlq_backlog(&[PeerDlqBacklog {
            peer_id: busy.clone(),
            pending: 4,
            oldest_failed_unix: Some(1_000),
        }]);
        let idle_after = snapshot_for(&idle).unwrap();
        assert_eq!(idle_after.push_dlq_depth, Some(0));
        assert_eq!(idle_after.push_dlq_oldest_failed_unix, None);
        let busy_after = snapshot_for(&busy).unwrap();
        assert_eq!(busy_after.push_dlq_depth, Some(4));
        assert_eq!(busy_after.push_dlq_oldest_failed_unix, Some(1_000));
    }
}
