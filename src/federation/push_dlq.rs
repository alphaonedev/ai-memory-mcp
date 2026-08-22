// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Track D #933 — federation push DLQ + replay worker.
//!
//! ## What this module owns
//!
//! - The [`FederationDlqSink`] trait — abstract interface that
//!   `broadcast_store_quorum` calls into on per-peer fanout failure to
//!   record a `federation_push_dlq` row.
//! - The [`spawn_replay_federation_push_dlq`] task — spawned alongside
//!   the catchup loop in
//!   `daemon_runtime::spawn_catchup_loop_with_store`. Polls the DLQ
//!   every N seconds, re-attempts `post_once` against each peer, and
//!   stamps `replayed_at` (or DELETEs) on Ack.
//! - The [`federation_push_dlq_depth`] Prometheus gauge mirror — kept
//!   live by the replay worker.
//!
//! ## Why a DLQ
//!
//! Pre-#933 the per-peer push tasks inside `broadcast_store_quorum`
//! had no audit surface: if the leader's local commit succeeded but a
//! peer was unreachable (or slow past the deadline), nothing recorded
//! the missed push. On the peer's recovery the catchup loop pulled
//! rows the peer was behind on but the leader never re-attempted the
//! original push. Cross-recall consistency only worked when both
//! daemons shared a postgres store (Track B finding #925 masked the
//! gap). See the issue body for the full RCA.
//!
//! ## Contract surface
//!
//! - On a `Fail(reason)` or no-Ack-before-deadline per-peer outcome,
//!   `broadcast_store_quorum` calls
//!   [`FederationDlqSink::enqueue_push_failure`] with the memory id,
//!   peer id, payload body, and the failure reason.
//! - The sink writes a `federation_push_dlq` row (CREATE-or-bump-
//!   attempt_count via the partial unique index).
//! - The replay worker polls
//!   [`FederationDlqSink::take_pending_dlq_rows`] every N seconds and
//!   re-issues `post_once`. Successful Acks stamp `replayed_at` via
//!   [`FederationDlqSink::mark_dlq_row_replayed`].
//!
//! ## What this module deliberately does NOT do
//!
//! - No reverse direction. The DLQ is leader → peer. Peer → leader is
//!   covered by the existing catchup loop in `federation::receive`.
//! - No unbounded retry. Rows retry up to [`MAX_REPLAY_ATTEMPTS`]
//!   (~50 min at the default tick), then quarantine: the take query
//!   excludes them (#1578) and the
//!   `federation_push_dlq_quarantined` counter +
//!   `federation_push_dlq_depth` gauge are the operator alert
//!   surface. Quarantined rows are never silently dropped — the
//!   data-layer drain procedure lives in docs/TROUBLESHOOTING.md
//!   §federation-push-DLQ.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use super::FederationConfig;
use super::sync::{AckOutcome, post_once};

/// Tracing target for the push-DLQ enqueue + replay surface (this
/// module plus the enqueue branches in `sync::broadcast_store_quorum`
/// (#933) and `sync::broadcast_delete_quorum` (#2498)).
/// #1558 tracing-target SSOT.
pub(crate) const PUSH_DLQ_TRACE_TARGET: &str = "ai_memory::federation::push_dlq";

/// A single pending DLQ row, surfaced to the replay worker.
///
/// `payload_json` is the **newest failed push body** for this
/// `(memory_id, peer_id)` pair. `enqueue_push_failure` REFRESHES it on
/// every conflict (a re-failed push replaces the stale first-failure
/// body), so the replay re-POSTs the freshest attempted shape rather
/// than an outdated first snapshot; the receiver-side LWW
/// `insert_if_newer` makes replaying newer content safe. `attempt_count`
/// is the persisted retry counter — advisory for the worker's retry
/// loop, but ALSO the optimistic-concurrency token the Ack path uses
/// (`mark_dlq_row_replayed(id, attempt_count)`) so a concurrent failure
/// that upserts a fresher body between take-time and mark-time is not
/// lost.
#[derive(Debug, Clone)]
pub struct FederationPushDlqRow {
    pub id: i64,
    pub memory_id: String,
    pub peer_id: String,
    pub payload_json: serde_json::Value,
    pub attempt_count: i32,
    pub last_error: String,
    /// #2716 (CB-12) — the RFC3339 UTC instant this row's erasure /
    /// failed push was recorded (`federation_push_dlq.failed_at`). Read
    /// into the struct so the DB-less [`replay_once`] orchestrator can run
    /// the F9 restore-race guard on the POST path: a pending DELETE whose
    /// id is LIVE again locally with an `updated_at` at/after this instant
    /// is an AUTHORIZED restore that must SUPERSEDE the delete (never
    /// destroy the just-restored replica, #2666). Both backends normalise
    /// to RFC3339 (sqlite stores TEXT; postgres decodes `TIMESTAMPTZ` and
    /// `to_rfc3339()`s it here) so [`restore_supersedes`] compares
    /// backend-identically.
    pub failed_at: String,
}

/// Abstract dead-letter-queue interface backing the
/// `federation_push_dlq` table.
///
/// Concrete impls live in `src/db.rs` (sqlite legacy path) and
/// `src/store/postgres.rs` (postgres SAL path). Both adapters were
/// extended at v48 with the migration that ships this table.
///
/// The trait is intentionally small — three methods cover the full
/// happy path (enqueue on failure, list pending for replay, mark
/// success). No CLI surface ships at v0.7.0 (#1578); operator
/// inspection/drain is direct SQL per docs/TROUBLESHOOTING.md
/// §federation-push-DLQ.
#[async_trait::async_trait]
pub trait FederationDlqSink: Send + Sync {
    /// Insert a new pending row OR bump `attempt_count` + refresh
    /// `last_error` on an existing pending row for the same
    /// `(memory_id, peer_id)`. Implementations MUST be safe to call
    /// concurrently (the production call path inside
    /// `broadcast_store_quorum` runs in a per-fanout task).
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String>;

    /// Return up to `limit` pending rows ordered by `failed_at` ASC
    /// (oldest first so the replay worker drains the tail before
    /// fresh failures). Empty vector = nothing to replay.
    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String>;

    /// Mark a DLQ row as replayed (the peer Acked), GUARDED by the
    /// `attempt_count` observed at take-time so a concurrent failure that
    /// upserted a fresher body between the take and this call is not
    /// clobbered. Implementations stamp `replayed_at` (or DELETE) ONLY
    /// when the persisted row still carries `expected_attempt_count` and
    /// is still pending. Returns `Ok(true)` when exactly the observed row
    /// was marked, `Ok(false)` when 0 rows matched (a concurrent
    /// `enqueue_push_failure` bumped `attempt_count` mid-tick) — the
    /// caller then leaves the row pending for the next tick (fail-closed:
    /// re-deliver the newest body rather than lose the concurrent
    /// failure).
    async fn mark_dlq_row_replayed(
        &self,
        id: i64,
        expected_attempt_count: i32,
    ) -> Result<bool, String>;

    /// Bump `attempt_count` + refresh `last_error` on an existing
    /// pending row. Used by the replay worker when a retry attempt
    /// itself fails (so operators can tell from `attempt_count` how
    /// long the row has been stuck).
    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String>;

    /// Return the current number of pending DLQ rows. Used by the
    /// replay worker to maintain the `federation_push_dlq_depth`
    /// Prometheus gauge.
    async fn pending_dlq_count(&self) -> Result<i64, String>;

    /// #1544 — refresh `last_error` on a pending row WITHOUT bumping
    /// `attempt_count`. Called when a replay attempt is THROTTLED (peer
    /// 429): the row is left pending so it converges once the quota
    /// window rolls, and the attempt budget is preserved so a transient
    /// throttle never quarantines a valid row. Recording the throttle
    /// reason lets the cause-label classifier + the un-quarantine sweep
    /// recognise the row.
    async fn note_dlq_throttled(&self, id: i64, last_error: &str) -> Result<(), String>;

    /// #1544 — un-quarantine rows that were quarantined SOLELY because a
    /// 429 throttle burned their `attempt_count` past
    /// [`MAX_REPLAY_ATTEMPTS`] before the quota window rolled. Resets
    /// `attempt_count = 0` for pending rows at/over the ceiling whose
    /// `last_error` indicates a throttle (429) — scoped to throttles so
    /// genuinely-systematic failures (signature/schema refusals) stay
    /// quarantined (resetting those would resume infinite no-op POST
    /// amplification). Returns the number of rows un-quarantined.
    async fn reset_throttled_quarantine(&self) -> Result<u64, String>;

    /// #2446 — expand ONE erasure-outbox sentinel row (a row whose
    /// `peer_id` is [`crate::federation::erasure_outbox::ALL_PEERS_SENTINEL_PEER_ID`])
    /// into per-peer delete rows, then clear the sentinel — all in ONE
    /// transaction.
    ///
    /// The MCP / CLI erasure funnels cannot key a row per peer (they never
    /// construct a `FederationConfig` — see the `erasure_outbox` module
    /// docs), so they queue ONE sentinel meaning "fan out to every
    /// currently-configured peer". The DAEMON owns the live peer set, so
    /// the expansion happens here on the first drain tick. After it,
    /// everything downstream — attempt budget, quarantine, cause labels,
    /// depth gauge, operator drain — is the existing per-peer machinery,
    /// unchanged.
    ///
    /// ## The restore-after-delete guard (data integrity)
    ///
    /// Implementations MUST first check whether `memory_id` is LIVE in
    /// `memories` and, if so, return
    /// [`SentinelExpansion::SupersededByLiveRow`] WITHOUT writing any
    /// per-peer row (the sentinel is still cleared). A queued erasure that
    /// replays AFTER the id was legitimately restored locally would
    /// DESTROY the peer's copy of a row this node currently holds — the
    /// highest-order harm under the repo's North Star. The outbox has a
    /// drain delay the inline broadcast does not, so it can and must
    /// re-check.
    ///
    /// `expected_attempt_count` is the optimistic-concurrency token
    /// observed at take-time (same contract as [`Self::mark_dlq_row_replayed`]):
    /// when the persisted row no longer carries it, implementations MUST
    /// write nothing and return [`SentinelExpansion::Contended`] so the
    /// next tick re-reads the row.
    ///
    /// # Errors
    ///
    /// Returns the formatted backend error when the transaction fails. The
    /// caller leaves the sentinel pending and retries on the next tick.
    async fn expand_erasure_sentinel(
        &self,
        row_id: i64,
        expected_attempt_count: i32,
        memory_id: &str,
        peer_ids: &[String],
        per_peer_payload: &serde_json::Value,
        per_peer_last_error: &str,
    ) -> Result<SentinelExpansion, String>;

    /// #2716 (CB-12) F9 — the replay-POST-path restore-race guard.
    ///
    /// Returns `true` when the local `memories` row for `memory_id` is
    /// LIVE **and** its `updated_at` is at or after `erasure_failed_at` —
    /// i.e. an AUTHORIZED restore / re-store (which stamps `updated_at =
    /// now`) POST-DATES the queued erasure. In that case the pending
    /// DELETE (an erasure-outbox per-peer row OR a #2498 delete-lane DLQ
    /// landing) MUST be SUPERSEDED — never POSTed — or it would destroy
    /// the just-restored copy on the peer (the #2666 hazard, narrowed but
    /// not closed by the one-shot liveness probe inside
    /// [`Self::expand_erasure_sentinel`]).
    ///
    /// Returns `false` when the id is not live locally, or when the live
    /// row's `updated_at` PRE-dates the erasure (an LWW resurrection
    /// carries the peer's original pre-delete `updated_at`) — so a
    /// legitimate erasure still propagates.
    ///
    /// The comparison is [`restore_supersedes`] (parsed RFC3339 instants,
    /// fail-safe toward supersede). `erasure_failed_at` is the pending
    /// row's own [`FederationPushDlqRow::failed_at`]; because the
    /// authorized-restore branch (the only one that can classify a LIVE
    /// row as superseded) stamps `updated_at` from the SAME node that
    /// queued `failed_at`, the dangerous "silent-delete a restored row"
    /// direction cannot arise from clock skew.
    ///
    /// # Errors
    ///
    /// Returns the formatted backend error on a read failure. The caller
    /// FAILS SAFE: it leaves the pending delete UNSENT for the tick rather
    /// than risk destroying a possibly-restored replica.
    async fn erasure_delete_superseded_by_restore(
        &self,
        memory_id: &str,
        erasure_failed_at: &str,
    ) -> Result<bool, String>;
}

/// #2716 (CB-12) — decide whether a LIVE row's `updated_at` supersedes a
/// queued erasure's `failed_at`, comparing them as PARSED RFC3339 instants
/// (never lexically — a lexical compare misorders the many RFC3339
/// renderings of one instant).
///
/// Fail-safe: an unparseable timestamp on EITHER side returns `true`
/// (treat as SUPERSEDED → do NOT delete → preserve the live row), because
/// the North Star ranks "never cause unintentional data loss" ABOVE
/// "purged content must not resurrect". A false-supersede leaves a loud,
/// operator-re-issuable erasure pending; a false-delete destroys data.
#[must_use]
pub(crate) fn restore_supersedes(live_updated_at: &str, erasure_failed_at: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(live_updated_at),
        chrono::DateTime::parse_from_rfc3339(erasure_failed_at),
    ) {
        (Ok(live), Ok(failed)) => live >= failed,
        _ => true,
    }
}

/// #2716 — is this pending DLQ payload a DELETE (a `deletions:[...]`
/// body)? Only delete-shaped rows pay the F9 restore-race re-check on the
/// replay POST path; store / link / catch-up rows fall straight through.
fn payload_is_delete(payload: &serde_json::Value) -> bool {
    payload
        .get("deletions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|d| !d.is_empty())
}

/// #2446 — outcome of one erasure-outbox sentinel expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentinelExpansion {
    /// The sentinel was expanded into `n` per-peer rows and cleared.
    Expanded(u64),
    /// The memory id is LIVE again locally — a legitimate restore
    /// superseded the queued erasure, so NO delete was fanned out and the
    /// sentinel was cleared. Never propagating a stale erasure over a
    /// restored row is the fail-safe direction: it leaves data intact
    /// rather than destroying a replica.
    SupersededByLiveRow,
    /// A concurrent writer changed the row between take-time and now; the
    /// sentinel is left pending for the next tick.
    Contended,
}

/// Spawn the federation push DLQ replay worker.
///
/// Runs alongside the catchup loop (also in `daemon_runtime`). Every
/// `interval` ticks it:
///
/// 1. Reads up to `backlog.clamp(REPLAY_BATCH_SIZE, replay_max_batch())`
///    pending rows from the sink (#1579 B5 adaptive batch — the
///    fixed-64 take capped bulk drains at 128 rows/min/peer).
/// 2. For each row, attempts `post_once` against the matching peer's
///    `sync_push_url`. On `AckOutcome::Ack` it stamps `replayed_at`
///    via `mark_dlq_row_replayed`. On any other outcome it bumps the
///    row's `attempt_count` so operators alerting on the
///    `federation_push_dlq_depth` gauge can tell which rows are
///    repeatedly failing.
/// 3. Updates the `ai_memory_federation_push_dlq_depth` Prometheus
///    gauge to the current pending count.
///
/// Errors are logged at `tracing::warn` but never propagated — the
/// worker is best-effort by design (same posture as the catchup
/// loop).
///
/// Returns a `JoinHandle` so the bootstrap can hold it for the
/// lifetime of the daemon (it intentionally never terminates).
#[must_use]
pub fn spawn_replay_federation_push_dlq(
    config: FederationConfig,
    sink: Arc<dyn FederationDlqSink>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Same upfront delay as the catchup loop so the first replay
        // tick doesn't fire before the daemon's HTTP server has bound
        // — avoids spurious "connection refused" on a fresh cluster
        // boot if the peer is also coming up.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            replay_once(&config, sink.as_ref()).await;
            tokio::time::sleep(interval).await;
        }
    })
}

/// Baseline batch size for one replay tick — also the floor of the
/// #1579 B5 adaptive batch below. Tuned high enough to drain a
/// steady-state backlog quickly (a peer down for an hour with a
/// 100/min ingest rate accumulates ~6000 rows) but low enough that a
/// single tick won't monopolise the runtime if every replay attempt
/// itself succeeds against a peer that's now healthy.
pub const REPLAY_BATCH_SIZE: usize = 64;

/// #1579 B5 — env knob naming the upper cap of the adaptive replay
/// batch. The fixed 64-row tick gave a drain ceiling of 128 rows/min/
/// peer at the 30s cadence — a 62k-row backlog (the #1578 event) took
/// 8+ hours to drain. The worker now scales the per-tick take to
/// `backlog.clamp(REPLAY_BATCH_SIZE, cap)`; this env var overrides the
/// compiled cap ([`DEFAULT_REPLAY_MAX_BATCH`]). Zero / garbage values
/// fall through to the default (house style — a stray `0` can never
/// wedge the drain). Quarantine semantics (`MAX_REPLAY_ATTEMPTS`, the
/// #1578 `attempt_count` take-exclusion) are unchanged.
pub const ENV_FED_DLQ_REPLAY_MAX_BATCH: &str = "AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH";

/// #1579 B5 — compiled default for the adaptive replay-batch cap.
/// 2048 rows/tick at the default 30s cadence = ~4096 rows/min/peer
/// bulk-drain ceiling (vs the fixed-64 ceiling of 128/min), while
/// bounding per-tick memory: DLQ payloads are single-memory push
/// bodies (KB-scale), so a full cap-sized take stays in the low tens
/// of MB even on a 62k-row backlog.
pub const DEFAULT_REPLAY_MAX_BATCH: usize = 2048;

/// #1579 B5 — resolve the adaptive replay-batch cap: env override
/// ([`ENV_FED_DLQ_REPLAY_MAX_BATCH`]) > compiled default. Values that
/// fail to parse, are zero, or undercut the [`REPLAY_BATCH_SIZE`]
/// floor fall through to the default with a warn — the cap may never
/// shrink the worker below its historical fixed batch.
#[must_use]
pub fn replay_max_batch() -> usize {
    match std::env::var(ENV_FED_DLQ_REPLAY_MAX_BATCH) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(v) if v >= REPLAY_BATCH_SIZE => v,
            _ => {
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    raw = %raw,
                    "ignoring {ENV_FED_DLQ_REPLAY_MAX_BATCH}={raw} (must be an integer >= \
                     {REPLAY_BATCH_SIZE}); using default {DEFAULT_REPLAY_MAX_BATCH}"
                );
                DEFAULT_REPLAY_MAX_BATCH
            }
        },
        Err(_) => DEFAULT_REPLAY_MAX_BATCH,
    }
}

/// #1032 (HIGH, 2026-05-21) — quarantine threshold for DLQ rows.
///
/// Pre-#1032 the replay worker retried every pending row forever. A
/// row that systematically rejects (peer-side schema validation
/// refusal, leader-side key rotation invalidating the signature, or
/// per-row size cap mismatch) would accumulate `attempt_count`
/// indefinitely while the worker kept re-issuing HTTP POSTs to the
/// peer every tick (network amplification) AND the `pending_dlq_count`
/// gauge would never settle. Once `attempt_count >= MAX_REPLAY_ATTEMPTS`
/// the row is *quarantined*: the take query EXCLUDES it (#1578 — the
/// pre-fix exclusion happened only in-loop, so once a full batch of
/// oldest rows hit the ceiling they starved the take set and the
/// queue wedged), the `federation_push_dlq_quarantined` Prometheus
/// counter increments, and the operator gets a tracing::warn line.
/// No CLI drain ships at v0.7.0; the data-layer drain procedure is
/// documented in docs/TROUBLESHOOTING.md §federation-push-DLQ.
///
/// 100 attempts at ~30-second tick cadence = ~50 minutes of retries
/// before quarantine. That's generous for legitimate transient
/// failures (peer restart, network blip) and tight enough to surface
/// systematic-rejection footguns quickly.
pub const MAX_REPLAY_ATTEMPTS: i32 = 100;

/// #1544 — env knob for the federation push-DLQ depth WARN threshold.
const FED_DLQ_DEPTH_WARN_THRESHOLD_ENV: &str = "AI_MEMORY_FED_DLQ_DEPTH_WARN_THRESHOLD";
/// Compiled default depth at which the rising-edge WARN fires.
const DEFAULT_FED_DLQ_DEPTH_WARN_THRESHOLD: i64 = 1000;

/// Resolve the depth-WARN threshold (env > compiled default). A
/// non-positive / unparseable value falls through to the default.
fn dlq_depth_warn_threshold() -> i64 {
    std::env::var(FED_DLQ_DEPTH_WARN_THRESHOLD_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_FED_DLQ_DEPTH_WARN_THRESHOLD)
}

/// #1544 — rising-edge tracker so the DLQ-depth WARN fires ONCE when the
/// depth crosses up through the threshold (and an INFO once on recovery
/// below it), not every replay tick — a per-tick WARN at 80k rows would
/// drown the very signal it is meant to be. `0` = below, `1` = at/over.
static DLQ_DEPTH_OVER_THRESHOLD: AtomicI64 = AtomicI64::new(0);

use crate::federation::peer::is_legacy_positional_peer_id;
use crate::federation::receive_auth::{
    CAUSE_NAMESPACE_PROBE_UNRESOLVABLE, CAUSE_UNENROLLED_AUTHOR_STRICT,
};

/// #2442 — marker prefixed onto `last_error` when a DLQ row is found to carry
/// a pre-#2442 POSITIONAL routing key.
///
/// Deliberately NOT fed to [`classify_quarantine_cause`]. That classifier is
/// an ORDERED SUBSTRING matcher over `last_error`, and while no peer-supplied
/// TEXT reaches that string (every producer formats only counts, a status
/// code, or a local error), a peer-supplied INTEGER does:
/// `sync::success_report_non_ack_reason` interpolates the receiver's own
/// `skipped` count via `as_u64`. A peer answering 200 with `{"skipped": 429}`
/// therefore mints a `last_error` containing `429` — which already matches
/// this classifier's FIRST arm (`quota`) and `reset_throttled_quarantine`'s
/// `LIKE '%429%'` on both backends, resetting `attempt_count = 0` forever and
/// defeating the quarantine ceiling (#2672). Adding an arm keyed on a token in
/// this string would widen that same laundering surface. It would ALSO
/// override the row's real quarantine cause: a legacy-keyed row that was
/// already failing `http 400` is still a `permanent` row, and the routing key
/// is the secondary fact. The legacy condition is decided from the SHAPE of
/// `row.peer_id` — structured input a peer cannot influence — and surfaced on
/// its own counter (`ai_memory_federation_push_dlq_legacy_positional_total`),
/// never by string-matching an error message.
const LEGACY_PEER_ID_MARKER: &str = "[#2442 legacy positional peer_id]";

/// #2442 — has this row's `last_error` already been annotated with
/// [`LEGACY_PEER_ID_MARKER`]?
///
/// Re-annotating on every tick would append the marker ~100 times before the
/// row quarantines and grow `last_error` without bound. Annotating exactly
/// once keeps the ORIGINAL enqueue reason — the forensic record of why the
/// write was undelivered in the first place — verbatim and permanent inside
/// the string.
fn already_marked_legacy(last_error: &str) -> bool {
    last_error.starts_with(LEGACY_PEER_ID_MARKER)
}

/// #2442 — fires the operator-facing WARN once per process rather than once
/// per row per tick. A large legacy backlog would otherwise emit the same
/// paragraph thousands of times a minute and drown the signal it exists to
/// raise — the same reasoning as the edge-triggered depth alarm above.
static LEGACY_PEER_ID_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// #1544 — map a free-text DLQ `last_error` to a CLOSED-set quarantine
/// cause label so the Prometheus label cardinality is bounded by
/// construction (never the raw string). `quota` is operator-actionable
/// (raise `AI_MEMORY_MAX_MEMORIES_PER_DAY` / wait for the daily reset);
/// `permanent` is a broken row needing a manual drain.
fn classify_quarantine_cause(last_error: &str) -> &'static str {
    if last_error.contains("429") {
        "quota"
    } else if last_error.contains(CAUSE_UNENROLLED_AUTHOR_STRICT) {
        // #1801→#1954 item 7 — a honored third-party relayed write refused
        // under the v1.0.0 write-sig flip because the ORIGIN author has no
        // locally-enrolled key. Distinct from `unenrolled_peer` (the transport
        // peer): here the PEER is enrolled but the attributed AUTHOR is not.
        // Operator-actionable — enroll the author's key at the receiving node
        // (the manual substitute for the deferred TOFU key distribution).
        CAUSE_UNENROLLED_AUTHOR_STRICT
    } else if last_error.contains(CAUSE_NAMESPACE_PROBE_UNRESOLVABLE) {
        // #2488 — the receiver could not RESOLVE the target row's namespace, so
        // the federated-delete scope gate failed closed. Distinct from a scope
        // refusal: the peer's config is fine and the row is un-erasable until
        // the read succeeds. Operator-actionable at the RECEIVER's storage, not
        // at the sender's allowlist.
        //
        // STILL DORMANT after #2498. The delete lane now DOES enqueue, so the
        // refused deletion reaches the DLQ and is retried — but this specific
        // LABEL remains unreachable, and #2498 did not change that. The
        // receiver emits the `namespace_probe_unresolvable` token ONLY as a
        // `tracing` field (`src/handlers/federation_receive.rs:892,2168,2494,
        // 2600`; `src/handlers/federation_signing_check.rs:671`) and never in
        // the HTTP 200 response body — the body carries only the `skipped`
        // counter — so the sender's `last_error` is #2341's
        // `success_report_non_ack_reason` text ("peer 2xx but N item(s)
        // skipped …") and can never contain the token. The remaining
        // precondition is a RECEIVER-side wire change that echoes the cause in
        // the 200 body (a wire-shape change needing its own vote, #2498 §3 of
        // the issue). Classified here so the closed label set is already
        // correct when that lands, and so the token has exactly one meaning
        // across the substrate.
        CAUSE_NAMESPACE_PROBE_UNRESOLVABLE
    } else if last_error.contains("401") || last_error.contains("403") {
        // The replay last_error is the `http {status}` shape, so 401/403
        // is the enrolment/auth signal (the peer's JSON `peer_not_enrolled`
        // body is not carried in last_error).
        "unenrolled_peer"
    } else if last_error.contains("id_drift") {
        "id_drift"
    } else if last_error.contains("no longer in FederationConfig") {
        "peer_removed"
    } else if last_error.contains("400")
        || last_error.contains("422")
        || last_error.contains("signature")
        || last_error.contains("schema")
        // #2341 — a 2xx whose receiver report counted the push
        // `unsupported_on_postgres` is structurally un-appliable on that
        // peer (FED-RQ-01 subcollection gap), not a transient flap.
        || last_error.contains(crate::handlers::UNSUPPORTED_ON_POSTGRES_FIELD)
    {
        "permanent"
    } else {
        "other"
    }
}

/// Drive one replay pass. Public so the integration test in
/// `tests/federation_dlq_replay.rs` can advance the worker manually
/// without waiting on the `tokio::time::sleep` cadence.
pub async fn replay_once(config: &FederationConfig, sink: &dyn FederationDlqSink) {
    // #1544 — before draining, un-quarantine rows that were quarantined
    // SOLELY because a 429 throttle (per-agent / federation quota window)
    // burned their attempt budget past MAX_REPLAY_ATTEMPTS before the
    // window rolled (the #1535 atlas-corpus burst stalled ~75k valid
    // rows this way). Throttle-scoped, so genuinely-systematic failures
    // stay quarantined. Cheap bounded UPDATE that no-ops when nothing is
    // throttle-quarantined.
    match sink.reset_throttled_quarantine().await {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            target: PUSH_DLQ_TRACE_TARGET,
            "replay: un-quarantined {n} throttle-stalled (429) DLQ row(s) for retry"
        ),
        Err(e) => tracing::warn!(
            target: PUSH_DLQ_TRACE_TARGET,
            "replay: reset_throttled_quarantine failed (non-fatal): {e}"
        ),
    }
    // #1579 B5 — adaptive drain batch. Scale the per-tick take with
    // the live backlog (`min(backlog, configurable cap)`, floored at
    // the historical REPLAY_BATCH_SIZE) so a bulk backlog drains at
    // thousands of rows/min instead of the fixed-64 ceiling of
    // 128/min, while an idle queue keeps paying exactly one small
    // SELECT per tick. A count error degrades to the legacy fixed
    // batch — the worker stays best-effort.
    let batch = match sink.pending_dlq_count().await {
        Ok(backlog) => usize::try_from(backlog)
            .unwrap_or(REPLAY_BATCH_SIZE)
            .clamp(REPLAY_BATCH_SIZE, replay_max_batch()),
        Err(e) => {
            tracing::warn!(
                target: PUSH_DLQ_TRACE_TARGET,
                "replay_federation_push_dlq: pending count failed ({e}); \
                 using fixed batch {REPLAY_BATCH_SIZE}"
            );
            REPLAY_BATCH_SIZE
        }
    };
    let rows = match sink.take_pending_dlq_rows(batch).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: PUSH_DLQ_TRACE_TARGET,
                "replay_federation_push_dlq: failed to load pending rows: {e}"
            );
            return;
        }
    };

    if rows.is_empty() {
        // Still refresh the gauge — operators alert on it sitting at
        // 0 long-term; an unreachable sink would otherwise leave the
        // gauge stale.
        refresh_depth_gauge(sink).await;
        return;
    }

    tracing::info!(
        target: PUSH_DLQ_TRACE_TARGET,
        rows = rows.len(),
        "federation: replay_federation_push_dlq draining {} row(s)",
        rows.len(),
    );

    for row in rows {
        // #1032 — skip rows that have exceeded the replay-attempt
        // ceiling. The row stays in the DLQ (operator can inspect /
        // drain manually) but the worker no longer wastes network
        // bandwidth re-issuing POSTs that systematically fail.
        if row.attempt_count >= MAX_REPLAY_ATTEMPTS {
            crate::metrics::registry()
                .federation_push_dlq_quarantined
                .inc();
            // #1544 — cause-labeled sibling counter (closed-set label).
            let cause = classify_quarantine_cause(&row.last_error);
            crate::metrics::registry()
                .federation_push_dlq_quarantined_by_cause
                .with_label_values(&[cause])
                .inc();
            if cause == "quota" {
                // Operator-actionable: name the remediation explicitly.
                // (Post-#1544 a 429 is a Throttle that never burns an
                // attempt, so reaching quarantine via a quota cause means
                // a peer-side throttle the leader cannot classify — still
                // recoverable by raising the cap or waiting for the reset.)
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    peer_id = %row.peer_id,
                    memory_id = %row.memory_id,
                    cause,
                    "replay: row {} quarantined with a QUOTA (429) cause — raise \
                     AI_MEMORY_MAX_MEMORIES_PER_DAY on the peer or wait for the daily \
                     quota window to reset; the row will converge once admitted (#1544)",
                    row.id,
                );
            } else {
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    peer_id = %row.peer_id,
                    memory_id = %row.memory_id,
                    attempt_count = row.attempt_count,
                    cause,
                    "replay: row {} quarantined after {} attempts (ceiling {MAX_REPLAY_ATTEMPTS}, \
                     cause={cause}); no CLI drain surface ships at v0.7.0 — see \
                     docs/TROUBLESHOOTING.md §federation-push-DLQ for the data-layer drain \
                     procedure (#1578)",
                    row.id,
                    row.attempt_count,
                );
            }
            continue;
        }

        // #2446 — erasure-outbox sentinel expansion. This MUST run BEFORE
        // the peer-resolution branch below: the sentinel is not a peer id,
        // so `find(|p| p.id == row.peer_id)` would miss it and the row
        // would be bumped every tick under the LIE `peer_removed` (a real
        // `classify_quarantine_cause` label) until quarantine — an erasure
        // silently converted into an operator-drain chore. It runs AFTER
        // the quarantine ceiling above so a sentinel whose expansion is
        // systematically failing still quarantines (its `last_error` is
        // then a backend error, which classifies as the honest catch-all
        // `other`, never a fabricated cause).
        if row.peer_id == super::erasure_outbox::ALL_PEERS_SENTINEL_PEER_ID {
            expand_erasure_sentinel_row(config, sink, &row).await;
            continue;
        }

        // Resolve the peer URL via the live FederationConfig. If the
        // peer has been removed from the config since the DLQ row was
        // written, log + bump attempt_count + leave the row for the
        // operator to drain manually.
        //
        // #2442 — this `find` is EXACTLY where the positional-id defect
        // detonated: with `id = peer-{i}`, decommissioning one peer shifted
        // every higher index down, so this lookup SUCCEEDED against the wrong
        // host, POSTed another tenant's content there, and stamped the row
        // `replayed_at`. Peer ids are now derived from peer identity, so a
        // surviving peer is never re-keyed and this lookup can only fail —
        // never succeed against the wrong endpoint. What remains is
        // classifying WHY it failed.
        let Some(peer) = config.peers.iter().find(|p| p.id == row.peer_id) else {
            // #2442 — a row written by a PRE-fix binary carries a positional
            // routing key that this binary can no longer resolve. We refuse
            // to remap `peer-N` -> `config.peers[N]`: that mapping is only
            // correct if the peer list has not changed since the row was
            // written, and a binary upgrade is precisely when operators DO
            // change it. Guessing would reintroduce the misdelivery this
            // issue exists to close. DEGRADE (loud, actionable quarantine)
            // beats CORRUPT (content to the wrong host). The cost is stated
            // in the message: these rows stop retrying and need an
            // operator-supplied re-key.
            if is_legacy_positional_peer_id(&row.peer_id) {
                crate::metrics::registry()
                    .federation_push_dlq_legacy_positional
                    .inc();
                // Annotate `last_error` EXACTLY ONCE, preserving the original
                // enqueue reason verbatim after the marker. `bump_dlq_attempt`
                // overwrites `last_error`, so a naive constant reason would
                // permanently destroy the forensic record of why this write
                // was undelivered — the row IS that record.
                //
                // The attempt bump itself is not optional, and this is the
                // one place the cost is genuinely unavoidable: pending rows
                // are drained `ORDER BY failed_at ASC` and legacy rows are by
                // construction the OLDEST, so a row that never burns its
                // budget sits at the head of every batch forever and STARVES
                // live rows out of the replay window. Bumping lets these
                // converge to take-exclusion and hands the queue back.
                let reason = if already_marked_legacy(&row.last_error) {
                    row.last_error.clone()
                } else {
                    format!(
                        "{LEGACY_PEER_ID_MARKER} original enqueue reason: {}",
                        row.last_error
                    )
                };
                let _ = sink.bump_dlq_attempt(row.id, &reason).await;
                if !LEGACY_PEER_ID_WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: PUSH_DLQ_TRACE_TARGET,
                        row_id = row.id,
                        peer_id = %row.peer_id,
                        memory_id = %row.memory_id,
                        "replay: DLQ row {} is keyed by a PRE-#2442 POSITIONAL peer id ({}) — \
                         the --quorum-peers flag INDEX, written by an older binary. This binary \
                         keys by stable peer identity, so the row has no live endpoint. It will \
                         NOT be auto-remapped: `peer-N` -> peers[N] is only correct if your peer \
                         list never changed, and an upgrade is exactly when it does, so guessing \
                         would deliver this write to the WRONG HOST (that is #2442 itself). \
                         WHAT IS LOST IF YOU DO NOTHING: after {MAX_REPLAY_ATTEMPTS} attempts \
                         these rows stop being retried; the payloads are RETAINED, never \
                         deleted, but the writes stay undelivered until the peer's own \
                         /sync/since catch-up carries them. REMEDIATION: see \
                         docs/TROUBLESHOOTING.md §federation-push-DLQ — it gives the \
                         operator-gated re-key (which MUST also reset attempt_count) and the \
                         one-liner that computes a peer's stable id from its URL. This warning \
                         fires ONCE per process; the per-row detail is at debug level and the \
                         ai_memory_federation_push_dlq_legacy_positional_total counter tracks \
                         the volume.",
                        row.id,
                        row.peer_id,
                    );
                } else {
                    tracing::debug!(
                        target: PUSH_DLQ_TRACE_TARGET,
                        row_id = row.id,
                        peer_id = %row.peer_id,
                        memory_id = %row.memory_id,
                        "replay: skipping DLQ row {} — pre-#2442 positional peer id {} \
                         (see the once-per-process WARN above)",
                        row.id,
                        row.peer_id,
                    );
                }
            } else {
                let _ = sink
                    .bump_dlq_attempt(row.id, "peer no longer in FederationConfig")
                    .await;
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    peer_id = %row.peer_id,
                    "replay: peer {} not in FederationConfig — leaving row pending",
                    row.peer_id,
                );
            }
            continue;
        };

        // #2716 (CB-12) F9 — restore-race guard on the replay POST path.
        // A pending DELETE (an erasure-outbox per-peer row OR a #2498
        // delete-lane DLQ landing) that would replay AFTER the id was
        // legitimately restored / re-stored locally must be SUPERSEDED,
        // never POSTed — else it destroys the peer's just-restored copy
        // (the #2666 hazard the one-shot expand-time probe cannot see,
        // since the restore happens AFTER expansion). Delete-shaped
        // payloads only; every other lane falls straight through.
        if payload_is_delete(&row.payload_json) {
            match sink
                .erasure_delete_superseded_by_restore(&row.memory_id, &row.failed_at)
                .await
            {
                Ok(true) => {
                    crate::metrics::registry()
                        .federation_erasure_superseded
                        .inc();
                    // Clear the superseded row (guarded by the take-time
                    // attempt snapshot, same contract as the Ack path). A
                    // 0-row no-op (a concurrent bump) just leaves it
                    // pending — the next tick re-checks and still will not
                    // POST while the restore stands.
                    if let Err(e) = sink.mark_dlq_row_replayed(row.id, row.attempt_count).await {
                        tracing::warn!(
                            target: PUSH_DLQ_TRACE_TARGET,
                            row_id = row.id,
                            "replay: superseded erasure row {} could not be cleared \
                             (non-fatal; stays pending, re-checked next tick): {e}",
                            row.id,
                        );
                    }
                    tracing::warn!(
                        target: PUSH_DLQ_TRACE_TARGET,
                        row_id = row.id,
                        memory_id = %row.memory_id,
                        peer_id = %row.peer_id,
                        failed_at = %row.failed_at,
                        "replay: pending DELETE for {} SUPERSEDED — the id is LIVE again \
                         locally with a restore/re-store that POST-DATES the queued erasure \
                         ({}), so the delete was NOT sent to peer {} (it would have destroyed \
                         a just-restored replica — #2666/#2716). Re-issue the erasure if it \
                         is still intended",
                        row.memory_id,
                        row.failed_at,
                        row.peer_id,
                    );
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    // FAIL SAFE — an undeterminable liveness must NOT let
                    // the delete fly (it could destroy a restored replica).
                    // Leave the row pending for the next tick WITHOUT
                    // burning the attempt budget (this is not a delivery
                    // failure): "never cause unintentional data loss"
                    // OUTRANKS "purged content must not resurrect".
                    tracing::warn!(
                        target: PUSH_DLQ_TRACE_TARGET,
                        row_id = row.id,
                        memory_id = %row.memory_id,
                        "replay: could not evaluate the restore-race guard for {} ({e}); \
                         leaving the pending delete UNSENT this tick (fail-safe: never \
                         destroy a possibly-restored replica) — retrying next tick (#2716)",
                        row.memory_id,
                    );
                    continue;
                }
            }
        }

        let outcome = post_once(
            &config.client,
            &peer.sync_push_url,
            &row.payload_json,
            &row.memory_id,
            Some(&row.memory_id),
            config.api_key.as_deref(),
            config.signing_key.as_deref(),
        )
        .await;

        match outcome {
            AckOutcome::Ack => {
                // Guard the clear with the `attempt_count` snapshot taken
                // when this row was drained: if a concurrent
                // `enqueue_push_failure` bumped the counter (and refreshed
                // `payload_json`) between the take and now, the guarded
                // UPDATE matches 0 rows and we leave the row pending so the
                // next tick re-POSTs the newest body — never lose the
                // concurrent failure.
                match sink.mark_dlq_row_replayed(row.id, row.attempt_count).await {
                    Ok(true) => {
                        tracing::info!(
                            target: PUSH_DLQ_TRACE_TARGET,
                            row_id = row.id,
                            memory_id = %row.memory_id,
                            peer_id = %row.peer_id,
                            "replay: peer {} acked for {} (DLQ row {} cleared)",
                            row.peer_id,
                            row.memory_id,
                            row.id,
                        );
                    }
                    Ok(false) => {
                        tracing::warn!(
                            target: PUSH_DLQ_TRACE_TARGET,
                            row_id = row.id,
                            peer_id = %row.peer_id,
                            attempt_count = row.attempt_count,
                            "replay: peer {} acked stale body for DLQ row {} but a \
                             concurrent failure refreshed it mid-tick — leaving pending \
                             so the newest body is re-delivered next tick",
                            row.peer_id,
                            row.id,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: PUSH_DLQ_TRACE_TARGET,
                            row_id = row.id,
                            "replay: peer {} acked but mark_dlq_row_replayed failed: {e}",
                            row.peer_id,
                        );
                    }
                }
            }
            AckOutcome::IdDrift => {
                // Peer received the row but rewrote the id —
                // operator-visible divergence. Bump and keep row so
                // the audit trail captures the drift.
                let _ = sink
                    .bump_dlq_attempt(row.id, "replay observed id_drift on peer ack")
                    .await;
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    "replay: peer {} returned id_drift on row {} — leaving pending",
                    row.peer_id,
                    row.id,
                );
            }
            AckOutcome::Fail(reason) => {
                let _ = sink.bump_dlq_attempt(row.id, &reason).await;
                tracing::debug!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    "replay: peer {} still failing on row {}: {reason}",
                    row.peer_id,
                    row.id,
                );
            }
            // #1544 — a THROTTLE (peer 429: per-agent / federation quota
            // window) is retryable on its own once the window rolls. Do
            // NOT call `bump_dlq_attempt` — burning a `MAX_REPLAY_ATTEMPTS`
            // attempt on a throttle is exactly what quarantined ~75k valid
            // rows before the daily quota reset (#1544). Refresh
            // `last_error` for operator visibility (so the cause-label
            // classifier + un-quarantine sweep can see it) but leave the
            // attempt budget intact so the row keeps retrying until it
            // lands.
            AckOutcome::Throttled(reason) => {
                let _ = sink.note_dlq_throttled(row.id, &reason).await;
                tracing::debug!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    row_id = row.id,
                    "replay: peer {} throttled (429) on row {} — leaving pending without \
                     burning a quarantine attempt: {reason}",
                    row.peer_id,
                    row.id,
                );
            }
        }
    }

    refresh_depth_gauge(sink).await;
}

/// #2446 — `last_error` stamped on a per-peer row minted by expanding an
/// erasure-outbox sentinel.
///
/// Load-bearing beyond observability, for the same reason as the queued
/// sentinel's own text: it must contain NONE of
/// [`classify_quarantine_cause`]'s tokens so a row that later quarantines
/// classifies as the honest catch-all rather than a fabricated cause.
const ERASURE_EXPANDED_LAST_ERROR: &str =
    "queued erasure expanded to this peer (#2446); not yet attempted";

/// #2446 — expand ONE erasure-outbox sentinel row into per-peer delete
/// rows. Best-effort: every failure leaves the sentinel pending for the
/// next tick (never drops the erasure).
async fn expand_erasure_sentinel_row(
    config: &FederationConfig,
    sink: &dyn FederationDlqSink,
    row: &FederationPushDlqRow,
) {
    let sentinel = super::erasure_outbox::ALL_PEERS_SENTINEL_PEER_ID;
    // Fail-closed collision guard. The sentinel token is not a producible
    // `PeerEndpoint::id` under the historical positional derivation nor
    // the #2442 successor, but a mis-fan-out would be silent and
    // unrecoverable, so verify against the LIVE peer set rather than
    // trusting the derivation to stay that way.
    if config.peers.iter().any(|p| p.id == sentinel) {
        let _ = sink
            .bump_dlq_attempt(
                row.id,
                "erasure sentinel collides with a configured peer id; refusing to fan out",
            )
            .await;
        tracing::error!(
            target: PUSH_DLQ_TRACE_TARGET,
            row_id = row.id,
            memory_id = %row.memory_id,
            "replay: a configured peer id equals the reserved erasure sentinel {sentinel} — \
             REFUSING to expand row {} (rename the peer; the erasure stays queued, not lost)",
            row.id,
        );
        return;
    }
    let peer_ids: Vec<String> = config.peers.iter().map(|p| p.id.clone()).collect();
    if peer_ids.is_empty() {
        // Unreachable in production (`FederationConfig::build` returns
        // `None` on an empty peer list, so no worker is spawned), but a
        // silent drop of an erasure is never acceptable: leave it pending.
        tracing::warn!(
            target: PUSH_DLQ_TRACE_TARGET,
            row_id = row.id,
            "replay: erasure sentinel row {} has no configured peers to expand to — \
             leaving pending",
            row.id,
        );
        return;
    }
    // The DAEMON owns the federation identity, so the canonical delete
    // body is built HERE, not by the MCP / CLI writer (which has none).
    let body = super::erasure_outbox::deletion_body(&config.sender_agent_id, &row.memory_id);
    match sink
        .expand_erasure_sentinel(
            row.id,
            row.attempt_count,
            &row.memory_id,
            &peer_ids,
            &body,
            ERASURE_EXPANDED_LAST_ERROR,
        )
        .await
    {
        Ok(SentinelExpansion::Expanded(n)) => tracing::info!(
            target: PUSH_DLQ_TRACE_TARGET,
            row_id = row.id,
            memory_id = %row.memory_id,
            peers = n,
            "replay: expanded queued erasure for {} into {n} per-peer delete row(s) (#2446)",
            row.memory_id,
        ),
        Ok(SentinelExpansion::SupersededByLiveRow) => {
            // #2716 (CB-12) — a supersede is a data-integrity event, never
            // silent: it CANCELS an erasure the caller requested. LOUD
            // (WARN) + OBSERVABLE (metric) so an operator can tell an
            // authorized restore (correct cancel) from a case that needs
            // the erasure re-issued.
            crate::metrics::registry()
                .federation_erasure_superseded
                .inc();
            tracing::warn!(
                target: PUSH_DLQ_TRACE_TARGET,
                row_id = row.id,
                memory_id = %row.memory_id,
                "replay: queued erasure for {} SUPERSEDED — the id is LIVE again locally with \
                 an `updated_at` that POST-DATES the erasure (an archive restore or an \
                 authorized re-store), so the delete was NOT fanned out. An LWW resurrection \
                 (older `updated_at`) would instead PROCEED. Re-issue the erasure if it is \
                 still intended (#2446/#2716)",
                row.memory_id,
            );
        }
        Ok(SentinelExpansion::Contended) => tracing::debug!(
            target: PUSH_DLQ_TRACE_TARGET,
            row_id = row.id,
            "replay: erasure sentinel row {} changed mid-tick — retrying next tick",
            row.id,
        ),
        Err(e) => {
            let _ = sink
                .bump_dlq_attempt(row.id, &format!("erasure sentinel expansion failed: {e}"))
                .await;
            tracing::warn!(
                target: PUSH_DLQ_TRACE_TARGET,
                row_id = row.id,
                memory_id = %row.memory_id,
                "replay: failed to expand erasure sentinel row {}: {e}",
                row.id,
            );
        }
    }
}

/// Refresh the `ai_memory_federation_push_dlq_depth` Prometheus gauge
/// from the sink's live pending count.
async fn refresh_depth_gauge(sink: &dyn FederationDlqSink) {
    match sink.pending_dlq_count().await {
        Ok(depth) => {
            crate::metrics::registry()
                .federation_push_dlq_depth
                .set(depth);
            // #1544 — edge-triggered, rate-limited depth alarm. Fire ONE
            // WARN when the backlog crosses UP through the threshold and
            // ONE INFO when it recovers below it; never per-tick (the
            // pre-#1544 stall was silent — operators only saw a growing
            // gauge, never an alert).
            let threshold = dlq_depth_warn_threshold();
            let now_over = i64::from(depth >= threshold);
            let was_over = DLQ_DEPTH_OVER_THRESHOLD.swap(now_over, Ordering::Relaxed);
            if now_over == 1 && was_over == 0 {
                tracing::warn!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    depth,
                    threshold,
                    "federation push-DLQ depth {depth} crossed the alert threshold \
                     {threshold} — pushes are backing up. Common cause: a peer-side \
                     per-agent quota (429) throttle on a corpus-scale federation; the \
                     replayer drains automatically once admitted, or raise \
                     AI_MEMORY_MAX_MEMORIES_PER_DAY (tune the alarm via \
                     AI_MEMORY_FED_DLQ_DEPTH_WARN_THRESHOLD). #1544",
                );
            } else if now_over == 0 && was_over == 1 {
                tracing::info!(
                    target: PUSH_DLQ_TRACE_TARGET,
                    depth,
                    threshold,
                    "federation push-DLQ depth recovered below the alert threshold \
                     {threshold} (now {depth})"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                target: PUSH_DLQ_TRACE_TARGET,
                "replay: failed to refresh federation_push_dlq_depth: {e}"
            );
        }
    }
}

/// Sqlite implementation of [`FederationDlqSink`] backed by a
/// **dedicated** writable `rusqlite::Connection` (#1580 / F5.11).
///
/// Previously the sink wrapped the shared `handlers::Db` writer mutex
/// and `take_pending_dlq_rows` held that mutex across its SELECT — so a
/// DLQ poll blocked every concurrent HTTP request at the coarse tokio
/// mutex (Reviewer-5 F5.11). The sink now owns a private connection to
/// the same database file: its reads run WAL-concurrently with the HTTP
/// writer, and its brief writes serialize with the writer only at
/// SQLite's fine-grained WAL lock (`busy_timeout`), never the process
/// mutex. The DLQ table lives in the same DB, so a second WAL connection
/// is consistent with whatever the HTTP path commits.
pub struct SqliteDlqSink {
    conn: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
}

impl SqliteDlqSink {
    /// Open a dedicated writable connection for the DLQ worker, learning
    /// the on-disk path from the daemon's shared [`crate::handlers::Db`]
    /// (so callers keep passing the same handle they already hold).
    ///
    /// # Errors
    ///
    /// Returns the formatted open-error string when the dedicated
    /// connection cannot be opened (e.g. the path is unwritable). The
    /// shared handle was already opened successfully by the caller, so
    /// this is not expected in practice.
    pub async fn new(db: crate::handlers::Db) -> Result<Self, String> {
        let db_path = {
            let guard = db.lock().await;
            guard.1.clone()
        };
        let conn = crate::storage::open(&db_path)
            .map_err(|e| format!("SqliteDlqSink: open dedicated connection: {e}"))?;
        Ok(Self {
            conn: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
        })
    }
}

#[async_trait::async_trait]
impl FederationDlqSink for SqliteDlqSink {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        let payload_str = payload_json.to_string();
        let conn = self.conn.lock().await;
        // Use `ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS
        // NULL DO UPDATE` so a flapping peer doesn't stack duplicate
        // pending rows — bumps attempt_count + refreshes last_error
        // instead. The conflict path ALSO refreshes `payload_json` +
        // `failed_at` to the newest failed push so the pending row
        // always carries the freshest attempted body (a later failure
        // must not coalesce onto the stale first-failure snapshot); the
        // receiver-side LWW `insert_if_newer` makes replaying newer
        // content safe. Partial unique index from the v48 migration
        // backs this conflict target.
        conn.execute(
            "INSERT INTO federation_push_dlq \
                 (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?5) \
                 ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS NULL \
                 DO UPDATE SET \
                   attempt_count = attempt_count + 1, \
                   last_error    = excluded.last_error, \
                   payload_json  = excluded.payload_json, \
                   failed_at     = excluded.failed_at",
            rusqlite::params![memory_id, peer_id, payload_str, last_error, now],
        )
        .map_err(|e| format!("sqlite enqueue_push_failure: {e}"))?;
        Ok(())
    }

    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, memory_id, peer_id, payload_json, attempt_count, last_error, \
                        failed_at \
                 FROM federation_push_dlq \
                 WHERE replayed_at IS NULL AND attempt_count < ?2 \
                 ORDER BY failed_at ASC \
                 LIMIT ?1",
            )
            .map_err(|e| format!("sqlite take_pending_dlq_rows prepare: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![limit as i64, MAX_REPLAY_ATTEMPTS],
                |row| {
                    let payload_str: String = row.get(3)?;
                    let payload_json =
                        serde_json::from_str(&payload_str).unwrap_or(serde_json::json!({}));
                    Ok(FederationPushDlqRow {
                        id: row.get(0)?,
                        memory_id: row.get(1)?,
                        peer_id: row.get(2)?,
                        payload_json,
                        attempt_count: row.get(4)?,
                        last_error: row.get(5)?,
                        // #2716 — RFC3339 TEXT column, used verbatim by the
                        // F9 restore-race guard.
                        failed_at: row.get(6)?,
                    })
                },
            )
            .map_err(|e| format!("sqlite take_pending_dlq_rows query: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("sqlite take_pending_dlq_rows collect: {e}"))?;
        Ok(rows)
    }

    async fn mark_dlq_row_replayed(
        &self,
        id: i64,
        expected_attempt_count: i32,
    ) -> Result<bool, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().await;
        // Optimistic-concurrency guard: only clear the row the worker
        // actually drained (same `attempt_count`, still pending). A
        // concurrent `enqueue_push_failure` that bumped the counter
        // mid-tick fails this match (0 rows) and the row stays pending.
        let n = conn
            .execute(
                "UPDATE federation_push_dlq SET replayed_at = ?1 \
                 WHERE id = ?2 AND attempt_count = ?3 AND replayed_at IS NULL",
                rusqlite::params![now, id, expected_attempt_count],
            )
            .map_err(|e| format!("sqlite mark_dlq_row_replayed: {e}"))?;
        Ok(n == 1)
    }

    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE federation_push_dlq \
                 SET attempt_count = attempt_count + 1, last_error = ?1 \
                 WHERE id = ?2 AND replayed_at IS NULL",
            rusqlite::params![last_error, id],
        )
        .map_err(|e| format!("sqlite bump_dlq_attempt: {e}"))?;
        Ok(())
    }

    async fn pending_dlq_count(&self) -> Result<i64, String> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT COUNT(*) FROM federation_push_dlq WHERE replayed_at IS NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| format!("sqlite pending_dlq_count: {e}"))
    }

    async fn note_dlq_throttled(&self, id: i64, last_error: &str) -> Result<(), String> {
        // #1544 — refresh last_error ONLY; do NOT touch attempt_count.
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE federation_push_dlq SET last_error = ?1 \
             WHERE id = ?2 AND replayed_at IS NULL",
            rusqlite::params![last_error, id],
        )
        .map_err(|e| format!("sqlite note_dlq_throttled: {e}"))?;
        Ok(())
    }

    async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
        // #1544 — un-quarantine rows quarantined SOLELY by a 429 throttle.
        // Scoped to throttle rows (last_error names a 429) so genuinely
        // systematic failures stay quarantined.
        let conn = self.conn.lock().await;
        let n = conn
            .execute(
                "UPDATE federation_push_dlq SET attempt_count = 0 \
                 WHERE replayed_at IS NULL \
                   AND attempt_count >= ?1 \
                   AND last_error LIKE '%429%'",
                rusqlite::params![MAX_REPLAY_ATTEMPTS],
            )
            .map_err(|e| format!("sqlite reset_throttled_quarantine: {e}"))?;
        Ok(n as u64)
    }

    async fn expand_erasure_sentinel(
        &self,
        row_id: i64,
        expected_attempt_count: i32,
        memory_id: &str,
        peer_ids: &[String],
        per_peer_payload: &serde_json::Value,
        per_peer_last_error: &str,
    ) -> Result<SentinelExpansion, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let payload_str = per_peer_payload.to_string();
        let conn = self.conn.lock().await;
        // BEGIN IMMEDIATE (not DEFERRED): the body both reads and writes,
        // and a deferred read-then-upgrade is the classic SQLITE_BUSY
        // deadlock shape against the HTTP writer on the same file.
        let write_txn = crate::storage::connection::WriteTxn::begin(&conn)
            .map_err(|e| format!("sqlite expand_erasure_sentinel begin: {e}"))?;
        let outcome = (|| -> rusqlite::Result<SentinelExpansion> {
            // Optimistic-concurrency guard, same token as
            // `mark_dlq_row_replayed`.
            use rusqlite::OptionalExtension as _;
            // Optimistic-concurrency guard + the sentinel's own `failed_at`
            // in ONE read: absent row => contended.
            let failed_at: Option<String> = conn
                .query_row(
                    "SELECT failed_at FROM federation_push_dlq \
                     WHERE id = ?1 AND attempt_count = ?2 AND replayed_at IS NULL",
                    rusqlite::params![row_id, expected_attempt_count],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(failed_at) = failed_at else {
                return Ok(SentinelExpansion::Contended);
            };
            // #2446/#2716 restore-after-delete guard — see the trait doc.
            // SUPERSEDE only when the id is LIVE **and** its `updated_at`
            // POST-DATES the erasure (an authorized restore/re-store). An
            // LWW resurrection carries the peer's older pre-delete
            // `updated_at`, so the legitimate erasure PROCEEDS (fans out) —
            // closing the F10 silent-cancel.
            let live_updated_at: Option<String> = conn
                .query_row(
                    "SELECT updated_at FROM memories WHERE id = ?1",
                    rusqlite::params![memory_id],
                    |r| r.get(0),
                )
                .optional()?;
            let superseded = live_updated_at
                .as_deref()
                .is_some_and(|u| restore_supersedes(u, &failed_at));
            let expansion = if superseded {
                SentinelExpansion::SupersededByLiveRow
            } else {
                let mut written = 0u64;
                for peer_id in peer_ids {
                    // On conflict with an EXISTING pending per-peer row (a
                    // #2498/#2662 delete-lane landing, or a #933 store-lane
                    // failure for the same memory), the delete body
                    // SUPERSEDES: the erasure is the newer intent and
                    // replaying a superseded store would resurrect a row the
                    // origin erased. `attempt_count` is NOT bumped (an
                    // erasure is not a delivery failure) and `failed_at` is
                    // NOT refreshed, so an older pending row keeps its place
                    // in the `ORDER BY failed_at ASC` drain queue instead of
                    // being starved by fresh erasures.
                    conn.execute(
                        "INSERT INTO federation_push_dlq \
                             (memory_id, peer_id, payload_json, attempt_count, last_error, \
                              failed_at) \
                         VALUES (?1, ?2, ?3, 0, ?4, ?5) \
                         ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS NULL \
                         DO UPDATE SET \
                           last_error   = excluded.last_error, \
                           payload_json = excluded.payload_json",
                        rusqlite::params![
                            memory_id,
                            peer_id,
                            payload_str,
                            per_peer_last_error,
                            now
                        ],
                    )?;
                    written += 1;
                }
                SentinelExpansion::Expanded(written)
            };
            // Clear the sentinel in the SAME transaction so the expansion
            // and the clear are atomic.
            conn.execute(
                "UPDATE federation_push_dlq SET replayed_at = ?1 \
                 WHERE id = ?2 AND attempt_count = ?3 AND replayed_at IS NULL",
                rusqlite::params![now, row_id, expected_attempt_count],
            )?;
            Ok(expansion)
        })();
        match outcome {
            Ok(v) => {
                write_txn
                    .commit()
                    .map_err(|e| format!("sqlite expand_erasure_sentinel commit: {e}"))?;
                Ok(v)
            }
            Err(e) => {
                write_txn.rollback();
                Err(format!("sqlite expand_erasure_sentinel: {e}"))
            }
        }
    }

    async fn erasure_delete_superseded_by_restore(
        &self,
        memory_id: &str,
        erasure_failed_at: &str,
    ) -> Result<bool, String> {
        use rusqlite::OptionalExtension as _;
        let conn = self.conn.lock().await;
        let live_updated_at: Option<String> = conn
            .query_row(
                "SELECT updated_at FROM memories WHERE id = ?1",
                rusqlite::params![memory_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("sqlite erasure_delete_superseded_by_restore: {e}"))?;
        Ok(live_updated_at
            .as_deref()
            .is_some_and(|u| restore_supersedes(u, erasure_failed_at)))
    }
}

/// Postgres implementation of [`FederationDlqSink`] backed by the
/// `PostgresStore`'s connection pool.
///
/// Only available under `--features sal-postgres` (which transitively
/// enables `sal`).
#[cfg(feature = "sal-postgres")]
pub struct PostgresDlqSink {
    store: std::sync::Arc<crate::store::postgres::PostgresStore>,
}

#[cfg(feature = "sal-postgres")]
impl PostgresDlqSink {
    /// Build a new sink over the daemon's `PostgresStore` handle.
    #[must_use]
    pub fn new(store: std::sync::Arc<crate::store::postgres::PostgresStore>) -> Self {
        Self { store }
    }
}

#[cfg(feature = "sal-postgres")]
#[async_trait::async_trait]
impl FederationDlqSink for PostgresDlqSink {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        let pool = self.store.pool();
        // The conflict path refreshes `payload_json` + `failed_at` to the
        // newest failed push (mirrors the sqlite arm) so a later failure
        // never coalesces onto the stale first-failure body. `failed_at`
        // has a `DEFAULT now()` (see migrations/postgres/0030_*), so
        // `EXCLUDED.failed_at` is the fresh insert-time instant.
        sqlx::query(
            "INSERT INTO federation_push_dlq \
             (memory_id, peer_id, payload_json, attempt_count, last_error) \
             VALUES ($1, $2, $3::jsonb, 1, $4) \
             ON CONFLICT (memory_id, peer_id) WHERE replayed_at IS NULL \
             DO UPDATE SET \
               attempt_count = federation_push_dlq.attempt_count + 1, \
               last_error    = EXCLUDED.last_error, \
               payload_json  = EXCLUDED.payload_json, \
               failed_at     = EXCLUDED.failed_at",
        )
        .bind(memory_id)
        .bind(peer_id)
        .bind(payload_json.to_string())
        .bind(last_error)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres enqueue_push_failure: {e}"))?;
        Ok(())
    }

    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        let pool = self.store.pool();
        let limit_i64: i64 = limit.try_into().unwrap_or(i64::MAX);
        let rows: Vec<(
            i64,
            String,
            String,
            serde_json::Value,
            i32,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, memory_id, peer_id, payload_json, attempt_count, last_error, failed_at \
             FROM federation_push_dlq \
             WHERE replayed_at IS NULL AND attempt_count < $2 \
             ORDER BY failed_at ASC \
             LIMIT $1",
        )
        .bind(limit_i64)
        .bind(MAX_REPLAY_ATTEMPTS)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("postgres take_pending_dlq_rows: {e}"))?;
        Ok(rows
            .into_iter()
            .map(
                |(id, memory_id, peer_id, payload_json, attempt_count, last_error, failed_at)| {
                    FederationPushDlqRow {
                        id,
                        memory_id,
                        peer_id,
                        payload_json,
                        attempt_count,
                        last_error,
                        // #2716 — normalise the `TIMESTAMPTZ` to RFC3339 so
                        // the backend-blind F9 guard compares identically.
                        failed_at: failed_at.to_rfc3339(),
                    }
                },
            )
            .collect())
    }

    async fn mark_dlq_row_replayed(
        &self,
        id: i64,
        expected_attempt_count: i32,
    ) -> Result<bool, String> {
        let pool = self.store.pool();
        // Optimistic-concurrency guard (mirrors the sqlite arm): only
        // clear the row the worker drained. A concurrent
        // `enqueue_push_failure` that bumped `attempt_count` mid-tick
        // fails this match (0 rows) and the row stays pending.
        let res = sqlx::query(
            "UPDATE federation_push_dlq SET replayed_at = now() \
             WHERE id = $1 AND attempt_count = $2 AND replayed_at IS NULL",
        )
        .bind(id)
        .bind(expected_attempt_count)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres mark_dlq_row_replayed: {e}"))?;
        Ok(res.rows_affected() == 1)
    }

    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
        let pool = self.store.pool();
        sqlx::query(
            "UPDATE federation_push_dlq \
             SET attempt_count = attempt_count + 1, last_error = $1 \
             WHERE id = $2 AND replayed_at IS NULL",
        )
        .bind(last_error)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres bump_dlq_attempt: {e}"))?;
        Ok(())
    }

    async fn pending_dlq_count(&self) -> Result<i64, String> {
        let pool = self.store.pool();
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM federation_push_dlq WHERE replayed_at IS NULL")
                .fetch_one(pool)
                .await
                .map_err(|e| format!("postgres pending_dlq_count: {e}"))?;
        Ok(row.0)
    }

    async fn note_dlq_throttled(&self, id: i64, last_error: &str) -> Result<(), String> {
        // #1544 — refresh last_error ONLY; do NOT touch attempt_count.
        let pool = self.store.pool();
        sqlx::query(
            "UPDATE federation_push_dlq SET last_error = $1 \
             WHERE id = $2 AND replayed_at IS NULL",
        )
        .bind(last_error)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres note_dlq_throttled: {e}"))?;
        Ok(())
    }

    async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
        // #1544 — un-quarantine 429-throttled rows only (see trait doc).
        let pool = self.store.pool();
        let res = sqlx::query(
            "UPDATE federation_push_dlq SET attempt_count = 0 \
             WHERE replayed_at IS NULL \
               AND attempt_count >= $1 \
               AND last_error LIKE '%429%'",
        )
        .bind(MAX_REPLAY_ATTEMPTS)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres reset_throttled_quarantine: {e}"))?;
        Ok(res.rows_affected())
    }

    async fn expand_erasure_sentinel(
        &self,
        row_id: i64,
        expected_attempt_count: i32,
        memory_id: &str,
        peer_ids: &[String],
        per_peer_payload: &serde_json::Value,
        per_peer_last_error: &str,
    ) -> Result<SentinelExpansion, String> {
        // Backend PARITY implementation. Today nothing writes an erasure
        // sentinel into the POSTGRES `federation_push_dlq`: the MCP stdio
        // surface is structurally sqlite-only (CLAUDE.md #1675/n24) and the
        // CLI erasure verbs open a local rusqlite connection, so the write
        // side is sqlite-by-construction. The DRAIN side must still be
        // backend-blind — a postgres-backed `serve` drains the postgres
        // table, and the moment any postgres-side writer queues a sentinel
        // (a future pg CLI, or a peer relaying one) it MUST expand
        // identically rather than quarantining as an unknown peer.
        let pool = self.store.pool();
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| format!("postgres expand_erasure_sentinel begin: {e}"))?;
        // Optimistic-concurrency guard + the sentinel's own `failed_at` in
        // ONE read: absent row => contended.
        let sentinel: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
            "SELECT failed_at FROM federation_push_dlq \
             WHERE id = $1 AND attempt_count = $2 AND replayed_at IS NULL",
        )
        .bind(row_id)
        .bind(expected_attempt_count)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("postgres expand_erasure_sentinel guard: {e}"))?;
        let Some((failed_at,)) = sentinel else {
            return Ok(SentinelExpansion::Contended);
        };
        // #2446/#2716 restore-after-delete guard — see the trait doc.
        // SUPERSEDE only when the id is LIVE **and** its `updated_at`
        // POST-DATES the erasure (an authorized restore). An LWW
        // resurrection carries an older `updated_at`, so the legitimate
        // erasure PROCEEDS — closing the F10 silent-cancel. Both columns
        // are `TIMESTAMPTZ`, so the comparison is a typed instant compare
        // (no parse, no fail-safe branch needed here).
        let live: Option<(chrono::DateTime<chrono::Utc>,)> =
            sqlx::query_as("SELECT updated_at FROM memories WHERE id = $1")
                .bind(memory_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| format!("postgres expand_erasure_sentinel liveness probe: {e}"))?;
        let superseded = live.is_some_and(|(u,)| u >= failed_at);
        let expansion = if superseded {
            SentinelExpansion::SupersededByLiveRow
        } else {
            let mut written = 0u64;
            for peer_id in peer_ids {
                sqlx::query(
                    "INSERT INTO federation_push_dlq \
                         (memory_id, peer_id, payload_json, attempt_count, last_error) \
                     VALUES ($1, $2, $3::jsonb, 0, $4) \
                     ON CONFLICT (memory_id, peer_id) WHERE replayed_at IS NULL \
                     DO UPDATE SET \
                       last_error   = EXCLUDED.last_error, \
                       payload_json = EXCLUDED.payload_json",
                )
                .bind(memory_id)
                .bind(peer_id)
                .bind(per_peer_payload.to_string())
                .bind(per_peer_last_error)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("postgres expand_erasure_sentinel insert: {e}"))?;
                written += 1;
            }
            SentinelExpansion::Expanded(written)
        };
        sqlx::query(
            "UPDATE federation_push_dlq SET replayed_at = now() \
             WHERE id = $1 AND attempt_count = $2 AND replayed_at IS NULL",
        )
        .bind(row_id)
        .bind(expected_attempt_count)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("postgres expand_erasure_sentinel clear: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("postgres expand_erasure_sentinel commit: {e}"))?;
        Ok(expansion)
    }

    async fn erasure_delete_superseded_by_restore(
        &self,
        memory_id: &str,
        erasure_failed_at: &str,
    ) -> Result<bool, String> {
        let pool = self.store.pool();
        let live: Option<(chrono::DateTime<chrono::Utc>,)> =
            sqlx::query_as("SELECT updated_at FROM memories WHERE id = $1")
                .bind(memory_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("postgres erasure_delete_superseded_by_restore: {e}"))?;
        // Normalise the typed `TIMESTAMPTZ` to RFC3339 and run the shared
        // fail-safe comparator so both backends agree byte-for-byte.
        Ok(live.is_some_and(|(u,)| restore_supersedes(&u.to_rfc3339(), erasure_failed_at)))
    }
}

#[cfg(test)]
mod replay_arm_tests {
    //! Coverage for the `replay_once` decision arms that the
    //! `tests/federation_dlq_replay.rs` integration suite does not reach
    //! (quarantine skip, peer-no-longer-in-config, empty-queue gauge
    //! refresh, pending-count-error fallback) plus the `replay_max_batch`
    //! env resolver arms. A lightweight in-memory mock sink drives the
    //! arms without any HTTP peer; the `Fail` arm is reached by pointing
    //! the worker at a peer URL that refuses TCP.

    use super::{
        CAUSE_NAMESPACE_PROBE_UNRESOLVABLE, CAUSE_UNENROLLED_AUTHOR_STRICT,
        DEFAULT_REPLAY_MAX_BATCH, ENV_FED_DLQ_REPLAY_MAX_BATCH, FederationDlqSink,
        FederationPushDlqRow, MAX_REPLAY_ATTEMPTS, REPLAY_BATCH_SIZE, SentinelExpansion,
        classify_quarantine_cause, replay_max_batch, replay_once,
    };
    use crate::federation::{FederationConfig, PeerEndpoint};
    use crate::replication::QuorumPolicy;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// In-memory mock sink that records which trait methods fired so the
    /// test can assert the worker took the expected branch.
    #[derive(Default)]
    struct MockSink {
        rows: Mutex<Vec<FederationPushDlqRow>>,
        marked_replayed: Mutex<Vec<i64>>,
        bumped: Mutex<Vec<(i64, String)>>,
        // #1544 — records note_dlq_throttled calls so a test can assert a
        // 429 throttle did NOT go through bump_dlq_attempt.
        throttled: Mutex<Vec<(i64, String)>>,
        count_should_err: bool,
        take_should_err: bool,
        take_calls: AtomicUsize,
        // #2446/#2716 — (memory_id, updated_at) the mock treats as LIVE
        // locally, so a test can drive the restore-after-delete supersede
        // arm AND the F10/F9 updated_at-vs-failed_at discriminator (a
        // resurrection with an OLDER updated_at must NOT supersede).
        live_rows: Mutex<Vec<(String, String)>>,
        // #2446 — records `expand_erasure_sentinel` calls: (row_id, peers).
        expanded: Mutex<Vec<(i64, Vec<String>)>>,
    }

    #[async_trait::async_trait]
    impl FederationDlqSink for MockSink {
        async fn enqueue_push_failure(
            &self,
            memory_id: &str,
            peer_id: &str,
            payload_json: &serde_json::Value,
            last_error: &str,
        ) -> Result<(), String> {
            self.rows.lock().unwrap().push(FederationPushDlqRow {
                id: (self.rows.lock().unwrap().len() + 1) as i64,
                memory_id: memory_id.to_string(),
                peer_id: peer_id.to_string(),
                payload_json: payload_json.clone(),
                attempt_count: 1,
                last_error: last_error.to_string(),
                failed_at: chrono::Utc::now().to_rfc3339(),
            });
            Ok(())
        }

        async fn take_pending_dlq_rows(
            &self,
            _limit: usize,
        ) -> Result<Vec<FederationPushDlqRow>, String> {
            self.take_calls.fetch_add(1, Ordering::SeqCst);
            if self.take_should_err {
                return Err("mock take error".to_string());
            }
            Ok(self.rows.lock().unwrap().clone())
        }

        async fn mark_dlq_row_replayed(
            &self,
            id: i64,
            expected_attempt_count: i32,
        ) -> Result<bool, String> {
            // Model the guarded UPDATE: only clear when the live row still
            // carries the observed attempt_count (a concurrent bump makes
            // this a 0-row no-op → Ok(false)).
            let matched = {
                let rows = self.rows.lock().unwrap();
                rows.iter()
                    .any(|r| r.id == id && r.attempt_count == expected_attempt_count)
            };
            if !matched {
                return Ok(false);
            }
            self.marked_replayed.lock().unwrap().push(id);
            Ok(true)
        }

        async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
            self.bumped
                .lock()
                .unwrap()
                .push((id, last_error.to_string()));
            Ok(())
        }

        async fn pending_dlq_count(&self) -> Result<i64, String> {
            if self.count_should_err {
                return Err("mock count error".to_string());
            }
            Ok(self.rows.lock().unwrap().len() as i64)
        }

        async fn note_dlq_throttled(&self, id: i64, last_error: &str) -> Result<(), String> {
            // Record the throttle WITHOUT bumping attempt_count, then
            // refresh last_error on the matching row.
            self.throttled
                .lock()
                .unwrap()
                .push((id, last_error.to_string()));
            for row in self.rows.lock().unwrap().iter_mut() {
                if row.id == id {
                    row.last_error = last_error.to_string();
                }
            }
            Ok(())
        }

        async fn reset_throttled_quarantine(&self) -> Result<u64, String> {
            let mut n = 0u64;
            for row in self.rows.lock().unwrap().iter_mut() {
                if row.attempt_count >= MAX_REPLAY_ATTEMPTS && row.last_error.contains("429") {
                    row.attempt_count = 0;
                    n += 1;
                }
            }
            Ok(n)
        }

        async fn expand_erasure_sentinel(
            &self,
            row_id: i64,
            expected_attempt_count: i32,
            memory_id: &str,
            peer_ids: &[String],
            per_peer_payload: &serde_json::Value,
            per_peer_last_error: &str,
        ) -> Result<SentinelExpansion, String> {
            let mut rows = self.rows.lock().unwrap();
            let Some(pos) = rows
                .iter()
                .position(|r| r.id == row_id && r.attempt_count == expected_attempt_count)
            else {
                return Ok(SentinelExpansion::Contended);
            };
            let failed_at = rows[pos].failed_at.clone();
            // #2716 — SUPERSEDE only when the id is live AND its updated_at
            // post-dates the erasure (mirrors the real backend guard).
            let superseded = self
                .live_rows
                .lock()
                .unwrap()
                .iter()
                .find(|(id, _)| id == memory_id)
                .is_some_and(|(_, u)| super::restore_supersedes(u, &failed_at));
            if superseded {
                rows.remove(pos);
                return Ok(SentinelExpansion::SupersededByLiveRow);
            }
            rows.remove(pos);
            let mut next_id = rows.iter().map(|r| r.id).max().unwrap_or(row_id) + 1;
            for peer_id in peer_ids {
                rows.push(FederationPushDlqRow {
                    id: next_id,
                    memory_id: memory_id.to_string(),
                    peer_id: peer_id.clone(),
                    payload_json: per_peer_payload.clone(),
                    attempt_count: 0,
                    last_error: per_peer_last_error.to_string(),
                    // The per-peer row inherits the sentinel's erasure
                    // instant so the F9 replay re-check compares against the
                    // original delete-intent time.
                    failed_at: failed_at.clone(),
                });
                next_id += 1;
            }
            self.expanded
                .lock()
                .unwrap()
                .push((row_id, peer_ids.to_vec()));
            Ok(SentinelExpansion::Expanded(peer_ids.len() as u64))
        }

        async fn erasure_delete_superseded_by_restore(
            &self,
            memory_id: &str,
            erasure_failed_at: &str,
        ) -> Result<bool, String> {
            Ok(self
                .live_rows
                .lock()
                .unwrap()
                .iter()
                .find(|(id, _)| id == memory_id)
                .is_some_and(|(_, u)| super::restore_supersedes(u, erasure_failed_at)))
        }
    }

    fn cfg_with_peer(peer_id: &str, url: &str) -> FederationConfig {
        FederationConfig {
            policy: QuorumPolicy::new(1, 1, Duration::from_millis(200), Duration::from_secs(30))
                .unwrap(),
            peers: vec![PeerEndpoint {
                id: peer_id.to_string(),
                sync_push_url: url.to_string(),
            }],
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
            sender_agent_id: "ai:cov3-dlq".to_string(),
            api_key: None,
            signing_key: None,
            dlq_sink: None,
        }
    }

    fn row(id: i64, peer_id: &str, attempt_count: i32) -> FederationPushDlqRow {
        FederationPushDlqRow {
            id,
            memory_id: format!("mem-{id}"),
            peer_id: peer_id.to_string(),
            failed_at: "1970-01-01T00:00:00+00:00".to_string(),
            payload_json: serde_json::json!({"id": format!("mem-{id}")}),
            attempt_count,
            last_error: String::new(),
        }
    }

    #[test]
    fn replay_max_batch_env_arms() {
        let _g = env_lock();
        // SAFETY: env mutation under the test-scoped lock.
        unsafe {
            std::env::remove_var(ENV_FED_DLQ_REPLAY_MAX_BATCH);
        }
        assert_eq!(
            replay_max_batch(),
            DEFAULT_REPLAY_MAX_BATCH,
            "unset → default"
        );

        unsafe {
            std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "5000");
        }
        assert_eq!(replay_max_batch(), 5000, "valid override honoured");

        // Below the REPLAY_BATCH_SIZE floor → default with warn.
        unsafe {
            std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "10");
        }
        assert_eq!(
            replay_max_batch(),
            DEFAULT_REPLAY_MAX_BATCH,
            "below floor falls through"
        );

        // Garbage → default.
        unsafe {
            std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, "not-a-number");
        }
        assert_eq!(
            replay_max_batch(),
            DEFAULT_REPLAY_MAX_BATCH,
            "garbage → default"
        );

        // Exactly the floor is accepted.
        unsafe {
            std::env::set_var(ENV_FED_DLQ_REPLAY_MAX_BATCH, &REPLAY_BATCH_SIZE.to_string());
        }
        assert_eq!(replay_max_batch(), REPLAY_BATCH_SIZE, "floor accepted");

        unsafe {
            std::env::remove_var(ENV_FED_DLQ_REPLAY_MAX_BATCH);
        }
    }

    #[tokio::test]
    async fn empty_queue_only_refreshes_gauge() {
        let sink = MockSink::default();
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert_eq!(sink.take_calls.load(Ordering::SeqCst), 1);
        assert!(sink.marked_replayed.lock().unwrap().is_empty());
        assert!(sink.bumped.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn quarantined_row_is_skipped() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(row(1, "peer-0", MAX_REPLAY_ATTEMPTS));
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        // Quarantined → neither replayed nor bumped; no POST attempted.
        assert!(sink.marked_replayed.lock().unwrap().is_empty());
        assert!(sink.bumped.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn peer_no_longer_in_config_bumps_and_leaves() {
        let sink = MockSink::default();
        sink.rows.lock().unwrap().push(row(7, "peer-gone", 1));
        // Config has a DIFFERENT peer, so the row's peer is unresolvable.
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        let bumped = sink.bumped.lock().unwrap();
        assert_eq!(bumped.len(), 1);
        assert_eq!(bumped[0].0, 7);
        assert!(bumped[0].1.contains("no longer in FederationConfig"));
    }

    #[tokio::test]
    async fn unreachable_peer_yields_fail_and_bumps() {
        let sink = MockSink::default();
        sink.rows.lock().unwrap().push(row(3, "peer-0", 1));
        // TCP refused (port 1) → post_once returns Fail → bump.
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert!(
            !sink.bumped.lock().unwrap().is_empty(),
            "a failed POST must bump attempt_count"
        );
        assert!(sink.marked_replayed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pending_count_error_degrades_to_fixed_batch() {
        let mut sink = MockSink::default();
        sink.count_should_err = true;
        sink.rows.lock().unwrap().push(row(1, "peer-gone", 1));
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        // Count error → fixed batch; take still runs; peer-gone arm bumps.
        replay_once(&cfg, &sink).await;
        assert_eq!(sink.take_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn take_error_returns_early() {
        let mut sink = MockSink::default();
        sink.take_should_err = true;
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        // Take errored → early return, no replay/bump.
        assert!(sink.marked_replayed.lock().unwrap().is_empty());
        assert!(sink.bumped.lock().unwrap().is_empty());
    }

    // ----- #1544 throttle / un-quarantine -----------------------------

    fn dlq_row(id: i64, attempt_count: i32, last_error: &str) -> FederationPushDlqRow {
        FederationPushDlqRow {
            id,
            memory_id: format!("m{id}"),
            peer_id: "peer-0".to_string(),
            payload_json: serde_json::json!({}),
            attempt_count,
            last_error: last_error.to_string(),
            failed_at: "1970-01-01T00:00:00+00:00".to_string(),
        }
    }

    /// #1544 — a 429 throttle must un-quarantine ONLY rows whose
    /// last_error names the throttle; a genuinely-systematic failure
    /// (e.g. http 400) stays quarantined so the worker doesn't resume
    /// infinite no-op POST amplification against a permanently-broken row.
    #[tokio::test]
    async fn reset_throttled_quarantine_is_scoped_to_429_rows() {
        let sink = MockSink::default();
        {
            let mut rows = sink.rows.lock().unwrap();
            rows.push(dlq_row(
                1,
                MAX_REPLAY_ATTEMPTS,
                "http 429 Too Many Requests",
            ));
            rows.push(dlq_row(2, MAX_REPLAY_ATTEMPTS, "http 400 Bad Request"));
            rows.push(dlq_row(3, 5, "http 429 Too Many Requests")); // not quarantined
        }
        let n = sink.reset_throttled_quarantine().await.expect("reset");
        assert_eq!(n, 1, "only the quarantined 429 row is un-quarantined");
        let rows = sink.rows.lock().unwrap();
        let by_id = |id: i64| rows.iter().find(|r| r.id == id).unwrap().attempt_count;
        assert_eq!(by_id(1), 0, "429-quarantined row reset to 0");
        assert_eq!(
            by_id(2),
            MAX_REPLAY_ATTEMPTS,
            "permanent-failure (400) row STAYS quarantined"
        );
        assert_eq!(by_id(3), 5, "below-ceiling 429 row untouched");
    }

    /// #1544 — a throttle records via note_dlq_throttled and must NOT go
    /// through bump_dlq_attempt (which would burn a quarantine attempt).
    #[tokio::test]
    async fn throttle_notes_without_bumping_attempt_count() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(dlq_row(1, 5, "previous error"));
        sink.note_dlq_throttled(1, "http 429 Too Many Requests")
            .await
            .expect("note");
        assert!(
            sink.bumped.lock().unwrap().is_empty(),
            "a throttle must NOT bump attempt_count"
        );
        assert_eq!(sink.throttled.lock().unwrap().len(), 1);
        assert!(
            sink.rows.lock().unwrap()[0].last_error.contains("429"),
            "last_error refreshed to the throttle reason"
        );
    }

    /// #1544 — the quarantine-cause classifier maps free-text last_error
    /// onto a CLOSED label set (bounded Prometheus cardinality).
    #[test]
    fn classify_quarantine_cause_maps_to_closed_set() {
        assert_eq!(
            classify_quarantine_cause("http 429 Too Many Requests"),
            "quota"
        );
        assert_eq!(
            classify_quarantine_cause("http 400 Bad Request"),
            "permanent"
        );
        assert_eq!(
            classify_quarantine_cause("http 422 invalid signature"),
            "permanent"
        );
        assert_eq!(
            classify_quarantine_cause("http 401 Unauthorized"),
            "unenrolled_peer"
        );
        assert_eq!(
            classify_quarantine_cause("replay observed id_drift on peer ack"),
            "id_drift"
        );
        assert_eq!(
            classify_quarantine_cause("peer no longer in FederationConfig"),
            "peer_removed"
        );
        // #1801→#1954 item 7 — the honored-third-party unenrolled-author cause
        // is its own closed-set label, distinct from `unenrolled_peer`.
        assert_eq!(
            classify_quarantine_cause(
                "sync_push: honored third-party relay refused (unenrolled_author_strict)"
            ),
            CAUSE_UNENROLLED_AUTHOR_STRICT
        );
        // #2488 — an un-erasable row (the receiver could not RESOLVE the target
        // row's namespace, so the federated-delete scope gate failed closed) is
        // its own closed-set label. Distinct from a scope refusal: the peer's
        // config is fine and the remedy lives at the RECEIVER's storage.
        assert_eq!(
            classify_quarantine_cause(
                "sync_push: refusing federated deletion (namespace_probe_unresolvable)"
            ),
            CAUSE_NAMESPACE_PROBE_UNRESOLVABLE
        );
        assert_eq!(
            classify_quarantine_cause("connection reset by peer"),
            "other"
        );
        // #2341 — a peer-2xx-but-unsupported_on_postgres non-ack reason is
        // structurally permanent for that peer, not "other".
        assert_eq!(
            classify_quarantine_cause(
                "peer 2xx but 1 item(s) unsupported_on_postgres (not applied on this peer)"
            ),
            "permanent"
        );
    }

    /// #2360 — the `mark_dlq_row_replayed` CAS contract the `replay_once` Ack
    /// arm relies on: a mark whose `expected_attempt_count` no longer matches
    /// the persisted row is a 0-row no-op (`Ok(false)`, row left pending); a
    /// matching mark clears it (`Ok(true)`).
    #[tokio::test]
    async fn mark_dlq_row_replayed_is_attempt_count_guarded_2360() {
        let sink = MockSink::default();
        sink.rows.lock().unwrap().push(row(9, "peer-0", 1));

        // Stale snapshot (expected=2 while the live row is at 1) → no-op.
        assert!(
            !sink.mark_dlq_row_replayed(9, 2).await.unwrap(),
            "stale-snapshot mark must not clear"
        );
        assert!(
            sink.marked_replayed.lock().unwrap().is_empty(),
            "no row marked under a stale snapshot"
        );

        // Matching snapshot (expected=1) → clears the row.
        assert!(
            sink.mark_dlq_row_replayed(9, 1).await.unwrap(),
            "matching-snapshot mark clears"
        );
        assert_eq!(sink.marked_replayed.lock().unwrap().as_slice(), &[9]);
    }

    // ----- #2716 (CB-12) erasure restore-race + silent-cancel guards -----

    const TS_OLD: &str = "2026-01-01T00:00:00+00:00";
    const TS_MID: &str = "2026-06-01T00:00:00+00:00";
    const TS_NEW: &str = "2026-12-01T00:00:00+00:00";

    fn erasure_payload(mem: &str) -> serde_json::Value {
        serde_json::json!({"memories": [], "deletions": [mem], "dry_run": false})
    }

    fn sentinel_row(id: i64, mem: &str, failed_at: &str) -> FederationPushDlqRow {
        FederationPushDlqRow {
            id,
            memory_id: mem.to_string(),
            peer_id: crate::federation::erasure_outbox::ALL_PEERS_SENTINEL_PEER_ID.to_string(),
            payload_json: erasure_payload(mem),
            attempt_count: 1,
            last_error: "queued".to_string(),
            failed_at: failed_at.to_string(),
        }
    }

    fn delete_row(id: i64, mem: &str, peer_id: &str, failed_at: &str) -> FederationPushDlqRow {
        FederationPushDlqRow {
            id,
            memory_id: mem.to_string(),
            peer_id: peer_id.to_string(),
            payload_json: erasure_payload(mem),
            attempt_count: 0,
            last_error: String::new(),
            failed_at: failed_at.to_string(),
        }
    }

    /// #2716 F10 — an LWW RESURRECTION (a live row whose `updated_at`
    /// PRE-dates the erasure) must NOT silently cancel the erasure: the
    /// sentinel EXPANDS and the delete fans out. This is the defect —
    /// pre-#2716 any live row cancelled the erasure mesh-wide.
    #[tokio::test]
    async fn erasure_sentinel_over_lww_resurrection_proceeds_2716() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(sentinel_row(1, "mem-x", TS_MID));
        // Resurrection: live, but with an OLDER updated_at (the peer's
        // pre-delete value re-delivered via catch-up).
        sink.live_rows
            .lock()
            .unwrap()
            .push(("mem-x".to_string(), TS_OLD.to_string()));
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert_eq!(
            sink.expanded.lock().unwrap().len(),
            1,
            "#2716 F10: a resurrection OLDER than the erasure must NOT cancel it — the \
             sentinel must EXPAND (fan the delete out to peers)"
        );
    }

    /// #2716 — an AUTHORIZED restore (a live row whose `updated_at`
    /// POST-dates the erasure) correctly SUPERSEDES the erasure (no
    /// fan-out) — the F9/#2666 fail-safe direction, preserved.
    #[tokio::test]
    async fn erasure_sentinel_over_authorized_restore_supersedes_2716() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(sentinel_row(1, "mem-x", TS_MID));
        sink.live_rows
            .lock()
            .unwrap()
            .push(("mem-x".to_string(), TS_NEW.to_string()));
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert!(
            sink.expanded.lock().unwrap().is_empty(),
            "#2716: an authorized restore NEWER than the erasure must SUPERSEDE — no fan-out"
        );
        assert!(
            sink.rows.lock().unwrap().is_empty(),
            "#2716: the superseded sentinel is cleared, not retried forever"
        );
    }

    /// #2716 F9 — a pending per-peer DELETE that replays AFTER an
    /// authorized restore (live row newer than the erasure) must be
    /// SUPERSEDED on the POST path — NEVER sent to the peer (it would
    /// destroy the just-restored replica, #2666). This is the race the
    /// pre-#2716 replay path (no re-check) left open.
    #[tokio::test]
    async fn pending_delete_superseded_by_restore_is_not_posted_2716() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(delete_row(7, "mem-x", "peer-0", TS_MID));
        sink.live_rows
            .lock()
            .unwrap()
            .push(("mem-x".to_string(), TS_NEW.to_string()));
        // Dead peer URL: if the guard failed to fire, post_once would run
        // and the row would be BUMPED (a delivery failure) — the asserts
        // catch that regression directly.
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert_eq!(
            sink.marked_replayed.lock().unwrap().as_slice(),
            &[7],
            "#2716 F9: a delete superseded by a restore must be CLEARED, not POSTed"
        );
        assert!(
            sink.bumped.lock().unwrap().is_empty(),
            "#2716 F9: the superseded delete must NOT reach post_once (no attempt bump)"
        );
    }

    /// #2716 F9 — the guard does NOT over-supersede: a pending delete for
    /// an id that is NOT live locally still POSTs (and bumps on failure),
    /// so a legitimate erasure keeps propagating.
    #[tokio::test]
    async fn pending_delete_for_absent_row_still_posts_2716() {
        let sink = MockSink::default();
        sink.rows
            .lock()
            .unwrap()
            .push(delete_row(7, "mem-gone", "peer-0", TS_MID));
        // live_rows empty → the id is not live → not superseded.
        let cfg = cfg_with_peer("peer-0", "http://127.0.0.1:1/api/v1/sync/push");
        replay_once(&cfg, &sink).await;
        assert!(
            sink.marked_replayed.lock().unwrap().is_empty(),
            "#2716: an absent (truly-erased) row is never superseded"
        );
        assert!(
            !sink.bumped.lock().unwrap().is_empty(),
            "#2716: the delete reached post_once and bumped on the failed POST"
        );
    }

    /// #2716 — the pure comparator: instant (not lexical) `>=` ordering,
    /// and FAIL-SAFE (supersede → preserve data) on any unparseable input.
    #[test]
    fn restore_supersedes_is_fail_safe_and_instant_ordered_2716() {
        assert!(
            super::restore_supersedes(TS_NEW, TS_MID),
            "newer supersedes"
        );
        assert!(
            super::restore_supersedes(TS_MID, TS_MID),
            ">=: an equal instant supersedes"
        );
        assert!(
            !super::restore_supersedes(TS_OLD, TS_MID),
            "an older live row does NOT supersede (erasure proceeds)"
        );
        assert!(
            super::restore_supersedes("not-a-timestamp", TS_MID),
            "unparseable live updated_at → fail-safe SUPERSEDE (preserve data)"
        );
        assert!(
            super::restore_supersedes(TS_OLD, "garbage"),
            "unparseable failed_at → fail-safe SUPERSEDE (preserve data)"
        );
    }
}
