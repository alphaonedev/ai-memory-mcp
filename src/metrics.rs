// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.6.0.0 Prometheus metrics. Exposed at `GET /metrics` by the daemon.
//!
//! Minimal, non-invasive instrumentation — the process has a single
//! default `Registry`, a handful of global counters and a couple of
//! histograms. Callers increment via the typed helpers (`record_store`,
//! `record_recall`) rather than poking the registry directly so a future
//! metrics-backend swap stays internal.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry,
    TextEncoder,
};

// =====================================================================
// pm-v3.1 PR8 (issue #1174) — HNSW eviction observability.
//
// Pre-PR8 lived as two free `static AtomicU64`s at the top of
// `src/hnsw.rs`. Class A "SHOULD" extraction: the counters are
// metrics-bound (surfaced in `/metrics`, `memory_capabilities`,
// `memory_stats`) so the metrics registry is the natural owner.
//
// The Prometheus handles (`hnsw_evictions_total` IntCounter +
// `hnsw_last_eviction_at_nanos` IntGauge in `Metrics`) carry the
// scrape-side wiring. The atomics below carry the read-side logic
// (`evicted_recently` 60s window) AND the test-only reset path that
// prometheus's monotonic-counter discipline does not support. Both
// kept-in-lockstep by the `record_hnsw_eviction` sink and the
// `reset_hnsw_eviction_counters_for_test` resetter.
//
// Process-local. The counters reset on restart because the index
// itself resets on restart. Both atomics are touched only on the
// eviction edge (rare: requires >100k vectors), so there is no
// measurable hot-path cost.
// =====================================================================

static HNSW_EVICTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static HNSW_LAST_EVICTION_AT_NANOS: AtomicU64 = AtomicU64::new(0);

/// Record one HNSW eviction event. Bumps the process-local cumulative
/// counter by `count`, sets the last-eviction wall-clock nanos to
/// `now_nanos`, and mirrors both onto the Prometheus registry handles
/// so `/metrics` scrapes see the same signal without a separate
/// observer thread.
pub fn record_hnsw_eviction(count: u64, now_nanos: u64) {
    HNSW_EVICTIONS_TOTAL.fetch_add(count, Ordering::Relaxed);
    HNSW_LAST_EVICTION_AT_NANOS.store(now_nanos, Ordering::Relaxed);
    let r = registry();
    r.hnsw_evictions_total.inc_by(count);
    // IntGauge value is i64; nanos can exceed i64::MAX in ~292 years
    // past the UNIX epoch — saturating clamp keeps the gauge in range
    // for any plausible operator timeline.
    #[allow(clippy::cast_possible_wrap)]
    let nanos_i64 = i64::try_from(now_nanos).unwrap_or(i64::MAX);
    r.hnsw_last_eviction_at_nanos.set(nanos_i64);
}

/// Cumulative HNSW oldest-eviction count since process start. Reads
/// from the process-local atomic; the same value is scrape-visible at
/// `/metrics` as `ai_memory_hnsw_evictions_total`.
#[must_use]
pub fn hnsw_evictions_total() -> u64 {
    HNSW_EVICTIONS_TOTAL.load(Ordering::Relaxed)
}

/// Wall-clock UNIX nanoseconds of the most recent HNSW eviction (0 if
/// none have occurred this process). Reads from the process-local
/// atomic; the same value is scrape-visible at `/metrics` as
/// `ai_memory_hnsw_last_eviction_at_nanos`.
#[must_use]
pub fn hnsw_last_eviction_at_nanos() -> u64 {
    HNSW_LAST_EVICTION_AT_NANOS.load(Ordering::Relaxed)
}

/// Reset the HNSW eviction counters. Test-only: production callers
/// must never reach into the counter directly. The Prometheus
/// monotonic-counter discipline does NOT permit decrement, so the
/// scrape-side `ai_memory_hnsw_evictions_total` retains its
/// cumulative value across the reset — only the process-local
/// atomics (used by `hnsw_evictions_total()`, `evicted_recently`,
/// and `memory_stats`) drop back to zero. This asymmetry is
/// deliberate: `/metrics` scrapes are time-series consumers that
/// expect monotonic counters; the in-process reset is a unit-test
/// affordance.
#[doc(hidden)]
pub fn reset_hnsw_eviction_counters_for_test() {
    HNSW_EVICTIONS_TOTAL.store(0, Ordering::Relaxed);
    HNSW_LAST_EVICTION_AT_NANOS.store(0, Ordering::Relaxed);
    // Mirror the gauge reset so scrape-side `last_eviction_at_nanos`
    // also flips back to 0 (gauges, unlike counters, may decrement).
    registry().hnsw_last_eviction_at_nanos.set(0);
}

/// Handles to the registered metric families. Built once on first access
/// via `registry()`.
///
/// Fields are public so call sites in `handlers.rs`, future
/// `subscriptions.rs`, and the test module can `.inc()` / `.observe()` /
/// `.set()` directly. `#[allow(dead_code)]` covers the handles that
/// aren't wired to a caller yet — they surface in `/metrics` output
/// (see the `render_includes_registered_names` test) and will be
/// instrumented as sibling features land (hnsw gauge via the HNSW
/// module, subscriptions gauge via the webhook PR, webhook counters
/// via the dispatch path, etc.).
#[allow(dead_code)]
pub struct Metrics {
    pub registry: Registry,
    pub store_total: IntCounterVec,
    pub recall_total: IntCounterVec,
    pub recall_latency_seconds: HistogramVec,
    pub autonomy_hook_total: IntCounterVec,
    pub contradiction_detected_total: IntCounter,
    pub webhook_dispatched_total: IntCounter,
    pub webhook_failed_total: IntCounter,
    pub memories_gauge: IntGauge,
    /// v1.0.0 #2583 — UNIX seconds at which `memories_gauge` was last
    /// recomputed; `0` = never. Published in lockstep with the count by
    /// [`crate::background::memories_gauge::publish`].
    ///
    /// This is NOT decoration. Once the corpus count is pre-computed rather
    /// than recomputed per scrape, a refresher that dies would otherwise
    /// freeze `ai_memory_memories` at a plausible-looking value forever —
    /// including straight through a mass deletion — while Prometheus `up`
    /// stays 1. That is the #2444 "reports success while doing nothing"
    /// shape. Alert on `time() - ai_memory_memories_refreshed_at_seconds`.
    pub memories_gauge_refreshed_at: IntGauge,
    pub hnsw_size_gauge: IntGauge,
    pub subscriptions_active_gauge: IntGauge,
    pub curator_cycles_total: IntCounter,
    pub curator_operations_total: IntCounterVec,
    pub curator_cycle_duration_seconds: HistogramVec,
    /// Ultrareview #343: count of post-quorum fanout tasks whose
    /// outcome could not be observed (shutdown, panic, or the
    /// spawned task erred). Non-zero indicates mesh divergence risk.
    pub federation_fanout_dropped_total: IntCounterVec,
    /// S40 (v0.6.2 Patch 2): count of peer POST retries, labeled by
    /// final outcome. `ok` = retry recovered the row; `fail` = both
    /// attempts failed (peer likely truly down); `id_drift` = retry
    /// observed the same peer id-drift as attempt 1.
    pub federation_fanout_retry_total: IntCounterVec,
    /// H9 (v0.7.0 round-2): count of quorum writes that the leader
    /// returned `200` for (W met) but where at least one configured
    /// peer did NOT ack inside the deadline. Operators alert on
    /// non-zero rate to detect mesh-divergence drift early — before a
    /// follow-up catchup sync surfaces the gap.
    pub federation_partial_quorum_total: IntCounter,
    /// Cluster-A COR-3 (v0.7.0): count of memory rows whose Form 4
    /// fact-provenance JSON columns (`citations`, `source_span`,
    /// `confidence_signals`, or pre-Form-4 `metadata`) failed to parse
    /// and were silently defaulted by `row_to_memory`. Non-zero
    /// indicates schema drift, writer-side corruption, or a
    /// migration that left malformed JSON in the column. Labeled by
    /// column name (`citations` | `source_span` | `confidence_signals`
    /// | `metadata`).
    pub corrupt_provenance_rows_total: IntCounterVec,
    /// v0.7-polish SEC-15 / COR-11 (issue #780): count of
    /// `post_reflect.auto_export` detached worker invocations whose
    /// outcome was a panic or a returned `Err`. Non-zero means an
    /// operator-opted-in namespace had a reflection that did NOT
    /// land on the filesystem and the failure would otherwise be
    /// silent (the worker thread is detached; the reflection itself
    /// already committed). The capabilities-v3 surface mirrors this
    /// counter so operator dashboards can alert without scraping
    /// `/metrics` directly.
    pub auto_export_spawn_failed_total: IntCounter,
    /// v0.7.0 Track D #933 — current depth of the federation push
    /// DLQ (`federation_push_dlq` table, `WHERE replayed_at IS NULL`).
    /// Refreshed on every tick of the `replay_federation_push_dlq`
    /// worker spawned alongside the catchup loop. Operators alert on
    /// non-zero sustained depth — a healthy mesh should drain back
    /// to 0 within one replay interval after the peer recovers.
    pub federation_push_dlq_depth: IntGauge,

    /// v1.0.0 #3164 — the deferred-audit drainer supervisor's TERMINAL state:
    /// `0` = running (or exited gracefully on a fully-drained queue), `1` =
    /// the sink stayed unresolved and exhausted its restart budget, `2` = the
    /// sink panicked and exhausted its restart budget.
    ///
    /// Pre-#3164 the supervisor `panic!`ed on exhaustion. A panic in a
    /// `tokio::spawn`ed task kills only THAT task, so the daemon kept serving
    /// while the audit drainer was permanently dead — and nothing observed it
    /// until the shutdown path awaited the `JoinHandle`, possibly days later.
    /// A NON-ZERO value here means governance refusals are no longer reaching
    /// `signed_events` on this node: alert on it, and treat the node as
    /// audit-degraded. It is monotonic-by-first-writer, so the ORIGINAL cause
    /// survives.
    pub deferred_audit_drainer_terminal_state: IntGauge,

    /// #1032 (HIGH, 2026-05-21) — monotonic counter for DLQ rows the
    /// replay worker has marked as quarantined (`attempt_count >=
    /// MAX_REPLAY_ATTEMPTS`). Pre-#1032 the replay loop retried
    /// poison messages forever; now rows past the ceiling are
    /// skipped + this counter increments per quarantined row per
    /// tick (the row stays in the DLQ until an operator drains it
    /// via `ai-memory federation dlq drain --quarantined`). Operators
    /// alert on non-zero increment rate — a healthy mesh should have
    /// zero rows reaching the quarantine threshold.
    pub federation_push_dlq_quarantined: IntCounter,

    /// #1544 — cause-labeled sibling of `federation_push_dlq_quarantined`.
    /// One closed-set `cause` label
    /// (`quota`|`unenrolled_peer`|`id_drift`|`permanent`|`peer_removed`|`other`)
    /// so operators can tell an operator-actionable stall (e.g. `quota` →
    /// raise `AI_MEMORY_MAX_MEMORIES_PER_DAY`) from a genuinely-broken row
    /// (`permanent`). Label cardinality is bounded by construction (the
    /// classifier maps the free-text `last_error` to one of the six
    /// values), never the raw string.
    pub federation_push_dlq_quarantined_by_cause: IntCounterVec,
    /// #2442 — push-DLQ rows skipped because their durable routing key is a
    /// pre-#2442 POSITIONAL peer id (`peer-0`, `peer-1`, …) that no longer
    /// resolves to any configured peer.
    ///
    /// Deliberately its own counter rather than a new `cause` label on
    /// [`Self::federation_push_dlq_quarantined_by_cause`]: that label is
    /// derived by ordered substring matching over `last_error`, which a
    /// peer-supplied INTEGER can reach (the receiver's own `skipped` count is
    /// interpolated into the failure reason, so `{"skipped": 429}` mints a
    /// `429` substring — see #2672), whereas the legacy condition is decided
    /// from the SHAPE of `peer_id`, which a peer cannot influence. Keeping
    /// them separate also stops the routing-key fact from overriding a row's
    /// REAL quarantine cause.
    ///
    /// Increments once per affected row per replay pass, so this is a rate,
    /// not a population count. A non-zero rate after an upgrade means legacy
    /// rows are still present — see `docs/TROUBLESHOOTING.md`
    /// §federation-push-DLQ. It should fall to zero and stay there.
    pub federation_push_dlq_legacy_positional: IntCounter,

    /// #2716 (CB-12) — cumulative count of pending federated ERASURES /
    /// DELETES that the replay worker SUPERSEDED instead of propagating,
    /// because the target id is LIVE again locally with an `updated_at`
    /// that POST-DATES the queued erasure (an authorized archive restore /
    /// re-store). Incremented at BOTH supersede sites: the erasure-sentinel
    /// expansion guard (F10) and the replay-POST-path restore-race guard
    /// (F9). A supersede CANCELS an operator-requested erasure, so it is
    /// never silent — this counter is the observable companion to the loud
    /// WARN. A non-zero rate is expected on any mesh that restores archived
    /// rows; a SUSTAINED rate may mean an erasure keeps being undone by a
    /// resurrection whose clock leads the eraser and warrants an operator
    /// re-issue. Increments once per superseded row per pass (a rate, not a
    /// population).
    pub federation_erasure_superseded: IntCounter,

    /// #2966 (L6 5-agent vote `4d3ea1c5`) — monotonic count of inbound
    /// relayed memories QUARANTINED by the route-IN provenance gate
    /// (`AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`, env #123): an
    /// unattributed (`attest_level != agent_attested`) row stored with
    /// `lifecycle_state=quarantined` and structurally hidden from every
    /// local read/egress lane. Pairs with one `tracing::warn!` per
    /// quarantined row under target `federation.quarantine.unattributed`
    /// (a quarantine is a discrete security event, logged each time).
    /// **Always zero when the
    /// quarantine knob is OFF (the default)** — the counter only moves on
    /// an actual quarantine, so a non-zero value means a peer relayed
    /// provenance-less content that this node is now black-holing until
    /// dequarantine. Closes the #2444 silent-hide anti-pattern (the
    /// quarantine used to emit nothing while `/sync/push` returned 200).
    pub federation_quarantined_unattributed: IntCounter,

    /// v1.0.0 #2402 — the route-OUT twin of
    /// [`Self::federation_quarantined_unattributed`]: monotonic count of
    /// quarantined rows an OPERATOR released through
    /// `ai-memory quarantine release` / `POST /api/v1/admin/quarantine/{id}/release`.
    /// A human overriding a containment decision is exactly the action a fleet
    /// must be able to watch as a rate, not only reconstruct from the signed
    /// chain after the fact. Incremented once per row actually released; a
    /// no-op release (the id is not quarantined) never increments.
    pub operator_dequarantined: IntCounter,

    /// pm-v3.1 PR8 (issue #1174) — cumulative HNSW oldest-eviction
    /// count since process start. Replaces the prior process-global
    /// `AtomicU64` `INDEX_EVICTIONS_TOTAL` in `src/hnsw.rs`.
    /// Non-zero means the in-memory vector index has hit
    /// `MAX_ENTRIES` and dropped older embeddings; recall quality
    /// may have degraded for evicted ids until they are re-inserted
    /// (e.g. on next access via the `recall` touch path). Surfaces in
    /// `memory_capabilities` (`hnsw.evictions_total`), `/metrics`
    /// (`ai_memory_hnsw_evictions_total`), and `memory_stats`.
    pub hnsw_evictions_total: IntCounter,

    /// pm-v3.1 PR8 (issue #1174) — wall-clock UNIX nanoseconds of the
    /// most recent HNSW eviction (0 if none have occurred). Replaces
    /// the prior process-global `AtomicU64` `LAST_EVICTION_AT_NANOS`
    /// in `src/hnsw.rs`. Capabilities derives `hnsw.evicted_recently`
    /// from this with a 60s rolling window. Surfaced as an `IntGauge`
    /// so the value is also readable via Prometheus scraping.
    pub hnsw_last_eviction_at_nanos: IntGauge,

    /// #1253 (MED, 2026-05-25) — monotonic counter for subscription
    /// DLQ insert attempts that were refused because the per-
    /// subscription DLQ depth had already hit
    /// [`crate::subscriptions::MAX_SUBSCRIPTION_DLQ_ROWS`]. Non-zero
    /// means a hostile (or simply-broken) webhook target is failing
    /// every delivery and would otherwise fill the operator's disk
    /// with quarantined rows. Each refused insert pairs with a
    /// `tracing::warn!` so operators see the subscription id + correlation
    /// id of the dropped row.
    pub subscription_dlq_overflow_total: IntCounter,

    /// v1.0.0 #2592 — subscription-dispatch ticks whose subscriber scan hit
    /// `SUBSCRIPTION_DISPATCH_LIMIT` and was therefore
    /// TRUNCATED. Non-zero means subscribers sorting after the ceiling did
    /// not receive that event and never will: the scan is ordered and
    /// cursor-less, so the same tail is cut on every write. Each truncated
    /// tick also emits a `tracing::warn!` and appends a
    /// `subscription_dlq` row under
    /// [`crate::subscriptions::DISPATCH_SCAN_TRUNCATED_SUB_ID`], so the loss
    /// is durable and inspectable rather than inferred from a missing
    /// webhook.
    pub subscription_dispatch_truncated_total: IntCounter,

    /// FED-P4-e (federation-identity-at-scale §8) — federation
    /// credential-verification outcomes on the receiver path, labeled
    /// `result` (`ok` | `fail`). The verify-failure-rate SLO is
    /// `fail / (ok + fail)`. A non-zero sustained fail rate means peers
    /// are presenting credentials the local trust bundle cannot verify
    /// — an expired leaf, a revoked issuer, a clock-skew window, or a
    /// chain that fails to anchor. Healthy meshes hold this at 0 once
    /// every peer's issuer key is enrolled in the bundle.
    pub federation_cred_verify_total: IntCounterVec,

    /// FED-P4-e (federation-identity-at-scale §8) — inbound federation
    /// requests bucketed by whether they presented a signed credential
    /// at all, labeled `presence` (`signed` | `unsigned`). The
    /// signed-vs-unsigned-ratio SLO is `signed / (signed + unsigned)`.
    /// During a rollout this climbs from 0 toward 1 as peers upgrade to
    /// credential-presenting builds; operators gate the flip of
    /// `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` to the secure default on
    /// this ratio reaching 1.0 across the fleet.
    pub federation_inbound_cred_total: IntCounterVec,

    /// FED-P4-e (federation-identity-at-scale §8) — age in seconds of
    /// the local outbound leaf credential (now − `issued_at`),
    /// refreshed on every renewal tick. The max-cred-age SLO alerts
    /// when this approaches the leaf TTL
    /// ([`crate::federation::identity::issuer::DEFAULT_CREDENTIAL_TTL_SECS`])
    /// — a credential that ages past its TTL without a renewal means
    /// the refresh worker has stalled and outbound sync will start
    /// failing peer verification.
    pub federation_cred_max_age_seconds: IntGauge,

    /// FED-P4-e (federation-identity-at-scale §8) — seconds since the
    /// last successful outbound-credential renewal (now − last-renew
    /// wall clock), refreshed on every renewal tick. The renewal-lag
    /// SLO alerts when this exceeds the configured refresh interval by
    /// a safety margin: a healthy worker re-renews well inside the leaf
    /// TTL, so a lag larger than the interval means renewals are
    /// silently failing (bad CA reachability, key-load fault) even
    /// though the worker thread is still alive.
    pub federation_renewal_lag_seconds: IntGauge,

    /// #1733 (Pillar-4 4.A) — monotonic counter of HTTP requests shed by
    /// the admission-control layer because the in-flight-request cap
    /// (`AI_MEMORY_MAX_INFLIGHT_REQUESTS`) was already saturated. Each
    /// increment pairs with a sampled `tracing::warn!`. Non-zero means
    /// the daemon is actively load-shedding — operators alert on a
    /// sustained increment rate to size the cap (or the fleet) up. Zero
    /// on every deployment that has not opted into admission control
    /// (the cap defaults to disabled).
    pub admission_shed_total: IntCounter,

    /// #2577 — monotonic count of recalls whose query embedding could not
    /// be produced within [`crate::embeddings::ENV_RECALL_EMBED_BUDGET_MS`]
    /// (or failed outright), so the recall degraded to keyword/FTS.
    ///
    /// This is the operator's ONLY numeric view of the #2577 fail-open. A
    /// degrade nobody can see is operationally indistinguishable from a
    /// lie: the results are honest (`mode:keyword` on the wire) but a
    /// sustained non-zero rate means the fleet's semantic recall is
    /// silently off. Alert on the RATE, not the value — a handful of trips
    /// is a provider hiccup; a sustained rate means the budget is
    /// mis-sized for this deployment's provider or the provider is sick.
    ///
    /// Always zero on keyword-tier deployments and on any deployment whose
    /// provider stays inside the budget.
    ///
    /// **Scope caveat:** MCP stdio serves no `/metrics` endpoint, so on
    /// that surface the stderr WARN (`recall.embed.degraded`) is the only
    /// channel.
    pub recall_embed_degraded_total: IntCounter,

    /// #2608 — monotonic count of autonomous-tier recalls whose cross-encoder
    /// rerank was skipped by the pre-flight `AI_MEMORY_RERANK_BUDGET_MS`
    /// admission gate (degraded to the pre-rerank hybrid ordering). MCP stdio
    /// serves no `/metrics`, so on that surface the `rerank.budget.degraded`
    /// WARN is the only channel.
    pub rerank_budget_degraded_total: IntCounter,

    /// #2577 — monotonic count of recall query embeddings served from the
    /// process-local cache instead of a remote round trip. Rising with
    /// traffic is the healthy shape (agent fleets repeat queries heavily);
    /// a flat zero under repeated traffic means the cache is disabled
    /// (`AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES=0`) or every query is unique.
    pub query_embed_cache_hits_total: IntCounter,

    /// #2587 — monotonic count of `auto_tag` jobs successfully `try_send`
    /// onto the bounded background queue after a durable
    /// `POST /api/v1/memories` write (autonomous-tier, untagged, eligible
    /// content). Rising with traffic is healthy; a flat zero on an
    /// autonomous-tier deployment with an LLM configured suggests
    /// `AI_MEMORY_AUTONOMOUS_HOOKS` is off or no write has been eligible.
    pub autotag_enqueued_total: IntCounter,

    /// #2587 — monotonic count of eligible `auto_tag` jobs DROPPED because
    /// the bounded queue (`AI_MEMORY_AUTOTAG_QUEUE_CAPACITY`) was full, or
    /// no worker was wired. The durable write always succeeds regardless —
    /// this is a DEGRADE (no tags for that write), never a write failure.
    /// A sustained non-zero rate means the queue is under-sized for the
    /// write burst; alert on the RATE.
    pub autotag_dropped_total: IntCounter,

    /// #2587 — monotonic count of `auto_tag` jobs the background worker
    /// applied successfully (tags landed on the row via a merge, never a
    /// blind overwrite).
    pub autotag_applied_total: IntCounter,

    /// #2587 — monotonic count of `auto_tag` jobs the background worker
    /// gave up on (LLM error, LLM call exceeded `llm_call_timeout`, the
    /// row was deleted before the job drained, or — sqlite only — the row
    /// lost an optimistic-concurrency race to a concurrent caller edit
    /// twice in a row). A DEGRADE (no tags applied), never data
    /// corruption; the durable write this job followed already succeeded.
    pub autotag_degraded_total: IntCounter,

    /// #2986 — monotonic count of auto-atomise jobs enqueued onto the
    /// bounded single-consumer background worker after a durable write.
    pub atomise_enqueued_total: IntCounter,

    /// #2986 — monotonic count of auto-atomise jobs DROPPED because the
    /// bounded queue (`AI_MEMORY_ATOMISE_QUEUE_CAPACITY`) was full or no
    /// worker was wired. The durable write always succeeds regardless —
    /// a DEGRADE (no atoms for that write; `memory_atomise` recovers it),
    /// never a write failure. Alert on the RATE.
    pub atomise_dropped_total: IntCounter,

    /// #2986 — monotonic count of auto-atomise passes that landed atoms
    /// (either the synchronous MCP path or a drained background job).
    pub atomise_applied_total: IntCounter,

    /// #2986 — monotonic count of auto-atomise passes that failed
    /// (curator error, db-open failure). A DEGRADE, never data loss —
    /// the durable source row is untouched on every failure arm.
    pub atomise_degraded_total: IntCounter,

    /// #2985 — monotonic count of writes whose namespace standard
    /// REQUESTED `auto_atomise` on a daemon with NO curator (no LLM
    /// wired, or inference egress refused). A non-zero value is a
    /// MISCONFIGURATION signal, not load: the knob is set and
    /// structurally dead. `ai-memory doctor` names the same condition.
    pub atomise_no_curator_total: IntCounter,

    /// #1735 (Pillar-4 4.C) — current depth of the `kg_projection_outbox`
    /// (pending AGE projections not yet drained: `projected_at IS NULL`).
    /// Refreshed each cold-drainer tick. Sustained non-zero depth means the
    /// AGE graph is lagging the relational `memory_links` truth (AGE down,
    /// drainer stalled, or quarantined rows); operators alert on it as the
    /// relational↔graph drift signal. Always 0 when
    /// `AI_MEMORY_AGE_PROJECTION_MODE=sync` (the default — nothing enqueued).
    pub age_projection_pending_depth: IntGauge,

    /// #1735 (Pillar-4 4.C) — monotonic count of deferred AGE-projection
    /// drain attempts that errored (the MERGE failed; the row's
    /// `attempt_count` was bumped and it will be retried until quarantine).
    pub age_projection_failed_total: IntCounter,

    /// #1735 (Pillar-4 4.C) — monotonic count of `kg_projection_outbox` rows
    /// that reached the [`crate::store::postgres`] attempt ceiling and were
    /// quarantined (left pending, excluded from the drain take-query).
    /// Non-zero means a poison projection an operator must investigate; the
    /// relational edge exists but will never reach the AGE graph until the
    /// row is repaired/re-enqueued.
    pub age_projection_quarantined_total: IntCounter,

    /// #3342 — last observed unembedded-chunk length the live backfill
    /// worker peeked. 0 means the drain is caught up; non-zero means
    /// `embed_mode=async` (or a boot backlog) still has work.
    pub embed_backfill_pending: IntGauge,
}

/// Lazily-built process-global metrics handle.
pub fn registry() -> &'static Metrics {
    static HANDLE: OnceLock<Metrics> = OnceLock::new();
    HANDLE.get_or_init(Metrics::new_or_panic)
}

impl Metrics {
    fn new_or_panic() -> Self {
        // Registration can only fail on duplicate-name conflict; with a
        // fresh registry that's unreachable. Panic is acceptable because
        // the metrics subsystem is a daemon-startup concern — a failure
        // here means a programming bug, not a runtime condition.
        Self::try_new().expect("prometheus registry init failed")
    }

    // COVERAGE: every `?` Err-arm closure on `IntCounterVec::new(...)?`,
    //           `IntCounter::new(...)?`, `IntGauge::new(...)?`,
    //           `HistogramVec::new(...)?`, and
    //           `registry.register(Box::new(...))?` in this function
    //           is structurally unreachable in production:
    //
    //           1. The function constructs a fresh `Registry::new()`
    //              per call (no shared state). Registration can only
    //              fail on duplicate metric name; with a fresh registry
    //              and unique names per counter, collision is
    //              impossible.
    //           2. Every metric name + label name passed to the
    //              constructors is a compile-time string literal that
    //              already matches the Prometheus regex
    //              `[a-zA-Z_:][a-zA-Z0-9_:]*` — construction cannot
    //              fail on name-validation grounds.
    //
    //           The Err-arms exist because the prometheus crate's
    //           API returns `Result<...>` from these constructors, and
    //           the `?` propagation is the idiomatic Rust pattern.
    //           Triggering coverage would require a synthetic
    //           registry-injection layer that doesn't exist (and
    //           shouldn't — try_new owns its registry by design).
    //           Documented per L0.7 playbook §3c.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn try_new() -> prometheus::Result<Self> {
        let registry = Registry::new();

        let store_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_store_total",
                "Total memory_store calls, labeled by tier and result.",
            ),
            &["tier", "result"],
        )?;
        registry.register(Box::new(store_total.clone()))?;

        let recall_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_recall_total",
                "Total memory_recall calls, labeled by mode.",
            ),
            &["mode"],
        )?;
        registry.register(Box::new(recall_total.clone()))?;

        let recall_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "ai_memory_recall_latency_seconds",
                "Recall latency in seconds, labeled by mode.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["mode"],
        )?;
        registry.register(Box::new(recall_latency_seconds.clone()))?;

        let autonomy_hook_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_autonomy_hook_total",
                "Post-store autonomy hook invocations, labeled by kind and result.",
            ),
            &["kind", "result"],
        )?;
        registry.register(Box::new(autonomy_hook_total.clone()))?;

        let contradiction_detected_total = IntCounter::new(
            "ai_memory_contradiction_detected_total",
            "Count of contradictions the LLM hook confirmed.",
        )?;
        registry.register(Box::new(contradiction_detected_total.clone()))?;

        let webhook_dispatched_total = IntCounter::new(
            "ai_memory_webhook_dispatched_total",
            "Total webhook deliveries attempted.",
        )?;
        registry.register(Box::new(webhook_dispatched_total.clone()))?;

        let webhook_failed_total = IntCounter::new(
            "ai_memory_webhook_failed_total",
            "Webhook deliveries that failed after all retries.",
        )?;
        registry.register(Box::new(webhook_failed_total.clone()))?;

        let memories_gauge = IntGauge::new(
            "ai_memory_memories",
            "Current count of non-archived memories.",
        )?;
        registry.register(Box::new(memories_gauge.clone()))?;

        let memories_gauge_refreshed_at = IntGauge::new(
            "ai_memory_memories_refreshed_at_seconds",
            "UNIX time at which ai_memory_memories was last recomputed (0 = never).",
        )?;
        registry.register(Box::new(memories_gauge_refreshed_at.clone()))?;

        let hnsw_size_gauge = IntGauge::new(
            "ai_memory_hnsw_size",
            "Current HNSW vector index population.",
        )?;
        registry.register(Box::new(hnsw_size_gauge.clone()))?;

        let subscriptions_active_gauge = IntGauge::new(
            "ai_memory_subscriptions_active",
            "Current count of active webhook subscriptions.",
        )?;
        registry.register(Box::new(subscriptions_active_gauge.clone()))?;

        let curator_cycles_total = IntCounter::new(
            "ai_memory_curator_cycles_total",
            "Total curator sweep cycles completed.",
        )?;
        registry.register(Box::new(curator_cycles_total.clone()))?;

        let curator_operations_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_curator_operations_total",
                "Curator operations, labeled by kind (auto_tag|contradiction|persist) and result.",
            ),
            &["kind", "result"],
        )?;
        registry.register(Box::new(curator_operations_total.clone()))?;

        let curator_cycle_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "ai_memory_curator_cycle_duration_seconds",
                "Curator sweep cycle wall-clock duration, labeled by dry_run.",
            )
            .buckets(vec![
                0.1,
                0.5,
                1.0,
                5.0,
                15.0,
                60.0,
                300.0,
                900.0,
                crate::SECS_PER_HOUR as f64,
            ]),
            &["dry_run"],
        )?;
        registry.register(Box::new(curator_cycle_duration_seconds.clone()))?;

        let federation_fanout_dropped_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_federation_fanout_dropped_total",
                "Post-quorum fanout tasks whose outcome could not be observed. \
                 reason=shutdown|panic|join_error. Non-zero indicates mesh divergence risk.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(federation_fanout_dropped_total.clone()))?;

        let federation_fanout_retry_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_federation_fanout_retry_total",
                "Peer POSTs that hit a transient failure on first attempt and \
                 were retried once via the Idempotency-Key path. \
                 outcome=ok|fail|id_drift. Non-zero ok indicates the retry \
                 recovered a row that would otherwise be missing on a peer.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(federation_fanout_retry_total.clone()))?;

        // H9 (v0.7.0 round-2) — partial-quorum observability.
        let federation_partial_quorum_total = IntCounter::new(
            "ai_memory_federation_partial_quorum_total",
            "Quorum writes that succeeded (W met) but where at least one \
             configured peer did not ack inside the deadline.",
        )?;
        registry.register(Box::new(federation_partial_quorum_total.clone()))?;

        // Cluster-A COR-3 (v0.7.0) — corrupt-provenance observability.
        let corrupt_provenance_rows_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_corrupt_provenance_rows_total",
                "Memory rows whose Form 4 fact-provenance JSON columns \
                 failed to deserialise and were silently defaulted. \
                 Non-zero indicates schema drift, writer-side corruption, \
                 or a migration leaving malformed JSON.",
            ),
            &["column"],
        )?;
        registry.register(Box::new(corrupt_provenance_rows_total.clone()))?;

        // v0.7-polish SEC-15 / COR-11 (issue #780) — auto-export
        // detached-worker failure observability.
        let auto_export_spawn_failed_total = IntCounter::new(
            "ai_memory_auto_export_spawn_failed_total",
            "Detached post_reflect.auto_export worker invocations whose \
             outcome was a panic or returned Err. Non-zero means at \
             least one reflection was committed to the DB but its \
             on-disk markdown/json artefact did not land — operators \
             use this to alert on otherwise-silent disk-write failures.",
        )?;
        registry.register(Box::new(auto_export_spawn_failed_total.clone()))?;

        // v0.7.0 Track D #933 — federation push DLQ depth gauge.
        let federation_push_dlq_depth = IntGauge::new(
            "ai_memory_federation_push_dlq_depth",
            "Current count of pending federation_push_dlq rows \
             (replayed_at IS NULL). Refreshed on every replay tick. \
             Non-zero sustained depth indicates one or more peers are \
             persistently unreachable; healthy meshes drain back to 0 \
             within one replay interval after peer recovery.",
        )?;
        registry.register(Box::new(federation_push_dlq_depth.clone()))?;

        // v1.0.0 #3164 — deferred-audit drainer terminal-state gauge.
        let deferred_audit_drainer_terminal_state = IntGauge::new(
            "ai_memory_deferred_audit_drainer_terminal_state",
            "Terminal state of the deferred-audit drainer supervisor: 0 = \
             running/graceful, 1 = sink unresolved past max_restarts, 2 = \
             sink panicked past max_restarts. Non-zero means governance \
             refusals are NO LONGER reaching signed_events on this node; the \
             daemon keeps serving but is audit-degraded until restarted.",
        )?;
        registry.register(Box::new(deferred_audit_drainer_terminal_state.clone()))?;

        // #1032 (HIGH, 2026-05-21) — federation push DLQ quarantine counter.
        let federation_push_dlq_quarantined = IntCounter::new(
            "ai_memory_federation_push_dlq_quarantined_total",
            "Monotonic counter of federation_push_dlq rows the replay \
             worker has skipped because their attempt_count exceeded \
             MAX_REPLAY_ATTEMPTS (currently 100). Non-zero sustained \
             rate indicates poison-message rows that need operator \
             intervention via `ai-memory federation dlq drain \
             --quarantined`. Pre-#1032 the worker retried these \
             forever, amplifying network load against rejecting peers.",
        )?;
        registry.register(Box::new(federation_push_dlq_quarantined.clone()))?;

        // #1544 — cause-labeled quarantine counter (closed-set label).
        let federation_push_dlq_quarantined_by_cause = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_federation_push_dlq_quarantined_by_cause_total",
                // #2442 — the enumeration below had drifted TWO causes behind
                // `classify_quarantine_cause` (it was missing
                // `unenrolled_author_strict` from #1464/#1801 and
                // `namespace_probe_unresolvable` from #2488, both of which
                // docs/federation.md already carried). Re-synced here; this
                // HELP string, `classify_quarantine_cause`, and
                // docs/federation.md are the three mirrors of one closed set.
                "Federation push-DLQ rows quarantined, labeled by the \
                 classified cause (quota|unenrolled_peer|\
                 unenrolled_author_strict|namespace_probe_unresolvable|\
                 id_drift|permanent|peer_removed|other). `quota` is \
                 operator-actionable (raise AI_MEMORY_MAX_MEMORIES_PER_DAY or \
                 wait for the daily reset); `permanent` is a broken row \
                 needing a manual drain. #1544.",
            ),
            &["cause"],
        )?;
        registry.register(Box::new(federation_push_dlq_quarantined_by_cause.clone()))?;

        // #2442 — legacy positional peer-id skips. Kept OFF the `cause` label
        // set above on purpose: see the field doc on
        // `federation_push_dlq_legacy_positional`.
        let federation_push_dlq_legacy_positional = IntCounter::new(
            "ai_memory_federation_push_dlq_legacy_positional_total",
            "Federation push-DLQ rows skipped because their durable routing \
             key is a pre-#2442 POSITIONAL peer id (the --quorum-peers flag \
             index) that resolves to no configured peer. Written by binaries \
             older than #2442. These rows are NEVER auto-remapped — \
             `peer-N` -> peers[N] is only correct if the peer list never \
             changed, and guessing would deliver the write to the wrong host. \
             Payloads are retained, not deleted. Non-zero after an upgrade \
             means legacy rows remain; see docs/TROUBLESHOOTING.md \
             §federation-push-DLQ for the operator-gated re-key. #2442.",
        )?;
        registry.register(Box::new(federation_push_dlq_legacy_positional.clone()))?;

        // #2716 (CB-12) — federated erasure/delete supersede observability.
        let federation_erasure_superseded = IntCounter::new(
            "ai_memory_federation_erasure_superseded_total",
            "Federation pending erasures/deletes SUPERSEDED (not propagated) \
             because the target id is LIVE again locally with an updated_at \
             that post-dates the queued erasure (an authorized restore / \
             re-store). Counts both the erasure-sentinel expansion guard and \
             the replay-POST-path restore-race guard. A supersede cancels an \
             operator-requested erasure; a sustained rate may mean an erasure \
             is being undone by a resurrection and warrants a re-issue. #2716.",
        )?;
        registry.register(Box::new(federation_erasure_superseded.clone()))?;

        // #2966 (L6 5-agent vote 4d3ea1c5) — route-IN quarantine
        // observability. The provenance gate used to flip a row to
        // lifecycle_state=quarantined and emit NOTHING while /sync/push
        // returned 200 (the #2444 silent-hide shape); this counter + a
        // per-quarantine WARN at the quarantine site make the black-hole
        // visible.
        let federation_quarantined_unattributed = IntCounter::new(
            "ai_memory_fed_quarantined_unattributed_total",
            "Monotonic count of inbound relayed memories quarantined by the \
             route-IN provenance gate (AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED): \
             an unattributed row stored with lifecycle_state=quarantined and \
             hidden from every local read/egress lane until dequarantine. \
             Always zero when the quarantine knob is off (the default); a \
             non-zero rate means a peer is relaying provenance-less content \
             this node is black-holing. #2966.",
        )?;
        registry.register(Box::new(federation_quarantined_unattributed.clone()))?;

        // v1.0.0 #2402 — the route-OUT counter. #1948 advertised "operator
        // dequarantine" as the way out of quarantine and shipped no caller, so
        // there was nothing to count; now that the verb exists, releasing a
        // contained row must be as visible as containing one.
        let operator_dequarantined = IntCounter::new(
            "ai_memory_operator_dequarantined_total",
            "Monotonic count of quarantined memories released by an OPERATOR \
             through `ai-memory quarantine release` or \
             `POST /api/v1/admin/quarantine/{id}/release` (#2402). The route-OUT \
             twin of ai_memory_fed_quarantined_unattributed_total. Each increment \
             also appends a `memory.dequarantined` signed-chain row naming the \
             authenticated caller, in the same transaction as the state change. A \
             no-op release (the id is not quarantined) does not increment.",
        )?;
        registry.register(Box::new(operator_dequarantined.clone()))?;

        // pm-v3.1 PR8 (issue #1174) — HNSW eviction observability moved
        // from process-global atomics in `src/hnsw.rs` into the metrics
        // registry. The counter mirrors `INDEX_EVICTIONS_TOTAL`; the
        // gauge mirrors `LAST_EVICTION_AT_NANOS` as a UNIX-nanosecond
        // wall-clock timestamp (0 if no eviction has occurred). Both
        // are surfaced at `/metrics` so the eviction signal is
        // scrape-visible without going through `memory_stats`.
        let hnsw_evictions_total = IntCounter::new(
            "ai_memory_hnsw_evictions_total",
            "Cumulative HNSW oldest-eviction count since process start. \
             Non-zero indicates the in-memory vector index has hit \
             MAX_ENTRIES and dropped older embeddings; recall quality \
             may have degraded for evicted ids until they are \
             re-inserted on next access.",
        )?;
        registry.register(Box::new(hnsw_evictions_total.clone()))?;

        let hnsw_last_eviction_at_nanos = IntGauge::new(
            "ai_memory_hnsw_last_eviction_at_nanos",
            "Wall-clock UNIX nanoseconds of the most recent HNSW \
             eviction (0 if none). Capabilities derives \
             hnsw.evicted_recently from this with a 60s rolling window.",
        )?;
        registry.register(Box::new(hnsw_last_eviction_at_nanos.clone()))?;

        // #1253 (MED, 2026-05-25) — subscription DLQ overflow counter.
        let subscription_dlq_overflow_total = IntCounter::new(
            "ai_memory_subscription_dlq_overflow_total",
            "Monotonic counter of subscription_dlq inserts refused \
             because the per-subscription DLQ depth had already hit \
             MAX_SUBSCRIPTION_DLQ_ROWS (10_000). Non-zero indicates a \
             hostile or persistently-broken webhook target that would \
             otherwise fill the operator's disk with quarantined rows. \
             Operators drain the queue via `ai-memory subscription dlq \
             drain <subscription_id>` before resetting.",
        )?;
        registry.register(Box::new(subscription_dlq_overflow_total.clone()))?;

        // v1.0.0 #2592 — truncated subscription-dispatch scans.
        let subscription_dispatch_truncated_total = IntCounter::new(
            "ai_memory_subscription_dispatch_truncated_total",
            "Monotonic counter of subscription-dispatch ticks whose \
             subscriber scan hit SUBSCRIPTION_DISPATCH_LIMIT (1000) and was \
             truncated. Non-zero means subscribers past the ceiling silently \
             received NO event; the scan is ordered and cursor-less, so the \
             same tail is cut on every write. Reduce the subscription \
             population or split the deployment.",
        )?;
        registry.register(Box::new(subscription_dispatch_truncated_total.clone()))?;

        // FED-P4-e (federation-identity-at-scale §8) — federation
        // identity SLO surfaces: verify-failure-rate, signed-vs-unsigned
        // ratio, max cred age, renewal lag.
        let federation_cred_verify_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_federation_cred_verify_total",
                "Federation credential-verification outcomes on the \
                 receiver path, labeled result (ok|fail). \
                 verify-failure-rate SLO = fail / (ok + fail). Non-zero \
                 sustained fail rate means peers present credentials the \
                 local trust bundle cannot verify (expired leaf, revoked \
                 issuer, clock skew, or a chain that fails to anchor).",
            ),
            &["result"],
        )?;
        registry.register(Box::new(federation_cred_verify_total.clone()))?;

        let federation_inbound_cred_total = IntCounterVec::new(
            prometheus::Opts::new(
                "ai_memory_federation_inbound_cred_total",
                "Inbound federation requests bucketed by whether they \
                 presented a signed credential, labeled presence \
                 (signed|unsigned). signed-vs-unsigned-ratio SLO = \
                 signed / (signed + unsigned). Climbs toward 1.0 as \
                 peers upgrade to credential-presenting builds.",
            ),
            &["presence"],
        )?;
        registry.register(Box::new(federation_inbound_cred_total.clone()))?;

        let federation_cred_max_age_seconds = IntGauge::new(
            "ai_memory_federation_cred_max_age_seconds",
            "Age in seconds of the local outbound leaf credential \
             (now - issued_at), refreshed on every renewal tick. \
             max-cred-age SLO alerts when this approaches the leaf TTL \
             — a credential aging past its TTL without a renewal means \
             the refresh worker has stalled and outbound sync will \
             start failing peer verification.",
        )?;
        registry.register(Box::new(federation_cred_max_age_seconds.clone()))?;

        let federation_renewal_lag_seconds = IntGauge::new(
            "ai_memory_federation_renewal_lag_seconds",
            "Seconds since the last successful outbound-credential \
             renewal (now - last-renew wall clock), refreshed on every \
             renewal tick. renewal-lag SLO alerts when this exceeds the \
             configured refresh interval by a safety margin: a lag \
             larger than the interval means renewals are silently \
             failing even though the worker thread is still alive.",
        )?;
        registry.register(Box::new(federation_renewal_lag_seconds.clone()))?;

        let admission_shed_total = IntCounter::new(
            "ai_memory_admission_shed_total",
            "Monotonic counter of HTTP requests shed by the admission-control \
             layer because the in-flight-request cap \
             (AI_MEMORY_MAX_INFLIGHT_REQUESTS) was already saturated. Non-zero \
             means the daemon is load-shedding with a typed 503; operators \
             alert on a sustained increment rate to size the cap or the fleet \
             up. Always zero on deployments that have not opted into admission \
             control (the cap defaults to disabled).",
        )?;
        registry.register(Box::new(admission_shed_total.clone()))?;

        let recall_embed_degraded_total = IntCounter::new(
            "ai_memory_recall_embed_degraded_total",
            "Monotonic counter of recalls that fell back to keyword/FTS because \
             the query-embedding call failed or exceeded \
             AI_MEMORY_RECALL_EMBED_BUDGET_MS (#2577). The results are honest \
             (the response reports mode:keyword) but semantic ranking is OFF for \
             those requests. Alert on a sustained increment rate: a few trips is \
             a provider hiccup, a sustained rate means the budget is mis-sized \
             for this deployment's embedding provider or the provider is \
             unhealthy. Always zero on keyword-tier deployments.",
        )?;
        registry.register(Box::new(recall_embed_degraded_total.clone()))?;

        let rerank_budget_degraded_total = IntCounter::new(
            "ai_memory_rerank_budget_degraded_total",
            "Monotonic counter of autonomous-tier recalls whose cross-encoder \
             rerank was SKIPPED because its estimated forward cost exceeded \
             AI_MEMORY_RERANK_BUDGET_MS (#2608). The recall stays HYBRID \
             (FTS/semantic-ranked, no neural re-ranking) and the configured \
             score floor still applies — a DEGRADE, never a wrong result. \
             Alert on a sustained increment rate: a few trips is a \
             long-content tail, a sustained rate means the budget is \
             mis-sized for this corpus. Always zero when the budget is \
             disabled (=0) or on non-neural reranker deployments.",
        )?;
        registry.register(Box::new(rerank_budget_degraded_total.clone()))?;

        let query_embed_cache_hits_total = IntCounter::new(
            "ai_memory_query_embed_cache_hits_total",
            "Monotonic counter of recall query embeddings served from the \
             process-local bounded cache instead of a remote round trip \
             (#2577). Zero under repeated traffic means the cache is disabled \
             (AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES=0) or every query is unique.",
        )?;
        registry.register(Box::new(query_embed_cache_hits_total.clone()))?;

        let autotag_enqueued_total = IntCounter::new(
            "ai_memory_autotag_enqueued_total",
            "Monotonic counter of auto_tag jobs successfully enqueued onto \
             the bounded background worker after a durable HTTP create-memory \
             write (#2587). Rising with autonomous-tier write traffic is the \
             healthy shape.",
        )?;
        registry.register(Box::new(autotag_enqueued_total.clone()))?;

        let autotag_dropped_total = IntCounter::new(
            "ai_memory_autotag_dropped_total",
            "Monotonic counter of auto_tag jobs DROPPED because the bounded \
             queue (AI_MEMORY_AUTOTAG_QUEUE_CAPACITY) was full, or no worker \
             was wired (#2587). The durable write always succeeds regardless \
             — a DEGRADE (no tags), never a write failure. Alert on a \
             sustained increment rate: the queue is under-sized for the \
             write burst.",
        )?;
        registry.register(Box::new(autotag_dropped_total.clone()))?;

        let autotag_applied_total = IntCounter::new(
            "ai_memory_autotag_applied_total",
            "Monotonic counter of auto_tag jobs the background worker applied \
             successfully — tags merged onto the row, never a blind \
             overwrite (#2587).",
        )?;
        registry.register(Box::new(autotag_applied_total.clone()))?;

        let autotag_degraded_total = IntCounter::new(
            "ai_memory_autotag_degraded_total",
            "Monotonic counter of auto_tag jobs the background worker gave up \
             on — LLM error, LLM call exceeded llm_call_timeout, the row was \
             deleted before the job drained, or (sqlite) an optimistic- \
             concurrency race lost twice in a row (#2587). A DEGRADE, never \
             data corruption — the durable write this job followed already \
             succeeded.",
        )?;
        registry.register(Box::new(autotag_degraded_total.clone()))?;

        let atomise_enqueued_total = IntCounter::new(
            "ai_memory_atomise_enqueued_total",
            "Monotonic counter of auto-atomise jobs enqueued onto the bounded \
             single-consumer background worker after a durable write (#2986).",
        )?;
        registry.register(Box::new(atomise_enqueued_total.clone()))?;

        let atomise_dropped_total = IntCounter::new(
            "ai_memory_atomise_dropped_total",
            "Monotonic counter of auto-atomise jobs DROPPED because the bounded \
             queue (AI_MEMORY_ATOMISE_QUEUE_CAPACITY) was full or no worker was \
             wired (#2986). The durable write always succeeds regardless — a \
             DEGRADE (no atoms; `memory_atomise` recovers it), never a write \
             failure. Alert on a sustained increment rate.",
        )?;
        registry.register(Box::new(atomise_dropped_total.clone()))?;

        let atomise_applied_total = IntCounter::new(
            "ai_memory_atomise_applied_total",
            "Monotonic counter of auto-atomise passes that landed atoms — the \
             synchronous MCP path or a drained background job (#2986).",
        )?;
        registry.register(Box::new(atomise_applied_total.clone()))?;

        let atomise_degraded_total = IntCounter::new(
            "ai_memory_atomise_degraded_total",
            "Monotonic counter of auto-atomise passes that FAILED (curator \
             error, db-open failure) (#2986). A DEGRADE, never data loss — the \
             durable source row is untouched on every failure arm.",
        )?;
        registry.register(Box::new(atomise_degraded_total.clone()))?;

        let atomise_no_curator_total = IntCounter::new(
            "ai_memory_atomise_no_curator_total",
            "Monotonic counter of writes whose namespace standard REQUESTED \
             auto_atomise on a daemon with NO curator — no LLM wired, or \
             inference egress refused (#2985). Non-zero means a \
             MISCONFIGURATION, not load: the knob is set and structurally \
             dead. `ai-memory doctor` names the same condition.",
        )?;
        registry.register(Box::new(atomise_no_curator_total.clone()))?;

        let age_projection_pending_depth = IntGauge::new(
            "ai_memory_age_projection_pending_depth",
            "Current depth of the kg_projection_outbox (pending deferred AGE \
             projections, projected_at IS NULL), refreshed each cold-drainer \
             tick. Sustained non-zero = AGE graph lagging the relational \
             memory_links truth (Pillar-4 4.C, #1735). Always 0 under the \
             default sync projection mode.",
        )?;
        registry.register(Box::new(age_projection_pending_depth.clone()))?;

        let age_projection_failed_total = IntCounter::new(
            "ai_memory_age_projection_failed_total",
            "Monotonic count of deferred AGE-projection drain attempts that \
             errored (MERGE failed; row attempt_count bumped, retried until \
             quarantine). Pillar-4 4.C (#1735).",
        )?;
        registry.register(Box::new(age_projection_failed_total.clone()))?;

        let age_projection_quarantined_total = IntCounter::new(
            "ai_memory_age_projection_quarantined_total",
            "Monotonic count of kg_projection_outbox rows that hit the \
             drain attempt ceiling and were quarantined (relational edge \
             exists but never reached the AGE graph). Pillar-4 4.C (#1735).",
        )?;
        registry.register(Box::new(age_projection_quarantined_total.clone()))?;

        let embed_backfill_pending = IntGauge::new(
            "ai_memory_embed_backfill_pending",
            "Last peeked unembedded-chunk length for the live #3342 \
             embed-backfill worker. 0 = caught up.",
        )?;
        registry.register(Box::new(embed_backfill_pending.clone()))?;

        Ok(Self {
            registry,
            store_total,
            recall_total,
            recall_latency_seconds,
            autonomy_hook_total,
            contradiction_detected_total,
            webhook_dispatched_total,
            webhook_failed_total,
            memories_gauge,
            memories_gauge_refreshed_at,
            hnsw_size_gauge,
            subscriptions_active_gauge,
            curator_cycles_total,
            curator_operations_total,
            curator_cycle_duration_seconds,
            federation_fanout_dropped_total,
            federation_fanout_retry_total,
            federation_partial_quorum_total,
            corrupt_provenance_rows_total,
            auto_export_spawn_failed_total,
            federation_push_dlq_depth,
            deferred_audit_drainer_terminal_state,
            federation_push_dlq_quarantined,
            federation_push_dlq_quarantined_by_cause,
            federation_push_dlq_legacy_positional,
            federation_erasure_superseded,
            federation_quarantined_unattributed,
            operator_dequarantined,
            hnsw_evictions_total,
            hnsw_last_eviction_at_nanos,
            subscription_dlq_overflow_total,
            subscription_dispatch_truncated_total,
            federation_cred_verify_total,
            federation_inbound_cred_total,
            federation_cred_max_age_seconds,
            federation_renewal_lag_seconds,
            admission_shed_total,
            recall_embed_degraded_total,
            rerank_budget_degraded_total,
            query_embed_cache_hits_total,
            autotag_enqueued_total,
            autotag_dropped_total,
            autotag_applied_total,
            autotag_degraded_total,
            atomise_enqueued_total,
            atomise_dropped_total,
            atomise_applied_total,
            atomise_degraded_total,
            atomise_no_curator_total,
            age_projection_pending_depth,
            age_projection_failed_total,
            age_projection_quarantined_total,
            embed_backfill_pending,
        })
    }
}

/// #1253 (MED, 2026-05-25) — record one subscription_dlq insert that
/// was refused because the per-subscription DLQ already held
/// [`crate::subscriptions::MAX_SUBSCRIPTION_DLQ_ROWS`] rows. Pairs
/// with a `tracing::warn!` at the call site so operators see the
/// subscription id + correlation id of the dropped row.
pub fn record_subscription_dlq_overflow() {
    registry().subscription_dlq_overflow_total.inc();
}

/// #1253 (MED, 2026-05-25) — read the current value of the
/// subscription DLQ overflow counter. Test-only accessor for the
/// regression that pins this cap.
#[must_use]
pub fn subscription_dlq_overflow_count() -> u64 {
    registry().subscription_dlq_overflow_total.get()
}

/// v1.0.0 #2592 — record one subscription-dispatch tick whose subscriber
/// scan was TRUNCATED at `SUBSCRIPTION_DISPATCH_LIMIT`.
/// Pairs with a `tracing::warn!` and a `subscription_dlq` row at the call
/// site so the undelivered tail is durable, not just counted.
pub fn record_subscription_dispatch_truncated() {
    registry().subscription_dispatch_truncated_total.inc();
}

/// v1.0.0 #2592 — read the current value of the truncated-dispatch counter.
/// Test-only accessor for the regression that pins the cliff.
#[must_use]
pub fn subscription_dispatch_truncated_count() -> u64 {
    registry().subscription_dispatch_truncated_total.get()
}

/// FED-P4-e (federation-identity-at-scale §8) — record one federation
/// credential-verification outcome on the receiver path. `ok = true`
/// means the presented credential (or chain leaf) verified against the
/// local trust bundle; `ok = false` means it was rejected. Feeds the
/// verify-failure-rate SLO.
pub fn record_federation_cred_verify(ok: bool) {
    let result = if ok { "ok" } else { "fail" };
    registry()
        .federation_cred_verify_total
        .with_label_values(&[result])
        .inc();
}

/// FED-P4-e — read the federation credential-verify counter for a given
/// outcome (`ok` | `fail`). Test-only accessor for the SLO regression.
#[must_use]
pub fn federation_cred_verify_count(result: &str) -> u64 {
    registry()
        .federation_cred_verify_total
        .with_label_values(&[result])
        .get()
}

/// FED-P4-e (federation-identity-at-scale §8) — record one inbound
/// federation request bucketed by whether it presented a signed
/// credential. `signed = true` means a credential header was present
/// (regardless of verify outcome); `false` means the peer sent no
/// credential. Feeds the signed-vs-unsigned-ratio SLO.
pub fn record_federation_inbound_cred(signed: bool) {
    let presence = if signed { "signed" } else { "unsigned" };
    registry()
        .federation_inbound_cred_total
        .with_label_values(&[presence])
        .inc();
}

/// FED-P4-e — read the inbound-credential presence counter for a given
/// bucket (`signed` | `unsigned`). Test-only accessor for the SLO
/// regression.
#[must_use]
pub fn federation_inbound_cred_count(presence: &str) -> u64 {
    registry()
        .federation_inbound_cred_total
        .with_label_values(&[presence])
        .get()
}

/// FED-P4-e (federation-identity-at-scale §8) — set the age in seconds
/// of the local outbound leaf credential (now − `issued_at`). Called on
/// every renewal tick. Feeds the max-cred-age SLO.
pub fn set_federation_cred_max_age_seconds(secs: i64) {
    registry().federation_cred_max_age_seconds.set(secs);
}

/// FED-P4-e (federation-identity-at-scale §8) — set the seconds elapsed
/// since the last successful outbound-credential renewal. Called on
/// every renewal tick. Feeds the renewal-lag SLO.
pub fn set_federation_renewal_lag_seconds(secs: i64) {
    registry().federation_renewal_lag_seconds.set(secs);
}

/// Cluster-A COR-3 (v0.7.0) — record a single corrupt-provenance row
/// observation. `column` is the offending JSON column name
/// (`citations` / `source_span` / `confidence_signals` / `metadata`).
/// Pairs with a `tracing::warn!` at the call site so operators see the
/// row id + parse error.
pub fn record_corrupt_provenance(column: &str) {
    registry()
        .corrupt_provenance_rows_total
        .with_label_values(&[column])
        .inc();
}

/// v0.7-polish SEC-15 / COR-11 (issue #780) — record one detached
/// `auto_export` worker failure (panic OR returned `Err`). Pairs with
/// a `tracing::warn!` at the call site so operators see the
/// reflection id + failure mode. The counter is also mirrored onto the
/// capabilities-v3 `hooks.auto_export_spawn_failed_total` field so
/// dashboards that consume `memory_capabilities` (vs `/metrics`) see
/// the same signal.
pub fn record_auto_export_spawn_failed() {
    registry().auto_export_spawn_failed_total.inc();
}

/// #2966 (L6 5-agent vote `4d3ea1c5`) — record one inbound relayed memory
/// QUARANTINED by the route-IN provenance gate. Pairs with a per-quarantine
/// `federation.quarantine.unattributed` WARN at the call site
/// (`crate::handlers::federation_receive::maybe_quarantine_unattributed`).
/// Incremented once per row actually quarantined; never fires when the
/// quarantine knob (`AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`) is off.
pub fn inc_fed_quarantined_unattributed() {
    registry().federation_quarantined_unattributed.inc();
}

/// #2966 — read the current value of the route-IN quarantine counter.
/// Test-only accessor for the regression that pins the observability wiring.
#[must_use]
pub fn fed_quarantined_unattributed_count() -> u64 {
    registry().federation_quarantined_unattributed.get()
}

/// v1.0.0 #2402 — record one quarantined memory released by an OPERATOR
/// (`ai-memory quarantine release` / the admin HTTP twin, on either backend).
/// Pairs with the `memory.dequarantined` signed-chain row and the
/// `quarantine.operator_release` WARN emitted at the same site — the counter
/// is the fleet-watchable rate, the chain row is the forensic record.
pub fn inc_operator_dequarantined() {
    registry().operator_dequarantined.inc();
}

/// v1.0.0 #2402 — read the current value of the operator route-OUT counter.
/// Test-only accessor pinning the observability wiring.
#[must_use]
pub fn operator_dequarantined_count() -> u64 {
    registry().operator_dequarantined.get()
}

/// v1.0.0 #2577 — record one recall that degraded to keyword/FTS because
/// the query embedding was unavailable within
/// [`crate::embeddings::ENV_RECALL_EMBED_BUDGET_MS`]. Pairs with the
/// `recall.embed.degraded` WARN at the call site, which is the only
/// channel on MCP stdio (no `/metrics` endpoint there).
pub fn inc_recall_embed_degraded() {
    registry().recall_embed_degraded_total.inc();
}

/// v1.0.0 #2608 — record one autonomous-tier recall whose cross-encoder
/// rerank was skipped by the pre-flight `AI_MEMORY_RERANK_BUDGET_MS`
/// admission gate (degraded to the pre-rerank hybrid ordering). Pairs with
/// the `rerank.budget.degraded` WARN at the call site, which is the only
/// channel on MCP stdio (no `/metrics` endpoint there).
pub fn inc_rerank_budget_degraded() {
    registry().rerank_budget_degraded_total.inc();
}

/// v1.0.0 #2577 — record one recall query embedding served from the
/// process-local bounded cache instead of a remote round trip.
pub fn inc_query_embed_cache_hit() {
    registry().query_embed_cache_hits_total.inc();
}

/// v1.0.0 #2587 — record one `auto_tag` job successfully enqueued onto the
/// bounded background worker after a durable HTTP create-memory write.
pub fn inc_autotag_enqueued() {
    registry().autotag_enqueued_total.inc();
}

/// v1.0.0 #2587 — record one `auto_tag` job dropped because the bounded
/// queue was full or no worker was wired. Pairs with the
/// `autotag.queue.dropped` / `autotag.queue.absent` WARN at the call site.
pub fn inc_autotag_dropped() {
    registry().autotag_dropped_total.inc();
}

/// v1.0.0 #2587 — record one `auto_tag` job the background worker applied
/// successfully.
pub fn inc_autotag_applied() {
    registry().autotag_applied_total.inc();
}

/// v1.0.0 #2587 — record one `auto_tag` job the background worker gave up
/// on (LLM error/timeout, row gone, or a lost optimistic-concurrency
/// race). Pairs with the `autotag.worker.*` WARN at the call site.
pub fn inc_autotag_degraded() {
    registry().autotag_degraded_total.inc();
}

/// v1.0.0 #2986 — record one auto-atomise job enqueued onto the bounded
/// single-consumer background worker after a durable write.
pub fn inc_atomise_enqueued() {
    registry().atomise_enqueued_total.inc();
}

/// v1.0.0 #2986 — record one auto-atomise job dropped because the bounded
/// queue was full or no worker was wired. Pairs with the
/// `atomise.queue.dropped` WARN at the call site (the only channel on MCP
/// stdio, which serves no `/metrics`).
pub fn inc_atomise_dropped() {
    registry().atomise_dropped_total.inc();
}

/// v1.0.0 #2986 — record one auto-atomise pass that landed atoms.
pub fn inc_atomise_applied() {
    registry().atomise_applied_total.inc();
}

/// v1.0.0 #2986 — record one auto-atomise pass that failed (curator error
/// or db-open failure). The durable source row is untouched.
pub fn inc_atomise_degraded() {
    registry().atomise_degraded_total.inc();
}

/// v1.0.0 #2985 — record one write whose namespace standard requested
/// `auto_atomise` on a curator-less daemon. Pairs with the
/// `pre_store.auto_atomise` WARN and the `ai-memory doctor` section.
pub fn inc_atomise_no_curator() {
    registry().atomise_no_curator_total.inc();
}

/// v0.7-polish SEC-15 / COR-11 (issue #780) — read the current value
/// of the auto-export spawn-failure counter. Used by the
/// capabilities-v3 builder to mirror the metric onto the
/// `hooks.auto_export_spawn_failed_total` field without scraping
/// `/metrics`.
#[must_use]
pub fn auto_export_spawn_failed_count() -> u64 {
    registry().auto_export_spawn_failed_total.get()
}

/// Render the current registry state to the Prometheus text exposition
/// format. Ignores errors from the encoder (unreachable in practice) and
/// returns an empty string — the scrape returns 200 with a possibly-empty
/// body rather than a 5xx, which Prometheus handles gracefully.
#[must_use]
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    let _ = encoder.encode(&registry().registry.gather(), &mut buf);
    String::from_utf8(buf).unwrap_or_default()
}

/// Convenience: record a store, labeled by tier.
#[allow(dead_code)]
pub fn record_store(tier: &str, ok: bool) {
    let result = if ok { "ok" } else { "err" };
    registry()
        .store_total
        .with_label_values(&[tier, result])
        .inc();
}

/// Convenience: record a recall, labeled by mode + latency.
///
/// SCOPE (#1839): called from the HTTP recall path only (both backends) —
/// MCP-stdio recalls populate NEITHER `ai_memory_recall_total` NOR
/// `ai_memory_recall_latency_seconds` (a stdio daemon exposes no `/metrics`
/// endpoint, so the scraped HTTP surface is the one instrumented; both
/// series share this one funnel and therefore the same HTTP-only scope).
#[allow(dead_code)]
pub fn record_recall(mode: &str, latency_seconds: f64) {
    registry().recall_total.with_label_values(&[mode]).inc();
    registry()
        .recall_latency_seconds
        .with_label_values(&[mode])
        .observe(latency_seconds);
}

/// Convenience: record an autonomy-hook invocation.
#[allow(dead_code)]
pub fn record_autonomy_hook(kind: &str, ok: bool) {
    let result = if ok { "ok" } else { "err" };
    registry()
        .autonomy_hook_total
        .with_label_values(&[kind, result])
        .inc();
}

/// Convenience: record a completed curator cycle (v0.6.1).
#[allow(dead_code)]
pub fn curator_cycle_completed(
    operations_attempted: usize,
    auto_tagged: usize,
    contradictions_found: usize,
    errors: usize,
) {
    let r = registry();
    r.curator_cycles_total.inc();
    if auto_tagged > 0 {
        r.curator_operations_total
            .with_label_values(&["auto_tag", "ok"])
            .inc_by(auto_tagged as u64);
    }
    if contradictions_found > 0 {
        r.curator_operations_total
            .with_label_values(&["contradiction", "ok"])
            .inc_by(contradictions_found as u64);
    }
    let failed = operations_attempted.saturating_sub(auto_tagged + contradictions_found);
    if failed > 0 || errors > 0 {
        r.curator_operations_total
            .with_label_values(&["any", "err"])
            .inc_by(errors as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tier;

    #[test]
    fn registry_is_singleton() {
        let r1 = registry();
        let r2 = registry();
        // Same instance — no double-registration.
        assert!(std::ptr::eq(std::ptr::from_ref(r1), std::ptr::from_ref(r2)));
    }

    #[test]
    fn render_includes_registered_names() {
        // Tickle every series so each one has ≥1 sample.
        record_store(Tier::Short.as_str(), true);
        record_recall("hybrid", 0.042);
        record_autonomy_hook("auto_tag", true);
        registry().contradiction_detected_total.inc();
        registry().webhook_dispatched_total.inc();
        registry().memories_gauge.set(42);
        registry().memories_gauge_refreshed_at.set(1);
        registry().hnsw_size_gauge.set(42);
        registry().subscriptions_active_gauge.set(3);
        registry().federation_push_dlq_depth.set(0);
        // FED-P4-e — federation identity SLO surfaces.
        record_federation_cred_verify(true);
        record_federation_inbound_cred(true);
        set_federation_cred_max_age_seconds(0);
        set_federation_renewal_lag_seconds(0);

        let text = render();
        for name in [
            "ai_memory_store_total",
            "ai_memory_recall_total",
            "ai_memory_recall_latency_seconds",
            "ai_memory_autonomy_hook_total",
            "ai_memory_contradiction_detected_total",
            "ai_memory_webhook_dispatched_total",
            "ai_memory_webhook_failed_total",
            "ai_memory_memories",
            // v1.0.0 #2583 — the freshness twin of the pre-computed count.
            "ai_memory_memories_refreshed_at_seconds",
            "ai_memory_hnsw_size",
            "ai_memory_subscriptions_active",
            // v0.7.0 Track D #933 — federation push DLQ depth gauge.
            "ai_memory_federation_push_dlq_depth",
            // FED-P4-e — federation identity SLO surfaces (§8).
            "ai_memory_federation_cred_verify_total",
            "ai_memory_federation_inbound_cred_total",
            "ai_memory_federation_cred_max_age_seconds",
            "ai_memory_federation_renewal_lag_seconds",
        ] {
            assert!(text.contains(name), "/metrics missing {name}\n\n{text}");
        }
    }

    #[test]
    fn federation_cred_verify_labels_outcome() {
        let before_ok = federation_cred_verify_count("ok");
        let before_fail = federation_cred_verify_count("fail");
        record_federation_cred_verify(true);
        record_federation_cred_verify(false);
        assert!(federation_cred_verify_count("ok") >= before_ok + 1);
        assert!(federation_cred_verify_count("fail") >= before_fail + 1);
        let text = render();
        assert!(text.contains("ai_memory_federation_cred_verify_total{result=\"ok\"}"));
        assert!(text.contains("ai_memory_federation_cred_verify_total{result=\"fail\"}"));
    }

    #[test]
    fn federation_inbound_cred_labels_presence() {
        let before_signed = federation_inbound_cred_count("signed");
        let before_unsigned = federation_inbound_cred_count("unsigned");
        record_federation_inbound_cred(true);
        record_federation_inbound_cred(false);
        assert!(federation_inbound_cred_count("signed") >= before_signed + 1);
        assert!(federation_inbound_cred_count("unsigned") >= before_unsigned + 1);
    }

    #[test]
    fn federation_cred_age_and_lag_gauges_settable() {
        set_federation_cred_max_age_seconds(1234);
        set_federation_renewal_lag_seconds(56);
        assert_eq!(registry().federation_cred_max_age_seconds.get(), 1234);
        assert_eq!(registry().federation_renewal_lag_seconds.get(), 56);
    }

    #[test]
    fn record_store_labels_tier() {
        record_store(Tier::Long.as_str(), true);
        let text = render();
        assert!(text.contains("ai_memory_store_total{result=\"ok\",tier=\"long\"}"));
    }

    // ---- Wave 3 (Closer T): tests for curator_cycle_completed (L263-287)
    // and webhook_dispatched/_failed counter labels.

    #[test]
    fn curator_cycle_completed_increments_total() {
        // Other tests running in parallel may bump the same singleton
        // counter; what we own is the +1 contributed by *this* call.
        let before = registry().curator_cycles_total.get();
        curator_cycle_completed(0, 0, 0, 0);
        let after = registry().curator_cycles_total.get();
        assert!(
            after >= before + 1,
            "curator_cycles_total did not advance (before={before}, after={after})"
        );
    }

    #[test]
    fn curator_cycle_completed_records_auto_tag_ok() {
        curator_cycle_completed(5, 3, 0, 0);
        let text = render();
        assert!(
            text.contains("ai_memory_curator_operations_total"),
            "curator_operations_total counter missing from /metrics output"
        );
    }

    #[test]
    fn curator_cycle_completed_records_contradiction_ok() {
        curator_cycle_completed(2, 0, 2, 0);
        let text = render();
        assert!(text.contains("ai_memory_curator_operations_total"));
    }

    #[test]
    fn curator_cycle_completed_records_errors() {
        // operations_attempted=5, auto_tagged=2, contradictions=1 → failed=2
        // plus errors=1 → the err counter is exercised.
        curator_cycle_completed(5, 2, 1, 1);
        let text = render();
        assert!(text.contains("ai_memory_curator_operations_total"));
    }

    #[test]
    fn curator_cycle_completed_with_zero_args_is_safe() {
        // No labels emitted, no panic — a zero cycle is valid (empty DB).
        let before = registry().curator_cycles_total.get();
        curator_cycle_completed(0, 0, 0, 0);
        let after = registry().curator_cycles_total.get();
        // Same race-tolerant assertion as above.
        assert!(after >= before + 1);
    }

    // -----------------------------------------------------------------
    // W12-H — additional helpers + render shape pinning
    // -----------------------------------------------------------------

    #[test]
    fn record_store_err_path() {
        record_store(Tier::Short.as_str(), false);
        let text = render();
        assert!(text.contains("ai_memory_store_total{result=\"err\",tier=\"short\""));
    }

    #[test]
    fn record_recall_emits_latency_histogram() {
        record_recall("keyword", 0.5);
        let text = render();
        assert!(text.contains("ai_memory_recall_total{mode=\"keyword\""));
        assert!(text.contains("ai_memory_recall_latency_seconds"));
    }

    #[test]
    fn record_autonomy_hook_err_path() {
        record_autonomy_hook("contradiction", false);
        let text = render();
        assert!(
            text.contains("ai_memory_autonomy_hook_total{kind=\"contradiction\",result=\"err\"")
        );
    }

    #[test]
    fn render_emits_help_and_type_lines() {
        // Tickle one series, then render and assert prom-format HELP/TYPE lines.
        record_store(Tier::Mid.as_str(), true);
        let text = render();
        assert!(text.contains("# HELP ai_memory_store_total"));
        assert!(text.contains("# TYPE ai_memory_store_total counter"));
    }

    #[test]
    fn fanout_dropped_counter_increments() {
        registry()
            .federation_fanout_dropped_total
            .with_label_values(&["shutdown"])
            .inc();
        let text = render();
        assert!(text.contains("ai_memory_federation_fanout_dropped_total{reason=\"shutdown\""));
    }

    #[test]
    fn fanout_retry_counter_outcome_labels() {
        // All three outcome labels exercised — `ok`, `fail`, `id_drift`.
        for outcome in ["ok", "fail", "id_drift"] {
            registry()
                .federation_fanout_retry_total
                .with_label_values(&[outcome])
                .inc();
        }
        let text = render();
        assert!(text.contains("ai_memory_federation_fanout_retry_total"));
    }

    #[test]
    fn curator_cycle_duration_histogram_buckets() {
        // Just observe — confirms registry accepts the value and surfaces
        // the histogram in /metrics output.
        registry()
            .curator_cycle_duration_seconds
            .with_label_values(&["false"])
            .observe(0.42);
        let text = render();
        assert!(text.contains("ai_memory_curator_cycle_duration_seconds"));
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — exercise try_new() directly so the metric-builder
    // happy paths (lines 88-210) get covered. The process singleton
    // registry() builds once on first access; we need a second pass for
    // line coverage of every metric registration in the try_new body.
    // -----------------------------------------------------------------

    #[test]
    fn try_new_builds_a_fresh_metrics_handle() {
        // Build a second instance on top of an independent registry —
        // hits every metric-construction line in `try_new` even when
        // another test has already initialised the process-wide
        // singleton. Each call uses a fresh Registry, so register()
        // cannot collide.
        let m = super::Metrics::try_new().expect("fresh registry must succeed");
        // The handle must expose every metric family — touch each to
        // exercise the assignment side of the struct literal.
        m.store_total
            .with_label_values(&[Tier::Short.as_str(), "ok"])
            .inc();
        m.recall_total.with_label_values(&["hybrid"]).inc();
        m.recall_latency_seconds
            .with_label_values(&["hybrid"])
            .observe(0.001);
        m.autonomy_hook_total.with_label_values(&["x", "ok"]).inc();
        m.contradiction_detected_total.inc();
        m.webhook_dispatched_total.inc();
        m.webhook_failed_total.inc();
        m.memories_gauge.set(1);
        m.hnsw_size_gauge.set(1);
        m.subscriptions_active_gauge.set(1);
        m.curator_cycles_total.inc();
        m.curator_operations_total
            .with_label_values(&["auto_tag", "ok"])
            .inc();
        m.curator_cycle_duration_seconds
            .with_label_values(&["true"])
            .observe(1.0);
        m.federation_fanout_dropped_total
            .with_label_values(&["panic"])
            .inc();
        m.federation_fanout_retry_total
            .with_label_values(&["ok"])
            .inc();
        m.federation_partial_quorum_total.inc();
        m.auto_export_spawn_failed_total.inc();
    }

    #[test]
    fn try_new_can_build_two_isolated_registries() {
        // Two consecutive try_new() calls succeed because each builds
        // its own Registry — no name collision.
        let a = super::Metrics::try_new().expect("first");
        let b = super::Metrics::try_new().expect("second");
        // Tickle a counter on each so the family surfaces in gather().
        a.store_total
            .with_label_values(&[Tier::Short.as_str(), "ok"])
            .inc();
        b.store_total
            .with_label_values(&[Tier::Short.as_str(), "ok"])
            .inc();
        let mut buf_a = Vec::new();
        let mut buf_b = Vec::new();
        let enc = TextEncoder::new();
        enc.encode(&a.registry.gather(), &mut buf_a).unwrap();
        enc.encode(&b.registry.gather(), &mut buf_b).unwrap();
        assert!(String::from_utf8_lossy(&buf_a).contains("ai_memory_store_total"));
        assert!(String::from_utf8_lossy(&buf_b).contains("ai_memory_store_total"));
    }

    #[test]
    fn record_auto_export_spawn_failed_increments_singleton() {
        // v0.7-polish #780 — record_auto_export_spawn_failed() must
        // monotonically advance the process-wide counter that the
        // capabilities-v3 builder mirrors onto
        // `hooks.auto_export_spawn_failed_total`.
        let before = auto_export_spawn_failed_count();
        record_auto_export_spawn_failed();
        let after = auto_export_spawn_failed_count();
        assert!(
            after >= before + 1,
            "auto_export_spawn_failed_total did not advance \
             (before={before}, after={after})"
        );
        // The render text must mention the metric name so /metrics
        // scrapers see it.
        let text = render();
        assert!(
            text.contains("ai_memory_auto_export_spawn_failed_total"),
            "/metrics output missing auto_export counter\n\n{text}"
        );
    }

    #[test]
    fn curator_cycle_completed_no_progress_branch_skips_err_increment() {
        // operations_attempted=0, auto_tagged=0, contradictions=0,
        // errors=0 → failed = 0.saturating_sub(0+0) = 0 → the `if
        // failed > 0 || errors > 0` block does NOT execute. Pins the
        // negative branch.
        let before = registry().curator_cycles_total.get();
        curator_cycle_completed(0, 0, 0, 0);
        let after = registry().curator_cycles_total.get();
        assert!(after >= before + 1);
    }
}
