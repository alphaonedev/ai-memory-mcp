---
layout: doc
---
# Observability and incident tracing — the operator contract

This page is the one place that says **which process emits which signal, what
an absent or stale signal means, and how to trace an incident end to end**
([#3666](https://github.com/alphaonedev/ai-memory-mcp/issues/3666)). It ties
together the surfaces documented in more detail elsewhere:

| Surface | Detail page |
|---|---|
| Metadata-only health API for an external monitor (`/api/v1/monitoring/*`) | [`HEALTH-MONITORING.md`](../HEALTH-MONITORING.md) |
| `ai-memory doctor` (local and `--remote`) | [`doctor.md`](doctor.md) |
| Operational logs (file / stdout / syslog sinks) | [`os-tier-logging.md`](os-tier-logging.md) |
| Signed audit chain and forensic JSONL | [`../security/audit-trail-coverage.md`](../security/audit-trail-coverage.md) |
| Per-peer federation freshness | [`../federation.md`](../federation.md#per-peer-freshness-3654) |

Nothing here is a claim that every failure mode is instrumented. The gaps are
listed where they apply, with the issue that owns each one.

## 1. Topology: which process emits what

Every ai-memory process keeps its **own** in-memory Prometheus registry
(`src/metrics.rs::registry`). Only the HTTP daemon (`ai-memory serve`) serves it.

| Process | HTTP metrics | Operational logs | Audit (`signed_events`) |
|---|---|---|---|
| `ai-memory serve` (HTTP daemon) | `/metrics`, `/api/v1/metrics` (full registry); `/api/v1/monitoring/metrics` (18 unlabelled counters) | console to **stderr** always; plus the configured `[logging]` sink when `enabled = true` | yes |
| `ai-memory mcp` (stdio) | **none** | configured `[logging]` sink only; stdout is the JSON-RPC channel | yes |
| `ai-memory curator`, `watch`, `wake-hub`, `wake-listen` | none | console to **stderr**; plus the `[logging]` sink | per verb |
| Other CLI verbs | none | configured `[logging]` sink only | per verb |

Consequences an operator (or an AI monitor) must not get wrong:

- **Scrape the daemon, not "the node".** Work done by an MCP stdio process, a
  CLI invocation or a separately-run `curator` increments counters in THAT
  process, which no endpoint exposes. On the daemon's scrape those series are
  absent or flat — never evidence that the work did not happen, and never
  evidence that it succeeded.
- **Counters reset on restart.** A drop in any `_total` series is a process
  restart; use `rate()` / `increase()`, never raw values.
- **A fleet is N independent registries.** There is no cross-node aggregate.
  Label each scrape target with its node and alert per node.
- **Signals on MCP stdio are WARN log lines.** Several degrade paths (recall
  embed budget, rerank budget, autotag drop) document that their WARN is the
  only channel on MCP stdio, which serves no `/metrics`.

## 2. Endpoints

| Endpoint | Auth | Content | Use it for |
|---|---|---|---|
| `GET /api/v1/health` | exempt from the API key | `status`, `version`, `embedder_ready`, `federation_enabled`, cached `fts_integrity`; **503** on a failed store probe or a cached FTS integrity failure | liveness / readiness probe |
| `GET /api/v1/monitoring/status` | TLS **and** an enrolled key, bound mTLS peer or operator key | versioned JSON, `healthy` / `degraded` / `failing` with reason codes; **503** when failing | external monitor (see [`HEALTH-MONITORING.md`](../HEALTH-MONITORING.md)) |
| `GET /api/v1/monitoring/metrics` | as above | 18 unlabelled process counters | privacy-bounded scrape for a monitor-only credential |
| `GET /metrics`, `GET /api/v1/metrics` | API key when one is configured | the full registry below, with labels | operator Prometheus |
| `GET /api/v1/capabilities`, `GET /api/v1/stats` | API key | effective posture, feature state, counts | `ai-memory doctor --remote` |

`/api/v1/health`, both `/metrics` paths and `/api/v1/monitoring/*` are exempt
from HTTP admission control, so an overloaded daemon still answers its probe
and its scraper (`src/lib.rs`, the admission layer). TLS and authentication
still apply to the monitoring routes under overload.

## 3. Unknown, stale and absent — never "healthy"

| Signal | What absence or staleness means |
|---|---|
| A series missing from a scrape | **Unavailable**, not zero. Either nothing has happened in this process yet, the work ran in another process (§1), or the feature is not configured. |
| `/api/v1/monitoring/status` field `{"state":"unavailable", ...}` | Not instrumented (`not_yet_instrumented`, with the owning issue) or not yet observed (a reason, no issue). At this release a responding node reports `degraded` with `required_observations_unavailable`; it never reports `healthy` from silence. |
| `ai_memory_memories` | Refreshed on a cadence (`AI_MEMORY_METRICS_GAUGE_REFRESH_SECS`, default 60 s). Check `ai_memory_memories_refreshed_at_seconds`: `0` means never refreshed; an old value means the refresher is dead and the count is frozen. |
| `fts_integrity` in `/api/v1/health` | `pending` (no check completed yet), `stale` (an `ok` verdict older than three intervals), `disabled` (`AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS=0`) — none of these assert the index is sound. Only `failed` answers 503. |
| Federation peer with no recent attempt | **Unknown**, not healthy. A push happens only when there is something to push; the pull direction is the only periodic liveness probe (see [`federation.md`](../federation.md#per-peer-freshness-3654)). |
| `ai_memory_deferred_audit_drainer_terminal_state` | Non-zero means the deferred-audit drainer supervisor gave up (`1` = sink unresolved, `2` = sink panicked, each past `max_restarts`); read its HELP text in §4 before acting. |
| No WARN lines in the log | Proves nothing unless the log sink is known to be delivering. Logging delivery itself is not instrumented yet (`logging_delivery`, #3651). |

## 4. Metric catalog

All 71 series the binary registers, generated from `src/metrics.rs` (the HELP
column is the text `/metrics` serves). Label values are bounded sets except
`peer`, which is bounded by configured federation membership and never carries
a URL. Only the 18 series listed in [`HEALTH-MONITORING.md`](../HEALTH-MONITORING.md)
appear on `/api/v1/monitoring/metrics`.

| Series | Type | Labels | Meaning (the HELP text the binary serves) |
|---|---|---|---|
| `ai_memory_admission_shed_total` | counter | — | Monotonic counter of HTTP requests shed by the admission-control layer because the in-flight-request cap (AI_MEMORY_MAX_INFLIGHT_REQUESTS) was already saturated. Non-zero means the daemon is load-shedding with a typed 503; operators alert on a sustained increment rate to size the cap or the fleet up. Always zero on deployments that have not opted into admission control (the cap defaults to disabled). |
| `ai_memory_age_projection_failed_total` | counter | — | Monotonic count of deferred AGE-projection drain attempts that errored (MERGE failed; row attempt_count bumped, retried until quarantine). Pillar-4 4.C (#1735). |
| `ai_memory_age_projection_pending_depth` | gauge | — | Current depth of the kg_projection_outbox (pending deferred AGE projections, projected_at IS NULL), refreshed each cold-drainer tick. Sustained non-zero = AGE graph lagging the relational memory_links truth (Pillar-4 4.C, #1735). Non-zero in SYNC mode too: an inline projection failure records a pending row here and the drainer reconciles it, so this is NOT always 0 in sync mode (#3883). |
| `ai_memory_age_projection_quarantined_total` | counter | — | Monotonic count of kg_projection_outbox rows that hit the drain attempt ceiling and were quarantined (relational edge exists but never reached the AGE graph). Pillar-4 4.C (#1735). |
| `ai_memory_atomise_applied_total` | counter | — | Monotonic counter of auto-atomise passes that landed atoms — the synchronous MCP path or a drained background job (#2986). |
| `ai_memory_atomise_degraded_total` | counter | — | Monotonic counter of auto-atomise passes that FAILED (curator error, db-open failure) (#2986). A DEGRADE, never data loss — the durable source row is untouched on every failure arm. |
| `ai_memory_atomise_dropped_total` | counter | — | Monotonic counter of auto-atomise jobs DROPPED because the bounded queue (AI_MEMORY_ATOMISE_QUEUE_CAPACITY) was full or no worker was wired (#2986). The durable write always succeeds regardless — a DEGRADE (no atoms; `memory_atomise` recovers it), never a write failure. Alert on a sustained increment rate. |
| `ai_memory_atomise_enqueued_total` | counter | — | Monotonic counter of auto-atomise jobs enqueued onto the bounded single-consumer background worker after a durable write (#2986). |
| `ai_memory_atomise_no_curator_total` | counter | — | Monotonic counter of writes whose namespace standard REQUESTED auto_atomise on a daemon with NO curator — no LLM wired, or inference egress refused (#2985). Non-zero means a MISCONFIGURATION, not load: the knob is set and structurally dead. `ai-memory doctor` names the same condition. |
| `ai_memory_auth_backoff_episodes_total` | counter | — | Backoff episodes begun since boot: times one source's auth failures crossed the threshold into 429 refusal (edge-triggered; a later success does not decrement). |
| `ai_memory_auth_failures_total` | counter | — | Total HTTP transport-auth failures (missing or unknown API key) since boot, all sources, no per-source label. |
| `ai_memory_auto_export_spawn_failed_total` | counter | — | Detached post_reflect.auto_export worker invocations whose outcome was a panic or returned Err. Non-zero means at least one reflection was committed to the DB but its on-disk markdown/json artefact did not land — operators use this to alert on otherwise-silent disk-write failures. |
| `ai_memory_autonomy_hook_total` | counter | kind, result | Post-store autonomy hook invocations, labeled by kind and result. |
| `ai_memory_autotag_applied_total` | counter | — | Monotonic counter of auto_tag jobs the background worker applied successfully — tags merged onto the row, never a blind overwrite (#2587). |
| `ai_memory_autotag_degraded_total` | counter | — | Monotonic counter of auto_tag jobs the background worker gave up on — LLM error, LLM call exceeded llm_call_timeout, the row was deleted before the job drained, or (sqlite) an optimistic- concurrency race lost twice in a row (#2587). A DEGRADE, never data corruption — the durable write this job followed already succeeded. |
| `ai_memory_autotag_dropped_total` | counter | — | Monotonic counter of auto_tag jobs DROPPED because the bounded queue (AI_MEMORY_AUTOTAG_QUEUE_CAPACITY) was full, or no worker was wired (#2587). The durable write always succeeds regardless — a DEGRADE (no tags), never a write failure. Alert on a sustained increment rate: the queue is under-sized for the write burst. |
| `ai_memory_autotag_enqueued_total` | counter | — | Monotonic counter of auto_tag jobs successfully enqueued onto the bounded background worker after a durable HTTP create-memory write (#2587). Rising with autonomous-tier write traffic is the healthy shape. |
| `ai_memory_capability_expansion_audit_suppressed_total` | counter | — | Monotonic counter of capability-expansion audit appends SUPPRESSED under an engaged record-stop (#3818); the expansion itself still resolves. |
| `ai_memory_contradiction_detected_total` | counter | — | Count of contradictions the LLM hook confirmed. |
| `ai_memory_corrupt_provenance_rows_total` | counter | column | Memory rows whose Form 4 fact-provenance JSON columns failed to deserialise and were silently defaulted. Non-zero indicates schema drift, writer-side corruption, or a migration leaving malformed JSON. |
| `ai_memory_curator_cycle_duration_seconds` | histogram | dry_run | Curator sweep cycle wall-clock duration, labeled by dry_run. |
| `ai_memory_curator_cycles_total` | counter | — | Total curator sweep cycles completed. |
| `ai_memory_curator_operations_total` | counter | kind, result | Curator operations, labeled by kind (auto_tag\|contradiction\|persist) and result. |
| `ai_memory_deferred_audit_drainer_terminal_state` | gauge | — | Terminal state of the deferred-audit drainer supervisor: 0 = running/graceful, 1 = sink unresolved past max_restarts, 2 = sink panicked past max_restarts. Non-zero means governance refusals are NO LONGER reaching signed_events on this node; the daemon keeps serving but is audit-degraded until restarted. |
| `ai_memory_embed_task_failed_total` | counter | surface | HTTP-path embed/rerank tasks run on the blocking pool that did not complete (panicked, or the runtime was shutting down), labeled by surface (#4089). Each such request degraded exactly as an embed failure does (vectorless write, keyword recall, pre-rerank ordering, keyword family routing) or failed closed (check_duplicate 503); never a wrong result. Any increment is a bug to investigate: the embedder or reranker panicked. |
| `ai_memory_fed_cross_id_title_merge_total` | counter | — | Monotonic count of inbound federated memories folded into a local row of a DIFFERENT id by the newer-wins (title, namespace) merge (the inbound id was never created on this node). Legitimate for two nodes that independently stored the same title; on a fleet that consolidates, a non-zero rate is the signature of a memory delivered before the tombstone that freed its title (#3699). Each increment pairs with a WARN naming both ids. |
| `ai_memory_fed_quarantined_unattributed_total` | counter | — | Monotonic count of inbound relayed memories quarantined by the route-IN provenance gate (AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED): an unattributed row stored with lifecycle_state=quarantined and hidden from every local read/egress lane until dequarantine. Always zero when the quarantine knob is off (the default); a non-zero rate means a peer is relaying provenance-less content this node is black-holing. #2966. |
| `ai_memory_federation_catchup_interval_seconds` | gauge | — | Configured federation catch-up interval in seconds; absent when the catch-up loop is not running (#3654). |
| `ai_memory_federation_cred_max_age_seconds` | gauge | — | Age in seconds of the local outbound leaf credential (now - issued_at), refreshed on every renewal tick. max-cred-age SLO alerts when this approaches the leaf TTL — a credential aging past its TTL without a renewal means the refresh worker has stalled and outbound sync will start failing peer verification. |
| `ai_memory_federation_cred_verify_total` | counter | result | Federation credential-verification outcomes on the receiver path, labeled result (ok\|fail). verify-failure-rate SLO = fail / (ok + fail). Non-zero sustained fail rate means peers present credentials the local trust bundle cannot verify (expired leaf, revoked issuer, clock skew, or a chain that fails to anchor). |
| `ai_memory_federation_erasure_superseded_total` | counter | — | Federation pending erasures/deletes SUPERSEDED (not propagated) because the target id is LIVE again locally with an updated_at that post-dates the queued erasure (an authorized restore / re-store). Counts both the erasure-sentinel expansion guard and the replay-POST-path restore-race guard. A supersede cancels an operator-requested erasure; a sustained rate may mean an erasure is being undone by a resurrection and warrants a re-issue. #2716. |
| `ai_memory_federation_fanout_dropped_total` | counter | reason | Post-quorum fanout tasks whose outcome could not be observed. reason=shutdown\|panic\|join_error. Non-zero indicates mesh divergence risk. |
| `ai_memory_federation_fanout_retry_total` | counter | outcome | Peer POSTs that hit a transient failure on first attempt and were retried once via the Idempotency-Key path. outcome=ok\|fail\|id_drift. Non-zero ok indicates the retry recovered a row that would otherwise be missing on a peer. |
| `ai_memory_federation_inbound_cred_total` | counter | presence | Inbound federation requests bucketed by whether they presented a signed credential, labeled presence (signed\|unsigned). signed-vs-unsigned-ratio SLO = signed / (signed + unsigned). Climbs toward 1.0 as peers upgrade to credential-presenting builds. |
| `ai_memory_federation_partial_quorum_total` | counter | — | Quorum writes that succeeded (W met) but where at least one configured peer did not ack inside the deadline. |
| `ai_memory_federation_peer_clock_skew_seconds` | gauge | peer | Peer clock minus local clock in whole seconds, from the peer's HTTP Date header on the last catch-up response (#3654). |
| `ai_memory_federation_peer_configured` | gauge | peer | 1 for every peer in this node's configured federation membership (#3654). |
| `ai_memory_federation_peer_consecutive_failures` | gauge | peer, direction | Failed attempts since the last success with a peer. direction=pull\|push (#3654). |
| `ai_memory_federation_peer_failures_total` | counter | peer, direction, class | Failed exchanges with a peer. direction=pull\|push; class=unauthorized\|throttled\|rejected\|server_error\|unreachable\|bad_response\|not_applied\|task_failed\|other (#3654). |
| `ai_memory_federation_peer_last_attempt_timestamp_seconds` | gauge | peer, direction | Unix seconds (local clock) of the last attempted exchange with a peer. direction=pull\|push. Absent until the first attempt (#3654). |
| `ai_memory_federation_peer_last_success_timestamp_seconds` | gauge | peer, direction | Unix seconds (local clock) of the last successful exchange with a peer; a push counts only when the peer applied it. direction=pull\|push. Absent until the first success (#3654). |
| `ai_memory_federation_peer_push_dlq_depth` | gauge | peer | Pending federation_push_dlq rows per peer, refreshed each replay tick (#3654). |
| `ai_memory_federation_peer_push_dlq_oldest_failed_timestamp_seconds` | gauge | peer | Unix seconds of the oldest pending federation_push_dlq failure per peer; absent when the peer's backlog is empty (#3654). |
| `ai_memory_federation_push_dlq_bookkeeping_failed_total` | counter | op | Federation push-DLQ bookkeeping writes that FAILED, labeled by the write (op=bump_attempt\|note_throttled\|mark_replayed\|reset_throttled\|enqueue). This is the LOCAL DLQ store failing to persist, not the peer: the row's attempt budget and last_error stay frozen and it is retried next tick; a failed enqueue means the failed push was not queued for retry. Sustained non-zero means the DLQ store is broken (disk, lock, schema). #3658. |
| `ai_memory_federation_push_dlq_depth` | gauge | — | Current count of pending federation_push_dlq rows (replayed_at IS NULL). Refreshed on every replay tick. Non-zero sustained depth indicates one or more peers are persistently unreachable; healthy meshes drain back to 0 within one replay interval after peer recovery. |
| `ai_memory_federation_push_dlq_legacy_positional_total` | counter | — | Federation push-DLQ rows skipped because their durable routing key is a pre-#2442 POSITIONAL peer id (the --quorum-peers flag index) that resolves to no configured peer. Written by binaries older than #2442. These rows are NEVER auto-remapped — `peer-N` -> peers[N] is only correct if the peer list never changed, and guessing would deliver the write to the wrong host. Payloads are retained, not deleted. Non-zero after an upgrade means legacy rows remain; see docs/TROUBLESHOOTING.md §federation-push-DLQ for the operator-gated re-key. #2442. |
| `ai_memory_federation_push_dlq_quarantined_by_cause_total` | counter | cause | Federation push-DLQ rows quarantined, labeled by the classified cause (quota\|unenrolled_peer\|unenrolled_author_strict\|namespace_probe_unresolvable\|id_drift\|permanent\|peer_removed\|other). `quota` is operator-actionable; `permanent` is a broken row needing a manual drain. #1544. |
| `ai_memory_federation_push_dlq_quarantined_total` | counter | — | Monotonic counter of federation_push_dlq rows the replay worker has skipped because their attempt_count exceeded MAX_REPLAY_ATTEMPTS (currently 100). Non-zero sustained rate indicates poison-message rows that need operator intervention via `ai-memory federation dlq drain --quarantined`. Pre-#1032 the worker retried these forever, amplifying network load against rejecting peers. |
| `ai_memory_federation_renewal_lag_seconds` | gauge | — | Seconds since the last successful outbound-credential renewal (now - last-renew wall clock), refreshed on every renewal tick. renewal-lag SLO alerts when this exceeds the configured refresh interval by a safety margin: a lag larger than the interval means renewals are silently failing even though the worker thread is still alive. |
| `ai_memory_governance_check_audit_suppressed_total` | counter | — | Monotonic counter of governance.check audit appends SUPPRESSED under an engaged record-stop (#3818): the check still answers, the audit row is skipped and a WARN names it. |
| `ai_memory_hnsw_evictions_total` | counter | — | Cumulative HNSW oldest-eviction count since process start. Non-zero indicates the in-memory vector index has hit MAX_ENTRIES and dropped older embeddings; recall quality may have degraded for evicted ids until they are re-inserted on next access. |
| `ai_memory_hnsw_last_eviction_at_nanos` | gauge | — | Wall-clock UNIX nanoseconds of the most recent HNSW eviction (0 if none). Capabilities derives hnsw.evicted_recently from this with a 60s rolling window. |
| `ai_memory_hnsw_size` | gauge | — | Current HNSW vector index population. |
| `ai_memory_memories` | gauge | — | Current count of non-archived memories. |
| `ai_memory_memories_refreshed_at_seconds` | gauge | — | UNIX time at which ai_memory_memories was last recomputed (0 = never). |
| `ai_memory_operator_dequarantined_total` | counter | — | Monotonic count of quarantined memories released by an OPERATOR through `ai-memory quarantine release` or `POST /api/v1/admin/quarantine/{id}/release` (#2402). The route-OUT twin of ai_memory_fed_quarantined_unattributed_total. Each increment also appends a `memory.dequarantined` signed-chain row naming the authenticated caller, in the same transaction as the state change. A no-op release (the id is not quarantined) does not increment. |
| `ai_memory_query_embed_cache_hits_total` | counter | — | Monotonic counter of recall query embeddings served from the process-local bounded cache instead of a remote round trip (#2577). Zero under repeated traffic means the cache is disabled (AI_MEMORY_QUERY_EMBED_CACHE_ENTRIES=0) or every query is unique. |
| `ai_memory_recall_embed_degraded_total` | counter | — | Monotonic counter of recalls that fell back to keyword/FTS because the query-embedding call failed or exceeded AI_MEMORY_RECALL_EMBED_BUDGET_MS (#2577). The results are honest (the response reports mode:keyword) but semantic ranking is OFF for those requests. Alert on a sustained increment rate: a few trips is a provider hiccup, a sustained rate means the budget is mis-sized for this deployment's embedding provider or the provider is unhealthy. Always zero on keyword-tier deployments. |
| `ai_memory_recall_latency_seconds` | histogram | mode | Recall latency in seconds, labeled by mode. |
| `ai_memory_recall_total` | counter | mode | Total memory_recall calls, labeled by mode. |
| `ai_memory_record_stop_gate_indeterminate_total` | counter | — | Monotonic counter of record-stop gate FAIL-CLOSED refusals: the audit chain could not be read, so the mutating write was refused rather than proceeding (#3877, vote 4d3ea1c5). Alert on a sustained rate: every gated write is being refused. |
| `ai_memory_rerank_budget_degraded_total` | counter | — | Monotonic counter of autonomous-tier recalls whose cross-encoder rerank was SKIPPED because its estimated forward cost exceeded AI_MEMORY_RERANK_BUDGET_MS (#2608). The recall stays HYBRID (FTS/semantic-ranked, no neural re-ranking) and the configured score floor still applies — a DEGRADE, never a wrong result. Alert on a sustained increment rate: a few trips is a long-content tail, a sustained rate means the budget is mis-sized for this corpus. Always zero when the budget is disabled (=0) or on non-neural reranker deployments. |
| `ai_memory_store_total` | counter | tier, result | Total memory_store calls, labeled by tier and result. |
| `ai_memory_subscription_dispatch_truncated_total` | counter | — | Monotonic counter of subscription-dispatch ticks whose subscriber scan hit SUBSCRIPTION_DISPATCH_LIMIT (1000) and was truncated. Non-zero means subscribers past the ceiling silently received NO event; the scan is ordered and cursor-less, so the same tail is cut on every write. Reduce the subscription population or split the deployment. |
| `ai_memory_subscription_dlq_overflow_total` | counter | — | Monotonic counter of subscription_dlq inserts refused because the per-subscription DLQ depth had already hit MAX_SUBSCRIPTION_DLQ_ROWS (10_000). Non-zero indicates a hostile or persistently-broken webhook target that would otherwise fill the operator's disk with quarantined rows. Operators drain the queue via `ai-memory subscription dlq drain <subscription_id>` before resetting. |
| `ai_memory_subscriptions_active` | gauge | — | Current count of active webhook subscriptions. |
| `ai_memory_unstamped_mutation_allowed_total` | counter | backend, funnel | Caller-scoped mutations admitted on an UNSTAMPED (legacy-unowned, no metadata.agent_id) memory row under AI_MEMORY_UNSTAMPED_MUTATION=warn, labeled by backend and funnel. Non-zero means rows to re-own (ai-memory reown) before setting the knob to refuse. |
| `ai_memory_webhook_audit_last_failure_at_seconds` | gauge | — | Unix seconds of the last webhook delivery-audit bookkeeping failure; 0 = none since boot. |
| `ai_memory_webhook_audit_status_persisted_total` | counter | — | Webhook delivery-audit status transitions (ack/failed) that reached subscription_events since boot. |
| `ai_memory_webhook_audit_update_failed_total` | counter | stage | Webhook delivery-audit bookkeeping failures since boot, by stage (open \| status_update \| status_no_row \| dispatch_counter). Any increment means the persisted delivery history disagrees with the wire outcome. |
| `ai_memory_webhook_dispatched_total` | counter | — | Total webhook deliveries attempted. |
| `ai_memory_webhook_failed_total` | counter | — | Webhook deliveries that failed after all retries. |

## 5. Alert threshold examples

Starting points, not tuned SLOs. Each assumes one scrape target per daemon
labelled with `instance`.

```promql
# Daemon scrape lost — every other alert is blind without this one.
up{job="ai-memory"} == 0

# Corpus gauge frozen: the refresher stopped (default cadence 60 s).
time() - ai_memory_memories_refreshed_at_seconds > 600

# Admission control is shedding traffic, including writes.
rate(ai_memory_admission_shed_total[5m]) > 0

# Recall is silently degrading to keyword (embedder slow or down).
rate(ai_memory_recall_embed_degraded_total[10m]) > 0

# Derived-data workers dropping jobs (durable writes still succeed).
rate(ai_memory_autotag_dropped_total[15m]) > 0
rate(ai_memory_atomise_dropped_total[15m]) > 0

# Federation backlog and quarantine.
ai_memory_federation_push_dlq_depth > 1000
increase(ai_memory_federation_push_dlq_quarantined_by_cause_total[1h]) > 0

# A peer has not answered a pull for three catch-up intervals.
(time() - ai_memory_federation_peer_last_success_timestamp_seconds{direction="pull"})
  > on(instance) group_left() (3 * ai_memory_federation_catchup_interval_seconds)

# Deferred-audit drainer stopped.
ai_memory_deferred_audit_drainer_terminal_state != 0

# Vector index evicting (recall quality may degrade).
increase(ai_memory_hnsw_evictions_total[1h]) > 0
```

Pair metric alerts with a probe on `/api/v1/health` (503 = act now) and a
periodic `ai-memory doctor --remote <url> --json` sweep (exit 2 = critical).

## 6. Safe diagnostics during an incident

- **Prefer read-only tools.** `ai-memory doctor` (local or `--remote`),
  `/api/v1/health`, `/api/v1/monitoring/status` and
  `ai-memory verify-audit-trail` read; they do not change the store.
- **Raise log verbosity narrowly and briefly.** `RUST_LOG=ai_memory=debug`
  (the postgres adapter logs under `store::postgres`, which an `ai_memory=…`
  filter does not match). Treat any debug or trace capture as sensitive: do
  not ship it to a shared channel or off-host collector, and return to
  `info` when done.
- **Never paste configuration or environment dumps.** Several knobs are
  secrets (API keys, store URLs with passwords, passphrases); see the
  classification column of the environment-variable table in `docs/reference/ARCHITECTURE_REFERENCE.md`.
- **Do not enable test-only knobs** (`AI_MEMORY_TEST_*`,
  `AI_MEMORY_AUTO_EXPORT_INJECT_PANIC`) on a production process.
- **Do not "fix" the store while diagnosing it.** Take an
  `ai-memory backup` first; `backup` and `export` keep working even when the
  daemon refuses to boot on a newer schema or an unknown config key.

## 7. Tracing an incident end to end

A worked walk for "an agent says a memory it stored is gone":

1. **Is the daemon alive and its store readable?** `curl` `/api/v1/health`.
   A 503 names the failed probe; stop and recover the store first.
2. **Which process wrote it?** MCP stdio, CLI and HTTP writes all land in
   the same store, but only HTTP writes move the daemon's
   `ai_memory_store_total`. Check the agent's own logs for its write
   receipt.
3. **Was it refused?** Search the operational log for governance refusals
   and `signed_events` for `governance.check` rows naming the agent
   (`ai-memory verify-audit-trail` first, to know the chain is intact).
4. **Was it removed?** Look for the row in the archive (`ai-memory archive`
   subcommands) — GC archives before deleting by default
   (`archive_on_gc`), a forget can archive, and consolidation tombstones
   its sources while the lineage DAG is on — and for a `forget_tombstones`
   entry if the node federates.
5. **Did federation move it?** Check `ai_memory_federation_push_dlq_depth`,
   the quarantine counters, `ai_memory_fed_quarantined_unattributed_total`
   (quarantined inbound rows are hidden from reads) and per-peer freshness.
6. **Is recall just not finding it?** Compare
   `ai_memory_recall_total{mode=...}` and
   `ai_memory_recall_embed_degraded_total`: a node that degraded to keyword
   mode ranks differently but has not lost data.

## 8. Verifying recovery

An incident is closed when the signal that opened it is **observed**
healthy again, not when it stops firing:

- `/api/v1/health` answers 200 and `fts_integrity` is `ok` with a recent
  `checked_at` (not `pending` or `stale`).
- `ai_memory_memories_refreshed_at_seconds` is advancing.
- The relevant `rate(...)` is back to zero over a full window, and the
  per-peer `last_success_timestamp_seconds` has advanced past the incident.
- `ai-memory doctor` exits 0 and `ai-memory verify-audit-trail` is clean.

Signals this contract does not yet cover — per-operation latency for writes,
wake-plane pressure, logging and webhook-audit delivery, read-audit delivery
(#3660), restore evidence — are listed with their owning issues in
[`HEALTH-MONITORING.md`](../HEALTH-MONITORING.md#status-fields).
