# Health monitoring API (v1)

ai-memory supplies a vendor-neutral interface for an external monitor, a
Prometheus scraper, or an operator's script. No monitor, dashboard, alert rules,
or commercial consumer is required or included. This contract is issue #3646;
the instrumentation audit and independently tracked gaps are in #3645.

## Transport and health-only credentials

Use the daemon's existing `--tls-cert` and `--tls-key`. Both endpoints below
refuse plaintext listeners, including loopback, and ignore `X-Forwarded-Proto`.
Terminate TLS in the daemon for this contract. No additional listener, signing
root, token format, or secret is introduced.

Enroll an ordinary agent using the existing agent API-key enrollment workflow.
Assign its principal a health-only scope in the daemon configuration **before
handing the credential to a monitor**:

```toml
[monitoring]
agent_ids = ["ai:production-monitor"]
peer_ids = []
```

Enrollment and revocation use the existing live enrolled-key registry and its
refresh cadence (`AI_MEMORY_AGENT_KEY_REFRESH_SECS`). Scope assignments are
loaded at daemon startup; restart after changing them. They restrict all keys
belonging to the named principal, even if it also appears in `[admin]` or HTTP
identity binding is disabled. Use a dedicated principal and do not reuse the
operator's shared key as an enrolled key. Once any monitoring scope is configured,
unresolved credentials cannot fall through to anonymous writes in an otherwise
shared-key-free deployment. The legacy liveness probe remains available.

For mTLS, use the existing `--mtls-allowlist` plus
`AI_MEMORY_FED_CERT_PEER_BINDING_MAP`, and put the operator-bound peer identity in
`monitoring.peer_ids`. Boot refuses peer scopes without TLS, an allowlist, and
matching certificate bindings. No certificate subject or HTTP identity header
can supply that binding. The ordinary allowlist verifier must accept the client
certificate before the request reaches the router. Possession of an allowlisted
but **unbound** certificate alone does not authenticate these endpoints.

Send an enrolled key in the `X-API-Key` header, or present the bound mTLS client
certificate. The existing shared operator API key can also read the health
surface. A health-only principal is refused with `403 monitoring_scope_refused`
on **every other path and every non-GET/HEAD method**, including legacy health,
legacy metrics, recall, writes, federation, unknown routes, and future routes.
A second credential or spoofed `X-Agent-Id` does not elevate it. Missing/revoked
credentials return 401. TLS refusal returns 403.

The guarantee is **a monitoring credential cannot authenticate to any mutating
funnel through the shipped HTTP surface**. One outer request gate enforces this
before every router handler and fallback, including all legacy authentication
exemptions. The storage layer does not enforce monitoring authority; #3672 tracks
that additional defence. Embedders of the Rust router must provide actual
listener TLS posture through `EnrolledAgentKeys::with_monitoring`; defaults are
TLS-disabled and do not enable health access.

## Endpoints and version policy

| Method and path | Content type | Purpose |
|---|---|---|
| `GET /api/v1/monitoring/status` | `application/json` | Qualitative state and observation gaps |
| `GET /api/v1/monitoring/metrics` | `text/plain; version=0.0.4; charset=utf-8` | Prometheus exposition, with HELP and TYPE |

HEAD uses the same checks and returns no body. Successful scrapes are HTTP 200.
A failing status document returns HTTP 503 **with the same JSON schema**. Transport,
authentication, timeout and overload failures are error responses, not status
documents; clients must check the response status and schema version.

JSON `schema_version` is integer **1**, pinned by tests. Within v1, additions are
allowed; consumers must tolerate new fields and treat unknown state/reason values
as unknown. Removing/renaming fields, changing types, units or meaning requires a
new major schema version and URL. Numeric series names, units and semantics follow
the same policy. Missing numeric samples mean unavailable, never zero. Counter
resets indicate a process restart. Aggregates have process scope, not tenant scope.

## Status fields

| Field | Type and meaning |
|---|---|
| `schema_version`, `software_version` | Contract major integer and binary version string |
| `observed_at_seconds` | UTC Unix seconds when this snapshot was assembled; individual checks are not atomic |
| `status` | `healthy`, `degraded`, or `failing`; failure takes precedence |
| `reasons` | Stable reason-code array, never underlying error text |
| `backend` | Active storage backend (`sqlite` or `postgres`) |
| `database_schema_version` | Active database's recorded positive schema integer; null when unreadable/unknown |
| `posture` | Transport, accepted authentication mechanisms and health read-only scope; no configuration values |
| `singleton.process` | `responding`: the process answered this request |
| `singleton.store_connection` | `reachable` or `failing`, from the live bounded backend probe |
| `singleton.fts_index` | SQLite bounded FTS probe state; `not_applicable` on Postgres |
| `singleton.fts_integrity` | Cached deep-check `state` and nullable `checked_at_seconds`; pending/stale/disabled do not assert soundness |
| `singleton.embedder_loaded` | Boolean: an embedder is loaded, not proof of successful embedding |
| `singleton.vector_index_loaded` | Boolean: an index handle exists, not proof of index soundness |
| `federation.enabled` | This daemon has an outbound federation configuration |
| `federation.node_identity_ref` | SHA-256 of configured sender identity; null without federation |
| `federation.peers[].identity_ref` | Full SHA-256 of configured peer identity; stable across restarts with the same identity |

`posture.scope` describes this health surface. An operator credential can still
have broader privileges on other routes.

Legacy peer IDs may contain credential URLs, so neither raw peer IDs nor endpoints
are returned. Operators correlate a peer by hashing its configured ID locally
(SHA-256 over its UTF-8 bytes, lowercase hex). These references describe configured
membership, not successful remote identity verification. Peers in inbound-only or
catch-up-only configurations are not enumerated here; #3654 owns complete observed
membership. An empty peer array must not be read as proof that a fleet is healthy.

At this release head, required operation and wake observations are unavailable,
so a responding, readable node reports `degraded` with
`required_observations_unavailable`. Store, FTS or schema lookup failures report
`failing` and the applicable `store_connection_failed`, `index_failed`, or
`database_schema_unavailable` reason. `keyword_only_by_design` identifies an
unloaded embedder without presenting it as an error. This surface does not claim a
quiet peer is healthy. Wake fallback is not inferred from configuration: once
#3657 supplies real observations, bounded-poll fallback can be reported as a
by-design degradation.

Unavailable fields have exactly this shape (no fabricated numeric value):

```json
{"state":"unavailable","reason":"not_yet_instrumented","issue":3654}
```

| Fields | Owning audit issue |
|---|---|
| Per-peer `reachability`, `last_successful_push_age_seconds`, `last_push_attempt_at_seconds`, `last_accepted_push_at_seconds`, `replication_lag`, `dlq_depth`, `dlq_oldest_age_seconds`, `catch_up_progress`, `clock_skew_seconds` | #3654 |
| `singleton.embedder_operation_health`, `singleton.operation_rates_and_latency`, `federation.quorum_outcomes` | #3653 |
| `singleton.disk_wal_backup` (remote diagnostic coverage) | #3656 |
| `federation.nonce_cache` | #3662 |
| `federation.dlq_bookkeeping` | #3658 |
| `wake.connected_agents`, `queue_pressure`, `egress_pressure`, `drops_by_cause`, `backstop_reliance`, `fallback_state`, `agent_liveness` | #3657 |
| `logging_delivery`, `webhook_audit_delivery`, `read_audit_delivery`, `restore_evidence` | #3651, #3659, #3660, #3661 respectively |

These are explicit integration gaps, not implemented instrumentation or claims
that their owner issues are complete. Follow-on wiring must use observed values,
carry freshness where appropriate, and preserve the v1 absence semantics.
An instrumented field remains a signal object, with an available state and
additive `value`/freshness fields; it must not replace an unavailable object
with a bare number.

## Numeric signals and privacy

The metrics endpoint selects existing, live, **unlabelled** process counters.
It does not forward the global registry, whose arbitrary labels are outside this
privacy boundary. All names below begin with `ai_memory_`; all are counters of
events since process start:

| Series suffix | Counted event |
|---|---|
| `admission_shed_total` | HTTP requests rejected by admission control |
| `recall_embed_degraded_total` | Query embedding fell back to keyword recall |
| `rerank_budget_degraded_total` | Reranking was skipped due to budget |
| `query_embed_cache_hits_total` | Query embedding cache hit |
| `autotag_enqueued_total`, `autotag_dropped_total`, `autotag_applied_total`, `autotag_degraded_total` | Auto-tag queue acceptance, drops, applied jobs and degraded jobs |
| `atomise_enqueued_total`, `atomise_dropped_total`, `atomise_applied_total`, `atomise_degraded_total` | Atomisation queue acceptance, drops, applied jobs and degraded jobs |
| `federation_partial_quorum_total` | Quorum succeeded while at least one peer did not acknowledge in time; not all quorum failures |

No memory/inbox/transcript bodies, titles, namespace-private policy values, raw
errors, DSNs, endpoints, credential hashes or key material are serialized. Seeded
regressions exercise both backends, peer URL identities, and poisoned global metric
labels. Health reads do not invoke recall, transcript writes, or provider requests.
The status probe uses bounded database reads and cached integrity facts; it does
not run a deep index scan per scrape. Normal request timeouts bound it; admission
control exempts health so overload remains diagnosable. TLS and authentication
still apply under overload.

The legacy `/api/v1/health`, `/metrics`, and `/api/v1/metrics` retain their existing
contracts and are not part of this metadata-only scope. Monitor-only credentials
cannot use them. Broader operator observability and incident guidance is tracked
in #3666.
