# Observability audit — issue #3645

**Verdict: NO — the suite is not yet production-observable under the stated enterprise/operator contract.** A singleton has useful health checks and a fleet has substantial defensive machinery, but emitted output alone cannot reliably establish end-to-end health.

The three largest problems are: **sensitive action/provider/query data can enter diagnostics; the logging pipeline can suppress or lose the very failures it should report; and essential operation/peer/wake telemetry is absent, unwired, or lacks freshness and correlation.**

Audited release: `f0175b709cc304fffd8731669c67c16a5388e5fa` (2026-09-12). Read-only product audit: no production changes, migrations, operator database access, key access, daemon restarts, or fault injection against deployed systems. Findings below are source-confirmed paths, not claims of an observed production incident. Report and census are the only repository artifacts. All 21 findings have separate issues: 4 CRITICAL, 14 HIGH, 3 MEDIUM.

## Scope and reproducibility

Inspected daemon boot/log sinks, HTTP/MCP boundaries, CLI/doctor/backup, SQLite and SAL/Postgres adapters, federation push/catch-up/quorum/DLQ/nonce cache, governance and signed events, embedding/index fallback, wake hub/sink/client, SDK transport/wake output, and shipped supervisor/install documentation. CodeGraph 1.6.0 navigation ran first from `/home/fate_two/v07/v09-dev`; every cited product line was then checked in the exact-head worktree. The release-root graph can show newer line numbers, so report links are pinned to the audited commit.

CodeGraph queries (all `codegraph explore`, from the release root):

- `logging tracing observability health doctor metrics federation wake signed_events`
- `init_logging health_handler metrics_handler doctor`
- `federation push_to_peer catch_up WriteFunnel WakeMeta NonceCache`
- `logging init_tracing doctor backup restore`
- `LlmClient embed_with_status handler_error_500 sync_since`
- `dispatch_tool record_store signed_events emit_inbox_wake`
- `replay_once FederationPushDlqSink bump_dlq_attempt gate_read emit_check_event`
- `wrap_transport_error handle_response wake_listen doctor backup auto-link-detector transcript-extractor`

Important traced relationships: `embed_create_before_lock → Embedder::embed_with_status → Embed::embed` (including dynamic embed implementations); `record_store → registry` with only test callers; `replay_once → dyn FederationDlqSink::{bump_dlq_attempt,note_dlq_throttled} → SqliteDlqSink/PostgresDlqSink`; `init_file_logging → build_appender/init_syslog_logging → main`; `gate_read → emit_check_event → append_signed_event`.

The census lexically scans 501 tracked Rust files in `src`, first-party tool `src` trees and `loadtest/src`, excluding test-named files and `#[cfg(test)]` items. It masks comments, strings and chars before recognizing macros. Counts include mutually exclusive platform/feature branches, are source sites rather than runtime volume, and exclude dependencies, generated macro expansions, `write!/writeln!` serializers, SDK exceptions and intentional CLI data bodies. The latter were reviewed separately; they must not be mistaken for structured operational events. A heuristic “no explicit fields” count is not a parser-level proof of schema quality. No claim is made that static inspection proves every dependency error or panic content-safe.

## Quantified output inventory

| Level | Sites |
|---|---:|
| ERROR | 143 |
| WARN | 956 |
| INFO | 274 |
| DEBUG | 97 |
| TRACE | 1 |

**1,471 tracing/log event sites; 173 direct print-family sites** (107 eprintln, 61 println, 1 eprint, 4 print). One explicit application MCP span site; HTTP spans come from the pinned tower-http layer. **756 events use module-default targets; 715 explicit targets; 563 explicit-target sites do not match `ai_memory`**. **693 event sites** lack a named assignment or `%`/`?` field shorthand by the lexical heuristic (bare-field shorthand and prose interpolation are limitations). All source locations are in [emission-sites.csv](emission-sites.csv).

### Per crate/area

| Area | ERROR | WARN | INFO | DEBUG | TRACE | Direct print |
|---|---:|---:|---:|---:|---:|---:|
| loadtest/src | 0 | 0 | 0 | 0 | 0 | 17 |
| src/actions | 0 | 0 | 1 | 0 | 0 | 0 |
| src/approvals.rs | 0 | 2 | 0 | 0 | 0 | 0 |
| src/atomisation | 0 | 3 | 0 | 0 | 0 | 0 |
| src/audit.rs | 1 | 3 | 0 | 0 | 0 | 0 |
| src/autonomy.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| src/background | 5 | 29 | 10 | 0 | 0 | 2 |
| src/cli | 2 | 28 | 10 | 3 | 0 | 7 |
| src/confidence | 0 | 1 | 3 | 0 | 0 | 0 |
| src/config.rs | 1 | 11 | 0 | 0 | 0 | 20 |
| src/coordination_audit.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| src/cost | 0 | 0 | 0 | 10 | 0 | 0 |
| src/curator | 5 | 10 | 4 | 0 | 0 | 0 |
| src/daemon_runtime.rs | 10 | 70 | 63 | 6 | 0 | 23 |
| src/egress.rs | 0 | 3 | 0 | 0 | 0 | 0 |
| src/embeddings.rs | 0 | 4 | 0 | 0 | 0 | 2 |
| src/erasure | 0 | 34 | 2 | 0 | 0 | 0 |
| src/export_taxonomy.rs | 0 | 4 | 0 | 0 | 0 | 0 |
| src/federation | 2 | 87 | 17 | 20 | 0 | 1 |
| src/forensic | 0 | 1 | 0 | 0 | 0 | 0 |
| src/governance | 21 | 30 | 2 | 3 | 0 | 0 |
| src/handlers | 61 | 259 | 4 | 11 | 0 | 0 |
| src/hnsw.rs | 3 | 4 | 0 | 0 | 0 | 0 |
| src/hooks | 6 | 19 | 8 | 4 | 0 | 0 |
| src/identity | 2 | 18 | 3 | 1 | 0 | 1 |
| src/inbox_wake.rs | 0 | 3 | 0 | 0 | 0 | 0 |
| src/lib.rs | 0 | 2 | 0 | 0 | 0 | 0 |
| src/llm.rs | 0 | 2 | 4 | 2 | 0 | 0 |
| src/logging.rs | 0 | 2 | 0 | 2 | 0 | 0 |
| src/main.rs | 0 | 0 | 0 | 0 | 0 | 8 |
| src/mcp | 7 | 45 | 7 | 4 | 0 | 47 |
| src/migrate.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| src/notification | 0 | 1 | 0 | 0 | 0 | 0 |
| src/observations | 0 | 2 | 0 | 0 | 0 | 0 |
| src/offload | 0 | 0 | 1 | 0 | 0 | 0 |
| src/portability | 0 | 16 | 0 | 0 | 0 | 0 |
| src/quotas.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| src/recover | 0 | 5 | 5 | 0 | 0 | 1 |
| src/reload.rs | 0 | 5 | 3 | 0 | 0 | 5 |
| src/reranker.rs | 0 | 7 | 0 | 1 | 0 | 1 |
| src/secret_screen.rs | 0 | 5 | 0 | 0 | 0 | 0 |
| src/signed_events.rs | 1 | 2 | 0 | 0 | 0 | 0 |
| src/spawn_audit.rs | 0 | 2 | 0 | 1 | 0 | 0 |
| src/storage | 1 | 73 | 5 | 12 | 1 | 0 |
| src/store | 4 | 99 | 99 | 7 | 0 | 0 |
| src/store_url.rs | 0 | 2 | 0 | 0 | 0 | 0 |
| src/subscriptions.rs | 1 | 25 | 0 | 0 | 0 | 0 |
| src/tls.rs | 1 | 2 | 0 | 0 | 0 | 0 |
| src/transcripts | 0 | 6 | 0 | 0 | 0 | 0 |
| src/vectorlite.rs | 5 | 2 | 1 | 0 | 0 | 0 |
| src/visibility.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| src/wake_client | 0 | 1 | 3 | 2 | 0 | 0 |
| src/wake_hub | 2 | 14 | 12 | 6 | 0 | 0 |
| src/wake_sink | 2 | 7 | 7 | 2 | 0 | 0 |
| src/write_events.rs | 0 | 1 | 0 | 0 | 0 | 0 |
| tools/auto-link-detector | 0 | 0 | 0 | 0 | 0 | 2 |
| tools/post-ship-converge | 0 | 0 | 0 | 0 | 0 | 5 |
| tools/t0-orchestrate | 0 | 0 | 0 | 0 | 0 | 29 |
| tools/transcript-extractor | 0 | 0 | 0 | 0 | 0 | 2 |

All product tracing sites belong to the `ai-memory` package (`ai_memory` library); the separate first-party tool/loadtest packages above emit direct output. CLI also writes through `CliOutput`/`writeln!`, so its small direct-print count is not its total output volume.

### Every explicit target

Counts below resolve file-local and imported string constants; `memory_smart_load` resolves the aliased registry constant. Module-default targets are listed separately above. This enumerates the additional filter mismatches beyond `store::postgres`.

| Target | Sites | Matches ai_memory |
|---|---:|---|
| `access.fold` | 4 | NO |
| `ai_memory::audit` | 1 | yes |
| `ai_memory::authz` | 17 | yes |
| `ai_memory::coordination` | 1 | yes |
| `ai_memory::daemon_runtime` | 2 | yes |
| `ai_memory::federation::erasure_outbox` | 8 | yes |
| `ai_memory::federation::push_dlq` | 31 | yes |
| `ai_memory::federation::sync` | 3 | yes |
| `ai_memory::fts_integrity` | 12 | yes |
| `ai_memory::governance` | 4 | yes |
| `ai_memory::governance::audit` | 11 | yes |
| `ai_memory::governance::chain_graft` | 2 | yes |
| `ai_memory::governance::policy_read` | 2 | yes |
| `ai_memory::governance::standard_severed` | 3 | yes |
| `ai_memory::handlers::db_op` | 5 | yes |
| `ai_memory::handlers::skills` | 3 | yes |
| `ai_memory::identity::attest` | 3 | yes |
| `ai_memory::identity::replay` | 10 | yes |
| `ai_memory::mcp` | 1 | yes |
| `ai_memory::metrics_gauge` | 5 | yes |
| `ai_memory::quarantine` | 2 | yes |
| `ai_memory::read_pool` | 2 | yes |
| `ai_memory::storage::checks` | 1 | yes |
| `ai_memory::storage::migrations` | 10 | yes |
| `ai_memory::storage::schema_integrity` | 3 | yes |
| `ai_memory::storage::txn_guard` | 1 | yes |
| `ai_memory::storage::update` | 2 | yes |
| `ai_memory::subscriptions` | 3 | yes |
| `ai_memory::tls` | 1 | yes |
| `ai_memory::verify` | 2 | yes |
| `ai_memory::visibility` | 1 | yes |
| `approvals.signed` | 2 | NO |
| `atomisation` | 1 | NO |
| `atomisation::curator` | 2 | NO |
| `atomise.worker` | 5 | NO |
| `audit.attestation` | 1 | NO |
| `bulk_create` | 6 | NO |
| `capabilities` | 1 | NO |
| `cid.enforce` | 2 | NO |
| `compliance.unenforced` | 1 | NO |
| `confidence.calibrate` | 6 | NO |
| `confidence.shadow` | 2 | NO |
| `config.max_memory_mb` | 1 | NO |
| `coordination.lease_sweep` | 1 | NO |
| `cost` | 10 | NO |
| `covenant.authorship_immutable` | 1 | NO |
| `covenant.why_trace` | 1 | NO |
| `create_memory` | 1 | NO |
| `curator::compaction` | 6 | NO |
| `embeddings.capability_drift` | 1 | NO |
| `embeddings.degrade` | 1 | NO |
| `encryption.envelope_owner_reconciled` | 1 | NO |
| `encryption.undecryptable_row_skipped` | 3 | NO |
| `erasure::cold_tier` | 34 | NO |
| `federation` | 4 | NO |
| `federation.quarantine.unattributed` | 1 | NO |
| `federation::attestation` | 80 | NO |
| `federation::clock_skew` | 1 | NO |
| `federation::peer_attestation` | 3 | NO |
| `federation::peer_id` | 1 | NO |
| `federation::quota` | 2 | NO |
| `federation::reflection_bookkeeping` | 2 | NO |
| `federation::scope` | 6 | NO |
| `federation::signing` | 35 | NO |
| `forget.tombstone` | 4 | NO |
| `governance` | 7 | NO |
| `governance.rules` | 1 | NO |
| `handlers::parity` | 1 | NO |
| `handlers::route_1111` | 1 | NO |
| `hnsw.eviction` | 4 | NO |
| `hnsw.rebuild` | 1 | NO |
| `hooks` | 4 | NO |
| `hooks.enforce.namespace_unresolved` | 2 | NO |
| `hooks.enforce.violation` | 1 | NO |
| `http::auth` | 9 | NO |
| `identity.bind.challenge_miss` | 1 | NO |
| `identity.bind.proof_invalid` | 1 | NO |
| `identity.lineage.recovery` | 1 | NO |
| `identity::hub_cache::producer_binding` | 2 | NO |
| `identity::keypair` | 3 | NO |
| `lease.sweep` | 4 | NO |
| `logging` | 2 | NO |
| `mcp.reflect` | 1 | NO |
| `memory_smart_load` | 2 | NO |
| `memory_store` | 1 | NO |
| `namespace.standard.not_live` | 1 | NO |
| `namespace.standard.withheld` | 1 | NO |
| `notification.invalidation` | 2 | NO |
| `observations` | 3 | NO |
| `offload.ttl_sweep` | 2 | NO |
| `portability::import` | 16 | NO |
| `post_reflect.auto_export` | 2 | NO |
| `post_reflect.auto_persona` | 2 | NO |
| `pre_store.auto_atomise` | 14 | NO |
| `pre_store.auto_atomise.sync` | 4 | NO |
| `proactive_conflict` | 1 | NO |
| `recall.embed.budget` | 1 | NO |
| `recall.embed.degraded` | 1 | NO |
| `reflection.decorrelation.advisory` | 5 | NO |
| `rerank.budget` | 1 | NO |
| `rerank.budget.degraded` | 1 | NO |
| `reranker` | 1 | NO |
| `reranker.fallback` | 1 | NO |
| `reranker.warmup` | 1 | NO |
| `schema_guard` | 5 | NO |
| `schema_init` | 3 | NO |
| `secret.redacted` | 4 | NO |
| `secret.refused` | 1 | NO |
| `security.posture` | 2 | NO |
| `security.posture.enterprise_federation` | 3 | NO |
| `signed_events` | 29 | NO |
| `skills.bomb` | 1 | NO |
| `store::postgres` | 126 | NO |
| `store::postgres::chain_append` | 1 | NO |
| `store::postgres::kg` | 18 | NO |
| `store::postgres::kg::adapter_defect` | 2 | NO |
| `store::postgres::tx_retry` | 2 | NO |
| `synthesis` | 17 | NO |
| `transcripts.bomb` | 1 | NO |
| `transcripts.lifecycle` | 4 | NO |
| `transcripts.replay` | 1 | NO |
| `visibility.unknown_scope` | 1 | NO |

## Health surface: what exists and what it proves

| Surface/signal | Actual emitted contract at this head | Missing for a trusted monitor |
|---|---|---|
| HTTP `/health`, `/api/v1/health` | `status`, service/version, embedder object presence, federation configured flag, connection/FTS reachability; cached FTS verdict with checked_at/interval and 503 on unhealthy verdict (`transport.rs:1225`). Postgres uses store health_check; SQLite has bounded SQL probes. | No fleet convergence, required-component readiness, wake delivery or log sink readiness; underlying probe errors may collapse to booleans. Do not interpret embedder_ready as a recent successful inference. |
| Prometheus `/metrics`, `/api/v1/metrics` | 51 registry families, listed below. Cold corpus prime selects the active backend, then uses refreshed-at timestamps. | Registered is not instrumented; no write duration/working store count, complete request errors, per-peer lag, nonce or wake exporter. |
| Local doctor | Configuration, identity, storage/schema/core relations/durability, index/dimensions, embedding-space and recall coverage, lifecycle, governance/pending actions, sync, webhooks, LLM/embed reachability, reflection, atomisation, optional PG extensions and wake probe. | On-demand facts are not running-daemon gauges. Several SQL errors collapse into empty/N/A; no complete continuous fleet view. |
| Remote doctor | Capabilities (including federation posture), recall capability and stats. Explicit N/A for Index/Governance/Sync/Webhook. | Does not consume health; cannot establish those remote component states. |
| Read latency/errors | HTTP successful recall count and histogram by mode; MCP span emits tool/rpc_id/elapsed_ms and outcome after dispatch. | Failing/cancelled reads, other read verbs and full error taxonomy; MCP has no common scrape surface. |
| Write latency/errors | Registered store counter by tier/result. | No production updates to it; no write histogram or complete storage result classes. |
| Federation quorum/DLQ | Fanout dropped by reason; retry by outcome; partial quorum; aggregate push DLQ depth; quarantine/legacy/erasure counters; credential verification/age/renewal. | Failed-quorum denominators, per-peer acceptance/freshness/lag/oldest age, dead worker detection, local bookkeeping failure signals. |
| Nonce cache | WARNs and peer eviction accessor; bounded in-memory cache and best-effort disk mirror. | Exported occupancy, peer/FIFO evictions, persistence state and replay-rate classification. |
| Embedder/index | Health embedder presence; recall embed/rerank degradation and cache counters; HNSW size/evictions; cached FTS integrity freshness; AGE projection backlog/failure/quarantine. | Universal embed attempts/failures/latency and breaker state, backend-specific index freshness; HNSW metric does not establish pgvector health. |
| Schema/disk/WAL/backup | Doctor can report schema and DB size; backups have manifests/checksums/signatures and CLI outcomes. | Continuous active-backend schema drift, disk free/WAL growth, backup last success/age/size and restore verification history. External OS/DB exporters may supply resource data, but must be documented/wired. |
| Wake hub/sink/client | Rich in-process hub counters (connections/refusals/rate limits/queues/drops/wakes/fanout and latency histograms); 11 sink counters; owner socket health/posture; client reasons include wake/gap/lagged/backstop/reconnect. | Live hub/sink export and freshness. `--posture` metrics_schema is deliberately an empty schema, not live telemetry. |

The registry families are:

```text
ai_memory_store_total
ai_memory_recall_total
ai_memory_recall_latency_seconds
ai_memory_autonomy_hook_total
ai_memory_contradiction_detected_total
ai_memory_webhook_dispatched_total
ai_memory_webhook_failed_total
ai_memory_memories
ai_memory_memories_refreshed_at_seconds
ai_memory_hnsw_size
ai_memory_subscriptions_active
ai_memory_curator_cycles_total
ai_memory_curator_operations_total
ai_memory_curator_cycle_duration_seconds
ai_memory_federation_fanout_dropped_total
ai_memory_federation_fanout_retry_total
ai_memory_federation_partial_quorum_total
ai_memory_corrupt_provenance_rows_total
ai_memory_auto_export_spawn_failed_total
ai_memory_federation_push_dlq_depth
ai_memory_deferred_audit_drainer_terminal_state
ai_memory_federation_push_dlq_quarantined_total
ai_memory_federation_push_dlq_quarantined_by_cause_total
ai_memory_federation_push_dlq_legacy_positional_total
ai_memory_federation_erasure_superseded_total
ai_memory_fed_quarantined_unattributed_total
ai_memory_operator_dequarantined_total
ai_memory_hnsw_evictions_total
ai_memory_hnsw_last_eviction_at_nanos
ai_memory_subscription_dlq_overflow_total
ai_memory_subscription_dispatch_truncated_total
ai_memory_federation_cred_verify_total
ai_memory_federation_inbound_cred_total
ai_memory_federation_cred_max_age_seconds
ai_memory_federation_renewal_lag_seconds
ai_memory_admission_shed_total
ai_memory_recall_embed_degraded_total
ai_memory_rerank_budget_degraded_total
ai_memory_query_embed_cache_hits_total
ai_memory_autotag_enqueued_total
ai_memory_autotag_dropped_total
ai_memory_autotag_applied_total
ai_memory_autotag_degraded_total
ai_memory_atomise_enqueued_total
ai_memory_atomise_dropped_total
ai_memory_atomise_applied_total
ai_memory_atomise_degraded_total
ai_memory_atomise_no_curator_total
ai_memory_age_projection_pending_depth
ai_memory_age_projection_failed_total
ai_memory_age_projection_quarantined_total
```

Positive evidence matters: cached FTS integrity has a timestamp and durable failed verdict; the corpus gauge has freshness; admitted deferred governance events have durable spool/recovery and a terminal-state gauge; federation DLQ classes are typed and retries retain rows; wake hints are content-free and carry gap/backstop semantics. Clock-skew WARN already exists (`handlers/federation_receive.rs:456`), with sender and signed skew, but its target is filtered by the default and there is no continuous per-peer gauge. This audit does not recommend replacing those safeguards.

## Findings by audit area

### 4. Secrets, credentials and tenant content

**F01 — CRITICAL: Forensic governance JSONL persists unscreened action payloads ([#3647](https://github.com/alphaonedev/ai-memory-mcp/issues/3647)). Areas 4.

emit_forensic_decision serializes the entire action and decision_detail. AgentAction contains Bash.command, ProcessSpawn.args, Custom.payload and Read.query. try_record_decision places payload directly in the signed JSONL row. main initializes this sink without checking audit.enabled. No content/credential redaction occurs on this path; signing is integrity protection, not confidentiality.

Evidence: [src/governance/agent_action.rs:1284](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/agent_action.rs#L1284), [src/governance/agent_action.rs:128](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/agent_action.rs#L128), [src/governance/audit.rs:434](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/audit.rs#L434), [src/main.rs:334](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/main.rs#L334).

**Operator impact:** A governed command containing a token, arbitrary custom tenant payload, or sensitive recall query becomes a second plaintext copy in the forensic log and its SIEM/backup retention domain, including refused actions.

**Fix direction / acceptance evidence:** Emit an allowlisted identity/outcome envelope and a content hash; redact before signing. Make forensic enablement and sensitive-field policy explicit. Regression tests must place sentinel secrets in every AgentAction variant and inspect real emitted JSONL, including refused actions and default boot configuration.

**F02 — CRITICAL: LLM and embedder errors expose provider bodies through logs and HTTP ([#3648](https://github.com/alphaonedev/ai-memory-mcp/issues/3648)). Areas 4.

Non-2xx chat/embed responses interpolate read_capped_text into anyhow errors; malformed successful responses interpolate the entire JSON body. embed_with_status formats the full error chain into reason, logs it, and create returns that reason as embed_status_reason. MCP also logs arbitrary handler error strings. The response-size cap is not redaction.

Evidence: [src/llm.rs:1784](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/llm.rs#L1784), [src/llm.rs:1805](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/llm.rs#L1805), [src/llm.rs:2505](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/llm.rs#L2505), [src/llm.rs:2527](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/llm.rs#L2527), [src/embeddings.rs:1442](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/embeddings.rs#L1442), [src/handlers/create.rs:1006](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/handlers/create.rs#L1006), [src/mcp/mod.rs:3707](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/mcp/mod.rs#L3707).

**Operator impact:** A provider/proxy echoing input, credentials or another tenant diagnostic can put it in operational logs and caller-visible failure metadata. Exposure is conditional on response contents, but the raw emission path is proven.

**Fix direction / acceptance evidence:** Replace provider text with bounded typed status/error codes and safe provider identity. Do not pass raw downstream bodies to tracing, Display, or wire responses. Test both non-2xx and malformed-2xx echo bodies end to end with a mock provider.

**F03 — CRITICAL: HTTP diagnostic spans include the full query-bearing URI ([#3649](https://github.com/alphaonedev/ai-memory-mcp/issues/3649)). Areas 4.

The router installs TraceLayer::new_for_http without a custom MakeSpan. The pinned tower-http 0.6.8 DefaultMakeSpan records %request.uri() at DEBUG (headers excluded). GET recall accepts query text in the URI. Verified against the locally installed 0.6.8 dependency source, trace/make_span.rs:85-104. The default console INFO filter suppresses these spans; an enabled debug filter/file sink exposes them.

Evidence: [src/lib.rs:1611](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/lib.rs#L1611), [src/models/memory.rs:1952](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/models/memory.rs#L1952), [Cargo.lock:4557](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/Cargo.lock#L4557).

**Operator impact:** Enabling HTTP diagnostics during an incident can copy private recall queries or query-string credentials into logs. This is a conditional diagnostic-mode disclosure, not a claim that normal INFO logs contain all queries.

**Fix direction / acceptance evidence:** Use matched route templates and method, excluding query strings and sensitive path segments. Test sentinel query values with tower_http=debug and JSON/plain sinks.

**F21 — CRITICAL: Postgres query-form passwords bypass URL redaction in boot and doctor output ([#3667](https://github.com/alphaonedev/ai-memory-mcp/issues/3667)). Areas 4.

redact_url_password inspects only the authority userinfo and returns URLs with no @ unchanged. SQLx 0.8.6 accepts password in URL query parameters (locally verified options/parse.rs:88 and its query-password test). Thus postgres://user@db.example/memory?password=AUDIT_CANARY_3645 retains the credential. redact_urls_in_message delegates to the same helper, and boot, doctor and unsupported-feature refusal output use it. A standalone rustc test of the exact extracted redactor confirms the query canary survives; a second test confirms ordinary userinfo passwords are masked (2 passed, 0 failed). These are audit reproductions of current behavior, not fix regression tests.

Evidence: [src/logging.rs:949](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L949), [src/daemon_runtime.rs:5062](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/daemon_runtime.rs#L5062), [src/cli/doctor.rs:1373](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/doctor.rs#L1373), [src/store_url.rs:205](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/store_url.rs#L205).

**Operator impact:** A legitimate password-bearing DSN can expose its password to diagnostic logs, doctor JSON/text and startup errors even though the output is described as redacted. No real credentials were used in verification.

**Fix direction / acceptance evidence:** Parse and redact all supported credential representations, including percent-encoded query keys/values and repeated password parameters; keep malformed-input redaction fail-safe. Audit peer/provider URL renderers too. Test boot/doctor/refusal output with synthetic userinfo and query-password DSNs.

### 1. Level discipline

**F08 — HIGH: Catch-up outages are DEBUG-only and fleet replication lacks per-peer freshness ([#3654](https://github.com/alphaonedev/ai-memory-mcp/issues/3654)). Areas 1,6.

All catch-up variants route non-success HTTP and unreachable errors through DEBUG helpers. Successful pulls emit INFO with peer/row count in prose. Current federation metrics count retry/drop/partial quorum and aggregate DLQ state, but no configured-peer census, last attempt/success, last accepted push, per-peer lag/oldest backlog or failure streak. Join errors in broadcast paths lose peer attribution.

Evidence: [src/federation/receive.rs:23](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/receive.rs#L23), [src/federation/receive.rs:27](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/receive.rs#L27), [src/federation/receive.rs:35](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/receive.rs#L35), [src/federation/sync.rs:717](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/sync.rs#L717), [src/metrics.rs:641](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L641).

**Operator impact:** An unreachable or rejecting peer can stop converging without an INFO-level failure event or an alertable freshness series. A quiet peer, dead worker, partition and rejected pushes are not reliably distinguishable.

**Fix direction / acceptance evidence:** Publish per-peer expected membership, attempt/success timestamps, push/apply outcomes, lag and backlog age with stable node/peer identifiers. Escalate sustained failures while rate-limiting transients. Test idle healthy peer versus unreachable, 401/500, clock skew and stalled worker.

**F19 — MEDIUM: Invalid vector insertions emit per-item ERROR without distinguishing caller data from index failure ([#3665](https://github.com/alphaonedev/ai-memory-mcp/issues/3665)). Areas 1.

Strict dimension rejection and empty vector rejection emit ERROR at each insertion boundary. These data-validation cases share alert severity with unavailable/corrupt index failures. Capacity rejection and excessive eviction are genuinely actionable and should remain distinguished from invalid data.

Evidence: [src/hnsw.rs:950](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/hnsw.rs#L950), [src/vectorlite.rs:370](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/vectorlite.rs#L370), [src/vectorlite.rs:383](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/vectorlite.rs#L383).

**Operator impact:** Repeated malformed vector inputs can inflate infrastructure ERROR alerts and obscure actual index loss; whether input originated in a caller or embedder is not classified here.

**Fix direction / acceptance evidence:** Classify invalid-input rejection separately, preserve operator escalation for embedder dimension drift or sustained failure, and use counters/rate thresholds. Test malformed input versus backend failure and capacity exhaustion.

### 2. Structure and machine consumption

**F04 — HIGH: Default logging filter suppresses 563 explicitly targeted event sites ([#3650](https://github.com/alphaonedev/ai-memory-mcp/issues/3650)). Areas 2.

The console adds ai_memory=info. The census finds 563 explicit event sites outside that prefix, including store::postgres, federation::attestation/signing/scope, signed_events, governance, schema_guard, hnsw.eviction, encryption.undecryptable_row_skipped and logging. The complete target/count inventory accompanies the report. The unrecognized-sink warning is also emitted before installing the requested subscriber.

Evidence: [src/logging.rs:46](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L46), [src/logging.rs:129](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L129), [src/federation/mod.rs:118](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/mod.rs#L118), [src/signed_events.rs:142](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/signed_events.rs#L142), [src/store/postgres.rs:109](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/store/postgres.rs#L109), [packaging/systemd/ai-memory.service:22](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/packaging/systemd/ai-memory.service#L22).

**Operator impact:** Boot, security, replay, schema and degradation events can disappear under the shipped filter. Operators see different incident evidence across backends and sink choices.

**Fix direction / acceptance evidence:** Normalize targets beneath ai_memory, or ship a complete tested default filter. Exercise representative events from every target under the actual boot subscriber and supervisor environment; assert the pre-subscriber fallback warning is visible.

**F18 — MEDIUM: Operational event fields and levels lack a stable cross-backend schema ([#3664](https://github.com/alphaonedev/ai-memory-mcp/issues/3664)). Areas 2.

693 of 1471 event sites have no explicit named-field assignment or %-/?-field shorthand by the documented lexical heuristic. Many identity/status/error values are interpolation-only; JSON mode wraps them in message rather than making them structured. Field vocabulary varies (err/error/reason/detail, peer_id/sender). CLI direct output is outside the tracing envelope.

Evidence: [src/federation/receive.rs:23](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/receive.rs#L23), [src/federation/sync.rs:717](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/sync.rs#L717), [src/handlers/errors.rs:230](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/handlers/errors.rs#L230), [src/mcp/mod.rs:3707](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/mcp/mod.rs#L3707), [src/logging.rs:216](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L216).

**Operator impact:** Automated triage depends on prose parsing and backend-specific templates, and schema drift can silently break alerting.

**Fix direction / acceptance evidence:** Publish an event schema/version and bounded error taxonomy; use stable component, operation, outcome and peer fields. Add capture-contract tests for representative backend/transport parity. Preserve intentional human CLI output but provide explicit machine mode.

### 3. Correlation and traceability

**F17 — HIGH: Operation correlation breaks at transport, storage, federation and wake boundaries ([#3663](https://github.com/alphaonedev/ai-memory-mcp/issues/3663)). Areas 3.

MCP has tool/rpc_id span timing, HTTP has default method/URI spans, CallerContext.request_id constructors initialize None, SignedEvent has event id/sequence and optional cause_hash, federation logs memory/peer ids, and WakeMeta has inbox row id/sender/digest/host sequence. These are useful local identifiers, but no operation identifier maps/threads all boundaries. Spawned peer/blocking tasks are not uniformly instrumented with a propagated parent. Wake metadata may shed sender/namespace/digest while retaining row id/sequence.

Evidence: [src/mcp/mod.rs:3570](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/mcp/mod.rs#L3570), [src/lib.rs:1611](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/lib.rs#L1611), [src/store/mod.rs:649](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/store/mod.rs#L649), [src/signed_events.rs:517](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/signed_events.rs#L517), [src/federation/sync.rs:717](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/sync.rs#L717), [src/wake_sink/mod.rs:176](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/wake_sink/mod.rs#L176).

**Operator impact:** An operator cannot join a request to its signed write, peer apply, notification and recipient read using emitted telemetry alone. Memory id alone conflates retries and successive mutations.

**Fix direction / acceptance evidence:** Define a privacy-safe operation id and explicit links among request id, signed-event id/hash, federation attempt/peer, inbox row and recipient read. Persist/propagate an authenticated context or stable mappings across hops; avoid putting bodies or unbounded identifiers in metric labels. Test one operation across two nodes and a wake recipient.

### 5. Health monitoring

**F07 — HIGH: Request and storage metrics cannot measure write health or complete request SLOs ([#3653](https://github.com/alphaonedev/ai-memory-mcp/issues/3653)). Areas 5.

record_store and store_total have no production update callers (only tests and registration). There is no write latency histogram. HTTP recall records mode/latency on successful completion only, without error class; MCP has tool span timing but no shared exported request metrics. The registry also lacks disk/WAL growth, schema-drift, backup-success-age and read/write backend error-class families.

Evidence: [src/metrics.rs:523](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L523), [src/metrics.rs:1385](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L1385), [src/metrics.rs:1397](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L1397), [src/handlers/recall.rs:753](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/handlers/recall.rs#L753), [src/handlers/recall.rs:1186](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/handlers/recall.rs#L1186).

**Operator impact:** A zero/absent store series looks idle during actual writes or failures. Latency excludes failing recalls. Neither singleton nor fleet dashboards can calculate complete availability and tail latency from this surface.

**Fix direction / acceptance evidence:** Instrument request completion and the common storage boundary across both backends and transports, including failures/cancellations. Use bounded operation/backend/outcome/error-class labels, durations and explicit feature applicability; add freshness-aware resource and backup signals. Test real operations, not direct calls to metric helpers.

**F09 — HIGH: Doctor masks sync query failures and stale peers as unavailable or healthy ([#3655](https://github.com/alphaonedev/ai-memory-mcp/issues/3655)). Areas 5,7.

section_sync turns COUNT errors into peer_count=0, labeling the result no peers/single node. A later skew query error adds a fact but leaves severity Info. doctor_max_sync_skew_secs converts prepare failure to None, skips malformed rows/timestamps, and compares last_seen_at to last_pulled_at instead of either timestamp to now.

Evidence: [src/cli/doctor.rs:2730](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/doctor.rs#L2730), [src/cli/doctor.rs:2760](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/doctor.rs#L2760), [src/storage/doctor.rs:527](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/storage/doctor.rs#L527).

**Operator impact:** Broken sync tables or equally old seen/pulled watermarks can yield no critical result and a successful doctor exit. Automated monitors may classify an impaired fleet as a singleton or healthy mesh.

**Fix direction / acceptance evidence:** Keep unavailable, invalid and empty distinct; mark failed required probes unhealthy. Report per-peer watermark age against current time and probe freshness. Test absent/corrupt table, malformed timestamps, and peers whose two cursors are equal but old.

**F10 — HIGH: Remote doctor omits the health probe and core fleet diagnostics ([#3656](https://github.com/alphaonedev/ai-memory-mcp/issues/3656)). Areas 5,6.

run_remote requests capabilities and stats, never /health, and emits explicit NotAvailable sections for Index, Governance, Sync and Webhook. /health itself proves connection/FTS state plus cached FTS integrity, embedder object presence and federation configuration, not fleet/wake/replication readiness.

Evidence: [src/cli/doctor.rs:3471](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/doctor.rs#L3471), [src/handlers/transport.rs:1225](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/handlers/transport.rs#L1225), [docs/operations/doctor.md:6](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/operations/doctor.md#L6).

**Operator impact:** A remote doctor report can miss the daemon's own failed cached FTS verdict and cannot validate fleet convergence or governance delivery. Calling this fleet doctor does not make its omissions healthy assertions.

**Fix direction / acceptance evidence:** Consume actual health and freshness-aware component status, preserve unavailable/disabled/failed distinctions, and expose authenticated remote diagnostic facts. Test remote doctor against a live HTTP fixture with healthy stats but failed health and stale component checks.

**F11 — HIGH: Wake counters exist in memory but are not emitted by the shipped daemon/hub ([#3657](https://github.com/alphaonedev/ai-memory-mcp/issues/3657)). Areas 5,6.

install_uds returns Arc<SinkMetrics>, but boot discards it. Standalone wake-hub binds and serves without a metrics exporter/reporter; --posture intentionally prints a default metrics_schema, not live counters. Public library snapshots and tests can read hub counters; the installed operator cannot scrape these from the daemon metrics route.

Evidence: [src/wake_sink/boot.rs:125](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/wake_sink/boot.rs#L125), [src/wake_sink/uds.rs:329](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/wake_sink/uds.rs#L329), [src/wake_sink/mod.rs:292](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/wake_sink/mod.rs#L292), [src/wake_hub/metrics.rs:66](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/wake_hub/metrics.rs#L66), [src/cli/wake_hub.rs:180](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/wake_hub.rs#L180), [src/cli/wake_hub.rs:510](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/wake_hub.rs#L510).

**Operator impact:** Delivery drops, queue pressure, metadata shedding, bus lag, and wake/fanout latency cannot feed a live dashboard despite having implemented counters. Health probes prove socket response, not successful wake delivery.

**Fix direction / acceptance evidence:** Retain sink metrics in runtime state, expose hub live snapshots over an authenticated/owner-only control surface, and bridge both into stable metrics with freshness and process identity. Keep client backstop/gap/reconnect reasons distinct. Test actual scrape after overflow and hub failure.

**F16 — HIGH: Nonce-cache persistence and pressure lack an exported health contract ([#3662](https://github.com/alphaonedev/ai-memory-mcp/issues/3662)). Areas 5,7.

Persistence insert/delete failures only WARN; peer evictions have a private atomic/accessor and per-peer FIFO evictions have no emitted count. No nonce-cache family is registered in metrics, and doctor/health do not expose occupancy, eviction rate, persistence degradation or freshness.

Evidence: [src/identity/replay.rs:880](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/identity/replay.rs#L880), [src/identity/replay.rs:960](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/identity/replay.rs#L960), [src/identity/replay.rs:982](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/identity/replay.rs#L982), [src/metrics.rs:111](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L111).

**Operator impact:** An operator cannot alert before replay-window pressure or distinguish durable nonce protection from in-memory-only degradation after storage failure.

**Fix direction / acceptance evidence:** Export global/per-peer bounded occupancy, capacities, evictions, replay refusals and persistence-failure state, including last successful persistence. Classify sustained loss of restart protection as actionable and test fill/evict/storage-failure behavior.

### 6. Federated fleet

See the cross-area findings indexed below.

### 7. Silent failures

**F05 — HIGH: Logging failures can silently degrade boot and runtime delivery ([#3651](https://github.com/alphaonedev/ai-memory-mcp/issues/3651)). Areas 7,9.

main catches every init_file_logging error and continues. This includes configured syslog without the feature, despite the documented boot refusal. File/stdout use the default lossy non-blocking appender without retaining/exporting its ErrorCounter. Syslog send failures return Ok(buf.len()) and increment only a private u64. Duplicate subscriber installation is only DEBUG and reports success to its caller.

Evidence: [src/main.rs:249](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/main.rs#L249), [src/logging.rs:196](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L196), [src/logging.rs:559](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L559), [src/logging.rs:232](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L232), [docs/operations/os-tier-logging.md:173](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/operations/os-tier-logging.md#L173).

**Operator impact:** A daemon can serve normally while the selected collector receives nothing; the health monitor cannot distinguish quiet traffic from a failed log pipeline.

**Fix direction / acceptance evidence:** Honor required-sink boot failures; expose selected/active sink and delivery/queue loss counters plus last successful delivery. Rate-limit fallback diagnostics to a separate working channel and bound connect, DNS, write and flush. Test unavailable collectors, full queues, and duplicate subscriber installation.

**F12 — HIGH: Federation DLQ drops bookkeeping errors at the trait boundary ([#3658](https://github.com/alphaonedev/ai-memory-mcp/issues/3658)). Areas 7.

replay_once ignores Results from bump_dlq_attempt and note_dlq_throttled. The SqliteDlqSink and PostgresDlqSink implementations propagate their storage errors; the dyn FederationDlqSink caller discards them. The surrounding log describes the peer outcome, not failure to persist local bookkeeping; no corresponding bookkeeping-failure counter is incremented.

Evidence: [src/federation/push_dlq.rs:789](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/push_dlq.rs#L789), [src/federation/push_dlq.rs:828](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/push_dlq.rs#L828), [src/federation/push_dlq.rs:979](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/push_dlq.rs#L979), [src/federation/push_dlq.rs:997](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/push_dlq.rs#L997), [src/federation/push_dlq.rs:1016](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/federation/push_dlq.rs#L1016).

**Operator impact:** Retry budgets and last_error can remain frozen, starving newer rows or retrying indefinitely. A monitor attributes failure to the peer while the local DLQ store is broken.

**Fix direction / acceptance evidence:** Handle each bookkeeping Result with row/peer/op/error-class diagnostics and a dedicated failure counter; define replay behavior on failed persistence. Fault-inject the trait for every ignored call and cover SQLite/Postgres parity.

**F13 — HIGH: Webhook delivery audit status update errors disappear ([#3659](https://github.com/alphaonedev/ai-memory-mcp/issues/3659)). Areas 7.

update_event_status returns silently when opening its connection fails; update_event_status_with_conn discards conn.execute. Neither branch logs or counts the persistence failure. Other dispatch counters describe network delivery and cannot prove the audit status update succeeded.

Evidence: [src/subscriptions.rs:2201](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/subscriptions.rs#L2201), [src/subscriptions.rs:2210](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/subscriptions.rs#L2210).

**Operator impact:** The persisted subscription delivery history can contradict actual ACK/failure outcomes, undermining doctor success rates, replay decisions and incident reconstruction.

**Fix direction / acceptance evidence:** Return or explicitly observe persistence errors, with subscription/correlation identity and a distinct audit-update failure counter; preserve successful delivery semantics without claiming durable history. Test open and UPDATE failures independently.

### 8. Durable audit versus operational output

**F14 — HIGH: Engaged read decisions can lose durable audit evidence despite DLQ-backed wording ([#3660](https://github.com/alphaonedev/ai-memory-mcp/issues/3660)). Areas 8.

gate_read logs emit_check_event errors and proceeds with the decision. emit_check_event directly calls append_signed_event; that path starts an IMMEDIATE transaction and propagates failure, without admitting this read occurrence to the deferred spool/DLQ. The separate forensic file emission is best effort. The log comment claiming DLQ-backed recovery does not establish it on this call path.

Evidence: [src/governance/agent_action.rs:1485](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/agent_action.rs#L1485), [src/governance/agent_action.rs:1310](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/agent_action.rs#L1310), [src/signed_events.rs:2872](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/signed_events.rs#L2872).

**Operator impact:** An engaged read verdict may exist only in rotated/best-effort files and cannot be reconstructed from signed_events. Zero-rule reads intentionally emit no audit; this finding concerns evaluated decisions whose append failed.

**Fix direction / acceptance evidence:** Provide bounded durable admission or explicitly document and expose the evidence gap with counters and enterprise policy. Preserve the intentional read availability policy unless enterprise requirements select stricter behavior. Test a forced signed-event append failure and verify durable alternate residence.

**F15 — HIGH: Unverified restore evidence is confined to a best-effort forensic file ([#3661](https://github.com/alphaonedev/ai-memory-mcp/issues/3661)). Areas 8.

note_unverified_restore emits stderr and record_decision only; it does not establish a signed_events entry or durable acknowledged administrative journal. The off-database placement intentionally survives database replacement, but record_decision swallows writer failures. The JSON audit_sink flag indicates enablement, not successful persistence.

Evidence: [src/cli/backup.rs:2072](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/backup.rs#L2072), [src/governance/audit.rs:490](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/audit.rs#L490), [src/cli/backup.rs:2844](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/backup.rs#L2844).

**Operator impact:** A restore bypass can complete while evidence survives only in terminal output or a rotated file; the durable substrate record cannot prove who accepted unverified bytes.

**Fix direction / acceptance evidence:** Durably journal restore intent and outcome outside the replacement target, acknowledge persistence, and import/link evidence into the new signed-events spine without losing it during rollback. Test sink failure and database-swap outcomes.

### 9. Rotation and retention

**F06 — HIGH: File logging and forensic sinks lack an OS rotation and bounded retention contract ([#3652](https://github.com/alphaonedev/ai-memory-mcp/issues/3652)). Areas 9.

The optional operational sink rotates by time with max_files; max_size_mb is not consumed by its builder, rotation=never is allowed, and retention_days is applied by a manual archive command. Flat audit holds one append-only file handle; forensic keeps the same path handle until the daily name changes/reset. No OS-rotation inode check or SIGHUP reopen is wired for these handles. launchd docs pin stdout/stderr paths but provide no rotation/reopen arrangement. In-process locks/workers serialize their own streams; there is no shared inter-process file/chain lock for multiple CLI/daemon writers. The shipped active-curator installer explicitly generates StandardOutput=append and StandardError=append to curator.log, also without a reopen/rotation contract.

Evidence: [src/logging.rs:893](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/logging.rs#L893), [src/config.rs:7130](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/config.rs#L7130), [src/audit.rs:300](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/audit.rs#L300), [src/governance/audit.rs:203](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/governance/audit.rs#L203), [src/cli/logs.rs:388](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/cli/logs.rs#L388), [docs/operations/os-tier-logging.md:113](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/operations/os-tier-logging.md#L113), [scripts/install-batman-active.sh:283](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/scripts/install-batman-active.sh#L283).

**Operator impact:** Rename/unlink rotation can strand writes on an old inode; a single file/day can grow without a size ceiling. Multiple processes cannot rely on one coherent flat/forensic chain. The current docs overstate automatic OS ownership and unified-log capture for file paths.

**Fix direction / acceptance evidence:** Prefer supervisor-captured stderr/JSON for operational logs. Document journald retention and a real launchd collector/rotation arrangement. For any retained application file sink, define/test reopen, size/retention and multi-writer behavior; preserve signed evidence across rotation rather than copytruncate promises.

### 10. Documentation

**F20 — MEDIUM: Operator documentation lacks one complete observability and incident-tracing contract ([#3666](https://github.com/alphaonedev/ai-memory-mcp/issues/3666)). Areas 10.

Doctor, OS logging, audit coverage and troubleshooting pages exist; this is not a claim of no documentation. They do not supply one complete metric/label/scope/freshness catalog, fleet alerts and end-to-end incident tracing runbook. OS logging says enabled=false silences operational logs, while daemon console logging still runs; syslog fail-closed and rotation statements differ from boot behavior.

Evidence: [docs/operations/doctor.md:6](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/operations/doctor.md#L6), [docs/operations/os-tier-logging.md:40](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/operations/os-tier-logging.md#L40), [docs/security/audit-trail-coverage.md:64](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/docs/security/audit-trail-coverage.md#L64), [src/metrics.rs:1397](https://github.com/alphaonedev/ai-memory-mcp/blob/f0175b709cc304fffd8731669c67c16a5388e5fa/src/metrics.rs#L1397).

**Operator impact:** An AI monitor can treat absent/unavailable signals as healthy, scrape the wrong process, misinterpret HTTP-only metrics, or enable secret-bearing diagnostics during an incident.

**Fix direction / acceptance evidence:** Publish a tested observability page with singleton/fleet topology, active versus configured components, all signals and units/labels, unknown/stale semantics, threshold examples, retention/reopen policy, safe diagnostics, trace walk-through and recovery verification. Link it from installation and doctor docs.

Area cross-index: 1 → F08/F19; 2 → F04/F18; 3 → F17; 4 → F01–F03/F21; 5 → F07/F09–F11/F16; 6 → F08/F10/F11; 7 → F05/F09/F12/F13/F16; 8 → F14/F15; 9 → F05/F06; 10 → F20.

### Secret and silent-failure review boundaries

Reviewed key-bearing Debug paths: AppConfig, LlmSection, ResolvedLlm/ResolvedEmbeddings, LlmProvider and capability issuer/token implementations have explicit redaction controls. FederationConfig avoids derived Debug; PeerEndpoint and Memory remain derived-Debug data carriers, so whole-value logging is not inherently safe. SQLSTATE is retained in Postgres errors and URL passwords are scrubbed by to_store_err, but raw downstream Display text and panic payloads are not a general content-safe interface. `handlers/transport.rs:124`, `read_pool.rs:280` and `curator/mod.rs:746` format arbitrary panic detail; this review does not claim a demonstrated secret-bearing production panic. Follow-up redaction tests must cover these boundaries and dependency errors, not only named api_key fields.

The silent sweep distinguished intentionally abandoned response-body drains/channel replies and fixture cleanup from lost state. Confirmed state-loss sites are F05/F09/F12–F16. Additional log-only observation failures include recall ledger writes (`handlers/recall.rs:725,1048`, `mcp/tools/recall.rs:815`) and flat audit emission/flush (`audit.rs:576,628`); these require the per-class observability/evidence contract in F07/F13/F14. A declared counter is insufficient unless the failing branch increments an exported signal. Static lexical matches for `.ok()`, `let _ =` and defaults were treated as candidates, not automatic defects.

Level review covered all 143 ERROR sites in the census. Configuration failures, missing authority, failed transactions, corrupt schema/FTS, lost audit delivery, failed writer tasks and index capacity are operator-actionable ERROR cases; routine signature/policy/quota refusals generally use WARN or typed replies. The confirmed under-level outage is F08; F19 isolates per-vector input rejection instead of arbitrarily lowering all index errors. No blanket “all WARNs must be ERROR” recommendation is made.

## Rotation and retention contract

**Operational diagnostics should go to the supervisor-captured stderr stream (or explicitly selected JSON stdout when stdout is not MCP/data). The OS/collector owns rotation, retention and forwarding.** Journald capture does not require application SIGHUP reopen. Units should declare capture and retention expectations and test restart/flush behavior. MCP stdout must remain JSON-RPC only.

At this head the default daemon console cooperates with this stream contract, and the packaged systemd daemon uses the default journal capture. The optional file sink and flat/forensic audit files do not satisfy a general rename/reopen contract (F06). `max_files` limits file count, not bytes; `max_size_mb` is not implemented; `retention_days` needs a manual archive action. The active-curator generated unit uses append-file output. launchd StandardOutPath/StandardErrorPath are file paths, not proof of unified-log ingestion or retention. A supervisor-owned fd still needs a defined reopening/restart or collector strategy after rename.

Within one process, the console stream locks and worker queues serialize writes; flat audit locks serialize its chain/write; forensic has one writer worker. This is not a proof of lossless output: non-blocking queues can drop, write/flush can fail, process termination can truncate outstanding work, and multiple processes do not share a chain lock. No live rotation or concurrent-writer experiment was performed. F05/F06 require deterministic sink and rotation tests before claiming loss-free/non-interleaved behavior. Durable signed_events and admitted spool evidence are a separate retention domain; operational log rotation must not erase the only record of an administrative decision.

## Prioritized enterprise-federation gaps

1. **P0 — Make emitted data safe:** close F01–F03/F21 before expanding central log collection. Test mocked provider echoes, governed actions and diagnostic query logging. Publish an allowlisted schema/redaction boundary.
2. **P0 — Make observability failures observable:** fix filtering and sink startup/loss (F04–F06). Export active sink, drops and freshness; fail closed for required collection. Define OS rotation and evidence retention.
3. **P0 — Prove each configured peer is doing work:** expected membership, node identity/version, last attempt/success/accepted push, failure class/streak, convergence watermark/lag, oldest DLQ age and worker heartbeat (F08/F12/F16). Distinguish disabled, idle, partitioned, rejected and stopped. Zero traffic is not proof of health.
4. **P0 — Correct the dashboards at their source:** instrument actual write/read completion, failures and latency on both backends; expose live wake counters and preserve stale/unknown distinctions in health/doctor (F07/F09–F11). Verify idle healthy versus wedged components under fault injection.
5. **P1 — Preserve evidence and follow an operation:** durable read/restore administrative records and local DLQ/webhook bookkeeping; request → signed event → peer apply → inbox wake → recipient read linkage (F13–F15/F17).
6. **P1 — Publish actionable fleet alerts/runbooks:** component/peer-specific thresholds, scrape freshness, backend/index/schema drift, disk/WAL capacity, backup age and restore verification. Document units, labels, cardinality budgets, baseline reset behavior, privacy, and unavailable states (F18/F20).

Until those exist, an automated monitor may assist a human using selective logs, SQL diagnostics and external OS/DB monitoring; it should not be trusted to declare the fleet healthy from /health, /metrics and remote doctor alone.

## Validation and lane handoff

Branch: `fix/3645-observability-audit`, directly based on `f0175b709cc304fffd8731669c67c16a5388e5fa`. Repository changes are this report and the emission census only.

- `cargo fmt --check`: PASS (read-only formatting verification).
- `cargo clippy --all-targets -- -D warnings`: PASS.
- `cargo clippy --all-targets --features sal -- -D warnings -W clippy::pedantic`: PASS.
- `cargo clippy --all-targets --features sal-postgres -- -D warnings -W clippy::pedantic`: PASS.
- `cargo test --lib metrics::tests -- --test-threads=1`: **32 passed, 0 failed, 0 ignored**, 8,353 filtered out. The filter includes nested metrics modules; these are baseline counter/registry tests, not fixes for the findings.
- Standalone Rust tests using the exact extracted URL-redaction function: **2 passed, 0 failed** (`issue_3645_query_password_survives_current_redactor`, `issue_3645_userinfo_password_is_redacted_control`). Synthetic canaries only; the first confirms F21's defect, the second verifies the existing user-info control.
- Census validation: 1,644 source locations checked; all 21 finding issues linked. No live Postgres tests, deployed-system fault injection or rotation experiments were run.

Every Cargo command ran through the required cargo-slot wrapper with `CARGO_TARGET_DIR=/mnt/t9/v07/cargo-target-codex-3645` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only`; disk and RAM floors were checked before each run. The test build was slow under disk writeback pressure but completed successfully.

Rust standard read in full: `/home/fate_two/.claude/skills/rust-1.98/SKILL.md`. Rules applied to the review: ERRORS-01/02/06/19 (recoverable errors, propagation, production panics and discarded Results), ERRORS-15 (cause preservation), CONCURRENCY-07/11/20/23 (counters, task completion, blocking guards and cancellation), PERF-02/03/07 (checked/saturating numerics), UNSAFE-01 (safety documentation). No Rust implementation was changed; no fix-specific fail-before/pass-after tests were added because this lane explicitly requests findings, not fixes. Each child issue states the required regression evidence for its eventual fix.
