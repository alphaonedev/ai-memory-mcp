# Telemetry & Observability Policy

**Audience:** operators evaluating what `ai-memory` emits, where it goes, and what guarantees the binary makes about your data leaving the host. **Companion guide:** [`production-deployment.md`](production-deployment.md). **Threat model:** [`SECURITY.md`](../SECURITY.md).

The short version: **`ai-memory` does not phone home, does not register your deployment anywhere, and does not emit telemetry to any destination you have not explicitly configured.** Every observability surface in the binary is operator-controlled. The remaining sections enumerate exactly what is emitted and how to route it.

---

## 1. What `ai-memory` emits

The binary emits structured `tracing` spans on every meaningful operation. The categories are stable across v0.7.x:

- **MCP tool calls** — one span per JSON-RPC request. Includes the tool name, the resolved agent_id, the namespace, duration in microseconds, and the result tag (`ok`, `denied`, `error`).
- **Governance decisions** — one span per policy evaluation (hook deny, namespace inheritance refusal, attestation verification). Includes the rule that fired and the verdict.
- **Federation events** — one span per outbound push, inbound pull, signature verification, and allowlist refusal. Includes peer agent_id and message-class metadata.
- **Audit emissions** — one span per audit-trail row. Includes audit kind and the hash of the appended row (for downstream chain verification).

Span format (canonical):

```
operation_name     // e.g. "memory_store", "federation_push", "hook_pre_store"
agent_id           // resolved per the precedence ladder in CLAUDE.md §Agent Identity
namespace          // logical store namespace, never the memory content
duration_us        // wall-clock microseconds
result             // "ok" | "denied" | "error"
```

Spans do **not** contain memory content, embeddings, prompts, recall results, or any payload bytes. The substrate emits operation metadata only.

---

## 2. Operator-controlled telemetry — explicit commitment

`ai-memory` makes one binding commitment about telemetry that distinguishes it from competing memory stacks and most observability libraries:

> **No outbound network connection is initiated by the binary except to destinations the operator has explicitly configured.**

That means:

- **No phone-home on first run.** No anonymous usage ping, no install registration, no update-availability check that touches a remote server.
- **No third-party SaaS sinks compiled in.** There is no Datadog client, no Honeycomb client, no Sentry hook, and no PostHog beacon in the binary. Adding one is an operator choice via the file-logging path or a custom hook.
- **`RUST_LOG` controls verbosity, not destination.** Setting `RUST_LOG=ai_memory=debug` increases what the binary records to stderr or your configured file sink. It does not change where logs go.

If you build with default Cargo features, the only outbound network calls the binary can make are: (a) federation push/pull to peers on your mTLS allowlist, (b) embedder fetches from HuggingFace if you have explicitly enabled the smart tier, and (c) LLM completions to your configured Ollama endpoint if you have enabled the autonomous tier. All three are off by default and named in the verbose `ai-memory doctor` report.

---

## 3. Sinks — where spans go

Three surfaces ship in v0.7.0 (stderr, rolling file, Prometheus `/metrics`), plus a forward-looking OTLP commitment; you choose any combination:

**stdout/stderr (default).** Spans render to stderr via `tracing-subscriber::fmt`. Suitable for systemd journals (`journalctl -u ai-memory`), Docker log drivers, and pipeline ingestion (`ai-memory serve 2>&1 | vector --config ...`).

**Rolling file appender.** Opt-in via `[logging]` in `config.toml`:

```toml
[logging]
enabled = true
path = "~/.local/state/ai-memory/logs/"
max_size_mb = 100
max_files = 30
retention_days = 90
structured = true     # JSON output for SIEM ingestion
level = "info"        # tracing::EnvFilter syntax
```

The appender writes rotated files (`ai-memory.log.YYYY-MM-DD`) under the resolved path. Path precedence: CLI flag `--log-dir` > `AI_MEMORY_LOG_DIR` env > `[logging] path` config > platform default. The substrate refuses world-writable log directories — set `chmod 750` on the parent. Shipped in v0.7.0 at 98.98% test coverage; see `src/logging.rs` and the SIEM ingestion runbook at [`security/audit-trail.md`](security/audit-trail.md).

**OpenTelemetry OTLP exporter (forward-looking).** The substrate's span shape is intentionally OTel-compatible. An OTLP exporter that reads `OTEL_EXPORTER_OTLP_ENDPOINT` (and the standard `OTEL_*` companion variables) is a v1.0 commitment — see ROADMAP §7.6. Until then, the file-sink path with `structured = true` produces JSON that any OTel-aware collector can ingest as a log-receiver input.

**Prometheus `/metrics` (HTTP daemon, pull-based).** The `serve` daemon additionally exposes a Prometheus scrape surface at the bare `/metrics` path (alias `/api/v1/metrics`; `src/metrics.rs`). It is pull-only — nothing is pushed anywhere. The registered series at v0.7.0 include the core counters/gauges `ai_memory_store_total`, `ai_memory_recall_total`, `ai_memory_recall_latency_seconds`, `ai_memory_memories`, the HNSW gauges (`ai_memory_hnsw_size`, `ai_memory_hnsw_evictions_total`, `ai_memory_hnsw_last_eviction_at_nanos`), the webhook/subscription series (`ai_memory_webhook_dispatched_total`, `ai_memory_webhook_failed_total`, `ai_memory_subscriptions_active`, `ai_memory_subscription_dlq_overflow_total`), the curator series (`ai_memory_curator_cycles_total`, `ai_memory_curator_cycle_duration_seconds`, `ai_memory_curator_operations_total`), the autonomy/quality series (`ai_memory_autonomy_hook_total`, `ai_memory_contradiction_detected_total`, `ai_memory_corrupt_provenance_rows_total`, `ai_memory_auto_export_spawn_failed_total`), and the federation series (`ai_memory_federation_push_dlq_depth`, `ai_memory_federation_push_dlq_quarantined_total`, `ai_memory_federation_fanout_retry_total`, `ai_memory_federation_fanout_dropped_total`, `ai_memory_federation_partial_quorum_total`, `ai_memory_federation_cred_verify_total`, `ai_memory_federation_inbound_cred_total`, `ai_memory_federation_cred_max_age_seconds`, `ai_memory_federation_renewal_lag_seconds`). Metric values are operation counts and durations only — never memory content.

---

## 4. Privacy-preserving design

Three substrate behaviors give operators a defensible privacy posture without changing the deployment topology:

**`AI_MEMORY_ANONYMIZE=1`.** When set (or `[identity] anonymize_default = true` in `config.toml`), the binary replaces the resolved `agent_id` in every emitted span with a stable anonymized hash. The original id is still recorded inside the database for the operator's own audit needs; only externally-visible spans carry the redacted form. Shipped via issue #198 closure.

**Memory content is never in spans.** This is structural, not policy: the `tracing::info!` call sites never receive `content`, `title`, or `metadata` payloads. Adding a span macro that violated this would fail code review against [`docs/AI_DEVELOPER_GOVERNANCE.md`](AI_DEVELOPER_GOVERNANCE.md) §Hard Prohibitions. Operators can audit this themselves: `grep -rn "tracing::\(info\|warn\|error\)" src/` against the field set of `models::Memory`.

**Agent-id resolution is local.** The precedence ladder (CLI flag > env > MCP `clientInfo` > `host:<hostname>:pid-…`) is resolved entirely in-process. There is no central agent registry to consult. If the resolved id contains a hostname or PID you do not want surfaced (the default fallback `host:<hostname>:pid-…` does both), set `AI_MEMORY_AGENT_ID` to an opaque value. Tracking history: issue #198.

---

## 5. The `doctor` command — local-only health

`ai-memory doctor` returns a nine-section health dashboard
(pinned by `local_run_on_empty_db_produces_nine_sections` in
`src/cli/doctor.rs`):

1. Storage (DB integrity, schema version, retention drift)
2. Index (vector index / embedder state)
3. Recall (pipeline health)
4. Governance (rule corpus, pending actions)
5. Sync (federation state)
6. Webhook (subscription health)
7. Capabilities (advertised surface)
8. Reflection Health (L1-4)
9. LLM Reachability (#1146)

Eight of the nine sections are computed locally against the SQLite
or PostgreSQL store with no network access. The exception is the
**LLM Reachability** section (#1146), which probes the *resolved,
operator-configured* LLM endpoint (`<base_url>/api/tags` for Ollama
or `<base_url>/models` for OpenAI-compatible backends) — still only
a destination you configured, never a third party. It is safe to run
from a paging-on-health-check loop or a Nagios-style monitoring
probe.

---

## 6. v1.0 OpenTelemetry standardization — forward-looking commitment

Per ROADMAP §7.6, every internal tracing span converts to canonical OTel spans at v1.0:

- Span attributes match the OTel semantic conventions where they exist (`code.namespace`, `code.function`, `db.system`, etc.).
- An OTLP exporter ships in-tree, with the standard env-var configuration surface (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`).
- Backwards compatibility: the rolling-file sink continues to ship and remains operator-toggleable; OTel becomes one more sink, not a replacement for the file path.

Operators who want to forward-compatibly capture spans today can run the file sink in `structured = true` mode and route the JSON through `vector` or `fluent-bit` to their OTel collector. The output schema will gain canonical attributes at v1.0; field renaming is the only churn.

---

## See also

- [`production-deployment.md`](production-deployment.md) — operator deployment guide (Section 6 cross-references this doc)
- [`SECURITY.md`](../SECURITY.md) — threat model and disclosure policy
- [`security/audit-trail.md`](security/audit-trail.md) — SIEM ingestion runbook for the file sink
- `src/logging.rs` — implementation of the rotating file appender (98.98% test coverage)
- ROADMAP §7.6 — v1.0 OTel standardization commitment
