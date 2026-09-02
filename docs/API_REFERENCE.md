---
layout: doc
---
# ai-memory HTTP API Reference

Complete reference for every endpoint the `ai-memory serve` daemon
exposes. All endpoints are prefixed with `/api/v1/` unless noted.

## Base URL

Default: `http://127.0.0.1:9077`.

Configure via `ai-memory serve --host <host> --port <port>`. Production
deployments should always bind TLS: `--tls-cert` + `--tls-key`.

## Authentication

### API key

When an `api_key` is configured (the top-level `api_key = "…"` field in
`config.toml`, or injected via `AI_MEMORY_API_KEY` by the Plan-C
container entrypoint — there is **no** `--api-key` CLI flag on `serve`),
every endpoint except `/api/v1/health` requires the header:

```
x-api-key: <key>
```

The header is the **only** credential channel.

Failure → **401** `{"error": "missing or invalid API key"}`.

> **BREAKING CHANGE at v1.0.0 — `?api_key=` query credential REMOVED**
> ([#2032](https://github.com/alphaonedev/ai-memory-mcp/issues/2032) L1;
> deprecated since v0.7.0 by
> [#1574](https://github.com/alphaonedev/ai-memory-mcp/issues/1574)).
>
> `GET /api/v1/memories?api_key=<key>` used to authenticate. It no longer
> does: `api_key_auth` reads the credential from the `x-api-key` header
> and nothing else (`src/handlers/transport.rs`), so a caller still
> putting the key in the query string gets **401
> `{"error": "missing or invalid API key"}`** — the same body a caller
> with no credential at all gets.
>
> **Migration.** Move the credential from the query string to the header:
>
> ```bash
> # before (v0.7.0 – v0.10.0) — now 401
> curl "http://127.0.0.1:9077/api/v1/memories?api_key=$KEY"
> # after (v1.0.0)
> curl -H "x-api-key: $KEY" http://127.0.0.1:9077/api/v1/memories
> ```
>
> **Diagnosing it.** The daemon emits a once-per-process WARN under the
> `http::auth` target when any request arrives carrying an `api_key=`
> query parameter, naming the header alternative. The per-request
> response is still a bare 401 — the WARN is in the daemon log, not on
> the wire. Grep for it before assuming a key-rotation problem.
>
> **Why.** URL-embedded credentials leak into access logs, `Referer`
> headers, and proxy logs (OWASP A07/A09). Every caller on the removed
> path is a credential already written to disk somewhere; rotate the key
> after migrating.

When mTLS fingerprint pinning is enforced (`--mtls-allowlist`), the
`/api/v1/sync/*` federation paths bypass the api-key check — the mTLS
handshake plus the `X-Memory-Sig` signed-message gate (#791/#1031) are
the stronger authentication step there.

`AI_MEMORY_REQUIRE_API_KEY=1` hard-refuses a keyless daemon start on
ANY bind host, including loopback (#1458).

### Agent identity — `X-Agent-Id`

Optional on writes. Identifies the caller for governance + attribution.

```
X-Agent-Id: ai:claude-opus-4.7@host.local
X-Agent-Id: alice
X-Agent-Id: host:prod-web-01:pid-12345-a1b2c3d4
```

Resolution (v0.7.0, header-first — the pre-v0.7.0 body-wins precedence
was the #874-class spoof vector):

1. The `X-Agent-Id` header is the **authoritative** identity slot.
2. A body `agent_id` field (or `?agent_id=` query param where
   accepted) is a *refinement* that MUST match the header-resolved id;
   a mismatch is rejected with **403**
   (`agent_id_body_header_mismatch` / `agent_id_query_header_mismatch`).
3. With no header and no body claim, a per-request anonymous id
   (`anonymous:req-<uuid8>`) is synthesized and logged at WARN.

Validation pattern: `^[A-Za-z0-9_\-:@./]{1,128}$`.

### Admin-gated endpoints (v0.7.0 #943/#945/#946 cluster)

Corpus-scale endpoints require an **admin** caller: `GET /stats`,
`POST /gc`, `GET /export`, `POST /import`, `GET /agents`,
`POST /forget`, `GET /namespaces` (list form), `GET /taxonomy`,
`GET /archive`, `GET /archive/stats`, the seven `/skill/*` routes, and
`PUT /agents/{id}/pubkey` (#1539 — bind an agent's Ed25519 attestation
public key: body `{"pubkey_b64": "<base64 32-byte key>"}`, response
`{"bound": true, "agent_id": "..."}`; the pubkey is validated as a real
curve point and the agent must already be registered. Gives attesting
clients a first-party enrollment surface instead of an out-of-band DB
write — store-path attestation is required by default on the HTTP direct-write surface only since v1.0.0 (#1985, correcting #1751; MCP/CLI stay permissive)
(#1751; opt out with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`)).
The admin allowlist is `[admin] agent_ids = [...]` in `config.toml`
(plus `AI_MEMORY_ADMIN_AGENT_IDS`); when empty (the default) these
endpoints return **403** to every caller. Per
[#1570](https://github.com/alphaonedev/ai-memory-mcp/issues/1570), on a
deployment with **no `api_key` configured**, a bare self-asserted
`X-Agent-Id` naming an admin id is NOT trusted for admin-role
resolution (boot emits a WARN); set `AI_MEMORY_ADMIN_HEADER_TRUST=1`
only to restore the legacy header-trust posture on isolated/mTLS-fronted
deployments.

### mTLS (Layer 2 peer mesh)

When `--mtls-allowlist` is set, every TCP connection must present a
client certificate whose SHA-256 fingerprint appears (hex, optional
`:` separators, `#` comments) on the allowlist file. Peers without a
listed cert cannot even open the TCP connection.

See `docs/ADMIN_GUIDE.md` § "Peer-mesh security" for setup.

## Response envelopes

### Compression (v0.7.0, #1579 B4)

The daemon gzip-compresses responses when the request advertises
`Accept-Encoding: gzip` (standard `tower-http` CompressionLayer;
measured ~4.6× smaller recall payloads). Requests without the header
receive identity-coded responses, byte-identical to earlier releases.
The SSE surface (`GET /api/v1/approvals/stream`) is never compressed —
`text/event-stream` is exempted so events flush immediately.

### Success (2xx)

JSON body, shape depends on endpoint. Common patterns:

```json
{ "memory": { … } }
{ "memories": [ … ], "count": 5 }
{ "id": "abc123" }
{ "ok": true }
```

### Error (4xx, 5xx)

Uniform envelope:

```json
{ "error": "descriptive message" }
```

Status codes you'll commonly encounter:

| Code | Meaning |
|------|---------|
| 200 | OK |
| 201 | Created |
| 202 | Accepted — governance pending |
| 400 | Bad request — validation, parse, or limit error |
| 401 | Unauthorized — missing / invalid API key |
| 403 | Forbidden — governance denied |
| 404 | Not found |
| 409 | Conflict — duplicate `(title, namespace)`, or stale `If-Match` |
| 429 | Per-agent write quota exhausted — see below |
| 500 | Internal server error |
| 503 | Service unavailable — admission-control shed, or `/health` reporting unhealthy |

### 429 — per-agent write quotas

**429 is a real response code on the primary write surfaces.** It is
returned when the calling agent's per-agent quota row (daily memories,
storage bytes, or daily links — see Limits below) is exhausted. Body:

```json
{ "code": "QUOTA_EXCEEDED", "error": "…", "limit": "memories_per_day",
  "current": 1000, "max": 1000, "agent_id": "alice" }
```

Emitting surfaces, verified in the daemon:

| Surface | Site |
|---|---|
| `POST /api/v1/memories` | `src/handlers/create.rs` |
| `PUT /api/v1/memories/{id}` (storage-byte growth on update) | `src/handlers/memories.rs` |
| `POST /api/v1/links` | `src/handlers/links.rs` |
| `POST /api/v1/consolidate` | `src/handlers/power_consolidation.rs` |
| `POST /api/v1/signals` | `src/handlers/coordination.rs` |
| `POST /api/v1/sync/push` (federation receive) | `src/handlers/federation_receive.rs`, `federation_signing_check.rs` |
| any Postgres-backed route surfacing `StoreError::QuotaExceeded` | `src/handlers/postgres_gate.rs` |

The federation-receive 429 additionally carries `x-quota-reset-at` (UTC
midnight) and `x-quota-limit` headers.

**`POST /api/v1/memories/bulk` does NOT return 429.** A quota-rejected row
in a bulk batch is folded into the response `errors[]` array and the batch
still answers 200 — see the bulk section below.

Read paths (`GET /recall`, `/search`, `/memories`, …) are not quota-charged
and never return 429.

## Limits

- Bulk / list / sync page-size cap: **1000 items by default**
  (`/memories/bulk`, `/sync/push`, and the per-page cap on list
  responses). **Operator-tunable** (#1156 follow-up) via the
  `[limits].max_page_size` config field or the `AI_MEMORY_MAX_PAGE_SIZE`
  env var (precedence: env > config > compiled default `1000`). The cap
  bounds per-request in-memory materialization to guard against OOM
  under an unbounded `limit=`. `/import` is capped at the **compiled**
  `MAX_BULK_SIZE` (1000), independent of `max_page_size`.
- Request body size: **2 MiB** (`HTTP_BODY_LIMIT_BYTES` in `src/lib.rs`).
- Recall: capped at **50** per request.
- Sync/since: capped at **10,000** per request.
- Per-agent write quotas (daily memories, storage bytes, daily links)
  are **operator-tunable** via `[limits].max_memories_per_day` /
  `max_storage_bytes` / `max_links_per_day` (or the matching
  `AI_MEMORY_MAX_*` env vars). Defaults: 1000 memories/day, 100 MiB,
  5000 links/day. See [`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.html).
- **Per-agent write quotas are enforced and return 429** (see the 429
  section above): daily memories, storage bytes, and daily links, charged
  per authenticated agent. There is no requests-per-second throttle; the
  quotas are daily counters plus a storage ceiling, not a rate limiter.
- **A global in-flight concurrency cap is enforced by default and returns
  503** (see Admission control below). It is global, not per-client.
- All writes contend for a single `Mutex<Connection>` on the SQLite
  backend. Batch or throttle at the caller.

### Admission control — overload shedding (#1733 Pillar-4 4.A; default-on since #2032 M3)

**Admission control is ON by default.** The daemon admits at most `n`
concurrent in-flight requests and **sheds** the rest at the outermost
layer — before the timeout future, body decode, or any handler work.

`n` resolves as a **tri-state** (`[limits].max_inflight_requests` /
`AI_MEMORY_MAX_INFLIGHT_REQUESTS`; env > config > compiled default):

| Value | Effective cap |
|---|---|
| **unset** (the default) | `clamp(available_parallelism × 64, 256, 4096)` — CPU-scaled, so 256 on a small node and up to 4096 on a large one |
| positive `n` | exactly `n` |
| **explicit `0`** | **disabled** — no admission layer is composed |

Only an *explicit* `0` disables it. Unset resolves to the CPU-scaled
default (`config::resolve_default_max_inflight_requests`), so a single
authenticated caller cannot saturate the daemon's one
`Arc<Mutex<Connection>>` for a denial of service. This is the safer
posture and it is the one you get with no configuration.

A shed request answers **503** with `Retry-After: 1`:

```json
{ "error": "server_overloaded", "code": "OVERLOADED", "max_inflight": 512 }
```

`GET /api/v1/health`, `GET /api/v1/metrics`, and the bare `GET /metrics`
are **EXEMPT** from the cap so liveness/readiness probes and Prometheus
scrapes survive an overload (otherwise the orchestrator's health probe
would be shed, the node killed, and graceful shedding would become a
crash-loop). Shed events increment the `ai_memory_admission_shed_total`
Prometheus counter and emit a sampled WARN.

**Sizing note.** A client that holds many long-lived concurrent requests
(streaming, slow embedding round-trips) consumes permits for their whole
duration. If you see 503/`OVERLOADED` under a load you consider normal,
raise the cap explicitly rather than setting `0` — `0` removes the DoS
floor for every caller.

## The `Memory` object

```json
{
  "id": "uuid-v4",
  "tier": "mid",
  "namespace": "global",
  "title": "Memory title",
  "content": "Memory body",
  "tags": ["tag1", "tag2"],
  "priority": 5,
  "confidence": 0.95,
  "source": "api",
  "access_count": 3,
  "created_at": "2026-04-19T10:30:00Z",
  "updated_at": "2026-04-19T10:30:00Z",
  "last_accessed_at": "2026-04-19T12:00:00Z",
  "expires_at": "2026-04-26T10:30:00Z",
  "metadata": {
    "agent_id": "ai:claude-opus-4.7",
    "scope": "private",
    "custom_field": "value"
  }
}
```

`tier` is one of `"short"` | `"mid"` | `"long"` (see `Tier` enum in
`src/models/memory.rs`). `last_accessed_at` and `expires_at` are omitted
from the JSON when not set — they are NOT serialized as `null`.

Fields marked in `metadata` are preserved across update / upsert /
sync / consolidate.

---

## Health + metrics

### `GET /api/v1/health`

No authentication required — this endpoint is exempt from the api-key
middleware (`src/handlers/transport.rs::api_key_auth`) and from admission
control, so probes survive an overload. It reads **no request headers**;
`X-Agent-Id`, `X-Peer-Id` and mTLS peer identity are not consulted, so a
200 here proves transport reachability only, never authentication.

**Status codes**

| Code | When |
|---|---|
| **200** | connection answers SQL, FTS5 index is reachable, and the cached FTS5 integrity verdict is not `failed` |
| **503** | the DB connection or the FTS5 reachability probe errored, **or** the cached FTS5 integrity verdict is `failed` |

That is the whole failure contract (`health_status_code`,
`src/handlers/transport.rs`). Write your orchestrator probe against it:
the endpoint **does** take the node out of rotation, so a probe that only
checks for HTTP reachability will mask a corrupted FTS5 index.

**Response body (200 and 503 alike)**

```json
{
  "status": "ok",
  "service": "ai-memory",
  "version": "1.0.0",
  "embedder_ready": true,
  "federation_enabled": false,
  "checks": {
    "connection": "ok",
    "fts_index": "reachable"
  },
  "fts_integrity": {
    "status": "ok",
    "checked_at": "2026-07-30T04:11:22+00:00",
    "interval_secs": 21600
  }
}
```

| Field | Meaning |
|---|---|
| `status` | `"ok"` on 200, `"error"` on 503 |
| `version` | the daemon's package version |
| `embedder_ready` | an embedder is wired on this node (semantic recall available) |
| `federation_enabled` | federation is configured on this node |
| `checks.connection` | `"ok"` \| `"error"` — the SQL liveness ping |
| `checks.fts_index` | `"reachable"` \| `"error"` \| `"not_applicable"` (Postgres backend) — a bounded MATCH proving the FTS5 module is registered and its shadow tables are readable. **REACHABLE, not VERIFIED.** |
| `fts_integrity.status` | the deep verdict — see below |
| `fts_integrity.checked_at` | RFC3339 instant the verdict was produced, or `null` if none has completed |
| `fts_integrity.interval_secs` | the configured check cadence |

**The FTS5 integrity verdict is CACHED, not per-request** (#2579). The
full FTS5 `'integrity-check'` re-tokenizes the whole corpus and is
prepared by SQLite as a writer, so running it per probe held the WAL
write lock and blew past a Kubernetes default `timeoutSeconds: 1` on
exactly the largest corpora. It now runs on its own connection on a
background cadence — default **21600 s (6 h)**, tunable via
`AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS`; `0` disables it. The first pass
fires at a random offset within 5 minutes of boot and each subsequent
pass carries ±20% jitter, so a fleet restart does not check in lockstep.

| `fts_integrity.status` | Meaning | Effect on the HTTP code |
|---|---|---|
| `ok` | a check completed clean within the freshness window | 200 |
| `pending` | no check has completed yet on this process | 200 |
| `stale` | the last `ok` is older than 3 intervals — the checker stopped running | 200 |
| `disabled` | `AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS=0` | 200 |
| `failed` | a check returned `SQLITE_CORRUPT` / `SQLITE_CORRUPT_VTAB` | **503** |

Only a confirmed corruption takes the node out of rotation. `pending` /
`stale` / `disabled` are *no assertion*, not *failed assertion* —
503-ing on those would deadlock a rolling restart across a fleet.
Correspondingly, **a 200 does not mean the index was just verified**: it
can be up to `interval_secs` old, or never checked at all. Alert on
`fts_integrity.status` being `stale` or `disabled` separately from the
HTTP code, and use `ai-memory doctor` to run the deep check on demand.

An operational error such as `SQLITE_BUSY` retains the previous verdict
rather than recording a failure, so the cadence introduces no false-503
class.

**A `failed` verdict is DURABLE across restart (v1.0.0,
[#2630](https://github.com/alphaonedev/ai-memory-mcp/issues/2630)).** `/health`
is scraped as a liveness probe, and an orchestrator answers a failing liveness
probe by RESTARTING the container — which used to clear the verdict, because it
lived only in process memory: the new process started `pending`, answered `200`,
and served keyword recall over a corrupt index for the whole startup-spread
window before the next check re-failed it, every restart. A completed verdict is
now recorded beside the database as `<db-path>.fts-verdict` and adopted at boot,
so a failure survives the restart until a fresh check clears it. Notes for
operators:

- **Only a failure is recorded.** A passing check REMOVES the file; a clean boot
  still starts `pending`. A pass a *previous* process performed is never
  re-presented as this process's assertion.
- **A node that boots with an adopted failure skips the startup spread** and
  re-checks immediately, so a real repair (`INSERT INTO
  memories_fts(memories_fts) VALUES('rebuild')`) is re-verified in seconds
  rather than after a full jittered interval — restart is now the fast
  *re-verification* lever instead of the fast *reset* lever. Only already-failed
  nodes skip the spread, so fleet desynchronisation is unchanged.
- **A file that exists but cannot be read or parsed reads as a FAILURE** (fail
  closed). It is self-healing: the first passing check clears it.
- **With the checker disabled (`…INTERVAL_SECS=0`) the record is NOT adopted** —
  nothing would ever run to clear it, so adopting would fence the node at 503
  with no in-band way back. The file is kept, and its presence is announced at
  WARN; re-enable the cadence to have it adopted and re-verified.
- The file is sqlite-only and sits beside the database, so it travels with the
  same volume and backup as the corpus it describes. It holds no memory content
  — one line: a format tag, `failed`, and a UNIX timestamp.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9077/api/v1/health
curl -sS http://127.0.0.1:9077/api/v1/health | jq .fts_integrity
```

### `GET /metrics` and `GET /api/v1/metrics`

Prometheus text exposition format. Scrape from Prometheus, alertmanager,
or Grafana Agent.

```bash
curl http://127.0.0.1:9077/metrics
```

Both paths are **exempt from admission control** (#1733 / #2032 M3) so
Prometheus keeps scraping under overload. Since #2583 the steady-state
scrape does **no database work** — every value is pre-computed by
background refreshers — so its cost is independent of corpus size and of
scrape rate. The one exception is a cold prime: a process whose gauge
refresher has never run (a router built without the daemon loop, or
`AI_MEMORY_METRICS_GAUGE_REFRESH_SECS=0`) pays a single `COUNT` on its
FIRST scrape, rather than serving a `0` that is indistinguishable from an
empty corpus.

Series an operator should wire alerts to (canonical registration:
`src/metrics.rs`):

| Series | Type | Meaning |
|---|---|---|
| `ai_memory_memories` | gauge | Corpus size. Refreshed on a paced loop (`AI_MEMORY_METRICS_GAUGE_REFRESH_SECS`, default `60`; `0` disables the loop), not per scrape. |
| `ai_memory_memories_refreshed_at_seconds` | gauge | UNIX seconds at which the gauge above was last recomputed; `0` = never. **Not optional — alert on `time() - ai_memory_memories_refreshed_at_seconds`.** Without it a dead refresher would freeze a plausible-looking count forever, including through a mass deletion, while Prometheus `up` stayed `1`. |
| `ai_memory_admission_shed_total` | counter | Requests shed by admission control with a typed `503`. |
| `ai_memory_recall_embed_degraded_total` | counter | Recalls that exceeded `AI_MEMORY_RECALL_EMBED_BUDGET_MS` and degraded to keyword (#2577). |
| `ai_memory_rerank_budget_degraded_total` | counter | Recalls whose cross-encoder stage was skipped pre-flight under `AI_MEMORY_RERANK_BUDGET_MS`, shipping the hybrid ordering (#2608). |
| `ai_memory_query_embed_cache_hits_total` | counter | Query-embedding cache hits (#2577). |
| `ai_memory_corrupt_provenance_rows_total{column}` | counter | Rows skipped by a discovery scan because a provenance column would not open (e.g. `encrypted_envelope`, #2383). |
| `ai_memory_fed_quarantined_unattributed_total` | counter | Inbound relayed memories quarantined by the route-IN provenance gate (`AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`, #2966). Always zero when the quarantine knob is off (the default); a non-zero rate means a peer is relaying provenance-less content this node is black-holing until dequarantine. Pairs with the `federation.quarantine.unattributed` WARN. |
| `ai_memory_operator_dequarantined_total` | counter | The route-OUT twin (#2402): quarantined memories released by an OPERATOR through `ai-memory quarantine release` or `POST /api/v1/admin/quarantine/{id}/release`. Each increment also appends a `memory.dequarantined` signed-chain row naming the authenticated caller, in the same transaction as the state change; a no-op release does not increment. Pairs with the `quarantine.operator_release` WARN. |
| `ai_memory_hnsw_evictions_total`, `ai_memory_hnsw_size` | counter, gauge | Vector-index pressure; see `AI_MEMORY_VECTOR_INDEX_CAPACITY`. |
| `ai_memory_federation_push_dlq_depth`, `..._quarantined_by_cause_total{cause}` | gauge, counter | Federation push-DLQ backlog and its cause breakdown. |
| `ai_memory_deferred_audit_drainer_terminal_state` | gauge | Terminal state of the deferred-audit drainer supervisor: `0` = running/graceful, `1` = sink unresolved past `max_restarts`, `2` = sink panicked past `max_restarts` (#3164). **Page on any non-zero value** — the daemon keeps serving requests, but governance refusals are no longer reaching `signed_events` on that node, so it is audit-degraded until restarted. |

This table is the operationally load-bearing subset, not the full
registry — scrape the endpoint for the complete list.

`GET /api/v1/health` additionally reports a cached
`fts_integrity: {status, checked_at, interval_secs}` verdict. The FTS5
integrity check re-tokenizes the whole corpus and is prepared by SQLite
as a WRITER, so since #2579 it runs on its own paced background
connection (`AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS`, default 6 h, `0` =
`disabled`) rather than on every probe. A cached `failed` still answers
**503**; an `ok` verdict older than three intervals degrades itself to
`stale` so a dead checker cannot re-present its last pass; `pending`
means no check has completed yet. `ai-memory doctor` runs the same deep
check on demand.

### `GET /api/v1/stats`

Structured database stats (counts by tier/namespace, links, size,
last GC). **Admin-gated** (#946 cluster). SQLite and PostgreSQL both emit
`by_tier` and `by_namespace` as the documented lists below.

```json
{
  "total_memories": 150,
  "by_tier": [{"tier":"short","count":20},{"tier":"mid","count":100},{"tier":"long","count":30}],
  "by_namespace": [{"namespace":"global","count":90}],
  "expiring_soon": 5,
  "links_count": 23,
  "db_size_bytes": 524288,
  "live": 145,
  "expired_pending_gc": 5,
  "storage_backend": "sqlite"
}
```

## Memory CRUD

### `POST /api/v1/memories` — create

```json
{
  "title": "Quick note",
  "content": "Content",
  "tier": "mid",
  "namespace": "global",
  "tags": ["urgent"],
  "priority": 7,
  "confidence": 0.9,
  "source": "api",
  "ttl_secs": 604800,
  "expires_at": "2026-05-08T10:30:00Z",
  "metadata": {"custom": "data"},
  "agent_id": "alice",
  "scope": "private",
  "signature": "base64-std-detached-ed25519-sig",
  "created_at": "2026-05-08T10:30:00Z"
}
```

`ttl_secs` is HTTP-only — the MCP `memory_store` tool exposes
`expires_at` instead (also accepted on this HTTP endpoint). See the
HTTP ↔ MCP parameter coverage table at the bottom of this document.

An optional `kind` field is also accepted. Omitting it keeps the
`observation` default; a supplied value MUST be one of the canonical
variants (`observation`, `reflection`, `persona`, `concept`, `entity`,
`claim`, `relation`, `event`, `conversation`, `decision`) or the request
is rejected with **400** (#1467 — this endpoint previously coerced an
unknown `kind` to `observation`; it now rejects to match the CLI and MCP
surfaces). See `docs/memory-kind-vocab.md`.

#### Agent attestation (`signature` + `created_at`) — #626 Layer-3

A caller MAY present a detached Ed25519 `signature` to upgrade the write
from a **claimed** `agent_id` to a cryptographically **attested** one.
The signature is computed over the canonical `SignableWrite` envelope
(`agent_id` + `namespace` + `title` + `kind` + `created_at` +
`sha256(content)`) and encoded as **standard base64**. When `signature`
is present, `created_at` (RFC 3339) is **required** — it is the exact
timestamp that was signed.

- The daemon verifies the signature against the agent's bound public key
  (registered via `memory_agent_register` + bind-key). On success it
  stamps `metadata.attest_level = "agent_attested"` and **adopts the
  signed `created_at` verbatim**.
- A `signature` whose `created_at` is outside a **±300 s** freshness
  window is rejected.
- As of v0.9.0 ([#1751](https://github.com/alphaonedev/ai-memory-mcp/issues/1751)), an unsigned write is **rejected** by default
  (`403 ATTESTATION_FAILED`) rather than landing `metadata.attest_level =
  "claimed"`. Only with the explicit opt-out
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` (or `=false`) does an unsigned
  write land `claimed`; any other value falls through to the required
  default. This flag governs only the unsigned-write disposition; a
  presented signature is always verified regardless.

This wire is identical across the three store surfaces (MCP
`memory_store`, this HTTP endpoint, and the CLI `--sign` path).

- **201 Created** with `{ "id": "...", "tier": "mid", "namespace": "...", "title": "...", "agent_id": "..." }`.
- **202 Accepted** (governance pending) with `{ "status": "pending", "pending_id": "...", "action": "store" }`.
- **400** when `signature` is present but `created_at` is missing or not RFC 3339.
- **403** with `{ "code": "ATTESTATION_FAILED" }` when a signature fails verification, or when an unsigned write is rejected under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`.
- **400 / 403 / 500** per validation / governance / server error.

```bash
curl -X POST http://127.0.0.1:9077/api/v1/memories \
  -H "X-API-Key: KEY" -H "X-Agent-Id: alice" \
  -H "Content-Type: application/json" \
  -d '{"title":"Meeting notes","content":"Q2 roadmap","tier":"mid"}'
```

### `GET /api/v1/memories` — list

Query params: `namespace`, `tier`, `limit` (default 20, capped at
`max_page_size` — compiled default 1000), `offset`, `min_priority`,
`since`, `until`, `tags` (comma list), `agent_id`.

```json
{ "memories": [ … ], "count": 1 }
```

### `GET /api/v1/memories/{id}` — get

UUID or unique prefix. Returns memory + its links.

```json
{
  "memory": { … },
  "links": [{"source_id":"…","target_id":"…","relation":"related_to","created_at":"…"}]
}
```

### `PUT /api/v1/memories/{id}` — update

All fields optional. Tier never downgrades.

```json
{ "title": "New", "priority": 8, "tier": "long" }
```

- **200** on success, **409** on `(title, namespace)` collision, **404** on missing.

### `DELETE /api/v1/memories/{id}` — delete

Archives before delete when `archive_on_gc=true`.

- **200 OK** `{"deleted": true}` or **202** when governance is pending.

### `POST /api/v1/memories/bulk` — batch create

Body is a JSON array of `CreateMemory` objects, **≤ `max_page_size`**
items (compiled default **1000**; operator-tunable via
`[limits].max_page_size` / `AI_MEMORY_MAX_PAGE_SIZE`). Exceeding the cap
returns **400 Bad Request** with an error echoing the configured cap.

The response is a truthful per-row ledger (#2550/#2551/#2552/#2588/#2594):

```json
{
  "sent": 1000, "created": 996, "updated": 1, "deduped": 1, "rejected": 2,
  "errors": [
    { "index": 17, "code": "VALIDATION_FAILED", "field": "create",
      "error": "validation failed" },
    { "index": 402, "code": "QUOTA_EXCEEDED", "field": "quota",
      "error": "quota exceeded" }
  ],
  "deduped_rows": [ { "index": 88, "superseded_by": 401 } ],
  "pending": [],
  "warnings": []
}
```

`created + updated + deduped + rejected + pending.length === sent` is a
reconciliation identity a loader can assert on every batch.

| field | meaning |
|---|---|
| `created` | rows this call INSERTED |
| `updated` | rows it upserted onto an existing `(title, namespace)` |
| `deduped` | input rows whose content was superseded by a LATER row in the SAME batch — the row is NOT what you sent; `deduped_rows[]` gives the input indices |
| `rejected` | rows not persisted; `errors[]` carries `{index, code, field?, error}` |
| `pending` | rows queued for governance approval |
| `warnings` | post-commit replication problems; the rows ARE durable locally |

Optional `embed_status` / `embed_status_reason` appear only when vectorisation
degraded — the rows are stored but not yet semantically recallable.

**Status.** `200` only when every submitted row landed as its own distinct
row. `207 Multi-Status` on any partial application. `202 Accepted` when every
row is queued for approval. When NOTHING was persisted the status is the
dominant cause, with retryable causes winning: `429` (quota), `503`
(replication / backend), `500`, `403`, `409`, `400`. A batch that persisted
nothing is never `200`.
Postgres-backed daemons additionally carry `"pending": [ … ]` — the rows
a governance standard routed to approval instead of writing.

> ⚠️ **A 200 from this endpoint does NOT mean any row was created.**
>
> Once the batch passes the size/auth/attestation preconditions, the
> terminal response is a bare JSON body with **no status code override**
> (`src/handlers/memories_query.rs`), so it is always **HTTP 200** —
> whatever the per-row outcome was. Per-row failures do not fail the
> request: validation errors, governance refusals, **per-agent quota
> rejections**, and store errors are all accumulated into `errors[]` and
> the corresponding rows are skipped.
>
> A batch in which *every* row was rejected by the per-agent daily write
> quota answers **`200` with `{"created": 0, "errors": [ …one entry per
> row… ]}`**. Nothing was written.
>
> **Callers MUST inspect `created` and `errors` — the status code is not
> a success signal for this endpoint.** A retry policy keyed on
> `response.ok` will treat a wholly-rejected batch as delivered and drop
> the data. Key it on `created === body.length && errors.length === 0`
> instead, and surface `errors[]` to the operator.
>
> Note this endpoint does **not** return 429 even though the single-write
> `POST /api/v1/memories` does; the quota rejection is a per-row entry in
> `errors[]` here.
>
> Returning `207 Multi-Status` (or 400 on total rejection) is tracked as
> [#2588](https://github.com/alphaonedev/ai-memory-mcp/issues/2588). Until
> that lands, the contract above is what the daemon does — write your
> client against it.

## Recall + search

### `GET /api/v1/recall` and `POST /api/v1/recall`

Hybrid recall (FTS5 + semantic + blend).

**Recall is PURE.** It writes zero rows to `memories` — no access-count
bump, no TTL extension, no tier promotion, on any surface, on either
backend ([#1953](https://github.com/alphaonedev/ai-memory-mcp/issues/1953);
the `AI_MEMORY_RECALL_TOUCH_SYNC` opt-back-in was removed at v1.0.0). The
only write a recall performs is one row in the append-only
`recall_observations` ledger. That makes recall safe to retry and safe to
serve from a read replica.

The access ladders still exist — they are applied out of band by the
periodic **fold job** from unfolded ledger rows: access-count bump,
per-tier TTL floor extension, mid→long promotion at 5 accesses, the
priority decade ladder. **The fold job only runs inside `ai-memory
serve`** (its own 60 s loop, `AI_MEMORY_ACCESS_FOLD_INTERVAL_SECS`, plus a
fold at the top of every GC tick). On an MCP-stdio or CLI-only topology
with no daemon, nothing folds until a GC chokepoint runs — so
`access_count`, `last_accessed_at` and tier promotion can lag arbitrarily
there. That is a freshness property of the derived ranking signal, not of
the memory text.

Query / body fields: `context` (required), `namespace`, `limit`
(default 10, max 50), `tags`, `since`, `until`, `as_agent`,
`budget_tokens`, `format` (`json` default | `toon` | `toon_compact` —
v0.7.0 #1579 B4; the TOON variants return `text/plain` rendered by the
same encoder the MCP tools use, `toon_compact` ≈ 79% smaller than the
JSON envelope; an unrecognised value is a 400).

```json
{
  "memories": [ { …, "score": 0.87 } ],
  "count": 5,
  "tokens_used": 234,
  "budget_tokens": 3000
}
```

```bash
curl -X POST http://127.0.0.1:9077/api/v1/recall \
  -H "Content-Type: application/json" \
  -d '{"context":"quarterly planning","limit":10}'
```

**v0.8.0 §2.5 read-time attested-provenance decoration** ([#1709](https://github.com/alphaonedev/ai-memory-mcp/issues/1709)). Under verbose provenance (the MCP default; HTTP opts in), each recall row carries read-time-composed fields in addition to `score` — all decoration-only (the stored `confidence` ranking contribution is unchanged):

- `provenance_tier` — composed from the row's `confidence_source` + the strongest incident link attestation: `signed_peer` > `curator_derived` > `self_signed` > `unsigned_caller`.
- `confidence_tier`, `freshness_state`, `latest_link_attest_level` — the existing v0.7.0 Gap-7 decoration.
- `scheduled_validity` (`valid` | `expiring` | `expired`) — present only when `AI_MEMORY_CONFIDENCE_DECAY` is enabled **and** the row has a validity anchor (`expires_at`, else `created_at` + tier TTL); recomputed deterministically against an hour-quantized "as-of" bucket (no exp-decay write). **v1.0.0 #2431** — when the row carries the #1834 claim-validity interval, that interval OVERRIDES the TTL anchor: the horizon is `min(anchor, valid_until)` and the window start is `max(created_at, valid_from)`, so a claim whose `valid_until` has closed reports `expired` (half-open `[valid_from, valid_until)` — a claim ending at T is not valid AT T) instead of the `valid` the TTL anchor alone used to assert. A row whose `valid_from` has NOT been reached yet OMITS the field entirely: the vocabulary describes life remaining and has no point meaning "not yet", so the substrate asserts nothing rather than something false. An unparsable bound fails closed to `expired`.

When a `confidence_tier` filter is requested, the response envelope adds a `meta` object reporting what the filter dropped, so `count: 0` is distinguishable from "no memory":

```json
{ "memories": [ … ], "count": 0,
  "meta": { "confidence_filtered_out": 4, "had_filtered_candidates": true } }
```

These fields are uniform across MCP `memory_recall`, HTTP recall, and `memory_session_start`.

### `GET /api/v1/search`

Read-only FTS5 keyword search. Same filter params as list, plus `q`
(required) and `format` (`json` default | `toon` | `toon_compact` —
v0.7.0 #1579 B4, same semantics as recall above).

```json
{ "results": [ … ], "count": 3, "query": "urgent deadline" }
```

> **Note (HTTP ↔ MCP parity):** The MCP `memory_recall`,
> `memory_search`, and `memory_list` tools accept the same optional
> `format` parameter (`json` | `toon` | `toon_compact`). As of v0.7.0
> (#1579 B4) the HTTP recall + search endpoints expose `format` too
> (HTTP defaults to `json` for backwards compat; MCP defaults to
> `toon_compact`). `GET /api/v1/memories` (list) is the one surface that
> does **not** accept `format` — `ListQuery` has no such field.
> The MCP `memory_recall` tool requires the `context` parameter — the
> `query` / `q` alias ladder is HTTP-only (#1606); an MCP call passing
> `query` is refused with "context is required". `context_tokens`
> (v0.6.0.0 contextual recall — recent conversation tokens biasing the
> query embedding at 70/30) is available on **both** transports: the
> `POST /api/v1/recall` body takes a JSON array, and the `GET` query
> string takes the comma-separated form `context_tokens=alpha,beta`
> (#1622).

## Lifecycle

### `POST /api/v1/memories/{id}/promote`

Bump to long tier. 200 / 202 / 404.

### `POST /api/v1/forget`

```json
{ "namespace": "scratch", "pattern": "deprecated", "tier": "short" }
```

At least one filter required. **Admin-gated**. Returns `{"deleted": N}`.

### `POST /api/v1/consolidate`

```json
{
  "ids": ["id1","id2","id3"],
  "title": "Summary",
  "summary": "Merged content",
  "namespace": "global",
  "tier": "long"
}
```

201 with `{"id":"consolidated-uuid","consolidated":3}`.

### `POST /api/v1/gc`

Immediate garbage collection. Empty body. **Admin-gated**. Returns
`{"expired_deleted":N}`.

## Links

### `POST /api/v1/links`

```json
{ "source_id": "abc", "target_id": "def", "relation": "supersedes" }
```

Relations (nine at v0.8.0; was six at v0.7.0, four at v0.6.x): `related_to`, `supersedes`, `contradicts`, `derived_from`, `reflects_on` (recursive-learning Task 1/8), `derives_from` (WT-1-A atomisation — atom row → parent memory), `decomposes_into`, `depends_on`, `advances` (the last three are the v0.8.0 Pillar-2 typed-cognition Goal/Plan/Step relations, #1709). Canonical enum in `src/models/link.rs::MemoryLinkRelation` (`COUNT = 9`).

### `GET /api/v1/links/{id}`

Returns inbound + outbound links for a memory under `{"links": [...]}`.

Each row is the graph-view projection — **eight columns**, exactly what
`db::get_links` selects ([#860](https://github.com/alphaonedev/ai-memory-mcp/issues/860)):

| Field | Notes |
|---|---|
| `source_id`, `target_id` | the edge endpoints |
| `relation` | one of the nine typed relations above |
| `created_at` | RFC3339 |
| `valid_from`, `valid_until` | v0.7 temporal validity; omitted when null |
| `observed_by` | the `agent_id` asserting the edge; omitted when null |
| `attest_level` | `"unsigned"` \| `"self_signed"` \| `"peer_attested"`; omitted when null |

**`signature` is deliberately NOT surfaced here**, and `signed_at` does
not exist — there is no such column on `memory_links` (the row's time
fields are `created_at` / `valid_from` / `valid_until`).

Withholding the signature is a design decision, not an omission: this is
a read-only graph view, and the verification surface is owned by
**`memory_verify`** — over HTTP, `POST /api/v1/links/verify`. That
endpoint returns `{verified, attest_level, signature_present,
observed_by, source_id, target_id, relation, findings}`. Build link
attestation checks against it; `GET /api/v1/links/{id}` will never carry
the bytes to verify against.

## Knowledge Graph + taxonomy (v0.6.3)

These endpoints operate on the temporal-validity knowledge graph
(`memory_links` with `valid_from` / `valid_until` / `observed_by`
columns added in schema v15) and the namespace taxonomy. See
`docs/MIGRATION-v0.6.2-to-v0.6.3.md` for the schema changes and
`docs/USER_GUIDE.md` for the matching MCP tools.

### `GET /api/v1/taxonomy`

Walk live (non-expired) memories grouped by namespace into a
hierarchical tree. **Admin-gated** (#945).

Query params: `prefix` (optional, restricts walk; `root` is an accepted
alias — `prefix` wins when both are supplied), `depth` (max 8 =
`MAX_NAMESPACE_DEPTH`, default 8), `limit` (1-10000, default 1000).

```json
{
  "tree": [
    { "namespace": "alphaone", "count": 0, "subtree_count": 47, "children": [...] }
  ],
  "total_count": 47,
  "truncated": false
}
```

### `POST /api/v1/check_duplicate`

Embedding cosine-similarity duplicate detection.

```json
{
  "title": "Project uses PostgreSQL 15",
  "content": "The main database is PostgreSQL 15 with pgvector for embeddings.",
  "namespace": "my-app",
  "threshold": 0.85
}
```

Response:

```json
{
  "is_duplicate": true,
  "threshold": 0.85,
  "nearest": { "id": "...", "title": "...", "namespace": "...", "similarity": 0.92 },
  "suggested_merge": "...",
  "candidates_scanned": 412
}
```

`threshold` is clamped to a 0.5 floor. Requires the `semantic` feature
tier or higher — without an embedder the endpoint returns **503**
(Service Unavailable); threshold mismatches return `200` with
`is_duplicate: false`.

### `POST /api/v1/entities`

Register an entity-as-typed-memory. Idempotent on
`(canonical_name, namespace)`.

```json
{
  "canonical_name": "PostgreSQL",
  "namespace": "my-app",
  "aliases": ["pg", "postgres"],
  "metadata": {}
}
```

Response: `{"entity_id":"ent-...","canonical_name":"PostgreSQL","namespace":"my-app","aliases":["pg","postgres","PostgreSQL"],"created":true}`.

Returns `409` if a non-entity memory with the same
`(title, namespace)` exists.

### `GET /api/v1/entities/by_alias`

Resolve an alias to its canonical entity.

Query params: `alias` (required), `namespace` (optional; without it,
picks the most-recently-created match across namespaces).

```json
{
  "found": true,
  "entity_id": "ent-...",
  "canonical_name": "PostgreSQL",
  "namespace": "my-app",
  "aliases": ["pg", "postgres", "PostgreSQL"]
}
```

`found: false` (and null fields) when the alias resolves to nothing.

### `GET /api/v1/kg/timeline`

Ordered timeline of links anchored at a source. Skips links with NULL
`valid_from`.

Query params: `source_id` (required), `since` / `until` (RFC 3339,
optional), `limit` (1-1000, default 200).

```json
{
  "source_id": "...",
  "events": [
    { "target_id": "...", "relation": "depends_on", "valid_from": "...", "valid_until": null, "observed_by": "..." }
  ],
  "count": 1
}
```

### `POST /api/v1/kg/invalidate`

Mark a link superseded by setting `valid_until`. **Does NOT delete**
the link — historical queries pinned to `valid_at < now` still see
it. Idempotent.

```json
{
  "source_id": "...",
  "target_id": "...",
  "relation": "depends_on",
  "valid_until": "2026-04-26T03:00:00Z"
}
```

Response: `{"found":true,"valid_until":"...","previous_valid_until":null}`.

> **Federation:** invalidations apply locally and propagate
> asynchronously via the sync-daemon — they are NOT quorum-broadcast.

### `POST /api/v1/kg/query`

Recursive-CTE traversal of the temporal knowledge graph rooted at a
source memory.

```json
{
  "source_id": "...",
  "max_depth": 3,
  "valid_at": "2026-04-26T00:00:00Z",
  "allowed_agents": ["ai:claude-code@host:pid-12345"],
  "limit": 200
}
```

Constraints: `max_depth` defaults to **1** when omitted and must be in
1..=5 (`KG_QUERY_MAX_SUPPORTED_DEPTH`; depth 0 errors,
depth > 5 errors). `allowed_agents: []` (empty array) returns zero
rows; omit the field to skip the agent filter entirely.

Response:

```json
{
  "source_id": "...",
  "max_depth": 3,
  "memories": [
    {
      "target_id": "...",
      "title": "...",
      "target_namespace": "my-app",
      "relation": "depends_on",
      "valid_from": "...",
      "valid_until": null,
      "observed_by": "...",
      "depth": 1,
      "path": "src->tgt"
    }
  ],
  "paths": ["src->tgt->..."],
  "count": 1
}
```

Ordering: `depth ASC, COALESCE(valid_from, link_created_at) ASC,
link_created_at ASC`.

## Namespaces

### `GET /api/v1/namespaces`

Lists namespaces with live-memory counts (**admin-gated**, #945). With
`?namespace=<ns>` the same route instead fetches that namespace's
standard (query-string twin of the `{ns}/standard` path form below).

```json
{ "namespaces": [{"namespace":"global","count":50},{"namespace":"project-x","count":30}] }
```

### `GET /api/v1/namespaces/{ns}/standard` — get namespace standard

Query: `inherit` (boolean, default `false`). When `true`, returns the
full N-level resolved chain (global `*` → ancestors → namespace) instead
of the single namespace's standard.

```json
{ "namespace": "engineering/auth", "standards": [ … ], "chain": ["*","engineering","engineering/auth"], "count": 3 }
```

Returns 200 with `count: 0` and an empty `standards` array when no
standard is set. Equivalent MCP tool: `memory_namespace_get_standard`
(`src/mcp/tools/namespace.rs`).

### `POST /api/v1/namespaces/{ns}/standard` — set namespace standard

Body: `{ "id": "<memory-id>", "parent": "<optional-parent-namespace>", "governance": { … } }`.
`governance` accepts `write` / `promote` / `delete` (each `any` |
`registered` | `owner` | `approve`), `approver` (ApproverType), and
`inherit` (boolean, default `true`). Equivalent MCP tool:
`memory_namespace_set_standard` (`src/mcp/tools/namespace.rs`).

### `DELETE /api/v1/namespaces/{ns}/standard` — clear namespace standard

Removes the namespace's pinned standard (the standard memory itself is
not deleted; only the `namespace_meta.standard_id` link). Equivalent
MCP tool: `memory_namespace_clear_standard` (`src/mcp/tools/namespace.rs`).

## Archive

### `GET /api/v1/archive` — list archived memories

**Admin-gated** (#943). Query: `namespace`, `limit` (default 50,
clamped 1-1000; `limit=0` → 400), `offset`.

```json
{ "archived": [ … ], "count": 24 }
```

Equivalent MCP tool: `memory_archive_list` (`src/mcp/tools/archive.rs`).
A `POST /api/v1/archive` form also exists (archive an explicit list of
memory ids; `≤ 1000` ids per request).

### `POST /api/v1/archive/{id}/restore` — restore archived memory

Path param: `id` (archived memory id). On success the row is removed
from `archived_memories` and re-inserted into `memories` with
`original_tier` and `original_expires_at` re-applied where present.
Equivalent MCP tool: `memory_archive_restore` (`src/mcp/tools/archive.rs`).

### `DELETE /api/v1/archive?older_than_days=30` — purge archived memories

Query: `older_than_days` (optional). Without the query param, all
archived rows are eligible. Returns `{"purged": N}`. Equivalent MCP
tool: `memory_archive_purge` (`src/mcp/tools/archive.rs`).

### `GET /api/v1/archive/stats` — archive counters

**Admin-gated** (#943).

```json
{ "archived_total": 24, "by_namespace": [{"namespace":"global","count":18}, … ] }
```

Equivalent MCP tool: `memory_archive_stats` (`src/mcp/tools/archive.rs`).

## Agents + governance

### `POST /api/v1/agents`

```json
{ "agent_id": "alice", "agent_type": "human", "capabilities": ["read","write"] }
```

`agent_type` accepts `human`, `system`, or any `ai:<name>` form
(`ai:claude-opus-4.7`, `ai:gpt-5`, etc.).

### `GET /api/v1/agents`

**Admin-gated** (#946). Returns `{"agents":[…],"count":N}`.

### `GET /api/v1/pending` — list pending governance actions

Query: `status=pending|approved|rejected`, `limit` (default 100, max 1000).

```json
{ "pending": [ { "id": "…", "action_type": "store", "namespace": "…", "status": "pending", "approvals": [ … ] } ], "count": 3 }
```

Equivalent MCP tool: `memory_pending_list` (`src/mcp/tools/pending.rs`).

### `POST /api/v1/pending/{id}/approve` — approve pending action

Path param: `id`. Stamps `decided_by` with the caller's `X-Agent-Id`.
200 if consensus reached (and the governed action is executed). 202 if
still collecting approvers. Equivalent MCP tool: `memory_pending_approve`
(`src/mcp/tools/pending.rs`).

### `POST /api/v1/pending/{id}/reject` — reject pending action

Path param: `id`. Returns `{"rejected":true,"id":"…","decided_by":"alice"}`.
Equivalent MCP tool: `memory_pending_reject` (`src/mcp/tools/pending.rs`).

## Sync / federation

### `POST /api/v1/sync/push`

Peer-to-peer push with timestamp-aware merge.

```json
{
  "sender_agent_id": "peer-remote-1",
  "memories": [ { … up to max_page_size (default 1000) … } ],
  "dry_run": false
}
```

Response includes `applied`, `noop`, `skipped`, `receiver_agent_id`,
`receiver_clock`.

**Federation headers (v0.7.0 secure defaults).** Under
`AI_MEMORY_FED_REQUIRE_SIG=1` (default, #791) the request must carry an
Ed25519 `X-Memory-Sig` over the body, attributed via `X-Peer-Id` to an
enrolled peer key; under `AI_MEMORY_FED_REQUIRE_NONCE=1` (default,
#922) a fresh per-message `X-Memory-Nonce` is also required (the
signature binds `body || 0x00 || nonce`), so byte-replays produce
`401 x_memory_nonce_replay`. `GET /api/v1/sync/since` enforces the same
signed-message gate over canonical GET bytes
(`method || path || query`, #1031).

### `GET /api/v1/sync/since`

Query: `since` (RFC3339, optional), `limit` (default 500, max 10000),
`peer` (attribution tag).

```json
{ "count": 5, "limit": 500, "memories": [ … ] }
```

## Import / export

### `GET /api/v1/export`

**Admin-gated.** Returns
`{"memories":[…],"links":[…],"count":N,"exported_at":"…"}`.

### `POST /api/v1/import`

**Admin-gated.** Body matches export shape. `≤ 1000` memories per call
(compiled `MAX_BULK_SIZE`). Returns `{"imported":N,"errors":[…]}`.
Preserves original `metadata.agent_id` into
`metadata.imported_from_agent_id`.

## Webhooks (v0.6.0.0)

Three endpoints under `/api/v1/subscriptions` — create them via MCP
tools or the REST surface. Dispatch is SSRF-hardened (rejects
private-range IPs; requires `https://` unless loopback).

Every write surface emits the same events (v1.0.0 #3403): the MCP tools,
the HTTP handlers, and the `ai-memory` CLI write verbs (`store`,
`delete`, `promote`, `link`, `resolve`, `consolidate`) all dispatch
through one shared funnel (`src/write_events.rs`), so the event stream is
a complete record of writes regardless of which surface made them. Before
#3403 no CLI verb dispatched anything, and subscribers were silently
blind to CLI-originated writes. Delivery is fire-and-forget, so a one-shot
CLI invocation drains the fan-out before exiting; if that drain hits its
budget the write is still durable and each admitted delivery has a
persisted audit row for replay-from-cursor.

### `POST /api/v1/subscriptions` — register webhook

Body: `{ "url": "https://…", "events": "memory_store,memory_delete", "secret": "<shared-secret>", "namespace_filter": "…", "agent_filter": "…" }`.
`events` is a **comma-separated string** (default `"*"`). Canonical
event types (`WEBHOOK_EVENT_TYPES` in `src/subscriptions.rs`):
`memory_store`, `memory_promote`, `memory_delete`,
`memory_link_created`, `memory_link_invalidated`,
`memory_consolidated`, `approval_requested`. Stores `secret` as a
SHA-256 hash; dispatched events carry an
`X-AI-Memory-Signature: sha256=<hex>` HMAC header. Returns the new
subscription `id`. Equivalent MCP tool: `memory_subscribe`
(`src/mcp/tools/subscribe.rs`).

### `DELETE /api/v1/subscriptions?id=<id>` — unregister webhook

Returns `{"deleted": true}`. Equivalent MCP tool: `memory_unsubscribe`
(`src/mcp/tools/subscribe.rs`).

### `GET /api/v1/subscriptions` — list subscriptions

Returns `{"subscriptions":[…],"count":N}`. Each entry includes `url`,
`events`, `created_at`, `dispatch_count`, `failure_count`. Equivalent
MCP tool: `memory_list_subscriptions` (`src/mcp/tools/subscribe.rs`).

## Federation (v0.7, opt-in via `--quorum-writes`)

When `ai-memory serve --quorum-writes N --quorum-peers URL,URL,…` is
set, every write fans out to peers and returns **only** once W-1 peer
acks land within `--quorum-timeout-ms`.

- **201** + `{"quorum_acks": W}` when quorum is met.
- **202 Accepted** + `{"quorum_met":false,"acks":X,"needed":Y,"reason":"unreachable|timeout|id_drift","durability":"local"}` when the local write committed but quorum was not met (v0.8.1 W3 / gap G12).

The local write is durably committed and **never** rolled back, so an
under-replicated write is reported as a **`202 Accepted`**, not a `5xx`
(the pre-v0.8.1 `503` + `Retry-After: 2` misreported a locally-durable
write as a service failure). The replication state is carried in the
body; the sync-daemon's eventual-consistency loop + the federation
push-DLQ converge peers afterwards (per `ADR-0001`), so there is no
client retry to perform. A genuine **local** write failure still
returns the appropriate error status.

## Curl recipes

```bash
# Health
curl http://127.0.0.1:9077/api/v1/health

# Store a memory
curl -X POST -H "Content-Type: application/json" \
  http://127.0.0.1:9077/api/v1/memories \
  -d '{"title":"hi","content":"there","tier":"mid"}'

# Recall
curl -X POST -H "Content-Type: application/json" \
  http://127.0.0.1:9077/api/v1/recall \
  -d '{"context":"what did I store","limit":5}'

# Incremental sync pull since a timestamp
curl 'http://127.0.0.1:9077/api/v1/sync/since?since=2026-04-01T00:00:00Z&limit=1000'

# Prometheus scrape
curl http://127.0.0.1:9077/metrics
```

## HTTP ↔ MCP parameter coverage

A small set of parameters are surfaced by only one transport. The MCP
tool schema is authoritative via the per-tool `<ToolName>Request`
structs in `src/mcp/tools/<name>.rs` (schemars-derived; consumed by
`registered_tools()` in `src/mcp/registry.rs` and projected to
`tools/list` by `tool_definitions()`). The HTTP body / query types in
`src/models/` and the route handlers in `src/handlers/` are
authoritative for HTTP.

| Tool | Param | HTTP | MCP | Notes |
|---|---|---|---|---|
| `memory_store` | `ttl_secs` | ✓ | ✗ | HTTP-only (`CreateMemory.ttl_secs`). The MCP `memory_store` tool exposes neither `ttl_secs` nor `expires_at` — set the expiry afterwards with MCP `memory_update` (`expires_at`), or let the tier default apply. |
| `memory_store` | `expires_at` | ✓ | (via `update`) | HTTP body accepts; documented in the `POST /api/v1/memories` example. On MCP it lives on `memory_update`, not `memory_store`. |
| `memory_store` | `signature` | ✓ | ✓ | #626 Layer-3 — std-base64 detached Ed25519 over the `SignableWrite` envelope; upgrades `agent_id` claimed→`agent_attested`. Same wire on both transports. |
| `memory_store` | `created_at` | ✓ | ✓ | #626 Layer-3 — RFC 3339; **required when `signature` is present** (the signed timestamp, adopted verbatim; ±300 s freshness window). |
| `memory_recall` | `format` | ✓ | ✓ | Both transports (#1579 B4). `GET`/`POST /api/v1/recall` negotiate `json` (HTTP default) \| `toon` \| `toon_compact` before doing any work; an unrecognised value is a 400. MCP defaults to `toon_compact`. |
| `memory_recall` | `context_tokens` | ✓ | ✓ | Both transports. The `POST` body takes a JSON array; the `GET` query string takes the comma-separated form `context_tokens=alpha,beta` (#1622). |
| `memory_search` | `format` | ✓ | ✓ | Both transports (#1579 B4). `GET /api/v1/search` negotiates the same three values with the same 400-on-unknown rule. |
| `memory_list` | `format` | ✗ | ✓ | **MCP-only.** `ListQuery` (`src/models/memory.rs`) carries no `format` field, so `GET /api/v1/memories` always answers JSON. |

**TOON on HTTP is worth taking.** The `toon` / `toon_compact` variants
return `text/plain` rendered by the same encoder the MCP tools use;
`toon_compact` runs roughly 79% smaller than the JSON envelope on the
same result set. If you are paying for tokens on recall or search
results, request it explicitly — HTTP defaults to `json` purely for
backwards compatibility, not because it is the better wire.

The single remaining gap (`memory_list` `format`) is a transport-level
surface-area difference captured here so operators don't re-derive it.

## v0.7.0 net-new endpoints

The HTTP routes added since v0.6.4. All accept the same auth +
agent-identity headers documented above. Wire-shape source of truth is
the per-domain handler modules under `src/handlers/`; the route-path
SSOT is `src/handlers/routes.rs` (#1558 batch 4), registered by the
router in `src/lib.rs`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/quota/status` | K8 quota status — read the calling agent's daily quota row. Auto-inserts a default row on first call. See [`docs/k8-quotas.md`](k8-quotas.html). MCP: `memory_quota_status`. |
| `GET`  | `/api/v1/approvals/stream` | K10 SSE approval channel — server-sent events for pending-approval state changes. See [`docs/k10-sse-approvals.md`](k10-sse-approvals.html). |
| `POST` | `/api/v1/approvals/{pending_id}` | K10 approval decide path — body `{"decision":"approve|deny","remember":"once|session|forever"}`, HMAC-gated via `X-AI-Memory-Signature`. |
| `POST` | `/api/v1/auto_tag` | LLM auto-tag endpoint (v0.7 smart-tier surface; 503 when no LLM is configured). |
| `POST` | `/api/v1/expand_query` | HTTP parity for the MCP `memory_expand_query` tool. |
| `POST` | `/api/v1/kg/find_paths` | KG chain-walk over HTTP; Cypher on AGE / recursive-CTE on SQLite. |
| `POST` | `/api/v1/find_paths` | Alias for `/api/v1/kg/find_paths` (#934 — legacy callers). |
| `POST` | `/api/v1/links/verify` | Ed25519 link verification surface — wire shape: `{verified, attest_level, signature_present, observed_by, source_id, target_id, relation, findings}`. |
| `DELETE` | `/api/v1/links` | Delete a link. Returns `{"deleted": N}`. |
| `GET`  | `/api/v1/contradictions` | Detect contradiction candidates (similar titles in a namespace). |
| `POST` | `/api/v1/memory_load_family` | HTTP parity for the always-on `memory_load_family` MCP loader. |
| `POST` | `/api/v1/capture_turn` | #1416 — L4 layered-capture HTTP mirror of MCP `memory_capture_turn` (idempotent per-turn write via `MemoryStore::capture_turn_idempotent`). |
| `POST` | `/api/v1/share` | #1095 — copy a memory into the recipient agent's `_shared/<from>→<to>/` namespace; body `{source_memory_id, target_agent_id}`. MCP: `memory_share`. |
| `POST` | `/api/v1/session/start` | HTTP parity for `memory_session_start` (auto-recall session boot). |
| `GET`  | `/api/v1/capabilities` | Capabilities envelope (schema_version `"3"`; `Accept-Capabilities` header negotiates v1/v2). MCP: `memory_capabilities`. |
| `POST` | `/api/v1/notify` | Agent-to-agent inbox message. Sender resolved from `X-Agent-Id` only (#901); body `agent_id` must match or 403. MCP: `memory_notify`. |
| `GET`  | `/api/v1/inbox` | Read the calling agent's inbox. MCP: `memory_inbox`. |
| `GET` `POST` `DELETE` | `/api/v1/skill/list`, `/api/v1/skill/register`, `/api/v1/skill/{id}`, `/api/v1/skill/{id}/resource`, `/api/v1/skill/{id}/export`, `/api/v1/skill/{id}/promote`, `/api/v1/skill/{id}/compose` | Cluster E API-2 (#767) — Agent Skills HTTP parity for the seven `memory_skill_*` MCP tools. **Admin-gated.** |
| `POST` | `/api/v1/memory_smart_load`, `/api/v1/memory_reflect`, `/api/v1/memory_recall_observations`, `/api/v1/memory_reflection_origin`, `/api/v1/memory_dependents_of_invalidated`, `/api/v1/memory_export_reflection`, `/api/v1/memory_atomise`, `/api/v1/memory_calibrate_confidence`, `/api/v1/memory_verify`, `/api/v1/memory_replay`, `/api/v1/memory_subscription_replay`, `/api/v1/memory_subscription_dlq_list`, `/api/v1/memory_rule_list`, `/api/v1/memory_check_agent_action` | #1111 — 14 thin HTTP wrappers around the same-named MCP substrate handlers (`src/handlers/route_1111.rs`); wire envelopes are byte-equal across MCP and HTTP. |
| `GET`  | `/api/v1/admin/quarantine` | v1.0.0 [#2402](https://github.com/alphaonedev/ai-memory-mcp/issues/2402) — list the memories currently held in federation quarantine (`handlers::list_quarantined`). **Admin-gated.** Identifying metadata ONLY (id, namespace, title, source, kind, timestamps) — never `content`: a quarantined row is untrusted input by construction and its content may be an at-rest seal sentinel. `?namespace=` narrows, `?limit=` pages (clamped to 1000). |
| `POST` | `/api/v1/admin/quarantine/{id}/release` | v1.0.0 [#2402](https://github.com/alphaonedev/ai-memory-mcp/issues/2402) — release one quarantined memory back to `lifecycle_state=open` (`handlers::release_quarantined`), the operator half of the [#1948](https://github.com/alphaonedev/ai-memory-mcp/issues/1948) route-OUT contract that shipped with no caller. **Admin-gated**; the audit actor is the principal `require_admin` RETURNS — an id it admits only when it is on the admin allowlist AND the deployment has request authentication configured (#1570), and, under the `enforce` identity-binding posture, only when it is key-attested to a per-agent api key (#2044). The handler never reads `X-Agent-Id` itself. Appends a `memory.dequarantined` signed audit row in the SAME transaction as the state change on both backends. Idempotent: an id that is not currently quarantined answers `200 {"released": false}` and writes nothing (deliberately not `404` — that would leak the existence of rows this surface does not return). |
| `GET`  | `/api/v1/tools/list` | MCP `tools/list` mirror for harness ops — returns the live tool surface for the daemon's profile (104 at `full`, 7 at `core`) — SSOT: `Profile::full()/core().expected_tool_count()` in `src/profile.rs`. |

> **Total HTTP surface at v1.0.0: 82 unique URL paths across 96
> production route registrations** (several paths carry more than one
> method), on the sqlite-backed daemon and on the postgres-backed daemon
> under `--features sal-postgres`. Both numbers are pinned in
> `src/lib.rs` as `EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = 82` and
> `EXPECTED_PRODUCTION_ROUTES_COUNT = 96`, asserted by
> `tests/route_count_invariant.rs`. Three further routes are
> `#[cfg(test)]`-gated and never registered in a production build
> (`EXPECTED_TEST_ROUTES_COUNT = 3`).
>
> Re-derive the path count yourself against the route-path SSOT:
>
> ```bash
> grep -oE '"/[^"]*"' src/handlers/routes.rs | sort -u | wc -l   # 80
> ```
>
> That is 79 `/api/v1/*` paths plus the bare `/metrics`. Do not count
> `.route(` occurrences in `src/lib.rs` to get the registration total —
> the router also registers test-only routes under `#[cfg(test)]`, so a
> raw grep overcounts; the pinned const is the answer.
>
> **Postgres caveat.** Not every registered route is served on the
> Postgres backend. `postgres_endpoint_supported()`
> (`src/handlers/postgres_gate.rs`) is an explicit allowlist; a route
> outside it answers a uniform **501 NOT IMPLEMENTED** on a
> Postgres-backed daemon. Check the gate before assuming parity.

### v0.8.0 net-new endpoints

The #1718 Pillar-1 distributed-coordination write surfaces. Only these
two coordination paths are exposed over HTTP; the rest of the
coordination toolset (action CRUD, leases, checkpoints, routines) is
MCP-only.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/actions/{id}/transition` | Coordination action-state transition (`handlers::transition_action`) — local CAS write + W-of-N federation fanout. MCP: `memory_action_transition`. |
| `POST` | `/api/v1/signals` | Signed inter-agent signal send (`handlers::send_signal`) — local write + W-of-N fanout. MCP: `memory_signal_send`. |

### v0.9.0 + v1.0.0 net-new endpoints

The four paths below complete the 80-unique-path inventory. Each is
registered in `src/lib.rs` against the corresponding
`src/handlers/routes.rs` const, so the path string here is the SSOT
value, not a transcription.

| Method | Path | Purpose |
|---|---|---|
| `PUT` | `/api/v1/agents/{id}/pubkey` | Bind an Ed25519 attestation public key to a registered agent (`handlers::bind_agent_pubkey`, [#1539](https://github.com/alphaonedev/ai-memory-mcp/issues/1539)). **Admin-gated.** The bound key is what the write-attestation and federation author-verification paths check a presented signature against — see §"Admin-gated endpoints". CLI twin: `ai-memory agents bind-key`. |
| `GET` | `/api/v1/memories/{id}/lineage` | Walk a memory's derivation lineage-DAG — ancestors/descendants over the provenance relation subset `derived_from` / `reflects_on` / `derives_from` (`handlers::get_lineage`, v0.9.0 G13-mem [#1859](https://github.com/alphaonedev/ai-memory-mcp/issues/1859)). Three-surface parity with the `memory_lineage` MCP tool and `ai-memory lineage`. Requires the lineage DAG to be enabled (`AI_MEMORY_LINEAGE_DAG`, default on). |
| `POST` | `/api/v1/checkpoints/{id}/resolve` | Resolve a commit-checkpoint (`handlers::resolve_checkpoint`, [#2391](https://github.com/alphaonedev/ai-memory-mcp/issues/2391)) — local resolve plus W-of-N federation fanout via `federation::broadcast_checkpoint_resolution_quorum`. This is the SEND leg of the FED-RQ-01 ([#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936)) checkpoint-federation transport; the receive leg is gated by `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` (fail-closed by default). MCP: `memory_checkpoint_resolve`. |
| `POST` | `/api/v1/skill/{id}/retire` | Retire or unretire a skill lineage (`handlers::skill_retire_route`, [#2024](https://github.com/alphaonedev/ai-memory-mcp/issues/2024)). **Admin-gated and reversible** — it sets the schema-v82 `retired_at` / `retired_by` / `retire_reason` columns and deletes nothing. Pass `unretire=true` to reverse. The irreversible sibling `memory_skill_delete` is deliberately MCP-only with no HTTP route; see [`agent-skills.md`](agent-skills.html). |

### v0.7.0 net-new MCP tools

The 31 MCP tools added since v0.6.4 are documented inline in
`src/mcp/registry.rs` and enumerated in
[`docs/MIGRATION_v0.7.md` §"New MCP tools"](MIGRATION_v0.7.html#new-mcp-tools).
Highlights for HTTP-equivalent surfaces:

| MCP tool | HTTP equivalent | Notes |
|---|---|---|
| `memory_load_family` | `POST /api/v1/memory_load_family` | Always-on. |
| `memory_quota_status` | `POST /api/v1/quota/status` | K8. |
| `memory_find_paths` | `POST /api/v1/kg/find_paths` | J7. |
| `memory_verify` | `POST /api/v1/links/verify` | H4. |
| `memory_pending_list` / `memory_pending_approve` / `memory_pending_reject` | `GET /api/v1/pending`, `POST /api/v1/pending/{id}/approve`, `POST /api/v1/pending/{id}/reject` | K10. The MCP tool names changed from the v0.7-alpha drafts (`memory_approval_pending` / `memory_approval_decide`); the HTTP paths are stable. |
| `memory_agent_register` / `memory_agent_list` | `POST /api/v1/agents`, `GET /api/v1/agents` | `meta` family. Register an NHI agent (`agent_type`, `capabilities`) in `_agents` (refreshes `last_seen_at`, preserves `registered_at`) and list every registered agent (ordered by `registered_at`). `agent_id` is CLAIMED, not attested — pair with attestation (#626 Layer-3) for a security boundary. |

For the canonical full inventory — **103 entries advertised at `--profile full`** (102 callable tools plus the always-on `memory_capabilities` bootstrap), matching the `GET /api/v1/tools/list` row above:

```bash
grep -oE 'crate::mcp::[a-z_]+::[A-Za-z]+Tool' src/mcp/registry.rs | sort -u | wc -l   # 103
```

The `registered_tools()` iterator in `src/mcp/registry.rs` is the source of truth, and `Profile::full().expected_tool_count()` in `src/profile.rs` is the SSOT the registry is pinned against (`const_count_matches_full_profile`). `memory_capabilities` is counted inside the `full` families, which is why `full` is 103 and not 104.

Default `--profile core` selects **7** family tools (`Profile::core().expected_tool_count()`), and `tools/list` then appends the always-on `memory_capabilities` (`profile::ALWAYS_ON_TOOLS`), so a `core` daemon advertises **8 entries on the wire**. Both numbers are correct and mean different things; cite the one you need.

The v0.8.0 net-new tools were the coordination families `memory_action_*`, `memory_lease_*`, `memory_signal_*`, `memory_checkpoint_*`, and `memory_routine_*`.

## See also

- `docs/USER_GUIDE.md` — MCP tool reference (parallel to this HTTP doc).
- `sdk/typescript/README.md` — TypeScript SDK using these endpoints.
- `sdk/python/README.md` — Python sync + async SDK.
- `docs/CLI_REFERENCE.md` — corresponding CLI surface.
- `docs/SECURITY.md` — API key + mTLS + governance.
- `docs/TROUBLESHOOTING.md` — common error scenarios.
