---
layout: doc
---
# `ai-memory doctor` — operator health dashboard

**Phase P7 / R7** (v0.6.3.1). Read-only health-and-fitness report for an
ai-memory deployment. Runs against a local SQLite DB or, with `--remote`,
against a live `ai-memory serve` daemon (the **fleet doctor** mode at T3+).

## Quick start

```bash
# Inspect the local DB. Default path is the same one `ai-memory store`
# writes to.
ai-memory doctor

# Read from a non-default DB.
ai-memory --db /var/lib/ai-memory/store.db doctor

# Machine-readable output for CI / scripting.
ai-memory doctor --json | jq '.sections[] | select(.severity == "critical")'

# Treat warnings as failures (useful for `pre-commit` / CI gates).
ai-memory doctor --fail-on-warn

# Fleet doctor — read a remote daemon's capabilities + stats endpoints.
ai-memory doctor --remote https://node-a.example.com:9077

# Combine: JSON + remote, no DB lookup at all.
ai-memory doctor --remote https://node-a.example.com:9077 --json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Healthy. No critical findings. (Warnings allowed unless `--fail-on-warn`.) |
| `1`  | At least one warning, with `--fail-on-warn` set. |
| `2`  | At least one critical finding. Always returned regardless of flags. |

Suitable for shell-style branching:

```bash
if ! ai-memory doctor --fail-on-warn; then
    pagerduty-cli incident create --service ai-memory --severity warn
fi
```

## Report sections

Each section carries a severity (`INFO`, `WARN`, `CRIT`, `N/A`) and a list
of `(key, value)` facts. The overall report severity is the max across
sections.

### Configuration

- `config_path` and `status` identify the configuration file and whether it can be loaded.
- `archive_on_gc` (#3385) reports the **effective** GC archive policy — the value
  the TTL sweep and `memory_forget` will actually use on this host. `true` (the
  compiled default) archives an expired memory into `archived_memories` before
  deleting it, so eviction stays reversible; `false` is a permanent hard delete
  with no archive and no rollback.
- `archive_on_gc_source` (#3385) reports WHICH layer supplied that value:
  - `config` — `[storage].archive_on_gc`, the documented v2 key (highest precedence).
  - `legacy` — the DEPRECATED flat top-level `archive_on_gc` key. Resolving it also
    emits a one-shot stderr WARN; move it under `[storage]` or run
    `ai-memory config migrate`.
  - `compiled-default` — neither key is set, so archiving is on.

  When both keys are set the `[storage]` one wins and the flat key is ignored;
  if the two disagree, a one-shot stderr WARN names the winner.

  An UNUSABLE configuration reports the load `error` instead: no config was
  resolved, so there is no honest effective policy to print.

### Storage

- `total_memories`, `expiring_within_1h`, `links`, `db_size_bytes`
- per-tier and per-namespace counts
- `dim_violations` — count of memories whose `embedding_dim` disagrees
  with their namespace's modal dim. **Critical** when > 0.
  - On pre-P2 schemas the column doesn't exist; the field renders as
    `not_observed (pre-P2 schema)` with no severity bump.

### Index

- `hnsw_size_estimate` — count of memories with a non-null embedding
  (proxy for the in-memory HNSW index size).
- `cold_start_rebuild_secs_estimate` — rough estimate of daemon-restart
  cost at the canonical 50k inserts/sec rate.
- `index_evictions_total` — eviction count from `MAX_ENTRIES = 100_000`.
  **Critical** when > 0 once P3 wires the counter; `not_observed` until
  then. The doctor still raises a **warning** when `hnsw_size >= 95k`
  as a forward-leaning hint.

### Recall

- `recall_mode_distribution` — distribution of `hybrid` vs `keyword_only`
  vs `degraded` over the rolling window. `not_observed` until P3 lands.
- `reranker_used_distribution` — distribution of `neural` vs
  `lexical_fallback` vs `off`. `not_observed` until P3 lands.
- `--remote` mode reports the live `recall_mode_active` and
  `reranker_active` from Capabilities v2 (P1) instead.

### Governance

- `namespaces_with_policy` / `namespaces_without_policy` — count of
  namespaces with a registered standard whose
  `metadata.governance` block is non-null.
- `inheritance_depth` — histogram of `parent_namespace` chain depths
  across `namespace_meta` rows (`d0=N,d1=N,...`).
- `oldest_pending_age_secs` — age of the oldest `pending_actions` row
  in `pending` status. **Critical** when > 86400 (24h).
- `pending_actions_total` — count of `pending` rows.

### Sync

- `probed_at` — the RFC 3339 instant every age below is measured against.
- Rows are enumerated from the UNION of `sync_state` and `sync_peer_contact`
  (#3655 v3): a peer that has only ever answered empty windows has a contact
  row and no `sync_state` row, and is still listed — its data cursors read
  `never_pulled`, never `0`. Contact without data is normal; data without
  contact cannot happen. Peer ids of URL shape are redacted (credentials
  never reach a fact or note).
- `peer_count` — physical rows in that union (valid + invalid);
  `invalid_rows` — rows whose cursors are NULL or not RFC 3339, each named
  as `peer::<agent>/<peer>::invalid = <column and reason>`. **Warning** when
  > 0: an invalid row is neither healthy nor absent (#3655).
- Per peer (`peer::<agent>/<peer>::…`, #3655):
  - `reachability` — `reachable`, or `unknown:<reason>` using the SAME
    definition the live daemon's `/health` uses (#3654): a peer's last
    ANSWERED pull older than 3 × its catch-up cadence is
    `unknown:pull_observation_stale` → **Critical** (the mesh is not
    converging through this node); a row with no recorded contact is
    `unknown:no_pull_observation`, and one whose contact carries no cadence
    is `unknown:no_catchup_loop` → **Warning**, counted in `unknown_peers`
    — neither healthy nor stale, and never rendered as an age of 0.
  - `contact_age_secs` / `catchup_interval_secs` — seconds since the peer
    last answered a pull (`sync_peer_contact.last_contact_at`, this node's
    clock; stamped on every answered pull, EMPTY window included) and the
    cadence of the loop that pulled; `not_observed` when absent.
  - `advanced_age_secs` — seconds since the data watermark last advanced
    (`last_pulled_at`, this node's clock). `last_pulled_at` only moves when
    a pull carried rows, so it is a data-watermark stamp, not a contact
    time: old is the normal state of a quiet peer and is not a finding.
  - `data_age_secs` — seconds since the newest peer data seen
    (`last_seen_at`, the peer's clock). Old is legitimate for a quiet peer.
  - `pushed_age_secs` — seconds since the last local watermark the peer
    accepted, or `never_pushed`.
  - `clock_lead_secs` — signed `last_seen_at - last_pulled_at`. **Critical**
    when it exceeds the sync daemon's pull-cursor future bound (300s): the
    peer stamps data in this node's future, so its cursors will be refused.
    Negative is the quiet-peer case and is not a finding.
- `stale_peers`, `unknown_peers`, `max_contact_age_secs`,
  `max_advanced_age_secs`, `max_data_age_secs` — measured counts and maxima
  over valid rows (`not_observed` when nothing was measured);
  `max_skew_secs` (the largest `|clock_lead_secs|`) is kept for existing
  consumers and no longer drives severity.
- **Critical** with `sync_state = unreadable` and `sync_query_error` when the
  table cannot be queried — peer health is unknown, which is not the same as
  a single node (#3655).
- `N/A` when no peers are registered (single-node deployment).

### Webhook

- `subscription_count` — rows in `subscriptions`.
- `dispatched_total` / `failed_total` — lifetime totals from the
  `dispatch_count` / `failure_count` columns.
- `success_rate_pct` — `(dispatched - failed) / dispatched * 100`.
  **Warning** when < 95% over the lifetime totals (P5 will refine this
  to a rolling-1h window).

### Capabilities

- In `--remote` mode: queries `/api/v1/capabilities` and reports
  `schema_version`, `recall_mode_active`, `reranker_active`. Bumps to
  **Warning** when the daemon reports `recall_mode_active != hybrid`
  on a tier (`semantic` / `smart` / `autonomous`) that should support
  it (silent-degradation signal from P1).
- In local mode: `N/A` — the local doctor doesn't construct a
  TierConfig. Use `--remote http://localhost:9077` for the live read.

### LLM Reachability (#1146)

- Resolves the canonical LLM configuration via `AppConfig::resolve_llm`
  (the same path MCP stdio, the HTTP daemon, `atomise`, `curator`, and
  the boot banner consume) and probes the endpoint with the resolved
  Bearer key: `GET <base_url>/api/tags` (Ollama) or
  `GET <base_url>/models` (OpenAI-compatible).
- Facts: `backend`, `model`, `base_url`, `config_source`,
  `key_source` (never the key itself), `http_status`, `latency_ms`.
- Severity: **INFO** on 2xx; **WARN** on 401/403 (auth), 429
  (rate-limit), 5xx (vendor outage); **CRIT** on other 4xx (likely
  wrong `base_url`), network / DNS / TLS errors.

### Embeddings Reachability (#1598)

- The embeddings sibling of the LLM section. Resolves the canonical
  embeddings configuration via `AppConfig::resolve_embeddings` (the
  same #1598 ladder the MCP stdio init + daemon `build_embedder`
  consume) and probes: `GET <url>/api/tags` (ollama backend, no auth)
  or `POST <url>/embeddings` with a 1-char input + the resolved
  Bearer key (API backends).
- Facts: `backend`, `model`, `base_url`, `config_source`,
  `key_source`, `probe_url`, `http_status`, `latency_ms`; `key_error`
  when key resolution failed (the probe still runs so reachability is
  reported independently).
- Severity mapping matches the LLM section. When NO operator
  embeddings configuration exists anywhere (env / `[embeddings]` /
  legacy flat all absent), the section is **INFO without probing** —
  the tier preset governs, preserving the fresh-DB all-INFO invariant.
- **Operator GPU-policy WARN** — fires when the resolved backend is
  `ollama` on a host with no detectable NVIDIA GPU (`nvidia-smi -L`).
  Operator policy: local Ollama embeddings only on GPU-equipped
  nodes; CPU-only nodes use API backends. See the
  [enterprise reference architectures](../reference-architecture/enterprise-cpu-memory.md).

### Wake hub (#3471)

Renders on every local run; reads only the filesystem and this process's own
`RLIMIT_NOFILE` — it never binds, never connects, and never opens a database
(the wake hub has none).

- `configured` — `yes` when a `[wake_hub]` block is present OR a socket is
  actually on disk. A host running neither reports `no` and nothing else, so
  `doctor` does not start warning about an optional subsystem nobody enabled.
- `socket`, `socket_present`, `socket_mode`, `socket_dir_mode`,
  `socket_owner_is_self`, `socket_dir_owner_is_self` — the on-disk posture.
  **Critical** when a socket is PRESENT and is not `0600`, is not owned by
  this user, or sits in a group/other-accessible directory: a 0600 socket is
  only as private as the directory holding it, and either fault is a live
  exposure of every agent's wake plane to any local user. A socket that is
  simply ABSENT is not a finding — the hub may not be running.
- `rlimit_nofile_soft` / `_hard` / `_desired` / `_floor`,
  `fd_headroom_reserved` — the file-descriptor budget. On a host that runs a
  hub: **Warning** below `_desired` (4096; the hub runs at a smaller
  connection ceiling and says so at start-up), **Critical** below `_floor`
  (the hub would refuse to bind at all). macOS's default soft limit of 256 is
  the case this exists to surface. Fix with `LimitNOFILE=` in the systemd unit
  or `SoftResourceLimits`/`HardResourceLimits` `NumberOfFiles` in the launchd
  plist.
- `supervisor_unit` — where a shipped unit is installed, or `not installed`.
  **Info always**: running the hub in the foreground or under another
  supervisor is a legitimate deployment, so an absent unit is never a finding.

Reachability is a separate question with its own verb: `ai-memory wake-hub
--health` connects as an ordinary client and exits non-zero when the hub
cannot be reached. `doctor` deliberately does not connect — it must never be
able to hang against a wedged hub.

## Severity rules (initial)

| Severity | Trigger |
|----------|---------|
| **Critical** | `dim_violations > 0`; pending action older than 24h; a sync peer not observed for > 600s, a peer clock leading this node beyond the 300s pull-cursor bound, or an unreadable `sync_state` (#3655); HNSW evictions > 0; a live wake-hub socket that is not owner-only (#3471) |
| **Warning**  | Capabilities v2 reports a silent-degrade flag (`recall_mode_active != hybrid` on a capable tier); subscription delivery success < 95%; a `sync_state` row with an unreadable cursor (#3655) |
| **Info**     | Anything else worth surfacing |
| **N/A**      | The section can't be queried in this mode (raw SQL section in `--remote`, P2/P3-only fields on a pre-P2/P3 schema) |

## Remote (fleet) mode

`--remote <url>` queries the daemon's existing HTTP surfaces:

- `GET /api/v1/capabilities` — the full Capabilities v2 (P1) JSON.
- `GET /api/v1/stats` — total memories, expiring soon, link count.

Sections that need raw SQL access (`Index`, `Governance`, `Sync`,
`Webhook`) render as **N/A** in remote mode. T3+ deployments will gain
a `/api/v1/doctor` endpoint that returns those sections directly so the
fleet doctor stops being read-by-API-only — tracked under R7.

Example fleet sweep:

```bash
for node in node-a node-b node-c; do
    echo "=== $node ==="
    ai-memory doctor --remote "https://$node.example.com:9077" --json \
        | jq '{node: "'"$node"'", overall, criticals: [.sections[] | select(.severity == "critical") | .name]}'
done
```

## What's stubbed pending P1/P2/P3

The doctor ships a working baseline against the v0.6.3 surface set. The
following fields render as `not_observed (pre-PX surface)` until those
phases land:

| Field | Lands with |
|-------|------------|
| `dim_violations` (numeric value > 0) | P2 — `embedding_dim` column |
| `index_evictions_total` (numeric value) | P3 — eviction counter |
| `recall_mode_distribution` (rolling window) | P3 — recall_mode counter |
| `reranker_used_distribution` (rolling window) | P3 — reranker counter |
| `recall_mode_active` (in `--remote`) | P1 — Capabilities v2 |
| `reranker_active` (in `--remote`) | P1 — Capabilities v2 |

When any of those phases merges, the doctor wires up automatically
without further code changes — every consumer is gated on schema /
field presence and falls back gracefully when absent.

## Anti-goals (per spec)

- The doctor does not introduce new monitoring infrastructure (no
  Prometheus, OTel exporters). It reads existing surfaces only.
- The doctor never writes to the database. Read-only.
- The doctor uses indexed `COUNT(*)` queries to keep its DB-lock window
  sub-millisecond on a populated store.
