# ai-memory Troubleshooting

Common errors, causes, and fixes. If your scenario isn't here, check
`journalctl -u ai-memory --since "1 hour ago"` first, then open an
issue at <https://github.com/alphaonedev/ai-memory-mcp/issues>.

## Startup

### "database is locked"

**Symptom**: `ai-memory <cmd>` reports `Error: database is locked`.

**Cause**: Another ai-memory process (CLI, daemon, curator, or sync)
holds the SQLite write lock. SQLite uses a process-global lock; two
writers can't coexist.

**Fix**:

1. List any running ai-memory processes: `ps -ef | grep ai-memory`.
2. If a daemon is running, route your operation through it (HTTP API
   or MCP) instead of the CLI.
3. If you suspect a stale lock, stop every process and check the WAL
   companion files next to the database (`<db>.db-wal` /
   `<db>.db-shm`); they are recovered automatically on the next open.
4. The `busy_timeout` is a compiled 5 s PRAGMA
   (`src/storage/connection.rs`) — it is not operator-tunable. For
   long-running imports that keep hitting the lock, stop the competing
   writer (or route the import through the daemon) instead.

### "could not find embedding model"

**Symptom**: First `recall` or `search` hangs then fails. Log shows
`hf-hub` download errors or `candle` model-load failure.

**Cause**: ai-memory downloads the embedding model lazily on first
semantic recall. First run needs ~90 MB for `all-MiniLM-L6-v2` (or
~270 MB for `nomic-embed-text-v1.5` on `smart`/`autonomous` tiers).
Network or disk issues interrupt the download.

**Fix**:

1. Confirm outbound access to `huggingface.co`.
2. Check `~/.cache/huggingface/hub/` for a partial download. Delete
   the model directory and retry.
3. For air-gapped environments, pre-stage the model via
   `huggingface-cli download sentence-transformers/all-MiniLM-L6-v2`.
4. If you don't need semantic recall, run with `--tier keyword` —
   FTS5-only, zero model load.
5. Post-#1598, CPU-only / egress-restricted hosts can skip the local
   model entirely: point `[embeddings]` at an API backend (any #1067
   alias, or `openai-compatible` for a self-hosted TEI/vLLM/llama.cpp
   `/v1/embeddings` endpoint). See the
   [enterprise reference architectures](reference-architecture/enterprise-cpu-memory.md).

### Semantic recall degraded to keyword — "embedder init failed" / "EMBEDDER LOAD FAILED" (#1593 / #1598)

**Symptom**: stderr shows
`embedder init failed (backend=…, model=…, url=…, source=…): … —
semantic recall DEGRADED to keyword (#1143, #1593, #1598)` (MCP
stdio) or the ERROR-level `EMBEDDER LOAD FAILED` marker (daemon).
`memory_capabilities` reports `embedder_loaded: false` and
`recall_mode_active: "degraded"`.

**Cause**: embedder construction failed — for API backends usually a
wrong `base_url`, a missing/rejected API key, or no network egress;
for local backends a HuggingFace download or memory issue. This is
the **fail-closed** posture (#1593): the substrate keeps serving
keyword/FTS recall and NEVER silently routes embeddings through the
chat LLM client. #1594 makes the degradation truthful at request
time too — a remote embedder whose endpoint starts failing flips
`embedder_loaded` to `false` in live `memory_capabilities` output.

**Fix**:

1. **Run `ai-memory doctor` and inspect the `Embeddings Reachability
   (#1598)` section.** It probes the resolved endpoint (ollama
   `GET /api/tags`; API backends `POST /embeddings` with the
   resolved Bearer key) and reports
   `backend`/`model`/`base_url`/`config_source`/`key_source` plus
   HTTP status — auth (401/403), rate-limit (429), vendor outage
   (5xx), wrong base_url (4xx-other), or network/DNS.
2. If `config_source = compiled-default`, no operator embeddings
   config exists anywhere — set `AI_MEMORY_EMBED_BACKEND` or write
   an `[embeddings]` section
   (see [`docs/CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md)).
3. If `key_source = error(...)`, fix the referenced env var or key
   file perms (mode 0400 required for `api_key_file`).
4. If the section carries a `gpu_policy` WARN, you resolved
   `backend = ollama` on a host with no compatible GPU — operator
   policy is API embeddings on CPU-only nodes; switch the backend or
   move the workload to a GPU node.
5. To silence the degradation deliberately, set `tier = "keyword"`.

### "port 9077 already in use"

**Symptom**: `ai-memory serve` fails immediately with `Address
already in use`.

**Cause**: Another `ai-memory serve`, a development tool, or an old
process from a previous shutdown.

**Fix**:

```bash
# Find the offender
lsof -i :9077
# or
ss -tlpn | grep 9077

# Bind to a different port
ai-memory serve --port 19077
```

## MCP integration

### Claude Code / Desktop / Cursor don't see ai-memory tools

**Symptom**: Restarted the IDE after adding the MCP config; no
`memory_*` tools appear in the tool list.

**Causes + fixes**:

1. **Wrong config path**. Verify:
   - Claude Code: `mcpServers` in `~/.claude.json` (user scope) or
     `.mcp.json` in the project root (NOT `settings.json`).
   - Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).
   - Cursor: Settings → Features → MCP.

2. **JSON syntax error**. Paste the config into `jq '.' file.json`
   to validate.

3. **`ai-memory` not on PATH**. MCP servers inherit the IDE's PATH.
   Absolute path the command: `"command": "/usr/local/bin/ai-memory"`.

4. **Old IDE version**. MCP support landed in Claude Desktop 0.7+,
   Cursor 0.45+, Claude Code 1.0+.

5. **Server crashed on stdio**. Run `ai-memory mcp` manually in a
   terminal; you should see it waiting on stdin. If it exits
   immediately, check stderr for errors.

### "tools/list returned 31 tools, expected 34"

**Symptom**: Integration test fails on MCP tool count.

**Cause**: A new tool landed in `src/mcp/tools/<name>.rs` + `registered_tools()`
in `src/mcp/registry.rs` (#987 D1.6 recipe; pre-#1066 the source was the
monolithic `src/mcp.rs`) without updating the tool-count assertion. Harmless
— it's a test that locks the tool count to prevent accidental removal.
The canonical post-#1187 source is `crate::mcp::tool_names::*` consts +
`Profile::full().expected_tool_count()` in `src/profile.rs`. Update the
assertion to match the new count and add the tool's `tool_names::*` const
reference where the test enumerates expected tools.

### MCP tool returns "no memories found" but `ai-memory list` shows them

**Cause**: The MCP server and the CLI point at different databases.

**Fix**: Every entry point reads `AI_MEMORY_DB`. Set it consistently:

```jsonc
// Claude Code ~/.claude.json (user scope) or .mcp.json (project scope)
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp"],
      "env": { "AI_MEMORY_DB": "/Users/you/ai-memory.db" }
    }
  }
}
```

## Autonomy / curator

### "no LLM client configured" in curator report

**Symptom**: `ai-memory curator --once --json` report shows
`"errors": ["no LLM client configured"]` and zero operations.

**Cause**: The feature tier doesn't wire an LLM, or the configured
backend is unreachable.

**Fix (v0.7.x — preferred)**:

1. **Run `ai-memory doctor` and inspect the `LLM Reachability
   (#1146)` section.** It probes the configured backend (Ollama,
   xAI, OpenAI, Anthropic, etc.) and reports the resolved
   `backend`/`model`/`base_url`/`config_source`/`key_source` plus
   HTTP status. The severity tag (INFO / WARN / CRIT) tells you
   whether the issue is auth (401), rate-limit (429), vendor
   outage (5xx), wrong base_url (4xx-other), or network/DNS/TLS.
2. If `config_source = compiled-default`, no operator LLM config is
   present anywhere. Either set `AI_MEMORY_LLM_BACKEND` (env) or
   write a `[llm]` section in `~/.config/ai-memory/config.toml`
   (see [`docs/CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md)).
3. If `key_source = error(...)`, the resolved API key
   (`api_key_env` / `api_key_file`) couldn't be read — fix the
   referenced env var or file perms (0400 required for
   `api_key_file` by default).
4. Check the feature tier: `curator` has no `--tier` flag — it reads
   the `tier` field from `config.toml`. Set `tier = "smart"` (or
   `"autonomous"`) there and re-run.

**Fix (legacy v0.6.x flat-field config)**:

If you're still on v0.6.x flat fields (`llm_model`, `ollama_url`),
the deprecation WARN at config-load tells you it's time to migrate:

```bash
ai-memory config migrate --dry-run    # preview the v2 shape
ai-memory config migrate              # apply with timestamped .bak
ai-memory doctor                      # verify LLM Reachability
```

The legacy fields continue to work in v0.7.x but will be removed in
v0.8.0.

### Curator cycle times are long (> 10 min)

**Cause**: Each eligible memory triggers an Ollama round-trip (~1–5 s).
With a large corpus and `--max-ops 100`, a cycle can take 5–10 min.

**Fix**:

- Lower `--max-ops` to fit your cycle budget.
- Enable Ollama KV compression (`OLLAMA_KV_CACHE_TYPE=q4_0`) to
  speed up each call. See `docs/RUNBOOK-ollama-kv-tuning.md`.
- Run `--daemon --interval-secs 3600` and let it catch up slowly.

### Curator made a bad call — how to undo it

```bash
# See the last 20 actions
ai-memory list --namespace _curator/rollback --limit 20

# Reverse a specific one
ai-memory curator --rollback <id>

# Reverse the last 5
ai-memory curator --rollback-last 5
```

Reversed entries are **tagged** `_reversed`, not deleted — the audit
trail is preserved.

## HTTP API

### "401 missing or invalid API key"

**Cause**: The daemon has an `api_key` configured (the `api_key` field
in `config.toml` — there is no `--api-key` serve flag). Pass the key:

```bash
curl -H "X-API-Key: YOUR_KEY" http://127.0.0.1:9077/api/v1/stats
# or (DEPRECATED #1574 — URL keys leak into access/proxy logs;
# accepted with a WARN at v0.7.0, slated for v0.8 rejection)
curl 'http://127.0.0.1:9077/api/v1/stats?api_key=YOUR_KEY'
```

`/api/v1/health` is always exempt — use it as a reachability probe.

### "500 Internal Server Error" with no body

**Cause**: Error-sanitisation strips stack traces from production
responses to avoid leaking internals.

**Fix**: Check the daemon log (`journalctl -u ai-memory`) for the
full error. If running in foreground, look at stderr. Raise verbosity
with `RUST_LOG=ai_memory=debug`.

### "503 quorum_not_met" on every write

**Cause**: Federation is configured (`--quorum-writes N --quorum-peers …`)
but peers are unreachable or slow.

**Diagnosis**:

1. Body carries `{"got":X,"needed":Y,"reason":"…"}`. `reason`:
   - `unreachable` — no peers responded at all (network / DNS).
   - `timeout` — some peers acked but not enough before
     `--quorum-timeout-ms`.
   - `id_drift` — peers returned different memory ids (replication
     divergence).
2. Curl each peer directly: `curl https://peer-a:9077/api/v1/health`.
3. Check peer mTLS allowlist — your fingerprint may not be listed.

**Fix**: lower `--quorum-writes` temporarily, restore peer
connectivity, restart with the original setting. For `timeout` on a
**cross-region** mesh, raise `--quorum-timeout-ms` — the 2000 ms
default is same-DC-tuned; WAN meshes need 5000-10000 ms (the do-1461
3-region reference deploy uses `FED_QUORUM_TIMEOUT_MS=8000`; see
[#1565](https://github.com/alphaonedev/ai-memory-mcp/issues/1565)).
The write commits locally first, so the longer wait affects only the
synchronous-durability gate.

## Sync / federation

### Memories stop syncing between peers

**Cause**: Multiple possibilities.

**Diagnosis**:

1. On each peer: `ai-memory sync-daemon` must be running.
   `systemctl status ai-memory-sync` or check the log.
2. Divergence check: run `ai-memory stats` on each peer and compare
   the `total` counts; the per-peer vector clock lives in the
   `sync_state` table
   (`sqlite3 <db> "SELECT * FROM sync_state"`).
3. mTLS fingerprint drift: if you rotated certs, the allowlist must
   be regenerated on every receiver.
4. `--batch-size 500` default may be too small for a backlog. Bump to
   `5000` temporarily.

### Split-brain: two peers diverged

**Cause**: Network partition. Both halves accepted writes. Now they
disagree on `(title, namespace)` content.

**Fix**: Decide which side is authoritative. On that side, run
`ai-memory export > snapshot.json`. On the other side,
`ai-memory import --trust-source < snapshot.json`. The upsert on
`(title, namespace)` will overwrite the divergent copies with the
authoritative ones.

Per-namespace conflict resolution is an open work item (sync-phase
Layer 2b).

### Federation push-DLQ backlog / quarantined rows {#federation-push-dlq}

**Symptom**: the daemon logs
`replay: row N quarantined after 100 attempts (ceiling 100)` and/or
the `federation_push_dlq_depth` gauge stays high.

Failed quorum pushes land in the `federation_push_dlq` table and a
background worker replays them (oldest first, batches per tick). The
per-tick batch is **adaptive** (#1579 B5): it scales with the live
backlog up to a cap (`min(backlog, cap)`, floor 64; cap default 2048,
operator-tunable via `AI_MEMORY_FED_DLQ_REPLAY_MAX_BATCH`), so a bulk
backlog drains at thousands of rows/min instead of the historical
fixed-64 ceiling of 128 rows/min/peer. Replays reuse the daemon's
pooled federation connections (no per-row TLS handshake), and the
captured payload ships the source embedding vector when one was
available at enqueue time (#1566), so a healthy receiver applies a
replayed row in milliseconds — receivers **no longer re-embed
synchronously on receive** (the pre-#1566 ~1 s/row embed-on-receive
that inflated replay latency and quorum deadlines is gone; rows
without a usable shipped vector are embedded by a background task
after the ack).
Rows that fail `MAX_REPLAY_ATTEMPTS` (100) times are *quarantined*:
the take query excludes them (#1578) and they wait for operator
review. **No CLI drain surface ships at v0.7.0** — inspection and
drain are direct SQL against the daemon's store:

```sql
-- Inspect (postgres-backed daemons: table lives in the daemon's
-- schema, e.g. ic_peer_1.federation_push_dlq on shared fleets):
SELECT attempt_count, count(*), max(left(last_error, 60))
FROM federation_push_dlq WHERE replayed_at IS NULL GROUP BY 1;

-- Drain quarantined rows after confirming the target memories
-- already converged (compare distinct memory counts across peers, or
-- GET each memory_id on the destination peer). Marking replayed
-- retains the rows for audit; deleting is equivalent operationally:
UPDATE federation_push_dlq SET replayed_at = now()
WHERE replayed_at IS NULL AND attempt_count >= 100;
```

A large backlog of *replayable* (below-ceiling) rows whose memories
already converged via async catch-up (e.g. a historical quota-429
burst) can be drained the same way — drop the `attempt_count`
predicate after verifying convergence. The replay worker handles
everything else on its own.

## Performance

### `recall` is slow (> 2 s)

**Common causes**:

1. **First semantic recall after startup** — model load is ~500 ms
   cold. Warm up with a throwaway recall call.
2. **Async-boot HNSW warm window (#1579 B3)** — `serve` and `mcp`
   become ready immediately and build the HNSW index in the
   background; until the swap lands, semantic recall serves the
   keyword/FTS blend (correct, but ranked without the vector phase)
   and can look "worse" or slower on big corpora. Watch for the
   readiness line: `serve` logs INFO `HNSW index warm (#1579 B3)`;
   `mcp` prints `ai-memory: HNSW index ready (N entries, warmed in
   X.Xs)` on stderr. One-shot `ai-memory recall` CLI invocations skip
   the graph build entirely below 20k embedded rows
   (`hnsw::CLI_HNSW_BUILD_MIN_ENTRIES`) and linear-scan instead —
   that path is expected to answer in tens of ms, not to build an
   index.
3. **Disk I/O bottleneck** — `iostat 1` to confirm. Move DB to SSD.
4. **SQLite contention under concurrent writes** — use `stats`
   output to see WAL size. If the daemon is doing a lot of writes,
   recall waits.

### Memory usage grows unbounded

**Cause**: HNSW index size grows with the number of memories. At
~100k memories × 384-dim vectors × 4 bytes = ~150 MB just for the
index.

**Fix**:

- Aggressive `gc` + reduce retention on `short` tier.
- Move to Postgres + pgvector for out-of-process index
  (`--features sal-postgres`, v0.7) — the canonical answer at
  100k+ memory scale.

## Governance

### My action returned "202 Accepted" but nothing happened

**Cause**: Governance requires an approval. Your action is in the
pending queue.

**Fix**:

```bash
# List pending
ai-memory pending list --status pending

# Approve (requires registered approver)
ai-memory pending approve <pending-id>

# Or reject
ai-memory pending reject <pending-id>
```

Consensus rules require multiple distinct registered agents — see
`docs/ADMIN_GUIDE.md` § "Governance".

## Still stuck?

1. Run `ai-memory stats --json` and attach to the issue.
2. Attach the last 50 lines of `journalctl -u ai-memory`.
3. State your tier (`ai-memory curator --once --dry-run --json` shows
   effective tier + errors).
4. Open <https://github.com/alphaonedev/ai-memory-mcp/issues>.
