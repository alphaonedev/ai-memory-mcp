# Production Deployment Guide

**Audience:** operators standing up `ai-memory` for real workloads — single-instance, hub-spoke teams, or W-of-N federations. **Reading time:** 10 minutes.

This guide collects the must-do steps for a hardened deployment. It assumes you have the binary on disk (`brew install alphaonedev/tap/ai-memory`, `cargo install ai-memory`, `sudo dpkg -i ai-memory_<ver>_<arch>.deb` from the GH release, COPR `dnf install ai-memory`, or `docker pull ghcr.io/alphaonedev/ai-memory:latest`) and a host with persistent storage. For the threat model and disclosure policy see [`SECURITY.md`](../SECURITY.md). For telemetry and observability see [`telemetry.md`](telemetry.md).

---

## 1. Operator responsibilities

`ai-memory` is operator-controlled substrate. The binary does not phone home, does not auto-update, and does not register your deployment with any central registry. Five things only you can decide:

1. **Identity material.** Generate Ed25519 keypairs per agent (Section 2). Private keys never leave the host; you decide the rotation cadence.
2. **mTLS allowlist.** Federation refuses any peer whose Ed25519 public key is not on your allowlist (Section 3). Allowlists are mutual.
3. **Storage backend.** SQLite (default, single-instance, WAL mode) or PostgreSQL with Apache AGE (multi-writer hub-spoke). The substrate is the same; the operational profile differs.
4. **Topology.** Single-instance, hub-spoke, or W-of-N federation (Section 7).
5. **Backup discipline.** No data leaves the host without your action — that includes losing it. Schedule snapshots (Section 4).

The remaining sections are mechanical: keypairs, allowlist, backups, migrations, observability, topology, upgrades.

---

## 2. Keypair provisioning

Every agent in a deployment needs its own Ed25519 keypair. The CLI never auto-generates one for you — generation is explicit so a typo cannot silently rotate a long-lived peer.

```bash
ai-memory identity generate --agent-id alice@team-finance
ai-memory identity generate --agent-id bob@team-finance
ai-memory identity list
ai-memory identity export-pub --agent-id alice@team-finance
```

Default storage paths (overridable with `--key-dir` or `AI_MEMORY_KEY_DIR`):

- **Linux:** `~/.config/ai-memory/keys/`
- **macOS:** `~/Library/Application Support/ai-memory/keys/`
- **Windows:** `%APPDATA%\ai-memory\keys\`

Files land with strict permissions on Unix (`0600` private key / `0644` public key). `generate` refuses an existing `--agent-id` unless you pass `--force` — rotation is opt-in. Two agents sharing a keypair is a configuration error; the substrate cannot detect it but every audit chain you produce afterwards will be ambiguous about provenance.

Hardware-backed key storage (TPM 2.0, PKCS#11 HSMs, Apple Secure Enclave, cloud KMS adapters) is intentionally out of OSS scope and ships in the commercial tier.

---

## 3. mTLS allowlist bootstrap

Federation peers exchange signed messages over mTLS. The allowlist is the operator's source of truth for which peers may speak with this node.

```bash
# Export local public key
ai-memory identity export-pub --agent-id alice@team-finance > alice.pub

# Out-of-band: send alice.pub to bob, receive bob.pub
ai-memory identity import --agent-id bob@team-finance --pub bob.pub
```

After import, the allowlist is mutual: alice's node only accepts inbound federation messages signed by bob's key, and vice versa. A peer presenting a key not on the allowlist is rejected at the handshake — no log record of the message contents is created, only a metric increment.

Allowlist format: a directory of public-key files keyed by agent id. There is no central allowlist file to corrupt; adding or removing a peer is `ai-memory identity import`/`rm`. Audit your allowlist with `ai-memory identity list` whenever you suspect drift.

---

## 3b. HTTP API key authentication

The HTTP daemon takes an optional shared API key from the `api_key` field of `~/.config/ai-memory/config.toml` (there is no `--api-key` CLI flag on `serve`; container deployments inject it via the `AI_MEMORY_API_KEY` env consumed by `entrypoint.plan-c.sh`, which renders it into the config file). When set, every endpoint except `/api/v1/health` requires the key; `AI_MEMORY_REQUIRE_API_KEY=1` additionally hard-refuses daemon start without a key on ANY bind host, including loopback ([#1458](https://github.com/alphaonedev/ai-memory-mcp/issues/1458)) — set it for reverse-proxy / `--network=host` deployments.

**The supported credential channel is the `x-api-key` request header** (constant-time compared in `handlers::transport::api_key_auth`). The `?api_key=` query-parameter form is **deprecated** ([#1574](https://github.com/alphaonedev/ai-memory-mcp/issues/1574)): a credential in the URL leaks into access logs, `Referer` headers, and proxy logs, all of which may outlive your key-rotation window. At v0.7.0 the query form is still accepted for back-compat and emits a once-per-process operator-visible WARN on first use; v0.8 is slated to reject it outright, with a temporary opt-back-in escape hatch for callers that cannot migrate in time. Migrate callers to the header now:

```bash
curl -H "x-api-key: $KEY" http://127.0.0.1:9077/api/v1/stats   # supported
curl "http://127.0.0.1:9077/api/v1/stats?api_key=$KEY"         # deprecated — logs capture it
```

mTLS-authenticated federation peers bypass the api-key check on `/api/v1/sync/*` only (they have already cleared a stronger gate; see [`federation.md`](federation.md)).

---

## 4. Backup and restore

SQLite deployments use `ai-memory backup` (a `VACUUM INTO` wrapper that emits a defragmented snapshot plus a sha256 manifest):

```bash
ai-memory backup --to /var/backups/ai-memory --keep 48
ai-memory restore --from /var/backups/ai-memory   # uses newest snapshot
```

`--keep` rotates oldest-first. The manifest pins the snapshot's sha256, byte size, source-DB path, and binary version that produced it. `restore` verifies the sha256 before swapping the target file in. Pass `--skip-verify` only if you have already verified out-of-band — the flag exists for restoring from cold storage that has been re-hashed by a separate tool, not as a routine bypass.

PostgreSQL deployments use the standard tooling:

```bash
pg_dump --format=custom ai_memory > ai-memory-$(date -u +%Y%m%dT%H%M%SZ).pgdump
pg_restore --clean --create --dbname=postgres ai-memory-<timestamp>.pgdump
```

**Post-restore verification.** v0.7.0 ships two ad-hoc verifiers: `ai-memory verify-reflection-chain <memory_id>` (L1-3 — walks `reflects_on` edges backward to depth 0 and verifies each Ed25519 signature; exit 0 on a fully-verified chain) and `ai-memory verify-signed-events-chain --format json` (V-4 — walks the cross-row `signed_events` hash chain; `chain_holds: true` is the pass signal). Run both against the restored database before promoting it.

Backup cadence target: hourly snapshots, 48-hour rotation, weekly off-host transfer to a separate failure domain. Sizing: a 1 GB SQLite file produces a ~700-900 MB snapshot after `VACUUM INTO`.

---

## 5. Schema migrations

Migrations are forward-only and run automatically on the first daemon start after an upgrade. There is no offline migration step. The substrate refuses to start against a database newer than the binary expects (downgrade refusal) and progresses through every intermediate version on upgrade — never skips.

**Forward-only is by design; snapshot-restore is the rollback** ([#1576](https://github.com/alphaonedev/ai-memory-mcp/issues/1576)). Before any schema-mutating upgrade runs, the binary automatically snapshots the live SQLite file as a sibling of the database: `<db-file>.pre-migration-v<FROM>-to-v<TO>-<token>.bak` (`snapshot_before_migration` / `PRE_MIGRATION_BACKUP_INFIX` in `src/storage/migrations.rs`). The snapshot is produced with `VACUUM INTO` — transactionally consistent, folds pending WAL frames, inherits the source's SQLCipher keying — and the migration refuses to mutate the schema if the snapshot fails. To roll back: stop the daemon, reinstall the previous binary, copy the `.pre-migration-…bak` snapshot over the live DB file (removing stale `-wal`/`-shm` siblings), and start. See [`ADMIN_GUIDE.md` §Migration](ADMIN_GUIDE.md) for the step-by-step procedure.

There is no offline dry-run preview for the schema ladder itself (the existing `ai-memory migrate --dry-run` in `--features sal` builds is the *cross-backend copy tool*, not a schema-migration preview). The recommended workflow on a major-version upgrade is:

1. Take a snapshot (`ai-memory backup --to <path>`).
2. Start the new binary against a copy of the snapshot in a scratch directory.
3. Observe the migration log; the binary writes one INFO line per schema-version step.
4. Promote the new binary against the live database only after the scratch migration completes cleanly.

Migration failures roll back; the database is never left in a half-migrated state. If a migration aborts mid-way the binary refuses to serve and prints the offending schema-version transition.

---

## 6. Observability

Out-of-the-box observability lands in three places:

- **Tracing spans on stderr.** Every MCP tool call, every governance decision, every federation event emits a `tracing::info!` span. `RUST_LOG=ai_memory=info` is the default; `RUST_LOG=ai_memory=debug` for deep traces. Note (post-#1562, 2026-06-09): the postgres SAL adapter emits under the literal targets `store::postgres` / `store::postgres::kg`, which an `ai_memory=...` filter does not match — postgres-backed deployments wanting those events must add e.g. `store::postgres=debug` to the filter.
- **File logging.** Opt-in via `[logging]` in `config.toml` (path, rotation size, retention days, `structured = true` for JSON). Routes to a rotating appender; off by default.
- **`ai-memory doctor`.** A 9-section health dashboard run locally at v0.7.0: Storage / Index / Recall / Governance / Sync / Webhook / Capabilities / Reflection Health / LLM Reachability (#1146). Nothing leaves the host except the opt-in LLM reachability probe against your configured backend.

Hooks (`pre_store`, `post_store`, `post_recall`, `pre_governance_decision`, etc. — 25 lifecycle events, see [`hook-pipeline.md`](hook-pipeline.md)) are the supported extension surface for routing events to a SIEM, paging an operator, or short-circuiting writes. See [`docs/integrations/`](integrations/) and [`telemetry.md`](telemetry.md).

---

## 7. Deployment topologies

**Single-instance.** One host, SQLite, WAL mode. Defaults are correct. This is the recommended starting topology for any deployment under ~5 agents or under ~10 GB of stored memories.

**Hub-spoke (team).** One PostgreSQL+AGE hub, N spoke agents pushing federated memories on a schedule. The hub is the source of truth for cross-agent recall; spokes hold their own local SQLite for offline work. mTLS allowlist on the hub names every spoke; spokes have an allowlist of one entry (the hub).

**W-of-N federation.** Three or more peers, each holding its own SQLite, mesh-federating writes with a quorum commit requiring the local write plus W−1 peer acknowledgements within `--quorum-timeout-ms` before the write returns OK (per [`ADR-0001`](ADR-0001-quorum-replication.md); per-message Ed25519 signing rides on `AI_MEMORY_FED_REQUIRE_SIG`). Default 2000 ms assumes same-DC peers; cross-region (WAN) meshes need 5000-10000 ms — the do-1461 reference deployment uses 8000 (#1565). Resolves the "any single operator can rewrite history" problem. CRDT-based eventual consistency by default; opt-in MVCC strict-consistency mode ships in v1.0.

Sizing guide (Apple M2, 16 GB, SQLite reference):

| Topology | Agents | Stored memories | Notes |
|---|---|---|---|
| Single | 1-5 | up to 1M | WAL mode, BLOB content paged on demand |
| Hub-spoke | 5-50 | up to 10M | Postgres+AGE hub, SQLite spokes |
| W-of-N | 3-9 peers | up to 1M per peer | Federation broadcasts dominate at high write rates |

---

## 7b. LLM backend wiring (smart / autonomous tier)

If your deployment uses `--tier smart` or `--tier autonomous`, the
substrate needs an LLM backend. Two wire shapes apply, with **different
discoverability stories** for the env vars:

- **HTTP daemon (`ai-memory serve`).** The daemon inherits the env of
  the user / systemd unit / Docker container that launched it. Setting
  `AI_MEMORY_LLM_BACKEND` / `AI_MEMORY_LLM_API_KEY` / `AI_MEMORY_LLM_MODEL`
  in the unit file's `Environment=` / `EnvironmentFile=` directives (or
  in the container's `ENV` / `--env-file`) is the canonical pattern.
  Shell exports work for interactive launch but not for systemd /
  Docker / Kubernetes — those have their own env contracts.
- **MCP servers (`ai-memory mcp`).** Spawned by AI clients (Claude
  Code, Claude Desktop, Cursor, Codex CLI, Cline, Continue, Zed,
  Windsurf, Goose, Roo Code, etc.) as a **fresh subprocess** with only
  the `env:` keys declared in the MCP server config. Shell exports
  from `.zshrc` / `.bashrc` / `.profile` are NOT visible. This was the
  operator paper-cut behind [#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144).
- **Curator daemon (`ai-memory curator --daemon`).** A long-running
  background tagger, almost always started by a service manager
  (launchd LaunchAgent on macOS, systemd unit on Linux). Like `serve`,
  it inherits ONLY the unit/plist env — **not** your login-shell
  exports. A curator that can't resolve its key fails open: it reports
  `key_source=error`, disables the LLM client, and logs `tagged=0`
  every cycle with no louder error. Wire its key the same way as
  `serve` (below).

**Env-independent option (recommended for service daemons).** Rather
than threading the key through each launcher's env contract, point
`[llm].api_key_file` at a `0400` key file in `config.toml`:

```
# ~/.config/ai-memory/config.toml
[llm]
backend = "openrouter"
api_key_file = "/etc/ai-memory/openrouter-api.key"  # mode 0400
```

This resolves identically under launchd, systemd, Docker, and an
interactive shell — no per-platform `Environment=` / `EnvironmentVariables`
plumbing required.

For MCP usage, the LLM env vars MUST live inside the MCP server
config's `env:` block. Copy-pasteable per-backend recipes (Ollama,
LMStudio, vLLM, llama.cpp server, xAI, OpenAI, Anthropic, Gemini,
DeepSeek, Kimi, Qwen, Mistral, Groq, Together, Cerebras, OpenRouter,
Fireworks) + multi-agent / multi-DC / fleet considerations:
[`integrations/llm-backends.md`](integrations/llm-backends.md).

Fleet rollout pattern (systemd):

```
# /etc/systemd/system/ai-memory.service
[Service]
EnvironmentFile=/etc/ai-memory/llm.env
# NOTE: `serve` does NOT accept a --tier flag — the daemon's tier comes
# from the `tier` field in config.toml (compiled default: semantic).
ExecStart=/usr/local/bin/ai-memory serve --store-url postgres://...
User=ai-memory
Group=ai-memory
```

```
# /etc/ai-memory/llm.env  (chmod 0640, owned by root:ai-memory)
AI_MEMORY_LLM_BACKEND=xai
AI_MEMORY_LLM_API_KEY=xai-...
AI_MEMORY_LLM_MODEL=grok-4.3
```

For fleet deployments managed via Ansible / Chef / Puppet / Salt / Nix,
render `/etc/ai-memory/llm.env` from a template and pull the secret
from your vault. Rotation = vault rotate + `systemctl restart
ai-memory`.

macOS launchd (curator daemon) pattern:

```
<!-- ~/Library/LaunchAgents/dev.alphaone.ai-memory.curator.plist -->
<!-- The GUI launchd domain does NOT inherit a shell `export
     OPENROUTER_API_KEY`. Either use [llm].api_key_file (above), or
     declare the key var inside this EnvironmentVariables dict: -->
<key>EnvironmentVariables</key>
<dict>
  <key>OPENROUTER_API_KEY</key>
  <string>sk-or-...</string>
</dict>
```

The full curator plist (ProgramArguments, KeepAlive, ProcessType) lives
in [`batman-active-mode.md` § Making it permanent](batman-active-mode.md#making-it-permanent).

For multi-DC deployments with regional cloud LLM endpoints, override
the per-alias default URL with `AI_MEMORY_LLM_BASE_URL`. See
[`integrations/llm-backends.md` § Multi-DC / multi-region](integrations/llm-backends.md#multi-dc--multi-region--regional-cloud-endpoints).

---

## 8. Upgrades

The canonical upgrade sequence:

```bash
# 1. Snapshot the live database
ai-memory backup --to /var/backups/ai-memory

# 2. Stop the daemon
systemctl stop ai-memory   # or pkill, brew services stop, etc.

# 3. Install the new binary (channel-appropriate command)
brew upgrade ai-memory     # or apt, dnf, cargo install --force, docker pull

# 4. Start the daemon; migrations run automatically
systemctl start ai-memory

# 5. Verify
ai-memory doctor
```

Rollback: stop the daemon, restore the pre-upgrade snapshot, downgrade the binary. The substrate refuses to start against a database newer than the binary expects, so a partial rollback fails loudly rather than silently corrupting data.

---

## See also

- [`SECURITY.md`](../SECURITY.md) — threat model, disclosure policy
- [`telemetry.md`](telemetry.md) — what the binary emits, where it goes, what it does not do
- [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md) — SQLite-to-Postgres migration
- [`RUNBOOK-chaos-campaign.md`](RUNBOOK-chaos-campaign.md) — operator drill for partition + power-loss recovery
- [`../cookbook/production-deployment/01-secure-bootstrap.sh`](../cookbook/production-deployment/01-secure-bootstrap.sh) — runnable end-to-end demo of Sections 2-4 + 7
