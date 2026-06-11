# `ai-memory` v0.6.x → v0.7.0 migration quickstart

**Purpose.** The shortest, safest path to upgrade an existing
`ai-memory` install from v0.6.x to v0.7.0. Three tiers — pick the
one that matches your role:

- **[Tier 1](#tier-1--non-technical-end-user-5-steps)** — Non-technical end user (Claude Code / Cursor / local MCP only, 5 commands)
- **[Tier 2](#tier-2--sme--admin--architect-10-steps)** — SME / admin / architect (multi-host fleet, NFS-shared config, staged security flips)
- **[Tier 3](#tier-3--devops--iac-idempotent-shell)** — DevOps / IaC (idempotent shell snippet for ansible / terraform / CI)

All three converge on the **same underlying steps**:

1. Stop the existing daemon
2. Back up the DB
3. Install v0.7.0 binary
4. Migrate config (one command)
5. Restart + verify

The differences are only in fleet orchestration, security-posture
staging, and idempotency framing. **The DB schema migration
(v20 → v55) is fully automatic on first open** — no operator
action required for the database itself.

> **Compatibility statement.** v0.7.0 is **backward-incompatible
> at the DB schema layer past v34** (sqlite). Once a v0.7.0 binary
> opens a v0.6.x DB and walks it to v55, a v0.6.x binary will refuse
> to open it. **Always back up the DB before upgrading.** Cross-binary
> alternation is not supported. (The migrator also takes an automatic
> pre-migration snapshot next to the DB —
> `<db>.pre-migration-v<from>-to-v<to>-<token>.bak`, produced via
> `VACUUM INTO` — restoring that snapshot is the supported rollback;
> migrations themselves are forward-only.)

---

## What changed in v0.7.0 (executive summary)

| Area | v0.6.4 | v0.7.0 |
|---|---|---|
| **LLM backends** | Local Ollama only | **15 vendor aliases** + generic OpenAI-compatible (#1067): ollama, openai, xai, anthropic, gemini, deepseek, kimi, qwen, mistral, groq, together, cerebras, openrouter, fireworks, lmstudio, openai-compatible |
| **Config schema** | Flat fields (`llm_model`, `ollama_url`, ...) | **Sectioned v2** (`[llm]`, `[llm.auto_tag]`, `[embeddings]`, `[reranker]`, `[storage]`) — see [`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md). Legacy v1 continues to work with deprecation WARN; removed in v0.8.0. |
| **Secret handling** | Inline `api_key = "..."` accepted | **REJECTED at parse time** (#1146). Use `api_key_env` (env var reference) or `api_key_file` (mode 0400 enforced). |
| **DB schema** | v20 | v55 (35 version bumps bridge the gap, auto-applied on first open) |
| **Memory struct** | 15 fields | 26 fields (added reflection_depth, memory_kind, entity_id, persona_version, citations, source_uri, source_span, confidence_source, confidence_signals, confidence_decayed_at, version) |
| **MemoryLink variants** | 4 (related_to, supersedes, contradicts, derived_from) | 6 (+ reflects_on, derives_from) |
| **MCP tools at `--profile full`** | ~60 | **74** (73 callable + memory_capabilities bootstrap) |
| **MCP tools at `--profile core`** | 5 | **7** (added memory_load_family + memory_smart_load) |
| **CLI subcommands** | 40 | **79** in the default build, **81** with `--features sal` (adds `migrate` + `schema-init`) — added `config migrate`, `atomise`, `persona`, `skill <…>`, `verify-signed-events-chain`, `expand`, `recover-previous-session`, … |
| **`ai-memory doctor`** | 7 sections | **10 sections** (+ Reflection Health + LLM Reachability; #1598 added Embeddings Reachability) |
| **Permissions mode default** | `advisory` | **`enforce`** (#K3 governance gate) — set `AI_MEMORY_PERMISSIONS_MODE=advisory` to preserve v0.6.x posture during rollout |
| **Federation sig required** | Off | **On by default** (`AI_MEMORY_FED_REQUIRE_SIG=1`) — set `=0` during peer Ed25519-key enrolment |
| **Federation nonce required** | Off | **On by default** (`AI_MEMORY_FED_REQUIRE_NONCE=1`) — set `=0` for legacy senders |
| **SSRF DNS-fail posture** | Open | **Closed** (`AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=0`) — set `=1` if you operate against a flaky internal resolver |
| **Governance fail-open on error** | Open | **Closed** (`AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0`) — set `=1` if you operate a custom rule provider |
| **Passphrase file permissions** | Unenforced | **Mode 0400 required** (`AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=0`) — `chmod 0400 passphrase.txt` or set `=1` |
| **Boot banner LLM field** | `llm=gemma3:4b` | `llm=<backend>:<model>` when backend != ollama; legacy shape preserved when backend == ollama |

---

## Tier 1 — Non-technical end user (5 steps)

For solo developers with one MCP server (Claude Code / Cursor /
Codex CLI) on macOS or Linux. No fleet, no NFS, no Postgres.

```bash
# 1. Stop ai-memory (whichever launcher you use). Pick ONE:
pkill -INT ai-memory                                                  # CLI-launched
launchctl unload ~/Library/LaunchAgents/<your-ai-memory>.plist        # macOS launchd (if you created a LaunchAgent)
systemctl --user stop ai-memory                                       # Linux systemd
#    (If you launch via Claude Code's MCP config, just close Claude Code.)

# 2. Back up the DB
cp ~/.claude/ai-memory.db{,.v064.bak}      # or wherever your DB lives;
                                            # default v0.7.0 path is the same

# 3. Install v0.7.0 (pick ONE channel)
#    a) Homebrew (after the v0.7.0 release lands on alphaonedev/homebrew-tap):
brew upgrade ai-memory
#    b) Pre-built binary — release assets are named by Rust target triple:
#       ai-memory-x86_64-unknown-linux-gnu.tar.gz, ai-memory-aarch64-unknown-linux-gnu.tar.gz,
#       ai-memory-x86_64-apple-darwin.tar.gz, ai-memory-aarch64-apple-darwin.tar.gz,
#       ai-memory-x86_64-pc-windows-msvc.zip. Example (Linux x86_64):
curl -fsSL "https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz -C ~/.local/bin
#    c) From source (until v0.7.0 ships on crates.io):
cargo install --git https://github.com/alphaonedev/ai-memory-mcp \
  --tag v0.7.0 --locked ai-memory

# 4. Migrate config + scrub the now-redundant ~/.claude.json env block
ai-memory config migrate --also-clean-claude-json

# 5. Restart + verify
#    (Restart your MCP host — Claude Code / Cursor / etc — to pick up
#    the new binary. Then verify wiring end-to-end:)
ai-memory doctor
```

**Expected `ai-memory doctor` output**: 9 INFO sections, no CRIT.
The `LLM Reachability (#1146)` section reports the resolved
`backend`, `model`, `base_url`, `config_source`, `key_source` +
HTTP status. If you see WARN or CRIT there, see
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) §"no LLM client configured".

**That's it.** The DB schema walks v20 → v55 automatically when
the v0.7.0 binary opens the DB. Your legacy config.toml's flat
fields have been rewritten to the v2 sectioned shape; a
timestamped backup lives next to the original.

---

## Tier 2 — SME / admin / architect (10 steps)

For fleets of ~10 hosts with NFS-shared `config.toml`, staged
security-posture rollout, and federation-peer enrolment windows.

### Pre-flight

```bash
# 0. Read CONFIG_SCHEMA.md (the canonical v2 schema reference).
#    Read this MIGRATION_QUICKSTART.md and the "What changed" matrix above.
#    Verify your fleet inventory: hostnames, MCP launcher per host,
#    federation peer list (if any), Postgres backend deployments.
```

### Steps

```bash
# 1. Drain + snapshot per host (run on every fleet member).
#    There is no `ai-memory stop` subcommand — stop via your service
#    manager (or pkill -INT for shell-launched daemons):
for H in $FLEET; do
  ssh "$H" "systemctl --user stop ai-memory && cp ~/.local/share/ai-memory/ai-memory.db{,.v064.bak}"
done

# 2. NFS-shared config.toml — migrate ONCE on the leader, then rsync.
#    (The migrator writes a timestamped .bak; running on N hosts in
#    the same second produces colliding backup filenames.)
LEADER=${FLEET%% *}
# (--dry-run prints the diff to stderr — redirect 2>&1 to capture it)
ssh "$LEADER" "ai-memory config migrate --dry-run 2>&1 | tee ~/v07-config-diff.txt"
# Review the diff. When satisfied:
ssh "$LEADER" "ai-memory config migrate"

# 3. Distribute the rewritten config.toml across the fleet
for H in $FLEET; do
  rsync /nfs/ai-memory/config.toml "$H:/nfs/ai-memory/"
done

# 4. Install v0.7.0 on every host. Assets are named by Rust target
#    triple (e.g. ai-memory-x86_64-unknown-linux-gnu.tar.gz). Pin the
#    expected sha256 per target in your fleet inventory and verify it.
for H in $FLEET; do
  ssh "$H" 'set -e
    TARGET=x86_64-unknown-linux-gnu   # adjust per host arch
    curl -fsSL https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-${TARGET}.tar.gz -o ./m.tgz
    echo "${EXPECTED_SHA256}  ./m.tgz" | sha256sum -c -
    tar -xzf ./m.tgz -C /usr/local/bin/
  '
done

# 5. Stage security-posture defaults — temporarily PERMISSIVE so the
#    fleet boots cleanly while peers/agents/policies enrol the new
#    secure-by-default surface. Set in /etc/ai-memory/env (or
#    equivalent systemd EnvironmentFile):
cat >> /etc/ai-memory/env <<'EOF'
# v0.6.x → v0.7.0 staged rollout — flip these back to '1' / '0'
# after fleet enrolment completes (Step 10 below).
AI_MEMORY_FED_REQUIRE_SIG=0
AI_MEMORY_FED_REQUIRE_NONCE=0
AI_MEMORY_PERMISSIONS_MODE=advisory
AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1
AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1
EOF
# (Skip individual lines if your fleet was already strict at v0.6.x.)

# 6. Migrate governance → permissions (v0.7.0 K9/K11 policy refactor).
#    Default (no --config-out) prints the rendered [[permissions.rules]]
#    block without writing; --config-out <config path> merges in place.
ai-memory governance migrate-to-permissions               # preview (dry-run)
ai-memory governance migrate-to-permissions \
  --config-out ~/.config/ai-memory/config.toml            # apply in place

# 7. Start the fleet — DB walks v20 → v55 on first open
for H in $FLEET; do ssh "$H" 'systemctl --user start ai-memory'; done

# 8. Verify per host (the JSON report's pass field is `chain_holds`)
for H in $FLEET; do
  ssh "$H" 'ai-memory doctor && \
            ai-memory verify-signed-events-chain --format json | jq -e .chain_holds'
done

# 9. Provision federation Ed25519 keypairs across the fleet
for H in $FLEET; do
  ssh "$H" "ai-memory identity generate --agent-id ai:daemon@$H"
  # ... and distribute peer pubkeys via your existing key-distribution
  # channel (operator.key.pub, .well-known, signed allowlist, etc.)
done

# 10. Flip security defaults back to the v0.7.0 secure posture
sed -i 's/AI_MEMORY_FED_REQUIRE_SIG=0/AI_MEMORY_FED_REQUIRE_SIG=1/
        s/AI_MEMORY_FED_REQUIRE_NONCE=0/AI_MEMORY_FED_REQUIRE_NONCE=1/
        s/AI_MEMORY_PERMISSIONS_MODE=advisory/AI_MEMORY_PERMISSIONS_MODE=enforce/
        s/AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1/AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0/
        s/AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1/AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=0/' \
       /etc/ai-memory/env
for H in $FLEET; do ssh "$H" 'systemctl --user restart ai-memory && ai-memory doctor'; done
```

### Postgres / Apache AGE / pgvector deployments

If you run `ai-memory serve --store-url postgres://…` with the
`sal-postgres` feature, the schema upgrade happens via
`ai-memory schema-init --store-url postgres://…` — opening the
store walks the in-process `migrate_v34()…migrate_v55()` async
ladder as a side effect (there is no `--upgrade` flag). Apache AGE
(`memory_graph`) is provisioned by the same command if the `age`
extension is installed. Note the pre-built release binaries are
default-feature builds without `migrate`/`schema-init` — use a
`--features sal,sal-postgres` build for the postgres path.
See [`docs/migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md)
for the postgres-specific recipe.

### Operator-visible behavior changes (Tier 2 callouts)

- **Boot banner LLM field shape.** Now `llm=<backend>:<model>` for
  non-Ollama backends (e.g., `llm=xai:grok-4.3`); preserved as
  `llm=<model>` for backend == ollama. Scrapers that grep the boot
  manifest for `llm=gemma3:4b` will still match Ollama deployments
  but need to accept the colon-separated shape for non-Ollama.
- **MCP `core` profile grew from 5 → 7 tools.** Strict v0.6.x MCP
  clients that hardcode the 5-tool surface and refuse unknown
  tools will need an update. The new tools (`memory_load_family`,
  `memory_smart_load`) are read-only loaders.
- **`tools/list` returns 74 entries** at `--profile full` (was ~60
  at v0.6.4, 43 at v0.6.3). Operator scripts using
  `jq '.tools | length == 60'` will diverge.

### `--also-clean-claude-json` scope

`ai-memory config migrate --also-clean-claude-json` removes
`mcpServers.<*>.env` blocks **only** from entries whose `command`
ends in `/ai-memory` or equals `"ai-memory"`. If you launch via a
wrapper script (e.g., `node wrapper.js`, `npx ai-memory`, a
Windows `.exe`), the env block is NOT touched. Audit manually:

```bash
grep -l AI_MEMORY_LLM ~/.claude.json && \
  echo "Manual cleanup needed: wrapper-script-launched MCP entries"
```

---

## Tier 3 — DevOps / IaC (idempotent shell)

Drop this snippet into ansible / terraform / CI / Makefile.
Every step is idempotent — safe to run on every play.

```bash
#!/usr/bin/env bash
# v0.6.x → v0.7.0 idempotent migration. Run multiple times safely.

set -euo pipefail

VER=v0.7.0
TARGET=x86_64-unknown-linux-gnu   # Rust target triple — adjust per host
EXPECTED_SHA256=<pin-from-your-inventory>
BIN=/usr/local/bin/ai-memory
# Project HARD RULE — no /tmp scratch. Use a local tempdir.
TMP=$(mktemp -d "$PWD/.ai-memory-upgrade-XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# --- 1. Install v0.7.0 binary (idempotent — only fetches if version differs)
if ! "$BIN" --version 2>/dev/null | grep -q "${VER#v}"; then
  curl -fsSL "https://github.com/alphaonedev/ai-memory-mcp/releases/download/${VER}/ai-memory-${TARGET}.tar.gz" -o "$TMP/m.tgz"
  echo "${EXPECTED_SHA256}  $TMP/m.tgz" | sha256sum -c -
  tar -xzf "$TMP/m.tgz" -C "$TMP"
  install -m 0755 "$TMP/ai-memory" "$BIN"
fi

# --- 2. Config migration (idempotent — no-op on schema_version >= 2)
ai-memory config migrate || true

# --- 3. Postgres schema migration (idempotent — schema-init re-runs safely;
#         requires a --features sal,sal-postgres build of the binary)
if [ -n "${AI_MEMORY_STORE_URL:-}" ]; then
  ai-memory schema-init --store-url "$AI_MEMORY_STORE_URL" || true
fi

# --- 4. Governance → permissions (idempotent — in-place merge)
ai-memory governance migrate-to-permissions \
  --config-out ~/.config/ai-memory/config.toml || true

# --- 5. Health gate — fail the play if any check is critical
#        (doctor also exits 2 on its own when any section is critical)
ai-memory doctor --json | jq -e '
  [.sections[] | select(.severity == "critical")] | length == 0
' || { echo "doctor reports CRIT"; ai-memory doctor; exit 1; }
ai-memory verify-signed-events-chain --format json | jq -e '.chain_holds == true'

# --- 6. Apply v0.7.0 secure-default posture (idempotent — env file)
install -d /etc/ai-memory/env.d
cat > /etc/ai-memory/env.d/v07-secure.env <<'EOF'
AI_MEMORY_PERMISSIONS_MODE=enforce
AI_MEMORY_FED_REQUIRE_SIG=1
AI_MEMORY_FED_REQUIRE_NONCE=1
AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0
AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS=0
AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=0
EOF

# --- 7. Reload (idempotent — systemd reload is no-op when unchanged)
systemctl --user daemon-reload
systemctl --user reload ai-memory || systemctl --user restart ai-memory
```

For ansible, wrap each block in an `ansible.builtin.shell` task
with `creates:` / `removes:` guards as appropriate. For
terraform, this is a single `null_resource` with
`local-exec` provisioners.

---

## Rollback

The DB schema migration past v34 is **forward-only** (no down
migrations). If you need to roll back to v0.6.x, restore either the
`.v064.bak` DB you took in step 2 of Tier 1 / 2 OR the automatic
pre-migration snapshot the migrator writes next to the DB before any
schema-mutating upgrade
(`<db>.pre-migration-v<from>-to-v<to>-<token>.bak`, a
transactionally-consistent `VACUUM INTO` image). The config.toml
`.bak.<timestamp>` written by `ai-memory config migrate` can be
restored similarly.

---

## Related docs

- [`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md) — canonical v2 schema reference
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md) — full CLI surface incl. `config migrate` + `doctor`
- [`integrations/llm-backends.md`](integrations/llm-backends.md) — per-backend MCP env-block recipes
- [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.md) — Postgres + AGE + pgvector specifics
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — when `ai-memory doctor` reports WARN/CRIT
- [`AI_DEVELOPER_GOVERNANCE.md`](AI_DEVELOPER_GOVERNANCE.md) — security posture rationale
- [`CHANGELOG.md`](../CHANGELOG.md) — full v0.7.0 release entry

---

> **Filed:** 2026-05-23 against `release/v0.7.0` HEAD `a757b3104`.
> Per prime directive pm-v3 — verified against the actual code paths
> in `src/cli/commands/config.rs`, `src/storage/migrations.rs`,
> `src/cli/boot.rs`, `src/daemon_runtime.rs`. Every command above is
> exercised by an existing unit / integration test in the v0.7.0
> test suite (4699 passing at HEAD).
