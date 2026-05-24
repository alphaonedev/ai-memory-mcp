# ai-memory v0.7.0 — install quickstart (Path A: super simple)

A friendly, no-jargon install guide. If you can use a terminal, you can
get ai-memory running in under five minutes. No software engineering
background required.

> **This is Path A — the singleton, single-laptop case.** One AI
> client, one user, defaults work. If you're standing up a production
> deployment (multi-agent on one node, multi-server, multi-DC, swarm,
> hive, postgres + Apache AGE storage), this is the wrong page —
> jump to [Path B: production / fleet deployment](#path-b--need-to-go-deeper-fleet-postgres-tuning)
> at the bottom of this file, or directly to
> [`production-deployment.md`](production-deployment.md).

For the wire-it-up-to-an-AI step, see
[`docs/integration-guide.md`](integration-guide.md).

For the full SME reference (every flag, every package channel, every
production knob) see [`docs/INSTALL.md`](INSTALL.md).

## 1. What is ai-memory, in one paragraph

**ai-memory is a persistent memory substrate for AI agents.** Claude,
Cursor, ChatGPT, Grok, Gemini, Continue.dev, Aider, Cody, Windsurf,
Zed, Goose — anything that speaks the Model Context Protocol (MCP) —
can plug into it. It stores what your AI learns in a local SQLite
database on your machine, ranks those memories by relevance when the
AI asks to recall them, and auto-promotes important ones to permanent
storage. **It runs entirely locally and never phones home.** No
cloud account, no telemetry, no outbound network calls (except when
*you* deliberately enable peer-federation or a hosted LLM provider).
The same database is shared across every AI client you wire up, so
your assistants share a memory.

## 2. Choose your platform

Pick the row that matches your machine. If you're not sure, the
**curl one-liner** (top row) works on every Mac and Linux box.

| Platform | Command | Notes |
|---|---|---|
| **macOS / Linux** — pre-built binary (recommended) | `curl -fsSL https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.sh \| sh` | Downloads the right binary for your CPU, drops it in `~/.cargo/bin` or `~/.local/bin`. No Rust toolchain needed. |
| **macOS / Linux** — Homebrew tap | `brew install alphaonedev/tap/ai-memory` | The Homebrew tap is owned by AlphaOne. If the tap is not yet live in your region or the formula lags the latest release, fall back to the curl one-liner above or `cargo install ai-memory`. |
| **Linux / any Unix** — cargo | `cargo install ai-memory` | Needs the Rust toolchain (`rustup`) installed first. Build takes ~2 minutes on a modern laptop. |
| **Linux** — Docker | `docker pull ghcr.io/alphaonedev/ai-memory:0.7.0` then `docker run --rm -v ai-memory-data:/data ghcr.io/alphaonedev/ai-memory:0.7.0 ai-memory --version` | Zero-toolchain install. The image carries the binary and ships ready to run as a daemon. |
| **Fedora / RHEL** — COPR | `sudo dnf copr enable alpha-one-ai/ai-memory && sudo dnf install ai-memory` | Official RPM channel. |
| **Arch / Manjaro** — AUR | `paru -S ai-memory` *(or your AUR helper of choice)* | Community-maintained, tracking upstream. |
| **Windows** — PowerShell (pre-built binary) | `irm https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.ps1 \| iex` | Drops `ai-memory.exe` into your `%USERPROFILE%\.local\bin` (or equivalent). |
| **Windows** — cargo via WSL | Inside WSL: `cargo install ai-memory` | Treat WSL like Linux. |
| **Windows** — cargo native | From a Developer PowerShell: `cargo install ai-memory` | Native Windows build; requires the MSVC toolchain and `rustup` installed first. |
| **Mobile (iOS / Android) / IoT / edge** | See [`docs/mobile-iot-deployment.md`](mobile-iot-deployment.md) | The mobile artifacts (`ai-memory-ios.xcframework.tar.gz`, `ai-memory-android.tar.gz`) ship with every v0.7.x release and embed into your mobile app via the FFI layer. Not a stand-alone CLI install. |

> **Don't have `cargo`?** Install Rust first:
> `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
> then restart your terminal (or `source ~/.cargo/env`).

> **Behind a corporate proxy?** Set `HTTPS_PROXY` before running the
> curl one-liner or any `cargo install` command.

## 3. Verify the install

Open a fresh terminal and run:

```bash
ai-memory --version
```

You should see something like:

```
ai-memory 0.7.0
```

If you see `command not found`, your shell's `PATH` is missing the
install directory. The two common fixes:

- **cargo install** put it in `~/.cargo/bin` — add to your shell's
  startup file: `export PATH="$HOME/.cargo/bin:$PATH"`.
- **curl one-liner** put it in `~/.local/bin` — same fix:
  `export PATH="$HOME/.local/bin:$PATH"`.

Then `source ~/.bashrc` (or `~/.zshrc`) and run `ai-memory --version`
again.

## 4. First-time setup

Solo use needs exactly one command. Generate a cryptographic identity
keypair (this is what lets ai-memory cryptographically prove which
agent wrote which memory):

```bash
ai-memory identity generate
```

That writes two files under `~/.config/ai-memory/keys/` — a public
key (`*.pub`) and a private key (`*.priv`) — and prints your
canonical agent ID. **The private key never leaves your machine.**
The agent ID is what shows up in the audit trail when your AI writes
a memory.

For the conceptual primer on identity, see
[`docs/agent-identity.html`](agent-identity.html).

That's it. No service to start, no account to create, no port to
open. The MCP server launches on demand when your AI client calls
it; the HTTP daemon only runs when you explicitly start it.

> **Multi-user / multi-host?** See
> [`docs/enterprise-deployment.md`](enterprise-deployment.md) for the
> shared-database, peer-federation, and agent-to-agent setup.

## 5. What's on disk

After install + first use, ai-memory creates these files. **All of
them stay on your machine.** Nothing is uploaded.

| Path | What lives here |
|---|---|
| `~/.claude/ai-memory.db` *(or `./ai-memory.db` if you don't override)* | The SQLite database. This is the memory itself. Back it up like any other valuable file. |
| `~/.config/ai-memory/config.toml` | Optional config file (tier defaults, LLM backend, daemon settings). Created lazily on first config write. |
| `~/.config/ai-memory/keys/` | Your Ed25519 identity keypairs (one pair per agent). |
| `~/.config/ai-memory/operator.key.{pub,priv}` | The operator keypair (only present if you ran `ai-memory governance install-defaults`). |
| `~/.local/state/ai-memory/audit/` | Append-only audit log of governance decisions. |
| `~/.local/state/ai-memory/logs/` | Operational logs (rotated). |
| `~/.ai-memory/reflections/` | File-backed reflection chain (only if you opt into auto-export). |

**Windows equivalents** — replace `~/.config/ai-memory/` with
`%APPDATA%\ai-memory\` and `~/.local/state/ai-memory/` with
`%LOCALAPPDATA%\ai-memory\state\`. The database default path becomes
`%USERPROFILE%\.claude\ai-memory.db`.

You can move the database anywhere with the `--db` flag, or by
setting the `AI_MEMORY_DB` environment variable:

```bash
export AI_MEMORY_DB=/Volumes/MyBackup/ai-memory.db
```

## 6. Try it without any AI hooked up

```bash
# Store a memory
ai-memory store \
  --title "ai-memory is installed" \
  --content "Worked through the quickstart on 2026-05-22." \
  --tier mid

# Recall it
ai-memory recall "did I install ai-memory"

# See your tier counts + recent activity
ai-memory stats
```

If the recall returns the memory you just stored, the install is
fully working. You can now wire it to your AI assistant.

## 7. Optional configuration knobs

You can skip this section entirely — defaults are sane. Knobs you
might want to set once and forget:

| Setting | How to set | What it does |
|---|---|---|
| Database path | `export AI_MEMORY_DB=/path/to/db` | Move the SQLite file anywhere on disk. |
| Default agent ID | `export AI_MEMORY_AGENT_ID=alice` | Stamps every memory `alice` wrote with that ID (instead of the leaky `host:<hostname>:pid-<pid>-<uuid>` fallback). Recommended on shared machines. |
| LLM backend | **Recommended:** `[llm]` section in `~/.config/ai-memory/config.toml` (see below). **Override:** `export AI_MEMORY_LLM_BACKEND=xai` etc. | Picks which LLM the `smart` and `autonomous` tiers talk to. Aliases for `ollama`, `openai`, `xai`, `anthropic`, `gemini`, `deepseek`, `kimi`, `qwen`, `mistral`, `groq`, `together`, `cerebras`, `openrouter`, `fireworks`, `lmstudio` are recognized. Pair with `api_key_env = "<NAME>"` (config-file path) or `AI_MEMORY_LLM_API_KEY=…` / per-vendor env (override path) for hosted providers; `ollama` and `lmstudio` need no key. See [`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md) for the canonical `[llm]` schema, [`integrations/llm-backends.md`](integrations/llm-backends.md) for per-backend MCP env-block recipes, and [#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144) → [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) for the operator paper-cut history + retirement. |
| Permissions mode | `export AI_MEMORY_PERMISSIONS_MODE=advisory` | Loosens v0.7.0's enforced governance gate to the v0.6.x permissive posture. Default is `enforce` and you should leave it on unless you're debugging. |
| Encrypted DB | `export AI_MEMORY_ENCRYPT_AT_REST=1` | Requires a sqlcipher build + `--db-passphrase-file`. See [`docs/INSTALL.md`](INSTALL.md) § encrypted-at-rest. |

Put any of those in `~/.bashrc` / `~/.zshrc` (or `~/.config/fish/config.fish`,
or Windows `setx`) and every new shell session picks them up. For
the full env-var ladder, see the **Environment Variables** section
of the project [`CLAUDE.md`](../CLAUDE.md).

You can also put settings in `~/.config/ai-memory/config.toml`
instead of env vars — useful when you want one config for both
interactive shells and the launchd / systemd unit that runs
`ai-memory serve`. **This is the recommended path for the LLM
backend post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)
(v0.7.0)** — every surface (MCP, HTTP daemon, CLI, boot banner,
`ai-memory doctor`) reads the same file, so the boot banner and the
live MCP server agree on the backend. Example for xAI Grok 4.3:

```toml
# ~/.config/ai-memory/config.toml
schema_version = 2

[llm]
backend     = "xai"
model       = "grok-4.3"
base_url    = "https://api.x.ai/v1"
api_key_env = "XAI_API_KEY"                       # process-env-var name (NOT the key)
# api_key_file = "/etc/ai-memory/keys/xai.key"    # alt — mode 0400 enforced
```

**Inline API keys in `config.toml` are rejected at parse time** —
use `api_key_env` (env-var reference) or `api_key_file` (file path).

Precedence ladder (uniform across all four resolvers — LLM /
embeddings / reranker / storage):

```
CLI flag  >  AI_MEMORY_* env  >  config.toml section  >  legacy flat fields  >  compiled default
```

`ai-memory config migrate` rewrites a legacy v0.6.x flat-field
`config.toml` in place; `--dry-run` prints the diff;
`--also-clean-claude-json` additionally strips redundant
`mcpServers.<*>.env` blocks. Canonical schema reference:
[`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md).

## 8. Next: connect your AI

The full integration recipes — Claude Code, Cursor, ChatGPT,
Continue.dev, Codex CLI, Grok CLI, Gemini CLI, generic MCP clients,
and the HTTP fallback for clients that don't speak MCP — live in
[`docs/integration-guide.md`](integration-guide.md).

The TL;DR for the most common case (Claude Code):

```bash
ai-memory install claude-code --apply
```

This writes the right config into `~/.claude.json`, registers the
SessionStart hook so every new conversation boots memory-aware, and
backs up your existing settings to a timestamped file first. Restart
Claude Code and you're done.

> **Using `smart` or `autonomous` tier with a non-Ollama LLM?** The
> installer writes a default MCP block without LLM-backend env vars
> (so the default Ollama path keeps working out of the box). The
> **recommended** path is to write a `[llm]` section in
> `~/.config/ai-memory/config.toml` (see §"You can also put settings
> in config.toml" above) — one file, every surface, no MCP-config edits
> per AI client. The **override** path is to hand-edit
> `~/.claude.json`'s `memory` server block and add an `env` map with
> `AI_MEMORY_LLM_BACKEND`, `AI_MEMORY_LLM_API_KEY`, and
> `AI_MEMORY_LLM_MODEL` — useful for CI / per-session tweaks. Shell
> exports work for the CLI / HTTP daemon but **not** for MCP-spawned
> subprocesses. Copy-pasteable per-backend recipes:
> [`integrations/llm-backends.md`](integrations/llm-backends.md).
> Background: [#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)
> (env-block paper-cut) → [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)
> (single source of truth, retires the env-block requirement).

## 9. Uninstall

Clean removal in three steps. The order matters — remove integrations
first, the binary second, the data last (so a misclick on step 3
doesn't strand wired-up AI clients pointing at a missing binary).

**Step 1 — remove every integration you installed:**

```bash
ai-memory install claude-code  --uninstall --apply
ai-memory install cursor       --uninstall --apply
ai-memory install continue     --uninstall --apply
ai-memory install codex-cli    --uninstall --apply
ai-memory install gemini-cli   --uninstall --apply
# ...repeat for every harness you used
```

Each `--uninstall --apply` removes the managed block from that
client's config and restores the pre-install backup if one exists.

**Step 2 — remove the binary:**

| Install method | Uninstall command |
|---|---|
| curl one-liner | `rm ~/.local/bin/ai-memory` (or wherever `which ai-memory` reports) |
| Homebrew | `brew uninstall alphaonedev/tap/ai-memory && brew untap alphaonedev/tap` |
| cargo | `cargo uninstall ai-memory` |
| Docker | `docker rmi ghcr.io/alphaonedev/ai-memory:0.7.0` |
| DNF (COPR) | `sudo dnf remove ai-memory && sudo dnf copr disable alpha-one-ai/ai-memory` |
| AUR | `paru -R ai-memory` (or your AUR helper's remove command) |
| Windows installer | `Remove-Item $env:USERPROFILE\.local\bin\ai-memory.exe` |

**Step 3 — remove the data** (optional — skip this if you want to
keep your memory corpus for a future reinstall):

```bash
rm -rf ~/.claude/ai-memory.db ~/.config/ai-memory ~/.local/state/ai-memory ~/.ai-memory
```

The database is just a file; you can also archive it
(`cp ~/.claude/ai-memory.db ~/memory-backup-2026-05-22.db`) before
deleting if you might want to restore it later.

## 10. Troubleshooting

Common errors with one-line fixes. If your problem isn't here, run
the failing command with `RUST_LOG=ai_memory=debug` prefixed and
file an issue on
[GitHub](https://github.com/alphaonedev/ai-memory-mcp/issues) with
the full output.

| Symptom | Fix |
|---|---|
| `command not found: ai-memory` after install | Your shell's `PATH` doesn't include the install directory. Add `export PATH="$HOME/.cargo/bin:$PATH"` (or `~/.local/bin`) to `~/.bashrc` / `~/.zshrc` and reload. |
| `ai-memory --version` prints the wrong version | A stale binary is shadowing the new one. `which -a ai-memory` shows every copy on `PATH`; delete the older ones or reorder `PATH` so the new install wins. |
| `Error: database is locked` | Another `ai-memory` process is holding the SQLite write lock. List them with `pgrep -fa ai-memory`; stop the stray ones (`kill <pid>`) and retry. Most often this is a stuck MCP server from a previously-killed AI client. |
| `Error: failed to open database` with permission denied | The DB file is owned by another user. Either `chown` it to yourself or use `--db <new-path>` to write to a path you own. |
| First semantic recall hangs for a minute | First run downloads the `sentence-transformers/all-MiniLM-L6-v2` embedding model (~90 MB). One-time only; subsequent calls are instant. If it never completes, check your internet connection and proxy settings. |
| `Error: governance refused` on a write | Permissions mode defaults to `enforce` at v0.7.0. Either approve the pending action (`ai-memory pending list` then `ai-memory pending approve <id>`) or temporarily set `AI_MEMORY_PERMISSIONS_MODE=advisory` while you debug. |
| `Error: no MCP tools advertised` in the AI client | The AI client started ai-memory with the wrong `--profile` or no `--tier` flag. Confirm the args in the client's MCP config match the snippets in [`docs/integration-guide.md`](integration-guide.md). |
| Memories from one session don't appear in another | The two clients are pointing at different DB files. Set `AI_MEMORY_DB` to the same path in every client's MCP config, or use `--db <shared-path>` consistently. |

## Path B — Need to go deeper? (fleet, postgres, tuning)

If Path A above met your needs, you're done. Use ai-memory as documented
above; nothing else in this section applies.

Read on **only if** any of these is true:

- You're running **more than one AI agent on one machine** (Batman /
  swarm / hive on a single node).
- You're standing up ai-memory on a **server** with multiple agents
  connecting over the network, or behind a service mesh.
- You're deploying across **multiple servers, racks, data centers, or
  regions**.
- You need **PostgreSQL + Apache AGE** as the storage backend (multi-
  tenant, multi-writer, >10M memories, or graph-heavy workloads).
- You want every **tuning knob** exposed (TTL per tier, governance
  modes, federation auth layers, hook pipeline, sidechain transcripts,
  signed-events V-4 chain, …).

The Path-B doc set, in reading order:

1. **[`INSTALL.md`](INSTALL.md)** — full SME install reference. Every
   package channel, every flag, every Windows / Docker / Kubernetes
   variant.
2. **[`production-deployment.md`](production-deployment.md)** — 10-min
   hardening checklist: keypair provisioning, mTLS allowlist, backup
   discipline, schema migrations, observability, topology (single-
   instance / hub-spoke / W-of-N).
3. **[`ADMIN_GUIDE.md`](ADMIN_GUIDE.md)** — every env var, every
   `config.toml` field, the full LLM-backend matrix, the embedder /
   reranker tuning surface.
4. **[`enterprise-deployment.md`](enterprise-deployment.md)** — 60–90
   min planning artefact. 8 deployment topologies from singleton on a
   laptop to multi-region federated fleet; capacity envelope and
   graduation triggers for each.
5. **[`postgres-age-guide.md`](postgres-age-guide.md)** — PostgreSQL +
   Apache AGE first-class storage backend. When to switch off sqlite,
   how to provision pgvector + AGE, the `ai-memory schema-init` CLI,
   migration runbook, AGE Cypher KG.
6. **[`federation.md`](federation.md)** — mTLS, peer attestation,
   `X-API-Key`, per-message Ed25519 signing + nonce freshness, signed-
   events V-4 cross-row hash chain.
7. **[`integrations/llm-backends.md`](integrations/llm-backends.md)** —
   MCP env-block recipes for every supported LLM provider (Ollama /
   LMStudio / vLLM / llama.cpp server / xAI / OpenAI / Anthropic /
   Gemini / DeepSeek / Kimi / Qwen / Mistral / Groq / Together /
   Cerebras / OpenRouter / Fireworks). Includes a fleet / multi-agent
   / multi-DC considerations section.
8. **[`batman-active-mode.md`](batman-active-mode.md)** — multi-agent
   coordination on one node (Batman A2A); operator how-to for turning
   Forms 1–6 + 7th from capable → active.
9. **[`a2a-harness-integration.md`](a2a-harness-integration.md)** —
   agent-to-agent across nodes (full A2A wire shape).
10. **[`mobile-iot-deployment.md`](mobile-iot-deployment.md)** — iOS,
    Android, edge / IoT, resource-constrained deployment.

## See also

- [`docs/integration-guide.md`](integration-guide.md) — wire ai-memory
  to any AI.
- [`docs/INSTALL.md`](INSTALL.md) — full install reference (every
  package channel, every flag, every Windows variant).
- [`docs/QUICKSTART.md`](QUICKSTART.md) — first memory in five
  minutes (CLI / MCP / HTTP path comparisons).
- [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) — every CLI subcommand
  and flag.
- [`docs/API_REFERENCE.md`](API_REFERENCE.md) — every HTTP endpoint.
- [`docs/agent-identity.html`](agent-identity.html) — what `agent_id`
  and the identity keypair mean.
- [`docs/mobile-iot-deployment.md`](mobile-iot-deployment.md) — iOS,
  Android, edge / IoT deployment.
- [`docs/enterprise-deployment.md`](enterprise-deployment.md) —
  multi-user, peer-federation, agent-to-agent.
