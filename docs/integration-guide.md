# ai-memory v0.7.0 — integration guide

How to wire ai-memory to **any AI** — Claude, Cursor, ChatGPT,
Continue.dev, generic MCP clients, and even AIs that don't speak MCP
at all. Target audience: same as
[`docs/install-quickstart.md`](install-quickstart.md) — anyone
comfortable in a terminal — plus prosumers and tinkerers who want
multiple AIs sharing one memory.

If you haven't installed yet, do that first:
[`docs/install-quickstart.md`](install-quickstart.md).

## 1. The pattern, in one paragraph

ai-memory exposes itself in three ways: a **stdio MCP server**
(`ai-memory mcp`), an **HTTP/REST daemon** (`ai-memory serve`), and
a **CLI** (`ai-memory store / recall / search / ...`). The MCP
server is how every modern AI client connects, because MCP — the
Model Context Protocol — is the industry-standard plug for AI
agents to talk to local tools. Any MCP-compatible client points at
the binary, ai-memory boots a per-session process, and the AI now
has 7 to 73 memory tools at its disposal (depending on the
`--profile` flag). For AIs that don't speak MCP, the HTTP API
covers everything the MCP surface does, plus a few more endpoints
(87 route registrations / 73 unique URL paths at v0.7.0).

Every recipe below assumes the binary is on your `PATH`. If
`ai-memory --version` doesn't print `0.7.0`, go back to
[`docs/install-quickstart.md`](install-quickstart.md) §3.

## 2. Claude Code (Anthropic)

The fast path is the bundled installer:

```bash
ai-memory install claude-code --apply
```

That writes a SessionStart hook + an MCP server block into
`~/.claude/settings.json` (and `~/.claude.json`), backs up the
prior file to `<config>.bak.<timestamp>`, and is idempotent.
Restart Claude Code; the next session boots memory-aware.

If you'd rather do it by hand, edit `~/.claude/mcp.json` (or merge
into `~/.claude.json` if you already use that file). The exact
snippet:

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": [
        "--db", "~/.claude/ai-memory.db",
        "mcp",
        "--tier", "semantic"
      ],
      "env": {
        "AI_MEMORY_DB": "${HOME}/.claude/ai-memory.db"
      }
    }
  }
}
```

For the full SessionStart-hook story (so Claude proactively recalls
memory on every conversation start), see
[`docs/integrations/claude-code.md`](integrations/claude-code.md).

> **`--tier semantic` is the right default.** It uses local
> sentence-transformer embeddings — no LLM provider key required.
> The other tiers (`keyword` / `smart` / `autonomous`) are
> documented in
> [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) § `mcp`.

> **Using `--tier smart` or `--tier autonomous` with a non-default LLM backend?** Extend the `env` block above with `AI_MEMORY_LLM_BACKEND`, `AI_MEMORY_LLM_API_KEY`, and `AI_MEMORY_LLM_MODEL`. **Do not** rely on shell exports — MCP-spawned subprocesses don't see your interactive shell's environment ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)). Copy-pasteable recipes for every supported provider (Ollama, LMStudio, vLLM, llama.cpp server, xAI Grok, OpenAI, Anthropic, Gemini, DeepSeek, Kimi, Qwen, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks): [`integrations/llm-backends.md`](integrations/llm-backends.md).

## 3. Cursor

```bash
ai-memory install cursor --apply
```

Or by hand — edit `~/.cursor/mcp.json` (global) or
`<project>/.cursor/mcp.json` (project-scoped; project wins for
same-named servers):

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": [
        "--db", "~/.claude/ai-memory.db",
        "mcp",
        "--tier", "semantic"
      ],
      "env": {
        "AI_MEMORY_DB": "${HOME}/.claude/ai-memory.db"
      }
    }
  }
}
```

Restart Cursor. Verify under Settings → Tools & MCP — a green dot
next to `ai-memory` means it's live. Full recipe (including the
project-rules `.cursorrules` directive that nudges Cursor to recall
on session start):
[`docs/integrations/cursor.md`](integrations/cursor.md). LLM-backend
env-block recipe for smart / autonomous tiers:
[`integrations/llm-backends.md`](integrations/llm-backends.md).

> **Cursor has a ~40 tool cap across all MCP servers.** Stick to
> `--profile core` (the default — 7 tools) unless you really need
> the full surface.

## 4. ChatGPT Desktop

**State of the world (v0.7.0):** ChatGPT Desktop does not currently
ship native MCP-client support. The integration paths are (in order
of operational simplicity):

### 4a. HTTP API fallback (recommended for ChatGPT Desktop today)

Start the daemon:

```bash
ai-memory serve --host 127.0.0.1 --port 9077
```

Then use ChatGPT's **custom GPT actions** to call ai-memory over
HTTP. Build a custom GPT, add an Action with the OpenAPI schema
from [`docs/API_REFERENCE.md`](API_REFERENCE.md), and point the
server URL at your exposed daemon (use a tunnel like Cloudflare
Tunnel or Tailscale Funnel if you want it reachable from
ChatGPT's cloud).

The handful of routes you'll actually call:

```bash
# Store a memory
curl -X POST http://127.0.0.1:9077/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","content":"Stored from ChatGPT","tier":"mid"}'

# Recall
curl -X POST http://127.0.0.1:9077/api/v1/recall \
  -H "Content-Type: application/json" \
  -d '{"context":"what did I store","limit":5}'
```

See §7 for the full HTTP-fallback section.

### 4b. Programmatic via OpenAI SDK

If you drive the OpenAI Apps SDK / Assistants / Responses API
yourself, prepend `ai-memory boot` to the system message of every
request. The SDK recipe lives in
[`docs/integrations/openai-apps-sdk.md`](integrations/openai-apps-sdk.md).
There's also a built-in wrapper:
`ai-memory wrap openai-cli -- chat --model gpt-4.1` injects the
boot context as the system prompt before launching the downstream
CLI — no SDK code needed.

### 4c. Via an MCP-aware ChatGPT CLI

If you're calling ChatGPT models through any MCP-aware harness
(Codex CLI, Continue.dev, Aider), use that harness's native MCP
config. Codex example:

```toml
# ~/.codex/config.toml
[mcp_servers.ai-memory]
command = "ai-memory"
args = ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "semantic"]
enabled = true
```

When native ChatGPT Desktop MCP lands upstream, the recipe is the
same shape as Claude Code — point the client at `ai-memory mcp`.

## 5. Continue.dev (VS Code / JetBrains)

```bash
ai-memory install continue --apply
```

Or by hand — edit `~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: ai-memory
    command: ai-memory
    args:
      - "--db"
      - "~/.claude/ai-memory.db"
      - "mcp"
      - "--tier"
      - "semantic"
    env:
      AI_MEMORY_DB: "${HOME}/.claude/ai-memory.db"
```

If you're on the older `config.json` schema:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "ai-memory",
          "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "semantic"]
        }
      }
    ]
  }
}
```

Full recipe (including the `systemMessage` that nudges Continue
to recall on session start):
[`docs/integrations/continue.md`](integrations/continue.md).

> **MCP tools in Continue only work in agent mode**, not in chat
> mode. Switch to agent mode in the Continue side panel.

## 6. Generic MCP-compatible AI client

If your client speaks MCP but isn't listed above, the universal
pattern is **JSON-RPC 2.0 over stdio**. Tell the client to launch:

```
command: ai-memory
args:    ["mcp"]
# optionally:
#   ["--db", "/path/to/ai-memory.db", "mcp", "--tier", "semantic"]
#   ["mcp", "--profile", "full"]  # advertise all 73 tools
```

That's it. ai-memory speaks MCP 2024-11-05 protocol, advertises 7
tools by default and up to 73 with `--profile full`. Per-harness
copy-paste recipes live in [`docs/integrations/`](integrations/):
**aider**, **claude-agent-sdk**, **cline**, **codex-cli**, **cody**,
**gemini**, **goose**, **grok-and-xai**, **openclaw**, **roo-code**,
**windsurf**, **zed**, and **local-models** (Ollama / llama.cpp /
LM Studio / vLLM). See
[`integrations/README.md`](integrations/README.md) for the
Category-1 (hook-capable) vs. Category-2 (MCP-only) matrix.

## 7. HTTP API fallback — for clients that don't speak MCP

ai-memory ships an HTTP/REST daemon with **87 route registrations / 73 unique URL paths at v0.7.0**
covering everything the MCP surface does. Use it for AI clients
with no MCP support (most browser-based assistants), custom
scripts, multi-host setups, and browser extensions.

```bash
ai-memory serve --host 127.0.0.1 --port 9077
curl http://127.0.0.1:9077/api/v1/health  # {"status":"ok"}
```

**Three curl recipes you'll actually use:**

```bash
# Store a memory
curl -X POST http://127.0.0.1:9077/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{"title":"Deploy target","content":"EKS in us-west-2","tier":"long","namespace":"platform"}'

# Recall (semantic + keyword hybrid)
curl -X POST http://127.0.0.1:9077/api/v1/recall \
  -H "Content-Type: application/json" \
  -d '{"context":"what is our deploy target","namespace":"platform","limit":5}'

# Check whether an action would be governance-allowed (v0.7.0 7th-form)
curl -X POST http://127.0.0.1:9077/api/v1/memory_check_agent_action \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"ai:gpt-5@my-laptop","action":"store","namespace":"platform","content":"test"}'
```

**Production hardening:**

- Set an API key: `ai-memory serve --api-key "$(cat /etc/ai-memory/api.key)"`.
  All callers then pass `-H "X-API-Key: <key>"`.
- Add TLS: `--tls-cert /etc/ai-memory/cert.pem --tls-key /etc/ai-memory/key.pem`.
- Pin who can connect: `--mtls-allowlist /etc/ai-memory/peer-fingerprints.txt`.

Full HTTP surface:
[`docs/API_REFERENCE.md`](API_REFERENCE.md).

## 8. Multi-AI setup — one ai-memory, many clients

You can wire **Claude Code + Cursor + Continue.dev + Codex CLI**
to the same memory at the same time. They all read and write a
single SQLite database. The pattern:

1. Pick a canonical DB path that's stable on this host (e.g.
   `~/.claude/ai-memory.db`).
2. Export it in your shell profile so every AI client picks it
   up the same way:

   ```bash
   # ~/.zshrc or ~/.bashrc
   export AI_MEMORY_DB="${HOME}/.claude/ai-memory.db"
   ```

3. In each AI client's MCP config, pass the same path explicitly
   (the snippets in §§2–6 already do this with
   `"--db", "~/.claude/ai-memory.db"`).

**Concurrent access notes:** SQLite WAL mode handles many readers
+ one writer concurrently. Occasional `database is locked` errors
under sustained write load are the signal to either throttle on the
caller or move to the **postgres+AGE** backend
(`ai-memory serve --store-url postgres://...` — see
[`docs/postgres-age-guide.md`](postgres-age-guide.md)). Every
memory carries an `agent_id` so you can always tell which AI wrote
which memory; the MCP server auto-detects the client name via
`initialize.clientInfo.name`.

**Optional but recommended:** run the curator daemon in the
background to keep the corpus tidy across the swarm of AIs.

```bash
ai-memory curator --daemon
```

It de-duplicates, tags, and consolidates across whatever every
client has been writing. Runs hourly by default.

## 9. A2A (agent-to-agent) basics

ai-memory can act as a **shared substrate for multiple AI agents
that need to coordinate** — not just per-host but across hosts.
The shorthand stack:

- Each agent registers with `ai-memory agents register --agent-id ai:<name>`.
- Each writes / recalls against a shared namespace, tagging
  memories with its own `agent_id`.
- Federation peers (`ai-memory sync-daemon --peers ...`) replicate
  the same memory corpus across machines with mTLS + Ed25519
  signature checking + per-peer nonce replay protection.
- Webhook subscriptions (HMAC-signed, namespace-filtered) turn
  the store into a message bus — agent A's write triggers a
  webhook that wakes up agent B.

That's the one-paragraph version. For the full deep dive — peer
allowlist, quorum rules, vector-clock CRDT merge, agent-to-agent
approval flow, and the recommended deployment topologies — see
[`docs/enterprise-deployment.md`](enterprise-deployment.md).

## 10. Security defaults

ai-memory v0.7.0 ships with secure defaults already on. **You do
not have to configure these to get them.** Worth knowing about:

- **Permissions enforced by default.** `permissions.mode = "enforce"`
  is the v0.7.0 default (was `"advisory"` in v0.6.4). Policy
  violations return **403 Forbidden**, not a silent pass-through.
  Escape hatch: `AI_MEMORY_PERMISSIONS_MODE=advisory`.
- **Cryptographically signed audit chain.** Every governance
  decision is appended to `signed_events` with a cross-row Ed25519
  hash chain (V-4 closeout). Tampering is detectable;
  `ai-memory verify-signed-events-chain` walks it end-to-end.
- **Per-memory attestation.** With an identity keypair
  (`ai-memory identity generate`), every memory you write carries
  a verifiable Ed25519 signature. `memory_verify(link_id)` returns
  `{signature_verified, attest_level, signed_by, signed_at}`.
- **Federation requires signed + nonce'd posts.** `/sync/push`
  enforces `X-Memory-Sig` + `X-Memory-Nonce` by default
  (`AI_MEMORY_FED_REQUIRE_SIG=1`, `AI_MEMORY_FED_REQUIRE_NONCE=1`).
  Replay attacks drop with `401`.
- **SSRF guard + governance fail-CLOSED.** Webhook / federation
  dispatch refuses to send on DNS failure; transient rule
  consultation errors block the write. Escape hatches
  (`AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1`,
  `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1`) exist for narrow
  operational needs.
- **Encrypted DB available.** Build with `--features sqlcipher`,
  set `AI_MEMORY_ENCRYPT_AT_REST=1`, provide a `chmod 0400`
  passphrase file via `--db-passphrase-file`.

The trust + audit story works without operator action. This posture
is opinionated on purpose.

## See also

- [`docs/install-quickstart.md`](install-quickstart.md) — get the
  binary on disk first.
- [`docs/INSTALL.md`](INSTALL.md) — every install method, every
  flag.
- [`docs/integrations/README.md`](integrations/README.md) — the
  per-harness recipe matrix (Category 1 hook-capable vs.
  Category 2 MCP-only vs. Category 3 programmatic).
- [`docs/API_REFERENCE.md`](API_REFERENCE.md) — every HTTP
  endpoint.
- [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md) — every CLI
  subcommand.
- [`docs/agent-identity.html`](agent-identity.html) — what
  `agent_id` and Ed25519 attestation mean.
- [`docs/enterprise-deployment.md`](enterprise-deployment.md) —
  multi-user, peer-federation, A2A in depth.
- [`docs/mobile-iot-deployment.md`](mobile-iot-deployment.md) —
  iOS / Android / edge.
- [`docs/postgres-age-guide.md`](postgres-age-guide.md) — switch
  to postgres+AGE for higher-concurrency multi-AI setups.
