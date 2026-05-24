# ai-memory Quickstart — first memory in under 5 minutes

This guide gets you from zero to a working ai-memory install and your
first stored + recalled memory. Choose one of three paths depending
on how you want to use it.

> **Looking for a friendlier walkthrough?** This page is the
> single-developer / single-laptop CLI + MCP + HTTP comparison. For a
> super-simple, copy-paste install + config walkthrough with zero
> jargon, see [`install-quickstart.md`](install-quickstart.md).
>
> **Standing up a fleet / multi-DC / postgres+AGE deployment?** This
> page is the wrong starting point — see
> [`production-deployment.md`](production-deployment.md) and
> [`enterprise-deployment.md`](enterprise-deployment.md).

## Install

```bash
# macOS / Linux (with Homebrew or prebuilt binary)
curl -sSL https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.sh | sh

# Or from cargo (any platform with Rust 1.88+)
cargo install --git https://github.com/alphaonedev/ai-memory-mcp ai-memory
```

Verify:

```bash
ai-memory --version
# ai-memory 0.6.3+patch.1   (release tag: v0.6.3.1; +patch.N is the crates.io-compatible encoding)
```

Full install reference including Windows, Docker, Fedora COPR, Ubuntu
PPA, and Homebrew tap: `docs/INSTALL.md`.

## Path A — CLI (fastest, 60 seconds)

```bash
# 1. Store your first memory
ai-memory store \
  --title "My first memory" \
  --content "ai-memory keeps this around for 7 days by default" \
  --tier mid

# 2. Recall it
ai-memory recall "what did I store"

# 3. See the stats
ai-memory stats
```

That's it. Memories live in `~/ai-memory.db` (override with `--db` or
`AI_MEMORY_DB`). Store anything, recall anything, no server running.

## Path B — Claude Code / Claude Desktop / Cursor / Codex (MCP)

ai-memory is an MCP server. Wire it into your AI IDE and every
conversation gets persistent memory across sessions.

**Claude Code** — add to `~/.claude.json` (user scope):

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp", "--tier", "semantic"]
    }
  }
}
```

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "ai-memory": { "command": "ai-memory", "args": ["mcp"] }
  }
}
```

**Cursor** — Settings → Features → Model Context Protocol → Add:

```
Command: ai-memory
Args: mcp --tier semantic
```

**Smart / autonomous tier with a cloud LLM** (any of xAI Grok, OpenAI,
Anthropic, Gemini, DeepSeek, Kimi, Qwen, Mistral, Groq, Together,
Cerebras, OpenRouter, Fireworks, LMStudio, vLLM, llama.cpp server) —
the recommended path is the `[llm]` section in
`~/.config/ai-memory/config.toml` ([#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)).
Example for xAI Grok:

```toml
# ~/.config/ai-memory/config.toml
schema_version = 2

[llm]
backend     = "xai"
model       = "grok-4.3"
base_url    = "https://api.x.ai/v1"
api_key_env = "XAI_API_KEY"            # process-env-var name (NOT the literal key)
```

Export `XAI_API_KEY` in your shell rc (`.zshrc` / `.bashrc`) so the
AI client's parent process inherits it. The MCP config stays minimal:

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp", "--tier", "autonomous"]
    }
  }
}
```

Verify: `ai-memory boot --quiet --limit 1` should report
`llm=xai:grok-4.3`. Full canonical schema:
[`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.md).

> **Override path — `env:` block.** Adding an `env:` block to the MCP
> config (with `AI_MEMORY_LLM_BACKEND` / `_API_KEY` / `_MODEL`) still
> works and takes precedence over `config.toml`. Useful for CI /
> per-session tweaks. Background: [#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)
> (the env-block paper-cut, retired by #1146 above). Full per-backend
> recipes: [`integrations/llm-backends.md`](integrations/llm-backends.md).
>
> **Inline API keys in `config.toml` are rejected at parse time** — use
> `api_key_env` (process-env reference) or `api_key_file` (file path;
> mode 0400 enforced).

Restart the IDE. You'll now see 23 `memory_*` tools in the tool list.
Ask the assistant "remember that my preferred deploy target is
Kubernetes" and next session it'll recall it.

Full MCP setup for every IDE: `docs/INSTALL.md` § "MCP client setup".

## Path C — HTTP daemon (for applications + services)

```bash
# Start the daemon (plain HTTP, loopback only)
ai-memory serve --host 127.0.0.1 --port 9077 &

# Store via curl
curl -X POST http://127.0.0.1:9077/api/v1/memories \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My first HTTP memory",
    "content": "Via the REST API",
    "tier": "mid"
  }'

# Recall via curl
curl -X POST http://127.0.0.1:9077/api/v1/recall \
  -H "Content-Type: application/json" \
  -d '{"context": "HTTP memory", "limit": 5}'

# Stop
kill %1
```

Use the TypeScript or Python SDK instead of hand-rolling HTTP:
`sdk/typescript/README.md` and `sdk/python/README.md`.

For production (TLS, API key, mTLS, systemd): `docs/ADMIN_GUIDE.md`.

## Verify everything works

```bash
# Counts by tier + namespace
ai-memory stats

# Full list
ai-memory list --limit 20

# Keyword search
ai-memory search "first"

# Semantic recall (needs the embedding model; first run downloads it)
ai-memory recall "memories I recently created"
```

First semantic recall on a fresh install downloads the
sentence-transformers/all-MiniLM-L6-v2 embedding model (~90 MB). This
is one-time; subsequent calls are instant.

## What to read next

- **Learning what each concept means** → `docs/GLOSSARY.md`
- **All CLI flags** → `docs/CLI_REFERENCE.md`
- **All HTTP endpoints** → `docs/API_REFERENCE.md`
- **MCP tool reference** → `docs/USER_GUIDE.md`
- **Running in production** → `docs/ADMIN_GUIDE.md`
- **Common errors** → `docs/TROUBLESHOOTING.md`
- **Contributing code** → `docs/DEVELOPER_GUIDE.md`
