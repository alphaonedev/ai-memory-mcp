# LLM backends — MCP env-block recipes for every supported provider

**Audience:** operators wiring ai-memory's `smart` / `autonomous` tiers to a specific LLM provider via an MCP-capable AI client (Claude Code, Claude Desktop, Cursor, Codex CLI, Cline, Continue, Zed, Windsurf, Goose, Roo Code, Aider, Cody, Gemini CLI, OpenClaw, …).

**Why this page exists.** ai-memory v0.7.0 (#1067 / #1142 / #1143) ships a provider-agnostic LLM client. Any of 16+ backends can power the smart/autonomous tiers — local Ollama, LMStudio, vLLM, llama.cpp server, xAI Grok, OpenAI, Anthropic, Google Gemini, DeepSeek, Kimi/Moonshot, Qwen/Dashscope, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks, plus the generic `openai-compatible` escape hatch for anything else that speaks the OpenAI wire shape.

The selector is the `AI_MEMORY_LLM_BACKEND` environment variable, paired with `AI_MEMORY_LLM_API_KEY` (or a per-vendor fallback like `XAI_API_KEY`) and `AI_MEMORY_LLM_MODEL`. **Setting those vars in `.zshrc` / `.bashrc` / `.profile` is sufficient for the standalone `ai-memory` CLI and the HTTP daemon — but it is NOT sufficient for MCP usage.**

## Critical — MCP clients do not inherit your interactive shell

When Claude Code, Claude Desktop, Cursor, Codex, Cline, Continue, Zed, Windsurf, Goose, Roo Code, etc. launch `ai-memory mcp` as an MCP server, they spawn it as a **fresh subprocess** with only the environment variables explicitly declared in the MCP server config's `env:` block (plus a minimal inherited set the client controls). Shell-exported variables from your interactive terminal session are **NOT visible** to that subprocess.

So this in your `.zshrc`:

```bash
export AI_MEMORY_LLM_BACKEND=xai
export XAI_API_KEY=xai-...
export AI_MEMORY_LLM_MODEL=grok-4.3
```

…will let `ai-memory mcp --tier autonomous` produce `LLM ready (backend=xai, model=grok-4.3)` when you run it manually from that shell. It will silently fall back to the legacy Ollama default (`gemma4:e4b`) when Claude Code / Cursor / etc. spawn the same binary.

The fix: **the LLM env vars MUST live inside the MCP server config's `env:` block.** Recipes below show this for every supported backend.

### How to know it took effect

Restart your AI client. Inspect the ai-memory boot banner that prints on first MCP session-start (or run `ai-memory boot` directly with the same env vars). You should see:

```text
ai-memory: LLM ready (backend=<vendor>, model=<name>)
ai-memory: LLM client is OpenAI-compatible (non-Ollama wire shape);
           building dedicated Ollama embed client at http://localhost:11434 (#1143)
```

The second line appears only when `backend` is non-Ollama and confirms the embed-client wire-shape disambiguation from #1143 is taking effect (semantic recall still uses Ollama-native embed at `localhost:11434` while chat goes to the cloud vendor). If you see `llm=gemma4:e4b` or another local Ollama tag when you intended a cloud backend, the `env:` block didn't land — re-check the path of the MCP config file your AI client actually reads.

## The canonical recipe shape

Every example below is the **`memory` MCP server entry** in your AI client's config file. The file path differs per client (Claude Code: `~/.claude.json`; Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows; Cursor: `~/.cursor/mcp.json`; Codex: `~/.codex/config.toml`; etc. — see [`platforms.md`](platforms.md) for the full path table). The **server block shape** is identical across clients (Codex uses TOML, every other client uses JSON — Codex shape shown at the end of this page).

> **Replace the API key** in every example below with your own — do not paste examples verbatim into your config file.

## Index

- [Ollama (local default — no key required)](#ollama-local-default)
- [LMStudio (local — no key required)](#lmstudio-local)
- [vLLM, llama.cpp server, generic OpenAI-compatible (self-hosted)](#generic-openai-compatible-self-hosted)
- [xAI Grok](#xai-grok)
- [OpenAI](#openai)
- [Anthropic (via OpenAI shim)](#anthropic)
- [Google Gemini](#google-gemini)
- [DeepSeek](#deepseek)
- [Kimi (Moonshot)](#kimi-moonshot)
- [Qwen (DashScope)](#qwen-dashscope)
- [Mistral](#mistral)
- [Groq](#groq)
- [Together AI](#together-ai)
- [Cerebras](#cerebras)
- [OpenRouter](#openrouter)
- [Fireworks](#fireworks)
- [Codex CLI TOML shape](#codex-cli-toml-shape)

---

## Ollama (local default)

No env block is required — Ollama at `http://localhost:11434` is the default. This recipe is shown only for explicitness or for pointing the backend at a non-default host/port.

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "ollama",
        "AI_MEMORY_LLM_MODEL": "gemma4:e4b",
        "AI_MEMORY_LLM_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
```

| Knob | Default | Notes |
|---|---|---|
| `AI_MEMORY_LLM_BACKEND` | `ollama` | Implied when unset. |
| `AI_MEMORY_LLM_MODEL` | `gemma4:e2b` (smart) / `gemma4:e4b` (autonomous) | Any locally-pulled Ollama tag. `ollama pull <tag>` first. |
| `AI_MEMORY_LLM_BASE_URL` | `http://localhost:11434` | Override for remote Ollama on the LAN. Legacy `OLLAMA_BASE_URL` is still honoured. |

Pull the model once before first MCP session:

```bash
ollama pull gemma4:e4b   # ~2.3 GB Q4 — autonomous default
```

## LMStudio (local)

LMStudio exposes an OpenAI-compatible endpoint at `http://localhost:1234/v1` by default. No API key required.

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "lmstudio",
        "AI_MEMORY_LLM_MODEL": "lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF",
        "AI_MEMORY_LLM_BASE_URL": "http://localhost:1234/v1"
      }
    }
  }
}
```

`AI_MEMORY_LLM_BASE_URL` is optional — `lmstudio` alias pre-fills `http://localhost:1234/v1`. Override only if you've changed LMStudio's local server port.

## Generic OpenAI-compatible (self-hosted)

Use this for **vLLM**, **llama.cpp server**, **TGI**, **TabbyAPI**, or any other self-hosted endpoint that speaks the OpenAI wire shape. `AI_MEMORY_LLM_BASE_URL` is **required** — there is no default URL for the generic alias.

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "openai-compatible",
        "AI_MEMORY_LLM_BASE_URL": "http://your-host:8000/v1",
        "AI_MEMORY_LLM_MODEL": "your-model-tag",
        "AI_MEMORY_LLM_API_KEY": "your-bearer-token-or-blank"
      }
    }
  }
}
```

If your endpoint doesn't require auth (vLLM with `--api-key` unset, local llama.cpp server, etc.), leave `AI_MEMORY_LLM_API_KEY` set to any non-empty placeholder (e.g. `"none"`) — the field is non-optional in OpenAI-shape clients but the value is ignored by no-auth servers.

## xAI Grok

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "xai",
        "AI_MEMORY_LLM_API_KEY": "xai-...",
        "AI_MEMORY_LLM_MODEL": "grok-4.3"
      }
    }
  }
}
```

Fallback env var: `XAI_API_KEY` is honoured if `AI_MEMORY_LLM_API_KEY` is unset. Common model tags: `grok-4.3`, `grok-4-latest`, `grok-code-fast-1`. See xAI's model catalog for the current list.

## OpenAI

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "openai",
        "AI_MEMORY_LLM_API_KEY": "sk-...",
        "AI_MEMORY_LLM_MODEL": "gpt-4o"
      }
    }
  }
}
```

Fallback env var: `OPENAI_API_KEY`. Common tags: `gpt-4o`, `gpt-4o-mini`, `o1-mini`.

## Anthropic

ai-memory talks to Anthropic via the OpenAI-compatible shim at `https://api.anthropic.com/v1` (the alias pre-fills this).

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "anthropic",
        "AI_MEMORY_LLM_API_KEY": "sk-ant-...",
        "AI_MEMORY_LLM_MODEL": "claude-sonnet-4-6"
      }
    }
  }
}
```

Fallback env var: `ANTHROPIC_API_KEY`. Common tags: `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`.

## Google Gemini

Gemini exposes an OpenAI-compatible endpoint at `https://generativelanguage.googleapis.com/v1beta/openai`.

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "gemini",
        "AI_MEMORY_LLM_API_KEY": "AIza...",
        "AI_MEMORY_LLM_MODEL": "gemini-2.5-pro"
      }
    }
  }
}
```

Fallback env vars: `GEMINI_API_KEY`, `GOOGLE_API_KEY`. Common tags: `gemini-2.5-pro`, `gemini-2.5-flash`.

## DeepSeek

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "deepseek",
        "AI_MEMORY_LLM_API_KEY": "sk-...",
        "AI_MEMORY_LLM_MODEL": "deepseek-chat"
      }
    }
  }
}
```

Fallback env var: `DEEPSEEK_API_KEY`. Common tags: `deepseek-chat`, `deepseek-reasoner`.

## Kimi (Moonshot)

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "kimi",
        "AI_MEMORY_LLM_API_KEY": "sk-...",
        "AI_MEMORY_LLM_MODEL": "moonshot-v1-128k"
      }
    }
  }
}
```

The `moonshot` alias is identical to `kimi`. Fallback env vars: `MOONSHOT_API_KEY`, `KIMI_API_KEY`.

## Qwen (DashScope)

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "qwen",
        "AI_MEMORY_LLM_API_KEY": "sk-...",
        "AI_MEMORY_LLM_MODEL": "qwen-max"
      }
    }
  }
}
```

The `dashscope` alias is identical to `qwen`. Fallback env vars: `DASHSCOPE_API_KEY`, `QWEN_API_KEY`. Common tags: `qwen-max`, `qwen-plus`, `qwen-turbo`.

## Mistral

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "mistral",
        "AI_MEMORY_LLM_API_KEY": "...",
        "AI_MEMORY_LLM_MODEL": "mistral-large-latest"
      }
    }
  }
}
```

Fallback env var: `MISTRAL_API_KEY`. Common tags: `mistral-large-latest`, `mistral-small-latest`, `codestral-latest`.

## Groq

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "groq",
        "AI_MEMORY_LLM_API_KEY": "gsk_...",
        "AI_MEMORY_LLM_MODEL": "llama-3.3-70b-versatile"
      }
    }
  }
}
```

Fallback env var: `GROQ_API_KEY`. Common tags: `llama-3.3-70b-versatile`, `mixtral-8x7b-32768`, `gemma2-9b-it`.

## Together AI

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "together",
        "AI_MEMORY_LLM_API_KEY": "...",
        "AI_MEMORY_LLM_MODEL": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
      }
    }
  }
}
```

Fallback env var: `TOGETHER_API_KEY`. See Together's model catalog for the full tag list.

## Cerebras

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "cerebras",
        "AI_MEMORY_LLM_API_KEY": "csk-...",
        "AI_MEMORY_LLM_MODEL": "llama-3.3-70b"
      }
    }
  }
}
```

Fallback env var: `CEREBRAS_API_KEY`.

## OpenRouter

OpenRouter is a unified gateway — use `<vendor>/<model>` slugs.

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "openrouter",
        "AI_MEMORY_LLM_API_KEY": "sk-or-...",
        "AI_MEMORY_LLM_MODEL": "anthropic/claude-sonnet-4-6"
      }
    }
  }
}
```

Fallback env var: `OPENROUTER_API_KEY`.

## Fireworks

```json
{
  "mcpServers": {
    "memory": {
      "command": "ai-memory",
      "args": ["--db", "~/.claude/ai-memory.db", "mcp", "--tier", "autonomous"],
      "env": {
        "AI_MEMORY_LLM_BACKEND": "fireworks",
        "AI_MEMORY_LLM_API_KEY": "fw_...",
        "AI_MEMORY_LLM_MODEL": "accounts/fireworks/models/llama-v3p3-70b-instruct"
      }
    }
  }
}
```

Fallback env var: `FIREWORKS_API_KEY`.

## Codex CLI TOML shape

Codex CLI's config (`~/.codex/config.toml`) uses TOML rather than JSON, but the env-block contract is identical. Example shown for xAI Grok — swap the three values for any backend above.

```toml
[mcp_servers.memory]
command = "ai-memory"
args = ["--db", "~/.local/share/ai-memory/memories.db", "mcp", "--tier", "autonomous"]
enabled = true

[mcp_servers.memory.env]
AI_MEMORY_LLM_BACKEND = "xai"
AI_MEMORY_LLM_API_KEY = "xai-..."
AI_MEMORY_LLM_MODEL = "grok-4.3"
```

Or use the `env_vars` form to forward shell variables (only works if the shell that launched the Codex client itself had the var exported — same MCP-vs-shell caveat applies):

```toml
[mcp_servers.memory]
command = "ai-memory"
args = ["--db", "~/.local/share/ai-memory/memories.db", "mcp", "--tier", "autonomous"]
env_vars = ["AI_MEMORY_LLM_BACKEND", "AI_MEMORY_LLM_API_KEY", "AI_MEMORY_LLM_MODEL"]
enabled = true
```

## Tier semantics — when does any of this matter?

| Tier | LLM backend used? |
|---|---|
| `keyword` (FTS5 only) | **No.** The env block is ignored. |
| `semantic` (default — embeddings only) | **No.** The env block is ignored. |
| `smart` (+ LLM-backed query expansion, auto-tagging, contradiction detection) | **Yes.** |
| `autonomous` (smart + cross-encoder reranking + reflection + atomisation) | **Yes.** |

Keyword and semantic tiers don't call the LLM at all. The env block above is for `smart` and `autonomous` tiers only. Setting it on keyword/semantic is harmless — the env vars are unused — but adds no value either.

## API-key precedence ladder

For every backend except `ollama` and `lmstudio` (which don't need a key), the API key resolves through this ladder (first match wins):

1. `AI_MEMORY_LLM_API_KEY` — canonical, backend-agnostic.
2. Per-vendor fallback env var (from this table):

| Backend | Fallback env vars (in resolution order) |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `xai` | `XAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `gemini` | `GEMINI_API_KEY`, then `GOOGLE_API_KEY` |
| `deepseek` | `DEEPSEEK_API_KEY` |
| `kimi` / `moonshot` | `MOONSHOT_API_KEY`, then `KIMI_API_KEY` |
| `qwen` / `dashscope` | `DASHSCOPE_API_KEY`, then `QWEN_API_KEY` |
| `mistral` | `MISTRAL_API_KEY` |
| `groq` | `GROQ_API_KEY` |
| `together` | `TOGETHER_API_KEY` |
| `cerebras` | `CEREBRAS_API_KEY` |
| `openrouter` | `OPENROUTER_API_KEY` |
| `fireworks` | `FIREWORKS_API_KEY` |

3. **Error** — backend rejects the request at the first chat/embed call.

The same precedence applies whether the var lives in your shell or in the MCP `env:` block. The recommended pattern is to put the canonical `AI_MEMORY_LLM_API_KEY` in the MCP env block — it's unambiguous and doesn't depend on the per-vendor fallback chain.

## Embedding wire shape (#1143)

ai-memory's embedder is Ollama-native (`/api/embed`). When the LLM backend is non-Ollama (e.g. xAI, OpenAI), the MCP server detects the wire-shape mismatch and builds a **dedicated Ollama embed client** at `http://localhost:11434` (configurable via `AI_MEMORY_EMBED_URL`) while chat goes to the cloud vendor. You'll see the `(#1143)` banner line on first MCP start confirming this disambiguation took effect.

If you don't have a local Ollama running and you've selected a non-Ollama LLM backend, semantic recall will fall back to keyword-only. To run fully cloud-side, either:
- Install Ollama locally just for the embedder (`brew install ollama && ollama serve &` — no models need to be pulled; the embed endpoint accepts any embedding model tag the daemon knows about).
- OR drop to `semantic` tier with Ollama unset and accept the limited recall surface.

A native OpenAI-compatible embedder path is tracked for v0.7.x — once shipped, the disambiguation line will go away and the embedder will use whatever the LLM backend exposes at `/v1/embeddings`.

## Verification — quick smoke test

After editing your MCP config, restart your AI client and ask it a question that exercises the smart/autonomous tier (e.g. "what do you remember about X?"). Then check the ai-memory boot banner — it appears in the AI client's MCP server log (Claude Code: `~/Library/Logs/Claude/mcp*.log` on macOS; Cursor: Settings → Tools & MCP → server detail panel; etc.).

Expected output:

```text
ai-memory: requested tier = autonomous
ai-memory: profile = 8 families (...); expected tool count = 73
ai-memory: LLM ready (backend=<your-backend>, model=<your-model>)
ai-memory: LLM client is OpenAI-compatible (non-Ollama wire shape);
           building dedicated Ollama embed client at http://localhost:11434 (#1143)
ai-memory: embedder loaded (nomic-embed-text-v1.5 (768-dim, Ollama))
ai-memory: atomisation engine ready (curator=LlmCurator)
ai-memory MCP server started (stdio, tier=autonomous)
```

If you see `llm=gemma4:e4b` or `llm=gemma4:e2b` when you intended a non-Ollama backend, the `env:` block isn't being picked up — re-check the path of the config file your AI client actually reads (see [`platforms.md`](platforms.md) for the per-client path table).

## Multi-agent / fleet / multi-DC considerations

The recipes above assume the **singleton** case — one operator, one
machine, one AI client. Fleet and multi-DC deployments add concerns
the singleton case can ignore. None of them change the env-block
shape; they change which **values** you put in the env block and how
those values flow across nodes.

### Storage backend is orthogonal to LLM backend

ai-memory's storage backend (SQLite-WAL vs. PostgreSQL + Apache AGE,
selected via `--store-url postgres://…` or the default sqlite path)
is **independent** of the LLM backend (selected via
`AI_MEMORY_LLM_BACKEND`). Any combination is supported:

| Storage backend | LLM backend | Works? |
|---|---|---|
| SQLite (default) | Ollama (default) | Yes — the default zero-decision case. |
| SQLite | xAI Grok / OpenAI / Anthropic / any cloud | Yes. |
| PostgreSQL + AGE | Ollama (default) | Yes. |
| PostgreSQL + AGE | xAI Grok / OpenAI / Anthropic / any cloud | Yes. |

Switching storage backends does **not** require touching the LLM env
block, and vice versa. The cross-product is fully supported.
Storage-side setup: [`postgres-age-guide.md`](../postgres-age-guide.md).

### Multiple agents on one node — shared vs. per-agent backend

Two patterns, both valid:

**Pattern 1 — single shared LLM backend across all agents on the node.**

Every agent's MCP config points at the same `AI_MEMORY_LLM_BACKEND` +
`AI_MEMORY_LLM_API_KEY` + `AI_MEMORY_LLM_MODEL`. Cost is shared,
rate-limit budget is shared, key rotation is one place to touch. The
attribution story is muddier: the cloud vendor sees all of your
agents under one API-key identity.

```json
// Same env block in every agent's MCP server config:
{
  "env": {
    "AI_MEMORY_LLM_BACKEND": "xai",
    "AI_MEMORY_LLM_API_KEY": "xai-shared-org-key",
    "AI_MEMORY_LLM_MODEL": "grok-4.3"
  }
}
```

**Pattern 2 — per-agent backend (different keys / different models).**

Each agent's MCP config carries a distinct API key (or distinct
backend). Cost / rate-limit / attribution are per-agent; key rotation
is N-touches. Useful when different agents have different
trust / capability tiers (e.g. cheap-and-fast for routine recall, a
premium model for the reflection / curator daemon).

```json
// Agent A — autonomous tier, premium model:
{
  "env": {
    "AI_MEMORY_LLM_BACKEND": "xai",
    "AI_MEMORY_LLM_API_KEY": "xai-agent-a-key",
    "AI_MEMORY_LLM_MODEL": "grok-4.3"
  }
}
```

```json
// Agent B — smart tier, cheap-and-fast model:
{
  "env": {
    "AI_MEMORY_LLM_BACKEND": "groq",
    "AI_MEMORY_LLM_API_KEY": "gsk-agent-b-key",
    "AI_MEMORY_LLM_MODEL": "llama-3.3-70b-versatile"
  }
}
```

For the multi-agent coordination layer itself (A2A wire shape, ranges
of memory each agent can see, identity attestation across agents on
one node), see [`batman-active-mode.md`](../batman-active-mode.md).

### Multi-server in one DC — env-block strategy

On a fleet of nodes each running one or more ai-memory MCP servers,
the env block lives **per-node** (in each node's MCP config files).
Three rollout patterns:

1. **Config-management tool (Ansible / Chef / Puppet / Salt / Nix).**
   Render the MCP config files from a template. Operator commits the
   template; secret material (API keys) comes from a vault. Re-running
   the playbook against every node reconciles drift in one pass.
2. **Container image baked.** The MCP config is baked into a custom
   image alongside the `ai-memory` binary. Operator rolls a new image
   on key rotation. Works well with Kubernetes / Plan-C deployments
   (see [`plan-c-deployment.md`](../plan-c-deployment.md)).
3. **Secret-manager sidecar.** A secrets-fetch sidecar (Vault Agent,
   AWS Secrets Manager CSI driver, etc.) writes the MCP config to a
   local file on container start, pulling secrets from the secret
   store at boot. Avoids baking secrets into images.

The env-block contract is the same in all three patterns — they
differ only in **how the file gets there**, not in **what it
contains**.

### Multi-DC / multi-region — regional cloud endpoints

For latency-sensitive workloads, pick a cloud LLM provider with
regional endpoints. xAI, OpenAI, Anthropic, Gemini, etc. publish
regional URLs in their model-catalog docs. Override the per-alias
default base URL with `AI_MEMORY_LLM_BASE_URL`:

```json
// Asia-Pacific deployment pointed at a regional OpenAI endpoint:
{
  "env": {
    "AI_MEMORY_LLM_BACKEND": "openai",
    "AI_MEMORY_LLM_BASE_URL": "https://your-azure-openai-resource.openai.azure.com/v1",
    "AI_MEMORY_LLM_API_KEY": "...",
    "AI_MEMORY_LLM_MODEL": "gpt-4o"
  }
}
```

For self-hosted vLLM / llama.cpp endpoints inside your own DC, point
`AI_MEMORY_LLM_BASE_URL` at the regional inference cluster. The
ai-memory MCP server doesn't care where the endpoint lives — it just
speaks the OpenAI wire shape.

### Federation / A2A interaction

ai-memory's federation layer (`/sync/push`, mTLS allowlist,
`X-Memory-Sig` + nonce freshness, signed-events V-4 chain — see
[`federation.md`](../federation.md)) is **independent** of the LLM
backend choice. Federated peers can each use a different LLM backend;
the memory rows that cross the wire are LLM-agnostic.

That said, if you rely on LLM-backed features that travel with the
data (auto-tag, contradiction detection, atomisation, reflection),
peers running different LLM backends will produce slightly different
artefacts for the same input. For deterministic-equivalent
deployments across a federation, pin every peer to the same LLM
backend + model + version.

### Key management at fleet scale

For >5 nodes, do NOT bake API keys into the MCP config files
checked into version control. Use one of:

- **A secret manager (HashiCorp Vault / AWS Secrets Manager / GCP
  Secret Manager / Azure Key Vault / 1Password Connect / sops).**
  Render the MCP config from a template; pull the secret at deploy
  time. Rotation is one secret update + a rolling restart.
- **Per-host file with strict perms** (`chmod 0400` on `.env`-shape
  files, sourced into the MCP-launcher's startup). Audit failure mode
  if the perms slip — `AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS`-style
  guards do not apply to the LLM API-key file; that's an operator
  policy concern.
- **Per-agent identity-bound keys.** Each agent's
  `AI_MEMORY_AGENT_ID` is provisioned alongside its own LLM API key
  during agent enrolment; rotation is per-agent. Works well with the
  Ed25519 identity-keypair-per-agent pattern from
  [`production-deployment.md`](../production-deployment.md) §2.

### Postgres + Apache AGE deployments — same env block, different daemon launch

Postgres-backed deployments launch the daemon with `--store-url
postgres://…`. The MCP `env:` block for LLM-backend selection is
identical to the sqlite case — neither the storage nor the LLM care
about each other's choice. The full storage-side setup:
[`postgres-age-guide.md`](../postgres-age-guide.md).

For multi-writer postgres deployments, the LLM backend is typically
**not** per-agent at the env-block level. Instead, every agent's MCP
server uses a shared backend identity (Pattern 1 above), and
per-agent attribution lands on the postgres side via
`metadata.agent_id` columns + per-agent governance rules. The LLM
backend in that posture is operating as infrastructure — a fungible
inference engine — rather than as part of the agent's identity.

### Swarm / hive — coordination layer is above this

For swarm / hive deployments, the LLM-backend selection is the *unit
configuration* — every agent in the swarm needs one. The
coordination layer (which agent talks to which, when to fan-out,
when to converge) lives above: see
[`batman-active-mode.md`](../batman-active-mode.md) and
[`enterprise-deployment.md`](../enterprise-deployment.md) topologies
6–8. Choice of LLM backend per agent is a swarm-design decision (do
you want premium models on the critical-path agents and cheap-and-
fast on the perimeter? do you want every agent identical for
behavioural reproducibility?) — see
[`enterprise-deployment.md`](../enterprise-deployment.md) §6 for the
LLM-cost / behaviour tradeoffs at fleet scale.

## Related

- [`ADMIN_GUIDE.md` § LLM Backend Setup](../ADMIN_GUIDE.md#llm-backend-setup-smart--autonomous-tiers) — the standalone-CLI / HTTP-daemon flavour of the same setup (shell-side `export`).
- [`INSTALL.md`](../INSTALL.md) — the broader install path, including the MCP config base examples this page extends.
- [`install-quickstart.md`](../install-quickstart.md) — Path-A super-simple singleton install.
- [`production-deployment.md`](../production-deployment.md) — single-node hardening, hub-spoke, W-of-N topologies.
- [`enterprise-deployment.md`](../enterprise-deployment.md) — 8-topology continuum: singleton → multi-region swarm.
- [`postgres-age-guide.md`](../postgres-age-guide.md) — PostgreSQL + Apache AGE storage backend.
- [`batman-active-mode.md`](../batman-active-mode.md) — multi-agent on one node (A2A coordination).
- [`federation.md`](../federation.md) — peer-federation wire shape, mTLS, signing.
- [`grok-and-xai.md`](grok-and-xai.md) — using ai-memory to feed memory INTO Grok (the inverse direction). Cross-links back here for the Grok-as-backend case.
- [`platforms.md`](platforms.md) — per-AI-client MCP config-file path table.
- Issues [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067), [#1142](https://github.com/alphaonedev/ai-memory-mcp/issues/1142), [#1143](https://github.com/alphaonedev/ai-memory-mcp/issues/1143), [#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144) — the backend-resolver and docs-gap history that produced this page.
