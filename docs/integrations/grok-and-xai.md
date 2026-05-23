# xAI Grok — programmatic prepend, via Cursor, or as ai-memory's LLM backend

**Category 3 (programmatic) for raw API; category 2 if used via Cursor; ALSO usable as ai-memory's own LLM backend (see below).**

xAI's Grok models are accessible via the xAI API (raw HTTP / OpenAI-compat
SDK), via Cursor (where Grok is one of several model choices), and via the
xAI consumer apps. The integration depends on the surface.

## Three directions Grok intersects ai-memory

1. **Grok-as-AI-client.** Grok reads ai-memory's boot context at session
   start (this is what most of this doc covers — Category 3 programmatic
   integration via the xAI SDK).
2. **Grok via Cursor.** Cursor's Grok model picker plus the standard
   Cursor MCP integration — see [`cursor.md`](cursor.md).
3. **Grok-as-ai-memory's-LLM-backend.** ai-memory's smart / autonomous
   tiers call out to an LLM for query expansion, auto-tagging,
   contradiction detection, atomisation, reflection. As of v0.7.0
   ([#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) /
   [#1142](https://github.com/alphaonedev/ai-memory-mcp/issues/1142) /
   [#1143](https://github.com/alphaonedev/ai-memory-mcp/issues/1143)),
   that LLM can be Grok via xAI. **This is the inverse direction** —
   ai-memory's own internals talking to Grok, rather than Grok reading
   from ai-memory. See the dedicated section below.

## Use Grok as ai-memory's LLM backend

ai-memory's `smart` and `autonomous` tiers need an LLM. xAI Grok is one
of 16+ supported backends (see [`llm-backends.md`](llm-backends.md) for
the full vendor matrix — OpenAI, Anthropic, Gemini, DeepSeek, Kimi,
Qwen, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks,
LMStudio, vLLM, llama.cpp server, local Ollama all work identically).

**MCP env-block recipe for Grok:**

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

Place this block in your AI client's MCP config file (Claude Code:
`~/.claude.json`; Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS; Cursor: `~/.cursor/mcp.json`; Codex: `~/.codex/config.toml`
in TOML shape — see [`llm-backends.md` § Codex CLI TOML shape](llm-backends.md#codex-cli-toml-shape)).

**Critical — MCP clients do not inherit your interactive shell.**
Setting `export AI_MEMORY_LLM_BACKEND=xai` in `.zshrc` works for the
standalone `ai-memory` CLI but **NOT** for MCP usage — Claude Code /
Cursor / Codex / etc. spawn the MCP server as a fresh subprocess. Put
the env vars inside the MCP config's `env:` block as shown above.
This was the operator paper-cut behind
[#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144).

**Verification.** Restart your AI client and check the ai-memory boot
banner — you should see:

```text
ai-memory: LLM ready (backend=xai, model=grok-4.3)
ai-memory: LLM client is OpenAI-compatible (non-Ollama wire shape);
           building dedicated Ollama embed client at http://localhost:11434 (#1143)
```

If you see `llm=gemma4:e4b` (the legacy Ollama default), the env
block didn't land — re-check the MCP config path your AI client
reads.

**Common Grok model tags:** `grok-4.3`, `grok-4-latest`,
`grok-code-fast-1`. xAI's API-key fallback env var (`XAI_API_KEY`) is
honoured if `AI_MEMORY_LLM_API_KEY` is unset.

**Going further:** for the full per-backend matrix, multi-agent / fleet
considerations, and storage-vs-LLM-backend independence, see
[`llm-backends.md`](llm-backends.md).

## Or for the simple wrapper case — `ai-memory wrap`

If your integration is just "spawn a Grok CLI", PR-6 of issue #487
ships a built-in cross-platform Rust subcommand:

```bash
ai-memory wrap grok-cli -- chat --model grok-2-latest
```

`ai-memory wrap` runs `ai-memory boot` in-process, builds a system
message, and spawns the named CLI with the system message delivered
via the appropriate strategy. Pure Rust — same binary works on macOS
/ Linux / Windows / Docker / Kubernetes with no shell wrapper.

For SDK code (the pattern below) `wrap` doesn't apply — that's for
the launcher case.

## Via the xAI API (programmatic — recommended)

The xAI API is OpenAI-compatible. Use the `openai-apps-sdk.md` recipe
verbatim, swapping the base URL and model:

```python
import subprocess
from openai import OpenAI

memory = subprocess.check_output(
    ["ai-memory", "boot", "--quiet", "--no-header", "--format", "text", "--limit", "10"],
    text=True,
).strip()

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)

instructions = "You are a helpful assistant."
if memory:
    instructions += f"\n\n## Recent context (ai-memory)\n{memory}"

response = client.chat.completions.create(
    model="grok-2-latest",
    messages=[
        {"role": "system", "content": instructions},
        {"role": "user", "content": user_message},
    ],
)
```

100% reliable.

## Via Cursor (Grok Code Fast 1, etc.)

Use the [`cursor.md`](cursor.md) recipe — Grok runs inside Cursor's MCP
host, so the memory wiring is identical to any other Cursor model.
Category 2 (best-effort directive in `.cursorrules` until Cursor lands a
session-start hook).

## Via the xAI consumer app

The consumer Grok app does not expose tooling for MCP integration today.
No recipe yet — track for when xAI adds developer hooks.

## Related

- [`README.md`](README.md), Issue #487
- [`openai-apps-sdk.md`](openai-apps-sdk.md) — same pattern for any
  OpenAI-compatible API.
