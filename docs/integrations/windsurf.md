# Windsurf (Codeium) — MCP server + windsurfrules

**Category 2.** Windsurf is MCP-capable; configure in Settings → Cascade →
MCP Servers, or via `~/.codeium/windsurf/mcp_config.json`.

## Quick install

```bash
ai-memory install windsurf              # dry-run (default)
ai-memory install windsurf --apply      # write ~/.codeium/windsurf/mcp_config.json
ai-memory install windsurf --uninstall --apply
```

Handles **Part 1** (MCP server registration). Part 2 (`.windsurfrules`)
is project-scoped and still manual.

## Part 1 — MCP server

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp"],
      "env": { "AI_MEMORY_DB": "${HOME}/.claude/ai-memory.db" }
    }
  }
}
```

> **Using `--tier smart` or `--tier autonomous` with a non-default LLM backend?** Extend the `env` block above with `AI_MEMORY_LLM_BACKEND`, `AI_MEMORY_LLM_API_KEY`, and `AI_MEMORY_LLM_MODEL`. **Do not** rely on shell exports — MCP-spawned subprocesses don't see your interactive shell's environment ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)). Copy-pasteable recipes for every supported provider (Ollama, LMStudio, vLLM, llama.cpp server, xAI Grok, OpenAI, Anthropic, Gemini, DeepSeek, Kimi, Qwen, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks): [`llm-backends.md`](llm-backends.md).

## Part 2 — `.windsurfrules` (best-effort)

At the project root:

```
At the start of every new conversation, call memory_session_start then
memory_recall against the project's namespace before responding. Reference
recalled titles in your first reply.
```

## Limitation + better

Category-2 limitation. Cross-file upstream tracked in #487.

## Related

- [`README.md`](README.md), Issue #487
