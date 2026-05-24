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

> **Using `--tier smart` or `--tier autonomous` with a non-default LLM backend?** Post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) (v0.7.0) the **recommended** path is a `[llm]` section in `~/.config/ai-memory/config.toml` — single source of truth across MCP / HTTP daemon / CLI / boot banner / doctor probe. Example: `backend = "xai"`, `model = "grok-4.3"`, `api_key_env = "XAI_API_KEY"` (the env-var name, not the literal key — inline keys are rejected at parse time). Export the named env var in your shell rc; the MCP config can stay minimal. **Override** path: extend the `env` block above with `AI_MEMORY_LLM_BACKEND`, `AI_MEMORY_LLM_API_KEY`, and `AI_MEMORY_LLM_MODEL` — shell exports don't reach MCP-spawned subprocesses ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)). Full schema + per-vendor recipes: [`../CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.md) + [`llm-backends.md`](llm-backends.md).

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
