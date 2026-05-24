# Cline (VS Code extension) — MCP server + custom instructions

**Category 2.** Cline is MCP-capable; configure via Cline's Settings
panel or `~/.cline/mcp_settings.json` (varies by version).

## Quick install

Cline's MCP config path varies between releases (the file has lived at
`~/.cline/mcp_settings.json` and under the VS Code extension data dir),
so the installer requires `--config <path>`:

```bash
# TODO(#487): once Cline pins a canonical path, --config will be optional.
ai-memory install cline --config ~/.cline/mcp_settings.json
ai-memory install cline --config ~/.cline/mcp_settings.json --apply
ai-memory install cline --config ~/.cline/mcp_settings.json --uninstall --apply
```

Find your active config by opening Cline → Settings → MCP and noting the
file path it reads from. This handles **Part 1** below; Part 2 (custom
instructions) is still manual.

## Part 1 — MCP server

```json
{
  "mcpServers": {
    "ai-memory": {
      "command": "ai-memory",
      "args": ["mcp"],
      "env": { "AI_MEMORY_DB": "${HOME}/.claude/ai-memory.db" },
      "disabled": false,
      "autoApprove": ["memory_session_start", "memory_recall", "memory_capabilities"]
    }
  }
}
```

`autoApprove` lets the model call read-only memory tools without prompting
for permission on every call — required for a smooth boot path.

> **Using `--tier smart` or `--tier autonomous` with a non-default LLM backend?** Post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) (v0.7.0) the **recommended** path is a `[llm]` section in `~/.config/ai-memory/config.toml` — single source of truth across MCP / HTTP daemon / CLI / boot banner / doctor probe. Example: `backend = "xai"`, `model = "grok-4.3"`, `api_key_env = "XAI_API_KEY"` (the env-var name, not the literal key — inline keys are rejected at parse time). Export the named env var in your shell rc; the MCP config can stay minimal. **Override** path: extend the `env` block above with `AI_MEMORY_LLM_BACKEND`, `AI_MEMORY_LLM_API_KEY`, and `AI_MEMORY_LLM_MODEL` — shell exports don't reach MCP-spawned subprocesses ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)). Full schema + per-vendor recipes: [`../CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.md) + [`llm-backends.md`](llm-backends.md).

## Part 2 — Custom Instructions (best-effort)

Settings → Cline → Custom Instructions:

> At the start of every conversation, before responding to the user's first
> message, call `memory_session_start` then `memory_recall` against the
> current project's namespace. Reference recalled titles in your first reply.

## Limitation

Same as Cursor (category 2). A native SessionStart hook would close the
gap; cross-file at Cline upstream tracked in #487.

## Related

- [`README.md`](README.md), Issue #487
