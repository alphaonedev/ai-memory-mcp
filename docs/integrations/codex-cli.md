# OpenAI Codex CLI — programmatic system-message prepend

**Category 3 (programmatic).** 100% reliable when implemented.

OpenAI's Codex CLI does not have an MCP host or a session-start hook
mechanism. The integration is at the application boundary: prepend
`ai-memory boot` output to the system message before each new
conversation.

> **Codex DOES launch ai-memory as an MCP server when configured in `~/.codex/config.toml` (`mcp_servers.memory`).** If you're using that path AND running `--tier smart` or `--tier autonomous` with a non-default LLM backend, the **recommended** path post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) is a `[llm]` section in `~/.config/ai-memory/config.toml` (single source of truth — no `mcp_servers.memory.env` block needed; export the API-key env var named by `api_key_env` in your shell rc). The **override** path is a TOML env-block in `mcp_servers.memory.env`; see [`llm-backends.md` § Codex CLI TOML shape](llm-backends.md#codex-cli-toml-shape) for the recipe. Shell exports do NOT reach the MCP-spawned subprocess ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144) → [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)). Full schema: [`../CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.md).

## Use `ai-memory wrap` (recommended — pure Rust, cross-platform)

PR-6 of issue #487 ships a built-in subcommand that does the wrapping
in Rust with no shell. Same code path on macOS / Linux / Windows /
Docker / Kubernetes. No bash, no PowerShell, no `chmod +x`, no
`%PATH%` quirks.

```text
ai-memory wrap codex -- chat --model gpt-5
```

What it does:

1. Calls `ai-memory boot --quiet --format text --limit 10
   --budget-tokens 4096` in-process (no subprocess).
2. Builds a system message of the form
   `<preamble>\n\n<boot output>` where the preamble tells the agent
   it has ai-memory access.
3. Spawns `codex --system "<system message>" chat --model gpt-5`
   with stdin/stdout/stderr inherited unmodified.
4. Exits with whatever code `codex` returned, so shell pipelines and
   CI scripts that branch on `$?` still work.

Use `--no-boot` to skip the in-process boot call (useful for testing
or when the DB is known to be unavailable):

```text
ai-memory wrap codex --no-boot -- chat --model gpt-5
```

The default lookup table maps `codex` and `codex-cli` to the
`SystemFlag { flag: "--system" }` strategy. If your Codex variant
exposes a different flag (`--system-prompt`, env-var-only, etc.),
override:

```text
# Different flag
ai-memory wrap codex --system-flag --system-prompt -- chat

# Env-var instead of flag
ai-memory wrap codex --system-env OPENAI_CLI_SYSTEM -- chat

# File-based delivery (for very long boot contexts)
ai-memory wrap codex --message-file-flag --message-file -- chat
```

## Caveats

- The exact flag name depends on which Codex CLI variant is installed.
  Check `codex --help` and override with `--system-flag` or
  `--system-env` if needed.
- `ai-memory wrap` loads memory **once per CLI invocation**. Multi-turn
  conversations within one invocation share the boot context.
- For richer memory access (mid-session), the developer would need to
  add function-calling support pointing at `ai-memory`'s HTTP API.
  That's a larger integration than the boot recipe and lives outside
  this doc.

## Related

- [`README.md`](README.md), Issue #487
- `ai-memory wrap --help` for the full flag surface.
