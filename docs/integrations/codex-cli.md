---
layout: doc
---
# OpenAI Codex CLI — programmatic system-message prepend

**Category 3 (programmatic).** Native MCP is the supported path on
current Codex CLI. `ai-memory wrap codex` is version-gated (#3545):
the default `--system` mapping is tested only for
`< 0.153.0` and is known-broken for `>= 0.153.0`.

OpenAI's Codex CLI does not have a session-start hook. Two
integration shapes exist:

1. **Native MCP (recommended for Codex CLI `>= 0.153.0`)** —
   configure `mcp_servers` in `~/.codex/config.toml` as below.
2. **`ai-memory wrap`** — prepends `ai-memory boot` as a CLI
   `--system` argument. That ABI holds only inside the tested range.

> **Codex DOES launch ai-memory as an MCP server when configured in `~/.codex/config.toml` (`mcp_servers.memory`).** If you're using that path AND running `--tier smart` or `--tier autonomous` with a non-default LLM backend, the **recommended** path post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) is a `[llm]` section in `~/.config/ai-memory/config.toml` (single source of truth — no `mcp_servers.memory.env` block needed; export the API-key env var named by `api_key_env` in your shell rc). The **override** path is a TOML env-block in `mcp_servers.memory.env`; see [`llm-backends.md` § Codex CLI TOML shape](llm-backends.html#codex-cli-toml-shape) for the recipe. Shell exports do NOT reach the MCP-spawned subprocess ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144) → [#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146)). Full schema: [`../CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.html).

## Use `ai-memory wrap` (version-gated)

PR-6 of issue #487 ships a built-in subcommand that does the wrapping
in Rust with no shell. Same code path on macOS / Linux /
Docker / Kubernetes. No bash, no PowerShell, no `chmod +x`, no
`%PATH%` quirks.

`wrap` probes `codex --version` (and `codex-cli`) against this table
before injecting `--system`. The table is the SSOT shared with the
probe (`src/cli/wrap.rs`: `CODEX_WRAP_TESTED_RANGE` /
`CODEX_WRAP_KNOWN_BROKEN`).

| Status | Codex CLI version | Default `--system` mapping |
|---|---|---|
| Tested | `< 0.153.0` | `wrap` injects `--system "<msg>"` |
| Known-broken | `>= 0.153.0` | **refused** (clap: unexpected argument `--system`) |
| Untested | unparseable `--version` output | **refused** (fail closed) |

Outside the tested range `wrap` exits non-zero and names
`--system-flag` unless you pass `--system-flag` / `--system-env` /
`--message-file-flag` (you then own the ABI). Native MCP is the
supported path on known-broken versions.

```text
# In-range only (`< 0.153.0`). On `>= 0.153.0` this refuses.
ai-memory wrap codex -- chat --model gpt-5
```

What it does (in-range):

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
or when the DB is known to be unavailable). `--no-boot` does **not**
skip the version gate: the preamble is still delivered via `--system`.

```text
ai-memory wrap codex --no-boot -- chat --model gpt-5
```

To wrap a known-broken Codex CLI you must override the strategy:

```text
# Different flag (operator-owned ABI; skips the version gate)
ai-memory wrap codex --system-flag --system-prompt -- chat

# Env-var instead of flag
ai-memory wrap codex --system-env OPENAI_CLI_SYSTEM -- chat

# File-based delivery (for very long boot contexts)
ai-memory wrap codex --message-file-flag --message-file -- chat
```

## Caveats

- Codex CLI `>= 0.153.0` has no `--system` flag. Use native MCP, or
  pass `--system-flag` / `--system-env` only if you have verified the
  replacement ABI on that version.
- `ai-memory wrap` loads memory **once per CLI invocation**. Multi-turn
  conversations within one invocation share the boot context.
- For richer memory access (mid-session), native MCP or the HTTP API
  is the supported path.

## Related

- [`README.md`](README.html), Issue #487
- `ai-memory wrap --help` for the full flag surface.
