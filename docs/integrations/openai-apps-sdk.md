# OpenAI Apps SDK / Assistants / Responses — system-message prepend

**Category 3 (programmatic).** 100% reliable when implemented.

OpenAI's Assistants API, Responses API, and Apps SDK all expose system
messages / instructions as the integration point. Prepend `ai-memory boot`
output before creating the assistant or before the first request.

> **Cross-reference — using OpenAI as ai-memory's own LLM backend.** This doc covers OpenAI-family endpoints as the AI client. For the inverse direction (ai-memory's smart / autonomous tier calling OpenAI internally for query expansion, auto-tag, contradiction detection), the recommended path post-[#1146](https://github.com/alphaonedev/ai-memory-mcp/issues/1146) (v0.7.0) is a `[llm]` section in `~/.config/ai-memory/config.toml` (`backend = "openai"`, `model = "gpt-5"`, `api_key_env = "OPENAI_API_KEY"`); see [`../CONFIG_SCHEMA.md`](../CONFIG_SCHEMA.md) for the canonical schema. The override path is the MCP env-block recipe in [`llm-backends.md` § OpenAI](llm-backends.md#openai) — shell exports don't reach MCP-spawned subprocesses ([#1144](https://github.com/alphaonedev/ai-memory-mcp/issues/1144)).

## Or for the simple wrapper case — `ai-memory wrap`

For callers that just want to spawn an OpenAI-compatible CLI with
boot context prepended (no SDK code in your path), PR-6 of issue
#487 ships a built-in cross-platform Rust subcommand:

```bash
# Wraps a CLI that exposes --system <msg> (the default for most
# OpenAI-compatible chat clients).
ai-memory wrap openai-cli -- chat --model gpt-4.1

# Override the flag if your CLI uses a different name.
ai-memory wrap mycli --system-flag --instructions -- chat
```

`ai-memory wrap` is the cross-platform Rust replacement for the
bash / PowerShell wrappers earlier PRs shipped. Same binary works on
macOS / Linux / Windows / Docker / Kubernetes; no shell required.

For SDK code (the patterns below) `wrap` doesn't apply — `wrap` is
for the launcher case where the SDK isn't in your code path.

## Assistants API (Python)

```python
import subprocess
from openai import OpenAI

def boot_context() -> str:
    try:
        return subprocess.check_output(
            ["ai-memory", "boot", "--quiet", "--no-header",
             "--format", "text", "--limit", "10"],
            text=True,
        ).strip()
    except Exception:
        return ""

memory = boot_context()
instructions = "You are a helpful assistant."
if memory:
    instructions += f"\n\n## Recent context (ai-memory)\n{memory}"

client = OpenAI()
assistant = client.beta.assistants.create(
    name="memory-aware",
    instructions=instructions,
    model="gpt-4.1",
)
```

## Responses API (TypeScript)

```typescript
import OpenAI from "openai";
import { execSync } from "node:child_process";

const memory = (() => {
  try {
    return execSync(
      "ai-memory boot --quiet --no-header --format text --limit 10",
      { encoding: "utf-8" }
    ).trim();
  } catch { return ""; }
})();

const client = new OpenAI();
const response = await client.responses.create({
  model: "gpt-4.1",
  instructions: `You are a helpful assistant.${memory ? `\n\n## Recent context (ai-memory)\n${memory}` : ""}`,
  input: userMessage,
});
```

## Apps SDK

The Apps SDK uses an `instructions` field on the App Definition. Build the
string the same way as the other examples and pass it at app construction.

## Caveats

- For long-lived assistants, boot context becomes stale. Prefer recreating
  the assistant per session, or use the `additional_instructions` field
  on `runs.create` to inject fresh boot context per run.
- For Responses API: `instructions` is per-request, so freshness is free.

## Related

- [`README.md`](README.md), Issue #487
