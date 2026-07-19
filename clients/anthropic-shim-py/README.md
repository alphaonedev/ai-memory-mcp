# ai-memory Anthropic shim (Python)

Record each **Anthropic Messages** turn to [ai-memory](https://github.com/alphaonedev/ai-memory-mcp)
automatically. A Direct-API SDK shim (issue #1390) for callers who use the
`anthropic` SDK in their own scripts — without a host harness (Claude Code,
IDE plugins) that already writes a recoverable transcript.

## Install

```bash
pip install ai-memory-anthropic-shim
pip install anthropic   # peer dependency — you bring your own client
```

You also need the `ai-memory` binary on `PATH` (or set `AI_MEMORY_BIN`). The
shim records turns by calling the `memory_capture_turn` MCP tool per
[RFC-0001](../../docs/rfc/RFC-0001-mcp-turn-capture.md).

## Use

```python
from anthropic import Anthropic
from ai_memory_anthropic_shim import wrap

client = wrap(Anthropic())          # or wrap(AsyncAnthropic()) for async

resp = client.messages.create(
    model="claude-opus-4-8",
    max_tokens=256,
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)
# Two turns are now recorded to ai-memory: your user message and the reply.
print(resp.content[0].text)
```

`wrap()` returns a transparent proxy — use it exactly like the original
client. Every attribute delegates to the wrapped client unchanged; only
`messages.create` is intercepted.

### Options

```python
client = wrap(
    Anthropic(),
    host_session_id="my-session",   # stable dedup key (default: per-wrap UUID)
    namespace="project/notes",       # ai-memory namespace to record into
    ai_memory_bin="/usr/local/bin/ai-memory",
    host_kind="anthropic-sdk",
)
```

## Guarantees

- **Non-wedging.** A capture failure (missing binary, substrate error,
  unexpected response shape) NEVER disturbs your LLM call — it emits a stderr
  WARN and returns your response unchanged.
- **Opaque / pass-through.** Arguments and responses are forwarded verbatim;
  the shim makes minimal assumptions about the vendor SDK's internals.
- **Streaming.** A `stream=True` call records the request turn and passes the
  stream through untouched (consuming it to record the reply would break
  passthrough).
- **Idempotent.** Turns dedup on `host_session_id` + `host_turn_index`, so a
  re-run does not duplicate memories.

## Tests

```bash
pip install -e '.[dev]'
pytest                     # offline: fakes + recorded cassettes, no key needed
ANTHROPIC_API_KEY=sk-... pytest      # + real-SDK shape-extraction leg
AI_MEMORY_TEST_BIN=$(command -v ai-memory) pytest   # + real self-spawned capture
```

## License

Apache-2.0
