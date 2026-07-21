# ai-memory OpenAI shim (Python)

Record each **OpenAI Chat Completions** turn to
[ai-memory](https://github.com/alphaonedev/ai-memory-mcp) automatically. A
Direct-API SDK shim (issue #1390) for callers who use the `openai` SDK in their
own scripts — without a host harness that already writes a recoverable
transcript.

## Install

```bash
pip install ai-memory-openai-shim
pip install openai   # peer dependency — you bring your own client
```

You also need the `ai-memory` binary on `PATH` (or set `AI_MEMORY_BIN`). The
shim records turns via the `memory_capture_turn` MCP tool per
[RFC-0001](../../docs/rfc/RFC-0001-mcp-turn-capture.md).

## Use

```python
from openai import OpenAI
from ai_memory_openai_shim import wrap

client = wrap(OpenAI())          # or wrap(AsyncOpenAI()) for async

resp = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)
# Two turns recorded to ai-memory: your user message and the reply.
print(resp.choices[0].message.content)
```

`wrap()` returns a transparent proxy — use it exactly like the original
client. Only `chat.completions.create` is intercepted; everything else
delegates unchanged.

### Options

```python
client = wrap(
    OpenAI(),
    host_session_id="my-session",   # stable dedup key (default: per-wrap UUID)
    namespace="project/notes",
    ai_memory_bin="/usr/local/bin/ai-memory",
    host_kind="openai-sdk",
)
```

## Guarantees

- **Non-wedging.** A capture failure never disturbs your LLM call — it emits a
  stderr WARN and returns your response unchanged.
- **Opaque / pass-through.** Arguments and responses are forwarded verbatim.
- **Streaming.** A `stream=True` call records the request turn and passes the
  stream through untouched.
- **Idempotent with a stable session id.** Turns dedup on `host_session_id` +
  `host_turn_index`. The default per-wrap UUID deduplicates only within that
  wrapped client; pass a stable `host_session_id` (as above) to deduplicate
  across process re-runs.

## Tests

```bash
pip install -e '.[dev]'
pytest                     # offline: fakes + recorded cassettes, no key needed
OPENAI_API_KEY=sk-... pytest          # + real-SDK shape-extraction leg
AI_MEMORY_TEST_BIN=$(command -v ai-memory) pytest   # + real self-spawned capture
```

## License

Apache-2.0
