# ai-memory OpenAI shim (TypeScript)

Record each **OpenAI Chat Completions** turn to
[ai-memory](https://github.com/alphaonedev/ai-memory-mcp) automatically. A
Direct-API SDK shim (issue #1390) for callers who use the `openai` SDK in their
own scripts — without a host harness that already writes a recoverable
transcript.

## Install

```bash
npm install @alphaone/ai-memory-openai-shim
npm install openai   # peer dependency — you bring your own client
```

You also need the `ai-memory` binary on `PATH` (or set `AI_MEMORY_BIN`). The
shim records turns via the `memory_capture_turn` MCP tool per
[RFC-0001](../../docs/rfc/RFC-0001-mcp-turn-capture.md).

## Use

```ts
import OpenAI from "openai";
import { wrap } from "@alphaone/ai-memory-openai-shim";

const client = wrap(new OpenAI());

const resp = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "What is the capital of France?" }],
});
// Two turns recorded to ai-memory: your user message and the reply.
console.log(resp.choices[0].message.content);
```

`wrap()` returns a transparent proxy — use it exactly like the original
client. Only `chat.completions.create` is intercepted; everything else
delegates unchanged.

### Options

```ts
const client = wrap(new OpenAI(), {
  hostSessionId: "my-session", // stable dedup key (default: per-wrap UUID)
  namespace: "project/notes",
  aiMemoryBin: "/usr/local/bin/ai-memory",
  hostKind: "openai-sdk",
});
```

## Guarantees

- **Non-wedging.** A capture failure never disturbs your LLM call — it emits a
  stderr WARN and returns your response unchanged.
- **Opaque / pass-through.** Arguments and responses are forwarded verbatim.
- **Streaming.** A `stream: true` call records the request turn and passes the
  stream through untouched.
- **Idempotent with a stable session id.** Turns dedup on `hostSessionId` +
  `hostTurnIndex`. The default per-wrap UUID deduplicates only within that
  wrapped client; pass a stable `hostSessionId` (as above) to deduplicate
  across process re-runs.

## Tests

The offline suite runs with Node's built-in test runner + type-stripping — no
build step, no jest, no `node_modules`:

```bash
npm test          # node --experimental-strip-types --test (Node >= 22.6)
npm run build     # tsc -> dist/ (publish artifact)
npm run typecheck # tsc --noEmit
```

## License

Apache-2.0
