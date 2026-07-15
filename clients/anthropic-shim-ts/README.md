# ai-memory Anthropic shim (TypeScript)

Record each **Anthropic Messages** turn to
[ai-memory](https://github.com/alphaonedev/ai-memory-mcp) automatically. A
Direct-API SDK shim (issue #1390) for callers who use `@anthropic-ai/sdk` in
their own scripts — without a host harness that already writes a recoverable
transcript.

## Install

```bash
npm install @alphaone/ai-memory-anthropic-shim
npm install @anthropic-ai/sdk   # peer dependency — you bring your own client
```

You also need the `ai-memory` binary on `PATH` (or set `AI_MEMORY_BIN`). The
shim records turns via the `memory_capture_turn` MCP tool per
[RFC-0001](../../docs/rfc/RFC-0001-mcp-turn-capture.md).

## Use

```ts
import Anthropic from "@anthropic-ai/sdk";
import { wrap } from "@alphaone/ai-memory-anthropic-shim";

const client = wrap(new Anthropic());

const resp = await client.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 256,
  messages: [{ role: "user", content: "What is the capital of France?" }],
});
// Two turns recorded to ai-memory: your user message and the reply.
console.log(resp.content[0].text);
```

`wrap()` returns a transparent proxy — use it exactly like the original
client. Only `messages.create` is intercepted; everything else delegates
unchanged.

### Options

```ts
const client = wrap(new Anthropic(), {
  hostSessionId: "my-session", // stable dedup key (default: per-wrap UUID)
  namespace: "project/notes",
  aiMemoryBin: "/usr/local/bin/ai-memory",
  hostKind: "anthropic-sdk",
});
```

## Guarantees

- **Non-wedging.** A capture failure never disturbs your LLM call — it emits a
  stderr WARN and returns your response unchanged.
- **Opaque / pass-through.** Arguments and responses are forwarded verbatim.
- **Streaming.** A `stream: true` call records the request turn and passes the
  stream through untouched.
- **Idempotent.** Turns dedup on `hostSessionId` + `hostTurnIndex`.

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
