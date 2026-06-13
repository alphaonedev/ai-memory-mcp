# v0.7.0 test configuration

> **Status:** living doc. Operator-stamped configuration for future
> test runs against the v0.7.0 substrate.

## Substrate LLM (current standing default, 2026-05-31)

**Canonical model id:** `google/gemma-4-26b-a4b-it`
**Provider:** OpenRouter (`https://openrouter.ai/api/v1`, OpenAI-compatible wire shape)
**API key env var:** `OPENROUTER_API_KEY` (lives in `~/.env` on the .50.100 node, sourced via `set -a; source ~/.env; set +a`)
**ai-memory backend alias:** `openrouter` (per `src/llm.rs::alias_default_base_url`; recognized at `AI_MEMORY_LLM_BACKEND=openrouter`)

Operator directive 2026-05-31 (supersedes the 2026-05-21 #1067 xAI
Grok 4.3 and 2026-05-31-morning Ollama gemma4:e4b configs):

- **Local ai-memory daemon** (the daemon serving this node's Claude
  Code MCP at `~/.claude/ai-memory.db`) — wired via
  `~/.config/ai-memory/config.toml` `[llm]` section. Backups of the
  prior xAI and Ollama configs preserved as
  `~/.config/ai-memory/config.toml.bak.20260531-105716` (xAI/grok-4.3)
  and `~/.config/ai-memory/config.toml.bak.20260531-openrouter`
  (Ollama/gemma4:e4b) for reversion-without-reconstruction.
- **IronClaw A2A docker-compose** (Track B's `ic-parity-alice` +
  `ic-parity-bob` ai-memory services on the lan-parity-test fleet) —
  wired via `infra/lan-parity-test/docker-compose.yml`. The same
  model and env-var conventions apply.

**Connectivity probe (2026-05-31 11:23 ET):**

```
$ curl https://openrouter.ai/api/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENROUTER_API_KEY" \
    -d '{ "model": "google/gemma-4-26b-a4b-it",
          "messages": [{"role":"user","content":"How many rs are in strawberry?"}] }'

HTTP 200, 2.197s latency
Response: "There are **3** \"r\"s in the word strawberry (st**r**awbe**rr**y)."
Cost: $0.0000137 per call (prompt 22 tok + completion 26 tok)
Provider: NextBit (vllm-0.20.2rc1.dev49+g9b4e83934-tp4-ep)
```

**Cost + latency baseline (vs prior substrate choices):**

| Choice | $/M prompt | $/M completion | Probe call cost | Context window |
|---|---|---|---|---|
| xAI grok-4.3 (pre-2026-05-31) | $3.00 | $15.00 | ~$0.0015 | ~256K |
| Local Ollama gemma4:e4b (interim) | $0 | $0 | $0 | ~8K |
| **OpenRouter google/gemma-4-26b-a4b-it (now)** | **$0.06** | **$0.33** | **~$0.0000137** | **262,144** |

50-95× cheaper than xAI Grok 4.3 at the per-token unit. Effectively
free at the substrate's operating volume (autonomous-tier hot path
firing on every `memory_store` / `memory_recall`; ~1000 calls/day
estimate → ~$0.014/day operating cost vs $44+/day on Grok 4.3).
262144-token context is a material upgrade over the 8K local Ollama
window for long reflect / atomise / calibrate prompts.

**Reasoning + parameter posture.** `google/gemma-4-26b-a4b-it` accepts
OpenAI-compatible `reasoning.enabled: true` extension (per OpenRouter's
docs and confirmed via the connectivity probe payload above). For
substrate AI NHI workloads (auto_tag, query_expansion,
contradiction_detection, atomise, persona, reflect, calibrate) the
default `reasoning.enabled` posture is **left UNSET** — Gemma 4 26B
ships its strongest output by default; the reasoning toggle is
reserved for the cross-LLM evaluation track (xAI Grok 4.3 + future
benchmark engagements), not the substrate's day-to-day operation.

**What this choice covers in the campaign reports:**

- Track A build-install — N/A (no LLM in build path)
- Track B IronClaw A2A — **OpenRouter Gemma 4 26B** is the LLM substrate
  for both `ic-parity-alice` and `ic-parity-bob` (canonical heterogeneous
  AI NHI dialog). Prior campaign runs that recorded "xAI Grok 4.3" or
  "Ollama gemma4:e4b" as the substrate model reflect the historical
  daemon snapshot at the time of those runs; this section is the
  forward-going truth.
- Track C postgres+AGE — N/A
- Track D docs-pages drift — N/A
- Track E COALA citation — LLM substrate is OpenRouter Gemma 4 26B
- Track F AI NHI assessment v3 — heterogeneous-AI-NHI v1 evaluation
  CONTINUES to use the operator-stamped cross-LLM matrix (xAI Grok 4.3,
  Claude Opus 4.7, etc.) for the verdict — the substrate's day-to-day
  LLM (Gemma 4 26B) is a SUBJECT of that evaluation, not a participant
  in the verdict-issuing committee.

**Future re-evaluation triggers.** Switch the default again when ANY
of these become true:
- OpenRouter Gemma 4 26B becomes rate-limited or pricing-changed in a
  way that materially affects the daily-operating-cost line above
- A materially stronger Gemma / open-weights model lands on OpenRouter
  at comparable or lower cost
- The substrate's privacy posture changes (e.g., a customer engagement
  requires on-host inference; switch back to the local Ollama config
  preserved in the `~/.config/ai-memory/config.toml.bak.20260531-openrouter`
  snapshot)

## xAI model id for cross-LLM AI NHI evaluation

**Canonical model id:** `grok-4.3`

Operator note 2026-05-15. Replaces `grok-4.20-0309-reasoning` (used for
the Phase E AI NHI cross-LLM verdict at the v0.7.0 ship campaign,
2026-05-14, doc `docs/v0.7.0/ai-nhi-verdict-claude-vs-grok.md`).

Applies to:

- Re-runs of the LongMemEval benchmark (`docs/benchmarks/longmemeval-reflection.md`)
- PersonaMem benchmark engagement (companion doc; targets v0.7.0+)
- Any future cross-LLM AI NHI evaluation against the substrate
- AI NHI workflow brief construction: any agent dispatching xAI API
  calls should use `grok-4.3` in the model field

API endpoint and key conventions are unchanged
(`https://api.x.ai/v1/chat/completions`, `XAI_API_KEY` env). Only the
`"model"` field in the request body changes.

## `reasoning_effort` parameter

`grok-4.3` is a reasoning model and supports a `reasoning_effort`
parameter controlling how much thinking the model does before
responding. Operator-stamped guidance:

| Effort | Behavior | Use when |
|---|---|---|
| `"none"` | Disables reasoning entirely; no thinking tokens used | Simple use cases needing near-instant response |
| `"low"` (default) | Some reasoning tokens, still fast | General agentic use, tool calling |
| `"medium"` | More thinking, less latency-sensitive | Complex data analysis, long-context reasoning |
| `"high"` | Deep thinking | Very challenging problems, complex math, multi-step logic, competition-level tasks |

For ai-memory's cross-LLM AI NHI evaluation (15-scenario substrate
evaluation pattern from Phase E), **`"medium"` is the recommended
default** — scenarios require the model to reason about substrate
behaviour over the course of an evaluation; `"low"` undershoots on the
harder cases (S5 recursive reflection, S6 evidence-packet integrity)
while `"high"` adds latency without a verdict-quality improvement at
the scenario shapes ai-memory exercises.

### Incompatible parameters

When using `grok-4.3`, the following request parameters **return an
error** (do not include them):

- `presence_penalty`
- `frequency_penalty`
- `stop`

If the upstream xAI SDK or any wrapper sets these by default, override
them to `None` / strip them before dispatch.

### Summarized reasoning content

`grok-4.3` exposes summarized reasoning via `chunk.reasoning_content`
when streaming. For audit-honest evaluation reports (per the
audit-honest discipline of Phase E), the reasoning summary SHOULD be
captured alongside the final response — operators and procurement
reviewers reading the verdict report benefit from seeing the
model's stated reasoning path, not just its conclusion.

Sample stream pattern (Python xAI SDK):

```python
chat = client.chat.create(model="grok-4.3", reasoning_effort="medium", messages=[...])
for response, chunk in chat.stream():
    if chunk.reasoning_content:
        print(chunk.reasoning_content, end="", flush=True)
    if chunk.content:
        print(chunk.content, end="", flush=True)
```

## Multi-agent variant: `grok-4.20-multi-agent`

There's also a multi-agent variant. The `reasoning.effort` parameter
on `grok-4.20-multi-agent` controls **agent count**, NOT reasoning
depth:

| `reasoning.effort` | Agent count |
|---|---|
| `"low"` / `"medium"` | 4 |
| `"high"` / `"xhigh"` | 16 |

ai-memory cross-LLM evaluation does not use the multi-agent variant
by default. Single-agent `grok-4.3` at `medium` reasoning is the
canonical pattern for v0.7.0+ test runs.

## Cost discipline

Reasoning tokens are billed as part of total consumption. For
multi-agent variants, ALL tokens from both the leader agent and
sub-agents bill — 16 agents (`"high"` / `"xhigh"`) uses significantly
more tokens than 4 agents.

For ai-memory's standard 15-scenario evaluation:
- `grok-4.3` `"low"` effort: ~5-10× baseline tokens
- `grok-4.3` `"medium"` effort: ~15-25× baseline tokens
- `grok-4.3` `"high"` effort: ~40-80× baseline tokens
- `grok-4.20-multi-agent` `"high"` (16 agents): ~150-300× baseline

Budget guidance: ~$3-5 USD per cross-LLM 15-scenario run on
`grok-4.3` `"medium"` at v0.7.0 release pricing. The multipliers above
are the load drivers; the dollar figure is the operating cap a
campaign run should size against.

## Future test runs that will use grok-4.3 @ medium

- v0.7.0.1 post-tag verification (if any)
- v0.8.0 ship campaign cross-LLM verdict
- Benchmark engagements (WideSearch, SWE-bench, AA-LCR, PersonaMem)
  per the companion benchmark doc

## Why this matters

Phase E AI NHI evaluation derived its convergent-favorable verdict
from Claude Opus 4.7 + Grok 4.20-0309-reasoning. Re-running the same
scenarios on a newer model is meaningful only if both LLMs are
identified by their canonical ids AND the reasoning depth is held
constant. This note pins both so the agent dispatching scenarios
doesn't inadvertently hit a stale SKU or use the wrong reasoning
budget.
