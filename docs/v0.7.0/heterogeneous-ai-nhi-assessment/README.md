# Heterogeneous AI NHI Assessment of ai-memory v0.7.0 (`attested-cortex`)

A first-of-its-kind multi-evaluator, model-heterogeneous assessment of the v0.7.0 substrate by three frontier AI NHI agents (Anthropic Claude Opus 4.7, OpenAI GPT 5.5, xAI Grok 4.3) running the same prompt in isolation, then synthesized.

**Operator:** Justin Jessup, AlphaOne LLC.
**Issue:** [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171)
**Substrate version:** ai-memory v0.7.0 at `release/v0.7.0` HEAD (post-#1168 merge).
**Date:** 2026-05-24.

## Why three evaluators

ai-memory v0.7.0 runs an LLM-agnostic reflection boundary by design. The substrate does not care which model wrote a reflection. This assessment exercises that property at the assessment layer itself — the decorrelated errors across three model families with different training distributions, RLHF lineage, and architectural priors are the entire methodological point. Same-model reflection re-introduces the echo-chamber problem this assessment exists to surface.

See [`prompt.md`](./prompt.md) §0 for the full heterogeneity-as-design argument and the three computational facts that distinguish an NHI from a human reviewer.

## Evaluator pool & reports

| Evaluator | Provider | Report | Status |
|---|---|---|---|
| Claude Opus 4.7 (v1) | Anthropic | [`report-claude-opus-4-7.md`](./report-claude-opus-4-7.md) | Phase 1 initial — 2026-05-24 |
| Claude Opus 4.7 (v2) | Anthropic | [`report-claude-opus-4-7-v2.md`](./report-claude-opus-4-7-v2.md) | Phase 1 re-run — 2026-05-25 (isolated DB, curator LIVE) |
| Claude Opus 4.7 (v3) | Anthropic | [`report-claude-opus-4-7-v3.md`](./report-claude-opus-4-7-v3.md) | **2026-05-28 re-run post-FX-12/FX-C3/ARCH-2 + ship-gate fixes, HEAD `be3347d70`; SHIP verdict; 22 probes, 15 LIVE; filed D-v3-1/2/3 + observation O-v3-1 (historical chain-break at seq=28 — substrate-correct)** |
| GPT 5.5 | OpenAI | [`report-gpt-5-5.md`](./report-gpt-5-5.md) | Awaiting independent execution |
| Grok 4.3 | xAI | [`report-grok-4-3.md`](./report-grok-4-3.md) | Awaiting independent execution |

| Synthesis | Author | Output |
|---|---|---|
| Phase 2 orchestrator pass | Claude Opus 4.7 (synthesizer-role, post-Phase 1) | [`synthesis.md`](./synthesis.md) — awaiting all three Phase 1 reports |

## Files in this directory

- **[`prompt.md`](./prompt.md)** — the verbatim assessment prompt. Anchor for all three reports. The probe matrix (P1-P22 across 5 tiers) is concrete and code-path-anchored; the deliverable shape (§A-§I, ~2500-4000 words) is structured; the honesty discipline is load-bearing.
- **[`report-claude-opus-4-7.md`](./report-claude-opus-4-7.md)** — Anthropic Claude Opus 4.7 evaluator report.
- **[`report-gpt-5-5.md`](./report-gpt-5-5.md)** — OpenAI GPT 5.5 evaluator report.
- **[`report-grok-4-3.md`](./report-grok-4-3.md)** — xAI Grok 4.3 evaluator report.
- **[`synthesis.md`](./synthesis.md)** — orchestrator-pass synthesis after all three Phase 1 reports land.

## Three-phase protocol

**Phase 1 — Isolated execution (90-120 min per evaluator, no cross-talk).** Each evaluator runs the full probe matrix against its own `/tmp/v070-nhi-assessment-<ts>-<evaluator>/` (or `.local-runs/`-equivalent per the CLAUDE.md `/tmp` hard-rule override) workspace and writes its own report. Evaluators do NOT read each other's reports during this phase. This preserves the decorrelated-errors property.

**Phase 2 — Orchestrator synthesis.** An orchestrator pass (run by Claude Opus 4.7 as synthesizer-role, against all three reports as input) produces `synthesis.md` with:
- Points of agreement (high-confidence claims about v0.7.0).
- Points of principled disagreement, organized by axis (latency tolerance, surface-size opinion, magic-vs-feature framing, reference-architecture grading, what counts as a step-change primitive).
- Cross-model bias-detection — claims one evaluator made that another flagged as model-specific bias rather than substrate property. This is the highest-information output of the multi-evaluator design.

**Phase 3 — Operator review.** Jim reviews the synthesis. Disagreements get resolved by (a) re-probing the contested primitive, (b) operator override with rationale, or (c) filing as known cross-model uncertainty in the v0.7.0 release notes.

## Cross-evaluator scoreboard

To be populated post-Phase 2. Tracks the agreement matrix on:
- Step-change primitives (§B) — count of evaluators who flagged each primitive
- Concern→primitive mapping (§D) — agreement on which v0.7.0 primitives satisfy each AI NHI existential concern
- Architectural maturity grading (§E) — % coverage scores per reference architecture, by evaluator
- Operational verdict (§I) — SHIP / SHIP-WITH-CAVEATS / NEEDS-WORK distribution

## After all three reports land

A GitHub Pages render publishes the full assessment at:
[https://alphaonedev.github.io/ai-memory-mcp/v0.7.0/heterogeneous-ai-nhi-assessment/](https://alphaonedev.github.io/ai-memory-mcp/v0.7.0/heterogeneous-ai-nhi-assessment/)

The cross-evaluator synthesis becomes the public-facing high-confidence verdict on what v0.7.0 brings to AI NHI cognition.
