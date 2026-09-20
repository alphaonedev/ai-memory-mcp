# Cache-to-Cache (C2C) — 3x7 adversarial assessment for ai-memory

**Paper:** *Cache-to-Cache: Direct Semantic Communication Between Large Language Models* (arXiv 2510.03215, ICLR 2026): LLMs exchange KV-cache fragments through a learned fuser instead of text, reported as 8.5-10.5 % accuracy over text-to-text communication and about 2x lower latency between paired open-weight models.

**Method.** Seven independent lenses (ciso, data, sre, procurement, adopter, commercial, adversary) balloted alone against the paper and the v1.0.0 codebase (base `436459898`, codegraph-navigated), round 1 (112 findings), then a converge round in which every lens attacked the round-1 majorities (58 findings). The tally is mechanical: 5/7 decides, 3-4/7 goes to the Conductor. Ballots and tallies: `f1-audit-3x7/ballots/F-r*-c2c-*.md`, `tallies/F-r1-c2c.md`, `tallies/F-r2-c2c.md` (Conductor archive).

## Verdict

**NOT-APPLICABLE for v1.0.x, WATCH with a named trigger.** No roadmap line is written; the acceptance criteria below are recorded so a future integrator does not have to rediscover them.

| topic | round-1 majority | converge | decision |
|---|---|---|---|
| (1) applicability to the substrate | NOT-APPLICABLE 14/16 | held; the *reason* was replaced (see below) | NOT-APPLICABLE |
| (2) a "cache-fragment" memory kind | RISK 15/26 | held, with a recorded minority | RISK, not built |
| (3) security | RISK 21/22 | held 7/7 | RISK, not built |
| (4) federation / wake plane | NOT-APPLICABLE 11/14 | held | NOT-APPLICABLE |
| (5) commercial | RISK 14/20 | held | RISK |
| (6) WATCH trigger | WATCH | WATCH 8/11 | WATCH |
| (7) roadmap line | NOT-APPLICABLE 4/7 | Conductor adjudication | none written |

## Findings by topic

**(1) Wrong layer, and the honest reason.** ai-memory is a text-and-row substrate: the three integration categories it ships (MCP tools, HTTP API, SDK shims) all carry text; the boot and wrap recipes are prompt text; the paid tiers document Claude, GPT and Gemini reached through vendor APIs, where no caller has KV-cache access. The converge round rejected round 1's first phrasing ("the substrate does no weight handling"): the codebase does ship third-party weights and tokenisers for local embedding and reranking, so that sentence is rebuttable in one grep. The reason that survives every lens is narrower and true: **a C2C fuser is a model-side artefact between two co-located open-weight models; nothing in the substrate's layer changes whether or not a customer's fleet adopts it.** The GPU policy already shipped points the other way (CPU-first embedding, no resident model), and local hosts (Ollama, vLLM, llama.cpp) expose no fused-KV interface today.

**(2) A cache-fragment memory kind: refused at every ingress.** A KV fragment is bound to one model build, one layer schema and one host; measured as bytes stored per millisecond saved it is roughly ten times worse than the text it replaces (the converge round corrected a round-1 overstatement in our own favour by that factor). The 65 536-byte content cap (`src/models/mod.rs`) and the reserved-kind refusal make the kind physically untransportable through the current write funnels, and the secret screen cannot inspect an opaque tensor. The data lens holds a minority position that the substrate's derived-artefact pattern (embeddings and reranker scores derived from a row and re-derivable from it) could name such a kind in v1.1.x; recorded, not adopted.

**(3) Security: RISK, and which mechanism is the unfixable one.** Every lens found the same cluster: a fused fragment is opaque to the secret screen, the covenant and the forensic ledger, so any recall-time memory-as-prompt-injection finding from the red team would become invisible rather than solved. The converge round settled two disputes: the "intra-host fusion is blind" cluster was one finding filed seven times, not seven findings, and the strongest unfixable mechanism is not the screen (blindness to an opaque blob is an already-adjudicated bounded property) but **re-certification**: a buyer's security review prices "we would have to re-certify the enterprise-federation posture" instantly, and no C2C benefit offsets that.

**(4) Federation and the wake plane: NOT-APPLICABLE.** The wake plane is a latency optimisation over a durable row (hub loss costs latency only, the inbox row stays). Cross-node fusion would require moving model-bound tensors between hosts that the reserved-kind refusal already rejects; the argument rests on that refusal, not on the byte cap. A federated buyer is the one who would pay for cross-node latency, which is why this is WATCH and not NONE.

**(5) Commercial: RISK.** No billing unit exists for a fused fragment: it is not a row, not a token, not a call. "No billing unit, no SKU" survived every model of the market the seven lenses tried. The operations cost (a resident open-weight pair per host, GPU residency, fuser retraining per model build) only exists if a customer adopts C2C, and zero of the substrate's paid-tier customers can enable it without first buying a different stack.

**(6) The WATCH trigger, stated once.** Reopen this assessment when all three hold: (a) a host API the substrate integrates with exposes KV-cache read and write for a model the customer runs (an API, not a paper); (b) a fragment kind can be bound to a model build id, a layer schema and a host so the screen, the covenant and the ledger can refuse or attest it as a unit; (c) a paying customer names cross-agent latency as the purchase criterion. Engineering preconditions (a) and (b) without (c) produce no revenue to price against the re-certification cost.

**(7) Roadmap.** No `docs/ROADMAP` line. This document is the record; the trigger above is the acceptance criterion for writing one.

## Corrections the converge round made to round 1
- The "no weight handling" premise was false as written (embedding and reranking weights ship); verdict unchanged, reason replaced.
- The cache-fragment cost was overstated tenfold in the substrate's favour; corrected and still RISK.
- The screen-blindness argument is weaker than seven lenses assumed; re-certification is the load-bearing security reason.
- Three scattered "design note" rows were one finding; recorded once.

*Prepared by the Conductor (Claude Fable 5.1) from the f1 3x7 program run under the binary2029 account, 2026-09-17/18. Decision document only: it changes no product code and triggers no release.*
