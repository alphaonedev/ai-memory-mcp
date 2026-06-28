# Agent 11 — Sibling Repo / Future-Proofing (ISOLATED)

**Lens:** Sibling Repo / Future-Proofing  
**Subagent ID:** `019f0e12-71db-70c3-9447-865c7710ff5c`  
**Run:** ISOLATED — no cross-talk with Agents 1–10  
**Date:** 2026-06-28  
**Codebase:** `release/v0.8.0` @ `c85b9c56` (CodeGraph mandatory)  
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) §0  
**Prior art:** [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md)  
**Paper:** [RQGM arXiv:2606.26294](https://arxiv.org/abs/2606.26294)

---

## Structured verdict (machine fields)

| Field | Value |
|-------|-------|
| **VERDICT** | EXTERNAL L3 **hard**; RQ-01 epoch manifest schema **P0**; `ai-memory-rqgm` sibling v0.9.1+ |
| **CONFIDENCE** | **87%** (91% on external L3 boundary; 78% on ASI utility measurability survivability of any L3 algorithm) |
| **ASI_MOONSHOT_GRADE** | **A−** — pathway preserves all seven §2 properties through ASI; −½ for missing RQ-01 consumer in `src/` today |
| **TOP_RISK** | No signed `epoch_manifest.json` consumer → external L3 is deployable fiction |
| **KILLER_OBJECTION** | Internal RQGM ossifies wrong layer; **algorithm churn must live in sibling** |

### Votes

| Q | Vote | Rationale (one line) |
|---|------|----------------------|
| **Q1** | **YES** — principles only; **CUT** full RQGM algorithm from `src/` | Red Queen *principles* load-bearing for §2.6; search is not substrate law |
| **Q2** | **HYBRID-as-contract** — L1+L2 internal; **L3 EXTERNAL (hard)** | HYBRID is a signed manifest contract, not feature flags in curator |
| **Q3** | Quorum + signed epoch manifest + shadow ledger + optional exterior runner | L2 consumes manifest; L3 proposes N+1; operator signs |
| **Q4** | v0.9 substrate spine → curator L2 → **`ai-memory-rqgm` sibling v0.9.1+** | RQ-01 Week 1; sibling SHOULD not block v0.9 tag |
| **Q5** | **§2.6 N≥3 quorum + epoch substrate > internal RQGM** | RQGM = optional L3 reference algorithm, not core dependency |

### DISSENT_FROM_11_AGENT

Agent 11 **dissents** if the orchestrator merge adopts any of:

1. **Internal RQGM** in `src/storage/` or curator evolutionary search loops — ossifies algorithm at wrong abstraction layer.
2. **HYBRID interpreted as `--rqgm` flags** merging L2+L3 in one process — three curator stacks (rusqlite / SAL / RQGM) and MCP SLO coupling.
3. **MCP surface as search host** — registry must remain L1 law (`memory_store`, `memory_reflect`, …); no `memory_evolve_panel` tool.
4. **Ship without RQ-01** — external L3 without schema is marketing, not architecture.
5. **Live utility wire (#1707) before shadow proof (#1706)** — epoch discipline requires measurement before enforce.

Agent 11 **does not dissent** from unanimous principles adoption, attestation-before-enforce, or shadow-before-live-wire.

---

## Algorithm churn — infinite future

Moonshot §3.5–§3.6: at ASI the substrate **cannot evaluate** reasoning; it **attests** and **refuses**. RQGM assumes **measurable utility** within epochs — that assumption may not survive ASI (Agent 6 reservation). What **does** survive:

| Layer | What churns | What stays constant |
|-------|-------------|---------------------|
| **L1** (`ai-memory` `src/`) | Attestation primitives, quorum gates, depth cap, ledger | Seven §2 properties; MCP registry as law |
| **L2** (`ai-memory` curator CLI) | Manifest consumer, decorrelation cadence, panel slot injection | Epoch **host** — tick, stamp `metadata.epoch_id`, apply signed pack |
| **L3** (`ai-memory-rqgm` sibling) | RQGM, successors, operator custom search | **Read** ledger + probe → **propose** manifest N+1 |

**Algorithm churn infinite future** = L3 repos can fork, version, and replace search algorithms weekly without a core `ai-memory` release. The **contract** is RQ-01 `epoch_manifest.json`, not shared Rust crates embedding population genetics.

```
┌─────────────────────────────────────────────────────────────┐
│ L3 — ai-memory-rqgm (CHURN ZONE — sibling repo)             │
│     Utility evolution · panel breeding · adversarial search │
│     rqgm/2606.26294@rev → rqgm-next@rev → operator forks    │
└───────────────────────────┬─────────────────────────────────┘
                            │ signed epoch_manifest.json (RQ-01)
┌───────────────────────────▼─────────────────────────────────┐
│ L2 — ai-memory curator CLI (STABLE HOST — in repo, separate)│
│     Epoch tick · manifest load · decorrelation every cycle  │
└───────────────────────────┬─────────────────────────────────┘
                            │ SAL / MCP tools
┌───────────────────────────▼─────────────────────────────────┐
│ L1 — ai-memory substrate (CONSTANT LAW — MCP/HTTP/CLI)        │
│     persist · gate · attest · depth cap · record_recall       │
└─────────────────────────────────────────────────────────────┘
```

**MCP registry = L1 law; curator CLI = L2; never search host on MCP surface.**

---

## ASI_MOONSHOT_GRADE — property-by-property

| §2 Property | Grade | Agent 11 read |
|-------------|-------|---------------|
| 2.1 Endpoint-resident | **A** | IoT/mobile stay L1-only; L3 runs on operator fleet, not in phone binary |
| 2.2 Coherent | **A** | Epoch stamps + manifest `policy_version` give cross-generation continuity |
| 2.3 Stoppable | **A** | Quorum refuse + signed packs; L3 cannot bypass §2.5 without operator key |
| 2.4 Improvable | **A−** | Skills/atoms compound in L1; evaluator improvement is L3 optional |
| 2.5 Attested | **A** | Manifest Ed25519 matches forensic bundle / governance pack pattern |
| 2.6 Bias-displaced | **B+** → **A** post D3-012/021 | Today CLAIMED-only (`enforce` inert); manifest panel + attestation closes gap |
| 2.7 LLM-agnostic | **A** | Panel slots per-backend; no single `AI_MEMORY_LLM_*` co-evolution block |

**Composite ASI_MOONSHOT_GRADE: A−** (becomes **A** when RQ-10..13 manifest consumer lands in v0.9).

---

## Codegraph evidence (isolated)

| Finding | Evidence | Implication |
|---------|----------|-------------|
| Stationary judge | `build_curator_llm` @ `src/cli/curator.rs:114-136` — single resolver, one client | Panel must come from **manifest injection** (RQ-12), not env |
| Decorrelation not in daemon | `run_decorrelation_probe` @ `decorrelation_probe.rs:254`; **0** hits in `daemon_runtime.rs` | Probe only on `--reflect` path (`curator.rs:786`); RQ-11 = every cycle |
| `enforce` inert | `decorrelation_probe.rs:272-280` degrades Enforce → advisory | Attestation before enforce; internal RQGM would bypass |
| SQLite daemon ≠ reflection epoch | `run_once` @ `curator.rs:223` vs SAL `store_backed_reflection_sweep` @ `438` | L2 bifurcation; unify before epoch stamps |
| MCP hooks empty | `reflect_with_hooks(..., ReflectHooks::empty())` — sqlite `843`, postgres `7906` | D1 gate before any L3 loop (Agent 5; Agent 11 concurs) |
| No epoch manifest type | CodeGraph: forensic `Manifest` @ `forensic/bundle.rs:151` is tar bundle, not epoch | **RQ-01 P0** — schema delivered @ [`docs/contracts/epoch_manifest.schema.json`](../contracts/epoch_manifest.schema.json) |
| MCP = persistence law | `registry::tool_names` — `memory_store`, `memory_reflect`, checkpoints; **no** evolution tool | L3 must stay off MCP hot path (Agent 8 killer aligns) |
| `record_recall` ledger | `observations/mod.rs` | L3 shadow utility input; stays L1 |

---

## `ai-memory-rqgm` sibling — minimum viable scope (RQ-20..23)

**Repo:** `alphaonedev/ai-memory-rqgm` (SHOULD, v0.9.1+, not blocking v0.9.0 tag)

| Component | Responsibility | Must NOT |
|-----------|----------------|----------|
| Ledger reader | Pull `recall_observations`, decorrelation probe export | Write memories without L1 MCP/HTTP |
| Panel breeder | Propose `panel.slots[]` for epoch N+1 | Mutate `RuleEngine` or governance DB |
| Manifest writer | Emit unsigned `epoch_manifest.json` draft | Self-sign (operator signs) |
| RQGM reference harness | Reproduce paper loop against fixture corpus | Ship inside `ai-memory` `src/curator/` |

**Dependency direction:** sibling → reads L1 exports; L2 → reads signed manifest. **No** `ai-memory` → `ai-memory-rqgm` compile dependency.

---

## Q4 pathway (Agent 11 lens)

### Phase 0 — Contract (Week 1) MUST

| ID | Deliverable | Agent 11 status |
|----|-------------|-----------------|
| RQ-00 | 11-agent vote doc | ✅ exists |
| **RQ-01** | `epoch_manifest.json` schema | ✅ **this run** → `docs/contracts/epoch_manifest.schema.json` |
| RQ-02 | `RECURSIVE_LEARNING.md` L1/L2/L3 boundary | pending |
| RQ-03 | `honest-limitations.md` Red Queen addendum | pending |

### Phase 1 — v0.9 P0 (substrate + curator L2)

RQ-10..13: manifest load, decorrelation every cycle, panel rotation, epoch stamps — **blocking for HYBRID contract to be real**.

### Phase 2 — v0.9.1+ sibling

RQ-20..23: reference harness only after RQ-01 consumer exists in L2.

### CUT (Agent 11 reinforces 11/11)

- RQGM population genetics in `src/`
- `--rqgm` feature flag merging L2+L3
- MCP tools for evolutionary search
- Marketing “implements Red Queen” / “co-evolving evaluators shipped”

---

## Claims discipline

**Allowed:** “Red Queen–ready (~55–65%)” · “epoch-gated bias-displacement trajectory” · “optional exterior runner contract (RQ-01)”

**Banned:** “implements RQGM” · “co-evolving evaluators shipped” · “decorrelation enforce” (v0.8.0) · “self-improving agent framework”

---

## One-sentence outcome (Agent 11 isolated)

> Adopt Red Queen **principles** in L1+L2; keep **all algorithm churn** in **`ai-memory-rqgm`**; bind layers with **signed RQ-01 epoch manifests** — preserving endpoint memory law through AGI→ASI without scope creep or ossified search in core `src/`.

---

**AI involvement:** Single isolated subagent execution (Agent 11 lens only). Operator directive 2026-06-28. Crossroads cite: `4d3ea1c5`. RQ-01 schema authorship: this run.