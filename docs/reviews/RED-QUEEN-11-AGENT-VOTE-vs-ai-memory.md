---
layout: doc
redirect_from:
  - /reviews/RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md
---

# Red Queen vs ai-memory — 11-Agent Adversarial Vote (ISOLATED RUN)

**Status:** FINAL synthesis from **11 independent agent executions**  
**Date:** 2026-06-27  
**Vote protocol:** 5-agent crossroads `4d3ea1c5` pattern · 11 adversarial lenses · **isolated subagents, no cross-talk**  
**Codebase:** `release/v0.8.0` @ `c85b9c56` (each agent mandated CodeGraph)  
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) §0  
**Prior art:** [`RQGM-2606.26294-vs-v0.8.0.md`](RQGM-2606.26294-vs-v0.8.0.html)

**Paper:** [The Red Queen Gödel Machine (arXiv:2606.26294)](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al., 24 Jun 2026)

---

## Methodology (load-bearing)

| Property | Prior doc (2026-06-27 AM) | This doc |
|----------|---------------------------|----------|
| Agent execution | Single author, 11 styled personas | **11 parallel isolated subagents** (`composer-2.5-fast`) |
| Cross-talk | N/A | **None** — each agent received one lens only |
| CodeGraph | Yes | **Mandatory per agent** |
| Merge | N/A | Orchestrator synthesis below |

**Agent IDs (audit trail):**

| Agent | Lens | Subagent ID |
|-------|------|-------------|
| 1 | North Star / Scope Purist | `019f0e12-71d9-7421-a942-45f6752719ed` |
| 2 | Architecture / Layering | `019f0e12-71d9-7421-a942-46056bba26d3` |
| 3 | Security / Fail-Closed | `019f0e12-71d9-7421-a942-4615be1e8854` |
| 4 | Curator Runtime | `019f0e12-71da-71e0-8970-ba9c16c13df9` |
| 5 | D1 Recursive Learning | `019f0e12-71da-71e0-8970-baa6bdae4fd2` |
| 6 | ASI Trajectory | `019f0e12-71da-71e0-8970-bab14fa66c10` |
| 7 | Procurement / Claims | `019f0e12-71da-71e0-8970-bac63f0d7743` |
| 8 | Performance / Ops | `019f0e12-71da-71e0-8970-bad0b245df4b` |
| 9 | Federation | `019f0e12-71da-71e0-8970-bae7e6d3340f` |
| 10 | Alternatives Analyst | `019f0e12-71db-70c3-9447-8647482e2a61` |
| 11 | Sibling Repo / Future | `019f0e12-71db-70c3-9447-865c7710ff5c` |

---

## Executive synthesis (orchestrator merge)

| Question | **FINAL** (post 11-agent merge) | Agreement |
|----------|----------------------------------|-----------|
| **Q1** Should Red Queen be used? | **YES — principles + epoch discipline** · **CUT full RQGM algorithm from `src/`** | **11/11** |
| **Q2** Where? | **HYBRID** — L1+L2 internal · **L3 EXTERNAL (hard line)** | **11/11** (Agent 1 says EXTERNAL for search; all others HYBRID with external L3) |
| **Q3** How? | Quorum + signed epoch manifest + shadow ledger + optional exterior runner | **11/11** |
| **Q4** Pathway? | v0.9 substrate spine → curator L2 → `ai-memory-rqgm` sibling v0.9.1+ | **10/11** (Agent 6 reserves ASI utility measurability) |
| **Q5** Correct path? Better than RQGM? | **§2.6 N≥3 quorum + epoch substrate > internal RQGM**; RQGM = optional L3 reference | **11/11** |

**Confidence (synthesis):** **87%** (range across agents: 78–91%)

**Unanimous (11/11):**

1. Red Queen **principles MUST** inform v0.9+ (stationary judges fail at swarm scale).
2. Full RQGM **MUST NOT** ship inside ai-memory core (`src/storage/`, evolutionary search in curator).
3. Curator = **L2 epoch host**, not L3 search engine.
4. **Attestation before enforce** (D3-012 → D3-021); **shadow before live wire** (#1706 → #1707).
5. **§2.6 N≥3 quorum** is the primary ASI-durable answer; RQGM is accelerant for agent-heavy L3 only.
6. **`enforce` decorrelation on CLAIMED metadata** = security theater (Agent 7 killer objection; aligns CUT D3-001).

**Documented dissent:**

| Agent | Dissent |
|-------|---------|
| **1** | Q2 vote label **EXTERNAL** (stricter than HYBRID label — same substance: search outside repo) |
| **6** | RQGM **algorithm may not survive ASI** (utility measurability cliff); principles survive |
| **10** | If panel converges on internal RQGM, **dissents** — quorum alone suffices for endpoint memory |
| **11** | HYBRID must mean **contract**, not “merge flags into curator” |
| **8** | Corrects prior “MCP mutex” myth per #965; HTTP mutex is real contention surface |
| **9** | Checkpoints **not federated** on `SyncPushBody` today — epoch boundaries are per-node |

---

## Tally tables

### Q1 — Should Red Queen be used?

| Agent | Q1 Vote |
|-------|---------|
| 1 | YES principles · CUT algorithm |
| 2 | YES principles · CUT algorithm |
| 3 | YES principles · CUT algorithm |
| 4 | YES principles · CUT algorithm |
| 5 | YES principles · CUT algorithm |
| 6 | YES principles · CUT algorithm |
| 7 | YES principles · CUT algorithm |
| 8 | YES principles · CUT algorithm |
| 9 | YES principles · CUT algorithm |
| 10 | YES principles · CUT algorithm |
| 11 | YES principles · CUT algorithm |

**FINAL: 11/11 YES (principles only). 0/11 internal RQGM algorithm.**

---

### Q2 — External vs internal

| Agent | Q2 Vote |
|-------|---------|
| 1 | **EXTERNAL** (search) |
| 2 | HYBRID |
| 3 | HYBRID |
| 4 | HYBRID (L2 internal, L3 external) |
| 5 | HYBRID |
| 6 | HYBRID (IoT L1-only; swarm L2+L3 optional) |
| 7 | HYBRID |
| 8 | HYBRID (L3 search EXTERNAL) |
| 9 | HYBRID (+ federated manifest) |
| 10 | HYBRID |
| 11 | HYBRID-as-**contract**; L3 EXTERNAL **hard** |

**FINAL: HYBRID unanimous on substance.** L3 evolutionary search is **EXTERNAL** to core repo (11/11). Agent 1 refuses the HYBRID label to avoid scope creep interpretation.

```
┌─────────────────────────────────────────────────────────────┐
│ L3 — ai-memory-rqgm / operator runner (EXTERNAL — HARD)     │
│     Utility evolution · panel breeding · adversarial search │
└───────────────────────────┬─────────────────────────────────┘
                            │ signed epoch_manifest.json (RQ-01)
┌───────────────────────────▼─────────────────────────────────┐
│ L2 — ai-memory curator CLI (IN REPO, separate process)      │
│     Epoch tick · manifest consumer · decorrelation probe    │
└───────────────────────────┬─────────────────────────────────┘
                            │ SAL / MCP tools
┌───────────────────────────▼─────────────────────────────────┐
│ L1 — ai-memory substrate (IN REPO, MCP/HTTP/CLI)            │
│     persist · gate · attest · depth cap · ledger            │
└─────────────────────────────────────────────────────────────┘
```

---

### Q5 — Correct pathway? Better than full RQGM?

| Agent | Q5 |
|-------|-----|
| 1 | Seven-property substrate + optional external epoch runner |
| 2 | §2.6 quorum + epoch curator; internal RQGM wrong locus |
| 3 | Quorum > internal RQGM; RQGM = L3 reference |
| 4 | §2.6 quorum + curator L2; RQGM optional L3 |
| 5 | D1 + quorum primary; RQGM optional |
| 6 | North Star correct; quorum > algorithm at ASI |
| 7 | Partially correct; quorum > internal RQGM |
| 8 | Quorum pathway correct; RQGM optional accelerant |
| 9 | Federated manifest + quorum; external L3 |
| 10 | **N≥3 quorum strictly better fit** than internal RQGM |
| 11 | Quorum + manifest contract; internal RQGM worse |

**FINAL: Moonshot §2.6 N≥3 attested quorum + epoch-gated substrate + curator L2 is the correct infinite-horizon pathway. RQGM is the best reference algorithm for optional exterior L3.**

---

## Individual agent verdicts (isolated outputs)

### Agent 1 — North Star Scope Purist

**VERDICT:** Q1 SHOULD (principles) · Q2 EXTERNAL · Q5 substrate is constant; RQGM optional swarm orchestration  
**CONFIDENCE:** 88%  
**TOP_RISK:** “Red Queen-enabled” label pulls RSI platform scope into IoT/mobile binary  
**KILLER_OBJECTION:** In-repo RQGM collapses moonshot anchor into self-evolving agent framework  
**VOTES:** Q1=SHOULD · Q2=EXTERNAL · Q5=Seven-property endpoint substrate; RQGM at most external epoch runner  

**Q4 (lens):** v0.8 attestation + decorrelation → v0.9 quorum → post-v0.9 `ai-memory-rqgm` sibling; never merge search into `src/curator/` or `src/storage/`.

---

### Agent 2 — Architecture / Layering

**VERDICT:** Q1 YES principles · Q2 HYBRID · Q5 internal RQGM wrong locus  
**CONFIDENCE:** 86%  
**TOP_RISK:** `--rqgm` flag merges L2+L3; rusqlite vs SAL curator bifurcation worsens  
**KILLER_OBJECTION:** Three curator stacks (rusqlite / SAL / RQGM) if RQGM embedded  
**VOTES:** Q1=YES principles CUT core · Q2=HYBRID · Q5=quorum + curator L2 through ASI  

**Codegraph:** `MemoryStore` seam; MCP `spawn_blocking` vs curator CLI; `store_backed_reflection_sweep` 1 caller; decorrelation not in daemon loop.

---

### Agent 3 — Security / Fail-Closed

**VERDICT:** Q1 YES principles · Q2 HYBRID · Q3 attestation-before-enforce; shadow-before-live  
**CONFIDENCE:** 91%  
**TOP_RISK:** Single-vendor “panel” = monoculture with extra steps  
**KILLER_OBJECTION:** Internal RQGM mutating rules without signed packs bypasses §2.5  
**VOTES:** Q1=YES · Q2=HYBRID · Q5=quorum > internal RQGM  

**Codegraph:** `enforce` inert `decorrelation_probe.rs:272-280`; `RuleEngine::evaluate` static; decorrelation only `run_reflect`.

---

### Agent 4 — Curator Runtime

**VERDICT:** Q2 L2 epoch host · Q4 MUST unify reflect+decorrelation in daemon · CUT evolutionary loop in curator  
**CONFIDENCE:** 86%  
**TOP_RISK:** L2/L3 merge via feature creep; SQLite vs SAL half-hosts  
**KILLER_OBJECTION:** One `AI_MEMORY_LLM_*` block cannot co-evolve evaluators; need manifest injection  
**VOTES:** Q1=YES principles · Q2=HYBRID · Q5=quorum + curator L2  

**Codegraph:** Default SQLite daemon = upkeep only (no reflection); SAL daemon = consolidation→reflection; decorrelation `--reflect` only; single `AutonomyLlm`.

---

### Agent 5 — D1 Recursive Learning

**VERDICT:** D1 prerequisite before any Red Queen loop; MCP `ReflectHooks::empty()` is blocking gap  
**CONFIDENCE:** 84%  
**TOP_RISK:** L3 before D1 A+ = Red Queen cosplay on v0.7 primitive  
**KILLER_OBJECTION:** Category error — RQGM optimizes benchmarks; ai-memory optimizes governed persistence  
**VOTES:** Q1=YES principles CUT core · Q2=HYBRID · Q5=D1 + quorum primary  

**Codegraph:** `reflect_with_hooks` 20 callers; `handle_reflect` → empty hooks unless auto_export.

---

### Agent 6 — ASI Trajectory

**VERDICT:** Principles survive ASI; RQGM algorithm may not (utility measurability)  
**CONFIDENCE:** 79%  
**TOP_RISK:** Utility measurability cliff at AGI/ASI  
**KILLER_OBJECTION:** Substrate attests, cannot evaluate ASI reasoning — RQGM assumes measurable utility  
**VOTES:** Q1=YES principles CUT core · Q2=HYBRID (IoT L1-only tiering) · Q5=North Star correct; algorithm CUT at ASI  

**Trajectory:** IoT → L1 only; developer → L1+L2 fixed panel; swarm → L1+L2+optional L3.

---

### Agent 7 — Procurement / Claims Honesty

**VERDICT:** “Red Queen–ready (~55–65%)” max claim; never “implements RQGM”  
**CONFIDENCE:** 91%  
**TOP_RISK:** `enforce` enum footgun in feature matrices  
**KILLER_OBJECTION:** `enforce` inert = security theater (CUT D3-001 class)  
**VOTES:** Q1=YES principles CUT core · Q2=HYBRID · Q5=quorum > internal RQGM  

**Codegraph:** Full `enforce` inert path traced; daemon lacks decorrelation call.

---

### Agent 8 — Performance / Operations

**VERDICT:** RQGM search off hot path; shadow #1706 default; `max_ops` does not bound search genetics  
**CONFIDENCE:** 82%  
**TOP_RISK:** N≥3 panel × every cycle × full corpus = cost explosion  
**KILLER_OBJECTION:** Internal RQGM couples search spikes to MCP/HTTP SLOs (#965: no MCP mutex, but stdio serial + HTTP mutex)  
**VOTES:** Q1=YES principles · Q2=EXTERNAL search / HYBRID overall · Q5=quorum pathway without mandatory RQGM  

---

### Agent 9 — Federation / Multi-Endpoint

**VERDICT:** Federated panel manifest via signals; checkpoint fanout gap  
**CONFIDENCE:** 78%  
**TOP_RISK:** Cross-node utility comparison leaks competitive data  
**KILLER_OBJECTION:** Internal RQGM + federation = split-brain epoch boundaries  
**VOTES:** Q1=YES · Q2=HYBRID + federated manifest · Q5=substrate pathway correct with epoch closure  

**Codegraph:** `SyncPushBody` has signals/transitions; checkpoints local-only today.

---

### Agent 10 — Alternatives Analyst

**VERDICT:** **N≥3 quorum + epoch discipline > full RQGM** for endpoint memory North Star  
**CONFIDENCE:** 85%  
**TOP_RISK:** Paper benchmarks mistaken as proof substrate should internalize search  
**KILLER_OBJECTION:** Category error — RQGM optimizes agents; ai-memory optimizes governed persistence  
**VOTES:** Q1=YES principles CUT core · Q2=HYBRID · Q5=quorum primary; RQGM L3 reference only  

**Explicit dissent:** If 11/11 internal RQGM, Agent 10 dissents — quorum suffices.

---

### Agent 11 — Sibling Repo / Future-Proofing

**VERDICT:** EXTERNAL L3 **hard**; RQ-01 epoch manifest schema P0  
**CONFIDENCE:** 87% (91% on external boundary)  
**TOP_RISK:** No manifest schema → external L3 becomes fiction  
**KILLER_OBJECTION:** Internal RQGM ossifies wrong layer; algorithm churn must live in sibling  
**VOTES:** Q1=YES · Q2=EXTERNAL L3 hard / HYBRID contract · Q5=quorum > internal RQGM  

**MCP registry = L1 law; curator CLI = L2; never search host on MCP surface.**

---

## Q3 — How (merged mechanism stack)

1. **L1 substrate:** N≥3 attested quorum on reflect/consolidate (#1719, #1171, D3-021); depth cap; `record_recall` ledger; governance refuse/escalate; checkpoints (local → federated).
2. **L2 curator:** `interval_secs` + `max_ops` epoch tick; load signed `epoch_manifest.json`; decorrelation **every** daemon cycle; panel slots from manifest; stamp `metadata.epoch_id`.
3. **L3 exterior:** Read ledger + probe → propose manifest N+1 → operator signs → curator applies.
4. **Shadow utility (#1706)** before live recall wire (#1707 DEFER).
5. **CUT:** Population genetics, utility gradient search, `enforce` on CLAIMED metadata, governance auto-mutation without signed packs.

---

## Q4 — Development pathway (merged)

### Phase 0 — Contract (Week 1) MUST

| ID | Deliverable |
|----|-------------|
| RQ-00 | This vote doc (isolated run) |
| RQ-01 | `epoch_manifest.json` schema |
| RQ-02 | `RECURSIVE_LEARNING.md` L1/L2/L3 boundary |
| RQ-03 | `honest-limitations.md` Red Queen addendum |
| FED-RQ-01 | Checkpoint resolution on `SyncPushBody` (Agent 9) |

### Phase 1 — v0.9 P0–P1 (substrate + curator)

| ID | Work |
|----|------|
| V09-RL-D3-012 | Attested `model_family` |
| V09-RL-D3-002 | #1171 panel synthesis |
| V09-RL-D1-001/004 | MCP PreReflect hooks (Agent 5 gate) |
| V09-RL-D4-015 | Shadow feedback #1706 |
| V09-RL-D2-001 | Unify reflection in daemon |
| RQ-10..13 | Manifest load, decorrelation every cycle, panel rotation, epoch stamps |
| V09-RL-D3-021 | Enforce post-012 |

### Phase 2 — v0.9.1+ sibling (SHOULD, not blocking v0.9 tag)

| ID | Work |
|----|------|
| RQ-20..23 | `ai-memory-rqgm` reference harness |
| FED-RQ-02..05 | Federated manifest + policy_version gate |

### CUT (11/11)

- RQGM in `src/storage/` or curator search loops
- #1707 live wire before #1706 proof
- Default compaction without rollback (#1771)
- Marketing “implements Red Queen” / “co-evolving evaluators shipped”

---

## Curator + Red Queen — codegraph-confirmed gaps

| Gap | Evidence | Fix |
|-----|----------|-----|
| Decorrelation not in daemon | `run_decorrelation_probe` 1 caller → `run_reflect` only | RQ-11 |
| SQLite daemon ≠ reflection epoch | `run_once` upkeep vs SAL `store_backed_reflection_sweep` | Unify + SAL port (Agent 2, 4) |
| Stationary judge | Single `build_curator_llm` | RQ-12 manifest panel |
| `enforce` inert | `decorrelation_probe.rs:272-280` | D3-012 then D3-021 |
| MCP hooks empty | `handle_reflect` → `ReflectHooks::empty()` | D1-001 (Agent 5 gate) |

---

## Alternatives ranked (Agent 10 + merge)

| Pathway | Fit endpoint memory? |
|---------|---------------------|
| Static Gödel Machine (fixed verifier) | **Poor** — stale judges |
| Full internal RQGM | **Wrong category** — agent framework creep |
| **§2.6 N≥3 quorum + epoch gates** | **Primary — 11/11** |
| Human Escalate only | Necessary floor, insufficient ceiling |
| Empirical decorrelation only | Incomplete without enforce post-attestation |
| RQGM principles + hybrid L1/L2/L3 | **Recommended deployment model** |

---

## Claims discipline (Agent 7 — adopted 11/11)

**Allowed:** “Red Queen–ready (~55–65%)” · “epoch-gated bias-displacement trajectory” · “optional exterior runner contract”

**Banned:** “implements RQGM” · “co-evolving evaluators shipped” · “decorrelation enforce” (v0.8.0) · “self-improving agent framework”

---

## Relation to other docs

| Doc | Status |
|-----|--------|
| [`RQGM-2606.26294-vs-v0.8.0.md`](RQGM-2606.26294-vs-v0.8.0.html) | Mechanism map still valid; placement superseded by this vote |
| [`v0.9.0/RECURSIVE-LEARNING-A-PLUS-ROADMAP.md`](../v0.9.0/RECURSIVE-LEARNING-A-PLUS-ROADMAP.md) | **Execution DAG** — unchanged; this vote adds L1/L2/L3 framing |
| [`moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) | **North Star** — authoritative |

---

## One-sentence outcome

> **11/11:** Adopt Red Queen **principles**; keep RQGM **search EXTERNAL**; strengthen **§2.6 quorum + epoch curator L2** inside ai-memory; treat RQGM as **optional L3 reference** for agent-heavy operators — preserving endpoint memory law through AGI→ASI without scope creep.

---

**AI involvement:** 11 isolated subagent executions + orchestrator synthesis (Grok). Operator directive 2026-06-27. Crossroads cite: `4d3ea1c5`.