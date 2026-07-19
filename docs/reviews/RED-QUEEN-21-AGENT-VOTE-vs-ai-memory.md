---
layout: doc
redirect_from:
  - /reviews/RED-QUEEN-21-AGENT-VOTE-vs-ai-memory.md
---

# Red Queen vs ai-memory — 21-Agent Adversarial Vote (FULL SPECTRUM / ASI MOONSHOT)

**Status:** FINAL synthesis from **21 independent agent executions**  
**Date:** 2026-06-28  
**Vote protocol:** 5-agent crossroads `4d3ea1c5` pattern · 21 adversarial lenses · **isolated subagents, no cross-talk**  
**Codebase:** `release/v0.8.0` @ `c85b9c56`  
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) §0 (endpoint substrate through AGI→ASI→beyond)  
**Prior art:** [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.html) · [`RQGM-2606.26294-vs-v0.8.0.md`](RQGM-2606.26294-vs-v0.8.0.html) · [`docs/contracts/epoch_manifest.schema.json`](../contracts/epoch_manifest.schema.json)

**Paper:** [The Red Queen Gödel Machine (arXiv:2606.26294)](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al., 24 Jun 2026)

---

## Methodology (load-bearing)

| Property | 11-agent run (2026-06-27) | **21-agent run (this doc)** |
|----------|---------------------------|-----------------------------|
| Agent execution | 11 parallel isolated subagents | **21 parallel isolated subagents** (11 retained + 10 new lenses) |
| Cross-talk | None | **None** |
| Scope | RQGM placement + curator L1/L2/L3 | **Full-spectrum** moonshot §2.1–§2.7 + federation + identity + ledger + parity + IoT + governance + KG + hooks + encryption |
| CodeGraph | Mandatory per agent | Mandatory per agent (some agents substituted grep/read when MCP unavailable) |
| ASI framing | Present | **Primary** — infinite-horizon relevance to endpoint AI/AGI/ASI |

**Agent roster (audit trail):**

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
| **12** | **Mobile/IoT Endpoint Tiering (§2.1)** | `019f0e1c-493f-7e50-9311-c96471d0a21b` |
| **13** | **Governance / PE-5 / RuleEngine** | `019f0e1c-493f-7e50-9311-c9791d3ba7fe` |
| **14** | **V-4 Attestation / signed_events** | `019f0e1c-4940-7633-b7ec-250ce30ff882` |
| **15** | **KG / AGE / memory_links** | `019f0e1c-4940-7633-b7ec-251a9ee6933c` |
| **16** | **Hooks PE-1 / Webhooks / PreReflect** | `019f0e1c-4940-7633-b7ec-252e118b473a` |
| **17** | **Encryption / Visibility / #1720** | `019f0e1c-4940-7633-b7ec-253ea7933370` |
| **18** | **Observations Ledger / Shadow #1706** | `019f0e1c-4940-7633-b7ec-254288ccd601` |
| **19** | **NHI Identity / D3-012 Family Attestation** | `019f0e1c-4940-7633-b7ec-255f4e377bb0` |
| **20** | **MCP/HTTP/CLI Parity / #965** | `019f0e1c-4941-7013-b95f-e02afbc3e21f` |
| **21** | **Moonshot Integrator (§2.1–§2.7 holistic)** | `019f0e1c-4941-7013-b95f-e03dd99fe1ed` |

---

## Executive synthesis (orchestrator merge — 21/21)

| Question | **FINAL** (post 21-agent merge) | Agreement |
|----------|----------------------------------|-----------|
| **Q1** Should Red Queen be used? | **YES — principles + epoch discipline** · **CUT full RQGM algorithm from `src/`** | **21/21** |
| **Q2** Where? | **HYBRID-as-contract** — L1+L2 internal · **L3 EXTERNAL (hard line)** | **21/21** (Agent 1/12 label EXTERNAL for search/tier-A IoT) |
| **Q3** How? | N≥3 quorum · signed `epoch_manifest.json` (RQ-01) · V-4 `epoch.manifest_applied` (RQ-10) · shadow #1706 · optional exterior runner | **21/21** |
| **Q4** Pathway? | v0.9 substrate spine (D3-012, D1 hooks, shadow) → curator L2 unified daemon → `ai-memory-rqgm` sibling v0.9.1+ | **20/21** (Agent 6 reserves ASI utility measurability for L3 algorithms) |
| **Q5** Correct path? Better than RQGM? | **§2.6 N≥3 quorum + epoch-gated substrate > internal RQGM**; RQGM = optional L3 reference | **21/21** |

**Confidence (synthesis):** **86%** (range across agents: 72–91%)

**Composite ASI moonshot grade:** **B+** (hybrid principles path) · **D+** (if internal RQGM ships)

**Unanimous (21/21):**

1. Red Queen **principles MUST** inform v0.9+ (stationary judges fail at swarm/ASI scale).
2. Full RQGM **MUST NOT** ship inside ai-memory core.
3. Curator = **L2 epoch host**, not L3 search engine.
4. **Attestation before enforce** (D3-012 → D3-021); **shadow before live wire** (#1706 → #1707 DEFER).
5. **§2.6 N≥3 quorum** is the primary ASI-durable answer; RQGM is accelerant for agent-heavy L3 only.
6. **`enforce` decorrelation on CLAIMED metadata** = security theater (CUT D3-001 class).
7. **Governance rules must never auto-mutate** under Red Queen; signed packs gate epoch changes.
8. **Epoch manifest apply must hit V-4 chain** (RQ-10) — RQ-01 schema alone is insufficient.
9. **MCP `ReflectHooks::empty()`** blocks D1/quorum on primary NHI path (D1-001 gate).
10. **SQLite vs SAL curator bifurcation** blocks L2 epoch parity until unified daemon (RQ-PARITY-01).

---

## ASI moonshot grade matrix (21-agent lens rollup)

| Lens cluster | Agents | Grade | Load-bearing finding |
|--------------|--------|-------|----------------------|
| North Star / scope | 1, 21 | **B+ → A− path** | Seven properties strengthen with principles; internal RQGM weakens all |
| Architecture / parity | 2, 20 | **B / C+ impl** | Three curator stacks if RQGM embedded; SQLite daemon ≠ SAL epoch host |
| Security / governance | 3, 13, 17 | **B+ pathway** | RuleEngine static; federated utility leaks behavior not row bodies |
| Curator / L2 | 4, 16 | **B− wiring** | Single `AutonomyLlm`; decorrelation `--reflect` only; hooks unwired |
| D1 / recursive learning | 5, 16 | **A− principle / C+ impl** | `reflect_with_hooks` works; MCP path empty |
| ASI trajectory | 6, 18, 21 | **B** | Utility measurability cliff at L3; principles survive |
| Procurement | 7, 14, 19 | **52–58% ready** | Family-verify readiness ~15–25%; epoch V-4 writer missing |
| Performance | 8 | **B+ pathway** | #965: no MCP mutex myth; HTTP mutex real |
| Federation | 9, 17 | **B+ / FED-RQ-02 OPEN** | FED-RQ-01 checkpoints shipped; manifest federation not |
| Alternatives | 10 | **A quorum path** | N≥3 + epoch freeze > quorum alone (Agent 21 refines) |
| Sibling / contract | 11, 14 | **C contract / A− path** | RQ-01 schema shipped; no `src/` consumer |
| IoT tiering | 12 | **B** | Tier A = L1-only; RQGM inapplicable on MCU; ~18 MB min RSS |
| KG / lineage | 15 | **B+ / F if RQGM in KG** | Graph = provenance audit; not evolutionary host |
| Identity / family | 19 | **C+ composite** | Ed25519 attests agent, not model_family |
| Ledger / fitness | 18 | **B measurement** | Ledger = one-axis telemetry; not full RQGM fitness |

---

## Tally tables

### Q1 — Should Red Queen be used?

**FINAL: 21/21 YES (principles only). 0/21 internal RQGM algorithm.**

### Q2 — External vs internal

**FINAL: HYBRID unanimous on substance.** L3 evolutionary search is **EXTERNAL** (21/21).

**Endpoint tiering (Agent 12 + 6 + 20 — adopted):**

```
┌─────────────────────────────────────────────────────────────┐
│ TIER C — Operator fleet / swarm (ASI-relevant)              │
│ L3 EXTERNAL: ai-memory-rqgm (utility evolution, optional)   │
│ L2: curator --store-url postgres (epoch host)               │
│ L1: HTTP serve (postgres SAL) + federation quorum           │
└───────────────────────────┬─────────────────────────────────┘
                            │ signed epoch_manifest.json (RQ-01)
┌───────────────────────────▼─────────────────────────────────┐
│ TIER B — Hub / Pi / mobile daemon / developer                 │
│ L2 IN REPO: curator epoch tick · manifest consumer            │
│ L1: MCP(sqlite) + HTTP + CLI                                │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ TIER A — Field sensor / phone (keyword, ephemeral)            │
│ L1 ONLY: store · FTS recall · gate · attest · sync push       │
│ NO curator · NO decorrelation · NO RQGM                     │
└─────────────────────────────────────────────────────────────┘

TIER ∅ — MCU / Zephyr / NuttX: ai-memory NOT resident;
         gateway or phone holds L1 (mobile-iot-deployment.md §11.D)
```

### Q5 — Correct pathway? Better than full RQGM?

**FINAL: Moonshot §2.6 N≥3 attested quorum + epoch-gated substrate + curator L2 + V-4 manifest apply is the correct infinite-horizon pathway. RQGM is the best reference algorithm for optional exterior L3.**

**Agent 21 refinement (adopted):** Quorum alone is **necessary, not sufficient** — epoch freeze + signed manifest prevents mid-epoch judge drift (the core Red Queen problem).

---

## Individual agent verdicts — Agents 12–21 (new lenses)

### Agent 12 — Mobile/IoT Endpoint Tiering (§2.1)

| Field | Value |
|-------|-------|
| **VERDICT** | Red Queen principles YES; RQGM **inapplicable** at kilobyte-RAM MCU; Tier A = L1-only |
| **CONFIDENCE** | 84% |
| **ASI_MOONSHOT_GRADE** | **B** (capped: ~18–25 MB min RSS vs moonshot kilobyte claim) |
| **TOP_RISK** | "Red Queen–ready" marketing on fat-edge binaries |
| **KILLER_OBJECTION** | RQGM on MCU = wrong product on wrong silicon; keyword tier has `llm_model: None` |

**Key findings:** `FeatureTier::from_memory_budget` → `<256 MB = Keyword`; curator LLM absent on keyword; decorrelation 0 hits in `daemon_runtime.rs`; Tier ∅ needs gateway-held L1.

**Dissent:** Generic HYBRID label understates Tier A — substance is EXTERNAL-leaning (L2 hub-side). Moonshot §2.1 kilobyte RAM contradicts `mobile-iot-deployment.md`.

---

### Agent 13 — Governance / PE-5 / RuleEngine

| Field | Value |
|-------|-------|
| **VERDICT** | Governance = L1 static law; Red Queen = epoch panel rotation via manifest only |
| **CONFIDENCE** | 89% |
| **ASI_MOONSHOT_GRADE** | **B+ governance / C+ RQ integration** |
| **TOP_RISK** | Epoch transition without `policy_version` gate + stale `RuleCache` |
| **KILLER_OBJECTION** | Internal RQGM mutating `governance_rules` = legislature+executive+judge collapse |

**Key findings:** `RuleEngine::evaluate` read-only; `Decision::Escalate` fails closed (§2.3); MCP mutation tools disabled; no `epoch_manifest` consumer in `src/curator/`. **Dissent:** Integrity rules R005+ should be **P0 before any L3 runner**.

---

### Agent 14 — V-4 Attestation / signed_events

| Field | Value |
|-------|-------|
| **VERDICT** | Epoch manifest compatible with V-4 as `epoch.manifest_applied` append; RQ-10 blocks procurement |
| **CONFIDENCE** | 86% |
| **ASI_MOONSHOT_GRADE** | **B+ today / C with RQ epoch layer** |
| **TOP_RISK** | Epoch params applied without `signed_events` row |
| **KILLER_OBJECTION** | L2 manifest apply without V-4 append = §2.5 theater at Red Queen boundary |

**Key findings:** Template = `governance.rules_store::remove_signed`; need `SignableEpochManifest` + `event_types::EPOCH_MANIFEST_APPLIED`; `record_recall` off V-4 chain (best-effort). **Dissent:** RQ-01 schema without RQ-10 writer = deployable fiction.

---

### Agent 15 — KG / AGE / memory_links

| Field | Value |
|-------|-------|
| **VERDICT** | RQGM search NOT in KG; graph traversal CAN audit decorrelation post-attestation |
| **CONFIDENCE** | 86% |
| **ASI_MOONSHOT_GRADE** | **B+ substrate / F if RQGM in KG** |
| **TOP_RISK** | Coupling L3 genetics to `kg_find_paths` hot path |
| **KILLER_OBJECTION** | Evolutionary search on provenance mirror ≠ endpoint governance |

**Key findings:** `kg_projection_outbox` = cold-path perf, not RQGM queue; `reflects_on` subgraph audit = SHOULD v0.9; deferred AGE → CTE fallback load-bearing for RYOW audits.

---

### Agent 16 — Hooks PE-1 / Webhooks / PreReflect

| Field | Value |
|-------|-------|
| **VERDICT** | Hooks = L1 dual-egress (not L3); webhook ≠ epoch manifest |
| **CONFIDENCE** | 86% |
| **ASI_MOONSHOT_GRADE** | **B−** (design A− / wiring C+) |
| **TOP_RISK** | Operators confuse hooks.toml with Red Queen L3 closure |
| **KILLER_OBJECTION** | HMAC webhook ≠ Ed25519 RQ-01 manifest; procurement theater |

**Key findings:** `PreReflect` in PE-1 schema but not wired on MCP reflect (unlike `PreSignalSend`); `WEBHOOK_EVENT_TYPES` = 7 closed slugs, no epoch event; `enforce_required_event_presence` tests-only. **Dissent nuance:** Hooks are **L1 exterior** at cognition↔operator boundary.

---

### Agent 17 — Encryption / Visibility / #1720

| Field | Value |
|-------|-------|
| **VERDICT** | #1720 closes private-row leaks; federated utility comparison = unclosed behavioral leak |
| **CONFIDENCE** | 84% |
| **ASI_MOONSHOT_GRADE** | **B** (ASI multi-tenant isolation **B−**) |
| **TOP_RISK** | Cross-node utility via `shadow_ledger_refs` / signals without redaction |
| **KILLER_OBJECTION** | Per-node encryption ≠ federation E2E; utility telemetry not content-encrypted |

**Key findings:** Federation decrypts→plaintext wire→re-seal; `is_visible_to_caller` + `sync_since` post-filter shipped; `AI_MEMORY_AGENT_ID` unset = trust-all; curator `bypass_visibility` by design.

---

### Agent 18 — Observations Ledger / Shadow #1706

| Field | Value |
|-------|-------|
| **VERDICT** | Ledger = L1 recall-utility telemetry (necessary, insufficient for full RQGM fitness) |
| **CONFIDENCE** | 84% |
| **ASI_MOONSHOT_GRADE** | **B** |
| **TOP_RISK** | Equating `consumed` citation with epoch utility → Goodhart |
| **KILLER_OBJECTION** | #1707 live wire before #1706 shadow = gameable proxy on hot path |

**Key findings:** `access_count` still live fitness proxy; D4-015 sweep not in `src/`; consume parity MCP-sqlite-only (#1705 partial); federated utility needs aggregated attestations not raw rates (Agent 9/17).

---

### Agent 19 — NHI Identity / D3-012 Family Attestation

| Field | Value |
|-------|-------|
| **VERDICT** | v0.8.0: **NO** verify decorrelated families; Ed25519 attests agent not cognition |
| **CONFIDENCE** | 89% v0.8 / 72% D3-012 alone sufficient at ASI |
| **ASI_MOONSHOT_GRADE** | **C+ composite** (agent NHI B+ / family verify D+) |
| **TOP_RISK** | Enrollment mistaken for family attestation |
| **KILLER_OBJECTION** | Red Queen panel without D3-012 = monoculture with extra labels |

**Key findings:** `SignableWrite` has no family field; `enforce` inert correct posture; family-verify readiness **~15–25%** not 55–65%. Loader-digest TOFU ≠ provider family chain (moonshot §6 gap).

---

### Agent 20 — MCP/HTTP/CLI Parity / #965

| Field | Value |
|-------|-------|
| **VERDICT** | L1 reflect wire parity shippable; L2 epoch parity blocked by curator bifurcation |
| **CONFIDENCE** | 84% |
| **ASI_MOONSHOT_GRADE** | **B+** |
| **TOP_RISK** | SQLite `run_once` daemon ≠ SAL reflection epoch |
| **KILLER_OBJECTION** | "Surface parity" ≠ same backend; epoch must not become MCP tools |

**Key findings:** Postgres hub uses HTTP not stdio MCP (#1675); #965 confirms no MCP mutex; `epoch_manifest` schema exists but no `src/` loader. **Dissent:** Exposing epoch panel as MCP tools violates L1 law.

---

### Agent 21 — Moonshot Integrator (§2.1–§2.7 holistic)

| Field | Value |
|-------|-------|
| **VERDICT** | Principles = load-bearing moonshot fuel; internal RQGM = moonshot kryptonite |
| **CONFIDENCE** | 84% holistic / 91% on internal-RQGM weakens §0 |
| **COMPOSITE_ASI_GRADE** | **B+** hybrid path → **A−** post D3-012 + RQ-10 |
| **TOP_RISK** | §2.6 policy theater until D3-012 |
| **KILLER_OBJECTION** | Internal RQGM falsifies one-sentence anchor (category error) |

**Per-property grades (Agent 21):**

| Property | Grade (hybrid, no internal RQGM) |
|----------|----------------------------------|
| §2.1 Endpoint-resident | **A** |
| §2.2 Coherent | **A−** |
| §2.3 Stoppable | **A** |
| §2.4 Improvable | **B+ → A−** |
| §2.5 Attested | **A** |
| §2.6 Bias-displaced | **B → A−** |
| §2.7 LLM-agnostic | **A** |

**Dissent:** Agent 6 cliff hits L3 not substrate; Agent 10 quorum alone insufficient without epoch freeze.

---

## Cross-cutting findings catalog (all 21 agents)

### A. Placement & architecture

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-01 | Full RQGM MUST NOT ship in `src/` | 21/21 | **CUT** |
| F-02 | L3 search EXTERNAL hard line (`ai-memory-rqgm`) | 21/21 | **MUST** |
| F-03 | HYBRID = **contract** (manifest), not flag merge into curator | 11, 13, 16, 20 | **MUST** |
| F-04 | Three curator stacks if RQGM embedded (rusqlite/SAL/RQGM) | 2, 4, 20 | **CUT** |
| F-05 | SQLite daemon `run_once` ≠ SAL `store_backed_reflection_sweep` | 2, 4, 12, 20 | **P0** |
| F-06 | IoT Tier A = L1-only; RQGM inapplicable on MCU | 6, 12 | **MUST** |
| F-07 | MCP stdio sqlite-only; postgres fleets use HTTP | 20 | **Document** |

### B. §2.6 bias-displacement & decorrelation

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-10 | `run_decorrelation_probe` 1 caller → `--reflect` only | 3, 4, 7, 12, 15, 16 | **P0 RQ-11** |
| F-11 | `enforce` mode INERT at v0.8.0 (`decorrelation_probe.rs:272-280`) | 3, 7, 13, 17, 19 | **Correct posture** |
| F-12 | D3-012 attested `model_family` blocks D3-021 enforce | 5, 13, 19, 21 | **P0** |
| F-13 | Single `build_curator_llm` = stationary judge | 4, 11, 19 | **RQ-12 manifest panel** |
| F-14 | N≥3 quorum refuse unbuilt (#1719/#1171) | 5, 10, 19, 21 | **P0** |
| F-15 | Graph-augmented `reflects_on` audit = SHOULD v0.9 | 15 | **SHOULD** |

### C. D1 / hooks / MCP gaps

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-20 | MCP `handle_reflect` → `ReflectHooks::empty()` | 5, 16, 20 | **P0 D1-001** |
| F-21 | `pre_reflect` in hooks.toml not fired on MCP path | 16 | **P0** |
| F-22 | PE-1 `enforce_required_event_presence` tests-only | 16 | **P1** |
| F-23 | `HookVeto` wire mapping unreachable on MCP | 16 | **P0** |

### D. Epoch manifest & V-4 attestation

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-30 | RQ-01 schema **shipped** (`docs/contracts/epoch_manifest.schema.json`) | 11, 14 | **Done** |
| F-31 | No `src/curator` manifest consumer | 11, 13, 14, 16, 20 | **P0 RQ-10..13** |
| F-32 | `epoch.manifest_applied` event type missing | 14 | **P0 RQ-10** |
| F-33 | `SignableEpochManifest` missing in `sign.rs` | 14 | **P0** |
| F-34 | `utility.frozen_within_epoch: true` in schema | 11, 14, 21 | **Contract OK** |
| F-35 | Governance auto-mutation without signed packs = §2.5 bypass | 3, 13 | **CUT** |

### E. Federation & multi-tenant

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-40 | FED-RQ-01 checkpoints on `SyncPushBody` **shipped** | 9 | **Done** |
| F-41 | FED-RQ-02..05 federated manifest OPEN | 9, 17 | **P1** |
| F-42 | Cross-node utility comparison leaks behavior | 9, 17, 18 | **P1** |
| F-43 | Federation E2E encryption deferred (#1809) | 17 | **v0.9** |
| F-44 | `AI_MEMORY_FED_SYNC_TRUST_PEER=1` skips visibility | 17 | **Escape hatch** |

### F. Ledger / shadow utility

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-50 | `recall_observations` = one-axis telemetry, not full RQGM fitness | 18 | **Honest** |
| F-51 | D4-015 shadow sweep (#1706) not implemented | 18 | **P1** |
| F-52 | #1707 live wire correctly DEFERRED | 18 | **Hold** |
| F-53 | #1705 consume parity MCP-sqlite-only | 18 | **P0** |
| F-54 | `access_count` = silent live fitness proxy | 8, 18 | **Benchmark target** |

### G. KG / lineage

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-60 | KG = provenance infrastructure, not RSI engine | 15 | **MUST** |
| F-61 | `kg_projection_outbox` ≠ evolutionary queue | 15 | **MUST** |
| F-62 | Subgraph monoculture audit = optional L1/L2 enhancement | 15 | **SHOULD** |

### H. Identity & procurement claims

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-70 | Ed25519 attests `agent_id`, not `model_family` | 19 | **P0 D3-012** |
| F-71 | Family-verify readiness ~15–25% (not 55–65%) | 19 | **Honest metric** |
| F-72 | "Red Queen–ready (~55–65%)" max headline claim | 7, 14, 19 | **Allowed w/ caveats** |
| F-73 | Banned: "implements RQGM" / "decorrelation enforce shipped" | 7, 21 | **Banned** |

### I. ASI infinite-horizon

| ID | Finding | Agents | Severity |
|----|---------|--------|----------|
| F-80 | Substrate attests, cannot evaluate ASI reasoning | 6, 18, 21 | **Permanent** |
| F-81 | RQGM utility gradient may not survive ASI (L3 cliff) | 6, 18, 21 | **Externalize** |
| F-82 | Principles (judge drift, epoch freeze) survive ASI | 6, 21 | **Load-bearing** |
| F-83 | Epic moonshot value = endpoint structural humility ± optional L3 accelerant | 21 | **Anchor** |

---

## Q3 — How (merged mechanism stack — 21-agent)

```
┌─────────────────────────────────────────────────────────────┐
│ L3 — ai-memory-rqgm / operator runner (EXTERNAL — HARD)     │
│     Utility evolution · panel breeding · adversarial search   │
│     READS: ledger, shadow metrics, graph monoculture stats  │
│     WRITES: signed epoch_manifest.json (RQ-01) only         │
└───────────────────────────┬─────────────────────────────────┘
                            │ operator Ed25519 signature
┌───────────────────────────▼─────────────────────────────────┐
│ L2 — ai-memory curator CLI (IN REPO, separate process)      │
│     Verify manifest → V-4 epoch.manifest_applied (RQ-10)  │
│     Epoch tick · decorrelation every cycle (RQ-11)          │
│     Panel slots from manifest · stamp metadata.epoch_id     │
└───────────────────────────┬─────────────────────────────────┘
                            │ SAL / MCP tools / hooks.toml
┌───────────────────────────▼─────────────────────────────────┐
│ L1 — ai-memory substrate (MCP/HTTP/CLI)                   │
│     persist · gate · attest · depth cap · N≥3 quorum refuse │
│     record_recall ledger · governance RuleEngine (static)   │
│     visibility #1720 · V-4 chain · federation checkpoints │
└─────────────────────────────────────────────────────────────┘
```

1. **L1 substrate:** N≥3 attested quorum on reflect/consolidate; depth cap; `record_recall` ledger; governance refuse/escalate; checkpoints federated (FED-RQ-01); `PreReflect` hooks wired (D1-001); static `RuleEngine`.
2. **L2 curator:** Unified daemon (`--store-url` on postgres fleets); load signed manifest; decorrelation **every** cycle; panel from manifest; V-4 apply row per epoch.
3. **L3 exterior:** Read ledger + probe → propose manifest N+1 → operator signs → L2 applies.
4. **Shadow utility (#1706)** before live recall wire (#1707 DEFER).
5. **CUT:** Population genetics in `src/`; `enforce` on CLAIMED metadata; governance auto-mutation; webhook-as-manifest; internal RQGM; epoch MCP tools.

---

## Q4 — Development pathway (merged — 21-agent)

### Phase 0 — Contract (Week 1)

| ID | Deliverable | Status |
|----|-------------|--------|
| RQ-00 | 21-agent vote doc (this file) | **DONE** |
| RQ-00b | 11-agent vote doc | **DONE** |
| RQ-01 | `epoch_manifest.schema.json` | **DONE** |
| RQ-02 | `RECURSIVE_LEARNING.md` L1/L2/L3 boundary | OPEN |
| RQ-03 | `honest-limitations.md` Red Queen addendum | OPEN |
| FED-RQ-01 | Checkpoint resolution on `SyncPushBody` | **DONE** (`federation_receive.rs`) |

### Phase 1 — v0.9 P0 (substrate + curator — blocking tag)

| ID | Work | Agent gate |
|----|------|------------|
| V09-RL-D3-010/011/012 | Attested `model_family` | 19 **P0** |
| V09-RL-D3-002 | #1171 panel synthesis | 5, 10 |
| V09-RL-D1-001/004 | MCP PreReflect hooks | 5, 16 **P0** |
| V09-RL-D4-015 | Shadow feedback #1706 | 18 **P1** |
| V09-RL-D2-001 | Unify reflection in daemon | 4, 20 **P0** |
| RQ-10 | `SignableEpochManifest` + V-4 `epoch.manifest_applied` | 14 **P0** |
| RQ-11..13 | Manifest load, decorrelation every cycle, panel rotation, epoch stamps | 4, 7, 12 |
| V09-RL-D3-021 | Enforce post-012 | 3, 19 |
| RQ-PARITY-01 | SQLite daemon = SAL epoch capabilities | 20 **P0** |
| #1705 | Consume parity all surfaces | 18 **P0** |
| D4-009/010 | Governance integrity rules before L3 | 13 **P0** |

### Phase 2 — v0.9.1+ (SHOULD, not blocking v0.9 tag)

| ID | Work |
|----|------|
| RQ-20..23 | `ai-memory-rqgm` reference harness |
| FED-RQ-02..05 | Federated manifest + privacy-preserving utility attestation |
| RQ-PARITY-04 | MCP-over-HTTP proxy documentation for postgres hubs |
| F-15 | Graph-augmented decorrelation subgraph audit |

### CUT (21/21)

- RQGM in `src/storage/`, `src/curator/`, or KG handlers
- #1707 live wire before #1706 proof
- `enforce` decorrelation claims at v0.8.0
- Governance auto-mutation without signed packs
- Webhook/HMAC as authoritative epoch manifest transport
- Epoch panel rotation as MCP tools
- Marketing "implements Red Queen" / "co-evolving evaluators shipped"
- Cross-node raw utility leaderboards without redaction

---

## Alternatives ranked (21-agent consensus)

| Pathway | Fit endpoint memory / ASI? | Agents |
|---------|---------------------------|--------|
| Static Gödel Machine (fixed verifier) | **Poor** — stale judges | 10 |
| Full internal RQGM | **Wrong category** — agent framework creep | 21/21 |
| **§2.6 N≥3 quorum + epoch gates + V-4 manifest apply** | **Primary — 21/21** | 10, 21 |
| Quorum alone (no epoch freeze) | **Insufficient** — mid-epoch judge drift | 21 dissent refines 10 |
| Human Escalate only (PE-5) | Necessary floor, insufficient ceiling | 13 |
| Empirical decorrelation only (no enforce) | Incomplete post-attestation | 3, 19 |
| RQGM principles + hybrid L1/L2/L3 contract | **Recommended deployment model** | 21/21 |
| Hooks.toml as L3 substitute | **Procurement theater** | 16 |

---

## Claims discipline (21-agent adopted)

**Allowed:**

- "Red Queen–ready (~55–65%)" for **principles + partial measurement spine**
- "Family-verify readiness (~15–25%)" for **§2.6 structural closure sub-metric** (Agent 19)
- "epoch-gated bias-displacement trajectory"
- "optional exterior runner contract (RQ-01 shipped)"
- "FED-RQ-01 checkpoint federation shipped"

**Banned:**

- "implements RQGM" / "co-evolving evaluators shipped"
- "decorrelation enforce" (v0.8.0)
- "epoch closure shipped" (until RQ-10 V-4 writer)
- "utility evolution attested" (until shadow #1706 + V-4 bind)
- "self-improving agent framework"
- "Hive multi-tenant isolation under Red Queen" (until FED-RQ-02..05)

---

## Epic moonshot value at ASI (Agent 21 synthesis — adopted 21/21)

**Without RQGM (substrate-only path):** ai-memory is civilization-scale **endpoint governance infrastructure** — the layer that enforces structural humility when behavioral alignment fails: refuse ASI actions without phantom-context corruption, persist cognitive identity across model discontinuities, and supply procurement-defensible audit chains at every endpoint where ASI meets physics, biology, or other minds. Epic because it is **orthogonal to capability**: it does not compete with ASI; it bounds how ASI may commit self into durable reality.

**With RQGM (correct placement — external L3 only):** the substrate gains an **optional accelerant** for agent-population operators: co-evolving evaluators propose better epoch manifests; shadow ledger supplies empirical fuel; L2 enforces freeze and quorum. Epic value **compounds** — frozen-weight cognitions accumulate skills across generations *and* across improving judge panels — without ai-memory becoming an agent framework.

**The moonshot anchor (§0 seven properties) remains constant; RQGM is a reference algorithm for sibling-repo epoch proposal, not the anchor.**

---

## Relation to other docs

| Doc | Status |
|-----|--------|
| [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.html) | **Superseded for placement** by this 21-agent doc; agent 1–11 verdicts retained above |
| [`RQGM-2606.26294-vs-v0.8.0.md`](RQGM-2606.26294-vs-v0.8.0.html) | Mechanism map valid |
| [`AGENT-9-FEDERATION-ISOLATED.md`](AGENT-9-FEDERATION-ISOLATED.html) | Federation lens detail |
| [`RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE.md`](RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE.html) | Sibling contract detail |
| [`docs/contracts/epoch_manifest.schema.json`](../contracts/epoch_manifest.schema.json) | **RQ-01 shipped** |
| [`v0.9.0/RECURSIVE-LEARNING-A-PLUS-ROADMAP.md`](../v0.9.0/RECURSIVE-LEARNING-A-PLUS-ROADMAP.md) | **Execution DAG** |
| [`moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) | **North Star — authoritative** |

---

## One-sentence outcome

> **21/21:** Adopt Red Queen **principles** through **§2.6 N≥3 quorum + signed epoch manifest + V-4 apply + unified curator L2** inside ai-memory; keep RQGM **search EXTERNAL** in `ai-memory-rqgm`; tier IoT to **L1-only**; close **D3-012 family attestation**, **D1-001 MCP hooks**, and **RQ-10 V-4 writer** as v0.9 P0 — preserving endpoint substrate epic moonshot value through AGI→ASI without scope creep.

---

**AI involvement:** 21 isolated subagent executions (11 from 2026-06-27 + 10 from 2026-06-28) + orchestrator synthesis (Grok). Operator directive 2026-06-28. Crossroads cite: `4d3ea1c5`.