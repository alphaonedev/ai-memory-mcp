---
layout: doc
redirect_from:
  - /reviews/AGENT-9-FEDERATION-ISOLATED.md
---

# Agent 9 — Federation / Multi-Endpoint (ISOLATED RUN)

**Status:** Isolated subagent execution (no cross-talk)  
**Date:** 2026-06-28  
**Lens:** Federation / Hive multi-endpoint / federated Red Queen epoch closure  
**Codebase:** `release/v0.8.0` @ workspace HEAD  
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) §0, §2.6  
**Prior merge doc:** [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.html)  
**Subagent ID:** `019f0e12-71da-71e0-8970-bae7e6d3340f` (audit trail from orchestrator)  
**Paper:** [The Red Queen Gödel Machine (arXiv:2606.26294)](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al., 24 Jun 2026)

---

## VERDICT

**Federated panel manifest via signals; checkpoint fanout was the blocking gap — now closed on receive path (FED-RQ-01).**

| Field | Value |
|-------|-------|
| **CONFIDENCE** | 78% |
| **ASI_MOONSHOT_GRADE** | **B+** — substrate pathway correct; federation epoch closure incomplete until FED-RQ-02..05 |
| **TOP_RISK** | Cross-node utility comparison leaks competitive data |
| **KILLER_OBJECTION** | Internal RQGM + federation without federated epoch manifest = split-brain epoch boundaries |

---

## Q1 — Should Red Queen be used?

**YES — principles + epoch discipline · CUT full RQGM algorithm from `src/`**

Stationary judges fail at Hive scale (§2.6). Red Queen **principles** (non-stationary evaluation, epoch-bound utility) MUST inform v0.9+ federation design. Full RQGM search MUST NOT ship in core — it couples evolutionary genetics to MCP/HTTP hot paths and splits epoch boundaries across nodes without a signed manifest.

---

## Q2 — External vs internal?

**HYBRID + federated manifest (hard L3 external line)**

```
┌─────────────────────────────────────────────────────────────┐
│ L3 — ai-memory-rqgm / operator runner (EXTERNAL — HARD)     │
│     Utility evolution · panel breeding · adversarial search │
└───────────────────────────┬─────────────────────────────────┘
                            │ signed epoch_manifest.json (RQ-01)
                            │ + federated checkpoint closure (FED-RQ-01..05)
┌───────────────────────────▼─────────────────────────────────┐
│ L2 — curator CLI (epoch tick · manifest consumer)             │
└───────────────────────────┬─────────────────────────────────┘
                            │ SAL / MCP
┌───────────────────────────▼─────────────────────────────────┐
│ L1 — ai-memory substrate (federation mesh · checkpoints)      │
└─────────────────────────────────────────────────────────────┘
```

Hive/ASI deployments **require** cross-node agreement on epoch gates before curator L2 can claim cluster-wide epoch closure. Signals already federate; checkpoints did not — that was the split-brain vector.

---

## Q3 — How?

1. **L1:** N≥3 quorum on reflect/consolidate; **checkpoints federated on `SyncPushBody`** (FED-RQ-01, implemented); signals for panel manifest propagation.
2. **L2:** Curator loads signed `epoch_manifest.json`; stamps `metadata.epoch_id`; decorrelation every cycle (RQ-11).
3. **L3:** Exterior runner proposes manifest N+1; operator signs; no in-repo search.
4. **Shadow #1706** before live recall wire (#1707 DEFER).
5. **CUT:** Internal RQGM; cross-node utility leaderboard without governance.

---

## Q4 — Development pathway?

| Phase | Federation deliverable | Status |
|-------|------------------------|--------|
| **P0** | FED-RQ-01 — checkpoint create + resolution on `SyncPushBody` | **SHIPPED** (this run) |
| **P0** | RQ-01 `epoch_manifest.json` schema | OPEN (Agent 11 P0) |
| **P1** | FED-RQ-02..05 — federated manifest + `policy_version` gate | OPEN (v0.9.1+) |
| **P1** | HTTP quorum fanout for checkpoint writes (Commit B/C parity with #1718 signals) | OPEN (follow-on) |
| **P1** | `/sync/since` checkpoint delta pull | OPEN (catch-up parity) |

Substrate spine → curator L2 → `ai-memory-rqgm` sibling remains correct; federation work is **on the critical path** for swarm-tier Red Queen readiness, not optional polish.

---

## Q5 — Correct pathway? Better than full RQGM?

**YES — §2.6 N≥3 quorum + federated epoch substrate > internal RQGM.**

RQGM optimizes agent populations; ai-memory optimizes governed persistence at the endpoint boundary. For Hive/ASI, the durable answer is **attested quorum + epoch-gated substrate + federated manifest contract**. RQGM is an optional L3 accelerant for agent-heavy operators — never the core law.

---

## Codegraph — `SyncPushBody` checkpoints gap (confirmed → fixed)

### Pre-fix evidence (v0.8.0 @ orchestrator merge)

| Symbol | Finding |
|--------|---------|
| `handlers::federation_receive::SyncPushBody` | Fields: `memories`, `signals`, `action_transitions` — **no `checkpoints`** |
| `federation::sync::broadcast_signal_create_quorum` | Outbound signal fanout wired (#1718 Commit B) |
| `federation::sync::broadcast_action_transition_quorum` | Outbound transition fanout wired |
| *(none)* | No `broadcast_checkpoint_*_quorum` |
| `checkpoints::insert` / `checkpoint_resolve` | Local MCP + SAL only |
| `handlers::coordination` | HTTP fanout for signals + action transitions; **no checkpoint HTTP surface** |

**Orchestrator dissent (Agent 9, adopted in merge):** *"Checkpoints not federated on `SyncPushBody` today — epoch boundaries are per-node."*

### Post-fix (FED-RQ-01, this isolated run)

| Change | Location |
|--------|----------|
| `checkpoints: Vec<Checkpoint>` on wire | `src/handlers/federation_receive.rs` |
| Fail-closed resolution auth | `src/federation/receive_auth.rs` (`authorize_remote_checkpoint_resolution`, `AI_MEMORY_FED_REQUIRE_CHECKPOINT_RESOLUTION_SIG`, default fail-closed) |
| Pending→terminal CAS + verbatim attestation | `src/checkpoints/mod.rs` (`apply_federated`) |
| Postgres twin | `src/store/postgres.rs` (`checkpoint_apply_federated`) |
| Sqlite receive + postgres receive | `federation_receive.rs`, `federation_signing_check.rs` |
| Integration test | `tests/cov_ga2_federation.rs::sync_push_applies_checkpoints_sqlite` |

**Remaining gaps (honest):**

- Outbound W-of-N fanout on local checkpoint create/resolve (Commit B/C parity with signals) — not in FED-RQ-01 scope.
- `/sync/since` does not yet return checkpoint deltas for catch-up pull.
- FED-RQ-02..05 federated `epoch_manifest.json` propagation — Phase 2.

---

## FED-RQ item ledger (Agent 9 ownership)

| ID | Deliverable | Priority | Status |
|----|-------------|----------|--------|
| **FED-RQ-01** | Checkpoint create + resolution on `SyncPushBody` | P0 MUST | **DONE** (2026-06-28) |
| **FED-RQ-02** | Federated `epoch_manifest.json` on `SyncPushBody` or signal envelope | P1 | OPEN |
| **FED-RQ-03** | Cross-node `policy_version` gate (refuse stale manifest) | P1 | OPEN |
| **FED-RQ-04** | Checkpoint catch-up on `/sync/since` | P1 | OPEN |
| **FED-RQ-05** | HTTP quorum fanout for checkpoint writes | P1 | OPEN |

---

## DISSENT_FROM_11_AGENT

| Topic | Orchestrator merge | Agent 9 isolated dissent |
|-------|-------------------|--------------------------|
| **FED-RQ-01 timing** | Listed Phase 0 Week 1 MUST | **Agree** — was blocking; implemented this run |
| **Q2 HYBRID label** | 11/11 HYBRID on substance | **Agree on substance**; insist label must mean **signed manifest contract**, not feature flags in curator |
| **L3 optional** | RQGM = optional L3 reference | **Agree** for single-node; **dissent for Hive tier**: optional L3 becomes **operationally mandatory** for panel breeding at 32+ endpoints — still EXTERNAL, but not "nice to have" |
| **Confidence** | Synthesis 87% | **Hold 78%** until FED-RQ-02..04 land; epoch closure claim premature at 87% for federation lens |
| **ASI utility measurability** | Agent 6 dissent adopted | **Reinforce**: cross-node utility comparison is a **data-leak + Goodhart** surface; federation must propagate **manifest + checkpoint attestations**, not raw utility scores |

**Explicit:** Agent 9 does **not** dissent from Q1/Q5 unanimous conclusions. Dissent is on **confidence inflation** and **Hive-tier L3 "optional" framing** only.

---

## Claims discipline (federation lens)

**Allowed after FED-RQ-01:** "Federated checkpoint resolution receive path on `/sync/push`" · "Red Queen–ready (~55–65%)"

**Still banned:** "implements RQGM" · "federated epoch manifest shipped" · "cluster-wide epoch closure" (until FED-RQ-02..04)

---

## One-sentence outcome (Agent 9)

> Adopt Red Queen **principles** with **HYBRID + federated manifest** placement; **FED-RQ-01 closes the checkpoint fanout gap on receive**; finish **FED-RQ-02..05** before claiming Hive epoch closure; keep RQGM search **EXTERNAL** — preserving endpoint memory law through AGI→ASI without split-brain epoch boundaries.

---

**AI involvement:** Isolated Agent 9 execution (Grok). Operator directive 2026-06-28. Crossroads cite: `4d3ea1c5`.