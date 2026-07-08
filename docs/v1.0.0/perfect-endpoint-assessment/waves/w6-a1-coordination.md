# W6-A1 — Multi-agent hive coordination (actions / leases / signals / checkpoints)

**Lens:** What would a *perfect* endpoint coordination surface be, and how close is v0.9 Pillar-1?
**Surfaces:** actions + DAG + frontier · leases · signals · checkpoints · federation write fanout.
**Code anchors:** `src/models/{action,signal,checkpoint}.rs`, `src/actions/`, `src/signals/`, `src/checkpoints/`, `src/handlers/coordination.rs`, `src/federation/receive_auth.rs`, `src/background/lease_sweep.rs`, `docs/coordination.md`, ROADMAP §11.4 Pillar-1 / maturity “Hive coordination 40%”.
**Scope cut (W3-A4):** primitives IN; general-purpose orchestrator / subagent spawner OUT.

---

## VERDICT

**ACCEPT as endpoint coordination substrate. REJECT as perfect multi-agent hive coordination plane.**

v0.8–v0.9 ships a **real, typed, dual-backend coordination kit**: dependency DAG with legal state machine, single-holder leases + reclaim, Ed25519-signed signals, attested checkpoint resolution, CAS transitions for federated replay, and W-of-N fanout on two authority/data writes (`POST …/actions/{id}/transition`, `POST …/signals`). That is the right *shape* for hive coordination.

It is **not** perfect: federation is **node-granular** (daemon attests transitions, not per-actor leases end-to-end), leases/checkpoints/creates are largely **local MCP**, condition types are mostly **manual resolve** (not auto-evaluated gates), edge taxonomy (`unlocks`) is **under-enforced** in frontier, signal author strictness defaults **permissive**, and the product deliberately **is not a coordinator**. Perfect surface = durable multi-agent work graph with **non-repudiable actor authority**, **federated exclusive claim**, **condition-true gates**, and **partition-safe progress** — without becoming a general agent OS.

---

## SCORE (distance to perfect coordination surface)

| Axis | Score | Note |
|------|------:|------|
| Local action SM + edge model | **0.82** | Closed transition graph; 5 edge types; illegal edges rejected at SAL |
| Frontier / next scheduling | **0.68** | `requires`/`gated_by`/`blocks` load-bearing; `unlocks` decorative |
| Lease exclusive claim | **0.70** | CAS acquire + renew + hourly reclaim; **not federated** |
| Signal messaging + non-repudiation | **0.74** | Sign/verify + hooks; strict receive author gate **opt-in** |
| Checkpoint gates | **0.55** | Resolve+attest yes; auto `external_signal`/`predicate`/`deadline` thin |
| Federated coordination | **0.48** | W-of-N transition/signal; node-attested; lease mesh incomplete |
| Surface parity (MCP / HTTP / CLI / PG) | **0.60** | MCP rich; HTTP = 2 write routes; create/lease/checkpoint HTTP sparse |
| Separation-of-powers (coord vs cognition) | **0.78** | Authority transitions fail-closed by default; data signals accept-and-flag |
| **Composite (perfect hive surface)** | **0.62** | Aligns with ROADMAP hive-coordination ~40% *maturity*; primitives higher |

Scores = fraction of perfect-surface requirements met **as shipped defaults**, not “exists in code somewhere.”

---

## REQUIREMENTS (perfect surface)

1. **Work graph** — actions as first-class nodes; typed edges; monotonic *progress* under concurrent claim; frontier = pure function of graph + state.
2. **Exclusive claim** — at most one live holder per action across the trust domain (local **and** federated), with heartbeat + reclaim + signed release.
3. **Authority writes** — state transitions are actor-attested, lease-bound, CAS, replay-safe (nonce + expected `from`).
4. **Messaging** — signals: typed, signed, threadable, ackable; author = enrolled key, not wire pubkey.
5. **Gates** — checkpoints block progress until **evaluated** conditions (approval / signal / predicate / deadline) with attested resolution; multi-party approval when N>1.
6. **Federation** — W-of-N for authority ops; no silent dual-holder under partition; DLQ + causality (`vector_clock` or equivalent) actually drive merge.
7. **Hooks & stoppability** — PreSignalSend / transition governance; operator stop does not corrupt graph.
8. **Non-goals (keep OUT)** — subagent spawn, planner/LLM orchestration, global scheduler as product (W3-A4).

---

## GAPS (v0.9 vs perfect)

| # | Gap | Evidence |
|---|-----|----------|
| G1 | **`unlocks` not in frontier** | `frontier_where_tail` only `requires`/`gated_by` + `blocks` (`src/actions/mod.rs`) |
| G2 | **Leases not federated** | `receive_auth`: “full federated-lease auth tracked separately”; no lease W-of-N |
| G3 | **Local transition ≠ lease-bound** | `transition` updates state/`claimed_by` without requiring live lease holder match; receive path is best-effort on *local* lease only |
| G4 | **Node ≠ actor on fanout** | `coordination.rs`: broadcast attests **daemon** agent_id; caller `claimed_by` is local concern |
| G5 | **HTTP write surface partial** | Only transition + signal send; no create/edge/lease/checkpoint/frontier HTTP |
| G6 | **Checkpoint conditions mostly manual** | Types exist (`external_signal`, `condition_predicate`, `deadline`); auto-evaluator not a closed loop into frontier |
| G7 | **No multi-resolver checkpoint quorum** | Single `resolved_by` + one Ed25519 resolution; hive multi-party approval is application-layer |
| G8 | **Signal strict author default OFF** | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` permissive; Layer-1 allowlist only when enrolled |
| G9 | **`vector_clock` underused** | Column present; transition signable deliberately omits heavy merge semantics |
| G10 | **Lease reclaim cadence coarse** | Hourly sweep (`lease_sweep.rs`); short-TTL holders can strand work until next tick or CAS re-acquire on expiry check |
| G11 | **Partition dual-progress** | ADR-0001 local-commit + 503-on-miss quorum: under-replication visible, not rolled back — dual leaders possible across partitions |
| G12 | **Coordinator OUT by design** | Perfect *hive behavior* still needs external planner; substrate alone ≠ hive intelligence |

**Shipped strengths (do not underrate):** `transition_cas` + non-monotonic SM awareness (#1718 H1); `FED_REQUIRE_TRANSITION_SIG` fail-closed; transition replay nonce (#1805); signal hooks Pre/Post; lease CAS Conflict; dual sqlite/postgres frontier predicate parity; checkpoint dual-use for audit/governance anchors (G5b/G9) without polluting coordination model.

---

## VOTE (5-axis synthetic)

| Lens | Stance |
|------|--------|
| Precedent | Extend Pillar-1 + #1718/#1805; do not invent a second orchestration product |
| Spec / moonshot §2.5–2.6 | Primitives strengthen attestation + SoP; do not claim hive-complete |
| Security | Keep authority-lane fail-closed; promote signal/lease strictness with enrolled-key bind |
| Testability | Golden CAS + dual-holder partition fixtures + frontier edge-matrix tests |
| Blast radius | Additive: federated leases, condition evaluators, HTTP parity; no general orchestrator |

**Tally:** 5/5 — **perfect the coordination *substrate*; never absorb the coordinator.**

**Chosen pathway:** (1) lease↔transition binding + federated lease auth, (2) frontier edge completeness + auto-checkpoint evaluation hooks into `gated_by`, (3) actor-attested transition fanout (or dual-sign node+actor), (4) HTTP/CLI parity for create/lease/checkpoint reads, (5) document partition dual-leader as residual until stronger consensus (out of scope as BFT product).

---

## KILLER_OBJECTION

**“We already have actions + leases + signals + W-of-N, so hive coordination is done.”**  
Without **federated exclusive claim** and **actor-bound authority** (not just node envelope + local lease), two enrolled peers can each believe they hold progress under partition, and a federated transition can move work **without** a mesh-visible lease. That is a **task queue with crypto garnish**, not perfect multi-agent coordination. Primitives without claim-domain integrity invite double-work and double-authority — the exact failure mode a hive surface is supposed to make impossible.

---

## TOP_RISK

**False maturity: “Hive coordination 40%” treated as cosmetic when operators wire production multi-agent workflows on local leases + fanout transitions.** Secondary: expanding edge types / routines / HTTP candy without closing G2–G4 increases surface area while the dual-holder and node/actor split remain load-bearing defects. Tertiary: pressure to absorb an orchestrator (W3-A4 eternal cut) would destroy substrate focus and SoP.

---

## One-line north star

> **Perfect hive coordination is exclusive, attested, condition-gated progress on a shared DAG — substrate enforces the physics of claim and authority; something else may plan the work.**
