# Red Queen / RQGM vs ai-memory — 21-Lens Adversarial Assessment (OPUS)

**Status:** FINAL synthesis — **21 isolated lenses across 3 sequential waves of 7 subagents (7-concurrent hard cap)**
**Author / orchestrator:** Claude Opus 4.8 (1M context)
**Date:** 2026-06-28
**Codebase:** `release/v0.8.0` @ `ead3da0c` (delta vs prior Grok base `c85b9c56` = **docs-only**, 2 commits, no `src/` change)
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../strategy/moonshot-synthesis.md) §0 (endpoint substrate through AGI→ASI→beyond)
**Paper:** [The Red Queen Gödel Machine (arXiv:2606.26294)](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al., 24 Jun 2026)
**Provenance:** Surfaced to the project by **Nick Jensen** — [X post](https://x.com/howtoprompt__/status/2070824205663273175) · [abstract](https://arxiv.org/abs/2606.26294) · [PDF](https://arxiv.org/pdf/2606.26294)
**Prior art (re-verified, not assumed):** [`RQGM-2606.26294-vs-v0.8.0.md`](RQGM-2606.26294-vs-v0.8.0.md) · [`RED-QUEEN-21-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-21-AGENT-VOTE-vs-ai-memory.md) (Grok) · [`RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-11-AGENT-VOTE-vs-ai-memory.md) · GitHub issue #1820
**Companion:** [`RQGM-2606.26294-vs-v0.8.0-OPUS.md`](RQGM-2606.26294-vs-v0.8.0-OPUS.md) (paper↔code mechanism map)

---

## Plain-English verdict (one paragraph)

ai-memory v0.8.0 **does not implement RQGM and should never try to** — RQGM optimizes *agents*, ai-memory governs *persistence*, and welding a self-improving optimizer into the layer whose entire value is being a trustworthy, frozen, attested verifier is a category error that would falsify the project's own one-sentence anchor. What the substrate *should* adopt is the Red Queen **principles** — frozen-within-epoch evaluation, decorrelated multi-grader quorum, and adversarial bias-checking — with the evolutionary **search engine kept in an external sibling repo** that reads substrate telemetry and writes back a single **signed** epoch artifact the in-repo curator verifies and anchors to the V-4 audit chain. At v0.8.0 the substrate already ships the *measurement and attestation scaffolding* (observation ledger with dual-backend *record* parity — though the *consume* flip is dead code, see C-1; V-4 chain, attested checkpoints, bounded depth-capped reflect, an honest advisory-only decorrelation probe) but **none of the optimization half**, and the two load-bearing preconditions for bias-displacement to be real — **attested model-family provenance** and a **reachable MCP PreReflect veto** — are not built (`SignableWrite` carries no model_family; the MCP reflect path runs `ReflectHooks::empty()`). The correct path is the moonshot's own §2.6 — **N≥3 attested-family quorum + epoch-freeze + V-4 manifest-apply** — which is more ASI-durable than internal RQGM because its *mechanism* is capability-orthogonal (it counts signatures and freezes a window; it never out-thinks the cognition it audits) — **conditional on two predicates the substrate has not yet built: family-distinctness (~5% today) and vote-independence (0% — it cannot yet tell genuine decorrelated agreement from N rubber-stamp votes by one model in N hats)** (C-3). Ship the v0.9 substrate spine (family attestation → then enforce; shadow → then live; MCP hooks; V-4 epoch writer; unified curator) as P0; keep the RQGM runner as a v0.9.1+ external sibling.

---

## Adversarial self-review corrections (7-agent red-team, 2026-06-28)

This synthesis was itself red-teamed by 7 independent adversarial agents (citation integrity · divergence correctness · checkpoint-vs-manifest · 11-agent-stale · self-overclaim · ASI-rigor · sibling-boundary). They confirmed it is **citation-sound with zero fabrications**, and surfaced corrections that **supersede** any conflicting statement below. (Companion doc carries the same table as C-1…C-8.)

| # | Affected claim | **Correction** |
|---|----------------|----------------|
| C-1 | F-62 / Lens 18: "consume-parity FULL (both backends, all 3 surfaces)" | Backend **twins** exist (refutes Grok F-53's sqlite-only) **but the consume FLIP is wired to ZERO production surfaces** — dead capability (test-only callers). Strengthens "ledger is write-only". New defects **D-OPUS-6** (consume dead) + **D-OPUS-7** (LIST split-brain MCP-sqlite vs HTTP-SAL). |
| C-2 | F-06 / Lens 10: epoch_manifest "duplicates" the Checkpoint → bind "instead of" a JSON file | **False dichotomy → COMPLEMENTARY.** The Checkpoint signature *excludes* `condition`/`metadata` (`sign.rs:650-657`), so it cannot carry a content-attested epoch payload. Correct: bind a content-signed manifest **TO** an `EpochAdvance` Checkpoint (manifest signs WHAT; Checkpoint federates/attests WHEN+WHO + pins `content_hash` in its signed `resolution`). |
| C-3 | Plain-English + Q5: "§2.6 quorum+epoch **strictly more ASI-durable**" | **Conditional.** Quorum is capability-orthogonal in *mechanism* (agreement = vote-count, `store/mod.rs:2395,3116`) but "N attested families agreed" needs two **unbuilt** predicates: family-distinctness (~5%) **and vote-independence (0% — substrate can't distinguish genuine agreement from N rubber-stamp votes by one model in N hats)**. → "more durable **conditional on two unbuilt attestation predicates**." |
| C-4 | Exec table + grade rollup: "B+ → A− **after D3-012 + RQ-10**" | A− must gate on the **full v0.9 P0 spine** (D3-012, D1-001, RQ-10, RQ-PARITY-01, F-40, F-41) — not 2 items. Also: name the two grade axes — **moonshot-§0 substrate-fitness** (the B+ composite; per-property mostly A/A−) vs **RQGM-readiness** (~15%) — so B+ beside D+/5% is not self-contradictory. |
| C-5 | F-15 vs F-06: "epoch-freeze is **not mechanized anywhere**" | **Refuted as literal; substantive point stands.** Freeze **primitives** exist (`routine_freeze` `postgres.rs:2907,15133`; attested Checkpoint; leadership-epoch fencing token `sequencer.rs:66`); the **utility-epoch freeze LOOP** does not. |
| C-6 | F-81 / Lens 6 dissent (measurability cliff softer) | **Split it.** Bounded **structural-invariant** signals ARE substrate-measurable / capability-orthogonal vs ASI (invariant-violation COUNTs `connection.rs:183-200`, partial-quorum `metrics.rs:469`, `DepthExceeded`). **Semantic-judgment** signals are NOT (contradiction-density = an LLM call `llm.rs:2076` → capability-coupled). Cliff is softer only for the structural class. |
| C-7 | Lens 14 / D-OPUS: "**6** Signable* structs" | **7** — add `SignableRoutineFreeze` (`sign.rs:770`). "No `SignableEpochManifest`" point unaffected. |
| C-8 | F-22 / D-OPUS-3: "PE-1 procurement-theater" | Retitle: **"`doctor --hooks` over-asserts unreachable PE-1 Deny."** PE-1 is a legitimate opt-in default-off gate; the narrow defect is the doctor string promising enforcement with zero production wiring. |

**Methodology correction (Auditor 4):** the "delta vs Grok base `c85b9c56` = docs-only, no `src/` change" line describes *committed* history; the **working tree** assessed here carries **uncommitted FED-RQ-01** (+~282 lines, 4 files `M`). FED-RQ-01 is **in-flight, not merged** — so the prior 11-agent doc's "checkpoints not federated" was true at its base and the working tree now contradicts it (see the OPUS 11-agent re-issue).

**Process flag for the operator:** FED-RQ-01 (an authority-granting federated write path) and the `epoch_manifest.schema.json` (a persisted/attested wire contract) both match crossroads triggers **T1/T3/T4**. If they are committed without a `5-agent vote (4d3ea1c5)` citation, that is a self-flag worth surfacing.

---

## Methodology (load-bearing)

- **21 lenses · 3 waves × 7 subagents max.** Claude Code caps concurrent subagents at 7, so 21 lenses ran as **three sequential isolated waves of seven**, each wave collected in full before the next launched.
- **Isolation / anti-groupthink.** Each subagent received only its lens assignment + repo path + the paper links + the Q1–Q5 schema + the placement model to validate/refute. **No prior-wave verdicts and no Grok-doc conclusions were passed in**; subagents were explicitly instructed *not* to read `docs/reviews/RED-QUEEN*` / `RQGM*`. They formed independent judgments from the paper and the code.
- **CodeGraph as L1 evidence.** The CodeGraph **MCP server** was not connected this session; CodeGraph was driven via its **CLI** (`/Users/fate/.grok/bin/codegraph`, identical query backend; warm index 846 files / 27,062 nodes / 92,578 edges). Every load-bearing claim carries a `file:line` touchpoint. The ai-memory **memory MCP** was likewise unavailable → file-based memory used. Both substitutions are documented per the prime directive's verify-before-claiming rule; no live-daemon behavioral claim is made without a code touchpoint.
- **Wave timing (parallel within wave):** W1 ≈ 64–107 s/agent · W2 ≈ 47–119 s/agent · W3 ≈ 65–137 s/agent. No lens failed; all 21 returned. No supplemental retry batch needed.

| Wave | Lenses |
|------|--------|
| **Wave 1 (1–7)** | North Star · Architecture · Security · Curator · D1 Recursive-Learning · ASI Trajectory · Procurement |
| **Wave 2 (8–14)** | Performance · Federation · Alternatives · Sibling-Repo · IoT Tiering · Governance/PE-5 · V-4 Attestation |
| **Wave 3 (15–21)** | KG/AGE · Hooks/Webhooks · Encryption/Visibility · Observations Ledger · NHI Identity · MCP/HTTP/CLI Parity · Moonshot Integrator |

---

## Executive synthesis (orchestrator merge — 21/21)

| Question | **FINAL** | Agreement |
|----------|-----------|-----------|
| **Q1** Use Red Queen? | **YES — principles + epoch discipline.** **CUT the full RQGM algorithm from `src/`.** | **21/21** |
| **Q2** Where? | **L3 evolutionary SEARCH is EXTERNAL (hard line).** In-repo = L1 substrate + L2 curator consumer/verifier only → **HYBRID-as-contract.** | **21/21 on substance** (label split 10 EXTERNAL / 10 HYBRID / 1 "INTERNAL=L1-reflect-primitive scope") |
| **Q3** How? | N≥3 **attested**-family quorum · frozen-within-epoch utility · **V-4 `epoch.manifest_applied` apply** · shadow (#1706) before live (#1707) · optional exterior runner · **epoch boundary should bind to the existing attested Checkpoint, not a net-new JSON file** | **21/21** (+ Opus checkpoint-vs-manifest refinement) |
| **Q4** Pathway? | v0.9 P0 substrate spine (family attestation → enforce; MCP PreReflect; V-4 epoch writer; unify curator; close governance silent-disable) → `ai-memory-rqgm` sibling at v0.9.1+ | **21/21** |
| **Q5** §2.6 quorum+epoch better than internal RQGM? | **YES — capability-orthogonal beats capability-coupled.** Quorum **alone** is necessary-not-sufficient; **needs epoch-freeze**, which is **not mechanized in code yet**. | **21/21** |

**Synthesis confidence:** **~88%** (per-lens range 82–93%).

**Composite ASI moonshot grade:** **B+** on the hybrid-principles path *today* (capped by §2.6 enforce-inert + the untracked/arguably-duplicative epoch contract + family-verify ≈ 5%) → **A−** after D3-012 (attested family) + RQ-10 (V-4 epoch writer). **C− / D+** if internal RQGM ships in `src/`.

### Unanimous (21/21)

1. Red Queen **principles MUST** inform v0.9+ — stationary judges go stale at swarm/ASI scale (the core Red Queen problem).
2. Full RQGM **MUST NOT** ship inside ai-memory core (`rg 'epoch_manifest|Agent-as-Judge|co-evolv|RQGM|evolutionary|genetic|fitness' src/` = **0 production hits today** — keep it that way).
3. Curator = **L2 epoch host**, not L3 search engine — but it is **not built into one yet** (0 epoch machinery in `src/`).
4. **Attestation before enforce** (D3-012 → D3-021) and **shadow before live** (#1706 → #1707 DEFER) — both already encoded as code-level dependencies.
5. **§2.6 N≥3 attested quorum + epoch-freeze** is the primary ASI-durable answer; RQGM is an optional accelerant for agent-heavy L3 only.
6. `enforce` decorrelation on **CLAIMED** metadata = security theater — the INERT degrade is the **correct** v0.8.0 posture.
7. Governance rules **must never auto-mutate** under Red Queen; operator-signed packs gate any epoch change.
8. An epoch apply **must hit the V-4 chain** (`epoch.manifest_applied`) — a signed contract schema alone is insufficient and is, at v0.8.0, **untracked with no `src/` consumer**.
9. The **MCP `ReflectHooks::empty()`** gap blocks the D1/quorum veto on the primary NHI path (D1-001).
10. **SQLite vs SAL curator bifurcation** blocks L2 epoch parity on postgres fleets until a unified daemon (RQ-PARITY-01).

---

## Tally tables (21/21)

### Q1 — Should Red Queen be used?
**21/21 YES (principles only). 0/21 full RQGM algorithm in `src/`.**

### Q2 — External vs internal
**21/21 agree the L3 evolutionary SEARCH is EXTERNAL (hard line).** Label distribution (a wording difference, not a substance disagreement — "HYBRID" counts the in-repo L2 verifier; "EXTERNAL" emphasizes the search boundary; Lens 5's "INTERNAL" refers only to the L1 reflect primitive being a local write and still keeps RQGM external):

| Label | Lenses | Count |
|-------|--------|-------|
| EXTERNAL | 2, 3, 4, 6, 7, 8, 12, 13, 15, 17 | 10 |
| HYBRID (L1+L2 internal consumer, L3 external search) | 1, 9, 10, 11, 14, 16, 18, 19, 20, 21 | 10 |
| INTERNAL (scope = L1 reflect primitive only; RQGM still external) | 5 | 1 |

### Q3 — Mechanism stack
21/21 converge on: **attested-family quorum (N≥3) → frozen-within-epoch utility → signed epoch artifact → V-4 `epoch.manifest_applied` apply → shadow-#1706-before-live-#1707 → optional external runner.** Opus refinement (Lens 10, adopted): the epoch boundary should **bind to the existing attested Checkpoint primitive** (`src/models/checkpoint.rs:106-128`) rather than introduce a parallel JSON manifest, OR the two must be explicitly reconciled.

### Q4 — Pathway
21/21: v0.9 P0 substrate spine first; L3 RQGM runner is a v0.9.1+ external sibling. (Agent 6 reserves ASI utility-measurability for L3 algorithms — see dissent.)

### Q5 — Is §2.6 quorum + epoch better than internal RQGM?
**21/21 YES.** Refinement (Lens 6, 10, adopted): quorum **alone** is necessary-not-sufficient (defeats *spatial* correlation, defeated by *temporal* judge-drift); **epoch-freeze** supplies the temporal half and is **not yet mechanized in code** (the attested Checkpoint could supply it).

---

## ASI moonshot grade rollup

| Lens cluster | Lenses | Grade (hybrid path) | Load-bearing finding |
|--------------|--------|---------------------|----------------------|
| North Star / scope | 1, 21 | **A− → A** post-D3-012 | 7 properties strengthen with principles; internal RQGM downgrades §2.1/§2.3/§2.5/§2.6 |
| Architecture / parity | 2, 20 | **B+ / B** | Schema-without-consumer; curator `run_once` ⊋ SAL sweep → no postgres L2 epoch parity |
| Security / governance | 3, 13, 17 | **B+ / B− / B−** | Rules static+signed; **silent-disable hole**; cross-node utility = behavioral leak |
| Curator / L2 | 4, 16 | **D+ / D-wiring** | Single `AutonomyLlm`; decorrelation `--reflect`-only (1 caller); PreReflect dead; PE-1 tests-only |
| D1 / recursive learning | 5 | **A principle / B+ impl** | `reflect_with_hooks` real + depth-bounded; MCP veto unreachable |
| ASI trajectory | 6, 18, 21 | **A− / B− / A−** | Utility-measurability cliff at L3; principles survive; ledger is one-axis telemetry |
| Procurement | 7, 14, 19 | **C+ / B / D+** | Substrate-readiness ≈15%, family-verify ≈5%; V-4 epoch writer + SignableEpochManifest missing |
| Performance | 8 | **A−** | #965 verified (HTTP mutex real, MCP dispatch mutex-free); `access_count` silent live proxy |
| Federation | 9, 17 | **B / B−** | FED-RQ-01 checkpoints shipped both backends; epoch-manifest federation absent; utility side-channel |
| Alternatives | 10 | **B+** | Quorum needs epoch-freeze; epoch-manifest duplicates the attested Checkpoint |
| Sibling / contract | 11 | **C+** | Schema untracked, zero consumer, no verifier; RQ-A…RQ-F gaps |
| IoT tiering | 12 | **B** | Tier A=L1-only validated; "kilobytes RAM" overclaim (~31 MB / ~18–25 MB RSS) |
| KG / lineage | 15 | **A / F-if-RQGM-in-KG** | KG = provenance mirror; `kg_projection_outbox` = perf outbox, not RQGM queue |

---

## Per-lens verdicts (grouped by wave)

> Each lens returned `VERDICT / CONFIDENCE / ASI_GRADE / TOP_RISK / KILLER_OBJECTION / Q1–Q5 / touchpoints / dissent`. Condensed below; `file:line` evidence retained for load-bearing claims.

### Wave 1

**Lens 1 — North Star / Scope Purist** · A− (C if internal) · 88%
RQGM principles are the *same* federalist separation-of-powers move §2.6 already makes; embedding the optimizer inside the verifier destroys the property that makes the verifier trustworthy. **Killer objection:** a verifier that adversarially improves itself is no longer a trustworthy verifier (`moonshot-synthesis.md:104,190`). **Dissent:** ship the epoch-manifest CONSUMER as P0 *only* if hard-gated on attested model-family; a signed ledger over CLAIMED diversity *launders* unattested decorrelation into a cryptographically-signed artifact — worse than no ledger. Touchpoints: `decorrelation_probe.rs:254,71-74`; `store/mod.rs:4107`; `postgres.rs:16113`; `signed_events.rs:14-69`; `sequencer.rs:66` (NOTE: Raft leadership-epoch ≠ RQGM utility-epoch — do not conflate).

**Lens 2 — Architecture / Layering** · B+ · 86%
L1/L2/L3 is the correct line, but it is a **contract-without-a-consumer** and the curator already bifurcates. **Killer objection:** `epoch_manifest` appears ONLY in `docs/contracts/…json` — no Rust consumer in `src/` or `tests/`. A manifest consumer added to the conn-bound `run_once` (`curator/mod.rs:261`) would be sqlite-only and silently break postgres-fleet epoch parity → a *third* curator stack. Touchpoints: `curator.rs:204-207` (dispatch fork), `:200-203` (admitted "not yet trait-ported"); `curator/mod.rs:261,542`.

**Lens 3 — Security / Fail-Closed** · B+ · 88%
Genuinely fail-closed and already enforces attestation-before-enforce: enforce hard-degrades to advisory, rules are operator-Ed25519-signed-only, V-4 is fail-closed. **The one true hazard is any future internal path that lets an RQGM loop write `governance_rules`** — legislature+executive+judge collapse. Touchpoints: `decorrelation_probe.rs:272-281` (enforce INERT, exact line); `config.rs:4969-4984`; `agent_action.rs:782-800,983`; `rules_store.rs:187-249`; `signed_events.rs:14-99`. **Note (e):** cross-node utility comparison must be aggregate-only, never per-row.

**Lens 4 — Curator Runtime** · D+ · 88%
The curator is a plausible epoch-host *shell* but the placement model materially **overstates today's wiring** — "decorrelation every cycle" and "epoch tick/manifest consumer" are fiction in `src/`. **Killer objection:** exactly ONE production judge (`OllamaClient` @ `autonomy.rs:125`); decorrelation probe has exactly **1 production caller** (`run_reflect` only), never in `run_once`/`store_backed_sweep`; enforce INERT. Touchpoints: `curator.rs:114` (build_curator_llm, 3 callers, all single OllamaClient); `decorrelation_probe.rs:254,59,67-74`; `config.rs:7283` (compaction default OFF), `:5025` (decorrelation default `off`); `rg -ni 'epoch_manifest|epoch_id|epoch_tick' src/` = 0.

**Lens 5 — D1 Recursive Learning** · A principle / B+ impl · 93%
The reflect primitive is real, depth-bounded, audit-emitting, and correctly draws the learning-vs-self-improvement line — but **the in-substrate PreReflect veto is dead on every NHI path**: `handle_reflect` builds hooks that only set `post_reflect`; `pre_reflect: None` everywhere; `HookVeto` structurally unreachable. The **depth cap does NOT depend on the hook and IS enforced before any transaction opens**, so runaway recursion is genuinely refused. Touchpoints: `storage/reflect.rs:298,413,454,531,391-398,43-55`; `mcp/tools/reflect.rs:496` (`ReflectHooks::empty()`); `reflect.rs:73-82,1219-1224` (docstring/test admit unreachable).

**Lens 6 — ASI Trajectory** · A− · 84%
The RQGM **utility gradient does not survive ASI** — a frozen-capability substrate cannot score a more-capable cognition's utility (unbounded Agent-as-Judge regress) → utility-evolution MUST be external. What survives is the **principles**; the substrate already ships their honest first increment (ATTEST + REFUSE, never EVALUATE). **Killer objection:** "decorrelated quorum" is theater-adjacent today — `producer_signal` ranks CLAIMED strings, so a monoculture in N hats passes the count. **Dissent (important):** the measurability cliff may be *softer* than asserted — bounded signals (invariant-violations, refusal-rate deltas, contradiction-density) may stay substrate-measurable vs ASI; and **epoch-FREEZE is not mechanized anywhere in code** (no `src/` evidence) — the "epoch-gated substrate" half of the durable answer is currently unbuilt, not just deferred. Touchpoints: `sign.rs:319-340` (SignableWrite, 6 fields, NO model_family); `decorrelation_probe.rs:101-117,242-278`; `signed_events.rs:14-69`.

**Lens 7 — Procurement / Claims** · C+ · 93%
Ships the MEASUREMENT scaffolding, ZERO of the OPTIMIZATION loop; `epoch_manifest.schema.json` is **git-untracked with no `src/` consumer**; `SignableWrite` attests `agent_id` only. **Readiness: substrate ≈15%, family-verify ≈5%.** Allowed/banned claim lists produced. Touchpoints: `sign.rs:318-340`; `observations/mod.rs:65,108,144`; `decorrelation_probe.rs:55,68-74,242,273-276`; `git ls-files docs/contracts/` empty.

### Wave 2

**Lens 8 — Performance / Ops** · A− · 86%
External placement is the performant choice; **#965 verified TRUE**: HTTP `Db = Arc<Mutex<(Connection,…)>>` (mutex real, `transport.rs:22`), MCP dispatch holds plain `&rusqlite::Connection` (no dispatch mutex, `mcp/mod.rs:1147`, audit pins `:4001-4127`). **Nuance (new vs Grok's flat "no MCP mutex"):** a *separate* `Arc<Mutex<Connection>>` DOES exist in MCP — but it is the governance pre-write hook-consultation conn (`mcp/mod.rs:3240-3250`), NOT the dispatch path, so the audit invariant holds. `access_count` is a silent live fitness proxy on the recall hot path (`storage/mod.rs:1459-1490`); per-epoch utility recompute inline would regress p95 — an external runner needs zero new hot-path instrumentation.

**Lens 9 — Federation** · B · 88%
Strong, properly-layered attested-coordination transport: **FED-RQ-01 checkpoints federated on `SyncPushBody.checkpoints` and applied FAIL-CLOSED on BOTH backends** (sqlite `federation_receive.rs:1583-1641`; postgres SAL `federation_signing_check.rs:680-737`; both via `authorize_remote_checkpoint_resolution`, forged rejected unconditionally). **Zero epoch primitive**; epoch-manifest federation (FED-RQ-02+) absent. **Killer objection:** an epoch boundary is more than a single approval gate; nothing maps a frozen-within-epoch manifest to `condition_type`/W-of-N today. Suggests a `ConditionType::EpochAdvance` checkpoint condition + flipping any utility/ranking record to authority-grade (require write-sig). Authority lane (`require_transition_sig` default true) vs data lane (`require_write_sig` default false) is the right shape.

**Lens 10 — Alternatives Analyst** · B+ · 82%
Model is coherent but its load-bearing rungs are unbuilt. **Decisive finding:** quorum is **necessary but NOT sufficient** — it decorrelates in *space*, epoch-freeze decorrelates in *time*; you need both, and **the substrate already owns the freeze primitive (attested Checkpoint) it has not wired to the reflection lane**. **Killer objection (key Opus divergence):** `epoch_manifest.json` is a NEW invention that **duplicates the attested-checkpoint** (`checkpoint.rs:106-128`, Ed25519 resolution) — proposing a parallel JSON manifest instead of binding the epoch to a checkpoint row is unreconciled architecture. Full alternatives ranking below.

**Lens 11 — Sibling Repo / Contract** · C+ · 88%
Contract well-designed, un-implemented: schema encodes the load-bearing `utility.frozen_within_epoch=true` but is **git-untracked, zero `src/` consumer, no `EpochManifest`/`SignableEpochManifest`/verifier**. **Killer objection:** the schema promises a signature block but nothing in `src/` can verify it → unenforceable by the consumer it names. Gaps RQ-A (track schema) … RQ-F (JSON-schema validation step). Touchpoints: `epoch_manifest.schema.json:8-16,64,72-76,154-166`; `sign.rs:319,358,397` (the precedent a SignableEpochManifest would mirror).

**Lens 12 — Mobile/IoT Tiering** · B · 88%
Tier A/B/C **validated**: `from_memory_budget(<256)` → Keyword (`config.rs:269-279`), keyword `llm_model:None` (`config.rs:239`); reflect/atomise/consolidate DEFER to hub. **But moonshot §2.1 "kilobytes of RAM" is REFUTED** — real floor ≈31 MB binary, ≈18–25 MB idle RSS (`mobile-iot-deployment.md:319-327`), a ~1000× overclaim. RQGM is categorically a Tier B/C concern.

**Lens 13 — Governance / PE-5 / RuleEngine** · B− · 88%
`RuleEngine::evaluate` is read-only first-refusal/escalation-wins; `Decision::Escalate` fails closed; all production mutation is operator-CLI + Ed25519. **But NOT yet safe for an external L3 runner:** **no `policy_version`/ruleset-digest concept anywhere**, and **`set_enabled(false)` / raw `UPDATE enabled=0` silently neuters a refuse rule with no signature AND no audit** (the load filter `WHERE enabled=1` excludes it; `set_enabled` emits no event). The signature commits to `enabled` (blocks OFF→ON) but **not ON→OFF removal**. P0 integrity rules before any L3 runner. Touchpoints: `agent_action.rs:782,796-803,286,296,1461`; `rules_store.rs:62,205,540,593,611`; `cli/rules.rs:340-378`; `policy_version` = no match.

**Lens 14 — V-4 Attestation** · B today / A− with epoch · 93%
V-4 chain is real and production-grade (`prev_hash` + `UNIQUE sequence`, atomic IMMEDIATE tx, fail-closed `verify_chain`/`verify_audit_trail`). **RQ-10 surface absent:** no `epoch.manifest_applied` event type (15 EVENT_* consts, none for epoch, `signed_events.rs:144-228`); no `SignableEpochManifest` (`sign.rs` has 6 Signable* structs, none epoch). `record_recall` is OFF-chain best-effort (`observations/mod.rs:73-77` INSERT OR IGNORE). **Killer objection:** an "epoch applied" claim with no V-4 row is unfalsifiable. **Low-effort fix:** mirror `rules_store::remove_signed` (~40 LOC) + one event const + one Signable struct.

### Wave 3

**Lens 15 — KG / AGE / memory_links** · A (F if RQGM in KG) · 93%
KG is unambiguously a provenance/audit mirror, not a search host: `memory_links` (relational) is source of truth, AGE is a projection, `kg_projection_outbox` is a transactional-outbox **perf** queue with attempt/quarantine ceiling — not an RQGM work queue. **Killer objection:** an evolutionary search MUTATES its substrate every epoch; every KG write here is deterministic provenance or an idempotent existence-rechecked MERGE — no fitness, no population, no selection. A bounded read-only `reflects_on`-subgraph decorrelation audit is a *sibling* enhancement, never wiring genetics into `find_paths`. Touchpoints: `postgres.rs:7326-7335,7446-7565,7476-7496,6688-6724`; `kg/cycle_check.rs:50-90`.

**Lens 16 — Hooks PE-1 / Webhooks / PreReflect** · B design / D wiring · 93%
Hooks/webhooks are L1 operator-egress, categorically NOT an L3 epoch-manifest substitute (HMAC-SHA256 webhook = symmetric, forgeable, no non-repudiation, no epoch binding; closed 7-slug `WEBHOOK_EVENT_TYPES`, no epoch slug). **Two wiring-debt findings:** (1) **`PreReflect` is NEVER fired** on any path (only PostReflect auto-export/persona); the `reflect.rs:111` docstring *falsely* claims it fires "today"; contrast `PreSignalSend` which IS wired (`mcp/mod.rs:1454`). (2) **`enforce_required_event_presence` has ZERO production callers** (test-module only `enforce.rs:260-356`) yet `doctor --hooks` prints "WILL DENY" → procurement theater. Touchpoints: `subscriptions.rs:102-110,8,17,942-946`; `hooks/enforce.rs:126,188-201,260-356`; `mcp/tools/reflect.rs:477-506`.

**Lens 17 — Encryption / Visibility / #1720** · B− · 88%
Genuine per-row CONTENT isolation (`is_visible_to_caller` + `sync_since` post-filter drop other-owner `scope=private` rows before serialization; `AI_MEMORY_AGENT_ID` unset → trust-all single-tenant). **But the two surfaces a fleet RQGM loop traverses are NOT closed:** federation is not E2E (decrypt → transient plaintext → re-seal, #1809), and **cross-node UTILITY comparison (recall rates, rankings, signed-but-plaintext signals) is a behavioral side-channel** that leaks tenant behavior even when content stays private. **Killer objection:** `is_visible_to_caller` guards CONTENT; RQGM evolves on UTILITY — the isolation stack guards the wrong axis for the loop, and is bypassable via `AI_MEMORY_FED_SYNC_TRUST_PEER=1`. Touchpoints: `visibility.rs:46-78`; `identity/mod.rs:276-288`; `federation_sync_since.rs:244,297,175-178`; `encryption/mod.rs:11-16`.

**Lens 18 — Observations Ledger / Shadow #1706** · B− · 88%
Ledger is identity-stamped, **full consume-parity across all three surfaces AND both backends** (`sqlite.rs:869` + `postgres.rs:14164,14176` twins) — **explicitly NOT MCP-sqlite-only (refutes Grok F-53)**. But it is **write-only**: reranker reads neither `consumed` nor observations; **#1706 shadow sweep does NOT exist in `src/`** (0 refs, contract-only); #1707 correctly deferred. **Killer objection:** you cannot call the ledger the "RQGM measurement layer" when no code aggregates `consumed` into a rate — it has a feed but no meter. `access_count` is the real live-proxy Goodhart exposure (`storage/mod.rs:3688,4244,10269`). Federated utility needs AGGREGATED signed attestations, not raw rates.

**Lens 19 — NHI Identity / D3-012 Family Attestation** · D+ · 93%
The substrate **cannot verify decorrelated cognitive families**: `SignableWrite` (6 fields, `sign.rs:319-340`) carries NO model_family; Ed25519 attests the AGENT KEY only; `model_family` exists exclusively as a CLAIMED free-string metadata key read by a non-enforcing probe. **Family-verify readiness ≈5%.** Substrate is HONEST about it (CLAIMED-not-attested caveat; enforce INERT). **Killer objection:** `producer_signal` falls back model_family→agent_id→source, so one Opus under two agent_ids reads as two producers — distinctness trivially forgeable. Loader-digest TOFU is necessary-not-sufficient: it attests WHICH weights ran, not training-overlap/RLHF-distance — a fine-tune of family X loads under a fresh digest yet stays cognitively correlated (live §6 gap). Touchpoints: `sign.rs:319-383`; `attest.rs:165-180`; `verify.rs:159-167`; `decorrelation_probe.rs:55,68-74,99-117,272-279`.

**Lens 20 — MCP/HTTP/CLI Parity / #965** · B · 88%
**#965 confirmed exactly** (MCP `&Connection`, HTTP `Arc<Mutex<Connection>>`). L1 reflect WIRE primitive ships with true three-surface + SAL parity; **L2 EPOCH host is blocked by the curator `run_once`(sqlite) ⊋ `store_backed_reflection_sweep`(SAL) bifurcation** — the only postgres-reachable arm is a strict subset, so "L2 on postgres" is structurally impossible without the unified daemon (RQ-PARITY-01). **Epoch-as-MCP-tools REFUTED** (sqlite-only #1675 + puts L2 law on L1 surface). Touchpoints: `mcp/mod.rs:1147,4006-4061`; `transport.rs:22`; `cli/curator.rs:188-206,201-203`; `daemon_runtime.rs:825,860` (`--store-url` absent on `mcp`).

**Lens 21 — Moonshot Integrator** · composite A− (→A post-D3-012+RQ-10; C− internal) · 84%
Principles at an external L3 boundary STRENGTHEN §0; internal RQGM FALSIFIES it (verifier↔player collapse). **Killer objection:** the anchor says "verifies rather than trusts" — an internal Agent-as-Judge is the substrate trusting its own trained grader; you cannot be verifier and player at one layer. Per-property grades + "epic moonshot value" paragraph below.

**Per-property grades (Lens 21, hybrid path / internal-RQGM downgrade):**

| Property | Hybrid path | Internal-RQGM downgrade |
|----------|-------------|--------------------------|
| §2.1 endpoint-resident | **A** | C (optimizer won't fit small endpoints) |
| §2.2 coherent | **A−** | B (co-evolution churn) |
| §2.3 stoppable | **A** | **D** (sharpest falsification — can't cleanly stop a self-improving loop) |
| §2.4 improvable | **A** (where Red Queen adds most) | A-but-at-cost-of-all-else |
| §2.5 attested | **A** | C (self-referential self-signing) |
| §2.6 bias-displaced | **C+ now → A− (L3 path)** | **F-direction** (re-correlates producer↔judge) |
| §2.7 LLM-agnostic | **A** | B (couples optimizer to one family) |

---

## Cross-cutting findings catalog (F-IDs)

### A. Placement & architecture
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-01 | Full RQGM MUST NOT ship in `src/` (0 production hits today) | 21/21 | **CUT** |
| F-02 | L3 search EXTERNAL hard line (`ai-memory-rqgm` sibling) | 21/21 | **MUST** |
| F-03 | HYBRID = signed-manifest **contract**, not a flag merged into curator | 1,2,10,16,20 | **MUST** |
| F-04 | Three curator stacks if RQGM embedded (rusqlite / SAL / RQGM) | 2,4,20 | **CUT** |
| F-05 | `run_once`(sqlite) ⊋ `store_backed_reflection_sweep`(SAL) → no postgres L2 epoch parity | 2,4,12,20 | **P0** (RQ-PARITY-01) |
| F-06 | **Epoch boundary should bind to the existing attested Checkpoint, not a net-new JSON manifest** (or reconcile) | 9,10 | **DESIGN-FORK (Opus)** |
| F-07 | MCP stdio sqlite-only (#1675); postgres fleets use HTTP; epoch-as-MCP-tools refuted | 20 | **Document** |

### B. §2.6 bias-displacement & decorrelation
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-10 | `run_decorrelation_probe` exactly **1 production caller** → `--reflect` only, NOT in `run_once`/`store_backed_sweep` | 3,4,15,16 | **P0 RQ-11** |
| F-11 | `enforce` INERT at v0.8.0 (`decorrelation_probe.rs:272-281`) — correct posture | 3,5,7,13,17,19 | **Correct** |
| F-12 | D3-012 attested `model_family` blocks D3-021 enforce | 1,3,5,13,19,21 | **P0** |
| F-13 | Single `build_curator_llm`/`OllamaClient` = stationary judge monoculture | 4,16,19 | **RQ-12 manifest panel** |
| F-14 | N≥3 attested quorum unbuilt (#1719/#1171); `producer_signal` ranks CLAIMED strings | 1,5,6,10,19,21 | **P0** |
| F-15 | Quorum alone insufficient — needs epoch-freeze; **freeze not mechanized in code** | 6,10 | **P0 (new emphasis)** |

### C. D1 / hooks / MCP gaps
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-20 | MCP `handle_reflect` → `ReflectHooks::empty()`; HookVeto unreachable | 5,16,20 | **P0 D1-001** |
| F-21 | `PreReflect` never fired on any path; `reflect.rs:111` docstring falsely claims it fires | 5,16 | **P0 + docs defect (D-OPUS-2)** |
| F-22 | PE-1 `enforce_required_event_presence` tests-only while `doctor --hooks` prints "WILL DENY" | 16 | **P1 procurement-theater (D-OPUS-3)** |

### D. Epoch manifest & V-4 attestation
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-30 | `epoch_manifest.schema.json` exists with `frozen_within_epoch=true` but is **git-untracked** | 7,11 | **Correct to "untracked", not "DONE"** |
| F-31 | No `src/` manifest consumer / `EpochManifest` / verifier | 2,7,11,13,14,20 | **P0 RQ-10..13** |
| F-32 | `epoch.manifest_applied` V-4 event type missing | 14 | **P0 RQ-10** |
| F-33 | `SignableEpochManifest` missing in `sign.rs` | 11,14 | **P0** |
| F-34 | V-4 writer template available (`rules_store::remove_signed`, ~40 LOC) | 14 | **Low-effort** |

### E. Governance integrity (new)
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-40 | **Silent-disable:** `set_enabled(false)`/raw UPDATE neuters a refuse rule, no sig + no audit | 13 | **P0 defect (D-OPUS-1)** |
| F-41 | No `policy_version`/ruleset-digest concept anywhere | 11,13 | **P0 before any L3 runner** |
| F-42 | Governance auto-mutation without signed packs would collapse separation-of-powers | 3,13,21 | **CUT** |

### F. Federation & multi-tenant
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-50 | FED-RQ-01 checkpoints federated + fail-closed on BOTH backends | 9 | **Done** |
| F-51 | Epoch-manifest federation (FED-RQ-02+) absent | 9,17 | **P1** |
| F-52 | Cross-node utility comparison = behavioral side-channel (visibility-exempt) | 9,17,18 | **P1** |
| F-53 | Federation not E2E (decrypt→plaintext→reseal, #1809) | 17 | **v0.9** |

### G. Ledger / measurement
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-60 | Ledger write-only; **#1706 shadow sweep not in `src/`** | 7,18 | **P1** |
| F-61 | #1707 live wire correctly DEFERRED | 18 | **Hold** |
| F-62 | **Consume-parity FULL (both backends) — refutes Grok F-53 "MCP-sqlite-only"** | 18 | **Corrected** |
| F-63 | `access_count` silent live fitness proxy on hot path (Goodhart) | 8,18 | **Benchmark target** |

### H. Identity / procurement / IoT
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-70 | Ed25519 attests `agent_id`, not `model_family`; SignableWrite 6 fields | 6,7,14,19 | **P0 D3-012** |
| F-71 | **Family-verify readiness ≈5%** (below Grok's 15–25%) | 19 | **Honest metric (Opus harsher)** |
| F-72 | Substrate optimization-readiness ≈15% | 7 | **Honest metric** |
| F-73 | Banned: "implements RQGM" / "decorrelation enforce shipped" / "attests model family" | 7,21 | **Banned** |
| F-74 | **Moonshot §2.1 "kilobytes of RAM" overclaim (~1000×)** | 12 | **Docs defect (D-OPUS-5)** |

### I. ASI infinite-horizon
| ID | Finding | Lenses | Severity |
|----|---------|--------|----------|
| F-80 | Substrate ATTESTS, cannot EVALUATE ASI reasoning | 6,18,21 | **Permanent** |
| F-81 | RQGM utility gradient may not survive ASI (L3 measurability cliff) — but cliff may be *softer* for bounded signals | 6 | **Externalize (with dissent)** |
| F-82 | Principles (judge-drift, epoch-freeze, decorrelated quorum) survive ASI | 6,10,21 | **Load-bearing** |
| F-83 | KG = provenance audit, NOT evolutionary host (F if RQGM in KG) | 15 | **MUST** |

---

## Q3 — merged mechanism stack

```
L3 — ai-memory-rqgm / operator runner (EXTERNAL — HARD)
     utility evolution · evaluator-population breeding · adversarial bias search
     READS: observation ledger, shadow metrics, decorrelation/dominance stats (read-only, aggregate)
     WRITES: ONE signed epoch artifact (Ed25519) only
            │ operator/quorum signature
L2 — ai-memory curator (IN REPO, separate process)
     verify signed artifact → V-4 epoch.manifest_applied (RQ-10) → stamp metadata.epoch_id
     decorrelation EVERY cycle (hoist probe out of --reflect, RQ-11) · panel slots from artifact
     [Opus: bind the epoch boundary to an attested Checkpoint row, reconcile with the JSON schema]
            │ SAL / hooks
L1 — ai-memory substrate (MCP / HTTP / CLI)
     persist · gate · bounded reflect (depth cap, pre-tx) · N≥3 ATTESTED quorum refuse
     record_recall ledger · static operator-signed RuleEngine · V-4 chain · federation checkpoints · visibility
```

**CUT (21/21):** population genetics in `src/`; `enforce` on CLAIMED metadata; governance auto-mutation; webhook-as-manifest; internal RQGM; epoch panel as MCP tools; cross-node raw utility leaderboards without redaction.

---

## Q4 — development pathway

### Sprint 0 — Honesty & contract hygiene (immediate, docs/process)
- Git-track `epoch_manifest.schema.json` **after** resolving the checkpoint-vs-manifest fork (F-06).
- `honest-limitations.md` Red Queen addendum (shadow≠live, CLAIMED≠ATTESTED, no AGI safety, family-verify ≈5%).
- Fix the `reflect.rs:111` docstring (D-OPUS-2) and the moonshot §2.1 RAM overclaim (D-OPUS-5).

### v0.9 P0 (substrate spine — blocking tag)
| ID | Work | Lens gate | GitHub |
|----|------|-----------|--------|
| D3-010/011/012 | Attested `model_family` (extend `SignableWrite` + new AttestLevel) | 19,6,14 | #1719 |
| D3-002 | #1171 heterogeneous panel synthesis | 1,10 | #1171 |
| D1-001/004 | MCP `PreReflect` veto wired (close `ReflectHooks::empty()`) | 5,16 | #655 |
| RQ-10 | `SignableEpochManifest` + V-4 `epoch.manifest_applied` (mirror `remove_signed`) | 14 | — |
| RQ-PARITY-01 | Unify curator so SAL/postgres reaches epoch capabilities | 2,4,20 | — |
| **F-40** | **Close governance silent-disable: signed+audited `set_enabled`** | 13 | **D-OPUS-1 (new)** |
| F-41 | `policy_version`/ruleset digest gate before any L3 runner | 13,11 | — |
| RQ-11 | Decorrelation EVERY curator cycle (hoist out of `--reflect`) | 4 | #1764 |
| F-22 | Wire PE-1 `enforce_required_event_presence` into production dispatch | 16 | **D-OPUS-3 (new)** |
| D4-036 | honest-limitations RL addendum | 7 | — |

### v0.9 P1/P2
D3-021 enforce (after 012) · D4-015 shadow #1706 · #1705 already FULL parity (downgrade from Grok P0) · FED-RQ-02+ federated epoch.

### v0.9.1+ (SHOULD, not blocking v0.9 tag)
`ai-memory-rqgm` reference runner · privacy-preserving aggregate utility attestation · graph-augmented `reflects_on` decorrelation subgraph audit · #1707 live wire (only after #1706 proves signal).

---

## Alternatives ranked (Lens 10, adopted)

| # | Pathway | Fit | Note |
|---|---------|-----|------|
| 1 | **N≥3 attested quorum + epoch-freeze + V-4 manifest apply** | **BEST CEILING** | Fully unbuilt; gates on #1719 |
| 2 | RQGM principles + hybrid L1/L2/L3 contract | **BEST PRAGMATIC** | Partially shipped; correct category |
| 3 | Empirical decorrelation advisory only | **SHIPPED FLOOR** | Honest but CLAIMED-not-ATTESTED |
| 4 | Quorum ALONE (no epoch-freeze) | Necessary-not-sufficient | Defeated by temporal judge-drift + unauditable |
| 5 | Human-Escalate-only governance | Floor, not ceiling | Doesn't scale to ASI cognitive distance |
| 6 | Static Gödel Machine (fixed verifier) | Goes stale | This IS the RQGM failure mode |
| 7 | hooks.toml as L3 substitute | Category error / theater | HMAC webhook ≠ Ed25519 manifest |
| 8 | Full internal RQGM in `src/` | Wrong category | Falsifies the §0 anchor |

---

## Claims discipline

**Allowed:** "RQGM-principles-aligned substrate (~15% optimization-readiness)" · "family-verify readiness ~5%" · "advisory, visibility-only decorrelation probe" · "FED-RQ-01 checkpoint federation shipped (both backends)" · "signed epoch-boundary contract **spec** (untracked, no consumer yet)".

**Banned:** "implements RQGM" · "co-evolving evaluators shipped" · "decorrelation enforce shipped" (INERT) · "attests model family / cognition diversity" (CLAIMED) · "epoch closure shipped" (no V-4 writer; schema untracked) · "self-improving agent framework" · "RQ-01 contract shipped" (it is untracked).

---

## Epic moonshot value at ASI (Lens 21 synthesis)

**Without external L3 RQGM:** ai-memory is a cryptographically-attested, stoppable, endpoint-resident persistence-and-governance boundary whose §2.6 bias-displacement is held by **operator discipline** (config names producer/reflector; the substrate verifies cryptographic *identity* but not cognitive-*family* decorrelation — the named single-largest gap). Epic because **orthogonal to capability**: it does not compete with ASI, it bounds how ASI may commit self into durable reality.

**With Red Queen principles at an external L3:** the substrate becomes the thing the moonshot names but cannot yet build — the layer at which a less-capable observer can **structurally guarantee** that a more-capable cognition's account of itself was reflected by a quorum of *attestably-decorrelated* graders, frozen within an epoch, BEFORE it entered the entity's accumulating self — separation-of-powers that holds when behavioral alignment fails, achieved **without depending on frontier-lab cooperation**. The substrate stays the skeptical verifier; the Red Queen optimizes on the far side of an attested wire. Inline that algorithm into L1 and you delete exactly the separation that gives the substrate its civilizational value.

---

## Compare / contrast vs the prior Grok 21-agent doc

This Opus run **broadly agrees** with [`RED-QUEEN-21-AGENT-VOTE-vs-ai-memory.md`](RED-QUEEN-21-AGENT-VOTE-vs-ai-memory.md) on the headline (principles yes, RQGM external, quorum+epoch primary, attestation-before-enforce, shadow-before-live). The differences below are where Opus **diverges, corrects, or sharpens** — each with re-verified evidence.

| # | Topic | Grok 21-agent doc | **Opus finding** | Evidence |
|---|-------|-------------------|------------------|----------|
| **D1** | epoch_manifest contract | "RQ-01 schema **SHIPPED / DONE**" (F-30) | **git-UNTRACKED, no `src/` consumer** — "spec", not "shipped" | `git ls-files docs/contracts/` empty |
| **D2** | Epoch artifact design | Net-new `epoch_manifest.json` is the contract | **It duplicates the attested Checkpoint primitive** — bind epoch to a Checkpoint row, or reconcile (DESIGN-FORK F-06) | `checkpoint.rs:106-128` |
| **D3** | Consume-parity | "#1705 consume parity **MCP-sqlite-only**, P0" (F-53) | **FULL parity, both backends** — not sqlite-only | `sqlite.rs:869`; `postgres.rs:14164,14176` |
| **D4** | Family-verify readiness | "~15–25%" (F-71) | **~5%** — `producer_signal` fallback makes distinctness trivially forgeable | `sign.rs:319-340`; `decorrelation_probe.rs:99-117` |
| **D5** | #965 MCP mutex | "no MCP mutex" (flat) | True for **dispatch**; a *separate* `Arc<Mutex<Connection>>` exists for governance hook consultation | `mcp/mod.rs:3240-3250` |
| **D6** | Governance integrity | "RuleEngine read-only; MCP mutation disabled" | **NEW defect:** `set_enabled(false)`/raw UPDATE silently neuters a refuse rule, no sig + no audit; no `policy_version` | `rules_store.rs:593` |
| **D7** | PE-1 / PreReflect | "PE-1 tests-only (P1)"; "PreReflect not wired (P0)" | Sharpened: **`doctor --hooks` prints "WILL DENY" while the guard has zero prod callers**; **`reflect.rs:111` docstring falsely claims PreReflect fires "today"** | `enforce.rs:260-356`; `reflect.rs:105-112` |
| **D8** | IoT §2.1 | "B grade capped (~18–25 MB RSS)" | **Explicit overclaim:** "kilobytes of RAM" is ~1000× off → docs defect | `moonshot-synthesis.md:33`; `mobile-iot-deployment.md:319-327` |
| **D9** | ASI measurability cliff | "Utility gradient may not survive ASI — externalize" (firm) | **Dissent retained:** cliff may be *softer* for bounded signals (invariant-violations, refusal-rate, contradiction-density); and **epoch-freeze is not mechanized in code** at all | Lens 6 dissent |

**No contradiction** on the load-bearing conclusion: both runs reach 21/21 "principles + epoch discipline, RQGM external, quorum+epoch primary". Opus is **more conservative on what is shipped** (untracked schema, ~5% family-verify) and surfaces **two new governance/hooks defects** Grok's run did not catch.

---

## Candidate defects (per prime directive — flagged for operator authorization to file)

| ID | Defect | Evidence | Proposed fix |
|----|--------|----------|--------------|
| D-OPUS-1 | Governance silent-disable (no sig/audit on rule disable) | `rules_store.rs:593` | Signed+audited `set_enabled` + ruleset digest; ~30–50 LOC |
| D-OPUS-2 | `reflect.rs:111` docstring falsely claims PreReflect fires "today" | `storage/reflect.rs:105-112` vs `mcp/tools/reflect.rs:496` | Wire PreReflect (D1-001) or correct docstring |
| D-OPUS-3 | PE-1 guard tests-only while `doctor` asserts "WILL DENY" | `hooks/enforce.rs:126,260-356`; `cli/doctor.rs:387-389` | Wire guard into dispatch; ~20–40 LOC |
| D-OPUS-4 | `epoch_manifest.schema.json` untracked | `git ls-files docs/contracts/` | `git add` after F-06 reconciliation |
| D-OPUS-5 | Moonshot §2.1 "kilobytes of RAM" overclaim | `moonshot-synthesis.md:33` | Re-word to "tens-of-MB endpoints"; MCUs hold L1 via gateway |

> Per the sole-authority repo policy, these are surfaced to the operator with proposed fixes rather than auto-filed. They are first-party findings of this assessment, not deferrals.

---

## One-sentence outcome

> **21/21 (Opus):** Adopt Red Queen **principles** via **§2.6 N≥3 *attested* quorum + epoch-freeze + V-4 `epoch.manifest_applied` apply + a unified curator L2**, keep the RQGM **search EXTERNAL** in `ai-memory-rqgm`, **bind a content-signed epoch manifest TO an `EpochAdvance` Checkpoint** (complementary — the manifest signs the panel/utility/policy payload, the Checkpoint federates and attests the boundary crossing; not either/or), and close **D3-012 family attestation**, **D1-001 MCP PreReflect**, **RQ-10 V-4 writer**, and the **governance silent-disable hole** as v0.9 P0 — preserving the endpoint-substrate moonshot value through AGI→ASI without scope-creep into agent-framework RSI.

---

**AI involvement:** 21 isolated subagent structural probes across 3 sequential waves of ≤7 (Claude Code 7-concurrent cap honored) + orchestrator synthesis, authored by **Claude Opus 4.8 (1M context)**, CodeGraph CLI as L1 evidence, against `release/v0.8.0` @ `ead3da0c`. Operator directive 2026-06-28 (provenance: Nick Jensen). Crossroads cite: `5-agent vote (4d3ea1c5)` pattern scaled to 21 lenses.
