# DecentMem mapping (Hao et al. 2026)

> **Document classification:** Public-facing strategic supplement.
>
> **Date:** 2026-06-15.
>
> **Status:** Reference material. Not a constraint. The moonshot synthesis ([`docs/strategy/moonshot-synthesis.md`](moonshot-synthesis.md)) and the seven §2 properties in [`ROADMAP.md`](../../ROADMAP.md) remain the authoritative anchors. Where DecentMem and the moonshot disagree, the moonshot wins.
>
> **Purpose.** Map ai-memory's substrate primitives to the decentralized-memory vocabulary of *Self-Evolving Multi-Agent Systems via Decentralized Memory* (Hao, Long, Zhao, arXiv:2605.22721) for readers familiar with the multi-agent-systems literature. This document does not derive the substrate's properties from DecentMem — those derive from the moonshot. DecentMem serves as a retrospective organizing lens.

---

## 1. Executive position

ai-memory already implements the structural primitives DecentMem's per-agent decentralized memory requires — store, retrieve, consolidate, score, expire, per-agent isolation — and operates one layer *below* DecentMem's contribution. DecentMem is a multi-agent-systems *orchestration strategy* (per-agent dual pools, online utility reweighting); ai-memory is the *substrate* such an orchestrator runs on. DecentMem's value here is academic legibility for the MAS-memory literature, not architectural authority. The full assessment is recorded in issue [#1704](https://github.com/alphaonedev/ai-memory-mcp/issues/1704).

---

## 2. DecentMem in one paragraph

DecentMem gives each agent in a self-evolving multi-agent system its own **dual-pool memory**: an **exploitation pool** of consolidated past trajectories and an **exploration pool** of LLM-generated candidate memories for unseen contexts, reweighted online by an LLM-as-a-judge contextual bandit (claimed `O(log T)` regret, global reachability). It is **decentralized**: each agent keeps its own memory with no central coordination, argued to preserve agent diversity (the paper's thesis is that a *centralized shared* memory homogenizes a collective and collapses its diversity) and to reduce coordination/privacy cost. DecentMem does **not** address attestation, endpoint residency, separation-of-powers reflection, or cryptographic non-repudiation; its evaluation is end-to-end MAS task accuracy inside AutoGen / DyLAN / AgentNet, a metric that is only measurable against a full agent collective, not against a memory substrate.

---

## 3. Side-by-side mapping

Descriptive only. Code anchors are current as of v0.7.1.

### 3.1 Dual-pool memory

| DecentMem primitive | DecentMem definition | ai-memory realization | Code anchors |
|---|---|---|---|
| **Exploitation pool** | Consolidated past trajectories the agent reuses | `MemoryKind::Reflection` + the Observation→Reflection→Skill curator pipeline (consolidates co-recalled observations into typed reflections with `reflects_on` provenance). Note: ai-memory consolidates *co-recalled*, not *task-succeeded*, trajectories — the success signal is an orchestration concern. | `src/curator/reflection_pass.rs`, `src/storage/reflect.rs`, `memory_consolidate`, `MemoryKind` enum |
| **Exploration pool** | LLM-generated speculative candidates for unseen contexts | **Intentionally absent.** Every ai-memory write originates from a real observation/ingest/reflection over real data; there is no proactive speculative-candidate generator (`src/synthesis/mod.rs` is reactive dedup only). Generating memories the agent never observed cuts against §2.5 (attestation — a speculative memory has no attestable provenance) and §4 (cognitive artifacts of *engagement*, not bare propositions). This is agent-orchestration behavior, scope-out per §16. | (no production path; `src/synthesis/mod.rs:141`) |
| **Per-agent isolation** | Each agent's pool is private; no shared corpus | `MemoryScope::Private` (default-deny) + `is_visible_to_caller` + per-agent `metadata.agent_id`. An operator can deploy ai-memory in a fully per-agent-isolated posture today. | `src/models/namespace.rs:124`, `src/visibility.rs:46` |

### 3.2 Online reweighting / feedback

| DecentMem primitive | DecentMem definition | ai-memory realization | Code anchors |
|---|---|---|---|
| **Utility scoring** | LLM-judge contextual bandit reweights memories by downstream task success | Static substrate primitives an orchestrator would compose: 6-factor recall blend, Form-5 confidence calibration, cross-encoder reranker with score floor. None is an *online* success-driven reweighter — the bandit control loop is agent-layer. | `src/storage/mod.rs:2949-2954` (blend), `src/confidence/`, `src/reranker.rs` |
| **Stage-wise feedback** | Per-stage success signal feeds the reweighter | The `recall_observations` ledger records the *input half* of this loop: `record_recall` logs each candidate; `mark_consumed` flips `consumed` + `consumed_by_memory_id` when a recalled memory is cited downstream. **The loop is currently open** — the consumed signal is recorded telemetry; no production scoring path reads it back (the only reader is the `memory_recall_observations` inspection tool). | `src/observations/mod.rs:65,108,162` |

> **Scope firewall.** Closing the `recall_observations` loop — feeding the consumed signal back into recall scoring — is tracked as a **shadow-first** v0.9 enhancement ([#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706)), gated on a v0.8.0 ledger backend-parity + integrity prerequisite ([#1705](https://github.com/alphaonedev/ai-memory-mcp/issues/1705)); the live ranking change is a conditional follow-up ([#1707](https://github.com/alphaonedev/ai-memory-mcp/issues/1707)). This mapping describes current state only and proposes no design.

### 3.3 Decentralized coordination

| DecentMem mechanism | ai-memory realization | Code anchors / ROADMAP |
|---|---|---|
| **No central coordination** | v0.7.0 baseline is **shared-nothing per-agent SQLite-1:1 + CRDT P2P federation** (newer-wins merge with deterministic id-tiebreak) — not the centralized shared repository DecentMem argues against | `src/storage/mod.rs:7309` (`insert_if_newer`), ROADMAP §11.4 Pillar-4 (`ROADMAP.md:608-610`) |
| **Diversity preservation** | The §11.4 v0.8 *module* model introduces an opt-in shared consolidated Postgres+AGE corpus, and the ROADMAP independently names the diversity-collapse risk DecentMem describes | ROADMAP §5 (`ROADMAP.md:183`), §11.4 Pillar-4 |

---

## 4. What ai-memory adds beyond DecentMem

| ai-memory property | DecentMem coverage | Substrate's structural answer |
|---|---|---|
| **§2.1 Endpoint-resident** | None — DecentMem is agnostic to deployment topology | Rust core + SQLite default + LLVM-portable; mobile cross-compile gate (#1068) |
| **§2.5 Attested with cryptographic non-repudiation** | None — DecentMem does not address audit or attestation | V-4 `signed_events` cross-row hash chain, per-agent Ed25519 attestation |
| **§2.3 Stoppable without silent corruption** | None | Typed refusals, `permissions.mode = enforce` fail-CLOSED, attested checkpoints |
| **§2.6 Bias-displaced through separation-of-powers** | Partial — DecentMem's decentralization *preserves* diversity but has no reflection-boundary primitive | LLM-agnostic reflection boundary; §5 decorrelation enforcement (committed v0.8/v0.9) |

DecentMem's decentralization thesis and ai-memory's §2.6/§5 decorrelation commitment are **the same concern from different angles** (a shared corpus homogenizes the agents drawing from it). DecentMem is a second independent corroboration of that axis — after the DeepMind paper (#1698) — but it changes no commitment: §5 is already committed.

---

## 5. The DecentMem-named direction ai-memory is closing

**Recall-usage feedback.** DecentMem's stage-wise reweighting (favor memories that contributed to downstream success) is the *concept* of feedback-driven recall-utility weighting. ai-memory already records the input signal (`recall_observations.consumed`) and is closing the loop **shadow-first** (#1706), correctly de-scoped from DecentMem's online per-stage LLM-judge to an offline calibration sweep that respects the substrate's ~35 ms recall p95 budget. This is a *direction in progress*, not a closed gap.

---

## 6. Honest limits of the mapping

1. **DecentMem operates at the agent-orchestration layer; ai-memory is the substrate below it.** Two of DecentMem's four mechanisms (the exploration pool, the online bandit reweighting) are agent-runtime behaviors ai-memory deliberately does not implement (§4 / §16 scope test). The mapping describes structural equivalences for the primitives an orchestrator would compose, not feature parity.

2. **DecentMem's anti-centralization critique largely misses ai-memory's architecture.** ai-memory's baseline is shared-nothing federation, not a central repository — so the paper's headline empirical win is against an architecture ai-memory does not use. The diversity-collapse concern lands only on the opt-in v0.8 shared-corpus module, which §5 already addresses.

3. **The headline numbers are not substrate-comparable.** DecentMem reports MAS task-accuracy (and the abstract's "+23.8% / −49%" are single best-cell figures; the body averages are ~8.6% accuracy / ~43% tokens). These measure a full agent collective, not a memory store; they cannot be claimed or refuted by ai-memory's recall-fidelity metrics (LongMemEval, §9.5).

4. **The `O(log T)` regret theory is bandit-framing-specific.** A storage substrate has no arm, round, or reward, so the regret bound does not apply to ai-memory.

---

## 7. Disposition

This document is reference material. It does not commit the substrate to any DecentMem-specific implementation. The seven properties in ROADMAP §2 are the authoritative test. The §3 scope test is controlling. The moonshot synthesis is the North Star.

If a future revision or successor work changes the taxonomy, this document will be revised to track. The substrate's commitments will not change in response to framework drift.

---

## References

Hao, G., Long, Y., & Zhao, Z. (2026). Self-Evolving Multi-Agent Systems via Decentralized Memory. arXiv:2605.22721.

---

*Revision history:*
- *2026-06-15 (initial): created as reference supplement, derived from the 5-agent adversarial assessment (#1704) and the 7-agent execution-design panel. No substrate code changes. No commitments added or modified. No §2 properties changed. No §3 scope-test modifications.*

*End of document.*
