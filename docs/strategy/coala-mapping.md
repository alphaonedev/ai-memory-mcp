# CoALA mapping (Sumers et al. 2024)

> **Document classification:** Public-facing strategic supplement.
>
> **Date:** 2026-05-27.
>
> **Status:** Reference material. Not a constraint. The moonshot synthesis ([`docs/strategy/moonshot-synthesis.md`](moonshot-synthesis.md)) and the seven §2 properties in [`ROADMAP.md`](../../ROADMAP.md) remain the authoritative anchors. Where CoALA and the moonshot disagree, the moonshot wins.
>
> **Purpose.** Map ai-memory's substrate primitives to the Cognitive Architectures for Language Agents framework (Sumers, Yao, Narasimhan, Griffiths, *TMLR* 02/2024, arXiv:2309.02427) for readers familiar with the academic literature on language-agent design. This document does not derive the substrate's properties from CoALA — those derive from the moonshot. CoALA serves as a retrospective organizing lens.

---

## 1. Executive position

ai-memory implements every CoALA primitive (modular memory, structured action space, generalized decision procedure) and extends the framework with six structural-governance properties CoALA does not anticipate. Three CoALA-named open directions ship as load-bearing substrate primitives. CoALA's value here is academic legibility, not architectural authority.

---

## 2. CoALA in one paragraph

CoALA organizes language agents along three dimensions: **modular memory** (working memory + long-term memory split into episodic / semantic / procedural); **structured action space** (internal actions = reasoning, retrieval, learning; external actions = grounding); and a **generalized decision-making procedure** structured as a planning → execution loop. The paper positions the LLM as the core component of the architecture and treats text as the de facto internal representation. Source code is procedural memory; updates to source code are flagged as alignment-risky. CoALA explicitly notes that modifying and deleting memory ("unlearning"), updating retrieval procedures, and learning new learning procedures are understudied in the language-agent literature. CoALA does not address attestation, federation, decorrelated-priors reflection, or endpoint residency.

---

## 3. Side-by-side mapping

### 3.1 Memory modules

| CoALA primitive | CoALA definition | ai-memory realization | Code anchors |
|---|---|---|---|
| **Working memory** | Data structure that persists across LLM calls; the central hub carrying perceptual inputs, active knowledge, agent's active goals between cycles | The typed MCP request lifecycle: `ToolDispatchCtx` + `RuntimeContext` + the hook payload schema. The working-memory primitive is the dispatch envelope that carries `agent_id`, namespace, governance resolution, action class, pending audit row, and intermediate reasoning state between LLM calls. | `src/mcp/mod.rs::ToolDispatchCtx`, `src/runtime_context.rs`, `src/hooks/events.rs` (25 lifecycle events with typed payloads), `resolve_governance_policy` chain walk |
| **Episodic memory** | Stored experience: training I/O pairs, event flows, trajectories | `MemoryKind::Observation` + `memory_transcripts` (session transcripts) + `signed_events` chain (the experience of the agent's own state transitions) + per-reflection `reflects_on` provenance | `MemoryKind` enum, `memory_transcripts`, `signed_events` v34 with V-4 cross-row chain (`prev_hash + sequence`), `memory_replay` for transcript walk |
| **Semantic memory** | Agent's knowledge about world and self; facts; retrievable | Vector index substrate (sqlite-vec + vectorlite + builtin fallback, ROADMAP §23), knowledge graph (`memory_kg_query`), `MemoryKind::Persona` (knowledge about self), `alphaone-dev-skills` sibling for bare propositions | ROADMAP §23 (v0.9), `memory_kg_query`, `memory_persona`, FTS5 + HNSW hybrid (current), Apache AGE Cypher (Postgres) |
| **Procedural memory** | Two forms: implicit (LLM weights) + explicit (agent's code/skills); CoALA flags updates as alignment-risky | (a) **Agent Skills** (`MemoryKind::Skill` + 7 MCP tools: register, list, get, resource, export, `promote_from_reflection`, `compositional_context`) as the explicit code/procedure layer. (b) Routines (v0.8 Pillar 1) as parameterized action templates with frozen-immutability for regulatory hold. The LLM-weights tier is out of substrate scope per §2.7 LLM-agnostic. | L1-5 substrate (5 skill tools) + L2-6 + L2-7 (commits `505c538`, `0966b57`), v0.8 Pillar 1 routines (5 MCP tools planned), `effective_max_reflection_depth` as the structural ceiling on procedural-memory growth |

### 3.2 Action space

| CoALA primitive | CoALA definition | ai-memory realization | Code anchors |
|---|---|---|---|
| **Reasoning** | Read from + write to working memory using LLM; summarize, distill, generate new information | Curator passes (reflection-pass, atomisation pass), `memory_atomise`, `memory_reflect`, persona synthesis. All gated by `pre_reflect` / `pre_store::auto_atomise` hooks; all bounded by `effective_max_reflection_depth`. | `src/atomisation/mod.rs`, `src/storage/reflect.rs`, L2-1 reflection-pass curator (`c3f6e82`), `pre_reflect` / `post_reflect` hooks |
| **Retrieval** | Read from long-term memory into working memory; CoALA flags **adaptive context-specific recall as understudied** | Hierarchy-aware recall, 6-factor recall scoring, recall-atom-preference (WT-1-E), reflection-aware reranker boost (L2-8), `kg_query` multi-hop, `find_paths`, default-on cross-encoder reranker (v0.9) | `memory_recall`, `memory_recall_observations`, `memory_kg_query`, L2-8 reranker boost (`90291c0`), v0.9 fail-loud reranker |
| **Learning** | Write to long-term memory; CoALA flags **modifying/deleting ("unlearning") as understudied** and **procedural-memory updates as alignment-risky** | `memory_promote`, `promote_from_reflection`, compaction pipeline with rollback (v0.8 Pillar 2.5), L2-3 reflection invalidation propagation (notification, not cascade), `supersedes` + `contradicts` link relations, `kg_invalidate` with caller-vs-owner gate (#938), `invalidate_link` with `BEGIN IMMEDIATE` wrap | L2-6 promote (`505c538`), v0.8 Pillar 2.5 compaction (6 stages), L2-3 invalidation propagation (`3f419be`), `contradicts` + `supersedes` in `VALID_RELATIONS`, schema v33 SQL-side CHECK constraint |
| **Grounding (external)** | Physical / dialogue / digital environment interaction | v0.8 Pillar 1: actions/leases/DAG (already in baseline) + signed signals (3 sessions) + attested checkpoints (3 sessions, cutline-protected) + routines (2 sessions). All cryptographically attested. Policy Engine (ROADMAP §22) gates external `AgentAction::Bash`, `FilesystemWrite`, `NetworkRequest`, `ProcessSpawn`, `Custom`. | `memory_action_*` tools, lease + heartbeat, federation-aware quorum claiming, vector clock per `action_id`. v0.8: 5 signal tools + 4 checkpoint tools + 5 routine tools + 2 frontier/next tools. Policy Engine: `governance_rules` table with operator-keypair-signed seed rules, `check_agent_action` wired into `storage::insert` (L1-6 Deliverable E). |

### 3.3 Decision procedure

| CoALA primitive | CoALA definition | ai-memory realization | Code anchors |
|---|---|---|---|
| **Planning (proposal + evaluation + selection)** | Use reasoning + retrieval to propose, evaluate, and select learning/grounding actions | Policy Engine (ROADMAP §22) with typed `Allow` / `Deny` / `Modify` / `AskUser` / `Escalate` decisions. `memory_action_frontier` (ranked unblocked actions) + `memory_action_next` (single highest-priority for calling agent's permissions). Hook decisions are CoALA's "evaluation" phase. | ROADMAP §22 PE-1 through PE-8, `HookDecision` enum, `memory_action_frontier` + `memory_action_next` (v0.8) |
| **Execution** | Execute the selected action; observe outcome; loop | Atomic write semantics across `memory_store`, `memory_reflect`, `memory_atomise` (`BEGIN IMMEDIATE` / `COMMIT` with ROLLBACK on any failure). `post_*` hooks fire only after durable commit. Action state machine (pending → claimed → in_progress → done / failed / abandoned) with lease + heartbeat resilience. | `BEGIN IMMEDIATE` discipline substrate-wide, `post_reflect` / `post_store` notify-class hooks, action state machine, lease sweeper |
| **Impasse / subgoal** | Soar's hierarchical task decomposition for tied or invalid actions | Partial realization via `Decision::Escalate { rule_id, prompt }` (PE-5 severity-based human escalation), `HookDecision::AskUser` with default-on-timeout, `pending_actions` sweeper. **Intentionally not implemented** as a generic subgoal-stack primitive — that is strategic-layer cognition, scope-out per ROADMAP §4. | `src/hooks/decision.rs:108-113`, PE-5, L1-8 Approval-API surface |

---

## 4. What ai-memory adds beyond CoALA

| ai-memory property | CoALA coverage | Substrate's structural answer |
|---|---|---|
| **§2.1 Endpoint-resident** | None — CoALA is agnostic to deployment topology | Rust core + SQLite default + LLVM-portable; mobile cross-compile gate (`#1068`); 5-channel distribution |
| **§2.2 Coherent across sessions and model generations** | Partial — CoALA's episodic memory captures session continuity but does not address model-generation hand-off | AgentKeypair-signed personas (`src/persona/mod.rs:200-229`), idempotent persona versioning, episodic→semantic→procedural pipeline as load-bearing substrate property |
| **§2.3 Stoppable without silent corruption** | None — CoALA does not have a refusal-as-structured-data primitive | `ReflectError::HookVeto` distinct from `ReflectError::DepthExceeded`, `AtomiseError::TierLocked`, `permissions.mode = enforce` fail-CLOSED defaults, `Decision::Escalate`, attested checkpoints with 4 typed condition types |
| **§2.4 Improvable across model generations** | Partial — CoALA acknowledges procedural memory can be updated but flags it as risky and notes no agents do it in practice | Agent Skills (7 MCP tools), `promote_from_reflection`, compaction pipeline with verify+rollback, depth-cap as substrate-enforced ceiling |
| **§2.5 Attested with cryptographic non-repudiation** | None — CoALA does not address audit or attestation | V-4 `signed_events` cross-row hash chain (schema v34), per-agent Ed25519 attestation, `verify-signed-events-chain` operator CLI, model signature verification chain (ROADMAP §11.4.D), V08-PE-8 audit-trail completeness verifier |
| **§2.6 Bias-displaced through architectural separation-of-powers** | None — CoALA does not address bias in reflection | LLM-agnostic reflection boundary at config layer; `Opus producer × Grok reflector` composition; `ReflectionOrigin` peer/signer split; ROADMAP §5 open structural gap held for adjudication |
| **§2.7 LLM-agnostic at every cognitive boundary** | None — CoALA positions LLM as the core component; ai-memory positions LLM as a configurable component | `#1067` provider-agnostic substrate (15+ vendors via OpenAI-compat). §2.7 inverts CoALA's frame: CoALA assumes the LLM is the agent's identity; ai-memory assumes the substrate is the agent's identity and the LLM is replaceable infrastructure |

Four of the seven properties (§2.1, §2.3, §2.5, §2.6) name properties CoALA does not have. One (§2.7) inverts CoALA's core framing. This is not a deficiency of CoALA — the paper organized 2023-era agent literature, not endpoint-resident alignment-by-architecture infrastructure. It is the locus where ai-memory's intellectual contribution sits.

---

## 5. CoALA-named gaps that ai-memory closes

### 5.1 "Adaptive and context-specific recall remains understudied" (CoALA §4.3)

CoALA flags adaptive context-specific recall as a future direction. ai-memory closes it: 6-factor recall scoring with hierarchy-aware namespace inheritance, recall-atom-preference (WT-1-E), reflection-aware reranker boost with depth-graduated weighting (L2-8), and the namespace-scoped governance that determines which atoms surface at recall time. The default-on cross-encoder reranker at v0.9 with fail-loud-on-unavailable closes the remaining gap.

### 5.2 "Modifying and deleting (unlearning) are understudied" (CoALA §4.5)

CoALA names this as understudied. ai-memory has shipped it as a load-bearing primitive: `supersedes` and `contradicts` link relations promoted from v23 trigger to v33 SQL-side CHECK constraint; L2-3 reflection invalidation propagation (commit `3f419be`) writes notification memories to `_invalidations` namespaces when a Reflection→Reflection `supersedes` edge fires — explicit, audited, non-cascading unlearning; `kg_invalidate` with caller-vs-owner gate (#938); compaction pipeline Stage-6 verify+rollback makes unlearning reversible.

### 5.3 "Procedural-memory updates are alignment-risky; no agents implement this safely" (CoALA §4.5)

CoALA acknowledged the problem and noted no agent had solved it. ai-memory's structural answer:

1. **Depth cap.** `effective_max_reflection_depth` (default 3) is a substrate-enforced ceiling. `cap = 0` is a documented kill-switch. Federation cannot launder depth (L2-2 — receivers stamp `reflection_origin` and the local cap applies regardless of source peer's cap).
2. **Hook veto.** `pre_reflect` and `pre_store` hooks refuse procedural-memory writes with typed `Deny { reason, code }` returning `ReflectError::HookVeto`.
3. **Audited refusal.** Every depth-cap refusal writes a `reflection.depth_exceeded` row to `signed_events` under canonical-CBOR.
4. **Operator-signed governance rules.** L1-6 `governance_rules` table; `verify_rule_signature` runs on load; bad signature refuses daemon start. MCP-side mutation is operator-only.
5. **Identical-digest reproducibility.** L2-6 `memory_skill_promote_from_reflection` produces a SKILL.md with `derived_from_reflection_id` frontmatter; promote → export → re-register produces the IDENTICAL SHA-256 digest.
6. **Compaction rollback.** v0.8 Pillar 2.5 Stage-6 verify+rollback means even successful procedural-memory growth is reversible.

---

## 6. Honest limits of the mapping

Three places where the mapping is partial, lossy, or where CoALA's framing diverges from the substrate's:

1. **CoALA positions the LLM as the agent's core.** ai-memory positions the substrate as the agent's identity and the LLM as replaceable infrastructure. These framings are not reconcilable; they reflect different design priors. The mapping above describes structural equivalences, not framing agreement.

2. **CoALA does not have bias-displacement, attestation, endpoint-residency, or structural stoppability primitives.** Saying "ai-memory exceeds CoALA" on these axes is technically true but misleading — CoALA does not address them at all. The substrate adds axes CoALA did not consider, rather than improving on CoALA's coverage of those axes.

3. **Soar-style hierarchical task decomposition is intentionally not in the substrate.** That is strategic-layer cognition per ROADMAP §4. A reader looking for CoALA's full impasse/subgoal handling will not find it here, and that is a correct scope choice, not a deficiency.

---

## 7. Disposition

This document is reference material. It does not commit the substrate to any CoALA-specific implementation. The seven properties in ROADMAP §2 are the authoritative test. The §3 scope test is controlling. The moonshot synthesis is the North Star.

If a future CoALA revision (v2 or successor framework) changes the taxonomy, this document will be revised to track. The substrate's commitments will not change in response to framework drift.

---

## References

Sumers, T. R., Yao, S., Narasimhan, K., & Griffiths, T. L. (2024). Cognitive Architectures for Language Agents. *Transactions on Machine Learning Research*. arXiv:2309.02427.

---

*Revision history:*
- *2026-05-27 (initial): created as reference supplement, derived from full-spectrum AI NHI assessment.*

*End of document.*
