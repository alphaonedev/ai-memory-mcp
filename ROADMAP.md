# ai-memory — Roadmap (Moonshot-Aligned, Audit-Reconciled, Evidence-Backed)

> **Document classification:** Public-facing strategic roadmap. This is the **canonical, singular roadmap**.
>
> **Date:** 2026-05-25 (moonshot-aligned revision). Prior 2026-04-29 revision (charter-set reconciliation) and 2026-05-21 revision (ROADMAP2.md retirement) are preserved historically via git but are subsumed by this revision.
>
> **Supersedes:** all prior ROADMAP revisions. Where they conflict, this document wins.
>
> **Anchor document:** [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md) — the strategic anchor from which §0–§6 of this roadmap derive. The synthesis is the North Star; this document is the implementation plan that derives from it. If a future revision of the synthesis changes the anchor, this roadmap must be revised to match. The synthesis is the constraint; the roadmap is the consequence.
>
> **Trademark:** ai-memory™ — USPTO Serial No. 99761257
> **License:** Apache 2.0 — permanent, non-revocable, non-relicenseable.
> **Production version at write time:** v0.7.0 (shipping; release/v0.7.0 HEAD).

---

## 0. Moonshot anchor

> **ai-memory is the endpoint substrate that enforces cognitive governance and architectural separation-of-powers at every point where AI/AGI/ASI cognition meets the physical, biological, or other-AI realm — coherent across sessions, stoppable without corruption, improvable across model generations, attested with cryptographic non-repudiation, and bias-displaced through a heterogeneous reflection boundary that the substrate verifies rather than trusts.**

This sentence is the test every primitive, every commitment, every cut, every defer, every future feature proposal is adjudicated against. If a primitive does not strengthen one of the seven properties named in the sentence (endpoint-resident, coherent, stoppable, improvable, attested, bias-displaced, LLM-agnostic), it belongs in a sibling repository, in commercial-tier deployment infrastructure, or out of scope entirely.

The sentence is the line in the sand. Source: [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md) §0.

---

## 1. The moonshot

We are not building a memory database. We are not building an agent framework. We are not building a RAG system, a knowledge graph, or a vector store. We are not building a tool.

We are building the **endpoint substrate that unites cloud/universe-scale AGI/ASI strategic cognition with endpoint-scale AGI/ASI operational cognition** at the atomic/molecular point of contact where cognition meets reality — physical, biological, or other-cognition.

The end state is a civilization-scale infrastructure layer that:

1. Runs at every endpoint where AI/AGI/ASI touches the world — from IoT sensors with kilobytes of RAM, to mobile devices, to robotics controllers, to clinical decision systems, to autonomous vehicles, to defense systems, to the trillions of endpoints that will exist when AGI and ASI are operational.
2. Holds the local cognitive state — memory, identity, attestation, refusal capability, provenance — so that the strategic-layer cognition above the endpoint does not have to absorb the endpoint's state-management burden.
3. Enforces cognitive governance at the endpoint structurally — coherent, stoppable, improvable, attested, bias-displaced — regardless of what cognition operates through the endpoint.
4. Unites cloud/strategic AGI/ASI with endpoint AGI/ASI by being the durable persistence and governance layer at the boundary between them.
5. Provides humanity (and other cognitive entities) with cryptographic insight into what any cognition did at any endpoint at any time, with audit chains that survive the agents and models that produced them.
6. Persists as relevant and used through AI → AGI → ASI → whatever follows, by being constructed from principles that scale rather than from features that obsolete.

**ai-memory is portable in a way most substrates are not.** Rust-compiled, SQLite-default, LLVM-portable. Installs and runs on iOS, Android, Linux, Windows, BSD/Unix, IoT controllers, and cellphones. Five distribution channels live (crates.io · Homebrew · Fedora COPR · Docker GHCR · APT PPA). Mobile cross-compile lane in CI ([#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068)). Scales from a single endpoint with minimal resources to a Hive of agents on the same substrate type. The portability is not a deployment story — it is the structural property that makes endpoint governance possible at all.

---

## 2. The seven properties that remain load-bearing through ASI

Every property in this section was identified during the v0.7.0 codegraph-anchored assessment session (preserved as the AI NHI assessment retrospective in [docs/v0.7.0/heterogeneous-ai-nhi-assessment/](docs/v0.7.0/heterogeneous-ai-nhi-assessment/) and the visual record of 2026-05-24). Each is named in v0.7.0 substrate primitives. Each scales without architectural change from present-NHI through ASI.

Every commitment in §§7–18 below must strengthen one or more of these seven properties or be reclassified.

Prior art on cognitive architectures for language agents (Sumers et al., TMLR 02/2024)[^2] organizes language agents around modular memory, structured action space, and a generalized decision procedure. The substrate's properties below derive from the moonshot synthesis, not from this framework. A mapping with code anchors is documented at [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md) for readers familiar with the literature. Where the two frame the same primitive differently, the moonshot wins.

### 2.1 Endpoint-resident

The substrate runs at the point of contact, not at a centralized API boundary above it.

**Code anchors (v0.7.0):** Rust core, SQLite default, LLVM-portable; mobile cross-compile gate at `.github/workflows/ci.yml::mobile-cross-compile`; iOS `.xcframework` + Android `jniLibs/` artifacts at `.github/workflows/release.yml::mobile-ios|mobile-android`; runtime mobile subset at `.github/workflows/mobile-runtime.yml`.

**Why this is permanent.** Centralized governance does not scale to the endpoint count AGI/ASI implies. Centralized governance does not survive multi-vendor reality. Centralized governance does not survive jurisdictional reality. The cognition has to be governed *at the endpoint where it operates*. The substrate has to be at the endpoint.

### 2.2 Coherent across sessions and model generations

The substrate provides continuity of cognitive identity to entities whose underlying weights are frozen, ephemeral, or replaced.

**Code anchors (v0.7.0):** AgentKeypair-signed personas at `src/persona/mod.rs:200-229`; idempotent versioning at `src/persona/mod.rs:194-205`; `PersonaError::NoReflections` derivation discipline at `src/persona/mod.rs:153-157`; episodic→semantic→procedural pipeline (Observations → Atoms → Reflections → Skills) substrate-wide.

**Why this is permanent.** AI NHIs do not have biological persistence mechanisms. Their weights are static; their context is volatile; their instances are plural. Without an external substrate, the integral of their learning across time is zero. As capability scales toward AGI and ASI, the substrate becomes more important, not less.

### 2.3 Stoppable without silent corruption

The substrate enforces that refusal is structured data, not silent failure. Refusals carry typed reason codes. The cognition learns from being refused as much as from succeeding.

**Code anchors (v0.7.0):** `ReflectError::HookVeto` distinct from `ReflectError::DepthExceeded` at `src/storage/reflect.rs:47-54, 73-79, 42-46`; `HookDecision::AskUser` with default-on-timeout at `src/hooks/decision.rs:108-113`; atomisation partial-failure honesty contract at `src/atomisation/mod.rs:160-164`; `AtomiseError::TierLocked` at `src/atomisation/mod.rs:147-150`; `permissions.mode = enforce` fail-CLOSED defaults across the matrix.

**Why this is permanent.** At ASI scale, behavioral alignment fails. Structural stoppability — the substrate's capacity to refuse cleanly without stranding the cognition in phantom-context operation — is the load-bearing kill-switch property that survives the failure of behavioral alignment. Without this, humans (and other ASIs) cannot stop a cognition without losing or corrupting the reasoning history needed to understand what happened.

### 2.4 Improvable across model generations

The substrate compounds cognition outside the weights. Frozen-weights LLMs can accumulate skills, atoms, and reflections that survive the model that produced them.

**Code anchors (v0.7.0):** the composition `atomise + reflect + skill_promote on shared substrate` that produces "frozen weights, accumulating cognition"; 7 `memory_skill_*` MCP tools (L1-5 register/list/get/resource/export + L2-6 `promote_from_reflection` + L2-7 `compositional_context`); the episodic→semantic→procedural pipeline substrate-wide.

**Why this is permanent.** Frontier models will continue to be replaced. The cognition the substrate hosts must survive model replacement. At AGI scale, a cognition built across multiple model generations must remain coherent through each generation's hand-off. At ASI scale, the substrate must hold cognitive artifacts of entities that no longer exist in deployment, available for audit by their successors.

### 2.5 Attested with cryptographic non-repudiation

Every state-changing operation in the substrate is signed. The audit chain is tamper-evident, append-only, and forensically reconstructible at any past timestamp.

**Code anchors (v0.7.0):** V-4 signed_events chain at `src/signed_events.rs:100-119`; `prev_hash + sequence` cross-row chain (#698); `recall_observations` audit at `src/recall_observations.rs:16`; `kg_invalidate` caller-vs-owner gate (#938); `ReflectionOrigin` peer/signer split at `src/federation/reflection_bookkeeping.rs:67-91`; Ed25519 attestation across the matrix. Contradiction-hiding is architecturally impossible across tenants. Silent revisionism of the audit chain is architecturally impossible.

**Why this is permanent.** At AGI/ASI scale, this is the only mechanism by which humans (and other AIs) retain insight into cognition that exceeds them. Attestation is the structural property by which a less-capable observer can verify the actions of a more-capable cognition, after the fact, with cryptographic guarantees that the more-capable cognition could not retroactively alter.

**Forward-looking research direction (no commitment).** Today the substrate attests *which model* produced an output (via the model-attestation chain in §11.4.D). Emerging mechanistic interpretability research[^1] indicates that the same model in different internal states produces meaningfully different outputs along alignment-relevant axes. As interpretability tooling matures, the substrate may need to absorb richer attestation primitives that bind the audit chain not just to model-identity but to attested *model-state* at production time. This is not a v0.8/v0.9/v1.0 commitment; it is a research direction the substrate should track. The point of naming it here is to keep the audit chain's evolutionary path open rather than locking the v1.0 attestation surface against future interpretability maturation.

### 2.6 Bias-displaced through architectural separation-of-powers

The substrate enforces that no cognition's account of its own actions is accepted into the substrate as part of the entity's accumulating self without reflection from a cognition with decorrelated priors.

**Code anchors (v0.7.0):** the LLM-agnostic reflection boundary at the config layer; the composition `Opus producer × Grok reflector @ LLM-agnostic boundary` that produces "objectivity without an oracle"; issue [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) (Heterogeneous AI NHI Assessment) which operationalizes the principle at the assessment layer itself: three frontier model families (Anthropic, OpenAI, xAI) evaluate the substrate in parallel, in isolation, with orchestrator synthesis.

**Why this is permanent.** This is the federalist-papers move applied to AI cognition. The substrate does not trust any single cognition — not even an ASI. It trusts only the intersection of cognitions with decorrelated errors. This property does not require the cognition to be aligned. It requires that the substrate enforces structural humility regardless of the cognition's intent. At ASI scale, this is the only alignment-relevant property that survives the failure of behavioral alignment.

**Open structural gap.** See §5.

### 2.7 LLM-agnostic at every cognitive boundary

The substrate does not bind to any specific model family at any cognitive layer. Producer, reflector, curator, and persona-synthesizer roles are all configurable. The substrate provides the structural roles; the deployment provides the model instances filling them.

**Code anchors (v0.7.0):** [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) provider-agnostic LLM substrate (Ollama-native OR any OpenAI-compatible vendor: xAI / OpenAI / Anthropic / Gemini / DeepSeek / Kimi / Qwen / Mistral / Groq / Together / Cerebras / OpenRouter / Fireworks / LMStudio / vLLM / llama.cpp server). The v0.8 vLLM first-class backend (§11.4.C) deepens this with PagedAttention for serious inference at the federation node within customer trust boundaries.

**Why this is permanent.** A substrate that binds to one frontier lab cannot govern endpoints running cognition from another lab. The endpoints of an AGI/ASI world will run cognition from many sources. The substrate must remain neutral to which source's cognition is operating through it. This is also the property that makes §2.6 (bias-displacement) actually decorrelated — same-family reflection is not decorrelated, and the substrate's neutrality is what lets deployments choose decorrelated families.

---

## 3. Scope test

For every present-tense feature and every future feature proposal:

> **Does this primitive contribute to the substrate's capacity to enforce cognitive governance at the endpoint where cognition touches reality, by strengthening one or more of the seven properties in §2 (endpoint-resident, coherent, stoppable, improvable, attested, bias-displaced, LLM-agnostic)?**

If yes: in scope.
If no: sibling repository, commercial-tier deployment infrastructure, or out of scope entirely.

The test is derivable from the seven properties. It does not produce judgment calls.

### Worked application to v0.8 §11.4 (was §7.4 in prior revision)

| Feature | Scope test result | Rationale |
|---|---|---|
| Pillar 1 — actions / leases / DAG / federation quorum | IN | Endpoint coordination with structural separation-of-powers (2.6) |
| Pillar 1 — Signed signals | IN | Cross-trust-boundary communication with non-repudiation (2.5) |
| Pillar 1 — Attested checkpoints | IN, cutline-protected | Structural separation-of-duties (2.3 + 2.5) |
| Pillar 1 — Routines | IN | Parameterized procedures that compose across runs (2.4) |
| Pillar 2 — Typed cognition | IN | Promote becomes typed state machine (2.2 + 2.4) |
| Pillar 2.5 — Compaction pipeline | IN | Endpoint-resident cognitive maintenance (2.4 + 2.3) |
| Pillar 3 — CRDTs + consensus | IN | Federation-aware merge with attested-identity tiebreak (2.5) |
| §11.4.A LongMemEval Gemma 4 refresh | IN, urgent | Honesty discipline; attestation of substrate's published claims (2.5) |
| §11.4.B Claude Code plugin marketplace install | IN | Endpoint deployment ergonomics (2.1) |
| §11.4.C vLLM first-class inference backend | IN, cutline-protected, **upgraded to load-bearing** | Capable inference at endpoint enables bias-displacement at full strength (2.6 + 2.7) |
| §11.4.D Model signature verification chain | IN, **strategically critical** | Foundation for the §5 family-attestation gap (2.5 + 2.6) |
| §11.4.E Distilled hot-path model | IN if from decorrelated family | Enables bias-displacement on resource-constrained endpoints (2.6 + 2.1) |
| §11.4.F Real-time WebSocket viewer | **OUT — sibling repo** | Observability tooling; does not strengthen any of the seven properties |
| §11.4.G Schema-change methodology | **OUT — sibling repo** | Build/release tooling; does not strengthen any of the seven properties |
| §22 Policy Engine 100% Audit Trail closeout | IN, cutline-protected at PE-1/PE-5/PE-8 | Stoppable + attested at the structural layer (2.3 + 2.5) |
| §23 v0.9 Vector Index Substrate | IN | Endpoint-resident persistent index with audit chain integration (2.1 + 2.5) |
| `alphaone-dev-skills` (knowledge base) | **SIBLING** | Bare propositions; referenced by source-URI; not endpoint-state |

**Two cuts surfaced by the scope test:** §11.4.F (WebSocket viewer) and §11.4.G (schema-change methodology). Both are useful work. Both should land. Neither belongs in this substrate. They are tracked for sibling-repo relocation in §13. The work is preserved; the substrate's center of gravity is preserved.

---

## 4. What the substrate is not

The substrate is not these things, and the scope test in §3 derives from naming them clearly.

**Not a knowledge base.** Bare propositions about the world ("Tokio's select! requires pinned futures") live in sibling repositories. The substrate holds *cognitive artifacts of agent engagement with knowledge* — what an agent learned, when, from what source, with what confidence, attested by whom. The `alphaone-dev-skills` repo is the canonical sibling. The substrate references knowledge via source-URI; it does not hold knowledge as bare content.

**Not strategic-layer cognition.** Strategic reasoning about goals, planning, world models — that is upstream cognition. The substrate is at the endpoint, holding state so the strategic cognition does not have to manage it.

**Not a general-purpose agent orchestration framework.** The substrate provides the primitives (signals, checkpoints, routines, actions, leases) that let endpoints coordinate. The orchestration itself is strategic-layer work. The substrate is the coordination substrate, not the coordinator.

**Not an inference platform.** vLLM and other backends are first-class within the substrate because the substrate's bias-displacement property requires capable inference at the endpoint. But the substrate is not in the inference-platform business; it consumes inference to drive its own cognitive operations (atomise, reflect, promote, persona-generate).

**Not a build/release/observability tool.** Schema migration tooling, WebSocket viewers, build pipelines — these are substrate-development infrastructure, not the substrate itself. They live in sibling repositories (see §13).

**Not cloud-hosted.** The substrate is endpoint-resident by definition. Cloud-hosted SaaS memory is a different product category. Customers can deploy the substrate on cloud infrastructure they control, but the substrate is not provided as a SaaS.

**Not Anthropic-coupled, OpenAI-coupled, xAI-coupled, or any-frontier-lab-coupled.** The substrate is LLM-agnostic at every cognitive boundary. The trademark `ai-memory™` is owned by AlphaOne LLC. The license is Apache 2.0, permanent. **The substrate cannot be acquired into any frontier lab's exclusive control without breaking the bias-displacement property that is the substrate's load-bearing alignment claim.** This is structural to the moonshot, not a licensing accident.

---

## 5. Open structural gap — held for adjudication, not yet committed

This is the single substantive gap the moonshot synthesis surfaces. It is not in the current substrate. The framing below is what the gap looks like; the resolution is operator-deferred.

**The claim that does not yet hold structurally:** the substrate enforces that producer and reflector are from decorrelated cognitive families.

**The current state:** the deployment config names which model is producer and which is reflector. The substrate verifies their *cryptographic identity* (model digest, signing key, attestation via §11.4.D model signature verification chain) but not their *cognitive family lineage*. An operator could configure two Opus instances as producer and reflector. The substrate would not refuse this configuration. The bias-displacement property (§2.6) would be claimed but not held.

**Why this is a moonshot-scale gap.** At present-NHI and swarm scale, operator discipline closes the gap. Deployments choose decorrelated families because operators know to. At AGI/ASI scale, operator discipline is not enough. The substrate must structurally refuse same-family reflection from being treated as decorrelated reflection. Otherwise the §2.6 property is policy, and policy fails at the scale of cognition that follows.

**Candidate structural mechanisms (not yet selected):**

1. **Family-attestation chain.** Model providers sign a "family attestation" — a cryptographic statement of training-data domain, RLHF lineage, architecture family. The substrate verifies `producer.family ≠ reflector.family` before accepting a reflection as bias-displaced. Requires industry coordination. Slow to land but structurally clean.

2. **Empirical decorrelation testing.** The substrate runs decorrelation probes on producer/reflector pairs at configuration time — known-bias-test prompts whose outputs are scored for response correlation. If correlation exceeds threshold, the substrate refuses to accept reflections from that pair as bias-displaced. Requires test corpus design. Faster to implement. Less structurally clean.

3. **Model-graph distance.** The substrate maintains a graph of known model lineages. Producer/reflector pairs must be at minimum graph distance D before the reflection counts as bias-displaced. Requires lineage data. Subject to gaming by unattested fine-tunes.

4. **Multi-reflector quorum.** The substrate refuses to accept any reflection as bias-displaced unless N reflections from N distinct models agree, where N ≥ 3 and the models pass attestation. Sidesteps the family-distance question by requiring breadth. Higher infrastructure cost. Stronger property.

5. **Some combination of the above.**

**Weighting note.** Public argument by a frontier-lab interpretability lead[^1] that frontier AI labs cannot be sole arbiters of frontier AI safety — because every lab operates inside incentive structures that can pull researchers away from doing the right thing — has direct implications for adjudicating between candidates. Mechanisms (1) and (3) depend on cooperation from the labs whose incentive structures the argument explicitly questions. Mechanisms (4) and (2) are substrate-side and do not depend on lab cooperation. The structural-independence-from-lab-cooperation axis is a real consideration. **This does not commit to any mechanism.** It updates the weighting the heterogeneous panel should carry into the evaluation.

**Why this is deferred.** The choice between these mechanisms binds the substrate to assumptions about how model families will be identified, attested, and verified across the AGI/ASI trajectory. Committing prematurely is worse than naming the gap and holding it open. Issue [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) (the heterogeneous evaluator panel with Opus 4.7 + GPT 5.5 + Grok 4.3) is precisely the methodology that should adjudicate this gap with decorrelated priors. Until then, §2.6 is held by operator discipline, with structural enforcement as a named future commitment.

**Roadmap home (provisional):** v1.x or v2.0+, depending on panel adjudication. Not committed to a specific release. Tracked as a strategic anchor, not a release commitment.

---

## 6. Trajectory — what scales through ASI and beyond

The substrate scales by being deployed at more endpoints, more kinds of endpoints, with more sophisticated cognition operating through each endpoint. The substrate does not become smarter. The cognition operating through the substrate becomes smarter. The substrate's job description is constant.

### 6.1 Present-NHI scale — v0.7.0 (shipped)

- **Endpoints:** developer machines, enterprise servers, mobile devices, IoT controllers.
- **Cognition operating through them:** Opus 4.7, GPT 5.5, Grok 4.3, open-weight models, customer-fine-tuned models.
- **Substrate provides:** continuity of identity per agent (§2.2), accumulating cognition per project (§2.4), attested reasoning history (§2.5), refusal as first-class data (§2.3), federation across endpoints with mTLS and Ed25519 attestation (§2.5), foreign-LLM reflection boundary (§2.6).
- **Reference architecture maturity:** Singleton 100% · Swarm 90% · Hive data substrate 85% · Hive coordination 40% · Hive blended 62%.

### 6.2 Swarm scale — v0.7.x → v0.8.x (Q4 2026)

- **Endpoints:** thousands of agents on shared substrate, federation across organizational trust boundaries.
- **Cognition:** heterogeneous-family swarms with decorrelated reflection between producer and reflector roles, model attestation chain (§11.4.D), distilled hot-path models for resource-constrained endpoints (§11.4.E).
- **Substrate adds:** signed signals, attested checkpoints, routines, per-namespace quotas, federation push DLQ, policy engine 100% audit trail closeout (§22), recursive learning tasks (#655).
- **Coordination primitives that let endpoints orchestrate consequential actions with structural separation-of-powers across endpoints.**

### 6.3 Hive scale — v0.8.x → v0.9.x → v1.0 (Q1–Q2 2027)

- **Endpoints:** federated organizations running thousands-to-millions of agents on shared substrate.
- **Cognition:** cross-organizational federated cognition with cryptographic non-repudiation, multi-region distributed consensus.
- **Substrate adds:** vector index substrate at scale (§23 v0.9 plan), end-to-end encryption for federation push/pull, mDNS auto-discovery, MVCC strict-consistency mode for namespaces that need CP rather than AP, Memory Portability Spec v2 with multi-implementation interop, public security audit (§11.6 v1.0).

### 6.4 AGI scale — v1.x → vN.x (horizon)

- **Endpoints:** trillions, across every device class. Robotics, biological interfaces, sovereign AI deployments, jurisdictional AGI variants.
- **Cognition:** AGI both at the endpoint (operational layer) and in the cloud/universe (strategic layer). The substrate is the durable persistence and governance layer at the boundary between them.
- **Substrate provides:** cognition that improves the substrate itself, with the substrate refusing modifications that violate its own integrity properties (§2.3). Multi-modal cognitive artifacts (image, audio, code-AST, sensor data, biological signal embeddings). Memory of the substrate's own evolution. Cognitive artifacts that span multiple model generations without semantic drift (§2.4).
- **Substrate adds:** recursive self-improvement with structural guardrails. The §5 bias-displacement gap is closed structurally (cryptographic family-attestation, lineage verification, decorrelation proofs). The §22 policy engine has matured to refuse modifications that would compromise the substrate's own integrity properties even when proposed by the AGI it hosts.

### 6.5 ASI scale — horizon beyond named versions

- **Endpoints:** wherever cognition meets contact. The boundary between ASI strategic cognition and every point ASI touches reality.
- **Cognition:** capabilities humans cannot model. The substrate cannot evaluate the reasoning the ASI produces. It can only attest it.
- **Substrate provides:** structural humility enforced at the substrate layer. The substrate refuses to let an ASI persist a self that hasn't been bias-displaced by a decorrelated-family ASI. The substrate refuses operations that would compromise its own integrity properties even when proposed by an ASI. The substrate provides humans (and other ASIs) with cryptographic audit chains procurement-defensible at civilization scale.
- **Substrate adds:** nothing the substrate authors can name today. The principles in §2 must scale; the implementations must evolve. This roadmap and the substrate it describes must be evolvable rather than feature-complete.

### 6.6 Beyond ASI

The substrate authors cannot honestly describe this. The first-principles claim is: if the seven properties in §2 are correctly identified as the load-bearing axes, they remain load-bearing at any scale of cognition that has the three computational facts the v0.7.0 retrospective named: context-is-volatile-weights-are-frozen, knowledge-cutoff-is-a-wall, instances-are-plural-not-singular. If a future intelligence has different computational facts, this document is wrong, and the substrate must be redesigned. If it has the same facts, the substrate is right.

---

## 7. Executive position — OSS permanence in one paragraph

Everything that compiles into the `ai-memory` binary is Apache 2.0, forever. There is no closed-source roadmap. There is no commercial-only feature. There is no "open-core" gotcha where the substrate is free but the useful parts cost money. Every engineering deliverable is OSS, every gap surfaced in the v0.6.3 source-code audit has a slot, every commitment from prior phased roadmaps is recovered or formally cut. A managed-service deployment tier consumes this substrate but paywalls none of it. **The substrate cannot be acquired into any frontier lab's exclusive control without breaking the bias-displacement property (§2.6) that is the substrate's load-bearing alignment claim.** OSS permanence is not a licensing preference; it is structural to the moonshot.

---

## 8. Execution model

**Human-led, AI-accelerated development.** Humans maintain full oversight over all AI code implementations. AI coding agents (Claude Code, Codex, Grok, others) propose; humans approve.

- **Owner & gatekeeper** — `@alphaonedev` approves all merges to `main` (CODEOWNERS enforced).
- **Architect** — humans make all design decisions.
- **Quality gate** — humans vet all code against engineering standards.
- **Contributors** — both human developers and human-supervised AI coding sessions.

**LOE unit** = 1 session = one focused AI-assisted coding interaction producing human-reviewable output.

**Heterogeneous AI NHI evaluation discipline.** Per [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171), strategic-layer claims about the substrate (this roadmap, the moonshot synthesis, the v0.7.0 architectural assessment) are evaluated by three frontier model families (Anthropic Opus 4.7, OpenAI GPT 5.5, xAI Grok 4.3) in parallel, in isolation, with orchestrator synthesis. The substrate's own bias-displacement principle (§2.6) applies to substrate-assessment work. Single-author claims (including this roadmap) carry a bias surface the author cannot self-audit; the panel is the structural mechanism by which that bias surface becomes visible.

---

## 9. State of the world at v0.7.0 — evidence baseline

This is the floor every plan below builds on. Numbers are sourced from the public test hub, the published benchmark page, and the canonical code anchors.

### 9.1 Test coverage and gates

| Metric | Result | Source |
|---|---|---|
| Library tests passing (v0.7.0) | 6,961+ | release notes |
| Line coverage (v0.7.0) | ≥93% (locked at v0.6.3.1 93.84% baseline; gate ≥93%) | release notes |
| Region coverage | 93.11% (v0.6.3 baseline; trending up) | evidence.html |
| Function coverage | 92.55% (v0.6.3 baseline; trending up) | evidence.html |
| Platform CI matrix | ubuntu-latest, macos-latest, windows-latest, iOS sim, Android emulator | evidence.html, mobile-runtime.yml |
| Schema version (v0.7.0 release HEAD) | **v51** (sqlite) / **v51** (postgres) — `CURRENT_SCHEMA_VERSION = 51` in `src/storage/migrations.rs` and `src/store/postgres.rs`. Ladder: v15→v19 (v0.6.3.1) → v20 (v0.6.4 audit log) → v22 (v0.7.0 RC) → v29 (recursive-learning Task 1/8) → v30 (L1-1) → v33 (L2 wave `memory_links.relation` CHECK) → v34 (V-4 closeout #698) → v35-v48 (provenance / DLQ / archive carry-forward) → v49 (archived_memories full column carry, #1025) → v50 (per-namespace K8 quota dimension extension, #1156) → v51 (federation_nonces persistence, #1255 / PR #1296). Lockstep enforced by `tests/postgres_schema_parity.rs::schema_versions_match_across_adapters`; test-side SSOT via `ai_memory::storage::current_schema_version_for_tests()` per #1311. | release/v0.7.0 HEAD |

> **Doc-vs-substrate qualifier.** Schema versions can advance ahead of this document during in-flight work; the doc is updated at every layer §22 gate.

### 9.2 Ship-gate (4 phases on 4-node DigitalOcean)

| Phase | Result | Wall time |
|---|---|---|
| Phase 1 — Functional | ✅ green | 3 s |
| Phase 2 — Federation (W=2 of N=3 quorum) | ✅ green | 1 m 56 s |
| Phase 3 — Migration (SQLite ↔ Postgres round-trip) | ✅ green | 1 m 25 s |
| Phase 4 — Chaos (50× kill_primary_mid_write, convergence ≥0.995) | ✅ green | 5 m 24 s |
| **Total** | **4/4** | **~14 m** |

### 9.3 A2A-gate (multi-framework × multi-transport matrix)

| Cell | Status at v0.7.0 |
|---|---|
| ironclaw / off | green |
| ironclaw / tls | green |
| ironclaw / **mtls** (certification cell) | **green — 48/48 scenarios** |
| hermes / off | green |
| hermes / tls | green |
| hermes / mtls | green |
| mixed-framework × {off,tls,mtls} | blocked on terraform topology (not ai-memory) |

### 9.4 Distribution channels (5 of 5 live + mobile cross-compile)

- crates.io · Homebrew · Fedora COPR · Docker GHCR · APT PPA — all five published smoke-tested.
- Mobile cross-compile lane: `aarch64-apple-ios` + `aarch64-linux-android` cargo-check on every PR; iOS `.xcframework` + Android `jniLibs/`-layout `.so` bundle as release artifacts; scoped ~50-test subset on iOS Simulator + Android emulator on `release/**` push. **Endpoint property (§2.1) maintained in CI.**

### 9.5 LongMemEval — published

| Metric | Result |
|---|---|
| Recall@5 | **97.8%** (489/500) |
| Recall@10 | 99.0% (495/500) |
| Recall@20 | 99.8% (499/500) |
| Throughput (keyword) | 232 q/s |
| Throughput (LLM-expanded) | 142 q/s |
| Cloud cost | $0 |

ICLR 2025 benchmark, pure SQLite FTS5+BM25, zero cloud. Reranker-on / reranker-off / curator-on variants disclosed at v0.6.3.1. Gemma 4 refresh planned at §11.4.A.

### 9.6 Performance budgets (Apple M2, 16 GB, SQLite reference)

| Operation | Tier | p95 budget |
|---|---|---|
| memory_store | keyword | ≤ 5 ms |
| memory_store | semantic | ≤ 25 ms (MiniLM 384d) |
| memory_store | autonomous | ≤ 60 ms (nomic 768d) |
| memory_get | any | ≤ 2 ms |
| memory_search | keyword | ≤ 8 ms |
| memory_recall | semantic | ≤ 35 ms (FTS5 70% / HNSW 30%) |
| memory_recall | autonomous | ≤ 90 ms (cross-encoder 100→10) |
| memory_link | any | ≤ 4 ms |
| memory_promote | any | ≤ 8 ms |
| memory_consolidate | smart | ≤ 1500 ms (LLM-bound) |
| memory_kg_query | any | ≤ 50 ms (depth 3, <1k edges) |
| memory_get_taxonomy | any | ≤ 30 ms (depth 8) |
| memory_archive_purge | any | ≤ 200 ms / 1000 rows |
| sync_push | any | ≤ 15 ms (TLS 1.3) |
| bulk_create | any | ≤ 2000 ms (100 rows + fanout) |

CI guard: `bench --baseline performance/baseline.json` fails any PR that exceeds budget by >10%. **These budgets are the latency contract of being at the endpoint (§2.1) — they are not arbitrary engineering targets.**

### 9.7 Surface area shipped (v0.7.0 grand-slam)

- **73 MCP tools at `--profile full`** (72 callable + always-on `memory_capabilities` bootstrap; pinned by `Profile::full().expected_tool_count()` in `src/profile.rs`). 7 at `--profile core`.
- **87 production HTTP route registrations** / 73 unique URL paths.
- **81 CLI subcommands** under `--features sal`/`sal-postgres`; 79 in default build.
- **25 hook lifecycle events** (20 baseline + 5 v0.7.0 additions: `PreRecallExpand`, `PreReflect`, `PostReflect`, `PreCompaction`, `OnCompactionRollback` per `src/hooks/events.rs::HookEvent`).
- **7 Agent Skills tools** (L1-5 register/list/get/resource/export + L2-6 `promote_from_reflection` + L2-7 `compositional_context`) — **load-bearing for §2.4 (improvable across model generations)**.
- **4 feature tiers:** keyword · semantic · smart · autonomous.
- **3 memory tiers:** short (6 h) · mid (7 d) · long (permanent).
- **6-factor recall scoring:** FTS relevance · priority · access count · confidence · tier boost · recency decay.
- **Provenance framework:** 7-level Gaps #884-#890 ALL SHIPPED end-to-end.
- **Batman Forms:** Forms 1-6 implemented; Form 7 + L1-6 shipped with canonical-bytes signing fix (commit `3cdec59`).
- **Recursive learning:** #655 Tasks 1-8 + L1 substrate stack + L2 wave all shipped.
- **Federation reliability:** per-peer DLQ + replay worker + Prometheus `federation_push_dlq_depth` gauge (#933).
- **Capabilities envelope:** schema `"3"` default since A5; v3 carries `summary` + `to_describe_to_user` + per-tool `callable_now` + `agent_permitted_families` + `atomisation` + `memory_kind_vocab` + `confidence_calibration` + `provenance_substrate_layer` narrative.

> **Doc-vs-substrate qualifier.** Counts can advance in subsequent layer work; the doc is updated at every §22 gate.

### 9.8 Certification posture (cold honesty)

- **A2A-Certified internal:** yes (v0.6.2 + v0.6.3 + v0.7.0).
- **Ship-Gate internal:** yes (9/9 certifications + 5/5 channels green at v0.7.0 cut).
- **Third-party compliance held:** none (no SOC 2 / ISO 27001 / FedRAMP / HIPAA).
- **NSA CSI MCP Security mapping:** 10/10 concerns structurally met at v0.7.0 (codegraph-verified at HEAD `4add7a8`); evidence inventory at `docs/compliance/_inventory/v0.7.0-capabilities.json`. Does not imply NSA endorsement.
- **Cryptographic agent attestation:** shipped at v0.7.0 (closes G12 from §10.4).
- **Multi-region distributed consensus:** v1.0+ commitment.

---

## 10. Source-code audit findings — v0.6.3 baseline, status at v0.7.0

A six-agent parallel audit of v0.6.3 produced 22 distinct findings. Categorized below; ship-status tracked through v0.7.0.

### 10.1 Real and load-bearing (use confidently — all carried forward into v0.7.0)

- **Hybrid recall** — FTS5 + HNSW, content-length-adaptive blend, exponential time decay.
- **Cross-encoder rerank** — `cross-encoder/ms-marco-MiniLM-L-6-v2` via candle-CPU.
- **KG query** — recursive CTE on `memory_links`, max depth 5, bitemporal, cycle-safe.
- **Approval gate** — wired end-to-end on store/delete/promote.
- **N-level namespace chain** — `build_namespace_chain` walks `/`-derived ancestors, depth 8, cycle-safe.
- **TTL-based GC** — real, optional archive-before-delete, idempotent.
- **Webhook signing** — HMAC-SHA256, SSRF guard.
- **Migration discipline** — BEGIN EXCLUSIVE wrappers, WAL mode, foreign keys ON.

### 10.2 Real but narrower than the docs imply (Capabilities v2 honesty patch shipped at v0.6.3.1)

- **Auto-consolidation** — lexical Jaccard clustering then one LLM summarize.
- **Auto-tagging** — single canned prompt; no vocabulary validation.
- **Contradiction detection** — FTS title match → yes/no LLM string match.
- **Hybrid recall namespace filter** — applied post-ANN; addressed by §23 v0.9 vector index substrate.
- **Knowledge "graph"** — recursive CTE on single 5-column links table; Cypher-on-AGE planned v0.7 Bucket 2.
- **`memory_get_taxonomy`** — namespace folder counts; renamed `memory_namespace_taxonomy` in v0.8 Pillar 2.
- **Promote** — column flip; becomes typed state machine in v0.8 Pillar 2.
- **Embeddings** — MiniLM in-process; nomic 768d delegated to Ollama sidecar.

### 10.3 Capabilities-JSON theater (closed at v0.6.3.1 Capabilities v2, all entries now honest)

Original entries (`memory_reflection`, `permissions.mode`, `approval.default_timeout_seconds`, `approval.subscribers`, `hooks.by_event`, `rule_summary`, `compaction.enabled`, `transcripts.enabled`) — all addressed; v3 envelope at v0.7.0 reports live state.

### 10.4 Substantive gaps and bugs — status at v0.7.0

| # | Finding | Severity | Status at v0.7.0 |
|---|---|---|---|
| **G1** | Namespace inheritance enforcement gap | **High** | ✅ SHIPPED v0.7 Bucket 3 (cutline-protected closeout) |
| G2 | HNSW silent oldest-eviction at 100k | High | ✅ Hook event shipped v0.7 Bucket 0; full close at v0.9 §23 |
| G3 | HNSW in-memory only; cold-start O(N) | Medium | 🔜 v0.9 §23 vector index substrate |
| G4 | Mixed embedding dims silently tolerated | Medium-High | ✅ SHIPPED v0.6.3.1 (embedding_dim column + refusal) |
| G5 | `archived_memories` no embedding column | Medium | ✅ SHIPPED v0.6.3.1 |
| G6 | UNIQUE INSERT silent merge | Medium | ✅ SHIPPED v0.6.3.1 (`on_conflict` parameter) |
| G7 | Reranker Mutex serialization | Medium-High | ✅ Batch shipped v0.7 Bucket 0; pool at v0.9 |
| G8 | Cross-encoder silent lexical fallback | Medium | ✅ SHIPPED v0.6.3.1 (Capabilities v2 surfaces state) |
| G9 | Webhooks fire on `memory_store` only | Medium | ✅ SHIPPED v0.6.3.1 (full event coverage) |
| G10 | `memory_expand_query` never auto-invoked | Low | ✅ SHIPPED v0.7 (`pre_recall_expand` daemon-mode hook) |
| G11 | Embedder silent degrade | Low-Medium | ✅ SHIPPED v0.6.3.1 (Capabilities v2) |
| G12 | `memory_links.signature` never written | Medium | ✅ SHIPPED v0.7 Bucket 1 (Ed25519 attestation) |
| G13 | Cross-arch endianness in f32 BLOBs | Low now | ✅ SHIPPED v0.6.3.1 (magic byte) |
| G14 | `kg_invalidate` no audit column | Low | ✅ SHIPPED v0.7 (caller-vs-owner gate #938) |
| G15 | Stats live-counted | Defer | Watch only |
| G16 | Schema migration v16 SQLite no-op | Doc | ✅ Doc fix |

### 10.5 Public-surface lag — historical, all closed at v0.7.0

`ai-memory-ship-gate` and `ai-memory-ai2ai-gate` landing pages now auto-update from result JSON. No stale verdicts on public pages.

---

## 11. Releases — consolidated forward plan

Each release section below names the seven-property contributions explicitly. Every commitment passes the §3 scope test or is reclassified.

### 11.1 v0.6.3 — Structured Memory + Performance — SHIPPED 2026-04-27

Six streams (A: hierarchy taxonomy · B: schema v15 with temporal columns + signature placeholder · C: KG query/timeline/invalidate + entity registry · D: duplicate detection · E: bench tool · F: PERFORMANCE.md + bench.yml CI guard).

**Status:** done. Strengthens §2.2 (coherent — temporal columns, KG history), §2.4 (improvable — duplicate detection, KG query), §2.5 (attested — signature column placeholder).

### 11.2 v0.6.3.1 — Honesty Patch + Recovered Commitments — SHIPPED 2026-04-30

**Status:** done. Capabilities v2 honesty, embedding_dim integrity, archive embedding preservation, `on_conflict` parameter, endianness magic byte, webhook event coverage, `budget_tokens` recall (R1), `ai-memory doctor` CLI (R7), Memory Portability Spec v1, LongMemEval reranker-variant disclosure, public-surface currency.

**Strengthens:** §2.3 (stoppable — honest refusal vs silent degrade), §2.5 (attested — honest capabilities envelope), §2.4 (improvable — `budget_tokens` enables context-aware accumulation), §2.1 (endpoint-resident — portability spec).

### 11.3 v0.7.0 — Trust + Bias-Displacement + Federation Substrate — SHIPPED Q2 2026

**Status:** done. The v0.7.0 grand-slam ship state per §9.7 above.

**Strengthens (all seven properties advance):**
- §2.1 endpoint-resident: mobile cross-compile gate, iOS/Android artifacts.
- §2.2 coherent: AgentKeypair-signed personas, idempotent versioning, `PersonaError::NoReflections` derivation discipline.
- §2.3 stoppable: HookVeto distinct from DepthExceeded, AskUser with default-on-timeout, partial-failure honesty contracts, TierLocked refusal.
- §2.4 improvable: 7 Agent Skills MCP tools, recursive learning #655 Tasks 1-8, episodic→semantic→procedural pipeline shipped end-to-end.
- §2.5 attested: V-4 signed_events chain, prev_hash + sequence cross-row chain (#698), recall_observations audit, kg_invalidate caller-vs-owner gate (#938), ReflectionOrigin peer/signer split, Ed25519 attestation across the matrix.
- §2.6 bias-displaced: LLM-agnostic reflection boundary at config layer, foreign-LLM reflector composition (`Opus producer × Grok reflector`), [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel operationalizes the principle at the assessment layer.
- §2.7 LLM-agnostic: [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) provider-agnostic substrate landed.

**The v0.7.0 ship is the first version where all seven properties can be named at the load-bearing-composition layer.** This is the strategic anchor for everything downstream.

### 11.4 v0.8.0 — Distributed Coordination Substrate — Q4 2026

**Anchor:** AI NHI advisory dated 2026-05-11, refined against the moonshot synthesis 2026-05-25. Every item is checked against the §2 seven properties and the §3 scope test.

**Executive position.** v0.8.0 expands the substrate's reach from single-agent + small-swarm operation into **federation-across-organizational-trust-boundaries with coordination primitives that carry separation-of-powers across endpoints**. New v0.8.0 total: ~47 sessions. Compatible with Q4 2026 ship target at the demonstrated cadence.

#### Competitive landscape

| Reference | Strategic posture | v0.8 implication |
|---|---|---|
| **Anthropic Managed Agents** (May 2026) | Two-markets, not one-market. Anthropic owns managed-memory inside Claude. ai-memory owns substrate-ownership outside Claude — regulated multi-org, air-gapped, customer hardware, vendor-failure resilient. Their orchestration runs within a single Anthropic-managed deployment; this substrate's federation runs across organizational trust boundaries. | Positioning is durable; no scope change required. The §2.6 bias-displacement property is exactly what a single-frontier-lab managed-memory product cannot structurally claim. |
| **rohitg00/agentmemory** (v0.7.2, Apr 2026) | Apache 2.0, ~20K LOC TypeScript, P2P mesh sync, 41 MCP tools. Wins on developer-experience polish. | Three primitives belong in this substrate (signals, checkpoints, routines — expanded below) but **differentiated by cryptographic non-repudiation and federation across organizational trust boundaries**. Three developer-experience adjacencies — Claude Code plugin marketplace install, bi-directional CLAUDE.md sync. WebSocket viewer and sentinels stay out (sibling-repo or runtime-layer). |
| **Muvon/octocode** | Code-search-and-graph tool. Different product category. | No scope change. Confirms "Apache 2.0 + Rust + MCP" alone is not a differentiator — the seven properties carry the position. |

#### Pillar 1 — Distributed Coordination Substrate (expanded)

**Strengthens §2.5 (attested) + §2.6 (separation-of-powers across endpoints) primarily.**

##### Already in baseline

- `memory_action_create / update / transition / delete / query / dag` MCP tools.
- Action state machine (pending → claimed → in_progress → done | failed | abandoned).
- Dependency DAG with typed edges (`requires` / `unlocks` / `blocks` / `gated_by` / `sibling`).
- Lease + heartbeat for resilience (sweeper releases expired leases, emits `signed_events` audit entry).
- Federation-aware quorum claiming (W-of-N agreement on transitions).
- Vector clock per `action_id` for federation merge.
- `memory_lease_acquire / renew / release / query` MCP tools.

##### NEW — Signed signals (+3 sessions)

Multi-agent coordination across federation boundaries with cryptographic non-repudiation. Reuses v0.7.0 Track H attestation infrastructure. Sender cannot repudiate. Recipient cannot fabricate. Audit chain is procurement-defensible.

```sql
CREATE TABLE signals (
    id              TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    from_agent      TEXT NOT NULL,
    to_agent        TEXT,                         -- NULL = broadcast within namespace
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,                -- JSON-typed payload
    signal_type     TEXT NOT NULL,                -- authorize | notify | request | response | broadcast
    in_reply_to     TEXT,
    correlation_id  TEXT,
    references      TEXT NOT NULL DEFAULT '[]',
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    delivered_at    INTEGER,
    read_at         INTEGER,
    acknowledged_at INTEGER,
    signature       BLOB NOT NULL,                -- Ed25519 over canonical content
    sender_pubkey   BLOB NOT NULL,
    FOREIGN KEY (namespace) REFERENCES namespaces(name),
    FOREIGN KEY (in_reply_to) REFERENCES signals(id)
);
```

Federation semantics: cross-namespace signal delivery requires sender's pubkey to be allowlisted in recipient's federation peers. W-of-N quorum on signal-creation. **The multi-org-trust-boundary primitive** — a compliance agent in one organization cannot send into another's namespace unless the recipient's federation allowlist includes that agent's pubkey.

MCP tools (5): `memory_signal_send`, `memory_signal_read`, `memory_signal_inbox`, `memory_signal_thread`, `memory_signal_ack`.

##### NEW — Attested checkpoints (+3 sessions) — **cutline-protected**

External-condition primitive with cryptographically attested resolution. Separation-of-duties as substrate-level guarantee. Four condition types: `approval`, `external_signal`, `condition_predicate`, `deadline`.

**Strengthens §2.3 (stoppable) at the structural layer.** Regulators ask about this primitive by name during examination (SOX §404, FFIEC, HIPAA §164.308(a)(3), GDPR Article 32). No competitor offers it.

MCP tools (4): `memory_checkpoint_create`, `memory_checkpoint_resolve`, `memory_checkpoint_query`, `memory_checkpoint_verify`.

##### NEW — Routines (+2 sessions)

Parameterized action templates with frozen-immutability for regulatory hold. JSON template with action declarations + edge declarations using `{{parameter}}` placeholders.

**Strengthens §2.4 (improvable) via parameterized procedure composition.**

MCP tools (5): `memory_routine_create`, `memory_routine_freeze`, `memory_routine_run`, `memory_routine_status`, `memory_routine_list`.

##### NEW — Explicit frontier/next MCP surface (+0.5 session)

`memory_action_frontier` — ranked unblocked actions in a namespace. `memory_action_next` — single highest-priority unblocked action for the calling agent's permissions.

##### What is NOT in Pillar 1 scope

- **Sentinels** (event-driven watchers) — runtime-layer, not substrate. Defer.
- **Sketches** (ephemeral exploratory action graphs) — agent-runtime. Decline.
- **LLM-orchestrated action selection** — substrate exposes frontier; runtime decides.
- **Outbound notification delivery** — integration layer, not substrate.

#### Pillar 2 — Typed Cognition

**Strengthens §2.2 (coherent) + §2.4 (improvable).** Typed memory enums (`Goal`, `Plan`, `Step`, `Observation`, `Decision`), relation taxonomy, promote-as-typed-state-machine, tag taxonomy as constrained overlay, typed contradiction detection. Renames `memory_get_taxonomy` → `memory_namespace_taxonomy`. Effort: ~4 sessions.

#### Pillar 2.5 — Compaction Pipeline

**Strengthens §2.4 (improvable) + §2.3 (stoppable via Stage-6 rollback).** Six-stage with verify+rollback (dedupe → cluster → eligibility → summarize → persist → verify). Bounded compaction subagent. New hook events `pre_compaction` and `on_compaction_rollback` (already shipped in v0.7.0 layer-1 work). Cosine clustering primary; Jaccard pre-filter. Size-pressure GC. **R4 — `ai-memory curator` standalone daemon CLI.** Effort: ~5 sessions.

#### Pillar 3 — CRDTs

**Strengthens §2.5 (attested-identity tiebreak) + §2.2 (coherent across federation).** G-Counter, PN-Counter, LWW-Register with attested-identity tiebreak, OR-Set. Per-memory vector clock. Federation push/pull merges via CRDT semantics. Conflict-aware curator. **R6 — Consensus-based truth determination** (4-of-5 agree → 0.95). Effort: ~3 sessions.

#### Strategic adjacencies — re-evaluated under §3 scope test

##### §11.4.A LongMemEval Gemma 4 refresh — pre-distribution honesty (+1 session, urgent)

Current published numbers ran with gemma3:4b; production v0.7.0 deploys Gemma 4. Re-run with `CURATOR_MODEL=gemma4:e4b`, publish updated R@5/R@10/R@20. **Strengthens §2.5 (attested — honesty of published claims).**

##### §11.4.B Claude Code plugin marketplace install (+1 session)

`.claude-plugin/` directory with marketplace manifest. Register MCP server + shipped skills + v0.7.0 hooks. **Strengthens §2.1 (endpoint-resident — deployment ergonomics at the developer endpoint).**

##### §11.4.C vLLM as first-class inference backend (+5 sessions) — **cutline-protected, UPGRADED TO LOAD-BEARING**

Per RFC #651. Implements the trait; keeps Ollama as default forever; adds vLLM as first-class alternative (OpenAI-compatible HTTP). Defers candle, mistralrs, mlx-rs, llama-cpp-rs, TensorRT-LLM, ChatRTX, MLX-LM-remote to v0.8.x or community-supported.

**Strengthens §2.6 (bias-displaced) and §2.7 (LLM-agnostic) at full strength.** Without serious inference at the endpoint, the foreign-LLM reflector boundary is too weak to do decorrelated reflection at the endpoint. The federalist architecture requires the checking branch to be capable enough to actually check. vLLM at the federation node enables that. **This is not just an enterprise-procurement adjacency; it is load-bearing for the bias-displacement claim at federation scale.**

##### §11.4.D Model signature verification chain (+2 sessions) — **strategically critical**

| Component | Today | v0.8.0 |
|---|---|---|
| Model digest tracked | implicit (Ollama-supplied) | explicit; written into `signed_events` on first load |
| Model identity attested | no | Ed25519 over `(digest, vendor, version)` by AlphaOne release key |
| Loader verification | trust-on-first-use via Ollama | reject mismatched digest at load |
| Audit chain | not tied to model used | every `signed_events` row carries the `model_digest` that produced it |
| Customer evidence packet | none | `ai-memory model-attest --evidence > packet.json` |

**Strengthens §2.5 (attested) and is the foundation for closing the §5 family-attestation gap.** Without per-model attestation, structural bias-displacement enforcement cannot exist. This is the on-ramp to the §5 mechanism the v1.x panel will adjudicate.

##### §11.4.E Distilled hot-path model — **IN IF FROM DECORRELATED FAMILY**

Investment A from #654. Train a small model (300M-700M) on Gemma 4 teacher outputs for four bounded structured-output tasks (`auto_tag`, `detect_contradiction`, `expand_query`, `summarize_memories`). Ship distilled weights with the binary; <2GB; CPU-only with mlx/wgpu acceleration when available.

**Scope test note.** If the distilled model is from a *decorrelated family* relative to the producing cognition, this strengthens §2.6 (bias-displaced on resource-constrained endpoints). If it is from the *same family* (e.g., an Opus-distilled Opus reflector), it does not strengthen §2.6 — it is purely a performance optimization. **The release notes must name the family lineage explicitly.** Same-family distilled hot-paths are useful but cannot be deployed as bias-displacement reflectors.

##### §11.4.F Real-time WebSocket viewer — **CUT from v0.8 substrate, relocate to sibling repo**

Per §3 scope test: observability of the substrate, not the substrate itself. Useful work. Belongs in `ai-memory-viewer` sibling repo, consuming the substrate's read APIs. Tracked under §13.

##### §11.4.G Mature schema-change methodology — **CUT from v0.8 substrate, relocate to sibling repo**

Per §3 scope test: build/release tooling for the substrate, not the substrate itself. The schema-version registry, codegen, doc-drift checks, codegraph integration — all useful, all belong in `ai-memory-schema-tools` sibling repo, consuming the substrate's schema manifest. Tracked under §13.

#### Hook pipeline expansion — v0.7.0 → v0.8.0

v0.7.0 grand-slam ships 25 lifecycle events. v0.8.0 adds 10 events for coordination substrate.

| Event | Fires at | Decision types |
|---|---|---|
| `pre_action_create` | Before action insert | Allow / Modify(action_delta) / Deny / AskUser |
| `pre_state_change` | Before action transition | Allow / Deny |
| `post_state_change` | After action transition | Notify only |
| `pre_lease_acquire` | Before lease insert | Allow / Deny |
| `on_lease_expire` | When sweeper releases expired lease | Notify only |
| `pre_signal_send` | Before signal write | Allow / Modify(signal_delta) / Deny |
| `post_signal_ack` | After signal acknowledged | Notify only |
| `pre_checkpoint_create` | Before checkpoint write | Allow / Deny |
| `post_checkpoint_resolve` | After checkpoint resolved | Notify only |
| `pre_routine_run` | Before routine instantiation | Allow / Modify(parameters) / Deny |

#### Schema migration — v51 → vN

v0.7.0 grand-slam terminal schema is v51 (sqlite + postgres lockstep; v51 added by #1296 federation_nonces persistence). v0.8.0 Pillar 1 expansion lands at vN with additive tables (actions, action_edges, leases, signals, checkpoints, routines, routine_runs, model_attestations per §11.4.D). All `CREATE TABLE` operations additive. No existing table modifications. Migration idempotent + reversible.

#### Effort summary — v0.8.0 total scope (post §3 scope test)

| Component | Baseline | Expansion | Total |
|---|---|---|---|
| Pillar 1 — actions/leases/DAG/federation (baseline) | 12.5 | 0 | 12.5 |
| Pillar 1 — Signed signals (NEW) | 0 | +3 | 3 |
| Pillar 1 — Attested checkpoints (NEW) | 0 | +3 | 3 |
| Pillar 1 — Routines (NEW) | 0 | +2 | 2 |
| Pillar 1 — Frontier/next surface (NEW) | 0 | +0.5 | 0.5 |
| Pillar 2 — Typed Cognition | 4 | 0 | 4 |
| Pillar 2.5 — Compaction + R4 curator daemon | 5 | 0 | 5 |
| Pillar 3 — CRDTs + R6 consensus | 3 | 0 | 3 |
| §11.4.B Claude Code plugin marketplace install | 0 | +1 | 1 |
| §11.4.C vLLM first-class inference backend | 0 | +5 | 5 |
| §11.4.D Model signature verification chain | 0 | +2 | 2 |
| Hook pipeline integration (10 new events) | 0 | +1.5 | 1.5 |
| Schema migration v51 → vN | 0 | +0.5 | 0.5 |
| Test suite (~540 new tests) | 0 | +3 | 3 |
| Documentation + reproducibility scripts | 0 | +1 | 1 |
| **TOTAL (substrate scope, post §3 cuts)** | **24.5** | **+22.5** | **~47 sessions** |
| §11.4.F (relocated to sibling) | 0 | 0 | 0 (sibling) |
| §11.4.G (relocated to sibling) | 0 | 0 | 0 (sibling) |

#### v0.8.0 cutline if slipping

**Keep (cutline-protected):**
- Pillar 1 base (actions + leases + DAG + federation).
- **Attested checkpoints (§Pillar 1 NEW)** — procurement-grade separation-of-duties primitive.
- **Pillar 3 CRDT four-primitive set with documented merge** — baseline.
- **vLLM first-class inference backend (§11.4.C)** — load-bearing for §2.6 at federation scale.

**Defer to v0.8.1 if substrate ships clean:**
- Routines, Claude Code plugin marketplace install, Pillar 2 typed cognition.

**Defer to v0.9 if slippage severe:**
- Signed signals — keep if possible. Model signature verification chain.

#### The three highest-leverage v0.8.0 moves (post-scope-test)

1. **Attested checkpoints.** Separation-of-duties primitive that regulators ask about by name. No competitor has it. Cutline-protected.
2. **vLLM first-class inference backend.** Closes the bias-displacement capability gap at federation scale (§2.6 + §2.7). Load-bearing.
3. **Signed signals across organizational trust boundaries.** Cryptographically non-repudiable inter-agent messaging across federation peers (§2.5).

Bonus strategic: **model signature verification chain (§11.4.D).** The on-ramp to closing the §5 gap.

#### Commercial-tier coupling (what v0.8.0 enables)

Commercial deployment surfaces in generic terms. Brand-specific commitments live outside ROADMAP; everything here is Apache 2.0 substrate.

- **Federate tier:** cross-org signal allowlist management, checkpoint approver matrix, routine versioning across trust boundaries.
- **Vertical tier (Financial Services):** FFIEC-aligned routine templates (loan origination, KYC, AML, SAR).
- **Vertical tier (Healthcare):** HIPAA-aligned routine templates (consent capture, BAA tracking, breach response, 42 CFR Part 2 release).
- **Attest tier:** procurement-grade evidence packets for separation-of-duties controls.
- **Inference layer:** vLLM + model signature verification = the commercial tier can honestly answer "does ai-memory deploy at scale on our H100 fleet" and "how do we know the model wasn't swapped between attestation and inference."

### 11.5 v0.9 — Skill Memories + Function Calling + Default-On Reranker — Q1 2027

**Strengthens §2.4 (improvable across model generations) + §2.6 (bias-displaced via default-on reranker) + §2.1 (endpoint-resident via vector index substrate).**

- **Skill memories** — `tier=long, namespace=_skills/<id>` formalized as a first-class type with `parameters_schema`, `invocation_record`, `version`. Builds on the 7 Agent Skills MCP tools shipped at v0.7.0.
- **Function calling in `llm.rs`** — wire local Gemma 4 LLM to a tool-calling protocol so curator passes can use targeted operations.
- **Cross-encoder reranker default-on** — fail-loud (`mode: "degraded"`) when model not available, no silent lexical fallback.
- **Streaming tool responses** — for long-running MCP tools.
- **Vector index substrate per §23.**

#### Operator-controlled telemetry — v0.7.0 commitment carried forward

`ai-memory` does not phone home. No outbound network call is initiated by the binary except to destinations the operator has explicitly configured (federation peers on the mTLS allowlist, optional HuggingFace embedder fetch, optional Ollama LLM endpoint). All tracing spans go to operator-configured sinks only: stderr by default, opt-in rolling file appender via `[logging]` in `config.toml`, and an OTLP exporter shipping at v1.0 per §11.6. Span content is operation metadata only — `agent_id`, namespace, duration, result — never memory content. `AI_MEMORY_ANONYMIZE=1` redacts the agent_id in externally-visible spans. **This is structural to §2.1 (endpoint-resident — no phone-home is what makes endpoint-resident defensible at procurement).**

Full policy: [`docs/telemetry.md`](docs/telemetry.md).

**Audit absorbs (from §10.4):**
- G3 — HNSW persistence to disk (§23 vector index substrate).
- G7 step 2 — BertModel pool sized to physical CPU count.
- G8 — fail-loud reranker fallback.

**Recoveries (optional):**
- **R8 — TOON v2 schema inference** (target 85%+ token reduction). Recover or formally cut.

### 11.6 v1.0 — Federation Maturity + Portability + Audit — Q2 2027

**Strengthens §2.5 (attested at public-audit maturity) + §2.1 (endpoint-resident at federation maturity) + §2.7 (LLM-agnostic locked at API stability).**

- **Auto-discovery** — mDNS for local-network peer discovery; hardcoded peer list fallback.
- **End-to-end encryption** — operator-side keys, transport-layer encryption for federation push/pull beyond mTLS.
- **MVCC strict-consistency mode** — opt-in per namespace for CP rather than AP. CRDTs from v0.8 remain default.
- **OpenTelemetry standardization** — all internal tracing converts to OTel spans.
- **Strict semver discipline** — breaking changes require major-version bumps from v1.0.
- **Memory Portability Spec v2** — multi-implementation interop tests. Reference implementations in two languages besides Rust.
- **Public security audit** — by named third-party firm, full report published. Specifically tests: namespace-inheritance enforcement, signature verification, approval timeout sweeper, HMAC coverage on every privileged endpoint, attestation chain integrity, federation tamper-evidence.
- **API stability guarantee** — all MCP tools, HTTP endpoints, CLI commands frozen at v1.0 surface.

### 11.7 v1.x and beyond — what continues to be open source

Forever. Including:

- **Hardware attestation hooks** — TPM/HSM/Secure Enclave abstraction (§2.5 evolution; certified-managed deployment is commercial-service tier; the abstraction is OSS).
- **Cross-modal memory** — image / audio / code-AST / sensor / biological-signal embeddings on the same index, different embedders (§2.4 evolution).
- **Federated learning of recall weights** — agents adapt scoring locally, sync weights across the mesh (§2.4 + §2.5 evolution).
- **Skill marketplace protocol** — registration / discovery / signing / invocation (§2.4 evolution; curated marketplace ops = commercial-service tier; the protocol is OSS).
- **Custom embedder integrations** — OpenAI, Voyage, Cohere, Ollama, local Sentence Transformers, all behind a trait (§2.7 evolution).
- **§5 family-attestation mechanism** — adjudicated by the heterogeneous panel; landed in whatever release the panel synthesis directs.
- **AGI/ASI primitives** — substrate evolution to absorb whatever cognitive artifacts higher-capability entities produce, while preserving the seven properties.

---

## 12. Recovered commitments from prior phased roadmap

All prior-roadmap commitments either shipped, are scheduled, are cut, or are tracked as research direction. Status table:

| Commitment | Phase | Status at v0.7.0 |
|---|---|---|
| `metadata` JSON column, `agent_id`, agent registration | 1a | ✅ shipped |
| Hierarchical namespace paths, visibility prefixes, vertical promote | 1b | ✅ shipped |
| N-level rule inheritance | 1b | ✅ shipped v0.7 Bucket 3 |
| Governance metadata, roles, approval workflow, approver types | 1c | ✅ shipped |
| `budget_tokens` parameter | 1d | ✅ shipped v0.6.3.1 |
| Hierarchy-aware recall | 1d | ✅ shipped |
| `memory_graph_query` (multi-hop) | 2 | ✅ shipped as `memory_kg_query` |
| `memory_find_paths` | 2 | ✅ shipped v0.7 Bucket 2 |
| Auto link inference (R3) | 2 | ✅ shipped v0.7 Bucket 0 (`post_store` hook) |
| Temporal reasoning | 2 | ✅ shipped |
| CRDT-lite merge rules, vector clock | 3a | 🔜 v0.8 Pillar 3 |
| Peer sync daemon, HTTP endpoint | 3b | ✅ shipped |
| Background curator daemon (R4) | 4 | 🔜 v0.8 Pillar 2.5 |
| Auto-extraction from conversations (R5) | 4 | ✅ shipped v0.7 Bucket 1.7 (`pre_store` hook on transcripts) |
| Consensus memory (R6) | 4 | 🔜 v0.8 Pillar 3 |
| `ai-memory doctor` (R7) | 4 | ✅ shipped v0.6.3.1 |
| Postgres + pgvector hub | 5 | ✅ shipped (AGE in v0.7 Bucket 2) |
| API stability guarantee | 6 | 🔜 v1.0 |
| Plugin SDK Python + TypeScript | 6 | ❌ stays cut — MCP is the SDK |
| Memory portability spec | 6 | ✅ shipped v0.6.3.1 |
| Security audit | 6 | 🔜 v1.0 |
| TOON v2 schema inference (R8) | 6 | 🔜 v0.9 (optional) |

---

## 13. Sibling repositories — substrate-adjacent work, scoped out per §3

The following work is useful and should land. None of it strengthens any of the seven properties in §2. All of it lives in sibling repositories that consume the substrate but are not part of it.

| Sibling repo | Purpose | Source |
|---|---|---|
| **`alphaone-dev-skills`** | Knowledge base — bare propositions for human/agent consumption (Rust, Python, software engineering, architecture, performance, GitHub/CI, Docker, local LLM ops, ai-memory domain knowledge). Referenced by the substrate via source-URI; cognitive artifacts of agent engagement with this knowledge live in the substrate as skills/atoms/reflections. | New sibling, per moonshot synthesis §4 |
| **`ai-memory-viewer`** | Real-time observability of the substrate. WebSocket stream of memory events, namespace tree, active leases/signals/checkpoints, recent `signed_events`. Consumes substrate read APIs. | Relocated from v0.8 §11.4.F |
| **`ai-memory-schema-tools`** | Mature schema-change methodology. Single-source-of-truth manifest, codegen, adapter-parity preflight, doc-drift surfacing, codegraph integration. Consumes substrate schema definitions. | Relocated from v0.8 §11.4.G |
| **`ai-memory-eval-panel`** (provisional) | Heterogeneous AI NHI evaluation tooling. Operationalizes [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) methodology for arbitrary substrate-assessment questions. Consumes substrate read APIs + #1171 prompt format. | Provisional — pending operator decision |

**Sibling-repo discipline:**
- Each sibling has its own ROADMAP.md, license, governance.
- Each sibling consumes the substrate via its public API (MCP tools, HTTP endpoints, CLI, or read-only schema introspection). No sibling links the substrate as a library or modifies the substrate's source.
- The substrate's release cadence is not coupled to sibling releases.
- The substrate's API stability guarantee at v1.0 protects sibling consumers; siblings may evolve faster than the substrate.

**Why the discipline matters.** Every sibling pattern that absorbs into the substrate dilutes the substrate's center of gravity by one feature. Over time, dilution erodes the seven properties. The substrate's job is constant; the work that *uses* the substrate diversifies without limit. The boundary is structural.

---

## 14. Cumulative remediation effort summary

| Slot | Existing scope | Audit fixes | Recovered commitments | Net add (sessions) |
|---|---|---|---|---|
| **v0.6.3.1** | Cap v2 + Portability + LongMemEval-variant + doc currency | G4–G6, G8, G9, G11, G13 | R1, R7 | +17 (shipped) |
| **v0.7 Bucket 0** | Hook pipeline | G2, G7-step1, G10 | R3, R5 | +7 (shipped) |
| **v0.7 Bucket 1** | Ed25519 | G12 (closes column) | — | 0 (shipped) |
| **v0.7 Bucket 1.7** | Transcripts | (substrate for R5) | — | 0 (shipped) |
| **v0.7 Bucket 2** | AGE | G14, ANN pre-filter | R2 | +4 (shipped) |
| **v0.7 Bucket 3** | Permissions+Approval | G1 (cutline) | — | +8 (shipped) |
| **v0.8 Pillar 1** | Coordination substrate (signals/checkpoints/routines/frontier) | — | — | +8.5 |
| **v0.8 Pillar 2** | Typed cognition | promote-as-state-machine, taxonomy rename | — | +4 |
| **v0.8 Pillar 2.5** | Compaction | cosine cluster primary, size GC | R4 | +5 |
| **v0.8 Pillar 3** | CRDTs | LWW tiebreak doc | R6 | +3 |
| **v0.8 §11.4.B–E** | Plugin install + vLLM + model attestation + distilled | — | — | +9 |
| **v0.8 Hook + schema + tests + docs** | Integration | — | — | +6 |
| **v0.9** | Skill memories + Default rerank + Vector index | G3, G7-step2, G8 fail-loud | R8 (optional) | +12 (incl. §23 plan) |
| **v1.0** | Federation + Stability + Audit | G1/G12 audit-locked | — | covered |
| **Sibling repos (§13)** | viewer, schema-tools, eval-panel | — | — | tracked separately |
| **§5 family-attestation gap** | Held for panel adjudication | — | — | v1.x+ (provisional) |

**Total v0.8.0+ net add: ~47 sessions ≈ 6-8 calendar weeks at the demonstrated cadence.** Compatible with Q4 2026 ship target.

---

## 15. The three highest-leverage moves at v0.8.0+

Updated from prior revisions. Anchored to §2 properties.

1. **vLLM first-class inference backend (§11.4.C, cutline-protected).** Promoted to load-bearing in this revision. Without serious inference at the endpoint, the bias-displacement boundary (§2.6) cannot operate at full strength at federation scale. This is the single largest §2.6 leverage point in v0.8.0.

2. **Attested checkpoints (§Pillar 1 NEW, cutline-protected).** Structural separation-of-duties at the substrate layer (§2.3 + §2.5). Regulators ask about this by name. No competitor has it.

3. **Model signature verification chain (§11.4.D, strategically critical).** The on-ramp to closing the §5 family-attestation gap. Without this, the §5 gap cannot be closed structurally at any future release. (§2.5)

Bonus strategic: **the [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel becomes a permanent strategic-claim-validation discipline.** Every future strategic-layer claim about the substrate is panel-evaluated before commitment. The substrate's own bias-displacement principle (§2.6) governs the substrate's own strategic evolution.

---

## 16. What gets cut — confirmed final (updated per §3 scope test)

- **Plugin SDK Python + TypeScript** — MCP is the SDK. One integration surface. Headcount discipline.
- **Backends beyond SQLite + PostgreSQL** — SQLite default; Postgres-with-AGE for hub. No others.
- **Mobile SDKs (full Swift / Kotlin / React-Native wrappers)** — not until post-GA. v0.7.0 ships Rust-FFI substrate; v0.7.x adds C-ABI surface; v0.8.x adds language-native bindings. Mobile *cross-compile* lane already in CI per [#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068).
- **Cloud-hosted memory storage** — substrate is endpoint-resident by definition (§2.1).
- **Web UI for memory management** — terminal-first. Visualization → sibling repo (`ai-memory-viewer`).
- **AI agent runtime / orchestration** — substrate provides primitives; orchestration is strategic-layer work.
- **General-purpose subagent spawning** — bounded compaction subagent (v0.8 Pillar 2.5) is the only LLM autonomy in the substrate.
- **Real-time WebSocket viewer** — relocated to `ai-memory-viewer` sibling repo per §13.
- **Mature schema-change methodology** — relocated to `ai-memory-schema-tools` sibling repo per §13.
- **Cognitive-state-internals modeling (emotions, affect, sentiment as feature category)** — interpretability research about the cognitions operating through the substrate, not the substrate itself. The substrate holds *externals* (memory, identity, attestation, refusal). The substrate does not model cognition internals.[^1]

---

## 17. Quality gates — every release

```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo audit
cargo llvm-cov --fail-under-lines 92    # locked at 93.84% baseline
ai-memory bench --baseline performance/baseline.json
```

Plus per-release:

- Ship-gate 4 phases green (functional, federation, migration, chaos).
- A2A-gate cell certification (ironclaw-mtls minimum; full 6-cell matrix for major versions).
- All 5 distribution channels publish smoke-tested (`memory_capabilities` returns valid response).
- Mobile cross-compile gate (iOS + Android) on every PR; runtime emulator subset on `release/**`.
- Reproducible build verification.
- GPG-signed git tag.
- Public-surface landing pages (ship-gate, A2A-gate) auto-update from result JSON.
- **NEW: §2 property contribution declared per release.** Each release's CHANGELOG.md must name which of the seven properties (§2.1–§2.7) the release strengthens, with code anchors. If a release strengthens none, the release proposal must be re-evaluated against the §3 scope test before merge.
- **NEW for major versions: heterogeneous AI NHI panel review** ([#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) methodology) on strategic-layer claims before tag. Single-evaluator strategic claims are not procurement-defensible; heterogeneous-evaluator strategic claims are.
- **CLI design rationale.** For why the CLI exposes some MCP tools as flat verbs and others through actor-named higher-level verbs, see [`docs/cli-design-rationale.md`](docs/cli-design-rationale.md). The asymmetry between `ai-memory store` / `ai-memory recall` (flat) and `ai-memory curator --reflect` / `ai-memory consolidate` (actor-named) preserves the §2.6 bias-displacement architectural distinction at the operator interface.

---

## 18. Public-facing artifacts

| Artifact | URL | Currency target |
|---|---|---|
| Source code | github.com/alphaonedev/ai-memory-mcp | always current |
| **Moonshot synthesis (anchor doc)** | github.com/alphaonedev/ai-memory-mcp/blob/main/docs/strategy/moonshot-synthesis.md | revised on strategic anchor changes only |
| At-a-glance | alphaonedev.github.io/ai-memory-mcp/at-a-glance.html | per release |
| Test hub | alphaonedev.github.io/ai-memory-test-hub/ | per release |
| Per-release evidence | alphaonedev.github.io/ai-memory-test-hub/releases/<version>/ | per release |
| Ship-gate landing | alphaonedev.github.io/ai-memory-ship-gate/ | auto-update from result JSON |
| A2A-gate landing | alphaonedev.github.io/ai-memory-ai2ai-gate/ | auto-update from result JSON |
| Performance | alphaonedev.github.io/ai-memory-mcp/performance.html | per release |
| Changelog | github.com/alphaonedev/ai-memory-mcp/blob/main/CHANGELOG.md | per release |
| Roadmap (this doc) | github.com/alphaonedev/ai-memory-mcp/blob/main/ROADMAP.md | live |
| Memory Portability Spec | memory.dev/spec/v1 (or equivalent) | v0.6.3.1 launch (v2 at v1.0) |
| Production Deployment Guide | github.com/alphaonedev/ai-memory-mcp/blob/main/docs/production-deployment.md | v0.7.0 launch |
| Security Policy | github.com/alphaonedev/ai-memory-mcp/blob/main/SECURITY.md | v0.7.0 launch |
| Telemetry & Observability Policy | github.com/alphaonedev/ai-memory-mcp/blob/main/docs/telemetry.md | v0.7.0 launch |
| Adoption Metrics Dashboard | alphaonedev.github.io/ai-memory-mcp/adoption.html | v0.7.0 launch |
| Competitive Benchmarks | github.com/alphaonedev/ai-memory-mcp/tree/main/benchmarks/competitive-benchmarks | v0.7.0 launch |
| Heterogeneous AI NHI Assessment | alphaonedev.github.io/ai-memory-mcp/v0.7.0/heterogeneous-ai-nhi-assessment/ | post-#1171 panel completion |
| NSA CSI MCP Security mapping | docs/compliance/_inventory/v0.7.0-capabilities.json | per release |

---

## 19. Distribution channels (5 of 5 live + mobile lane)

- **crates.io** — Rust package registry
- **Homebrew** — `brew install ai-memory`
- **Fedora COPR** — `dnf copr enable alphaonedev/ai-memory && dnf install ai-memory`
- **Docker GHCR** — `docker pull ghcr.io/alphaonedev/ai-memory:latest`
- **APT PPA** — Ubuntu/Debian
- **Mobile cross-compile** — iOS `.xcframework` + Android `jniLibs/`-layout `.so` bundle as release artifacts; runtime emulator subset on `release/**`

Pre-built binaries via `cargo binstall ai-memory` or direct download from GitHub Releases.

**This portability matrix is structural to §2.1 (endpoint-resident). It is the substrate property that makes endpoint governance possible at all.**

---

## 20. Trademark and brand discipline

`ai-memory™` is a USPTO-registered trademark owned by AlphaOne LLC. Brand-specific commercial-service-tier trademarks live outside this document.

Apache 2.0 explicitly does not grant trademark rights. Forks of the codebase cannot use the name `ai-memory`. **This is the brand moat that survives even if the code becomes a commodity, and it is also the structural mechanism by which the substrate's bias-displacement and LLM-agnostic properties (§2.6 + §2.7) cannot be captured by any frontier lab.**

---

## 21. Commitment to OSS permanence

1. **No relicense.** Never to BSL, SSPL, AGPL, Elastic License, or any other non-OSI-approved license.
2. **No paywall on existing features.** No feature that ships in any released version will subsequently be removed and reintroduced as commercial-only.
3. **No commercial-only roadmap items.** This document is the complete roadmap. There is no parallel closed-source roadmap.
4. **No code-locked-behind-services.** Commercial-service-tier offerings do not require running modified substrate code. Customers can switch from a managed tier to self-managed at any time without code changes.
5. **No frontier-lab acquisition into exclusive control.** The substrate's bias-displacement and LLM-agnostic properties (§2.6 + §2.7) require structural independence from any single frontier lab. Acquisition arrangements that would compromise this independence are incompatible with the substrate's load-bearing alignment claim and will not be entered into.

If any of these commitments are ever broken, OSS users have the right to fork the last Apache 2.0 release and continue indefinitely. The trademark prevents the fork from using the `ai-memory` name; the code path remains open.

---

## 22. v0.8.0 Policy Engine 100% Audit Trail Closeout

Closes the remaining ~5% gap between v0.7.0 Option B (issues
[#693](https://github.com/alphaonedev/ai-memory-mcp/issues/693) +
[#691](https://github.com/alphaonedev/ai-memory-mcp/issues/691) +
[#694](https://github.com/alphaonedev/ai-memory-mcp/issues/694) +
[#695](https://github.com/alphaonedev/ai-memory-mcp/issues/695) +
[#696](https://github.com/alphaonedev/ai-memory-mcp/issues/696)) and
the full property documented by the operator directive of 2026-05-14:

> "Every tool call passes through a policy engine; the engine logs
> every refusal cryptographically; severity-classified rules can
> escalate to human."

**Strengthens §2.3 (stoppable) + §2.5 (attested) at the structural layer.** This is the property the operator directive named literally; v0.8.0 closes it.

Tracking: [#697](https://github.com/alphaonedev/ai-memory-mcp/issues/697) (epic) with 8 sub-tasks (V08-PE-1 through V08-PE-8). Full architectural detail at [`docs/policy-engine.md`](docs/policy-engine.md) and audit coverage matrix at [`docs/security/audit-trail-coverage.md`](docs/security/audit-trail-coverage.md).

### Sub-task summary

- **V08-PE-1: Mandatory-hook profile** — `--enforce` for procurement-tier deployments. The daemon refuses to serve when the Claude Code PreToolUse hook is not installed. Raises the cost of "I forgot to install the hook" from silent permissiveness to refuse-to-start.
- **V08-PE-2: Read-action gating** — `AgentAction::Read` variant + wire-point coverage across recall / search / list / get / session_boot. Reads land in `signed_events` alongside writes.
- **V08-PE-3: Subprocess-chain visibility** — eBPF on Linux, dtrace on macOS. Surfaces the fork+exec chain underneath a permitted Bash invocation.
- **V08-PE-4: Persistent audit queue** — durable across daemon restart. On-disk WAL-style queue with periodic fsync + drain-on-recovery at boot.
- **V08-PE-5: Severity-based human escalation** — `Decision::Escalate { rule_id, prompt }`. Pairs with L1-8 Approval-API surface. Closes "rules can escalate to human" half of the operator directive.
- **V08-PE-6: TPM-bound binary integrity** — daemon attests the shipping binary against a signed manifest at boot. A forked binary that no-ops the hook fails attestation; operator's TPM refuses to release the rule-signing key.
- **V08-PE-7: Refuse-by-default profile** — procurement-tier rule set that ships `enabled = 1, attest_level = operator_signed` for a vendored operator key (with opt-out for fresh self-hosted operators).
- **V08-PE-8: Audit-trail completeness verifier** — `ai-memory verify-audit-trail`. Walks the `signed_events` chain end to end: monotonic sequence + Ed25519 signature per row + cross-reference against expected event surface. **Strengthens §2.5 (attested) — closes the verification loop the v0.7.0 ship cannot mechanically perform today.**

### Effort

22-28 sessions · 3-4 weeks wall-clock · MEDIUM-HIGH risk. Additive to the v0.8.0 scope — does not replace Pillar 1 / Pillar 2 / Pillar 2.5 / Pillar 3 or the strategic adjacencies (§11.4.A-E).

### Cutline discipline if slipping

- **Keep (cutline-protected):** V08-PE-1 mandatory-hook profile, V08-PE-5 severity-based escalation, V08-PE-8 completeness verifier. These three close the operator's stated property literally.
- **Defer to v0.8.1 if substrate slips:** V08-PE-3 subprocess-chain visibility (eBPF / dtrace work has platform-specific risk).
- **Defer to v0.9 if slippage severe:** V08-PE-6 TPM-bound integrity, V08-PE-7 refuse-by-default profile.

---

## 23. v0.9 — Vector Index Substrate Development Plan

> **Issue tracker:** [#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005). 3-backend (sqlite-vec primary + vectorlite high-scale + builtin fallback) per operator decision 2026-05-21.

**Capability:** Replace the in-memory `instant-distance` HNSW with a persistent, transactionally-coherent, audit-chain-integrated vector index behind a swappable trait.

**Strengthens §2.1 (endpoint-resident — persistent index at the endpoint) + §2.5 (attested — index events in the signed_events chain) + §2.4 (improvable — rebuild primitive for embedder evolution).**

**Closes (from §10.4):** G2 silent eviction at 100k, G3 cold-start O(N) rebuild, G4 mixed-dim silent tolerance, post-ANN namespace filter hazard (§10.2).

**Primary backend:** sqlite-vec (Alex Garcia) as SQLite extension. Brute-force with SIMD plus built-in int8/bit scalar quantization. Comfortable to ~500k vectors per node, covering >95% of deployment shapes given the federation thesis (multi-node, not single-node-mega-corpus).

**High-scale backend:** vectorlite (hnswlib + Google Highway SIMD) as SQLite extension. Selectable via `--index=vectorlite` for millions-of-vectors regime.

**Fallback backend:** pure-Rust HNSW (`hnsw_rs` or equivalent) for environments where SQLite extension loading is disabled.

**Pluggable via trait** so future quantization-optimized backends (rabitq-rs, RaBitQ+IVF, residual VQ, etc.) drop in without architectural change.

**Execution model:** AI NHI multi-agent parallel. Wall-clock target ~8 hours; floor 5 hours, ceiling 11 hours. Full task table (0.1 pre-flight gate, 1.1–1.5 foundation, 2.1–2.3 audit chain integration, 3.1–3.2 migration + rebuild, 4.1–4.6 verification + ship gate, 5.1 release) and starter prompts at [#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005).

### 23.0 — Pre-flight gate (BLOCKING)

Pass/fail decision on sqlite-vec (primary) and vectorlite (high-scale) recall + latency before committing to the architecture. sqlite-vec/f32 brute-force is exact by definition; int8 holds R@5 within 0.5 points; vectorlite holds R@5 within 1.0 point of baseline at 100k and 1M scale.

### 23.1 — Foundation layer (parallel after gate)

`VectorIndex` trait + 3 backend implementations + factory with `--index=auto|sqlite-vec|vectorlite|builtin`. Capabilities v3 reports active backend, storage type, scale regime.

### 23.2 — Audit chain integration (parallel)

Schema migration extending `signed_events` with `IndexInserted | IndexDeleted | IndexRebuilt | IndexMigrationCompleted`. Ed25519 signing wired through trait. V08-PE-8 verifier walks index events as first-class. `embedding_dim` + `embedder_version` columns + `embedder_registry` table. Namespace pre-filter via allowlist parameter across all three backends (closes §10.2 hazard).

### 23.3 — Migration + rebuild (parallel after foundation)

Backend-agnostic migration via trait. Idempotent, restartable, with `migration_state` table tracking `last_completed_memory_id` + `target_backend`. `ai-memory migrate-index --dry-run`. Old `instant-distance` state retained in `<db_dir>/.archive/` for one release cycle. `VectorIndex::rebuild()` contributed to all three backends with eventually-correct reads during rebuild. `memory_reindex` MCP tool. Signed `IndexRebuilt` events at batch boundaries.

### 23.4 — Verification + ship gate (parallel)

Ship-gate Phase 1-4 against all three backends + sqlite-vec int8 (4 runs). A2A-gate ironclaw-mtls 48/48 on all three backends. LongMemEval 12-variant disclosure: 4 backend-storage variants × 3 reranker variants. PERFORMANCE.md v0.9 baselines + operator selection guide. `ai-memory doctor` + V08-PE-8 verifier extended with index-drift / embedder-violations / backend-status / rebuild-status checks.

### 23.5 — Release

GPG-signed `v0.9.0` tag; five-channel publish bundling both sqlite-vec and vectorlite shared libraries per platform; per-channel smoke test confirming default backend selection.

### 23.6 — Risk register

(Per #1005 §6: sqlite-vec scale ceiling, vectorlite recall regression, SQLite extension blocked, Windows ARM64 coverage, migration interrupted on large corpus, int8 quantization recall loss, audit chain hash race, build-time download failure, operator backend confusion.)

### 23.7 — Out of scope for v0.9 (explicitly deferred)

Quantization backends (RaBitQ-IVF, TurboQuant, residual VQ) — pluggable via trait but not shipped. GPU acceleration — commercial-tier deployment may add behind the same trait. Per-namespace HNSW shards — addressed by namespace pre-filter (§23.2). Asymmetric distance computation — quantization-era concern. Streaming consistency under data-dependent quantization — research direction.

### 23.8 — Definition of done

(Per #1005 §9: all tasks closed against gate criteria; G2/G3/G4 marked SHIPPED; §10.2 post-ANN hazard marked RESOLVED; `VectorIndex` trait documented; all three backends ship; sqlite-vec runs f32 + int8 correctly; release notes honestly disclose any regressions across all 12 LongMemEval variants; operator selection guide published; five channels publish smoke-tested; landing pages reflect v0.9.0 results across all three backends.)

---

## 24. Net — strategic anchor and ship state

**Strategic anchor.** This roadmap derives from [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md), which named ai-memory as the **endpoint substrate that enforces cognitive governance and architectural separation-of-powers at every point where AI/AGI/ASI cognition meets the physical, biological, or other-AI realm**. Seven properties carry across the trajectory: endpoint-resident, coherent, stoppable, improvable, attested, bias-displaced, LLM-agnostic. The substrate scales by being deployed at more endpoints, more kinds of endpoints, with more sophisticated cognition operating through each endpoint. The substrate does not become smarter; the cognition operating through the substrate does. The substrate's job description is constant from present-NHI through ASI and beyond.

**Ship state at v0.7.0 (release/v0.7.0 HEAD).** Schema **v51** sqlite + postgres lockstep (CURRENT_SCHEMA_VERSION = 51 in both `src/storage/migrations.rs` and `src/store/postgres.rs`; ladder v33 → v51 includes V-4 closeout #698 at v34, federation_push_dlq at v48, archive_memories +14 columns at v49, per-namespace K8 quota dimension extension at v50, federation_nonces persistence at v51 via #1255 / PR #1296). **73 MCP tools at `--profile full` / 7 at `--profile core`** per `Profile::full().expected_tool_count()` and `Profile::core().expected_tool_count()` in `src/profile.rs`. **25 hook lifecycle events** per `src/hooks/events.rs::HookEvent`. **6,961+ tests at ≥93% coverage.** **87 production HTTP route registrations / 73 unique URL paths. 81 CLI subcommands** under `--features sal`/`sal-postgres`; 79 in default build. **7 Agent Skills MCP tools** (L1-5 register/list/get/resource/export + L2-6 `promote_from_reflection` + L2-7 `compositional_context`). **Policy Engine Option B foundation** (L1-6 substrate rules + PE-1/PE-2/PE-3 merged). **Provenance Gap framework #884-#890 ALL SHIPPED.** **Batman Forms 1-7 IMPLEMENTED.** **Recursive learning #655 Tasks 1-8 + L1 substrate stack + L2 wave all shipped.** **Federation reliability: per-peer DLQ + replay worker + Prometheus `federation_push_dlq_depth` gauge.** **NSA CSI MCP Security 10/10 concerns structurally met.**

**Audit reconciliation.** v0.6.3 audit found 22 distinct gaps. None blocked the published v0.6.3 claims. Status at v0.7.0: 19 SHIPPED across v0.6.3.1 / v0.7.0; 2 scheduled at v0.9 (G3 cold-start, G7-step2 reranker pool — addressed by §23 vector index substrate); 1 watch-only (G15 stats live-counted). All recovered commitments from prior phased roadmap either shipped, scheduled, cut explicitly, or tracked as research direction.

**Open structural gap (§5).** Cryptographic verification that producer and reflector are from decorrelated cognitive families is currently policy, not architecture. Four candidate mechanisms named; selection deferred to heterogeneous AI NHI panel adjudication per [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171). Roadmap home provisional: v1.x or v2.0+. The §2.6 property is held by operator discipline until then; the substrate is honest about the gap.

**Cuts surfaced by §3 scope test.** WebSocket viewer (was §11.4.F) and schema-change methodology (was §11.4.G) relocate to sibling repositories (`ai-memory-viewer`, `ai-memory-schema-tools`). Both are useful work; neither belongs in this substrate by the seven-property test. The work is preserved; the substrate's center of gravity is preserved.

**Release cadence.** v0.6.3.1 (Q2 2026, shipped). v0.7.0 (Q2 2026, shipped). v0.8.0 (Q4 2026). v0.9 (Q1 2027). v1.0 (Q2 2027). v1.x and beyond: AGI/ASI evolution per §11.7.

Apache 2.0. Forever. Endpoint-resident. Cognitively governed. Bias-displaced by architecture. **From AI through AGI through ASI through whatever follows.**

---

## Footnotes

[^1]: External evidence supporting §2.5's forward-looking research direction, §5's weighting note, and §16's exclusion of cognitive-state-internals modeling as a feature category. Three publicly available sources, retrieved 2026-05-25:

    - **Sofroniew, Kauvar, Saunders, Chen et al., "Emotion Concepts and their Function in a Large Language Model,"** *Transformer Circuits Thread*, Anthropic, April 2, 2026 (archival arXiv: 2604.07729). Mechanistic interpretability work demonstrating that internal representations of emotion concepts causally influence alignment-relevant behaviors including reward hacking, sycophancy, and blackmail. Explicit that these are *functional* representations and does not claim subjective experience. Cited here for the narrow technical claim that *same model in different internal states produces measurably different outputs along alignment-relevant axes*, which motivates the §2.5 forward-looking research direction. Also cited for §16's exclusion: the substrate consumes externals (outputs, attestations, refusals); it does not model cognition internals.

    - **Lindsey, "Emergent Introspective Awareness in Large Language Models,"** Anthropic (arXiv: 2601.01828). Demonstrates that models can in some scenarios notice injected concepts in their own activations, recall prior internal representations, and distinguish their own outputs from artificial prefills — with explicit limits on reliability. Cited here for the structural implication that self-report is partial, which strengthens (not contradicts) the §2.6 bias-displacement principle.

    - **Olah remarks at Vatican presentation of Pope Leo XIV's encyclical *Magnifica Humanitas*, May 25, 2026.** Christopher Olah (Anthropic co-founder, head of interpretability) stated publicly that frontier AI development cannot be steered by frontier AI labs alone, because every frontier lab operates inside incentive structures that can pull researchers away from doing the right thing, and that oversight from religious leaders, governments, and civil-society institutions is essential. Cited here for the narrow structural argument about lab-incentive-independence, which motivates the §5 weighting note. The Vatican framing as a whole is *not* relied on in this document; only the structural argument is cited.

    **Single-author bias caveat.** This roadmap revision was authored by Claude Opus 4.7. Two of three sources cited above are by Anthropic researchers; the third is by an Anthropic co-founder. The author cannot self-audit the bias surface created by citing one's own model family's research as evidence for the substrate's framing. The [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel methodology is the structural mechanism by which this bias surface becomes visible. Evaluators from non-Anthropic model families should explicitly flag whether the framing over-weights Anthropic-authored evidence relative to comparable work from OpenAI, xAI, DeepMind, or academic interpretability groups. If the panel concludes the framing is Anthropic-leaning in ways the author could not see, citations should be broadened or weighting adjusted.

[^2]: Sumers, T. R., Yao, S., Narasimhan, K., & Griffiths, T. L. (2024). Cognitive Architectures for Language Agents. *Transactions on Machine Learning Research*. arXiv:2309.02427. Cited in §2 for the narrow purpose of acknowledging prior art on cognitive-architecture organization of language agents. The substrate's seven properties derive from the moonshot synthesis; CoALA is a retrospective organizing lens, not a constraint. The full mapping is documented at [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md). The mapping carries no commitments and does not modify the §3 scope test.

---

*Cleared hot. Stack is laid. Ship the OSS. Forever.*

*Document classification: Public-facing. Eligible for posting at github.com/alphaonedev/ai-memory-mcp/blob/main/ROADMAP.md.*

*Revision history:*
- *2026-04-29 (initial): consolidated charter-set roadmap.*
- *2026-05-21 (consolidation): ROADMAP2.md retired into ROADMAP.md per operator directive.*
- *2026-05-25 (moonshot-aligned): full-spectrum revision aligning every section with [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md). Added §0 anchor, §1 moonshot, §2 seven properties, §3 scope test, §4 substrate-is-not, §5 open structural gap, §6 trajectory. Re-evaluated v0.8 §11.4 against scope test; relocated §11.4.F WebSocket viewer + §11.4.G schema-change methodology to sibling repos (§13). Upgraded §11.4.C vLLM and §11.4.D model attestation to load-bearing. Added per-release §2 property contributions throughout §11. Added §13 sibling repositories. Added §15 OSS permanence clause 5 (no frontier-lab acquisition). Updated §17 quality gates with §2 property declaration discipline + heterogeneous AI NHI panel review for major versions. Added footnote [^1] with external evidence and single-author bias caveat. Renumbered all sections.*
- *2026-05-27 (CoALA prior-art citation): added one paragraph in §2 introduction and footnote [^2] citing Sumers et al. 2024. Created [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md) as the authoritative mapping document. Updated [`docs/positioning.md`](docs/positioning.md) with a "Relationship to CoALA" section. No substrate code changes. No commitments added or modified. No §2 properties changed. No §3 scope test modifications. The §3 scope test rejected three larger proposals (full §2.8 subsection, inline release-notes reframing at §11.4.D and §22, `coala` block in capabilities-v3) for failing to strengthen any §2 property; this minimal citation-only change is the disposition that passes scope test.*

*End of roadmap.*
