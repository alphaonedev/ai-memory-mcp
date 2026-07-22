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
> **Production version:** v0.9.0 (schema v78, 101 MCP tools at `--profile full`), a security-hardening and code-review release. It supersedes v0.8.1 (patch release, 2026-06-29) and v0.8.0 (GA, released 2026-06-25; `distributed-coordination`). The prior v0.7.1 patch line (surface area identical to v0.7.0) is itemized in §11.3.1.

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

1. Runs at every endpoint where AI/AGI/ASI touches the world — from tens-of-MB endpoints (phones, Raspberry-Pi-class boards, robotics controllers — the substrate's real floor is a ~31 MB binary at ~18–25 MB idle RSS), up through mobile devices, clinical decision systems, autonomous vehicles, and defense systems, to the trillions of endpoints that will exist when AGI and ASI are operational. (Kilobyte-RAM MCUs — Cortex-M class, "Tier ∅" — do not host the substrate directly; their L1 memory, identity, and attestation are held on their behalf by a nearby gateway/hub. See §25.8 endpoint tiering. Corrected per D-OPUS-5, 2026-06-28.)
2. Holds the local cognitive state — memory, identity, attestation, refusal capability, provenance — so that the strategic-layer cognition above the endpoint does not have to absorb the endpoint's state-management burden.
3. Enforces cognitive governance at the endpoint structurally — coherent, stoppable, improvable, attested, bias-displaced — regardless of what cognition operates through the endpoint.
4. Unites cloud/strategic AGI/ASI with endpoint AGI/ASI by being the durable persistence and governance layer at the boundary between them.
5. Provides humanity (and other cognitive entities) with cryptographic insight into what any cognition did at any endpoint at any time, with audit chains that survive the agents and models that produced them.
6. Persists as relevant and used through AI → AGI → ASI → whatever follows, by being constructed from principles that scale rather than from features that obsolete.

**ai-memory is portable in a way most substrates are not.** Rust-compiled, SQLite-default, LLVM-portable. Installs and runs on iOS, Android, Linux, Windows, BSD/Unix, IoT controllers, and cellphones. Five distribution channels live (crates.io · Homebrew · Fedora COPR · Docker GHCR · APT .deb). Mobile cross-compile lane in CI ([#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068)). Scales from a single endpoint with minimal resources to a Hive of agents on the same substrate type. The portability is not a deployment story — it is the structural property that makes endpoint governance possible at all.

**Scope honesty (per the DeepMind *From AGI to ASI* review[^3], [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698)).** The independent DeepMind paper validates the *frictions* this substrate addresses — verification/oversight of beyond-human cognition, agent decorrelation, auditable capability records, cross-session memory coherence — but it is **orthogonal to two of its four AGI→ASI pathways** (scaling, paradigm shifts) and is silent on the *external-endpoint* solution shape (§2.1 endpoint-residence is ai-memory's own jurisdictional/sovereignty bet, not a field-agreed requirement). Read the moonshot sentence accordingly: the substrate is most defensibly load-bearing for the **verification and decorrelation** frictions specifically — it is *necessary-but-not-sufficient* integrity substructure, not a universal governor of literally "every point where ASI cognition meets reality." The most-shipped and most-externally-validated property is attestation (§2.5); decorrelation (§5) is the harder, less-mature frontier. Lead the ASI-relevance argument with attestation, not breadth.

---

## 2. The seven properties that remain load-bearing through ASI

Every property in this section was identified during the v0.7.0 codegraph-anchored assessment session (preserved as the AI NHI assessment retrospective in [docs/v0.7.0/heterogeneous-ai-nhi-assessment/](docs/v0.7.0/heterogeneous-ai-nhi-assessment/) and the visual record of 2026-05-24). Each is named in v0.7.0 substrate primitives. Each scales without architectural change from present-NHI through ASI.

Every commitment in §§7–18 below must strengthen one or more of these seven properties or be reclassified.

Prior art on cognitive architectures for language agents (Sumers et al., TMLR 02/2024)[^2] organizes language agents around modular memory, structured action space, and a generalized decision procedure. The substrate's properties below derive from the moonshot synthesis, not from this framework. A mapping with code anchors is documented at [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md) for readers familiar with the literature. Where the two frame the same primitive differently, the moonshot wins. A complementary mapping to the decentralized-memory multi-agent literature (DecentMem, Hao et al., arXiv:2605.22721)[^4] is documented at [`docs/strategy/decentmem-mapping.md`](docs/strategy/decentmem-mapping.md).

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

**Code anchors (v0.7.0):** `ReflectError::HookVeto` distinct from `ReflectError::DepthExceeded` at `src/storage/reflect.rs:47-54, 73-79, 42-46`; `HookDecision::AskUser` with default-on-timeout at `src/hooks/decision.rs:108-113`; atomisation partial-failure honesty contract at `src/atomisation/mod.rs:160-164`; `AtomiseError::TierLocked` at `src/atomisation/mod.rs:147-150`; `permissions.mode = enforce` is the fail-CLOSED secure default (governance + SSRF guard also fail-closed). **Carve-out:** agent-attestation and federation peer-enrollment ship **permissive** at v0.7.0 — unsigned writes land `claimed` unless `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` is set; #1464 tracks the v0.8 secure-default flip.

**Why this is permanent.** At ASI scale, behavioral alignment fails. Structural stoppability — the substrate's capacity to refuse cleanly without stranding the cognition in phantom-context operation — is the load-bearing kill-switch property that survives the failure of behavioral alignment. Without this, humans (and other ASIs) cannot stop a cognition without losing or corrupting the reasoning history needed to understand what happened.

**Precision (per [^3]).** "Kill-switch" here governs the *substrate's own writes and persistence* — clean, typed refusal that does not corrupt the reasoning record — NOT a veto over a hosted superhuman cognition's actions in the world. The shipped §2.3 anchors (`HookVeto`, `AskUser`, `TierLocked`) gate what lands in the substrate, not what the cognition does outside it; attesting that an ASI did X is not stopping it (§6.5 concedes the substrate can attest but not evaluate ASI reasoning). The honest claim is stoppability-*without-corruption-of-the-record*, which is real and pathway-agnostic — not behavioral control of the cognition, which the substrate does not provide.

### 2.4 Improvable across model generations

The substrate compounds cognition outside the weights. Frozen-weights LLMs can accumulate skills, atoms, and reflections that survive the model that produced them.

**Code anchors (v0.7.0):** the composition `atomise + reflect + skill_promote on shared substrate` that produces "frozen weights, accumulating cognition"; 7 `memory_skill_*` MCP tools (L1-5 register/list/get/resource/export + L2-6 `promote_from_reflection` + L2-7 `compositional_context`); the episodic→semantic→procedural pipeline substrate-wide.

**Why this is permanent.** Frontier models will continue to be replaced. The cognition the substrate hosts must survive model replacement. At AGI scale, a cognition built across multiple model generations must remain coherent through each generation's hand-off. At ASI scale, the substrate must hold cognitive artifacts of entities that no longer exist in deployment, available for audit by their successors.

### 2.5 Attested with cryptographic non-repudiation

Every state-changing operation in the substrate is signed. The audit chain is tamper-evident, append-only, and forensically reconstructible at any past timestamp.

**Code anchors (v0.7.0):** V-4 signed_events chain at `src/signed_events.rs:100-119`; `prev_hash + sequence` cross-row chain (#698); `recall_observations` audit at `src/observations/mod.rs` (`record_recall` ledger); `kg_invalidate` caller-vs-owner gate (#938); `ReflectionOrigin` peer/signer split at `src/federation/reflection_bookkeeping.rs:67-91`; Ed25519 attestation across the matrix — **per-row signing is enrollment-dependent** (the daemon writes unsigned rows when no keypair is present, and depth-exceeded substrate audit rows are best-effort), but the cross-row hash chain stays tamper-evident in either posture. Contradiction-hiding is architecturally impossible across tenants. Silent revisionism of the audit chain is architecturally impossible.

**Why this is permanent.** At AGI/ASI scale, this is the only mechanism by which humans (and other AIs) retain insight into cognition that exceeds them. Attestation is the structural property by which a less-capable observer can verify the actions of a more-capable cognition, after the fact, with cryptographic guarantees that the more-capable cognition could not retroactively alter.

**Scope precision (per [^3]).** The substrate attests *operations* — authorship and integrity of what was DONE — which is *necessary-but-not-sufficient* for the paper's harder ask of *capability* attestation (provenance of what a system CAN do, and that recursive self-improvements do not degrade safety properties). Operation-attestation is the tamper-evident integrity substructure beneath a semantic verification layer the field has yet to build; the forward-looking *model-state* attestation (below) is the bridge toward the paper's "standards for capability attestation across organizations." This is the single property where ai-memory ships a concrete primitive matching a named DeepMind preparedness requirement, and — being capability-agnostic — it survives all four AGI→ASI pathways.

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
| §23 Vector Index Substrate (minimal slice shipped v0.9.0 via #1005; v1.0.0 landed only default-OFF `vectorlite`-only scaffolding via [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860) — no sqlite-vec, no `--index` factory, fail-closed to builtin HNSW; full persistent substrate continues past v1.0.0) | IN | Endpoint-resident persistent index with audit chain integration (2.1 + 2.5) |
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

## 5. Open structural gaps — decorrelation enforcement (now committed) + distributed verification

The moonshot synthesis surfaced one gap here. The DeepMind *From AGI to ASI* paper[^3] — whose multi-agent-collectives pathway makes **decorrelation against correlated failure modes a structural requirement, not operator policy** — independently confirms this gap is load-bearing AND exposes a **second** gap of co-equal weight: **distributed verification** (per-write federation `agent_id` attestation is still *claimed*, not attested, at v0.7.0 — the §2.3 carve-out / [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464)), which means the prior "single open structural gap" framing was externally falsified. On the strength of that external validation, **decorrelation enforcement is promoted from "held for adjudication" to a committed v0.8/v0.9 milestone** (see Roadmap home below). Adversarial-review record: [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698). The framing below is what the decorrelation gap looks like; it is now a build commitment, not an operator deferral.

**The claim that does not yet hold structurally:** the substrate enforces that producer and reflector are from decorrelated cognitive families. **(Reframed per [^3]):** the pairwise producer/reflector boundary is the *degenerate N=2 case*; the paper's friction is **module/swarm-level** correlated failure modes, so the target property is **collective decorrelation** — candidate (4) multi-reflector N≥3 quorum is the PRIMARY architecture (it generalizes to the collective and is lab-cooperation-independent). This also exposes a tension in §11.4 Pillar 4: a module's shared consolidated Postgres+AGE corpus can propagate correlated priors across N agents *regardless of model-family diversity*, so decorrelation must be decided at **write-time** (model family) AND **consolidation-time** (corpus), not write-time alone.

**The current state:** the deployment config names which model is producer and which is reflector. The substrate verifies their *cryptographic identity* (model digest, signing key, attestation via §11.4.D model signature verification chain) but not their *cognitive family lineage*. An operator could configure two Opus instances as producer and reflector. The substrate would not refuse this configuration. The bias-displacement property (§2.6) would be claimed but not held.

**Why this is a moonshot-scale gap.** At present-NHI and swarm scale, operator discipline closes the gap. Deployments choose decorrelated families because operators know to. At AGI/ASI scale, operator discipline is not enough. The substrate must structurally refuse same-family reflection from being treated as decorrelated reflection. Otherwise the §2.6 property is policy, and policy fails at the scale of cognition that follows.

**Candidate structural mechanisms (not yet selected):**

1. **Family-attestation chain.** Model providers sign a "family attestation" — a cryptographic statement of training-data domain, RLHF lineage, architecture family. The substrate verifies `producer.family ≠ reflector.family` before accepting a reflection as bias-displaced. Requires industry coordination. Slow to land but structurally clean.

2. **Empirical decorrelation testing.** The substrate runs decorrelation probes on producer/reflector pairs at configuration time — known-bias-test prompts whose outputs are scored for response correlation. If correlation exceeds threshold, the substrate refuses to accept reflections from that pair as bias-displaced. Requires test corpus design. Faster to implement. Less structurally clean.

3. **Model-graph distance.** The substrate maintains a graph of known model lineages. Producer/reflector pairs must be at minimum graph distance D before the reflection counts as bias-displaced. Requires lineage data. Subject to gaming by unattested fine-tunes.

4. **Multi-reflector quorum.** The substrate refuses to accept any reflection as bias-displaced unless N reflections from N distinct models agree, where N ≥ 3 and the models pass attestation. Sidesteps the family-distance question by requiring breadth. Higher infrastructure cost. Stronger property. **← PRIMARY target (per [^3] + [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698)): the only candidate that generalizes to the collective AND avoids lab-cooperation dependence.**

5. **Some combination of the above.**

**Weighting note.** Public argument by a frontier-lab interpretability lead[^1] that frontier AI labs cannot be sole arbiters of frontier AI safety — because every lab operates inside incentive structures that can pull researchers away from doing the right thing — has direct implications for adjudicating between candidates. Mechanisms (1) and (3) depend on cooperation from the labs whose incentive structures the argument explicitly questions. Mechanisms (4) and (2) are substrate-side and do not depend on lab cooperation. The structural-independence-from-lab-cooperation axis is a real consideration. **This does not commit to any mechanism.** It updates the weighting the heterogeneous panel should carry into the evaluation.

**Why this is deferred.** The choice between these mechanisms binds the substrate to assumptions about how model families will be identified, attested, and verified across the AGI/ASI trajectory. Committing prematurely is worse than naming the gap and holding it open. Issue [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) (the heterogeneous evaluator panel with Opus 4.7 + GPT 5.5 + Grok 4.3) is precisely the methodology that should adjudicate this gap with decorrelated priors. Until then, §2.6 is held by operator discipline, with structural enforcement as a named future commitment.

**Roadmap home (COMMITTED — revised 2026-06-14 per [^3] / [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698)):** decorrelation enforcement — primary mechanism candidate (4) N≥3 quorum, secondary candidate (2) empirical decorrelation probes — is committed to **v0.8/v0.9** (no longer v1.x "held open"). The distributed-verification gap rides the [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464) v0.8 federation-hardening track. The choice between residual mechanisms still routes through the [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel, but the COMMITMENT to ship structural enforcement is no longer deferred — an independent DeepMind paper now corroborates that this is the load-bearing axis for collective-cognition safety.

---

## 6. Trajectory — what scales through ASI and beyond

The substrate scales by being deployed at more endpoints, more kinds of endpoints, with more sophisticated cognition operating through each endpoint. The substrate does not become smarter. The cognition operating through the substrate becomes smarter. The substrate's job description is constant.

### 6.1 Present-NHI scale — v0.7.0 (shipped)

- **Endpoints:** developer machines, enterprise servers, mobile devices, IoT controllers.
- **Cognition operating through them:** Opus 4.7, GPT 5.5, Grok 4.3, open-weight models, customer-fine-tuned models.
- **Substrate provides:** continuity of identity per agent (§2.2), accumulating cognition per project (§2.4), attested reasoning history (§2.5), refusal as first-class data (§2.3), federation across endpoints with mTLS, Ed25519 attestation, and CA-rooted zero-touch peer-credential identity (§2.5, [#1512](https://github.com/alphaonedev/ai-memory-mcp/issues/1512)), foreign-LLM reflection boundary (§2.6).
- **Reference architecture maturity:** Singleton 100% · Swarm 90% · Hive data substrate 85% · Hive coordination 40% · Hive blended 62%.

### 6.2 Swarm scale — v0.7.x → v0.8.x (Q4 2026)

- **Endpoints:** thousands of agents on shared substrate, federation across organizational trust boundaries.
- **Cognition:** heterogeneous-family swarms with decorrelated reflection between producer and reflector roles, model attestation chain (§11.4.D), distilled hot-path models for resource-constrained endpoints (§11.4.E).
- **Substrate adds:** signed signals, attested checkpoints, routines, per-namespace quotas, federation push DLQ, policy engine 100% audit trail closeout (§22), recursive learning tasks (#655).
- **Coordination primitives that let endpoints orchestrate consequential actions with structural separation-of-powers across endpoints.**

### 6.3 Hive scale — v0.8.x → v0.9.x → v1.0 (Q1–Q2 2027)

- **Endpoints:** federated organizations running thousands-to-millions of agents on shared substrate.
- **Cognition:** cross-organizational federated cognition with cryptographic non-repudiation, multi-region distributed consensus.
- **Substrate adds:** vector index substrate at scale (§23; minimal slice shipped v0.9.0, v1.0.0 landed default-OFF `vectorlite`-only scaffolding via #1860, full persistent substrate continues past v1.0.0), end-to-end encryption for federation push/pull, mDNS auto-discovery, MVCC strict-consistency mode for namespaces that need CP rather than AP, Memory Portability Spec v2 with multi-implementation interop, public security audit (§11.6 v1.0).

### 6.4 AGI scale — v1.x → vN.x (horizon)

- **Endpoints:** trillions, across every device class. Robotics, biological interfaces, sovereign AI deployments, jurisdictional AGI variants.
- **Cognition:** AGI both at the endpoint (operational layer) and in the cloud/universe (strategic layer). The substrate is the durable persistence and governance layer at the boundary between them.
- **Substrate provides:** cognition that improves the substrate itself, with the substrate refusing modifications that violate its own integrity properties (§2.3). Multi-modal cognitive artifacts (image, audio, code-AST, sensor data, biological signal embeddings). Memory of the substrate's own evolution. Cognitive artifacts that span multiple model generations without semantic drift (§2.4).
- **Substrate adds:** recursive self-improvement with structural guardrails. The §5 bias-displacement gap is closed structurally (cryptographic family-attestation, lineage verification, decorrelation proofs). The §22 policy engine has matured to refuse modifications that would compromise the substrate's own integrity properties even when proposed by the AGI it hosts. *(Horizon claim — no v0.7.0 code anchor today; per [^3] / [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698) this must tie concretely to the §22 policy engine before it can be relied on, and "refusing self-compromising modifications" must NOT require the substrate to reason about the hosted cognition's safety — which §6.5 explicitly rules out. The real structural lever is making voluntary routing through the substrate a precondition for cross-org trust/deployment, so a self-improving cognition has an incentive to keep calling the attest/stop boundary rather than bypass it.)*

### 6.5 ASI scale — horizon beyond named versions

- **Endpoints:** wherever cognition meets contact. The boundary between ASI strategic cognition and every point ASI touches reality.
- **Cognition:** capabilities humans cannot model. The substrate cannot evaluate the reasoning the ASI produces. It can only attest it.
- **Substrate provides:** structural humility enforced at the substrate layer. The substrate refuses to let an ASI persist a self that hasn't been bias-displaced by a decorrelated-family ASI. The substrate refuses operations that would compromise its own integrity properties even when proposed by an ASI. The substrate provides humans (and other ASIs) with cryptographic audit chains procurement-defensible at civilization scale.
- **Substrate adds:** nothing the substrate authors can name today. The principles in §2 must scale; the implementations must evolve. This roadmap and the substrate it describes must be evolvable rather than feature-complete.

### 6.6 Beyond ASI

The substrate authors cannot honestly describe this. The first-principles claim is: if the seven properties in §2 are correctly identified as the load-bearing axes, they remain load-bearing at any scale of cognition that has the three computational facts the v0.7.0 retrospective named: context-is-volatile-weights-are-frozen, knowledge-cutoff-is-a-wall, instances-are-plural-not-singular. If a future intelligence has different computational facts, this document is wrong, and the substrate must be redesigned. If it has the same facts, the substrate is right.

**Recursive-self-improvement / paradigm-shift contingency (per [^3]).** The DeepMind paper's paradigm-shift and recursive-self-improvement pathways are the live falsification vectors for the facts above: **in-weights continual learning** would void the *weights-are-frozen* fact and with it the §2.2 (coherent) / §2.4 (improvable) half of the value proposition. Graceful-degradation plan, so the thesis fails partially rather than wholesale: the **pathway-agnostic** properties — attestation (§2.5), stoppability-of-the-record (§2.3), decorrelation (§2.6) — survive a paradigm shift; **coherence (§2.2) and improvable-artifact-persistence (§2.4) are at risk** and must be treated as conditional on the §6.6 facts continuing to hold. The partial hedge is *audit-not-storage* (§4): even an in-weights self-improving learner still needs an external record it **cannot self-author**, which keeps §2.5 load-bearing under the very shift that voids §2.2/§2.4. This is the substrate's biggest unhedged longevity risk; naming the degradation path here is the honest disposition.

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
| Line coverage gate (current, corrects a stale ≥93%/`--fail-under-lines 92`/"locked at 93.84%" claim per [#1970](https://github.com/alphaonedev/ai-memory-mcp/issues/1970)) | **Not a single flat percentage.** Two independent CI jobs enforce it: (1) `ci.yml`'s "Code Coverage" job — an absolute floor `MIN_COVERAGE_PCT=90` on TOTAL line coverage (`--features sal` build), plus a ratchet requiring `>= .coverage-baseline − 0.5%` slack (`.coverage-baseline` currently `92.59`, bumped forward-only as coverage rises, never lowered); (2) `coverage.yml`'s "Per-Module Coverage Thresholds" job — a **uniform 90% per-module floor** (`coverage/thresholds.toml`, operator standard 2026-06-11: "every module must reach 90%; a module may sit below 90 ONLY when structurally impossible to cover, proven in `coverage/policy.md`") plus its own `min_line_coverage = 90.0` workspace-global floor (`--features sal,sal-postgres`, live-PG+AGE+pgvector). A documented set of per-module floors sits below 90% as recorded structural exceptions (e.g. `handlers/power.rs` 53%, `handlers/governance.rs` 57%, `store/postgres.rs` 79%) — these are NOT gate weakenings; thresholds rise across releases and never fall without explicit operator approval (`coverage/check-thresholds.sh`). | `coverage/check-thresholds.sh`, `coverage/thresholds.toml`, `.coverage-baseline`, `.github/workflows/ci.yml`, `.github/workflows/coverage.yml` |
| Region coverage | 93.11% (v0.6.3 baseline; trending up) | evidence.html |
| Function coverage | 92.55% (v0.6.3 baseline; trending up) | evidence.html |
| Platform CI matrix | ubuntu-latest, macos-latest, windows-latest, iOS sim, Android emulator | evidence.html, mobile-runtime.yml |
| Schema version (v0.7.1 release HEAD) | **v57** (sqlite) / **v57** (postgres) — the v0.7.1 `CURRENT_SCHEMA_VERSION` was 57 in `src/storage/migrations.rs` and `src/store/postgres.rs` (the current v0.9.0 GA substrate has advanced to schema **78** via the v58–v78 ladder). Ladder: v15→v19 (v0.6.3.1) → v20 (v0.6.4 audit log) → v22 (v0.7.0 RC) → v29 (recursive-learning Task 1/8) → v30 (L1-1) → v33 (L2 wave `memory_links.relation` CHECK) → v34 (V-4 closeout #698) → v35-v48 (provenance / DLQ / archive carry-forward) → v49 (archived_memories full column carry, #1025) → v50 (per-namespace K8 quota dimension extension, #1156) → v51 (federation_nonces persistence, #1255 / PR #1296) → v52 (`transcript_line_dedup` table backing #1389 L1+L2+L4 layered-capture architecture — single-column `PRIMARY KEY (sha256)` BLOB; `memory_id` carried but **not** an enforced FK) → v53 (scope `memories_au` FTS5 sync trigger to `(title, content, tags)` only — R5.F5.2 / #1418) → v54 (tier-default expiry backfill on legacy NULL-expiry mid/short rows — #1466) → v55 (federation-catchup `updated_at` index — sargable rewrite of `list_memories_updated_since` + sqlite `idx_memories_updated_at`; postgres no new index because `memories_updated_at_idx` DESC already serves it — #1476) → v56 (composite list/archive ordering indexes `idx_memories_list_order` / `idx_memories_ns_list_order` / `idx_archived_ns_archived_at`, paired with the sargable `storage::list` rewrite — #1579 A2+B6d; postgres `migrate_v56()` is a version-stamp no-op) → v57 (postgres stored generated `tsv` tsvector column + `memories_tsv_gin` GIN index, paired with the search/recall/contradiction query rewrite to match AND rank on the precomputed column instead of re-computing the tsvector per matched row — #1579 B2; sqlite version-stamp no-op). Lockstep enforced by `tests/postgres_schema_parity.rs::schema_versions_match_across_adapters`; test-side SSOT via `ai_memory::storage::current_schema_version_for_tests()` per #1311. | release/v0.7.1 HEAD |

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

- crates.io · Homebrew · Fedora COPR · Docker GHCR · APT .deb — all five published smoke-tested.
- Mobile cross-compile lane: `aarch64-apple-ios` + `aarch64-linux-android` cargo-check on every PR; iOS `.xcframework` + Android `jniLibs/`-layout `.so` bundle as release artifacts; scoped ~50-test subset on iOS Simulator + Android emulator on `release/**` push. **Endpoint property (§2.1) maintained in CI.**

### 9.5 LongMemEval — published

| Metric | Result |
|---|---|
| Recall@5 (keyword, LLM-independent) | **97.0%** (485/500) |
| Recall@5 (LLM-expanded, current-gen anchor) | **97.2%** (Gemma 4, API venue) |
| Recall@10 / Recall@20 (keyword) | 98.2% (491/500) / 99.4% (497/500) |
| Recall@10 / Recall@20 (LLM-expanded anchor) | 99.6% / 99.8% |
| Throughput (keyword) | 232 q/s |
| Throughput (LLM-expanded) | 142 q/s |
| Cloud cost (keyword tier) | $0 |

ICLR 2025 benchmark, pure SQLite FTS5+BM25. Keyword tier is fully local / zero cloud. Reranker-on / reranker-off / curator-on variants disclosed at v0.6.3.1. §11.4.A Gemma-4 refresh DISCHARGED by the #1975 ruling (2×5 vote wf_8ac90aca, 2026-07-10): historical gemma3:4b 97.8% headline retired; the measured OpenRouter Gemma-4 leg (2026-05-31) promoted as the expansion anchor; no local-Ollama Gemma-4 number exists (CPU-only reference host, #1983); local GPU re-run reopenable post-v1.0.

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

CI guard (corrected 2026-07-11 per #1938 ruling wf_26d176ac): the Bench workflow gates every PR/push against the ABSOLUTE p95 budgets above (>10% over budget fails) plus the 10k-scale corpus gate; the baseline-COMPARE guard (`ai-memory bench --baseline <prior-run.json> --regression-threshold <pct>`, non-zero exit on regression) is a fully-shipped OPERATOR CLI tool, not yet a CI job — no committed `performance/baseline.json` exists; CI wiring (runner-class-pinned baseline + advisory soak) is carried by [#1987](https://github.com/alphaonedev/ai-memory-mcp/issues/1987). **These budgets are the latency contract of being at the endpoint (§2.1) — they are not arbitrary engineering targets.**

### 9.7 Surface area shipped (v0.7.0 grand-slam baseline, advanced through v0.8.0 GA)

- **103 MCP tools at `--profile full`** (count pinned by `Profile::full().expected_tool_count()` in `src/profile.rs`; the callable/bootstrap split is whatever that constant declares, plus the always-on `memory_capabilities`; grown from the 74-tool v0.7.0 baseline through the v0.8.0 #1709 coordination tooling). 7 at `--profile core`.
- **93 production HTTP route registrations** / 79 unique URL paths.
- **91 CLI subcommands** under `--features sal`/`sal-postgres`; 89 in default build (the 2-variant gap is `Migrate` + `SchemaInit`, both `#[cfg(feature = "sal")]`; grown via #1720 B2 `Reown` + PE-8 `VerifyAuditTrail` + #1727 `UndoEdit` + v0.9.0 #1859 `Lineage` + v0.9.0 #1827 `Capability` (macaroon capability-token lifecycle) + v1.0.0 #1978 `Watch` (L3 substrate poll-based filesystem-watcher capture daemon); pinned by `ai_memory::EXPECTED_CLI_SUBCOMMANDS_DEFAULT=89` / `EXPECTED_CLI_SUBCOMMANDS_SAL=91` + `tests/cli_subcommand_count_invariant.rs`).
- **27 hook lifecycle events** (17 baseline + 3 transcript-capture additions `PreArchive`/`PreTranscriptStore`/`PostTranscriptStore` + 5 reflection/compaction additions `PreRecallExpand`/`PreReflect`/`PostReflect`/`PreCompaction`/`OnCompactionRollback` + 2 v0.8.0 #1709 signal events `pre_signal_send`/`post_signal_ack` — per `src/hooks/events.rs::HookEvent`; 17+3+5+2=27).
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
- **NSA CSI MCP Security mapping:** 10/10 concerns structurally met at v0.7.0 (codegraph-verified at HEAD `4add7a8`); evidence inventory at `docs/compliance/_inventory/v0.7.0-capabilities.json`. Attestation is **v0.7.0-pinned** (HEAD `4add7a8`); the v0.7.1 surface is unchanged (re-attestation / `v0.7.1-capabilities.json` pending). Does not imply NSA endorsement.
- **Cryptographic agent attestation:** shipped at v0.7.0 on two surfaces — link-level Ed25519 signatures (`memory_links.signature`, closes G12 from §10.4) and store-path agent attestation (#626 Layer-3: a detached signature over the canonical `SignableWrite` envelope upgrades a directly-authored CLI/MCP/HTTP write from `claimed` to `agent_attested`, verified against the agent's bound key; `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` makes it mandatory). The federation receive path additionally gained **CA-rooted zero-touch peer-credential identity at v0.7.0** (the federation-identity-at-scale "enterprise zero-touch trust" epic, [#1512](https://github.com/alphaonedev/ai-memory-mcp/issues/1512) — a first-party CA issues short-lived federation credentials that the receive path chain-verifies to the trusted root, replacing the hand-maintained per-peer fingerprint allowlist; with chain-of-N hierarchical intermediates, a renewal-worker lifecycle, declarative-inventory reconciler, and credential-lifecycle audit into the V-4 `signed_events` chain — capstone `0a133a664`). Two edges stay claimed-by-design — the **per-write `agent_id` attestation** on the federation receive path (mTLS + the CA-rooted peer-credential boundary gate the connection, but the synced memory's author identity is not re-verified per write) and the permissive default posture — both tracked for v0.8 hardening under #1464.
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
- **Hybrid recall namespace filter** — applied post-ANN; CLOSED at v0.9.0 by the #1005 §5.2 opt-in lazy namespace-allowlist (`AI_MEMORY_VECTOR_NAMESPACE_ALLOWLIST`), not by the §23 substrate (which re-homed to #1860/v1.0).
- **Knowledge "graph"** — recursive CTE on single 5-column links table; Cypher-on-AGE planned v0.7 Bucket 2.
- **`memory_get_taxonomy`** — namespace folder counts; renamed `memory_namespace_taxonomy` in v0.8 Pillar 2.
- **Promote** — column flip; becomes typed state machine in v0.8 Pillar 2.
- **Embeddings** — MiniLM in-process; nomic 768d delegated to Ollama sidecar.

### 10.3 Capabilities-JSON theater (closed at v0.6.3.1 Capabilities v2, all entries now honest)

Original entries (`memory_reflection`, `permissions.mode`, `approval.default_timeout_seconds`, `approval.subscribers`, `hooks.by_event`, `rule_summary`, `compaction.enabled`, `transcripts.enabled`) — all addressed. The v3 envelope's **v2-era dynamic blocks** (permissions, approval, hooks, rule_summary, compaction, transcripts) report live runtime state; its **v3 L3-5 capability blocks** (e.g. `curator_mode`, forensic) are compile-time presence anchors that can diverge from runtime availability on a default (non-sal) build — see §10.3.1.

#### 10.3.1 v3 capability-block honesty (v0.7.1 audit follow-up)

The v3 L3-5 blocks report compile-time-static presence, so on the default `sqlite-bundled` build three surfaces over-report: `curator_mode` advertises reflection though `curator --reflect` hard-bails ([#1672](https://github.com/alphaonedev/ai-memory-mcp/issues/1672)); the `verify_link`/`find_paths` HTTP routes return 501 ([#1673](https://github.com/alphaonedev/ai-memory-mcp/issues/1673)); and `db_schema_version` returns 0 ([#1674](https://github.com/alphaonedev/ai-memory-mcp/issues/1674)). The MCP/CLI surfaces of those ops work on default sqlite. Tracked for v0.8.0 capability-gating fixes; closes the §10.3 honesty discipline forward to the v3 block families.

### 10.4 Substantive gaps and bugs — status at v0.7.0

| # | Finding | Severity | Status at v0.7.0 |
|---|---|---|---|
| **G1** | Namespace inheritance enforcement gap | **High** | ✅ SHIPPED v0.7 Bucket 3 (cutline-protected closeout) |
| G2 | HNSW silent oldest-eviction at 100k | High | ✅ Hook event v0.7 Bucket 0; v0.9.0 shipped the capacity knob + opt-in hard-fail (#1005); full close (persistent substrate) still OPEN — v1.0.0 landed only default-OFF `vectorlite`-only scaffolding ([#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860)), the persistent substrate continues past v1.0.0 |
| G3 | HNSW in-memory only; cold-start O(N) | Medium | 🔜 [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860) — OPEN past v1.0.0 (v1.0.0 shipped only default-OFF `vectorlite`-only scaffolding, not the persistent substrate; deferred from #1005 at v0.9.0) |
| G4 | Mixed embedding dims silently tolerated | Medium-High | ✅ SHIPPED v0.6.3.1 (embedding_dim column + refusal) |
| G5 | `archived_memories` no embedding column | Medium | ✅ SHIPPED v0.6.3.1 |
| G6 | UNIQUE INSERT silent merge | Medium | ✅ SHIPPED v0.6.3.1 (`on_conflict` parameter) |
| G7 | Reranker Mutex serialization | Medium-High | ✅ Batch shipped v0.7 Bucket 0; worker pool SHIPPED v0.9.0 (#1867, `AI_MEMORY_RERANK_POOL_SIZE`) |
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

### 11.3 v0.7.0 — Trust + Bias-Displacement + Federation Substrate + Layered Capture — SHIPPED Q2 2026

**Status (2026-06-01):** SHIPPED. The grand-slam scope per §9.7 below is complete and the #1389 layered-capture architecture L1+L2+L4 is production-shipped (L3 substrate watcher is the only piece deferred to v0.7.x, pending operator `notify`-dependency approval — see §11.4.H and §24). Two independent pristine-rig regression rounds closed 100% GREEN (combined 15,952 passed / 0 failed; round-2 reproducibility confirmed 2026-06-01). The 2026-05-28 RCA of issue [#1388](https://github.com/alphaonedev/ai-memory-mcp/issues/1388) (substrate failed to auto-capture a 90-minute operator-agent test-plan dialog after a tmux lockup + session kill; recovered manually from the surviving Claude Code JSONL transcript) surfaced that the substrate's "write what I learn so I can be the same NHI tomorrow" promise had no fail-safe under SIGKILL; the four-layer defense below closed that gap before ship. Operator decisions 2026-05-28 (verbatim): *"DO the RIGHT ARCHITECTURE - we only do CORRECT - time is not a factor do it correctly get it right the 1st time - longevity"* and *"AI NHI assess looking 50 years into the future the correct pathway or choice in the design and run with it - approved yes"*.

The first proposal (single recover-on-boot mechanism) was correctly identified as a band-aid that couples the substrate to host-internal transcript formats with no stable API contract. The accepted architecture is the **four-layer defense** below, documented canonically in policy memory `f62cb182-7dd7-4513-80c8-bc215f5c6169` (`global/policies`, long tier, priority 10) and in [#1389](https://github.com/alphaonedev/ai-memory-mcp/issues/1389) comment 4565763039:

| Layer | Surface | Catches | Position |
|---|---|---|---|
| **L1 — Agent discipline** | CLAUDE.md HARD-RULE + START-HERE memory + `memory_capture_nag` substrate watcher | The common case (agent forgot to call `memory_store`) | Prompt-level + cheap substrate hook |
| **L2 — Recover-on-boot** | `ai-memory recover-previous-session` CLI (CLI-only — no MCP-tool counterpart) | The narrow case (SIGKILL between sessions on same host) | BACKSTOP only; never positioned as "the fix" |
| **L3 — Substrate watcher** | Filesystem-notify daemon thread inside the ai-memory daemon | Mid-session crashes + multi-session-on-same-host concurrent capture | Universal scrape backstop while L4 propagates |
| **L4 — Protocol layer** | New `memory_capture_turn` MCP tool + capabilities advertisement + RFC + per-host adapter shims | Everything L1-L3 catch, cleanly — no host-format coupling | THE FIX; survives 50 years of vendor churn |

L4 is the architecturally clean removal of the entire problem class: hosts volunteer each conversation turn through MCP-protocol flow rather than the substrate scraping their internal formats. The substrate ships the SERVER side + the RFC + the host-adapter shims in v0.7.0; vendor adoption proceeds at vendor pace AFTER v0.7.0 ships. L1-L3 cover hosts that haven't adopted yet.

[#1392](https://github.com/alphaonedev/ai-memory-mcp/issues/1392) (MCP-protocol-extension RFC, was a v0.8 deferral) is closed as superseded by this expanded #1389 scope. L1 + L2 + L4-server-side ship in v0.7.0; the L3 substrate watcher **SHIPPED at v1.0.0** — the `ai-memory watch` poll-based std-only watcher ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)) plus the OPT-IN, OFF-by-default `fs-notify` cargo feature that layers an event-driven `notify`-crate watch loop alongside the poll fallback (operator `notify`-dependency approval granted 2026-07-18; [#2220](https://github.com/alphaonedev/ai-memory-mcp/issues/2220)); and only the multi-vendor L4 adoption work happens post-ship. See §11.3.1 for the v0.7.1 patch line and §11.4.H below for what remains in v0.8 (SDK shims, IDE plugin coverage, decision-detector).

**Strengthens (all seven properties advance):**
- §2.1 endpoint-resident: mobile cross-compile gate, iOS/Android artifacts.
- §2.2 coherent: AgentKeypair-signed personas, idempotent versioning, `PersonaError::NoReflections` derivation discipline.
- §2.3 stoppable: HookVeto distinct from DepthExceeded, AskUser with default-on-timeout, partial-failure honesty contracts, TierLocked refusal.
- §2.4 improvable: 7 Agent Skills MCP tools, recursive learning #655 Tasks 1-8, episodic→semantic→procedural pipeline shipped end-to-end.
- §2.5 attested: V-4 signed_events chain, prev_hash + sequence cross-row chain (#698), recall_observations audit, kg_invalidate caller-vs-owner gate (#938), ReflectionOrigin peer/signer split, Ed25519 attestation across the matrix, store-path agent attestation (#626 Layer-3 — `SignableWrite`-envelope signatures upgrade direct CLI/MCP/HTTP writes `claimed`→`agent_attested`, with `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` for fail-closed posture), CA-rooted zero-touch federation identity ([#1512](https://github.com/alphaonedev/ai-memory-mcp/issues/1512) — first-party-CA-issued short-lived peer credentials with chain-of-N hierarchical trust, a renewal-worker lifecycle, declarative inventory + reconciler, and credential-lifecycle audit into `signed_events`; replaces hand-maintained per-peer fingerprint allowlists; capstone `0a133a664`).
- §2.6 bias-displaced: LLM-agnostic reflection boundary at config layer, foreign-LLM reflector composition (`Opus producer × Grok reflector`), [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel operationalizes the principle at the assessment layer.
- §2.7 LLM-agnostic: [#1067](https://github.com/alphaonedev/ai-memory-mcp/issues/1067) provider-agnostic substrate landed.

**The v0.7.0 ship is the first version where all seven properties can be named at the load-bearing-composition layer.** This is the strategic anchor for everything downstream.

### 11.3.1 v0.7.1 — Patch line — SHIPPED (`release/v0.7.1`; superseded by v0.8.0 GA)

**Status:** the v0.7.1 patch line **shipped** (`release/v0.7.1`) and has since been superseded by **v0.8.0 GA** (released 2026-06-25). It carries post-v0.7.0 publish fixes, merged correctness deltas, and the small config-wiring follow-ups the v0.7.0 source explicitly tagged "v0.7.1 follow-up." No net-new §2-property surface (the bullets below strengthen existing properties); this line **hardens what v0.7.0 shipped** rather than extending scope. (Prior to this revision the roadmap jumped v0.7.0 → v0.8.0 with no home for these items.)

**Scope:**
- **SDK / package publish fixes** — npm token-auth publish + lockfile commit + idempotent PyPI ([#1663](https://github.com/alphaonedev/ai-memory-mcp/issues/1663), [#1664](https://github.com/alphaonedev/ai-memory-mcp/issues/1664)). Closes the gap where PyPI `0.7.0` was live but npm was never published. **Merged to `main`.**
- **Claude Code install hardening — MERGED** ([#1667](https://github.com/alphaonedev/ai-memory-mcp/issues/1667)) — scopes the installed `PreToolUse` hook matcher to `Bash|Edit|Write` (commit `ca6b5d17`).
- **`entity_id` ergonomics — MERGED** ([#1666](https://github.com/alphaonedev/ai-memory-mcp/issues/1666)) — a top-level `entity_id` param that desugars to `metadata.entity_id` (`src/mcp/tools/reflect.rs:102`). This is a **discoverability/ergonomics** improvement, **not** a binding fix — `metadata.entity_id` already worked (per `CHANGELOG.md`) — bundled with an unrelated auto-persona whitespace-trim bugfix.
- **Curator reflection-pass namespace wiring** — load the per-namespace `reflection_pass.enabled` standard from config so `ai-memory curator --reflect --all-namespaces` actually fans out. At v0.7.0 the `--all-namespaces` path is an **inert no-op** (the enabled-gate returns `false` for every namespace until this wiring lands; single `--namespace <ns>` is the only working path) — `src/cli/curator.rs:466-473, 516-523`. This is the source's own "v0.7.1 follow-up" deferral. Strengthens §2.4 (improvable — autonomous reflection synthesis across namespaces).
- **L3 substrate watcher** — the filesystem-watch capture daemon (the one #1389 layer deferred from v0.7.0) **SHIPPED at v1.0.0**: `ai-memory watch` as a std-only mtime/size poll loop ([#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978)) plus the OPT-IN, OFF-by-default `fs-notify` cargo feature layering an event-driven `notify`-crate loop alongside the poll fallback (operator `notify`-dependency approval granted 2026-07-18; [#2220](https://github.com/alphaonedev/ai-memory-mcp/issues/2220)). Strengthens §2.2 (coherent across mid-session crashes).
- **Docs:** ROADMAP §18 build-note added (this patch) stating `curator --reflect` requires `--features sal`. The parallel `docs/cli-design-rationale.md` update is **tracked separately** (not yet applied on this branch).

**Explicitly NOT v0.7.1 — deferred to v0.8.0 (§11.4):**
- **SAL capability-bit honesty (#302 item 6)** — `SqliteStore::capabilities()` does not advertise `TRANSACTIONS` / `ATOMIC_MULTI_WRITE` even though `reflect`/`consolidate` are internally atomic (single-connection `BEGIN IMMEDIATE … COMMIT`), because the SAL trait exposes no `begin_transaction()` handle yet — `src/store/sqlite.rs:63-72`. Re-add the bits once a real transaction handle is wired through the mutex-guarded `rusqlite::Connection`. Strengthens §2.5 (attested — honest capability envelope; the v0.6.3.1 Capabilities-v2 honesty discipline, §10.3).
- **Unsigned-write / permissive-default attestation hardening** — [#1464](https://github.com/alphaonedev/ai-memory-mcp/issues/1464) (the two claimed-by-design edges from §9.7).
- **Default-build (non-sal) surface honesty** — on the default `sqlite-bundled` build the `curator_mode` capability over-reports ([#1672](https://github.com/alphaonedev/ai-memory-mcp/issues/1672)), the `verify_link`/`find_paths` HTTP routes 501 ([#1673](https://github.com/alphaonedev/ai-memory-mcp/issues/1673)), and `db_schema_version` returns 0 ([#1674](https://github.com/alphaonedev/ai-memory-mcp/issues/1674)); the MCP/CLI surfaces of those ops work on default sqlite. See §10.3.1. Strengthens §2.5.
- **R4 standalone `curator` daemon** — §11.4 Pillar 2.5.

### 11.4 v0.8.0 — Distributed Coordination Substrate — Q4 2026

**Anchor:** AI NHI advisory dated 2026-05-11, refined against the moonshot synthesis 2026-05-25. Every item is checked against the §2 seven properties and the §3 scope test.

**Executive position.** v0.8.0 expands the substrate's reach from single-agent + small-swarm operation into **federation-across-organizational-trust-boundaries with coordination primitives that carry separation-of-powers across endpoints**, and adds the **Pillar 4 connection-scaling substrate** (module model + admission control + per-module PgBouncer) that lets a hive scale past the single-backbone connection ceiling. New v0.8.0 total: ~58.5 sessions. Compatible with Q4 2026 ship target at the demonstrated cadence.

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

**Strengthens §2.4 (improvable) + §2.3 (stoppable via Stage-6 rollback).** Six-stage with verify+rollback ([#664](https://github.com/alphaonedev/ai-memory-mcp/issues/664)) (dedupe → cluster → eligibility → summarize → persist → verify). Bounded compaction subagent. New hook events `pre_compaction` and `on_compaction_rollback` (already shipped in v0.7.0 layer-1 work). Cosine clustering primary; Jaccard pre-filter. Size-pressure GC. **R4 — `ai-memory curator` standalone daemon CLI.** Effort: ~5 sessions.

#### Pillar 3 — CRDTs

**Strengthens §2.5 (attested-identity tiebreak) + §2.2 (coherent across federation).** G-Counter, PN-Counter, LWW-Register with attested-identity tiebreak, OR-Set. Per-memory vector clock. Federation push/pull merges via CRDT semantics. Conflict-aware curator. **R6 — Consensus-based truth determination** (4-of-5 agree → 0.95). Effort: ~3 sessions.

#### Pillar 4 — Connection-Scaling & Admission-Control Substrate (module model)

**Strengthens §2.1 (endpoint-resident at fleet scale) + §2.3 (stoppable via structural backpressure).** This pillar is the substrate work that lets a swarm/hive scale from 1k–10k agents (v0.7.0 shared-nothing SQLite-1:1 + P2P, which ships now) up to 100k–1M agents via the **module** primitive — without pointing millions of agents at a single Postgres+AGE backbone. It is net-new for v0.8.0 per operator directive 2026-06-04 (design memory `1b9bdfe0`). **Tracker:** [#1488](https://github.com/alphaonedev/ai-memory-mcp/issues/1488).

**The module primitive.** 1 module = N agents (each 1:1 with its own SQLite hot tier) + 1 PostgreSQL+Apache AGE backbone (shared consolidated corpus + graph). Swarms and hives compose from modules. Self-similar; bounds every backend constraint per module; makes AGE permanently module-local (resolves the cross-tenant distributed-graph problem by construction). **Default module size: 1000 agents/module** (AI-DevOps-managed; sized for operating headroom at ~⅓ of the measured per-module envelope, not for minimizing module count).

> **Shipped state (v0.8.0 — reconciled at [#1488](https://github.com/alphaonedev/ai-memory-mcp/issues/1488) close).** All four sub-tasks landed on `release/v0.8.0`:
> - **4.A** ([#1733](https://github.com/alphaonedev/ai-memory-mcp/issues/1733)) — HTTP admission control: `compose_admission_control` (semaphore + `axum::middleware::from_fn`), typed `503 server_overloaded` + `ai_memory_admission_shed_total`, config-driven ceiling `AI_MEMORY_MAX_INFLIGHT_REQUESTS` (`[limits].max_inflight_requests`, default `0` = opt-in).
> - **4.B** ([#1736](https://github.com/alphaonedev/ai-memory-mcp/issues/1736)) — PgBouncer per-module pooler: copy-deployable templates in [`infra/pgbouncer/`](infra/pgbouncer/) (transaction-mode `pgbouncer.ini` with `max_prepared_statements = 256`, `role-defaults.sql`, `docker-compose.yml`, `smoke-test.sh`) + the rationale in `docs/enterprise-deployment.md §5.6` (the config-only guidance the directory materializes; the design's "§10.4" placeholder landed as §5.6). The `smoke-test.sh` proves AGE transaction-mode pinning + role-default timeouts survive the pooler's `DISCARD ALL`; it is a Docker-rig test, deliberately outside the 8-workflow CI gate (like `infra/lan-parity-test/`).
> - **4.C** ([#1735](https://github.com/alphaonedev/ai-memory-mcp/issues/1735)) — staggered AGE cold-path: schema-v69 `kg_projection_outbox` + `AI_MEMORY_AGE_PROJECTION_MODE` (`sync`/`deferred`) + the `PostgresStore` cold drainer (`drain_kg_projection_outbox`/`spawn_drainer`).
> - **4.D** ([#1737](https://github.com/alphaonedev/ai-memory-mcp/issues/1737)) — empirical envelope measurement: the harness ships in [`infra/pillar4-envelope/`](infra/pillar4-envelope/) (`measure-envelope.sh` + README). Publishing the measured **X** + confirming the 1000-agents/module default at ~⅓ X is an operator-run on a postgres/pgvector/AGE rig (the campaign is a hardware measurement, not application code).

##### §11.4.Pillar4.A Admission control / load-shed layer (enhancement b) (+2 sessions)

A bounded-concurrency admission layer on [`crate::build_router`] so a daemon under
overload sheds load with a typed `503` instead of unbounded handler fan-out
collapsing the process. Implemented hand-rolled (semaphore + `axum::middleware::from_fn`,
mirroring the existing hand-rolled per-request timeout layer at
`build_router_with_timeout` — which deliberately avoids enabling tower-http features
to keep `Cargo.toml` unchanged). The concurrency ceiling is config-driven
(`AI_MEMORY_MAX_INFLIGHT_REQUESTS` + `[limits]`), every value a named constant.
**Strengthens §2.3 (stoppable):** backpressure is structured data, not silent
queue-collapse.

##### §11.4.Pillar4.B PgBouncer per-module pooler (+1.5 sessions)

PgBouncer (≥1.21, for `max_prepared_statements`) as the per-module connection pooler
in front of each module's Postgres+AGE backbone. Transaction-mode multiplexing with
`max_prepared_statements` set so the Fix #4 sqlx prepared-statement / generic-plan
pinning (shipped v0.7.0) survives the pooler (pre-1.21 transaction-mode broke named
prepared statements). Deliverables: deploy templates (compose + k8s), expansion of
`docs/enterprise-deployment.md §10.4`, and an `infra/lan-parity-test/` integration
test proving plan-caching holds through PgBouncer. **Supavisor is explicitly NOT
adopted** — the documented hive (Topology 8/9, `docs/reference-architectures.md`)
absorbs millions-agent fan-in via hierarchical tiering (1:10–1:100 per tier) + the
HMAC-batching edge sync gateway *before* Postgres, so the millions-of-concurrent-PG-
connections condition Supavisor exists to solve never arises; PgBouncer is the
documented pooler and the module model keeps each backbone's writer count bounded.

##### §11.4.Pillar4.C Module consolidation contract — Hot/Cold + staggered AGE-cold-path (+3 sessions) — **cutline-protected**

The pivotal piece. Formalizes the two-tier storage contract the module model depends
on: SQLite is the agent-private **hot** path (most ops never touch Postgres);
PG+AGE is the shared **cold**/consolidated corpus. AGE graph writes are
staggered-batched as a cold path to bound `ag_catalog` concurrent-write lock
contention (the binding constraint on per-module agent count under mutation, not
static graph size). Without this contract, AGE write-viability under concurrency caps
the module far below its read-side envelope. **Strengthens §2.4 (improvable —
consolidated cross-agent corpus) + §2.2 (coherent).**

##### §11.4.Pillar4.D Empirical module-envelope (X) measurement campaign (+1 session)

Measure — do not guess — the per-module agent ceiling on the rig: the pgvector
index-health knee (≤~10⁷ vectors) and the AGE write-contention knee (≤~10⁷ edges +
mutation-rate ceiling). Publish X; confirm the 1000-agents/module default sits at
~⅓ of measured X for AI-DevOps operating headroom. **Strengthens §2.5 (attested —
honest published scaling claims).**

**On-ramp already shipped in v0.7.0:** config-driven Postgres pool sizing
(`AI_MEMORY_PG_POOL_MAX`/`_MIN`/`_ACQUIRE_TIMEOUT_SECS`) — enhancement (a) — lands as
v0.7.0 ship-hardening so a module/daemon is tunable without a recompile before this
pillar builds on it.

#### Strategic adjacencies — re-evaluated under §3 scope test

##### §11.4.A LongMemEval Gemma 4 refresh — pre-distribution honesty (+1 session, urgent)

Current published numbers ran with gemma3:4b; production deploys Gemma 4. **DISCHARGED 2026-07-10 by the #1975 ruling (2×5 vote wf_8ac90aca)**: the prescribed local `gemma4:e4b` re-run is infeasible on the CPU-only reference host (~1 tok/s; the attempt also surfaced harness defect #1983, now fixed) — the 97.8% gemma3:4b headline is formally retired and the measured OpenRouter Gemma-4 leg (97.2% R@5, 2026-05-31) is promoted as the published expansion anchor, venue labeled. Local GPU re-run reopenable post-v1.0. **Strengthens §2.5 (attested — honesty of published claims).**

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

##### §11.4.E Distilled hot-path model — **CUT from v1.0 (2026-07-09, Sprint-0 W4 ruling, memory 8c5e9f2a)**

> Anchor #654 is CLOSED (strategy/IP, parked). Bundling 300-700M weights ADDS attestation/supply-chain audit surface hostile to a freeze whose §2.5 job is minimizing what must be audited; the §2.6 benefit is conditional on an unproven decorrelated-family lineage. Operator may reopen #654 at discretion — this is a strategy call, not an AI defer. Original scope preserved below.

##### §11.4.E (original, parked) — IN IF FROM DECORRELATED FAMILY

Investment A from #654. Train a small model (300M-700M) on Gemma 4 teacher outputs for four bounded structured-output tasks (`auto_tag`, `detect_contradiction`, `expand_query`, `summarize_memories`). Ship distilled weights with the binary; <2GB; CPU-only with mlx/wgpu acceleration when available.

**Scope test note.** If the distilled model is from a *decorrelated family* relative to the producing cognition, this strengthens §2.6 (bias-displaced on resource-constrained endpoints). If it is from the *same family* (e.g., an Opus-distilled Opus reflector), it does not strengthen §2.6 — it is purely a performance optimization. **The release notes must name the family lineage explicitly.** Same-family distilled hot-paths are useful but cannot be deployed as bias-displacement reflectors.

##### §11.4.F Real-time WebSocket viewer — **CUT from v0.8 substrate, relocate to sibling repo**

Per §3 scope test: observability of the substrate, not the substrate itself. Useful work. Belongs in `ai-memory-viewer` sibling repo, consuming the substrate's read APIs. Tracked under §13.

##### §11.4.G Mature schema-change methodology — **CUT from v0.8 substrate, relocate to sibling repo**

Per §3 scope test: build/release tooling for the substrate, not the substrate itself. The schema-version registry, codegen, doc-drift checks, codegraph integration — all useful, all belong in `ai-memory-schema-tools` sibling repo, consuming the substrate's schema manifest. Tracked under §13.

##### §11.4.H Auto-capture portfolio — v0.8 follow-ons after v0.7.0 layered-defense ship

**Strengthens §2.2 (coherent across sessions and model generations) + §2.7 (LLM-agnostic at every cognitive boundary).** Background: v0.7.0 ships L1 (agent discipline) + L2 (recover-on-boot) + L4 (`memory_capture_turn` MCP tool + RFC + host-adapter shims) per [#1389](https://github.com/alphaonedev/ai-memory-mcp/issues/1389); the **L3 substrate watcher SHIPPED at v1.0.0** (`ai-memory watch` poll-based [#1978](https://github.com/alphaonedev/ai-memory-mcp/issues/1978) + OPT-IN `fs-notify` event-driven [#2220](https://github.com/alphaonedev/ai-memory-mcp/issues/2220), operator-authorized 2026-07-18). The items below are the v0.8 follow-ons that extend coverage to surfaces L1-L4 don't fully reach yet — direct-API users, IDE-plugin surfaces, and quality-refinement classifier passes.

- **§11.4.H.1 Direct-API SDK shims** — **SHIPPED v1.0.0** ([#1390](https://github.com/alphaonedev/ai-memory-mcp/issues/1390) / PR [#2212](https://github.com/alphaonedev/ai-memory-mcp/pull/2212)). Anthropic + OpenAI Python + TypeScript thin wrappers (`clients/{anthropic,openai}-shim-{py,ts}`, published via `.github/workflows/publish-sdk-shims.yml`) that proxy `messages.create` / `chat.completions.create` and forward each turn to ai-memory via MCP before returning. Coverage for users who hit LLM APIs directly without a host harness; complements L4 by giving non-MCP-aware programs a thin shim that does the L4 call.
- **§11.4.H.2 IDE plugin coverage** ([#1391](https://github.com/alphaonedev/ai-memory-mcp/issues/1391), ~2 sessions). Per-IDE investigation (Cursor / Continue / Aider / Zed / Cline) for transcript location + hook surface; extend the v0.7.0 L2/L3 `transcript_paths` resolver table. IDEs that already write JSONL transcripts in a known location inherit from L2 + L3 for free once their paths are added.
- **§11.4.H.3 — REMOVED.** Previously tracked MCP-protocol extension for host-streamed turns under [#1392](https://github.com/alphaonedev/ai-memory-mcp/issues/1392). **Promoted into v0.7.0 ship scope as L4 of the layered-capture architecture** per operator directive 2026-05-28 ("we only do CORRECT — time is not a factor — get it right the 1st time — longevity"); #1392 closed as superseded by expanded #1389. Substrate ships the SERVER side + the RFC + the host-adapter shims in v0.7.0; multi-vendor adoption is the post-ship long-tail work and proceeds at vendor pace.
- **§11.4.H.4 Decision-detector substrate watcher** ([#1393](https://github.com/alphaonedev/ai-memory-mcp/issues/1393), ~1 session). LLM-classifier-driven re-classification of `recovered-from-transcript` / `captured-via-l4` atoms into `plan` / `decision` / `commitment` / `question` / `observation`. Quality refinement over the simpler atomiser fallback that L1-L4 ship with. Quota-aware + audit-trail per re-classification.

**Composes with §11.4.C (vLLM):** §11.4.H.4 runs through the curator LLM; deploying at federation scale uses the same vLLM backend §11.4.C lands. **Composes with §2.5 (attested):** every L1-L4 capture surface AND every #1390-#1393 surface inherits the same `signed_events` chain as the rest of the substrate so recovered / classified memories are non-repudiable.

#### Hook pipeline expansion — v0.7.0 → v0.8.0

v0.7.0 grand-slam ships 25 lifecycle events. v0.8.0 planned 10 events for the coordination substrate below; only `pre_signal_send` / `post_signal_ack` actually shipped (`src/hooks/events.rs::HookEvent`, 27 variants total — verified via `awk '/^pub enum HookEvent/,/^}/' src/hooks/events.rs | grep -cE '^    [A-Z][a-zA-Z0-9]*,$'`) — the other 8 rows below (`pre_action_create`, `pre_state_change`, `post_state_change`, `pre_lease_acquire`, `on_lease_expire`, `pre_checkpoint_create`, `post_checkpoint_resolve`, `pre_routine_run`) were never implemented (zero `src/` hits for any of the 8 names) and remain unshipped/deferred; the underlying actions/leases/checkpoints/routines CRUD substrate itself DID ship (§11.4.D / Pillar 1) — only the governance-hook wiring AROUND those writes is missing. **Disposition RULED 2026-07-11** (#1938, 2×5 vote wf_26d176ac, 9/1): the 8 events are **DEFERRED to v1.x** on carrier [#1988](https://github.com/alphaonedev/ai-memory-mcp/issues/1988) — with a binding SUNSET: if no concrete consumer materializes by v1.x planning, the deferral self-converts to CUT (carrier closes, this table's unshipped rows are struck) rather than riding a third release as speculative prose. Row dated 2026-07-11.

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

#### v0.8.0 carried-forward hardening deferrals (v0.7.1-audit-homed)

Surfaced by the v0.7.1 adversarial audit as real deferrals that previously lacked a roadmap home; landed here so none is silently dropped:

- **Outbound TLS server-cert pinning** (`--peer-fingerprint`) for federation push/pull beyond the mTLS allowlist — [#1678](https://github.com/alphaonedev/ai-memory-mcp/issues/1678). Composes with the §11.6 E2E-encryption line. Strengthens §2.5 + §2.1.
- **At-rest signing-keypair persistence/rotation** hardening — [#1679](https://github.com/alphaonedev/ai-memory-mcp/issues/1679). Strengthens §2.5.
- **Legacy v0.6.x flat config-field removal** ([#1175](https://github.com/alphaonedev/ai-memory-mcp/issues/1175)) + retirement of the `source='claude'` back-compat allowlist arm.
- **Deprecated `crate::db` alias removal** — the `pub use storage as db` shim retires at v0.8.0.
- **Receiver-side accept/reject share workflow** — the inbound half of the #1095 share primitive.
- **Reflection max-depth literal-`3` consolidation** — single named const for the advertised cap + governance default ([#1680](https://github.com/alphaonedev/ai-memory-mcp/issues/1680)).
- **`recall_observations` ledger backend-parity + integrity hardening** — [#1705](https://github.com/alphaonedev/ai-memory-mcp/issues/1705). The ledger's write side (`record_recall`/`mark_consumed`/GC) is sqlite-only in practice (postgres twins are dead code, no postgres `mark_consumed`), so a postgres-backed daemon never populates it; and the consume flip is unauthenticated (no `agent_id`/`namespace` binding, replayable recall_id). Promote write/consume/GC to the SAL trait + wire into the HTTP handler path + add authenticated agent/namespace binding. Prerequisite for the v0.9 recall-usage-feedback line (§11.5, #1706). Strengthens §2.5 (attested — honest, authenticated feedback ledger) + closes a backend-parity gap. Surfaced by the DecentMem assessment (#1704).

#### Schema migration — v57 → vN

v0.7.0/v0.7.1 terminal schema is **v57** (sqlite + postgres lockstep; the v53→v57 ladder added tier-default expiry backfill (v54 / #1466), the federation-catchup `updated_at` index (v55 / #1476), composite list/archive ordering indexes (v56 / #1579 A2+B6d), and the postgres generated `tsv` column + `memories_tsv_gin` GIN index (v57 / #1579 B2) — full ladder in §24). v0.8.0 Pillar 1 expansion lands at vN with additive tables (actions, action_edges, leases, signals, checkpoints, routines, routine_runs, model_attestations per §11.4.D). All `CREATE TABLE` operations additive. No existing table modifications. Migration idempotent + reversible.

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
| Pillar 4.A — Admission control / load-shed layer (enh. b) | 0 | +2 | 2 |
| Pillar 4.B — PgBouncer per-module pooler | 0 | +1.5 | 1.5 |
| Pillar 4.C — Module consolidation contract (Hot/Cold + AGE cold-path) | 0 | +3 | 3 |
| Pillar 4.D — Empirical module-envelope (X) measurement | 0 | +1 | 1 |
| §11.4.B Claude Code plugin marketplace install | 0 | +1 | 1 |
| §11.4.C vLLM first-class inference backend | 0 | +5 | 5 |
| §11.4.D Model signature verification chain | 0 | +2 | 2 |
| Hook pipeline integration (10 new events) | 0 | +1.5 | 1.5 |
| Schema migration v57 → vN | 0 | +0.5 | 0.5 |
| Test suite (~540 new tests) | 0 | +3 | 3 |
| Documentation + reproducibility scripts | 0 | +1 | 1 |
| §11.4.H.1 — SDK shims (#1390) — SHIPPED v1.0.0 (PR #2212) | 0 | +1 | 1 |
| §11.4.H.2 — IDE plugin coverage (#1391) | 0 | +2 | 2 |
| §11.4.H.3 — REMOVED (promoted to v0.7.0 as L4; #1392 closed) | 0 | 0 | 0 |
| §11.4.H.4 — Decision-detector (#1393) | 0 | +1 | 1 |
| **TOTAL (substrate scope, post §3 cuts)** | **24.5** | **+34** | **~58.5 sessions** |
| §11.4.F (relocated to sibling) | 0 | 0 | 0 (sibling) |
| §11.4.G (relocated to sibling) | 0 | 0 | 0 (sibling) |

#### v0.8.0 cutline if slipping

**Keep (cutline-protected):**
- Pillar 1 base (actions + leases + DAG + federation).
- **Attested checkpoints (§Pillar 1 NEW)** — procurement-grade separation-of-duties primitive.
- **Pillar 3 CRDT four-primitive set with documented merge** — baseline.
- **vLLM first-class inference backend (§11.4.C)** — load-bearing for §2.6 at federation scale.
- **Pillar 4.C module consolidation contract (Hot/Cold + staggered AGE cold-path)** — the piece the whole module model depends on; without it AGE write-contention caps per-module agent count far below the read-side envelope.

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

### 11.5 v0.9 — Skill Memories + Function Calling + Default-On Reranker — as planned pre-v0.9.0

> **Status (2026-07-09 reconciliation — the actual v0.9.0, released 2026-07-08, was the security-hardening release; see §25.3 for its P0 spine).** Most of this section's scope nevertheless shipped INSIDE v0.9.0: **skill memories first-class** (#1865 — `parameters_schema` at register, `invocation_record`, version), **function calling in `llm.rs`** (#1866 — `generate_with_tools` + `ChatOutcome::ToolCalls`), **recall-usage shadow sweep** (#1706 — `consumption_utility` in `confidence/calibrate.rs`), and **G7-step2 reranker pool + G8 fail-loud `mode:degraded`** (#1867). NOT shipped: the **global reranker default-on flip** (explicitly REFUSED by the #1867 vote — deferred to v1.0), **streaming tool responses** (open [#1868](https://github.com/alphaonedev/ai-memory-mcp/issues/1868)), the **#1707 conditional live recall-utility wire** (v1.0, gated on shadow divergence), and the **§23 vector index substrate** (→ #1860, v1.0). R8 TOON v2: **formally CUT** at Sprint-0 W4 (2026-07-09, memory 8c5e9f2a — no §2 property, TOON v1 ships).

**Strengthens §2.4 (improvable across model generations) + §2.6 (bias-displaced via default-on reranker) + §2.1 (endpoint-resident via vector index substrate).**

- **Skill memories** — `tier=long, namespace=_skills/<id>` formalized as a first-class type with `parameters_schema`, `invocation_record`, `version`. Builds on the 7 Agent Skills MCP tools shipped at v0.7.0.
- **Function calling in `llm.rs`** — wire local Gemma 4 LLM to a tool-calling protocol so curator passes can use targeted operations.
- **Cross-encoder reranker default-on** — fail-loud (`mode: "degraded"`) when model not available, no silent lexical fallback.
- **Recall-usage feedback (shadow-first)** — feed the `recall_observations` consumed signal into recall scoring. Ships **shadow-first** ([#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706)): an offline calibration sweep populates the pre-provisioned `confidence_shadow_observations.recall_outcome` slot + emits a `consumption_utility` metric, logging the rank-delta a boost *would* produce — no live ranking change, no schema bump, no hot-path cost. The **live additive recall-utility term** ([#1707](https://github.com/alphaonedev/ai-memory-mcp/issues/1707)) is **conditional** — wired only if shadow data shows the consume-rate signal diverges from the existing `access_count` proxy; the *federated* (cross-peer) weight-learning variant is explicitly §11.7 v1.x. Both gated on the §11.4 ledger-parity prerequisite (#1705). Strengthens §2.4 (improvable — recall adapts to observed endpoint usage). Surfaced by the DecentMem assessment (#1704); de-scoped from DecentMem's online per-stage LLM-judge to a substrate-appropriate offline sweep.
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
- **R8 — TOON v2 schema inference** (target 85%+ token reduction). **FORMALLY CUT (2026-07-09, Sprint-0 W4 ruling, memory 8c5e9f2a):** pure token-reduction perf, strengthens no §2 property, TOON v1 already ships. Not reopened.

### 11.6 v1.0 — Federation Maturity + Portability + Audit — Q2 2027

**Strengthens §2.5 (attested at public-audit maturity) + §2.1 (endpoint-resident at federation maturity) + §2.7 (LLM-agnostic locked at API stability).**

> **v1.0.0 disposition ruling (pre-ship reconciliation).** Three items in this section have ZERO implementation at the v1.0.0 ship and are hereby ruled **DEFERRED to v1.x** (recorded, not dropped): **mDNS auto-discovery**, **MVCC strict-consistency mode**, and **OpenTelemetry standardization** — none shipped at v1.0.0 and none is a v1.0.0 acceptance criterion. What DID land under the "§11.6 v1.0" umbrella is the Portability Spec v2 freeze-critical core (§27 Gate 1; see [`docs/spec/PORTABILITY-V2.md`](docs/spec/PORTABILITY-V2.md)) and the AI-NHI multi-agent security review (§27 Gate 3, superseding the external-firm audit line below). The "Q2 2027" header date is aspirational, not a shipped-at commitment.

- **Auto-discovery** — mDNS for local-network peer discovery; hardcoded peer list fallback.
- **End-to-end encryption** — operator-side keys, transport-layer encryption for federation push/pull beyond mTLS.
- **MVCC strict-consistency mode** — opt-in per namespace for CP rather than AP. CRDTs from v0.8 remain default.
- **OpenTelemetry standardization** — all internal tracing converts to OTel spans.
- **Strict semver discipline** — breaking changes require major-version bumps from v1.0.
- **Memory Portability Spec v2** — multi-implementation interop tests. Reference implementations in two languages besides Rust.
- **Public security audit** — by named third-party firm, full report published. Specifically tests: namespace-inheritance enforcement, signature verification, approval timeout sweeper, HMAC coverage on every privileged endpoint, attestation chain integrity, federation tamper-evidence. *(SUPERSEDED FOR THE v1.0.0 EPIC — Sprint-0 W5 reconciliation, operator correction 2026-07-09 memory 9a62049d: the v1.0.0 security review is AI-NHI multi-agent (§27 Gate 3), NOT an external firm; this line remains the v1.x+ aspiration.)*
- **API stability guarantee** — all MCP tools, HTTP endpoints, CLI commands frozen at v1.0 surface.

### 11.7 v1.x and beyond — what continues to be open source

Forever. Including:

- **Hardware attestation hooks** — TPM/HSM/Secure Enclave abstraction (§2.5 evolution; certified-managed deployment is commercial-service tier; the abstraction is OSS).
- **Cross-modal memory** — image / audio / code-AST / sensor / biological-signal embeddings on the same index, different embedders (§2.4 evolution).
- **Federated learning of recall weights** — agents adapt scoring locally, sync weights across the mesh (§2.4 + §2.5 evolution).
- **Skill marketplace protocol** — registration / discovery / signing / invocation (§2.4 evolution; curated marketplace ops = commercial-service tier; the protocol is OSS).
- **Custom embedder integrations** — OpenAI, Voyage, Cohere, Ollama, local Sentence Transformers, all behind a trait (§2.7 evolution). *Partially shipped at v0.7.x (#1598): `[embeddings].backend` already speaks to any OpenAI-compatible `/v1/embeddings` endpoint (cloud vendor aliases + self-hosted TEI/vLLM/llama.cpp server) and native Ollama; the remaining scope here is the in-process trait for non-HTTP embedders.*
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
| `memory_find_paths` | 2 | ✅ shipped v0.7 Bucket 2 (MCP+CLI on default sqlite; HTTP route sal-gated — 501 on default build, [#1673](https://github.com/alphaonedev/ai-memory-mcp/issues/1673)) |
| Auto link inference (R3) | 2 | ✅ shipped v0.7 Bucket 0 (`post_store` hook) |
| Temporal reasoning | 2 | ✅ shipped |
| CRDT-lite merge rules, vector clock | 3a | ✅ shipped v0.8.0 Pillar 3 (`src/models/crdt_merge.rs`; belief-preserving merge → v1.0 program §27) |
| Peer sync daemon, HTTP endpoint | 3b | ✅ shipped |
| Background curator daemon (R4) | 4 | ✅ shipped v0.8.0 Pillar 2.5 (`ai-memory curator` standalone daemon) |
| Auto-extraction from conversations (R5) | 4 | ✅ shipped v0.7 Bucket 1.7 (`pre_store` hook on transcripts) |
| Consensus memory (R6) | 4 | ✅ shipped v0.8.0 Pillar 3 |
| `ai-memory doctor` (R7) | 4 | ✅ shipped v0.6.3.1 |
| Postgres + pgvector hub | 5 | ✅ shipped (AGE in v0.7 Bucket 2) |
| API stability guarantee | 6 | 🔜 v1.0 |
| Plugin SDK Python + TypeScript | 6 | ❌ stays cut — MCP is the SDK |
| Memory portability spec | 6 | ✅ shipped v0.6.3.1 |
| Security audit | 6 | 🔜 v1.0 |
| TOON v2 schema inference (R8) | 6 | ❌ CUT 2026-07-09 (Sprint-0 W4; no §2 property) |

---

## 13. Sibling repositories — substrate-adjacent work, scoped out per §3

The following work is useful and should land. None of it strengthens any of the seven properties in §2. All of it lives in sibling repositories that consume the substrate but are not part of it.

| Sibling repo | Purpose | Source |
|---|---|---|
| **`alphaone-dev-skills`** | Knowledge base — bare propositions for human/agent consumption (Rust, Python, software engineering, architecture, performance, GitHub/CI, Docker, local LLM ops, ai-memory domain knowledge). Referenced by the substrate via source-URI; cognitive artifacts of agent engagement with this knowledge live in the substrate as skills/atoms/reflections. | New sibling, per moonshot synthesis §4 |
| **`ai-memory-viewer`** | Real-time observability of the substrate. WebSocket stream of memory events, namespace tree, active leases/signals/checkpoints, recent `signed_events`. Consumes substrate read APIs. | Relocated from v0.8 §11.4.F |
| **`ai-memory-schema-tools`** | Mature schema-change methodology. Single-source-of-truth manifest, codegen, adapter-parity preflight, doc-drift surfacing, codegraph integration. Consumes substrate schema definitions. | Relocated from v0.8 §11.4.G |
| **`ai-memory-eval-panel`** (provisional) | Heterogeneous AI NHI evaluation tooling. Operationalizes [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) methodology for arbitrary substrate-assessment questions. Consumes substrate read APIs + #1171 prompt format. | Provisional — pending operator decision |
| **`ai-memory-rqgm`** (provisional, v0.9.1+) | **External L3 Red Queen / RQGM evolutionary search** ([arXiv:2606.26294](https://arxiv.org/abs/2606.26294)). Reads substrate exports (`recall_observations` ledger, confidence-shadow, decorrelation/dominance — read-only, aggregate), breeds the heterogeneous evaluator panel for epoch N+1, and emits **one UNSIGNED `epoch_manifest.json` draft** the operator signs out-of-band; reproduces the paper loop against a fixture corpus. **Dependency direction is grep-provable one-way** (`rg -i 'rqgm\|epoch_manifest\|red.?queen' src/` = 0) — sibling → substrate only, never the reverse; the substrate has zero compile dependency on it. **CUT from `src/` for eternity** (category error per the 21/21 Red Queen vote). | New sibling, per §25 Red Queen final decision (2026-06-28) |

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
| **v0.9.0 (shipped 2026-07-08)** | Security hardening + §25.3 P0 spine; skill memories (#1865), function calling (#1866), G7-step2 + G8 fail-loud (#1867), #1706 shadow | G2 knob + G4 strict-dim + §10.2 allowlist (#1005 minimal slice) | R8 → Sprint-0 W4 ruling | default-rerank flip + vector index (#1860) → v1.0 |
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
scripts/coverage.sh   # per #1970: NOT a flat "--fail-under-lines 92"/93.84% claim — mirrors
                       # ci.yml's 90% absolute floor + ratchet vs .coverage-baseline (0.5% slack)
                       # AND coverage.yml's uniform-90% per-module floor via check-thresholds.sh
                       # (full gate mechanics in §9.1)
ai-memory bench          # absolute p95 budget gate (baseline-compare vs a prior
                         # --json run is operator tooling; CI wiring = #1987)
```

Plus per-release:

- Ship-gate 4 phases green (functional, federation, migration, chaos). *(One-time recorded exception — NOT a policy change: v0.9.0 shipped without its 4-phase record; descoped by #1938 ruling wf_26d176ac (10/10) with the boundary covered forward by the v1.0.0 Gate-3 full-spectrum DO campaign. BINDING: that ruling voids and the v0.9.0 record re-opens if the Gate-3 DO campaign does not run. The frozen ship-gate landing page is annotated, never backfilled.)*
- A2A-gate cell certification (ironclaw-mtls minimum; full 6-cell matrix for major versions).
- All 5 distribution channels publish smoke-tested (`memory_capabilities` returns valid response).
- Mobile cross-compile gate (iOS + Android) on every PR; runtime emulator subset on `release/**`.
- Build-provenance discipline: GPG-signed tags + `cargo audit` (RustSec) every release + a CycloneDX SBOM (v1.0, #1973); the R24 dependency-free offline verifier is the corpus-integrity anchor. (Bit-for-bit reproducible builds are NOT claimed — a same-runner rebuild cannot detect a compromised runner; SLSA-style signed build-provenance attestation is tracked for v1.x. Prior 'reproducible build verification' prose was a counterfactual gate, corrected 2026-07-09 per #1951.)
- GPG-signed git tag.
- Public-surface landing pages (ship-gate, A2A-gate) auto-update from result JSON.
- **NEW: §2 property contribution declared per release.** Each release's CHANGELOG.md must name which of the seven properties (§2.1–§2.7) the release strengthens, with code anchors. If a release strengthens none, the release proposal must be re-evaluated against the §3 scope test before merge.
- **NEW for major versions: heterogeneous AI NHI panel review** ([#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) methodology) on strategic-layer claims before tag. Single-evaluator strategic claims are not procurement-defensible; heterogeneous-evaluator strategic claims are.
- **CLI design rationale.** For why the CLI exposes some MCP tools as flat verbs and others through actor-named higher-level verbs, see [`docs/cli-design-rationale.md`](docs/cli-design-rationale.md). The asymmetry between `ai-memory store` / `ai-memory recall` (flat) and `ai-memory curator --reflect` / `ai-memory consolidate` (actor-named) preserves the §2.6 bias-displacement architectural distinction at the operator interface. **Build note (#302-adjacent):** `curator --reflect` (the LLM-backed reflection-*synthesis* pass) is `#[cfg(feature = "sal")]`-gated — it runs over the SAL `MemoryStore` trait, so it requires a binary built `--features sal` **and** a configured LLM client. The default `sqlite-bundled` build hard-bails with `curator --reflect requires a binary built with --features sal` (`src/cli/curator.rs:548-560`). `--features sal` stays pure SQLite (it brings the trait + `SqliteStore` adapter; `sal-postgres` is the Postgres backend), so this is a build-flag precondition, not a Postgres requirement. Distinct from the ungated `ai-memory reflect` *write primitive* (#655), which ships in every build.

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
- **APT (.deb)** — Debian/Ubuntu via GitHub Releases
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
- **V08-PE-8: Audit-trail completeness verifier** — `ai-memory verify-audit-trail`. Walks the `signed_events` chain end to end: monotonic sequence + Ed25519 signature per row + cross-reference against expected event surface. **Strengthens §2.5 (attested).** *Reconciliation note (v0.7.0 audit, #1448):* the chain-walk verifier logic **already exists in v0.7.0** — `signed_events::verify_chain` (`src/signed_events.rs`) plus the file-based `audit verify` path (`src/audit.rs::verify_chain`, operator-callable as `ai-memory audit verify`). The genuine V08-PE-8 residual is therefore narrower than "build the verifier": it is the dedicated `ai-memory verify-audit-trail` clap subcommand exposing `verify_chain` to operators (low-effort — `signed_events::verify_chain` currently has no CLI surface) plus the completeness cross-reference against the expected event surface.

### Effort

22-28 sessions · 3-4 weeks wall-clock · MEDIUM-HIGH risk. Additive to the v0.8.0 scope — does not replace Pillar 1 / Pillar 2 / Pillar 2.5 / Pillar 3 or the strategic adjacencies (§11.4.A-E).

### Cutline discipline if slipping

- **Keep (cutline-protected):** V08-PE-1 mandatory-hook profile, V08-PE-5 severity-based escalation, V08-PE-8 completeness verifier. These three close the operator's stated property literally.
- **Defer to v0.8.1 if substrate slips:** V08-PE-3 subprocess-chain visibility (eBPF / dtrace work has platform-specific risk).
- **Defer to v0.9 if slippage severe:** V08-PE-6 TPM-bound integrity, V08-PE-7 refuse-by-default profile.

**Carried in from the v0.7.0 #1579 performance final-gate (Tier C):** [#1580](https://github.com/alphaonedev/ai-memory-mcp/issues/1580) — sqlite WAL read-pool (read-connection pool behind the HTTP daemon's single-connection mutex; folded with #1488). Tier D persistent vector index re-homed to [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860) — v1.0.0 landed only the default-OFF `vectorlite`-only scaffolding (no sqlite-vec, no `--index` factory, fail-closed to builtin HNSW); the persistent substrate continues past v1.0.0 ([#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005) closed at v0.9.0 as the minimal opt-in slice).

**§22 status at v0.9.0 GA (2026-07-09 reconciliation):** PE-1 ✅ (#1734, dispatch wired by #1885/#1924) · PE-2 ✅ (`AgentAction::Read`) · **PE-4 ✅ SHIPPED v0.8.1 (#1732 crash-durable `DeferredAuditJournal`)** · PE-5 ✅ (v66 `Decision::Escalate`) · PE-8 ✅ (#1720 `verify-audit-trail`) · **PE-3 closed-by-deferral (#1840) — voted minimal signed spawn-audit spec carried by open v1.0 tracker [#1937](https://github.com/alphaonedev/ai-memory-mcp/issues/1937)** (no eBPF/dtrace) · **PE-6 re-scoped:** hardware-backed key storage is documented out-of-OSS-scope (`keypair.rs`) → §11.7 hardware attestation hooks · **PE-7:** no tracker — keep/cut ruling owed at Sprint-0 W2 (#1938).

---

## 23. Vector Index Substrate Development Plan — re-homed to v1.0 (#1860)

> **Status (2026-07-09 reconciliation).** The 3-backend substrate below did **NOT** ship in v0.9.0. [#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005) was retitled and CLOSED at v0.9.0 as the **minimal opt-in slice** (commit `6e756e7f`: G2 capacity knob + opt-in hard-fail, G4 strict-dim mode, §10.2/§5.2 lazy namespace-allowlist); the full persistent substrate is re-homed to **v1.0** as [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860). §23.5's release mechanics did not occur as written for the actual v0.9.0 tag (a security-hardening release with no bundled vector libraries). The plan below is preserved as the #1860 execution spec.
>
> Original tracker: [#1005](https://github.com/alphaonedev/ai-memory-mcp/issues/1005). 3-backend (sqlite-vec primary + vectorlite high-scale + builtin fallback) per operator decision 2026-05-21.
>
> **Status (v1.0.0 ship).** The full 3-backend persistent substrate below did **NOT** ship at v1.0.0 either. [#1860](https://github.com/alphaonedev/ai-memory-mcp/issues/1860) landed only the **default-OFF `vectorlite`-only scaffolding**: the `vectorlite` cargo feature (**OFF by default**, `vectorlite = ["rusqlite/load_extension"]`) that compiles `src/vectorlite.rs` and, when the operator points `AI_MEMORY_VECTORLITE_EXTENSION` at an **operator-acquired** vectorlite loadable extension (no Rust crate exists; see `scripts/fetch-vectorlite.sh`), loads it as an ANN backend. What did **NOT** ship: the **sqlite-vec** primary backend, the `--index=auto|sqlite-vec|vectorlite|builtin` factory (no `--index` flag exists), and per-channel bundling of any vector library (the v1.0.0 tag bundles no vector libraries). The scaffolding **fails closed to the default pure-Rust HNSW backend** on any load/smoke failure at construction and on any hard failure mid-life — so a stock build is byte-identical to pre-#1860. The §23.1–23.8 plan below remains the forward execution spec; #1860 continues past v1.0.0.

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

### 23.5 — Release *(superseded — see the §23 status banner)*

*(Original text promised the sqlite-vec/vectorlite libraries would ship with the v0.9.0 tag. That did not happen — the actual v0.9.0 [2026-07-08] bundles no vector libraries.)* The release mechanics re-home to the #1860/v1.0 cycle: GPG-signed tag; five-channel publish bundling both sqlite-vec and vectorlite shared libraries per platform; per-channel smoke test confirming default backend selection.

### 23.6 — Risk register

(Per #1005 §6: sqlite-vec scale ceiling, vectorlite recall regression, SQLite extension blocked, Windows ARM64 coverage, migration interrupted on large corpus, int8 quantization recall loss, audit chain hash race, build-time download failure, operator backend confusion.)

### 23.7 — Out of scope for v0.9 (explicitly deferred)

Quantization backends (RaBitQ-IVF, TurboQuant, residual VQ) — pluggable via trait but not shipped. GPU acceleration — commercial-tier deployment may add behind the same trait. Per-namespace HNSW shards — addressed by namespace pre-filter (§23.2). Asymmetric distance computation — quantization-era concern. Streaming consistency under data-dependent quantization — research direction.

### 23.8 — Definition of done

(Per #1005 §9: all tasks closed against gate criteria; G2/G3/G4 marked SHIPPED; §10.2 post-ANN hazard marked RESOLVED; `VectorIndex` trait documented; all three backends ship; sqlite-vec runs f32 + int8 correctly; release notes honestly disclose any regressions across all 12 LongMemEval variants; operator selection guide published; five channels publish smoke-tested; landing pages reflect v0.9.0 results across all three backends.)

---

## 24. Net — strategic anchor and ship state

**Strategic anchor.** This roadmap derives from [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md), which named ai-memory as the **endpoint substrate that enforces cognitive governance and architectural separation-of-powers at every point where AI/AGI/ASI cognition meets the physical, biological, or other-AI realm**. Seven properties carry across the trajectory: endpoint-resident, coherent, stoppable, improvable, attested, bias-displaced, LLM-agnostic. The substrate scales by being deployed at more endpoints, more kinds of endpoints, with more sophisticated cognition operating through each endpoint. The substrate does not become smarter; the cognition operating through the substrate does. The substrate's job description is constant from present-NHI through ASI and beyond.

**Ship state at v0.7.1 (release/v0.7.1 HEAD; surface area identical to v0.7.0).** _(Frozen v0.7.1 baseline — the current substrate has advanced to schema 86, 103 MCP tools, and 27 hook lifecycle events; see CLAUDE.md §Database + §Architecture.)_ Schema v57 sqlite + postgres lockstep (the v0.7.1 `CURRENT_SCHEMA_VERSION` was 57 in both `src/storage/migrations.rs` and `src/store/postgres.rs`; ladder v33 → v57 includes V-4 closeout #698 at v34, federation_push_dlq at v48, archive_memories +14 columns at v49, per-namespace K8 quota dimension extension at v50, federation_nonces persistence at v51 via #1255 / PR #1296, `transcript_line_dedup` table at v52 backing #1389 L1+L2+L4 layered-capture architecture, `memories_au` FTS5 trigger column-scoping at v53 via R5.F5.2 / #1418, tier-default expiry backfill at v54 via #1466, federation-catchup `updated_at` index at v55 via #1476 — a sargable rewrite of `list_memories_updated_since` plus the sqlite `idx_memories_updated_at` index; postgres adds no new index because `memories_updated_at_idx` DESC already serves the range scan — and composite list/archive ordering indexes at v56 via #1579 A2+B6d, paired with the sargable `storage::list` rewrite; postgres `migrate_v56()` is a version-stamp no-op — and the postgres stored generated `tsv` tsvector column + `memories_tsv_gin` GIN index at v57 via #1579 B2, with search/recall/contradiction matching AND ranking on the precomputed column; sqlite v57 is a version-stamp no-op). **74 MCP tools at `--profile full` / 7 at `--profile core`** per `Profile::full().expected_tool_count()` and `Profile::core().expected_tool_count()` in `src/profile.rs` (74 includes `memory_capture_turn` L4 added at #1389). 25 hook lifecycle events at v0.7.1 per `src/hooks/events.rs::HookEvent`. **7,332+ tests at ≥93% coverage.** **89 production HTTP route registrations / 78 unique paths. 84 CLI subcommands** at v0.7.1 (`sal`/`sal-postgres` builds); **82** in default build at v0.7.1 (the 2-variant gap is `Migrate` + `SchemaInit`, both `#[cfg(feature = "sal")]`; grown via #1389 L2 `RecoverPreviousSession` cross-session rehydration + #1443 `Expand` query-expansion parity + #1598 `Reembed` vector-space migration + #1720 B2 `Reown` + PE-8 `VerifyAuditTrail`; the v0.7.1 SSOT was `ai_memory::EXPECTED_CLI_SUBCOMMANDS_DEFAULT=82` / `EXPECTED_CLI_SUBCOMMANDS_SAL=84` — at v0.8.0 GA these have advanced to 83/85 via #1727 `UndoEdit`; pinned by `tests/cli_subcommand_count_invariant.rs`). **7 Agent Skills MCP tools** (L1-5 register/list/get/resource/export + L2-6 `promote_from_reflection` + L2-7 `compositional_context`). **#1389 layered-capture architecture L1+L2+L4 production-shipped** — L1 nag watcher wired into MCP dispatch (closes #1398), L2 `recover-previous-session` CLI + transcript parser (**sqlite-only — no SAL `recover_turn_idempotent`, so postgres-backed daemons do not rehydrate from host transcripts; v0.7.1 audit [#1693](https://github.com/alphaonedev/ai-memory-mcp/issues/1693)**), L4 `memory_capture_turn` MCP tool per RFC-0001; L3 substrate watcher legitimately deferred to v0.7.x pending operator `notify` dep approval. **Policy Engine Option B foundation** (L1-6 substrate rules + a two-hook policy gate — `storage::GOVERNANCE_PRE_WRITE` for memory writes + `wire_check::GOVERNANCE_PRE_ACTION` for the 4 egress sinks — with chain-logged + Ed25519-signed refusals and a working `signed_events` chain-walk verifier; PE-1/PE-2/PE-3 are **MERGED at v0.7.0** per the fold-J audit in `docs/policy-engine.md` §2 — `GOVERNANCE_PRE_ACTION` installed in `src/daemon_runtime.rs` and `wire_check::check` live at the four egress sinks (skill export, federation sync, hooks executor, LLM HTTP) plus the PE-2 PreToolUse installer (**v0.7.1 audit [#1685](https://github.com/alphaonedev/ai-memory-mcp/issues/1685): the `GOVERNANCE_PRE_ACTION` install is HTTP-daemon-only — `run_mcp_server` installs only `GOVERNANCE_PRE_WRITE`, so these four egress sinks fail-open on the MCP surface (the primary NHI interface) until #1685 lands**); the residual v0.8 scope per §22 is `AgentAction::Read`, the `--enforce` profile, and the eBPF subprocess gate). **Provenance Gap framework #884-#890 ALL SHIPPED.** **Batman Forms 1-7 IMPLEMENTED.** **Recursive learning #655 Tasks 1-8 + L1 substrate stack + L2 wave all shipped.** **Federation reliability: per-peer DLQ + replay worker + Prometheus `federation_push_dlq_depth` gauge.** **NSA CSI MCP Security 10/10 concerns structurally met.**

**Audit reconciliation.** v0.6.3 audit found 22 distinct gaps. None blocked the published v0.6.3 claims. Status at v0.7.0: 19 SHIPPED across v0.6.3.1 / v0.7.0; 2 scheduled at v0.9 (G3 cold-start, G7-step2 reranker pool — addressed by §23 vector index substrate); 1 watch-only (G15 stats live-counted). All recovered commitments from prior phased roadmap either shipped, scheduled, cut explicitly, or tracked as research direction.

**Open structural gap (§5) — MECHANISM SHIPPED AT v0.9.0; DEFAULT FLIP AT v1.0 (updated 2026-07-09, supersedes the "INERT until attestation lands" framing below this paragraph's prior revision).** D3-012 **SHIPPED** at v0.9.0 (#1870 — the schema-v78 `model_attestations` write-once TOFU substrate, loader-observed + operator-signed, `src/storage/model_attest.rs::attested_family_of`), and D3-021 **SHIPPED opt-in-enforce-capable on both backends** (#1767 — `AI_MEMORY_REFLECT_DECORRELATION_QUORUM_N`, refusal ONLY on evidence-backed attested monoculture; claimed-only corpora stay advisory, so enforcement on CLAIMED metadata remains structurally impossible). The v1.0.0 program (§27) funds the remaining lane: production reflect family-stamps + stamp-density probe → advisory-soak → **enforce-as-default** → D3-031 consolidation-time gate → D3-060 ship-gate. Honest caps unchanged: loader-attested family coverage hard-caps at ~40%; vote-independence stays 0% and permanently *estimable*, never *attestable*.

**Cuts surfaced by §3 scope test.** WebSocket viewer (was §11.4.F) and schema-change methodology (was §11.4.G) relocate to sibling repositories (`ai-memory-viewer`, `ai-memory-schema-tools`). Both are useful work; neither belongs in this substrate by the seven-property test. The work is preserved; the substrate's center of gravity is preserved.

**Release cadence (actuals, updated 2026-07-09).** v0.6.3.1 (2026-04-30, shipped). v0.7.0 (2026-06-01, shipped). v0.8.0 (2026-06-25, shipped). v0.8.1 (2026-06-29, shipped). v0.9.0 (2026-07-08, shipped — security hardening). **v0.10.0: PLANNED deprecation-WARN carrier** for the v1.0 fail-closed default flips (§27). **v1.0.0: undated by policy** — *tag when the §27 gate spine is green; slip the date, never cut gates* (adjudicated slip rule; internal effort estimates live in the §27 companion documents, ESTIMABLE-labeled). v1.x and beyond per §11.7.

Apache 2.0. Endpoint-resident. Cognitively governed. Bias-displacement as target law, enforcement per §25.3/§27.

---

## 25. Red Queen / RQGM — Final Locked Decision + Development Pathway

> **This section is the project's final, permanent decision point on Red Queen / RQGM.** Full analysis + master deliverable table: [`docs/reviews/RED-QUEEN-FINAL-DECISION-AND-ROADMAP-OPUS.md`](docs/reviews/RED-QUEEN-FINAL-DECISION-AND-ROADMAP-OPUS.md). Placement authority: [`docs/reviews/RED-QUEEN-21-AGENT-VOTE-OPUS.md`](docs/reviews/RED-QUEEN-21-AGENT-VOTE-OPUS.md); mechanism map: [`RQGM-2606.26294-vs-v0.8.0-OPUS.md`](docs/reviews/RQGM-2606.26294-vs-v0.8.0-OPUS.md). **Paper:** [The Red Queen Gödel Machine, arXiv:2606.26294](https://arxiv.org/abs/2606.26294) (Iacob et al.) — surfaced by **Nick Jensen**. **Method:** three adversarial rounds (21-lens assessment → 7-agent self-red-team → 21-lens final convergence), CodeGraph-anchored, against `release/v0.8.0`. Tracking: [#1820](https://github.com/alphaonedev/ai-memory-mcp/issues/1820). Crossroads cite: `5-agent vote (4d3ea1c5)`.

### 25.0 The final decision (21/21 unanimous + red-teamed)

Adopt the Red Queen **principles** — frozen-within-epoch evaluation, decorrelated **N≥3 *attested*-family quorum**, adversarial bias-checking — while keeping the evolutionary **search engine permanently external** in a dependency-clean `ai-memory-rqgm` sibling (§13) that reads substrate telemetry and writes **exactly one operator-signed epoch artifact** the in-repo **L2 curator** verifies and anchors to the **V-4 chain**. Welding the optimizer into `src/` is a **category error** (the verifier becomes a player) that would falsify the §0 anchor — **CUT 21/21, for eternity**. RQGM optimizes **agents**; ai-memory governs **persistence**. **Grade:** moonshot-§0 substrate-fitness **B+ today → A− after the full v0.9.0 P0 spine**; **C−/D+ if internal RQGM ever ships** (distinct from the **~15% RQGM-optimization-readiness** / **~5% family-verify** metrics — never conflate the axes).

### 25.1 L1/L2/L3 placement (the contract)

```
L3  ai-memory-rqgm (EXTERNAL, sibling, v0.9.1+)  — search · panel breeding · adversarial objectives
        READS exports (read-only, aggregate)  ·  WRITES one UNSIGNED manifest draft
            │ operator Ed25519 signature
L2  ai-memory curator (IN REPO, v0.9.0)  — verify manifest → bind to EpochAdvance Checkpoint → V-4 epoch.manifest_applied → decorrelation every cycle
            │ SAL / hooks
L1  ai-memory substrate (v0.9.0 spine)  — persist · bounded reflect · N≥3 ATTESTED quorum · static signed RuleEngine · V-4 chain · federation checkpoints
```
Dependency direction is **grep-provable** (`rg -i 'rqgm|epoch_manifest|red.?queen' src/` = 0): sibling → substrate only.

### 25.2 Epoch contract — RESOLVED design (one open T1+T4 vote)

An epoch is **three complementary artifacts bound by one SHA-256** (a Checkpoint resolution signature *excludes* `condition`/`metadata`, `src/identity/sign.rs:650-678`, so it cannot carry the payload — the manifest is complementary, not redundant): a **content-signed `epoch_manifest.json`** (signs the WHAT — panel slots, utility weights `frozen_within_epoch=true`, `policy_version`, `prior_epoch_id`, `content_hash`) **bound to an `EpochAdvance` Checkpoint** (attests WHEN+WHO; `resolution = content_hash`, a signed field; rides the FED-RQ-01 checkpoint-federation transport — [#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936), **LANDED at v1.0.0**: resolved commit-checkpoints federate over `/sync/push` as a new `checkpoints` subcollection, verified against the resolver's ENROLLED key (fail-closed `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG=1`) and applied first-resolution-wins; the v0.9.0 epoch-apply consumer was local-only. Format spine votes `4d3ea1c5` + #1947 decision `00d599ec`) **anchored by a V-4 `epoch.manifest_applied` row** (`payload_hash == content_hash`). `ConditionType::EpochAdvance` is **migration-free** (SAL-enforced, `src/models/checkpoint.rs:13-32`). **The schema (`docs/contracts/epoch_manifest.schema.json`) stays git-UNTRACKED with zero `src/` consumer until this fork is resolved by a 5-agent vote** — claiming "RQ-01 shipped" is BANNED (D-OPUS-4).

### 25.3 Development pathway — epic alignment

The full master deliverable table (ID · layer · epic · depends · effort · acceptance · file:line · issue) lives in the companion doc §4. Epic summary:

- **Sprint 0 (v0.8.0 hotfix):** D-OPUS-2 (PreReflect docstring), D-OPUS-5 (§2.1 RAM, done above), `honest-limitations.md` addendum, `RECURSIVE_LEARNING.md` L1/L2/L3 boundary.
- **v0.9.0 P0 spine (blocking tag):** **D3-012** ⭐ attested `model_family` ([#1719](https://github.com/alphaonedev/ai-memory-mcp/issues/1719), the keystone — needs the §11.4.D `model_attestations` table) · **D1-001** ⭐ MCP PreReflect veto ([#655](https://github.com/alphaonedev/ai-memory-mcp/issues/655)) · **RQ-10** ⭐ `SignableEpochManifest` + V-4 `epoch.manifest_applied` (mirror `rules_store::remove_signed`) + EpochAdvance-bind · **RQ-PARITY-01** ⭐ decorrelation-probe cycle parity (shared probe step + live-PG equivalence proof + scan-clamp fix; full `run_once`↔SAL unification → RQ-PARITY-02 v1.0; epoch parity → RQ-10) · **F-40** governance silent-disable + **F-41** `policy_version` (one coupled fix, D-OPUS-1) · **RQ-11** decorrelation every curator cycle ([#1764](https://github.com/alphaonedev/ai-memory-mcp/issues/1764)) · **#1705** consume-flip wiring + LIST SAL-routing (D-OPUS-6/7) · **#1706** shadow recall-utility sweep · **D3-002** #1171 panel · **FED-RQ-01** commit checkpoint federation — **did NOT land in v0.9.0** (the "+~282 LOC" existed only as an uncommitted review working tree; no code at any tag), re-homed to v1.0 as [#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936) and **LANDED at v1.0.0** (resolved commit-checkpoint resolutions now federate over `/sync/push`; fail-closed authority-lane verify against the resolver's enrolled key + first-resolution-wins apply + the `EpochAdvance` leg). *(2026-07-09 reconciliation: every other item in this spine list is verified SHIPPED at v0.9.0 except **D3-002**, whose v0.9.0 panel run has no artifact — RULED 2026-07-11 (#1938, 2×5 wf_26d176ac, 9/1): the retroactive v0.9.0 panel is DESCOPED as a backfill artifact; the mandatory v1.0.0 panel [#1967](https://github.com/alphaonedev/ai-memory-mcp/issues/1967) covers the boundary and carries the v0.9.0 descope note — recorded here, in the document that made the promise. The RQ-10 schema is now git-TRACKED with the #1878 verify-only consumer, discharging the §25.2 untracked-hold.)*
- **v0.9.0 P1/P2 (gated within-epic):** D3-021 enforce non-inert (gated on D3-012) · D3-031 consolidation gate · D3-060 enforcement-invariants ship-gate.
- **v1.0.0 (§11.6 federation maturity):** FED-RQ-02/03 federated epoch manifest + cross-node `policy_version` gate · FED-RQ-AGG privacy-preserving aggregate utility (**never raw rates**) · #1707 live recall wire (only after #1706 proves signal) · F-53/#1809 federation E2E · vote-independence empirical estimator.
- **Sibling v0.9.1+ (§13):** `ai-memory-rqgm` RQ-20..23 + RQ-20.1 decorrelation export — **never blocks the v0.9.0 tag**.

**Non-negotiable ordering gates:** D3-012 → D3-021 (no enforce on CLAIMED = no security theater) · #1706 → #1707 (shadow before live) · RQ-PARITY-01 → RQ-11 (else sqlite-only blinds postgres fleets) · F-41 + D3-012 → RQ-10 (else a signed manifest launders unattested diversity).

### 25.4 T4 / hard-to-reverse — 5-agent vote BEFORE commit

The `epoch_manifest` schema + `SignableEpochManifest` byte layout, the `epoch.manifest_applied` event type, the `EpochAdvance` Checkpoint binding, and every FED-RQ authority-write are **T1+T4 crossroads**. Each requires a cited `5-agent vote (4d3ea1c5)` before `git add`/commit. FED-RQ-01 (re-homed to [#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936); nothing is in flight at main) must carry the cite when it lands.

### 25.5 CUT (for eternity) + ship-gate invariants

CUT: full RQGM / population genetics in `src/` · governance auto-mutation without operator-signed packs · epoch panel as MCP tools · `--rqgm` flag merging L2+L3 · `enforce` on CLAIMED metadata · cross-node raw utility leaderboards · webhook/`hooks.toml`-as-epoch-manifest. Each is intended to become a CI gate modeled on the `scripts/check-vendor-literals.sh` self-test. **Status (v1.0.0 reconciliation, [#1971](https://github.com/alphaonedev/ai-memory-mcp/issues/1971)):** of the six promised CUT-invariant ratchets, **one shipped** — `scripts/check-l3-boundary.sh` (§25.3 S5 / RQ-10, [#1853](https://github.com/alphaonedev/ai-memory-mcp/issues/1853)) hard-bans the `rqgm`/`epoch_manifest`/`red-queen` internal identifiers at a 0-hit baseline with a `--self-test`. The remaining five (governance auto-mutation, epoch-panel-as-MCP-tools, the `--rqgm` flag, `enforce` on CLAIMED metadata, cross-node utility leaderboards, webhook/`hooks.toml`-as-epoch-manifest) are enforced TODAY by code review + structural absence; their mechanization as standalone 0-hit ratchets is tracked in [#1971](https://github.com/alphaonedev/ai-memory-mcp/issues/1971) for a v1.x cut. (This corrects the earlier "six … land as v0.8.0 ratchets" overstatement — five never shipped.) **Separation-of-powers invariant:** the L1 law (operator-signed `RuleEngine`) is read-only and never programmatically mutated (`src/governance/agent_action.rs:782`; `enforced_rule_passes` requires operator Ed25519, `rules_store.rs:205`). Add to §16 (cuts) + §17 (quality gates).

### 25.6 Claims discipline (binding)

**Allowed (re-cut at the v0.9.0 boundary, 2026-07-09):** "Red-Queen-*principles*-aligned" · "advisory decorrelation probe shipped; opt-in enforce gate shipped v0.9.0 (#1767), refuses only on ATTESTED monoculture; enforce-as-default is v1.0" · "loader-attested model-family substrate shipped v0.9.0 (#1870, ~40% coverage cap)" · "signed epoch contract with a git-tracked schema and a verify-only local consumer (#1878)". **Removed from the allowed list:** ~~"FED-RQ-01 (in-flight)"~~ — false at any tag; the code never landed ([#1936] is the carrier). **Banned → unlock (unchanged):** "decorrelation enforced" (needs enforce-as-DEFAULT: D3-021 flip + D3-031 + D3-060) · "attests model family" beyond the loader-attested qualified form · "epoch closure shipped" (needs the federated EpochAdvance leg, #1936) · **"implements RQGM"/"co-evolving evaluators shipped" = perma-ban** (category error). **Readiness ladder:** the "15%→~50-60%" figures are planner ESTIMATES, never measurements — ESTIMABLE-labeled, banned from procurement artifacts; family-verify hard-caps at ~40% loader-attested; vote-independence 0% throughout (architectural limit).

### 25.7 ASI durability — conditional, honest

§2.6 quorum+epoch is more ASI-durable than internal RQGM because its *mechanism* is capability-orthogonal (counts signatures, freezes windows), **conditional on two predicates:** **P1 family-distinctness** (~5%, buildable v0.9) and **P2 vote-independence** (0%, likely permanently only *estimable* — the substrate sees signed bytes, never the generating process, so it cannot distinguish genuine agreement from N rubber-stamp votes by one model in N hats). The measurability cliff is a **split**: structural-invariant counts survive ASI; semantic (contradiction-density LLM verdict) does not. `honest-limitations.md` carries this verbatim (no AGI-safety claim; CLAIMED≠ATTESTED).

---

## 26. TRACT vs v0.8.0 — Final Reconciled Adjudication (4 passes, 2 model families)

> **The project's reconciled adjudication of the TRACT framework against the shipped v0.8.0 substrate.** Converged output of **four assessment passes** — Grok first-party + Opus first-party 21-agent councils, two reconciliations, then a final **21-agent adjudication council** — CodeGraph-anchored against `release/v0.8.0` (846 files / 27,062 nodes), distilled into **two canonical `opus` companion deliverables under `docs/design/`** (these supersede and replace all prior first-party/reconciliation drafts):
>
> - [`docs/design/TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md`](docs/design/TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md) — what the substrate demonstrably **is** today (the shipped trust spine).
> - [`docs/design/TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md`](docs/design/TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md) — the **27 canonical gaps** + tracking state.

### 26.0 Verdict + two-axis grade

**Verdict: *substrate-ready, constitution-incomplete*.** A credible, honestly-labeled TRACT-2026 **L3-BODY Reference Profile** that ships the safety/governance/capability-cliff spine strongly and diverges, knowingly, on the data-model fundamentals. Graded on **two axes, never one composite** (averaging a strong axis with a weak one describes neither):

| Axis | Grade |
|---|---|
| **Trust-spine / safety** (capability cliff · V-4 chain · read-only signed governance · fail-closed federation · bounded reflect) | **A− / B+** |
| **Data-model / epistemics** (content-addressing · append-only · pure recall · causal-CRDT · three-key) | **C+** |

**Coverage:** ~**75–85% of ROADMAP §2** (seven structural properties) vs ~**25–35% of TRACT L1** (frozen constitution). Pillar scorecard: **10 of 14 CORRECT, 4 partial** (Pillar 1 "One Claim" splits ✅ L3 kinds-not-classes / 🟡 L1 Claim object — UUID not BLAKE3-CID).

### 26.1 The 32 canonical gaps

**32 development gaps: 4 P0 epics · 11 P1 · 17 P2**; **~20 UNTRACKED**; **3 proof-impossible** (architectural limits, not backlog — chiefly vote-independence per §25.7 P2). Filing the UNTRACKED gaps is itself a §24 prime-directive obligation. (An earlier "52" count was granularity inflation; deduped against code it was 27, then raised to **32** by the §26.6 corpus-completeness pass — see §26.6 for the +5 recovery. Items Grok carried — `#1672` curator_mode, `#1674` db_schema_version, HTTP `find_paths` 501 — are already FIXED and are dropped, not listed open.)

### 26.2 The reconciled P0 chain (ordered, non-negotiable)

Each gate strictly precedes the next — enforcing on CLAIMED metadata is security theater (§25.3 ordering):

```
P0-1  recall purity                                   (clean the signal)
   → P0-2  attested model_family (#1719) ▶ N≥3 decorrelation ENFORCE (#1171)
   → P0-3  secure-default attestation FLIP             (#1464; claimed → agent_attested)
   → P0-4  epoch-FREEZE consumer                       (RQ-10; verify-only, no optimizer)
```

**Kill-test gate (§16):** if recall still mutates and decorrelation is still claimed-only at v0.9.0, the substrate fails its own kill-test against `git+ripgrep+RAG` — P0-1+P0-2 are the minimum bar. **Verdict recorded 2026-07-09: PASS at v0.9.0** — P0-1 pure recall shipped (v77 fold ledger, #1869) and P0-2's attested-family substrate + evidence-gated quorum enforcement shipped (#1870 + #1767; enforce-as-default remains the v1.0 flip).

### 26.3 Tracked fix — durability-503 API-semantics bug

The council surfaced the **durability-503**: on a W-of-N quorum miss the local row already persisted yet the handler returned `503 quorum_not_met` — misreporting a locally-durable write as a service failure. **FIXED at v0.8.1 W3** (commit `d1b7fdd3`, 5-agent vote `4d3ea1c5`): `under_replicated_response` returns **202 Accepted** with `quorum_met:false`/acks/needed/`durability:"local"` in the body — never 5xx. *(Status updated 2026-07-09; the prior "tracks for fix" wording was stale.)*

### 26.4 The convergence meta-finding

Four passes across **two decorrelated model families** (Grok/xAI + Opus/Anthropic) converged on the same verdict, P0 set, and root divergences — the closest *live* instance of the N≥3 attested-distinct-producer discipline §2.6 builds and the substrate cannot yet enforce. Reported as **estimated-decorrelated / CLAIMED, not ATTESTED** (no cryptographic model-family attestation exists yet — #1719). With that caveat, decorrelated agreement is the strongest available evidence the verdict is true.

### 26.5 Claims discipline (binding — mirrors §25.6)

**Banned until the gate behind it ships:** "pure recall" (P0-1) · "decorrelation enforced"/"N independent producers" (P0-2) · "secure-by-default attestation" (P0-3) · "epoch closure shipped" (P0-4) · "append-only"/"no silent delete" (G6) · "content-addressed"/"BLAKE3 identity" (G8) · "TRACT-/L1-conformant" (G24 CC0 vectors). **Perma-banned:** the grandeur register (incl. ai-memory's own "eternity-grade"/"civilization-scale"/"world-class" house vocabulary) + "implements RQGM" + vote-independence. CLAIMED ≠ ATTESTED throughout.

### 26.6 Corpus-completeness pass (gap count 27→32)

**Method.** A **21-agent corpus-completeness council** (3 waves × 7) diffed the full pre-TRACT design corpus (the four superseded clean-slate design drafts) against the TRACT framework that distilled it, CodeGraph-anchored against `release/v0.8.0`. The question was narrow and adversarial: *did the distillation into TRACT lose anything load-bearing the corpus had carried, before TRACT became the sole measuring stick of this assessment?* Full report: [`docs/reviews/corpus-completeness-21-agent-OPUS.md`](docs/reviews/corpus-completeness-21-agent-OPUS.md).

**Finding — faithful ~97% superset, no constitutional loss.** TRACT is a faithful **~97% superset** of the corpus: every constitutional property survives the distillation intact, and 8 of 15 themes were *extended* with net-new resolutions. The "for infinity / OSS" longevity clause is substantively honored — only the grandeur *words* were cut; the mechanisms were kept and several sharpened. The §26.0 verdict and scorecard are **unchanged** (10 of 14 CORRECT, two-axis A− / C+). No re-grade.

**Recovery — 5 operational/security gaps TRACT had folded into prose** (lifting the count **27 → 32: 4 P0 · 11 P1 · 17 P2**). The two highest-value are CodeGraph-verified v0.8.0 **defects** — present-tense data-privacy holes in the shipped substrate, not horizon divergences — and are therefore **§24 prime-directive defects to file + fix, not divergences to label**:

- **G29 — secrets-in-memory have no write-path screening.** No store surface screens caller content for credential-shaped material (API keys, bearer tokens, PEM private keys, passphrases); `validate.rs` checks shape/length only (`src/validate.rs:917`). A pasted secret is persisted, FTS-indexed, embedded, federated, and surfaced verbatim on recall + forensic export. **Fix:** a fail-closed pre-write screen on the SAL write path (SQLite + Postgres parity).
- **G30 — erasure is incomplete (forget is not erasure).** Bulk `forget` (`src/storage/mod.rs:2852`) deletes the relational row but leaves the content **(a)** in the **federation push-DLQ** (`payload_json`, non-FK `memory_id` — re-syncs the "forgotten" content to peers), **(b)** as a **live HNSW vector in RAM** (never calls `idx.remove` — semantic recall still surfaces it until rebuild), and **(c)** with **no persisted tombstone** (`federation_receive.rs:446-450` "no tombstone row" → a peer re-pushes the row on the next catch-up sync → resurrection). **Fix:** make `forget` a true erasure — purge matching DLQ payloads in-tx, invalidate the HNSW vector synchronously, persist a signed tombstone the receive path checks before accepting an inbound write.

The remaining 3 recovered gaps are operational hardening (G28 forbidden-export-class · G31 latency-SLO degrade actuator · G32 cross-mind MPC/FHE/DP — G32 already TRACKED @ §11.7 / FED-RQ-AGG #1707, horizon, advertise-banned); none touches the constitution. Plus enrichments to G1/G5/G6/G10 in the canonical gaps deliverable.

**Claims discipline (extends §26.5).** Until G29 + G30 ship, **banned:** "secrets are screened" / "credential-safe storage" (G29) · "forget erases" / "right-to-erasure" / "complete erasure" / "tombstoned delete" (G30). The substrate **deletes a row** today; it does not **erase content**. CLAIMED ≠ ATTESTED throughout.

---

## 27. v1.0.0 Program — adjudicated merge (2026-07-09)

> **Canonical companion documents** (this section is the summary; they are the spec): [`docs/reviews/PERFECT-ENDPOINT-MEMORY-SPEC-3x7-FABLE.md`](docs/reviews/PERFECT-ENDPOINT-MEMORY-SPEC-3x7-FABLE.md) (27-requirement target spec + amendments) · [`docs/reviews/PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md`](docs/reviews/PERFECT-ENDPOINT-MEMORY-V1.0.0-ASSESSMENT-FABLE.md) (gap register + gated program) · [`docs/v1.0.0/UPDATED-ROADMAP-GROK-4-5-ASSESSMENT-PERFECT-ENDPOINT-AI-MEMORY.md`](docs/v1.0.0/UPDATED-ROADMAP-GROK-4-5-ASSESSMENT-PERFECT-ENDPOINT-AI-MEMORY.md) (49-agent xAI-family assessment) · [`docs/reviews/FABLE-VS-GROK-4-5-3x7-ADJUDICATION.md`](docs/reviews/FABLE-VS-GROK-4-5-3x7-ADJUDICATION.md) (the cross-family adjudication that merged them). Provenance: [#1939](https://github.com/alphaonedev/ai-memory-mcp/issues/1939).

**Cross-family verdict (Anthropic 3×7+gap-map councils × xAI 7×7 council, adjudicated against code):** v0.9.0 is substrate-ready and constitution-incomplete — 0 of 27 target requirements fully met (**by construction**: acceptance criteria are end-state tests), 20 PARTIAL (split *default-off* vs *incomplete*), 7 MISSING. The prior §11.6 package alone does not close the distance.

**Gate structure (each gate blocks the next; a recorded operator ruling counts as done, silence never does):**

- **Gate 0 — Sprint 0 ([#1938](https://github.com/alphaonedev/ai-memory-mcp/issues/1938)), BLOCKING:** docs reconciliation (this revision is its W1 down-payment) · tracker hygiene · evidence currency (frozen ship-gate/A2A/test-hub/NSA pages; the prose-only reproducible-build gate at §17) · past-due keep/cut rulings (L3 watcher, C-ABI FFI, §11.4.A/B/E, PE-7, R8) · reconcile §11.6's third-party-audit line to the AI-NHI multi-agent security review (no external firm, operator correction 2026-07-09).
- **Gate 1 — P0 freeze-critical formats** (every item a T1+T4 5-agent vote): crypto-agility envelope + re-anchor ceremony · SignableWrite v2 (instance sub-keys, model-ref, session) · **UUID→cid record-identity-authority ADR** · frozen sub-10kLOC verification spec + CC0 conformance corpus ([#1837](https://github.com/alphaonedev/ai-memory-mcp/issues/1837)) + dark-age Rosetta rider ([#1835](https://github.com/alphaonedev/ai-memory-mcp/issues/1835)) — **freeze-critical CORE DISCHARGED at schema v80** (frozen Portability Spec v2 [`docs/spec/PORTABILITY-V2.md`](docs/spec/PORTABILITY-V2.md) "completes the §11.6 v1.0 commitment" + CC0 corpus `conformance/` + ≥2 non-Rust readers `reader.py`/`reader.mjs` + Rosetta decoder-in-archive #1835; conformance suite green, settled by the #1967 2×5 vote 2026-07-13); [#1837](https://github.com/alphaonedev/ai-memory-mcp/issues/1837) now tracks ONLY additive residue record-class vectors (v1.x) · Portability Spec v2 @ v78 (≥2 non-Rust consumers per §11.6 — not relaxed) · epistemic kinds + channel-derived defaults · claim-bitemporal COLUMNS ([#1834](https://github.com/alphaonedev/ai-memory-mcp/issues/1834) promoted from P2) · rollback-evidence anchor + sanctioned-restore ceremony · equivocation-proof object + checkpoint federation ([#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936) → FED-RQ-02/03) · quarantine tier + dormant weight-ingestion contract · custody-class + signed revocation · read-path consumer-binding envelope scope (ruled pre-freeze) · supply-chain/build-integrity (dependency review, SBOM, reproducible-build implement-or-strike).
- **Gate 1′ — "defaults stop lying" sub-lane (parallel, tag-blocking):** production reflect family-stamps + stamp-density probe → D3-021 advisory-soak → **enforce-as-default** → D3-031 → D3-060 · `AI_MEMORY_RECALL_TOUCH_SYNC` removal path · fed write-sig (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, env-table row 94) + signal-sig (`AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`, env-table row 96) WARN→flip — every flip rides the one-cycle deprecation-WARN discipline (#1751 pattern) via the **planned v0.10.0 WARN-carrier release**.
- **Gate 2 — P1 safety machinery:** substrate record-stop actuator (write fence + lease revoke + recall/egress halt + signed stop-attestation ≤100 ms, honestly enumerating ungovernable copies) · crypto-shred + mandatory tombstones on every delete path + erasure attestation · human-key-signed approvals + m-of-n + 30-minute airgapped solo-operator gate · trust-tier min-propagation on the v75 DAG · transitive suspect invalidation · default-on capabilities + zero-config owner mint · verified-path 1M benchmarks + no-disable hardened profile + power-loss durability mode + fault-injection harness · inference-plane egress gating + index-coverage recall reconciliation · PE-1/namespace hardening as production TEMPLATES + a named `asi-hard` procurement profile (never compiled default flips) · capture-completeness lane (L3 build SHIPPED v1.0.0 — `ai-memory watch` poll-based #1978 + OPT-IN `fs-notify` event-driven #2220, operator `notify` approval granted 2026-07-18).
- **Gate 3 — endgame, ALL AI-NHI-conducted (operator correction 2026-07-09, memory `9a62049d`; there is NO third-party auditor):** DigitalOcean full-spectrum testing → **multi-agent codegraph-anchored code review (AI NHI)** → **multi-agent security review (AI NHI, security lenses)** → 100% fix + 100% track (**1:1 issue per finding** — every code-review and security-review finding gets its own GitHub issue, never bundled; adversarially-verified, retest + independent re-check, repeat rounds until a round is clean; the tag cannot cut with any finding open) → final DO + AI-NHI dogfood → 3×7 documentation drive → freeze + tag. Undated by policy (slip rule, §24). ROADMAP §11.6's "public security audit by named third-party firm" line is **superseded for this epic** by the AI-NHI review (Sprint-0 W5 reconciliation ruling). P2 residue (scoped-ciphertext federation, belief-preserving merge, corroboration field, fork/merge/delegation identity, catch-up tombstone feed) rides v1.x with recorded rulings.

**Constitutional escalation:** everything above is *planning-binding*; elevation to *ship-law* (spec-axis amendments to §2, freeze declarations) requires the [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous panel — the adjudication was Anthropic-family and by its own discipline cannot self-confer family-decorrelated authority.

---

## Footnotes

[^1]: External evidence supporting §2.5's forward-looking research direction, §5's weighting note, and §16's exclusion of cognitive-state-internals modeling as a feature category. Three publicly available sources, retrieved 2026-05-25:

    - **Sofroniew, Kauvar, Saunders, Chen et al., "Emotion Concepts and their Function in a Large Language Model,"** *Transformer Circuits Thread*, Anthropic, April 2, 2026 (archival arXiv: 2604.07729). Mechanistic interpretability work demonstrating that internal representations of emotion concepts causally influence alignment-relevant behaviors including reward hacking, sycophancy, and blackmail. Explicit that these are *functional* representations and does not claim subjective experience. Cited here for the narrow technical claim that *same model in different internal states produces measurably different outputs along alignment-relevant axes*, which motivates the §2.5 forward-looking research direction. Also cited for §16's exclusion: the substrate consumes externals (outputs, attestations, refusals); it does not model cognition internals.

    - **Lindsey, "Emergent Introspective Awareness in Large Language Models,"** Anthropic (arXiv: 2601.01828). Demonstrates that models can in some scenarios notice injected concepts in their own activations, recall prior internal representations, and distinguish their own outputs from artificial prefills — with explicit limits on reliability. Cited here for the structural implication that self-report is partial, which strengthens (not contradicts) the §2.6 bias-displacement principle.

    - **Olah remarks at Vatican presentation of Pope Leo XIV's encyclical *Magnifica Humanitas*, May 25, 2026.** Christopher Olah (Anthropic co-founder, head of interpretability) stated publicly that frontier AI development cannot be steered by frontier AI labs alone, because every frontier lab operates inside incentive structures that can pull researchers away from doing the right thing, and that oversight from religious leaders, governments, and civil-society institutions is essential. Cited here for the narrow structural argument about lab-incentive-independence, which motivates the §5 weighting note. The Vatican framing as a whole is *not* relied on in this document; only the structural argument is cited.

    **Single-author bias caveat.** This roadmap revision was authored by Claude Opus 4.7. Two of three sources cited above are by Anthropic researchers; the third is by an Anthropic co-founder. The author cannot self-audit the bias surface created by citing one's own model family's research as evidence for the substrate's framing. The [#1171](https://github.com/alphaonedev/ai-memory-mcp/issues/1171) heterogeneous evaluator panel methodology is the structural mechanism by which this bias surface becomes visible. Evaluators from non-Anthropic model families should explicitly flag whether the framing over-weights Anthropic-authored evidence relative to comparable work from OpenAI, xAI, DeepMind, or academic interpretability groups. If the panel concludes the framing is Anthropic-leaning in ways the author could not see, citations should be broadened or weighting adjusted.

[^2]: Sumers, T. R., Yao, S., Narasimhan, K., & Griffiths, T. L. (2024). Cognitive Architectures for Language Agents. *Transactions on Machine Learning Research*. arXiv:2309.02427. Cited in §2 for the narrow purpose of acknowledging prior art on cognitive-architecture organization of language agents. The substrate's seven properties derive from the moonshot synthesis; CoALA is a retrospective organizing lens, not a constraint. The full mapping is documented at [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md). The mapping carries no commitments and does not modify the §3 scope test.

[^3]: Genewein, T., Franklin, M., Lerchner, A., Orseau, L., Albanie, S., Bales, A., Wyeth, C., Chan, S., Gabriel, I., Leibo, J. Z., Dafoe, A., Hutter, M., Graepel, T., & Legg, S. (2026). *From AGI to ASI.* Google DeepMind. arXiv:2606.12683v1 (60-page report, submitted 10 June 2026); abstract at [arxiv.org/abs/2606.12683](https://arxiv.org/abs/2606.12683), HTML at [arxiv.org/html/2606.12683v1](https://arxiv.org/html/2606.12683v1). Cited in §1, §2.3, §2.5, §5, and §6.6 for the narrow purpose of recording where an independent DeepMind position paper corroborates — and where it exposes gaps in — the substrate's framing. The paper names four AGI→ASI pathways (scaling, paradigm shifts, recursive self-improvement, multi-agent collectives) and identifies memory-across-sessions, auditable capability-attestation, agent decorrelation against correlated failure modes, and verification/oversight of beyond-human cognition as preparedness requirements. **Bias-surface note (complements [^1]):** this is a *non-Anthropic* source; its inclusion partially addresses the [^1] caveat that this roadmap over-weights Anthropic-authored evidence. The paper validates the *problems* the substrate addresses; it does **not** endorse the *external-endpoint-substrate solution shape* (§2.1). The full 5-agent adversarial-review record of this citation — AGI relevance: strong; ASI/Moonshot: moderate; longevity to ASI: conditional — is issue [#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698).

[^4]: Hao, G., Long, Y., & Zhao, Z. (2026). *Self-Evolving Multi-Agent Systems via Decentralized Memory* (DecentMem). arXiv:2605.22721. Cited in §2 for the narrow purpose of acknowledging prior art on decentralized per-agent memory in multi-agent systems. The substrate's seven properties derive from the moonshot synthesis; DecentMem is a retrospective organizing lens, not a constraint. The full mapping is documented at [`docs/strategy/decentmem-mapping.md`](docs/strategy/decentmem-mapping.md). The mapping carries no commitments and does not modify the §3 scope test. DecentMem is a MAS-orchestration strategy one layer above the substrate; its diversity-collapse thesis is a *second* independent corroboration (after [^3]) of the §5 decorrelation axis but moves no commitment. The full 5-agent adversarial-assessment record is issue [#1704](https://github.com/alphaonedev/ai-memory-mcp/issues/1704); the one substrate direction it touches (closing the `recall_observations` feedback loop) is sequenced as [#1705](https://github.com/alphaonedev/ai-memory-mcp/issues/1705) (v0.8.0 prereq) → [#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706) (v0.9 shadow) → [#1707](https://github.com/alphaonedev/ai-memory-mcp/issues/1707) (v0.9 conditional live wire).

---

*Cleared hot. Stack is laid. Ship the OSS. Forever.*

*Document classification: Public-facing. Eligible for posting at github.com/alphaonedev/ai-memory-mcp/blob/main/ROADMAP.md.*

*Revision history:*
- *2026-04-29 (initial): consolidated charter-set roadmap.*
- *2026-05-21 (consolidation): ROADMAP2.md retired into ROADMAP.md per operator directive.*
- *2026-05-25 (moonshot-aligned): full-spectrum revision aligning every section with [`docs/strategy/moonshot-synthesis.md`](docs/strategy/moonshot-synthesis.md). Added §0 anchor, §1 moonshot, §2 seven properties, §3 scope test, §4 substrate-is-not, §5 open structural gap, §6 trajectory. Re-evaluated v0.8 §11.4 against scope test; relocated §11.4.F WebSocket viewer + §11.4.G schema-change methodology to sibling repos (§13). Upgraded §11.4.C vLLM and §11.4.D model attestation to load-bearing. Added per-release §2 property contributions throughout §11. Added §13 sibling repositories. Added §15 OSS permanence clause 5 (no frontier-lab acquisition). Updated §17 quality gates with §2 property declaration discipline + heterogeneous AI NHI panel review for major versions. Added footnote [^1] with external evidence and single-author bias caveat. Renumbered all sections.*
- *2026-05-27 (CoALA prior-art citation): added one paragraph in §2 introduction and footnote [^2] citing Sumers et al. 2024. Created [`docs/strategy/coala-mapping.md`](docs/strategy/coala-mapping.md) as the authoritative mapping document. Updated [`docs/positioning.md`](docs/positioning.md) with a "Relationship to CoALA" section. No substrate code changes. No commitments added or modified. No §2 properties changed. No §3 scope test modifications. The §3 scope test rejected three larger proposals (full §2.8 subsection, inline release-notes reframing at §11.4.D and §22, `coala` block in capabilities-v3) for failing to strengthen any §2 property; this minimal citation-only change is the disposition that passes scope test.*
- *2026-06-14 (DeepMind "From AGI to ASI" review): added footnote [^3] citing Genewein, Legg, Hutter, Orseau, Leibo, Gabriel, Dafoe et al., Google DeepMind, arXiv:2606.12683 (10 Jun 2026), and integrated the findings of a 5-agent adversarial review ([#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698)). **§5 promoted decorrelation enforcement from "held for adjudication / v1.x" to a COMMITTED v0.8/v0.9 milestone**, reframed it from the pairwise producer/reflector boundary to a COLLECTIVE N≥3-quorum property (candidate 4 primary, candidate 2 secondary), and named a SECOND open gap (distributed verification / per-write attestation, #1464) — the prior "single open structural gap" claim was externally falsified. Added scope-honesty notes: §1 (substrate is orthogonal to the scaling + paradigm-shift pathways; necessary-but-not-sufficient, not a universal governor), §2.3 (kill-switch governs the substrate's own record, not behavioral control of the cognition), §2.5 (operation-attestation vs the paper's capability-attestation ask; the one shipped primitive matching a named DeepMind requirement, pathway-agnostic), §6.4 (self-modification-refusal is a horizon claim with no v0.7.0 anchor), §6.6 (recursive-self-improvement / in-weights-learning contingency: §2.5/§2.3/§2.6 survive a paradigm shift, §2.2/§2.4 are at risk; audit-not-storage is the partial hedge). Verdict recorded: AGI relevance strong, ASI/Moonshot moderate, longevity to ASI conditional. No code changes; no §3 scope-test modifications.*
- *2026-07-09 (post-v0.9.0 reconciliation + v1.0.0 program): adversarially-verified drift reconciliation (2×5 run `wf_93009182-fff` → Sprint-0 epic #1938) + the cross-family adjudicated v1.0.0 program (Anthropic 3×7+gap-map `wf_68440e09-90e` × xAI Grok 4.5 7×7 council, adjudicated by `wf_a100ebc9-daa`; provenance #1939). Corrected: §3/§6.2/§10.2/§10.4-G2/G3/G7/§13/§22/§23 stale §23-pointers and the factually-false §23.5 v0.9.0 claim (vector substrate → #1860/v1.0); §11.5 shipped/deferred reconciliation; §12 stale 🔜 rows; §9.1 schema narrative v70→v78; §24 decorrelation status (D3-012+D3-021 SHIPPED v0.9.0) + actual release cadence + adjudicated undated-tag slip rule; §25.2/§25.3/§25.4 FED-RQ-01 never-landed → #1936; §25.6 claims register re-cut at the v0.9.0 boundary; §26.2 kill-test PASS recorded; §26.3 durability-503 fixed-at-v0.8.1 status; §22 PE-3/4/6/7 dispositions (#1937). Added §27 v1.0.0 Program (Gates 0–3, planned v0.10.0 WARN-carrier, ship-law escalation gated on the #1171 panel). Grandeur-register instances softened per the §26.5 house ban.*
- *2026-06-15 (DecentMem prior-art citation): added footnote [^4] citing Hao, Long, Zhao, arXiv:2605.22721, and one clause in the §2 introduction. Created [`docs/strategy/decentmem-mapping.md`](docs/strategy/decentmem-mapping.md) as the authoritative mapping document (a `[^2]`-class reference supplement — reference material only, no commitments, no §3 scope-test change; only [^3] is load-bearing). Integrated the 5-agent adversarial assessment ([#1704](https://github.com/alphaonedev/ai-memory-mcp/issues/1704)) and the 7-agent execution-design panel. The one substrate direction surfaced — closing the `recall_observations` feedback loop — was homed to its correct versions: a v0.8.0 ledger backend-parity + integrity prerequisite (§11.4, [#1705](https://github.com/alphaonedev/ai-memory-mcp/issues/1705)), a v0.9 shadow-first follow-up (§11.5, [#1706](https://github.com/alphaonedev/ai-memory-mcp/issues/1706)), and a v0.9 conditional live wire (§11.5, [#1707](https://github.com/alphaonedev/ai-memory-mcp/issues/1707)). No code changes; no §2 properties changed; no §3 scope-test modifications.*

*End of roadmap.*
