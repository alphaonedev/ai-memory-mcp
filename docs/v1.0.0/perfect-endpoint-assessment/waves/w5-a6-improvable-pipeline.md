# W5-A6 — Improvable cognition pipeline under model replacement

**Lens:** Does `atomise → reflect → skill_promote → persona` compound cognition **outside the weights** so a successor model inherits usable, auditable artifacts — or only a graveyard of prior-generation prose?  
**Property:** ROADMAP **§2.4** (improvable across model generations) · couple to **§2.7** (LLM-agnostic) · falsifier **§6.6** (in-weights continual learning).  
**Code anchors:** `src/atomisation/`, `src/storage/reflect.rs`, `src/mcp/tools/skill_*.rs` (esp. `promote_from_reflection`), `src/persona/`, `src/cli/commands/reembed.rs` (#1598), `src/identity/model_family.rs` + schema **v78** `model_attestations` (#1870), lineage **v75** (#1859), `docs/{atomisation,RECURSIVE_LEARNING,agent-skills,persona}.md`.

---

## SCORE

Scores = held-fraction of **§2.4 under model replacement** (not raw feature count). Defaults + honest claim bar.

| Axis | Score | Headline |
|---|---:|---|
| **Pipeline completeness** (episodic→semantic→procedural surface) | **0.82** | Observation → atom → reflection → skill → persona is real end-to-end |
| **Provenance navigability** after model death | **0.75** | `derives_from` / `reflects_on` / `derived_from` + cid lineage + skill digest |
| **LLM-agnostic generation boundary** | **0.86** | #1067 multi-vendor; roles are config, not baked model ids |
| **Embedder migration (index ≠ mind)** | **0.78** | HNSW disposable; `ai-memory reembed` + fail-closed dim convert |
| **Model-family stamp on cognitive writes** | **0.40** | v78 TOFU exists; ~40% loader cap; most host-authored rows CLAIMED |
| **Handoff protocol (generation N → N+1)** | **0.28** | No first-class “model generation handoff”; versioned rows only |
| **Cross-generation semantic continuity** | **0.35** | Text survives; interpretation + ranking drift under new embed/LLM |
| **Bias-displaced improvement (not monoculture compound)** | **0.34** | Decorrelation default `off`; single-family reflection still legal |
| **Paradigm-shift resilience (§6.6)** | **0.20** | Conditional on frozen-weights; attestation hedge only |
| **§2.4 overall (model-replacement reading)** | **0.48** | **Structural pipeline strong; improvable-under-replacement weak** |

**Composite (no vanity %):** §2.4 is **held as artifact-persistence + portability**; **not held** as *guaranteed successor-usable improving cognition*.

---

## §2.4 — What the property actually requires

ROADMAP §2.4:

> The substrate compounds cognition outside the weights. Frozen-weights LLMs can accumulate skills, atoms, and reflections that **survive the model that produced them**.

**Surviving bytes ≠ improvable cognition.** Perfect §2.4 under model replacement needs all five:

1. **Persist** — artifacts outlive producer process/weights.  
2. **Provenance** — successor (or auditor) can walk who/what produced them.  
3. **Portability** — skill/persona/atom formats are host- and model-neutral contracts.  
4. **Handoff** — operator/agent can **re-bind** the active working set to a new model generation without silent laundering of prior-model monoculture as “truth.”  
5. **Compound without delusion** — later models refine via new reflections/skills **with** provenance + (ideally) decorrelated family stamps — not SFT-style self-echo on prior self-output (RECURSIVE_LEARNING.md Form-4 honesty).

ai-memory ships **1–3 well**, **4 thinly**, **5 as optional advisory**.

### Pipeline map (what ships)

```
Observation (episodic store)
    │ atomise (WT-1 LlmCurator) ──► atoms + derives_from + parent archive
    ▼
Reflection (memory_reflect; depth cap; reflects_on edges)
    │ promote_from_reflection ──► SKILL.md skill (digest-stable, exportable)
    │ auto_persona / memory_persona_generate ──► Persona vN + citations
    ▼
Compositional use: skill_get / compositional_context + recall
```

| Stage | Artifact | Model-death survival | Replacement friction |
|---|---|---|---|
| **Atomise** | Atomic Observation rows + signed `derives_from` | High (rows + archive parent) | Atom wording is producer-model-styled; re-atomise is full re-run, not delta |
| **Reflect** | `Reflection` + depth + `reflects_on` | High (atomic tx + depth refuse) | Depth chain may encode prior-family priors; stamp density uneven |
| **Skills** | Content-addressed SKILL.md + resources | **Highest** (export/register digest round-trip) | Host *interprets* body under new model — utility not verified by substrate |
| **Persona** | Versioned Persona + source citations + `derived_from` | High (old versions retained) | Regeneration under new LLM may diverge; both versions co-exist in recall |
| **Embeddings** | Vectors on rows | Disposable cache | Reembed migrates space; interim keyword degrade; ANN neighbors reshuffle |

**Embeddings-as-disposable-cache is correct TRACT posture** — index death ≠ mind death. It does **not** prevent **semantic neighbor reshuffle** after reembed, which can make “how the new model finds old atoms” feel like memory loss even when rows are intact.

---

## GAPS

| # | Gap | Severity | Evidence |
|---|-----|----------|----------|
| **G-IMP-1** | **No model-generation handoff primitive** | P0 for §2.4 claim | No signed “active producer/reflector/curator model_ref set” epoch for cognition roles; epoch-FREEZE is policy/epoch, not cognition-handoff |
| **G-IMP-2** | **Cognitive writes under-stamped** | P0 for 2.4×2.6 | Loader-attested family ~40% hard cap (`model_family.rs`); host MCP reflect often CLAIMED metadata only |
| **G-IMP-3** | **Monoculture compound still default-legal** | P0 (claim) | `AI_MEMORY_REFLECT_DECORRELATION_MODE` default `off`; enforce refuses only attested monoculture |
| **G-IMP-4** | **Skill utility is host-opaque** | P1 | Substrate stores/exports/promotes; never executes or A/B’s skill under model N vs N+1 |
| **G-IMP-5** | **Persona dual-version recall ambiguity** | P1 | Old + new Persona versions both long-tier recallable; no “active persona pin” per entity under current model gen |
| **G-IMP-6** | **Atom/reflect re-synthesis is full rewrite, not supersede-forward discipline** | P1 | Re-atomise / re-reflect can fan-out new graphs without mandatory SUPERSEDE of prior generation’s derived graph (`append_only` still opt-in) |
| **G-IMP-7** | **Embed space migration ≠ claim continuity** | P1 | `reembed` fixes dim/backend; does not re-validate atom quality or skill activation success |
| **G-IMP-8** | **Procedural loop incomplete without host** | P1 | Skills are contracts; routines (#1709) are coordination templates — neither is “learned policy executed by substrate” |
| **G-IMP-9** | **Curator multi-namespace reflect was historically inert** | P2 residual | `--all-namespaces` wiring was a known v0.7.1 gap; single-ns path works — multi-ns autonomous improve still operator-fragile |
| **G-IMP-10** | **§6.6 paradigm-shift unhedged for 2.4** | Horizon | In-weights continual learning voids frozen-weights premise; only §2.5/2.3/2.6 pathway-agnostic |

**What is NOT a gap (do not re-litigate):**

- Pipeline **existence** (7 skill tools, reflect depth cap, WT-1 atomise, persona engine).  
- **Digest-stable skill export** round-trip.  
- **Partial-failure honesty** on atomise / depth refuse (stoppability of the *write*, §2.3).  
- **LLM vendor neutrality** of the generation boundary (§2.7).

---

## VOTE (single-lens synthetic; 5-axis internal)

| Lens | Stance |
|------|--------|
| **Precedent** | Keep composition as L1 §2.4 story; extend stamps + handoff — do not rebuild a new “mind format” |
| **Spec / TRACT** | Artifacts = claims/kinds with provenance; embeddings derived; no grandeur “perfect improvable mind” |
| **Security / 2.6** | Improvement without decorrelation is **bias accumulation**; refuse marketing “improvable” without family stamps |
| **Testability** | Model-swap golden: store under model A → reembed + reflect under model B → skill activate + lineage walk must green |
| **Blast radius** | Additive: require stamps on curator paths first; handoff as CLI/MCP epoch-like record; no hard-delete of prior gen |

**Tally:** 5/5 — **pipeline is load-bearing structure; §2.4 under model replacement is CONDITIONAL PASS only.**

**Chosen pathway:**

1. **Stamp E2E** — every substrate-invoked atomise/reflect/persona/curator write gets `loader_observed` family + model_ref (close density gap).  
2. **Handoff record** — signed “cognition role binding” (producer/reflector/curator/embedder model_ref set) with supersede semantics when operators swap models.  
3. **Active pins** — entity → active persona version; skill → preferred version under current binding (history retained).  
4. **Swap harness** — competitive/longmemeval-class test that freezes corpus under A and measures successor B *utility + lineage integrity*, not only R@k.  
5. **Keep** skill-as-contract + embed-as-cache + depth cap — do not execute skills in-substrate.

---

## KILLER

**“We already accumulate skills and reflections, so model replacement is solved.”**

Accumulation without **handoff + stamp density + (eventual) decorrelated refinement** is how delusion compounds *across* generations: model N+1 treats model N’s self-reflections and promoted skills as ground truth corpus, re-embeds them into a new similarity space, and **improves fluency of prior error**. That is SFT-style self-training lifted into the storage layer — exactly the failure RECURSIVE_LEARNING.md disclaims for *intra*-session hallucination while still risking it *inter*-generation via unstamped, monoculture-legal writes. Bytes survived; improvable *truthfulness* did not.

Secondary killer: claiming §2.4 while **decorrelation defaults off** sells “accumulating cognition” that is statistically **same-family echo** — the federalist property (§2.6) that makes multi-generation improvement *safe enough to compound*.

---

## TOP_RISK

**Silent semantic laundering at model swap:** operators change `AI_MEMORY_LLM_*` / embed backend, run `reembed`, and assume continuity. Rankings reshuffle, unstamped prior reflections dominate recall, personas dual-exist, skills activate under a host that misreads prior-generation instructions — and the audit trail still shows a “healthy” chain of writes. The failure looks like **product success** (more long-tier rows) while §2.4’s real product (successor-usable improving cognition) erodes.

Secondary: paradigm shift to in-weights learning (§6.6) makes the entire external-artifact bet optional unless attestation/audit remains the non-self-authorable spine.

---

## One-line north star

> **Artifacts must outlive models; improvement must not outlive provenance. §2.4 is a handoff discipline, not a pile of rows.**
