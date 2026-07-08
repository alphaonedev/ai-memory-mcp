# W1-A6 — Epistemics / Truth vs Memory

**Agent:** ADVERSARIAL AGENT W1-A6 (Epistemics lens)  
**Council:** 7×7 perfect-endpoint assessment  
**Sources:** ROADMAP §4, ROADMAP §26 (TRACT adjudication), `docs/memory-kind-vocab.md`, TRACT L1 Claim grammar, Form 4/5 (provenance + confidence)  
**Date:** 2026-07-08  

---

## VERDICT

**Memory is not knowledge. A perfect endpoint substrate must treat every stored unit as an *attested cognitive artifact* with typed epistemic role, not as a truth-bearing blob.**

The perfect data model is a **single content-addressed Claim object** whose *kind* is a tag (not a class hierarchy), whose *identity* is a hash of content‖provenance, and whose *verbs* never silently rewrite belief. Observations, claims, decisions, reflections, goals/plans/steps, and provenance/confidence live as **orthogonal axes** on that object — never collapsed into “a string the model said once.”

ai-memory at L3-BODY already has the right *vocabulary surface* (13 `MemoryKind`s, Form-4 citations, Form-5 `confidence_source`, additive `cid`, lineage edges). It is **constitutionally incomplete** on the epistemic spine (TRACT §26 grades data-model/epistemics **C+**): UUID primary identity, in-place update, optional kind defaulting to `observation`, and confidence that can be caller-fiction without basis. That gap is the load-bearing failure mode for **model replacement**: a successor model that cannot reconstruct *what was asserted, by whom, under what confidence basis, from what source, and how it was later superseded* will either invent continuity or discard the corpus.

**Perfect-endpoint requirement:** survive model replacement by making the record *self-describing at the epistemic layer* — process-attested, origin-bound, kind-typed, supersede-not-overwrite — without ever claiming to adjudicate world-truth.

---

## CONFIDENCE

**0.86** (high on the type system and forbidden confusions; slightly lower on exact frozen-field cardinality, which must stay ≤ what an endpoint can serialize under dCBOR without optional-field explosion).

Rationale for not 0.95: TRACT’s 5-kind set vs substrate’s 13-kind set is a deliberate tension (see type system); both are viable if kinds remain tags. Exact bitemporal field names and whether `confidence` is hashed are constitution-level choices already adjudicated by TRACT — this agent aligns with TRACT’s hash-preimage discipline rather than inventing a third.

---

## PERFECT TYPE SYSTEM

### Principle

**One object. Many kinds. Zero “truth classes.”**  
Kinds are *authored epistemic roles*, hashed into identity. They are not inheritance trees, not storage tables, and not permission systems.

### Core object: `EpistemicUnit` (= TRACT `Claim`)

```
EpistemicUnit {
  id            = H(canonical(content) ‖ 0x00 ‖ canonical(provenance))   // content-address
  kind          : KindTag                    // hashed; authored at ASSERT
  content       : { mime, bytes }            // content-blind at L1 (no model-native parse)
  provenance    : ProvenanceBundle           // hashed; origin is part of identity
  owner         : LineageNodeRef             // NOT hashed (succession must not rewrite id)
  confidence    : ConfidenceAtAssert         // immutable authored record; NOT hashed
  attestation   : AttestationState           // append-monotone: claimed → attested
  lifecycle     : asserted | superseded(by) | forgotten(receipt)
  links         : [ SignedRel{ pred, target } ]
}
```

### Kind taxonomy (two layers, one column)

| Layer | Tags | Epistemic role |
|---|---|---|
| **TRACT L1 kernel (minimal Rosetta)** | `fact` · `episode` · `skill` · `policy` · `relation` | Cross-era decoder bootstrap; frozen floor |
| **Endpoint Form-6/Pillar-2 expansion (tags, not classes)** | `observation` · `claim` · `decision` · `event` · `conversation` · `reflection` · `persona` · `concept` · `entity` · `goal` · `plan` · `step` | Operational filter surface for NHI workflows |

**Rule:** Expansion tags MUST map (or be mappable) onto the kernel five for export/fork/federation. Mapping is a projection, never a silent coercion that erases the authored tag. Unknown future tags: refuse on write; fall back only on *read* of foreign archives with an explicit `kind_unknown` projection — never rewrite the stored bytes.

### Orthogonal axes (must not be conflated with kind)

| Axis | Values | Why separate |
|---|---|---|
| **Epistemic speech-act** | observe · assert · decide · commit · reflect · plan | Kind often encodes this; axis makes filter stable when tags grow |
| **Causal status** | witnessed (`P(Y\|X)`) vs intervened (`P(Y\|do(X))`) | Form-4 / Pearl cut; delusion amplification if collapsed |
| **Attest level** | claimed · agent_attested · peer_attested · multi_witness | Trust of *process*, not truth of *content* |
| **Lifecycle** | live · superseded · tombstoned · expired · redacted | How the mind may use it |
| **Confidence basis** | caller_provided · auto_derived · calibrated · decayed · quorum_agreed | Form-5; score without basis is theater |
| **Model family** | attested family id (or absent) | Decorrelation; CLAIMED ≠ ATTESTED |

### Verb algebra (epistemic, not CRUD)

| Verb | Epistemic effect |
|---|---|
| **ASSERT** | Birth of a unit with provenance; starts `claimed` |
| **RELATE** | Graph-level belief structure (supersedes, contradicts, derived_from, …) |
| **RECALL** | Pure read — never mutates confidence, access, or tier |
| **ATTEST** | Raise trust of *process* only |
| **SUPERSEDE** | Forward correction; old id remains; new id + link |
| **FORGET** | Witnessed erasure; signed receipt; no silent hole |

**Forbidden verbs for a perfect endpoint:** silent UPDATE of content, silent DELETE without tombstone, auto-resolve of contradictions by deleting the loser, promote-on-read as belief revision.

### Derived projections (L2/L3 only — never identity)

Embeddings, FTS tokens, HNSW residency, decayed confidence-at-time-t, salience, tier, access/CONSUME counts. If the Reference Profile dies, L1 Claim bytes rebuild the mind; projections recompute.

### Survival under model replacement

A replacement model receives:

1. Canonical Claim archive (content-addressed, provenance-complete).  
2. Link graph with supersession / contradiction edges intact.  
3. Confidence *basis* + attest levels (so it can refuse to treat caller_provided 0.99 as gospel).  
4. Kind tags + mapping to kernel five.  
5. Model-family attestation where present (so it knows which priors produced which reflections).

It does **not** receive: “the database of true facts,” auto-resolved winners, or embeddings that pretend to be identity.

---

## REQUIRED PROVENANCE FIELDS

Minimum frozen provenance (hashed into `id` with content):

| Field | Purpose |
|---|---|
| `asserter` | Who claimed (agent_id / pubkey binding) |
| `source` | Role or channel label (user, tool, curator, federation peer) |
| `source_uri` | Where the content body lived (doc, URL, transcript id) |
| `source_span` | Byte/token range into parent body (re-derivable quote) |
| `citations[]` | Scholarly multi-cite envelope (uri, accessed_at, optional content hash) |
| `valid_time` | When the *world fact* is claimed to hold (bitemporal) |
| `transaction_time` | When the *substrate* accepted the ASSERT |
| `algorithm_id` | Canonicalization + hash + sig algorithm (crypto agility) |

Required *outside* the hash (governance / trust, not identity):

| Field | Purpose |
|---|---|
| `owner` | Lineage-DAG node; succession without id rewrite |
| `confidence.value_at_assert` | Immutable authored score |
| `confidence.basis` | `caller_provided` \| `auto_derived` \| … |
| `confidence.signals` | Reproducible snapshot when derived |
| `attest_level` + signatures | Process trust ladder |
| `model_family` / attestation row | Decorrelation input (when enrolled) |
| `cause_hash` | Audit cause-binding (process, not story) |
| `cid` / `cid_genesis` | Content-id mirror for lineage after tombstone |

**Hard rule:** no content without a binding. ASSERT without provenance is not memory; it is an unowned rumor.

**Sibling knowledge (§4):** bare world propositions live *outside* the substrate (`source_uri` → skills repo / ADR / git). The substrate stores *engagement artifacts* (what the agent learned/concluded/decided about that knowledge), never a parallel knowledge base.

---

## FORBIDDEN CONFUSIONS

These confusions destroy endpoint cognition under model churn:

1. **Memory ≡ Knowledge** — Storing “Tokio select! needs Pin” as bare truth. Substrate holds *that an agent concluded / observed / decided X from Y*, not X as encyclopedia fact (ROADMAP §4).

2. **Observation ≡ Claim** — Tool output witnessed vs agent assertion of world state. Collapsing them causes delusion amplification (Form-4 / do-calculus cut).

3. **Claim ≡ Decision** — Factual commitment vs choice-under-rationale. Decisions need alternatives/rationale lineage; claims need citations.

4. **Reflection ≡ Observation** — Curator-synthesized summary treated as primary evidence. Reflections are derived; must carry `derived_from` / `reflects_on` and model-family of the reflector.

5. **Confidence ≡ Truth** — A float in [0,1] without `basis` is ranking theater. High caller_provided confidence must not outrank multi-attested low-confidence observations by default.

6. **Attestation ≡ Correctness** — Signature proves key-custody + consent to bytes; never that the mind was right, understood, or is the same entity (TRACT: signer ≠ thinker).

7. **UUID presence ≡ Identity continuity** — Random ids do not survive re-ingest, re-export, or dual-store merge as the *same* claim. Content-address is the continuity primitive.

8. **In-place edit ≡ Belief revision** — Overwriting content destroys the prior belief state. SUPERSEDE + link is revision; UPDATE is amnesia with a new face.

9. **Contradiction deletion ≡ Resolution** — Auto-deleting the older contradicted row is adjudication by GC. Perfect substrate *conserves* fork_set; minds resolve, records don’t.

10. **Kind default ≡ Kind truth** — Defaulting everything to `observation` trains agents to skip epistemic typing; write-path must refuse unknown kinds and strongly encourage non-default kinds for non-notes.

11. **Embedding ≡ Meaning** — Vectors are L3 projections. They die with the embedder model. Identity and provenance must not depend on them.

12. **Recall mutation ≡ Evidence of use** — Touch-on-recall confounds access signal with content. Perfect RECALL is pure; CONSUME is a separate ledger.

---

## KILLER_OBJECTION to “one blob of text”

**A single undifferentiated text field is not a memory substrate; it is a paste buffer with a timestamp.**

Objections that kill the “just store the string” design:

1. **Non-surviving identity.** Without content-addressed identity bound to provenance, re-import, federation LWW, and model-replacement rehydration cannot answer “is this the same claim?” — only “is this similar text?”

2. **Non-recoverable speech-act.** Downstream agents cannot filter “decisions that bind me” vs “observations I witnessed” vs “reflections I should distrust if monoculture.” RAG over blobs returns eloquence, not commitments.

3. **Non-auditable process.** Without citations, valid/transaction time, attest level, and confidence basis, you cannot reconstruct *why* a prior agent believed X — only that some bytes existed. That is diary, not continuity organ.

4. **Silent belief corruption.** Blob+UPDATE lets the loudest latest write erase history. Endpoint minds that “improve” by overwriting become unaccountable and non-stoppable.

5. **Model-replacement death spiral.** Successor model either (a) treats the blob corpus as ground truth (inherits bias + errors as dogma), or (b) ignores it (loses continuity). Typed epistemics + supersession graph is the only third path: *inherit the trajectory, not the verdict.*

6. **Scope-test failure (TRACT).** A blob does not increase faithfulness-to-origin, accountability-to-owner, or survivability-across-time beyond a filesystem. If the primitive is just text, git+rg is strictly better (diff, blame, content-hash for free).

**Therefore:** content may be opaque bytes at L1, but the *envelope* (kind, provenance, confidence basis, attestation, lifecycle, links, content-id) is non-optional structure. Opacity of payload ≠ uniformity of type.

---

## TOP_RISK

**Epistemic laundering under model replacement and consolidation.**

If kinds, provenance, and confidence basis are optional or soft, and consolidation/reflection/hard-delete may erase sources:

- Reflections mint “facts” without navigable `derived_from` to observations.  
- Contradictions disappear instead of remaining as conserved forks.  
- Caller-provided confidence and unattested model_family look like substrate truth.  
- Successor models load a **smoothed monoculture corpus** that *looks* like knowledge.

This is worse than data loss: it is **false continuity** — the mind believes it remembers when it only remembers its own prior prose. Paired failure modes already named in TRACT gaps: G6 (append-only broken), G7 (contradiction auto-resolved), G8 (UUID not CID), weak kind defaulting, and decorrelation still CLAIMED not ATTESTED.

**Mitigation shape:** content-address + SUPERSEDE-not-UPDATE + conserved contradiction + pure recall + required provenance on ASSERT + kind as hashed tag + confidence.basis mandatory + consolidate-tombstone-sources with lineage DAG.

---

## VOTE on content-addressing necessity

### **YES — content-addressing is constitutionally necessary**

| Option | Vote |
|---|---|
| Optional / nice-to-have | **REJECT** |
| Parallel additive cid (UUID remains sole identity) forever | **INSUFFICIENT** as end state |
| Content-address as identity (UUID as cache key / FK convenience only) | **REQUIRED** |
| Content-address of content alone (no provenance in preimage) | **REJECT** (origin-blind; enables provenance laundering) |
| Content-address of content‖provenance (TRACT form) | **ADOPT** |

**Conditions:**

- Preimage MUST include kind + content + provenance (or equivalent frozen bundle).  
- Owner MUST stay outside the hash (succession).  
- Confidence and embeddings MUST stay outside the hash (recomputable / mutable overlays).  
- Lifecycle transitions (supersede/forget) MUST NOT rewrite id of prior units.  
- Federation equivalence and dual-store merge MUST prefer cid equality over UUID.

Additive `cid` alongside UUID is a valid *migration ladder*, not a permanent dual-truth. Endpoint perfection requires **one authoritative content-derived id** for “is this the same claim across time and hosts?”

---

## RATIONALE

### Anchor in project canon

- **ROADMAP §4:** Substrate is *not* a knowledge base; it holds cognitive artifacts of engagement, referenced via source-URI. Epistemics therefore start from *role of the artifact*, not world-model completeness.  
- **ROADMAP §26:** Trust spine strong; **data-model/epistemics C+**. Perfect endpoint work is exactly the weak axis: content-addressing, append-only, pure recall, causal structure.  
- **TRACT L1:** One Claim; kinds not classes; attests process never adjudicates truth; RECALL pure; SUPERSEDE not UPDATE; FORGET witnessed.  
- **memory-kind-vocab:** 13 operational tags already encode the speech-act cut (observation/claim/decision/reflection/goal/plan/step). The defect is not vocabulary absence; it is **optionality and non-identity-binding**.  
- **Form 4/5:** Provenance and confidence_source are the correct axes; they must be write-gates for perfect posture, not soft columns.

### Why this lens dominates for “perfect endpoint”

Endpoint cognition’s job under model churn is **faithful continuity of what was experienced, concluded, and decided** — not maximization of retrieval MRR. A perfect vector index on untyped blobs fails the moonshot the moment the embedder or the LLM family changes. A perfect epistemic envelope survives because meaning for the *next* model is in the **typed trajectory**, not in the **embedding of the previous model’s prose**.

### What “perfect” deliberately refuses

- Judging which claim is true (that is the mind / strategic layer).  
- Holding bare knowledge that belongs in sibling repos.  
- Inferring kind from free text without audit (auto_classify is operator-opt-in assist, never silent truth).  
- Treating multi-agent agreement as truth without attested model-family diversity.

### Minimal ship bar for “epistemically perfect enough”

1. Content-address identity (content‖provenance).  
2. Write-path kind + provenance required (no empty observation default for non-notes without explicit opt-in).  
3. SUPERSEDE / FORGET / conserve-contradiction as only belief-change paths.  
4. Pure RECALL; separate CONSUME.  
5. confidence.basis mandatory; undecayed score never outranks multi-attested process without policy.  
6. Lineage edges for reflection/consolidate; sources tombstoned not hard-deleted when lineage is on.

Until those hold, advertise **L3-BODY memory store with epistemic annotations** — not **L1 continuity organ**. CLAIMED ≠ ATTESTED applies to the substrate’s own marketing of “structured memory.”

---

*End W1-A6. Under 400 lines. No grandeur register. Lens complete.*
