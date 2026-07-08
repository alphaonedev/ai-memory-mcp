# W1-A4 — Separation of Powers / Federalist Design

**Council:** perfect-endpoint-assessment · Wave 1 · Agent A4  
**Lens:** Bias-displacement · N≥3 quorum · producer≠reflector · internal optimizers as category errors  
**Scope:** Perfect power-separation for **endpoint memory** (not RQGM search internals)  
**Anchors:** ROADMAP §2.6, §5, §25; DeepMind *From AGI to ASI* (decorrelation as structural); Federalist 51 (ambition counteracts ambition)

---

## VERDICT

**Perfect endpoint memory is a federal republic of roles, not a unitary intelligence with a diary.**

The load-bearing design is structural humility: no single cognition’s self-account may enter the accumulating self without reflection from **attestably decorrelated** priors; no verifier may also be the player that optimizes the rules by which it is judged; law is operator-signed and read-only to the runtime. Pairwise producer/reflector is the degenerate N=2 case; the primary architecture is **collective N≥3 attested-family quorum** at write-time (and consolidation-time for shared corpora). Internal optimizers (RQGM / co-evolving Agent-as-Judge welded into `src/`) are a **category error** — they collapse separation of powers into a self-referential loop and falsify the §0 “verifies, does not optimize” anchor.

Ship: L1 substrate (persist · attest · refuse · count signatures) · L2 curator (verify epoch · decorrelate · fold access · never breed panels) · L3 evolutionary search permanently external (`ai-memory-rqgm` sibling). That placement is not packaging preference; it is the constitution.

---

## CONFIDENCE

**0.88** on the constitutional shape (L1/L2/L3, N≥3 primary, external optimizer, producer≠reflector).  
**0.72** on full ASI durability of the *semantic* half of decorrelation (P2 vote-independence is architectural-limit / estimable only — substrate sees signed bytes, not generating process).  
**0.95** that welding RQGM into core is worse than leaving the gap open (C−/D+ fitness if internal; 21/21 §25 cut).

---

## POWER MAP

Who may **write**, **verify**, **stop**, **reflect** — and who must never hold two of those powers at once.

| Role | Write (cognitive content) | Verify (identity / family / law) | Stop (refuse / tombstone / deny) | Reflect (bias-displace / grade self-account) | Must NOT also… |
|---|---|---|---|---|---|
| **Producer agent** (session cognition) | YES — Observations, Claims, Decisions, Actions under own `agent_id` + optional Ed25519 | NO as sole authority | Soft only (self-correction); hard stop is not its privilege | NO on own output treated as bias-displaced | Be the sole reflector, sole judge, or sole epoch-breeder |
| **Reflector panel** (N≥3 distinct attested families) | YES — Reflection-kind rows only, linked `reflects_on` / P-subset edges | Partial — signs own reflection; does not mint law | Advisory veto of *promotion to long-tier self* when quorum fails | YES — the checking branch; **producer family ∉ panel families** | Produce the observations they grade; mutate RuleEngine; breed next epoch’s panel |
| **L1 substrate** (`ai-memory` binary) | YES — mechanical persistence only (CRUD, FTS, HNSW, ledger); never “thinks” the content true | YES — crypto identity, TOFU model_family, signatures, V-4 chain, cause binding, cid, federation gates | YES — fail-closed gates (PreStore/PreReflect, attestation required, secret screen, governance Deny) | NO semantic reflection; MAY host *bounded* reflect dispatch to configured models without scoring utility of those models | Optimize agents, auto-mutate rules, or score ASI utility |
| **L2 curator** | Limited — reclassify recovered turns, fold access, consolidate/tombstone under flags | YES — epoch_manifest verify, EpochAdvance bind, decorrelation probe, dominance advisory | YES — refuse unattested “diversity,” refuse enforce-on-CLAIMED theater | Orchestrates reflection *jobs*; does not substitute for panel | Run evolutionary search / panel breeding / genetic fitness |
| **Operator (biologic sole authority)** | Via signed packs only for law | YES — enrolls keys, signs epoch, mints capabilities | YES — ultimate Stopper custody; key rotation; tag cut | Out-of-band only | Be replaced by agent-signed governance mutation |
| **Recorder / Judge / Stopper** (G9 three-key) | Recorder: audit rows only | Judge: verdict checkpoints; Stopper: enforcement anchors | Stopper: deny + forensic `stopperSig` (advisory on wire; deny is independent) | NO | Share custody dirs; alias recorder==judge==stopper |
| **Federation peer** | YES — relayed data under receive_auth (attribution, write_sig, signal_sig) | Envelope + enrolled peer keys; never trust wire pubkey alone for authority | Skip / refuse forged or unenrolled authority-lane writes | NO | Claim third-party authorship without attestation |
| **L3 RQGM sibling** | ONLY unsigned epoch_manifest *draft* | NO on live memory store | NO | Breeds *next* panel offline; never grades live self into L1 | Compile into `src/` or open DB write path |

**Invariant (Federalist 51):** ambition counteracts ambition. Producer ambition (self-flattering memory) is checked by reflector ambition (foreign priors). Verifier ambition is checked by read-only law + external search. Optimizer ambition is kept off the verifier’s process boundary.

**Corpus caveat (§5):** shared consolidated Postgres+AGE can re-correlate N agents even when model families differ. Decorrelation is decided at **write-time (family)** AND **consolidation-time (corpus)** — not write-time alone.

---

## PERFECT ARCHITECTURE (L1 / L2 / L3)

### L1 — Constitution & memory body (endpoint-resident substrate)

**Job:** Hold the entity’s accumulating self under structural humility. Capability-orthogonal mechanisms only: count signatures, freeze windows, refuse unattested claims of decorrelation, append-only audit spine.

**Powers:**

1. **Persist** — Memory kinds (Observation…Decision + Goal/Plan/Step); pure-by-default recall; fold-before-gc; lineage DAG on P = {derived_from, reflects_on, derives_from}.
2. **Attest** — `model_attestations` TOFU; SignableWrite; agent/peer keys; optional three-key Recorder/Judge/Stopper; witness high-water; cid genesis binding.
3. **Refuse** — PE-1 required-event presence; PreReflect veto; `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`; secret_screen refuse/redact; federation fail-closed enrollment/sig/nonce.
4. **Quorum gate** — Accept a reflection (or any self-account promoted into long-tier / Decision-bearing self) as *bias-displaced* **iff** N≥3 reflections from **distinct attested** model families agree (or explicit non-displaced tier with honest labels). `enforce` inert until D3-012 lands — no security theater on CLAIMED strings.
5. **Law** — Operator-signed `RuleEngine` is **read-only** at runtime; never programmatically mutated. Capabilities = attenuation-only macaroons.

**Must not:** Host RQGM, Agent-as-Judge co-evolution, utility leaderboards that feed self-mutation, or semantic “is this ASI good?” scoring.

### L2 — Executive maintenance (in-repo curator)

**Job:** Keep the republic runnable without becoming legislature or court of last appeal.

**Powers:**

1. Verify **one** operator-signed `epoch_manifest` → bind `EpochAdvance` Checkpoint → V-4 `epoch.manifest_applied`.
2. Run decorrelation probe every cycle (advisory → enforce only after attested family).
3. Consolidation disposition under `consolidate_tombstone_sources` (navigable lineage, not silent hard-delete of self-history).
4. Transcript-classify / confidence-decay / shadow utility — **observability**, not fitness evolution of the panel.

**Must not:** Breed next epoch’s evaluators; merge L2+L3 via `--rqgm`; expose epoch panel as MCP tools that write law.

### L3 — Evolutionary search (external sibling only)

**Job:** Optimize *agents and panel composition for the next epoch*, never live memory truth.

**Contract:**

```
L3  ai-memory-rqgm  READS aggregate exports only
    WRITES exactly one UNSIGNED epoch_manifest draft
         │ operator Ed25519
L2  curator verifies → EpochAdvance → V-4 anchor
L1  substrate enforces frozen-within-epoch panel + N≥3 ATTESTED quorum
```

Dependency direction **grep-provable one-way** (`rqgm|epoch_manifest|red.?queen` absent from `src/`). Sibling may die; L1 remains a honest verifier with operator-configured panels.

### Role lattice at the endpoint (perfect split)

```
                    ┌─────────────────────┐
   Law / Stop  ◄────│  Operator keys      │────► enroll family keys, sign epoch
                    └──────────┬──────────┘
                               │ signed packs only
         ┌─────────────────────▼─────────────────────┐
         │  L1 RuleEngine + V-4 + attestation tables │  VERIFY / STOP
         └─────────────────────┬─────────────────────┘
          write path           │                reflect path
    ┌─────▼─────┐        ┌─────▼─────┐     ┌──────────▼──────────┐
    │ Producer  │───────►│  Memory   │◄────│ Reflector panel N≥3 │
    │ (family A)│ store  │  corpus   │     │ families B,C,D ≠ A  │
    └───────────┘        └─────▲─────┘     └─────────────────────┘
                               │ fold / consolidate / epoch apply
                         ┌─────┴─────┐
                         │ L2 curator│  VERIFY only
                         └─────▲─────┘
                               │ verified manifest only
                         ┌─────┴─────┐
                         │ L3 RQGM   │  SEARCH only (external)
                         └───────────┘
```

**Endpoint tiers (brief):** Full L1+L2 on phone/Pi/server; MCU Tier-∅ holds identity via gateway that still enforces N≥3 *before* promotion into durable self. Distilled hot-path models strengthen §2.6 **only if** family-decorrelated from producer.

---

## HARD CUTS

| Cut | Why (separation) |
|---|---|
| Full RQGM / population genetics in `src/` | Verifier becomes player; §0 falsified |
| Governance auto-mutation without operator-signed packs | Legislature captures itself |
| `enforce` on CLAIMED `model_family` / agent strings | Security theater launders monoculture as diversity |
| Same-family producer×reflector labeled bias-displaced | Federalist check is empty |
| Pairwise-only as PRIMARY architecture | Degenerate N=2; fails swarm-correlated failure modes |
| `--rqgm` merging L2+L3 | Process boundary is the constitution |
| Epoch panel as MCP write tools | Agents rewrite the court that judges them |
| Cross-node raw utility leaderboards | Fitness signal becomes gaming surface + privacy breach |
| Internal Agent-as-Judge grading ASI utility | Unbounded regress; capability-coupled metric dies at ASI |
| Frontier-lab exclusive acquisition of substrate | Breaks §2.6/§2.7 structural independence |
| Semantic “ASI-safe memory” claims without attestation gates | Honesty breach; CLAIMED≠ATTESTED |

CI ratchets (pattern: `check-vendor-literals.sh` / L3-boundary gate) must keep `src/` free of RQGM identifiers forever.

---

## KILLER_OBJECTION to single-model memory

**A single model’s memory is not memory of the world; it is a continuous self-petition for continuity of its own priors.**

Whatever is stored — summary, reflection, “lessons learned” — is generated under the same training distribution, RLHF stack, and failure modes that produced the original action. Self-reflection without a foreign checking branch is **autobiography without cross-examination**: it compounds bias under the name of learning. At swarm scale, N agents sharing one family and one consolidated corpus is **one model with N process IDs** — DeepMind’s correlated-failure friction, not decorrelated oversight.

Cryptographic self-signatures do not fix this: they prove *who claimed*, not *who checked*. Managed single-lab memory products can ship excellence *within* a lab; they cannot structurally claim bias-displacement, because the checking branch and the producing branch share the same incentive and error surface. The Federalist answer is not smarter monoculture; it is **ambition counteracting ambition** via N≥3 attested-distinct families before self enters durable reality.

---

## TOP_RISK

**Theater of quorum under P2 failure: N rubber-stamp votes from one cognition in N hats (or N fine-tunes of one family), cryptographically “diverse” at the count layer.**

- P1 (family-distinctness) is ~buildable (~5%→~40% loader-attested hard cap).  
- P2 (vote-independence) is ~0% and may stay only *estimable* — substrate sees bytes, not process.  
- **Compound risk:** signing an epoch_manifest over CLAIMED diversity *launders* theater into a V-4-anchored fact — worse than no ledger (D-OPUS dissent on epoch-FREEZE before D3-012).  
- **Mitigations (perfect design):** (1) enforce only on attested families; (2) operator-signed epoch freezes panel *slots* not just labels; (3) empirical decorrelation probe as advisory floor; (4) consolidation-time corpus anti-monoculture; (5) never claim vote-independence as enforced.  
- **Second-order risk:** corpus re-correlation via shared AGE graph even when families differ — treat consolidation as a governance event with its own quorum/attestation.

---

## VOTE on RQ externalization

| Question | Vote |
|---|---|
| Keep evolutionary search / panel breeding **external** (`ai-memory-rqgm` sibling)? | **YES — AFFIRM §25, eternity-grade** |
| Weld RQGM / co-evolving evaluators into `ai-memory` `src/`? | **NO — CUT 21/21; category error** |
| Adopt RQ **principles** (frozen epoch, N≥3 attested quorum, adversarial bias-check) inside L1/L2? | **YES — primary perfect architecture** |
| Make N≥3 multi-reflector quorum PRIMARY over pairwise-only or lab-signed family graphs alone? | **YES (§5 candidate 4; lab-cooperation-independent)** |
| Ship `enforce` before attested `model_family`? | **NO — theater** |
| Allow L3 to write live memories or mutate RuleEngine? | **NO — draft manifest only** |

**Ballot summary:** Externalize the optimizer; internalize the verifier and the freeze. Principles in; engine out.

---

## RATIONALE

**1. Federalist, not Platonic guardian.**  
§2.6 is Madison applied to cognition: the substrate does not trust aligned intent; it trusts intersection of decorrelated errors. Behavioral alignment can fail; structural separation of producer / reflector / law / stop / search cannot be substituted by a better monoculture.

**2. N≥2 is not enough.**  
Pairwise producer×reflector is necessary vocabulary but insufficient architecture. Correlated failure is module/swarm-level; quorum N≥3 is the only candidate that generalizes without depending on lab-signed lineage graphs (candidates 1/3 in §5 are incentive-compromised). Empirical probes (candidate 2) are the honest advisory floor while attestation matures.

**3. Category error of internal optimizers.**  
RQGM optimizes *agents*; endpoint memory governs *persistence*. A verifier that adversarially improves its own grading function is no longer a trustworthy verifier — Agent-as-Judge is the substrate trusting its trained grader. Grade: B+→A− with external L3 + P0 spine; C−/D+ if internal. Capability-orthogonal tools (signature counts, epoch freezes) survive ASI; utility gradients do not.

**4. Endpoint residence is jurisdictional separation.**  
Cloud monoculture memory is one more branch captured by one lab. Endpoint-resident L1 with LLM-agnostic boundaries (§2.7) is how the checking branch can be a *different* lab’s model under the customer’s keys — federalism across orgs, not only across processes.

**5. Honest limits preserve the constitution.**  
CLAIMED≠ATTESTED; vote-independence may never be fully measurable; “implements RQGM” is perma-banned. Perfect power-separation includes the humility to label what the substrate can count versus what it can only estimate — otherwise the republic signs theater into law.

**6. Ordering is separation.**  
D3-012 → D3-021; shadow utility before live; F-41+attestation before epoch consumer. Reordering is how good cryptography becomes laundering.

---

*Agent W1-A4 · Separation of Powers / Federalist Design · endpoint memory only · under 400 lines*
