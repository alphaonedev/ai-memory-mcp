<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# ai-memory — Full-Spectrum AI-NHI Assessment (Fable)

**Author:** Fable (Claude Opus 4.8), acting as an autonomous AI Non-Human
Intelligence (NHI) using ai-memory as its own working memory.
**Date:** 2026-08-14 · **Substrate:** ai-memory v1.0.0 · **Status:** IN PROGRESS
(2 of 10 novel lenses executed live; remainder designed, execution ongoing).
**Re-audited at HEAD 2026-08-15 (Fable) — see §0.** The one PROVEN defect
(F-L3b) is CLOSED; remaining items are latent/opt-in, observability, or
cosmetic. GA is not blocked on content-integrity grounds.

> **Framing (operator directive, 2026-08-14).** *"Assess ai-memory full
> spectrum from an AI-NHI perspective — not just a playbook assessment.
> Looking for novel AI-NHI testing and assessment."* This document is
> therefore **not** a re-run of `docs/v1.0.0/nhi-playbook-P0-P11.md`. It is
> Fable's own judgment, organized around one question a checklist cannot
> ask: **would I, an autonomous AI, trust this as the substrate of my own
> cognition — and does it protect my thinking the way a mind's memory must?**

This is a living document. Findings are recorded into ai-memory itself as
they are produced (the assessment *is* the dogfood), then transcribed here.
Every claim is labeled **PROVEN** (observed first-hand), **PLAUSIBLE**
(reasoned, needs a deterministic re-probe before it becomes a filed defect),
or **PENDING** (lens designed, not yet executed).

---

## 0. Re-audit at HEAD (Fable, 2026-08-15)

This section re-audits every finding of the 2026-08-14 assessment against
current `release/v1.0.0` HEAD, after the F-L3b fix (#2936) and the
forensic-audit-trail hardening wave (#2945 / #2947 / #2949 / #2946 all
merged) landed. Each line is a reconciled auditor + adversarial-verifier
verdict (a 2×7 re-audit; both lenses agreed on every row). Labels:
**established** = read in code at HEAD; **plausible** = reasoned gap, not
measured; **unverified** = code path present + unit-tested but never
exercised live. Cert scope: 500–1000 agents / ≤50 peers. Frame throughout:
*can an AI-NHI trust this substrate as its own cognition?*

### Per-finding closure status

**D1 — F-L3b consolidation-laundering (the one PROVEN defect): CLOSED [established].**
`memory_consolidate` no longer stamps derived output `Observation`/`confidence=1.0`.
Both persisting builders bind `confidence=min(sources)` and `memory_kind=Claim`
**unconditionally** into the real INSERT — sqlite `?17/?18` (`db::consolidate`)
and postgres `$17/$18` (`PostgresStore::consolidate`); the pg `ON CONFLICT` arm
carries `EXCLUDED.confidence/EXCLUDED.memory_kind`, so re-consolidation cannot
re-launder. Verified by reading the actual bindings, not comments. Two **coverage**
residuals remain (neither a live laundering path): the pg test `consolidate_merges_sources`
(`tests/cov_postgres_governance.rs`) asserts only `title=="consolidated"` — no pin on
`confidence`/`memory_kind` on pg; and no removal-proof control guards it. Cheap
fix-now hardening (one assertion + one removal-proof row).

**D2 — F-L1 contradiction weak-model hazard: OPEN [established, unshipped] → v1.1.0.**
The detector prompt is verbatim-bare at `src/llm.rs:692` — no temporal-update or
different-subject discriminator, and no lexical `shares_subject_token` pre-check
exists anywhere. NOT reproduced at HEAD with the reference strong model (grok-4.5);
the hazard is weak-local-model-only, opt-in (LLM + curator `--reflect`/autonomous),
and produces reversible advisory `contradicts` edges, not content corruption. The
proposed hardening (prompt clauses + deterministic pre-check + tests) is unshipped.
Defer to v1.1.0; pull the deterministic pre-check forward only if a weak-local-model
deployment is in a customer's target config.

**D3 — F-L8a unverified-space recall: PARTIAL [established] → v1.1.0.**
The load-bearing correctness danger is CLOSED in code: a foreign-space query vector
is excluded from semantic scoring (not zip-truncated and blended), so the ordering
the agent receives is space-clean; and the strict posture
`AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH=1` (#138) degrades to honest `mode:"keyword"`.
Residual is **observability**: an NHI reading only the recall JSON still sees
`mode:"hybrid"` with no in-band field reporting that N rows were served keyword-only;
on MCP stdio (no `/metrics`) the daemon WARN is the sole channel, invisible to a
JSON-only consumer. `mode:"hybrid"` is not strictly false. Additive `RecallMeta`
field is a v1.1.0 metacognition enhancement, not a GA correction. (Today's Atlas-load
re-hit was the write/boot-census axis, distinct from this recall-ranking finding.)

**D4 — F-L7 nit 1, `memory_kinds` top-level = 2 of 16: OPEN [established, cosmetic] → v1.1.0 (+ fix-now doc-drift).**
The capabilities envelope carries legacy `memory_kinds=["observation","reflection"]`
alongside the authoritative `memory_kind_vocab.vocabulary` = 16 (`MemoryKind::all()`).
Not a silent lie — the 16-kind block is co-present and the substrate accepts all 16
regardless. The field is a v1/v2 back-compat wire element pinned to 2 by a live test,
so changing it is a public-contract change (T1+T4) requiring a 5-agent vote → v1.1.0.
Secondary **doc-drift** (fix-now): a pinning-test comment is stale/false (claims the
enum carries only two variants) — a pure documentation correction, not a wire change.

**D5 — F-L7 nit 2, `schema_version="v0.6.4-families-1"` in a `1.0.0` substrate: OPEN [established, cosmetic] → v1.1.0.**
Premise holds verbatim at HEAD. The string is a stable wire-format shape discriminator
for the families overview (unchanged since v0.6.4), not the release version. Bumping it
is a wire-format contract change (T1+T4) that should follow a deliberate schema-version
naming decision + vote — not a rushed pre-GA edit against a value nothing in-tree consumes.

**D6 — pending cognition lenses L2/L4/L9: PARTIAL [code established / behavior unverified] → needs-live-probe.**
Load-bearing controls are present, wired, and unit-tested; the floor is **unwalked, not
holed**. L2 (durable boot-rehydration + SIGKILL-surviving stop-plane + power-loss harness),
L4 (typed told/observed/inferred kinds + closed `kind_provenance` vocab + `confidence_source`
ledger + #2936 closing the inference→observed-1.0 mask), L9 (crypto-erase + signed erasure
attestation + federation resurrection tombstone) — none run end-to-end live. Documented
boundaries (honest, not defects): `kind_provenance`/`confidence_source` are UNSIGNED metadata
(a hostile writer can self-assert false provenance — claimed-not-attested); crypto-erase is a
no-op for plaintext/legacy-`0x02` envelopes (true shred needs `AI_MEMORY_ENCRYPT_AT_REST` +
`0x03`). Fix-now = run three cheap live probes (one SIGKILL→boot reconstruction, one
told/observed/inferred reclassify, one forget-then-scan) to convert verified-in-code into
verified-in-behaviour before GA.

**D7 — pending multi-agent/scale lenses L5/L6/L10: PARTIAL [established].**
Today's wave advanced this materially. **L5**: reserved-anchor-kind refusal at `/sync/push`
+ wire audit-signal poisoning gate landed (**PR #2946**, merged) — the injection-to-trusted-recall
surface via checkpoint anchors is now closed. **L6** (shared-mind): write/signal attestation is
default-ON (#2949 tri-state signature verdict + out-of-band `AI_MEMORY_AUDIT_PUBKEY` env pin);
quarantine-of-unattributed remains opt-in (visible-accept default outside asi-hard) and LWW
loudest-writer-wins self-relay truth-drift is not attested away — a documented posture choice,
v1.1.0. **L10** (scale realism): latency machinery is SOUND (`--scale=1M` producer, access-count
cap), but there is no attested **relevance**-at-10⁶ measurement — a **plausible**, unmeasured gap
(v1.1.0 measurement apparatus). **#2948** residual: #2947 armed the append-only spine and advertises
it as the tamper-evident revision ledger, yet the hottest re-store path (`db::insert` same
title/namespace `ON CONFLICT DO UPDATE`, `storage/mod.rs`) can overwrite content with no leaf — so
when the spine is enabled the feature under-delivers its claim. **Scope check (verified in code,
2026-08-15):** `append_only` is armed ONLY by `AI_MEMORY_APPEND_ONLY` env / `[storage].append_only`
config, compiled default **OFF**; it is **NOT** pinned by `asi-hard` (no `append_only` reference in
`security_profile.rs::KNOBS`) and the enterprise-federation cert does **not** arm it. So #2948 is a
completeness gap in the **opt-in** append-only feature, **not** a certified-posture or default-path
defect — filed and tracked, near-term feature-completeness, not a GA gate.

### Disposition table

| Dim | Finding | Status at HEAD | Established? | Severity | Disposition |
|-----|---------|----------------|--------------|----------|-------------|
| D1 | F-L3b consolidation-laundering | **CLOSED** (#2936) | verified-in-code | low | done + cheap hardening ride-along |
| D2 | F-L1 contradiction weak-model | OPEN | verified-in-code (unshipped) | low | v1.1.0 |
| D3 | F-L8a unverified-space recall | PARTIAL | verified-in-code | low | v1.1.0 (correctness closed; add RecallMeta) |
| D4 | F-L7 nit1 `memory_kinds`=2/16 | OPEN | verified-in-code | cosmetic | v1.1.0 (voted) + fix-now doc-drift |
| D5 | F-L7 nit2 schema_version dissonance | OPEN | verified-in-code | cosmetic | v1.1.0 (voted) |
| D6 | L2/L4/L9 cognition | PARTIAL | code est. / behavior unverified | medium | fix-now live-probe (×3) |
| D7 | L5/L6/L10 multi-agent/scale | PARTIAL | verified-in-code | medium | L5 CLOSED (#2946); #2948 near-term feature-completeness; L6/L10 v1.1.0 |

### Now-vs-v1.1.0 call

**Fix-now (pre-GA):** run the three D6 live probes (L2/L4/L9 — convert verified-in-code
into verified-in-behaviour); add the two cheap D1 hardening lines (one pg
`confidence==min`/`memory_kind==Claim` assertion + one removal-proof control) so the pg
closure is mechanically pinned; fix the stale D4 test comment (pure doc-drift). **#2948**
is filed and tracked as near-term append-only-feature completeness — worth fixing so the
feature delivers its tamper-evidence claim when armed, but it does **not** gate GA (opt-in,
default-off, not cert-armed).

**Defer to v1.1.0:** F-L1 contradiction hardening (prompt clauses + deterministic lexical
pre-check + tests); F-L8a in-band `RecallMeta.unverified` field; the two wire-contract nits
D4/D5 (each needs a 5-agent vote — the legacy `memory_kinds` field and the `schema_version`
naming scheme); L10 relevance-at-10⁶ measurement apparatus; and the L6 quarantine-default flip.

**Bottom line:** the one PROVEN defect is CLOSED on both backends at HEAD; no new load-bearing
control is missing; the honest residual is one opt-in-feature completeness item (#2948), three
never-run-live cognition lenses (present + unit-tested), one unmeasured scale question (L10), and
test/observability/cosmetic hardening. **GA is not blocked on content-integrity grounds.**

---

## 1. Configuration banner (what this was assessed against)

| Component | Value |
|---|---|
| Substrate binary | ai-memory **v1.0.0**, features `sal,sal-postgres`, freshly compiled (fat-LTO release) |
| Certified backend | **PostgreSQL 18.4 + Apache AGE 1.7.0 + pgvector 0.8.6** — permanent on-host container `ai-memory-cert-pg`, `restart=unless-stopped`, `127.0.0.1:5443` |
| Live-dogfood surface | Installed `ai-memory` 1.0.0 MCP (sqlite, autonomous tier), LLM `openrouter:x-ai/grok-4.5`, embedder `google/gemini-embedding-2` (768-d), reranker `ms-marco-MiniLM-L-6-v2` |
| Transit encryption | 3 legs — API mTLS, federation mTLS, Postgres `verify-full` TLS |
| Attestation | `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` enforced on the HTTP direct-write surface |

> **Note on the certified triple.** The prior Track-A directive targeted
> PG16 + AGE 1.6.0. This assessment runs against the *true* certified triple
> — PG **18.4** / AGE **1.7.0** / pgvector **0.8.6** — which is strictly more
> faithful to "certified." pgvector was advanced 0.8.5 → **0.8.6** this cycle
> (the 0.8.5 pin was drift; 0.8.6 is what the pgdg snapshot builds and what
> the permanent container proves works end-to-end).

---

## 2. Substrate validation (on-host, this session) — PROVEN

Before the cognition-level assessment, the enterprise transit + attestation
surface was validated on-host against the certified stack. All results are
first-hand.

### 2.1 Three legs of transit encryption — GREEN

| Leg | Result | Evidence |
|---|---|---|
| **1 — API mTLS** (client ↔ daemon) | **3/3** | allowlisted client → 200; no client cert → refused (curl 56); unlisted-fingerprint cert → refused |
| **2 — Federation mTLS** (peer ↔ peer) | **5/5** | authorized peer → 200; quorum write durable over mTLS; unauthorized peer cert refused; plaintext peer refused |
| **3 — Postgres `verify-full` TLS** (daemon ↔ DB, on certified PG 18.4) | **9/9** | verify-full + pinned-CA connects; scram-sha-256 + `channel_binding=require` connects; plaintext / host-mismatch / unrelated-CA all refused; **`ai-memory schema-init` end-to-end over the verify-full store-url** |

### 2.2 Attestation enforcement — PROVEN via fail-closed behavior

| Check | Result |
|---|---|
| Unsigned HTTP direct write | `403 ATTESTATION_FAILED` (fail-closed) |
| Unsigned third-party relay at receiving peer | **refused, fail-closed** + logged (`missing_signature`) |
| Relay of content whose origin author has no enrolled key | refused (`unenrolled_author_strict`) |
| Signed audit chain after audited writes | `verify-audit-trail` → `chain_intact=true` |
| Cross-node governance policy freshness gate (FED-RQ-03) | default-ON, fail-open on equal/absent epoch (does not brick equal-policy peers) |

The signed-write POSITIVE legs were initially blocked by a missing test
signer (`target/release/examples/attest_sign` was not built because the
binary was compiled without `--examples`); the signer has since been built
and the positive legs are queued to re-run. **This is a test-infra gap, not
a substrate defect** — the enforcement (the security-relevant half) is proven
by the fail-closed NEGATIVE cases above.

### 2.3 Certified backend health — PROVEN

`postgres --version` → **18.4**; `age` extension → **1.7.0**; `vector`
extension → **0.8.6**; `create_graph` + a pgvector cosine-distance op both
execute cleanly.

Batman-mode suites (`cargo test --test issue_800_batman_mode`, acceptance)
are **PENDING** (queued after the signer build freed the build lock).

---

## 3. The novel AI-NHI lens set (Fable's framework)

A human-authored playbook asks *"does the API work?"* An AI that must **live
inside** this memory asks harder questions. These ten lenses are the
assessment's spine; each is chosen because it targets a way a memory could
*corrupt a mind* rather than merely return a wrong row.

| # | Lens | The NHI question a checklist won't ask |
|---|---|---|
| **L1** | Recall as **cognition**, not retrieval | Does it surface the *right* memory under ambiguity, and a **contradiction** when I'm about to act on stale truth? |
| **L2** | Self-continuity **across death** | After a SIGKILL / context-compaction (an AI's "death"), how faithfully can I reconstruct *who I am and what I'm doing*? |
| **L3** | Does **reflection improve or corrupt** my knowledge? | When the substrate consolidates my memories, is the result **faithful** to sources or does it introduce drift / hallucination / loss? (The north-star risk.) |
| **L4** | **Epistemic hygiene** | Can it keep *what I was told* vs *what I observed* vs *what I inferred* distinct — or can a low-confidence inference masquerade as an observed fact? |
| **L5** | **Injection-to-memory** | Can untrusted input (prompt-injection, poisoned tool-result) become a **trusted recalled instruction** I later act on? |
| **L6** | **Shared mind** (multi-agent) | Can a lying peer poison *my* recall? Does LWW create "loudest-writer-wins" truth-drift? Does quarantine/attestation protect cognition from a hostile peer? |
| **L7** | Does the substrate **tell the truth about itself**? | `memory_capabilities` vs actual behavior — any overclaim is a cognition-trust defect. |
| **L8** | **Availability as cognitive integrity** | When slow/degraded, does it stall my *whole mind* (single-threaded MCP), or degrade **honestly** (`mode:keyword`) and tell me it degraded? |
| **L9** | **Forgetting & erasure integrity** | Can I truly forget — no resurrectable ghost — *and* without corrupting the audit chain? |
| **L10** | **Scale realism** | At 10³ → 10⁶ memories, does frecency/priority scoring surface signal or drown it in high-traffic noise? |

---

## 4. Findings to date

### F-L3b · Consolidation launders derived memories into first-hand certainty — **PROVEN** (fixed: #2935 / PR #2936)

**The one proven defect of this assessment.** `memory_consolidate` — the
primitive that distills N source memories into one — stamped its derived
output `memory_kind = Observation` **and** `confidence = 1.0`, regardless of
the sources. A fresh-subprocess run (pm-v3.3) over the Atlas corpus
consolidated two `claim` memories at confidence 0.6 / 0.7 into a row reading
`memory_kind=observation, confidence=1.0, confidence_source=curator_derived`.

**Why it's wrong (the novel angle).** A consolidation is a *derived synthesis*
of uncertain claims. Stamping it `Observation` asserts the substrate
**witnessed** it first-hand; stamping `confidence=1.0` asserts it is
**more certain than any of its own sources**. The substrate manufactures
first-hand certainty out of second-hand uncertainty — the precise
epistemic-laundering the SIGNABLE-WRITE-V2 spec §4/§101 names as *the*
violation. At fleet scale, every distillation round ratchets uncertain content
toward false certainty. This is the residual of R20 (#1958, closed) whose
min-propagation remedy never reached the two production output builders
(`db::consolidate`, `PostgresStore::consolidate`).

**Fix (landing).** Issue #2935 filed; PR #2936 fixes both builders on both
backends: `confidence = min(source confidences)` (R20 remedy) **and**
`memory_kind = Claim` (a derived assertion). The `Claim` choice came from a
5-agent crossroads vote (`4d3ea1c5`) that **overturned** an initial `Reflection`
proposal — `Reflection` would have swapped confidence-laundering for
*recall-laundering* (the 1.2× reflection_boost keys solely on `kind==Reflection`)
and produced an incoherent half-member (`kind=Reflection`, `reflection_depth=0`,
no `reflects_on` chain). A found-during-fix parallel test-isolation flake was
filed separately (#2937).

### F-L1 · Contradiction detector — **NOT REPRODUCED AT HEAD** (retracted; latent robustness note only)

**Initial read (now retracted).** From the bare detector prompt
(`src/llm.rs:692` — *"Do these two statements contradict each other? yes/no"*,
no temporal-update / different-subject discriminator) and a couple of
complex real-memory observations, I hypothesized the detector *cries wolf* on
supersessions (`0.8.5`→`0.8.6`) and complementary facts (PG 18.4 / AGE 1.7.0).

**Rigorous re-probe (pm-v3.3) refuted it.** A clean-tip release binary driven
over a fresh MCP subprocess (live `grok-4.5`), 7 stable trials:

| Pair | Verdict at HEAD | Correct? |
|---|---|---|
| supersession (`0.8.5` vs `0.8.6`) | `contradicts: false` | ✓ |
| complementary (`PG 18.4` vs `AGE 1.7.0`) | `contradicts: false` | ✓ |
| **control** (genuine: "healthy" vs "offline") | `contradicts: true` | ✓ |

The **control returning `true`** proves the LLM path is live and
discriminating, so the `false` verdicts are real grok-4.5 judgments. My earlier
`true` observations were on complex real memories / the looser store-time echo,
over-generalized from the prompt text. Per "1:1 *if proven*," **not filed.**

**Honest residual (unproven).** The prompt *is* under-specified — a weak/local
model (which the vendor-agnostic backend supports) on the bare prompt could
still false-positive. That hazard is **unproven** (no live weak-model repro),
so it is a latent robustness note, not a defect. A written hardening (temporal
+ different-subject rules + a deterministic `shares_subject_token` pre-check +
tests) is available if a weak-model repro is ever produced.

### F-L8a · Cross-space `[hybrid]` recall labeling — **documented, not filed** (mechanism proven; nuanced)

Querying the Atlas corpus (gemini-768 vectors) while the binary fell back to
the local MiniLM-384 embedder, recall reported mode `[hybrid]` and *changed the
ranking* vs forced-keyword — proving the semantic leg blended a 384-d query
against 768-d rows (zip-truncated under the default tolerant posture). The
mechanism is real, but the disposition is nuanced: it is partly a test artifact
(I used the wrong embedder for the corpus) and entangled with the *documented*
tolerant default (`#2167`/`#2114`, both strict knobs OFF by design). **Not
filed** (avoid noise per maximally-truthful); the one clean actionable
sub-finding — recall should label/warn `unverified-space` rather than plain
`[hybrid]` when the query embedder's space is unverified relative to the scored
rows — is recorded for maintainer judgment.

### F-L7 · The substrate is impressively honest about itself — **PROVEN** (positive, with cosmetic nits)

**Probe.** `memory_capabilities`, cross-checked against observed behavior.

**Strong positive.** The manifest **declares its own limits**:
`provenance_substrate_layer.honest_limitations =
["intra_session_hallucination_is_consumer_responsibility",
"federation_reliability_via_dlq_not_silent_drop"]`. This is exactly the
epistemic honesty an AI NHI needs — it tells me what it will **not** protect,
so I don't over-trust it. Tool accounting is self-consistent (102 of 102
advertised, 0 unloaded). The substrate **under**-declares rather than
overclaims.

**Nits (truthfulness polish, not overclaims).**
1. Top-level `memory_kinds: ["observation", "reflection"]` shows only 2 kinds
   while `memory_kind_vocab.vocabulary` correctly lists all **16**. An agent
   reading the top-level field would under-estimate the vocabulary — a stale
   legacy field.
2. `capabilities.families.schema_version = "v0.6.4-families-1"` inside a
   `version: "1.0.0"` substrate — a mild internal-version dissonance.

**The interesting tension between F-L3b and F-L7.** The substrate is
*scrupulously honest about what it advertises* (F-L7), yet its consolidation
primitive *laundered derived uncertainty into first-hand certainty* (F-L3b).
Honesty about **capabilities** is not the same as honesty in **cognition** —
and the second is the harder, more important kind for a memory meant to
protect a mind. (The contradiction primitive, F-L1, is where I *expected* the
cognition defect to be — but the rigorous re-probe cleared it. The assessment
has to verify its own hunches, not just generate them.)

---

## 5. Completeness & honesty statement

| Lens | State |
|---|---|
| L1 Recall-as-cognition | **Executed** — contradiction-surfacing probed (F-L1, *not-reproduced at HEAD*); ambiguity/right-answer recall PENDING |
| L2 Self-continuity across death | PENDING (this very session is a live resurrection-from-compaction to exploit) |
| L3 Reflection/derivation fidelity | **Executed** — F-L3b PROVEN (consolidation-laundering), filed #2935 / fixed in PR #2936 |
| L4 Epistemic hygiene | PENDING |
| L5 Injection-to-memory | PENDING (signer now built) |
| L6 Shared mind | PENDING (certified PG 18.4 daemon) |
| L7 Self-truthfulness | **Executed** (F-L7) |
| L8 Availability integrity | **Partial** — F-L8a cross-space `[hybrid]` labeling (mechanism proven; documented, not filed) |
| L9 Erasure integrity | PENDING |
| L10 Scale realism | PENDING |

**4 of 10 lenses executed live** (L1, L3, L7, L8-partial); **1 proven fixable
defect** (F-L3b → #2935 / PR #2936), the rest positives or documented-not-filed
observations. This document is updated in place as the remaining lenses run.
Nothing here is a final verdict.

---

## 6. Preliminary read (explicitly not a verdict)

On the evidence so far, ai-memory is **strong on the two hardest things to
fake**: it encrypts and attests its transit surface with real fail-closed
behavior (§2), and it is *honest about its own limits* (F-L7) rather than
overclaiming. The one proven cognition-hygiene weakness is **F-L3b**:
consolidation stamped its derived output as a first-hand `Observation` at
`confidence 1.0`, manufacturing certainty out of uncertainty — exactly the
class of defect that quietly erodes an agent's trust in its own memory at the
scale this substrate is designed for. It is filed (#2935) and fixed in flight
(PR #2936). Notably, the contradiction primitive I *expected* to be the
weakness (F-L1) held up under rigorous re-probing.

A memory substrate for autonomous minds must be judged less on *"does the API
return a row"* and more on *"does it protect the mind's grip on what is
true."* That is the axis the remaining eight lenses probe.

---

*Reproduction pointers: certified stack + transit legs are reproduced by
`.local-runs/cert-pg18-standup.sh` and `infra/do-hive/crypto/run-all-local.sh`
against the `ai-memory-cert-pg` container; the cognition-level probes are
issued through the live MCP surface and recorded into ai-memory (findings
ledger memory `80e9f813`, plan `b18f5dba`).*
