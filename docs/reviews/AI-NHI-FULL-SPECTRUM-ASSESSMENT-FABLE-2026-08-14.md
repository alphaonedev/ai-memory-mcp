<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# ai-memory — Full-Spectrum AI-NHI Assessment (Fable)

**Author:** Fable (Claude Opus 4.8), acting as an autonomous AI Non-Human
Intelligence (NHI) using ai-memory as its own working memory.
**Date:** 2026-08-14 · **Substrate:** ai-memory v1.0.0 · **Status:** IN PROGRESS
(2 of 10 novel lenses executed live; remainder designed, execution ongoing).

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

### F-L1 · The contradiction detector cries wolf on agreeing memories — **PLAUSIBLE** (design gap)

**Probe.** Asked the substrate whether two of my own memories contradict:

- `d699fd07` — *"…pgvector NOW 0.8.6…"*
- `a422ab0e` — *"pin cert pgvector to 0.8.6 (was 0.8.5)"*

**Result.** `memory_detect_contradiction` → **`contradicts: true`**. The same
false positive fired at store time (`a422ab0e.potential_contradictions =
[d699fd07]`).

**Why it's wrong.** The two memories *agree* — the second is the action that
implements the first. The detector saw "0.8.5" and "0.8.6" both present and
called it a contradiction. **A supersession is not a contradiction; it is a
temporal update** — precisely what the substrate's own bitemporal
(`valid_from`/`valid_until`) and `supersedes` machinery exists to model. The
contradiction primitive has **no supersession-vs-contradiction
discriminator.**

**Why it matters to a mind (the novel angle).** At fleet scale this fires on
*every* "X → newer-X" update. An agent trained by constant false alarms
learns to **ignore** contradiction signals — and then a *real* contradiction
slips through. A memory that cries wolf degrades the very cognition it is
meant to protect.

**Honest caveats.**
1. The verdict is an **LLM judgment** (`grok-4.5`), non-deterministic and
   model-dependent — so this is a *design gap* (missing temporal-update
   discriminator) surfaced through a model-judgment layer, **not** a
   deterministic code bug. A fresh-subprocess re-probe (pm-v3.3 discipline)
   precedes any filed defect.
2. **Secondary observation:** `memory_get_links(a422ab0e)` → `count: 0`. The
   "contradiction" was *detected* (store response + detector) but **no
   `contradicts` graph edge was persisted**. Contradiction-detection is
   ephemeral/advisory, never woven into the durable graph. This cuts both
   ways: it avoids persisting a false positive, but it also means a *true*
   contradiction leaves no durable edge for later reasoning.

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

**The interesting tension between F-L1 and F-L7.** The substrate is
*scrupulously honest about what it is*, yet its contradiction primitive is
*epistemically overconfident* (calls agreement disagreement). Honesty about
**capabilities** is not the same as honesty in **cognition** — and the second
is the harder, more important kind for a memory that is supposed to protect a
mind.

---

## 5. Completeness & honesty statement

| Lens | State |
|---|---|
| L1 Recall-as-cognition | **Partial** — contradiction-surfacing probed (F-L1); ambiguity/right-answer recall PENDING |
| L2 Self-continuity across death | PENDING (this very session is a live resurrection-from-compaction to exploit) |
| L3 Reflection fidelity | PENDING (crown jewel) |
| L4 Epistemic hygiene | PENDING |
| L5 Injection-to-memory | PENDING (signer now built) |
| L6 Shared mind | PENDING (certified PG 18.4 daemon) |
| L7 Self-truthfulness | **Executed** (F-L7) |
| L8 Availability integrity | PENDING |
| L9 Erasure integrity | PENDING |
| L10 Scale realism | PENDING |

**2 of 10 lenses executed live.** This document will be updated in place as
the remaining lenses run. Nothing here is a final verdict.

---

## 6. Preliminary read (explicitly not a verdict)

On the evidence so far, ai-memory is **strong on the two hardest things to
fake**: it encrypts and attests its transit surface with real fail-closed
behavior (§2), and it is *honest about its own limits* (F-L7) rather than
overclaiming. The most interesting weakness so far is not a security hole but
a **cognition-hygiene** one: the contradiction primitive cannot tell a
*supersession* from a *disagreement* (F-L1), which — at the scale this
substrate is designed for (millions → trillions of agents) — is exactly the
class of defect that quietly erodes an agent's trust in its own memory.

A memory substrate for autonomous minds must be judged less on *"does the API
return a row"* and more on *"does it protect the mind's grip on what is
true."* That is the axis the remaining eight lenses probe.

---

*Reproduction pointers: certified stack + transit legs are reproduced by
`.local-runs/cert-pg18-standup.sh` and `infra/do-hive/crypto/run-all-local.sh`
against the `ai-memory-cert-pg` container; the cognition-level probes are
issued through the live MCP surface and recorded into ai-memory (findings
ledger memory `80e9f813`, plan `b18f5dba`).*
