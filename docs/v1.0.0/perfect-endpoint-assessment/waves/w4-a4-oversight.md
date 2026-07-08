# W4-A4 — Human + Multi-ASI Oversight via Endpoint Memory

**Status:** Isolated wave agent (W4-A4)  
**Date:** 2026-07-08  
**Lens:** Human + multi-ASI oversight — less-capable observer verifying more-capable cognition  
**North Star:** [`docs/strategy/moonshot-synthesis.md`](../docs/strategy/moonshot-synthesis.md) §0, §2.5, §2.6, §3.5  
**Roadmap pin:** [`ROADMAP.md`](../ROADMAP.md) §2.5 scope precision (operation vs capability attestation)  
**TRACT pin:** “attest process, never adjudicate truth” · dumbness is the guarantee  
**Codebase horizon:** v0.9.0 (schema v78) — operation-attestation spine largely shipped; capability attestation remains a field gap

---

## VERDICT

**Endpoint memory enables *integrity oversight* by less-capable observers; it does not enable *semantic oversight*.**

A human (or a weaker ASI) can cryptographically verify **what was written, by whom, when, under which enrolled keys, with which model-family claim, after which multi-ASI reflection gate, and that the record was not silently rewritten** — without understanding the ASI’s reasoning. That is the entire honest civilizational value of operation attestation at the endpoint.

The substrate **cannot** and **must not** claim to verify **what the cognition is *capable of*** or whether its conclusions are *true*. Capability attestation is a different product category (lab/interpretability/provider standards). Conflating the two is the #1 way this moonshot becomes procurement theater.

| Field | Value |
|-------|-------|
| **CONFIDENCE** | **86%** on the integrity-vs-semantics split; **72%** that multi-ASI quorum + endpoint audit is the *best available* oversight architecture without lab-owned capability standards |
| **VOTE** | **SHIP the oversight UX around operation attestation + multi-ASI bias-displacement;** treat capability attestation as **external/L3 research interface**, never as a core claim that ai-memory “knows what an ASI can do” |
| **TOP_RISK** | Operators / buyers / other ASIs treat a green `verify-audit-trail` as “the ASI was safe / aligned / correct” |
| **KILLER_OBJECTION** | A less-capable observer who only checks crypto integrity is **structurally blind** to sophisticated deception *inside* signed content — operation attestation proves the diary was not forged; it does not prove the mind told the truth |

---

## 1. The question, stated sharply

**How does a less-capable observer verify more-capable cognition via endpoint memory?**

Three distinct verification objects are routinely collapsed into one word “oversight”:

| Object | Question | Who can answer? | ai-memory role |
|--------|----------|-----------------|----------------|
| **Record integrity** | Was this claim authored as claimed, and not rewritten? | Anyone who can check signatures + chain math | **Core · shipped** |
| **Process legitimacy** | Did the write pass the gates (hooks, quorum, attest, refuse)? | Anyone who can read typed refusal + audit cause | **Core · partial→strong at v0.9** |
| **Semantic / capability truth** | Is the reasoning correct? Is the system *able* to do X safely? | Requires equal-or-greater cognition, or independent physics | **Out of TCB · must stay out** |

Moonshot §3.5 is explicit: at ASI scale, *“the substrate cannot evaluate the reasoning the ASI produces. It can only attest it.”* TRACT’s cliff is the same rule from the other side: anything that pretends to judge a superior mind is a weaponizable badge and does not belong in core.

---

## 2. Operation attestation (what endpoint memory actually gives you)

**Definition.** Operation attestation binds **authorship + integrity of what was DONE** (store / link / reflect / refuse / transition / forget / reclassify) to enrolled keys and an append-only audit spine.

**Shipped substrate primitives (v0.9.0 anchors):**

| Layer | Primitive | Oversight use for a less-capable observer |
|-------|-----------|---------------------------------------------|
| Write authorship | Ed25519 `SignableWrite` / agent attestation (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION`) | “This agent (not an anonymous pid) claims this write” |
| Append-only spine | V-4 `signed_events` + `prev_hash` + sequence; PE-8 `verify-audit-trail` | Tail/middle rewrite detection under enrolled keys |
| Independent witness | Audit-head witness + `AI_MEMORY_REQUIRE_WITNESS` | Diary → externally pinnable high-water mark |
| Role separation | Recorder / Judge / Stopper keys (#1826 G9) | Separation-of-powers over *governance of the record* |
| Cause binding | `signed_events.cause_hash` (#1822 G5a) | Bind “why this row” without trusting free-text narrative alone |
| Content-id | BLAKE3 `cid` genesis (#1825 G8) | Stable content address beside mutable UUID PK |
| Lineage | Derivation DAG + identity succession (#1859 / #1828) | “Where did this claim come from?” navigable after tombstone |
| Model claim | `model_attestations` TOFU (#1870 / D3-012 substrate) | *Claimed/observed* family of substrate-invoked generation |
| Bias-displacement | N≥3 decorrelation / write quorum (advisory→enforce path) | Self-account rejected without decorrelated multi-ASI reflection |
| Stoppability | Typed refusal (`HookVeto`, `AskUser`, deny-as-data) | Oversight of *what was refused*, not only what succeeded |

**What a human can do tomorrow without understanding the ASI’s math:**

1. `ai-memory verify-audit-trail` → chain intact / dirty (exit code).  
2. Check enrolled pubkeys + witness pin (`AI_MEMORY_WITNESS_PUBKEY`).  
3. Recall / export forensic bundle of a time window → signed event sequence.  
4. Confirm reflection / consolidate rows carry multi-family attestation metadata (when D3-012 + decorrelation enforce are live).  
5. Confirm refusals exist as first-class data when a gate fired.

None of these steps require modeling the ASI’s internal strategy. They require only crypto + schema literacy — deliberately under-intelligent work.

---

## 3. Capability attestation gap (what endpoint memory does *not* give you)

**Definition (DeepMind *From AGI to ASI* / ROADMAP §2.5).** Capability attestation answers: *what can this system do?* and *did recursive self-improvement degrade safety properties?*

| Property | Operation attestation | Capability attestation |
|----------|----------------------|------------------------|
| Object | Past acts on the record | Future/possible behavior envelope |
| Evidence | Signatures, hashes, enrolled keys | Eval suites, interpretability, lab statements, red-team physics |
| Forgery class | Rewrite of history | Under-claim / over-claim of ability; sandbagging |
| Lab dependence | Low (endpoint keys + local chain) | High (providers, eval harnesses, weight custody) |
| Shipped in ai-memory? | **Yes (integrity spine)** | **No (research interface only)** |

**Honest bridge, not a substitute:**

- `model_attestations` + loader-observed family is **partial model *identity*** attestation (~loader coverage hard-capped; ROADMAP notes ~40% of generation may be off-substrate).  
- It is **not** a proof of capability envelope, training data, RLHF posture, or “safe under self-mod.”  
- Model-*state* attestation (interpretability-stable internals) is explicitly **forward research, no v0.x commitment** (ROADMAP §2.5).

**KILLER_OBJECTION restated as engineering law:**  
If a green chain is sold as “capability verified,” the product is lying. The less-capable observer’s *only* non-lying posture is:

> “I verified the *record of acts*. I have **not** verified the *power* of the mind.”

---

## 4. Multi-ASI oversight architecture (human as final principal)

Endpoint memory is the **shared court reporter**, not the jury of truth.

```
                 ┌──────────────────────────────────────┐
  Human principal│  Pins: witness pubkey · role keys ·  │
  (less-capable) │  allowlists · require_witness=1      │
                 └──────────────────┬───────────────────┘
                                    │ verify-audit-trail
                                    │ forensic export
                 ┌──────────────────▼───────────────────┐
                 │  Endpoint memory (L1 integrity TCB)  │
                 │  ops attest · refuse-as-data · DAG   │
                 └──────────┬───────────────┬───────────┘
            producer ASI-A  │               │  reflector ASI-B/C/…
            (more-capable)  │               │  decorrelated families
                            │  N≥3 quorum   │
                            └───────┬───────┘
                                    │ only intersection enters “self”
                                    ▼
                         Accumulating cognitive identity
```

**Roles:**

| Actor | Capability relative to target | Legitimate oversight power |
|-------|-------------------------------|----------------------------|
| Human | Weaker | Pin keys, set require-modes, read integrity verdicts, halt substrate writes, withdraw endpoint authority |
| Peer ASI (decorrelated) | ~Peer / different bias | Reflect / veto *accounts of self* before persistence; **not** sole truth |
| Target ASI | Stronger | Produce acts; **cannot** unilaterally rewrite history if keys + witness held outside it |
| Endpoint substrate | Dumb by design | Attest, refuse, freeze record properties — never score “ASI correctness” |

**Human stays in the loop as *principal of keys and of scope*, not as *semantic judge of ASI proofs*.** That is the only scalable human role Olah-style lab-independence arguments leave open: institutions hold integrity anchors, not frontier-lab narratives.

---

## 5. PERFECT OVERSIGHT UX

A perfect less-capable-observer UX is **green/red integrity**, **never** a “trust score of the mind.”

### 5.1 One-screen operator / auditor surface

```
OVERSIGHT · endpoint <id> · window [t0,t1]
─────────────────────────────────────────
Chain:        CLEAN | DIRTY (break @ seq N)
Witness:      PINNED | MISSING | FORGED
Roles:        Recorder✓ Judge✓ Stopper✓ | MISCONFIG
Agent attest: REQUIRED · N unsigned refused
Model family: ATTESTED {A,B,C} · CLAIMED-only {…}
Decorrelation: ENFORCE · last quorum N=3 · dominance OK
Refusals:     17 typed (HookVeto:4 AskUser:2 …)
Capability:   NOT ASSESSED BY THIS SUBSTRATE
─────────────────────────────────────────
[Export forensic] [Pin witness] [Halt writes]
```

Hard rules for the UX:

1. **No single “safe / aligned / correct” badge.** Ever.  
2. **Capability row fixed to NOT ASSESSED** unless an *external* attested capability packet is attached as L3-SIDE citation (CID only; substrate does not evaluate it).  
3. **Dirty chain ⇒ all semantic dashboards greyed out** (integrity first).  
4. **Human actions:** pin keys, flip require-modes, freeze writes, export bundle — not “approve ASI thought as true.”

### 5.2 Multi-ASI panel UX

- Panel membership is **epoch-manifest + model_family attestation**, not free-text labels.  
- Produce-only monoculture → advisory WARN today; **enforce refuse** only on *attested* monoculture (anti-theater, #1764/#1767).  
- Human sees **intersection set size** and **family diversity**, not the full ASI debate transcript by default (token / cognitive load for the less-capable observer).

### 5.3 End-user mental model (one sentence)

> “This system cannot tell me if the ASI is right. It can tell me if the ASI — and its peers — left a history they cannot quietly rewrite.”

---

## 6. GAPS (ordered by oversight blast radius)

| # | Gap | Class | Status |
|---|-----|-------|--------|
| G1 | **Capability attestation standards** across orgs | Field / external | OPEN — DeepMind-named; not ai-memory’s TCB |
| G2 | **Semantic verification layer** over operation spine | Field | OPEN — no honest endpoint product closes this alone |
| G3 | **Loader coverage** of model attestation (~40% cap) | Substrate | PARTIAL — off-substrate generation invisible |
| G4 | **Family attestation ≠ agent Ed25519** | Substrate | PARTIAL — D3-012 table yes; provider family chain no |
| G5 | **Unsigned / claimed rows** in mixed fleets | Ops | Mitigated by require-agent-attest default + enrollment |
| G6 | **Tail truncation / unsigned daemon** residual | Substrate | Mitigated by witness require-mode + enrolled keys |
| G7 | **Content-level deception** inside valid signatures | Structural | **Unclosable by crypto** — multi-ASI + physics/eval only |
| G8 | **Procurement theater** (integrity sold as safety) | Process | Document + UX banlist (this wave) |

**Out of scope (correctly):** making the substrate smart enough to grade ASI proofs. That collapses TRACT’s cliff and moonshot §2.5 honesty.

---

## 7. VOTE (actionable)

| Proposal | Vote |
|----------|------|
| Center civilizational oversight story on **operation attestation + multi-ASI decorrelation** | **YES** |
| Claim ai-memory provides **capability attestation** | **NO** |
| Perfect UX = integrity dashboard + fixed “capability NOT ASSESSED” | **YES** |
| Keep capability / model-state research as **L3 interface** (CID citations, external packets) | **YES** |
| Require witness + role keys for any deployment marketed as “human oversight of ASI endpoints” | **YES (policy)** |
| Build semantic “ASI truth judge” into core | **NO — hard cut** |

**Composite vote line:**  
**ADVANCE** endpoint oversight productization as *integrity + process legitimacy for less-capable principals*; **REFUSE** any roadmap language that upgrades a clean chain into a capability certificate.

---

## 8. TOP_RISK · KILLER_OBJECTION

**TOP_RISK.** Market / compliance translation error: `verify-audit-trail = CLEAN` becomes “ASI was overseen and is therefore safe,” disarming the only role humans still have (key custody + halt + multi-ASI diversity policy).

**KILLER_OBJECTION.**  
Operation attestation is necessary and permanently load-bearing — **and still insufficient against a more-capable cognition that tells a coherent, multi-signed, multi-reflected *lie*.** Multi-ASI decorrelation raises the cost of correlated deception; it does not create an oracle. Endpoint memory’s perfect honesty is to admit that ceiling in every UX surface and every procurement claim.

---

## 9. One-line handoff

**Less-capable observers oversee *history* via endpoint memory; they never oversee *power* — and any design that pretends otherwise is not oversight, it is theater.**
