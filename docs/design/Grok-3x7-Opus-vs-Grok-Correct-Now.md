# Grok 3×7 — Opus vs Grok: What Is Correct Now (Reconciliation)

**Assessment date:** 2026-06-28  
**Method:** Second 21-lens council (3 waves × 7) comparing two first-party TRACT assessments of `release/v0.8.0`, with **CodeGraph** as tie-breaker (846 files / 27,062 nodes / 92,578 edges).  
**Measuring stick:** [`TRACT-the-definitive-endpoint-ai-memory.md`](TRACT-the-definitive-endpoint-ai-memory.md)  
**Inputs:**

| Analyst | Deliverable |
|---------|-------------|
| **Opus 4.8** | [`TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md`](TRACT-vs-ai-memory-v0.8.0-CORRECT-NOW-opus.md) |
| **Grok (xAI)** | [`Grok-TRACT-v0.8.0-Correct-Now.md`](Grok-TRACT-v0.8.0-Correct-Now.md) |

**Output:** This document — the **reconciled correct-now posture** after adversarial comparison. Companion gaps reconciliation: [`Grok-3x7-Opus-vs-Grok-Development-Gaps.md`](Grok-3x7-Opus-vs-Grok-Development-Gaps.md).

---

## Executive verdict (reconciled)

Both assessments agree on the headline:

> **ai-memory v0.8.0 is a strong, honest TRACT *L3-BODY Reference Profile* that nails the trust/governance/capability-cliff half of TRACT; it is not an L0/L1 frozen-core implementation.**

| Lens | Opus grade | Grok grade | **Grok reconciliation** |
|------|------------|------------|-------------------------|
| Safety / governance / capability cliff | **A−** | ~75–85% ROADMAP §2 | **A− / unanimous** |
| Data-model / six-verb algebra | **C / C+** | L1 ~25–35% | **C+** (Opus slightly generous on "Claim CORRECT") |
| L3-BODY (endpoint, transports, surface) | ~80% | ~80% | **~80% / unanimous** |
| Recall purity | partial | ~15% | **partial-correct measurement only** |
| Overall TRACT realization | ~45–50% | implicit ~50% | **~48%** |

**Grok reconciliation in one sentence:** Ship v0.8.0 as **TRACT-2026 L3-BODY** with **best-in-class governance honesty**; never advertise L1/CID/three-key/pure-recall conformance.

---

## 3×7 comparison method

### Wave 1 — Pillar-by-pillar agreement (7 lenses)

Compared Opus's 14-pillar scorecard vs Grok's ROADMAP §2 + TRACT § mapping.

### Wave 2 — Evidence discipline (7 lenses)

Re-verified disputed claims with CodeGraph (`touch_many`, `RuleEngine`, `run_decorrelation_probe`, `forget_if_superseded`, `SignableWrite`, `append_signed_event`).

### Wave 3 — Framing & procurement honesty (7 lenses)

Compared claims-discipline, divergent-defensible arguments, and score inflation risks.

---

## Unanimous correct-now (both assessments + CodeGraph confirm)

These are **load-bearing, shipped, and honestly labeled**. No adjudication needed.

### 1. Capability cliff — TRACT's deepest idea (**Opus A; Grok ✅**)

| Claim | Evidence |
|-------|----------|
| No "verified-safe" / safety-judge badge | `rg` zero production hits for weaponizable badges (Opus wave-3) |
| Substrate records scores, never maximizes | No in-core optimizer; RQGM external per ROADMAP §25.6 |
| `REFLECTION_DEPTH_EXCEEDED` fail-closed PRE-tx | `src/storage/reflect.rs:400-458`; CodeGraph → `emit_reflection_depth_exceeded_audit` |
| Decorrelation `enforce` INERT on claimed metadata | `src/curator/decorrelation_probe.rs:272-281` — **near-verbatim TRACT §7** |
| Signer ≠ thinker honored | `AttestLevel` = key-custody (`src/identity/verify.rs:159`) |

**Grok tie-break:** Opus's deeper `rg`-based absence proofs strengthen Grok's shorter claims. **Merged verdict: strongest correctness axis.**

### 2. Operational NHI Phase-0 (**both ✅**)

- Ed25519 keypair binding (`src/identity/keypair.rs`)
- **dCBOR** `SignableWrite` / `SignableLink` (`src/identity/sign.rs:358`) — TRACT `canonical() ≡ dCBOR` on *envelopes*
- `scope=private` + attestation gate (`src/identity/attest.rs`, `src/visibility.rs`)
- Boot lockout + durable stamps + `reown` (#1720 B1/B2/B3)

### 3. V-4 tamper-evident audit chain (**both ✅**, single-writer caveat)

- `prev_hash` + `sequence` (`src/signed_events.rs:51-69`)
- `verify_chain` + PE-8 `verify_audit_trail` CLI
- Deferred governance refusal drainer (#1732/#1734)
- **Caveat (both):** self-attested diary, not witness network — gaps doc

### 4. Read-only signed governance (**both ✅**)

- `RuleEngine::evaluate` read-only, first-refusal-wins (`src/governance/agent_action.rs:782`) — CodeGraph: `RuleEngine` struct + 14 `evaluate` callers
- Operator-signed rules only (`src/governance/rules_store.rs`)
- `Decision::Escalate` fail-closed (PE-5)
- Typed `GovernanceRefusal` + chain-logged refusals

### 5. Federation quarantine + Pillar 1 coordination (**both ✅**)

- Inbound lands `claimed`; forged sig unconditional reject (`src/federation/receive_auth.rs`)
- Peer enrollment secure default #1789
- Signed signals, attested checkpoints, actions/leases/routines (schema v59–v62)
- `authorize_remote_transition` fail-closed on authority lane (#1718)

### 6. Decorrelation advisory floor (**both ✅ near-verbatim**)

- `run_decorrelation_probe` visibility-only (`decorrelation_probe.rs:254` — CodeGraph confirmed)
- `CLAIMED_NOT_ATTESTED_CAVEAT` on every advisory (`:72-74`)
- ROADMAP §5 commitment without forgeable enforce badge

### 7. CONSUME ledger seam exists (**both partial-correct ✅**)

- `record_recall` + `mark_consumed` (`src/observations/mod.rs`) — **"surfaced ≠ used"**
- Wired: MCP recall → ledger; store/link → `mark_consumed` (`recall.rs:726`, `store/mod.rs:975`)
- **Caveat:** on-budget, wrong shape, recall still mutates — gaps doc

### 8. Backend-blind SAL + embeddings-as-cache (**both ✅**)

- `MemoryStore` trait (`src/store/mod.rs:615`); sqlite + postgres adapters
- HNSW async-rebuild; index loss ≠ memory loss (`src/hnsw.rs`)

### 9. Fail-closed secure defaults (**both ✅**)

- `permissions.mode=enforce`, SSRF/governance fail-closed, `FED_REQUIRE_SIG/NONCE/ENROLLMENT` defaults
- Embedder fail-closed → keyword mode (`src/embeddings.rs`)

### 10. Surface inventory + Pillar 1–4 closure (**Grok explicit; Opus implicit**)

Grok's mechanical table is the reconciled SSOT:

| Surface | v0.8.0 count |
|---------|----------------|
| MCP tools (`full` / `core`) | 100 / 7 |
| HTTP routes | 91 / 77 unique |
| CLI subcommands | 83 (85 sal) |
| Schema | v70 |
| Hook events | 27 |

### 11. Procurement / claims discipline (**Opus K; Grok §13**)

Opus documents ROADMAP §25.6 banned-claims vocabulary + 5-agent vote discipline more deeply. **Merged:** ai-memory's **claims honesty is itself a correct-now TRACT alignment** — both name the same banned grandeur.

---

## Adjudicated disagreements (CodeGraph tie-break)

### D1 · "One Claim object" — Opus ✅ vs Grok L1 ~25%

| Position | Argument |
|----------|----------|
| **Opus** | Pillar 1 CORRECT: single `Memory` struct, `memory_kind` over 13 kinds |
| **Grok** | L1 frozen 9-field Claim **not** implemented; UUID not BLAKE3-CID |

**Grok reconciliation:** **PARTIAL-CORRECT, not CORRECT.**

- **Opus is right** at TRACT *L3 projection* layer: one row type, kinds-not-classes (`src/models/memory.rs:51-115`).
- **Grok is right** at *L0/L1 literal*: no CID identity, 27 fields in hash preimage, owner outside TRACT grammar.
- **CodeGraph:** no `blake3` in `src/`; `Memory::FIELD_COUNT = 27`.

**Reconciled label:** ✅ **L3 kinds-not-classes** · 🟡 **L1 Claim object**

---

### D2 · Six-verb algebra — Opus 🟡 vs Grok spiritual cousins

| Verb | Opus | Grok | Reconciled |
|------|------|------|------------|
| ASSERT/RELATE | present | ✅ | ✅ |
| RECALL | present | ⚠️ mutating | 🟡 **shipped, non-conformant** |
| ATTEST | present | partial | 🟡 self-attest only |
| SUPERSEDE | path exists | partial | 🟡 opt-in llm/hook only |
| FORGET | present | partial | 🟡 archive+delete, no tombstone leaf |

**Grok reconciliation:** Grok's verb table is more TRACT-honest; Opus's "partial" is fair if read as *L3 transport mapping*, not L1 algebra.

---

### D3 · Recall / CONSUME — Opus "partial-correct" vs Grok "~15%"

**Both agree** on facts; differ in **score weighting**.

- `touch_many` on every recall path (`src/storage/mod.rs:1520` — CodeGraph blast-radius: recall post-ops)
- Ranking uses live `access_count` (`:3686-3691`) — Goodhart loop
- Ledger exists but sync + sqlite-primary

**Grok reconciliation:** **~15–20%** on recall-purity pillar (Grok); **"partial-correct on measurement seam only"** (Opus wording). Prefer Opus phrasing for operators, Grok percentage for planners.

---

### D4 · Endpoint thick-row TCB — Opus "honest divergence" vs Grok implicit

**Opus-only insight (adopted):** Co-located single-daemon + UUID row is **defensible L3-BODY engineering** for ~18–25 MB RSS endpoints; three-key separation and log-replay-at-query are **hub properties**.

**Grok reconciliation:** **Adopt Opus § honest divergence** into the canonical posture — with Grok's addendum: **durability-as-503-gate is never defensible** (bug, not tier choice; see gaps doc P0).

---

### D5 · Overall percentage — Opus ~45–50% vs Grok ~75–85% ROADMAP

Not a contradiction:

- **~75–85%** = ROADMAP §2 seven properties (moonshot implementation plan)
- **~45–50%** = TRACT L0–L1 constitution literal

**Grok reconciliation:** Report **both numbers** with explicit denominators — never conflate.

---

## Reconciled scorecard (post 3×7)

| TRACT pillar | Status | Notes |
|--------------|--------|-------|
| Capability cliff / no oracle | ✅ **CORRECT** | Unanimous; strongest axis |
| Operational NHI Phase-0 | ✅ **CORRECT** | dCBOR envelopes, visibility, reown |
| V-4 audit chain | ✅ **CORRECT** | Single-writer; not Merkle/witness |
| Governance RuleEngine | ✅ **CORRECT** | Read-only, signed, fail-closed |
| Decorrelation advisory | ✅ **CORRECT** | enforce INERT; caveat stamped |
| Federation quarantine + Pillar 1 | ✅ **CORRECT** | #1789, signals, checkpoints |
| Fail-closed threat matrix | ✅ **CORRECT** | Secure defaults |
| SAL + embeddings cache | ✅ **CORRECT** | Backend-blind |
| CONSUME ledger seam | 🟡 **PARTIAL** | Exists; not TRACT-shaped |
| One Claim (L1) | 🟡 **PARTIAL** | L3 kinds yes; L1 CID no |
| Six-verb algebra | 🟡 **PARTIAL** | Cousins; recall mutates |
| Recall purity | 🟡 **PARTIAL** | Measurement only |
| Endpoint tier manifests | 🟡 **PARTIAL** | Feature tiers, not ∅/A/B/C |
| Claims / procurement discipline | ✅ **CORRECT** | ROADMAP §25.6 + TRACT §16 |

---

## What Grok adds to Opus (net new)

1. **ROADMAP §2 property threading** — clearer moonshot mapping for operators
2. **Explicit MCP vs HTTP recall asymmetry** — MCP lacks #1580 read/write split
3. **Mechanical surface inventory table** — SSOT counts
4. **Pillar 4 closure checklist** — admission control, AGE deferred projection

## What Opus adds to Grok (net new)

1. **14-pillar TRACT scorecard** — faster TRACT-native navigation
2. **`rg` absence proofs** — no safety badge, no optimizer (stronger cliff evidence)
3. **Wave-3 durability/OSS/semantics** — archive-link restore v70, forensic offline verify, dogfood migration proof
4. **Honest divergence essay** — endpoint vs hub tier defensibility
5. **`forget_if_superseded` contradiction path** — autonomy curator collapses contradicts (CodeGraph: `src/autonomy.rs:483`, 3 callers) — belongs in gaps doc; Grok under-emphasized

---

## CodeGraph probes (this reconciliation round)

```
codegraph query "touch_many"              → src/storage/mod.rs:1520 (recall mutation)
codegraph query "RuleEngine"              → src/governance/agent_action.rs:707
codegraph query "run_decorrelation_probe" → src/curator/decorrelation_probe.rs:254
codegraph explore "forget_if_superseded"  → src/autonomy.rs:483 ← Opus-only gap anchor
codegraph explore "signed_events append"  → V-4 chain + deferred_audit
```

---

## Grok reconciled verdict — correct now

**Use Opus for TRACT-pillar navigation and capability-cliff depth; use Grok for ROADMAP property mapping and surface SSOT.** After 3×7 reconciliation:

1. **Unanimous:** v0.8.0 correctly implements TRACT's **trust spine** and **L3 Reference Profile body**.
2. **Split label:** "One Claim object" is **L3-correct, L1-incorrect** — do not merge the two.
3. **Adopt:** Opus honest-divergence framing for endpoint engineering; Grok explicit dual-percent reporting.
4. **Do not ship marketing** implying L1 conformance, pure recall, or decorrelation enforce.

**Operator one-liner:** *The substrate is correct now on safety, attestation, federation coordination, and honest epistemic labeling — and correctly incomplete on the frozen constitution.*

---

*Grok 3×7 reconciliation · CodeGraph tie-break · Inputs: Opus + Grok TRACT assessments · Measuring stick: TRACT-the-definitive-endpoint-ai-memory.md · Gaps: Grok-3x7-Opus-vs-Grok-Development-Gaps.md*