# Grok 3×7 — Opus vs Grok: Development Gaps (Reconciliation)

**Assessment date:** 2026-06-28  
**Method:** Second 21-lens council (3 waves × 7) merging two gap catalogs against **CodeGraph** + [`TRACT-the-definitive-endpoint-ai-memory.md`](TRACT-the-definitive-endpoint-ai-memory.md).  
**Inputs:**

| Analyst | Deliverable |
|---------|-------------|
| **Opus 4.8** | [`TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md`](TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md) |
| **Grok (xAI)** | [`Grok-TRACT-v0.8.0-Development-Gaps.md`](Grok-TRACT-v0.8.0-Development-Gaps.md) |

**Output:** This document — the **merged, deduplicated, prioritized gap roadmap** after Opus-vs-Grok adjudication. Companion correct-now reconciliation: [`Grok-3x7-Opus-vs-Grok-Correct-Now.md`](Grok-3x7-Opus-vs-Grok-Correct-Now.md).

---

## Executive verdict (reconciled)

| Metric | Opus | Grok | **Merged** |
|--------|------|------|------------|
| Gap count | ~35 named (P0–P3 + UNTRACKED) | 47 (P0–P3) | **52 unique** after dedupe |
| P0 blockers | 4 (G1–G4) | 8 (G-P0-01–08) | **8** (Grok superset; Opus G1–G4 ⊆) |
| UNTRACKED emphasis | Strong | Implicit | **14 UNTRACKED** flagged |
| Build order thesis | Safety spine first | 2–3 release cycles | **Unanimous** |

**Grok reconciliation:** Opus is **more precise on UNTRACKED blind spots** (append-only spine, contradiction collapse, CID migration). Grok is **more complete on P0 enumeration** (distributed verification split, behavioral decorrelation). **This document is the canonical merged backlog.**

---

## 3×7 merge method

### Wave 1 — ID alignment (7 lenses)

Mapped Opus `P0-G*` / `P1-G*` to Grok `G-P0-*` / `G-P1-*` by TRACT section + `file:line`.

### Wave 2 — Deduplication (7 lenses)

Collapsed synonyms; retained strictest evidence; flagged single-source gaps.

### Wave 3 — Priority + ROADMAP home (7 lenses)

Cross-walked `ROADMAP.md` §5, §11.4, §23, #1464, #1719, #1706/#1707; tagged **TRACKED** / **UNTRACKED**.

---

## Unanimous gaps (both catalogs, same evidence)

| Merged ID | TRACT | Consensus evidence | ROADMAP |
|-----------|-------|-------------------|---------|
| **M-P0-01** | §3 Commandment 5 | `touch_many` mutates recall + ranking uses `access_count` (`src/storage/mod.rs:1442-1483,3686-3691,10704-10727`) | #1706/#1707 |
| **M-P0-02** | §3 CONSUME | Ledger sync, per-recall rows, no distillation (`src/observations/mod.rs`) | #1706/#1707 |
| **M-P0-03** | §7 N≥3 enforce | Probe advisory; `enforce` INERT (`decorrelation_probe.rs:14-33`) | §5, #1719, #1171 |
| **M-P0-04** | §7 behavioral | No challenge-set / correlated-error metric | §5 candidate (2) |
| **M-P0-05** | §9 attestation default | `REQUIRE_AGENT_ATTESTATION` + `FED_REQUIRE_WRITE_SIG` opt-in | #1464 |
| **M-P0-06** | §7 family attestation | `model_family` claimed only (`decorrelation_probe.rs:55`) | §11.4.D, #1719 |
| **M-P0-07** | §11 epoch-freeze | `rg epoch_manifest` → 0 in `src/` | RQ-10 |
| **M-P1-01** | §2 CID identity | UUIDv4; no BLAKE3 (`storage/mod.rs:2083`) | UNTRACKED |
| **M-P1-02** | §5 sign-cause | `SignableWrite` output-bound (`identity/sign.rs:319`) | UNTRACKED |
| **M-P1-03** | §5 countersign | Self-attest diary (`identity/verify.rs:164`) | UNTRACKED |
| **M-P1-04** | §5 Merkle log | Flat `prev_hash` chain only | UNTRACKED |
| **M-P1-05** | §5 witness_level | Zero `src/` hits | UNTRACKED |
| **M-P1-06** | §2 FORGET tombstone | Hard DELETE paths | UNTRACKED |
| **M-P1-07** | §6 three keys | Single daemon TCB | UNTRACKED (hub) |
| **M-P1-08** | §8 fork_set | No recall `fork_set`; LWW merge (`crdt_merge.rs:228`) | Pillar 3 partial |
| **M-P1-09** | §8 durability tier | `503 quorum_not_met` write gate (`handlers/create.rs:665`) | PARTIAL-TRACKED |
| **M-P1-10** | §9 client sealing | Opt-in content encryption only | v0.9 E2E federation |
| **M-P1-11** | §9 tombstone-subscription | No replication back-edge | UNTRACKED |
| **M-P1-12** | §10 tier manifests | No ∅/A/B/C honesty manifests | UNTRACKED |

---

## Opus-only gaps (Grok under-emphasized — adopted)

### M-P1-13 · Contradiction auto-resolved in autonomy pass · **UNTRACKED** · Opus P1-G7

**TRACT:** §8 + §14 — contradiction conserved; permanent dissent; no silent collapse.

**v0.8.0:** `forget_if_superseded` (`src/autonomy.rs:483-543`) hard-DELETEs older contradicting memory when newer has higher confidence — called from `run_autonomy_passes`.

**CodeGraph:** `forget_if_superseded` → 3 callers in `autonomy.rs`; blast-radius on `forget` SAL path.

**Fix:** Replace hard-delete with conserved `fork_set` + signed tombstone; never let curator pick winner.

**Grok reconciliation:** **Promoted to P1** — Opus caught a spine break Grok's catalog missed.

---

### M-P1-14 · Append-only violated at write + erase ends · **UNTRACKED** · Opus P1-G6

**TRACT:** No UPDATE; FORGET = signed tombstone leaf.

**v0.8.0:**
- `storage::update` + `ON CONFLICT DO UPDATE` default path
- `EditSource::Human` in-place (`models/memory.rs:817-819`)
- Federation hard-delete without tombstone (`federation_receive.rs:446-449`)

**Grok reconciliation:** Merge with Grok G-P1-06; Opus provides **stronger erase-end evidence** (autonomy + federation).

---

### M-P1-15 · Fan-in ≤K and per-epoch reflection budget · Opus P0-G4 tail

**TRACT:** §11 bound reflection by D, K, B.

**v0.8.0:** Depth cap ✅ (`reflect.rs:413`); fan-in unbounded (`:317-334`); no epoch budget.

**Grok reconciliation:** Grok listed under §11 compounding; Opus correctly elevates **K/B** alongside epoch-freeze in **P0-adjacent** hardening.

---

### M-P1-16 · Promotion court / capability tokens / refusal-as-Claim · Opus P1-G9–G10

**TRACT:** §6 tokens; refusal readable as Claim; promotion adjudicated not automatic.

**v0.8.0:** `GovernanceRefusal` audit row (not recallable Claim); promote-on-access-count in `touch_many`; no capability tokens.

**Grok reconciliation:** Adopt Opus UNTRACKED tags; Grok had overlapping G-P1-07–G-P1-10 without promotion-court specificity.

---

### M-P1-17 · Human covenant clauses 1–2, 4–5 · Opus P2

**Grok reconciliation:** Merge Grok G-P2-07 with Opus detail (`why_trace`, dissent immutability, anti-coerced SUPERSEDE).

---

## Grok-only gaps (Opus thinner — adopted)

### M-P0-08 · MCP vs HTTP recall asymmetry

**Grok:** MCP `memory_recall` inline-touches; HTTP #1580 defers writes to phase-2 only.

**Opus:** Mentions mutating recall; less surface-specific.

**Grok reconciliation:** Add to **M-P0-01** fix scope — parity required across MCP/HTTP/CLI.

---

### M-P2-14 · Capability honesty (#1672–#1674)

**Grok:** `curator_mode` over-report; HTTP `verify_link`/`find_paths` 501; `db_schema_version` returns 0.

**Opus:** Wave-3 mentions honesty; less issue-specific.

**Grok reconciliation:** **Adopt as P2** — attestation-of-capabilities gap.

---

### M-P2-15 · Postgres archived_memory_links restore follow-up (v70)

**Grok G-P2-13** — table exists; postgres wiring tracked.

**Grok reconciliation:** Keep; Opus wave-3 notes v70 sqlite restore ✅.

---

## Adjudicated priority disagreements

### P0 count: Opus 4 vs Grok 8

| Opus P0 | Grok equivalent | Verdict |
|---------|-----------------|---------|
| G1 mutating recall | G-P0-01 + G-P0-02 | **Merge** — one epic, two sub-tasks |
| G2 N≥3 + model_family | G-P0-03 + G-P0-04 + G-P0-06 | **Keep split** — enforce vs behavioral |
| G3 attestation defaults | G-P0-05 + G-P0-08 | **Merge** — one flip epic |
| G4 epoch-freeze + K/B | G-P0-07 + M-P1-15 | **Split** — freeze consumer P0; K/B P1 |

**Reconciled P0 list (8):** M-P0-01 through M-P0-08 (Grok enumeration + Opus G4 K/B → P1).

---

### Durability 503 gate: bug vs tier

**Unanimous after reconciliation:** Opus "honest divergence" **does not apply**. **M-P1-09 is a bug** — partitioned node must keep writing locally; durability is subscription + recall surfacing, not synchronous 503.

---

### Three-key Stopper: gap vs hub deferral

**Unanimous:** **M-P1-07 UNTRACKED at hub**; endpoint ships **capability manifest** declaring what it cannot attest (TRACT §10). Do not block v0.9 on air-gapped three-key at phone tier.

---

## Merged gap roadmap (canonical)

### P0 — v0.9.0 blockers

| ID | Title | TRACKED | Primary fix |
|----|-------|---------|-------------|
| M-P0-01 | Kill mutating recall (+ MCP/HTTP parity) | #1706/#1707 | Decouple `touch_many`; pure `S(t)` |
| M-P0-02 | CONSUME ledger reshape + async distillation | #1706/#1707 | Epoch buckets; off-budget; RELATE edges |
| M-P0-03 | N≥3 decorrelation enforce gate | §5, #1719, #1171 | Write-time refusal after attested family |
| M-P0-04 | Behavioral decorrelation rung | §5 | Challenge corpus + correlated-error rate |
| M-P0-05 | Secure-default attestation flip | #1464 | Default-on + rollout escape hatch |
| M-P0-06 | Attested `model_family` primitive | #1719, §11.4.D | Cryptographic producer-family binding |
| M-P0-07 | Epoch-freeze consumer (verify-only) | RQ-10 | `SignableEpochManifest`; no optimizer |
| M-P0-08 | Distributed verification closure | #1464, §5 | Federation + agent paths default attested |

### P1 — v0.9.x structural hardening

| ID | Title | TRACKED |
|----|-------|---------|
| M-P1-01 | BLAKE3-CID parallel identity path | UNTRACKED |
| M-P1-02 | Sign-cause-not-output envelope | UNTRACKED |
| M-P1-03 | Countersignature + witness_level | UNTRACKED |
| M-P1-04 | Batch-Merkle transparency log | UNTRACKED |
| M-P1-05 | SUPERSEDE-not-UPDATE default | UNTRACKED |
| M-P1-06 | FORGET signed tombstone leaves | UNTRACKED |
| M-P1-13 | Stop contradiction collapse (`forget_if_superseded`) | UNTRACKED |
| M-P1-08 | Causal merge + `fork_set` on recall | Pillar 3 |
| M-P1-09 | Durability subscription (remove 503 gate) | PARTIAL |
| M-P1-15 | Reflection fan-in ≤K + budget ≤B | UNTRACKED |
| M-P1-16 | Capability tokens + promotion court | UNTRACKED |
| M-P1-07 | Hub three-key Stopper + endpoint manifest | UNTRACKED |

### P2 — v1.0 / conformance program

Client-side mandatory sealing · tombstone-subscription · tier ∅/A/B/C manifests · lineage-DAG succession · human covenant · CC0 test-vector harness · vector index substrate (§23) · federation E2E encryption · FED-RQ-02..05 · capability honesty #1672–#1674 · license/CC0 wire format (TRACT §13).

### P3 — proof-impossible (TRACT §15)

Vote-independence · signer≠thinker · legibility anti-ritual · singleton ASI · thin-client oblivious search · offline tombstone reach · civilization re-encode · append economics · deep-archive funding.

**Both assessments agree:** P3 items are **honesty labels**, not backlog lies.

---

## Opus vs Grok gap philosophy

| Dimension | Opus emphasis | Grok emphasis | **Use** |
|-----------|---------------|---------------|---------|
| Tagging | TRACKED / UNTRACKED | ROADMAP § crosswalk | **Opus tags on merged IDs** |
| Spine breaks | append-only, contradiction collapse | federation LWW, recall | **Both; M-P1-13 Opus catch critical** |
| Defensible deferrals | endpoint vs hub essay | tier manifest | **Opus framing + Grok manifest deliverable** |
| Enumeration | fewer, deeper P0s | 47-item completeness | **Merged 52 unique** |
| Phase sequence | safety-first build order | Phase A/B/C in gaps doc | **Identical: recall → attestation → L1 migration** |

---

## Reconciled development sequence (Grok)

### Phase A — v0.9.0 (close ROADMAP §5)

1. M-P0-01 + M-P0-02 (recall purity + CONSUME)
2. M-P0-06 → M-P0-03 + M-P0-04 (family attestation before enforce)
3. M-P0-05 + M-P0-08 (secure defaults)
4. M-P0-07 (epoch-freeze consumer, verify-only)

### Phase B — v0.9.x (spine integrity)

5. M-P1-13 (stop contradiction collapse) — **Opus priority boost**
6. M-P1-05 + M-P1-06 (SUPERSEDE default + tombstone FORGET)
7. M-P1-09 (durability subscription — **bug fix**)
8. M-P1-03 + M-P1-04 + M-P1-05 (diary → witness)
9. M-P1-08 (fork_set + causal merge)

### Phase C — v1.0 (constitution)

10. M-P1-01 + CC0 test vectors
11. Client sealing + tombstone-subscription
12. Hub Stopper + endpoint manifests

---

## Banned claims (unanimous — TRACT §16 + ROADMAP §25.6)

Do not market until gaps close:

- "decorrelation enforce shipped"
- "pure recall" / "reads never write"
- "TRACT L1 conformant" / "BLAKE3 Claim identity"
- "three-key separation on endpoint"
- "implements RQGM" (perma-ban)
- "ZK-synced semantic search"

---

## CodeGraph gap index (reconciliation probes)

```
touch_many              → M-P0-01 (both)
record_recall           → M-P0-02 (both)
run_decorrelation_probe → M-P0-03 (both)
forget_if_superseded    → M-P1-13 (Opus-only → adopted)
authorize_remote_transition → authority lane OK; data lane M-P0-05
SignableWrite           → M-P1-02 (both)
rg witness_level        → 0 hits → M-P1-05
```

---

## Grok reconciled verdict — gaps

After 3×7 Opus-vs-Grok merge:

1. **No material disagreement** on the deepest gap — **mutating recall** (M-P0-01).
2. **Opus wins** on UNTRACKED spine breaks (**contradiction collapse**, append-only erase).
3. **Grok wins** on P0 completeness and surface parity (**MCP recall**, capability honesty).
4. **Canonical backlog = this file** — 52 unique gaps, 8 P0 blockers, 14 UNTRACKED.
5. **Build order unanimous:** safety spine shipped ✅; next is **recall purity + attested decorrelation**, then **L1 migration spine**.

**Operator one-liner:** *The gap list is not two opinions — it's one substrate with two honest auditors; merge them and build Phase A.*

---

*Grok 3×7 reconciliation · 52 merged gaps · CodeGraph tie-break · Inputs: Opus + Grok gap catalogs · Measuring stick: TRACT-the-definitive-endpoint-ai-memory.md · Correct-now: Grok-3x7-Opus-vs-Grok-Correct-Now.md*