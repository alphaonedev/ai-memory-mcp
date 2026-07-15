---
layout: doc
---
# TRACT L1 Claim contract (G22) — NORMATIVE / UNIMPLEMENTED

> **STATUS — read this first.** This document is the **normative migration
> contract** for TRACT gap **G22** (#1836): the frozen 9-field Claim object +
> the six-verb closed algebra that TRACT L1 specifies. **The substrate does
> NOT implement the closed Claim algebra at v1.0.0.** ai-memory stores a thick
> 28-field `Memory` row (`src/models/memory.rs`) manipulated by RPC-style verbs;
> the TRACT L1 kernel is the INVERSE arrangement (a thin Claim kernel that the
> thick row *projects from*). Per the TRACT canonical-gaps doc, the full G22
> inversion is **Phase-C / v1.x** work and MUST NOT be attempted inside the
> v1.0.0 compat freeze. Do **not** read this as a claim of TRACT-/L1-
> conformance — the honesty ledger (§5) explicitly forbids that until the
> inversion lands. This contract exists so the gap is a *tracked, specified*
> defect (§24 prime directive) with a concrete v1.x target, and so the other
> Tier-B TRACT-gap items reference one canonical L1 kernel definition.

This is the **canonical root** for the Tier-B TRACT-gap conformance work: the
data-model divergences in the sibling items (#1833/#1832/#1830/#1829/#1839/
#1862/#1863/#1864) are described against the kernel defined here.

## 1. The frozen 9-field Claim (TRACT §1/§2)

A field is frozen-core iff it cannot be recomputed from {the rest of L1} +
{the active Reference Profile}. Everything recomputable is a derived projection
below the frozen line.

| # | Claim field | TRACT shape | Purpose |
|---|---|---|---|
| 1 | `id` | `BLAKE3-256(dCBOR(content) ‖ 0x00 ‖ dCBOR(provenance))` — CIDv1 | content+origin identity; `owner` deliberately NOT in the preimage |
| 2 | `kind` | `fact \| episode \| skill \| policy \| relation` (5, authored, hashed) | a *kind* tag, not a class |
| 3 | `content` | `{ mime, bytes }` — L1 is content-BLIND | the asserted payload |
| 4 | `provenance` | `{ asserter, source, span, valid_time, transaction_time }` — bitemporal, hashed | who/where/when |
| 5 | `owner` | lineage-DAG node ref — transferable by succession, NOT hashed | governs the claim |
| 6 | `confidence` | `{ value_at_assert, basis }` — immutable authored record, NOT hashed | confidence AT ASSERT |
| 7 | `attestation` | `{ level: claimed\|attested, sig_writer, sig_witnesses[], algorithm_id }` — append-monotone | trust ladder |
| 8 | `lifecycle` | `asserted \| superseded(by) \| forgotten(receipt)` — append-only | never in-place edited |
| 9 | `links` | `[ RELATE{ predicate: kernel-id \| open-CID, target, sig } ]` — ≤10 kernel + open CIDs | typed signed edges |

**Derived / residency (L2/L3 — NEVER frozen, NEVER hashed):** embedding, tier
(hot/warm/cold/tombstone), lod, cache_key, schema_cid, the `confidence_value(t)`
decay overlay, salience/access/CONSUME counts — carried as columns of the
Reference-Profile row, which is a *documented projection* of the Claim.

## 2. The six-verb closed algebra (TRACT §2)

The entire write surface; everything else composes from these.

| Verb | Meaning | Discipline |
|---|---|---|
| **ASSERT** | add a Claim with provenance; born *claimed* | no content without a binding |
| **RELATE** | typed directional signed edge | belief revision is a graph op |
| **RECALL** | owner-scoped relevance retrieval | **a pure read — reads never write** |
| **ATTEST** | raise *claimed → attested* | the only path to trust |
| **SUPERSEDE** | forward correction (new Claim + link) | **no UPDATE** |
| **FORGET** | witnessed-policy erasure; signed tombstone remains | **no silent DELETE** |

Kernel link predicates (frozen floor, ≤10): `supersedes · contradicts ·
derived_from · caused_by · attests · part_of · relates_to · invalidates`
(8 load-bearing + 2 reserved). Every non-kernel predicate is a content-addressed
CID resolving to a self-describing definition-Claim.

## 3. Projection mapping — 9-field Claim ⇄ 28-field `Memory` (with divergences)

The v1.x kernel must satisfy this mapping (Claim → row). At v1.0.0 the arrangement
is inverted (row is the source of truth), and the projection is **lossy** — the
`Option`/⚠️ rows below are the exact divergences the executable
[`crate::claim::ClaimView`](../../src/claim/mod.rs) records as a machine-checked
drift-guard.

| Claim field | `Memory` source | Divergence |
|---|---|---|
| `id` | `Memory.id` (UUID) / `Memory.cid` (v74 `b3:…`) | ⚠️ **UUID is the PK/FK/LWW-tiebreak, NOT TRACT CIDv1.** `cid` is BLAKE3 but over a DIFFERENT preimage (`agent_id+namespace+screen(title)+kind+created_at+SHA256(screen(content))`), not `dCBOR(content)‖dCBOR(provenance)` under a CIDv1 envelope. |
| `kind` | `Memory.memory_kind` (`MemoryKind`, 13–16 variants) | ⚠️ lossy: a 16→5 collapse to the frozen `fact\|episode\|skill\|policy\|relation` is not canonically specified. |
| `content` | `Memory.content` (`String`) | ⚠️ no `mime`; bytes are a UTF-8 `String`, not `{mime, bytes}`. |
| `provenance` | `metadata.agent_id` + `source` + `source_span` + `valid_from`/`valid_until` (v79) + `created_at` | ⚠️ synthesized from ≥4 columns; `valid_time` (bitemporal) only exists since schema v79. |
| `owner` | — | ⚠️ **UN-PROJECTABLE.** No lineage-DAG owner ref exists; `metadata.agent_id` is a claimed string, `scope`/`target_agent_id` are visibility, not ownership. `ClaimView.owner` is always `None`. |
| `confidence` | `Memory.confidence` (`f64`) + `confidence_source`/`confidence_signals` | ⚠️ `Memory.confidence` is MUTABLE (the decay sweep overwrites it, `confidence_decayed_at`), so `value_at_assert` may be unrecoverable. |
| `attestation` | `metadata.write_signature` + `attest_level` | ⚠️ single writer sig only; **no `sig_witnesses[]`** on a `Memory` row. |
| `lifecycle` | `Memory.lifecycle_state` (`LifecycleState`) | ⚠️ **different vocabulary** (Open/Active/Blocked/Done/Abandoned/Quarantined/Goal/Plan/Step), NOT `asserted\|superseded\|forgotten`; and see §4. |
| `links` | `MemoryLink` (separate table) | ⚠️ **not a column of `Memory`** — `ClaimView` requires the caller to pass link rows; a bare `&Memory` cannot populate it. |

## 4. Verb-semantics divergence (the DEFAULT path violates the closed algebra)

The closed algebra forbids in-place UPDATE (mutation is SUPERSEDE = a new claim)
and silent DELETE (removal is FORGET = a signed tombstone leaf that remains). The
substrate's **default** write path violates both:

- **No-UPDATE is violated by default.** For `human`/`agent` callers — and an
  `ai:*` NHI caller derives to `agent` — `memory_update` falls through to
  `db::update_with_expected_version` (`src/storage/mod.rs`), a plain in-place
  `UPDATE memories SET … version = version + 1`. SUPERSEDE-forward
  (`update_with_archive_on_supersede`) is selected ONLY for `edit_source ∈
  {llm, hook}`; the append-only revision-leaf spine is gated behind
  `AI_MEMORY_APPEND_ONLY` (default `false`).
- **No-silent-DELETE is violated by default.** The FORGET path
  (`storage::forget`) runs a literal `DELETE FROM memories` (both backends) and
  appends an identity+time+signature `forget_tombstones` row — a delete-plus-
  sidecar, not TRACT's "removal via a tombstone LEAF that remains in the claim
  spine."
- **RECALL purity** is *close* (post-#1869 recall does no synchronous
  write-back; access ladders fold off the hot path) but `access_count` still
  exists as a mutated field, so recall is not the strictly pure read TRACT
  specifies.

The TRACT-conformant machinery therefore **exists in-tree but is default-off** —
closing G22 is a default-flip (append-only / supersede / tombstone-leaf) **plus**
the kernel inversion, not building a new verb subsystem.

## 5. Conformance ledger (honesty)

| Property | v1.0.0 state |
|---|---|
| Six verbs exist as operations (ASSERT=store, RELATE=link, RECALL=recall, ATTEST=attest, SUPERSEDE=supersede, FORGET=forget) | ✅ present |
| Closed-algebra invariants (no-UPDATE, no-silent-DELETE) enforced by default | ❌ **NO** (§4) |
| 9-field Claim is the source of truth (row projects from it) | ❌ **NO** (row is source of truth) |
| TRACT-CIDv1 `id` | ❌ NO (UUID) |
| `owner` lineage-DAG | ❌ NO (un-projectable) |
| `ClaimView` read-only lossy projection (drift-guard) | ✅ shipped (`src/claim/`) — **non-authoritative, NOT conformance** |

**Forbidden claims (do NOT make):** "TRACT-/L1-conformant", "implements the Claim
algebra". These remain false at v1.0.0.

## 6. v1.x migration (the real G22 inversion — deferred)

Tracked as its own issue (filed 1:1 from #1836). The freeze-hostile redesign:
invert source-of-truth so the thin 9-field Claim kernel is authoritative and the
28-field row projects from it; flip the closed-algebra defaults (append-only /
supersede / tombstone-leaf ON); add the `owner` lineage-DAG ref; mint the
TRACT-CIDv1 `id`; move `links` into the kernel; and enforce no-UPDATE /
no-silent-DELETE. Gated on the CC0 conformance vectors (G24/#1837, now shipped)
so it is buildable against test-vectors, not prose.

---

*Normative for the v1.x G22 migration; NON-normative about v1.0.0 behavior except
where it states what is UNIMPLEMENTED. Byte layouts for the signed record classes
are authoritative in the format-decisions spec; TRACT L1 semantics are
authoritative here.*
