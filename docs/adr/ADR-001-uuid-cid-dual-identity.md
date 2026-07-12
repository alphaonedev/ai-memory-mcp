---
layout: doc
---
# ADR-001 — UUID / cid dual identity (C dual-binding)

Status: **ACCEPTED + IMPLEMENTED**

Date: 2026-07-12
Author: Claude Opus 4.8 (1M context) on behalf of @alphaonedev
Decision record: ai-memory memory `3cdc7834-2d7f-4826-be18-02da8537614d`
(2×5 adversarial vote `wf_a6806e03-4f7`; 5/5 wave-1 + 3/5 wave-2 for
**C dual-binding**, the two wave-2 dissents terminological — both agreed
the envelope signs the immutable genesis tuple, not the `uuid`, which *is*
the C mechanic).
Related: #1943 (this ADR), #1942 / #1941 (SignableWrite v2 crypto-core),
#1825 (G8 additive BLAKE3 content-id), crossroads-vote policy `4d3ea1c5`,
epic #1940 grant `f9a0f397`.
Spec SSOT: `docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`
§2.1.

---

## Context

The v1.0.0 crypto-core introduces the **SignableWrite v2 envelope** (#1942):
a per-write Ed25519 signature over a frozen, domain-tagged, canonical
CBOR-array pre-image (spec §2). A signature is only as meaningful as the
identity it commits to, so before the envelope could be frozen we had to
decide **which identity the signed bytes bind** — the record's `uuid` or
its content-address `cid`, or both.

Two record identifiers already coexist on every `Memory` row:

- **`uuid`** — the server-assigned primary key. It is the PK, the target of
  **every** foreign key (`memory_links.source_id` / `.target_id`
  `REFERENCES memories(id)`), and the **LWW total-order tiebreak** in CRDT
  merge (`crdt_merge.rs::remote_wins_lww` orders on
  `(updated_at, attest_rank, id = uuid)` — the #344/#345 deterministic-winner
  fix). It is **not signer-predictable**: in the #626 detached-signing flow
  the signer computes the signature *before* the server assigns the id, so a
  signature cannot commit a value the signer does not yet hold.
- **`cid`** — the additive, content-addressed `b3:<hex>` identity added at
  schema **v74** (#1825, G8). It is minted from a memory's immutable
  **genesis** fields and sits *alongside* the `uuid` without displacing it.

The envelope must commit a tamper-evident, receiver-recomputable identity
that a clean-room, offline, 100-year R24 verifier can re-derive from the
artifacts alone. That requirement, plus the two identifiers' existing
disjoint jobs, forced the choice below.

## Decision

Adopt **C dual-binding** with **disjoint, frozen roles** — the two
identifiers keep separate authorities and are co-bound at genesis so they
can never disagree about *which record* is meant. **The code already forces
this shape; the ADR ratifies it.**

- **Signed identity = the cid-genesis content-identity.** The v2 array
  commits the `canonical_cid_preimage` **six-tuple** that v1 already signs:
  `agent_id, namespace, screen(title), memory_kind, created_at,
  SHA256(screen(content))` (`sign.rs` ≡ `cid.rs::canonical_cid_preimage`).
  `cid = b3(genesis)` is therefore the **tamper-evident,
  receiver-recomputable, screen-mode-independent** signed content-address.
  (BLAKE3 is the outer address hash only; the inner content digest and the
  audit spine stay SHA-256.)
- **The envelope does NOT sign the `uuid`.** The `uuid` is server-assigned
  and not signer-predictable (above), which is exactly why the v1 six-field
  envelope already omits it.
- **`uuid` stays the storage / convergence authority — alone.** PK + every
  FK + the LWW tiebreak. `cid` **never** arbitrates a merge.
- **`cid` stays the signed content-identity — alone.** It is what the
  signature, the SubkeyCert chain, and the content digest anchor to.

Each question therefore has **exactly one** authority:
storage / convergence → `uuid` alone; signed content-identity → `cid`
alone. This resolves the dual-truth hazard (two identifiers arguing over one
role) by giving them **disjoint total roles**, not by ossifying an overlap.

### Status: IMPLEMENTED

The decision **and** its implementation are landed; this ADR document was
the remaining #1943 deliverable.

| Landed piece | Commit | Notes |
|---|---|---|
| v74 `cid` + `cid_genesis` columns (+ `idx_memories_cid`) | `2abf9668` (#1825, G8) | additive BLAKE3 genesis content-id, both backends; `cid_genesis` NULLed on erasure while `cid` is retained (no confirmation-oracle) |
| Stage-1 v2 envelope — pinned CBOR-array encoder + `SignableWriteV2` (commits the cid-genesis six-tuple) + golden vectors | `2254d534` (#1942) | `src/identity/cbor_array.rs` |
| Stage-3 live v2 verify path (cert → write → suite) | `9a2d2863` (#1942 / #1941 / #1945) | envelope verify wired onto the write path |

## Consequences

- **No dual-truth ambiguity.** A reader never has to decide which id
  "wins" for a given question — the authorities are disjoint and total.
- **Zero v1.0 cutover.** Storage stays byte-identical to schema v78; the
  envelope is additive and the `uuid`-keyed storage/merge machinery is
  untouched. Honors the ADR-only mandate for #1943.
- **NULL-`cid` `version >= 2` rows** (e.g. an undecryptable row, or a row
  re-stored after erasure) are handled by the existing **v74
  backfill-on-restore** path — not a v1.0 gap.
- **Erasure stays clean.** `cid_genesis` is destroyed on `RecordKind::Forget`
  so a forgotten row's signed identity cannot be re-derived (and the retained
  `cid` digest cannot act as a confirmation oracle).
- **Deferred (explicitly not pre-bought):** any move to **pure
  content-addressing** (an IPFS / Merkle-DAG model where the content-address
  *is* the primary key and the FK target) remains a **future breaking
  migration**. This envelope does not pre-buy it — `cid` is additive and
  advisory-to-storage, never the PK.

## Alternatives rejected

- **A — sign the `uuid` (uuid-only identity).** Rejected: it would freeze a
  100-year signature over a **random, opaque, server-assigned handle** that a
  clean-room verifier can never re-derive from content, and the `uuid` is not
  even available to the signer at signing time in the #626 detached-signing
  flow. A signature over an un-recomputable id is unverifiable by an offline
  reader — the opposite of the R24 goal.
- **B — make `cid` authoritative (cid-primary).** Rejected as **unsatisfiable
  additively**: `cid` is nullable (`Option<String>` — NULL on undecryptable
  and on `version >= 2` re-stored rows), it is **non-unique** so it cannot be
  a primary key, and `cid_genesis` is **destroyed on forget**, so a forgotten
  row's signed identity would be un-re-derivable. Promoting `cid` to the
  storage/FK/merge authority would require a breaking migration — precisely
  what the additive-only v1.0 mandate forbids. (B is the same pure
  content-addressing model listed under *Deferred* above.)

---

*C dual-binding is the decision the code already enforces: storage/convergence
is `uuid` alone, signed content-identity is `cid` alone, and the v2 envelope
signs the cid-genesis six-tuple — never the `uuid`.*
