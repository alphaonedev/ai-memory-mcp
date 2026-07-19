---
layout: doc
---
# TRACT L1 Claim contract (G22) — NORMATIVE / UNIMPLEMENTED

> **STATUS — read this first.** This document is the **normative migration
> contract** for TRACT gap **G22** (#1836): the frozen 9-field Claim object +
> the six-verb closed algebra that TRACT L1 specifies. **The substrate does
> NOT implement the closed Claim algebra at v1.0.0.** ai-memory stores a thick
> 30-field `Memory` row (`src/models/memory.rs`) manipulated by RPC-style verbs;
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

## 3. Projection mapping — 9-field Claim ⇄ 30-field `Memory` (with divergences)

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
substrate's **default** write path still violates the first and only partially
honors the second:

- **No-UPDATE is violated by default.** For `human`/`agent` callers — and an
  `ai:*` NHI caller derives to `agent` — `memory_update` falls through to
  `db::update_with_expected_version` (`src/storage/mod.rs`), a plain in-place
  `UPDATE memories SET … version = version + 1`. SUPERSEDE-forward
  (`update_with_archive_on_supersede`) is selected ONLY for `edit_source ∈
  {llm, hook}`; the append-only revision-leaf spine (#1823 G6) is gated behind
  `AI_MEMORY_APPEND_ONLY` (default `false`).
- **No-silent-DELETE is partially closed — but not TRACT-shaped.** The FORGET
  path (`storage::forget`) runs a literal `DELETE FROM memories` (both
  backends). Since schema v71 (G30) it appends an identity+time+signature
  `forget_tombstones` row in the same transaction, and since #1956 (R56
  crypto-erase) EVERY hard-delete path (forget / forget_for_caller / gc /
  size_gc) records a mandatory tombstone + per-record crypto-erase + a signed
  `substrate.crypto_erase` attestation on the audit chain. Hard deletes are
  therefore no longer *silent* — but they remain **delete-plus-sidecar** (the
  row is physically destroyed; the tombstone lives in a sidecar table), not
  TRACT's "removal via a tombstone LEAF that remains in the claim spine."
- **RECALL purity** is *close* (post-#1869 recall does no synchronous
  write-back; access ladders fold off the hot path) but `access_count` still
  exists as a mutated field, so recall is not the strictly pure read TRACT
  specifies.

The TRACT-conformant machinery therefore **exists in-tree but is default-off**
(or sidecar-shaped) — closing G22 is a default-flip (append-only / supersede /
tombstone-leaf ON) **plus** the kernel inversion, not building a new verb
subsystem.

## 5. Conformance ledger (honesty)

| Property | v1.0.0 state |
|---|---|
| Six verbs exist as operations (ASSERT=store, RELATE=link, RECALL=recall, ATTEST=attest, SUPERSEDE=supersede, FORGET=forget) | ✅ present |
| Closed-algebra invariants (no-UPDATE, no-silent-DELETE) enforced by default | ❌ **NO** (§4 — in-place UPDATE is the default path; deletes are tombstoned but physical delete-plus-sidecar, not spine leaves) |
| 9-field Claim is the source of truth (row projects from it) | ❌ **NO** (row is source of truth) |
| TRACT-CIDv1 `id` | ❌ NO (UUID) |
| `owner` lineage-DAG | ❌ NO (un-projectable) |
| `ClaimView` read-only lossy projection (drift-guard) | ✅ shipped (`src/claim/`) — **non-authoritative, NOT conformance** |

**Forbidden claims (do NOT make):** "TRACT-/L1-conformant", "implements the Claim
algebra". These remain false at v1.0.0.

## 6. v1.x migration (the real G22 inversion — deferred)

Tracked 1:1 as **#2052**. The freeze-hostile redesign:
invert source-of-truth so the thin 9-field Claim kernel is authoritative and the
30-field row projects from it; flip the closed-algebra defaults (append-only /
supersede / tombstone-leaf ON); add the `owner` lineage-DAG ref; mint the
TRACT-CIDv1 `id`; move `links` into the kernel; and enforce no-UPDATE /
no-silent-DELETE. Gated on the CC0 conformance vectors (G24/#1837, now shipped)
so it is buildable against test-vectors, not prose.

## 7. Open-predicate relations (G19, #1833) — PROVISIONAL mapping

The Claim `links` field (§1 field 9) is TRACT's **open predicate space over a
fixed kernel**: a caller authors an arbitrary predicate as a content-addressed
CID that is INVALID unless its definition-Claim (a gloss + ≥1 example) is
reachable in the same archive, over a frozen floor of ≤10 kernel relations
(`supersedes·contradicts·derived_from·caused_by·attests·part_of·relates_to·invalidates`,
8 load-bearing + 2 reserved). The substrate instead has a **closed 9-variant
`MemoryLinkRelation` enum + a DB `CHECK`** — a new relation needs a migration +
code change. The open-predicate mechanism is **UNIMPLEMENTED** at v1.0.0
(`crate::claim::relation::OPEN_PREDICATES_SUPPORTED = false`); closing it is the
freeze-hostile v1.x redesign (relax the CHECK, add authored-CID predicates +
definition-Claim resolution).

### 7.1 PROPOSED kernel mapping (NOT normative — v1.x is authoritative)

The compile-time drift-gate `crate::claim::relation::classify` proposes this
split; it is a **contestable design judgment surfaced, not settled** (the v1.x
open-predicate model — the actual consumer — decides). The `match` is exhaustive
with no wildcard, so a new relation variant breaks the build until classified.

| `MemoryLinkRelation` | Proposed | TRACT kernel / note |
|---|---|---|
| `related_to` | kernel | ≈ `relates_to` |
| `supersedes` | kernel | `supersedes` |
| `contradicts` | kernel | `contradicts` |
| `derived_from` | kernel | `derived_from` — ⚠️ but see §7.2 |
| `reflects_on` | extra | ⚠️ TRACT-homeless yet LOAD-BEARING (transcript replay, curator reflect-verify gate, forensic-bundle walks) |
| `derives_from` | extra | ⚠️ LINEAGE trio (see §7.2); distinct from `derived_from` (§7.3) |
| `decomposes_into` | extra | ⚠️ plausibly the inverse of the TRACT kernel `part_of` |
| `depends_on` | extra | substrate typed-cognition |
| `advances` | extra | substrate typed-cognition |

**Missing TRACT-kernel relations** (`crate::claim::relation::MISSING_TRACT_KERNEL_RELATIONS`):
`caused_by`, `attests`, `part_of`, `invalidates` — absent as `MemoryLinkRelation`
variants, with ZERO producers/consumers today. Adding a bare variant nothing
emits is dead vocabulary, so these are v1.x work (added with real producers).

### 7.2 Contested edge — the LINEAGE-trio bisection

`MemoryLinkRelation::LINEAGE = {DerivedFrom, ReflectsOn, DerivesFrom}` is a
single coherent provenance grouping in the code (uniform child→parent /
newer→older invariant, `is_lineage`). The §7.1 proposal splits it — `DerivedFrom`
kernel, the other two extras — which contradicts the substrate's own SSOT.
Whether the trio is one kernel concept or a kernel + two authored predicates is a
real v1.x decision; the drift-gate test pins that the proposal bisects it so the
tension can't be lost.

### 7.3 Latent defect — `derived_from` vs `derives_from`

These are NOT duplicates (opposite cardinalities: consolidation-merge N→1 vs
atomisation-split 1→N) but a near-homophone footgun; filed 1:1 as **#2055**
(now CLOSED — the footgun is documented + test-pinned in the link-relation
docs).

### 7.4 v1.x migration (deferred)

Tracked 1:1 as **#2054**. Relax the DB `CHECK` to a kernel + open-CID model; add
caller-authored CID predicates + definition-Claim reachability resolution;
migrate the 5 substrate extras to authored predicates or reversed-kernel
mappings; add the 4 missing kernel relations with real producers; resolve the
§7.2 bisection. Gated on the CC0 vectors (#1837).

## 8. The human↔AI covenant (G18, #1832) — where the 4 clauses stand

TRACT L1's human↔AI covenant is a four-clause mutual-obligation contract. It is
**NOT enforced by default** at v1.0.0: two clauses ship as opt-in (default
advisory-WARN) enforcement layers, one is ABSENT, and one is shipped as a
narrow, honestly-scoped primitive. Nothing in the substrate may assert "the
covenant is enforced" while §8.1 stands.

### 8.1 Clause ledger (honesty)

| # | Covenant clause | Substrate state at v1.0.0 |
|---|---|---|
| 1 | **`why_trace` write-gate** — a mutation must carry a recorded cause | ⚠️ OPT-IN (shipped via #2101; #2059 closed). `AI_MEMORY_REQUIRE_WHY_TRACE` gates the store write funnel on BOTH backends: a memory with no non-empty `metadata.why_trace` always WARNs; enforce mode REFUSES via the shared `GovernanceRefusal` envelope. **Default = advisory-WARN** — the mandatory-BY-DEFAULT flip is a freeze-hostile secure-default change and remains un-flipped (v1.x WARN-cycle discipline). |
| 2 | **Immutable authorship** — authorship cannot be silently rewritten | ⚠️ OPT-IN (shipped via #2101; #2060 closed). `AI_MEMORY_REQUIRE_IMMUTABLE_AUTHORSHIP` detects a caller-supplied `metadata.agent_id` rewrite at the update/merge funnel (defense-in-depth atop the silent `identity::preserve_agent_id` helpers, both backends): always WARNs, REFUSES under enforce. **Default = advisory-WARN**; the default-flip is likewise un-flipped. |
| 3 | **Permanent-dissent conservation (G7)** — a recorded dissent is never destroyed | ❌ ABSENT. No net-new dissent-conservation mechanism exists. **Freeze-hostile / v1.x** (net-new representation + write-path enforcement) → deferred **#2061**. |
| 4 | **Signed forget-receipt returned to the requester** — proof-of-erasure the requester actually receives | ✅ **SHIPPED** (v1.0.0, #1832). See §8.2. |

### 8.2 Clause 4 — the signed erasure attestation (shipped, de-branded)

The forget path (`storage::purge_and_tombstone_forget`) ALREADY computes and
persists, at forget time, a `forget_tombstones` row `{memory_id, namespace,
forgotten_at, agent_id, signature}` (schema v71, both backends), where
`signature` is the daemon audit key's Ed25519 over the versioned, content-FREE
[`forget_tombstone_signable_bytes`] pre-image (`forget-tombstone-v1\x00 ‖ id ‖
0x00 ‖ ns ‖ 0x00 ‖ forgotten_at`). Before #1832 that signature was DISCARDED —
`forget()` returned only a count.

#1832 surfaces it as a **read-only projection**, deliberately minimal so it
freezes essentially nothing new (the crypto contract — table columns, signable
pre-image, signature semantics — was already frozen at v71 / v0.8.1):

- `crate::db::ForgetReceipt` — `{memory_id, namespace, forgotten_at, agent_id,
  signature: Option<…>, signed: bool}`, `#[non_exhaustive]`.
- `crate::db::get_forget_tombstone(conn, id)` — projects the persisted row; never
  forgets, never re-signs.
- `crate::db::verify_forget_receipt(receipt, verifying_key)` — recomputes the
  signable bytes from the receipt's OWN fields (never a presented digest) and
  `verify_strict`s; verdict `Valid | Invalid | Unsigned`.
- CLI: `ai-memory forget --show-receipt <id>` / `--verify-receipt <id>`
  (query-only sub-modes of the existing `forget` command — no new top-level
  command, no MCP tool / HTTP route, mirroring the #1727 `undo-edit` CLI-only
  precedent).

**Relationship to the R56 (#1956) erasure attestation.** These are complementary
surfaces over the same forget transaction, not duplicates: R56's signed
`substrate.crypto_erase` event is an AUDIT-CHAIN record (surfaced by
`verify-audit-trail`) that crypto-erase ran on a hard-delete path; the forget
receipt here is the REQUESTER-facing projection of the v71 tombstone row —
the proof-of-erasure the requester actually receives.

**Honest scope (§2.5 discipline).** This is a right-to-be-forgotten RECEIPT
(proof a forget was RECORDED), **NOT** covenant enforcement — it is never named
"covenant" in any symbol. The signature commits ONLY to `{id, ns, forgotten_at}`,
NEVER content. On an unsigned daemon (no enrolled audit key — a common posture)
`signed = false` and the receipt carries identity + time but NO cryptographic
proof; `verify` returns `Unsigned`, never `Valid`. Because clauses 1–3 are not
enforced by default, a receipt can attest an erasure the full covenant might
have governed differently — the receipt makes NO claim beyond "this forget was
recorded."

### 8.3 v1.x migration (deferred, 1:1 issues)

Clause 3 (permanent-dissent conservation, G7) is tracked 1:1 as **#2061**. The
clause-1/2 enforce-BY-DEFAULT flips are v1.x secure-default work (the #2101
layers shipped default-advisory; flipping them rides the standard WARN-cycle
discipline). A postgres/HTTP/MCP forget-receipt surface beyond the sqlite CLI
is a separate additive v1.x follow-up (**#2062**).

## 9. Durability model — erasure cold tier is single-node; no no-primary multi-node placement (G16, #1830/#2064)

TRACT L2 wants an **(n,k) erasure-coded, no-primary cold tier** so any k-of-n
shards reconstruct the original — placed such that no single node is
load-bearing. As of #2064 (PR #2213, the operator-authorized
`reed-solomon-simd` dependency) the substrate HAS an opt-in **(k, m)
Reed-Solomon erasure-coded ARCHIVE cold tier** (`crate::erasure`): any k of
k+m shards reconstruct an archived row's bytes exactly, with per-shard +
whole-payload SHA-256 gates so loss/corruption beyond the m-shard parity
budget fails LOUD (degrade, never corrupt). **HONEST RESIDUAL:** shard
PLACEMENT is single-node (one local directory tree) — the tier hardens the
cold tier against partial disk corruption / lost shard files, NOT whole-node
loss, so the TRACT G16 end-state (**no-primary multi-node placement**) remains
the open residual. The executable anchor is `crate::durability`.

### 9.1 The actual durability model (honest taxonomy)

Codegraph-verified. There is **no** automatic full-copy replication; the label
"full-copy replication" would itself be an overclaim.

| Posture | When | Guarantee |
|---|---|---|
| **Local single-node** (default) | `synchronous = NORMAL` (`storage::connection::DEFAULT_DB_SYNCHRONOUS`), no quorum | One local SQLite DB (WAL). Survives a process crash; a **power loss** can lose the tail of un-checkpointed commits. **No replication.** |
| **Local single-node, power-loss-safe** | `AI_MEMORY_DB_SYNCHRONOUS = FULL`/`EXTRA`, or the `asi-hard` posture (#1961) | fsync-per-commit power-loss durability. Still single-node. |
| **Quorum-replicated** (opt-in) | `--quorum-writes > 0` with configured peers | Opt-in **W-of-N quorum** federation replication (`crate::replication` `QuorumPolicy`/`AckTracker`). This is quorum, **not** full-copy-to-N, and `crate::replication` is scaffolding **not wired into the store write path** (default `quorum_writes = 0`). |
| **Erasure-coded cold tier** (opt-in, #2064) | `AI_MEMORY_ERASURE_COLD_TIER` truthy | Opt-in (k, m) Reed-Solomon shard redundancy for the ARCHIVE cold tier: any k of k+m shards reconstruct exactly; loss beyond the parity budget fails loud. **Single-node shard placement** — `is_multi_node() == false` (whole-node loss is NOT survived; the no-primary multi-node placement is the G16 residual). The local power-loss posture is unchanged by this tier. |

### 9.2 The forcing-function anchor

`crate::durability::DurabilityModel` is a `#[non_exhaustive]` enum with exactly
the four shipped postures above; `resolve_durability_model` computes the live
DOMINANT posture from the REAL config (`synchronous` level, `quorum_writes`,
peers, the erasure cold-tier flag). The enum is consumed by wildcard-free
exhaustive matches (`label`, `is_multi_node`), so a future variant (the
no-primary multi-node tier) hard-breaks the build until it is consciously
wired AND this ledger is updated. The residual-honesty pin is
`durability::tests::g16_erasure_tier_exists_but_multi_node_is_still_quorum_only`:
the ONLY `is_multi_node()` posture is quorum replication — claiming multi-node
for the single-node-placed erasure tier would be an overclaim. The resolver is
CONSUMED at `serve` boot (`src/daemon_runtime.rs` — the "durability model:
<label>" disclosure line, closing the #2213 audit's F6 no-consumer note), so
the posture an operator actually has is disclosed, not assumed.

### 9.3 v1.x residual (no-primary multi-node placement)

The original #1830 blocker — the operator dependency-authorization decision —
RESOLVED on 2026-07-18 (`reed-solomon-simd` authorized; hand-rolling a
finite-field codec was vote-rejected, 5-agent vote `4d3ea1c5`), and the codec +
shard store + reconstruction/repair landed via #2064/PR #2213. What remains of
G16 is the **no-primary multi-node shard placement** (distributing the k+m
shards across nodes so any k nodes reconstruct with no primary). That is v1.x
federation-placement work; it enters through the §9.2 drift-gate (a deliberate
build-break-then-classify on the enum). The construction-independent acceptance
invariant is unchanged: **any k-of-n shards reconstruct the original bytes
exactly — across node loss, not just file loss.**

## 10. Retention — discrete TTL tiers, not a cost-of-access gradient (G15, #1829)

TRACT L2 wants retention to be a **continuous cost-of-access (Landauer)
gradient** — a single cost that scales with archival depth/age and GOVERNS
eviction, replacing discrete tiers. The substrate's retention/eviction is a
**discrete 3-tier TTL** model. The executable anchor is `crate::retention`.

> **"Landauer" here is a METAPHOR** (recall/retention should get *more expensive
> with depth/age*), NOT a literal `kT ln 2` thermodynamic model — the substrate
> implements no energy accounting, and §10 does not claim one.

### 10.1 Honest current state — do NOT claim "no gradient exists"

The eviction DECISION is discrete: a row's lifetime is `created_at +
Tier::default_ttl_secs()` (Short 6h / Mid 7d / Long permanent), and GC evicts on
expiry. That discreteness is the real gap. **But the substrate already has FOUR
partial age/access-gradient surfaces** — omitting them would be an
overclaim-by-omission (the inverse of §9's "glib label" trap). None GOVERNS
eviction; they are unbundled and serve different purposes:

| # | Surface | What it is | Symbol |
|---|---|---|---|
| 1 | **Recall ranking** | recency + capped access-count + tier bonus tilt *ordering* toward fresh/hot rows | the FTS score `+ MIN(access_count,50)*0.1 + … + recency_factor + tier_bonus` (`storage::mod`) |
| 2 | **TTL floor-extend on access** | an access raises `expires_at` by a per-tier floor — frequently-recalled rows live longer | `SHORT_TTL_EXTEND_SECS` / `MID_TTL_EXTEND_SECS` (`models::mod`), #1596 |
| 3 | **Confidence decay on touch** | a memory's `confidence` decays with age on recall touch | `crate::confidence::decay`, `ConfidenceSource::Decayed` |
| 4 | **Access-count promotion** | mid→long auto-promotion at 5 accesses; priority increments every 10 | recall-pipeline touch ops |

### 10.2 The true gap (localized)

There is **no single continuous cost that REPLACES discrete-tier eviction**. The
four surfaces above are *ranking / retention-extend / decay / promotion* signals,
each a different shape and unit; **none is an eviction-governing cost**, and they
are not unified. TRACT L2 wants one continuous cost-of-access function that
subsumes them and decides retention on a gradient rather than a 3-way tier cliff.

### 10.3 The forcing-function anchor

`crate::retention::RetentionModel` is a `#[non_exhaustive]` enum with the single
posture `DiscreteTtlTiers` and **no `CostOfAccessGradient` variant** — the absent
variant IS the machine-checked gap. It is **not** a floating anchor:
`Tier::default_ttl_secs` (the most-called TTL function — every eviction /
TTL-floor / archival / config-seed path) delegates through
`RetentionModel::current().ttl_secs_for(tier)`, so the enum has a real live
consumer on the hot path. The `ttl_secs_for` / `label` / `is_cost_of_access_gradient`
matches are exhaustive + wildcard-free, so adding a gradient variant hard-breaks
the build until it is consciously resolved AND this ledger is updated. The wiring
is provably byte-identical (the `DiscreteTtlTiers` arm returns exactly
`Tier::discrete_ttl_secs`) — pinned by
`retention::tests::model_ttl_matches_raw_discrete_values_for_every_tier` — so no
eviction behavior changed.

**No cost function ships** — not a GA `access_cost()` metric (an arbitrary,
consumer-less curve would freeze false-precision numbers via Hyrum's Law and
mint a fifth partial signal), not a test-only reference curve (property tests
over an unconsumed self-defined function are a tautology). The #1829 5-agent
vote `4d3ea1c5` rejected both.

### 10.4 v1.x migration (deferred, 1:1 issue)

A unified continuous cost-of-access model that GOVERNS eviction (subsuming the
four surfaces above) is v1.x, tracked 1:1 as **#2066**. Construction-independent
acceptance criteria for the eventual cost: **monotonically non-decreasing in
age/archival depth, non-increasing in recent access, and consistent with the
current tier ordering (cost `long < mid < short`).**

## 11. No latency-SLO degrade governor (G31, #1839)

TRACT L2 (Pillar 14) wants a **latency governor** that reads recall p95 and
selects a named degradation tier on a **latency budget** (full → drop rerank →
drop semantic → keyword-only), surfaced in the response — so "graceful
degradation tiers / latency-bounded recall" can be claimed. The substrate has
**no such governor**. This § pins the honest current state.

### 11.1 Honest current state — degrades are capability/load-cut, NOT latency

Do NOT claim a "degradation ladder." What actually exists:

| Degrade | Trigger | Axis |
|---|---|---|
| Embedder-failure → keyword (#1593) | the embedder is absent or `is_degraded()` — the query gets no semantic vector | **capability** (availability), not latency |
| Reranker-degraded → `degraded_lexical` (`reranker.rs`) | the cross-encoder fell back to a lexical scorer | **capability** |
| Admission-shed `503` (#1733) | global in-flight request cap exceeded | **load** — and it *rejects* the request (outermost middleware; it never reaches recall, produces no recall envelope, and is NOT a recall tier) |

The recall `mode` field (`hybrid+rerank` / `hybrid` / `keyword`;
`RECALL_MODE_*` in `models::recall_request`) reflects **which stages ran** — a
**capability cut** (embedder present → `hybrid`; + reranker re-order →
`hybrid+rerank`; else `keyword`). It is **not** latency-selected: a
`hybrid+rerank` recall may be slow and a `keyword` recall fast. All degrades
fire on FAILURE/LOAD, **never on a latency budget**. There is **no latency
governor** and **no named degradation ladder**; the G31 ladder's "drop semantic
*for latency*" rung **never occurs** (a `keyword` result only comes from
embedder absence, never a deliberate latency-driven semantic drop).

### 11.2 What #1839 shipped (honesty fixes, not the governor)

- **Recall p95 is now measured.** The `ai_memory_recall_latency_seconds`
  histogram was registered + `/metrics`-exposed (HELP "Recall latency in
  seconds, labeled by mode") but **never observed** — it reported permanent
  zeros (a §2.5 lie in the shipped surface). #1839 times the HTTP recall path
  (both sqlite + postgres backends) and `record_recall(mode, elapsed)`s into
  it, so the scraped metric is now truthful. This is **observability only** —
  nothing acts on it (measurement ≠ governance).
- **Mode vocabulary const-ified** (`RECALL_MODE_HYBRID`/`RECALL_MODE_KEYWORD`
  beside the existing `RECALL_MODE_HYBRID_RERANK`) — one typed source of truth,
  clearing a hardcoded-literal smell. NO degradation-tier type is minted: the
  recall modes are a 3-value capability vocabulary, and a `DegradationTier`
  enum would (a) fabricate arity (the 4th "drop-semantic" rung is unreachable),
  (b) be inert (nothing parses `mode` back — no read side / no forcing
  function), and (c) overclaim the very "graceful degradation tiers" the gap
  says cannot be claimed. The #1839 5-agent vote `4d3ea1c5` rejected it.

### 11.3 v1.x migration (deferred, 1:1 issue)

The latency governor (a p95-reading actuator) is v1.x, tracked as **#2068**. Per
the vote's wrong-axis finding it must reserve an **orthogonal actuation axis**
(candidate-set caps / per-stage time-boxing / partial results *within* a mode),
NOT assume the capability stages are the latency ladder.

## 12. Refusal is a typed error, not a recallable Claim (G10.2, #1862)

TRACT L1 wants a governance refusal to be a first-class **recallable Claim** so a
refused agent can `memory_recall` "was I denied X?" and let its own denial
history inform later reasoning + governance review. The substrate does **not**
persist refusals. The executable anchor is `crate::claim::refusal`.

### 12.1 Honest current state

A governance refusal is a typed `GovernanceRefusal` envelope
(`src/governance/refusal.rs`: `agent_id` + `action` + `namespace` +
`denied_level` + `owner` + `reason`) that is **minted in three independent
lanes** and returned as an **error** — never written to `memories`, never
recallable:

| Lane | Mint site | Handle |
|---|---|---|
| Permission-rule (K9) | `Permissions::evaluate` (`governance::mod`) — *stateless, every input a parameter* | no DB handle |
| Substrate-governance | `storage::enforce_governance` (`storage::mod`) via `evaluate_level` | `&Connection` (a choke for **this lane only**) |
| Agent-external | `wire_check::GOVERNANCE_PRE_ACTION` (`OnceLock` hook) | hook-scoped |

The ~21 `Deny` consumption sites (MCP tools + HTTP handlers) each render the
refusal to a string via the pure, identity-blind formatter
`governance::deny_message(action, gate, reason)` and return it.
`REFUSAL_PERSISTED_AS_CLAIM` (`crate::claim::refusal`) is `false`.

### 12.2 The forcing-function anchor

`crate::claim::refusal::RefusalClaim::of_refusal(&GovernanceRefusal)` projects a
refusal onto the read-only Claim shape it WOULD persist as (asserter + action +
namespace + denied_level + reason). It is **wired, not floating**:
`GovernanceRefusal`'s `Display` renders through the projection (its live
constructor on every refusal-format path), byte-identically — pinned by
`claim::refusal::tests::display_is_byte_identical_through_the_projection`. The
`#[non_exhaustive]` type + the `REFUSAL_PERSISTED_AS_CLAIM = false` honesty const
+ the round-trip drift-test machine-check the gap. **No persistence ships.**

### 12.3 Why persistence is deferred (v1.x, #2070) — the safety model is unbuilt

The #1862 5-agent vote (`4d3ea1c5`) verified in-tree that a naive persist-on-
refusal is freeze-hostile:

- **Re-entrancy.** The refusal-memory write re-enters `consult_governance_pre_
  write` UNCONDITIONALLY, and `CallerContext::for_admin` does **not** bypass it
  (it sets only `bypass_visibility`; the gate takes no caller context). So the
  refusal-write can itself be refused (silent audit loss) or recurse — no guard
  exists.
- **No central choke** across the three lanes → a single-lane persist is a
  misleading partial ledger (an agent reasons "I was never denied X" when it was,
  on an unwired lane).
- **Quota** is lose-lose: tool-layer → self-DOS the 1000/day cap under a denied-
  action retry loop; bypassed → unbounded flooding. No dedup.
- **Visibility/ownership** of a recallable refusal-Claim is undesigned; the safe
  answer (`scope=private`, owned by the refused agent) must be a hard acceptance
  criterion, not an assumption.

#2070 tracks the persist mechanism with the full safety model (re-entrancy guard,
three-lane coverage, private owner-scoping, opt-in default-OFF, dedup/rate-limit,
best-effort non-fatal, secret-screen, both backends) as acceptance criteria.

## 13. Promotion is not fully court-gated — access-count auto-promote is maintenance (G10.3, #1863)

TRACT L1 wants promotion above a configured tier to require an explicit, audited
approval flow — "a memory reaches `long` by being adjudicated, not by being
touched." The substrate has a promotion **court** for CALLER-initiated promotion,
but `long` (permanent) tier is reachable by two other lanes it does not gate.
This § pins the honest state; the machine-checks are
`storage::tests::g10_3_*`.

### 13.1 The three lanes to `long`

| Lane | Mechanism | Governance |
|---|---|---|
| **Caller promote** | `memory_promote` (MCP/CLI) | ✅ **court-gated** — `GovernedAction::Promote` → the namespace `promote` `GovernanceLevel` (Deny at `owner`, Pending at `approve`); capability `Ask→Allow`; `pending_approve`. |
| **Direct write** | `memory_store tier=long`, or upsert `mid→long` escalation (tier-monotonic-max) | ⚠️ gated by `GovernedAction::Store` → `policy.core.**write**`, **not** `promote`. So `long` is reachable via the write lane without the promote court. |
| **Access-count auto-promote** | the fold "maintenance verb" (`fold_recall_accesses`) flips `mid→long` at `PROMOTION_THRESHOLD = 5` | ❌ **ungoverned** — see §13.2. |

Consequence: **"no `long` past a configured court" is not achievable by gating the
auto-promote lane alone** — an operator wanting adjudicated-only permanence must
ALSO gate `write` (and even then access-count auto-promote applies).

### 13.2 Access-count auto-promote is substrate maintenance, not an adjudicable grant

The auto-promote lives in `fold_recall_accesses` — a callerless batch
**maintenance verb** (#1869) that folds aggregated `recall_observations`
(`GROUP BY memory_id`) with **no caller identity, no request context**. It is the
same class as substrate eviction (`substrate:eviction`) and GC, which are
deliberately exempt from caller-intent governance. Court-gating it is not merely
inappropriate but **structurally un-runnable**: `enforce_governance`'s promote arm
needs `agent_id` + `memory_owner` to adjudicate Owner/Approve, and a callerless
fold has neither — so a court check there could only no-op or convert a retention
function into court-gated **expiration** (a hot but unadjudicated memory GC'd).
Gating it on the caller-intent `promote` level is a category error.

### 13.3 The genuine residual (disclosed, not weaponized)

Access-count is caller-**influenceable**: a principal that can recall a row
`PROMOTION_THRESHOLD` times inflates it to permanent `long`, side-stepping a
`promote: owner/approve` court by traffic. This is an **access-count-integrity**
concern (partly mitigated by the #1705 recall-observations identity binding), NOT
a promote-court concern — the honest fix is not to mis-apply the caller gate to a
maintenance job.

### 13.4 v1.x migration (deferred, 1:1 issue)

Adjudicated-only permanence is v1.x, tracked as **#2072**: an opt-in, default-OFF
posture that (a) **suppresses** maintenance auto-promote in adjudicated-permanence
namespaces (keeping the row `mid` **with an expiry-hold** so it is not silently
GC'd), (b) **routes the direct `tier=long` write lane** to the promote court, and
(c) reaches both backends (the postgres set-based fold CTE needs a
court-namespace exclusion-set bind mirroring `build_namespace_chain`), behind a
flag + WARN cycle. **Not** court-gating the callerless fold.

## 14. Namespace is a filter, not an enforced trust boundary (G10.4, #1864)

TRACT §26 wants namespace to be a **trust boundary**: cross-namespace recall
should require an explicit **bridge-capability** (the read-side analogue of the
shipped G10.1 write-gate joiner). Today it does not — cross-namespace recall is
**unrestricted**. This § pins the honest state; the machine-checks are
`storage::tests::g10_4_*`.

### 14.1 Honest current state

- **Recall spans namespaces un-gated.** `RecallRequest.namespace` is an optional
  filter; `None` returns rows from **every** namespace (the `(?N IS NULL OR
  namespace = ?N)` predicate). The read path consults **no capability token** —
  `search`/`recall`/`list`/`session_start` have no `capability` parameter and
  never call `enforce_governance`.
- **The filter is EXACT-match, not hierarchical.** `namespace = "team"` does NOT
  match `team/eng` (`NS_FILTER_SARGABLE = "namespace = $1"`; sqlite exact-match).
  So only `namespace = None` (span-all) is genuinely "cross-namespace".
- **The only read isolation is the per-row scope ACL** (`scope = private / team /
  unit / org` via `is_visible_to_caller` / `scope_idx`) — it bounds
  *confidentiality*, but it is **not** a namespace bridge.

So namespace is a **filter, not an enforced trust boundary** — an agent/operator
who assumes namespace isolates reads is wrong at v1.0.0 GA.

### 14.2 Why the bridge-capability is deferred (v1.x, #2074) — not a clean reuse, and underspecified

The G10.1 capability primitive (`Caveat::NamespacePrefix`, `op_level_of("Reflect")
→ OpLevel::Read`) is the **intended** bridge, but recall does not consume it, and
wiring it is neither a clean reuse nor fully specified:

- **Not a reuse.** `apply_capability_grant` is a write-gate joiner that only flips
  `Deny`/`Ask`→`Allow`; recall is Allow-by-default, with no `GovernedAction::Read`
  / `policy.core.read` and no gate call. A read-bridge must first *invent* a
  base-`Deny`-on-cross-namespace posture (a security-posture inversion), then
  thread a token through the recall chain (both SAL backends + MCP/HTTP/CLI
  edge-parse).
- **Semantics don't compose.** The exact-match recall filter vs the hierarchical
  `NamespacePrefix` caveat; and there is **no home-namespace model** — recall's
  namespace is a per-request filter with no identity referent, so "cross-namespace"
  has nothing to gate against.
- **Can't be built to spec.** The B4-4 bridge cap must be **co-signed**, but
  co-signing/N-of-N is deferred (#1827); `require_bridge` has zero code.
- **Multi-surface + substrate-dependent.** The boundary would have to hold on
  recall + list + search + session_start at once, while **exempting** the
  substrate's own cross-namespace reads (persona synthesis, reflection-pass
  fan-out, the decorrelation probe, session bootstrap).

### 14.3 v1.x migration (deferred, 1:1 issue)

The read-side bridge-capability is v1.x, tracked as **#2074**, with the home-
namespace model, exact-vs-hierarchical reconciliation, co-signing, all-read-surface
token plumbing, substrate exemption, both backends, and a default-OFF flag + WARN
cycle as acceptance criteria.

---

*Normative for the v1.x G22 migration; NON-normative about v1.0.0 behavior except
where it states what is UNIMPLEMENTED. Byte layouts for the signed record classes
are authoritative in the format-decisions spec; TRACT L1 semantics are
authoritative here.*
