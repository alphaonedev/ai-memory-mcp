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
atomisation-split 1→N) but a near-homophone footgun; tracked as its own 1:1
issue.

### 7.4 v1.x migration (deferred)

Tracked 1:1 from #1833. Relax the DB `CHECK` to a kernel + open-CID model; add
caller-authored CID predicates + definition-Claim reachability resolution;
migrate the 5 substrate extras to authored predicates or reversed-kernel
mappings; add the 4 missing kernel relations with real producers; resolve the
§7.2 bisection + the §7.3 near-homophone. Gated on the CC0 vectors (#1837).

## 8. The human↔AI covenant (G18, #1832) — 1-of-4 clauses shipped

TRACT L1's human↔AI covenant is a four-clause mutual-obligation contract. It is
**NOT enforced** at v1.0.0: three of its four clauses are UNIMPLEMENTED and one
is shipped as a narrow, honestly-scoped primitive. Nothing in the substrate may
assert "the covenant is enforced" while §8.1 stands.

### 8.1 Clause ledger (honesty)

| # | Covenant clause | Substrate state at v1.0.0 |
|---|---|---|
| 1 | **`why_trace` write-gate** — a mutation must carry a recorded cause | ⚠️ PARTIAL. The cause exists as DATA (`signed_events.cause_hash`, schema v73) + an opt-in VERIFY-time require-mode (`AI_MEMORY_REQUIRE_CAUSE_BINDING`), but it is NOT a mandatory WRITE-gate. Making it mandatory-by-default is a default-flip → **freeze-hostile / v1.x**. |
| 2 | **Immutable authorship** — authorship cannot be silently rewritten | ⚠️ PARTIAL. `agent_lineage` (schema v76) is an append-only signed succession record + `metadata.agent_id` is preserved across every mutation path, but there is no covenant-level enforcement LAYER binding a write to an immutable author. **Freeze-hostile / v1.x.** |
| 3 | **Permanent-dissent conservation (G7)** — a recorded dissent is never destroyed | ❌ ABSENT. No net-new dissent-conservation mechanism exists. **Freeze-hostile / v1.x** (net-new representation + write-path enforcement). |
| 4 | **Signed forget-receipt returned to the requester** — proof-of-erasure the requester actually receives | ✅ SHIPPED (v1.0.0, #1832). See §8.2. |

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

**Honest scope (§2.5 discipline).** This is a right-to-be-forgotten RECEIPT
(proof a forget was RECORDED), **NOT** covenant enforcement — it is never named
"covenant" in any symbol. The signature commits ONLY to `{id, ns, forgotten_at}`,
NEVER content. On an unsigned daemon (no enrolled audit key — a common posture)
`signed = false` and the receipt carries identity + time but NO cryptographic
proof; `verify` returns `Unsigned`, never `Valid`. Because clauses 1-3 are
unenforced, a receipt can attest an erasure the full covenant might have governed
differently — the receipt makes NO claim beyond "this forget was recorded."

### 8.3 v1.x migration (deferred, 1:1 issues)

Clauses 1-3 are each tracked as their own v1.x issue (never bundled): the
mandatory `why_trace` write-gate default-flip (**#2059**); immutable-authorship
enforcement (**#2060**); permanent-dissent conservation G7 (**#2061**). A
postgres/HTTP/MCP forget-receipt surface beyond the sqlite CLI is a separate
additive v1.x follow-up (**#2062**).

## 9. Durability model — no erasure-coded no-primary cold tier (G16, #1830)

TRACT L2 wants an **(n,k) erasure-coded, no-primary cold tier** so any k-of-n
shards reconstruct the original. The substrate does **not** have one — durability
rests on replication/local persistence, not erasure coding. This § pins the
durability posture the substrate ACTUALLY provides, so the claim cannot silently
drift; the executable anchor is `crate::durability`.

### 9.1 The actual durability model (honest taxonomy)

Codegraph-verified. There is **no** automatic full-copy replication; the label
"full-copy replication" would itself be an overclaim.

| Posture | When | Guarantee |
|---|---|---|
| **Local single-node** (default) | `synchronous = NORMAL` (`storage::connection::DEFAULT_DB_SYNCHRONOUS`), no quorum | One local SQLite DB (WAL). Survives a process crash; a **power loss** can lose the tail of un-checkpointed commits. **No replication.** |
| **Local single-node, power-loss-safe** | `AI_MEMORY_DB_SYNCHRONOUS = FULL`/`EXTRA`, or the `asi-hard` posture (#1961) | fsync-per-commit power-loss durability. Still single-node. |
| **Quorum-replicated** (opt-in) | `--quorum-writes > 0` with configured peers | Opt-in **W-of-N quorum** federation replication (`crate::replication` `QuorumPolicy`/`AckTracker`). This is quorum, **not** full-copy-to-N, and `crate::replication` is scaffolding **not wired into the store write path** (default `quorum_writes = 0`). |
| **Erasure-coded no-primary cold tier** | — | **UNIMPLEMENTED** (gap G16). No erasure/shard/Reed-Solomon code exists. |

### 9.2 The forcing-function anchor

`crate::durability::DurabilityModel` is a `#[non_exhaustive]` enum with exactly
the three shipped postures above and **deliberately no erasure variant**;
`resolve_durability_model` computes the live posture from the REAL config
(`synchronous` level, `quorum_writes`, peers). The absent variant IS the
machine-checked gap record: the enum is consumed by wildcard-free exhaustive
matches (`label`, `is_multi_node`), so adding an erasure-coded cold-tier variant
hard-breaks the build until the tier is consciously wired AND this ledger is
updated. (Low fan-out — honest for a total gap: this is a disclosure anchor, not
a load-bearing projection like §3's `ClaimView`.) No erasure codec ships — not
compiled, not test-only (a hand-rolled or self-generated reference construction
would freeze a shard format the eventual audited crate won't match; the #1830
5-agent vote `4d3ea1c5` rejected it unanimously).

### 9.3 v1.x migration (deferred — subsystem BLOCKED on an operator decision)

#1830 stays on the v1.0.0 tracker (NOT silently re-milestoned). The v1.0.0 slice
shipped is this §9 disclosure anchor; the erasure **subsystem** (codec + shard
placement + no-primary coordination + reconstruction-on-read + repair) is v1.x
and is BLOCKED on an operator **dependency-authorization** decision (**#2064**):
a vetted erasure crate (e.g. `reed-solomon-simd`) requires operator sign-off
(sole-authority rule), and hand-rolling was vote-rejected. The
construction-independent acceptance invariant for whichever path is authorized:
**any k-of-n shards reconstruct the original bytes exactly.**

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
four surfaces above) is v1.x, tracked 1:1 as **#2066**. Construction-independent acceptance
criteria for the eventual cost: **monotonically non-decreasing in age/archival
depth, non-increasing in recent access, and consistent with the current tier
ordering (cost `long < mid < short`).**

---

*Normative for the v1.x G22 migration; NON-normative about v1.0.0 behavior except
where it states what is UNIMPLEMENTED. Byte layouts for the signed record classes
are authoritative in the format-decisions spec; TRACT L1 semantics are
authoritative here.*
