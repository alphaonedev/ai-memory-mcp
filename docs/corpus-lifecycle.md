# Corpus-lifecycle contract — EXPIRE / EVICT / DISTILL (#1965)

> Gate-2, v1.0.0. Bounded growth under a **named pressure policy**: the
> substrate bans infinite-corpus-by-default. Every live memory that leaves
> the working corpus does so through exactly one of three named lifecycle
> transitions, each driven by a distinct, independently-observable
> pressure. This document is the **contract**; the spec + scoring layer is
> `src/storage/lifecycle.rs`, and the live implementations are the existing
> `gc` / `size_gc` / consolidation paths (this contract renames and
> reconciles them — it does **not** change eviction behaviour).

## The three transitions

| Transition | Pressure | Trigger (the exact condition) | Live path |
|------------|----------|-------------------------------|-----------|
| **EXPIRE**  | time (TTL) | `expires_at IS NOT NULL AND expires_at < now` | `storage::gc` / `gc_if_needed` (`src/storage/mod.rs`), archive reason `ttl_expired` |
| **EVICT**   | capacity (bytes) | the namespace live corpus `SUM(len(title)+len(content)+len(metadata))` exceeds a positive `max_corpus_bytes` cap | `storage::size_gc` (`src/storage/mod.rs`), archive reason `size_gc` |
| **DISTILL** | redundancy | a same-namespace near-duplicate exists: Jaccard ≥ `0.55` **and** cosine ≥ `0.75`, both sides embedded | `curator::cluster::pair_merges` → `ConsolidationPass` (`src/curator/`) |

Each pressure is observed independently:

- **EXPIRE** is per-row and definitive — the row's own declared lifetime
  (`expires_at`) has elapsed. TTL floors are set at create time (short 6h,
  mid 7d, long = never) and can only ever be *extended* on access, never
  shortened (#1596). A `NULL` `expires_at` never expires.
- **EVICT** is per-namespace and capacity-driven — when a namespace's live
  corpus byte size crosses a configured byte cap, the lowest-value rows are
  shed until the corpus is back at/under cap. A non-positive cap is
  "disabled" (no eviction). The byte cap is **not operator-exposed by
  default** at v1.0.0 (per the #1750 vote it gets its own
  `[curator.size_gc]` switch when it is exposed); today the pressure is
  surfaced for visibility (see *Observability* below) but the default
  policy applies no byte cap.
- **DISTILL** is per-cluster and redundancy-driven — near-duplicate rows in
  the same namespace are merged so the surviving cluster member carries the
  information forward. A destructive merge **requires** the cosine safety
  gate (both sides embedded); lexical Jaccard overlap alone never triggers
  a merge (#1774). Consolidation is curator-driven and opt-in
  (`AI_MEMORY_COMPACTION_ENABLED`).

## Precedence

A single row can be under more than one pressure at once. The classifier
[`classify_lifecycle_transition`](../src/storage/lifecycle.rs) resolves this
with a fixed precedence — **EXPIRE > DISTILL > EVICT**:

1. **EXPIRE first.** An elapsed TTL is definitive: the row's declared
   lifetime ended, so no value judgement is needed and no cheaper
   transition can legitimately preserve it.
2. **DISTILL before EVICT.** Merging a near-duplicate *preserves the
   information* (the surviving cluster member carries it), while eviction is
   a lossy last resort. When both redundancy and capacity pressure apply,
   prefer the information-preserving transition.
3. **EVICT last.** Pure byte-capacity shedding, with no better option. The
   deterministic victim order — least-durable tier first (`short → mid →
   long`), then lowest `priority`, then lowest `access_count`, then oldest
   `last_accessed_at` — is a separate ranking
   ([`eviction_victim_key`](../src/storage/lifecycle.rs), mirroring
   `SQL_SIZE_GC_NEXT_VICTIM`). A high-value long-tier frequently-accessed
   row is evicted last, only if the corpus is still over cap after every
   cheaper victim is gone.

A row under **no** pressure stays resident — the bounded-growth policy only
ever *removes* a row under a named pressure, never speculatively.

## Restorability

| Transition | Recoverable? |
|------------|--------------|
| EXPIRE | Archived before delete when `archive_on_gc = true` (default); restorable from `archived_memories`, **with its `memory_links` edge graph** (#3161 — pre-v1.0.0 the auto-eviction paths were the one archive funnel that did NOT snapshot edges, so a gc-archived memory restored with an empty graph while an operator-driven `forget`/archive of the same row kept it). A **hard** (`archive = false`) expiry is still an explicit, irreversible delete. |
| EVICT | Archived before delete when the caller passes `archive = true` (the curator does); restorable. |
| DISTILL | The merged sources are consolidated into the survivor. With `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES` the sources are tombstoned (id + cid retained, navigable `derived_from` edges) rather than hard-deleted. |

## Scoring / classification layer

`src/storage/lifecycle.rs` is the pure, backend-agnostic spec + scoring
layer for this contract. It exposes:

- `LifecycleTransition` — the `{ Expire, Evict, Distill }` enum, with a
  stable wire slug (`expire` / `evict` / `distill`).
- `is_expired`, `is_near_duplicate`, `is_over_capacity` — the three pure
  pressure predicates, each pinned to the live path it mirrors (the
  DISTILL predicate delegates to the canonical
  `curator::cluster::pair_merges`, so this layer can never disagree with
  the live consolidation gate — a parity test enforces this).
- `tier_durability_rank` / `eviction_victim_key` — the deterministic EVICT
  victim ranking.
- `classify_lifecycle_transition` — applies the EXPIRE > DISTILL > EVICT
  precedence and returns which transition (if any) a candidate is under.

This layer **changes no eviction behaviour** — it formalises the boundaries
the existing paths already implement so they can be reasoned about, tested,
and surfaced as one contract. Per the issue's "spec/scoring only — no
compaction / size-GC default flips" constraint, no default was flipped.

## Observability

`ai-memory doctor` reports a **Corpus Lifecycle (#1965)** section:

- `expire_backlog` — rows past TTL awaiting the next gc sweep (EXPIRE
  pressure).
- `evict_largest_namespace` / `evict_largest_namespace_bytes` — the largest
  namespace's live corpus bytes (the EVICT / byte-cap pressure indicator).
- `distill_driver` — `curator_consolidation` (DISTILL is curator-driven).

See also the sibling **Recall Index Coverage (#1964)** section
(`docs/` — index-coverage reconciliation) for the recall-completeness
surface.
