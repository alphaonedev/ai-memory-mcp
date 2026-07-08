# W5-A2 — Vector index permanence (HNSW RAM vs disk, §23)

**Lens:** What must perfect endpoint memory do about ANN/HNSW permanence — RAM cache vs on-disk index?
**Surfaces:** cold-start rebuild, 100k cap, erase lockstep, multi-backend trait, pgvector vs sqlite.
**Code anchors:** `src/hnsw.rs` (`VectorIndex`, `VectorSearchIndex`, `DEFAULT_MAX_ENTRIES`, G2/G4/#1005 knobs), boot load (`spawn_vector_index_boot_load`), embeddings BLOB codec (`src/embeddings.rs`), postgres pgvector HNSW (`src/store/postgres.rs`), forget → `idx.remove`, ROADMAP §23 / #1005, TRACT L3-BODY “derived HNSW/FTS”.

---

## VERDICT

**The vector index is L3 disposable projection — never the system of record. Embeddings + claims are permanent; the graph is rebuildable cache.**

Perfect endpoint memory **must not** treat HNSW topology as truth. Truth is the content-addressed claim row and its durable embedding BLOB (or re-embed recipe under a registered embedder). The ANN structure is a **derived, swappable Reference-Profile artifact** (TRACT: “store the Claim, cache the vector; truth survives index death”).

What *is* load-bearing permanence:

| Layer | Permanence duty | Failure if wrong |
|-------|-----------------|------------------|
| **Claim + embedding bytes** | Disk SoR (sqlite BLOB / pgvector column) | Mind loses semantic material |
| **ANN graph (HNSW edges, IVF lists, …)** | Optional durable **cache** | Cold-start tax + temporary R@k lag — **not** amnesia if rebuild exists |
| **Index mutation attestation** | Audit of *process* (insert/delete/rebuild events) | Ops forensics gap; not claim-truth |

**§23 is the right *operational* program** (persistent backends, trait, txn coherence, G2/G3/G4 close) **only if** it stays L3: pluggable, rebuildable, erase-coherent, never a second identity for memories. Elevating a frozen on-disk HNSW file into “the memory” is a category error equal to confusing FTS5 with the corpus.

**v0.9 ship-state honesty:** sqlite path = **RAM HNSW over durable embeddings** (G3 cold-start still open; G2/G4/§5.2 knobs shipped opt-in). Postgres can use **on-disk pgvector HNSW** (disk-backed ANN, still not L1). Full §23 three-backend substrate (`sqlite-vec` / `vectorlite` / builtin + `Index*` signed events) is **planned, not present** (`src/index/` absent; trait is inert default around `instant-distance`).

---

## SCORE

| Axis (perfect endpoint) | Score | Note |
|-------------------------|------:|------|
| Layer honesty (index ≠ SoR) | **0.90** | TRACT + code comments; rebuild-from-BLOB path exists |
| Embedding durability | **0.88** | BLOB on both backends; reembed surface exists |
| ANN operational permanence (no cold O(N) cliff) | **0.35** | sqlite rebuild-at-boot; G3 OPEN |
| Capacity honesty (no silent quality death) | **0.72** | G2 capacity + hard-fail knobs + eviction metrics; default still soft-evict |
| Dim / embedder binding | **0.55** | G4 opt-in; no full `embedder_registry` / write fail-closed default |
| Erasure ↔ ANN lockstep | **0.78** | Builtin `remove` on forget; multi-backend residual (W4-A6 E6) |
| Swappable L3 backends | **0.40** | `VectorSearchIndex` seam only; §23 backends unshipped |
| Audit of index process | **0.20** | No `IndexInserted|Deleted|Rebuilt` events yet |
| Namespace-correct ANN | **0.70** | §5.2 allowlist opt-in; default post-filter starvation residual |
| **Composite readiness** | **0.58** | Strong architecture story; weak sqlite permanence + incomplete §23 |

**Confidence in diagnosis: 0.87** (code + ROADMAP §23 + TRACT aligned; pre-flight §23.0 results not in-tree).

---

## GAPS for perfect endpoint

| # | Gap | Why it matters | Perfect close |
|---|-----|----------------|---------------|
| **V1** | **G3 — sqlite ANN is process-RAM only** | Daemon restart = full graph rebuild; CLI skips build under 20k (`CLI_HNSW_BUILD_MIN_ENTRIES`) | On-disk index co-located with DB (sqlite-vec / pinned extension / pgvector-class) **or** proven lazy rebuild budget + warm snapshot |
| **V2** | **§23 backends / factory unshipped** | Single `instant-distance` impl; “move to dedicated vector DB” is log prose | `VectorSearchIndex` + factory `auto|sqlite-vec|vectorlite|builtin`; capabilities report backend + storage type |
| **V3** | **No same-txn index mutation with memory write** | Index lag / crash window between row and ANN | Insert/delete emit index op in same txn where backend allows; rebuild marked eventually-correct |
| **V4** | **Index audit kinds missing** | Erasure/forensics can’t prove ANN drop; rebuild not attested process | Signed `IndexInserted|Deleted|Rebuilt|MigrationCompleted` (identity-only payloads) |
| **V5** | **G2 default still soft-evict** | Silent R@k death past cap unless operator opts hard-fail | Documented regimes: soft-evict / hard-fail / disk-spill; hard-fail or spill default at “endpoint integrity” profile |
| **V6** | **G4 / embedder version not default-enforced** | Mixed-dim / model-switch poisons ANN | `embedder_registry` + dim enforce on write; reembed is the migration verb |
| **V7** | **§5.2 allowlist default off** | Small-namespace starvation under global ANN cutoff | Default-on for namespaced recall *or* always-correct pre-filter when ns set |
| **V8** | **Builtin erase multi-backend residual** | Alternative backend without `delete` reopens G30 RAM remanence | Trait `remove` mandatory; forget path backend-blind |
| **V9** | **Persistence ≠ irreplaceability myth** | Risk of treating HNSW file as backup of mind | Doctor + docs: “index death is recoverable from embeddings”; migration retains archive one cycle |
| **V10** | **§23.7 exotic / GPU deferred (correct)** | Must not block endpoint core | Stay cut; trait-only extension points |

**Already good (do not re-litigate):** async double-buffer rebuild (#968) keeps search live; embeddings are durable SoR; forget calls `remove` on builtin; capacity/eviction observability; trait seam named for future backends without renaming 23+ call sites incorrectly.

---

## VOTE (5-axis synthetic)

| Lens | Stance |
|------|--------|
| **Precedent / TRACT** | Index = L3 derived HNSW/FTS; L1 rebuilds mind if L3 dies |
| **Spec / §23** | Ship operational permanence + trait; keep quantization/GPU in §23.7 |
| **Security / erasure** | Durable ANN must delete as hard as content (G30); no “graph retains forgotten vectors” |
| **Testability** | Pre-flight R@k gate before backend lock-in; cold-start + kill-mid-write chaos |
| **Blast radius** | Additive disk backends; never make graph hash part of claim id |

**Tally: 5/5 — persist the *embeddings*; optionally persist the *index cache*; never confuse them.**

**Chosen pathway:**

1. Keep embeddings + claims as sole semantic SoR.  
2. Complete §23 L3 substrate: disk-backed primary for long-lived daemons; builtin RAM fallback where extensions blocked.  
3. Close G3 with rebuild-or-load, not “HNSW is L1.”  
4. Wire index events + mandatory `remove` + embedder/dim registry.  
5. Flip integrity defaults (hard-fail/allowlist/dim) behind an operator profile — not silent behavior change on all fleets.

---

## KILLER

**“Disk-backed HNSW makes memory permanent, so RAM is wrong.”**  
False dichotomy. **RAM-only graph + durable embeddings** already has permanent *content*; it lacks permanent *acceleration*. Moving the graph to disk without rebuild/erase/dim discipline creates a **second mutable corpus** that can disagree with the claim row (forgotten vectors, stale dims, silent cap eviction on a file nobody audits). Perfect permanence is **row-level durability + rebuildable projections**, not “the ANN file is the mind.”

---

## TOP_RISK

**Category error + half-migrated permanence:** shipping sqlite-vec/vectorlite as “the memory database” without (a) mandatory delete lockstep, (b) embedder/dim fail-closed, and (c) honest “index is cache” operator model — producing fleets that **backup HNSW files, skip embedding archives, and cannot prove forget**. Secondary: leaving G3 open while marketing “endpoint-resident at scale,” so cold-start multi-minute rebuilds and 100k soft-evict silently define production R@k.

---

## One-line north star

> **Embeddings on disk, graph on a leash: perfect endpoint memory survives index death, and never lets the cache outrank the claim.**
