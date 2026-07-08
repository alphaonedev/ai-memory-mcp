# W5-A3 — Compaction / Curator / Lifecycle for Infinite Corpus

> **Agent:** W5-A3 (Corpus Boundedness & Lifecycle Assessor)  
> **Date:** 2026-07-08  
> **Scope:** Can v0.9.0 **bound, distill, and lifecycle** a growing endpoint memory corpus so operators can treat it as **effectively infinite over time** without OOM, silent loss, or claim theater?  
> **Anchors:** Pillar-2.5 #1709/#1746–#1750, size-GC, `ConsolidationPass`, schema v64 lifecycle, G13-mem #1859 tombstone-sources, #1869 pure recall + fold, HNSW #1005 G2, K8 quotas #1156, B2-T5 EXPIRE/EVICT/DISTILL epic, TRACT distillation-as-RELATE  
> **Code:** `src/curator/{mod,compaction,cluster}.rs`, `src/autonomy.rs`, `src/storage`/`store` `size_gc`/`run_gc`, `src/hnsw.rs`, `src/models/memory.rs::LifecycleState`, `src/config.rs` compaction resolvers

---

## VERDICT

**PARTIAL PRIMITIVES; NOT HELD UNDER DEFAULTS; NOT “INFINITE CORPUS” AS A SHIPPED PRODUCT PROPERTY.**

v0.9.0 has a **stacked valve design** (TTL → promote → consolidate → size-GC → ANN residency → agent quotas → archive purge) that *can* keep a working set healthy **when operators arm it**. The **compiled defaults leave most valves closed**, tier is **promote-only**, long-tier rows are **immortal**, and the capabilities envelope still advertises compaction as **`planned`** while live `ConsolidationPass` exists behind opt-in flags. Perfect infinite-corpus lifecycle needs a **closed typed forgetting vocabulary** (epic B2-T5), **default-on pressure policy**, and honest **hot/cold** claims — not just more delete paths.

| Claim class | Council |
|---|---|
| Substrate has distillation + eviction **machinery** | **ACCEPT** (opt-in) |
| Default install bounds corpus for years of continuous write | **REJECT** |
| “Infinite corpus” / “self-compacting memory” marketing | **BANNED** until defaults + typed verbs + caps exposed |
| Single-node SQLite at multi-million live rows as product promise | **REJECT** (structural; Postgres path exists) |

---

## CONFIDENCE

**0.84**

| + | − |
|---|---|
| Dual-backend `size_gc` + curator driver + ConsolidationPass cutover | `max_corpus_bytes` not operator-exposed; still inert default |
| Tier TTLs + GC + archive-on-gc documented and exercised | Tier never demotes; long = unbounded without size-GC |
| HNSW 100k cap + hard-fail knob (#1005 G2) | ANN eviction ≠ durable corpus policy; silent quality loss if unobserved |
| Lineage-aware consolidate tombstone sources (#1859) | Default consolidate still hard-DELETE; edge loss on rollback residual |
| Capabilities `compaction.planned=true` honesty gap | Capabilities lag live code → claim risk |

---

## ARCHITECTURE (what exists today)

```
write ──► tier short/mid/long ──► optional promote (monotonic ↑)
                │
                ├─ TTL GC (30m): expire short/mid → archive? → DELETE   [EXPIRE-ish]
                ├─ ConsolidationPass / autonomy Pass-1 (opt-in): merge  [DISTILL-ish, hard-DELETE default]
                ├─ size_gc (cap + compaction.enabled): lowest-value     [EVICT-ish, archive-first]
                ├─ HNSW MAX_ENTRIES (100k): drop oldest ANN entry only  [working-set RAM]
                └─ K8 quotas: refuse NEW writes at agent caps           [admission, not lifecycle]
```

| Valve | Default | Effect | Infinite-corpus role |
|---|---|---|---|
| **TTL + `run_gc`** | ON (tier windows) | short 6h / mid 7d expire; long never | Time bound for hot noise only |
| **`archive_on_gc`** | true | restorable soft path | Ops undo; disk still grows until archive purge |
| **`ConsolidationPass`** | `enabled=false` | Jaccard∧cosine clusters → LLM summary; hard-DELETE sources (or tombstone if lineage flags) | Semantic compression |
| **`max_corpus_bytes` size-GC** | `None` + needs `enabled` | per-ns byte sum; short→long rank; archive then delete | **Only true infinite disk valve for long tier** |
| **HNSW capacity** | 100k, soft oldest | RAM ANN working set | Scale recall cost, **not** durable retention |
| **Agent quotas** | 1000/day, 100 MiB storage | write gate | Protect multi-tenant abuse; not curator policy |
| **`lifecycle_state`** | `open` (Goal/Plan/Step) + system `tombstoned` | cognition + lineage shell | **Not** Observation corpus lifecycle |
| **Confidence decay** | opt-in env | ranking soft forget | Soft; does not free bytes |
| **Append-only / revisions** | opt-in | identity growth | **Anti-bound** unless EVICT/REDACT paired |

**Ranking truth (size-GC):** `ORDER BY tier(short≺mid≺long), priority ASC, access_count ASC, last_accessed_at ASC NULLS FIRST` — frecency-ish, deterministic, LLM-free. Correct shape for EVICT; does **not** protect high-priority long rows from eventual eviction under a hard byte cap (by design pressure, not bug).

---

## GAPS

| ID | Gap | Severity |
|---|---|---|
| **C1** | **Defaults grow unbounded** for `long` + reflections + continuous store; size-GC + compaction off | **Critical** (product claim) |
| **C2** | **B2-T5 closed verbs** EXPIRE / EVICT / DISTILL (+ REDACT) not unified — GC/`size_gc`/consolidate/forget leave distinct, partially silent dispositions | High (forensic + claims) |
| **C3** | **`max_corpus_bytes` unwired to operator config** (struct field exists; vote: needs dedicated `[curator.size_gc]`, not under compaction alone) | High |
| **C4** | **Tier monotonicity** — no demote path; promote-to-long = immortality without size-GC | High |
| **C5** | **Capabilities still `compaction.planned=true`** while live pass ships — honesty/SSOT drift | Medium (claims) |
| **C6** | Consolidation **default hard-DELETE** vs lineage tombstone; rollback does not fully restore graph until archive-link path fully relied on | Medium |
| **C7** | Curator **ops/cycle + cluster caps** (100 ops, cluster≤8) correct safety, wrong for “catch-up compaction” of already-infinite backlog | Medium |
| **C8** | **Archive table + audit/revisions/ledger** can grow after live-set bound — cold plane unbounded unless purge policy armed | Medium |
| **C9** | HNSW eviction **silent quality** unless metrics/hooks watched; multi-backend ANN delete residual vs full DB | Medium |
| **C10** | SQLite single-writer / single-node structural ceiling (~100k sweet spot documented) — “infinite” ≠ one-file immortal | Structural |
| **C11** | No TRACT-style **distill → authored RELATE** as primary (today: merge-delete/tombstone) | Design residual |
| **C12** | Reflection pass can **amplify** corpus if enabled without paired compact+evict | Medium |

---

## SCORE

Held-fraction toward **perfect endpoint infinite-corpus lifecycle** (durable bound + distill + typed forget + recoverable ops + honest claims).

| Axis | Score | Notes |
|---|---:|---|
| **Time bound (TTL/GC)** | **0.78** | Solid for short/mid; long hole is intentional |
| **Semantic distill (consolidate)** | **0.62** | Live pass + dual backend; opt-in, LLM, hard-DELETE default |
| **Byte pressure (size-GC)** | **0.45** | Code complete both adapters; **product-inert** (no cap default/expose) |
| **ANN working set** | **0.70** | Cap + hard-fail + metrics; not corpus policy |
| **Typed lifecycle verbs** | **0.35** | Goal lifecycle ≠ corpus; Tombstoned only on consolidate path |
| **Cold plane (archive/audit)** | **0.50** | Archive + purge knobs; no unified retention SSOT |
| **Default install posture** | **0.28** | Most valves off → unbounded long growth |
| **Honesty / capabilities** | **0.40** | planned-flag lag; claim bans still load-bearing |

### Radar (defaults)

```
TTL/GC time bound     ████████░░ 0.78
ANN working set       ███████░░░ 0.70
Semantic distill      ██████░░░░ 0.62
Cold plane            █████░░░░░ 0.50
Byte pressure         ████░░░░░░ 0.45
Honesty/caps          ████░░░░░░ 0.40
Typed forget verbs    ███░░░░░░░ 0.35
Default install bound ██░░░░░░░░ 0.28
```

**Composite (do not market as %):** ~**0.48** under defaults; ~**0.72** if compaction+size-GC+archive purge+lineage tombstone+metrics all armed on Postgres. Neither is “infinite corpus product-ready.”

---

## VOTE

**Adopt “bounded working set + recoverable cold plane + typed distill” as the infinite-corpus constitution — reject “defaults already infinite.”**

| Option | Tally posture |
|---|---|
| **A — Claim infinite corpus / self-healing compaction at v0.9** | **REJECT** — defaults inert; capabilities planned |
| **B — Ship only more opt-in knobs, no default policy** | **REJECT as end-state** — C1 remains; operators will never discover size-GC |
| **C — Expose `[curator.size_gc]` + typed EXPIRE/EVICT/DISTILL leaves; keep compaction opt-in until soak; v1.0 default pressure policy per-ns** | **ADOPT** |
| **D — Force hard-DELETE everything at cap (no archive)** | **REJECT** — breaks dual-plane + ops undo |
| **E — Rely on HNSW 100k alone as corpus bound** | **REJECT** — RAM index ≠ durable lifecycle |

**Claims discipline (bind for W5/W6):**

| Banned until gate | Allowed now (caveated) |
|---|---|
| “infinite corpus”, “never fills up”, “self-compacting by default” | “opt-in ConsolidationPass merges near-dupes when `compaction.enabled`” |
| “size-GC always protects disk” | “`size_gc` implements lowest-value archive-evict when cap+enabled set” |
| “lifecycle manages all memories” | “`lifecycle_state` is Goal/Plan/Step (+ system tombstone on consolidate)” |

---

## KILLER

**Long-tier immortality + closed pressure valves = unbounded disk under the happy path the product teaches.**

An agent that correctly promotes useful knowledge to `long` (or stores with `tier=long`) will, under **default** curator/compaction, accumulate rows forever. TTL GC will not touch them. Consolidation will not run. Size-GC will not run (`max_corpus_bytes=None`). Quotas only stop *that agent* after 100 MiB — they do not distill. HNSW will silently drop ANN entries past 100k while **SQL + FTS still hold full bodies**, so recall degrades while disk grows. That is the opposite of “infinite corpus competence”: it is **finite RAM quality + infinite disk debt**.

Secondary killer: marketing or capabilities that imply compaction is still “planned” (or fully automatic) while the pass is live-but-dark creates **trust theater** — operators either under-enable (disk death) or over-claim (audit fail).

---

## TOP_RISK

**Silent quality / storage divergence without a default pressure policy or typed forget leaves.**

1. **Ops:** endpoint disks fill on long-lived dogfood; GC looks “healthy” (no TTL expiries) while corpus is the problem.  
2. **Forensics:** mixed EXPIRE/EVICT/DISTILL/FORGET dispositions without B2-T5 leaves make “why is this gone?” unanswerable in the audit spine.  
3. **Federation:** hard-DELETE consolidate + peer LWW can resurrect or orphan edges; size-GC archive restore races tombstones (A6 mesh bans still apply).  
4. **Scale lie:** quoting Postgres 1M+ guidance while default SQLite + no size-GC ships as “endpoint infinite memory.”

**Mitigation order (v1.0-facing):** (1) expose `[curator.size_gc].enabled` + cap with archive-first EVICT leaf; (2) flip capabilities compaction honesty; (3) B2-T5 verb set wired to GC/size_gc/consolidate; (4) optional per-ns default pressure after soak; (5) never claim infinite without cold-plane purge + backend guidance.

---

## ENDPOINT PHYSICS (why this axis matters)

Perfect endpoint memory must survive **years offline** on one box. Infinity is not “never delete”; it is **unbounded time with a bounded live working set**, recoverable cold storage, and signed distill/evict history. Cloud-only compaction fails radio-dark. Hard-delete-only fails ops. Unbounded long-tier fails the device. The fixed point is **C above**: pressure valves + typed leaves + honest defaults ladder — the same dual-plane instinct as W4-A6, applied to **capacity** rather than GDPR content.

---

*Base: workspace `ai-memory-mcp` HEAD at assessment date · schema narrative v78 · no live multi-million soak re-run this wave.*
