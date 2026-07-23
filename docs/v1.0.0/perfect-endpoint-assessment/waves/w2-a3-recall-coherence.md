# W2-A3 — Recall Purity & Coherence Assessor

> **Agent:** W2-A3 (Recall Purity & Coherence)  
> **Date:** 2026-07-08  
> **Scope:** ROADMAP §2.2 + pure-recall P0-1 (#1869) + capture completeness (S3 / 2.2-C)  
> **Wave-1 frame:** `w1-a7-synthesis.md` (CONFIRM 2.2 contingent; S3/S4 fold-ins; pure RECALL is S4 verb, not 8th peer)

---

## VERDICT

**SPLIT HOLD:**

| Axis | Status |
|---|---|
| **Pure recall (P0-1 / #1869)** | **SHIPPED — structurally held under scoped claim** |
| **§2.2 coherence (sessions + model generations)** | **PARTIAL — axes confirmed, not fully held** |
| **Capture completeness (S3 / 2.2-C)** | **PARTIAL — L1+L2+L4 live; L3 missing; L1 volunteer** |

Pure recall is a real architectural flip (default OFF sync-touch, schema v77 `folded`, FOLD maintenance, dump-compare kill-tests on every sqlite entry path + postgres parity suite). It closes the “recall silently rewrites memory state” kill-test against `git + ripgrep + RAG`.

§2.2 is **not** the same achievement. Continuity primitives exist (durable owner stamps, session_start, persona versioning, L2/L4 recovery), but **perfect coherence under process death remains incomplete without capture completeness**. Wave-1 chair correctly subordinated capture as **2.2-C / S3** — scoring pure recall as if it completed 2.2 would collapse ontology.

---

## CONFIDENCE

**0.88** overall (0.93 pure-recall code path; 0.82 §2.2/capture synthesis).

| Factor | Δ |
|---|---|
| Kill-tests `recall_purity_p01.rs` + `recall_purity_p01_postgres.rs` + caller-census guard | + |
| Default `AI_MEMORY_RECALL_TOUCH_SYNC` unset; flag parses only `"1"` as opt-in | + |
| Fold-before-gc + dedicated 60s fold loops (sqlite + SAL/postgres) | + |
| L2 dual-path (`recover_from_transcript` + `recover_from_transcript_store`) + L4 idempotent capture | + |
| L3 filesystem-notify watcher **explicitly deferred** (ROADMAP §11 / #1389) | − |
| Coherence contingent on frozen-weights (§6.6 / Wave-1 T3) — not code-falsifiable here | − |
| CLI-only / no-daemon topologies: fold freezes until manual `gc` | − |

---

## SHIPPED

### Pure recall (P0-1) — structural

| Anchor | Evidence |
|---|---|
| Schema v77 | `migrations/sqlite/0061_v77_recall_observations_folded.sql`; postgres `migrate_v77`; backfill `folded=1` on pre-v77 ledger rows |
| Default pure | `config::recall_touch_sync_enabled()` → true **only** when env `== "1"`; unset = pure |
| Surfaces gated | HTTP sqlite phase-2 (`handlers/recall.rs` ~803–816); HTTP postgres (`touch_after_recall` flag-gated ~522–529); `storage::apply_recall_post_ops` / hybrid post-ops; MCP free-fn path inherits storage gate; CLI/shell covered by kill-test census |
| Sanctioned write | Append-only `recall_observations` (`record_recall*` / SAL `record_recall_observation`); ledger rows carry `folded` |
| FOLD job | `db::fold_recall_accesses` (sqlite); `MemoryStore::fold_recall_accesses` (postgres CTE chunk); default trait no-op for third-party adapters |
| Daemon wiring | `spawn_sqlite_fold_loop_if_enabled` / `spawn_postgres_fold_loop_if_enabled`; **fold-before-gc load-bearing** in `spawn_gc_loop_with_shadow_retention` |
| Sync escape hatch | `AI_MEMORY_RECALL_TOUCH_SYNC=1` restores legacy touch; inserts **pre-mark `folded=1`** (no double-count); deprecated, removal targeted v1.0 |
| Determinism | Hybrid blend secondary-sort by memory `id` (HashMap order fix under purity kill-test) |
| Claims discipline | Epic §1.5: `"pure recall"` **scoped-allowed** only with ledger exception + eventual fold caveat |

### §2.2 scaffolding — present, not complete

| Anchor | Evidence |
|---|---|
| Durable `agent_id` | #1720 B1: `host:<hostname>` / clientInfo stamps **pid-free** (`src/identity/mod.rs`) |
| Session hydrate | `memory_session_start` + visibility filter path (`mcp/tools/session_start.rs`) |
| Persona identity | `PersonaGenerator` AgentKeypair-signed optional; **never in-place overwrite** (version++ rows); `PersonaError::NoReflections` |
| L1 capture discipline | CLAUDE.md hard-rule + `recover/nag.rs` (`AI_MEMORY_CAPTURE_NAG_THRESHOLD` default 5) → stderr WARN + `capture_lag` signed event |
| L2 recover | `recover_from_transcript` + SAL twin; `transcript_line_dedup` (schema v52); tag `recovered-from-transcript`; CLI-only (`recover-previous-session` — no MCP-tool counterpart was ever registered) |
| L4 capture_turn | MCP `memory_capture_turn` + HTTP `POST /api/v1/capture_turn`; idempotent SHA256 dedup; optional host Ed25519 allowlist |
| Owner lockout tooling | #1720 B2 `reown` + B3 boot guard (`AI_MEMORY_REQUIRE_OWNED_ROWS`) |
| Kind/pipeline surface | 13 `MemoryKind` + Goal/Plan/Step; reflect/atomise/skill composition (2.4-adjacent, feeds 2.2 externalized self) |

---

## GAPS

### Capture completeness? (S3 / 2.2-C) — **the 2.2 load-bearing hole**

| Layer | Status | Gap |
|---|---|---|
| **L1** agent `memory_store` | Policy + nag | **Volunteer.** No automatic store of operator multi-step directives; nag is soft (WARN/event), not refuse-to-continue |
| **L2** transcript recover | Shipped (sqlite + postgres) | Depends on **host JSONL surviving** and path resolution; recovers as default `Observation` until optional transcript-classify (`AI_MEMORY_TRANSCRIPT_CLASSIFY_ENABLED`, opt-in) |
| **L3** FS notify watcher | **DEFERRED** (ROADMAP; pending `notify` dep approval) | Mid-session crash **without** durable host transcript still loses uncaptured turns — the #1388 class partially unclosed |
| **L4** capture_turn | Shipped | Host/adapter must call it; allowlist empty ⇒ signed host path refuses (conservative); unsigned path is data-plane adoption work |

**Answer:** Capture is **architecturally multi-layer but not complete**. Perfect §2.2 under SIGKILL is **not held** while L1 is volunteer and L3 is absent. Score S3 ≈ **0.62** (strong backstops, open mid-session gap).

### Pure-recall residual gaps (do not re-open “shipped,” but bound claims)

1. **Eventual ladders** — access_count / TTL floor-extend / mid→long promotion / priority decades apply on fold (default 60s), not at recall response time. Response `access_count` / `freshness_state` can lag.  
2. **No-daemon topologies** — CLI-only freezes counts until manual `gc` (which folds first).  
3. **Legacy sync flag** still restores mutating recall until v1.0 removal.  
4. **Mixed-version PG caveat** (docs): pre-v77 daemon + v77 DB can double-count until all daemons upgrade.  
5. **Ledger GC safety valve** may prune aged *unfolded* rows (warn path) — rare if fold loop healthy.

### §2.2 residual (beyond capture)

- **Private-scope filtering off by default** (`resolve_read_visibility_caller` = `None` without `AI_MEMORY_AGENT_ID`) — single-operator trust-all; multi-agent coherence requires operator opt-in + reown of legacy pid rows.  
- **Paradigm contingency** (Wave-1 T3): in-weights continual learning voids 2.2/2.4 value half; dual-mode “audit-not-storage” is design honesty, not a shipped mode switch.  
- **Persona / skill continuity** still depends on reflection corpus quality + capture of decisions that *should* feed personas.

---

## SCORE

Scores = **held-fraction toward the Wave-1 frozen property** (1.0 = structurally complete under stated contingencies). Not a vanity total.

### §2.2 Coherent across sessions & model generations — **0.68**

| Dimension | Held | Notes |
|---|---|---|
| Externalized identity stamps | 0.85 | Durable B1; filtering opt-in |
| Session / boot rehydrate | 0.80 | session_start + L2 recover surfaces |
| Capture completeness (2.2-C) | **0.62** | L1 volunteer; **L3 missing** |
| Cross-generation artifacts (persona/reflect path) | 0.70 | Versioned personas; kind vocab; quality ≠ guaranteed |
| Contingency honesty (frozen-weights) | n/a | Property itself is contingent — score assumes §6.6 holds |

**Posture:** structural scaffolding **+** policy-dependent capture. **Not** “coherent by default under kill.”

### Pure recall (P0-1 / S4 RECALL verb) — **0.93**

| Dimension | Held | Notes |
|---|---|---|
| Zero silent `memories` mutation on default recall | **0.98** | Kill-tested multi-surface |
| Ledger-only sanctioned write | 0.95 | Best-effort ledger errors non-fatal |
| Fold fidelity vs legacy touch | 0.92 | Twin-DB / promotion / inbox pins in kill-test |
| Daemon freshness bound | 0.90 | 60s + fold-before-gc; CLI-only weaker |
| Escape-hatch hygiene | 0.85 | Sync mode pre-marks folded; still present |

**Posture:** **structural.** Default pure is the production contract; sync is deprecated opt-in.

### Sub-scores for Wave-2 radar (this agent’s slice)

| ID | Score | Label |
|---|---|---|
| **2.2** | **0.68** | Coherence (incl. capture as subordinate) |
| **S3** | **0.62** | Capture completeness L1–L4 |
| **P0-1 / pure RECALL** | **0.93** | Epistemic S4 verb — SHIPPED scoped |
| **S4 (full epistemics)** | *not fully scored here* | Pure recall strong; SUPERSEDE/cid/basis remain W2 peers |

---

## KILLER_OBJECTION

**Pure recall of a volunteer corpus is coherence theater.**

If the agent fails L1, L3 is absent, and no host transcript exists for L2, then after SIGKILL the substrate correctly refuses to mutate rows on `memory_recall` — and still has **nothing coherent to recall**. Shipping P0-1 without finishing capture completeness upgrades *read integrity* while leaving the #1388 failure mode’s root (uncaptured decisions) open. Marketing “session-coherent memory” from pure recall alone is the Wave-1 ontology collapse in miniature: right verb, wrong completeness claim.

---

## TOP_RISK

1. **L3 deferral + L1 volunteer** → mid-session / multi-session capture holes under process death (S3).  
2. **Operators treating pure-recall as “2.2 done”** → false confidence; capture lag invisible until the next kill.  
3. **CLI-only / fold-interval=0** deployments → stale TTL/promotion/inbox semantics vs daemon defaults.  
4. **Sync-flag residual** until v1.0 → any production `AI_MEMORY_RECALL_TOUCH_SYNC=1` silently reverts the kill-test win.

---

## VOTE

| Motion | Vote |
|---|---|
| Confirm pure recall as **structurally shipped** under Epic scoped claim | **YES** |
| Confirm §2.2 as **fully held** at v0.9 | **NO** |
| Score §2.2 as **PARTIAL (≈0.68)** with capture as primary gap | **YES** |
| Treat L3 as required for 2.2 distance ≥0.85 | **YES** |
| Promote pure-recall to peer §2 property | **NO** (Wave-1: fold under S4) |
| Allow public “pure recall” without “eventual fold / ledger exception” | **NO** |

**Ballot summary:** **SHIP P0-1 · HOLD 2.2 PARTIAL · DEMAND S3 completion for 2.2 close.**

---

## RATIONALE

Wave-1 froze 2.2 as *externalized self under volatile context / frozen weights / plural instances*, with **capture completeness as subordinate 2.2-C**. Pure recall is the **RECALL verb** of the epistemic spine (A6): reading must not rewrite belief/state. #1869 implemented exactly that with mechanical pins (v77, flag default, fold, multi-surface dump-compare) — rare for moonshot properties.

Coherence requires that what *should* survive *is written and rehydratable*. L2+L4 are serious backstops (idempotent, dual-backend L2, L4 HTTP+MCP). They do not replace L1 for live discipline, and L3’s absence is an explicit, documented hole. Durable agent stamps and reown close the self-lockout trap that would *break* coherence when multi-agent filtering turns on — necessary hygiene, not capture.

Therefore the honest dual score: **0.93 pure-recall (ship) · 0.68 §2.2 (partial) · 0.62 S3 (capture incomplete)**. Distance remaining on 2.2 is mostly **capture architecture + adoption**, not ranking math. Do not re-litigate the seven axes; measure this gap until L3 ships and L1 lag is operator-visible end-to-end under kill tests that assert *decision survival*, not just *row immutability on recall*.

---

## CODE ANCHORS (absolute paths)

- `/Users/fate/Downloads/ai-memory-mcp/src/config.rs` — `ENV_RECALL_TOUCH_SYNC`, `recall_touch_sync_enabled`, fold interval  
- `/Users/fate/Downloads/ai-memory-mcp/src/handlers/recall.rs` — pure default + phase-2 ledger/touch  
- `/Users/fate/Downloads/ai-memory-mcp/src/storage/mod.rs` — `fold_recall_accesses`, `apply_recall_post_ops`  
- `/Users/fate/Downloads/ai-memory-mcp/migrations/sqlite/0061_v77_recall_observations_folded.sql`  
- `/Users/fate/Downloads/ai-memory-mcp/src/recover/{mod,nag}.rs` — L2 + L1 nag  
- `/Users/fate/Downloads/ai-memory-mcp/src/mcp/tools/capture_turn.rs` — L4  
- `/Users/fate/Downloads/ai-memory-mcp/src/persona/mod.rs` — versioned personas  
- `/Users/fate/Downloads/ai-memory-mcp/tests/recall_purity_p01.rs` (+ `_postgres`, `_caller_guard`)  

---

*End W2-A3. Under 350 lines. No re-argument of seven properties; distance-to-ontology only.*
