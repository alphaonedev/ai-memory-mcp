# W6-A5 — Knowledge-graph / lineage interoperability

**Lens:** Can an agent (or peer product) treat ai-memory’s graph as *one* navigable substrate — or do KG tools and the G13-mem lineage DAG silently disagree?
**Surfaces:** `memory_links` (9 relations), `memory_kg_*` + `find_paths`, `memory_lineage` / `GET …/lineage` / `ai-memory lineage`, AGE `memory_graph` + `kg_projection_outbox` (v69), `source_cid`/`target_cid` (v75), entity registry.
**Code anchors:** `src/models/link.rs` (`MemoryLinkRelation::LINEAGE`, `is_lineage`), `src/storage/mod.rs` (`kg_query`, `lineage_traverse`, `LINEAGE_MAX_DEPTH`), `src/store/postgres.rs` (`lineage_cte`/`lineage_cypher`/`lineage_traverse`, AGE fallback), `src/kg/cycle_check.rs`, `src/handlers/links.rs::get_lineage`, ADRs 0002–0003, `docs/kg-backend-fallback.md`, #1859 G13-mem.

---

## SCORE

| Axis | Score (0–10) | Read |
|------|-------------:|------|
| **Single physical graph (SoR)** | **9** | One `memory_links` table; lineage is a *view over P*, not a second edge store |
| **Typed relation discipline** | **8** | Closed 9-relation CHECK; `LINEAGE = {derived_from, reflects_on, derives_from}` SSOT |
| **Backend parity (sqlite / PG-CTE / AGE)** | **7** | CTE twins + AGE→CTE graceful fallback; deferred projection forces CTE for RYW on lineage |
| **Semantic unity (KG vs lineage answers)** | **4** | Same edges, *different* filters: temporal current-view vs provenance-conserving walk |
| **Content-address stability (cid)** | **5** | Additive BLAKE3 cid + edge mirrors; UUID still FK/federation LWW; cid advisory (non-unique) |
| **Cross-surface API parity** | **8** | MCP + HTTP + CLI for lineage; graph family for KG; SAL trait methods |
| **External / multi-product interop** | **2** | No RDF/JSON-LD/GraphML export; no Zep/Graphiti/Neo4j wire; entity graph half-coupled |
| **Federation mesh agreement** | **4** | Link invalidate eventual (ADR-0003); lineage chrono guard bypassed on import; AGE lag |
| **Agent-usable mental model** | **3** | Two tool families + three “lineage” words (memory DAG / identity `agent_lineage` / reflection chain) |
| **Overall interoperability readiness** | **5.0** | Strong internal VIEW design; weak *semantic product* unity + external egress |

**Confidence:** 0.84 on gap inventory (code-anchored). 0.70 on external-export priority vs category moat (W3-A6). 0.78 on overall score.

---

## VERDICT

**ai-memory has one link store and two *query contracts*.** That is the right storage architecture (G13-mem: lineage adds no new relation) and the wrong *default agent story* if operators believe `memory_kg_query` ≡ `memory_lineage`.

- **KG contract (v0.6.3+):** temporal *current knowledge* — `valid_until` / `valid_at` / `include_invalidated`; all 9 relations; `find_paths` walks labels unfiltered; invalidate is soft + mesh-eventual.
- **Lineage contract (v0.9.0 #1859):** *conserved derivation* over P only — includes tombstoned nodes, ignores lifecycle filter, stamps/walks `source_cid`/`target_cid`, chrono acyclicity on local writes, no `valid_at` knob.
- **Identity lineage (v76 #1828):** third homonym — key succession, not memory provenance (W4-A1).

Interoperability *inside* the binary is mostly “shared table + mirrored AGE/CTE dispatch.” Interoperability *for cognition and peers* fails when temporal invalidation, multi-relation paths, typed-cognition edges (`decomposes_into`/`depends_on`/`advances`), and cid-vs-UUID resolve to different truths depending on which tool was called.

---

## GAPS

| # | Gap | Evidence / effect |
|---|-----|-------------------|
| **G1** | **Dual answer surfaces** | `kg_query` default drops invalidated edges; `lineage_traverse` has no `valid_until` predicate — an invalidated `derived_from` still appears in lineage |
| **G2** | **`find_paths` ≠ lineage** | CTE projects *every* relation; P-only walk is only on `memory_lineage` — agents get mixed-relation “provenance” from find_paths |
| **G3** | **Typed-cognition edges outside P** | `decomposes_into` / `depends_on` / `advances` are KG-visible structure but not lineage-DAG; plan trees ≠ derivation chains |
| **G4** | **`supersedes` outside P** | Version headship is KG/`supersedes`; derivation is P — multi-hop “what replaced what *and* what was distilled from what” needs two walks |
| **G5** | **cid advisory only** | LineageNode.cid from edge mirror or JOIN; COND 2: non-unique index; federation dedup still UUID — cross-node cid join is a *hint*, not merge key |
| **G6** | **AGE projection lag** | Deferred mode correctly reroutes lineage to CTE (COND 5a); sync AGE can still disagree until runtime fail→CTE; outbox quarantine is operator-silent to agents |
| **G7** | **Federation import bypass** | Lineage chrono guard skipped on `apply_remote_link` (clock skew) — mesh can land forward P-edges local nodes would 409 |
| **G8** | **Invalidate mesh lag** | ADR-0003: kg invalidate not quorum-broadcast; peers disagree on “current” KG for ≤ sync interval; lineage doesn’t care (G1) — *worsens* dual-view confusion |
| **G9** | **Naming collision** | `agent_lineage` vs memory lineage vs reflection “chain” vs `find_paths` — docs/tools still teach three words for three graphs |
| **G10** | **No export / open graph format** | No first-class dump of `memory_links`(+cid,+temporal,+attest) as portable graph for Graphiti/RDF/compliance tools |
| **G11** | **Entity registry half-coupled** | Entities are long-tier memories + `entity_aliases`; not first-class vertices in lineage wire shape |
| **G12** | **Flag seed / opt-out matrix** | `lineage_dag` atomic unseeded=false; consolidate tombstone tracks DAG flag — mixed daemon boot can write edges without cid mirrors then walk “lineage” on sparse cids |
| **G13** | **Hard-delete opt-out breaks multi-hop** | `AI_MEMORY_CONSOLIDATE_TOMBSTONE_SOURCES=0` → non-navigable `metadata.derived_from_cids` only — lineage + KG diverge by operator policy |
| **G14** | **Cycle guards split** | P-wide chrono guard vs `reflects_on`-only reflection cycle walk — different refusal classes for related invariants |

**What already works (do not rebuild):** shared SoR; `MemoryLinkRelation::LINEAGE`; depth cap shared with KG; three-surface lineage parity; AGE→CTE fallback + deferred RYW path; tombstone-preserving lineage walk when consolidate-tombstone ON; link pre-create gates unified at storage layer.

---

## VOTE (5-axis internal)

| Lens | Stance |
|------|--------|
| **Precedent** | Keep lineage as VIEW over P; never fork a second edge table |
| **Spec / G13-mem** | Preserve COND 1–5 (cid stamp, advisory cid, chrono local, AGE dispatch, tombstone inclusion) |
| **Agent UX** | One *product* graph story: “current facts” vs “derivation history” must be named, not two silent tool families |
| **Security / federation** | Do not make mesh lineage chrono fail-closed without clock/HLC policy; prefer labeled import provenance |
| **Blast radius** | Additive: temporal filter flag on lineage, relation filter on find_paths, export schema — no CHECK rebuild |

**Tally:** 5/5 — **interop = contract unification + egress, not a third graph engine.**

**Chosen pathway (dependency order):**
1. **Claims + tool docs** — freeze “KG = temporal current/history; lineage = P-conserving derivation; identity lineage = keys.”
2. **Wire honesty** — optional `respect_valid_until` / `as_of` on lineage (default off = conserved); optional `relations=` on find_paths (default all, document ≠ P).
3. **Golden vectors** — same fixture corpus: expected kg_query vs lineage vs find_paths matrices (AGE+CTE+sqlite).
4. **Export** — versioned `graph_export` (links + cid + temporal + attest_level + lifecycle) for offline/interop consumers.
5. **Mesh** — document import-bypass + invalidate lag; later: signed lineage package on federation push (pairs W4 P4.4 *memory* not only identity).
6. **cid promotion** — only after unique/enforce story (ROADMAP/G8 follow-through); do not claim cid-primary identity yet.

---

## KILLER_OBJECTION

**“We already share `memory_links` — interoperability is done.”**  
Sharing a table is storage unity, not cognitive unity. An agent that invalidates a wrong derivation, then audits via `memory_lineage`, still “sees” the edge; another that uses `kg_query` believes it gone; a third uses `find_paths` and walks through `related_to` noise. Peers on deferred AGE or lagging invalidate observe a fourth graph. **Without a single named contract (and tests that pin tool-answer matrices), the dual surface is a silent prior-laundering and audit-confusion channel** — the opposite of endpoint governance (W4-A3 T1).

---

## TOP_RISK

**Semantic fork under one table:** operators and NHI agents treat KG tools and lineage as interchangeable provenance, while temporal invalidation, relation filters, tombstone policy, AGE projection mode, and federation import bypass make answers **non-substitutable**. That produces false audit confidence (“we walked the lineage”) and false safety confidence (“we invalidated the link”) in the same corpus. Secondary: external graph ecosystems cannot consume the substrate without bespoke scrape — locking network effects to the single binary (W3-A6 anti-moat of implementation-as-standard).

---

## One-line north star

> **One edge store, two named contracts (temporal KG vs conserved derivation), portable export, and golden answer matrices — never a second silent graph.**
