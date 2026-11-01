# Assessment: arXiv 2610.39790 against ai-memory

**Status:** research record, advisory. Tracked by [#8458](https://github.com/alphaonedev/ai-memory-mcp/issues/8458). Nothing here changes v1.0.0 GA scope.
**Date:** 2026-11-01.
**Decision record:** 3-agent vote (6def5ab6), three read-only lenses (precedent, opportunity, blast-radius), unanimous on all three questions.
**Rule for this page:** it makes no performance claim about ai-memory. Every figure below is either a figure the paper reports (quoted as the paper states it) or a count of code elements. Any statement about ai-memory accuracy, recall or shrinkage awaits a measured result from the R2 to R4 rows in section 7, and none may be quoted before one exists.

## 1. The paper

Gupta, Han, Madrigal Diaz, Chen, Das, Ruehle, Rajmohan (Microsoft), "Long-Term Agent Memory through Complementary Curation and Consolidation", [arXiv 2610.39790v1](https://arxiv.org/abs/2610.39790), 29 October 2026. The page names no code or data release. Figures below were checked against the arXiv HTML of v1 on 2026-11-01 and are quoted as the paper states them.

| Section | What it describes |
|---|---|
| 3.1 Curation | After each session an Episodic Memory Manager writes timestamped records (title, one-sentence summary, details paragraph). A Relational Memory Manager extracts (entity, relation, object, timestamp, source context) tuples. |
| 3.2 Consolidation, Appendix C | Offline pass: embed (text-embedding-3-small), UMAP reduce (10 neighbours, 5 components), HDBSCAN cluster (minimum cluster size 10), then an LLM applies MERGE or DELETE inside each cluster to remove redundant, conflicting or outdated entries. The paper describes no safeguard, rollback or undo for either action. |
| 3.3 Retrieval | Independent top-k over each store (k=10 episodes, 2k tuples), both fed to the answering model. |
| 4.2 Results and Appendix D | LoCoMo 90.2 percent with gpt-4.1-mini (FullContext 91.3 percent, 87 percent fewer tokens); 83.5 percent with gpt-4o-mini at about 2.7K tokens per question against Mem0 61.3 percent and Zep 58.5 percent (Table 3); LongMemEval-S 85.5 percent. Episodic plus relational beats either alone (Appendix D, Table 6: 0.871 to 0.902 and 0.776 to 0.835; +6.3 multi-hop, +6.8 temporal with gpt-4o-mini). The consolidation pass shrinks the store 16.34 percent (Introduction and 4.2, Efficiency) for about a 1 point accuracy cost (Table 6: 0.902 to 0.892). The paper reports no token, latency or dollar cost of the consolidation pass itself. |
| 5.2 | Accuracy plateaus around k=10. |
| 5.3 Effect of cluster size | Table 5 sweeps the minimum cluster size. Every consolidated row sits at or below the unconsolidated baseline (0.902 baseline against 0.876 to 0.898); a minimum cluster size of 2 costs 2.6 points while 5 to 20 stays within about 1 point. The number of clusters, which the paper equates with the number of LLM consolidation calls, falls from 2,208 at size 2 to 144 at size 20, a reduction of up to 15x. |
| 7 Limitations | Results depend on the backbone LLM (a 6.7 point swing between backbones). |

## 2. Operator assessment (verbatim, 2026-11-01)

> **Microsoft's memory paper ([arXiv 2610.39790](https://arxiv.org/abs/2610.39790)): medium relevance, worth exploring.** It combines episodic memory, timestamped relation records, and an offline pass that clusters memories and then merges or deletes them. It scores 0.835 on LoCoMo with gpt-4o-mini, using about 2.7K tokens per question, against 0.613 for Mem0 and 0.585 for Zep. The consolidation pass shrank the store 16.3% for about one point of accuracy, but the paper doesn't say what that pass costs to run. I'd add a test to #6043 that runs ai-memory's existing curator pass and reports how much the store shrinks against accuracy, LLM calls, and time.

## 3. Mechanism-by-mechanism mapping

File:line anchors are against the chain base this page was cut from (recorded in the commit `Base:` trailer). "Gap" means no counterpart exists.

| Paper mechanism | ai-memory counterpart | Vote stance |
|---|---|---|
| 3.2 embed, cluster | `ConsolidationClustering` (`src/curator/cluster.rs:125`): a Jaccard pre-filter AND a cosine gate (default 0.75, operator configurable); singletons discarded, clusters of 2 or more kept (`cluster.rs:124`). Driven by `ConsolidationPass` (`src/curator/compaction.rs:158`); clustering at `compaction.rs:279` refuses un-embedded rows (#1774) and cross-embedding-space pairs (#2167). | Covered; measure, do not replace. |
| 3.2 UMAP plus HDBSCAN | None, by design. | Reject: new crates (operator-gated) and non-deterministic output. |
| 3.2 MERGE | `ConsolidationPass::run` (`compaction.rs:592`) with a `PreCompaction` decision gate before the destructive merge (`compaction.rs:622`), a write-ahead rollback entry (`compaction.rs:657`, persisted by `persist_rollback_write_ahead` at `compaction.rs:494`), a verify step (`compaction.rs:695`) and a reachability-checked rollback (`rollback_consolidation`, `compaction.rs:827`). Dry-run supported. Backend agnostic (SQLite and Postgres). | Covered; stricter than the paper, which describes none of these controls. |
| 3.2 DELETE of outdated or conflicting facts | Non-destructive supersession: `kg_invalidate` sets `valid_until` (`src/handlers/kg.rs:871`); contradiction detection only flags rows (`src/curator/mod.rs:391-406`). | Reject LLM DELETE: no criteria, no undo, a fail-closed posture change (T3), and it removes the durable text. |
| 3.1 episodic record (title, summary, details, timestamp) | Partial: `Memory` title, content and `created_at`; `memory_capture_turn` (`src/mcp/tools/capture_turn.rs:309`); `memory_atomise` splits a memory into 2 to 10 propositions (`src/mcp/tools/atomise.rs:261`, `Atomiser` at `src/atomisation/mod.rs:344`). No per-session pass writes a summary record. | Document; optional summary and event-time metadata is a later candidate. |
| 3.1 relational tuples (entity, relation, object, time, context) | Partial. The knowledge graph is memory-to-memory: `KgQueryRow` carries a `target_id` memory id and a relation string (a `MemoryLinkRelation` value) (`src/store/mod.rs:204-208`), with `valid_from` and `valid_until` on edges (`kg_timeline`, `src/store/sqlite.rs:4479`). Edges are authored by explicit calls. **Gap:** no LLM extraction of tuples and no source-context field. | Experiment first (R7). |
| 3.3 two-store independent top-k union | **Gap.** `recall_hybrid` (`src/store/sqlite.rs:2012`) returns memories from one store; `kg_query` (`sqlite.rs:4440`) runs separately and is not unioned into recall. | Experiment first, behind a flag, default off (R5). |
| 5.2 k plateau | Recall limit knobs exist; no k sweep has been measured. | Folded into R4. |
| 5.3 cluster-size sensitivity | `cosine_threshold` is configurable and clusters of 2 are kept (`cluster.rs:124`), the regime the paper's section 5.3 flags as costly. No sweep has been run. | Experiment first (R6). |
| 5.3 pass cost | The paper reports cluster counts and LLM-call reductions (section 5.3) but no token, latency or dollar cost of the pass itself; not measured for ai-memory either. `ConsolidationRunReport` carries cluster counts and rollback entries written. | Adopt as measurement (R2, R3, issue #6043). |
| LoCoMo harness | **Gap.** A LongMemEval harness (`benchmarks/longmemeval/`) and a reflection bench (`benches/longmemeval_reflection.rs`) exist; no LoCoMo harness. | Adopt (R4). |

Counted-stub precedent for a deterministic benchmark arm: the `AutonomyLlm` stub in `benchmarks/longmemeval_reflection/runner.rs` (`DeterministicLlmStub`, `:103`, `summarize_memories` at `:145`) and the counting stub in the curator tests (`CountingStubLlm`, `src/curator/mod.rs:3257`). `docs/ROADMAP-v110.md` cites this precedent in its harness section.

## 4. What ai-memory already covers

Consolidation exists and is stricter than the paper: gated, previewable, reversible and verified. The relational layer exists as a bitemporal link graph. What the paper's result rests on, the dual-store union at recall time (section 3.3, Appendix D), is the part ai-memory does not have. All three lenses agree on this reading (PARTIAL, confidence 80, 82 and 80).

Two cautions recorded by the lenses:

- Do not call the knowledge graph equivalent to the paper's relational store. Our edges link memories to memories; the paper's tuples are extracted strings with source context.
- Typed, signed links with `valid_from` and `valid_until` may already give agents most of the structure where agents author the links themselves; the tuple store may add little there. That is what the R7 experiment decides.

## 5. Rejected mechanisms and why

1. **LLM DELETE inside a cluster (3.2).** The paper gives no criteria, no prompt and no undo. A model-decided erase is a second destructive verb on the durable text, which the data-integrity directive does not allow, and it would change the fail-closed posture of the `PreCompaction` gate payload. Supersession through `kg_invalidate` already covers "outdated". Unanimous.
2. **UMAP plus HDBSCAN (3.2, Appendix C).** It needs new crates, and adding a dependency needs operator authorisation; the output is not deterministic across platforms, which would break the deterministic CI arm; and the Jaccard plus cosine gate is fail-closed by construction. Measure the existing clusterer first. Unanimous.

## 6. Risks the lenses recorded

- An LLM extractor on every session multiplies LLM cost and adds derived state that can drift from the text. It must be metered against `max_ops_per_cycle` (`src/curator/mod.rs`, `AUTONOMY_OP_RESERVE_DIVISOR` at `:107`), rebuildable, model-fingerprinted like embeddings (#2167 precedent) and off by default.
- Memory text is untrusted input to any LLM tuple extractor (R7): a stored memory can carry instructions aimed at the extractor, so the extractor must treat content as data, bound its output to the tuple schema, and fail closed on malformed or oversized output.
- A seeded synthetic store cannot reproduce LoCoMo conversational redundancy, so a shrinkage figure from it is not comparable with the paper's 16.34 percent. Any accuracy figure from a seeded store must not be quoted as task performance (the `NO_MEASURED_PERF_CLAIM` rule in `docs/ROADMAP-v110.md`).
- The paper reports a 6.7 point swing by backbone model, so any gain may not transfer to the operator's model or to agent-fleet corpora.
- The benchmark must run on a seeded copy store, never a live one, or the experiment becomes the destructive operation.

## 7. Adopted rows (acceptance criteria as recorded in the vote tally and the voter returns)

| Row | Item | Acceptance criterion | Size | Depends on |
|---|---|---|---|---|
| R1 | Assessment and mapping document | This page. Docs under `docs/research`, excluded mechanisms and why, no performance claim without a citation. | S | none |
| R2 | #6043 consolidation benchmark, deterministic CI arm | The existing `ConsolidationPass` on a seeded copy store with a counted stub LLM; pins shrink percent and LLM call count, and that rollback restores 100 percent of originals byte-identically. | M | none |
| R3 | #6043 operator arm | Real pinned LLM, fixed seed, run outside CI; reports shrinkage, R@5 and R@10, QA accuracy before and after, LLM call count, wall time and rollback entries as separate metrics. | S | R2 |
| R4 | LoCoMo harness | Runs the published LoCoMo protocol; R@k and QA scored separately; k sweep. | M | R2 |
| R5 | Fused dual-store recall experiment | Opt-in flag, default off, read-only; unions `recall_hybrid` top-k with `kg_query` rows; reports multi-hop and temporal deltas against recall-only. | M | R4 |
| R6 | Threshold by minimum-cluster-size sweep | `cosine_threshold` 0.70, 0.75, 0.85 by minimum cluster size 2, 3, 5; defaults change only on evidence. | S | R2 |
| R7 | Derived tuple index plus second recall channel | Derived from memory text, model-fingerprinted and rebuildable, default off until it shows at least 3 points gain with no integrity regression. | L | R4 |

R1 is delivered by this change. R2 and R3 are tracked under #6043. R4 to R7 are the v1.1.0 implementation issues #8461 (LoCoMo harness), #8462 (fused dual-store recall), #8463 (threshold by minimum-cluster-size sweep) and #8464 (derived tuple index), linked from `docs/ROADMAP-v110.md`.

A side finding is filed separately as #8459: the comment at `src/config.rs:9887-9888` still describes Postgres reversal as pending under #1748, although #1748 is closed.

## 8. Vote record

| Question | precedent | opportunity | blast-radius | Result |
|---|---|---|---|---|
| Q1 already addressed? | PARTIAL, 80 | PARTIAL, 82 | PARTIAL, 80 | PARTIAL, unanimous |
| Q2 worth applying? | EXPERIMENT-FIRST, 75 | EXPERIMENT-FIRST, 78 | EXPERIMENT-FIRST, 75 | EXPERIMENT-FIRST, unanimous |
| Q3 document and roadmap? | ROADMAP, 82 | ROADMAP, 85 | ROADMAP, 78 | ROADMAP, unanimous |

3-agent vote (6def5ab6). Voter returns and the tally are comments on [#8458](https://github.com/alphaonedev/ai-memory-mcp/issues/8458).

## 9. AI involvement

Drafted by Claude Sonnet 5.5 under the conductor's brief, from the vote returns and CodeGraph-checked file:line citations; reviewed by a code and a security lens before landing.
