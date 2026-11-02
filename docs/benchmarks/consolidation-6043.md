---
layout: doc
---
# Consolidation benchmark (#6043)

Measures how far the existing curator `ConsolidationPass`
(`src/curator/compaction.rs`) shrinks a store, against retrieval recall,
LLM calls and wall time, then rolls the shrink back: every original row's id,
namespace, title, content, metadata and tags come back identical; stored
vectors are not restored (#8465) and must be re-embedded. Adopted by the #8458
3-agent vote. The pass itself is not modified.

The corpus is synthetic. The result measures the mechanism (shrink, call
count, reversibility), not task performance, and is not a performance claim.

Code: `src/curator/bench_6043.rs` (in the crate because the pass is
`pub(crate)`).

## R2: deterministic CI arm

A fixed-seed corpus: six near-duplicate clusters (sizes 5, 4, 4, 3, 3, 2)
and 20 distinct rows, each with a stored 384-dimension synthetic embedding in
one embedding space. The pass runs with a counted in-tree stub
`AutonomyLlm`. No network, no model download.

```
cargo test --lib --features sal bench_6043
AI_MEMORY_TEST_POSTGRES_URL=<lane db> cargo test --lib --features sal-postgres bench_6043
```

The Postgres cell leaves its rows behind, so run it on a minted per-run clone
(the CI v2 template wrapper `scripts/test/pg_isolated_binary.py`) and drop the
clone and template afterwards. On CI a missing `AI_MEMORY_TEST_POSTGRES_URL`
fails the test; off CI it skips.

Each run prints one TOON line:

```
bench_6043_result[1]{backend,threshold,rows_before,rows_after,shrink_pct,pass_llm_calls,wall_ms,rollback_entries,r5_before,r5_after,r5_after_unembedded,r10_before,r10_after,r10_after_unembedded,rows_after_rollback,rollback_identical,embedding_restored}: ...
```

* `pass_llm_calls`: summarise calls the consolidation pass made (the operator
  arm's question-answering calls are not in this column).
* `r*_after`: recall with each summary given the centroid vector of the rows it
  replaced (the effect of the embedding backfill). `r*_after_unembedded`: the
  summaries have no vector yet.
* `rollback_identical`: after `reverse_rollback_entry_store` every original
  row's id, namespace, title, content, metadata and tags are identical to the
  seeded row.
* `embedding_restored`: the same check including the stored vector and its
  space. It is `false` today because rollback restores rows only; tracked in
  [#8465](https://github.com/alphaonedev/ai-memory-mcp/issues/8465). The test
  pins the current value so the fix forces this column into the main check.
  The numbers are measured with the lineage DAG off, where the pass
  hard-deletes the sources. With the DAG and tombstoning on, rollback merges
  over the tombstone and the vector survives; the tests hold
  `no_lineage_dag_guard` so the measured mode never depends on sibling tests.

The assertions are shown able to fail: a pass with rollback disabled fails the
identity check, and every comparator field (id, namespace, title, content,
metadata, tags, embedding, embedding space) is tampered with in a unit test.
The recall values and `shrink_pct` are pinned exactly per threshold; wall
time is asserted non-zero.

## R3: operator arm (real LLM)

`#[ignore]`d test `bench_6043_real_llm_threshold_sweep`. It runs the same
seeded flow against the LLM named by the existing `AI_MEMORY_LLM_*`
environment variables (no new secrets; never printed), sweeping
`cosine_threshold` over 0.70, 0.75 and 0.85. It also asks a fixed question per
topic, answered from the top 5 notes before and after consolidation (QA
accuracy). It skips only when `AI_MEMORY_LLM_BACKEND` is unset. Once that
variable is set, a client that cannot be built or any LLM error fails the test.

```
cargo test --lib --features sal bench_6043_real_llm -- --ignored --nocapture
```

The JSON report is written to `.local-runs/bench-6043/consolidation-report.json`
with shrinkage, recall at 5 and 10, QA accuracy before and after,
pass_llm_calls, wall_ms and rollback_entries per threshold. `.local-runs/` is gitignored and not
auto-cleaned; delete it when done.
