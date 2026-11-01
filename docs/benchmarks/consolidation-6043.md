---
layout: doc
---
# Consolidation benchmark (#6043)

Measures how far the existing curator `ConsolidationPass`
(`src/curator/compaction.rs`) shrinks a store, against retrieval recall,
LLM calls and wall time, and proves the shrink is reversible. Adopted by the
#8458 3-agent vote. The pass itself is not modified.

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

Each run prints one TOON line:

```
bench_6043_result[1]{backend,threshold,rows_before,rows_after,shrink_pct,llm_calls,wall_ms,rollback_entries,r5_before,r5_after,r5_after_unembedded,r10_before,r10_after,r10_after_unembedded,rows_after_rollback,rollback_identical,embedding_restored}: ...
```

* `r*_after`: recall with each summary given the centroid vector of the rows it
  replaced (the effect of the embedding backfill). `r*_after_unembedded`: the
  summaries have no vector yet.
* `rollback_identical`: after `reverse_rollback_entry_store` every original
  matches byte for byte on id, namespace, title, content, metadata and tags.
* `embedding_restored`: the same check including the stored vector and its
  space. It is `false` today because rollback restores rows only; tracked in
  [#8465](https://github.com/alphaonedev/ai-memory-mcp/issues/8465). The test
  pins the current value so the fix forces this column into the main check.

The assertions are shown able to fail: a pass with rollback disabled fails the
identity check, and every field of the comparator is mutated in a unit test.

## R3: operator arm (real LLM)

`#[ignore]`d test `bench_6043_real_llm_threshold_sweep`. It runs the same
seeded flow against the LLM named by the existing `AI_MEMORY_LLM_*`
environment variables (no new secrets; never printed), sweeping
`cosine_threshold` over 0.70, 0.75 and 0.85. It also asks a fixed question per
topic, answered from the top 5 notes before and after consolidation (QA
accuracy). It skips cleanly when no LLM is configured.

```
cargo test --lib --features sal bench_6043_real_llm -- --ignored --nocapture
```

The JSON report is written to `.local-runs/bench-6043/consolidation-report.json`
with shrinkage, recall at 5 and 10, QA accuracy before, llm_calls, wall_ms and
rollback_entries per threshold. `.local-runs/` is gitignored and not
auto-cleaned; delete it when done.
