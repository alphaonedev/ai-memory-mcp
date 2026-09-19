---
layout: doc
---

# `find_paths` executed engine (AGE 1.8.0 re-verify)

Issue [#3297](https://github.com/alphaonedev/ai-memory-mcp/issues/3297)
N15: re-verify the #2582 `find_paths` "relational CTE only" rationale
against the certified Apache AGE pin (**1.8.0**,
`EXPECTED_AGE_VERSION` / `deploy/docker-1461/provision/lib.sh`), not
the 1.7.0 parse-rejection that justified deleting the Cypher reader.

This page is the capture. It does **not** live under
`docs/compliance/evidence/` (Conductor-owned until #3607).

## Pin

| Field | Value |
|---|---|
| AGE `extversion` | `1.8.0` |
| Host | certified local PG 18 + AGE 1.8.0 + pgvector tier (TLS verify-full) |
| Database | a throwaway database created and dropped inside the probe |
| Date | 2026-09-11 |

## Grammar probes (list predicates)

On AGE **1.7.0**, `ALL(e IN relationships(p) WHERE …)` was a **parse**
rejection (`syntax error at or near "("`). On AGE **1.8.0**:

| Cypher | Result |
|---|---|
| `RETURN ALL(x IN [1,2,3] WHERE x > 0)` | **parses**, returns `true` |
| `RETURN ANY(x IN [1,2,3] WHERE x = 2)` | **parses**, returns `true` |
| `RETURN filter(x IN [1,2,3] WHERE x > 1)` | **parse-rejects** (`syntax error at or near "WHERE"`) |
| `MATCH p = (a:Memory)-[*1..2]->(b:Memory) WHERE ALL(e IN relationships(p) WHERE e.valid_until IS NULL) RETURN a.id, b.id` on a two-vertex seeded graph | **not a parse error**; runtime `ERROR: no relation entry for relid 2` |
| Control: same `MATCH` **without** the `ALL(…)` guard | **succeeds** (`"src"` → `"dst"`) |

So the 1.7.0 "list predicates are grammar keywords, not callable" claim
is **stale for `ALL`/`ANY` on 1.8.0**. The find_paths guard still does
not succeed (runtime, not parse). Restoring an AGE `find_paths` reader
is follow-up [#3609](https://github.com/alphaonedev/ai-memory-mcp/issues/3609);
the E4 decision below retains the relational reader and pins the runtime distinction.

## EXPLAIN of a PARSEABLE AGE walk (no `ALL` guard)

Empty `memory_graph`, depth-2 variable-length path — the plan shape
that #2582 measured on a 20k-vertex corpus (outer `Seq Scan` over
vertices, VLE nested loop):

```
 Hash Join  (cost=37.01..15134.14 rows=1000 width=32) (actual time=0.002..0.002 rows=0.00 loops=1)
   Hash Cond: (_age_default_alias_0.end_id = b.id)
   ->  Nested Loop  (cost=0.01..15082.00 rows=1000 width=80) (actual time=0.001..0.002 rows=0.00 loops=1)
         ->  Seq Scan on _ag_label_vertex a  (cost=0.00..22.00 rows=1200 width=40) (actual time=0.001..0.001 rows=0.00 loops=1)
         ->  Function Scan on age_vle _age_default_alias_0  (cost=0.01..12.51 rows=5 width=48) (never executed)
               Filter: (a.id = start_id)
   ->  Hash  (cost=22.00..22.00 rows=1200 width=40) (never executed)
         ->  Seq Scan on _ag_label_vertex b  (cost=0.00..22.00 rows=1200 width=40) (never executed)
 Planning Time: 0.276 ms
 Execution Time: 0.065 ms
```

The outer side in this captured plan is a `Seq Scan` on `_ag_label_vertex`.
This is evidence for the measured corpus and plan, not a universal proof
that AGE cannot win at any depth or after a supported rewrite.

## Production engine (unchanged)

`PostgresStore::find_paths` calls `find_paths_cte` on **both**
`KgBackend` values (`src/store/postgres.rs`). SQLite uses the same
bounded BFS. `kg_query` / `kg_timeline` / `lineage` still execute
AGE Cypher when the extension is present.

## E4 decision and reproducible native pins (#3609)

Retain the relational fallback on both `KgBackend` values. Since #3196,
`find_paths_cte` is a legacy method name for bounded level-by-level BFS in
Rust, fetching each frontier from `memory_links` with parameterized SQL.
It does **not** currently execute a recursive CTE or an AGE path reader.
The durable relational view preserves read-your-write behavior when the
AGE projection is delayed, plus current-view, undirected, cycle, depth,
prefix-budget and result-cap semantics. No per-request failing AGE probe
is introduced. A future AGE rewrite requires its own execution, parity
and workload measurements; scalar-list grammar support is insufficient.

Run on a throwaway database with an explicit `AI_MEMORY_TEST_AGE_URL`:

```sh
timeout 1800 cargo test --features sal-postgres --lib path_predicate_tests \
  -- --include-ignored --test-threads=1 --nocapture
```

`age_180_predicate_runtime_failure_has_a_live_control` is intentionally
version-bound to AGE 1.8.0. It executes scalar-list ALL/ANY, a seeded path
with and without the relationships predicate, and parse-rejected filter.
If a later AGE fixes the predicate, this characterization goes RED so the
engine decision is revisited. An unavailable or undeclared AGE fails when
the ignored native tests are explicitly selected; it never passes as CTE.

`age_dispatch_and_relational_dispatch_preserve_current_paths` executes the
production dispatcher with both backend settings against the same native
fixture and compares explicit expected paths. Its diamond, parallel edges,
expired shortcut/leaf, isolated node, reverse direction, depth and cap
checks prevent empty/empty equivalence. These are **two dispatch settings
using one relational reader**, not an advertised AGE Cypher equivalence.
The existing native postgres-ignored CI job selects both pins.

On 2026-09-19, native PostgreSQL18.6/AGE1.8.0/vector0.8.6 again measured
list ALL/ANY success, a two-row unguarded path control, and runtime
`no relation entry for relid` under path ALL. Detailed SHA-bound RED/GREEN
logs are retained under gitignored `.local-runs/path-predicates/` and in
the E4 PR notes. Prior 2026-09-11 plan capture above remains historical.
