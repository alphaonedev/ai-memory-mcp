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
| Host | local certified PG 18 + AGE + pgvector (TLS verify-full, :5445) |
| Database | throwaway `ai_memory_grok_3297` (created + dropped in the same probe; never `ai_memory_test`) |
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
this docs lane does not change the dispatcher.

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

The outer side is a `Seq Scan` on `_ag_label_vertex`. That is the
#2582 reason the dispatcher stays the relational CTE even if the
`ALL(…)` guard were rewritten to parse: a parseable AGE walk still
scales with `|V|`, not depth.

## Production engine (unchanged)

`PostgresStore::find_paths` calls `find_paths_cte` on **both**
`KgBackend` values (`src/store/postgres.rs`). SQLite uses the same
bounded BFS. `kg_query` / `kg_timeline` / `lineage` still execute
AGE Cypher when the extension is present.

Differential relational↔AGE suite for `find_paths`: stays v1.1 (V9)
per the #3297 comment.
