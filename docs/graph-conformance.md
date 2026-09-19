---
layout: doc
---
# Relational / AGE conformance (#3573)

Run `bash scripts/check-graph-conformance.sh` with `sal-postgres` and
`AI_MEMORY_TEST_AGE_URL` pointing to a **throwaway** database with AGE and
pgvector installed. The URL is the explicit declaration of AGE availability.
Credentials belong in the invoking process environment, never in evidence.
This suite inserts synthetic memories and edges; the provisioning caller owns
database cleanup. Tests run serially and require no external model service.

The selected certification leg fails in every unavailable configuration:

| Configuration | Report | Result |
|---|---|---|
| Neither database URL set | `GRAPH_CASE url-unset` | Failure |
| PostgreSQL URL only | `GRAPH_CASE undeclared` | Failure |
| AGE URL set, extension absent | `GRAPH_CASE declared-absent` | Failure |
| AGE URL set, connection unavailable | `GRAPH_CASE declared-unavailable` | Failure |
| AGE URL set, extension present | `GRAPH_CASE declared-present` | Execute both engines |

Ordinary library tests mark the two live tests **ignored**, rather than count
early-return no-ops as passing coverage. The cert script explicitly includes
them, checks executed versus listed test counts, requires every named cell,
and verifies stored, nonempty plans under `.local-runs/graph-conformance/`.

The test-only `graph_fetch!` observer captures the **actual SQL and bound
arguments** at the production execution sites. `EXPLAIN (ANALYZE, BUFFERS,
FORMAT JSON)` executes inside a nested transaction that is rolled back before
the original statement executes. This prevents a measured invalidation from
altering the prior state seen by the operation under test. No bind values or
SQL text are stored. Plans can contain the synthetic fixture identifiers;
never run this harness against a customer database.

The fixture includes parallel relations, branching, a diamond, a cycle,
three-hop traversal, provenance edges, an isolated node, and an invalidated
edge whose stamp is independently checked in both stores **before** reads.
Query depth 1/2/3, lineage in both directions, timeline, and invalidation run
both engines directly. `find_paths` is honestly classified as relational on
an AGE-enabled store (#2582/#2613); it is not counted as two-engine coverage.
The raw historical timestamp discrepancy is deliberately pinned as a known
divergence (#3809) pending E2; convergence must turn that pin red.

`bash scripts/check-graph-conformance.sh --self-test` runs the Rust-AST
inventory guard and its adversarial fixtures. The guard follows modules and
counts Cypher SQL literals and direct graph-table reads, including macro strings, regardless of the
function name. New read sites require a matrix cell; new writer sites require
an explicit classification. Appending a second SQL site changes the count.

Production builds retain the original query execution and contain no plan
observer or diagnostic environment toggle. Tests use task-local evidence, so
another concurrent operation cannot satisfy a cell's plan requirement.

## Which tier executes this matrix

| Runner / workflow | Database tier | New live matrix |
|---|---|---|
| Native f1 certification | PostgreSQL 18.6 / AGE 1.8.0 / pgvector 0.8.6, TLS verify-full | Executed |
| `cert-postgres-age.yml`, self-hosted Linux | Same certified versions, checked against deploy SSOT | Executed, with retained plans |
| `coverage.yml`, alternate container | PostgreSQL 16 / AGE 1.6.0 | Not selected |

The coverage workflow runs ordinary library/integration tests, then selects a
separate ignored embedding-dimension conversion test. It does not include
these two ignored conformance tests. Its existing AGE integrations therefore
do not establish that this new matrix passes on AGE 1.6.0. No such compatibility
claim is made here. The native results additionally cover the certified minor
versions, actual AGE 1.8.0 execution and TLS verify-full that the alternate
container does not certify. The GitHub cert workflow now uses a native tier;
its older container-build comments are historical, not its execution path.
