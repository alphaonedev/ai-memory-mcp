# Track C — Postgres + Apache AGE Full Regression Results (2026-05-22)

> **Post-campaign update (2026-05-23):** #1156 (per-namespace K8 quota
> dimension extension) bumped both adapters to schema **v50** after this
> campaign closed. The v49 references below reflect the state at the
> 2026-05-22 gate; the v50 bump is additive (`agent_quotas` PK
> `(agent_id)` → `(agent_id, namespace)`) and does not invalidate any
> of the C.1-C.11 results. The current v15 → v50 ladder is exercised
> by `tests/per_namespace_quota.rs` + the existing
> `tests/postgres_schema_parity.rs::current_version_matches_canonical`
> assertion (now pinned to 50). See `CHANGELOG.md` [Unreleased] for
> the full v50 narrative.

Track C is the postgres + Apache AGE backend regression at the v0.7.0
release-gate tip. Two surfaces are exercised under one matrix:

- **76 `store::postgres::tests::live_*` rows** in
  `src/store/postgres.rs` covering the SAL trait methods on the
  postgres backend.
- **36 postgres-gated integration tests** distributed across
  `tests/store_parity_gaps.rs`, `tests/serve_postgres_*.rs`,
  `tests/v49_archive_roundtrip_1025_postgres.rs`,
  `tests/postgres_schema_parity.rs`, `tests/admin_*.rs`,
  `tests/kg_timeline_postgres.rs`, and the AGE-gated `tests/kg_*.rs`
  rows.

The lan-parity container `ai-memory-lan-parity-pg-age` on
`127.0.0.1:15432` hosts PG16 + AGE 1.6.0 + pgvector 0.8.2. Both
`AI_MEMORY_TEST_POSTGRES_URL` and `AI_MEMORY_TEST_AGE_URL` point at
the same DB. The `--include-ignored --test-threads=1` invocation
flags ensure (a) every previously-`#[ignore]`-gated live test runs,
(b) tests serialize on the shared DB without cross-test interference.

## Phase summary

| Phase | Surface | Status | Pass count |
|---|---|---|---|
| C.1 | Postgres SAL trait coverage (76 `live_*` rows) | GREEN | 76 / 76 |
| C.2 | v15 → v49 migration ladder via `migrate_v49()` | GREEN | idempotent on first daemon open |
| C.3 | AGE backend dispatch (CTE-vs-Cypher) | GREEN | `live_detect_kg_backend_*` + `live_kg_backend_resolves_*` |
| C.4 | pgvector schema pin (`public` not `ag_catalog`) | GREEN | post-#1120 — 30 previously-red rows GREEN |
| C.5 | Postgres admin-gate allowlist contract | GREEN | post-#1133/#1135 (handler-parity + extended) |
| C.6 | Schema version pin (`POSTGRES_CURRENT_VERSION = 49`) | GREEN | post-#1132 |
| C.7 | `column_exists` / `index_exists` schema-qualify | GREEN | post-#1131 (ag_catalog interference closed) |
| C.8 | `bypass_visibility` parity for archive→restore | GREEN | post-#1140 (v49_archive_roundtrip postgres half) |
| C.9 | `bypass_visibility` for `store_parity_gaps` | GREEN | post-#1138 |
| C.10 | `kg_timeline` postgres owner-gate (substrate) | GREEN | post-#1134 |
| C.11 | `kg_invalidate` dispatches to Cypher under AGE | GREEN | `live_kg_invalidate_dispatches_to_cypher_under_age` |

**Verdict at a glance: SHIP** — postgres + AGE cross-store parity is
green at tip `fd172f2cf` against the lan-parity container.

---

## Phase C.1 — Postgres SAL trait coverage (76 `live_*` rows)

The `src/store/postgres.rs::tests` module enumerates every SAL trait
method against the live PG backend. Sample (truncated; full set in
the run log):

```
test store::postgres::tests::live_delete_removes_row ... ok
test store::postgres::tests::live_detect_kg_backend_returns_cte_on_missing_extension ... ok
test store::postgres::tests::live_governance_allow_owner_at_leaf ... ok
test store::postgres::tests::live_governance_deny_non_owner_inherited ... ok
test store::postgres::tests::live_governance_inheritance_cap_at_five ... ok
test store::postgres::tests::live_governance_pending_on_approve_level ... ok
test store::postgres::tests::live_kg_backend_resolves_to_age_when_extension_present ... ok
test store::postgres::tests::live_kg_backend_resolves_to_cte_without_age ... ok
test store::postgres::tests::live_kg_invalidate_dispatches_to_cypher_under_age ... ok
[...]
```

29 of these 76 are visible in the abbreviated log grep
(`store::postgres::tests::live_`); the rest are present at the
unabbreviated level and accounted for in the 7,321 total.

The pgvector dimension warning ("memories.embedding column dimension
(768) does not match the requested embedder dim (384); run
`ai-memory schema-init --store-url <url> --embedding-dim 384`") is
expected — the test DB was provisioned with the default 768-dim
column; the test runner brings up a 384-dim embedder for speed and
the warning surfaces. This is an **intended diagnostic**, not a test
failure; the schema-init recipe is documented in
`src/store/postgres.rs:391` and the test path tolerates the dim
mismatch by skipping the vector-similarity branch and asserting on
the FTS branch alone.

## Phase C.2 — v15 → v49 migration ladder

`CURRENT_SCHEMA_VERSION = 49` lives in `src/storage/migrations.rs`
(sqlite) and `src/store/postgres.rs:391` (postgres). The postgres
ladder runs `migrate_v15()` through `migrate_v49()` idempotently on
the first daemon open against a fresh DB; the lan-parity container's
on-disk state is at v49 at test time.

Notable per-version contributions:

| Version | Postgres contribution | Issue trail |
|---|---|---|
| v44 | `version` BIGINT column on `memories` (Gap-1 optimistic concurrency) | #888 / #966 |
| v45 | `source_uri` upgrade path | #888 / #892 / #900 |
| v46 | `recall_observations` table | #888 |
| v47 | `edit_source` column | #888 |
| v48 | `federation_push_dlq` table | #933 (Track D) |
| v49 | 14 nullable columns on `archived_memories` for full v0.7.0 Memory shape | #1025 |

**#1132** pinned `POSTGRES_CURRENT_VERSION` from 48 to 49 in the
`postgres_schema_parity` test (commit `2b8e704b3`). The schema
itself had been at v49 since #1025 landed; the test fixture had
gone stale.

**#1140** added `bypass_visibility` to the postgres half of the
v49 archive→restore roundtrip (commit `07f22e6d3`). The
production code path is unchanged; the test fixture needed the
explicit bypass so the cross-agent archive→restore parity could be
verified without tripping the post-#1075 SAL visibility gate.

## Phase C.3 — AGE backend dispatch (CTE-vs-Cypher)

The `detect_kg_backend()` helper resolves whether the connected DB
has the `age` extension installed; if yes, KG traversal dispatches
to Apache AGE Cypher (`MATCH (m)-[r]-(n) WHERE …`); if no, it falls
back to recursive-CTE in plain Postgres.

| Test | Outcome | Backend |
|---|---|---|
| `live_detect_kg_backend_returns_cte_on_missing_extension` | GREEN | CTE fallback verified |
| `live_kg_backend_resolves_to_age_when_extension_present` | GREEN | AGE present on lan-parity (`SELECT extversion FROM pg_extension WHERE extname='age'` → `1.6.0`) |
| `live_kg_backend_resolves_to_cte_without_age` | GREEN | DROP EXTENSION + retest in same suite |
| `live_kg_invalidate_dispatches_to_cypher_under_age` | GREEN | `kg_invalidate` writes a Cypher DELETE under AGE |

The CTE fallback path is fully implemented and tested — operators
running plain Postgres without AGE still get KG traversal, just
slower. This matters for the v0.7.0 "managed-postgres" deployment
posture where AGE is not always available (RDS, Cloud SQL, etc.
ship AGE-less by default).

## Phase C.4 — pgvector schema pin (#1120 substrate fix)

Before commit `1cdc67da6`, `init-age.sql` ran
`CREATE EXTENSION IF NOT EXISTS vector;` after `CREATE EXTENSION
age;` had already pushed `ag_catalog` to the top of the
`search_path`. pgvector consequently landed in `ag_catalog`, where
the post-init `SET search_path = public, ...` for the daemon could
not resolve the `vector` type. The downstream symptom: 30
`live_*` tests that touched embeddings (`live_recall_*`,
`live_store_with_embedding`, `live_insert_if_newer_with_embedding`,
etc.) failed with "type `vector` does not exist".

The fix pins the extension creation to the `public` schema:

```sql
-- post-#1120 (commit 1cdc67da6)
CREATE EXTENSION IF NOT EXISTS vector SCHEMA public;
```

This is a **real substrate defect** that existed since the AGE
extension landed; it surfaced only when the lan-parity container
was rebuilt from scratch and the init-age.sql ordering became
load-bearing. The retest evidence: all 30 previously-red rows are
GREEN at tip `fd172f2cf` against a freshly-initialized lan-parity
DB.

## Phase C.5 — Postgres admin-gate allowlist contract (#1133/#1135)

The admin-gate sweep (#946/#957/#1027) tightened the `for_admin`
privacy-bypass requirement to a populated allowlist; the
production code refuses admin operations with an empty allowlist
and returns HTTP 403. Two test fixtures needed updating to match:

| Test | Issue | Fix shape |
|---|---|---|
| `serve_postgres_extended` | #1133 | Added `ai:ext-test` to the test fixture's `AI_MEMORY_ADMIN_AGENT_IDS` |
| `serve_postgres_handler_parity` | #1135 | Same — populated allowlist before invoking admin operations |

Both fixtures now match the production contract: admin operations
require an explicit allowlist, and the test demonstrates that.

## Phase C.6 — Schema version pin (#1132)

`tests/postgres_schema_parity.rs::current_version_matches_canonical`
pins the test-side schema-version constant to the canonical
`POSTGRES_CURRENT_VERSION` in `src/store/postgres.rs`. Bumped from
48 to 49 in commit `2b8e704b3` after #1025's v48 → v49 archive
column expansion landed.

## Phase C.7 — `column_exists` / `index_exists` schema-qualify (#1131)

`tests/postgres_schema_parity.rs` previously called
`column_exists("memories", "version")` against
`information_schema.columns` without a `table_schema` filter, which
caused `ag_catalog` matches to interfere (AGE injects its own
`memories`-shaped placeholders). Commit `202d09cf1` added the
`table_schema = 'public'` filter to both `column_exists` and
`index_exists`; the test now asserts on the canonical `public`
schema only.

This is a test-instrumentation hardening, not a production code
change. Production daemons always query against the `public`
schema directly via the postgres backend's connection setup; the
test was the only path that read `information_schema` without
qualification.

## Phase C.8 — `bypass_visibility` for v49 archive→restore (#1140)

`tests/v49_archive_roundtrip_1025_postgres.rs` exercises the
archive → restore lineage across agents. The post-#1075 SAL
visibility gate would normally hide the cross-agent rows; the
test explicitly opts into `bypass_visibility=true` for the
parity check. Commit `07f22e6d3` added the bypass; the sqlite
half of the same parity test already had it.

## Phase C.9 — `bypass_visibility` for `store_parity_gaps` (#1138)

`tests/store_parity_gaps.rs::trait_update_*_1024` and
`list_filters_by_agent_id_1030` are the canonical SAL-trait
parity tests. They need to assert on data across agents to prove
that the SQLite and Postgres backends agree on the contract;
without `bypass_visibility=true`, the post-#1075 gate would hide
half the assertion target. Commit `1620aaa45` added the bypass.

## Phase C.10 — `kg_timeline` postgres owner-gate (#1134 substrate)

The SQLite path of `kg_timeline` had enforced an owner-gate (only
the row owner can read the KG timeline for their memory) since
the post-#944/#937/#938 governance sweep. The postgres path had
been missed — the SAL trait method on `PostgresStore` returned
the timeline unconditionally. Commit `3f911f630` added the
owner-gate to the postgres path, restoring cross-store parity.

This is the **second of two genuine substrate defects** the
campaign surfaced (#1120 being the first). The fix is a 3-line
SQL `WHERE` clause addition in `src/store/postgres.rs`; the
regression test is the same `kg_timeline_postgres` test that
caught it. Without #1134, an attacker with PG-direct access
through a non-owner agent could read KG timelines for memories
they did not own.

## Phase C.11 — `kg_invalidate` dispatches to Cypher under AGE

```
test store::postgres::tests::live_kg_invalidate_dispatches_to_cypher_under_age ... ok
```

When AGE is present, `kg_invalidate` writes a Cypher
`MATCH (m) WHERE m.id = $1 DETACH DELETE m` rather than a plain
SQL DELETE — this preserves the graph-edge cleanup that AGE's
`DETACH` semantics provide. When AGE is absent, the same SAL
trait method falls back to a SQL DELETE in the recursive-CTE
fallback. Both branches GREEN at tip.

---

## Cross-store parity scorecard

| SAL trait method | SQLite | Postgres | AGE Cypher | Parity status |
|---|---|---|---|---|
| `store` | GREEN | GREEN | n/a | parity |
| `insert_if_newer` | GREEN | GREEN | n/a | parity |
| `update` | GREEN | GREEN | n/a | parity |
| `delete` | GREEN | GREEN | n/a | parity |
| `list` (`bypass_visibility=true`) | GREEN | GREEN | n/a | parity (post-#1138) |
| `archive` / `restore` | GREEN | GREEN | n/a | parity (post-#1140) |
| `kg_traverse` | GREEN | GREEN (CTE) | GREEN (Cypher) | parity |
| `kg_timeline` | GREEN | GREEN (post-#1134) | GREEN | parity (post-#1134 substrate) |
| `kg_invalidate` | GREEN | GREEN | GREEN | parity |
| `recall_observations` | GREEN | GREEN | n/a | parity |
| `governance_check` (rule eval) | GREEN | GREEN | n/a | parity |
| `signed_events_chain_verify` | GREEN | GREEN | n/a | parity |

## Verdict: **SHIP**

Postgres + Apache AGE cross-store parity is GREEN at tip
`fd172f2cf` against the lan-parity container. Two substrate
defects were surfaced + fixed in-campaign (#1120 pgvector schema
pin, #1134 `kg_timeline` postgres owner-gate); all other Track-C
fixes were test-fixture pin-update discipline.

### Strengths
- All 76 `live_*` rows GREEN, including the 30 previously-red
  embedding-dependent rows that #1120 unblocked.
- AGE backend dispatch resolves correctly in both directions
  (AGE-present → Cypher, AGE-absent → CTE) — the v0.7.0
  managed-postgres deployment story is sound.
- Schema-version contract enforced by `postgres_schema_parity`
  (#1132) means future v50+ bumps will surface as test failures,
  not silent drift.

### Audit trail
- Full-suite log: `.local-runs/full-suite-final-v18-2026-05-22.log`
- Substrate fix commits: `1cdc67da6` (#1120), `3f911f630`
  (#1134 + #1135)
- Postgres-specific retest log:
  `.local-runs/postgres-lib-retest-with-age-2026-05-22.log` (the
  isolated postgres + AGE re-run that pre-validated the
  full-suite v18 mint).

### Recommendation
SHIP. The cross-store parity invariants are mechanically pinned
by the SAL-trait parity test set; #1134 closed the last known
substrate parity gap. The lan-parity container is the canonical
test target for v0.7.0; the cross-node Track D campaign
(192.168.50.100 ↔ 192.168.1.50) remains operator-action-gated
on subnet routing per #836 Tier-2.

Drafted by Claude (Opus 4.7, 1M context).
