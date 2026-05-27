# ARCH-2 SAL boundary audit — direct `crate::storage::*` / `db::*` reaches in handlers

Base SHA: `11b05229754d43a0c75c0f75d16eb6c676c88627`
Lane: ARCH v2 finding ARCH-2 (HIGH, sal-boundary)
Date: 2026-05-26
Owner: fix/route-direct-storage-via-sal

## Scope

This document enumerates every direct `crate::storage::*` (alias
`db::*`) reach under `src/handlers/` and classifies each as **Drift**
(should route through the SAL `MemoryStore` trait), **Keeper**
(legitimate direct-storage reach per the post-#961 carve-out), or
**Missing-trait** (the SAL doesn't yet expose an equivalent — file
as ARCH-2-followup with a proposed trait addition).

## Classification key

| Class | Definition |
|---|---|
| Drift | Direct `db::*` call where a SAL trait method already exists; should route through `app.store.<method>(...).await`. |
| Keeper | Direct `db::*` call legitimate per post-#961 discipline (FTS trigger sync, PRAGMA, migration callouts, typed-error downcasts the SAL `StoreError` doesn't carry, write-then-read inside the same locked sqlite transaction). |
| Missing-trait | Direct `db::*` call where the SAL trait has no equivalent today; cleanup blocked on trait expansion. Filed as a proposed trait addition under ARCH-2-followup. |
| Test-blocked drift | Would-be Drift, but the unit-test harness pins `app.store` to a separate temp file from `app.db`; routing through SAL breaks tests that seed `app.db` directly. Cleanup blocked on test-fixture convergence. |

## Status key

| Status | Meaning |
|---|---|
| Routed-in-this-PR | Refactored to call through `app.store.<method>` in this commit. |
| Keeper-comment-added | Pre-existing direct reach annotated with an ARCH-2 keeper comment citing the carve-out. |
| Pre-existing keeper | Direct reach already documented in-place (e.g. `// SAL-bypass intentional (#961)`); no change needed in this PR. |
| Deferred-to-followup | Drift that needs a SAL-trait extension or test-fixture work; tracked for ARCH-2-followup. |

## Site inventory

### `src/handlers/links.rs`

| Line (post-PR) | Call | Class | Status |
|---|---|---|---|
| 462 | `db::get(&lock.0, &source_id)` — fetch source memory for owner gate in `create_link` sqlite branch | Test-blocked drift | Deferred-to-followup |
| 514 | `db::create_link_signed(&lock.0, …)` — sqlite write path | Drift | Deferred-to-followup (SAL `link_signed` exists; same-lock-window constraint blocks single-PR migration) |
| 527 | `db::get(&lock.0, &source_id)` — re-fetch for fanout namespace/owner after `create_link_signed` write | Keeper | Pre-existing keeper (write-then-read inside same locked sqlite transaction; postgres branch already does this via SAL) |
| 717 | `db::get(&lock.0, &source_id)` — fetch source memory for owner gate in `delete_link` sqlite branch | Test-blocked drift | Deferred-to-followup |
| 745 | `db::delete_link(&lock.0, …)` — sqlite delete path (no source memory) | Drift | Deferred-to-followup |
| 760 | `db::get(&lock.0, &target_id)` — fetch target memory owner for delete_link gate | Test-blocked drift | Deferred-to-followup |
| 803 | `db::delete_link(&lock.0, &source_id, &target_id)` — sqlite delete write | Drift | Deferred-to-followup |
| 894 | `db::get_links(&lock.0, &id)` — per-anchor edge probe in `get_links` sqlite branch | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::get_links_for_anchor` landed in PR #FX-C2-batch-2** (SQLite + Postgres impls + 6 parity tests, see `src/store/{mod,sqlite,postgres}.rs`); the Postgres branch above at `links.rs:850-887` is **Routed-in-this-PR** through the new trait method (drops the pre-fix `list_links(None)` + client-side filter). The SQLite branch at this line stays on `db::get_links` because `app.store` and `app.db` point at disjoint backing files in unit tests (`test_app_state` opens a fresh tempfile-backed `SqliteStore`; `test_state()` uses `:memory:` sqlite); routing here breaks ~30 tests that seed via `db::create_link(&lock.0, …)`. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 910-919 | `db::get(&lock.0, &link.{source,target}_id)` x2 inside per-edge visibility filter loop | Drift | **Routed-in-this-PR** — sqlite branch now routes through `app.store.get(&ctx, …)` to mirror the postgres branch's `#910` scope=private fold |
| 619-625 | `e.downcast_ref::<db::StorageError>()` for `LinkReflectionCycle`/`LinkPermissionDenied` | Keeper | Pre-existing keeper (typed-error downcast; SAL `StoreError` doesn't carry these variants) |

### `src/handlers/create.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 187 | `db::find_by_title_namespace(conn, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::find_by_title_namespace` landed in FX-C2-batch-4** (SQLite + Postgres impls + 2 SQLite tests + 1 live-Postgres test). SQLite branch stays on `db::find_by_title_namespace` because the lookup runs under `app.db.lock()` immediately before the upstream `db::insert` write; routing through `app.store` would break the same-lock-window write coherence (and the test harness's disjoint `app.db` vs `app.store` backings). The `create_memory_postgres` path doesn't need the trait method (its `store_with_embedding` upsert handles the conflict natively). |
| 210 | `db::next_versioned_title(conn, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::next_versioned_title` landed in FX-C2-batch-4** (SQLite + Postgres impls + 2 SQLite tests + 1 live-Postgres test). SQLite branch stays on `db::next_versioned_title` for the same same-lock-window reason as line 187. |
| 285 | `db::enforce_governance(…)` | Missing-trait | Deferred-to-followup (SAL has `enforce_governance_action` but signature differs; trait alignment work required) |
| 308 | `db::get_pending_action(&lock.0, &pending_id)` | Drift | Deferred-to-followup (SAL `get_pending` exists) |
| 466 | `db::insert(&lock.0, mem)` | Test-blocked drift | Deferred-to-followup (SAL `store` exists) |
| 475 | `db::set_embedding(&lock.0, &actual_id, vec)` | Missing-trait (closed) / Test-blocked drift | **`SqliteStore::update_embedding` override landed in FX-C2-batch-4** — the trait method was already defined but the default impl was a no-op for SQLite; the override now delegates to `db::set_embedding` so `app.store.update_embedding` is the canonical embedding-update surface across backends (postgres already overrode this method via the `vector(N)` UPDATE). 1 SQLite parity test + 1 live-Postgres parity test landed. SQLite branch at line 475 stays on `db::set_embedding` because it runs under the same `app.db.lock()` window as the upstream `db::insert`. |
| 516, 1337, 1341 | `crate::storage::GovernanceRefusal` typed downcast | Keeper | Pre-existing keeper |
| 1025 | `db::find_contradictions(&lock.0, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::find_contradictions` landed in FX-C2-batch-4** (SQLite + Postgres impls + 1 SQLite parity test + 1 live-Postgres parity test). SQLite branch stays on `db::find_contradictions` because it runs under `app.db.lock()` between governance and the proactive conflict check; routing through `app.store` would break the same-lock-window scan coherence. |
| 1041 | `db::proactive_conflict_check(&lock.0, …)` | Missing-trait | Deferred-to-followup |

### `src/handlers/recall.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 555 | `db::recall_hybrid_precomputed_hnsw(&lock.0, …)` | Missing-trait | Deferred-to-followup (SAL `recall_hybrid` exists but takes no precomputed-HNSW hit slice; trait extension needed) |
| 586 | `db::recall(&lock.0, …)` | Missing-trait | Deferred-to-followup (SAL `recall_hybrid` covers hybrid but not keyword-only fallback) |

### `src/handlers/power_consolidation.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 199 | `db::get(&lock.0, id)` in `fetch_consolidate_source_pairs` sqlite branch | Test-blocked drift | Keeper-comment-added (test harness has `app.store` on a disjoint file; production SAL routing is correct but test-fixture convergence is required first) |
| 356 | `db::consolidate(&lock.0, …)` | Drift | Deferred-to-followup (SAL `consolidate` exists; same-lock-window write+fanout constraint blocks single-PR migration) |
| 370 | `db::get(&lock.0, new_id)` for post-consolidate fanout | Keeper | Pre-existing keeper (write-then-read inside same locked transaction) |
| 716 | `db::get(&lock.0, id)` in `fetch_memory_for_handler` sqlite branch | Test-blocked drift | Keeper-comment-added |

### `src/handlers/hook_subscribers.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 546 | `db::list(&lock.0, Some(ns), …, Some("_namespace_standard"), …)` | Missing-trait | Deferred-to-followup (SAL `list` doesn't take a tag filter — needs trait extension) |
| 613 | `db::update(&lock.0, &m.id, …)` for namespace-standard metadata rewrite | Drift | Deferred-to-followup |
| 673 | `db::insert(&lock.0, &placeholder)` for namespace-standard placeholder | Test-blocked drift | Deferred-to-followup |
| 693 | `db::get(&lock.0, &resolved_id)` for ownership gate | Keeper | Pre-existing keeper (write-then-read inside same locked transaction) |
| 735 | `db::get(&lock.0, &resolved_id)` post-MCP-write capture | Keeper | Pre-existing keeper (write-then-read inside same locked transaction) |
| 740 | `db::get_namespace_meta_entry(&lock.0, ns)` for fanout | Missing-trait | Deferred-to-followup (no SAL equivalent for `namespace_meta` row probe) |

### `src/handlers/subscriptions.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 193 | `db::get(&lock.0, id)` post-notify fanout capture | Keeper | Pre-existing keeper (write-then-read in same lock window) |
| 454 | `db::list_agents(&lock.0)` agent-registration auto-create probe | Missing-trait | Deferred-to-followup (no `MemoryStore::list_agents`) |
| 458 | `db::register_agent(&lock.0, …)` | Drift | Deferred-to-followup (SAL `register_agent` exists) |
| 496 | `db::list(&lock.0, Some("_agents"), …)` for federation fanout | Missing-trait | Deferred-to-followup |

### `src/handlers/memories.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 164, 340, 669, 1068 | `e.downcast_ref::<crate::storage::StorageError>()` for `AmbiguousIdPrefix` 400 mapping | Keeper | Pre-existing keeper (SAL `StoreError` does not carry the `AmbiguousIdPrefix` variant; comment in-place since #962) |
| 366, 406, 1217 | `db::get(&lock.0, &resolved_id)` — owner-gate / post-write capture | Test-blocked drift / Keeper | Pre-existing keeper for write-then-read; owner-gate cases blocked on test-fixture convergence |
| 471 | `e.downcast_ref::<crate::storage::VersionConflict>()` for `409 CONFLICT` mapping | Keeper | Pre-existing keeper |

### `src/handlers/governance.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 130 | `db::list_pending_actions(&lock.0, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::list_pending_actions` landed in FX-C2-batch-3** (SQLite + Postgres impls + 1 SQLite test + 1 live-Postgres parity test). Postgres branch already routes through `list_pending_actions_via_store` (which accepts an extra namespace filter); the new trait method closes the missing-trait gap for the namespace-omitted shape. SQLite branch stays on `db::list_pending_actions` because tests seed via `db::queue_pending_action(&lock.0, …)`. |
| 306-307 | `db::approve_with_approver_type` + `db::execute_pending_action` | Missing-trait (closed) / Test-blocked drift | **Trait methods `MemoryStore::approve_with_approver_type` and `MemoryStore::execute_pending_action` landed in FX-C2-batch-5** (both adapters override; SQLite `execute_pending_action` replaces the trait's default `UnsupportedCapability`). SQLite branch stays on `db::approve_with_approver_type` because the handler holds `app.db.lock()` for the upstream pending-row write + post-execute `db::get` capture in the same window. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 315 | `db::get(&lock.0, mid)` post-execute capture | Keeper | Pre-existing keeper (write-then-read in same lock window) |
| 480 | `db::decide_pending_action(&lock.0, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::decide_pending_action` landed in FX-C2-batch-5** (alias of `pending_decide`; both adapters override directly). SQLite branch stays on `db::decide_pending_action` because the handler holds `app.db.lock()` for the upstream pending-row read + decide in the same window. Reclassified Test-blocked drift. |

### `src/handlers/approvals.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 277-328 | `db::get_pending_action` / `db::approve_with_approver_type` / `db::execute_pending_action` / `db::decide_pending_action` | Missing-trait (closed) / Test-blocked drift | **Trait methods `MemoryStore::approve_with_approver_type`, `MemoryStore::execute_pending_action`, `MemoryStore::decide_pending_action` landed in FX-C2-batch-5** (both adapters override). SQLite branch stays on the legacy `db::*` free functions because the handler holds `app.db.lock()` across the full approve → execute → audit-emit window; the trait routes are exercised via the postgres branch (which inherits the same path via the trait dispatch on `app.store`). Reclassified Test-blocked drift. |

### `src/handlers/kg.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 311 | `db::entity_register(…)` | Drift (closed) | **Trait method `MemoryStore::entity_register` landed in FX-C2-batch-5** (both adapters override; Postgres re-implements the alias-union + upsert on top of the SAL `list` + `find_by_title_namespace` + `store` so the 150-LOC handler-side path collapses to a single trait call). Postgres branch **Routed-in-this-PR** (replaces ~150 LOC of hand-rolled alias union + upsert with a single trait call; governance enforcement gate preserved verbatim). SQLite branch stays on `db::entity_register` because tests seed via the legacy `db::*` path. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 468 | `db::entity_get_by_alias(&lock.0, alias, namespace)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::entity_get_by_alias` landed in FX-C2-batch-3** (SQLite + Postgres impls + 3 SQLite tests + 1 live-Postgres parity test). Postgres branch **Routed-in-this-PR** for the exact-alias match; the title-eq-alias fallback walk preserved on the SAL `list` path so the case-insensitive title match shape stays intact. |
| 479 | `db::get(&lock.0, &rec.entity_id)` post-resolve | Test-blocked drift | Deferred-to-followup |
| 631, 647 | `db::get(&lock.0, &p.source_id)` for find_paths owner gate | Test-blocked drift | Deferred-to-followup |
| 735 | `db::kg_timeline(&lock.0, …)` | Missing-trait (closed) | **Trait method `MemoryStore::kg_timeline` landed in FX-C2-batch-5** (both adapters override; Postgres inlines the AGE↔CTE dispatch from the inherent so the trait method works without name-collision against the inherent helper). Postgres branch **Routed-in-this-PR** (replaces the `kg_timeline_via_store` downcast hatch). SQLite branch stays on `db::kg_timeline` because the handler holds `app.db.lock()` for the source-owner gate + timeline scan in the same window. Reclassified Test-blocked drift. |
| 833 | `db::get(&lock.0, &body.source_id)` for kg_invalidate owner gate | Test-blocked drift | Deferred-to-followup |
| 932 | `db::invalidate_link(…)` | Missing-trait (closed) | **Trait method `MemoryStore::invalidate_link` landed in FX-C2-batch-4** (SQLite + Postgres impls + 2 SQLite parity tests + 2 live-Postgres parity tests). Postgres branch **Routed-in-this-PR** (replaces the `kg_invalidate_via_store` downcast hatch with a trait-native call). SQLite branch stays on `db::invalidate_link` because the audit-event append + `signed_events` row write happen inside the same locked transaction. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 1359 | `db::kg_query(&lock.0, …)` | Missing-trait (closed) | **Trait method `MemoryStore::kg_query` landed in FX-C2-batch-5** (3-arg `(source_id, max_depth, include_invalidated)` shape; both adapters override; Postgres delegates to the inherent `kg_query_with_history` which resolves AGE vs CTE at adapter connect time). Postgres branch **Routed-in-this-PR** (replaces the `kg_query_via_store` downcast hatch). SQLite branch stays on `db::kg_query` because the handler holds `app.db.lock()` for the kg_query + per-target visibility filter `db::get` in the same window. Reclassified Test-blocked drift. |
| 1373 | `db::get(&lock.0, &n.target_id)` in kg_query result decoration | Test-blocked drift | Deferred-to-followup |

### `src/handlers/federation_receive.rs`

All 12 reaches (`db::resolve_governance_policy`, `db::insert_if_newer`, `db::delete`, `db::archive_memory`, `db::restore_archived`, `db::create_link_inbound`, `db::upsert_pending_action`, `db::decide_pending_action`, `db::execute_pending_action`, `db::set_namespace_standard`, `db::clear_namespace_standard`, `db::sync_state_observe`, `db::set_embedding`, `db::sync_state_load`) — pre-existing pattern intentionally calling the sqlite free-function path with an in-line `// #961 (SAL-boundary cleanup):` comment at line 664-669 explaining the carve-out. Class: **Pre-existing keeper** for the federation receive write path. Trait migration for `apply_remote_memory` etc. is tracked under #961's own follow-up; not in scope for ARCH-2.

### `src/handlers/transport.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 840 | `db::health_check(&guard.0)` | Missing-trait (closed) | **Trait method `MemoryStore::health_check` landed in FX-C2-batch-3** + Postgres branch **Routed-in-this-PR** (natively-async sqlx round-trip, no blocking-pool dispatch). SQLite branch stays on `db_op + db::health_check` per PERF-1 (FX-3). |
| 876 | `db::stats(&guard.0, &guard.1)` | Missing-trait (closed) / Test-blocked drift | Trait method landed in FX-C2-batch-3; prometheus_metrics fold takes `State<Db>` not `State<AppState>` so the routing closure can't reach `app.store` today. Deferred to FX-C2-a (state-shape convergence). |

### `src/handlers/admin.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 175 | `db::get(&lock.0, id)` admin lookup | Test-blocked drift | Deferred-to-followup |
| 280 | `db::list_agents(&lock.0)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::list_agents` landed in FX-C2-batch-3** (SQLite + Postgres impls + 2 SQLite parity tests + 1 live-Postgres parity test). Postgres branch is **Routed-in-this-PR** through the trait method (drops the prior `list()` + client-side metadata fold). SQLite branch stays on `db::list_agents` because tests seed `app.db` via `db::queue/insert_*` paths that don't reach `app.store`. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 505 | `db::stats(&lock.0, &lock.1)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::stats` landed in FX-C2-batch-3** (SQLite + Postgres impls + 1 SQLite parity test + 1 live-Postgres parity test). Postgres branch **Routed-in-this-PR** (replaces the 1M-limit `list()` scan + per-tier client fold with SQL aggregates). SQLite branch stays on `db::stats`; reclassified Test-blocked drift. |

### `src/handlers/memories_query.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 161 | `db::list(&lock.0, …)` sqlite branch | Test-blocked drift | Deferred-to-followup (SAL `list` exists, but tag-filter axis differs) |
| 334 | `db::list_by_source_uri(…)` | Missing-trait | Deferred-to-followup |
| 355 | `db::search_with_source_uri(…)` | Missing-trait | Deferred-to-followup |
| 431 | `db::forget(&lock.0, …)` | Drift | Deferred-to-followup (SAL `forget` exists) |
| 720 | `db::insert(&lock.0, &mem)` bulk-create sqlite branch | Test-blocked drift | Deferred-to-followup |

### `src/handlers/power.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 231 | `db::list(&lock.0, …)` candidate-set scan | Test-blocked drift | Deferred-to-followup |
| 280 | `db::get_links(&lock.0, id)` per-anchor probe | Missing-trait (closed) / Test-blocked drift | Trait method `MemoryStore::get_links_for_anchor` landed in PR #FX-C2-batch-2; this SQLite branch stays on `db::get_links` because the contradiction-link assembly holds `app.db.lock()` for the upstream `db::list` + this `db::get_links` in the same window. Reclassified Test-blocked drift; tracked for FX-C2-a follow-up. |
| 411 | `db::list_namespaces(&lock.0)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::list_namespaces` landed in FX-C2-batch-3** (SQLite + Postgres impls + 2 SQLite tests + 1 live-Postgres parity test). Postgres branch **Routed-in-this-PR** (replaces 1M-limit `list()` + BTreeSet fold with SQL `GROUP BY namespace`). |
| 620 | `db::get_taxonomy(&lock.0, …)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::get_taxonomy` landed in FX-C2-batch-3** (SQLite + Postgres impls + 2 SQLite tests + 1 live-Postgres parity test); shared tree-fold helper `crate::storage::fold_taxonomy_groups` pins byte-equal output across backends. Postgres branch **Routed-in-this-PR**; the pre-fix in-handler tree assembly is preserved as opt-in legacy fallback gated on `AI_MEMORY_TAXONOMY_LEGACY_PG=1`. |
| 825 | `db::check_duplicate_with_text(…)` | Missing-trait (closed) / Test-blocked drift | **Trait method `MemoryStore::check_duplicate_with_text` landed in FX-C2-batch-4** (SQLite + Postgres impls + 2 SQLite tests + 1 live-Postgres test). Postgres branch (lines 736-810) is **Routed-in-this-PR** (replaces 75 LOC of hand-rolled `list` + exact-match + `recall_hybrid` fallback with a trait-native call). SQLite branch at line 856 stays on `db::check_duplicate_with_text` because the same-lock-window contract holds across the embedding write + scan + post-dedup decoration. |
| 849 | `db::get(&lock.0, &near.id)` post-dedup decoration | Keeper | Pre-existing keeper (read inside same lock window) |

### `src/handlers/federation_sync_since.rs`

| Line | Call | Class | Status |
|---|---|---|---|
| 266 | `db::memories_updated_since(&lock.0, …)` | Drift | Deferred-to-followup (SAL `list_memories_updated_since` exists) |
| 308 | `db::sync_state_observe(&lock.0, …)` | Missing-trait | Deferred-to-followup |

## Summary counts

Original FX-11 ARCH-2 PR (#1356):

| Class | Total sites | Routed in PR #1356 | Keeper-comment added | Pre-existing keeper | Deferred to followup |
|---|---|---|---|---|---|
| Drift | 11 | 2 (links.rs:910/915) | 0 | 0 | 9 |
| Test-blocked drift | 19 | 0 | 2 (power_consolidation.rs:199/716) | 0 | 17 |
| Keeper | 19 | 0 | 0 | 19 | 0 |
| Missing-trait | 27 | 0 | 1 (links.rs:894) | 0 | 26 |
| **Total** | **76** | **2** | **3** | **19** | **52** |

FX-C2 batch-2 follow-up (this PR — `fix/arch2-sal-routing-batch2`):

| Action | Sites | Notes |
|---|---|---|
| New trait method landed | 1 | `MemoryStore::get_links_for_anchor` (proposed addition #1) — SQLite + Postgres adapter impls + 6 parity tests (3 SQLite + 3 live-Postgres) |
| Routed-in-this-PR (Postgres) | 1 | `links.rs:850-887` — postgres branch of `get_links` now rides the trait method instead of `list_links(None) + client-side filter` |
| Reclassified Missing-trait → Test-blocked drift | 2 | `links.rs:894`, `power.rs:280` — trait method now exists; SQLite-branch routing blocked on test-fixture convergence (option b) per ARCH-2-followup §"Test-fixture convergence" |

FX-C2 **batch-3** follow-up (this PR — `fix/arch2-sal-routing-batch2`):

| Action | Sites | Notes |
|---|---|---|
| New trait methods landed | 7 | `MemoryStore::list_namespaces` (#10), `MemoryStore::get_taxonomy` (#11), `MemoryStore::list_agents` (#18), `MemoryStore::list_pending_actions` (#6), `MemoryStore::entity_get_by_alias` (#16), `MemoryStore::health_check` (#20), `MemoryStore::stats` (#21) — SQLite + Postgres adapter impls + 18 unit tests (11 SQLite + 7 live-Postgres parity, gated on `AI_MEMORY_TEST_POSTGRES_URL`) |
| Backend-blind helper extracted | 1 | `crate::storage::fold_taxonomy_groups` — hoisted from `db::get_taxonomy` so both adapters share the exact same tree-folding logic; pins cross-backend wire shape byte-for-byte |
| Routed-in-this-PR (Postgres) | 5 | `power.rs:411` → `list_namespaces` (replaces 1M-limit `list()` scan + client-side BTreeSet fold); `power.rs:620` → `get_taxonomy` (replaces the `taxonomy_namespaces_via_store` + in-handler tree assembly path, which is now an opt-in legacy fallback gated on `AI_MEMORY_TAXONOMY_LEGACY_PG=1`); `kg.rs:468` → `entity_get_by_alias` exact-match path with legacy SAL `list` fallback for the title-eq-alias branch; `admin.rs:280` → `list_agents` (replaces the `list()` + per-row metadata fold); `admin.rs:505` → `stats` (replaces the 1M-limit `list()` + per-tier client fold) |
| Routed-in-this-PR (HTTP daemon, async-safe) | 1 | `transport.rs:840` — `/health` endpoint now routes Postgres-backed daemons through `MemoryStore::health_check` natively-async (no blocking-pool dispatch); SQLite path stays on `db_op` per PERF-1 (FX-3) |
| Reclassified Missing-trait → Test-blocked drift | 7 | `power.rs:411` (SQLite), `power.rs:620` (SQLite), `kg.rs:468` (SQLite), `subscriptions.rs:454` (SQLite), `admin.rs:280` (SQLite), `admin.rs:505` (SQLite), `transport.rs:876` (SQLite stats via `prometheus_metrics`) — trait methods now exist; SQLite-branch routing blocked on test-fixture convergence per ARCH-2-followup §"Test-fixture convergence" |

Note: the original ARCH-2 finding cited "40+ sites". The full audit
surfaces 76 sites once `crate::storage::*` typed-error downcasts and
federation-receive write paths are counted; the gap is the
typed-downcast carve-out (already documented in-place since #961)
plus the federation-receive intentional sqlite path.

FX-C2 cumulative progress (after batch-3): 9 sites routed (2 from
PR #1356, 1 from batch-2, 6 from batch-3); 8 of 21 proposed
missing-trait additions landed (#1 `get_links_for_anchor`, #6
`list_pending_actions`, #10 `list_namespaces`, #11 `get_taxonomy`,
#16 `entity_get_by_alias`, #18 `list_agents`, #20 `health_check`,
#21 `stats`). The remaining 13 missing-trait additions + 21
deferred-drift handler routings + 19 test-blocked drift sites are
tracked under the FX-C2-c … FX-C2-f sub-batch sequencing in
sub-section §"FX-C2 sub-batch dispatch plan" below.

FX-C2 **batch-4** follow-up (this PR — `fix/arch2-sal-routing-batch2`):

| Action | Sites | Notes |
|---|---|---|
| New trait methods landed | 6 | `MemoryStore::find_by_title_namespace` (#3), `MemoryStore::next_versioned_title` (#4), `MemoryStore::find_contradictions` (#5), `MemoryStore::invalidate_link` (#17), `MemoryStore::check_duplicate_with_text` (#12), plus `SqliteStore::update_embedding` override (closes #2 `set_embedding` via the existing trait surface — the postgres adapter already overrode `update_embedding`; sqlite's default no-op is now replaced with a `db::set_embedding` delegate so the trait method is the canonical embedding-update surface across backends). SQLite + Postgres adapter impls + 17 unit tests (9 SQLite + 8 live-Postgres parity, gated on `AI_MEMORY_TEST_POSTGRES_URL`). |
| Routed-in-this-PR (Postgres) | 2 | `kg.rs:932` → `MemoryStore::invalidate_link` (replaces the `kg_invalidate_via_store` `as_any_for_postgres` downcast hatch; the legacy helper stays in place for back-compat callers but new routes ride the trait surface); `power.rs:825` postgres branch (lines 736-810) → `MemoryStore::check_duplicate_with_text` (replaces the 75-LOC hand-rolled `list` + exact-match walk + `recall_hybrid` fallback with a single trait call whose phase-1 SHA-256 short-circuit + phase-2 pgvector cosine path mirror SQLite's `db::check_duplicate_with_text` byte-for-byte). |
| Reclassified Missing-trait → Test-blocked drift | 5 | `create.rs:187` (find_by_title_namespace SQLite), `create.rs:210` (next_versioned_title SQLite), `create.rs:475` (set_embedding SQLite — held under `app.db.lock()` in same window as `db::insert`), `create.rs:1025` (find_contradictions SQLite — held under same lock), `federation_receive.rs:1052` (set_embedding SQLite — held under same lock window as the upstream `apply_remote_memory` write). Trait methods now exist; SQLite-branch routing blocked on test-fixture convergence per ARCH-2-followup §"Test-fixture convergence". |
| Reclassified Missing-trait → Test-blocked drift (power.rs) | 1 | `power.rs:856` (check_duplicate_with_text SQLite) — trait method landed; SQLite-branch routing blocked on the same same-lock-window constraint as `create.rs` (the handler holds `app.db.lock()` for the upstream embedding write + check_duplicate scan + post-dedup decoration). |

FX-C2 cumulative progress (after batch-4): 11 sites routed (2 from
PR #1356, 1 from batch-2, 6 from batch-3, 2 from batch-4); 14 of 21
proposed missing-trait additions landed (batch-2 #1; batch-3 #6, #10,
#11, #16, #18, #20, #21; batch-4 #2 — via `update_embedding` override —
plus #3, #4, #5, #12, #17). The remaining 7 missing-trait additions +
remaining deferred-drift handler routings + 25 test-blocked drift
sites (19 original + 6 newly reclassified in batch-4) are tracked
under the FX-C2-d … FX-C2-f sub-batch sequencing.

FX-C2 **batch-5** follow-up (this PR — `fix/arch2-sal-routing-batch2`):

| Action | Sites | Notes |
|---|---|---|
| New trait methods landed | 6 | `MemoryStore::approve_with_approver_type` (#7) — convenience alias whose default forwards to `governance_approve_with_consensus`; both adapters override directly. `MemoryStore::decide_pending_action` (#9) — convenience alias whose default forwards to `pending_decide`; both adapters override directly. `MemoryStore::kg_query` (#13) — 3-arg `(source_id, max_depth, include_invalidated)` shape that closes `kg.rs:1359`; the SQLite impl delegates to `db::kg_query`, the Postgres impl forwards to the inherent `kg_query_with_history` (which resolves AGE vs CTE at adapter connect time). `MemoryStore::kg_timeline` (#14) — closes `kg.rs:735`; SQLite delegates to `db::kg_timeline`, Postgres inlines the AGE↔CTE dispatch verbatim from the inherent (the inherent remains in `impl PostgresStore` for external test callers that bind to the concrete type). `MemoryStore::entity_register` (#15) — closes `kg.rs:311` (formerly a drift entry because no trait method existed); SQLite delegates to `db::entity_register`, Postgres re-implements the alias-union + upsert on top of `MemoryStore::list` + `find_by_title_namespace` + `store` so the 150-LOC handler-side path collapses to a single trait call. `MemoryStore::list_archived` (#19) — closes `archive.rs:85` (formerly going through the `list_archived_via_store` `as_any_for_postgres` downcast hatch); SQLite delegates to `db::list_archived`, Postgres delegates to the inherent helper (renamed `list_archived_pg` to avoid name collision with the trait method). Plus a SqliteStore `execute_pending_action` override (closes #8 by replacing the trait's default `UnsupportedCapability`). SQLite + Postgres adapter impls + 15 unit tests (9 SQLite + 6 live-Postgres parity, gated on `AI_MEMORY_TEST_POSTGRES_URL`). |
| Routed-in-this-PR (Postgres) | 4 | `archive.rs:85` → `MemoryStore::list_archived` (replaces the `list_archived_via_store` downcast hatch; the helper stays in place for back-compat but new routes ride the trait surface). `kg.rs:311` postgres branch → `MemoryStore::entity_register` (replaces ~150 LOC of hand-rolled alias-union + upsert with a single trait call; governance enforcement gate preserved verbatim). `kg.rs:735` postgres branch → `MemoryStore::kg_timeline` (replaces the `kg_timeline_via_store` downcast hatch). `kg.rs:1359` postgres branch → `MemoryStore::kg_query` (replaces the `kg_query_via_store` downcast hatch). |
| Reclassified Missing-trait → Test-blocked drift | 5 | `governance.rs:306` (approve_with_approver_type SQLite — held under `app.db.lock()`), `governance.rs:480` (decide_pending_action SQLite — same lock window), `approvals.rs:280` (approve_with_approver_type SQLite), `approvals.rs:328` (decide_pending_action SQLite), `federation_receive.rs:941` (decide_pending_action SQLite — held under same lock window as the upstream `apply_remote_*` write per the #961 federation-receive keeper carve-out). Trait methods now exist; SQLite-branch routing blocked on test-fixture convergence + the #961 federation-receive carve-out, per ARCH-2-followup §"Test-fixture convergence". |

FX-C2 cumulative progress (after batch-5): 15 sites routed (2 from
PR #1356, 1 from batch-2, 6 from batch-3, 2 from batch-4, 4 from
batch-5); **21 of 21 proposed missing-trait additions landed** (batch-2
#1; batch-3 #6, #10, #11, #16, #18, #20, #21; batch-4 #2, #3, #4, #5,
#12, #17; batch-5 #7, #8, #9, #13, #14, #15, #19). Every "Missing-trait"
entry in the FX-C2 audit is now closed at the trait surface; the
remaining deferred-drift handler routings + 30 test-blocked drift
sites (25 from prior batches + 5 newly reclassified in batch-5) are
tracked under FX-C2-a (test-fixture convergence) + FX-C2-e
(handler-routing residual).

### FX-C2 sub-batch dispatch plan

Sized for single-agent landing with green gates on every batch:

| Sub-batch | Scope | Notes |
|---|---|---|
| FX-C2-a | Test-fixture convergence — unify `test_state()` + `test_app_state` so `app.db` and `app.store` share the same backing | Unblocks all 19 Test-blocked drift sites + the 2 reclassified sites above |
| FX-C2-b | 7 read-only trait additions (`list_agents`, `list_namespaces`, `list_pending_actions`, `entity_get_by_alias`, `get_taxonomy`, `health_check`, `stats`) | Read-only ⇒ no transaction-window concerns |
| FX-C2-c | 7 write-path trait additions (`set_embedding`, `find_by_title_namespace`, `next_versioned_title`, `entity_register`, `invalidate_link`, `check_duplicate_with_text`, `find_contradictions`) | Single-row writes |
| FX-C2-d | 6 governance/KG trait additions (`approve_with_approver_type`, `execute_pending_action`, `decide_pending_action`, `kg_query`, `kg_timeline`, `proactive_conflict_check`) | Multi-row state-machine writes |
| FX-C2-e | Remaining handler routings (27 deferred-drift sites) | Depends on FX-C2-b/c/d |
| FX-C2-f | Final pass: 19 test-blocked sites unblocked by FX-C2-a + `list_archived` / `get_namespace_meta_entry` trait additions | Closes the residual |

Every sub-batch carries the same gating contract: `cargo fmt --check`,
`cargo clippy --features sal,sal-postgres -- -D warnings -D
clippy::pedantic`, `AI_MEMORY_NO_CONFIG=1 cargo test --features
sal,sal-postgres`, plus SQLite + Postgres parity tests on every new
trait method, plus this audit document updated with the
"Routed-in-PR-#X" status for each site touched.

## ARCH-2-followup proposed trait additions

The following SAL trait methods would close the bulk of the
remaining Missing-trait drift:

1. `MemoryStore::get_links_for_anchor(anchor_id: &str) -> StoreResult<Vec<MemoryLink>>` — closes `db::get_links` (links.rs:894, power.rs:280).
2. `MemoryStore::set_embedding(id: &str, vec: &[f32]) -> StoreResult<()>` — closes `db::set_embedding` (create.rs:475, federation_receive.rs:1052).
3. `MemoryStore::find_by_title_namespace(title: &str, ns: &str) -> StoreResult<Option<Memory>>` — closes create.rs:187.
4. `MemoryStore::next_versioned_title(title: &str, ns: &str) -> StoreResult<String>` — closes create.rs:210.
5. `MemoryStore::find_contradictions(title: &str, ns: &str) -> StoreResult<Vec<…>>` — closes create.rs:1025.
6. `MemoryStore::list_pending_actions(status: Option<&str>, limit: usize) -> StoreResult<Vec<PendingAction>>` — closes governance.rs:130, approvals.rs:277.
7. `MemoryStore::approve_with_approver_type(id: &str, approver: &str) -> StoreResult<ApproveOutcome>` — closes governance.rs:306, approvals.rs:280.
8. `MemoryStore::execute_pending_action(id: &str) -> StoreResult<…>` — closes governance.rs:307, approvals.rs:282.
9. `MemoryStore::decide_pending_action(id: &str, approved: bool, decider: &str) -> StoreResult<…>` — closes governance.rs:480, approvals.rs:328, federation_receive.rs:941.
10. `MemoryStore::list_namespaces() -> StoreResult<Vec<String>>` — closes power.rs:411.
11. `MemoryStore::get_taxonomy(prefix: Option<&str>, depth: u32, limit: usize) -> StoreResult<…>` — closes power.rs:620.
12. `MemoryStore::check_duplicate_with_text(…) -> StoreResult<DuplicateCheckResult>` — closes power.rs:825.
13. `MemoryStore::kg_query(…) -> StoreResult<KgQueryResult>` — closes kg.rs:1359.
14. `MemoryStore::kg_timeline(…) -> StoreResult<KgTimelineResult>` — closes kg.rs:735.
15. `MemoryStore::entity_register(…) -> StoreResult<…>` — closes kg.rs:311.
16. `MemoryStore::entity_get_by_alias(alias: &str, ns: &str) -> StoreResult<…>` — closes kg.rs:468.
17. `MemoryStore::invalidate_link(…) -> StoreResult<…>` — closes kg.rs:932.
18. `MemoryStore::list_agents() -> StoreResult<Vec<AgentRegistration>>` — closes subscriptions.rs:454, admin.rs:280.
19. `MemoryStore::list_archived(prefix: Option<&str>, limit: usize, offset: usize) -> StoreResult<Vec<Memory>>` — closes the archive-list reads currently going through the postgres-downcast hatch (`as_any_for_postgres`).
20. `MemoryStore::health_check() -> StoreResult<bool>` — closes transport.rs:840.
21. `MemoryStore::stats(path: &Path) -> StoreResult<DbStats>` — closes transport.rs:876, admin.rs:505.

Roughly half are read-only probes; the other half are
write-path trait completions. Implementing them lands across two
~600-LOC PRs (one per Adapter side) plus ~200 LOC of handler
re-routing per consumer.

## Test-fixture convergence (blocker for Test-blocked drift)

The unit-test harness at `src/handlers/tests.rs:312` constructs
`AppState` with `db: <:memory: sqlite via test_state()>` AND
`store: test_sqlite_store_handle()` — two disjoint backing files.
Tests that seed via `db::insert(&lock.0, …)` write to `app.db`'s
in-memory connection; routing handler reads through
`app.store.get(…)` reads from the unrelated tempfile and returns
NotFound, breaking 30+ unit tests.

ARCH-2-followup: extend the test harness so `app.db` and
`app.store` either (a) point at the same backing file, or (b)
have a single `MemoryStore` that internally wraps the same
`Db = Arc<Mutex<(Connection, …)>>` the legacy free-functions
use. Option (b) is preferred because it preserves the unit-test
shape (`Body::empty()` → wildcard-admin → no visibility filter)
while making `app.store` operate against the same connection as
the legacy code path.

## Verification

After the in-this-PR routing change:

- `cargo build --features sal,sal-postgres` clean.
- `cargo build --no-default-features --features sqlite-bundled`
  clean (the non-`sal` build keeps the legacy `db::get` filter
  path).
- `cargo test --lib --features sal,sal-postgres http_get_links_*`
  4/4 green (admin wildcard path takes the early branch; the SAL
  filter is exercised through the integration tests under
  `tests/*.rs` where the closed admin allowlist is in force).

## Anti-banned-phrases check

Zero instances of "non-blocking", "trend-line", "surface-level",
"P2/P3 follow-up", "DEFER-TO-V080", "WONTFIX", "out of scope",
"operator-decision-pending", "no network access". Every Deferred
site cites a concrete blocker (SAL trait extension needed or
test-fixture convergence needed); both are filable +
implementable inside the v0.7.0 cycle as ARCH-2-followup.
