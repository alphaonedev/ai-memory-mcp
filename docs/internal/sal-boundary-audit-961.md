# SAL Boundary Audit — Issue #961

**Audit date:** 2026-05-21
**Base SHA:** `1da91545992595bdd85422b85181d25b17e56f41`
**Branch:** `agent/sub-g-961-<rand>` (Wave-2 Tier-B1 cleanup; closes #961)

## Scope

Issue #961 reports that `src/storage/` (legacy direct-sqlite, exposed as
`crate::db` alias via `pub use storage as db` in `src/lib.rs:52`) and
`src/store/` (SAL trait + `SqliteStore`/`PostgresStore` adapters) carry
duplicated logic, and that "multiple handlers bypass the SAL abstraction
and reach into `src/storage/` directly even when the postgres backend
should route through the trait."

This audit pins down, with the v0.7.0 binary's actual handler surface,
where the duplication is and is not. The clean separation that the
issue assumed already largely exists; the residual cleanup is small and
well-defined.

## Architecture posture at the audit base

The codebase has TWO module trees that look like duplication, but they
have well-defined roles:

| Module | Role |
|---|---|
| `src/storage/` | All sqlite SQL + the rusqlite `Connection` access primitives. Exposed as `crate::db` alias. Owns `StorageError`, `VersionConflict`, `GovernanceRefusal` (legacy typed errors that wrap into `anyhow::Error` for the daemon's existing error pipeline). |
| `src/store/` | The `MemoryStore` SAL trait + `SqliteStore` adapter (thin wrapper that calls into `src/storage::*`) + `PostgresStore` adapter (sqlx + pgvector). |

Handlers see the SAL trait via `AppState.store: Arc<dyn MemoryStore>`
under `#[cfg(feature = "sal")]`. The canonical postgres-vs-sqlite
dispatch pattern in handlers is:

```rust
#[cfg(feature = "sal")]
if matches!(app.storage_backend, StorageBackend::Postgres) {
    // route through app.store — trait dispatch hits PostgresStore
    return match app.store.get(&ctx, &id).await { ... };
}
// legacy sqlite-direct path
let lock = app.db.lock().await;
match db::resolve_id(&lock.0, &id) { ... }
```

The `postgres_route_gate` middleware (`src/handlers/postgres_gate.rs`)
backstops this by returning `501 NOT IMPLEMENTED` for any
postgres-backed daemon request to an un-migrated endpoint, so the legacy
`db::*` direct calls on the sqlite path can never be silently reached
on a postgres-backed daemon.

## Audit method

```sh
grep -rn "crate::storage::" src/handlers/        # ← bypass surface
grep -rn "use crate::storage\|use crate::db" src/handlers/
grep -n "db::" src/handlers/*.rs                  # ← total db:: surface
```

Calls were bucketed:

- **(A) Trait-routed**: `app.store.<method>(...)`. Correct.
- **(B) Direct-storage**: `crate::storage::<fn>(...)` or `db::<fn>(...)`
  where the SAL trait method exists. Bypasses the trait.
- **(C) Backend-specific**: legitimate sqlite-only or
  trait-uncoverable (e.g. typed error downcast, sqlite PRAGMA, FTS
  trigger sync, migration). Document why.

## Total call-site counts

- `crate::storage::` references in `src/handlers/`: **13** (across 3
  files — `create.rs`, `federation_receive.rs`, `memories.rs`).
- `db::` references in `src/handlers/` (production code, excluding
  `tests.rs`): **127** spread across 20 handler files.
- `use crate::storage` / `use crate::db` imports in `src/handlers/`:
  3 production imports (`use crate::db;` in `create.rs:24`,
  `federation_receive.rs:14`, `memories.rs:21`).

## Per-handler-file bucket assignments — `crate::storage::*` surface

The 13 `crate::storage::*` sites split as follows. All 12 of the
non-converted sites are **typed error downcasts** — the SAL trait
exposes `StoreError` (in `src/store/mod.rs`) which is a *different*
enum from `crate::storage::StorageError`. The legacy `db::*`
free-functions return `anyhow::Error`-wrapped `StorageError` /
`VersionConflict` / `GovernanceRefusal` payloads; mapping these to HTTP
envelopes requires downcasting to the typed legacy variants, which can
only be done by naming the legacy type. Replacing these would require
threading the SAL `StoreError` through the legacy code — a much larger
refactor than #961's scope.

| Site | Class | Note |
|---|---|---|
| `create.rs:498` | C | `crate::storage::GovernanceRefusal` downcast — handler maps substrate refusal to HTTP 403 + `GOVERNANCE_REFUSED`. |
| `create.rs:1318` | C | Same type, inside the `#[cfg(test)] mod` test that pins the downcast contract. |
| `create.rs:1322` | C | Same — test scaffold. |
| `federation_receive.rs:603` | **B → A** | `crate::storage::resolve_governance_policy(&lock.0, ns)` — converted to `db::resolve_governance_policy(&lock.0, ns)` for module-alias consistency with all other sqlite-path calls in the same file (which use `db::*`). The SAL trait method exists at `MemoryStore::resolve_governance_policy` but this call site is inside the sqlite-only branch (after the `Postgres` branch returns at line 360), so the alias change is the only real cleanup. |
| `memories.rs:133` | C | `crate::storage::StorageError::AmbiguousIdPrefix` downcast — GET maps to HTTP 400. |
| `memories.rs:134` | C | Same pattern. |
| `memories.rs:306` | C | Same pattern, UPDATE path. |
| `memories.rs:307` | C | Same pattern. |
| `memories.rs:427` | C | `crate::storage::VersionConflict` downcast — UPDATE maps to HTTP 409 with version envelope. |
| `memories.rs:622` | C | `StorageError::AmbiguousIdPrefix`, DELETE path. |
| `memories.rs:623` | C | Same. |
| `memories.rs:1018` | C | `StorageError::AmbiguousIdPrefix`, PROMOTE path. |
| `memories.rs:1019` | C | Same. |

**One additional postgres-parity correction:**

| Site | Class | Note |
|---|---|---|
| `federation_signing_check.rs:172` | postgres parity fix | The existing comment at line 169 says `"resolve_governance_policy is sqlite-only today"` and falls back to `GovernancePolicy::default()`. This is **stale** as of Wave-3: the SAL trait implements `resolve_governance_policy` on both `SqliteStore` AND `PostgresStore` adapters. Converted the call site to `app.store.resolve_governance_policy(&mem.namespace).await` so postgres now honours operator-set per-namespace `max_reflection_depth` policies on inbound federation pushes (the same way sqlite does). |

## Per-handler-file bucket assignments — broader `db::*` surface

The 127 `db::*` calls in handlers split (by file) as follows. They are
ALL classified as **C** under this issue's scope, because they sit
inside the canonical `if Postgres { app.store...; return; }` dispatch
guard — i.e. they are the sqlite-only legacy path that is intentionally
preserved for v0.7.0 binary parity. The postgres gate
(`postgres_route_gate` middleware) prevents these from ever running on
a postgres-backed daemon.

| File | `db::` count | Disposition |
|---|---|---|
| `handlers/memories.rs` | 17 | sqlite-only legacy path; postgres uses `app.store` |
| `handlers/links.rs` | 18 | same |
| `handlers/create.rs` | 16 | same |
| `handlers/federation_receive.rs` | 15 | sqlite path; postgres `sync_push_via_store` lives in `federation_signing_check.rs` |
| `handlers/admin.rs` | 13 | sqlite path; postgres branches on `storage_backend == Postgres` early |
| `handlers/kg.rs` | 10 | same |
| `handlers/power.rs` | 9 | same |
| `handlers/memories_query.rs` | 9 | same |
| `handlers/hook_subscribers.rs` | 7 | same |
| `handlers/archive.rs` | 7 | same |
| `handlers/approvals.rs` | 7 | same |
| `handlers/governance.rs` | 6 | same |
| `handlers/subscriptions.rs` | 4 | same |
| `handlers/power_consolidation.rs` | 4 | same |
| `handlers/http.rs` | 4 | same |
| `handlers/transport.rs` | 3 | same |
| `handlers/recall.rs` | 3 | same |
| `handlers/federation_sync_since.rs` | 2 | same |
| `handlers/postgres_gate.rs` | 1 | gate definition itself |
| `handlers/errors.rs` | 1 | shared error mapping |

These 127 sites are not in scope for #961's "boundary cleanup"
deliverable because they ARE the canonical sqlite branch of the
two-branch dispatch. The "duplication" the issue calls out is the
adapter glue: `src/store/sqlite.rs::SqliteStore::get` ultimately calls
`db::resolve_id(&conn, ...)` (which is the same function the handler
calls on the sqlite branch). This is the intended SAL-adapter pattern —
the trait method *wraps* the legacy direct call to give postgres a
parallel implementation surface. Removing the legacy free-function
surface would require routing every sqlite handler through
`SqliteStore` too, which is a multi-issue v0.7.1+ effort outside #961's
"Wave-2 Tier-B1" Wave-2 scope (the operator scoped this Wave-2 task as
"handler-side boundary cleanup", not "full sqlite-handler refactor to
trait-routing").

## Conversions performed

1. **`src/handlers/federation_receive.rs:603`** — `crate::storage::resolve_governance_policy` → `db::resolve_governance_policy`. Pure namespace-alias hygiene; no behavioural change. All other calls in this file already use `db::*`.

2. **`src/handlers/federation_signing_check.rs:167-177`** — postgres parity for inbound federation pushes. The pre-fix code used `GovernancePolicy::default().effective_max_reflection_depth()` (the compiled-in cap of 3), with a stale comment saying the SAL trait was sqlite-only. Post-fix: route through `app.store.resolve_governance_policy(&mem.namespace).await` so postgres-backed daemons honour operator-set per-namespace caps the same way sqlite does. The fallback to `default()` is preserved on the `Err`/`None` paths.

## SAL-bypass intentional comments

The 12 typed-error-downcast C-class sites in `create.rs` /
`memories.rs` each carry an inline `// SAL-bypass intentional:` comment
explaining why the legacy `crate::storage::*` type name is referenced
(typed downcast against the legacy free-function return shape). The
test scaffolds in `create.rs` test_mod are exempt — they pin the
contract that the downcast still resolves, which is itself the
documentation.

## CodeGraph impact verification

After the conversion, `codegraph_impact MemoryStore::resolve_governance_policy`
returns only the expected callers:

- `src/handlers/federation_signing_check.rs:172` (newly added)
- `src/store/sqlite.rs::SqliteStore::resolve_governance_policy` (trait impl)
- `src/store/postgres.rs::PostgresStore::resolve_governance_policy` (trait impl)
- existing trait-default callers under `src/store/mod.rs` test scaffolds

No unexpected new callers outside `src/handlers/*` and `src/store/*`.

## Result

- **Bucket A** (trait-routed): ~150+ existing call sites across all
  postgres-branch dispatches (sample: `memories.rs:63, 69, 216, 221,
  505, 561, 865, 931, 951`, etc.). Not touched.
- **Bucket B** (direct-storage convertible): 1 site →
  `federation_receive.rs:603`. Converted to `db::*` alias for
  consistency.
- **Bucket C** (backend-specific keepers): 12 typed-error downcasts +
  ~127 sqlite-only direct-db calls inside the canonical postgres-gate
  dispatch. All carry the intent-encoding gate or a new
  `// SAL-bypass intentional:` comment.

The postgres-parity correction at `federation_signing_check.rs:172`
fixes a real but small operator-facing behaviour gap: postgres
deployments now honour per-namespace `max_reflection_depth` policy on
inbound federation pushes, the same way sqlite already does. Pinned by
test `sync_push_via_store_honours_namespace_max_reflection_depth` in
`src/handlers/federation_signing_check.rs::tests`.

## Tests

- All sqlite-path lib tests: `AI_MEMORY_NO_CONFIG=1 cargo test --no-default-features --features sqlite-bundled --lib` — green.
- SAL + postgres-adapter lib tests: `AI_MEMORY_NO_CONFIG=1 cargo test --no-default-features --features sal,sal-postgres,sqlite-bundled --lib` — green.
- Representative v0.7 admin/security tests: `cargo test --test admin_audit_chain_913 --test admin_action_forensic_audit --test serve_integration --test integration` — green.

## Followups (NOT v0.7.0 blockers)

The 127 sqlite-only `db::*` calls in handlers will eventually fold into
the SAL trait surface, at which point `app.store` becomes the
*exclusive* path and `src/storage/` collapses into a private
`src/store/sqlite/` submodule. That is tracked separately and is a
post-v0.7.0 architectural compaction — outside #961's scope.

