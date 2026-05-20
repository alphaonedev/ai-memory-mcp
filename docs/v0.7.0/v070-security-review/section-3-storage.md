# Section 3 — Storage Layer Security + SAL Parity + Migrations

**Specialist:** 3 of 6
**Domain:** storage layer security, SAL parity, migration ladder integrity
**Base SHA:** `b4ba16c8cfcfab459e08e1115518aaf8b273b407` (`local/install-815-816`)
**LSP usage:** rust-analyzer was available; primary surfaces were enumerated via ripgrep over `src/storage/`, `src/store/`, `migrations/sqlite/`, `migrations/postgres/` (the symbol set is wide rather than deep, so grep was the lower-latency path for trait-method enumeration than `findReferences`).

## Axis-by-axis verdict

### C.1 — SQL injection in rusqlite paths — **PASS**

`execute(...)` callsites in `src/storage/` + `src/store/`: ~315. `query_row(...)`: ~123. `prepare(...)`: ~99. All callsites where caller-controlled values reach SQL go through `?` placeholders bound via `params![...]` or tuple. Three `format!`-built SQL fragments exist:

- `src/storage/migrations.rs:2466` `format!("SELECT {column} FROM {table} LIMIT 0")` — **test-only** helper inside `#[cfg(test)] mod`; takes hardcoded identifiers.
- `src/storage/connection.rs:293,309` `format!("DROP INDEX IF EXISTS {ix}")` + `format!("ALTER TABLE memories DROP COLUMN {col}")` — **test-only** legacy-shape synthesis inside `#[cfg(test)] mod`; the loop iterates a hardcoded `&str` array.
- `src/storage/mod.rs:10526` `format!("PRAGMA table_info({table})")` — **test-only** helper.

No production rusqlite callsite interpolates caller input into SQL.

### C.2 — SQL injection in sqlx paths — **PASS**

`sqlx::query[_as|_scalar|_with](...)` callsites in `src/store/postgres.rs`: ~208. Every one binds caller values via `.bind(...)` against `$N` placeholders. Three `format!`-built SQL surfaces:

- `src/store/postgres.rs:2668` `format!("ALTER TABLE archived_memories ADD COLUMN embedding vector({dim_for_archive})")` — `dim_for_archive` is `u32` from a `SELECT atttypmod FROM pg_attribute` server-side query, not caller input.
- `src/store/postgres.rs:4522,4539` AGE Cypher with `{depth}`/`{cap}`/`{PATH_DELIM}` interpolated. `depth` is validated by `validate_find_paths_depth`; `cap` is clamped to `FIND_PATHS_MAX_LIMIT_SAL`; `PATH_DELIM` is a `const &str = "->"`. The doc comment at line 4447 explicitly calls this surface out and rationalizes the safety: AGE 1.5.0 rejects parameters at variable-length-pattern bounds.
- `src/store/postgres.rs:6114,6118` AGE edge MERGE with `{relation}` interpolated. Defense-in-depth `[a-z0-9_]+` validator at line 6013-6022 rejects non-alphanumeric `relation` before interpolation; upstream `validate::VALID_RELATIONS` enforces a closed taxonomy.

No production sqlx callsite interpolates caller input into SQL without prior validation.

### C.3 — sqlite ↔ postgres SAL parity — **PASS WITH CAVEAT**

`MemoryStore` trait defines 45 methods. `SqliteStore` overrides 40 of them; `PostgresStore` overrides 43. The three additional postgres overrides (`store_with_embedding`, `update_embedding`, `execute_pending_action`) are intentional: sqlite uses the trait default impl because embeddings live in a side table and pending-action execution flows through `db::execute_pending_action` rather than the trait. The defaults are documented at `src/store/mod.rs:375-410`.

Caveat: no method-by-method behavioral parity test pins this for **every** method. `tests/store_parity_gaps.rs` enumerates known gaps; nothing forces future additions through that file. Trend-line task — file separately if not already tracked.

### C.4 — Migration ladder integrity — **FAIL** (ship-blocker filed)

- sqlite ladder: ladder reaches `v47`, `CURRENT_SCHEMA_VERSION = 47`, `MAX_SUPPORTED_SCHEMA = 47` (boot.rs:130). 31 `.sql` files on disk; 30 referenced via `include_str!` in `src/storage/migrations.rs` and 1 (`0023_v07_check_constraints.sql`) via `src/storage/connection.rs` (the on-open partial-index reattach surface). **All 31 accounted for.**
- postgres ladder: ladder reaches `v46`, `CURRENT_SCHEMA_VERSION = 46`, `POSTGRES_CURRENT_VERSION = 46` (tests/postgres_schema_parity.rs:63). 20 `.sql` files on disk; 16 referenced via `include_str!`; 3 (`0010`, `0011`, `0012`) re-asserted inline in `postgres_schema.sql` (greenfield bootstrap). **One file orphaned**: `migrations/postgres/0024_v07_persona_signing_atomicity.sql` is on disk but unreferenced anywhere. It mirrors sqlite's `0037_v07_persona_signing_atomicity.sql` and adds `memory_links_attest_signature_atomic_ck` — the CHECK constraint that enforces the (`attest_level IN signed-set` → `signature IS NOT NULL AND octet_length(signature) = 64`) atomicity invariant. **Postgres deployments do not enforce this constraint**, opening a divergence where phantom-signed link rows pass on postgres and fail on sqlite. **Filed as issue #902** with concrete ~25 LOC fix.

### C.5 — Schema-version assertions — **PASS**

Live literal assertions:

- `src/store/postgres.rs:10474` — `assert_eq!(CURRENT_SCHEMA_VERSION, 46)` — matches ladder.
- `tests/wt_1_a_schema_migration.rs:197` — `assert_eq!(v1, 47)` — matches sqlite ladder.
- `tests/postgres_schema_parity.rs:63` — `POSTGRES_CURRENT_VERSION: i64 = 46` — matches.

Stale doc comments (filed under #903): `src/cli/boot.rs:57` ("34 in v0.7.0"), `src/config.rs:538` ("SQLite (schema v29) and Postgres (CURRENT_SCHEMA_VERSION 31)"). Not assertions — doc-drift only.

### C.6 — Path traversal — **PASS**

- `src/governance/audit.rs::init` takes an operator-supplied `dir`, calls `fs::create_dir_all`, and writes daily files via `daily_path(dir, now)` — the filename is a server-generated `YYYY-MM-DD.jsonl`, not caller-influenced. No `..` surface.
- `src/logging.rs::resolve_log_dir_with_override` and `src/audit.rs::resolve_audit_path_with_override` both reject world-writable directories (mode `0o002`) with a typed error — see `src/logging.rs:113-116` + `src/audit.rs:821`. Tests pin the refusal (`logging.rs:360`, `audit.rs:1978`).
- `src/cli/install.rs::AI_MEMORY_SYSTEM_PROMPT_DIR` is an operator-only override; the install path writes to a known filename inside the configured dir; no `..` interpolation.

### C.7 — Storage layer error sanitization — **PASS**

`src/handlers/postgres_gate.rs::store_err_to_response` (line 335) routes every `StoreError` variant through `sanitize_store_err_message` (line 398). The sanitizer redacts (1) `scheme://user:pass@host:port/db` URLs as `[redacted-url]` and (2) absolute filesystem paths as `[redacted-path]`. `IntegrityFailed` and `BackendUnavailable` collapse to a generic `"storage backend unavailable"` message; the raw error is captured to the structured tracing log for operators. Unit tests at line 479-549 pin the sanitizer against five leakage families (postgres URL, fs path, multiple leaks, relative paths preserved, unicode preserved). The wire envelope at line 370 is exactly `{"error": msg}` — no SQL state, no internal struct, no path remnants.

## Ship-blockers filed

- **#902** — `postgres: orphaned migration 0024_v07_persona_signing_atomicity.sql leaves attest/signature atomicity CHECK unenforced` (SAL parity, requires ~25 LOC fix before ship).
- **#903** — `docs drift: stale schema-version literals in src/cli/boot.rs:57 and src/config.rs:538` (doc-only, low priority but tracked per prime directive).

## SQL-injection probe summary

- ~315 rusqlite `execute` + 123 `query_row` + 99 `prepare` callsites audited.
- ~208 sqlx callsites audited.
- 9 total `format!`-built SQL fragments surfaced: 4 in `#[cfg(test)]` modules (hardcoded identifiers), 5 in production with internal-only or pre-validated tokens (postgres DDL with pg_attribute-sourced int, AGE Cypher with clamped int + validated relation token).
- **0 caller-controlled SQL string interpolations in production code.**

## Storage verdict

**SHIP-WITH-CAVEATS** — pending #902 (postgres orphan migration) merged. C.1, C.2, C.5, C.6, C.7 are clean. C.3 is structurally clean (trait defaults are intentional + documented). C.4 has one real defect requiring a ~25 LOC fix before tag-cut; the fix path is fully scoped in the issue body.

If #902 lands and the test pin requested in its "Proposed fix" §6 passes on the postgres adapter, this section flips to **SHIP**.
