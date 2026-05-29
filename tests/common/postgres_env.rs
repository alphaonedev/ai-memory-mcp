// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-test Postgres schema isolation helper (issue #1381).
//!
//! ## Why this exists
//!
//! The full v0.7.0 postgres+AGE regression run on the LAN-parity
//! container at `127.0.0.1:15432` (2026-05-28) surfaced 4 deterministic
//! test failures (filed as issue #1381) that all share a single root
//! cause: tests assume an empty / known `public.memories` schema state
//! but the container accumulates state from prior tests in the same
//! `cargo test --features sal,sal-postgres` invocation. CI's
//! Postgres-feature gate uses `--test-threads=1` and a one-shot
//! container per job so it doesn't manifest there; the lan-parity
//! shared-container path is what surfaces it.
//!
//! ## What this helper does
//!
//! [`PostgresTestEnv::new`] connects to the base
//! `AI_MEMORY_TEST_POSTGRES_URL`, `CREATE SCHEMA test_<test>_<uuid8>`,
//! and returns a per-test URL with `?options=-c%20search_path=<schema>`
//! appended so every connect from that URL lands its tables in the
//! isolated schema. Postgres tables created via unqualified
//! `CREATE TABLE IF NOT EXISTS memories (…)` (the shape used by the
//! production bootstrap in `src/store/postgres_schema.sql`) honour
//! `search_path` and land in the test schema, not in `public`.
//!
//! [`SchemaCleanupGuard`] is the `Drop`-time worker that issues
//! `DROP SCHEMA <schema> CASCADE` against the base URL so the test
//! container doesn't accumulate schema clutter across test runs. The
//! drop is best-effort (drop-on-panic safe) and surfaces failures via
//! `eprintln!` rather than propagating — drop is infallible by trait
//! contract.
//!
//! ## What this helper does NOT do
//!
//! - It does NOT touch `public.memories`. Tests that need a clean
//!   `public.*` for some reason (e.g., the post-fix `current_dim`
//!   probes that hardcode `n.nspname='public'` in
//!   `src/store/postgres.rs`) need their own scope discipline — see
//!   [`PostgresTestEnv::schema_name`] for the test-schema name to
//!   filter catalog probes against.
//! - It does NOT acquire the `MIGRATION_ADVISORY_LOCK_KEY`; the
//!   substrate's `PostgresStore::connect` does that already and the
//!   lock is process-global, not schema-scoped.
//!
//! ## When per-test schema isolation is NOT enough
//!
//! A handful of tests (e.g. `embedding_dim_migration`) specifically
//! exercise the substrate's `connect_with_dim_and_timeout_auto_migrate`
//! path which is HARDCODED to probe + migrate `public.memories` (see
//! `current_embedding_dim` at `src/store/postgres.rs:2782` — the
//! `n.nspname = 'public'` filter is intentional, not bug). For those
//! tests, [`PublicSchemaLock::acquire`] returns a cross-process
//! advisory lock that serialises ownership of `public.memories`
//! across every parallel test binary in the same cargo invocation.
//!
//! ## Usage
//!
//! ```ignore
//! mod common;
//! use common::postgres_env::PostgresTestEnv;
//!
//! #[tokio::test]
//! async fn my_test() {
//!     let Some(env) = PostgresTestEnv::new("my_test").await else {
//!         eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
//!         return;
//!     };
//!     let store = PostgresStore::connect(env.url()).await.unwrap();
//!     // … test body; schema dropped automatically on `env` drop …
//! }
//! ```

#![allow(dead_code)]

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Per-test isolated Postgres schema + URL wrapper.
///
/// Created via [`PostgresTestEnv::new`]; the returned struct holds a
/// [`SchemaCleanupGuard`] that fires `DROP SCHEMA <name> CASCADE` on
/// drop. Hold the env for the lifetime of the test body so the schema
/// isn't dropped out from under live connections.
pub struct PostgresTestEnv {
    base_url: String,
    url_with_search_path: String,
    schema_name: String,
    // Held purely for Drop side effects.
    _cleanup: SchemaCleanupGuard,
}

impl PostgresTestEnv {
    /// Connect to the base `AI_MEMORY_TEST_POSTGRES_URL`, create a
    /// unique schema `test_<test_name>_<uuid8>`, and return a wrapper
    /// whose `url()` accessor yields a URL with
    /// `?options=-c%20search_path=<schema>` appended so every connect
    /// from that URL lands in the isolated schema.
    ///
    /// Returns `None` when `AI_MEMORY_TEST_POSTGRES_URL` is unset, so
    /// the caller can `eprintln!("skip: …")` and return early — same
    /// shape as the existing per-test `postgres_url()` skip pattern.
    ///
    /// `test_name` is sanitised to be a valid postgres identifier:
    /// lowercased, non-alphanumeric characters mapped to `_`, and
    /// truncated to 24 chars. Combined with the 8-hex uuid suffix the
    /// final schema name fits comfortably within Postgres's 63-char
    /// `NAMEDATALEN` limit.
    pub async fn new(test_name: &str) -> Option<Self> {
        let base_url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        let sanitised = sanitise_for_pg_ident(test_name, 24);
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let schema_name = format!("test_{sanitised}_{}", &suffix[..8]);

        let pool = connect_admin_pool(&base_url).await;
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {schema_name}"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create schema {schema_name}: {e}"));

        let url_with_search_path = append_search_path_option(&base_url, &schema_name);

        let cleanup = SchemaCleanupGuard {
            base_url: base_url.clone(),
            schema_name: schema_name.clone(),
        };

        Some(Self {
            base_url,
            url_with_search_path,
            schema_name,
            _cleanup: cleanup,
        })
    }

    /// The per-test URL with `?options=-c%20search_path=<schema>`
    /// appended. Pass this to `PostgresStore::connect(...)` or any
    /// `sqlx` connect call so the session's `search_path` lands the
    /// isolated schema first.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url_with_search_path
    }

    /// The bare `AI_MEMORY_TEST_POSTGRES_URL` without the
    /// `search_path` override — useful when a test needs an inspection
    /// pool that explicitly bypasses the `search_path` scoping so it can
    /// probe catalog rows across all schemas.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The unique per-test schema name. Use this to filter catalog
    /// probes against `pg_namespace.nspname` so they only see the
    /// test's own schema and not residue from other tests in the
    /// shared container.
    #[must_use]
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }
}

/// Drop-time worker that issues `DROP SCHEMA <name> CASCADE` against
/// the base URL so the test container doesn't accumulate schema
/// clutter across test runs.
///
/// The drop is best-effort — failures are surfaced via `eprintln!`
/// (drop is infallible by trait contract). A spawned blocking thread
/// is used because `drop` is not async and we cannot await the sqlx
/// drop inline.
pub struct SchemaCleanupGuard {
    base_url: String,
    schema_name: String,
}

impl Drop for SchemaCleanupGuard {
    fn drop(&mut self) {
        let base_url = self.base_url.clone();
        let schema_name = self.schema_name.clone();
        // Drop is sync; sqlx is async. Spawn a thread that builds its
        // own tokio runtime to run the DROP SCHEMA. The thread joins
        // on drop completion so the schema is gone before the next
        // test's setup runs (important for the issue #1213 tests that
        // assert exact catalog row counts).
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build drop-time tokio runtime");
            rt.block_on(async move {
                let pool = match PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(std::time::Duration::from_secs(10))
                    .connect(&base_url)
                    .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "PostgresTestEnv cleanup: failed to connect for drop of {schema_name}: {e}"
                        );
                        return;
                    }
                };
                if let Err(e) = sqlx::query(&format!(
                    "DROP SCHEMA IF EXISTS {schema_name} CASCADE"
                ))
                .execute(&pool)
                .await
                {
                    eprintln!(
                        "PostgresTestEnv cleanup: DROP SCHEMA {schema_name} CASCADE failed: {e}"
                    );
                }
            });
        });
        // We deliberately let the thread join here so the cleanup
        // completes before the next test's PostgresTestEnv::new runs.
        // join() returning an Err means the thread panicked during
        // cleanup; we surface that to stderr but do NOT re-panic from
        // Drop (double-panic during unwind would abort the process).
        if let Err(e) = join.join() {
            eprintln!(
                "PostgresTestEnv cleanup thread for {} panicked: {:?}",
                self.schema_name, e
            );
        }
    }
}

/// Build a one-shot inspection pool against the base URL with the
/// `search_path` NOT scoped — used internally by [`PostgresTestEnv::new`]
/// to issue the `CREATE SCHEMA` and re-used by callers via
/// [`PostgresTestEnv::base_url`] when a test needs a cross-schema
/// inspection view.
async fn connect_admin_pool(base_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(base_url)
        .await
        .unwrap_or_else(|e| panic!("PostgresTestEnv: connect base pool: {e}"))
}

/// Append `?options=-c%20search_path=<schema>,public` to a Postgres
/// URL, preserving any pre-existing query string. We avoid pulling
/// in `url` just for this and stick to manual string handling
/// because the shape we need is small + stable.
///
/// `public` is appended after the test schema so DDL like
/// `CREATE TABLE memories (... embedding vector(N))` (the production
/// bootstrap shape from `src/store/postgres_schema.sql`) can still
/// resolve `vector` against the `public.vector` extension type
/// while `CREATE TABLE` (etc.) lands the `memories` row into the
/// test's schema (the first writable schema in `search_path` is the
/// default-write-target).
fn append_search_path_option(base_url: &str, schema: &str) -> String {
    // Postgres URL `options` query-string accepts the same `-c key=val`
    // syntax as a libpq connection string; we URL-encode the space
    // as `%20`. Multiple `-c` settings can be chained but we only
    // need search_path here.
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}options=-c%20search_path%3D{schema}%2Cpublic")
}

/// Sanitise an arbitrary string into a valid lowercase Postgres
/// identifier fragment. Maps non-`[a-z0-9_]` characters to `_` and
/// truncates to `max_len` chars.
fn sanitise_for_pg_ident(s: &str, max_len: usize) -> String {
    let lower = s.to_ascii_lowercase();
    let mapped: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: String = mapped.chars().take(max_len).collect();
    if trimmed.is_empty() {
        "test".to_string()
    } else {
        trimmed
    }
}

/// Cross-process advisory lock that serialises ownership of
/// `public.memories` across every parallel test binary in the same
/// cargo invocation.
///
/// Used by tests that exercise substrate paths hardcoded to probe
/// `public.memories` (e.g. `current_embedding_dim` at
/// `src/store/postgres.rs:2782`). The substrate already uses
/// `MIGRATION_ADVISORY_LOCK_KEY` for bootstrap-serialisation; we pick
/// a different magic number so we don't deadlock against
/// `PostgresStore::connect` itself.
///
/// The lock is session-scoped: the held connection in
/// [`PublicSchemaLock`] keeps the lock for the lifetime of the
/// guard, and the explicit `pg_advisory_unlock` in `Drop` releases
/// it deterministically (rather than relying on session-end
/// release on connection drop).
pub struct PublicSchemaLock {
    pool: PgPool,
    key: i64,
}

impl PublicSchemaLock {
    /// Magic integer keyed for the `public.memories` ownership lock.
    /// Picked outside the substrate's `MIGRATION_ADVISORY_LOCK_KEY`
    /// range so we don't accidentally re-acquire its lock and
    /// deadlock against the bootstrap path.
    const PUBLIC_MEMORIES_LOCK_KEY: i64 = 0x1381_5081_1F50_1357_u64.cast_signed();

    /// Acquire the cross-process advisory lock that serialises
    /// ownership of `public.memories`. Returns `None` when
    /// `AI_MEMORY_TEST_POSTGRES_URL` is unset so the caller can
    /// `eprintln!("skip: …")` and return early.
    ///
    /// The acquisition queues behind any existing holder
    /// (`pg_advisory_lock` is the queued, not the try-shape, variant)
    /// — slow peer tests simply make us wait.
    ///
    /// Designed to be `await`-ed from inside a `#[tokio::test]`
    /// runtime — we deliberately do NOT spin up a private runtime
    /// here because nested runtimes panic with "Cannot start a
    /// runtime from within a runtime" under sqlx's current-thread
    /// driver.
    pub async fn acquire() -> Option<Self> {
        let base_url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&base_url)
            .await
            .unwrap_or_else(|e| panic!("PublicSchemaLock: connect: {e}"));
        let key = Self::PUBLIC_MEMORIES_LOCK_KEY;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("PublicSchemaLock: pg_advisory_lock: {e}"));
        Some(Self { pool, key })
    }
}

impl Drop for PublicSchemaLock {
    fn drop(&mut self) {
        // Release the advisory lock explicitly. Best-effort — Drop
        // is infallible by trait contract, so we eprintln on
        // failure rather than propagating.
        //
        // Drop is sync; sqlx is async. Spawn a thread that builds its
        // OWN tokio runtime so we don't double-enter the test
        // runtime. The thread joins before Drop returns so the lock
        // is reliably released by the time the next test's
        // `acquire()` can re-take it.
        let key = self.key;
        let pool = self.pool.clone();
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build PublicSchemaLock drop-time tokio runtime");
            rt.block_on(async move {
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(key)
                    .execute(&pool)
                    .await
            })
        });
        match join.join() {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("PublicSchemaLock: pg_advisory_unlock failed: {e}"),
            Err(e) => eprintln!("PublicSchemaLock: unlock thread panicked: {e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{append_search_path_option, sanitise_for_pg_ident};

    #[test]
    fn append_search_path_uses_question_mark_when_no_query() {
        let url = append_search_path_option("postgres://u:p@h/db", "test_schema");
        // `,public` is appended so DDL like `embedding vector(N)` can
        // still resolve the `vector` type from the `public.vector`
        // extension while the test's own schema receives newly
        // CREATEd tables (first writable schema in search_path wins).
        assert_eq!(
            url,
            "postgres://u:p@h/db?options=-c%20search_path%3Dtest_schema%2Cpublic"
        );
    }

    #[test]
    fn append_search_path_uses_ampersand_when_query_present() {
        let url = append_search_path_option("postgres://u:p@h/db?sslmode=disable", "t1");
        assert_eq!(
            url,
            "postgres://u:p@h/db?sslmode=disable&options=-c%20search_path%3Dt1%2Cpublic"
        );
    }

    #[test]
    fn sanitise_maps_punctuation_to_underscore_and_truncates() {
        let s = sanitise_for_pg_ident("issue-1213::probe with spaces", 16);
        assert_eq!(s, "issue_1213__prob");
    }

    #[test]
    fn sanitise_empty_input_falls_back_to_test() {
        assert_eq!(sanitise_for_pg_ident("", 16), "test");
    }
}
