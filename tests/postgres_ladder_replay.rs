// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #2424 — POPULATED postgres ladder replay from a LEGACY shape to the tip.
//!
//! # The defect this closes
//!
//! A pre-v84 postgres deployment could not START v1.0.0: `connect()` failed.
//! Two live instances confirmed it — v67–v73 died on `memories.cid`, v74–v83 on
//! `memories.embedding_space`. Root cause: `src/store/postgres_schema.sql`
//! carried file-scope `CREATE INDEX` statements over columns the migrate ladder
//! ALTER-adds, and `PostgresStore::connect` executes that bootstrap on EVERY
//! open, ALWAYS BEFORE `migrate`. On a legacy database the pre-existing table
//! makes `CREATE TABLE IF NOT EXISTS` a no-op, the column is absent, and the
//! index DDL kills the open. (`CREATE INDEX IF NOT EXISTS` is no defence: it
//! keys on the INDEX NAME, which a legacy DB below the owning arm lacks.)
//!
//! # Why the pre-existing guardrails could not see it
//!
//! `tests/postgres_schema_parity.rs` bootstraps a FRESH, disposable database —
//! greenfield only; it never migrates an existing one.
//! `tests/migration_ladder_integrity.rs` asserts the ladder's SHAPE (prefix
//! uniqueness, gap freedom, arm monotonicity, cross-adapter tip agreement) but
//! never its AGREEMENT WITH THE BOOTSTRAP. Neither could observe a legacy open.
//!
//! # The invariant asserted here
//!
//! `bootstrap(fresh)` ≡ `ladder(legacy → tip)`. Concretely, for each pinned
//! legacy schema version V this suite:
//!
//!   1. synthesises a real V-era database on the LIVE postgres by stripping
//!      every column / index / table the ladder introduces ABOVE V (the strip
//!      set is DERIVED from the ladder source, so it cannot rot as arms land),
//!   2. POPULATES it with real rows across `memories`, `memory_links`,
//!      `signed_events` and `recall_observations`,
//!   3. runs the production `PostgresStore::connect()` — which must SUCCEED,
//!      not merely not-crash-in-a-skip,
//!   4. asserts it reached `CURRENT_SCHEMA_VERSION`,
//!   5. asserts EVERY populated row survived byte-intact (North Star: a
//!      migration never corrupts and never loses the durable text), and
//!   6. asserts the resulting column set, column types and FULL `indexdef` text
//!      are IDENTICAL to a greenfield `connect()` on the same server.
//!
//! Step 6 is the equivalence itself — it is what makes a bootstrap-only index
//! (the #2424 shape) impossible to reintroduce without this suite going red,
//! and it is checked against a REAL postgres, never a self-skip.
//!
//! # Gating
//!
//! Requires `feature = "sal-postgres"` and `AI_MEMORY_TEST_POSTGRES_URL`
//! pointing at a live server whose role may `CREATE DATABASE` (each test builds
//! and drops its own throwaway database, so the pointed-at database is never
//! mutated). Without the env the tests `eprintln!` a skip and return cleanly —
//! matching `tests/postgres_schema_parity.rs`.

#![cfg(feature = "sal-postgres")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::store::postgres::PostgresStore;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

mod common;
use common::postgres_url;

/// Legacy schema versions replayed to the tip.
///
/// `67` and `83` are the two shapes CONFIRMED to brick a live deployment
/// (`cid` and `embedding_space` respectively); `73` is the boundary between
/// them. Each is a frozen historical fact, so pinning them cannot rot — and the
/// strip set that synthesises them is derived from the ladder source, so new
/// arms are picked up automatically.
const REPLAY_FROM_VERSIONS: &[i32] = &[67, 73, 83];

// ─────────────────────────────────────────────────────────────────────────────
// Ladder-effect derivation (parsed from the ladder source, never hand-pinned)
// ─────────────────────────────────────────────────────────────────────────────

/// Source marker that opens a postgres migrate arm.
const ARM_MARKER: &str = "    async fn migrate_v";

/// What one `migrate_vN` arm introduces into the schema.
#[derive(Default, Debug)]
struct ArmEffects {
    tables: Vec<String>,
    indexes: Vec<String>,
    /// `(table, column)` pairs added via `ALTER TABLE … ADD COLUMN`.
    columns: Vec<(String, String)>,
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_repo(rel: &str) -> String {
    let p = repo_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Drop `//` Rust comments, `--` SQL comments and Rust string punctuation so
/// DDL quoted in an arm's DOC COMMENT is never mistaken for DDL the arm runs
/// (several arms describe their SQL in prose above the code).
fn strip_ddl_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let mut line = line;
        if line.trim_start().starts_with("//") {
            out.push('\n');
            continue;
        }
        if let Some(i) = line.find("//") {
            line = &line[..i];
        }
        let line = match line.find("--") {
            Some(i) => &line[..i],
            None => line,
        };
        out.push_str(&line.replace(['"', '\\'], " "));
        out.push('\n');
    }
    out
}

/// Trim SQL punctuation off an identifier token (`memories(cid),` -> `memories`).
fn ident(tok: &str) -> String {
    tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .split('(')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Index into `tokens` of the identifier following position `i`, skipping an
/// optional `CONCURRENTLY` modifier and an optional `IF [NOT] EXISTS` guard.
///
/// v1.0.0 #2578 — `CONCURRENTLY` handling is load-bearing, not cosmetic. The
/// v88 arm is the ladder's first `CREATE INDEX CONCURRENTLY`, and without this
/// skip the scanner captured the literal token `CONCURRENTLY` as the INDEX
/// NAME. `rewind_to_version` then issued `DROP INDEX IF EXISTS CONCURRENTLY`,
/// which postgres rejects (`syntax error at or near "CONCURRENTLY"`) — so the
/// whole populated-legacy-replay suite died before it could assert anything.
/// A silent variant of the same bug would be worse: had the DROP succeeded on
/// a wrong name, the synthesised "legacy" database would have kept a v88 index
/// it should not have, and the greenfield-vs-replay `indexdef` comparison
/// would have passed VACUOUSLY.
fn ident_pos(tokens: &[&str], mut i: usize) -> Option<usize> {
    if tokens
        .get(i)
        .is_some_and(|t| t.eq_ignore_ascii_case("CONCURRENTLY"))
    {
        i += 1;
    }
    if tokens.get(i).is_some_and(|t| t.eq_ignore_ascii_case("IF")) {
        i += 1;
        if tokens.get(i).is_some_and(|t| t.eq_ignore_ascii_case("NOT")) {
            i += 1;
        }
        if tokens
            .get(i)
            .is_some_and(|t| t.eq_ignore_ascii_case("EXISTS"))
        {
            i += 1;
        }
    }
    tokens.get(i).map(|_| i)
}

/// `MIGRATION_* const name -> repo-relative migration .sql path`, read from the
/// `include_str!` declarations at the top of the postgres adapter.
fn migration_const_files(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut pending: Option<String> = None;
    for line in src.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("const MIGRATION_")
            && let Some(colon) = rest.find(':')
        {
            pending = Some(format!("MIGRATION_{}", rest[..colon].trim()));
        }
        if let (Some(name), Some(start)) = (pending.as_ref(), t.find("include_str!(\"")) {
            let after = &t[start + "include_str!(\"".len()..];
            if let Some(end) = after.find('"') {
                let raw = &after[..end];
                if let Some(idx) = raw.find("migrations/") {
                    out.insert(name.clone(), raw[idx..].to_string());
                }
            }
            pending = None;
        }
    }
    out
}

/// Scan one blob of (comment-stripped) DDL text into an [`ArmEffects`].
fn scan_effects(text: &str, out: &mut ArmEffects) {
    // `cur` carries the most-recent `ALTER TABLE <t>` target across lines so the
    // multi-clause `ALTER TABLE t / ADD COLUMN a, / ADD COLUMN b;` form resolves
    // each clause to the right table.
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut i = 0usize;
        while i < tokens.len() {
            let t = tokens[i];
            if t.eq_ignore_ascii_case("ALTER")
                && tokens
                    .get(i + 1)
                    .is_some_and(|x| x.eq_ignore_ascii_case("TABLE"))
                && let Some(j) = ident_pos(&tokens, i + 2)
            {
                cur = Some(ident(tokens[j]));
                i = j + 1;
                continue;
            }
            if t.eq_ignore_ascii_case("ADD")
                && tokens
                    .get(i + 1)
                    .is_some_and(|x| x.eq_ignore_ascii_case("COLUMN"))
                && let Some(j) = ident_pos(&tokens, i + 2)
            {
                let col = ident(tokens[j]);
                if let Some(tbl) = cur.as_ref()
                    && !tbl.is_empty()
                    && !col.is_empty()
                {
                    out.columns.push((tbl.clone(), col));
                }
                i = j + 1;
                continue;
            }
            if t.eq_ignore_ascii_case("CREATE") {
                let mut k = i + 1;
                if tokens
                    .get(k)
                    .is_some_and(|x| x.eq_ignore_ascii_case("UNIQUE"))
                {
                    k += 1;
                }
                let kind = tokens.get(k).copied().unwrap_or("");
                if (kind.eq_ignore_ascii_case("INDEX") || kind.eq_ignore_ascii_case("TABLE"))
                    && let Some(j) = ident_pos(&tokens, k + 1)
                {
                    let name = ident(tokens[j]);
                    if !name.is_empty() {
                        if kind.eq_ignore_ascii_case("INDEX") {
                            out.indexes.push(name);
                        } else {
                            out.tables.push(name);
                        }
                    }
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
}

/// Derive, for every postgres `migrate_vN` arm, the schema objects it
/// introduces — from the arm body AND from any `MIGRATION_*` .sql file the arm
/// executes. Deriving (rather than pinning) is what keeps the synthesised
/// legacy shapes correct as new arms land: a v88 column is stripped from a v67
/// synthesis automatically, with no list to update.
fn ladder_effects_by_version() -> BTreeMap<i32, ArmEffects> {
    let src = read_repo("src/store/postgres.rs");
    let const_files = migration_const_files(&src);

    // Split the source at each arm definition; an arm body runs to the next one.
    let mut spans: Vec<(i32, usize)> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(ARM_MARKER) {
        let at = from + rel;
        let after = &src[at + ARM_MARKER.len()..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(v) = digits.parse::<i32>() {
            spans.push((v, at));
        }
        from = at + ARM_MARKER.len();
    }
    assert!(
        !spans.is_empty(),
        "#2424: parsed ZERO `migrate_vN` arms out of src/store/postgres.rs — the scanner is \
         broken, so a synthesised legacy shape would silently be the MODERN shape and this suite \
         would vacuously pass. Fail closed."
    );

    let mut out: BTreeMap<i32, ArmEffects> = BTreeMap::new();
    for (i, (version, start)) in spans.iter().enumerate() {
        let end = spans.get(i + 1).map_or(src.len(), |(_, s)| *s);
        let body = strip_ddl_comments(&src[*start..end]);

        let eff = out.entry(*version).or_default();
        scan_effects(&body, eff);

        // Any migration .sql the arm executes counts as part of that arm.
        for (const_name, rel) in &const_files {
            if body.contains(const_name.as_str()) {
                let text = read_repo(rel);
                scan_effects(&strip_ddl_comments(&text), eff);
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Throwaway-database plumbing
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite a postgres URL to point at a different database, preserving the
/// scheme, credentials, host, port and the whole query string (the TLS
/// parameters live there — `sslmode=verify-full&sslrootcert=…` — so dropping
/// them would silently downgrade the scratch connection).
fn url_with_db(url: &str, db: &str) -> String {
    let (base, query) = match url.find('?') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, ""),
    };
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    // `authority` ends at the first `/` AFTER the scheme; anything past it is
    // the database name we are replacing. A URL with no path separator (no
    // database named) still yields a well-formed result.
    let prefix = match base[scheme_end..].find('/') {
        Some(i) => &base[..=scheme_end + i],
        None => base,
    };
    if prefix.ends_with('/') {
        format!("{prefix}{db}{query}")
    } else {
        format!("{prefix}/{db}{query}")
    }
}

async fn admin_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect(url)
        .await
        .expect("admin pool connect")
}

/// A throwaway database, dropped by [`ScratchDb::destroy`].
struct ScratchDb {
    admin_url: String,
    name: String,
    url: String,
}

/// Scratch databases are named `ai_memory_replay_<tag>_<epoch_secs>_<nanos>`.
/// The epoch field is what makes the stale sweep safe.
const SCRATCH_PREFIX: &str = "ai_memory_replay_";

/// A scratch database is only reaped once it is older than this. An UNBOUNDED
/// sweep would drop a CONCURRENT run's in-flight database (two CI jobs against
/// one server), turning a cleanup convenience into a cross-run failure — and
/// DROP DATABASE is irreversible. Age-bounding keeps the sweep strictly to
/// wreckage no live run can still own.
const SCRATCH_STALE_AFTER_SECS: u64 = 3600;

fn epoch_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Parse the `<epoch_secs>` field out of a scratch database name, if it looks
/// like one this suite created.
fn scratch_created_at(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(SCRATCH_PREFIX)?;
    let mut parts = rest.rsplitn(3, '_');
    let _nanos = parts.next()?;
    parts.next()?.parse::<u64>().ok()
}

/// Best-effort sweep of scratch databases stranded by a previous run that
/// panicked mid-test. Leaving them to accumulate on a shared rehearsal server is
/// not manageable — self-heal instead of requiring manual cleanup — but only
/// ever for databases old enough that no live run can still own them.
async fn reap_stale_scratch_dbs(admin_url: &str) {
    let pool = admin_pool(admin_url).await;
    let Ok(rows) = sqlx::query_scalar::<_, String>(
        "SELECT datname FROM pg_database WHERE datname LIKE 'ai_memory_replay\\_%'",
    )
    .fetch_all(&pool)
    .await
    else {
        pool.close().await;
        return;
    };
    let now = epoch_secs_now();
    for name in rows {
        let stale = scratch_created_at(&name)
            .is_some_and(|created| now.saturating_sub(created) > SCRATCH_STALE_AFTER_SECS);
        if !stale {
            continue;
        }
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
        ))
        .execute(&pool)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&pool)
            .await;
    }
    pool.close().await;
}

impl ScratchDb {
    /// `tag` is caller-controlled but only ever a literal from this file
    /// (`fresh`, `v67`, …); the rest of the name is synthesized. Postgres cannot
    /// bind an identifier in DDL, so the name is interpolated — it is never
    /// derived from external input.
    async fn create(admin_url: &str, tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let name = format!("{SCRATCH_PREFIX}{tag}_{}_{nanos}", epoch_secs_now());
        let pool = admin_pool(admin_url).await;
        // Idempotent: a prior crashed run must not wedge this one.
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&pool)
            .await;
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&pool)
            .await
            .expect("CREATE DATABASE for the replay scratch (role needs CREATEDB)");
        pool.close().await;
        Self {
            admin_url: admin_url.to_string(),
            url: url_with_db(admin_url, &name),
            name,
        }
    }

    async fn destroy(self) {
        let pool = admin_pool(&self.admin_url).await;
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
            self.name
        ))
        .execute(&pool)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy-shape synthesis + schema introspection
// ─────────────────────────────────────────────────────────────────────────────

/// Rewind a tip-shaped database to the on-disk shape of schema version `v` by
/// removing every object the ladder introduces ABOVE `v`, then stamping the
/// version row. Indexes first, then columns, then tables — so a column drop
/// never races the table it lives on.
async fn rewind_to_version(pool: &PgPool, effects: &BTreeMap<i32, ArmEffects>, v: i32) {
    for (&version, eff) in effects.iter().rev() {
        if version <= v {
            continue;
        }
        for ix in &eff.indexes {
            sqlx::query(&format!("DROP INDEX IF EXISTS {ix}"))
                .execute(pool)
                .await
                .unwrap_or_else(|e| panic!("rewind: DROP INDEX {ix}: {e}"));
        }
        for (tbl, col) in &eff.columns {
            sqlx::query(&format!(
                "ALTER TABLE IF EXISTS {tbl} DROP COLUMN IF EXISTS {col} CASCADE"
            ))
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("rewind: DROP COLUMN {tbl}.{col}: {e}"));
        }
        for tbl in &eff.tables {
            sqlx::query(&format!("DROP TABLE IF EXISTS {tbl} CASCADE"))
                .execute(pool)
                .await
                .unwrap_or_else(|e| panic!("rewind: DROP TABLE {tbl}: {e}"));
        }
    }

    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .expect("rewind: clear schema_version");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(v)
        .execute(pool)
        .await
        .expect("rewind: stamp legacy schema_version");
}

/// `table.column -> "<data_type>/<is_nullable>"` for the public schema.
async fn column_shape(pool: &PgPool) -> BTreeMap<String, String> {
    let rows = sqlx::query(
        "SELECT table_name, column_name, data_type, is_nullable
         FROM information_schema.columns
         WHERE table_schema = 'public'",
    )
    .fetch_all(pool)
    .await
    .expect("read information_schema.columns");
    rows.into_iter()
        .map(|r| {
            let t: String = r.get("table_name");
            let c: String = r.get("column_name");
            let d: String = r.get("data_type");
            let n: String = r.get("is_nullable");
            (format!("{t}.{c}"), format!("{d}/{n}"))
        })
        .collect()
}

/// `indexname -> indexdef` for the public schema. Comparing the FULL definition
/// (not just the name) is what catches "the ladder builds a DIFFERENT index
/// than the bootstrap would have" drift.
async fn index_shape(pool: &PgPool) -> BTreeMap<String, String> {
    let rows =
        sqlx::query("SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("read pg_indexes");
    rows.into_iter()
        .map(|r| {
            (
                r.get::<String, _>("indexname"),
                r.get::<String, _>("indexdef"),
            )
        })
        .collect()
}

async fn schema_version_of(pool: &PgPool) -> i32 {
    sqlx::query_scalar::<_, Option<i32>>("SELECT MAX(version) FROM schema_version")
        .fetch_one(pool)
        .await
        .expect("read schema_version")
        .unwrap_or(0)
}

async fn inspect_pool(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(15))
        .connect(url)
        .await
        .expect("inspection pool connect")
}

// ─────────────────────────────────────────────────────────────────────────────
// Population (the "POPULATED replay" half — a migration must not lose data)
// ─────────────────────────────────────────────────────────────────────────────

/// Rows planted into the legacy database before the upgrade. Title/content are
/// the DURABLE SOURCE OF TRUTH (North Star); the assertions after the upgrade
/// compare them byte-for-byte.
const PLANTED: &[(&str, &str, &str)] = &[
    (
        "mem-2424-a",
        "legacy row A",
        "content A — must survive the ladder replay",
    ),
    (
        "mem-2424-b",
        "legacy row B",
        "content B — must survive the ladder replay",
    ),
    (
        "mem-2424-c",
        "legacy row C",
        "content C — must survive the ladder replay",
    ),
];

async fn populate_legacy(pool: &PgPool) {
    for (id, title, content) in PLANTED {
        sqlx::query(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority,
                                   confidence, source, metadata, access_count,
                                   created_at, updated_at)
             VALUES ($1, 'long', 'replay_2424', $2, $3, '{}', 5, 0.9, 'test',
                     '{\"agent_id\":\"replay-agent\"}'::jsonb, 0, NOW(), NOW())",
        )
        .bind(id)
        .bind(title)
        .bind(content)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("populate memories {id}: {e}"));
    }

    sqlx::query(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at)
         VALUES ($1, $2, 'related_to', NOW())",
    )
    .bind(PLANTED[0].0)
    .bind(PLANTED[1].0)
    .execute(pool)
    .await
    .expect("populate memory_links");

    sqlx::query(
        "INSERT INTO signed_events (id, agent_id, event_type, payload_hash, attest_level, timestamp)
         VALUES ('evt-2424', 'replay-agent', 'memory.store', '\\x00'::bytea, 'unsigned', NOW())",
    )
    .execute(pool)
    .await
    .expect("populate signed_events");

    sqlx::query(
        "INSERT INTO recall_observations (recall_id, memory_id, retriever, rank, score)
         VALUES ('rec-2424', $1, 'fts', 1, 0.75)",
    )
    .bind(PLANTED[0].0)
    .execute(pool)
    .await
    .expect("populate recall_observations");
}

/// Assert every planted row survived the upgrade byte-intact.
async fn assert_population_intact(pool: &PgPool, version: i32) {
    for (id, title, content) in PLANTED {
        let row = sqlx::query("SELECT title, content, namespace FROM memories WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .expect("read back memories")
            .unwrap_or_else(|| {
                panic!(
                    "#2424 v{version}→tip replay LOST memory `{id}` — a migration must never \
                     destroy the durable memory text."
                )
            });
        assert_eq!(
            row.get::<String, _>("title"),
            *title,
            "#2424 v{version}→tip replay CORRUPTED the title of `{id}`",
        );
        assert_eq!(
            row.get::<String, _>("content"),
            *content,
            "#2424 v{version}→tip replay CORRUPTED the content of `{id}`",
        );
        assert_eq!(row.get::<String, _>("namespace"), "replay_2424");
    }

    for (table, expected) in [
        ("memory_links", 1_i64),
        ("signed_events", 1),
        ("recall_observations", 1),
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("count {table}: {e}"));
        assert_eq!(
            n, expected,
            "#2424 v{version}→tip replay lost rows from `{table}` (found {n}, expected {expected})",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The tests
// ─────────────────────────────────────────────────────────────────────────────

fn skip_note(test: &str) {
    eprintln!(
        "SKIP {test}: set AI_MEMORY_TEST_POSTGRES_URL to a live postgres \
         (role needs CREATEDB — each test builds and drops its own throwaway database)"
    );
}

/// Build a greenfield tip database and return its `(columns, indexes)` shape —
/// the reference side of the `bootstrap(fresh)` ≡ `ladder(legacy → tip)`
/// equivalence.
async fn greenfield_shape(admin_url: &str) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let db = ScratchDb::create(admin_url, "fresh").await;
    let store = PostgresStore::connect(&db.url)
        .await
        .expect("greenfield connect must succeed");
    drop(store);

    let pool = inspect_pool(&db.url).await;
    let version = schema_version_of(&pool).await;
    assert_eq!(
        i64::from(version),
        ai_memory::storage::current_schema_version_for_tests(),
        "greenfield connect did not reach CURRENT_SCHEMA_VERSION",
    );
    let cols = column_shape(&pool).await;
    let idx = index_shape(&pool).await;
    pool.close().await;
    db.destroy().await;
    (cols, idx)
}

/// #2424 — the GA blocker itself: a POPULATED legacy database at each confirmed
/// bricking shape must OPEN CLEAN under the production `connect()`, reach the
/// tip, keep every row, and land a schema IDENTICAL to a greenfield install.
#[tokio::test]
async fn populated_legacy_replay_opens_clean_and_matches_greenfield() {
    let Some(admin_url) = postgres_url() else {
        skip_note("populated_legacy_replay_opens_clean_and_matches_greenfield");
        return;
    };

    reap_stale_scratch_dbs(&admin_url).await;

    let effects = ladder_effects_by_version();
    let (fresh_cols, fresh_idx) = greenfield_shape(&admin_url).await;

    for &v in REPLAY_FROM_VERSIONS {
        let db = ScratchDb::create(&admin_url, &format!("v{v}")).await;

        // 1. Build the tip shape, then rewind it to the v-era shape.
        {
            let store = PostgresStore::connect(&db.url)
                .await
                .expect("seed connect must succeed");
            drop(store);
        }
        let pool = inspect_pool(&db.url).await;
        rewind_to_version(&pool, &effects, v).await;

        // The synthesis must actually BE a legacy shape — if the strip set were
        // empty the "replay" would just be a modern database opening, and this
        // suite would prove nothing. Derive the expectation instead of pinning
        // it: every column introduced ONLY by an arm ABOVE v must now be gone.
        // (A column re-asserted by an arm at-or-below v — `memories.source_uri`
        // is added by both the v37-era and v44-era arms — legitimately stays.)
        let kept: BTreeSet<(String, String)> = effects
            .iter()
            .filter(|&(&ver, _)| ver <= v)
            .flat_map(|(_, e)| e.columns.iter().cloned())
            .collect();
        let must_be_gone: BTreeSet<(String, String)> = effects
            .iter()
            .filter(|&(&ver, _)| ver > v)
            .flat_map(|(_, e)| e.columns.iter().cloned())
            .filter(|pair| !kept.contains(pair))
            .collect();
        assert!(
            !must_be_gone.is_empty(),
            "#2424: rewinding to v{v} stripped NOTHING — the synthesised database is not a legacy \
             shape and this replay would vacuously pass. Fail closed.",
        );
        for (tbl, col) in &must_be_gone {
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_schema='public' AND table_name=$1 AND column_name=$2)",
            )
            .bind(tbl)
            .bind(col)
            .fetch_one(&pool)
            .await
            .expect("probe stripped column");
            assert!(
                !present,
                "#2424: rewind to v{v} left `{tbl}.{col}` in place even though only an arm ABOVE \
                 v{v} adds it — the synthesised database is NOT a faithful legacy shape. \
                 Fail closed.",
            );
        }

        // 2. Populate it, the way a real deployment is populated.
        populate_legacy(&pool).await;
        pool.close().await;

        // 3. THE ASSERTION: the production open path on a legacy DB. Pre-fix
        //    this returned `BackendUnavailable { init schema: column … does not
        //    exist }` and the deployment could not start.
        let store = PostgresStore::connect(&db.url).await.unwrap_or_else(|e| {
            panic!(
                "#2424 REGRESSION: PostgresStore::connect() FAILED against a populated v{v} \
                 legacy database — this is the GA blocker (a pre-v84 deployment cannot start). \
                 Error: {e}"
            )
        });
        drop(store);

        // 4-6. Reached the tip, kept every row, and converged on the greenfield
        //      schema.
        let pool = inspect_pool(&db.url).await;
        assert_eq!(
            i64::from(schema_version_of(&pool).await),
            ai_memory::storage::current_schema_version_for_tests(),
            "#2424: v{v} legacy replay opened but did not reach CURRENT_SCHEMA_VERSION",
        );
        assert_population_intact(&pool, v).await;

        let cols = column_shape(&pool).await;
        let idx = index_shape(&pool).await;
        pool.close().await;
        db.destroy().await;

        assert_shape_equivalent(v, "column", &fresh_cols, &cols);
        assert_shape_equivalent(v, "index", &fresh_idx, &idx);
    }
}

/// Diff two schema shapes with an actionable message. A key present ONLY in the
/// greenfield side is the #2424 shape itself: an object the BOOTSTRAP creates
/// that the LADDER does not, so a legacy upgrade silently never gets it.
fn assert_shape_equivalent(
    v: i32,
    kind: &str,
    fresh: &BTreeMap<String, String>,
    replayed: &BTreeMap<String, String>,
) {
    let fresh_keys: BTreeSet<&String> = fresh.keys().collect();
    let replayed_keys: BTreeSet<&String> = replayed.keys().collect();

    let only_fresh: Vec<&&String> = fresh_keys.difference(&replayed_keys).collect();
    let only_replayed: Vec<&&String> = replayed_keys.difference(&fresh_keys).collect();

    assert!(
        only_fresh.is_empty(),
        "#2424 BOOTSTRAP≢LADDER: {kind}(s) {only_fresh:?} exist after a GREENFIELD install but \
         NOT after a v{v}→tip ladder replay. The bootstrap creates them and no migrate arm does, \
         so every upgraded deployment silently lacks them. Move the DDL into the arm that owns \
         the underlying column (fresh installs still get it — they run every arm from version 0)."
    );
    assert!(
        only_replayed.is_empty(),
        "#2424 BOOTSTRAP≢LADDER: {kind}(s) {only_replayed:?} exist after a v{v}→tip ladder replay \
         but NOT after a greenfield install — the ladder creates something the bootstrap never \
         does, so the two install paths diverge."
    );

    for (k, fresh_def) in fresh {
        let replayed_def = &replayed[k];
        assert_eq!(
            fresh_def, replayed_def,
            "#2424 BOOTSTRAP≢LADDER: {kind} `{k}` DIFFERS between a greenfield install and a \
             v{v}→tip ladder replay (greenfield: {fresh_def} / replayed: {replayed_def}). The two \
             install paths must converge on one schema.",
        );
    }
}

/// Fail-closed guard on the derivation itself: if the ladder scanner silently
/// stopped finding arms or effects, every replay above would degenerate into
/// "a modern database opens", which proves nothing. Runs without a database.
#[test]
fn ladder_effect_derivation_is_not_vacuous() {
    let effects = ladder_effects_by_version();
    let tip = i32::try_from(ai_memory::storage::current_schema_version_for_tests())
        .expect("schema version fits i32");

    assert!(
        effects.len() > 40,
        "#2424: derived effects for only {} migrate arms — the ladder scanner regressed.",
        effects.len(),
    );
    assert!(
        effects.contains_key(&tip),
        "#2424: no derived effects for the tip arm migrate_v{tip} — the scanner regressed.",
    );

    // The three columns whose bootstrap-inline indexes bricked live deployments
    // MUST be visible to the scanner, or the synthesis cannot strip them.
    for (version, table, column) in [
        (67, "memories", "target_agent_id_idx"),
        (74, "memories", "cid"),
        (84, "memories", "embedding_space"),
    ] {
        let eff = effects
            .get(&version)
            .unwrap_or_else(|| panic!("#2424: no derived effects for migrate_v{version}"));
        assert!(
            eff.columns.iter().any(|(t, c)| t == table && c == column),
            "#2424: migrate_v{version} effects do not include the ALTER-added `{table}.{column}` \
             — the scanner missed it, so a synthesised legacy DB would still carry the column and \
             the replay would not exercise the defect.",
        );
    }
}

/// Unit-pin the two pure helpers the scratch-database plumbing rests on. They
/// run with NO database, so they hold in every CI leg — and both guard
/// irreversible operations: a mis-parsed URL would point `CREATE/DROP DATABASE`
/// at the wrong server, and a mis-parsed name would let the stale sweep reap a
/// concurrent run's live database.
#[test]
fn scratch_plumbing_helpers_are_correct() {
    // Query string (where the TLS parameters live) must survive verbatim.
    assert_eq!(
        url_with_db(
            "postgresql://u:p@127.0.0.1:5434/ai_memory_ladder?sslmode=verify-full&sslrootcert=/ca.crt",
            "scratch",
        ),
        "postgresql://u:p@127.0.0.1:5434/scratch?sslmode=verify-full&sslrootcert=/ca.crt",
    );
    assert_eq!(
        url_with_db("postgres://h/olddb", "newdb"),
        "postgres://h/newdb",
    );
    // No path component: still yields a well-formed URL rather than mangling
    // the authority.
    assert_eq!(
        url_with_db("postgres://h:5432", "newdb"),
        "postgres://h:5432/newdb"
    );

    // Only OUR names parse, and only the epoch field is read as the age.
    assert_eq!(
        scratch_created_at("ai_memory_replay_v67_1700000000_123456789"),
        Some(1_700_000_000),
    );
    assert_eq!(scratch_created_at("some_other_database"), None);
    assert_eq!(
        scratch_created_at("ai_memory_replay_v67_notanumber_1"),
        None
    );
    // A production-looking database must never parse as reapable.
    assert_eq!(scratch_created_at("ai_memory_test"), None);
    assert_eq!(scratch_created_at("ai_memory_ladder"), None);
}
