// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3528) — no `src/**` test may rewrite the schema stamp of the
//! SHARED live postgres database.
//!
//! # The defect
//!
//! `src/**/*.rs` compiles into ONE `cargo test --lib` binary, and every
//! postgres test in it reaches the SAME database through
//! `AI_MEMORY_TEST_POSTGRES_URL`. The #3401 v98 inbox-alias case rewound that
//! database's stamp with two autocommit statements:
//!
//! ```text
//! sqlx::query("DELETE FROM schema_version")            .execute(&store.pool)
//! sqlx::query("INSERT INTO schema_version VALUES (97)").execute(&store.pool)
//! ```
//!
//! Between them the shared, POPULATED database carries no stamp row at all.
//! The #2564 guard reads that as version 0, observes durable rows plus schema
//! structure no version-0 database ever had, and correctly REFUSES the
//! connection with `SchemaStampInvalid` — so any other lib test whose
//! `PostgresStore::connect` lands in that window fails through no fault of its
//! own. That is exactly how
//! `store::postgres::tests::live_get_taxonomy_assembles_hierarchical_tree`
//! failed a `--test-threads=8` gate run (#3528). While the stamp then sits at
//! 97, every concurrent `connect` additionally races the v98 ladder over the
//! same shared schema.
//!
//! Serialising the writer would not fix it: the victims are ordinary `connect`
//! calls that take no lock — the same reader-victim shape as #3475 / #3517.
//! The cure is a PRIVATE database, which removes both the window and the
//! shared schema by construction.
//!
//! # The rule this gate pins
//!
//! A `src/**/*.rs` file that reaches the shared database (it calls
//! `postgres_url()`) must not execute an INLINE stamp-MUTATING statement
//! unless it also creates its own database (`CREATE DATABASE`).
//!
//! Three scoping decisions keep it aimed at the defect rather than its
//! neighbourhood — a gate with a high false-positive rate gets switched off:
//!
//! * **Only files that reach the SHARED url.** The many `rusqlite` stamp
//!   rewinds under `src/storage/**` and `src/cli/**` operate on private temp
//!   FILES; they are not this defect and are not flagged.
//! * **Only INLINE `sqlx::query(...)` / `raw_sql(...)` literals.** The
//!   production writer in `src/store/postgres.rs` is a named `const`
//!   (`"INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT ..."`),
//!   which is both the house literal-de-duplication rule (pm-v3.1) and the
//!   thing that distinguishes a migration ladder from a test rewinding a
//!   stamp. Reads (`SELECT MAX(version) FROM schema_version`) are never
//!   flagged.
//! * **`CREATE DATABASE` is the sanctioned escape.** It is the marker of the
//!   real fix, not an allowlist entry that rots.
//!
//! The `detector_*` cases drive the predicate over synthetic buffers so the
//! gate is proven to CATCH the pre-#3528 shape and SPARE the corrected one,
//! rather than passing vacuously on today's tree (M-TAUTOLOGICAL-TESTS).

use std::path::{Path, PathBuf};

/// The accessor that returns the SHARED `AI_MEMORY_TEST_POSTGRES_URL`.
const SHARED_URL_ACCESSOR: &str = "postgres_url()";

/// The marker of the sanctioned fix: the file makes its own database.
const PRIVATE_DB_MARKER: &str = "CREATE DATABASE";

/// Statements that MUTATE the stamp. Reads are deliberately absent.
const STAMP_MUTATIONS: [&str; 3] = [
    "DELETE FROM schema_version",
    "INSERT INTO schema_version",
    "UPDATE schema_version",
];

/// An inline sqlx execution — as opposed to a named `const` the production
/// ladder uses.
const INLINE_SQLX: [&str; 2] = ["sqlx::query(", "sqlx::raw_sql("];

fn repo_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

/// `"<line-number>: <trimmed line>"` for every unsanctioned shared-database
/// stamp rewrite in `source`.
///
/// Factored out of the filesystem walk so the self-tests can drive it over
/// synthetic buffers.
fn shared_stamp_rewrites(source: &str) -> Vec<String> {
    // Scoping condition 1: does this file reach the SHARED database at all?
    if !source.contains(SHARED_URL_ACCESSOR) {
        return Vec::new();
    }
    // Scoping condition 3: a file that makes its own database is the fix.
    if source.contains(PRIVATE_DB_MARKER) {
        return Vec::new();
    }
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !is_comment_line(trimmed)
                // Scoping condition 2: an INLINE execution, not a named const.
                && INLINE_SQLX.iter().any(|k| line.contains(k))
                && STAMP_MUTATIONS.iter().any(|m| line.contains(m))
        })
        .map(|(i, line)| format!("{}: {}", i + 1, line.trim()))
        .collect()
}

/// THE GATE.
#[test]
fn no_lib_test_rewrites_the_shared_postgres_schema_stamp_3528() {
    let src = repo_src_dir();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    assert!(!files.is_empty(), "no src/**/*.rs files found");

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(manifest)
            .unwrap_or(file.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for finding in shared_stamp_rewrites(&source) {
            violations.push(format!("  {rel}:{finding}"));
        }
    }

    assert!(
        violations.is_empty(),
        "a `src/**` test rewrites the SHARED postgres schema stamp (#3528):\n{}\n\n\
         `src/**/*.rs` is ONE `cargo test --lib` binary and every postgres test in\n\
         it shares the `AI_MEMORY_TEST_POSTGRES_URL` database. Rewinding that\n\
         database's `schema_version` leaves it momentarily UNSTAMPED, which the\n\
         #2564 guard reads as version 0 on a populated database and refuses with\n\
         `SchemaStampInvalid` — failing every concurrent `PostgresStore::connect`\n\
         that lands in the window, and racing the ladder over the shared schema\n\
         while the stamp is rolled back.\n\n\
         Give the case its OWN database instead (the marker this gate accepts is\n\
         `CREATE DATABASE`); see the `ScratchDb` fixture in\n\
         `src/store/postgres_inbox_tests.rs`, or the sibling suites\n\
         `tests/postgres_schema_downgrade_guard_2445.rs` /\n\
         `tests/postgres_ladder_replay.rs`.\n\n\
         Serialising the writer does NOT work: the victims are ordinary `connect`\n\
         calls that take no lock (the #3475 / #3517 reader-victim shape).",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Detector self-tests.
// ---------------------------------------------------------------------------

/// The pre-#3528 shape: a shared-url test rewinding the stamp inline, with no
/// private database anywhere in the file.
#[test]
fn detector_catches_the_pre_3528_shared_stamp_rewind_3528() {
    let src = r#"
    fn postgres_url() -> Option<String> { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() }
    async fn case() {
        let url = postgres_url().unwrap();
        let store = PostgresStore::connect(&url).await.unwrap();
        sqlx::query("DELETE FROM schema_version").execute(&store.pool).await.unwrap();
        sqlx::query("INSERT INTO schema_version (version) VALUES (97)").execute(&store.pool).await.unwrap();
    }
"#;
    assert_eq!(
        shared_stamp_rewrites(src).len(),
        2,
        "both halves of the pre-#3528 rewind must be caught"
    );
}

/// The corrected shape: the same rewind, but the file creates its own
/// database. Differs from the case above ONLY by the private-database marker.
#[test]
fn detector_spares_a_private_database_rewind_3528() {
    let src = r#"
    fn postgres_url() -> Option<String> { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() }
    async fn case() {
        let admin = postgres_url().unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM schema_version").execute(&mut *tx).await.unwrap();
    }
"#;
    assert!(
        shared_stamp_rewrites(src).is_empty(),
        "a rewind on a self-created database is the sanctioned fix and must be spared"
    );
}

/// A `rusqlite` stamp rewind on a private temp FILE is a different (and
/// non-)defect — those files never reach the shared url, and there are dozens
/// of them under `src/storage/**`. Flagging them would make the gate unusable.
#[test]
fn detector_spares_a_rusqlite_private_file_rewind_3528() {
    let src = r#"
    fn case() {
        let conn = db::open(tmp.path()).unwrap();
        conn.execute("DELETE FROM schema_version", []).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (97)", []).unwrap();
    }
"#;
    assert!(
        shared_stamp_rewrites(src).is_empty(),
        "a rusqlite rewind on a private temp file must not be flagged"
    );
}

/// The PRODUCTION ladder writer is a named `const`, not an inline execution —
/// and it is the migration path, not a test. It must be spared even though it
/// lives in a file that also reaches the shared url.
#[test]
fn detector_spares_the_production_const_writer_3528() {
    let src = r#"
    fn postgres_url() -> Option<String> { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() }
    const SQL_STAMP: &str =
        "INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT (version) DO NOTHING";
"#;
    assert!(
        shared_stamp_rewrites(src).is_empty(),
        "the production named-const ladder writer must not be flagged"
    );
}

/// Reading the stamp is not mutating it.
#[test]
fn detector_spares_a_stamp_read_3528() {
    let src = r#"
    fn postgres_url() -> Option<String> { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() }
    async fn case() {
        let v: Option<i32> = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&store.pool).await.unwrap();
    }
"#;
    assert!(
        shared_stamp_rewrites(src).is_empty(),
        "a stamp READ must not be flagged"
    );
}

/// A commented-out rewind is not a rewind — this gate's own module header
/// quotes the defect verbatim.
#[test]
fn detector_spares_a_commented_out_rewind_3528() {
    let src = r#"
    fn postgres_url() -> Option<String> { std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() }
    // sqlx::query("DELETE FROM schema_version").execute(&store.pool).await.unwrap();
"#;
    assert!(
        shared_stamp_rewrites(src).is_empty(),
        "a commented-out rewind must not be flagged"
    );
}
