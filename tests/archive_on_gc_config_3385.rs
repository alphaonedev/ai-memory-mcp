// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3385 — `[storage].archive_on_gc` must GOVERN garbage collection,
//! not merely parse.
//!
//! ## The defect these tests pin closed
//!
//! `AppConfig::effective_archive_on_gc()` — the resolver every GC consumer
//! calls (`ai-memory gc`, the `gc_if_needed` hot-path sites in CLI
//! recall/store/crud/io, MCP `memory_gc` + `memory_forget`, the serve GC
//! loop) — read the DEPRECATED flat `archive_on_gc` key ALONE, while
//! `AppConfig::resolve_storage()` read the documented v2
//! `[storage].archive_on_gc`. The two disagreed, silently, in both
//! directions:
//!
//! - `[storage].archive_on_gc = false` (crypto-erase-on-expiry) was IGNORED
//!   by the GC path, so expired memories kept a recoverable archive copy the
//!   operator had explicitly asked to be rid of.
//! - `[storage].archive_on_gc = true` sitting next to a stale flat
//!   `archive_on_gc = false` let the flat key win, so the TTL sweep
//!   PERMANENTLY HARD-DELETED expired memories with no archive and no
//!   rollback — data loss against an explicit instruction to keep a copy.
//!
//! ## What is asserted
//!
//! 1. [`resolver_precedence_and_source_3385`] — the resolution ladder
//!    (`[storage]` > deprecated flat key > compiled `true`), that
//!    `effective_archive_on_gc()` and `resolve_storage().archive_on_gc` now
//!    AGREE on every placement (the split itself is the bug), and the
//!    provenance `doctor` reports.
//! 2. [`cli_gc_honours_v2_archive_policy_3385`] — the same matrix driven
//!    through the REAL `ai-memory gc` path against a real SQLite store: the
//!    DENIED path (`false` -> no `archived_memories` row) and the ALLOWED
//!    path (`true` -> archived), plus the `doctor` facts and the deprecation
//!    WARN. Asserting the resolver alone would not have caught the original
//!    defect, because the resolver `resolve_storage()` was already correct —
//!    it was the consuming path that was wrong.
//! 3. [`pg_gc_honours_v2_archive_policy_3385`] — the PostgreSQL twin of (2)
//!    over `MemoryStore::run_gc`, gated on `AI_MEMORY_TEST_POSTGRES_URL`.
//!    Deliberately NOT `#[ignore]`: the PR postgres job does not pass
//!    `--include-ignored`, so an ignored test silently never runs.

use ai_memory::config::{AppConfig, ConfigSource};
use std::process::Command;

/// `(config body, expected effective archive_on_gc, expected source)`.
///
/// Covers both placements, both values, the section-present-but-key-absent
/// case, and BOTH conflict directions — the conflict rows are the data-loss
/// ones, since pre-#3385 the flat key won them.
const CASES: &[(&str, bool, ConfigSource)] = &[
    ("", true, ConfigSource::CompiledDefault),
    ("[storage]\n", true, ConfigSource::CompiledDefault),
    ("archive_on_gc = false\n", false, ConfigSource::Legacy),
    ("archive_on_gc = true\n", true, ConfigSource::Legacy),
    (
        "[storage]\narchive_on_gc = false\n",
        false,
        ConfigSource::Config,
    ),
    (
        "[storage]\narchive_on_gc = true\n",
        true,
        ConfigSource::Config,
    ),
    (
        "archive_on_gc = false\n[storage]\n",
        false,
        ConfigSource::Legacy,
    ),
    // Conflict: [storage] wins. Pre-#3385 the flat `true` won and the
    // operator's `false` (crypto-erase) was silently ignored.
    (
        "archive_on_gc = true\n[storage]\narchive_on_gc = false\n",
        false,
        ConfigSource::Config,
    ),
    // Conflict, the data-LOSS direction: pre-#3385 the flat `false` won and
    // the operator's `true` (keep a restorable copy) was silently ignored,
    // so expiry hard-deleted with no rollback.
    (
        "archive_on_gc = false\n[storage]\narchive_on_gc = true\n",
        true,
        ConfigSource::Config,
    ),
];

/// A per-case scratch home under the repo's `.local-runs/` (never `/tmp`,
/// never the operator's real `~/.config/ai-memory`).
fn sandbox() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

#[test]
fn resolver_precedence_and_source_3385() {
    for (body, expected, source) in CASES {
        // Precedence must not depend on `schema_version`: an operator who
        // never wrote the version line still gets `[storage]` honoured.
        for version in ["", "schema_version = 2\n"] {
            let text = format!("{version}{body}");
            let config: AppConfig = toml::from_str(&text).expect("valid config");
            assert_eq!(
                config.effective_archive_on_gc(),
                *expected,
                "effective_archive_on_gc for:\n{text}"
            );
            // #3385 IS this equality: the two resolvers disagreeing is the
            // whole defect, so pin them together on every placement.
            assert_eq!(
                config.resolve_storage().archive_on_gc,
                *expected,
                "resolve_storage().archive_on_gc for:\n{text}"
            );
            assert_eq!(
                &config.archive_on_gc_source(),
                source,
                "archive_on_gc_source for:\n{text}"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn cli_gc_honours_v2_archive_policy_3385() {
    for (body, archive, source) in CASES {
        let archive = *archive;
        let dir = sandbox();
        let config_root = dir.path().join(".config").join("ai-memory");
        std::fs::create_dir_all(&config_root).expect("create config root");
        std::fs::write(
            config_root.join("config.toml"),
            format!("schema_version = 2\ntier = \"keyword\"\n{body}"),
        )
        .expect("write config");

        let db_path = dir.path().join("gc.db");
        let conn = ai_memory::db::open(&db_path).expect("open isolated sqlite");
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, source, \
                                   created_at, updated_at, expires_at) \
             VALUES ('expired-3385', 'short', 'test-3385', 'expired', 'body', 'test', \
                     '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00', \
                     '2020-01-01T00:00:00+00:00')",
            [],
        )
        .expect("seed expired memory");
        drop(conn);

        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_ai-memory"))
                .env_clear()
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("HOME", dir.path())
                .env("XDG_CONFIG_HOME", dir.path().join(".config"))
                .env(
                    "AI_MEMORY_KEY_DIR",
                    ai_memory::identity::test_key_dir::install(),
                )
                .current_dir(dir.path())
                .arg("--db")
                .arg(&db_path)
                .args(args)
                .output()
                .expect("run isolated CLI")
        };

        let gc = run(&["gc", "--json"]);
        assert!(
            gc.status.success(),
            "gc failed for:\n{body}\n{}",
            String::from_utf8_lossy(&gc.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&gc.stdout).expect("gc JSON");
        assert_eq!(
            result["expired_deleted"], 1,
            "gc must reap the fixture:\n{body}"
        );

        let conn = ai_memory::db::open(&db_path).expect("reopen isolated sqlite");
        let live: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = 'expired-3385'",
                [],
                |r| r.get(0),
            )
            .expect("count live rows");
        assert_eq!(live, 0, "expired row must leave active storage:\n{body}");
        let archived: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM archived_memories WHERE id = 'expired-3385'",
                [],
                |r| r.get(0),
            )
            .expect("count archived rows");
        assert_eq!(
            archived,
            i64::from(archive),
            "GC archive retention must follow the EFFECTIVE policy ({archive}) for:\n{body}"
        );
        drop(conn);

        // The deprecation WARN must reach an operator running a plain CLI
        // command (no tracing subscriber is installed there).
        let gc_stderr = String::from_utf8_lossy(&gc.stderr);
        let flat_set = body.starts_with("archive_on_gc");
        let section_set = body.contains("[storage]\narchive_on_gc");
        if flat_set && !section_set {
            assert!(
                gc_stderr.contains("WARN") && gc_stderr.contains("DEPRECATED"),
                "flat key in effect must WARN:\n{body}\n{gc_stderr}"
            );
            assert!(
                gc_stderr.contains("[storage]"),
                "WARN must name the migration destination:\n{body}\n{gc_stderr}"
            );
        } else if flat_set && section_set {
            assert!(
                gc_stderr.contains("conflicting"),
                "disagreeing keys must WARN:\n{body}\n{gc_stderr}"
            );
        } else {
            assert!(
                !gc_stderr.contains("DEPRECATED"),
                "v2-only / default config must not emit the flat-key WARN:\n{body}\n{gc_stderr}"
            );
        }

        // `doctor` must report the effective value AND which layer set it.
        let doctor = run(&["doctor", "--json"]);
        let report: serde_json::Value =
            serde_json::from_slice(&doctor.stdout).expect("doctor JSON");
        let configuration = report["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .find(|s| s["name"] == "Configuration")
            .expect("Configuration section");
        let facts = configuration["facts"].as_array().expect("facts");
        let fact = |key: &str| {
            facts
                .iter()
                .find(|f| f[0] == key)
                .and_then(|f| f[1].as_str())
                .map(str::to_string)
        };
        let expected_value = archive.to_string();
        assert_eq!(
            fact("archive_on_gc").as_deref(),
            Some(expected_value.as_str()),
            "doctor must report the effective policy for:\n{body}\n{configuration}"
        );
        assert_eq!(
            fact("archive_on_gc_source").as_deref(),
            Some(source.as_str()),
            "doctor must report the policy provenance for:\n{body}\n{configuration}"
        );
    }
}

/// PostgreSQL twin of [`cli_gc_honours_v2_archive_policy_3385`]: the daemon's
/// pg GC tick calls `store.run_gc(app_config.effective_archive_on_gc())`, so
/// pin that composition against a live store.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_gc_honours_v2_archive_policy_3385() {
    use ai_memory::models::{Memory, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return;
        }
    };
    let ctx = CallerContext::for_agent("archive-on-gc-3385");

    for (body, archive, _) in CASES {
        let archive = *archive;
        let config: AppConfig = toml::from_str(body).expect("valid config");
        assert_eq!(
            config.effective_archive_on_gc(),
            archive,
            "resolver disagreement for:\n{body}"
        );

        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let past = (now - chrono::Duration::hours(1)).to_rfc3339();
        let mem = Memory {
            id: id.clone(),
            tier: Tier::Short,
            namespace: "test-3385".to_string(),
            title: format!("expired-{id}"),
            content: "body".to_string(),
            source: "test".to_string(),
            created_at: past.clone(),
            updated_at: past.clone(),
            expires_at: Some(past),
            ..Memory::default()
        };
        MemoryStore::store(&store, &ctx, &mem)
            .await
            .expect("seed expired memory");

        // The composition under test — exactly the daemon's pg GC tick.
        let reaped = MemoryStore::run_gc(&store, config.effective_archive_on_gc())
            .await
            .expect("run_gc");
        assert!(reaped >= 1, "run_gc must reap the fixture for:\n{body}");

        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .expect("live probe");
        assert!(!live, "expired row must leave active storage for:\n{body}");

        let archived: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM archived_memories WHERE id = $1)")
                .bind(&id)
                .fetch_one(store.pool())
                .await
                .expect("archive probe");
        assert_eq!(
            archived, archive,
            "pg GC archive retention must follow the EFFECTIVE policy for:\n{body}"
        );

        // Leave the live-pg fixture clean for the next case / next run.
        let _ = sqlx::query("DELETE FROM archived_memories WHERE id = $1")
            .bind(&id)
            .execute(store.pool())
            .await;
    }
}
