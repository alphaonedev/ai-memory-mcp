// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4715 - `ai-memory doctor` flags an explicit `parent_namespace` chain that
//! is already past `GOVERNANCE_CHAIN_MAX_DEPTH` (8) and names it.
//!
//! #4477 refuses every governed operation under such a chain and #4492 stops a
//! NEW bind from making one, but pre-#4477 data and imports can still hold one;
//! the doctor printed only a depth histogram, so the chain failed closed
//! silently. The cells plant raw `namespace_meta` rows (the bind path refuses
//! them) and run the real `ai-memory doctor --json` on SQLite and PG 18.6:
//!
//! - a 9-hop chain is Critical and the offending root is named, with the
//!   shortening hint and exit code 2;
//! - an 8-hop chain (the bound) is not flagged;
//! - a row that fails to read is a Critical finding, never a quiet "none".

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

mod common;

const MAX: usize = 8;

fn ai_memory(db: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let keys = db.parent().expect("db in a tempdir").join("keys-4715");
    std::fs::create_dir_all(&keys).expect("key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .args(["--db", db.to_str().expect("utf8 path")]);
    cmd
}

/// `{p}0 -> {p}1 -> ... -> {p}{hops}` as (namespace, parent) link rows.
fn chain(p: &str, hops: usize) -> Vec<(String, String)> {
    (0..hops)
        .map(|i| (format!("{p}{i}"), format!("{p}{}", i + 1)))
        .collect()
}

fn plant_sqlite(db: &std::path::Path, links: &[(String, String)]) {
    let conn = ai_memory::db::open(db).expect("open");
    for (ns, parent) in links {
        conn.execute(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
             VALUES (?1, 'ghost', '2026-10-03T00:00:00Z', ?2)",
            rusqlite::params![ns, parent],
        )
        .expect("plant link");
    }
}

fn doctor_json(db: &std::path::Path) -> (Value, i32) {
    let out = ai_memory(db)
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse: {e}\n{stdout}"));
    (v, out.status.code().unwrap_or(-1))
}

fn section<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"].as_str().is_some_and(|n| n.starts_with(name)))
        .unwrap_or_else(|| panic!("no {name} section in {report}"))
}

fn fact<'a>(section: &'a Value, key: &str) -> Option<&'a str> {
    section["facts"]
        .as_array()?
        .iter()
        .find(|f| f[0].as_str() == Some(key))
        .and_then(|f| f[1].as_str())
}

fn is_critical(s: &Value) -> bool {
    s["severity"].as_str() == Some("critical")
}

fn fresh_db() -> (TempDir, std::path::PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("ai-memory.db");
    ai_memory(&db).args(["stats"]).assert().success();
    (tmp, db)
}

// ---------------------------------------------------------------- sqlite

#[test]
fn sqlite_storage_probe_flags_nine_hops_not_eight_4715() {
    let (_t, db) = fresh_db();
    plant_sqlite(&db, &chain("n", 9));
    plant_sqlite(&db, &chain("e", MAX));
    let conn = ai_memory::db::open(&db).expect("open");
    let found = ai_memory::db::doctor_over_depth_chains(&conn).expect("census");
    let roots: Vec<(&str, usize)> = found.iter().map(|c| (c.root.as_str(), c.hops)).collect();
    assert_eq!(roots, vec![("n0", 9)], "only the 9-hop chain is over depth");
}

#[test]
fn sqlite_storage_probes_surface_a_read_fault_4715() {
    let (_t, db) = fresh_db();
    plant_sqlite(&db, &chain("n", 9));
    let conn = ai_memory::db::open(&db).expect("open");
    // A BLOB where a namespace name belongs: a row that cannot be read as text.
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
         VALUES (X'DEADBEEF', 'ghost', '2026-10-03T00:00:00Z', 'zz')",
        [],
    )
    .expect("plant unreadable row");
    assert!(
        ai_memory::db::doctor_over_depth_chains(&conn).is_err(),
        "an unreadable link row must be an error, not a shorter census"
    );
    assert!(
        ai_memory::db::doctor_governance_depth_distribution(&conn).is_err(),
        "an unreadable row must be an error, not a shorter histogram"
    );
}

#[test]
fn doctor_cli_names_a_nine_hop_chain_critical_4715() {
    let (_t, db) = fresh_db();
    plant_sqlite(&db, &chain("n", 9));
    let (report, code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert!(is_critical(gov), "9 hops must be Critical: {gov}");
    assert_eq!(fact(gov, "over_depth_chains"), Some("1"), "{gov}");
    assert!(
        fact(gov, "over_depth::n0").is_some_and(|v| v.starts_with("9 hops")),
        "the offending root and its hop count are named: {gov}"
    );
    let note = gov["note"].as_str().unwrap_or_default();
    assert!(note.contains("n0"), "note names the namespace: {note}");
    assert!(
        note.contains("Shorten each chain"),
        "note carries the shortening hint: {note}"
    );
    assert_eq!(code, 2, "a Critical section exits 2");
}

#[test]
fn doctor_cli_does_not_flag_an_eight_hop_chain_4715() {
    let (_t, db) = fresh_db();
    plant_sqlite(&db, &chain("e", MAX));
    let (report, _code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert_eq!(fact(gov, "over_depth_chains"), Some("0"), "{gov}");
    assert!(fact(gov, "over_depth::e0").is_none(), "{gov}");
    assert!(!is_critical(gov), "8 hops is the bound, not past it: {gov}");
}

#[test]
fn doctor_cli_reports_a_read_fault_critical_not_empty_4715() {
    let (_t, db) = fresh_db();
    let conn = ai_memory::db::open(&db).expect("open");
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
         VALUES (X'DEADBEEF', 'ghost', '2026-10-03T00:00:00Z', 'zz')",
        [],
    )
    .expect("plant unreadable row");
    drop(conn);
    let (report, code) = doctor_json(&db);
    let gov = section(&report, "Governance");
    assert!(is_critical(gov), "a read fault is Critical: {gov}");
    assert!(
        fact(gov, "inheritance_depth_error").is_some(),
        "the histogram fault is surfaced: {gov}"
    );
    assert_eq!(fact(gov, "over_depth_chains"), Some("unreadable"), "{gov}");
    assert_eq!(code, 2);
}

// -------------------------------------------------------------- postgres

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;

    /// One cell at a time: they share the `namespace_meta` table.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn pool(url: &str) -> sqlx::PgPool {
        // Creates the schema (migrations) through the real adapter first.
        drop(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect postgres adapter"),
        );
        sqlx::PgPool::connect(url).await.expect("raw pool")
    }

    async fn reset(pool: &sqlx::PgPool, links: &[(String, String)]) {
        sqlx::query("DELETE FROM namespace_meta WHERE parent_namespace IS NOT NULL")
            .execute(pool)
            .await
            .expect("clear links");
        for (ns, parent) in links {
            sqlx::query(
                "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) \
                 VALUES ($1, 'ghost', $2)",
            )
            .bind(ns)
            .bind(parent)
            .execute(pool)
            .await
            .expect("plant link");
        }
    }

    fn doctor_pg(url: &str) -> (Value, i32) {
        let tmp = TempDir::new().expect("tempdir");
        let db = tmp.path().join("ai-memory.db");
        let out = ai_memory(&db)
            .env("AI_MEMORY_STORE_URL", url)
            .args(["doctor", "--json"])
            .output()
            .expect("run doctor");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let v = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse: {e}\n{stdout}"));
        (v, out.status.code().unwrap_or(-1))
    }

    const NAME: &str = "Governance chain depth";

    #[tokio::test]
    async fn pg_probe_flags_nine_hops_not_eight_4715() {
        let Some(url) = common::postgres_url() else {
            return;
        };
        let _s = SERIAL.lock().await;
        let pool = pool(&url).await;
        reset(&pool, &[chain("n", 9), chain("e", MAX)].concat()).await;
        let found = ai_memory::store::postgres::list_over_depth_chains_pg(&pool)
            .await
            .expect("census");
        let roots: Vec<(&str, usize)> = found.iter().map(|c| (c.root.as_str(), c.hops)).collect();
        assert_eq!(roots, vec![("n0", 9)]);
        reset(&pool, &[]).await;
    }

    #[tokio::test]
    async fn pg_probe_surfaces_a_read_fault_4715() {
        let Some(url) = common::postgres_url() else {
            return;
        };
        let _s = SERIAL.lock().await;
        let pool = pool(&url).await;
        pool.close().await;
        assert!(
            ai_memory::store::postgres::list_over_depth_chains_pg(&pool)
                .await
                .is_err(),
            "a closed pool must be an error, not an empty census"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pg_doctor_names_a_nine_hop_chain_and_clears_at_eight_4715() {
        let Some(url) = common::postgres_url() else {
            return;
        };
        let _s = SERIAL.lock().await;
        let pool = pool(&url).await;
        reset(&pool, &chain("n", 9)).await;
        let (report, code) = tokio::task::spawn_blocking({
            let url = url.clone();
            move || doctor_pg(&url)
        })
        .await
        .expect("join");
        let sec = section(&report, NAME);
        assert!(is_critical(sec), "9 hops must be Critical: {sec}");
        assert!(
            fact(sec, "over_depth::n0").is_some_and(|v| v.starts_with("9 hops")),
            "{sec}"
        );
        let note = sec["note"].as_str().unwrap_or_default();
        assert!(
            note.contains("n0") && note.contains("Shorten each chain"),
            "{note}"
        );
        assert_eq!(code, 2);

        reset(&pool, &chain("e", MAX)).await;
        let (report, _) = tokio::task::spawn_blocking(move || doctor_pg(&url))
            .await
            .expect("join");
        let sec = section(&report, NAME);
        assert_eq!(fact(sec, "over_depth_chains"), Some("0"), "{sec}");
        assert!(!is_critical(sec), "{sec}");
        reset(&pool, &[]).await;
    }

    /// A store whose `namespace_meta` cannot be read is Critical in the
    /// section, never an empty census: the probe runs against a database that
    /// exists but has no schema.
    #[tokio::test(flavor = "multi_thread")]
    async fn pg_doctor_reports_a_read_fault_critical_4715() {
        let Some(url) = common::postgres_url() else {
            return;
        };
        let _s = SERIAL.lock().await;
        let admin = sqlx::PgPool::connect(&url).await.expect("admin pool");
        // Ignore "already exists": the cell only needs the empty database.
        let _ = sqlx::query("CREATE DATABASE f1_4715_nometa")
            .execute(&admin)
            .await;
        let bare = url.replacen("/f1_4715?", "/f1_4715_nometa?", 1);
        if bare == url {
            eprintln!("skip: the test URL does not name database f1_4715");
            return;
        }
        let (report, code) = tokio::task::spawn_blocking(move || doctor_pg(&bare))
            .await
            .expect("join");
        let sec = section(&report, NAME);
        assert!(is_critical(sec), "an unreadable census is Critical: {sec}");
        assert_eq!(fact(sec, "over_depth_chains"), Some("unreadable"), "{sec}");
        assert!(fact(sec, "over_depth_chains_error").is_some(), "{sec}");
        assert_eq!(code, 2);
    }

    /// The section connects through the same #3705 sslmode floor as the store
    /// funnel: a weak DSN is refused in THIS section with the sibling's
    /// "REFUSED to connect" shape (#4333). Other doctor probes own their own
    /// socket behaviour, so the cell asserts the refusal, not a global socket
    /// count.
    #[test]
    fn pg_doctor_section_is_floored_and_refuses_weak_sslmode_4715() {
        let (report, _) = doctor_pg("postgres://u:pw4715@127.0.0.1:9/db?sslmode=prefer");
        let sec = section(&report, NAME);
        assert!(is_critical(sec), "{sec}");
        assert!(sec.to_string().contains("REFUSED to connect"), "{sec}");
        assert!(
            fact(sec, "over_depth_chains").is_none(),
            "no census was run: {sec}"
        );
    }
}
