// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3264 — live-Postgres coverage for the fail-closed, CLASSIFIED
//! pgvector bootstrap preflight and the `schema-init` preflight fields.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (the skip-if-unset pattern shared
//! by `tests/cov_postgres_core.rs`). Point it at any of the three shapes
//! and the suite pins the matching class:
//!
//! | DSN shape | expected |
//! |---|---|
//! | non-superuser role, `vector` NOT installed | `SQLSTATE 42501` class — classified superuser-pre-create remedy |
//! | server image without `vector.so` | `SQLSTATE 0A000` class — classified image remedy (#1065) |
//! | `vector` pre-created (any role) | connect SUCCEEDS, `schema-init --json` reports the facts |
//!
//! The oracle deliberately re-derives the catalog facts with its OWN SQL
//! rather than calling the adapter's probe: a test that reuses the
//! production query cannot catch a wrong production query.

#![cfg(feature = "sal-postgres")]

use ai_memory::store::postgres::PostgresStore;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

/// Independent oracle: `(available, installed, role_is_superuser, database)`.
async fn live_catalog_facts(url: &str) -> (bool, bool, bool, String) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(20))
        .connect(url)
        .await
        .expect("connect for the independent catalog oracle");

    let ext: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT installed_version, default_version FROM pg_available_extensions \
         WHERE name = 'vector'",
    )
    .fetch_optional(&pool)
    .await
    .expect("read pg_available_extensions");

    let installed = ext
        .as_ref()
        .is_some_and(|(inst, _)| inst.as_ref().is_some());
    let available = ext.as_ref().is_some_and(|(_, def)| def.as_ref().is_some());

    let rolsuper: Option<(bool,)> =
        sqlx::query_as("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_optional(&pool)
            .await
            .expect("read pg_roles");

    let (database,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("read current_database()");

    pool.close().await;
    (
        available,
        installed,
        rolsuper.is_some_and(|(s,)| s),
        database,
    )
}

/// The end-to-end pin: whatever the live backend looks like, the bootstrap
/// outcome must match the documented decision table — and every refusal
/// must carry its remedy, never the opaque `init schema: <driver error>`.
#[tokio::test]
async fn bootstrap_classifies_the_live_pgvector_posture_3264() {
    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping (#3264 live preflight)");
        return;
    };
    let (available, installed, rolsuper, database) = live_catalog_facts(&url).await;
    let result = PostgresStore::connect(&url).await;

    if installed || (available && rolsuper) {
        assert!(
            result.is_ok(),
            "pgvector installed={installed} available={available} rolsuper={rolsuper}: \
             bootstrap must proceed unchanged, got {:?}",
            result.err()
        );
        return;
    }

    let err = match result {
        Ok(_) => panic!(
            "bootstrap SUCCEEDED with pgvector installed={installed} available={available} \
             rolsuper={rolsuper} — the fail-closed CREATE EXTENSION gate is gone"
        ),
        Err(e) => e.to_string(),
    };

    assert!(
        !err.contains("init schema:"),
        "a classifiable fault must not surface the opaque form: {err}"
    );

    if available {
        // Available on the server, absent from this database, non-superuser
        // role: the CloudNativePG / RDS / Cloud SQL shape.
        for needle in [
            "42501",
            "CREATE EXTENSION vector;",
            "postInitApplicationSQL",
            "rds_superuser",
            database.as_str(),
        ] {
            assert!(
                err.contains(needle),
                "42501 remedy must name {needle:?}: {err}"
            );
        }
    } else {
        // The server image ships no pgvector at all (#1065).
        for needle in ["0A000", "Dockerfile.pg-age-vector", "#1065"] {
            assert!(
                err.contains(needle),
                "0A000 remedy must name {needle:?}: {err}"
            );
        }
    }
}

/// `schema-init --json` reports the four preflight fields off the live
/// catalog. Only runs when the backend is actually bootstrappable (the
/// refusing shapes are pinned by the test above, which asserts the SAME
/// classified text reaches this verb through the shared connect path).
#[tokio::test]
async fn schema_init_json_reports_the_preflight_fields_3264() {
    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping (#3264 schema-init fields)");
        return;
    };
    let (available, installed, rolsuper, _db) = live_catalog_facts(&url).await;
    if !(installed || (available && rolsuper)) {
        eprintln!("backend refuses bootstrap by design — skipping the success-path field pin");
        return;
    }

    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
    let args = ai_memory::cli::schema_init::SchemaInitArgs {
        store_url: url.clone(),
        json: true,
        embedding_dim: Some(384),
        force_reembed: false,
    };
    ai_memory::cli::schema_init::run(&args, None, &mut out)
        .await
        .expect("schema-init against the live postgres");

    let raw = String::from_utf8(stdout).expect("utf-8 json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parseable JSON");
    assert_eq!(v["kind"], "postgres");
    assert_eq!(
        v["pgvector_installed"], true,
        "a bootstrapped postgres must report pgvector installed: {raw}"
    );
    assert_eq!(
        v["pgvector_available"], true,
        "an installed extension is by definition available: {raw}"
    );
    assert_eq!(
        v["role_is_superuser"],
        serde_json::Value::Bool(rolsuper),
        "role_is_superuser must match the live catalog: {raw}"
    );
    assert!(
        v["age_catalog_usage"].is_boolean(),
        "age_catalog_usage must always be reported: {raw}"
    );
}

/// Older `schema-init --json` payloads (no #3264 fields) must still parse —
/// the four fields are `#[serde(default)]`, so a downstream tool pinned to
/// a stored payload does not break.
#[test]
fn older_schema_init_json_still_parses_3264() {
    let legacy = serde_json::json!({
        "url": "postgres://u@h/db",
        "kind": "postgres",
        "tables": [],
        "views": [],
        "functions": [],
        "indices": [],
        "extensions": ["vector"],
        "schema_version": 90,
        "age_projection_created": false,
    });
    let parsed: ai_memory::cli::schema_init::SchemaInitReport =
        serde_json::from_value(legacy).expect("legacy payload must still deserialize");
    assert!(!parsed.pgvector_available);
    assert!(!parsed.pgvector_installed);
    assert!(!parsed.role_is_superuser);
    assert!(!parsed.age_catalog_usage);
}

/// `ai-memory doctor` surfaces the same preflight against a live
/// `postgres://` store. Driven as a SUBPROCESS so the `AI_MEMORY_STORE_URL`
/// the section resolves from is scoped to that process (the repo's
/// env-mutating-test doctrine), with `HOME` pointed at a scratch dir so the
/// run cannot touch a real operator database.
#[test]
fn doctor_reports_the_postgres_extensions_section_3264() {
    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping (#3264 doctor section)");
        return;
    };
    let home = tempfile::tempdir().expect("scratch HOME");
    let out = assert_cmd::Command::cargo_bin("ai-memory")
        .expect("ai-memory binary")
        .env("HOME", home.path())
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_STORE_URL", &url)
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("doctor --json parse: {e}\n"));
    let section = report["sections"]
        .as_array()
        .expect("sections array")
        .iter()
        .find(|s| {
            s["name"]
                .as_str()
                .is_some_and(|n| n.contains("Postgres extensions"))
        })
        .expect("a postgres:// store must render the Postgres extensions section");

    let facts: std::collections::HashMap<String, String> = section["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .filter_map(|kv| {
            let pair = kv.as_array()?;
            Some((
                pair.first()?.as_str()?.to_string(),
                pair.get(1)?.as_str()?.to_string(),
            ))
        })
        .collect();

    for key in [
        "pgvector_available",
        "pgvector_installed",
        "pgvector_version",
        "role_is_superuser",
        "age_installed",
        "ag_catalog_usage",
        "pgvector_verdict",
    ] {
        assert!(facts.contains_key(key), "missing fact {key}: {section}");
    }
    // The DSN reaches the report ONLY through the shared redactor, so a
    // password can never land in a pasted doctor report (#1893 / #1579 A3).
    assert_eq!(
        facts.get("store").map(String::as_str),
        Some(ai_memory::logging::redact_url_password(&url).as_str()),
        "the store fact must be the redacted DSN, verbatim"
    );

    let installed = facts.get("pgvector_installed").map(String::as_str) == Some("true");
    let superuser = facts.get("role_is_superuser").map(String::as_str) == Some("true");
    let available = facts.get("pgvector_available").map(String::as_str) == Some("true");
    if installed || (available && superuser) {
        assert_ne!(
            section["severity"], "critical",
            "a bootstrappable backend must not be CRITICAL: {section}"
        );
    } else {
        assert_eq!(
            section["severity"], "critical",
            "an unbootstrappable backend MUST be CRITICAL (doctor exit 2): {section}"
        );
        assert_eq!(out.status.code(), Some(2), "doctor must exit 2");
        let note = section["note"].as_str().expect("CRITICAL carries a note");
        assert!(
            note.contains("CREATE EXTENSION vector") || note.contains("pgvector 0.8.x"),
            "the CRITICAL note must carry the remedy: {note}"
        );
    }
}
