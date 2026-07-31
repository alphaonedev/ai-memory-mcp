// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// The module docs below narrate the defect in prose, naming SQLite and
// Postgres as products rather than as code items. Matches the established
// `tests/` precedent for prose-heavy regression docs (see
// `tests/backup_fail_closed_2444.rs`).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #2490 — `export` / `export --full` / `import` must never report
//! success over an operation that did not happen.
//!
//! # The defects these tests pin
//!
//! #2444 made `backup` / `restore` fail closed when the resolved store is
//! Postgres. The sibling verbs in `src/cli/io.rs` carried the identical
//! shape, plus three losses of their own. All five were reproduced by
//! EXECUTION against the parent commit `b2a9f5bd`, not by reading:
//!
//! 1. **Postgres false-success (all three verbs).** With
//!    `AI_MEMORY_STORE_URL=postgres://…` and no `--db` file present,
//!    `export` exited 0, CREATED an 802,816-byte SQLite database, and
//!    emitted `{"count":0,"memories":[],"links":[]}`. `export --full` was
//!    worse — the conjured file bootstraps real default governance rules, so
//!    the v2 envelope carried `db_schema_version: 87`, four
//!    `governance_rules` and a `trust_anchor` wrapped around `memories: []`,
//!    and printed nothing at all on stderr. `import` exited 0 reporting
//!    `{"imported":1}` into the same conjured file; the served Postgres
//!    store never sees the row, so the write is not "diverged" — it is
//!    simply LOST at the moment the operator is told it landed.
//!
//! 2. **Non-existent database conjured on export.** Even with no store URL,
//!    `db::open` creates the file and runs the whole migration ladder, so
//!    the created database is not distinguishable from a real one by any
//!    schema probe. Non-existence is the only honest discriminator and the
//!    first invocation destroys it.
//!
//! 3. **Silent partial export.** A database holding three live memories —
//!    one carrying a PEM private key, one carrying an AWS key + a GitHub
//!    token, one clean — exported `count: 2`, exit 0, with the PEM row
//!    DROPPED entirely and the credential row's content silently MUTATED to
//!    `aws key [REDACTED:secret] token [REDACTED:secret]`. Nothing on stderr
//!    mentioned either. Because `count == memories.len()` always, the
//!    artifact is fully SELF-CONSISTENT: the loss is unfalsifiable from the
//!    bundle alone, which is why an out-of-band count is mandatory rather
//!    than a nicety.
//!
//! 4. **Total silent link loss on import.** The pre-fix loop was
//!    `if validate_link(..).is_err() { continue; }` then
//!    `let _ = db::create_link(..)`, and links were never counted in the
//!    report at all. A bundle whose link had a missing endpoint imported as
//!    `{"imported":1,"errors":[]}`, exit 0, EMPTY stderr, zero links landed.
//!    Same for an unrecognised relation. A restore whose entire graph
//!    vanished reported success.
//!
//! 5. **Import exits 0 with a non-empty `errors` array.** Every per-row
//!    refusal was reported and then discarded.
//!
//! # Why these tests drive the BINARY
//!
//! R-203 requires the regression to FAIL against the parent commit and PASS
//! after. Everything asserted here is reachable through the shipped CLI —
//! no new struct field is referenced — so the identical source compiles and
//! runs against `b2a9f5bd`, where the store-guard, exit-code and
//! link-accounting assertions all fail.
//!
//! Spawning a subprocess also keeps every `AI_MEMORY_*` mutation out of the
//! test process, so nothing here races the shared `config::test_env_lock()`
//! discipline (#2127 / #2146).

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// A Postgres DSN carrying a password, so the refusal path is also asserted
/// to REDACT the credential rather than echo it (#1579 A3).
const PG_STORE_URL: &str = "postgres://ai_memory:hunter2@127.0.0.1:5433/ai_memory_test";

/// The literal secret inside [`PG_STORE_URL`]; must never appear in output.
const PG_PASSWORD: &str = "hunter2";

/// Exit code for "artifact written but INCOMPLETE" — deliberately distinct
/// from 1 so an orchestrator can branch on it.
const EXIT_INCOMPLETE: i32 = 3;

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Seed a real single-row SQLite corpus so the control cases exercise a
/// genuine export rather than an empty one.
fn seed(db: &Path, title: &str, content: &str) {
    ai_memory(db)
        .args([
            "store",
            "--title",
            title,
            "--content",
            content,
            "--namespace",
            "probe",
            "--tier",
            "long",
        ])
        .assert()
        .success();
}

// ── 1. Postgres false-success — all three verbs ─────────────────────────

/// THE #2490 REGRESSION, `export`. A Postgres-configured deployment must
/// ERROR and leave NO conjured database behind.
///
/// Against the parent commit this fails on every assertion: exit 0, the
/// placeholder file is created, and a `count: 0` artifact lands on stdout.
#[test]
fn export_on_a_postgres_store_refuses_and_creates_no_database_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("placeholder.db");

    let assert = ai_memory(&db)
        .env("AI_MEMORY_STORE_URL", PG_STORE_URL)
        .arg("export")
        .assert()
        .failure();

    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("pg_dump"),
        "the refusal must name the supported Postgres path; stderr was: {stderr}"
    );
    assert!(
        !stderr.contains(PG_PASSWORD),
        "the refusal leaked the DSN password; stderr was: {stderr}"
    );
    assert!(
        !db.exists(),
        "FAIL CLOSED: export must not conjure a SQLite database at {}",
        db.display()
    );
    assert!(
        !stdout.contains("\"count\""),
        "no export artifact may be emitted on the refusal path; stdout was: {stdout}"
    );
}

/// Same for `export --full`, which is strictly worse pre-fix: the conjured
/// database bootstraps real default governance rules, so the emitted v2
/// envelope looks like a legitimate export of a real deployment.
#[test]
fn export_full_on_a_postgres_store_refuses_and_creates_no_database_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("placeholder.db");

    let assert = ai_memory(&db)
        .env("AI_MEMORY_STORE_URL", PG_STORE_URL)
        .args(["export", "--full"])
        .assert()
        .failure();

    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("pg_dump"),
        "the refusal must name the supported Postgres path; stderr was: {stderr}"
    );
    assert!(!stderr.contains(PG_PASSWORD), "refusal leaked the password");
    assert!(!db.exists(), "export --full must not conjure a database");
    assert!(
        !stdout.contains("spec_version"),
        "no v2 envelope may be emitted on the refusal path; stdout was: {stdout}"
    );
}

/// Same for `import` — the WRITE half, and the sharper one: pre-fix the row
/// was reported as imported while landing in a file the served store never
/// reads.
#[test]
fn import_on_a_postgres_store_refuses_and_writes_nothing_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("placeholder.db");

    let assert = ai_memory(&db)
        .env("AI_MEMORY_STORE_URL", PG_STORE_URL)
        .args(["import", "--json"])
        .write_stdin(bundle_one_memory())
        .assert()
        .failure();

    let output = assert.get_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("pg_dump"),
        "the refusal must name the supported Postgres path; stderr was: {stderr}"
    );
    assert!(!stderr.contains(PG_PASSWORD), "refusal leaked the password");
    assert!(!db.exists(), "import must not conjure a SQLite database");
    assert!(
        !stdout.contains("\"imported\""),
        "no success report may be emitted on the refusal path; stdout was: {stdout}"
    );
}

/// The WRITE-verb disagreement rule. `resolve_sqlite_source` REDIRECTS a
/// `sqlite://` URL that disagrees with `--db` (correct for a read), but the
/// documented posture is to `export AI_MEMORY_STORE_URL` at shell/cron
/// scope — so reusing that disposition on `import` would send a scratch
/// import into the deployment's real database behind a one-line `note:`.
/// `import` must REFUSE instead.
#[test]
fn import_refuses_a_sqlite_store_url_that_disagrees_with_db_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let scratch = tmp.path().join("scratch.db");
    let production = tmp.path().join("production.db");
    seed(&production, "prod row", "must not be touched");

    let assert = ai_memory(&scratch)
        .env(
            "AI_MEMORY_STORE_URL",
            format!("sqlite://{}", production.display()),
        )
        .args(["import", "--json"])
        .write_stdin(bundle_one_memory())
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("Refusing"),
        "an ambiguous WRITE target must be refused, never redirected; stderr was: {stderr}"
    );
    assert!(
        !scratch.exists(),
        "the refused import must not create the scratch database"
    );
}

// ── 2. Export against a database that does not exist ────────────────────

#[test]
fn export_refuses_to_conjure_a_missing_database_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("absent.db");

    let assert = ai_memory(&db).arg("export").assert().failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("refusing to create one"),
        "the refusal must explain that a conjured database yields a valid-looking \
         empty artifact; stderr was: {stderr}"
    );
    assert!(!db.exists(), "the database must NOT have been created");
}

/// CONTROL — a genuine SQLite export still succeeds, exits 0, and emits a
/// complete artifact. Without this the refusal tests could pass for the
/// wrong reason (the #2449 harness lesson: exit-127 and early-abort both
/// "fail" too).
#[test]
fn genuine_sqlite_export_still_succeeds_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("real.db");
    seed(&db, "kept row", "ordinary content");

    let assert = ai_memory(&db).arg("export").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");

    assert_eq!(v["count"].as_u64(), Some(1));
    assert_eq!(v["withheld"]["withheld"].as_u64(), Some(0));
    assert_eq!(v["withheld"]["redacted"].as_u64(), Some(0));
    // #2490 truthfulness fix — neither export mode reads these tables, and
    // the scope marker must say so.
    let excludes = v["excludes"].as_array().expect("excludes array");
    for class in ["archived_memories", "namespace_meta"] {
        assert!(
            excludes.iter().any(|c| c.as_str() == Some(class)),
            "the excludes marker must name {class}; got {excludes:?}"
        );
    }
}

// ── 3 + 4 + 5. Round-trip fidelity, loudly ──────────────────────────────

/// FIELD-BY-FIELD round-trip fidelity, not a row count. A count-only
/// assertion is precisely how this class hides.
#[test]
fn export_import_round_trip_preserves_every_field_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");

    ai_memory(&src)
        .args([
            "store",
            "--title",
            "M1 full shape",
            "--content",
            "content one",
            "--namespace",
            "probe",
            "--tier",
            "long",
            "--priority",
            "9",
            "--confidence",
            "0.87",
            "--source",
            "user",
            "--tags",
            "alpha,beta",
            "--kind",
            "claim",
            "--source-uri",
            "uri:https://example.com/doc",
            "--source-span",
            r#"{"start":0,"end":10}"#,
            "--valid-from",
            "2026-01-01T00:00:00Z",
            "--valid-until",
            "2027-01-01T00:00:00Z",
        ])
        .assert()
        .success();

    let exported = ai_memory(&src).arg("export").assert().success();
    let payload = String::from_utf8_lossy(&exported.get_output().stdout).into_owned();

    ai_memory(&dst)
        .args(["import", "--trust-source", "--json"])
        .write_stdin(payload.clone())
        .assert()
        .success();

    let re_exported = ai_memory(&dst).arg("export").assert().success();
    let after = String::from_utf8_lossy(&re_exported.get_output().stdout).into_owned();

    let before: serde_json::Value = serde_json::from_str(payload.trim()).expect("before JSON");
    let after: serde_json::Value = serde_json::from_str(after.trim()).expect("after JSON");
    let b = &before["memories"].as_array().expect("before rows")[0];
    let a = &after["memories"].as_array().expect("after rows")[0];

    // Every Memory field the wire form carries, asserted individually.
    // `version` is deliberately EXCLUDED: it is a destination-local CAS
    // counter that the merge path increments rather than adopting, so
    // carrying the source value would inject a foreign counter into the
    // destination's optimistic-concurrency lineage. `cid` is likewise
    // excluded — it commits to `agent_id`, so a re-mint at the destination
    // is correct-by-design (the narrow `--trust-source`-on-an-edited-row
    // residue belongs to #2385).
    for field in [
        "id",
        "tier",
        "namespace",
        "title",
        "content",
        "tags",
        "priority",
        "confidence",
        "source",
        "created_at",
        "memory_kind",
        "citations",
        "source_uri",
        "source_span",
        "confidence_source",
        "valid_from",
        "valid_until",
        "lifecycle_state",
    ] {
        assert_eq!(
            b.get(field),
            a.get(field),
            "field `{field}` did not round-trip: {:?} -> {:?}",
            b.get(field),
            a.get(field)
        );
    }
}

/// Links must round-trip AND be counted. Pre-fix the report never mentioned
/// links at all.
#[test]
fn import_reports_links_it_applied_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");
    seed(&src, "A", "alpha");
    seed(&src, "B", "beta");

    let ids = row_ids(&src);
    assert_eq!(ids.len(), 2, "fixture must have two rows");

    ai_memory(&src)
        .args(["link", &ids[0], &ids[1], "--relation", "related_to"])
        .assert()
        .success();

    let exported = ai_memory(&src).arg("export").assert().success();
    let payload = String::from_utf8_lossy(&exported.get_output().stdout).into_owned();

    let assert = ai_memory(&dst)
        .args(["import", "--trust-source", "--json"])
        .write_stdin(payload)
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("report JSON");

    assert_eq!(report["imported"].as_u64(), Some(2));
    assert_eq!(
        report["links_imported"].as_u64(),
        Some(1),
        "the import report must state how many edges actually landed; report was {report}"
    );
    assert_eq!(report["links_refused"].as_u64(), Some(0));
}

/// THE SILENT-LINK-LOSS REGRESSION. A bundle whose edge names an
/// unrecognised relation must be REPORTED and must make the command exit
/// non-zero. Pre-fix: `{"imported":2,"errors":[]}`, exit 0, empty stderr,
/// zero links landed.
#[test]
fn import_refuses_loudly_when_a_link_cannot_be_applied_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");
    seed(&src, "A", "alpha");
    seed(&src, "B", "beta");

    let exported = ai_memory(&src).arg("export").assert().success();
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&exported.get_output().stdout).expect("bundle JSON");
    let ids: Vec<String> = bundle["memories"]
        .as_array()
        .expect("rows")
        .iter()
        .filter_map(|m| m["id"].as_str().map(ToOwned::to_owned))
        .collect();
    bundle["links"] = serde_json::json!([{
        "source_id": ids[0],
        "target_id": ids[1],
        "relation": "bogus_relation",
        "created_at": "2026-01-01T00:00:00Z",
    }]);

    let assert = ai_memory(&dst)
        .args(["import", "--trust-source", "--json"])
        .write_stdin(bundle.to_string())
        .assert()
        .code(EXIT_INCOMPLETE);

    let output = assert.get_output();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        report["links_refused"].as_u64(),
        Some(1),
        "the unapplied edge must be COUNTED, not swallowed; report was {report}"
    );
    assert_eq!(report["links_imported"].as_u64(), Some(0));
    assert!(
        stderr.contains("INCOMPLETE"),
        "the operator must be told the destination is not a faithful copy; stderr was: {stderr}"
    );
}

/// The same for an edge whose endpoint is absent from the bundle — the
/// dangling-endpoint half of the silent loss.
#[test]
fn import_refuses_loudly_when_a_link_endpoint_is_missing_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("src.db");
    let dst = tmp.path().join("dst.db");
    seed(&src, "A", "alpha");
    seed(&src, "B", "beta");

    let ids = row_ids(&src);
    ai_memory(&src)
        .args(["link", &ids[0], &ids[1], "--relation", "related_to"])
        .assert()
        .success();

    let exported = ai_memory(&src).arg("export").assert().success();
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&exported.get_output().stdout).expect("bundle JSON");
    // Keep the edge, drop one endpoint.
    let first = bundle["memories"].as_array().expect("rows")[0].clone();
    bundle["memories"] = serde_json::json!([first]);

    let assert = ai_memory(&dst)
        .args(["import", "--trust-source", "--json"])
        .write_stdin(bundle.to_string())
        .assert()
        .code(EXIT_INCOMPLETE);
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("report JSON");

    assert_eq!(report["links_imported"].as_u64(), Some(0));
    assert_eq!(
        report["links_refused"].as_u64(),
        Some(1),
        "a dangling edge must be counted, not silently dropped; report was {report}"
    );
}

/// CONTROL — a clean bundle imports with exit 0 and no refusals, so the
/// non-zero assertions above cannot be passing for a trivial reason.
#[test]
fn clean_import_still_exits_zero_2490() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("dst.db");

    let assert = ai_memory(&db)
        .args(["import", "--trust-source", "--json"])
        .write_stdin(bundle_one_memory())
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("report JSON");

    assert_eq!(report["imported"].as_u64(), Some(1));
    assert_eq!(report["refused"].as_u64(), Some(0));
    assert_eq!(report["links_refused"].as_u64(), Some(0));
}

/// Ids of every live row in `db`, read back through `export` (the only
/// surface that returns the whole corpus as a flat array).
fn row_ids(db: &Path) -> Vec<String> {
    let exported = ai_memory(db).arg("export").assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&exported.get_output().stdout).expect("export JSON");
    v["memories"]
        .as_array()
        .expect("memories array")
        .iter()
        .filter_map(|m| m["id"].as_str().map(ToOwned::to_owned))
        .collect()
}

/// A minimal, valid v1 bundle carrying exactly one memory and no links.
fn bundle_one_memory() -> String {
    serde_json::json!({
        "memories": [{
            "id": "11111111-1111-4111-8111-111111111111",
            "tier": "long",
            "namespace": "probe",
            "title": "bundle row",
            "content": "bundle content",
            "tags": [],
            "priority": 5,
            "confidence": 0.9,
            "source": "cli",
            "access_count": 0,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "metadata": {},
            "reflection_depth": 0,
            "memory_kind": "observation",
            "citations": [],
            "confidence_source": "caller_provided"
        }],
        "links": []
    })
    .to_string()
}
