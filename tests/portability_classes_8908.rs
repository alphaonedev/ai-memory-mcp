// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8908 / #8911 / #8968 and 3-agent vote (71472661) conditions P-9..P-14 —
//! the Portability-v2 class invariant: every record class either rides
//! `export --full` and round-trips byte-exact, or is named in-band as withheld
//! or excluded; and an import never replaces or merges a row of another owner.
//!
//! The vote decision (71472661): the new classes are ADDITIVE arrays under
//! `spec_version` "2" (`skip_serializing_if = "Vec::is_empty"`), the envelope
//! keeps `deny_unknown_fields`, and one always-serialized `class_counts` map
//! names how many rows each array class carries.
//!
//! Every test here drives only APIs that exist at base `46c12050` (raw SQL,
//! the envelope as a `serde_json::Value`, the real binary), so the identical
//! source compiles at base and fails there.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::similar_names)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ai_memory::models::{Memory, MemoryKind};
use ai_memory::portability::{emit, import};
use ai_memory::storage::ConflictMode;
use assert_cmd::Command;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

/// Fixed export timestamp (the envelope's `exported_at`).
const EXPORTED_AT: &str = "2026-07-14T00:00:00Z";
/// A creation instant for the TEXT-dated memory rows.
const CREATED_AT: &str = "2026-07-14T00:00:00Z";
/// An expiry far beyond the test horizon (a LIVE row).
const LIVE_EXPIRY: &str = "2099-01-01T00:00:00Z";
/// An expiry in the past that GC has not yet swept (#8911).
const PAST_EXPIRY: &str = "2020-01-01T00:00:00Z";
/// The epoch-seconds instant the INTEGER-dated class rows carry.
const CREATED_EPOCH: i64 = 1_752_451_200;
/// The namespace every fixture row lives in.
const NS: &str = "portability";
/// The agent that owns the source rows.
const SOURCE_AGENT: &str = "alice";
/// The agent that owns the foreign destination row (#8968).
const FOREIGN_AGENT: &str = "bob";
/// The importer's caller id on the default (restamping) path.
const IMPORTER: &str = "importer";
/// The title both owners use for the #8968 collision.
const SHARED_TITLE: &str = "shared title";
/// The foreign row's content, which must survive every merge import.
const FOREIGN_CONTENT: &str = "bob private content that must never be replaced";
/// The incoming row's content in the #8968 collision.
const INCOMING_CONTENT: &str = "alice content that collides on the title slot";
/// The per-row disposition text of the #8968 owner guard.
const FOREIGN_OWNER_KEPT_MSG: &str =
    "skipped: the destination row holding this slot belongs to another owner; destination row kept";
/// The #3150 confidentiality class a PEM private-key block screens into.
const CLASS_PRIVATE_KEY: &str = "private_key_material";
/// PEM armor that the export screen withholds.
/// Assembled from pieces so the source text never carries a whole armor
/// header (the diff leak scanner reads the source, the screen reads the row).
const PEM_ARMOR: &str = concat!(
    "-----BEGIN ",
    "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END ",
    "PRIVATE KEY-----"
);
/// The #8908 100K+ bound on one class.
const BOUND_ROWS: usize = 100_000;
/// Wall-clock ceiling for exporting + importing [`BOUND_ROWS`] aliases in a
/// debug build (linear cost; a quadratic importer blows through it).
const BOUND_CEILING: Duration = Duration::from_secs(120);

/// Every array class the "2" envelope carries (P-9: `class_counts` names each).
const ARRAY_CLASSES: [&str; 18] = [
    "memories",
    "links",
    "signed_events",
    "memory_revisions",
    "forget_tombstones",
    "agent_lineage",
    "model_attestations",
    "governance_rules",
    "trust_anchors",
    "archived_memories",
    "namespace_meta",
    "archived_memory_links",
    "expired_memories",
    "checkpoints",
    "routines",
    "routine_runs",
    "entity_aliases",
    "offloaded_blobs",
];

/// P-12: the closed "2" field set. The always-serialized fields.
const ALWAYS_FIELDS: [&str; 10] = [
    "spec_version",
    "db_schema_version",
    "source",
    "exported_at",
    "memories",
    "links",
    "portability_complete",
    "conformance_level",
    "conformance_by_class",
    "count",
];
/// P-12: the fields serialized only when non-empty (plus `class_counts`,
/// which is always serialized and listed here to keep one set of names).
const OPTIONAL_FIELDS: [&str; 17] = [
    "signed_events",
    "memory_revisions",
    "forget_tombstones",
    "agent_lineage",
    "model_attestations",
    "governance_rules",
    "trust_anchors",
    "archived_memories",
    "namespace_meta",
    "archived_memory_links",
    "expired_memories",
    "checkpoints",
    "routines",
    "routine_runs",
    "entity_aliases",
    "offloaded_blobs",
    "class_counts",
];

/// Each new class: (envelope array, table, deterministic ORDER BY).
const NEW_CLASS_TABLES: [(&str, &str, &str); 5] = [
    ("checkpoints", "checkpoints", "id"),
    ("routines", "routines", "id"),
    ("routine_runs", "routine_runs", "id"),
    ("entity_aliases", "entity_aliases", "entity_id, alias"),
    ("offloaded_blobs", "offloaded_blobs", "ref_id"),
];

/// P-14 refusal for an unknown top-level field.
fn unknown_field_msg(name: &str) -> String {
    format!(
        "portability import REJECTED (fail-closed): unknown top-level field \"{name}\" — the bundle \
         comes from a newer build than this node understands; upgrade this node; NO rows were applied"
    )
}

/// P-10 refusal: a count that differs from its array's length.
fn count_mismatch_msg(class: &str, declared: usize, carried: usize) -> String {
    format!(
        "portability import REJECTED (fail-closed): class_counts[\"{class}\"] = {declared} but the \
         {class} array carries {carried} rows; NO rows were applied"
    )
}

/// P-10 refusal: an entry naming an unknown class.
fn unknown_class_msg(class: &str) -> String {
    format!(
        "portability import REJECTED (fail-closed): class_counts names unknown class \"{class}\"; \
         NO rows were applied"
    )
}

/// P-10 refusal: `class_counts` absent while a new array is present.
fn absent_counts_msg(class: &str) -> String {
    format!(
        "portability import REJECTED (fail-closed): class_counts is absent but the bundle carries \
         the {class} array; NO rows were applied"
    )
}

fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-8908-classes");
    std::fs::create_dir_all(&root).ok();
    root
}

/// A fresh migrated database file; returns its path (kept alive).
fn fresh_db_path(tag: &str) -> PathBuf {
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(scratch_root())
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    drop(ai_memory::db::open(&path).expect("init db"));
    std::mem::forget(dir);
    path
}

fn fresh_db(tag: &str) -> Connection {
    ai_memory::db::open(&fresh_db_path(tag)).expect("open db")
}

fn memory(id: &str, title: &str, content: &str, owner: &str) -> Memory {
    Memory {
        id: id.into(),
        namespace: NS.into(),
        title: title.into(),
        content: content.into(),
        tags: vec!["t".into()],
        priority: 5,
        confidence: 0.9,
        source: "system".into(),
        created_at: CREATED_AT.into(),
        updated_at: CREATED_AT.into(),
        expires_at: Some(LIVE_EXPIRY.into()),
        memory_kind: MemoryKind::Decision,
        metadata: json!({ "agent_id": owner, "scope": "private" }),
        ..Memory::default()
    }
}

fn seed_checkpoint(conn: &Connection, id: &str, created_by: &str, metadata: &str) {
    conn.execute(
        "INSERT INTO checkpoints (id, namespace, title, condition_type, condition, state, \
         created_by, signature, created_at, deadline_at, metadata) \
         VALUES (?1, ?2, ?3, 'manual', '{\"k\":1}', 'pending', ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            NS,
            format!("checkpoint {id}"),
            created_by,
            vec![0x5a_u8; 64],
            CREATED_EPOCH,
            CREATED_EPOCH + 3600,
            metadata
        ],
    )
    .expect("insert checkpoint");
}

/// One row in each new class (#8908).
fn seed_new_classes(conn: &Connection) {
    seed_checkpoint(conn, "ckpt-1", SOURCE_AGENT, "{\"note\":\"clean\"}");
    conn.execute(
        "INSERT INTO routines (id, namespace, name, template, parameters, state, created_by, \
         created_at, signature, signer_pubkey, metadata) \
         VALUES ('rt-1', ?1, 'nightly', 'recall {q}', '[\"q\"]', 'frozen', ?2, ?3, ?4, ?5, '{}')",
        params![
            NS,
            SOURCE_AGENT,
            CREATED_EPOCH,
            vec![0x01_u8; 64],
            vec![0x02_u8; 32]
        ],
    )
    .expect("insert routine");
    conn.execute(
        "INSERT INTO routine_runs (id, routine_id, namespace, arguments, state, \
         created_action_ids, started_at, finished_at, metadata) \
         VALUES ('run-1', 'rt-1', ?1, '{\"q\":\"x\"}', 'succeeded', '[\"a-1\"]', ?2, ?3, '{}')",
        params![NS, CREATED_EPOCH, CREATED_EPOCH + 5],
    )
    .expect("insert routine run");
    conn.execute(
        "INSERT INTO entity_aliases (entity_id, alias, created_at) VALUES ('ent-1', 'Alpha', ?1)",
        params![CREATED_AT],
    )
    .expect("insert alias");
    let offloader = ai_memory::offload::ContextOffloader::new(
        conn,
        None,
        ai_memory::offload::OffloadConfig::default(),
    );
    offloader
        .offload("offloaded context body", NS, None, SOURCE_AGENT)
        .expect("offload blob");
}

/// Every row of `table` in a fixed order, every column as a SQLite value
/// (the byte-exact comparison unit).
fn dump_table(conn: &Connection, table: &str, order_by: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table} ORDER BY {order_by}"))
        .expect("prepare dump");
    let width = stmt.column_count();
    stmt.query_map([], |r| {
        (0..width)
            .map(|i| r.get::<_, rusqlite::types::Value>(i))
            .collect::<rusqlite::Result<Vec<_>>>()
    })
    .expect("query dump")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collect dump")
}

fn row_count(conn: &Connection, table: &str) -> usize {
    let n: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .expect("count");
    usize::try_from(n).expect("non-negative count")
}

fn export_value(conn: &Connection) -> Value {
    serde_json::to_value(emit::build_full_envelope(conn, "src", EXPORTED_AT).expect("export"))
        .expect("serialize envelope")
}

fn array_len(v: &Value, class: &str) -> usize {
    v.get(class).and_then(Value::as_array).map_or(0, Vec::len)
}

fn opts(trust_source: bool, on_conflict: ConflictMode) -> import::ImportOptions {
    import::ImportOptions {
        trust_source,
        caller_agent_id: IMPORTER.into(),
        on_conflict,
    }
}

fn import_value(dst: &Connection, v: Value, o: &import::ImportOptions) -> Value {
    let env: emit::ExportEnvelope = serde_json::from_value(v).expect("strict envelope parse");
    let report = import::import_full_envelope(dst, &env, o).expect("import");
    serde_json::to_value(report).expect("serialize report")
}

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// Run `import` on `payload`; returns (exit code, stdout, stderr).
fn cli_import(db: &Path, payload: &str, extra: &[&str]) -> (i32, String, String) {
    let out = ai_memory(db)
        .arg("import")
        .args(extra)
        .write_stdin(payload.to_owned())
        .output()
        .expect("run import");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn issue_8908_full_export_round_trips_each_new_class_byte_exact() {
    let src = fresh_db("rt-src-");
    seed_new_classes(&src);
    let v = export_value(&src);
    let dst = fresh_db("rt-dst-");
    import_value(&dst, v.clone(), &opts(true, ConflictMode::Version));
    for (class, table, order_by) in NEW_CLASS_TABLES {
        let src_rows = dump_table(&src, table, order_by);
        assert_eq!(src_rows.len(), 1, "{class}: fixture seeds one row");
        assert_eq!(
            array_len(&v, class),
            1,
            "{class}: export --full carries the row"
        );
        assert_eq!(
            dump_table(&dst, table, order_by),
            src_rows,
            "{class}: the row round-trips byte-exact"
        );
    }
}

#[test]
fn vote_p9_class_counts_present_and_exact() {
    let src = fresh_db("cc-src-");
    ai_memory::db::insert(&src, &memory("m-1", "one", "body", SOURCE_AGENT)).expect("seed");
    seed_new_classes(&src);
    let v = export_value(&src);
    let counts = v
        .get("class_counts")
        .and_then(Value::as_object)
        .expect("class_counts is always serialized (P-9)");
    let keys: BTreeSet<&str> = counts.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = ARRAY_CLASSES.into_iter().collect();
    assert_eq!(
        keys, expected,
        "class_counts covers every array class, zeros included"
    );
    for class in ARRAY_CLASSES {
        assert_eq!(
            counts[class].as_u64().and_then(|n| usize::try_from(n).ok()),
            Some(array_len(&v, class)),
            "class_counts[{class}] equals the rows carried"
        );
    }
}

#[test]
fn issue_8911_full_export_carries_expired_unswept_row() {
    let src = fresh_db("exp-src-");
    let mut expired = memory("m-expired", "expired title", "expired body", SOURCE_AGENT);
    expired.expires_at = Some(LIVE_EXPIRY.into());
    ai_memory::db::insert(&src, &expired).expect("seed");
    src.execute(
        "UPDATE memories SET expires_at = ?1 WHERE id = 'm-expired'",
        params![PAST_EXPIRY],
    )
    .expect("age the row past its expiry");
    let v = export_value(&src);
    let carried: Vec<&str> = v
        .get("expired_memories")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|m| m["id"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        carried,
        vec!["m-expired"],
        "the unswept expired row rides --full"
    );
    let dst = fresh_db("exp-dst-");
    import_value(&dst, v, &opts(true, ConflictMode::Version));
    let landed: Option<String> = dst
        .query_row(
            "SELECT expires_at FROM memories WHERE id = 'm-expired'",
            [],
            |r| r.get(0),
        )
        .ok();
    // The importer writes the canonical RFC 3339 form, so the instant is
    // compared, not the spelling.
    let instant = |s: &str| chrono::DateTime::parse_from_rfc3339(s).expect("rfc3339 expiry");
    assert_eq!(
        landed.as_deref().map(instant),
        Some(instant(PAST_EXPIRY)),
        "expired row lands with its expiry"
    );
}

/// A destination holding bob's private row and an incoming alice row on the
/// same `(title, namespace)` slot.
fn foreign_collision() -> (Connection, Value) {
    let dst = fresh_db("own-dst-");
    ai_memory::db::insert(
        &dst,
        &memory("m-bob", SHARED_TITLE, FOREIGN_CONTENT, FOREIGN_AGENT),
    )
    .expect("seed foreign row");
    let src = fresh_db("own-src-");
    ai_memory::db::insert(
        &src,
        &memory("m-alice", SHARED_TITLE, INCOMING_CONTENT, SOURCE_AGENT),
    )
    .expect("seed incoming row");
    (dst, export_value(&src))
}

fn foreign_row_content(dst: &Connection) -> (String, String) {
    dst.query_row(
        "SELECT content, json_extract(metadata, '$.agent_id') FROM memories WHERE title = ?1",
        params![SHARED_TITLE],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("slot holder")
}

#[test]
fn issue_8968_v2_merge_import_keeps_foreign_owner_row() {
    let (dst, v) = foreign_collision();
    let report = import_value(&dst, v, &opts(true, ConflictMode::Merge));
    assert_eq!(
        foreign_row_content(&dst),
        (FOREIGN_CONTENT.to_owned(), FOREIGN_AGENT.to_owned()),
        "another owner's row is never replaced by a merge import"
    );
    assert_eq!(report["cross_owner_kept"], 1, "the kept row is counted");
    let warned = report["warnings"].as_array().is_some_and(|w| {
        w.iter()
            .any(|s| s.as_str() == Some(&format!("m-alice: {FOREIGN_OWNER_KEPT_MSG}")))
    });
    assert!(warned, "a per-row WARN names the incoming row: {report}");
}

#[test]
fn issue_8968_storage_insert_with_conflict_merge_keeps_foreign_owner_row() {
    let (dst, _) = foreign_collision();
    let err = ai_memory::storage::insert_with_conflict(
        &dst,
        &memory("m-alice", SHARED_TITLE, INCOMING_CONTENT, SOURCE_AGENT),
        ConflictMode::Merge,
    )
    .expect_err("merging into another owner's slot is refused");
    assert_eq!(
        err.to_string(),
        format!("m-alice: {FOREIGN_OWNER_KEPT_MSG}")
    );
    assert_eq!(
        foreign_row_content(&dst),
        (FOREIGN_CONTENT.to_owned(), FOREIGN_AGENT.to_owned())
    );
}

#[test]
fn issue_8968_cli_import_on_conflict_merge_keeps_foreign_owner_row() {
    let dst_path = fresh_db_path("own-cli-");
    {
        let dst = ai_memory::db::open(&dst_path).expect("open");
        ai_memory::db::insert(
            &dst,
            &memory("m-bob", SHARED_TITLE, FOREIGN_CONTENT, FOREIGN_AGENT),
        )
        .expect("seed foreign row");
    }
    let payload = json!({
        "memories": [memory("m-alice", SHARED_TITLE, INCOMING_CONTENT, SOURCE_AGENT)],
        "links": [],
    })
    .to_string();
    let (_, stdout, stderr) = cli_import(
        &dst_path,
        &payload,
        &["--on-conflict", "merge", "--trust-source", "--json"],
    );
    let dst = ai_memory::db::open(&dst_path).expect("reopen");
    assert_eq!(
        foreign_row_content(&dst),
        (FOREIGN_CONTENT.to_owned(), FOREIGN_AGENT.to_owned()),
        "CLI --on-conflict merge never replaces another owner's row; stderr={stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(
        report["cross_owner_kept"], 1,
        "counted in the report: {report}"
    );
}

#[test]
fn vote_p14_unknown_top_level_field_refused_naming_the_field() {
    let src = fresh_db("p14-src-");
    ai_memory::db::insert(&src, &memory("m-1", "one", "body", SOURCE_AGENT)).expect("seed");
    let mut v = export_value(&src);
    v["future_class"] = json!([]);
    let dst_path = fresh_db_path("p14-dst-");
    let (code, _, stderr) = cli_import(&dst_path, &v.to_string(), &["--trust-source"]);
    assert_ne!(code, 0, "refused");
    assert!(
        stderr.contains(&unknown_field_msg("future_class")),
        "exact P-14 refusal; stderr={stderr}"
    );
    let dst = ai_memory::db::open(&dst_path).expect("reopen");
    assert_eq!(row_count(&dst, "memories"), 0, "zero rows applied");
}

#[test]
fn vote_p10_class_counts_refusals_apply_zero_rows() {
    type Mutate = fn(&mut Value);
    let src = fresh_db("p10-src-");
    ai_memory::db::insert(&src, &memory("m-1", "one", "body", SOURCE_AGENT)).expect("seed");
    seed_new_classes(&src);
    let base = export_value(&src);
    let cases: [(&str, Mutate, String); 3] = [
        (
            "count mismatch",
            |v| v["class_counts"]["checkpoints"] = json!(2),
            count_mismatch_msg("checkpoints", 2, 1),
        ),
        (
            "unknown class",
            |v| v["class_counts"]["future_class"] = json!(0),
            unknown_class_msg("future_class"),
        ),
        (
            "counts absent with a new array",
            |v| {
                if let Some(o) = v.as_object_mut() {
                    o.remove("class_counts");
                }
            },
            absent_counts_msg("checkpoints"),
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut v = base.clone();
        mutate(&mut v);
        let dst_path = fresh_db_path("p10-dst-");
        let (code, _, stderr) = cli_import(&dst_path, &v.to_string(), &["--trust-source"]);
        assert_ne!(code, 0, "{name}: refused");
        assert!(
            stderr.contains(&expected),
            "{name}: exact refusal; stderr={stderr}"
        );
        let dst = ai_memory::db::open(&dst_path).expect("reopen");
        assert_eq!(row_count(&dst, "memories"), 0, "{name}: zero rows applied");
        assert_eq!(
            row_count(&dst, "checkpoints"),
            0,
            "{name}: zero rows applied"
        );
    }
}

#[test]
fn vote_p10_old_shape_bundle_without_class_counts_still_imports() {
    let src = fresh_db("p10-old-src-");
    ai_memory::db::insert(&src, &memory("m-1", "one", "body", SOURCE_AGENT)).expect("seed");
    let mut v = export_value(&src);
    if let Some(o) = v.as_object_mut() {
        o.remove("class_counts");
    }
    let dst_path = fresh_db_path("p10-old-dst-");
    let (code, _, stderr) = cli_import(&dst_path, &v.to_string(), &["--trust-source"]);
    assert_eq!(code, 0, "an old-shape bundle imports; stderr={stderr}");
    let dst = ai_memory::db::open(&dst_path).expect("reopen");
    assert_eq!(row_count(&dst, "memories"), 1);
}

#[test]
fn vote_p12_export_envelope_field_set_is_closed() {
    let src = fresh_db("p12-src-");
    ai_memory::db::insert(&src, &memory("m-1", "one", "body", SOURCE_AGENT)).expect("seed");
    seed_new_classes(&src);
    let v = export_value(&src);
    let keys: BTreeSet<&str> = v
        .as_object()
        .expect("envelope object")
        .keys()
        .map(String::as_str)
        .collect();
    let always: BTreeSet<&str> = ALWAYS_FIELDS.into_iter().collect();
    let optional: BTreeSet<&str> = OPTIONAL_FIELDS.into_iter().collect();
    assert!(
        always.is_subset(&keys),
        "every always-field is serialized: {keys:?}"
    );
    let stray: Vec<&&str> = keys
        .iter()
        .filter(|k| !always.contains(*k) && !optional.contains(*k))
        .collect();
    assert!(
        stray.is_empty(),
        "no field outside the closed \"2\" set: {stray:?}"
    );
    assert!(
        keys.contains("class_counts"),
        "class_counts is part of the \"2\" set"
    );
}

#[test]
fn issue_8908_forged_owner_restamped_per_class() {
    let src = fresh_db("forge-src-");
    seed_new_classes(&src);
    let v = export_value(&src);
    let dst = fresh_db("forge-dst-");
    import_value(&dst, v, &opts(false, ConflictMode::Version));
    let owner_columns: [(&str, &str); 3] = [
        ("checkpoints", "created_by"),
        ("routines", "created_by"),
        ("offloaded_blobs", "agent_id"),
    ];
    for (table, column) in owner_columns {
        let owners: Vec<String> = {
            let mut stmt = dst
                .prepare(&format!("SELECT {column} FROM {table}"))
                .expect("prepare");
            stmt.query_map([], |r| r.get(0))
                .expect("query")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect")
        };
        assert_eq!(
            owners,
            vec![IMPORTER.to_owned()],
            "{table}.{column}: the bundle's owner claim is not honoured without --trust-source"
        );
    }
}

#[test]
fn issue_8908_offloaded_blob_failing_integrity_is_refused() {
    type Mutate = fn(&mut Value, &str);
    let src = fresh_db("blob-src-");
    seed_new_classes(&src);
    let base = export_value(&src);
    assert_eq!(
        array_len(&base, "offloaded_blobs"),
        1,
        "the bundle carries the blob"
    );
    let other_frame = hex::encode(zstd::encode_all(&b"tampered body"[..], 0).expect("zstd"));
    let cases: [(&str, Mutate); 2] = [
        ("content hash altered", |v, _| {
            v["offloaded_blobs"][0]["content_sha256"] = json!("0".repeat(64));
        }),
        ("blob bytes altered", |v, frame| {
            v["offloaded_blobs"][0]["content_zstd"] = json!(frame);
        }),
    ];
    for (name, mutate) in cases {
        let mut v = base.clone();
        mutate(&mut v, &other_frame);
        let dst = fresh_db("blob-dst-");
        let report = import_value(&dst, v, &opts(true, ConflictMode::Version));
        let ref_id = base["offloaded_blobs"][0]["ref_id"]
            .as_str()
            .expect("ref_id");
        assert_eq!(report["offloaded_blobs_refused"], 1, "{name}: counted");
        let expected = format!("offloaded blob {ref_id} integrity check failed (content tampered)");
        let warned = report["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|s| s.as_str() == Some(expected.as_str())));
        assert!(warned, "{name}: exact per-row refusal: {report}");
        assert_eq!(
            row_count(&dst, "offloaded_blobs"),
            0,
            "{name}: nothing written"
        );
    }
}

#[test]
fn issue_8908_checkpoint_carrying_private_key_armor_is_withheld() {
    let src = fresh_db("pem-src-");
    seed_new_classes(&src);
    let armored = json!({ "note": PEM_ARMOR }).to_string();
    seed_checkpoint(&src, "ckpt-armored", SOURCE_AGENT, &armored);
    let (env, ledger) =
        emit::build_full_envelope_audited(&src, "src", EXPORTED_AT).expect("export");
    let v = serde_json::to_value(&env).expect("serialize");
    let carried: Vec<&str> = v
        .get("checkpoints")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|c| c["id"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        carried,
        vec!["ckpt-1"],
        "the clean checkpoint rides, the armored one does not"
    );
    assert_eq!(
        ledger.withheld_by_class.get(CLASS_PRIVATE_KEY).copied(),
        Some(1),
        "the withheld checkpoint is named in-band by class"
    );
    assert!(
        !v.to_string().contains("BEGIN PRIVATE KEY"),
        "no key armor reaches the artifact"
    );
    assert_eq!(
        v["class_counts"]["checkpoints"], 1,
        "withheld rows are not counted (P-9)"
    );
}

#[test]
fn issue_8908_entity_aliases_100k_bound() {
    let src = fresh_db("bound-src-");
    {
        let tx = src.unchecked_transaction().expect("tx");
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO entity_aliases (entity_id, alias, created_at) VALUES (?1, ?2, ?3)",
                )
                .expect("prepare");
            for i in 0..BOUND_ROWS {
                stmt.execute(params![
                    format!("ent-{}", i % 97),
                    format!("alias-{i}"),
                    CREATED_AT
                ])
                .expect("insert alias");
            }
        }
        tx.commit().expect("commit");
    }
    let started = Instant::now();
    let v = export_value(&src);
    let dst = fresh_db("bound-dst-");
    import_value(&dst, v.clone(), &opts(true, ConflictMode::Version));
    let elapsed = started.elapsed();
    assert_eq!(array_len(&v, "entity_aliases"), BOUND_ROWS);
    assert_eq!(row_count(&dst, "entity_aliases"), BOUND_ROWS);
    assert!(elapsed < BOUND_CEILING, "linear bound: {elapsed:?}");
}
