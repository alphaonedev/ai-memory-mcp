// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 GA — end-user migration capability pin: a real v0.6.4 database
//! upgrades to v0.7.0 **losslessly and idempotently**.
//!
//! Context (operator directive, 2026-06-05): end users will migrate from
//! ai-memory v0.6.4 to ai-memory v0.7.0, and the migration technical
//! capability must be verified at 100%. Per the documented schema SSOT
//! (`docs/MIGRATION_v0.7.md`, `docs/reference/ARCHITECTURE_REFERENCE.md` §Database), v0.6.4 ships logical
//! schema **v33** (the last v0.6.x bump — the first v0.7.0-era upgrade
//! arm is `if version < 34` in `src/storage/migrations.rs`) and v0.7.0
//! ships **v57** (`current_schema_version_for_tests()`).
//!
//! The existing ladder tests prove structural completeness:
//! `migrations.rs::tests::migrate_brings_v0_to_current` proves the
//! v0→v55 ladder reaches the current head against a full-schema DB, and
//! per-column tests (`wt_1_a_schema_migration`, `form_4_provenance`,
//! `form_5_confidence_calibration`, the v28→v29 rewind in
//! `recursive_learning_task7_shipgate_chaos_migration`) prove individual
//! `ALTER TABLE ADD COLUMN` arms execute on a legacy column-absent DB.
//!
//! What was NOT pinned — and what this file adds — is the **end-user
//! contract**: that a v0.6.4 DB carrying *real, multi-row data plus
//! links*, stamped at the v33 baseline, survives the full v34→v55
//! upgrade span with every row and edge preserved byte-equal (lossless),
//! the schema stamped at v55, FTS still functional, and a second open a
//! no-op (idempotent).
//!
//! Two fidelity levels:
//!   1. `v064_baseline_data_survives_full_v070_upgrade_*` — data seeded
//!      under the full schema, schema_version rewound to v33; proves the
//!      ladder is data-preserving + idempotent across the whole span.
//!   2. `v064_legacy_rows_physically_lacking_v070_columns_*` — the
//!      v0.7.0 columns are physically dropped (faithful v0.6.4 on-disk
//!      shape), then the rewind+reopen drives the real `ADD COLUMN`
//!      arms; proves legacy rows survive column re-addition and receive
//!      the documented backfill defaults.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::SECS_PER_DAY;
use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use chrono::{Duration, Utc};
use rusqlite::Connection;
use serde_json::json;

/// Last v0.6.x logical schema version. A released v0.6.4 binary stamps a
/// fresh DB at this version; the first v0.7.0-era upgrade arm in
/// `src/storage/migrations.rs` is `if version < 34`. Anchored to the
/// documented schema SSOT, NOT a bare literal scattered through asserts.
const V064_BASELINE_SCHEMA_VERSION: i64 = 33;

/// The v102 (#8341) abort guards on `memories`; their bodies read
/// `NEW.encrypted_envelope`, so a column-absent rewind drops them first.
const V102_PROJECTION_GUARD_TRIGGERS: [&str; 2] = [
    "agent_pubkey_history_projection_guard_insert",
    "agent_pubkey_history_projection_guard_update",
];

/// The closed-taxonomy relation used for the seeded edges. Any member of
/// the v0.7.0 `MemoryLinkRelation` taxonomy works; `related_to` is the
/// neutral choice and avoids the directional semantics of `supersedes` /
/// `derived_from`.
const SEED_LINK_RELATION: &str = "related_to";

/// A representative v0.6.4-era memory. Only the original v0.6.x columns
/// carry meaningful data; the v0.7.0 columns are left at their struct
/// defaults so the row mirrors what a v0.6.4 writer would have produced.
///
/// All timestamps derive from a single write-time instant (`now`) rather
/// than fixed calendar strings: `created_at`/`updated_at` are the write
/// time, `last_accessed_at` is one day later, and `expires_at` is derived
/// from the tier's own TTL contract (`Tier::default_ttl_secs`) — so a
/// Long row is permanent (`None`) and short/mid carry the tier-defined
/// expiry. This keeps the v54 tier-default-expiry backfill arm a no-op for
/// these rows (it only touches NULL-expiry rows) without pinning any magic
/// date literal.
fn v064_era_memory(id: &str, tier: Tier, namespace: &str, title: &str, body: &str) -> Memory {
    let now = Utc::now();
    let written_at = now.to_rfc3339();
    let last_accessed_at = Some((now + Duration::seconds(SECS_PER_DAY)).to_rfc3339());
    let expires_at = tier
        .default_ttl_secs()
        .map(|ttl_secs| (now + Duration::seconds(ttl_secs)).to_rfc3339());
    Memory {
        id: id.to_string(),
        tier,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: body.to_string(),
        tags: vec!["v064".to_string(), "upgrade".to_string()],
        priority: 6,
        confidence: 0.75,
        source: "v064-seed".to_string(),
        access_count: 2,
        created_at: written_at.clone(),
        updated_at: written_at,
        last_accessed_at,
        expires_at,
        metadata: json!({"agent_id": "ai:v064-user", "origin": "v0.6.4"}),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    }
}

/// Stable fingerprint of every memory row, ordered by id, capturing the
/// v0.6.x columns an end user cares about. Equality of two fingerprints
/// across a migration boundary == lossless for those columns.
fn memory_fingerprint(conn: &Connection) -> Vec<(String, String, String, String, String, i32)> {
    let mut rows = db::list(
        conn, None, None, 10_000, 0, None, None, None, None, None, None,
    )
    .expect("list all memories");
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows.into_iter()
        .map(|m| {
            (
                m.id,
                m.namespace,
                m.title,
                m.content,
                m.tier.as_str().to_string(),
                m.priority,
            )
        })
        .collect()
}

/// Read the highest stamped schema version.
fn stamped_version(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .expect("read schema_version")
}

/// Rewind the schema-version stamp to the v0.6.4 baseline so the next
/// `db::open` drives the v34→v55 upgrade arms exactly as a real v0.6.4
/// DB would on first open under a v0.7.0 binary.
fn rewind_to_v064_baseline(conn: &Connection) {
    conn.execute("DELETE FROM schema_version", [])
        .expect("clear schema_version");
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![V064_BASELINE_SCHEMA_VERSION],
    )
    .expect("stamp v0.6.4 baseline");
}

/// The four v0.6.4-era rows + two edges the data-preservation tests seed.
/// Returns the seeded ids in insert order.
fn seed_v064_corpus(conn: &Connection) -> Vec<String> {
    let rows = [
        v064_era_memory(
            "v064-long-001",
            Tier::Long,
            "alpha",
            "deployment runbook",
            "restart the federation daemon then verify quorum acks",
        ),
        v064_era_memory(
            "v064-mid-002",
            Tier::Mid,
            "alpha",
            "postgres tuning note",
            "raise the connection pool ceiling before the nightly batch",
        ),
        v064_era_memory(
            "v064-short-003",
            Tier::Short,
            "beta",
            "scratch reminder",
            "ping the operator about the pending key enrolment",
        ),
        v064_era_memory(
            "v064-long-004",
            Tier::Long,
            "beta",
            "architecture decision",
            "audit chain signing moved off the request thread",
        ),
    ];
    let mut ids = Vec::new();
    for m in &rows {
        ids.push(db::insert(conn, m).expect("seed v0.6.4 row"));
    }
    // Two edges so the migration's link-table handling is exercised too.
    db::create_link(conn, &ids[0], &ids[1], SEED_LINK_RELATION).expect("seed edge 1");
    db::create_link(conn, &ids[3], &ids[2], SEED_LINK_RELATION).expect("seed edge 2");
    ids
}

#[test]
fn v064_baseline_data_survives_full_v070_upgrade_lossless_and_idempotent() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();

    // 1. Seed a realistic v0.6.4 corpus under the full schema, then
    //    rewind the version stamp to the v0.6.4 baseline.
    let before_fp;
    let seeded_ids;
    {
        let conn = db::open(&path).expect("first open installs schema");
        seeded_ids = seed_v064_corpus(&conn);
        before_fp = memory_fingerprint(&conn);
        rewind_to_v064_baseline(&conn);
        assert_eq!(
            stamped_version(&conn),
            V064_BASELINE_SCHEMA_VERSION,
            "precondition: DB must read as v0.6.4 baseline before upgrade"
        );
    }

    // 2. Re-open: this is the real end-user upgrade path — the v34→v55
    //    ladder runs against a v33-stamped DB carrying live data.
    let conn = db::open(&path).expect("db::open upgrades v0.6.4 → v0.7.0");

    // 3a. Schema reached the v0.7.0 head.
    assert_eq!(
        stamped_version(&conn),
        db::current_schema_version_for_tests(),
        "upgrade must stamp the DB at the v0.7.0 head schema"
    );

    // 3b. Lossless: every row's v0.6.x columns are byte-equal.
    let after_fp = memory_fingerprint(&conn);
    assert_eq!(
        after_fp, before_fp,
        "v0.6.4 → v0.7.0 upgrade dropped or mutated row data (not lossless)"
    );
    assert_eq!(
        after_fp.len(),
        seeded_ids.len(),
        "row count changed across the upgrade"
    );

    // 3c. Every seeded row is individually retrievable with its body intact.
    for id in &seeded_ids {
        let got = db::get(&conn, id)
            .expect("get seeded row")
            .unwrap_or_else(|| panic!("row {id} vanished across the upgrade"));
        assert_eq!(&got.id, id);
        // v45 optimistic-concurrency stamp backfills to 1 on legacy rows.
        assert!(
            got.version >= 1,
            "legacy row {id} must carry a valid version stamp post-upgrade; got {}",
            got.version
        );
    }

    // 3d. Edges preserved.
    let edges_from_first = db::get_links(&conn, &seeded_ids[0]).expect("links for first row");
    assert!(
        edges_from_first
            .iter()
            .any(|l| l.target_id == seeded_ids[1]),
        "seeded edge {} -> {} lost across the upgrade",
        seeded_ids[0],
        seeded_ids[1]
    );

    // 3e. FTS still functional after the upgrade — search the body text.
    let hits = db::search(
        &conn, "quorum", None, None, 10, None, None, None, None, None, None, false, None,
    )
    .expect("FTS search post-upgrade");
    assert!(
        hits.iter().any(|m| m.id == seeded_ids[0]),
        "FTS index did not survive the upgrade (term 'quorum' missed its row)"
    );

    // 4. Idempotent: a second open is a no-op — version unchanged, data
    //    unchanged.
    drop(conn);
    let conn2 = db::open(&path).expect("second open is a no-op upgrade");
    assert_eq!(
        stamped_version(&conn2),
        db::current_schema_version_for_tests(),
        "second open must not drift the schema version"
    );
    assert_eq!(
        memory_fingerprint(&conn2),
        before_fp,
        "second open mutated data — migrate is not idempotent"
    );
}

#[test]
fn v064_legacy_rows_physically_lacking_v070_columns_upgrade_losslessly() {
    // Faithful v0.6.4 on-disk shape: physically remove a representative
    // span of v0.7.0-added `memories` columns so the rewind+reopen drives
    // the *real* `ALTER TABLE ADD COLUMN` arms (v37/v38/v39/v42/v44/v45),
    // not the column-already-present skip path. The atom_of column (v36)
    // is intentionally retained: it carries a self-referential FOREIGN
    // KEY, which SQLite forbids dropping — its add-arm is already pinned
    // by `wt_1_a_schema_migration`.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();

    let before_fp;
    let seeded_ids;
    {
        let conn = db::open(&path).expect("first open installs schema");
        seeded_ids = seed_v064_corpus(&conn);
        before_fp = memory_fingerprint(&conn);

        // Drop indexes that would otherwise block DROP COLUMN, then the
        // v0.7.0 columns themselves. DROP INDEX IF EXISTS is tolerant of
        // naming; column drops are existence-checked so the test is
        // resilient to schema reshuffles.
        // Mirror the proven legacy-reshape order in
        // `connection.rs::open_succeeds_on_legacy_pre_v36_memories_shape`:
        // every index that references a to-be-dropped column must go first,
        // including the cross-table `idx_personas_by_entity` (on `entity_id`)
        // and `idx_memories_confidence_source` — SQLite re-checks ALL index
        // definitions on `DROP COLUMN` and errors if any still references the
        // vanished column. `IF EXISTS` keeps extras harmless.
        for idx in [
            "idx_memories_atom_of",
            "idx_memories_atomised_into",
            "idx_personas_by_entity",
            "idx_memories_source_uri",
            "idx_memories_confidence_source",
            "idx_memories_mentioned_entity",
            "idx_memories_mentioned_entity_id",
        ] {
            conn.execute(&format!("DROP INDEX IF EXISTS {idx}"), [])
                .unwrap_or_else(|e| panic!("drop index {idx}: {e}"));
        }
        // A real v0.6.4 database carries none of the v102 projection guards
        // (#8341), and SQLite re-checks every trigger body on DROP COLUMN:
        // the guards read NEW.encrypted_envelope, so they go first. The
        // ladder re-installs them on the re-open (asserted below).
        for trigger in V102_PROJECTION_GUARD_TRIGGERS {
            conn.execute(&format!("DROP TRIGGER IF EXISTS {trigger}"), [])
                .unwrap_or_else(|e| panic!("drop trigger {trigger}: {e}"));
        }
        let droppable_v070_columns = [
            "atomised_into",         // v36 (index dropped above)
            "entity_id",             // v37
            "persona_version",       // v37
            "citations",             // v38
            "source_uri",            // v38 (partial index dropped above)
            "source_span",           // v38
            "confidence_source",     // v39
            "confidence_signals",    // v39
            "confidence_decayed_at", // v39
            "mentioned_entity_id",   // v42 (index dropped above)
            "encrypted_envelope",    // v44
            "version",               // v45
        ];
        for col in droppable_v070_columns {
            if column_present(&conn, "memories", col) {
                conn.execute(&format!("ALTER TABLE memories DROP COLUMN {col}"), [])
                    .unwrap_or_else(|e| panic!("drop column {col}: {e}"));
            }
        }

        // Precondition: at least one representative column is physically
        // gone, so the upgrade must really re-add it.
        assert!(
            !column_present(&conn, "memories", "version"),
            "rewind must physically remove the v45 version column"
        );

        rewind_to_v064_baseline(&conn);
    }

    // Re-open: the v34→v55 ladder runs and the ADD COLUMN arms execute
    // against legacy rows that genuinely lack the columns.
    let conn = db::open(&path).expect("db::open upgrades column-absent v0.6.4 DB");

    assert_eq!(
        stamped_version(&conn),
        db::current_schema_version_for_tests(),
        "upgrade of a column-absent legacy DB must reach the v0.7.0 head"
    );

    // The v102 rung re-installed both projection guards dropped above.
    for trigger in V102_PROJECTION_GUARD_TRIGGERS {
        let present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |r| r.get(0),
            )
            .expect("read sqlite_master");
        assert_eq!(present, 1, "the v102 ladder must re-install {trigger}");
    }

    // Columns re-added.
    for col in ["entity_id", "citations", "confidence_source", "version"] {
        assert!(
            column_present(&conn, "memories", col),
            "ADD COLUMN arm did not re-add memories.{col} on upgrade"
        );
    }

    // Lossless: the v0.6.x columns are byte-equal to the pre-drop seed.
    assert_eq!(
        memory_fingerprint(&conn),
        before_fp,
        "column-absent legacy upgrade was not lossless on v0.6.x columns"
    );

    // Legacy rows received the documented backfill defaults on the
    // re-added NOT NULL columns.
    for id in &seeded_ids {
        let got = db::get(&conn, id)
            .expect("get legacy row")
            .unwrap_or_else(|| panic!("legacy row {id} vanished on upgrade"));
        assert_eq!(
            got.version, 1,
            "re-added v45 version column must backfill legacy row {id} to 1; got {}",
            got.version
        );
        assert!(
            got.citations.is_empty(),
            "re-added v38 citations column must backfill legacy row {id} to empty"
        );
    }

    assert_guards_enforce_after_upgrade(&conn);
    drop(conn);
    replay_9273_on_upgraded_store(&path);
}

/// `SQLITE_CORRUPT_VTAB` (`SQLITE_CORRUPT | (1 << 8)`), the #9273 code.
const SQLITE_CORRUPT_VTAB_UPG: i32 = 267;
const INTEGRITY_CHECK_UPG: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
/// Fresh random keys per replay (the tokens of a base64 key decide whether a
/// later FTS5 'delete' trips over a desync), per `recursive_triggers` setting.
const REPLAYS_UPG: usize = 4;
const FAR_FUTURE_UPG: &str = "2099-01-01T00:00:00Z";

fn fts_check_upg(conn: &Connection) -> Result<(), i32> {
    match conn.execute_batch(INTEGRITY_CHECK_UPG) {
        Ok(()) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _)) => Err(e.extended_code),
        Err(other) => panic!("integrity-check failed with a non-SQLite error: {other}"),
    }
}

fn sqlite_code_upg(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
            _ => None,
        })
}

/// One replay of the #9273 CI sequence (plant a flat-bound roster row, bind
/// the legitimate key, merge the federated copy through `insert_if_newer`)
/// on an already-open connection, with the FTS5 integrity-check after every
/// step. Returns the first violation as `(step, code)`.
fn replay_9273_sequence_upg(conn: &Connection, tag: &str) -> Result<(), (&'static str, i32)> {
    use ai_memory::models::field_names;
    let victim = format!("ai:legacy-upgrade-victim-{tag}");
    let plant_id = format!("legacy-upgrade-plant-{tag}");
    let attacker_key =
        ai_memory::identity::keypair::generate(&format!("ai:legacy-upgrade-attacker-{tag}"))
            .expect("keypair")
            .public_base64();
    let as_code = |step: &'static str, e: &anyhow::Error| {
        let code = sqlite_code_upg(e).unwrap_or_else(|| panic!("{step}: non-SQLite error {e:#}"));
        (step, code)
    };
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    let metadata = json!({
        "agent_id": victim,
        (field_names::AGENT_PUBKEY): attacker_key,
        (field_names::PUBKEY_BOUND_AT): created,
        (field_names::WRITE_SIGNATURE): "forged-carried-signature",
        (field_names::ATTEST_LEVEL): "agent_attested",
    });
    let planted = Memory {
        id: plant_id.clone(),
        tier: Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: ai_memory::models::agent_registration_title(&victim),
        content: serde_json::to_string(&metadata).expect("mirror"),
        created_at: created.clone(),
        updated_at: created,
        metadata,
        ..Memory::default()
    };
    db::insert(conn, &planted).map_err(|e| as_code("insert", &e))?;
    fts_check_upg(conn).map_err(|code| ("insert+integrity-check", code))?;
    let legitimate = ai_memory::identity::keypair::generate(&victim).expect("keypair");
    db::bind_agent_pubkey_with_keypair(conn, &victim, &legitimate)
        .map_err(|e| as_code("bind", &e))?;
    fts_check_upg(conn).map_err(|code| ("bind+integrity-check", code))?;
    let mut federated = db::get(conn, &plant_id)
        .expect("read bound row")
        .expect("bound row present");
    federated.updated_at = FAR_FUTURE_UPG.to_string();
    federated
        .metadata
        .as_object_mut()
        .expect("metadata object")
        .insert(
            field_names::AGENT_PUBKEY.to_string(),
            serde_json::Value::String(attacker_key),
        );
    federated.content = serde_json::to_string(&federated.metadata).expect("mirror");
    db::insert_if_newer(conn, &federated).map_err(|e| as_code("insert_if_newer", &e))?;
    fts_check_upg(conn).map_err(|code| ("insert_if_newer+integrity-check", code))?;
    Ok(())
}

/// Ruling b430ff48 item 3: the guards the v102 rung re-installed on the
/// upgraded legacy store keep `memories_fts` in step under the #9273 replay,
/// `recursive_triggers` OFF (production default) and ON, and the index passes
/// its integrity-check after every step. Any violation is the defect; a
/// violation must be the exact code 267.
fn replay_9273_on_upgraded_store(path: &std::path::Path) {
    let mut violations = Vec::new();
    for recursive in [false, true] {
        let conn = db::open(path).expect("re-open the upgraded legacy store");
        let pragma = if recursive {
            "PRAGMA recursive_triggers=ON"
        } else {
            "PRAGMA recursive_triggers=OFF"
        };
        conn.execute_batch(pragma).expect("recursive_triggers");
        fts_check_upg(&conn).expect("the upgraded store's index passes before the replay");
        for replay in 0..REPLAYS_UPG {
            let tag = format!("{recursive}-{replay}");
            if let Err((step, code)) = replay_9273_sequence_upg(&conn, &tag) {
                assert_eq!(
                    code, SQLITE_CORRUPT_VTAB_UPG,
                    "recursive={recursive} replay={replay} {step}"
                );
                violations.push(format!(
                    "recursive={recursive} replay={replay} at {step}: code {code}"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "memories_fts out of step on the upgraded legacy store:\n{}",
        violations.join("\n")
    );
}

/// The re-installed v102 guards enforce on the upgraded legacy store: the
/// trigger body aborts a forged key, and the `UPDATE OF` list re-checks an
/// envelope-only unseal (#9406). Exact RAISE texts from 0086.
fn assert_guards_enforce_after_upgrade(conn: &Connection) {
    const AGENT: &str = "ai:legacy-upgrade-guard-8341";
    const MISMATCH_MESSAGE: &str = "agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)";
    const NON_OBJECT_MESSAGE: &str = "agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it";
    db::register_agent(conn, AGENT, "test", &[]).expect("register on the upgraded store");
    let kp = ai_memory::identity::keypair::generate(AGENT).expect("keypair");
    db::bind_agent_pubkey_with_keypair(conn, AGENT, &kp).expect("bind on the upgraded store");
    let title = ai_memory::models::agent_registration_title(AGENT);
    let ns = ai_memory::models::AGENTS_NAMESPACE;
    let raw = |err: &rusqlite::Error| match err {
        rusqlite::Error::SqliteFailure(_, Some(message)) => Some(message.clone()),
        _ => None,
    };

    let forged = conn
        .execute(
            "UPDATE memories SET metadata = json_set(metadata, '$.agent_pubkey', 'forged-8341')
              WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![ns, &title],
        )
        .expect_err("the re-installed update guard must abort a forged key");
    assert_eq!(raw(&forged).as_deref(), Some(MISMATCH_MESSAGE));

    conn.execute(
        "UPDATE memories SET content = '', encrypted_envelope = X'00'
          WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![ns, &title],
    )
    .expect("a sealed row with the ledger pair passes");
    let unseal = conn
        .execute(
            "UPDATE memories SET encrypted_envelope = NULL WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![ns, &title],
        )
        .expect_err("UPDATE OF encrypted_envelope must re-check an unseal on the upgraded store");
    assert_eq!(raw(&unseal).as_deref(), Some(NON_OBJECT_MESSAGE));
}

/// True when `table.column` exists, via `PRAGMA table_info`.
fn column_present(conn: &Connection, table: &str, column: &str) -> bool {
    conn.prepare(&format!(
        "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
    ))
    .and_then(|mut s| s.exists(rusqlite::params![column]))
    .unwrap_or(false)
}

/// A process-local, collision-resistant directory under the repo-local
/// run area (NEVER a temp dir) so the on-disk DB *and* the sibling
/// pre-migration snapshot the migration writes both land in a path the
/// operator's no-`/tmp` rule permits. Caller cleans it up.
fn local_run_dir(tag: &str) -> std::path::PathBuf {
    let token = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(LOCAL_RUN_ROOT)
        .join(format!("{tag}-{}-{token}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create local run dir");
    dir
}

/// Repo-local run area (gitignored). Mirrors the operator directive that
/// no agent-authored test artifact may live under a temp dir.
const LOCAL_RUN_ROOT: &str = ".local-runs";

#[test]
fn migrate_writes_recoverable_pre_migration_snapshot_before_schema_mutation() {
    // Operator directive (2026-06-05): a real v0.6.4 DB must be backed up
    // *within the migration scope* BEFORE the schema migration mutates it,
    // so a failed/partial upgrade is recoverable. This proves the snapshot
    // is taken automatically by `db::open`'s migration path, lands beside
    // the live DB (not a temp dir), and is itself a valid pre-migration
    // image: stamped at the v0.6.4 baseline and carrying every seeded row.
    let dir = local_run_dir("pre-migration-snapshot");
    let db_path = dir.join("v064-substrate.db");

    let seeded_ids;
    {
        let conn = db::open(&db_path).expect("first open installs schema");
        seeded_ids = seed_v064_corpus(&conn);
        rewind_to_v064_baseline(&conn);
    }

    // Snapshot the directory before the upgrade so we can pin the snapshot
    // as a file the migration *newly* created.
    let infix = db::pre_migration_backup_infix_for_tests();
    let before: std::collections::HashSet<std::path::PathBuf> = dir_entries(&dir);

    // The upgrade open — this is the path that must self-snapshot.
    let conn = db::open(&db_path).expect("db::open upgrades v0.6.4 → v0.7.0");
    assert_eq!(
        stamped_version(&conn),
        db::current_schema_version_for_tests(),
        "live DB must reach the v0.7.0 head after the upgrade"
    );
    drop(conn);

    let snapshot = dir_entries(&dir)
        .into_iter()
        .find(|p| {
            !before.contains(p)
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(infix))
        })
        .expect("migration must write a pre-migration snapshot sibling file");

    // The snapshot name encodes the from→to version span (no bare literal:
    // both ends come from the baseline const and the SSOT head accessor).
    let snapshot_name = snapshot
        .file_name()
        .and_then(|n| n.to_str())
        .expect("snapshot filename is UTF-8");
    let expected_from = format!("v{V064_BASELINE_SCHEMA_VERSION}-to-v");
    let expected_to = format!("-to-v{}-", db::current_schema_version_for_tests());
    assert!(
        snapshot_name.contains(&expected_from) && snapshot_name.contains(&expected_to),
        "snapshot name {snapshot_name} must encode the v{V064_BASELINE_SCHEMA_VERSION}→v{} span",
        db::current_schema_version_for_tests()
    );
    assert!(
        std::fs::metadata(&snapshot).expect("stat snapshot").len() > 0,
        "pre-migration snapshot must be a non-empty database image"
    );

    // The snapshot is a genuine PRE-migration image: opened raw (no
    // migrate), it still reads as the v0.6.4 baseline and carries every
    // seeded row. This is the recoverability contract — restoring it gives
    // the operator their exact pre-upgrade DB back.
    let snap = Connection::open(&snapshot).expect("open snapshot as plain sqlite");
    assert_eq!(
        stamped_version(&snap),
        V064_BASELINE_SCHEMA_VERSION,
        "snapshot must be stamped at the v0.6.4 baseline (taken before mutation)"
    );
    let snap_row_count: i64 = snap
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count snapshot rows");
    assert_eq!(
        snap_row_count,
        i64::try_from(seeded_ids.len()).expect("seed count fits i64"),
        "snapshot must preserve every seeded v0.6.4 row"
    );

    // Close the snapshot connection before removing the directory.
    // Windows refuses to delete a file with an open handle (sharing
    // violation, OS error 32); Unix allows the unlink, which is why this
    // only surfaced on `Check (windows-latest)`. Mirrors the `drop(conn)`
    // above and in the sibling tests.
    drop(snap);
    std::fs::remove_dir_all(&dir).expect("clean up local run dir");
}

#[test]
fn fresh_db_open_writes_no_pre_migration_snapshot() {
    // A brand-new DB stamps version 0 and has nothing to lose, so the
    // migration MUST NOT write a snapshot (the backup is reserved for
    // populated, pre-existing DBs being upgraded). Guards against the
    // snapshot path firing on every fresh `open` and littering the data
    // directory.
    let dir = local_run_dir("fresh-no-snapshot");
    let db_path = dir.join("fresh.db");

    let conn = db::open(&db_path).expect("fresh open installs schema + migrates from 0");
    assert_eq!(
        stamped_version(&conn),
        db::current_schema_version_for_tests(),
        "fresh open must reach the v0.7.0 head"
    );
    drop(conn);

    let infix = db::pre_migration_backup_infix_for_tests();
    let snapshots: Vec<_> = dir_entries(&dir)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(infix))
        })
        .collect();
    assert!(
        snapshots.is_empty(),
        "fresh DB open must not write a pre-migration snapshot; found {snapshots:?}"
    );

    std::fs::remove_dir_all(&dir).expect("clean up local run dir");
}

/// All regular-file entries directly under `dir`.
fn dir_entries(dir: &std::path::Path) -> std::collections::HashSet<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("read local run dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect()
}
