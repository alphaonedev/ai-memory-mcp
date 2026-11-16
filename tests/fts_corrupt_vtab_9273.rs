// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9273 (same signature as #8341): `SQLITE_CORRUPT_VTAB` (267) on the
//! external-content FTS5 index `memories_fts` inside the generic federation
//! merge (`insert_if_newer`).
//!
//! Class invariant: no sequence of product write paths, with
//! `recursive_triggers` ON or OFF, leaves `memories_fts` failing its FTS5
//! `integrity-check`, and no write returns code 267.
//!
//! Every case runs on ONE connection opened by `ai_memory::db::open` on its own
//! temp file, so a failure here cannot come from a second connection, a shared
//! database file or another test.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::models::field_names;
use std::sync::Mutex;

/// `SQLITE_CORRUPT_VTAB` (`SQLITE_CORRUPT | (1 << 8)`).
const SQLITE_CORRUPT_VTAB_9273: i32 = 267;
const INTEGRITY_CHECK_9273: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
/// Fresh random keys per replay: the tokens of a base64 key decide whether a
/// later FTS5 'delete' trips over the desync, so CI saw it only sometimes.
const REPLAYS_9273: usize = 8;
const VICTIM_9273: &str = "ai:generic-write-victim-9273";
const ATTACKER_9273: &str = "ai:generic-write-attacker-9273";
const PLANT_ID_9273: &str = "generic-registration-plant-9273";
const FAR_FUTURE_9273: &str = "2099-01-01T00:00:00Z";
/// Legacy `sqlite3_trace` marks the start of every trigger program with this.
const TRIGGER_MARK_9273: &str = "-- TRIGGER ";

fn open_db_9273(recursive_triggers: bool) -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let pragma = if recursive_triggers {
        "PRAGMA recursive_triggers=ON"
    } else {
        "PRAGMA recursive_triggers=OFF"
    };
    conn.execute_batch(pragma).expect("recursive_triggers");
    (f, conn)
}

/// The extended SQLite code anywhere in an error chain, or `None`.
fn sqlite_code_9273(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
            _ => None,
        })
}

fn fts_check_9273(conn: &rusqlite::Connection) -> Result<(), i32> {
    match conn.execute_batch(INTEGRITY_CHECK_9273) {
        Ok(()) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _)) => Err(e.extended_code),
        Err(other) => panic!("integrity-check failed with a non-SQLite error: {other}"),
    }
}

/// The roster row `generic_sqlite_writes_cannot_plant_or_replace_flat_binding_3464`
/// plants (`tests/bind_pubkey_possession_3464.rs:277-296`), field for field.
fn planted_row_9273(attacker_key: &str) -> ai_memory::models::Memory {
    let created = ai_memory::identity::attest::now_attestable_rfc3339();
    let metadata = serde_json::json!({
        "agent_id": VICTIM_9273,
        (field_names::AGENT_PUBKEY): attacker_key,
        (field_names::PUBKEY_BOUND_AT): created,
        (field_names::WRITE_SIGNATURE): "forged-carried-signature",
        (field_names::ATTEST_LEVEL): "agent_attested",
    });
    ai_memory::models::Memory {
        id: PLANT_ID_9273.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: ai_memory::models::agent_registration_title(VICTIM_9273),
        content: serde_json::to_string(&metadata).expect("mirror"),
        created_at: created.clone(),
        updated_at: created,
        metadata,
        ..ai_memory::models::Memory::default()
    }
}

/// The federated copy the 3464 test merges at :324-337: newer `updated_at`,
/// the attacker key put back into metadata, content rewritten to the metadata.
fn federated_row_9273(
    conn: &rusqlite::Connection,
    attacker_key: &str,
) -> anyhow::Result<ai_memory::models::Memory> {
    let mut federated = ai_memory::db::get(conn, PLANT_ID_9273)?
        .ok_or_else(|| anyhow::anyhow!("bound row vanished"))?;
    federated.updated_at = FAR_FUTURE_9273.to_string();
    federated
        .metadata
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("metadata is not an object"))?
        .insert(
            field_names::AGENT_PUBKEY.to_string(),
            serde_json::Value::String(attacker_key.to_string()),
        );
    federated.content = serde_json::to_string(&federated.metadata)?;
    Ok(federated)
}

/// One replay of the 3464 test up to its merge at :337, with the FTS5
/// invariant checked after every step. Returns the first violation as
/// `(step, code)`.
fn replay_3464_sequence_9273(recursive: bool) -> Result<(), (&'static str, i32)> {
    let (_f, conn) = open_db_9273(recursive);
    let attacker_key = ai_memory::identity::keypair::generate(ATTACKER_9273)
        .expect("keypair")
        .public_base64();
    let as_code = |step: &'static str, e: &anyhow::Error| {
        let code = sqlite_code_9273(e).unwrap_or_else(|| panic!("{step}: non-SQLite error {e:#}"));
        (step, code)
    };
    ai_memory::db::insert(&conn, &planted_row_9273(&attacker_key))
        .map_err(|e| as_code("insert", &e))?;
    fts_check_9273(&conn).map_err(|code| ("insert+integrity-check", code))?;
    let legitimate = ai_memory::identity::keypair::generate(VICTIM_9273).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM_9273, &legitimate)
        .map_err(|e| as_code("bind", &e))?;
    fts_check_9273(&conn).map_err(|code| ("bind+integrity-check", code))?;
    let federated = federated_row_9273(&conn, &attacker_key).expect("federated copy");
    ai_memory::db::insert_if_newer(&conn, &federated)
        .map_err(|e| as_code("insert_if_newer", &e))?;
    fts_check_9273(&conn).map_err(|code| ("insert_if_newer+integrity-check", code))?;
    Ok(())
}

/// The invariant over the exact CI sequence, production default
/// (`recursive_triggers` OFF) and the 3464 test's setting (ON), with fresh
/// random keys per replay. Every violation must be the exact code 267; any
/// violation at all is the defect.
#[test]
fn ci_sequence_keeps_memories_fts_in_step_9273() {
    let mut violations = Vec::new();
    for recursive in [false, true] {
        for replay in 0..REPLAYS_9273 {
            if let Err((step, code)) = replay_3464_sequence_9273(recursive) {
                assert_eq!(
                    code, SQLITE_CORRUPT_VTAB_9273,
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
        "memories_fts out of step with memories (SQLITE_CORRUPT_VTAB {SQLITE_CORRUPT_VTAB_9273}), \
         {} of {} replays:\n{}",
        violations.len(),
        2 * REPLAYS_9273,
        violations.join("\n")
    );
}

/// The operator remedy named in the finding: whatever state the merge leaves,
/// FTS5 `'rebuild'` derives the index from `memories` again (the content table
/// is the durable truth) and the integrity-check passes afterwards.
#[test]
fn rebuild_restores_memories_fts_after_the_merge_9273() {
    for recursive in [false, true] {
        let (_f, conn) = open_db_9273(recursive);
        let attacker_key = ai_memory::identity::keypair::generate(ATTACKER_9273)
            .expect("keypair")
            .public_base64();
        ai_memory::db::insert(&conn, &planted_row_9273(&attacker_key)).expect("insert");
        let legitimate = ai_memory::identity::keypair::generate(VICTIM_9273).expect("keypair");
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM_9273, &legitimate)
            .expect("bind");
        let federated = federated_row_9273(&conn, &attacker_key).expect("federated copy");
        let merged = ai_memory::db::insert_if_newer(&conn, &federated);
        if let Err(e) = &merged {
            assert_eq!(
                sqlite_code_9273(e),
                Some(SQLITE_CORRUPT_VTAB_9273),
                "recursive={recursive}: the merge may only fail with 267, got {e:#}"
            );
        }
        conn.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
            .expect("rebuild");
        assert_eq!(
            fts_check_9273(&conn),
            Ok(()),
            "recursive={recursive}: 'rebuild' restores the index"
        );
    }
}

static TRACE_9273: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn trace_sink_9273(sql: &str) {
    if let Some(name) = sql.strip_prefix(TRIGGER_MARK_9273) {
        TRACE_9273
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.trim().to_string());
    }
}

/// Phase A evidence: the trigger programs the merge statement runs, in firing
/// order, and the SQLite build they run on. Prints, then asserts the class
/// invariant on the merge alone (integrity-check after it).
#[test]
fn merge_trigger_order_and_sqlite_build_9273() {
    let (_f, mut conn) = open_db_9273(false);
    let version: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .expect("sqlite_version");
    let mut stmt = conn
        .prepare("PRAGMA compile_options")
        .expect("compile_options");
    let options: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    drop(stmt);
    let mut stmt = conn
        .prepare(
            "SELECT rowid, name FROM sqlite_schema \
             WHERE type = 'trigger' AND tbl_name = 'memories' ORDER BY rowid",
        )
        .expect("triggers");
    let triggers: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    drop(stmt);
    eprintln!("9273 sqlite_version={version}");
    eprintln!("9273 compile_options={}", options.join(","));
    for (rowid, name) in &triggers {
        eprintln!("9273 schema trigger rowid={rowid} name={name}");
    }

    let attacker_key = ai_memory::identity::keypair::generate(ATTACKER_9273)
        .expect("keypair")
        .public_base64();
    ai_memory::db::insert(&conn, &planted_row_9273(&attacker_key)).expect("insert");
    let legitimate = ai_memory::identity::keypair::generate(VICTIM_9273).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM_9273, &legitimate).expect("bind");
    assert_eq!(fts_check_9273(&conn), Ok(()), "in step before the merge");
    let federated = federated_row_9273(&conn, &attacker_key).expect("federated copy");

    TRACE_9273
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    conn.trace(Some(trace_sink_9273));
    let merged = ai_memory::db::insert_if_newer(&conn, &federated);
    conn.trace(None);
    let fired = TRACE_9273
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    eprintln!("9273 merge fired (in order): {}", fired.join(" -> "));
    eprintln!(
        "9273 merge result: {:?}",
        merged.as_ref().map(drop).map_err(sqlite_code_9273)
    );
    assert_eq!(
        fts_check_9273(&conn),
        Ok(()),
        "memories_fts out of step after the generic merge; triggers fired: {}",
        fired.join(" -> ")
    );
}

// ---------------------------------------------------------------------------
// Table over the product write paths to `memories` x recursive_triggers.
// ---------------------------------------------------------------------------

const PLAIN_NS_9273: &str = "fts-invariant-9273";
const PLAIN_A_9273: &str = "fts-plain-a-9273";
const PLAIN_B_9273: &str = "fts-plain-b-9273";
const CONSOLIDATOR_9273: &str = "ai:consolidator-9273";
/// Rows of the size bound and the wall-clock ceiling for one integrity-check
/// over them (debug test profile; 392 ms measured on f2, the ceiling leaves
/// CI-runner headroom and still catches a quadratic check).
const BOUND_ROWS_9273: i64 = 100_000;
const BOUND_CHECK_MS_9273: u128 = 20_000;

/// Records every invariant violation of one case instead of stopping at the
/// first, so the table reports the whole class in one run.
struct Probe9273<'c> {
    conn: &'c rusqlite::Connection,
    label: String,
    violations: Vec<String>,
}

impl Probe9273<'_> {
    /// Run one write path: the write must not fail with 267, and the FTS5
    /// integrity-check must pass after it. Returns the write's value on `Ok`.
    fn step<T>(&mut self, path: &str, result: anyhow::Result<T>) -> Option<T> {
        let value = match result {
            Ok(value) => Some(value),
            Err(e) => {
                let code = sqlite_code_9273(&e);
                self.violations.push(format!(
                    "{} {path}: write failed (sqlite code {code:?}): {e:#}",
                    self.label
                ));
                None
            }
        };
        if let Err(code) = fts_check_9273(self.conn) {
            self.violations.push(format!(
                "{} {path}+integrity-check: code {code}",
                self.label
            ));
            // Re-derive the index so the next path is judged on its own.
            self.conn
                .execute_batch("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
                .expect("rebuild between paths");
        }
        value
    }
}

/// The receive-side stored-namespace authorizer, granting every namespace (the
/// scope gate is not under test here).
fn allow_all_9273(_stored: &str) -> bool {
    true
}

fn plain_row_9273(id: &str, title: &str, content: &str) -> ai_memory::models::Memory {
    let now = ai_memory::identity::attest::now_attestable_rfc3339();
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: PLAIN_NS_9273.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["alpha9273".to_string()],
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({"agent_id": CONSOLIDATOR_9273}),
        ..ai_memory::models::Memory::default()
    }
}

/// Every write path that reaches an ordinary row: insert, title upsert, the
/// update of each FTS-indexed column (title, content, tags) and of metadata,
/// the raw metadata setter, touch, the generic merge, archive, restore,
/// consolidate and delete.
fn plain_write_paths_9273(p: &mut Probe9273<'_>) {
    let conn = p.conn;
    p.step(
        "insert",
        ai_memory::db::insert(
            conn,
            &plain_row_9273(PLAIN_A_9273, "plain alpha", "first body"),
        ),
    );
    p.step(
        "insert(title upsert)",
        ai_memory::db::insert(
            conn,
            &plain_row_9273("fts-plain-a2-9273", "plain alpha", "upserted body"),
        ),
    );
    let id = ai_memory::db::get(conn, PLAIN_A_9273)
        .ok()
        .flatten()
        .map_or_else(|| "fts-plain-a2-9273".to_string(), |m| m.id);
    let tags = vec!["beta9273".to_string(), "gamma9273".to_string()];
    let metadata = serde_json::json!({"agent_id": CONSOLIDATOR_9273, "note": "meta9273"});
    let none = None::<&str>;
    p.step(
        "update(title)",
        ai_memory::db::update(
            conn,
            &id,
            Some("plain renamed"),
            none,
            None,
            none,
            None,
            None,
            None,
            none,
            None,
        ),
    );
    p.step(
        "update(content)",
        ai_memory::db::update(
            conn,
            &id,
            none,
            Some("second body"),
            None,
            none,
            None,
            None,
            None,
            none,
            None,
        ),
    );
    p.step(
        "update(tags)",
        ai_memory::db::update(
            conn,
            &id,
            none,
            none,
            None,
            none,
            Some(&tags),
            None,
            None,
            none,
            None,
        ),
    );
    p.step(
        "update(metadata)",
        ai_memory::db::update(
            conn,
            &id,
            none,
            none,
            None,
            none,
            None,
            None,
            None,
            none,
            Some(&metadata),
        ),
    );
    p.step(
        "set_row_metadata",
        ai_memory::db::set_row_metadata(conn, &id, &metadata.to_string()),
    );
    p.step("touch", ai_memory::db::touch(conn, &id, 0, 0));
    if let Some(mut newer) = ai_memory::db::get(conn, &id).ok().flatten() {
        newer.updated_at = "2097-01-01T00:00:00Z".to_string();
        newer.content = "merged body".to_string();
        p.step(
            "insert_if_newer",
            ai_memory::db::insert_if_newer(conn, &newer),
        );
    }
    if let Some(mut newer) = ai_memory::db::get(conn, &id).ok().flatten() {
        // The same-id federation lane (overwrite_full_row_by_id) also renames.
        newer.updated_at = FAR_FUTURE_9273.to_string();
        newer.title = "plain merged".to_string();
        newer.content = "overwritten body".to_string();
        p.step(
            "merge_inbound_authorized(same id)",
            ai_memory::db::merge_inbound_authorized(conn, &newer, false, Some(&allow_all_9273)),
        );
    }
    p.step(
        "archive_memory",
        ai_memory::db::archive_memory(conn, &id, Some("fts-9273")),
    );
    p.step(
        "restore_archived",
        ai_memory::db::restore_archived(conn, &id),
    );
    p.step(
        "insert(second row)",
        ai_memory::db::insert(
            conn,
            &plain_row_9273(PLAIN_B_9273, "plain beta", "beta body"),
        ),
    );
    p.step(
        "consolidate",
        ai_memory::db::consolidate(
            conn,
            &[id.clone(), PLAIN_B_9273.to_string()],
            "plain consolidated",
            "consolidated body",
            PLAIN_NS_9273,
            &ai_memory::models::Tier::Long,
            "fts-9273",
            CONSOLIDATOR_9273,
            false,
        ),
    );
    p.step(
        "insert(delete target)",
        ai_memory::db::insert(
            conn,
            &plain_row_9273("fts-plain-c-9273", "plain gamma", "gone body"),
        ),
    );
    p.step("delete", ai_memory::db::delete(conn, "fts-plain-c-9273"));
}

/// Every write path that reaches a bound `_agents` registration row (the rows
/// the v97 projection triggers watch): update of title and content, the
/// newer-wins merge without and with a key change, archive and restore.
fn bound_registration_write_paths_9273(p: &mut Probe9273<'_>) {
    let conn = p.conn;
    let attacker_key = ai_memory::identity::keypair::generate(ATTACKER_9273)
        .expect("keypair")
        .public_base64();
    p.step(
        "insert(_agents)",
        ai_memory::db::insert(conn, &planted_row_9273(&attacker_key)),
    );
    let legitimate = ai_memory::identity::keypair::generate(VICTIM_9273).expect("keypair");
    p.step(
        "bind_agent_pubkey_with_keypair",
        ai_memory::db::bind_agent_pubkey_with_keypair(conn, VICTIM_9273, &legitimate),
    );
    let none = None::<&str>;
    let title = ai_memory::models::agent_registration_title(VICTIM_9273);
    p.step(
        "update(_agents title)",
        ai_memory::db::update(
            conn,
            PLANT_ID_9273,
            Some(&title),
            none,
            None,
            none,
            None,
            None,
            None,
            none,
            None,
        ),
    );
    let mirror = serde_json::json!({"agent_id": VICTIM_9273, "note": "rewritten9273"}).to_string();
    p.step(
        "update(_agents content)",
        ai_memory::db::update(
            conn,
            PLANT_ID_9273,
            none,
            Some(&mirror),
            None,
            none,
            None,
            None,
            None,
            none,
            None,
        ),
    );
    if let Some(mut newer) = ai_memory::db::get(conn, PLANT_ID_9273).ok().flatten() {
        newer.updated_at = "2098-01-01T00:00:00Z".to_string();
        p.step(
            "insert_if_newer(_agents same key)",
            ai_memory::db::insert_if_newer(conn, &newer),
        );
    }
    if let Ok(federated) = federated_row_9273(conn, &attacker_key) {
        p.step(
            "insert_if_newer(_agents key change)",
            ai_memory::db::insert_if_newer(conn, &federated),
        );
    }
    if let Ok(mut federated) = federated_row_9273(conn, &attacker_key) {
        federated.updated_at = "2099-06-01T00:00:00Z".to_string();
        p.step(
            "merge_inbound_authorized(_agents same id)",
            ai_memory::db::merge_inbound_authorized(conn, &federated, false, Some(&allow_all_9273)),
        );
    }
    p.step(
        "archive_memory(_agents)",
        ai_memory::db::archive_memory(conn, PLANT_ID_9273, Some("fts-9273")),
    );
    p.step(
        "restore_archived(_agents)",
        ai_memory::db::restore_archived(conn, PLANT_ID_9273),
    );
}

/// The class invariant over every product write path to `memories`, with
/// `recursive_triggers` OFF (the product default) and ON (what an embedding
/// host or the 3464 test sets). Every violation is listed.
#[test]
fn every_write_path_keeps_memories_fts_in_step_9273() {
    type Case9273 = fn(&mut Probe9273<'_>);
    const CASES_9273: &[(&str, Case9273)] = &[
        ("plain", plain_write_paths_9273),
        ("bound_registration", bound_registration_write_paths_9273),
    ];
    let mut violations = Vec::new();
    for recursive in [false, true] {
        for (case, run) in CASES_9273 {
            let (_f, conn) = open_db_9273(recursive);
            let mut probe = Probe9273 {
                conn: &conn,
                label: format!("{case} recursive={recursive}"),
                violations: Vec::new(),
            };
            run(&mut probe);
            violations.append(&mut probe.violations);
        }
    }
    assert!(
        violations.is_empty(),
        "{} write-path violation(s) of the memories_fts invariant:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Size and time bound: 100K rows written through the FTS sync triggers, then
/// one integrity-check under the wall-clock ceiling, and it passes.
#[test]
fn integrity_check_is_bounded_over_100k_rows_9273() {
    let (_f, conn) = open_db_9273(false);
    ai_memory::db::insert(
        &conn,
        &plain_row_9273(PLAIN_A_9273, "bound seed", "seed body"),
    )
    .expect("seed");
    // `table_info` lists the stored columns only (generated columns are hidden).
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('memories')")
        .expect("columns");
    let columns: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows");
    drop(stmt);
    let column_list = columns.join(", ");
    let seeded: Vec<String> = columns.iter().map(|c| format!("m.{c}")).collect();
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE bulk_9273 AS SELECT {column_list} FROM memories WHERE 0"
    ))
    .expect("bulk table");
    conn.execute(
        &format!(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1) \
             INSERT INTO bulk_9273 SELECT {} FROM memories m, n WHERE m.id = ?2",
            seeded.join(", ")
        ),
        rusqlite::params![BOUND_ROWS_9273, PLAIN_A_9273],
    )
    .expect("bulk rows");
    conn.execute_batch(&format!(
        "UPDATE bulk_9273 SET id = 'bound-9273-' || rowid, title = 'bound row ' || rowid, \
         content = 'bound body token' || rowid; \
         INSERT INTO memories ({column_list}) SELECT {column_list} FROM bulk_9273; \
         DROP TABLE bulk_9273"
    ))
    .expect("bulk insert through memories_ai");
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM memories", [], |r| r.get(0))
        .expect("count");
    assert!(rows > BOUND_ROWS_9273, "rows={rows}");
    let started = std::time::Instant::now();
    assert_eq!(fts_check_9273(&conn), Ok(()));
    let elapsed = started.elapsed().as_millis();
    eprintln!("9273 integrity-check over {rows} rows: {elapsed} ms");
    assert!(
        elapsed < BOUND_CHECK_MS_9273,
        "integrity-check over {rows} rows took {elapsed} ms (ceiling {BOUND_CHECK_MS_9273})"
    );
}
