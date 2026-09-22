// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3718 — a READ of a sealed row whose per-agent `.x25519.priv` is missing
//! must NEVER mint a key: it fails with the typed `KeyAbsent` (distinct from
//! an AEAD failure), writes NOTHING under the key directory, and leaves the
//! row untouched; restoring the file makes the row readable again. Sibling:
//! a WRITE for an agent whose key directory holds archived material of a
//! prior generation must not mint over it.
//!
//! FAILS ON THE PARENT by non-existence of `evict_cached_keypair` /
//! `load_keypair` / `KeyAbsent`; the head-compilable proof of the same
//! behaviour is `tests/encryption_key_absent_3718_head.rs`.

use ai_memory::encryption::{
    KeyAbsent, KeyGenerationGap, SealRefusedSealedRowsExist, evict_cached_keypair, load_keypair,
    seal_refused_sealed_rows_exist,
};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use rusqlite::params;
use std::collections::BTreeSet;
use std::path::Path;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const PRIV_SUFFIX: &str = ".x25519.priv";
const PUB_SUFFIX: &str = ".x25519.pub";

/// Serialises the env-gated tests in this binary.
static ENV_GATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard: at-rest encryption ON for the test, prior value restored.
struct EncryptGate {
    prev: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EncryptGate {
    fn on() -> Self {
        let lock = ENV_GATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serialized via ENV_GATE_LOCK; restored on Drop.
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
        Self { prev, _lock: lock }
    }
}

impl Drop for EncryptGate {
    fn drop(&mut self) {
        // SAFETY: still serialized via the held lock.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
    }
}

fn fresh_conn() -> rusqlite::Connection {
    let _ = key_dir_sandbox::pin();
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, content: &str, agent_id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "global".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": agent_id }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Every file name under the key directory (flat: these agents have no
/// `/` in their ids, so the pair sits directly in the sandbox).
fn listing(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

fn raw_row(conn: &rusqlite::Connection, id: &str) -> (Option<Vec<u8>>, String) {
    conn.query_row(
        "SELECT encrypted_envelope, content FROM memories WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("raw row")
}

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, bytes).expect("restore .priv");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}
#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("restore .priv");
}

/// The three assertions the Conductor named — the middle one is what
/// would have caught #3718: seal, delete the `.priv`, read, then assert
/// `KeyAbsent` AND no new file under the key dir AND the row untouched.
/// Then restore the file and read the original bytes back.
#[test]
fn read_with_absent_key_is_typed_never_mints_and_leaves_the_row_3718() {
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let key_dir = key_dir_sandbox::pin();
    let agent = format!("agent-3718-absent-{}", uuid::Uuid::new_v4().simple());
    let plaintext = "sealed secret — #3718";

    let id = db::insert(&conn, &make_mem("absent-key", plaintext, &agent)).expect("insert seals");
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    assert!(
        priv_path.is_file(),
        "the seal minted the agent's live key: {}",
        priv_path.display()
    );
    let before = listing(key_dir);
    let (env_before, content_before) = raw_row(&conn, &id);
    assert!(env_before.is_some(), "the row carries a sealed envelope");
    let priv_bytes = std::fs::read(&priv_path).expect("snapshot .priv");

    // The key is lost; the process restarts (cache cleared).
    std::fs::remove_file(&priv_path).expect("delete .priv");
    evict_cached_keypair(&agent);

    // 1. typed KeyAbsent — the class, the agent, never the path, never
    //    "decrypt failed".
    let err = db::get(&conn, &id).expect_err("#3718: an absent key must fail the read");
    let msg = format!("{err}");
    assert!(msg.contains(KeyAbsent::CLASS), "class must be named: {msg}");
    assert!(msg.contains("#3718"), "{msg}");
    assert!(msg.contains(&agent), "the agent is named: {msg}");
    assert!(
        !msg.contains("decrypt failed"),
        "an absent key is NOT a wrong-recipient failure: {msg}"
    );
    assert!(
        !msg.contains(&key_dir.display().to_string()) && !msg.contains(PRIV_SUFFIX),
        "the caller never sees the key path (operator-log only): {msg}"
    );

    // 2. NO NEW FILE under the key dir — the read did not mint.
    let mut expected = before.clone();
    expected.remove(&format!("{agent}{PRIV_SUFFIX}"));
    assert_eq!(
        listing(key_dir),
        expected,
        "#3718: a read must not create key material (a minted impostor would fork the corpus)"
    );
    assert!(!priv_path.exists(), "no impostor .priv");

    // 3. The row is untouched.
    assert_eq!(
        raw_row(&conn, &id),
        (env_before, content_before),
        "row bytes unchanged"
    );

    // The read-only accessor says so directly, and still mints nothing.
    assert!(
        load_keypair(&agent)
            .expect("load is Ok(None), not Err")
            .is_none()
    );
    assert_eq!(listing(key_dir), expected);

    // Restore from "backup": the original bytes read again.
    write_0600(&priv_path, &priv_bytes);
    evict_cached_keypair(&agent);
    let back = db::get(&conn, &id)
        .expect("restored key opens the row")
        .expect("the row is present");
    assert_eq!(back.content, plaintext);
}

/// The legacy 0x02 per-agent envelope arm takes the same read-only path.
#[test]
fn legacy_envelope_read_with_absent_key_never_mints_3718() {
    use ai_memory::encryption::{encrypt, get_or_create_keypair};
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let key_dir = key_dir_sandbox::pin();
    let agent = format!("agent-3718-legacy-{}", uuid::Uuid::new_v4().simple());
    let kp = get_or_create_keypair(&agent).expect("seal path mints once");
    let envelope = encrypt("legacy 0x02 secret", &kp.public)
        .expect("encrypt")
        .to_bytes();
    let id = db::insert(&conn, &make_mem("legacy", "", &agent)).expect("insert");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![envelope, &id],
    )
    .expect("stamp legacy envelope");
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    std::fs::remove_file(&priv_path).expect("delete .priv");
    evict_cached_keypair(&agent);
    let before = listing(key_dir);
    let msg = format!(
        "{}",
        db::get(&conn, &id).expect_err("absent key fails the read")
    );
    assert!(
        msg.contains(KeyAbsent::CLASS) && !msg.contains("decrypt failed"),
        "{msg}"
    );
    assert_eq!(listing(key_dir), before, "the legacy arm minted nothing");
}

/// Sibling: a WRITE for an agent whose key dir already holds ARCHIVED
/// material (a prior generation) and no live key must not mint over it —
/// refused with the typed generation-gap class, nothing written.
#[test]
fn write_over_archived_material_refuses_and_mints_nothing_3718() {
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let key_dir = key_dir_sandbox::pin();
    let agent = format!("agent-3718-gap-{}", uuid::Uuid::new_v4().simple());
    let archived = key_dir.join(format!("{agent}{PUB_SUFFIX}.1757000000"));
    std::fs::write(&archived, [7u8; 32]).expect("plant an archived prior generation");
    let before = listing(key_dir);

    let err = db::insert(
        &conn,
        &make_mem("gap", "must not seal under a new generation", &agent),
    )
    .expect_err("#3718 sibling: archived material + no live key refuses the write");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(KeyGenerationGap::CLASS),
        "class must be named: {msg}"
    );
    assert!(msg.contains("#3718") && msg.contains(&agent), "{msg}");
    assert!(
        !msg.contains(&key_dir.display().to_string()),
        "the caller never sees the archived paths (operator-log only): {msg}"
    );
    assert_eq!(listing(key_dir), before, "nothing minted, nothing written");
    assert!(!key_dir.join(format!("{agent}{PRIV_SUFFIX}")).exists());
    assert!(load_keypair(&agent).expect("read-only lookup").is_none());
    assert_eq!(listing(key_dir), before);
}

/// Rows owned by `agent` that are sealed at rest — the store's evidence that
/// the agent is NOT fresh.
fn sealed_rows(conn: &rusqlite::Connection, agent: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE encrypted_envelope IS NOT NULL \
         AND json_extract(metadata, '$.agent_id') = ?1",
        params![agent],
        |r| r.get(0),
    )
    .expect("count sealed rows")
}

/// Wipe every file of `agent`'s key material from the key dir.
fn wipe_key_material(key_dir: &Path, agent: &str) {
    for name in listing(key_dir) {
        if name.starts_with(agent) {
            std::fs::remove_file(key_dir.join(name)).expect("wipe key material");
        }
    }
    evict_cached_keypair(agent);
}

/// #3718 (review) — the case written FIRST: a corpus with NO sealed rows for
/// the agent and a wiped key dir is a FRESH agent, and its first seal mints
/// the key normally. Minting for a fresh agent is the seal path's job; the
/// guard must not turn every first write into a refusal.
#[test]
fn no_sealed_rows_with_wiped_key_dir_mints_normally_3718() {
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let key_dir = key_dir_sandbox::pin();
    let agent = format!("agent-3718-fresh-{}", uuid::Uuid::new_v4().simple());
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));

    // The agent once had a key (minted out of band) and lost it, but never
    // sealed a row with it: by the store's evidence it is fresh.
    ai_memory::encryption::get_or_create_keypair(&agent).expect("mint out of band");
    assert!(priv_path.is_file());
    wipe_key_material(key_dir, &agent);
    assert!(!priv_path.exists(), "the key dir is wiped for this agent");
    assert_eq!(
        sealed_rows(&conn, &agent),
        0,
        "no sealed rows: a fresh agent"
    );

    let id = db::insert(
        &conn,
        &make_mem("fresh-agent", "first sealed row — #3718", &agent),
    )
    .expect("#3718: a fresh agent's first seal mints its key normally");
    assert!(
        priv_path.is_file(),
        "the seal minted the live key for the fresh agent: {}",
        priv_path.display()
    );
    let (envelope, _) = raw_row(&conn, &id);
    assert!(envelope.is_some(), "the row is sealed");
    assert_eq!(sealed_rows(&conn, &agent), 1);
    let back = db::get(&conn, &id).expect("read").expect("present");
    assert_eq!(back.content, "first sealed row — #3718");
}

/// #3718 (review) — the seal path asked to mint for an agent that ALREADY has
/// sealed rows and no live key: the key was lost, this is not a fresh agent.
/// Minting would strand every sealed row behind a key nobody holds. The seal
/// REFUSES with the typed class naming the sealed-row count, mints NOTHING,
/// and writes nothing; the expected key path is operator-log only. Restoring
/// the key from backup makes the same write succeed.
#[test]
fn sealed_rows_with_wiped_key_dir_refuse_to_mint_3718() {
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let key_dir = key_dir_sandbox::pin();
    let agent = format!("agent-3718-lost-{}", uuid::Uuid::new_v4().simple());
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));

    let first = db::insert(&conn, &make_mem("lost-key-1", "row one — #3718", &agent))
        .expect("first seal mints");
    assert!(priv_path.is_file());
    let priv_bytes = std::fs::read(&priv_path).expect("snapshot .priv");
    let (env_first, content_first) = raw_row(&conn, &first);
    assert!(env_first.is_some());
    assert_eq!(sealed_rows(&conn, &agent), 1);

    // The key dir is wiped; the process restarts (cache cleared).
    wipe_key_material(key_dir, &agent);
    let before = listing(key_dir);
    assert!(!priv_path.exists());

    let err = db::insert(&conn, &make_mem("lost-key-2", "row two — #3718", &agent))
        .expect_err("#3718: a seal over sealed rows with no key must refuse, not mint");
    let refused = seal_refused_sealed_rows_exist(&err)
        .unwrap_or_else(|| panic!("the refusal is the typed class, got: {err:#}"));
    assert_eq!(refused.agent_id, agent);
    assert_eq!(
        refused.sealed_rows, 1,
        "the count of rows a new key would strand"
    );
    assert_eq!(
        refused.expected_path, priv_path,
        "the operator line names the expected key path"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains(SealRefusedSealedRowsExist::CLASS) && msg.contains("#3718"),
        "class named: {msg}"
    );
    assert!(
        msg.contains("1 sealed row"),
        "the count is in the message: {msg}"
    );
    assert!(msg.contains(&agent), "the agent is named: {msg}");
    assert!(
        !msg.contains(&key_dir.display().to_string()) && !msg.contains(PRIV_SUFFIX),
        "the caller never sees the key path (operator-log only): {msg}"
    );
    let line = refused.operator_line();
    assert!(
        line.contains(&priv_path.display().to_string()) && line.contains("1 sealed row"),
        "the operator line names the path and the count: {line}"
    );

    // Minted NOTHING, wrote NOTHING.
    assert_eq!(listing(key_dir), before, "#3718: no key was minted");
    assert!(!priv_path.exists(), "no impostor .priv");
    assert_eq!(sealed_rows(&conn, &agent), 1, "no second row was written");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'lost-key-2'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "the refused write left no row");
    assert_eq!(
        raw_row(&conn, &first),
        (env_first, content_first),
        "row one untouched"
    );

    // Restore the key from backup: the same write now seals under the
    // original key, and row one still opens.
    write_0600(&priv_path, &priv_bytes);
    evict_cached_keypair(&agent);
    let second = db::insert(&conn, &make_mem("lost-key-2", "row two — #3718", &agent))
        .expect("restored key seals");
    assert_eq!(sealed_rows(&conn, &agent), 2);
    let back = db::get(&conn, &first).expect("read").expect("present");
    assert_eq!(back.content, "row one — #3718");
    let back2 = db::get(&conn, &second).expect("read").expect("present");
    assert_eq!(back2.content, "row two — #3718");
}
