// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
// Test scaffolding: keep pedantic lints quiet where they add no value.
#![allow(clippy::doc_markdown)]

//! v0.7.0 (issue #228) — E2E memory content encryption at rest.
//!
//! This regression suite pins the substrate-level encryption contract
//! end-to-end:
//!
//! 1. Schema v44 migration applies cleanly on a fresh database —
//!    `memories.encrypted_envelope BLOB NULL` column is present, and
//!    `schema_version` reaches the binary's `CURRENT_SCHEMA_VERSION`.
//!
//! 2. Round-trip: encrypt plaintext → persist the envelope in the
//!    `encrypted_envelope` column → re-read the envelope from the
//!    DB → decrypt → recover the original plaintext byte-for-byte.
//!
//! 3. Non-encrypted memories are unchanged: the new column is NULL,
//!    the `content` column carries plaintext, and `db::get` returns
//!    the memory with the original `content` intact (zero behaviour
//!    drift for callers that haven't opted into encryption).
//!
//! 4. AEAD tamper detection: flipping a bit in the persisted envelope
//!    causes `decrypt` to fail (no silent plaintext fallback).
//!
//! 5. The encryption gate (`encryption_enabled`) respects both the
//!    config flag (`Some(true)`) and the `AI_MEMORY_ENCRYPT_AT_REST`
//!    env var, and defaults to off when neither source opts in.
//!
//! Runs under `AI_MEMORY_NO_CONFIG=1` — no embedder, no LLM, no
//! network dependencies.

use ai_memory::encryption::{
    Envelope, decrypt, encrypt, encryption_enabled, get_or_create_keypair,
};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use rusqlite::params;

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, content: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
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
        metadata: serde_json::json!({}),
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

#[test]
fn schema_v44_migration_applies_cleanly_and_adds_encrypted_envelope_column() {
    // Opening a fresh in-memory database runs migrate() implicitly via
    // `db::open`. The terminal version must equal the binary's
    // CURRENT_SCHEMA_VERSION, and the new column must be present on
    // the `memories` table.
    let conn = fresh_conn();

    let version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .expect("read schema_version");
    let expected = db::current_schema_version_for_tests();
    assert_eq!(
        version, expected,
        "schema_version must reach the binary's CURRENT_SCHEMA_VERSION ({expected}); \
         got {version}"
    );
    assert!(
        version >= 44,
        "v44 substrate must be installed (issue #228); got {version}"
    );

    // The encrypted_envelope BLOB column must be present.
    let mut stmt = conn
        .prepare("PRAGMA table_info(memories)")
        .expect("prepare PRAGMA");
    let cols: Vec<(String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .expect("query_map")
        .filter_map(Result::ok)
        .collect();
    let found = cols
        .iter()
        .find(|(name, _)| name == "encrypted_envelope")
        .expect("encrypted_envelope column must be present on memories after v44");
    assert!(
        found.1.eq_ignore_ascii_case("BLOB"),
        "encrypted_envelope must be BLOB-typed; got {}",
        found.1
    );
}

#[test]
fn encrypt_store_recall_decrypt_recovers_plaintext() {
    let conn = fresh_conn();

    // Caller-side: encrypt the plaintext content to the agent's
    // X25519 pubkey, then persist the envelope bytes on the
    // `encrypted_envelope` column. The `content` column carries the
    // empty placeholder. The memory's metadata.agent_id MUST match the
    // seal recipient so the #228 Commit B read path
    // (`row_to_memory` → `open_content`) can decrypt transparently.
    let agent = "test-agent-228";
    let plaintext = "the launch codes are 1138, 0451, 4815";
    let kp = get_or_create_keypair(agent).expect("keypair");
    let envelope = encrypt(plaintext, &kp.public).expect("encrypt");
    let envelope_bytes = envelope.to_bytes();

    // Insert the memory with the empty placeholder content + agent_id.
    let mut mem = make_mem("issue-228-roundtrip", "", "global");
    mem.metadata = serde_json::json!({ "agent_id": agent });
    let mem_id = mem.id.clone();
    let actual_id = db::insert(&conn, &mem).expect("insert");
    assert_eq!(actual_id, mem_id);

    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![envelope_bytes, &actual_id],
    )
    .expect("persist envelope");

    // Raw reader-side: pull the blob back out, parse the envelope, and
    // decrypt with the recipient's secret key. Must recover the
    // original plaintext byte-for-byte.
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&actual_id],
            |r| r.get(0),
        )
        .expect("read envelope back");
    assert_eq!(stored, envelope_bytes, "envelope bytes must round-trip");

    let parsed = Envelope::from_bytes(&stored).expect("parse envelope");
    let recovered = decrypt(&parsed, &kp.secret).expect("decrypt");
    assert_eq!(
        recovered, plaintext,
        "decrypt must recover the original plaintext byte-for-byte"
    );

    // #228 Commit B — `db::get` now TRANSPARENTLY decrypts: the envelope
    // is present, the agent_id matches the seal key, so the read path
    // recovers the plaintext into `content` (no placeholder leak).
    let fetched = db::get(&conn, &actual_id)
        .expect("db::get")
        .expect("memory must exist");
    assert_eq!(fetched.id, actual_id);
    assert_eq!(fetched.title, "issue-228-roundtrip");
    assert_eq!(
        fetched.content, plaintext,
        "#228 Commit B: db::get transparently decrypts envelope content"
    );

    // Silence unused-mut on mem — kept mutable so the make_mem helper
    // signature stays compatible with mutation patterns in sibling
    // tests.
    let _ = &mut mem;
}

#[test]
fn non_encrypted_memories_unchanged_after_v44() {
    // #228 Commit B — hold the gate lock with encryption forced OFF so a
    // concurrent on-path test's process-global env write can't flip this
    // off-path assertion (envelope must stay NULL with the gate disabled).
    let _gate = EncryptGate::off();
    // A memory written without the encryption opt-in carries
    // plaintext in `content` and NULL in `encrypted_envelope`. The
    // public `Memory` shape and the existing read paths must behave
    // exactly as they did pre-v44.
    let conn = fresh_conn();
    let plaintext = "this is plaintext, encryption gate off";
    let mem = make_mem("issue-228-non-encrypted", plaintext, "global");
    let actual_id = db::insert(&conn, &mem).expect("insert");

    let envelope: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&actual_id],
            |r| r.get(0),
        )
        .expect("query");
    assert!(
        envelope.is_none(),
        "non-encrypted memories must leave encrypted_envelope NULL"
    );

    let fetched = db::get(&conn, &actual_id)
        .expect("db::get")
        .expect("memory must exist");
    assert_eq!(fetched.content, plaintext);
}

#[test]
fn tampered_envelope_bytes_fail_aead_authentication() {
    // #228 Commit B — force the gate OFF so db::insert stores the
    // placeholder content verbatim (no re-seal) and the test's manually
    // tampered envelope is what db::get decrypts → fail-closed. Without
    // this, a leaked on-path env write would make insert seal the row.
    let _gate = EncryptGate::off();
    // The AEAD tag in ChaCha20-Poly1305 is non-malleable: any change
    // to the on-disk bytes — ephemeral pubkey, nonce, or ciphertext —
    // must cause decrypt to fail. No silent plaintext leak.
    let conn = fresh_conn();
    let agent = "test-agent-228-tamper";
    let kp = get_or_create_keypair(agent).expect("keypair");
    let envelope = encrypt("tamper-detect-payload", &kp.public).expect("encrypt");
    let mut bytes = envelope.to_bytes();
    // Flip a bit deep in the ciphertext (after the 1-byte version +
    // 32-byte pubkey + 12-byte nonce header).
    let cipher_idx = 1 + 32 + 12 + 4;
    bytes[cipher_idx] ^= 0x55;

    let mem = make_mem("issue-228-tamper", "[ENCRYPTED]", "global");
    let id = db::insert(&conn, &mem).expect("insert");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![bytes, &id],
    )
    .expect("persist tampered envelope");

    let stored: Vec<u8> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| r.get(0),
        )
        .expect("read");
    let parsed = Envelope::from_bytes(&stored).expect("parse tampered envelope");
    assert!(
        decrypt(&parsed, &kp.secret).is_err(),
        "AEAD must refuse to decrypt a tampered envelope"
    );
}

#[test]
fn encryption_gate_consults_config_flag_and_env_var() {
    // #228 Commit B — hold ENV_GATE_LOCK so this gate-mutating test
    // cannot interleave with the Commit-B on/off-path tests' process-
    // global `AI_MEMORY_ENCRYPT_AT_REST` writes.
    let _lock = ENV_GATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Save + restore the env var so this test doesn't perturb the
    // process state for sibling tests.
    let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
    // SAFETY: serialized via ENV_GATE_LOCK; restored at the end.
    unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
    assert!(!encryption_enabled(None), "default off");
    assert!(encryption_enabled(Some(true)), "config flag opts in");
    assert!(!encryption_enabled(Some(false)), "explicit false stays off");
    unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
    assert!(encryption_enabled(None), "env var opts in");
    unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "no") };
    assert!(!encryption_enabled(None), "falsy env stays off");

    // Restore.
    if let Some(v) = prev {
        unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v) };
    } else {
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
    }
}

// =====================================================================
// #228 Commit B — at-rest content-encryption WIRING (end-to-end).
//
// These tests exercise the full storage write+read wiring: with the
// `AI_MEMORY_ENCRYPT_AT_REST` gate on, `db::insert` seals content into
// `encrypted_envelope` and stores the empty placeholder in `content`;
// `db::get` transparently decrypts. With the gate off (default) the
// path is byte-identical to pre-wiring (plaintext content, NULL
// envelope). A row with a non-NULL envelope whose key is absent
// fails-closed on read (never leaks the placeholder), and a row written
// while the gate was on stays readable after the gate is toggled off
// (decrypt is gated on envelope PRESENCE, not the env var).
//
// `AI_MEMORY_ENCRYPT_AT_REST` is process-global, and cargo runs the
// tests in one integration binary on multiple threads, so the gate-
// mutating tests serialize through `ENV_GATE_LOCK`. They save + restore
// the prior env value so non-gate tests in this binary are unperturbed.
// =====================================================================

use std::sync::Mutex;

/// Serializes every test that toggles `AI_MEMORY_ENCRYPT_AT_REST`.
static ENV_GATE_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard: sets the gate to `on`, restores the prior value on drop.
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

    /// Toggle the gate OFF while the guard is still alive (the caller
    /// keeps `self` in scope, so `ENV_GATE_LOCK` stays held across the
    /// toggle — no other gate-mutating test can interleave).
    // `&self` is intentional: requiring the receiver forces the caller to
    // keep the live `EncryptGate` (and thus the held lock) in scope across
    // the toggle. The body doesn't read a field, but the contract is the
    // borrow itself.
    #[allow(clippy::unused_self)]
    fn toggle_off(&self) {
        // SAFETY: the caller still holds this `EncryptGate`, so the inner
        // `_lock` MutexGuard keeps ENV_GATE_LOCK acquired across this write.
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
    }

    /// Acquire the gate lock with encryption forced OFF for the guard's
    /// lifetime. Off-path tests (which assert plaintext/NULL-envelope
    /// behaviour) hold this so a concurrent on-path test's process-global
    /// `AI_MEMORY_ENCRYPT_AT_REST=1` write cannot perturb them. Restores
    /// the prior value on drop.
    fn off() -> Self {
        let lock = ENV_GATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
        // SAFETY: serialized via ENV_GATE_LOCK; restored on Drop.
        unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };
        Self { prev, _lock: lock }
    }
}

impl Drop for EncryptGate {
    fn drop(&mut self) {
        // SAFETY: still holding ENV_GATE_LOCK via `self._lock`.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
                None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
            }
        }
    }
}

#[test]
fn commit_b_on_path_seals_content_and_get_decrypts() {
    let _gate = EncryptGate::on();
    let conn = fresh_conn();

    let agent = "commit-b-on-agent";
    let plaintext = "sensitive at-rest content — #228 Commit B ON path";
    let mut mem = make_mem("commit-b-on", plaintext, "global");
    mem.metadata = serde_json::json!({ "agent_id": agent });
    let id = db::insert(&conn, &mem).expect("insert under encryption");

    // Raw row: content column holds the empty placeholder, envelope NOT NULL.
    let (raw_content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw read");
    assert_eq!(
        raw_content, "",
        "encryption ON: content column must hold the empty placeholder"
    );
    assert!(
        envelope.is_some(),
        "encryption ON: encrypted_envelope must be non-NULL"
    );

    // db::get transparently decrypts back to the original plaintext.
    let fetched = db::get(&conn, &id).expect("get").expect("exists");
    assert_eq!(
        fetched.content, plaintext,
        "encryption ON: db::get must recover the original plaintext"
    );
}

#[test]
fn commit_b_off_path_is_byte_identical() {
    // No gate: the default (encryption-off) path. Content is stored
    // verbatim and encrypted_envelope is NULL — byte-identical to the
    // pre-wiring behaviour.
    let _lock = ENV_GATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = std::env::var("AI_MEMORY_ENCRYPT_AT_REST").ok();
    // SAFETY: serialized via ENV_GATE_LOCK.
    unsafe { std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST") };

    let conn = fresh_conn();
    let plaintext = "plaintext content, gate OFF — #228 Commit B";
    let mut mem = make_mem("commit-b-off", plaintext, "global");
    mem.metadata = serde_json::json!({ "agent_id": "commit-b-off-agent" });
    let id = db::insert(&conn, &mem).expect("insert");

    let (raw_content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw read");
    assert_eq!(
        raw_content, plaintext,
        "encryption OFF: content column must hold the plaintext verbatim"
    );
    assert!(
        envelope.is_none(),
        "encryption OFF: encrypted_envelope must be NULL (byte-identical default)"
    );

    let fetched = db::get(&conn, &id).expect("get").expect("exists");
    assert_eq!(fetched.content, plaintext);

    // SAFETY: serialized via ENV_GATE_LOCK.
    unsafe {
        match prev {
            Some(v) => std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", v),
            None => std::env::remove_var("AI_MEMORY_ENCRYPT_AT_REST"),
        }
    }
}

#[test]
fn commit_b_missing_key_fails_closed_on_read() {
    // An encrypted row whose recipient keypair cannot decrypt the
    // envelope (sealed to agent A but the row's metadata.agent_id names
    // agent B) must FAIL the read — never return the empty placeholder
    // as if it were the plaintext content.
    let conn = fresh_conn();

    let seal_agent = "commit-b-seal-agent";
    let wrong_agent = "commit-b-wrong-agent";
    let kp = get_or_create_keypair(seal_agent).expect("keypair");
    let envelope = encrypt("secret for seal_agent", &kp.public).expect("encrypt");
    let envelope_bytes = envelope.to_bytes();

    // Row carries the WRONG agent_id, so row_to_memory resolves a
    // different keypair and decrypt fails.
    let mut mem = make_mem("commit-b-fail-closed", "", "global");
    mem.metadata = serde_json::json!({ "agent_id": wrong_agent });
    let id = db::insert(&conn, &mem).expect("insert");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![envelope_bytes, &id],
    )
    .expect("persist envelope sealed to a DIFFERENT agent");

    let result = db::get(&conn, &id);
    assert!(
        result.is_err(),
        "fail-closed: an undecryptable envelope must error the read, not leak the placeholder"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("decrypt failed"),
        "fail-closed error must name the decrypt failure; got: {msg}"
    );
}

#[test]
fn commit_b_toggle_off_still_reads_encrypted_rows() {
    // Write a row under encryption ON, then read it with the gate OFF.
    // Decryption is gated on envelope PRESENCE (not the env var), so the
    // row stays readable — toggling the flag off does not strand data.
    let gate = EncryptGate::on();
    let conn = fresh_conn();

    let agent = "commit-b-toggle-agent";
    let plaintext = "written while ON, read while OFF — #228 Commit B";
    let mut mem = make_mem("commit-b-toggle", plaintext, "global");
    mem.metadata = serde_json::json!({ "agent_id": agent });
    let id = db::insert(&conn, &mem).expect("insert under encryption ON");

    // Sanity: stored encrypted.
    let envelope: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| r.get(0),
        )
        .expect("read envelope");
    assert!(envelope.is_some(), "row must be stored encrypted");

    // Now toggle the gate OFF and read — decrypt still fires on presence.
    gate.toggle_off();
    let fetched = db::get(&conn, &id).expect("get").expect("exists");
    assert_eq!(
        fetched.content, plaintext,
        "toggle-off: encrypted rows stay readable (decrypt gated on envelope presence)"
    );
}

#[test]
fn get_memory_texts_batch_decrypts_encrypted_rows_1779() {
    // #1779 — reembed/backfill must embed the DECRYPTED content of an
    // at-rest-encrypted row, NOT the empty placeholder. Embedding the
    // placeholder yields a title-only vector and `set_embeddings_batch_reembed`
    // REPLACE semantics would burn it over the good store-time embedding
    // corpus-wide. A row whose envelope won't decrypt must be SKIPPED (omitted)
    // rather than embedded as a placeholder. Hermetic: builds envelopes
    // manually + holds the gate OFF so a concurrent on-path env write can't
    // make db::insert re-seal.
    let _gate = EncryptGate::off();
    let conn = fresh_conn();

    let agent = "reembed-1779-agent";
    let plaintext = "secret content that must be embedded, not the placeholder";
    let kp = get_or_create_keypair(agent).expect("keypair");
    let envelope_bytes = encrypt(plaintext, &kp.public).expect("encrypt").to_bytes();

    // Encrypted row: empty placeholder content + envelope + matching agent_id.
    let mut enc = make_mem("enc-1779", "", "global");
    enc.metadata = serde_json::json!({ "agent_id": agent });
    let enc_id = db::insert(&conn, &enc).expect("insert enc");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![envelope_bytes, &enc_id],
    )
    .expect("persist envelope");

    // Plain (unencrypted) row — content passes through verbatim.
    let plain = make_mem("plain-1779", "plain content here", "global");
    let plain_id = db::insert(&conn, &plain).expect("insert plain");

    // Undecryptable row: envelope present, but metadata.agent_id points at a
    // different agent whose key can't open it → must be SKIPPED.
    let mut orphan = make_mem("orphan-1779", "", "global");
    orphan.metadata = serde_json::json!({ "agent_id": "orphan-1779-no-key-match" });
    let orphan_id = db::insert(&conn, &orphan).expect("insert orphan");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![envelope_bytes, &orphan_id],
    )
    .expect("persist orphan envelope");

    let rows = db::get_memory_texts_batch(&conn, None, None, 100).expect("texts batch");
    let by_id: std::collections::HashMap<String, String> =
        rows.into_iter().map(|(id, _t, c)| (id, c)).collect();

    assert_eq!(
        by_id.get(&enc_id).map(String::as_str),
        Some(plaintext),
        "#1779: encrypted row must surface DECRYPTED content for embedding"
    );
    assert_eq!(
        by_id.get(&plain_id).map(String::as_str),
        Some("plain content here"),
        "plain row passes through verbatim"
    );
    assert!(
        !by_id.contains_key(&orphan_id),
        "#1779: undecryptable encrypted row must be SKIPPED, not embedded as placeholder"
    );
}

#[test]
fn federation_merge_seals_content_and_snapshots_1773() {
    // #1773 — a same-id federation merge (LWW remote-wins) must re-seal the
    // merged content + set encrypted_envelope as a MATCHED PAIR. Pre-fix the
    // overwrite wrote plaintext into `content` but left the STALE envelope, so
    // the next read decrypted the OLD content (silent merge loss). It must also
    // take a pre-merge snapshot (recoverable copy). Encryption ON via the gate.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let agent = "merge-1773-agent";

    // Existing local row — under the gate, db::insert seals "original".
    let mut existing = make_mem("merge-1773", "original local content", "global");
    existing.metadata = serde_json::json!({ "agent_id": agent });
    existing.updated_at = "2026-01-01T00:00:00+00:00".to_string();
    let id = db::insert(&conn, &existing).expect("insert existing");

    // Inbound federated row: SAME id, NEWER updated_at → remote content wins.
    let mut inbound = existing.clone();
    inbound.content = "merged via federation".to_string();
    inbound.updated_at = "2026-06-01T00:00:00+00:00".to_string();
    db::merge_inbound(&conn, &inbound).expect("merge_inbound");

    // HIGH: read must return the MERGED content (re-sealed), not stale.
    let fetched = db::get(&conn, &id).expect("get").expect("exists");
    assert_eq!(
        fetched.content, "merged via federation",
        "#1773: federation merge must re-seal content (no stale-envelope desync)"
    );
    // The merged row carries a (fresh) non-NULL envelope under encryption.
    let env: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| r.get(0),
        )
        .expect("env query");
    assert!(
        env.is_some(),
        "#1773: merged encrypted row must carry a fresh envelope"
    );
    // MEDIUM: a pre-merge snapshot was archived (recoverable copy).
    let snap_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1 AND archive_reason = 'federation_merge'",
            params![&id],
            |r| r.get(0),
        )
        .expect("snap count");
    assert_eq!(
        snap_count, 1,
        "#1773: federation merge must snapshot the pre-merge row"
    );
}
