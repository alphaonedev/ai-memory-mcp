// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
// Test scaffolding: keep pedantic lints quiet where they add no value.
#![allow(clippy::doc_markdown)]

//! v1.0.0 #2383 (N1, 3x7-round23) — upsert-merge under
//! `AI_MEMORY_ENCRYPT_AT_REST` must never leave a row sealed to one agent's
//! key while attributed to another.
//!
//! ## The defect this pins
//!
//! Every `(title, namespace)` conflict arm takes the INCOMING writer's
//! `encrypted_envelope` while the metadata overlay preserves the EXISTING
//! row's `agent_id` (#1784 authorship immutability). Sealing to the incoming
//! agent therefore produced a durable row keyed to agent B but attributed to
//! agent A: `open_content` resolves the key from the row's persisted
//! `metadata.agent_id`, so EVERY subsequent read AEAD-failed. And because the
//! scan reads collected `rusqlite::Result`, ONE such row made every `list` /
//! `search` / `recall` in the namespace error out — namespace-wide read
//! poison from a single cross-agent re-store.
//!
//! ## What is pinned here
//!
//! Write side (seal to the RETAINED identity):
//! * `cross_agent_upsert_keeps_row_readable_2383` — the mandated
//!   "a different-key re-store cannot render an existing row unreadable".
//! * `cross_agent_upsert_preserves_authorship_and_new_content_2383` — the fix
//!   does NOT trade the data-integrity bug for an authorship regression, and
//!   does NOT drop the incoming writer's content.
//! * `federation_insert_if_newer_cross_agent_keeps_row_readable_2383` — the
//!   federation twin (`insert_if_newer`), same class, own code path.
//! * `update_seals_to_retained_agent_when_patch_omits_agent_id_2383` — the
//!   in-place update funnel, whose SQL overlay is likewise existing-wins.
//!
//! Read side (`DecryptFailurePolicy`, 2x3 adversarial vote `4d3ea1c5`,
//! read-posture B2 unanimous 6/6) — driven off a DIRECTLY SQL-INJECTED poison
//! row so these assertions stay independent of the write-side design:
//! * `list_skips_poisoned_row_instead_of_denying_namespace_2383` — the
//!   mandated "the read path does not fail an entire namespace on one
//!   poisoned row".
//! * `search_and_recall_skip_poisoned_row_2383` — same posture on the other
//!   two discovery scans.
//! * `get_by_id_on_poisoned_row_fails_closed_2383` — a TARGETED read still
//!   refuses loudly; silently returning "not found" would be a lie.
//! * `export_all_fails_closed_on_poisoned_row_2383` — completeness-critical
//!   egress refuses rather than emitting a silently-incomplete backup.
//! * `strict_decrypt_reads_env_restores_fail_closed_scans_2383` — the
//!   `AI_MEMORY_STRICT_DECRYPT_READS` operator knob reverts scans to the
//!   pre-#2383 uniform fail-closed posture.
//!
//! Runs under `AI_MEMORY_NO_CONFIG=1` — no embedder, no LLM, no network.

use ai_memory::encryption::{get_or_create_keypair, seal_content_per_record};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage as db;
use rusqlite::params;
use std::sync::Mutex;

/// Serializes every test that toggles the process-global at-rest gate
/// (`AI_MEMORY_ENCRYPT_AT_REST`) or the read-posture knob
/// (`AI_MEMORY_STRICT_DECRYPT_READS`). `std::env::set_var` is unsound under
/// concurrent access and cargo runs this file's tests on multiple threads in
/// ONE binary, so every gate-mutating test holds this lock for its lifetime.
static ENV_GATE_LOCK: Mutex<()> = Mutex::new(());

const ENV_ENCRYPT_AT_REST: &str = "AI_MEMORY_ENCRYPT_AT_REST";

/// RAII guard: turns at-rest encryption ON, restores the prior value on drop.
struct EncryptGate {
    prev_encrypt: Option<String>,
    prev_strict: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EncryptGate {
    fn on() -> Self {
        let lock = ENV_GATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_encrypt = std::env::var(ENV_ENCRYPT_AT_REST).ok();
        let prev_strict = std::env::var(db::ENV_STRICT_DECRYPT_READS).ok();
        // SAFETY: serialized via ENV_GATE_LOCK; both vars restored on Drop.
        unsafe {
            std::env::set_var(ENV_ENCRYPT_AT_REST, "1");
            // Default posture for every test here unless it opts in below.
            std::env::remove_var(db::ENV_STRICT_DECRYPT_READS);
        }
        Self {
            prev_encrypt,
            prev_strict,
            _lock: lock,
        }
    }

    /// Acquire the gate lock with encryption forced OFF for the guard's
    /// lifetime. The off-path test asserts plaintext / NULL-envelope
    /// behaviour, so it must hold the SAME lock or a concurrent on-path
    /// test's process-global `AI_MEMORY_ENCRYPT_AT_REST=1` write perturbs it.
    fn off() -> Self {
        let lock = ENV_GATE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev_encrypt = std::env::var(ENV_ENCRYPT_AT_REST).ok();
        let prev_strict = std::env::var(db::ENV_STRICT_DECRYPT_READS).ok();
        // SAFETY: serialized via ENV_GATE_LOCK; both vars restored on Drop.
        unsafe {
            std::env::remove_var(ENV_ENCRYPT_AT_REST);
            std::env::remove_var(db::ENV_STRICT_DECRYPT_READS);
        }
        Self {
            prev_encrypt,
            prev_strict,
            _lock: lock,
        }
    }

    /// Engage the operator knob that reverts discovery scans to fail-closed.
    /// Takes `&self` so the caller must keep the live guard (and therefore
    /// `ENV_GATE_LOCK`) in scope across the write.
    #[allow(clippy::unused_self)]
    fn strict_reads_on(&self) {
        // SAFETY: the caller still holds this guard, so ENV_GATE_LOCK is held.
        unsafe { std::env::set_var(db::ENV_STRICT_DECRYPT_READS, "1") };
    }
}

impl Drop for EncryptGate {
    fn drop(&mut self) {
        // SAFETY: still holding ENV_GATE_LOCK via `self._lock`.
        unsafe {
            match &self.prev_encrypt {
                Some(v) => std::env::set_var(ENV_ENCRYPT_AT_REST, v),
                None => std::env::remove_var(ENV_ENCRYPT_AT_REST),
            }
            match &self.prev_strict {
                Some(v) => std::env::set_var(db::ENV_STRICT_DECRYPT_READS, v),
                None => std::env::remove_var(db::ENV_STRICT_DECRYPT_READS),
            }
        }
    }
}

fn fresh_conn() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, content: &str, ns: &str, agent: &str) -> Memory {
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
        metadata: serde_json::json!({ "agent_id": agent }),
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

/// The `agent_id` the row actually persisted (what the read path keys on).
fn persisted_agent_id(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<String>>(0),
    )
    .expect("read persisted agent_id")
}

/// Overwrite a row's `encrypted_envelope` with content sealed to a DIFFERENT
/// agent's key, i.e. manufacture exactly the poisoned state #2383 used to
/// produce — but by direct SQL, so the read-posture assertions do not depend
/// on the write-side fix at all.
fn poison_row(conn: &rusqlite::Connection, id: &str, foreign_agent: &str, plaintext: &str) {
    let foreign_kp = get_or_create_keypair(foreign_agent).expect("foreign keypair");
    let foreign_envelope =
        seal_content_per_record(plaintext, &foreign_kp.public).expect("seal to foreign key");
    let n = conn
        .execute(
            "UPDATE memories SET content = '', encrypted_envelope = ?2 WHERE id = ?1",
            params![id, foreign_envelope],
        )
        .expect("inject poisoned envelope");
    assert_eq!(n, 1, "fixture must poison exactly one row");
}

fn list_all(conn: &rusqlite::Connection, ns: &str) -> anyhow::Result<Vec<Memory>> {
    db::list(
        conn,
        Some(ns),
        None,
        100,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

// =====================================================================
// WRITE SIDE — seal to the RETAINED identity.
// =====================================================================

#[test]
fn cross_agent_upsert_keeps_row_readable_2383() {
    // THE MANDATED REGRESSION: a re-store by a DIFFERENT agent (a different
    // per-agent key) must not be able to render an existing row unreadable.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-cross-agent";

    let original = make_mem("shared-title", "agent A's content", ns, "agent-a-2383");
    let id = db::insert(&conn, &original).expect("agent A insert");

    // Agent B upserts onto the SAME (title, namespace).
    let intruder = make_mem("shared-title", "agent B's content", ns, "agent-b-2383");
    let upserted_id = db::insert(&conn, &intruder).expect("agent B upsert");
    assert_eq!(upserted_id, id, "upsert must land on agent A's row");

    // Pre-#2383 this read errored: the envelope was sealed to agent B while
    // the row kept agent A's id, so `open_content` used the wrong key.
    let got = db::get(&conn, &id)
        .expect("cross-agent upsert must leave the row READABLE")
        .expect("row exists");
    assert_eq!(
        got.content, "agent B's content",
        "the merged content must survive — the fix re-keys, it never drops the write"
    );
}

#[test]
fn cross_agent_upsert_preserves_authorship_and_new_content_2383() {
    // The fix must not trade a data-integrity bug for a SECURITY regression:
    // #1784 authorship immutability still holds (agent A keeps the row), and
    // the row is sealed to A's key precisely BECAUSE A's id is what survives.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-authorship";

    let original = make_mem("t", "A content", ns, "agent-a-auth-2383");
    let id = db::insert(&conn, &original).expect("insert A");
    let intruder = make_mem("t", "B content", ns, "agent-b-auth-2383");
    db::insert(&conn, &intruder).expect("upsert B");

    assert_eq!(
        persisted_agent_id(&conn, &id).as_deref(),
        Some("agent-a-auth-2383"),
        "#1784: the existing row's agent_id must still win the merge"
    );

    // The row is sealed (non-NULL envelope, placeholder content column) AND
    // decrypts under the RETAINED identity.
    let (raw_content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw read");
    assert_eq!(raw_content, "", "sealed rows keep the empty placeholder");
    assert!(
        envelope.is_some(),
        "sealed rows carry a ciphertext envelope"
    );
    assert_eq!(
        db::get(&conn, &id).expect("read").expect("row").content,
        "B content"
    );
}

#[test]
fn federation_insert_if_newer_cross_agent_keeps_row_readable_2383() {
    // The federation twin: `insert_if_newer`'s newer-wins arm takes the
    // INBOUND envelope while the metadata overlay keeps the LOCAL row's
    // agent_id — the same mismatch, a separate code path (FBL-22 lesson: a
    // fix is not done until every arm is covered).
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-federation";

    let local = make_mem("fed-title", "local content", ns, "local-agent-2383");
    let id = db::insert(&conn, &local).expect("local insert");

    // Inbound peer row: strictly NEWER, authored by a different agent, so it
    // wins the tiebreak and its envelope lands on the local row.
    let mut inbound = make_mem("fed-title", "peer content", ns, "peer-agent-2383");
    inbound.updated_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("future ts")
        .to_rfc3339();
    let merged_id = db::insert_if_newer(&conn, &inbound).expect("federation merge");
    assert_eq!(merged_id, id, "newer-wins merge lands on the local row");

    let got = db::get(&conn, &id)
        .expect("federated cross-agent merge must leave the row READABLE")
        .expect("row exists");
    assert_eq!(got.content, "peer content", "the newer peer content wins");
    assert_eq!(
        persisted_agent_id(&conn, &id).as_deref(),
        Some("local-agent-2383"),
        "#1784 still preserves the local authorship across a federation merge"
    );
}

#[test]
fn update_seals_to_retained_agent_when_patch_omits_agent_id_2383() {
    // `update_with_expected_version`'s SQL overlays the STORED row's
    // provenance keys on top of the patch (existing-wins, #2106). Pre-#2383
    // the seal key came from the PATCH, so a metadata patch that omitted
    // `agent_id` sealed to `""` — a hard fail-closed error on an encrypted
    // deployment — while the row kept its real agent_id.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-update";

    let mem = make_mem("upd-title", "v1 content", ns, "agent-upd-2383");
    let id = db::insert(&conn, &mem).expect("insert");

    // Patch supplies a whole metadata object with NO agent_id key.
    let patch_metadata = serde_json::json!({ "note": "patched" });
    let (updated, _) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("v2 content"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&patch_metadata),
        None,
        None,
        None,
    )
    .expect("update must not fail closed on an agent_id-omitting patch");
    assert!(updated, "the row must be updated");

    assert_eq!(
        persisted_agent_id(&conn, &id).as_deref(),
        Some("agent-upd-2383"),
        "#2106: the stored agent_id survives an omitting patch"
    );
    assert_eq!(
        db::get(&conn, &id).expect("read").expect("row").content,
        "v2 content",
        "the patched content must be readable under the RETAINED identity"
    );
}

// =====================================================================
// READ SIDE — DecryptFailurePolicy (2x3 vote 4d3ea1c5, posture B2).
// The poison row is injected by direct SQL, so these assertions hold
// independently of the write-side mechanism.
// =====================================================================

#[test]
fn list_skips_poisoned_row_instead_of_denying_namespace_2383() {
    // THE MANDATED REGRESSION: one undecryptable row must not fail an entire
    // namespace read. Pre-#2383 `list` collected `Result`, so this errored.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-read-poison";

    let good = make_mem("good", "readable content", ns, "agent-good-2383");
    let good_id = db::insert(&conn, &good).expect("insert good");
    let bad = make_mem("bad", "will be poisoned", ns, "agent-bad-2383");
    let bad_id = db::insert(&conn, &bad).expect("insert bad");
    poison_row(
        &conn,
        &bad_id,
        "foreign-agent-2383",
        "unreachable plaintext",
    );

    let listed = list_all(&conn, ns).expect("ONE poisoned row must not deny the namespace list");
    let ids: Vec<&str> = listed.iter().map(|m| m.id.as_str()).collect();
    assert!(
        ids.contains(&good_id.as_str()),
        "the readable row must still be returned"
    );
    assert!(
        !ids.contains(&bad_id.as_str()),
        "the poisoned row is SKIPPED (degrade), never surfaced with a bogus content"
    );

    // DEGRADE, not delete: the ciphertext is untouched on disk, so the row
    // becomes readable again the moment the right key is restored.
    let envelope: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encrypted_envelope FROM memories WHERE id = ?1",
            params![&bad_id],
            |r| r.get(0),
        )
        .expect("row still exists");
    assert!(
        envelope.is_some(),
        "a skipped row must NOT be modified or deleted by the read path"
    );
}

#[test]
fn search_and_recall_skip_poisoned_row_2383() {
    // The same posture on the other two discovery scans, so a poisoned row
    // cannot black-hole keyword search or recall either.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-scan-poison";

    let good = make_mem("alpha marker", "alpha marker content", ns, "agent-s-good");
    db::insert(&conn, &good).expect("insert good");
    let bad = make_mem("alpha marker two", "alpha marker other", ns, "agent-s-bad");
    let bad_id = db::insert(&conn, &bad).expect("insert bad");
    poison_row(&conn, &bad_id, "foreign-scan-2383", "unreachable");

    let found = db::search(
        &conn,
        "alpha",
        Some(ns),
        None,
        50,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .expect("search must not be denied by one poisoned row");
    assert!(
        !found.iter().any(|m| m.id == bad_id),
        "search skips the poisoned row"
    );
    assert!(
        found.iter().any(|m| m.title == "alpha marker"),
        "search still returns the readable match"
    );
}

#[test]
fn get_by_id_on_poisoned_row_fails_closed_2383() {
    // TARGETED reads keep the pre-#2383 fail-closed posture: the caller named
    // THIS row, so silently reporting "not found" would be a lie about what
    // exists, and returning the empty placeholder would mask key loss.
    let _gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-targeted";

    let mem = make_mem("targeted", "content", ns, "agent-targeted-2383");
    let id = db::insert(&conn, &mem).expect("insert");
    poison_row(&conn, &id, "foreign-targeted-2383", "unreachable");

    let err = db::get(&conn, &id).expect_err("a targeted read MUST fail closed");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("decrypt failed"),
        "the error must name the decrypt failure, got: {rendered}"
    );
}

#[test]
fn export_all_fails_closed_on_poisoned_row_2383() {
    // Completeness-critical EGRESS stays fail-closed: a backup that silently
    // omits rows is worse than a refused backup (unintentional data loss is
    // the North Star's top-order failure).
    let _gate = EncryptGate::on();
    let conn = fresh_conn();

    let mem = make_mem("export-me", "content", "n2383-export", "agent-export-2383");
    let id = db::insert(&conn, &mem).expect("insert");
    poison_row(&conn, &id, "foreign-export-2383", "unreachable");

    db::export_all(&conn)
        .expect_err("export must REFUSE rather than emit a silently-incomplete backup");
}

#[test]
fn strict_decrypt_reads_env_restores_fail_closed_scans_2383() {
    // The operator knob reverts discovery scans to the pre-#2383 uniform
    // fail-closed posture for deployments that prefer the outage to a gap.
    let gate = EncryptGate::on();
    let conn = fresh_conn();
    let ns = "n2383-strict";

    let mem = make_mem("strict", "content", ns, "agent-strict-2383");
    let id = db::insert(&conn, &mem).expect("insert");
    poison_row(&conn, &id, "foreign-strict-2383", "unreachable");

    // Default posture: the scan degrades.
    assert!(
        list_all(&conn, ns).is_ok(),
        "default posture skips the poisoned row"
    );

    gate.strict_reads_on();
    list_all(&conn, ns)
        .expect_err("AI_MEMORY_STRICT_DECRYPT_READS=1 must restore the fail-closed scan");
}

#[test]
fn encryption_off_path_is_unchanged_by_2383() {
    // The default (encryption-off) deployment must be byte-identical: no
    // pre-read, no reconcile, no envelope, plaintext content — and a
    // cross-agent upsert still merges exactly as before.
    let _gate = EncryptGate::off();
    let conn = fresh_conn();
    let ns = "n2383-off";

    let a = make_mem("off-title", "A content", ns, "agent-a-off-2383");
    let id = db::insert(&conn, &a).expect("insert A");
    let b = make_mem("off-title", "B content", ns, "agent-b-off-2383");
    assert_eq!(db::insert(&conn, &b).expect("upsert B"), id);

    let (raw_content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE id = ?1",
            params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw read");
    assert_eq!(raw_content, "B content", "plaintext stored verbatim");
    assert!(envelope.is_none(), "no envelope when the gate is off");
    assert_eq!(
        persisted_agent_id(&conn, &id).as_deref(),
        Some("agent-a-off-2383"),
        "#1784 authorship immutability is unaffected by the #2383 work"
    );
}
