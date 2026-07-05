// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S5 (RQ-10, #1878) — the verify-only epoch-apply consumer:
//! happy-path triple-anchor write + the full refusal matrix (bad
//! signature, tampered body, non-monotonic `epoch_seq`, stale policy
//! binding), each proving zero rows on refusal.

use std::path::Path;

use ai_memory::cli::epoch_apply::{EpochApplyArgs, epoch_content_hash, run};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::identity::sign::{SignableEpochManifest, sign_epoch};
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Stage the operator key in `dir` in the layout
/// `load_operator_signing_key_from_dir` expects (Layout 2:
/// `operator.key` raw seed + `operator.key.pub` base64url pubkey).
fn write_operator_key(dir: &Path, sk: &SigningKey) {
    let priv_path = dir.join("operator.key");
    std::fs::write(&priv_path, sk.to_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let pub_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
    std::fs::write(dir.join("operator.key.pub"), pub_b64).unwrap();
}

/// Build a manifest doc JSON signed by `sk`, binding the given policy
/// version. `mutate` is applied to the doc object AFTER signing (to
/// forge tamper cases); pass the identity closure for a valid manifest.
fn build_manifest(
    sk: &SigningKey,
    epoch_seq: i64,
    prior_epoch_id: &str,
    policy_seq: i64,
    policy_digest_hex: &str,
    created_at: &str,
) -> Value {
    let body = json!({
        "epoch_seq": epoch_seq,
        "prior_epoch_id": prior_epoch_id,
        "policy_seq": policy_seq,
        "policy_digest_hex": policy_digest_hex,
        "panel": {"slots": []},
        "utility_weights": {"frozen_within_epoch": true},
        "created_at": created_at,
    });
    let content = epoch_content_hash(&body).unwrap();
    let signable = SignableEpochManifest {
        epoch_seq,
        prior_epoch_id,
        policy_seq,
        policy_digest_hex,
        content_sha256: &content,
        created_at,
    };
    let kp = AgentKeypair {
        agent_id: "operator".to_string(),
        public: sk.verifying_key(),
        private: Some(sk.clone()),
    };
    let sig = sign_epoch(&kp, &signable).unwrap();
    let mut doc = body.as_object().unwrap().clone();
    doc.insert("content_hash".to_string(), json!(hex(&content)));
    doc.insert("signature".to_string(), json!(hex(&sig)));
    Value::Object(doc)
}

fn apply(db_path: &Path, key_dir: &Path, manifest: &Value) -> anyhow::Result<()> {
    let mpath = key_dir.join("manifest.json");
    std::fs::write(&mpath, serde_json::to_vec(manifest).unwrap()).unwrap();
    let args = EpochApplyArgs {
        manifest: mpath,
        key_dir: Some(key_dir.to_path_buf()),
    };
    let mut so: Vec<u8> = Vec::new();
    let mut se: Vec<u8> = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    run(db_path, args, true, &mut out)
}

fn epoch_event_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = 'epoch.manifest_applied'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn epoch_checkpoint_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM checkpoints WHERE condition_type = 'epoch_advance'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

/// Fresh temp-file db + a live policy version, so a manifest can bind the
/// CURRENT policy. Returns the temp dir, the db path, the operator key
/// dir, the operator signing key, and the live policy sequence + digest.
fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    SigningKey,
    i64,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("ai-memory.db");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(&key_dir).unwrap();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    write_operator_key(&key_dir, &sk);

    let conn = ai_memory::db::open(&db_path).unwrap();
    let pv = ai_memory::governance::policy_version::current_policy_version(&conn).unwrap();
    (dir, db_path, key_dir, sk, pv.seq, pv.digest_hex())
}

#[test]
fn happy_path_writes_triple_anchor() {
    let (_d, db_path, key_dir, sk, pseq, pdig) = setup();
    let manifest = build_manifest(&sk, 0, "", pseq, &pdig, "2026-07-04T00:00:00+00:00");
    apply(&db_path, &key_dir, &manifest).expect("valid manifest must apply");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(
        epoch_event_count(&conn),
        1,
        "one epoch.manifest_applied row"
    );
    assert_eq!(
        epoch_checkpoint_count(&conn),
        1,
        "one resolved EpochAdvance checkpoint"
    );
    // The checkpoint resolution is the hex content hash and the event
    // payload_hash is the raw content hash — the triple anchor shares it.
    let (resolution, state): (String, String) = conn
        .query_row(
            "SELECT resolution, state FROM checkpoints WHERE condition_type='epoch_advance'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "resolved");
    let payload_hash: Vec<u8> = conn
        .query_row(
            "SELECT payload_hash FROM signed_events WHERE event_type='epoch.manifest_applied'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        resolution,
        hex(&payload_hash),
        "checkpoint resolution == hex(event payload_hash)"
    );
}

#[test]
fn wrong_operator_key_is_refused_zero_rows() {
    let (_d, db_path, key_dir, _sk, pseq, pdig) = setup();
    // Sign with a DIFFERENT key than the one staged in key_dir.
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let manifest = build_manifest(&attacker, 0, "", pseq, &pdig, "2026-07-04T00:00:00+00:00");
    let err = apply(&db_path, &key_dir, &manifest).expect_err("wrong key must refuse");
    assert!(format!("{err:#}").contains("signature"), "got: {err:#}");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(epoch_event_count(&conn), 0);
    assert_eq!(epoch_checkpoint_count(&conn), 0);
}

#[test]
fn tampered_body_is_refused_zero_rows() {
    let (_d, db_path, key_dir, sk, pseq, pdig) = setup();
    let mut manifest = build_manifest(&sk, 0, "", pseq, &pdig, "2026-07-04T00:00:00+00:00");
    // Mutate a signed body field AFTER signing — content_hash no longer
    // matches the body, so integrity fails before signature check.
    manifest
        .as_object_mut()
        .unwrap()
        .insert("prior_epoch_id".to_string(), json!("forged-prior"));
    let err = apply(&db_path, &key_dir, &manifest).expect_err("tamper must refuse");
    assert!(format!("{err:#}").contains("content_hash"), "got: {err:#}");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(epoch_event_count(&conn), 0);
    assert_eq!(epoch_checkpoint_count(&conn), 0);
}

#[test]
fn non_monotonic_epoch_seq_is_refused_zero_rows() {
    let (_d, db_path, key_dir, sk, pseq, pdig) = setup();
    // Fresh db expects epoch_seq == 0; a genesis claiming seq 5 is refused.
    let manifest = build_manifest(&sk, 5, "epoch-4", pseq, &pdig, "2026-07-04T00:00:00+00:00");
    let err = apply(&db_path, &key_dir, &manifest).expect_err("non-monotonic must refuse");
    assert!(format!("{err:#}").contains("non-monotonic"), "got: {err:#}");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(epoch_event_count(&conn), 0);
    assert_eq!(epoch_checkpoint_count(&conn), 0);
}

#[test]
fn stale_policy_binding_is_refused_zero_rows() {
    let (_d, db_path, key_dir, sk, pseq, _pdig) = setup();
    // Bind a WRONG policy digest (stale) — dead on arrival.
    let manifest = build_manifest(
        &sk,
        0,
        "",
        pseq,
        "deadbeefdeadbeef",
        "2026-07-04T00:00:00+00:00",
    );
    let err = apply(&db_path, &key_dir, &manifest).expect_err("stale policy must refuse");
    assert!(format!("{err:#}").contains("stale policy"), "got: {err:#}");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(epoch_event_count(&conn), 0);
    assert_eq!(epoch_checkpoint_count(&conn), 0);
}

/// Advance the sqlite governance policy (a signed rule mutation bumps
/// `policy_seq` + changes the digest) and prove the stale-policy refusal
/// is NON-VACUOUS: a manifest bound to the PRIOR policy is refused, while
/// one bound to the CURRENT policy applies. This is the amendment-7
/// evidence that the epoch consumer reads the LIVE governance policy.
fn advance_policy(conn: &rusqlite::Connection, sk: &SigningKey, id: &str) {
    use ai_memory::governance::rules_store::{self, Rule};
    let rule = Rule {
        id: id.to_string(),
        kind: "bash".to_string(),
        matcher: r#"{"command_substring":"rm -rf"}"#.to_string(),
        severity: "refuse".to_string(),
        reason: "test".to_string(),
        namespace: "_global".to_string(),
        created_by: "operator".to_string(),
        created_at: 12345,
        enabled: true,
        signature: None,
        attest_level: "unsigned".to_string(),
    };
    rules_store::insert_signed(conn, &rule, sk, "operator").unwrap();
}

#[test]
fn stale_policy_after_advance_is_non_vacuous() {
    let (_d, db_path, key_dir, sk, pseq0, pdig0) = setup();

    // Advance the live governance policy on the same sqlite db.
    {
        let conn = ai_memory::db::open(&db_path).unwrap();
        advance_policy(&conn, &sk, "R-epoch-1");
    }
    let conn = ai_memory::db::open(&db_path).unwrap();
    let pv1 = ai_memory::governance::policy_version::current_policy_version(&conn).unwrap();
    assert!(pv1.seq > pseq0, "policy advanced");
    assert_ne!(pv1.digest_hex(), pdig0, "digest changed");

    // A manifest bound to the PRIOR (now stale) policy is refused.
    let stale = build_manifest(&sk, 0, "", pseq0, &pdig0, "2026-07-04T00:00:00+00:00");
    let err = apply(&db_path, &key_dir, &stale).expect_err("prior-policy manifest is stale");
    assert!(format!("{err:#}").contains("stale policy"), "got: {err:#}");
    assert_eq!(epoch_event_count(&conn), 0, "no rows on stale refusal");

    // A manifest bound to the CURRENT policy applies.
    let current = build_manifest(
        &sk,
        0,
        "",
        pv1.seq,
        &pv1.digest_hex(),
        "2026-07-04T02:00:00+00:00",
    );
    apply(&db_path, &key_dir, &current).expect("current-policy manifest applies");
    assert_eq!(epoch_event_count(&conn), 1);
}

#[test]
fn two_epochs_apply_monotonically() {
    let (_d, db_path, key_dir, sk, pseq, pdig) = setup();
    let m0 = build_manifest(&sk, 0, "", pseq, &pdig, "2026-07-04T00:00:00+00:00");
    apply(&db_path, &key_dir, &m0).expect("epoch 0 applies");
    // Second epoch must be seq 1 (prior + 1); policy unchanged.
    let m1 = build_manifest(&sk, 1, "epoch-0", pseq, &pdig, "2026-07-04T01:00:00+00:00");
    apply(&db_path, &key_dir, &m1).expect("epoch 1 applies");

    let conn = ai_memory::db::open(&db_path).unwrap();
    assert_eq!(epoch_event_count(&conn), 2);
    assert_eq!(epoch_checkpoint_count(&conn), 2);
}
