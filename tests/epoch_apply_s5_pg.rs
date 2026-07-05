// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S5 (RQ-10, #1878) — pg-backed-node integration for the
//! epoch consumer (amendment 7). Governance rules live ONLY in the sqlite
//! governance DB on every backend, so even on a Postgres-backed node the
//! epoch consumer reads the LIVE sqlite policy version — the stale-policy
//! refusal must be NON-VACUOUS. This test stands up a real `PostgresStore`
//! (the pg-backed node), advances the sqlite governance policy, and proves
//! a prior-policy manifest is refused while the current one applies.
//! Gated on `sal-postgres` + a live `AI_MEMORY_TEST_POSTGRES_URL`.

#![cfg(feature = "sal-postgres")]

use std::path::Path;

use ai_memory::cli::epoch_apply::{EpochApplyArgs, epoch_content_hash, run};
use ai_memory::identity::keypair::AgentKeypair;
use ai_memory::identity::sign::{SignableEpochManifest, sign_epoch};
use ai_memory::store::postgres::PostgresStore;
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

fn build_manifest(
    sk: &SigningKey,
    epoch_seq: i64,
    policy_seq: i64,
    policy_digest_hex: &str,
    created_at: &str,
) -> Value {
    let body = json!({
        "epoch_seq": epoch_seq,
        "prior_epoch_id": "",
        "policy_seq": policy_seq,
        "policy_digest_hex": policy_digest_hex,
        "panel": {"slots": []},
        "utility_weights": {"frozen_within_epoch": true},
        "created_at": created_at,
    });
    let content = epoch_content_hash(&body).unwrap();
    let signable = SignableEpochManifest {
        epoch_seq,
        prior_epoch_id: "",
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

#[tokio::test]
async fn pg_node_epoch_apply_reads_live_sqlite_policy() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    // The pg-backed node: a real Postgres store is present + migrated.
    let _store = PostgresStore::connect(&url).await.expect("connect pg node");

    // The node's LOCAL sqlite governance + checkpoints + audit chain.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("ai-memory.db");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(&key_dir).unwrap();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    write_operator_key(&key_dir, &sk);

    let conn = ai_memory::db::open(&db_path).unwrap();
    let pv0 = ai_memory::governance::policy_version::current_policy_version(&conn).unwrap();

    // Advance the sqlite governance policy (a signed rule insert).
    {
        use ai_memory::governance::rules_store::{self, Rule};
        let rule = Rule {
            id: "R-pg-epoch".to_string(),
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
        rules_store::insert_signed(&conn, &rule, &sk, "operator").unwrap();
    }
    let pv1 = ai_memory::governance::policy_version::current_policy_version(&conn).unwrap();
    assert!(
        pv1.seq > pv0.seq,
        "sqlite governance policy advanced on the pg node"
    );

    // A manifest bound to the PRIOR policy is refused (non-vacuous).
    let stale = build_manifest(
        &sk,
        0,
        pv0.seq,
        &pv0.digest_hex(),
        "2026-07-04T00:00:00+00:00",
    );
    let err = apply(&db_path, &key_dir, &stale).expect_err("prior-policy manifest is stale");
    assert!(format!("{err:#}").contains("stale policy"), "got: {err:#}");

    // A manifest bound to the CURRENT policy applies.
    let current = build_manifest(
        &sk,
        0,
        pv1.seq,
        &pv1.digest_hex(),
        "2026-07-04T02:00:00+00:00",
    );
    apply(&db_path, &key_dir, &current).expect("current-policy manifest applies");
    let applied: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'epoch.manifest_applied'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(applied, 1);
}
