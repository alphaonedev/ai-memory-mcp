// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S5 (RQ-10, #1878) — `ai-memory epoch-apply <manifest>`:
//! the VERIFY-ONLY epoch-freeze consumer.
//!
//! Pipeline (refuse-and-stop on any failure; zero rows on refusal):
//!   1. serde-parse the manifest JSON (the runtime contract IS this
//!      struct — the git-tracked JSON Schema under `docs/contracts/` is
//!      NEVER `include_str!`d from `src/`; schema-vs-struct conformance
//!      is asserted in `tests/`. See ROADMAP §25.2/§25.3).
//!   2. recompute the content hash over the canonical body bytes and pin
//!      it against the manifest's declared `content_hash` (integrity).
//!   3. verify the operator Ed25519 signature over the canonical CBOR of
//!      the [`crate::identity::sign::SignableEpochManifest`]
//!      ([`crate::identity::sign::verify_epoch`]), pinning the operator
//!      pubkey from the on-disk operator key.
//!   4. `epoch_seq == prior + 1` against the count of already-applied
//!      `epoch.manifest_applied` events (strict monotonic advance).
//!   5. policy binding: `(policy_seq, policy_digest_hex)` MUST equal the
//!      live [`crate::governance::policy_version::current_policy_version`]
//!      read from the sqlite governance DB (the sole rules store on every
//!      backend, amendment 7) — a stale-policy manifest is dead on arrival.
//!   6. in ONE transaction: insert + resolve an `EpochAdvance` checkpoint
//!      (`resolution = hex(content_hash)`, operator-signed) AND append the
//!      V-4 `epoch.manifest_applied` audit row (`payload_hash =
//!      content_hash`, operator-signed). The triple anchor (signed file +
//!      resolved checkpoint + audit row) shares ONE SHA-256.
//!
//! "epoch closure shipped" / "RQ-01 shipped" is claimable ONLY because
//! this wired + git-tracked consumer exists.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::CliOutput;
use crate::cli::rules::{OPERATOR_KEY_ID, load_operator_signing_key_from_dir, resolve_key_dir};
use crate::identity::keypair::AgentKeypair;
use crate::identity::sign::{SignableEpochManifest, verify_epoch};

#[derive(Args)]
pub struct EpochApplyArgs {
    /// Path to the operator-signed epoch manifest JSON.
    pub manifest: PathBuf,
    /// Override the default key storage directory.
    /// Honors `AI_MEMORY_KEY_DIR` when omitted.
    #[arg(long, value_name = "PATH")]
    pub key_dir: Option<PathBuf>,
}

/// The signed body of an epoch manifest — every field EXCEPT
/// `content_hash` + `signature`. Serialized in declaration order
/// (serde is deterministic for a struct), so the SHA-256 over these bytes
/// is a stable content fingerprint an auditor can re-derive.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochManifestBody {
    epoch_seq: i64,
    prior_epoch_id: String,
    policy_seq: i64,
    policy_digest_hex: String,
    panel: serde_json::Value,
    utility_weights: serde_json::Value,
    created_at: String,
}

/// The full on-disk manifest document (body + `content_hash` +
/// `signature`). This serde struct is the RUNTIME contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochManifestDoc {
    #[serde(flatten)]
    body: EpochManifestBody,
    /// Lowercase-hex SHA-256 over the canonical body bytes.
    content_hash: String,
    /// Lowercase-hex 64-byte operator Ed25519 signature over the
    /// canonical CBOR of the [`SignableEpochManifest`].
    signature: String,
}

/// v0.9.0 §25.3 S5 — the canonical content hash of an epoch manifest
/// body: SHA-256 over the KEY-SORTED JSON serialization of the body
/// object (serde_json serializes `Value` map keys in sorted order — the
/// crate is built WITHOUT `preserve_order`). Deterministic and
/// declaration-order-independent, so an operator sealing a manifest and
/// the consumer verifying it re-derive the identical hash. Exposed so
/// manifest-producing tooling / tests bind to the exact same encoding.
///
/// # Errors
/// Propagates `serde_json` encoding errors (unreachable for the fixed
/// value shape).
pub fn epoch_content_hash(body_value: &serde_json::Value) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(body_value).context("serialize epoch manifest body")?;
    Ok(Sha256::digest(&bytes).into())
}

fn canonical_body_hash(body: &EpochManifestBody) -> Result<[u8; 32]> {
    let v = serde_json::to_value(body).context("epoch manifest body → value")?;
    epoch_content_hash(&v)
}

/// Count of already-applied `epoch.manifest_applied` events — the prior
/// epoch sequence is this minus one, so the next valid `epoch_seq` equals
/// the count (genesis = 0 at count 0).
fn applied_epoch_count(conn: &rusqlite::Connection) -> Result<i64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [crate::signed_events::event_types::EPOCH_APPLIED],
            |row| row.get(0),
        )
        .context("epoch-apply: count applied epochs")?;
    Ok(count)
}

/// Entry point for `ai-memory epoch-apply`.
///
/// # Errors
///
/// Refuses (returns `Err`, writing nothing) on: unreadable/malformed
/// manifest, content-hash mismatch, bad/absent operator signature,
/// non-monotonic `epoch_seq`, or a stale/mismatched policy binding.
pub fn run(
    db_path: &Path,
    args: EpochApplyArgs,
    json: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // 1. Parse the manifest (serde struct = runtime contract).
    let raw = std::fs::read(&args.manifest)
        .with_context(|| format!("epoch-apply: read manifest {}", args.manifest.display()))?;
    let doc: EpochManifestDoc =
        serde_json::from_slice(&raw).context("epoch-apply: parse manifest JSON")?;

    // 2. Content-hash integrity.
    let computed = canonical_body_hash(&doc.body)?;
    let computed_hex = crate::signed_events::hex_lower(&computed);
    if computed_hex != doc.content_hash {
        bail!(
            "epoch-apply: content_hash mismatch (declared={}, computed={computed_hex}) — \
             manifest body was tampered",
            doc.content_hash
        );
    }

    // 3. Operator signature over the canonical CBOR of the signable view.
    let key_dir = resolve_key_dir(args.key_dir.as_deref())?;
    let signing_key = load_operator_signing_key_from_dir(&key_dir)?;
    let operator_pubkey = signing_key.verifying_key();
    let sig_bytes = hex_decode(&doc.signature)
        .context("epoch-apply: manifest signature is not valid lowercase hex")?;
    let signable = SignableEpochManifest {
        epoch_seq: doc.body.epoch_seq,
        prior_epoch_id: &doc.body.prior_epoch_id,
        policy_seq: doc.body.policy_seq,
        policy_digest_hex: &doc.body.policy_digest_hex,
        content_sha256: &computed,
        created_at: &doc.body.created_at,
    };
    verify_epoch(&operator_pubkey, &signable, &sig_bytes)
        .context("epoch-apply: operator signature verification failed")?;

    // Open the sqlite substrate (checkpoints + signed_events + the
    // governance policy surface all live here).
    let conn = crate::db::open(db_path)
        .with_context(|| format!("epoch-apply: open db {}", db_path.display()))?;

    // 4. Strict monotonic epoch advance (epoch_seq == prior + 1).
    let expected_seq = applied_epoch_count(&conn)?;
    if doc.body.epoch_seq != expected_seq {
        bail!(
            "epoch-apply: non-monotonic epoch_seq (manifest={}, expected next={expected_seq}) — \
             an epoch must be exactly one beyond the last applied",
            doc.body.epoch_seq
        );
    }

    // 5. Policy binding vs the live governance policy version (sqlite is
    //    the sole rules store on every backend — amendment 7).
    let pv = crate::governance::policy_version::current_policy_version(&conn)?;
    if doc.body.policy_seq != pv.seq || doc.body.policy_digest_hex != pv.digest_hex() {
        bail!(
            "epoch-apply: stale policy binding (manifest seq={}/digest={}, live seq={}/digest={}) \
             — a manifest must bind the CURRENT governance policy",
            doc.body.policy_seq,
            doc.body.policy_digest_hex,
            pv.seq,
            pv.digest_hex()
        );
    }

    // 6. Triple anchor in ONE transaction: resolved EpochAdvance
    //    checkpoint + the V-4 epoch.manifest_applied audit row, sharing
    //    the single content hash.
    let operator_kp = AgentKeypair {
        agent_id: OPERATOR_KEY_ID.to_string(),
        public: operator_pubkey,
        private: Some(signing_key.clone()),
    };
    let now = chrono::Utc::now().timestamp();
    let content_hex = computed_hex.clone();

    let tx = rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)
        .context("epoch-apply: begin IMMEDIATE tx")?;

    // Resolved EpochAdvance checkpoint — resolution = hex(content_hash),
    // operator-signed over the canonical resolution tuple.
    let mut cp = crate::models::Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "_epoch".to_string(),
        title: format!("epoch advance {}", doc.body.epoch_seq),
        condition_type: crate::models::ConditionType::EpochAdvance,
        condition: serde_json::Value::Null,
        state: crate::models::CheckpointState::Resolved,
        created_by: OPERATOR_KEY_ID.to_string(),
        resolved_by: Some(OPERATOR_KEY_ID.to_string()),
        resolution: Some(content_hex.clone()),
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: now,
        deadline_at: None,
        resolved_at: Some(now),
        metadata: serde_json::Value::Null,
    };
    crate::checkpoints::sign_resolution_into(&mut cp, &operator_kp)
        .context("epoch-apply: sign EpochAdvance checkpoint resolution")?;
    crate::checkpoints::insert(&tx, &cp).context("epoch-apply: insert EpochAdvance checkpoint")?;

    // V-4 epoch.manifest_applied audit row — payload_hash = content_hash,
    // operator-signed over that hash (the remove_signed idiom).
    let event_sig = signing_key.sign(&computed);
    let event = crate::signed_events::SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: OPERATOR_KEY_ID.to_string(),
        event_type: crate::signed_events::event_types::EPOCH_APPLIED.to_string(),
        payload_hash: computed.to_vec(),
        signature: Some(event_sig.to_bytes().to_vec()),
        attest_level: crate::governance::rules_store::OPERATOR_SIGNED_ATTEST_LEVEL.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..crate::signed_events::SignedEvent::default()
    };
    crate::signed_events::append_signed_event_no_tx(&tx, &event)
        .context("epoch-apply: append epoch.manifest_applied audit row")?;

    tx.commit().context("epoch-apply: commit triple anchor")?;

    let payload = serde_json::json!({
        "epoch_seq": doc.body.epoch_seq,
        "prior_epoch_id": doc.body.prior_epoch_id,
        "policy_seq": doc.body.policy_seq,
        "content_hash": content_hex,
        crate::cli::JSON_KEY_CHECKPOINT_ID: cp.id,
        "applied": true,
    });
    crate::cli::rules::emit_ok(json, out, "epoch-apply", &payload)?;
    Ok(())
}

/// Decode a lowercase-hex string to bytes. Small local helper so the
/// consumer has no hex-crate dependency in this path.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("odd-length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex byte"))
        .collect()
}
