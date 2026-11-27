// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10112 (Option B, 3-agent vote `V1-RECOVER-REBIND-ATTEST` R-1..R-15) —
//! armed guardian-recovery key rebind with single-transaction DB commit,
//! atomic staged+fsynced anchor swap, idempotent crash recovery, and
//! `#10040`-byte-identical row attestation signed by `K_new`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension as _, params};

use super::connection::WriteTxn;
use super::pubkey_history::bind_agent_pubkey_no_tx_at;
use super::row_attest::anchor::{AnchorLoad, TrustAnchor};
use super::row_attest::sqlite::{
    REFUSE_ANCHOR_UNATTESTED_KEY_SWAP, REFUSE_RECOVERY_KEY_MISMATCH, REFUSE_RECOVERY_MISSING_PRIV,
    REFUSE_RECOVERY_QUORUM_DRIFT, REFUSE_RECOVERY_REPLAY, REFUSE_RECOVERY_VERIFY_ONLY,
    advance_seal_after_recovery, arm_for_recovery_in_tx, restore_post_recovery_funnel,
    seal_is_current, was_armed_with,
};
use super::row_attest::{Attestation, key_id_of};
use super::{
    agent_pubkey, escalation_deferral, lineage_witness_event_type, read_lineage,
    verify_agent_lineage, verify_agent_lineage_with_policy,
};
use crate::identity::keypair::{
    self, agent_priv_path, agent_pub_path, archive_public_key_idempotent_at,
    canonical_history_contains, canonical_public_base64, decode_public_base64,
    enforce_key_path_chain_secure, find_existing_archived_public_key_at,
};
use crate::identity::lineage::{
    LineageReason, LineageRecord, RecoveryAttestation, RecoveryPolicy, VerifiedLineage,
    encode_recovery_quorum, verify_recovery_record,
};
use crate::identity::pubkey_bind::PossessionProof;
use crate::validate;

/// Arm posture supplied to [`recovery_preconditions`] (#10112 Option B, R-4, R-8).
pub enum RecoveryArm<'a> {
    /// Signing arm holding the recovering agent's fresh `K_new` private key.
    Signing(&'a SigningKey),
    /// Verify-only arm (no private key signing authority) — always refused (R-8).
    VerifyOnly,
    /// No `K_new` private key is present in the key directory — refused (R-8).
    MissingPrivateKey,
}

/// Inputs for a guardian-quorum key recovery (#10112).
pub struct RecoveryRequest<'a> {
    /// Agent identifier whose lost head key is being recovered.
    pub agent_id: &'a str,
    /// `--successor-pubkey` (R-4: must equal both the guardian-signed key and
    /// the signing arm's `K_new` public key).
    pub successor_pubkey_b64: &'a str,
    /// Collected M-of-N guardian attestations over the recovery record.
    pub quorum: &'a [RecoveryAttestation],
    /// Optional witness sequence high-water mark for recovery-as-revocation.
    pub suspected_compromise_from_seq: Option<u64>,
    /// Optional updated cold recovery public key commitment.
    pub recovery_pubkey_b64: Option<&'a str>,
    /// Exact RFC3339 `not_before` echoed from `recover-prepare`.
    pub not_before: &'a str,
    /// Optional staged key label inside `anchor_dir` whose `.{pub,priv}` holds
    /// `K_new` prior to installation as `<agent_id>.{pub,priv}`.
    pub staged_key_label: Option<&'a str>,
}

/// Fault-injection hook points proving crash order + idempotent convergence
/// (R-6). Private `#[cfg(test)]` only (C-F13 / S-F3, #10161).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryFaultPoint {
    None,
    BeforeDbCommit,
    AfterDbCommitBeforeArchive,
    AfterArchiveBeforePrivInstall,
    AfterPrivInstallBeforePubInstall,
    AfterPubInstallBeforeStagedCleanup,
    AfterPubInstallBeforeSealAdvance,
    RestoreFunnelFailure,
}

/// Outcome of a completed recovery rebind (#10112).
#[derive(Debug, Clone)]
pub struct RecoveryOutcome {
    /// Persisted (or resumed) `LineageRecord`.
    pub record: LineageRecord,
    /// Path where retired `K_old` public key was archived (`<agent>.pub.<ts>`).
    pub archived_pub: PathBuf,
    /// Path where active `K_new` public key was installed (`<agent>.pub`).
    pub new_pub: PathBuf,
    /// Shared handoff timestamp in Unix seconds (R-9).
    pub ts_secs: i64,
    /// Shared handoff timestamp in canonical RFC3339 (R-9).
    pub ts_rfc: String,
    /// `true` when this run converged an interrupted post-commit anchor swap (R-6).
    pub resumed_from_committed_db: bool,
}

enum RecoveryMode {
    Full {
        record: LineageRecord,
        quorum_blob: Vec<u8>,
    },
    ResumeAnchor {
        record: LineageRecord,
    },
}

/// Proof value returned by [`recovery_preconditions`] (#10112, CBC-03, CBC-05).
///
/// Private fields (and no `Clone`, `Copy`, or `Debug` — protecting `k_new_signing`
/// per R-14) guarantee that [`execute_recovery_rebind`] is reachable ONLY after:
/// 1. Full lineage chain verification produced a [`VerifiedLineage`] (#10159);
/// 2. Guardian M-of-N signatures verified against the committed quorum FIRST (R-1, R-2, R-3);
/// 3. `--successor-pubkey` equals both the guardian-signed key and the signing arm's `K_new` (R-4);
/// 4. The arm holds `K_new.priv` (verify-only and missing-priv refused preflight, R-8);
/// 5. Replay of an already-converged recovery or epoch/key reuse is refused (R-9).
#[must_use = "a RecoveryChecked proof must be consumed by execute_recovery_rebind"]
pub struct RecoveryChecked<'a> {
    agent_id: &'a str,
    anchor_dir: &'a Path,
    k_old_pub_bytes: [u8; PUBLIC_KEY_LENGTH],
    k_new_signing: &'a SigningKey,
    successor_pubkey_canonical: String,
    staged_key_label: Option<&'a str>,
    ts_secs: i64,
    ts_rfc: String,
    mode: RecoveryMode,
}

/// Resolve the committed `(guardian_set_id, recovery_threshold)` for a new
/// recovery record per R-2 (#10112) and #10159: takes [`VerifiedLineage`] by
/// reference so raw unverified `agent_lineage` rows can never compile as a
/// quorum source.
pub(crate) fn resolve_committed_quorum(
    verified: &VerifiedLineage,
    policy: &RecoveryPolicy,
) -> Result<(Vec<u8>, u64)> {
    if let Some((prior_gid, prior_thr)) = verified.committed_quorum() {
        if policy.guardian_set_id().as_slice() != prior_gid {
            bail!("{REFUSE_RECOVERY_QUORUM_DRIFT}");
        }
        return Ok((prior_gid.to_vec(), prior_thr));
    }
    let threshold = policy.threshold.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot mint a recovery record — AI_MEMORY_RECOVERY_THRESHOLD is unset; \
             set an explicit M-of-N threshold (a key-takeover primitive never defaults to 1)"
        )
    })?;
    let threshold_u64 = u64::try_from(threshold).context("recovery threshold exceeds u64 range")?;
    Ok((policy.guardian_set_id(), threshold_u64))
}

/// Single shared `INSERT INTO agent_lineage` helper (C-F7 / C-F4 / C-F8) with
/// checked integer conversions — called by both `storage::append_lineage_record`
/// and `execute_recovery_rebind`.
pub(crate) fn insert_agent_lineage_row(
    conn: &Connection,
    record: &LineageRecord,
    signature: &[u8],
    record_bytes: &[u8],
    created_at: &str,
) -> Result<()> {
    let epoch_i64 = i64::try_from(record.epoch).context("lineage epoch exceeds i64")?;
    let compromise_i64 = record
        .suspected_compromise_from_seq
        .map(|s| i64::try_from(s).context("suspected_compromise_from_seq exceeds i64"))
        .transpose()?;
    let threshold_i64 = record
        .recovery_threshold
        .map(|m| i64::try_from(m).context("recovery_threshold exceeds i64"))
        .transpose()?;
    conn.execute(
        "INSERT INTO agent_lineage \
            (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, \
             recovery_pubkey, not_before, prev_record_hash, signature, \
             record_bytes, created_at, custody_class, suspected_compromise_from_seq, \
             guardian_set_id, recovery_threshold) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            record.agent_id,
            epoch_i64,
            record.reason.as_str(),
            record.predecessor_pubkey_b64,
            record.successor_pubkey_b64,
            record.recovery_pubkey_b64,
            record.not_before,
            record.prev_record_hash,
            signature,
            record_bytes,
            created_at,
            record.custody_class.as_str(),
            compromise_i64,
            record.guardian_set_id.as_deref(),
            threshold_i64,
        ],
    )
    .context("insert agent_lineage row (duplicate epoch is refused by the C5 PK)")?;
    Ok(())
}

fn format_recovery_ts(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn parse_floor_ts(raw: &str, column: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("refusing recovery: malformed {column} timestamp {raw:?}"))?;
    Ok(parsed.with_timezone(&Utc))
}

fn pick_recovery_timestamp(conn: &Connection, agent_id: &str) -> Result<(i64, String)> {
    let latest_hist: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT bound_at, superseded_at FROM agent_pubkey_history
             WHERE agent_id = ?1 ORDER BY version DESC LIMIT 1",
            params![agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let latest_att: Option<String> = conn
        .query_row(
            "SELECT attested_at FROM row_attestations
             WHERE signature IS NOT NULL ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;

    let mut ts = Utc::now();
    if let Some((bound_s, sup_s)) = latest_hist {
        let bound_utc = parse_floor_ts(&bound_s, "agent_pubkey_history.bound_at")?;
        if ts <= bound_utc {
            ts = bound_utc + Duration::microseconds(1);
        }
        if let Some(sup_s) = sup_s {
            let sup_utc = parse_floor_ts(&sup_s, "agent_pubkey_history.superseded_at")?;
            if ts < sup_utc {
                ts = sup_utc;
            }
        }
    }
    if let Some(att_s) = latest_att {
        let att_utc = parse_floor_ts(&att_s, "row_attestations.attested_at")?;
        if ts < att_utc {
            ts = att_utc;
        }
    }
    Ok((ts.timestamp(), format_recovery_ts(ts)))
}

fn anchor_and_seal_converged(
    conn: &Connection,
    anchor_dir: &Path,
    agent_id: &str,
    k_old_bytes: &[u8; PUBLIC_KEY_LENGTH],
    k_new_verifying: &VerifyingKey,
    ts_secs: i64,
    staged_key_label: Option<&str>,
) -> Result<bool> {
    let pub_path = agent_pub_path(anchor_dir, agent_id);
    let pub_ok = match fs::read(&pub_path) {
        Ok(bytes) => bytes.as_slice() == k_new_verifying.as_bytes().as_slice(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "reading active public key {} during convergence check",
                    pub_path.display()
                )
            });
        }
    };
    if !pub_ok {
        return Ok(false);
    }
    let priv_path = agent_priv_path(anchor_dir, agent_id);
    if !priv_path.exists() {
        return Ok(false);
    }
    let loaded = keypair::load(agent_id, anchor_dir).with_context(|| {
        format!("loading keypair for '{agent_id}' during recovery convergence check")
    })?;
    let priv_ok = loaded
        .private
        .is_some_and(|sk| sk.verifying_key() == *k_new_verifying);
    if !priv_ok {
        return Ok(false);
    }
    if find_existing_archived_public_key_at(anchor_dir, agent_id, k_old_bytes, ts_secs)?.is_none() {
        return Ok(false);
    }
    if let Some(staged) = staged_key_label
        && staged != agent_id
        && (agent_pub_path(anchor_dir, staged).exists()
            || agent_priv_path(anchor_dir, staged).exists())
    {
        return Ok(false);
    }
    match TrustAnchor::load_dir(anchor_dir) {
        AnchorLoad::Anchored(_) => {}
        AnchorLoad::Unanchored(why) => {
            bail!(
                "refusing recovery convergence check on unusable anchor {}: {why}",
                anchor_dir.display()
            );
        }
    }
    seal_is_current(conn, anchor_dir)
}

fn check_arm<'a>(
    arm: RecoveryArm<'a>,
    expected_successor: &VerifyingKey,
) -> Result<&'a SigningKey> {
    match arm {
        RecoveryArm::VerifyOnly => bail!("{REFUSE_RECOVERY_VERIFY_ONLY}"),
        RecoveryArm::MissingPrivateKey => bail!("{REFUSE_RECOVERY_MISSING_PRIV}"),
        RecoveryArm::Signing(sk) => {
            if sk.verifying_key().to_bytes() != expected_successor.to_bytes() {
                bail!("{REFUSE_RECOVERY_KEY_MISMATCH}");
            }
            Ok(sk)
        }
    }
}

/// Validate EVERY recovery precondition before any DB write or anchor file
/// mutation (#10112 Option B, vote V1-RECOVER-REBIND-ATTEST R-1..R-9).
///
/// Exact order:
/// 1. Validate inputs + verify the ENTIRE existing lineage chain into a
///    [`VerifiedLineage`] (#10159: raw storage rows never decide anything);
/// 2. Resolve guardian quorum policy from `&VerifiedLineage` (R-2) or enrolled
///    operator policy (never CLI args/request);
/// 3. Verify M-of-N guardian signatures over `(agent_id, epoch, K_old, K_new)`
///    BEFORE evaluating any `K_new` signature or touching state (R-1, R-3);
/// 4. Evaluate `arm`: refuse verify-only (R-8), missing `K_new.priv` (R-8), or
///    `K_new.pub != --successor-pubkey` (R-4);
/// 5. Refuse replay of an already-converged recovery or epoch/key reuse (R-9),
///    or prepare an idempotent resume when DB committed before anchor swap (R-6);
/// 6. Verify `anchor_dir` existence, security chain, and pre-recovery anchor
///    agreement with `&VerifiedLineage` on armed stores (R-7 / #10160).
///
/// # Errors
///
/// Returns a named refusal leaving the database and anchor directory
/// byte-identical.
pub fn recovery_preconditions<'a>(
    conn: &Connection,
    anchor_dir: &'a Path,
    req: &RecoveryRequest<'a>,
    arm: RecoveryArm<'a>,
) -> Result<RecoveryChecked<'a>> {
    validate::validate_agent_id_shape(req.agent_id)?;
    if let Some(staged) = req.staged_key_label {
        validate::validate_agent_id_shape(staged)?;
    }
    let decoded_successor = decode_public_base64(req.successor_pubkey_b64)
        .context("decoding recovery successor pubkey")?;
    let successor_canonical = canonical_public_base64(req.successor_pubkey_b64)?;
    if let Some(rec) = req.recovery_pubkey_b64 {
        decode_public_base64(rec).context("decoding recovery pubkey")?;
    }
    if read_lineage(conn, req.agent_id)?.is_empty() {
        bail!(
            "no lineage enrolled for '{}' — nothing to recover",
            req.agent_id
        );
    }
    let policy = RecoveryPolicy::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot mint a recovery record — no recovery guardians enrolled \
             (set AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS)"
        )
    })?;
    // #10159 (S-F1): verify the FULL existing chain into `VerifiedLineage`
    // BEFORE considering `ResumeAnchor` or resolving any committed quorum.
    let verified = verify_agent_lineage_with_policy(conn, req.agent_id, Some(&policy))?
        .map_err(|e| anyhow::anyhow!("refusing recovery on unverified lineage chain: {e}"))?;
    let head = verified.head_record();
    let quorum_blob = encode_recovery_quorum(req.quorum)?;

    // Idempotent post-commit resume vs replay check (R-6 / R-9).
    // `head` comes exclusively from `VerifiedLineage` (witness + chain + quorum
    // + flat-binding already cryptographically verified above).
    let head_succ_canon = canonical_public_base64(&head.successor_pubkey_b64)?;
    if head.reason == LineageReason::Recovery
        && head_succ_canon == successor_canonical
        && head.not_before == req.not_before
    {
        // R-1: ALWAYS verify the guardian quorum FIRST, before evaluating K_new.
        verify_recovery_record(head, &quorum_blob, &policy)
            .map_err(|e| anyhow::anyhow!("refusing unverifiable recovery record: {e}"))?;
        // R-4 & R-8: check signing arm & key equality.
        let k_new_signing = check_arm(arm, &decoded_successor)?;
        if !anchor_dir.exists() {
            bail!(
                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor directory {} does not exist",
                anchor_dir.display()
            );
        }
        let k_old_key = decode_public_base64(&head.predecessor_pubkey_b64)
            .context("decoding predecessor pubkey on committed recovery head")?;
        let bound_at: String = conn.query_row(
            "SELECT bound_at FROM agent_pubkey_history
             WHERE agent_id = ?1 AND pubkey_b64 = ?2
             ORDER BY version DESC LIMIT 1",
            params![req.agent_id, &successor_canonical],
            |r| r.get(0),
        )?;
        let ts_secs = DateTime::parse_from_rfc3339(&bound_at)
            .context("parsing committed recovery bound_at")?
            .timestamp();
        if anchor_and_seal_converged(
            conn,
            anchor_dir,
            req.agent_id,
            &k_old_key.to_bytes(),
            &decoded_successor,
            ts_secs,
            req.staged_key_label,
        )? {
            bail!("{REFUSE_RECOVERY_REPLAY}");
        }
        enforce_key_path_chain_secure(anchor_dir, &agent_pub_path(anchor_dir, req.agent_id))?;
        return Ok(RecoveryChecked {
            agent_id: req.agent_id,
            anchor_dir,
            k_old_pub_bytes: k_old_key.to_bytes(),
            k_new_signing,
            successor_pubkey_canonical: successor_canonical,
            staged_key_label: req.staged_key_label,
            ts_secs,
            ts_rfc: bound_at,
            mode: RecoveryMode::ResumeAnchor {
                record: head.clone(),
            },
        });
    }

    // R-2: quorum set and threshold from `&VerifiedLineage` only.
    let (guardian_set_id, threshold_u64) = resolve_committed_quorum(&verified, &policy)?;

    // Build prospective recovery record at head.epoch + 1.
    let recovery_commit = req
        .recovery_pubkey_b64
        .map(str::to_string)
        .or_else(|| head.recovery_pubkey_b64.clone());
    let record = LineageRecord::recovery(
        head,
        req.successor_pubkey_b64,
        req.suspected_compromise_from_seq,
        recovery_commit,
        guardian_set_id,
        threshold_u64,
        req.not_before,
    )?;

    // R-1 & R-3: verify guardian M-of-N quorum FIRST, before any K_new check
    // and before any DB or anchor state change.
    verify_recovery_record(&record, &quorum_blob, &policy)
        .map_err(|e| anyhow::anyhow!("refusing to persist unverifiable recovery record: {e}"))?;

    // R-9: refuse replaying/reactivating any previously used key (including K_old).
    let mut stmt =
        conn.prepare("SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = ?1")?;
    let hist_keys: Vec<String> = stmt
        .query_map(params![req.agent_id], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if canonical_history_contains(&successor_canonical, &hist_keys)? {
        bail!("{REFUSE_RECOVERY_REPLAY}: successor key was already bound in history");
    }

    // R-4 & R-8: check signing arm (refuses verify-only, missing priv, mismatch).
    let k_new_signing = check_arm(arm, &decoded_successor)?;

    // R-7 / #10160: verify anchor_dir existence, security chain, and agreement
    // with `&VerifiedLineage` on armed stores before touching disk or DB.
    let armed = was_armed_with(conn, Some(anchor_dir))?;
    if armed {
        if !anchor_dir.exists() {
            bail!(
                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor directory {} does not exist on armed store",
                anchor_dir.display()
            );
        }
        match TrustAnchor::load_dir(anchor_dir) {
            AnchorLoad::Anchored(anchor) => {
                verify_anchor_against_verified_lineage(&anchor, req.agent_id, &verified)?;
            }
            AnchorLoad::Unanchored(why) => {
                bail!("{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: {why}");
            }
        }
    }
    let target_pub = agent_pub_path(anchor_dir, req.agent_id);
    if target_pub.exists() {
        enforce_key_path_chain_secure(anchor_dir, &target_pub)?;
    } else if anchor_dir.exists() {
        keypair::enforce_key_dir_secure(anchor_dir)?;
    }

    let k_old_key = decode_public_base64(&head.successor_pubkey_b64)
        .context("decoding current lineage head pubkey")?;
    let (ts_secs, ts_rfc) = pick_recovery_timestamp(conn, req.agent_id)?;

    Ok(RecoveryChecked {
        agent_id: req.agent_id,
        anchor_dir,
        k_old_pub_bytes: k_old_key.to_bytes(),
        k_new_signing,
        successor_pubkey_canonical: successor_canonical,
        staged_key_label: req.staged_key_label,
        ts_secs,
        ts_rfc,
        mode: RecoveryMode::Full {
            record,
            quorum_blob,
        },
    })
}

fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let handle = File::open(dir)
            .with_context(|| format!("opening directory {} for fsync", dir.display()))?;
        handle
            .sync_all()
            .with_context(|| format!("fsyncing directory {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Write `bytes` to a dot-prefixed staging sibling inside `anchor_dir` with
/// explicit `mode`, `sync_all()`, atomic `fs::rename`, and parent dir fsync
/// (R-6, R-14). Never writes outside `anchor_dir`.
fn atomic_write_in_anchor(anchor_dir: &Path, dest: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow::anyhow!("destination {} has no parent", dest.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating parent directory {}", parent.display()))?;
    enforce_key_path_chain_secure(anchor_dir, dest)?;

    let file_name = dest
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid target file name {}", dest.display()))?;
    let stage_name = format!(".recover-{file_name}-{}.tmp", uuid::Uuid::new_v4().simple());
    let stage_path = parent.join(stage_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let write_res = (|| -> Result<()> {
        let mut f = opts
            .open(&stage_path)
            .with_context(|| format!("creating staged file {}", stage_path.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing staged file {}", stage_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsyncing staged file {}", stage_path.display()))?;
        drop(f);
        fs::rename(&stage_path, dest).with_context(|| {
            format!(
                "atomically renaming {} to {}",
                stage_path.display(),
                dest.display()
            )
        })?;
        sync_dir(parent)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(&stage_path);
    }
    write_res
}

fn cleanup_staged_and_temps(
    anchor_dir: &Path,
    agent_id: &str,
    staged_label: Option<&str>,
) -> Result<()> {
    if let Some(staged) = staged_label
        && staged != agent_id
    {
        for p in [
            agent_pub_path(anchor_dir, staged),
            agent_priv_path(anchor_dir, staged),
        ] {
            if p.exists() {
                enforce_key_path_chain_secure(anchor_dir, &p)?;
                fs::remove_file(&p)
                    .with_context(|| format!("removing staged key file {}", p.display()))?;
            }
        }
    }
    let target_pub = agent_pub_path(anchor_dir, agent_id);
    let parent = target_pub
        .parent()
        .map_or_else(|| anchor_dir.to_path_buf(), Path::to_path_buf);
    enforce_key_path_chain_secure(anchor_dir, &target_pub)?;
    for entry in fs::read_dir(&parent).with_context(|| {
        format!(
            "reading anchor directory {} for temp cleanup",
            parent.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "iterating anchor directory {} for temp cleanup",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && s.starts_with(".recover-")
            && s.ends_with(".tmp")
        {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .with_context(|| format!("stat temp file {}", path.display()))?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                bail!(
                    "refusing to delete non-regular temp entry {}",
                    path.display()
                );
            }
            enforce_key_path_chain_secure(anchor_dir, &path)?;
            fs::remove_file(&path)
                .with_context(|| format!("removing leftover temp file {}", path.display()))?;
        }
    }
    sync_dir(&parent)?;
    Ok(())
}

/// Combine the DB transaction result and the post-recovery funnel-restore
/// result so neither error is ever swallowed (C-F4 / S-F4, #10162).
fn merge_commit_and_restore(commit_res: Result<()>, restore_res: Result<()>) -> Result<()> {
    match (commit_res, restore_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(restore_err)) => Err(restore_err),
        (Err(commit_err), Ok(())) => Err(commit_err),
        (Err(commit_err), Err(restore_err)) => Err(commit_err.context(format!(
            "also failed to restore post-recovery attestation funnel: {restore_err:#}"
        ))),
    }
}

/// Execute the guardian recovery rebind by consuming `checked` by value
/// (#10112 Option B, R-5, R-6, R-9, R-10, R-14).
///
/// # Errors
///
/// Rolls back all four DB writes on any Step-1 failure; on any Step-2/Step-3
/// failure an idempotent re-run converges cleanly.
pub fn execute_recovery_rebind(
    conn: &Connection,
    checked: RecoveryChecked<'_>,
) -> Result<RecoveryOutcome> {
    #[cfg(test)]
    {
        execute_recovery_rebind_with_fault(conn, checked, RecoveryFaultPoint::None)
    }
    #[cfg(not(test))]
    {
        execute_recovery_rebind_impl(conn, checked)
    }
}

struct RecoveryTxParams<'a> {
    agent_id: &'a str,
    anchor_dir: &'a Path,
    k_new_signing: &'a SigningKey,
    successor_pubkey_canonical: &'a str,
    ts_rfc: &'a str,
    record: &'a LineageRecord,
    quorum_blob: &'a [u8],
}

#[cfg(not(test))]
fn execute_recovery_rebind_impl(
    conn: &Connection,
    checked: RecoveryChecked<'_>,
) -> Result<RecoveryOutcome> {
    let RecoveryChecked {
        agent_id,
        anchor_dir,
        k_old_pub_bytes,
        k_new_signing,
        successor_pubkey_canonical,
        staged_key_label,
        ts_secs,
        ts_rfc,
        mode,
    } = checked;

    let (record, resumed_from_committed_db) = match mode {
        RecoveryMode::ResumeAnchor { record } => (record, true),
        RecoveryMode::Full {
            record,
            quorum_blob,
        } => {
            let tx_params = RecoveryTxParams {
                agent_id,
                anchor_dir,
                k_new_signing,
                successor_pubkey_canonical: &successor_pubkey_canonical,
                ts_rfc: &ts_rfc,
                record: &record,
                quorum_blob: &quorum_blob,
            };
            commit_recovery_tx_with_restore(
                conn,
                &tx_params,
                || Ok(()),
                restore_post_recovery_funnel,
            )?;
            (record, false)
        }
    };

    let archived_pub =
        archive_public_key_idempotent_at(anchor_dir, agent_id, &k_old_pub_bytes, ts_secs)?;
    if let Some(parent) = archived_pub.parent() {
        sync_dir(parent)?;
    }
    let priv_path = agent_priv_path(anchor_dir, agent_id);
    atomic_write_in_anchor(anchor_dir, &priv_path, &k_new_signing.to_bytes(), 0o600)?;
    let new_pub = agent_pub_path(anchor_dir, agent_id);
    atomic_write_in_anchor(
        anchor_dir,
        &new_pub,
        &k_new_signing.verifying_key().to_bytes(),
        0o644,
    )?;
    cleanup_staged_and_temps(anchor_dir, agent_id, staged_key_label)?;
    advance_seal_after_recovery(conn, anchor_dir)?;

    Ok(RecoveryOutcome {
        record,
        archived_pub,
        new_pub,
        ts_secs,
        ts_rfc,
        resumed_from_committed_db,
    })
}

fn commit_recovery_tx_with_restore(
    conn: &Connection,
    tx_params: &RecoveryTxParams<'_>,
    before_commit_hook: impl FnOnce() -> Result<()>,
    restore_fn: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    let RecoveryTxParams {
        agent_id,
        anchor_dir,
        k_new_signing,
        successor_pubkey_canonical,
        ts_rfc,
        record,
        quorum_blob,
    } = *tx_params;
    // Step 1 (R-5, R-9): single IMMEDIATE SQLite transaction covering:
    //   (a) arm_for_recovery_in_tx (verifies anchor vs lineage + signs unsigned cutovers + registers FixedAt K_new @ ts_rfc),
    //   (b) insert_agent_lineage_row (agent_lineage),
    //   (c) bind_agent_pubkey_no_tx_at (agent_pubkey_history append + _agents UPDATE -> fires row_attestations trigger under K_new @ ts_rfc),
    //   (d) signed_events witness append.
    let record_bytes = record.canonical_bytes()?;
    let witness_hash = record.witness_payload_hash()?;
    let write_txn = WriteTxn::begin(conn).context("execute_recovery_rebind: begin single tx")?;
    let tx_res = (|| -> Result<()> {
        arm_for_recovery_in_tx(conn, agent_id, k_new_signing, anchor_dir, ts_rfc)?;
        insert_agent_lineage_row(conn, record, quorum_blob, &record_bytes, ts_rfc)
            .context("execute_recovery_rebind: insert agent_lineage")?;

        let proof = PossessionProof::from_verified_guardian_recovery(
            agent_id,
            &record.predecessor_pubkey_b64,
            &record.successor_pubkey_b64,
        )?;
        bind_agent_pubkey_no_tx_at(conn, agent_id, successor_pubkey_canonical, &proof, ts_rfc)?;

        let witness = crate::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(),
            event_type: lineage_witness_event_type(record.reason).to_string(),
            payload_hash: witness_hash,
            signature: Some(quorum_blob.to_vec()),
            attest_level: crate::models::AttestLevel::LineageSigned
                .as_str()
                .to_string(),
            timestamp: ts_rfc.to_string(),
            ..crate::signed_events::SignedEvent::default()
        };
        let anchor = crate::signed_events::append_signed_event_no_tx(conn, &witness)
            .context("execute_recovery_rebind: witness append")?;
        escalation_deferral::defer_audit_anchor(conn, anchor);
        before_commit_hook()?;
        Ok(())
    })();

    let commit_res = match tx_res {
        Ok(()) => write_txn
            .commit()
            .context("execute_recovery_rebind: commit single tx"),
        Err(e) => {
            write_txn.rollback();
            Err(e)
        }
    };
    let restore_res = restore_fn(conn);
    merge_commit_and_restore(commit_res, restore_res)
}

#[cfg(test)]
fn execute_recovery_rebind_with_fault(
    conn: &Connection,
    checked: RecoveryChecked<'_>,
    fault: RecoveryFaultPoint,
) -> Result<RecoveryOutcome> {
    let RecoveryChecked {
        agent_id,
        anchor_dir,
        k_old_pub_bytes,
        k_new_signing,
        successor_pubkey_canonical,
        staged_key_label,
        ts_secs,
        ts_rfc,
        mode,
    } = checked;

    let (record, resumed_from_committed_db) = match mode {
        RecoveryMode::ResumeAnchor { record } => (record, true),
        RecoveryMode::Full {
            record,
            quorum_blob,
        } => {
            let tx_params = RecoveryTxParams {
                agent_id,
                anchor_dir,
                k_new_signing,
                successor_pubkey_canonical: &successor_pubkey_canonical,
                ts_rfc: &ts_rfc,
                record: &record,
                quorum_blob: &quorum_blob,
            };
            let before_commit = || -> Result<()> {
                if fault == RecoveryFaultPoint::BeforeDbCommit {
                    bail!("injected fault: BeforeDbCommit");
                }
                Ok(())
            };
            let restore = |c: &Connection| -> Result<()> {
                if fault == RecoveryFaultPoint::RestoreFunnelFailure {
                    bail!("injected fault: RestoreFunnelFailure");
                }
                restore_post_recovery_funnel(c)
            };
            commit_recovery_tx_with_restore(conn, &tx_params, before_commit, restore)?;
            (record, false)
        }
    };

    if fault == RecoveryFaultPoint::AfterDbCommitBeforeArchive {
        bail!("injected fault: AfterDbCommitBeforeArchive");
    }

    let archived_pub =
        archive_public_key_idempotent_at(anchor_dir, agent_id, &k_old_pub_bytes, ts_secs)?;
    if let Some(parent) = archived_pub.parent() {
        sync_dir(parent)?;
    }
    if fault == RecoveryFaultPoint::AfterArchiveBeforePrivInstall {
        bail!("injected fault: AfterArchiveBeforePrivInstall");
    }

    let priv_path = agent_priv_path(anchor_dir, agent_id);
    atomic_write_in_anchor(anchor_dir, &priv_path, &k_new_signing.to_bytes(), 0o600)?;
    if fault == RecoveryFaultPoint::AfterPrivInstallBeforePubInstall {
        bail!("injected fault: AfterPrivInstallBeforePubInstall");
    }

    let new_pub = agent_pub_path(anchor_dir, agent_id);
    atomic_write_in_anchor(
        anchor_dir,
        &new_pub,
        &k_new_signing.verifying_key().to_bytes(),
        0o644,
    )?;
    if fault == RecoveryFaultPoint::AfterPubInstallBeforeStagedCleanup {
        bail!("injected fault: AfterPubInstallBeforeStagedCleanup");
    }

    cleanup_staged_and_temps(anchor_dir, agent_id, staged_key_label)?;
    if fault == RecoveryFaultPoint::AfterPubInstallBeforeSealAdvance {
        bail!("injected fault: AfterPubInstallBeforeSealAdvance");
    }

    advance_seal_after_recovery(conn, anchor_dir)?;

    Ok(RecoveryOutcome {
        record,
        archived_pub,
        new_pub,
        ts_secs,
        ts_rfc,
        resumed_from_committed_db,
    })
}

/// R-7 / #10159: verify that `anchor`'s current and retired keys for `agent_id`
/// are backed exclusively by `verified: &VerifiedLineage` (built only by the
/// chain verifier).
///
/// # Errors
///
/// Returns [`REFUSE_ANCHOR_UNATTESTED_KEY_SWAP`] if `anchor`'s current key
/// disagrees with `verified.head_key` or if any retired key in `anchor` for
/// `agent_id` does not appear in `verified`.
pub fn verify_anchor_against_verified_lineage(
    anchor: &TrustAnchor,
    agent_id: &str,
    verified: &VerifiedLineage,
) -> Result<()> {
    let expected_key_id = key_id_of(&verified.head_key);
    let mut current_anchor_keys = Vec::new();
    let mut retired_anchor_keys = Vec::new();
    for (aid, kid, retired) in anchor.fingerprints() {
        if aid != agent_id {
            continue;
        }
        if retired {
            retired_anchor_keys.push(kid);
        } else {
            current_anchor_keys.push(kid);
        }
    }
    if current_anchor_keys.as_slice() != [expected_key_id.clone()] {
        bail!(
            "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor current key {current_anchor_keys:?} \
             does not match verified lineage head {expected_key_id} for '{agent_id}'"
        );
    }
    for retired_kid in retired_anchor_keys {
        if !verified.contains_key_id(&retired_kid) {
            bail!(
                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor retired key {retired_kid} \
                 is not in verified lineage for '{agent_id}'"
            );
        }
    }
    Ok(())
}

/// R-7: verify that the current (unretired) key for `agent_id` in `anchor` is
/// backed by the agent's quorum-verified lineage head. Swapping `<agent>.pub`
/// in the anchor directory without a quorum-verified recovery (or rotation)
/// lineage record is refused with [`REFUSE_ANCHOR_UNATTESTED_KEY_SWAP`].
///
/// # Errors
///
/// Returns an error if the lineage chain is missing/invalid (including an
/// unverified recovery quorum) or if the anchor's current key disagrees with
/// the verified lineage head.
pub fn verify_anchor_against_lineage(
    conn: &Connection,
    anchor: &TrustAnchor,
    agent_id: &str,
) -> Result<()> {
    if read_lineage(conn, agent_id)?.is_empty() {
        bail!("{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: no lineage enrolled for '{agent_id}'");
    }
    let verified = verify_agent_lineage(conn, agent_id)?.map_err(|e| {
        anyhow::anyhow!("{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: lineage verification failed: {e}")
    })?;
    verify_anchor_against_verified_lineage(anchor, agent_id, &verified)
}

/// R-7 / #10160: production store-wide anchor-vs-lineage check returning every
/// defect (used by `row_attest::sqlite::verify_inner` so `verify_sqlite`,
/// `verify_sqlite_with`, `audit verify-rows`, and doctor fail closed on any
/// bare anchor swap, whether or not `agent_lineage` was enrolled).
pub(crate) fn verify_anchor_against_lineage_for_store_defects(
    conn: &Connection,
    anchor: &TrustAnchor,
) -> Result<Vec<String>> {
    let mut by_agent: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for (aid, kid, retired) in anchor.fingerprints() {
        let entry = by_agent.entry(aid).or_default();
        if retired {
            entry.1.push(kid);
        } else {
            entry.0.push(kid);
        }
    }
    let mut defects = Vec::new();
    for (agent_id, (current_keys, retired_keys)) in by_agent {
        if !read_lineage(conn, &agent_id)?.is_empty() {
            match verify_agent_lineage(conn, &agent_id)? {
                Ok(verified) => {
                    if let Err(err) =
                        verify_anchor_against_verified_lineage(anchor, &agent_id, &verified)
                    {
                        defects.push(format!("{err:#}"));
                    }
                }
                Err(err) => {
                    defects.push(format!(
                        "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: lineage verification failed for '{agent_id}': {err}"
                    ));
                }
            }
            continue;
        }
        // Agent has zero enrolled `agent_lineage` rows.
        // Any retired archive `<agent>.pub.<ts>` in the anchor without a
        // lineage record is a bare key swap (refused fail-closed).
        if !retired_keys.is_empty() {
            defects.push(format!(
                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor holds retired key(s) {retired_keys:?} \
                 for '{agent_id}' with no enrolled lineage"
            ));
            continue;
        }
        // If the agent is bound in `_agents`, the sole current anchor key must
        // match the bound key (catches in-place `<agent>.pub` overwrite).
        if let Some(bound_b64) = agent_pubkey(conn, &agent_id)? {
            match decode_public_base64(&bound_b64) {
                Ok(bound_vk) => {
                    let bound_kid = key_id_of(&bound_vk);
                    if current_keys.as_slice() != [bound_kid.clone()] {
                        defects.push(format!(
                            "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor current key {current_keys:?} \
                             disagrees with bound key {bound_kid} for '{agent_id}'"
                        ));
                    }
                }
                Err(err) => {
                    defects.push(format!(
                        "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: bound key for '{agent_id}' is undecodable: {err:#}"
                    ));
                }
            }
        }
    }
    Ok(defects)
}

/// R-7 / #10160: fail-closed wrapper of [`verify_anchor_against_lineage_for_store_defects`]
/// for production arming entry points (`arm`, `arm_with_key`, `arm_for_recovery_in_tx`).
pub(crate) fn verify_anchor_against_lineage_for_store(
    conn: &Connection,
    anchor: &TrustAnchor,
) -> Result<()> {
    let defects = verify_anchor_against_lineage_for_store_defects(conn, anchor)?;
    if let Some(first) = defects.first() {
        bail!("{first}");
    }
    Ok(())
}

/// R-7 + R-12 snapshot verifier: checks that every key that ACTUALLY signed an
/// attestation in a backup snapshot is backed by the snapshot's verified
/// lineage (or bound key when no lineage is enrolled), so a pre-recovery backup
/// whose rows are all signed by archived `K_old` verifies cleanly under the
/// post-recovery anchor while any snapshot containing rows signed by an
/// unattested swapped key is refused.
pub(crate) fn verify_snapshot_signers_against_lineage(
    conn: &Connection,
    anchor: &TrustAnchor,
    attestations: &[Attestation],
) -> Result<Vec<String>> {
    let mut signed_keys_by_agent: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for att in attestations {
        if att.signature.is_some() && !att.agent_id.is_empty() && !att.key_id.is_empty() {
            signed_keys_by_agent
                .entry(att.agent_id.as_str())
                .or_default()
                .insert(att.key_id.as_str());
        }
    }
    let anchor_keys: BTreeSet<(String, String)> = anchor
        .fingerprints()
        .into_iter()
        .map(|(aid, kid, _)| (aid, kid))
        .collect();
    let mut defects = Vec::new();
    for (agent_id, key_ids) in signed_keys_by_agent {
        if !read_lineage(conn, agent_id)?.is_empty() {
            match verify_agent_lineage(conn, agent_id)? {
                Ok(verified) => {
                    for kid in key_ids {
                        if !verified.contains_key_id(kid)
                            || !anchor_keys.contains(&(agent_id.to_string(), kid.to_string()))
                        {
                            defects.push(format!(
                                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: snapshot signer {kid} \
                                 for '{agent_id}' is not in verified lineage"
                            ));
                        }
                    }
                }
                Err(err) => {
                    defects.push(format!(
                        "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: snapshot lineage verification failed for '{agent_id}': {err}"
                    ));
                }
            }
        } else if let Some(bound_b64) = agent_pubkey(conn, agent_id)? {
            match decode_public_base64(&bound_b64) {
                Ok(bound_vk) => {
                    let bound_kid = key_id_of(&bound_vk);
                    for kid in key_ids {
                        if kid != bound_kid {
                            defects.push(format!(
                                "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: snapshot signer {kid} \
                                 disagrees with bound key {bound_kid} for '{agent_id}'"
                            ));
                        }
                    }
                }
                Err(err) => {
                    defects.push(format!(
                        "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: snapshot bound key for '{agent_id}' is undecodable: {err:#}"
                    ));
                }
            }
        }
    }
    Ok(defects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::identity::keypair::{self, AgentKeypair};
    use crate::identity::lineage::{RECOVERY_GUARDIAN_PUBKEYS_ENV, RECOVERY_THRESHOLD_ENV};
    use crate::models::Memory;
    use crate::storage::row_attest::Outcome;
    use crate::storage::row_attest::sqlite::{arm_with_key, verify_sqlite_with};
    use ed25519_dalek::Signer as _;
    use tempfile::TempDir;

    struct UnitEnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl UnitEnvGuard {
        fn apply(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let lock = crate::identity::keypair::key_dir_env_lock()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut saved = Vec::with_capacity(pairs.len());
            for &(k, v) in pairs {
                saved.push((k, std::env::var_os(k)));
                // SAFETY: serialized by crate-wide `key_dir_env_lock` held in `_lock`.
                unsafe {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
            Self { saved, _lock: lock }
        }
    }

    impl Drop for UnitEnvGuard {
        fn drop(&mut self) {
            for (k, prev) in self.saved.iter().rev() {
                // SAFETY: serialized by crate-wide `key_dir_env_lock` held until drop.
                unsafe {
                    match prev {
                        Some(v) => std::env::set_var(k, v),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
    }

    fn private_dir() -> TempDir {
        let mut b = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            b.permissions(fs::Permissions::from_mode(0o700));
        }
        b.tempdir().expect("create 0700 tempdir")
    }

    fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(base: &Path, cur: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(cur).expect("read_dir") {
                let entry = entry.expect("dir entry");
                let p = entry.path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if p.is_file() {
                    let rel = p.strip_prefix(base).expect("strip_prefix").to_path_buf();
                    out.insert(rel, fs::read(&p).expect("read file"));
                }
            }
        }
        let mut out = BTreeMap::new();
        if root.exists() {
            walk(root, root, &mut out);
        }
        out
    }

    struct FaultFixture {
        _root: TempDir,
        db_path: PathBuf,
        anchor_dir: PathBuf,
        agent: String,
        guardians: [AgentKeypair; 3],
        _env: UnitEnvGuard,
    }

    impl FaultFixture {
        fn new(agent: &str) -> Self {
            let root = private_dir();
            let anchor_dir = root.path().join("keys");
            let witness_dir = root.path().join("witness");
            let home_dir = root.path().join("home");
            for d in [&anchor_dir, &witness_dir, &home_dir] {
                fs::create_dir_all(d).expect("mkdir");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(d, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
                }
            }
            let db_path = root.path().join("store.db");
            let g0 = keypair::generate("g0").expect("g0");
            let g1 = keypair::generate("g1").expect("g1");
            let g2 = keypair::generate("g2").expect("g2");
            let gpubs = format!(
                "{},{},{}",
                g0.public_base64(),
                g1.public_base64(),
                g2.public_base64()
            );
            let anchor_s = anchor_dir.to_string_lossy().into_owned();
            let witness_s = witness_dir.to_string_lossy().into_owned();
            let home_s = home_dir.to_string_lossy().into_owned();
            let env = UnitEnvGuard::apply(&[
                ("HOME", Some(&home_s)),
                ("AI_MEMORY_NO_CONFIG", Some("1")),
                ("AI_MEMORY_KEY_DIR", Some(&anchor_s)),
                ("AI_MEMORY_WITNESS_KEY_DIR", Some(&witness_s)),
                (RECOVERY_GUARDIAN_PUBKEYS_ENV, Some(&gpubs)),
                (RECOVERY_THRESHOLD_ENV, Some("2")),
                ("AI_MEMORY_STORE_URL", None),
            ]);
            let k_old = keypair::generate(agent).expect("k_old");
            keypair::save(&k_old, &anchor_dir).expect("save k_old");
            let cold = keypair::generate("cold").expect("cold");
            let conn = db::open(&db_path).expect("open");
            db::register_agent(&conn, agent, "ai:test", &[]).expect("register");
            db::enroll_lineage(&conn, agent, &k_old, Some(&cold.public_base64())).expect("enroll");
            arm_with_key(&conn, agent, k_old.private.as_ref().expect("priv")).expect("arm");
            let mem = Memory {
                namespace: "recovery-fault".to_string(),
                title: "pre-loss".to_string(),
                content: "pre-loss attested".to_string(),
                ..Memory::default()
            };
            db::insert(&conn, &mem).expect("insert");
            drop(conn);
            fs::remove_file(anchor_dir.join(format!("{agent}.priv"))).expect("lose k_old.priv");
            Self {
                _root: root,
                db_path,
                anchor_dir,
                agent: agent.to_string(),
                guardians: [g0, g1, g2],
                _env: env,
            }
        }

        fn prepare_and_sign(&self, k_new: &AgentKeypair) -> (String, Vec<RecoveryAttestation>) {
            let conn = db::open(&self.db_path).expect("open");
            let nb = Utc::now().to_rfc3339();
            let (rec, input) = db::prepare_recovery_challenge(
                &conn,
                &self.agent,
                &k_new.public_base64(),
                None,
                None,
                &nb,
            )
            .expect("prepare");
            let atts = [0, 1]
                .into_iter()
                .map(|i| RecoveryAttestation {
                    guardian_pubkey_b64: self.guardians[i].public_base64(),
                    signature: self.guardians[i]
                        .private
                        .as_ref()
                        .expect("g priv")
                        .sign(&input)
                        .to_bytes()
                        .to_vec(),
                })
                .collect();
            (rec.not_before, atts)
        }

        fn verify_clean(&self) {
            let conn = db::open(&self.db_path).expect("open");
            let anchor = TrustAnchor::load_dir(&self.anchor_dir);
            let rep = verify_sqlite_with(&conn, &anchor).expect("verify");
            assert!(
                matches!(rep.outcome(), Outcome::Clean),
                "expected Clean, got: {:?}",
                rep.outcome()
            );
        }
    }

    /// R-5 (moved into `#[cfg(test)]` per C-F13 / S-F3 #10161): failure inside
    /// the single SQLite transaction rolls back ALL FOUR tables and leaves the
    /// anchor directory untouched.
    #[test]
    fn r5_single_tx_rollback_on_before_db_commit_fault_10112() {
        let fx = FaultFixture::new("unit-r5-agent");
        let k_new = keypair::generate("unit-r5-new").expect("k_new");
        let (nb, atts) = fx.prepare_and_sign(&k_new);
        let conn = db::open(&fx.db_path).expect("open");
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).expect("count") };
        let lin_before = count("SELECT COUNT(*) FROM agent_lineage");
        let hist_before = count("SELECT COUNT(*) FROM agent_pubkey_history");
        let att_before = count("SELECT COUNT(*) FROM row_attestations");
        let pub_before = db::agent_pubkey(&conn, &fx.agent)
            .expect("pub")
            .expect("set");
        let dir_before = snapshot_tree(&fx.anchor_dir);

        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .expect("preconditions");
        let err =
            execute_recovery_rebind_with_fault(&conn, checked, RecoveryFaultPoint::BeforeDbCommit)
                .expect_err("BeforeDbCommit must abort");
        assert_eq!(format!("{err:#}"), "injected fault: BeforeDbCommit");

        assert_eq!(count("SELECT COUNT(*) FROM agent_lineage"), lin_before);
        assert_eq!(
            count("SELECT COUNT(*) FROM agent_pubkey_history"),
            hist_before
        );
        assert_eq!(count("SELECT COUNT(*) FROM row_attestations"), att_before);
        assert_eq!(
            db::agent_pubkey(&conn, &fx.agent)
                .expect("pub")
                .expect("set"),
            pub_before
        );
        assert_eq!(snapshot_tree(&fx.anchor_dir), dir_before);
        drop(conn);
        fx.verify_clean();
    }

    /// R-6 (moved into `#[cfg(test)]` per C-F13 / S-F3 #10161): fault injection
    /// at every post-commit step converges cleanly on idempotent re-run, and a
    /// third run refuses as exact `REFUSE_RECOVERY_REPLAY`.
    #[test]
    fn r6_fault_injection_every_step_converges_cleanly_on_rerun_10112() {
        let points = [
            (
                "after_db_commit",
                RecoveryFaultPoint::AfterDbCommitBeforeArchive,
            ),
            (
                "after_archive",
                RecoveryFaultPoint::AfterArchiveBeforePrivInstall,
            ),
            (
                "after_priv",
                RecoveryFaultPoint::AfterPrivInstallBeforePubInstall,
            ),
            (
                "after_pub_before_cleanup",
                RecoveryFaultPoint::AfterPubInstallBeforeStagedCleanup,
            ),
            (
                "after_pub_before_seal",
                RecoveryFaultPoint::AfterPubInstallBeforeSealAdvance,
            ),
        ];
        for (label, fault) in points {
            let agent = format!("unit-r6-{label}");
            let fx = FaultFixture::new(&agent);
            let staged_label = format!("{agent}-staged");
            let k_new = keypair::generate(&staged_label).expect("k_new");
            keypair::save(&k_new, &fx.anchor_dir).expect("stage");
            let (nb, atts) = fx.prepare_and_sign(&k_new);
            let req = RecoveryRequest {
                agent_id: &fx.agent,
                successor_pubkey_b64: &k_new.public_base64(),
                quorum: &atts,
                suspected_compromise_from_seq: None,
                recovery_pubkey_b64: None,
                not_before: &nb,
                staged_key_label: Some(&staged_label),
            };
            {
                let conn = db::open(&fx.db_path).expect("open");
                let checked = recovery_preconditions(
                    &conn,
                    &fx.anchor_dir,
                    &req,
                    RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
                )
                .expect("preconditions 1");
                let err = execute_recovery_rebind_with_fault(&conn, checked, fault)
                    .expect_err("fault must fail");
                assert!(
                    format!("{err:#}").starts_with("injected fault: "),
                    "{err:#}"
                );
            }
            {
                let conn = db::open(&fx.db_path).expect("open resume");
                let checked = recovery_preconditions(
                    &conn,
                    &fx.anchor_dir,
                    &req,
                    RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
                )
                .unwrap_or_else(|e| panic!("{label}: resume preconditions failed: {e:#}"));
                let outcome = execute_recovery_rebind(&conn, checked)
                    .unwrap_or_else(|e| panic!("{label}: resume execute failed: {e:#}"));
                assert!(outcome.resumed_from_committed_db);
            }
            fx.verify_clean();
            {
                let conn = db::open(&fx.db_path).expect("open replay");
                let err = recovery_preconditions(
                    &conn,
                    &fx.anchor_dir,
                    &req,
                    RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
                )
                .err()
                .expect("replay after convergence must refuse");
                assert_eq!(format!("{err:#}"), REFUSE_RECOVERY_REPLAY);
            }
        }
    }

    /// C-F4 / S-F4 (#10162): error returned by `restore_post_recovery_funnel`
    /// is propagated (never silently discarded with `let _ =`).
    #[test]
    fn cf4_sf4_restore_post_recovery_funnel_error_propagates_10162() {
        let fx = FaultFixture::new("unit-cf4-agent");
        let k_new = keypair::generate("unit-cf4-new").expect("k_new");
        let (nb, atts) = fx.prepare_and_sign(&k_new);
        let conn = db::open(&fx.db_path).expect("open");
        let req = RecoveryRequest {
            agent_id: &fx.agent,
            successor_pubkey_b64: &k_new.public_base64(),
            quorum: &atts,
            suspected_compromise_from_seq: None,
            recovery_pubkey_b64: None,
            not_before: &nb,
            staged_key_label: None,
        };
        let checked = recovery_preconditions(
            &conn,
            &fx.anchor_dir,
            &req,
            RecoveryArm::Signing(k_new.private.as_ref().expect("priv")),
        )
        .expect("preconditions");
        let err = execute_recovery_rebind_with_fault(
            &conn,
            checked,
            RecoveryFaultPoint::RestoreFunnelFailure,
        )
        .expect_err("restore_post_recovery_funnel error must propagate");
        assert_eq!(format!("{err:#}"), "injected fault: RestoreFunnelFailure");

        // Also pin `merge_commit_and_restore` when BOTH commit and restore fail.
        let both = merge_commit_and_restore(
            Err(anyhow::anyhow!("commit failed")),
            Err(anyhow::anyhow!("restore failed")),
        )
        .expect_err("both errors must surface");
        let msg = format!("{both:#}");
        assert!(msg.contains("commit failed"), "{msg}");
        assert!(msg.contains("restore failed"), "{msg}");
    }
}
