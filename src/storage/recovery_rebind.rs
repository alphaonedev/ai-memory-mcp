// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10112 (Option B, 3-agent vote `V1-RECOVER-REBIND-ATTEST` R-1..R-15) —
//! armed guardian-recovery key rebind with single-transaction DB commit,
//! atomic staged+fsynced anchor swap, idempotent crash recovery, and
//! `#10040`-byte-identical row attestation signed by `K_new`.

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
    seal_is_current,
};
use super::{
    escalation_deferral, lineage_head, lineage_witness_event_type, read_lineage,
    verify_agent_lineage,
};
use crate::identity::keypair::{
    self, PUB_SUFFIX, agent_priv_path, agent_pub_path, canonical_history_contains,
    canonical_public_base64, decode_public_base64, enforce_key_path_chain_secure,
};
use crate::identity::lineage::{
    LineageReason, LineageRecord, RecoveryAttestation, RecoveryPolicy, encode_recovery_quorum,
    verify_recovery_record,
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

/// Fault-injection hook points proving crash order + idempotent convergence (R-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFaultPoint {
    /// Normal execution with no injected crash.
    None,
    /// Abort inside the single SQLite `WriteTxn` right before `commit()` (R-5).
    BeforeDbCommit,
    /// Abort right after SQLite `commit()`, before archiving `K_old` (R-6).
    AfterDbCommitBeforeArchive,
    /// Abort right after archiving `<agent>.pub.<ts>`, before installing `<agent>.priv` (R-6).
    AfterArchiveBeforePrivInstall,
    /// Abort right after installing `<agent>.priv`, before replacing `<agent>.pub` (R-6).
    AfterPrivInstallBeforePubInstall,
    /// Abort right after replacing `<agent>.pub`, before removing staged sibling (R-6).
    AfterPubInstallBeforeStagedCleanup,
    /// Abort right after anchor swap, before advancing the anchored seal (R-6).
    AfterPubInstallBeforeSealAdvance,
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
/// 1. Guardian M-of-N signatures verified against the committed quorum FIRST (R-1, R-2, R-3);
/// 2. `--successor-pubkey` equals both the guardian-signed key and the signing arm's `K_new` (R-4);
/// 3. The arm holds `K_new.priv` (verify-only and missing-priv refused preflight, R-8);
/// 4. Replay of an already-converged recovery or epoch reuse is refused (R-9).
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

/// R-2 helper: return `(guardian_set_id, recovery_threshold)` committed on the
/// most recent prior signed lineage record that carries them, if any.
pub(crate) fn committed_quorum_from_lineage(
    lineage: &[(LineageRecord, Vec<u8>)],
) -> Option<(Vec<u8>, u64)> {
    lineage.iter().rev().find_map(|(rec, _)| {
        match (rec.guardian_set_id.as_ref(), rec.recovery_threshold) {
            (Some(gid), Some(thr)) => Some((gid.clone(), thr)),
            _ => None,
        }
    })
}

/// Resolve the committed `(guardian_set_id, recovery_threshold)` for a new
/// recovery record per R-2: read from the prior signed lineage record whenever
/// one committed a quorum, else from the enrolled operator `RecoveryPolicy`
/// (never from CLI arguments or the recovery request).
pub(crate) fn resolve_committed_quorum(
    lineage: &[(LineageRecord, Vec<u8>)],
    policy: &RecoveryPolicy,
) -> Result<(Vec<u8>, u64)> {
    if let Some((prior_gid, prior_thr)) = committed_quorum_from_lineage(lineage) {
        if policy.guardian_set_id() != prior_gid {
            bail!("{REFUSE_RECOVERY_QUORUM_DRIFT}");
        }
        return Ok((prior_gid, prior_thr));
    }
    let threshold = policy.threshold.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot mint a recovery record — AI_MEMORY_RECOVERY_THRESHOLD is unset; \
             set an explicit M-of-N threshold (a key-takeover primitive never defaults to 1)"
        )
    })?;
    let threshold_u64 = u64::try_from(threshold).unwrap_or(u64::MAX);
    Ok((policy.guardian_set_id(), threshold_u64))
}

fn format_recovery_ts(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
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
        if let Ok(bound) = DateTime::parse_from_rfc3339(&bound_s) {
            let bound_utc = bound.with_timezone(&Utc);
            if ts <= bound_utc {
                ts = bound_utc + Duration::microseconds(1);
            }
        }
        if let Some(sup_s) = sup_s
            && let Ok(sup) = DateTime::parse_from_rfc3339(&sup_s)
        {
            let sup_utc = sup.with_timezone(&Utc);
            if ts < sup_utc {
                ts = sup_utc;
            }
        }
    }
    if let Some(att_s) = latest_att
        && let Ok(att) = DateTime::parse_from_rfc3339(&att_s)
    {
        let att_utc = att.with_timezone(&Utc);
        if ts < att_utc {
            ts = att_utc;
        }
    }
    Ok((ts.timestamp(), format_recovery_ts(ts)))
}

fn find_existing_archive_with_bytes(
    dir: &Path,
    agent_id: &str,
    ts_secs: i64,
    expected_bytes: &[u8; PUBLIC_KEY_LENGTH],
) -> Option<PathBuf> {
    let base = dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts_secs}"));
    if fs::read(&base).ok().as_deref() == Some(expected_bytes.as_slice()) {
        return Some(base);
    }
    for attempt in 1..=64_u32 {
        let cand = dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts_secs}-{attempt}"));
        if fs::read(&cand).ok().as_deref() == Some(expected_bytes.as_slice()) {
            return Some(cand);
        }
    }
    None
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
    let pub_ok = fs::read(agent_pub_path(anchor_dir, agent_id))
        .ok()
        .as_deref()
        == Some(k_new_verifying.as_bytes().as_slice());
    if !pub_ok {
        return Ok(false);
    }
    let priv_ok = keypair::load(agent_id, anchor_dir)
        .ok()
        .and_then(|kp| kp.private.map(|sk| sk.verifying_key() == *k_new_verifying))
        .unwrap_or(false);
    if !priv_ok {
        return Ok(false);
    }
    if find_existing_archive_with_bytes(anchor_dir, agent_id, ts_secs, k_old_bytes).is_none() {
        return Ok(false);
    }
    if let Some(staged) = staged_key_label
        && staged != agent_id
        && (agent_pub_path(anchor_dir, staged).exists()
            || agent_priv_path(anchor_dir, staged).exists())
    {
        return Ok(false);
    }
    if !matches!(TrustAnchor::load_dir(anchor_dir), AnchorLoad::Anchored(_)) {
        return Ok(false);
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
/// 1. Validate inputs + read enrolled lineage (`lineage_head`);
/// 2. Resolve guardian quorum policy from prior signed lineage record (R-2) or
///    enrolled operator policy (never CLI args/request);
/// 3. Verify M-of-N guardian signatures over `(agent_id, epoch, K_old, K_new)`
///    BEFORE evaluating any `K_new` signature or touching state (R-1, R-3);
/// 4. Evaluate `arm`: refuse verify-only (R-8), missing `K_new.priv` (R-8), or
///    `K_new.pub != --successor-pubkey` (R-4);
/// 5. Refuse replay of an already-converged recovery or epoch/key reuse (R-9),
///    or prepare an idempotent resume when DB committed before anchor swap (R-6).
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
    let lineage = read_lineage(conn, req.agent_id)?;
    let Some((head, _)) = lineage.last() else {
        bail!(
            "no lineage enrolled for '{}' — nothing to recover",
            req.agent_id
        );
    };
    let policy = RecoveryPolicy::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot mint a recovery record — no recovery guardians enrolled \
             (set AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS)"
        )
    })?;
    let quorum_blob = encode_recovery_quorum(req.quorum)?;

    // Idempotent post-commit resume vs replay check (R-6 / R-9).
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

    // R-2: quorum set and threshold from prior signed lineage record (if any),
    // never from CLI arguments or the recovery request.
    let (guardian_set_id, threshold_u64) = resolve_committed_quorum(&lineage, &policy)?;

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

    // Verify anchor_dir security chain before touching disk.
    let target_pub = agent_pub_path(anchor_dir, req.agent_id);
    if target_pub.exists() {
        enforce_key_path_chain_secure(anchor_dir, &target_pub)?;
    } else if anchor_dir.exists() {
        enforce_key_path_chain_secure(anchor_dir, anchor_dir)?;
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

fn archive_k_old_idempotent(
    anchor_dir: &Path,
    agent_id: &str,
    k_old_bytes: &[u8; PUBLIC_KEY_LENGTH],
    ts_secs: i64,
) -> Result<PathBuf> {
    if let Some(existing) =
        find_existing_archive_with_bytes(anchor_dir, agent_id, ts_secs, k_old_bytes)
    {
        return Ok(existing);
    }
    for attempt in 0..=64_u32 {
        let cand = if attempt == 0 {
            anchor_dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts_secs}"))
        } else {
            anchor_dir.join(format!("{agent_id}{PUB_SUFFIX}.{ts_secs}-{attempt}"))
        };
        if cand.exists() {
            continue;
        }
        atomic_write_in_anchor(anchor_dir, &cand, k_old_bytes, 0o644)?;
        return Ok(cand);
    }
    bail!(
        "refusing to recover {agent_id}: every archive name for timestamp {ts_secs} under {} is taken",
        anchor_dir.display()
    );
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
    let parent = agent_pub_path(anchor_dir, agent_id)
        .parent()
        .map_or_else(|| anchor_dir.to_path_buf(), Path::to_path_buf);
    if let Ok(entries) = fs::read_dir(&parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(s) = name.to_str()
                && s.starts_with(".recover-")
                && s.ends_with(".tmp")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    sync_dir(&parent)?;
    Ok(())
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
    execute_recovery_rebind_with_fault(conn, checked, RecoveryFaultPoint::None)
}

/// [`execute_recovery_rebind`] with a fault-injection hook at each step of the
/// DB-commit -> anchor-swap -> seal-advance order (R-6).
///
/// # Errors
///
/// Propagates storage, filesystem, or injected fault errors.
pub fn execute_recovery_rebind_with_fault(
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
            // Step 1 (R-5, R-9): single IMMEDIATE SQLite transaction covering:
            //   (a) arm_for_recovery_in_tx (signs unsigned cutovers if never armed + registers FixedAt K_new @ ts_rfc),
            //   (b) INSERT INTO agent_lineage,
            //   (c) bind_agent_pubkey_no_tx_at (agent_pubkey_history append + _agents UPDATE -> fires row_attestations trigger under K_new @ ts_rfc),
            //   (d) signed_events witness append.
            let record_bytes = record.canonical_bytes()?;
            let witness_hash = record.witness_payload_hash()?;
            let write_txn =
                WriteTxn::begin(conn).context("execute_recovery_rebind: begin single tx")?;
            let tx_res = (|| -> Result<()> {
                arm_for_recovery_in_tx(conn, agent_id, k_new_signing, anchor_dir, &ts_rfc)?;
                conn.execute(
                    "INSERT INTO agent_lineage \
                        (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, \
                         recovery_pubkey, not_before, prev_record_hash, signature, \
                         record_bytes, created_at, custody_class, suspected_compromise_from_seq, \
                         guardian_set_id, recovery_threshold) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        record.agent_id,
                        i64::try_from(record.epoch).context("lineage epoch exceeds i64")?,
                        record.reason.as_str(),
                        record.predecessor_pubkey_b64,
                        record.successor_pubkey_b64,
                        record.recovery_pubkey_b64,
                        record.not_before,
                        record.prev_record_hash,
                        quorum_blob,
                        record_bytes,
                        ts_rfc,
                        record.custody_class.as_str(),
                        record
                            .suspected_compromise_from_seq
                            .map(|s| i64::try_from(s).unwrap_or(i64::MAX)),
                        record.guardian_set_id.as_deref(),
                        record
                            .recovery_threshold
                            .map(|m| i64::try_from(m).unwrap_or(i64::MAX)),
                    ],
                )
                .context("execute_recovery_rebind: insert agent_lineage")?;

                let proof = PossessionProof::from_verified_guardian_recovery(
                    agent_id,
                    &record.predecessor_pubkey_b64,
                    &record.successor_pubkey_b64,
                )?;
                bind_agent_pubkey_no_tx_at(
                    conn,
                    agent_id,
                    &successor_pubkey_canonical,
                    &proof,
                    &ts_rfc,
                )?;

                let witness = crate::signed_events::SignedEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    agent_id: agent_id.to_string(),
                    event_type: lineage_witness_event_type(record.reason).to_string(),
                    payload_hash: witness_hash,
                    signature: Some(quorum_blob.clone()),
                    attest_level: crate::models::AttestLevel::LineageSigned
                        .as_str()
                        .to_string(),
                    timestamp: ts_rfc.clone(),
                    ..crate::signed_events::SignedEvent::default()
                };
                let anchor = crate::signed_events::append_signed_event_no_tx(conn, &witness)
                    .context("execute_recovery_rebind: witness append")?;
                escalation_deferral::defer_audit_anchor(conn, anchor);

                if fault == RecoveryFaultPoint::BeforeDbCommit {
                    bail!("injected fault: BeforeDbCommit");
                }
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
            // Always restore the normal funnel so `conn` never keeps a frozen
            // recovery timestamp trigger on subsequent writes.
            let _ = restore_post_recovery_funnel(conn);
            commit_res?;
            (record, false)
        }
    };

    if fault == RecoveryFaultPoint::AfterDbCommitBeforeArchive {
        bail!("injected fault: AfterDbCommitBeforeArchive");
    }

    // Step 2a (R-6, R-9): archive retired K_old to `<agent>.pub.<ts_secs>`.
    let archived_pub = archive_k_old_idempotent(anchor_dir, agent_id, &k_old_pub_bytes, ts_secs)?;
    if fault == RecoveryFaultPoint::AfterArchiveBeforePrivInstall {
        bail!("injected fault: AfterArchiveBeforePrivInstall");
    }

    // Step 2b (R-6, R-14): install `K_new.priv` at `<agent>.priv` (mode 0600,
    // staged + fsynced + renamed strictly inside `anchor_dir`).
    let priv_path = agent_priv_path(anchor_dir, agent_id);
    atomic_write_in_anchor(anchor_dir, &priv_path, &k_new_signing.to_bytes(), 0o600)?;
    if fault == RecoveryFaultPoint::AfterPrivInstallBeforePubInstall {
        bail!("injected fault: AfterPrivInstallBeforePubInstall");
    }

    // Step 2c (R-6, R-9): install `K_new.pub` at `<agent>.pub` (mode 0644).
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

    // Step 2d: remove staged sibling keypair so TrustAnchor has zero duplicate key_id.
    cleanup_staged_and_temps(anchor_dir, agent_id, staged_key_label)?;
    if fault == RecoveryFaultPoint::AfterPubInstallBeforeSealAdvance {
        bail!("injected fault: AfterPubInstallBeforeSealAdvance");
    }

    // Step 3 (R-10): advance the anchored seal to the committed DB marks.
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
    let Some(_) = lineage_head(conn, agent_id)? else {
        bail!("{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: no lineage enrolled for '{agent_id}'");
    };
    let verified = verify_agent_lineage(conn, agent_id)?.map_err(|e| {
        anyhow::anyhow!("{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: lineage verification failed: {e}")
    })?;
    let expected_key_id = super::row_attest::key_id_of(&verified.head_key);
    let current_anchor_keys: Vec<String> = anchor
        .fingerprints()
        .into_iter()
        .filter(|(a, _, retired)| a == agent_id && !retired)
        .map(|(_, kid, _)| kid)
        .collect();
    if current_anchor_keys.as_slice() != [expected_key_id.as_str()] {
        bail!(
            "{REFUSE_ANCHOR_UNATTESTED_KEY_SWAP}: anchor current key {current_anchor_keys:?} \
             does not match quorum-verified lineage head {expected_key_id} for '{agent_id}'"
        );
    }
    Ok(())
}
