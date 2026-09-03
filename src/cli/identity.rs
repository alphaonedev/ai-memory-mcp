// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory identity` subcommand — per-agent Ed25519 keypair lifecycle
//! (Track H, Task H1).
//!
//! See [`crate::identity::keypair`] for the underlying lifecycle. This
//! module is the thin clap wrapper that turns command-line input into
//! the four verbs (`generate / import / list / export-pub`) and prints
//! the result via the standard [`CliOutput`] writer pair.
//!
//! ## Hardware-backed key storage is OUT of OSS scope
//!
//! TPM 2.0, PKCS#11 HSMs, Apple Secure Enclave, and cloud KMS adapters
//! are intentionally not in this subcommand. See the module-level
//! comment on [`crate::identity::keypair`] and `ROADMAP.md` —
//! AgenticMem™ is the commercial home for those backends.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;

use crate::cli::CliOutput;
use crate::identity::{self, keypair};
use crate::validate;

/// JSON output field for the base64 public key (#1558 batch 6).
const PUBLIC_KEY_B64_FIELD: &str = "public_key_b64";

#[derive(Args)]
pub struct IdentityArgs {
    /// Override the default key storage directory.
    /// Default by platform:
    ///   Linux:   `~/.config/ai-memory/keys/`,
    ///   macOS:   `~/Library/Application Support/ai-memory/keys/`,
    ///   Windows: `%APPDATA%\ai-memory\keys\`.
    /// Honors `AI_MEMORY_KEY_DIR` env var when this flag is omitted.
    #[arg(long, value_name = "PATH", global = true)]
    pub key_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub action: IdentityAction,
}

#[derive(Subcommand)]
pub enum IdentityAction {
    /// Generate a fresh Ed25519 keypair for `--agent-id` (or the
    /// NHI-hardened default if omitted) and persist it under the key
    /// storage directory with strict 0600/0644 modes on Unix.
    Generate {
        /// Agent identifier. Defaults to the same NHI-hardened id the
        /// rest of the CLI synthesizes (e.g. `host:<host>:pid-<pid>-<uuid8>`).
        #[arg(long)]
        agent_id: Option<String>,
        /// Allow overwriting an existing keypair for `--agent-id`.
        /// Without this flag, `generate` refuses on an existing id —
        /// the safe default to prevent a typo from silently rotating
        /// (and irrecoverably destroying) a daemon or peer key. Pass
        /// `--force` only when you intend to rotate.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Deprecated alias retained for backward compatibility with
        /// the v0.7.0 pre-Round-4 flag surface. The default behavior
        /// is now refuse-on-existing; this flag is a no-op. Use
        /// `--force` to opt INTO overwrite.
        #[arg(long, default_value_t = false, hide = true)]
        no_overwrite: bool,
    },
    /// Import a keypair from on-disk files written by another tool.
    /// `--pub` is required; `--priv` is optional (omit it to import a
    /// public-only handle for verification, e.g., a peer's allowlist
    /// entry).
    Import {
        /// Agent identifier the imported material will be saved under.
        #[arg(long)]
        agent_id: String,
        /// Path to a 32-byte raw Ed25519 public key file.
        #[arg(long = "pub", value_name = "PATH")]
        public: PathBuf,
        /// Optional path to a 32-byte raw Ed25519 private key file.
        #[arg(long = "priv", value_name = "PATH")]
        private: Option<PathBuf>,
    },
    /// List every keypair stored under the key storage directory.
    /// Private keys are never loaded — `list` is safe to wire into
    /// dashboards and shell autocompletion.
    List,
    /// Print a base64-encoded public key for `--agent-id` to stdout.
    /// Stable URL-safe-no-padding form so the output can be pasted
    /// into a Slack message or a peer allowlist file without binary
    /// hazards.
    ExportPub {
        /// Agent identifier whose public key should be exported.
        #[arg(long)]
        agent_id: String,
    },
    /// v0.9.0 G13 (#1828) — enroll an identity lineage: mint the
    /// epoch-0 self-signed GENESIS record anchored in the agent's
    /// current keypair, persisted atomically with its append-only
    /// `signed_events` witness. The agent must already be registered
    /// (`ai-memory agents register`). Single-node ROTATION-survival
    /// only — this is NOT key-loss protection (recovery lands in v1.0).
    EnrollLineage {
        /// Agent identifier. Defaults to the NHI-hardened id.
        #[arg(long)]
        agent_id: Option<String>,
        /// Optional base64 Ed25519 recovery public key committed into
        /// the genesis record. Carried for v1.0 forward-compat; the
        /// recovery VERIFY path does NOT exist in v0.9.0.
        #[arg(long, value_name = "PUBKEY_B64")]
        recovery_pubkey: Option<String>,
    },
    /// v0.9.0 G13 (#1828) — rotate the keypair WITH a signed lineage
    /// succession: the retiring key signs the handoff BEFORE it is
    /// destroyed, so the identity survives the rotation. Requires an
    /// enrolled lineage (`identity enroll-lineage`). The legacy
    /// `identity generate --force` rotation (no lineage) is unchanged.
    Succeed {
        /// Agent identifier. Defaults to the NHI-hardened id.
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// v0.9.0 G13 (#1828) — (re-)register the cold recovery public key
    /// by appending a self-succession record (the head key re-signs
    /// itself carrying the new recovery commitment). The recovery
    /// VERIFY path lands in v1.0 — registering the key today only
    /// commits it into the signed chain for forward-compat.
    RegisterRecoveryKey {
        /// Agent identifier. Defaults to the NHI-hardened id.
        #[arg(long)]
        agent_id: Option<String>,
        /// base64 Ed25519 recovery public key (URL-safe-no-pad or
        /// standard padding accepted).
        #[arg(long, value_name = "PUBKEY_B64")]
        recovery_pubkey: String,
    },
    /// v1.0.0 G17 (#1831) — phase 1 of the M-of-N recovery ceremony: mint
    /// the prospective recovery record that hands the LOST head off to a
    /// FRESH primary key (`--successor-pubkey`), and print the base64
    /// "challenge" bytes each enrolled recovery guardian must sign offline.
    /// DB-backed (reads the current head). Echo `not_before` verbatim into
    /// `recover`. This is the key-LOSS recovery path (closes gap G13).
    RecoverPrepare {
        /// Agent identifier whose identity is being recovered.
        #[arg(long)]
        agent_id: Option<String>,
        /// base64 Ed25519 PUBLIC key of the FRESH primary key that becomes
        /// the new head (generate it with `identity generate` + export-pub).
        #[arg(long, value_name = "PUBKEY_B64")]
        successor_pubkey: String,
        /// Optional: also date a suspected key compromise from this
        /// `signed_events` witness SEQUENCE (a recovery doubling as a
        /// revocation — for the stolen-AND-lost-key case).
        #[arg(long, value_name = "SEQ")]
        from_seq: Option<u64>,
        /// Optional: (re-)register a cold recovery public key on the fresh
        /// head. Absent carries the head's existing commitment forward.
        #[arg(long, value_name = "PUBKEY_B64")]
        recovery_pubkey: Option<String>,
    },
    /// v1.0.0 G17 (#1831) — guardian side of the M-of-N recovery ceremony:
    /// sign the base64 `--challenge` emitted by `recover-prepare` with THIS
    /// guardian's keypair and print `{guardian_pubkey_b64, signature_b64}`.
    /// DB-free — a guardian never needs the recovered agent's database.
    SignRecovery {
        /// The guardian's own key label (defaults to the NHI id). The
        /// guardian signs with the private key stored under this id.
        #[arg(long)]
        agent_id: Option<String>,
        /// base64 recovery challenge from `recover-prepare`.
        #[arg(long, value_name = "CHALLENGE_B64")]
        challenge: String,
    },
    /// v1.0.0 G17 (#1831) — phase 2 of the M-of-N recovery ceremony:
    /// re-mint the SAME recovery record (pass the `--not-before` echoed by
    /// `recover-prepare`), assemble the collected guardian attestations, and
    /// persist it — verifying the M-of-N quorum against the enrolled
    /// guardian set (`AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS` /
    /// `AI_MEMORY_RECOVERY_THRESHOLD`) + the committed trust bar in the signed
    /// record body, ordered by `not_before` anti-rollback monotonicity, BEFORE
    /// any write. There is NO wall-clock / liveness / dead-man silence-window
    /// gate (that time-windowed resolution is deferred to a future release).
    /// On success the fresh key is the new authoritative head.
    Recover {
        /// Agent identifier whose identity is being recovered.
        #[arg(long)]
        agent_id: Option<String>,
        /// The SAME fresh-primary public key passed to `recover-prepare`.
        #[arg(long, value_name = "PUBKEY_B64")]
        successor_pubkey: String,
        /// Echo the `not_before` value `recover-prepare` printed (so the
        /// re-minted record is byte-identical to what the guardians signed).
        #[arg(long, value_name = "RFC3339")]
        not_before: String,
        /// The SAME `--from-seq` (if any) passed to `recover-prepare`.
        #[arg(long, value_name = "SEQ")]
        from_seq: Option<u64>,
        /// The SAME `--recovery-pubkey` (if any) passed to `recover-prepare`.
        #[arg(long, value_name = "PUBKEY_B64")]
        recovery_pubkey: Option<String>,
        /// A guardian attestation `guardian_pubkey_b64:signature_b64` (from
        /// `sign-recovery`). Repeat once per guardian; M distinct enrolled
        /// signers must be presented.
        #[arg(long = "attestation", value_name = "PUBKEY_B64:SIG_B64")]
        attestations: Vec<String>,
    },
}

/// Resolve the key storage directory from `--key-dir` (caller override)
/// or the OSS default at `<config>/ai-memory/keys`.
fn resolve_key_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_dir {
        return Ok(p.to_path_buf());
    }
    keypair::default_key_dir()
}

/// Resolve the agent_id for a CLI invocation: explicit `--agent-id`
/// wins, otherwise fall back to the NHI default. We pass `None` for
/// the MCP client so the resolution stops at the host-or-anonymous
/// branch (CLI is not an MCP handshake).
fn resolve_id(explicit: Option<&str>) -> Result<String> {
    identity::resolve_agent_id(explicit, None)
}

/// `identity` handler.
///
/// Returns `Ok(())` on success, propagates errors otherwise. The
/// caller is `daemon_runtime::dispatch_command` which prints the error
/// + exits non-zero in the standard way.
///
/// `db_path` backs ONLY the G13 lineage verbs (`enroll-lineage` /
/// `succeed` / `register-recovery-key`) — the H1 keypair-lifecycle
/// verbs stay DB-free and never open it.
pub fn run(
    db_path: &Path,
    args: IdentityArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let dir = resolve_key_dir(args.key_dir.as_deref())?;
    match args.action {
        IdentityAction::Generate {
            agent_id,
            force,
            no_overwrite: _,
        } => generate(&dir, agent_id.as_deref(), force, json_out, out),
        IdentityAction::Import {
            agent_id,
            public,
            private,
        } => import(&dir, &agent_id, &public, private.as_deref(), json_out, out),
        IdentityAction::List => list(&dir, json_out, out),
        IdentityAction::ExportPub { agent_id } => export_pub(&dir, &agent_id, json_out, out),
        IdentityAction::EnrollLineage {
            agent_id,
            recovery_pubkey,
        } => enroll_lineage(
            db_path,
            &dir,
            agent_id.as_deref(),
            recovery_pubkey.as_deref(),
            json_out,
            out,
        ),
        IdentityAction::Succeed { agent_id } => {
            succeed(db_path, &dir, agent_id.as_deref(), json_out, out)
        }
        IdentityAction::RegisterRecoveryKey {
            agent_id,
            recovery_pubkey,
        } => register_recovery_key(
            db_path,
            &dir,
            agent_id.as_deref(),
            &recovery_pubkey,
            json_out,
            out,
        ),
        IdentityAction::RecoverPrepare {
            agent_id,
            successor_pubkey,
            from_seq,
            recovery_pubkey,
        } => recover_prepare(
            db_path,
            agent_id.as_deref(),
            &successor_pubkey,
            from_seq,
            recovery_pubkey.as_deref(),
            json_out,
            out,
        ),
        IdentityAction::SignRecovery {
            agent_id,
            challenge,
        } => sign_recovery(&dir, agent_id.as_deref(), &challenge, json_out, out),
        IdentityAction::Recover {
            agent_id,
            successor_pubkey,
            not_before,
            from_seq,
            recovery_pubkey,
            attestations,
        } => recover(
            db_path,
            agent_id.as_deref(),
            &successor_pubkey,
            &not_before,
            from_seq,
            recovery_pubkey.as_deref(),
            &attestations,
            json_out,
            out,
        ),
    }
}

fn generate(
    dir: &Path,
    explicit_agent_id: Option<&str>,
    force: bool,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // `identity generate` is an internal-bootstrap surface that must
    // legitimately accept [`validate::RESERVED_AGENT_IDS`] sentinels
    // (the daemon's own self-signing keypair label
    // `DAEMON_KEYPAIR_LABEL` = "daemon", the federation-catchup label,
    // etc.). Use [`validate::validate_agent_id_shape`] (shape-only,
    // doesn't reject reserved sentinels) for the explicit caller path,
    // bypassing the strict [`validate::validate_agent_id`] that
    // `resolve_id` → `identity::resolve_agent_id` applies. The
    // wire-side ingress boundaries (HTTP body, MCP tool param) still
    // strict-validate at their own boundary — this carve-out is
    // CLI-key-generation-only. Closes #1234 (RCA: this site was
    // missed when #977 introduced RESERVED_AGENT_IDS + the
    // shape/wire split).
    let id = match explicit_agent_id {
        Some(explicit) if !explicit.is_empty() => {
            validate::validate_agent_id_shape(explicit)?;
            explicit.to_string()
        }
        _ => resolve_id(explicit_agent_id)?,
    };
    let pub_path = dir.join(format!("{id}.pub"));
    // Round-4 — refuse-by-default. The pre-Round-4 default was OVERWRITE,
    // which let a typo silently rotate (and destroy) a daemon or peer
    // keypair. Now `generate` refuses if a key already exists; the
    // operator must pass `--force` to opt into rotation. The legacy
    // `--no-overwrite` flag is preserved as a hidden no-op for
    // backward compatibility with scripts that invoked it.
    if !force && pub_path.exists() {
        bail!(
            "keypair for {id} already exists at {} (pass --force to rotate; refused by default to prevent accidental key overwrite)",
            pub_path.display()
        );
    }
    // #1679 — a `--force` rotation over an EXISTING key goes through
    // `keypair::rotate`, which archives the prior PUBLIC key to a
    // timestamped sibling BEFORE overwriting (so the verification anchor
    // for historical signed_events is not silently destroyed; the old
    // PRIVATE key is destroyed by the overwrite = forward security). A
    // first-time create (no existing key) is the plain generate+save.
    let (kp, archived_pub) = if force && pub_path.exists() {
        let outcome = keypair::rotate(&id, dir)?;
        (keypair::load(&id, dir)?, Some(outcome.archived_pub))
    } else {
        let kp = keypair::generate(&id)?;
        keypair::save(&kp, dir)?;
        (kp, None)
    };
    if json_out {
        let mut obj = serde_json::json!({
            "generated": true,
            "rotated": archived_pub.is_some(),
            "agent_id": id,
            "key_dir": dir,
            (PUBLIC_KEY_B64_FIELD): kp.public_base64(),
        });
        if let Some(ref ap) = archived_pub {
            obj["archived_pub"] = serde_json::json!(ap.display().to_string());
        }
        writeln!(out.stdout, "{obj}")?;
    } else {
        let verb = if archived_pub.is_some() {
            "rotated"
        } else {
            "generated"
        };
        writeln!(out.stdout, "{verb} keypair for {id}")?;
        writeln!(out.stdout, "  key_dir = {}", dir.display())?;
        writeln!(out.stdout, "  pub_b64 = {}", kp.public_base64())?;
        if let Some(ref ap) = archived_pub {
            writeln!(out.stdout, "  archived_prior_pub = {}", ap.display())?;
        }
    }
    Ok(())
}

fn import(
    dir: &Path,
    agent_id: &str,
    pub_path: &Path,
    priv_path: Option<&Path>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    crate::validate::validate_agent_id(agent_id)?;
    let pub_bytes = keypair::read_raw_key_file(pub_path)
        .with_context(|| format!("reading --pub {}", pub_path.display()))?;
    let public = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes)
        .with_context(|| "decoding imported public key".to_string())?;

    let private = if let Some(p) = priv_path {
        let priv_bytes = keypair::read_raw_key_file(p)
            .with_context(|| format!("reading --priv {}", p.display()))?;
        let signing = SigningKey::from_bytes(&priv_bytes);
        // Cross-check before persisting — refuse mismatched pairs.
        if signing.verifying_key().to_bytes() != public.to_bytes() {
            bail!(
                "imported --priv {} does not match --pub {}",
                p.display(),
                pub_path.display()
            );
        }
        Some(signing)
    } else {
        None
    };

    let kp = keypair::AgentKeypair {
        agent_id: agent_id.to_string(),
        public,
        private,
    };
    if kp.private.is_some() {
        keypair::save(&kp, dir)?;
    } else {
        keypair::save_public_only(&kp, dir)?;
    }

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "imported": true,
                "agent_id": agent_id,
                "key_dir": dir,
                "private_imported": kp.private.is_some(),
                (PUBLIC_KEY_B64_FIELD): kp.public_base64(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "imported keypair for {agent_id} (private={})",
            if kp.private.is_some() { "yes" } else { "no" }
        )?;
        writeln!(out.stdout, "  key_dir = {}", dir.display())?;
        writeln!(out.stdout, "  pub_b64 = {}", kp.public_base64())?;
    }
    Ok(())
}

fn list(dir: &Path, json_out: bool, out: &mut CliOutput<'_>) -> Result<()> {
    let keys = keypair::list(dir)?;
    if json_out {
        let entries: Vec<_> = keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "agent_id": k.agent_id,
                    (PUBLIC_KEY_B64_FIELD): k.public_base64(),
                })
            })
            .collect();
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "count": entries.len(),
                "key_dir": dir,
                "keys": entries,
            })
        )?;
    } else if keys.is_empty() {
        writeln!(out.stdout, "no keypairs in {}", dir.display())?;
    } else {
        for k in &keys {
            writeln!(out.stdout, "{}  {}", k.agent_id, k.public_base64())?;
        }
        writeln!(out.stdout, "{} keypair(s) in {}", keys.len(), dir.display())?;
    }
    Ok(())
}

fn export_pub(dir: &Path, agent_id: &str, json_out: bool, out: &mut CliOutput<'_>) -> Result<()> {
    let kp = keypair::load(agent_id, dir)?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "agent_id": agent_id,
                (PUBLIC_KEY_B64_FIELD): kp.public_base64(),
            })
        )?;
    } else {
        // Plain text path: just the base64 — pipe-friendly for
        // `ai-memory identity export-pub --agent-id alice | xclip`.
        writeln!(out.stdout, "{}", kp.public_base64())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// v0.9.0 G13 (#1828) — identity-lineage verbs.
//
// Honest scope (C7): single-node key-ROTATION survival. NOT key-loss
// resilience (the recovery VERIFY path lands in v1.0), and invisible
// cross-host (federation peers resolve via the on-disk key store, not
// this chain). Advisory-only (C6): the attest_write enforcement path
// keeps reading the flat `metadata.agent_pubkey`, which every lineage
// append keeps in sync.
// ---------------------------------------------------------------------------

/// Resolve the lineage-verb agent id: shape-validate an explicit id
/// (reserved sentinels allowed — same carve-out as `generate`, #1234),
/// else the NHI default.
fn resolve_lineage_id(explicit: Option<&str>) -> Result<String> {
    match explicit {
        Some(id) if !id.is_empty() => {
            validate::validate_agent_id_shape(id)?;
            Ok(id.to_string())
        }
        _ => resolve_id(explicit),
    }
}

/// Write the shared `  head_pub_b64 = <b64>` readout line for the lineage
/// verbs — one definition so the format string is not scattered across the
/// enroll / succeed / recover handlers (pm-v3.1 no-scattered-literals).
fn write_head_pub_line(out: &mut CliOutput<'_>, pub_b64: &str) -> std::io::Result<()> {
    writeln!(out.stdout, "  head_pub_b64 = {pub_b64}")
}

fn enroll_lineage(
    db_path: &Path,
    dir: &Path,
    explicit_agent_id: Option<&str>,
    recovery_pubkey: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let id = resolve_lineage_id(explicit_agent_id)?;
    let kp = keypair::load(&id, dir)
        .with_context(|| format!("loading keypair for {id} (run `identity generate` first)"))?;
    let conn = crate::db::open(db_path)?;
    let record = crate::db::enroll_lineage(&conn, &id, &kp, recovery_pubkey)?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "enrolled": true,
                "agent_id": id,
                "epoch": record.epoch,
                (PUBLIC_KEY_B64_FIELD): record.successor_pubkey_b64,
                "recovery_pubkey_registered": record.recovery_pubkey_b64.is_some(),
            })
        )?;
    } else {
        writeln!(out.stdout, "enrolled identity lineage for {id} (epoch 0)")?;
        write_head_pub_line(out, &record.successor_pubkey_b64)?;
        if record.recovery_pubkey_b64.is_some() {
            writeln!(
                out.stdout,
                "  recovery key committed (VERIFY path lands in v1.0 — this is \
                 forward-compat registration, not key-loss protection yet)"
            )?;
        }
    }
    Ok(())
}

fn succeed(
    db_path: &Path,
    dir: &Path,
    explicit_agent_id: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let id = resolve_lineage_id(explicit_agent_id)?;
    let conn = crate::db::open(db_path)?;
    let recorded: std::cell::RefCell<Option<crate::identity::lineage::LineageRecord>> =
        std::cell::RefCell::new(None);
    // Sign-then-rotate seam: the succession is signed by K_old and
    // durably persisted (body + pubkey sync + witness, one tx) BEFORE
    // `save` destroys K_old on disk.
    let outcome = keypair::rotate_with_succession(&id, dir, |k_old, k_new| {
        let record = crate::db::append_succession(&conn, &id, k_old, &k_new.public_base64(), None)?;
        recorded.replace(Some(record));
        Ok(())
    })?;
    let record = recorded
        .into_inner()
        .context("succession closure did not run")?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "succeeded": true,
                "agent_id": id,
                "epoch": record.epoch,
                (PUBLIC_KEY_B64_FIELD): record.successor_pubkey_b64,
                "archived_pub": outcome.archived_pub.display().to_string(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "rotated keypair for {id} with signed succession (epoch {})",
            record.epoch
        )?;
        write_head_pub_line(out, &record.successor_pubkey_b64)?;
        writeln!(
            out.stdout,
            "  archived_prior_pub = {}",
            outcome.archived_pub.display()
        )?;
    }
    Ok(())
}

fn register_recovery_key(
    db_path: &Path,
    dir: &Path,
    explicit_agent_id: Option<&str>,
    recovery_pubkey: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let id = resolve_lineage_id(explicit_agent_id)?;
    let kp = keypair::load(&id, dir)
        .with_context(|| format!("loading keypair for {id} (run `identity generate` first)"))?;
    let conn = crate::db::open(db_path)?;
    // Self-succession: the head key re-signs itself carrying the new
    // recovery commitment — the head does not change, the epoch does.
    let record =
        crate::db::append_succession(&conn, &id, &kp, &kp.public_base64(), Some(recovery_pubkey))?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "recovery_key_registered": true,
                "agent_id": id,
                "epoch": record.epoch,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "registered recovery key for {id} (epoch {}) — the recovery VERIFY path \
             lands in v1.0; this commits the key for forward-compat only",
            record.epoch
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// v1.0.0 G17 (#1831) — M-of-N threshold key recovery ceremony.
//
// Honest scope: SINGLE-NODE key-LOSS recovery. The M-of-N recovery-quorum
// signatures + the lineage chain are ATTESTABLE; guardian-key custody +
// enrollment (AI_MEMORY_RECOVERY_GUARDIAN_PUBKEYS) are ESTIMABLE /
// operational (same custody boundary as the #1957 approver quorum).
// Cross-host propagation stays deferred like the rest of the lineage layer.
// ---------------------------------------------------------------------------

/// Decode a base64 blob accepting standard OR url-safe-no-pad spelling.
fn decode_recovery_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let t = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t))
        .map_err(|_| anyhow::anyhow!("value is not valid base64"))
}

fn recover_prepare(
    db_path: &Path,
    explicit_agent_id: Option<&str>,
    successor_pubkey: &str,
    from_seq: Option<u64>,
    recovery_pubkey: Option<&str>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use base64::Engine as _;
    let id = resolve_lineage_id(explicit_agent_id)?;
    let conn = crate::db::open(db_path)?;
    let not_before = chrono::Utc::now().to_rfc3339();
    let (record, challenge) = crate::db::prepare_recovery_challenge(
        &conn,
        &id,
        successor_pubkey,
        from_seq,
        recovery_pubkey,
        &not_before,
    )?;
    let challenge_b64 = base64::engine::general_purpose::STANDARD.encode(&challenge);
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "recovery_prepared": true,
                "agent_id": id,
                "epoch": record.epoch,
                "successor_pubkey": record.successor_pubkey_b64,
                (crate::models::field_names::NOT_BEFORE): record.not_before,
                "from_seq": from_seq,
                "challenge_b64": challenge_b64,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "prepared recovery for {id} (epoch {}) — distribute the challenge to each \
             enrolled recovery guardian:",
            record.epoch
        )?;
        writeln!(out.stdout, "  not_before   = {}", record.not_before)?;
        writeln!(out.stdout, "  challenge_b64 = {challenge_b64}")?;
        writeln!(
            out.stdout,
            "each guardian runs: ai-memory identity sign-recovery --agent-id <guardian> \
             --challenge {challenge_b64}"
        )?;
        writeln!(
            out.stdout,
            "then complete: ai-memory identity recover --agent-id {id} --successor-pubkey {} \
             --not-before {} --attestation <pub:sig> ...",
            record.successor_pubkey_b64, record.not_before
        )?;
    }
    Ok(())
}

fn sign_recovery(
    dir: &Path,
    explicit_agent_id: Option<&str>,
    challenge: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    let id = resolve_lineage_id(explicit_agent_id)?;
    let kp = keypair::load(&id, dir).with_context(|| {
        format!("loading guardian keypair for {id} (run `identity generate` first)")
    })?;
    let signing = kp
        .private
        .as_ref()
        .with_context(|| format!("guardian keypair for {id} is public-only — cannot sign"))?;
    let challenge_bytes = decode_recovery_b64(challenge).context("decoding --challenge")?;
    let sig = signing.sign(&challenge_bytes);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let guardian_pub = kp.public_base64();
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "signed": true,
                "guardian_pubkey_b64": guardian_pub,
                (crate::models::field_names::SIGNATURE_B64): sig_b64,
                "attestation": format!("{guardian_pub}:{sig_b64}"),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "signed recovery challenge as guardian {id}; hand this attestation back:"
        )?;
        writeln!(out.stdout, "  {guardian_pub}:{sig_b64}")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn recover(
    db_path: &Path,
    explicit_agent_id: Option<&str>,
    successor_pubkey: &str,
    not_before: &str,
    from_seq: Option<u64>,
    recovery_pubkey: Option<&str>,
    attestations: &[String],
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let id = resolve_lineage_id(explicit_agent_id)?;
    if attestations.is_empty() {
        bail!("no --attestation presented — collect M guardian attestations via sign-recovery");
    }
    let mut quorum: Vec<crate::identity::lineage::RecoveryAttestation> =
        Vec::with_capacity(attestations.len());
    for att in attestations {
        let (pk, sig) = att.split_once(':').with_context(|| {
            format!("malformed --attestation '{att}' (expected guardian_pubkey_b64:signature_b64)")
        })?;
        let signature = decode_recovery_b64(sig)
            .with_context(|| format!("decoding signature in --attestation for {pk}"))?;
        quorum.push(crate::identity::lineage::RecoveryAttestation {
            guardian_pubkey_b64: pk.trim().to_string(),
            signature,
        });
    }
    let conn = crate::db::open(db_path)?;
    let record = crate::db::append_recovery(
        &conn,
        &id,
        successor_pubkey,
        &quorum,
        from_seq,
        recovery_pubkey,
        not_before,
    )?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "recovered": true,
                "agent_id": id,
                "epoch": record.epoch,
                (PUBLIC_KEY_B64_FIELD): record.successor_pubkey_b64,
                "guardians_presented": quorum.len(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "RECOVERED identity {id} to a fresh head via M-of-N guardian quorum (epoch {})",
            record.epoch
        )?;
        write_head_pub_line(out, &record.successor_pubkey_b64)?;
        writeln!(
            out.stdout,
            "  the lost key is retired; install the fresh keypair on disk under '{id}'"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    fn fresh_env() -> (TestEnv, tempfile::TempDir) {
        let env = TestEnv::fresh();
        let dir = crate::test_support::secure_tempdir();
        (env, dir)
    }

    /// Test shim for the DB-free H1 verbs: the db_path parameter backs
    /// only the G13 lineage verbs and is opened lazily, so a
    /// never-created placeholder proves the legacy verbs stay DB-free
    /// (opening it would error the test loudly).
    fn run_nodb(args: IdentityArgs, json_out: bool, out: &mut CliOutput<'_>) -> Result<()> {
        run(
            Path::new("/nonexistent/ai-memory-identity-h1-verbs-are-db-free.db"),
            args,
            json_out,
            out,
        )
    }

    #[test]
    fn generate_then_list_then_export() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();

        // generate
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("alice".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(
            stdout.contains("generated keypair for alice"),
            "got: {stdout}"
        );

        // list
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::List,
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(stdout.contains("alice"), "got: {stdout}");
        assert!(stdout.contains("1 keypair(s)"), "got: {stdout}");

        // export-pub (text mode prints just the base64)
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::ExportPub {
                        agent_id: "alice".to_string(),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().trim().to_string();
        // Should round-trip through the keypair decoder.
        let decoded = keypair::decode_public_base64(&stdout).expect("decode");
        assert_eq!(decoded.to_bytes().len(), 32);
    }

    #[test]
    fn generate_refuses_existing_without_force() {
        // Round-4 — refuse-by-default semantics. A second `generate`
        // for an existing agent_id MUST fail unless `--force` is
        // passed. The legacy `--no-overwrite` flag is preserved as a
        // hidden no-op for backward compatibility with v0.7.0
        // pre-Round-4 scripts.
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        // First generate
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("alice".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        // Second generate WITHOUT --force should error (refuse-by-default).
        let result = {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("alice".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
        };
        let err = result.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already exists"), "got: {msg}");
        assert!(
            msg.contains("--force"),
            "error message should guide operator toward --force, got: {msg}"
        );

        // Third generate WITH --force should succeed (intentional rotation).
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::Generate {
                        agent_id: Some("alice".to_string()),
                        force: true,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        // #1679 — a --force rotation over an existing key reports
        // "rotated" (not "generated") and surfaces the archived prior
        // public key (the verification anchor preserved before overwrite).
        assert!(
            stdout.contains("rotated keypair for alice"),
            "rotation with --force should report rotation: {stdout}"
        );
        assert!(
            stdout.contains("archived_prior_pub"),
            "rotation should surface the archived prior public key: {stdout}"
        );
        // A timestamped `alice.pub.<ts>` archive sibling exists on disk;
        // no private-key copy was made.
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        assert!(
            entries
                .iter()
                .any(|n| n.starts_with("alice.pub.") && n != "alice.pub"),
            "rotation must leave an archived alice.pub.<ts> sibling; got {entries:?}"
        );
        assert!(
            !entries.iter().any(|n| n.contains(".priv.")),
            "rotation must NOT copy private-key material; got {entries:?}"
        );
    }

    #[test]
    fn list_json_emits_keys_array() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("alice".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::List,
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 1);
        assert_eq!(v["keys"][0]["agent_id"].as_str().unwrap(), "alice");
        assert!(v["keys"][0]["public_key_b64"].as_str().unwrap().len() > 10);
    }

    #[test]
    fn import_round_trip_through_raw_files() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();

        // Create a fresh keypair, dump raw bytes to disk, then `import`.
        let kp = keypair::generate("alice").unwrap();
        let pub_bytes = kp.public.to_bytes();
        let priv_bytes = kp.private.as_ref().unwrap().to_bytes();
        let staging = crate::test_support::secure_tempdir();
        let pub_file = staging.path().join("a.pub");
        let priv_file = staging.path().join("a.priv");
        std::fs::write(&pub_file, pub_bytes).unwrap();
        std::fs::write(&priv_file, priv_bytes).unwrap();

        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Import {
                        agent_id: "alice".to_string(),
                        public: pub_file.clone(),
                        private: Some(priv_file.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(
            stdout.contains("imported keypair for alice"),
            "got: {stdout}"
        );
        // Round-trip through load.
        let loaded = keypair::load("alice", &dir_path).unwrap();
        assert_eq!(loaded.public.to_bytes(), pub_bytes);
        assert!(loaded.can_sign());
    }

    #[test]
    fn import_refuses_priv_pub_mismatch() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let alice = keypair::generate("alice").unwrap();
        let bob = keypair::generate("bob").unwrap();
        let staging = crate::test_support::secure_tempdir();
        let pub_file = staging.path().join("alice.pub");
        let priv_file = staging.path().join("bob.priv");
        std::fs::write(&pub_file, alice.public.to_bytes()).unwrap();
        std::fs::write(&priv_file, bob.private.as_ref().unwrap().to_bytes()).unwrap();

        let result = {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::Import {
                        agent_id: "alice".to_string(),
                        public: pub_file,
                        private: Some(priv_file),
                    },
                },
                false,
                &mut out,
            )
        };
        let err = result.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does not match"), "got: {msg}");
    }

    // ------------------------------------------------------------------
    // L0.7-3 chunk-e2 — coverage uplift to ≥95%.
    // ------------------------------------------------------------------

    #[test]
    fn generate_json_mode_emits_payload() {
        // json_out=true on generate exercises the JSON emission branch
        // (lines 159-169) that the existing happy-path test skipped.
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::Generate {
                        agent_id: Some("carol".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["generated"], true);
        assert_eq!(v["agent_id"].as_str().unwrap(), "carol");
        assert!(v["public_key_b64"].as_str().unwrap().len() > 10);
        assert!(v["key_dir"].is_string());
    }

    #[test]
    fn import_public_only_text_mode() {
        // Public-only import (priv=None) covers the `private = None`
        // branch (line 206), the `save_public_only` branch (217), and
        // the text-mode "(private=no)" emission (lines 233-239).
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let kp = keypair::generate("dave").unwrap();
        let staging = crate::test_support::secure_tempdir();
        let pub_file = staging.path().join("d.pub");
        std::fs::write(&pub_file, kp.public.to_bytes()).unwrap();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Import {
                        agent_id: "dave".to_string(),
                        public: pub_file,
                        private: None,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(
            stdout.contains("imported keypair for dave"),
            "got: {stdout}"
        );
        assert!(stdout.contains("(private=no)"), "got: {stdout}");
        // Round-trip — load should succeed and report no signing key.
        let loaded = keypair::load("dave", &dir_path).unwrap();
        assert!(!loaded.can_sign());
    }

    #[test]
    fn import_public_only_json_mode() {
        // JSON emission covers lines 221-231 with `private_imported=false`.
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let kp = keypair::generate("eve").unwrap();
        let staging = crate::test_support::secure_tempdir();
        let pub_file = staging.path().join("e.pub");
        std::fs::write(&pub_file, kp.public.to_bytes()).unwrap();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::Import {
                        agent_id: "eve".to_string(),
                        public: pub_file,
                        private: None,
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["imported"], true);
        assert_eq!(v["agent_id"].as_str().unwrap(), "eve");
        assert_eq!(v["private_imported"], false);
        assert!(v["public_key_b64"].as_str().unwrap().len() > 10);
    }

    #[test]
    fn import_with_priv_json_mode_reports_private_imported_true() {
        // Mirrors the existing private import test but in json mode to
        // cover lines 220-231 with `private_imported=true`.
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let kp = keypair::generate("frank").unwrap();
        let staging = crate::test_support::secure_tempdir();
        let pub_file = staging.path().join("f.pub");
        let priv_file = staging.path().join("f.priv");
        std::fs::write(&pub_file, kp.public.to_bytes()).unwrap();
        std::fs::write(&priv_file, kp.private.as_ref().unwrap().to_bytes()).unwrap();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::Import {
                        agent_id: "frank".to_string(),
                        public: pub_file,
                        private: Some(priv_file),
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["private_imported"], true);
    }

    #[test]
    fn list_empty_text_mode_emits_no_keypairs() {
        // Empty list in text mode (line 266).
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::List,
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        assert!(env.stdout_str().contains("no keypairs in"));
    }

    #[test]
    fn list_empty_json_mode_emits_count_zero() {
        // JSON list with zero entries — covers the json branch with the
        // empty `entries` collection (line 264).
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::List,
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
        assert!(v["keys"].as_array().unwrap().is_empty());
    }

    #[test]
    fn export_pub_json_mode_emits_payload() {
        // JSON-mode export-pub (lines 278-286).
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        // First generate so there is something to export.
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("grace".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::ExportPub {
                        agent_id: "grace".to_string(),
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["agent_id"].as_str().unwrap(), "grace");
        assert!(v["public_key_b64"].as_str().unwrap().len() > 10);
    }

    #[test]
    fn resolve_key_dir_falls_through_to_default() {
        // No override path → falls through to `keypair::default_key_dir()`
        // (line 102). We don't assert on the contents (HOME-dependent),
        // only that we reach the call and get a `Result`.
        let r = resolve_key_dir(None);
        // The default-key-dir resolution depends on dirs::config_dir(),
        // which is generally available on macOS/Linux test hosts. Tolerate
        // both Ok (typical) and Err (CI without HOME).
        match r {
            Ok(p) => assert!(p.as_os_str().len() > 0),
            Err(_) => {}
        }
    }

    // ----- v0.9.0 G13 (#1828) lineage verbs ----------------------------

    /// Full CLI lifecycle: generate → register → enroll-lineage →
    /// succeed → register-recovery-key, asserting the printed surfaces
    /// and the DB-side chain state after each verb.
    #[test]
    fn lineage_verbs_end_to_end() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, "lin-alice", "ai:test", &[]).unwrap();
        }
        // generate the K0 keypair.
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Generate {
                        agent_id: Some("lin-alice".to_string()),
                        force: false,
                        no_overwrite: false,
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }

        // enroll-lineage (JSON mode). #1949 — recovery_pubkey is now
        // REQUIRED at genesis for new chains.
        let recovery_b64 = keypair::generate("lin-alice-recovery")
            .unwrap()
            .public_base64();
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some("lin-alice".to_string()),
                        recovery_pubkey: Some(recovery_b64.clone()),
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["enrolled"], true);
        assert_eq!(v["epoch"], 0);
        assert_eq!(v["recovery_pubkey_registered"], true);

        // succeed (text mode) — rotates on disk AND appends the chain.
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some("lin-alice".to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(
            stdout.contains("signed succession (epoch 1)"),
            "got: {stdout}"
        );
        assert!(stdout.contains("archived_prior_pub"), "got: {stdout}");

        // register-recovery-key (JSON) — self-succession at epoch 2.
        let recovery = keypair::generate("lin-alice").unwrap();
        env.stdout.clear();
        env.stderr.clear();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::RegisterRecoveryKey {
                        agent_id: Some("lin-alice".to_string()),
                        recovery_pubkey: recovery.public_base64(),
                    },
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["recovery_key_registered"], true);
        assert_eq!(v["epoch"], 2);

        // DB-side: the chain verifies and the head is the ACTIVE key.
        let conn = crate::db::open(&db_path).unwrap();
        let active = keypair::load("lin-alice", &dir_path).unwrap();
        let verified = crate::db::verify_agent_lineage(&conn, "lin-alice")
            .unwrap()
            .expect("chain verifies");
        assert_eq!(verified.epoch, 2);
        assert_eq!(verified.head_key.to_bytes(), active.public.to_bytes());
    }

    #[test]
    fn lineage_text_surfaces_and_refusals() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, "lin-bob", "ai:test", &[]).unwrap();
        }
        // enroll without a keypair on disk → clear error.
        {
            let mut out = env.output();
            let err = run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some("lin-bob".to_string()),
                        recovery_pubkey: None,
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("identity generate"),
                "got: {err:#}"
            );
        }
        // succeed without an enrolled lineage → refused (and the disk
        // keypair is untouched by the failed rotation).
        let k0 = keypair::generate("lin-bob").unwrap();
        keypair::save(&k0, &dir_path).unwrap();
        {
            let mut out = env.output();
            let err = run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some("lin-bob".to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("enroll-lineage"),
                "got: {err:#}"
            );
            let on_disk = keypair::load("lin-bob", &dir_path).unwrap();
            assert_eq!(on_disk.public.to_bytes(), k0.public.to_bytes());
        }
        // enroll with a recovery key, text mode — surfaces the honest
        // v1.0 scoping line.
        env.stdout.clear();
        env.stderr.clear();
        {
            let recovery = keypair::generate("lin-bob").unwrap();
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some("lin-bob".to_string()),
                        recovery_pubkey: Some(recovery.public_base64()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(
            stdout.contains("enrolled identity lineage"),
            "got: {stdout}"
        );
        assert!(stdout.contains("v1.0"), "got: {stdout}");
        // register-recovery-key text mode carries the scoping too.
        env.stdout.clear();
        env.stderr.clear();
        {
            let recovery = keypair::generate("lin-bob").unwrap();
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path),
                    action: IdentityAction::RegisterRecoveryKey {
                        agent_id: Some("lin-bob".to_string()),
                        recovery_pubkey: recovery.public_base64(),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str().to_string();
        assert!(stdout.contains("registered recovery key"), "got: {stdout}");
        assert!(stdout.contains("v1.0"), "got: {stdout}");
    }

    // ----- v1.0.0 G17 (#1831) M-of-N recovery ceremony (CLI) ----------

    /// Drive the full recovery ceremony through the CLI dispatch:
    /// enroll-lineage → recover-prepare → (guardians) sign-recovery →
    /// recover, then assert the chain verifies to the fresh head via the
    /// 2-of-3 guardian quorum. Exercises the actual `run()` handlers.
    #[test]
    fn recovery_ceremony_cli_end_to_end() {
        use crate::identity::lineage::{RECOVERY_GUARDIAN_PUBKEYS_ENV, RECOVERY_THRESHOLD_ENV};
        let _envg = keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, "rec-cli", "ai:test", &[]).unwrap();
        }
        // Generate + enroll K0 (with a cold recovery commitment).
        let cold = keypair::generate("cold").unwrap();
        let run_action = |env: &mut TestEnv, action: IdentityAction, json: bool| {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action,
                },
                json,
                &mut out,
            )
        };
        run_action(
            &mut env,
            IdentityAction::Generate {
                agent_id: Some("rec-cli".to_string()),
                force: false,
                no_overwrite: false,
            },
            false,
        )
        .unwrap();
        run_action(
            &mut env,
            IdentityAction::EnrollLineage {
                agent_id: Some("rec-cli".to_string()),
                recovery_pubkey: Some(cold.public_base64()),
            },
            false,
        )
        .unwrap();

        // Fresh primary + 3 guardians persisted on disk (sign-recovery
        // loads the guardian private key from the key dir).
        let k_new = keypair::generate("rec-cli-new").unwrap();
        keypair::save(&k_new, &dir_path).unwrap();
        for g in ["g0", "g1", "g2"] {
            let kp = keypair::generate(g).unwrap();
            keypair::save(&kp, &dir_path).unwrap();
        }
        let guardian_pub = |g: &str| keypair::load(g, &dir_path).unwrap().public_base64();
        // SAFETY: test-only env mutation serialised by the lock above.
        unsafe {
            std::env::set_var(
                RECOVERY_GUARDIAN_PUBKEYS_ENV,
                format!(
                    "{},{},{}",
                    guardian_pub("g0"),
                    guardian_pub("g1"),
                    guardian_pub("g2")
                ),
            );
            std::env::set_var(RECOVERY_THRESHOLD_ENV, "2");
        }

        // Phase 1 — recover-prepare (JSON).
        env.stdout.clear();
        env.stderr.clear();
        run_action(
            &mut env,
            IdentityAction::RecoverPrepare {
                agent_id: Some("rec-cli".to_string()),
                successor_pubkey: k_new.public_base64(),
                from_seq: None,
                recovery_pubkey: None,
            },
            true,
        )
        .unwrap();
        let prep: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(prep["recovery_prepared"], true);
        let challenge = prep["challenge_b64"].as_str().unwrap().to_string();
        let not_before = prep["not_before"].as_str().unwrap().to_string();

        // Phase 1.5 — two guardians sign.
        let mut attestations = Vec::new();
        for g in ["g0", "g1"] {
            env.stdout.clear();
            env.stderr.clear();
            run_action(
                &mut env,
                IdentityAction::SignRecovery {
                    agent_id: Some(g.to_string()),
                    challenge: challenge.clone(),
                },
                true,
            )
            .unwrap();
            let sig: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
            attestations.push(sig["attestation"].as_str().unwrap().to_string());
        }

        // Phase 2 — recover.
        env.stdout.clear();
        env.stderr.clear();
        run_action(
            &mut env,
            IdentityAction::Recover {
                agent_id: Some("rec-cli".to_string()),
                successor_pubkey: k_new.public_base64(),
                not_before,
                from_seq: None,
                recovery_pubkey: None,
                attestations,
            },
            true,
        )
        .unwrap();
        let rec: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(rec["recovered"], true);
        assert_eq!(rec["epoch"], 1);

        // The chain verifies to the fresh head via the guardian quorum.
        let conn = crate::db::open(&db_path).unwrap();
        let verified = crate::db::verify_agent_lineage(&conn, "rec-cli")
            .unwrap()
            .expect("chain verifies after recovery");
        assert_eq!(verified.head_key.to_bytes(), k_new.public.to_bytes());
        assert_eq!(verified.recovered_at_epoch, Some(1));

        // SAFETY: test-only env cleanup serialised by the lock above.
        unsafe {
            std::env::remove_var(RECOVERY_GUARDIAN_PUBKEYS_ENV);
            std::env::remove_var(RECOVERY_THRESHOLD_ENV);
        }
    }
}
