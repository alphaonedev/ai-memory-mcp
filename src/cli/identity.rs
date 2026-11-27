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
//! AgenticMem is the commercial home for those backends.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;

use crate::cli::CliOutput;
use crate::identity::{self, keypair};
use crate::validate;

/// JSON output field for the base64 public key (#1558 batch 6).
const PUBLIC_KEY_B64_FIELD: &str = "public_key_b64";

/// #10110 — canonical refusal message when `identity import` targets an agent
/// that already has a different key on disk. Names the signed succession path
/// (`ai-memory identity succeed`) so operators never destroy the trust
/// anchor's verification key for historical rows.
pub(crate) const IMPORT_REFUSED_DIFFERENT_KEY: &str = "refusing to overwrite existing keypair with a different key: import carries no succession \
     proof and would orphan historical attestations under the trust anchor; rotate via \
     `ai-memory identity succeed` instead";

/// Unforgeable proof (private fields, constructible ONLY by
/// [`decide_import_slot`]) that no different key exists for `kp.agent_id` in
/// `dir` and that writing `kp` to disk is permitted (#10110, CBC-03/05).
#[must_use]
struct FreshImportProof<'a> {
    dir: &'a Path,
    kp: &'a keypair::AgentKeypair,
}

/// Exhaustive decision for `identity import` before touching disk (#10110,
/// CBC-04). There is no boolean "exists" flag a caller can ignore: the write
/// helper [`persist_fresh_import`] accepts ONLY [`FreshImportProof`].
#[must_use]
enum ImportDecision<'a> {
    /// No key (or only a matching orphaned private half) exists — safe to write.
    Fresh(FreshImportProof<'a>),
    /// The existing public key on disk matches the imported public key — no-op.
    Identical,
    /// A different key already exists on disk — refuse and write nothing.
    RefusedDifferentKey { existing_path: PathBuf },
}

/// Classify `dir`'s key slot for `kp.agent_id` BEFORE any write (#10110).
/// Fails closed if existing key files are unreadable, corrupt, or under an
/// insecure directory chain.
fn decide_import_slot<'a>(
    dir: &'a Path,
    kp: &'a keypair::AgentKeypair,
) -> Result<ImportDecision<'a>> {
    let pub_path = keypair::agent_pub_path(dir, &kp.agent_id);
    match std::fs::symlink_metadata(&pub_path) {
        Ok(_) => {
            let existing = keypair::load_public(&kp.agent_id, dir)?;
            if existing.to_bytes() == kp.public.to_bytes() {
                Ok(ImportDecision::Identical)
            } else {
                Ok(ImportDecision::RefusedDifferentKey {
                    existing_path: pub_path,
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let priv_path = keypair::agent_priv_path(dir, &kp.agent_id);
            match std::fs::symlink_metadata(&priv_path) {
                Err(pe) if pe.kind() == std::io::ErrorKind::NotFound => {
                    Ok(ImportDecision::Fresh(FreshImportProof { dir, kp }))
                }
                Ok(_) => {
                    keypair::enforce_key_path_chain_secure(dir, &priv_path)?;
                    let priv_bytes = keypair::read_raw_key_file(&priv_path).with_context(|| {
                        format!("reading existing private key {}", priv_path.display())
                    })?;
                    let existing_pub = SigningKey::from_bytes(&priv_bytes).verifying_key();
                    if existing_pub.to_bytes() == kp.public.to_bytes() {
                        Ok(ImportDecision::Fresh(FreshImportProof { dir, kp }))
                    } else {
                        Ok(ImportDecision::RefusedDifferentKey {
                            existing_path: priv_path,
                        })
                    }
                }
                Err(pe) => Err(pe).with_context(|| {
                    format!("checking existing private key {}", priv_path.display())
                }),
            }
        }
        Err(e) => {
            Err(e).with_context(|| format!("checking existing public key {}", pub_path.display()))
        }
    }
}

/// The sole write funnel for `identity import`: accepts ONLY a
/// [`FreshImportProof`] minted by [`decide_import_slot`] (#10110).
fn persist_fresh_import(proof: FreshImportProof<'_>) -> Result<()> {
    if proof.kp.private.is_some() {
        keypair::save(proof.kp, proof.dir)
    } else {
        keypair::save_public_only(proof.kp, proof.dir)
    }
}

/// Exhaustively execute an [`ImportDecision`]: only `Fresh` writes to disk,
/// `Identical` is a no-op, and `RefusedDifferentKey` bails with
/// [`IMPORT_REFUSED_DIFFERENT_KEY`] (#10110).
fn apply_import_decision(decision: ImportDecision<'_>) -> Result<()> {
    match decision {
        ImportDecision::Fresh(proof) => persist_fresh_import(proof),
        ImportDecision::Identical => Ok(()),
        ImportDecision::RefusedDifferentKey { existing_path } => bail!(
            "{IMPORT_REFUSED_DIFFERENT_KEY} (existing key at {})",
            existing_path.display()
        ),
    }
}

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
    /// Refresh the public v97 hub allowlist (expires after 60 seconds).
    /// Omit previously listed principals to revoke them; all decisions are audited.
    HubCache(crate::cli::identity_hub_cache::HubCacheArgs),
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
    /// v1.0.0 #3468 — mint a SCOPED `a2a-hub/join/v1` delegation: a
    /// short-lived certificate, signed by this agent's ENROLLED key,
    /// authorising ONE freshly-generated key to present a hello at ONE
    /// named `ai-memory wake-hub` as this agent — and nothing else.
    ///
    /// The bundle it writes carries the DELEGATED private key, never the
    /// enrolled `.priv`, so a compromised wake-listener can be woken as
    /// this agent but can never write its history. The window is bounded
    /// alongside the refreshed public revocation cache.
    Delegate {
        /// Durable identity backend; standard store URL channels take precedence.
        #[arg(long, value_name = "URL")]
        store_url: Option<String>,
        /// Agent identifier. Defaults to the NHI-hardened id.
        #[arg(long)]
        agent_id: Option<String>,
        /// Delegation scope. Only `a2a-hub` is minted by this build; an
        /// unrecognised scope is refused rather than minted with a name
        /// nothing checks.
        #[arg(long, default_value = crate::identity::hub_delegation::A2A_HUB_SCOPE)]
        scope: String,
        /// The hub this delegation is valid at. A delegation is not
        /// portable across hubs.
        #[arg(long, default_value = crate::wake_hub::DEFAULT_HUB_ID)]
        hub_id: String,
        /// Lifetime in seconds. Bounded by the delegation maximum.
        #[arg(long, default_value_t = crate::cli::identity_delegate::DEFAULT_DELEGATION_TTL_SECS)]
        ttl_secs: i64,
        /// Where to write the bundle. Defaults to
        /// `<key-dir>/<agent-id>.a2a-hub.json`. Always written 0600.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
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
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
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
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
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
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
        successor_pubkey: String,
        /// Optional: also date a suspected key compromise from this
        /// `signed_events` witness SEQUENCE (a recovery doubling as a
        /// revocation — for the stolen-AND-lost-key case).
        #[arg(long, value_name = "SEQ")]
        from_seq: Option<u64>,
        /// Optional: (re-)register a cold recovery public key on the fresh
        /// head. Absent carries the head's existing commitment forward.
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
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
        // #3511: URL-safe base64 can begin with `-`, which clap would parse as
        // a flag. Plain `//` so the rationale stays out of the operator's help.
        #[arg(long, value_name = "CHALLENGE_B64", allow_hyphen_values = true)]
        challenge: String,
    },
    /// v1.0.0 G17 (#1831, #10112 Option B) — phase 2 of the M-of-N recovery
    /// ceremony: verify the M-of-N guardian quorum against the committed trust
    /// bar BEFORE any write, arm row attestation (#10040) with `K_new`'s
    /// private key from `--key-dir`, commit the lineage record, pubkey
    /// history, `_agents` update, and signed `row_attestations` row in one
    /// SQLite transaction, archive the lost `K_old` public key under the trust
    /// anchor as `<agent>.pub.<ts>`, install `K_new` as `<agent>.{pub,priv}`,
    /// and advance the anchored seal.
    ///
    /// Option B contract (#10112, vote V1-RECOVER-REBIND-ATTEST): recovery
    /// requires a signing arm holding `K_new.priv` inside `--key-dir` (either
    /// auto-matched by `--successor-pubkey` or named via `--successor-key-id`).
    /// A verify-only arm (`--verify-only`) or missing `K_new.priv` is refused
    /// preflight with zero database or anchor changes.
    Recover {
        /// Agent identifier whose identity is being recovered.
        #[arg(long)]
        agent_id: Option<String>,
        /// The SAME fresh-primary public key passed to `recover-prepare`
        /// (must equal both the guardian-signed key and the signing arm's `K_new`).
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
        successor_pubkey: String,
        /// Echo the `not_before` value `recover-prepare` printed (so the
        /// re-minted record is byte-identical to what the guardians signed).
        #[arg(long, value_name = "RFC3339")]
        not_before: String,
        /// The SAME `--from-seq` (if any) passed to `recover-prepare`.
        #[arg(long, value_name = "SEQ")]
        from_seq: Option<u64>,
        /// The SAME `--recovery-pubkey` (if any) passed to `recover-prepare`.
        #[arg(long, value_name = "PUBKEY_B64", allow_hyphen_values = true)]
        recovery_pubkey: Option<String>,
        /// Optional keypair label inside `--key-dir` holding `K_new.{pub,priv}`
        /// (when omitted, `--key-dir` is scanned for the keypair whose public
        /// key matches `--successor-pubkey`).
        #[arg(long, value_name = "LABEL")]
        successor_key_id: Option<String>,
        /// Explicit verify-only arm posture (always refused on recovery under
        /// Option B with zero database or anchor changes, #10112 R-8).
        #[arg(long, default_value_t = false)]
        verify_only: bool,
        /// A guardian attestation `guardian_pubkey_b64:signature_b64` (from
        /// `sign-recovery`). Repeat once per guardian; M distinct enrolled
        /// signers must be presented.
        // #3511: URL-safe base64 can begin with `-`, which clap would parse as
        // a flag. Plain `//` so the rationale stays out of the operator's help.
        #[arg(
            long = "attestation",
            value_name = "PUBKEY_B64:SIG_B64",
            allow_hyphen_values = true
        )]
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
        IdentityAction::HubCache(args) => crate::cli::identity_hub_cache::run(db_path, &args, out),
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
        IdentityAction::Delegate {
            store_url,
            agent_id,
            scope,
            hub_id,
            ttl_secs,
            out: bundle_path,
        } => {
            let id = resolve_id(agent_id.as_deref())?;
            crate::cli::identity_delegate::run(
                db_path,
                store_url.as_deref(),
                &dir,
                &id,
                &scope,
                &hub_id,
                ttl_secs,
                bundle_path.as_deref(),
                json_out,
                out,
            )
        }
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
            successor_key_id,
            verify_only,
            attestations,
        } => recover(
            db_path,
            &dir,
            &RecoverCmdArgs {
                explicit_agent_id: agent_id.as_deref(),
                successor_pubkey: &successor_pubkey,
                not_before: &not_before,
                from_seq,
                recovery_pubkey: recovery_pubkey.as_deref(),
                successor_key_id: successor_key_id.as_deref(),
                verify_only,
                attestations: &attestations,
            },
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
    let decision = decide_import_slot(dir, &kp)?;
    apply_import_decision(decision)?;

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
    let (outcome, record) = succeed_on_conn(&conn, dir, &id)?;
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

fn succeed_on_conn(
    conn: &rusqlite::Connection,
    dir: &Path,
    id: &str,
) -> Result<(
    keypair::RotateOutcome,
    crate::identity::lineage::LineageRecord,
)> {
    succeed_on_conn_with_hook(conn, dir, id, |_| Ok(()))
}

fn succeed_on_conn_with_hook(
    conn: &rusqlite::Connection,
    dir: &Path,
    id: &str,
    after_arm_hook: impl FnOnce(&rusqlite::Connection) -> Result<()>,
) -> Result<(
    keypair::RotateOutcome,
    crate::identity::lineage::LineageRecord,
)> {
    // #10118: fast-fail check BEFORE rotating on disk so a non-racing refusal
    // preserves the exact canonical order and message without touching disk.
    let preloaded = keypair::load(id, dir)?;
    let _prechecked = crate::db::succession_preconditions(conn, id, &preloaded)?;
    let recorded: std::cell::RefCell<Option<crate::identity::lineage::LineageRecord>> =
        std::cell::RefCell::new(None);
    let mut hook_slot = Some(after_arm_hook);
    // Sign-then-rotate seam: the succession is checked, armed, signed by K_old,
    // and durably persisted in ONE IMMEDIATE transaction BEFORE `save`
    // replaces K_old on disk (#10141).
    let outcome = keypair::rotate_with_succession(id, dir, |k_old, k_new| {
        // #10141: open the IMMEDIATE WriteTxn FIRST, then validate
        // preconditions, arm via `TxnArmed`, and append — ALL inside one
        // atomic unit. Any refusal, error, or panic drops `TxnArmed`, rolling
        // back cutovers + writes and disarming `conn`.
        let txn = crate::storage::connection::WriteTxn::begin(conn)
            .context("succession: begin write transaction (#10141)")?;
        let checked = crate::db::succession_preconditions_in_tx(&txn, id, k_old)?;
        let armed = crate::storage::row_attest::sqlite::TxnArmed::arm_for_succession(txn, &checked)
            .context("succession: row attestation could not be armed with K_old (#10089)")?;
        if let Some(hook) = hook_slot.take() {
            hook(armed.conn())?;
        }
        let record =
            crate::db::append_succession_in_tx(armed.txn(), checked, &k_new.public_base64(), None)?;
        armed
            .commit()
            .context("succession: commit transaction (#10141)")?;
        recorded.replace(Some(record));
        Ok(())
    })?;
    let record = recorded
        .into_inner()
        .context("succession closure did not run")?;
    Ok((outcome, record))
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
    // #10118 / #10141: validate and append inside ONE IMMEDIATE WriteTxn.
    let txn = crate::storage::connection::WriteTxn::begin(&conn)
        .context("register_recovery_key: begin write transaction (#10141)")?;
    let checked = crate::db::succession_preconditions_in_tx(&txn, &id, &kp)?;
    let record = crate::db::append_succession_in_tx(
        &txn,
        checked,
        &kp.public_base64(),
        Some(recovery_pubkey),
    )?;
    txn.commit()
        .context("register_recovery_key: commit transaction (#10141)")?;
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

/// Resolve `K_new`'s signing keypair strictly inside `dir` (#10112 Option B,
/// R-4, R-8, R-14). Never prints, logs, or copies private key material outside
/// `dir`. Returns `(loaded_keypair, staged_label_if_different_from_agent)`.
fn resolve_recovery_k_new_in_dir(
    dir: &Path,
    agent_id: &str,
    successor_pubkey: &str,
    explicit_label: Option<&str>,
) -> Result<(Option<keypair::AgentKeypair>, Option<String>)> {
    if let Some(label) = explicit_label {
        validate::validate_agent_id_shape(label)?;
        if !keypair::agent_pub_path(dir, label).exists() {
            // Defer missing-key refusal to `recovery_preconditions` so the
            // guardian M-of-N quorum is ALWAYS verified first (#10112 R-1).
            return Ok((None, None));
        }
        let kp = keypair::load(label, dir)?;
        let staged = (label != agent_id).then(|| label.to_string());
        return Ok((Some(kp), staged));
    }
    let target_pub =
        keypair::decode_public_base64(successor_pubkey).context("decoding --successor-pubkey")?;
    // First check `<agent_id>` itself (covers idempotent post-commit resume, R-6).
    if keypair::agent_pub_path(dir, agent_id).exists()
        && let Ok(kp) = keypair::load(agent_id, dir)
        && kp.public.to_bytes() == target_pub.to_bytes()
    {
        return Ok((Some(kp), None));
    }
    // Otherwise scan `dir` for a staged `<label>.pub` matching `target_pub`.
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok((None, None));
    };
    let mut labels: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') {
            continue;
        }
        if let Some(stem) = name_str.strip_suffix(keypair::PUB_SUFFIX)
            && !stem.is_empty()
            && !stem.contains('.')
        {
            labels.push(stem.to_string());
        }
    }
    labels.sort();
    for label in labels {
        let Ok(pk) = keypair::load_public(&label, dir) else {
            continue;
        };
        if pk.to_bytes() == target_pub.to_bytes() {
            let kp = keypair::load(&label, dir)?;
            let staged = (label != agent_id).then_some(label);
            return Ok((Some(kp), staged));
        }
    }
    Ok((None, None))
}

struct RecoverCmdArgs<'a> {
    explicit_agent_id: Option<&'a str>,
    successor_pubkey: &'a str,
    not_before: &'a str,
    from_seq: Option<u64>,
    recovery_pubkey: Option<&'a str>,
    successor_key_id: Option<&'a str>,
    verify_only: bool,
    attestations: &'a [String],
}

fn recover(
    db_path: &Path,
    dir: &Path,
    args: &RecoverCmdArgs<'_>,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let id = resolve_lineage_id(args.explicit_agent_id)?;
    if args.attestations.is_empty() {
        bail!("no --attestation presented — collect M guardian attestations via sign-recovery");
    }
    let mut quorum: Vec<crate::identity::lineage::RecoveryAttestation> =
        Vec::with_capacity(args.attestations.len());
    for att in args.attestations {
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

    // Resolve signing arm posture strictly inside `dir` (R-4, R-8, R-14).
    // `recovery_preconditions` ALWAYS verifies the guardian M-of-N quorum
    // FIRST (R-1) before inspecting `arm`, so a quorum shortfall is never
    // masked by a missing or mismatched `K_new`.
    let (loaded_k_new, staged_label) = if args.verify_only {
        (None, None)
    } else {
        resolve_recovery_k_new_in_dir(dir, &id, args.successor_pubkey, args.successor_key_id)?
    };
    let arm = if args.verify_only {
        crate::db::RecoveryArm::VerifyOnly
    } else if let Some(sk) = loaded_k_new.as_ref().and_then(|kp| kp.private.as_ref()) {
        crate::db::RecoveryArm::Signing(sk)
    } else {
        crate::db::RecoveryArm::MissingPrivateKey
    };

    let req = crate::db::RecoveryRequest {
        agent_id: &id,
        successor_pubkey_b64: args.successor_pubkey,
        quorum: &quorum,
        suspected_compromise_from_seq: args.from_seq,
        recovery_pubkey_b64: args.recovery_pubkey,
        not_before: args.not_before,
        staged_key_label: staged_label.as_deref(),
    };
    let checked = crate::db::recovery_preconditions(&conn, dir, &req, arm)?;
    let outcome = crate::db::execute_recovery_rebind(&conn, checked)?;
    let record = outcome.record;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "recovered": true,
                "agent_id": id,
                "epoch": record.epoch,
                (PUBLIC_KEY_B64_FIELD): record.successor_pubkey_b64,
                "archived_pub": outcome.archived_pub.display().to_string(),
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
            "  archived_prior_pub = {}",
            outcome.archived_pub.display()
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
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir = builder.tempdir().unwrap();
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
        let staging = tempfile::TempDir::new().unwrap();
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
        let staging = tempfile::TempDir::new().unwrap();
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
        let staging = tempfile::TempDir::new().unwrap();
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
        let staging = tempfile::TempDir::new().unwrap();
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
        let staging = tempfile::TempDir::new().unwrap();
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
                successor_key_id: None,
                verify_only: false,
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

    /// Snapshot every regular file (relative path -> raw bytes) under `dir`
    /// so refusal tests can prove the anchor directory is byte-identical (#10112 R-8).
    fn snapshot_dir_bytes(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(dir).expect("read dir for snapshot") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                out.insert(name, std::fs::read(&path).expect("read snapshot file"));
            }
        }
        out
    }

    /// #10112 (Option B, vote V1-RECOVER-REBIND-ATTEST) — red-first end-to-end
    /// pin beside `recovery_ceremony_cli_end_to_end`:
    /// 1. Refuses recovery when `K_new.priv` is missing (DB + anchor byte-identical).
    /// 2. With `K_new.priv` in the key dir (K_old.priv LOST), recovery attests
    ///    the `_agents` rebind row under `K_new`, archives `K_old` as
    ///    `<agent>.pub.<ts>`, installs `K_new` as `<agent>.pub`, and leaves
    ///    `verify_sqlite_with` `Outcome::Clean` (pre-recovery row under K_old
    ///    and rebind under K_new).
    /// 3. A later `identity succeed` passes without `REFUSE_ROW_DRIFT`.
    /// 4. Tampering the pre-recovery row is still detected as `Outcome::Defective`.
    #[test]
    fn recovery_rebind_arms_k_new_archives_k_old_and_verifies_history_10112() {
        use crate::identity::lineage::{RECOVERY_GUARDIAN_PUBKEYS_ENV, RECOVERY_THRESHOLD_ENV};
        use crate::storage::row_attest::Outcome;
        use crate::storage::row_attest::anchor::TrustAnchor;
        use crate::storage::row_attest::sqlite::{
            REFUSE_RECOVERY_MISSING_PRIV, TxnArmed, verify_sqlite_with,
        };

        const ROLE_ENV: &str = "AI_MEMORY_TEST_RECOVER_10112_ROLE";
        const MARKER_ENV: &str = "AI_MEMORY_TEST_RECOVER_10112_MARKER";
        const GUARDIAN_DIR_ENV: &str = "AI_MEMORY_TEST_RECOVER_10112_GDIR";
        const TEST_PATH: &str = "cli::identity::tests::recovery_rebind_arms_k_new_archives_k_old_and_verifies_history_10112";

        if std::env::var_os(ROLE_ENV).is_none() {
            let scratch = crate::identity::test_key_dir::private_tempdir();
            let home_dir = scratch.path().join("home");
            let xdg_dir = scratch.path().join("xdg-config");
            let witness_dir = scratch.path().join("witness");
            let guardian_dir = scratch.path().join("guardians");
            for sub in [&home_dir, &xdg_dir, &witness_dir, &guardian_dir] {
                std::fs::create_dir_all(sub).expect("create hermetic subdir");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(sub, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod 0700 subdir");
                }
            }
            let mut gpubs = Vec::new();
            for g in ["g10112-0", "g10112-1", "g10112-2"] {
                let kp = keypair::generate(g).unwrap();
                keypair::save(&kp, &guardian_dir).unwrap();
                gpubs.push(kp.public_base64());
            }
            let marker = scratch.path().join("child-ran");
            let output = std::process::Command::new(std::env::current_exe().expect("test exe"))
                .arg("--exact")
                .arg(TEST_PATH)
                .arg("--nocapture")
                .env("HOME", &home_dir)
                .env("XDG_CONFIG_HOME", &xdg_dir)
                .env("AI_MEMORY_WITNESS_KEY_DIR", &witness_dir)
                .env("AI_MEMORY_NO_CONFIG", "1")
                .env(RECOVERY_GUARDIAN_PUBKEYS_ENV, gpubs.join(","))
                .env(RECOVERY_THRESHOLD_ENV, "2")
                .env(GUARDIAN_DIR_ENV, &guardian_dir)
                .env(ROLE_ENV, "child")
                .env(MARKER_ENV, &marker)
                .output()
                .expect("spawn hermetic recovery child");
            assert!(
                output.status.success(),
                "hermetic recovery child failed ({}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(marker.exists(), "hermetic recovery child must run");
            return;
        }

        let mut env = TestEnv::fresh();
        let dir_path = crate::identity::test_key_dir::install().to_path_buf();
        let guardian_dir = PathBuf::from(std::env::var_os(GUARDIAN_DIR_ENV).unwrap());
        let db_path = env.db_path.clone();
        let agent = "rec-armed-10112";

        let run_action = |env: &mut TestEnv, key_dir: &Path, action: IdentityAction, json: bool| {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(key_dir.to_path_buf()),
                    action,
                },
                json,
                &mut out,
            )
        };

        // Seed agent + K_old + lineage + armed row attestation + pre-recovery row.
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent, "ai:test", &[]).unwrap();
        }
        run_action(
            &mut env,
            &dir_path,
            IdentityAction::Generate {
                agent_id: Some(agent.to_string()),
                force: false,
                no_overwrite: false,
            },
            false,
        )
        .unwrap();
        let k_old = keypair::load(agent, &dir_path).unwrap();
        let cold = keypair::generate("cold-10112").unwrap();
        run_action(
            &mut env,
            &dir_path,
            IdentityAction::EnrollLineage {
                agent_id: Some(agent.to_string()),
                recovery_pubkey: Some(cold.public_base64()),
            },
            false,
        )
        .unwrap();

        // Arm the store with K_old and write an attested pre-recovery memory row.
        let pre_mem_id = {
            let conn = crate::db::open(&db_path).unwrap();
            let txn = crate::storage::connection::WriteTxn::begin(&conn).unwrap();
            let armed = TxnArmed::arm_in_tx(txn, agent, k_old.private.as_ref().unwrap()).unwrap();
            let mut mem = crate::models::Memory::default();
            mem.namespace = "recovery-10112".to_string();
            mem.title = "pre-recovery-row".to_string();
            mem.content = "signed under K_old before loss".to_string();
            crate::db::insert(armed.conn(), &mem).unwrap();
            armed.commit().unwrap();
            let anchor = TrustAnchor::load_dir(&dir_path);
            let pre_report = verify_sqlite_with(&conn, &anchor).unwrap();
            assert!(
                matches!(pre_report.outcome(), Outcome::Clean),
                "pre-recovery store must be Clean: {:?}",
                pre_report.outcome()
            );
            mem.id
        };

        // Simulate key LOSS of K_old: remove `<agent>.priv`, keeping `<agent>.pub`.
        std::fs::remove_file(dir_path.join(format!("{agent}.priv"))).unwrap();

        // Prepare K_new (initially NOT saved in key dir so K_new.priv is missing).
        let k_new = keypair::generate("rec-armed-10112-new").unwrap();
        env.stdout.clear();
        run_action(
            &mut env,
            &dir_path,
            IdentityAction::RecoverPrepare {
                agent_id: Some(agent.to_string()),
                successor_pubkey: k_new.public_base64(),
                from_seq: None,
                recovery_pubkey: None,
            },
            true,
        )
        .unwrap();
        let prep: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let challenge = prep["challenge_b64"].as_str().unwrap().to_string();
        let not_before = prep["not_before"].as_str().unwrap().to_string();

        let mut attestations = Vec::new();
        for g in ["g10112-0", "g10112-1"] {
            env.stdout.clear();
            run_action(
                &mut env,
                &guardian_dir,
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

        // 1. Missing K_new.priv MUST be refused with exact constant and zero DB or anchor change (R-8).
        let db_bytes_before = std::fs::read(&db_path).unwrap();
        let dir_before = snapshot_dir_bytes(&dir_path);
        let missing_err = run_action(
            &mut env,
            &dir_path,
            IdentityAction::Recover {
                agent_id: Some(agent.to_string()),
                successor_pubkey: k_new.public_base64(),
                not_before: not_before.clone(),
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: None,
                verify_only: false,
                attestations: attestations.clone(),
            },
            true,
        )
        .expect_err("recovery without K_new.priv in key dir must be refused (#10112 R-8)");
        let missing_msg = format!("{missing_err:#}");
        assert!(
            missing_msg.contains(REFUSE_RECOVERY_MISSING_PRIV),
            "expected exact REFUSE_RECOVERY_MISSING_PRIV refusal, got: {missing_msg}"
        );
        assert_eq!(
            std::fs::read(&db_path).unwrap(),
            db_bytes_before,
            "refused recovery must leave DB byte-identical"
        );
        assert_eq!(
            snapshot_dir_bytes(&dir_path),
            dir_before,
            "refused recovery must leave anchor dir byte-identical"
        );

        // 2. Stage K_new.{pub,priv} inside key dir and complete recovery.
        keypair::save(&k_new, &dir_path).unwrap();
        env.stdout.clear();
        run_action(
            &mut env,
            &dir_path,
            IdentityAction::Recover {
                agent_id: Some(agent.to_string()),
                successor_pubkey: k_new.public_base64(),
                not_before,
                from_seq: None,
                recovery_pubkey: None,
                successor_key_id: None,
                verify_only: false,
                attestations,
            },
            true,
        )
        .unwrap();

        // K_old must be archived under anchor as `<agent>.pub.<ts>` and K_new
        // installed as `<agent>.pub`.
        let archived: Vec<_> = std::fs::read_dir(&dir_path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{agent}.pub."))
            })
            .collect();
        assert_eq!(
            archived.len(),
            1,
            "retired K_old must be archived as <agent>.pub.<ts> under anchor"
        );
        assert_eq!(
            std::fs::read(archived[0].path()).unwrap(),
            k_old.public.to_bytes().as_slice(),
            "archived retired key bytes must equal K_old"
        );
        assert_eq!(
            keypair::load_public(agent, &dir_path).unwrap().to_bytes(),
            k_new.public.to_bytes(),
            "current anchor key <agent>.pub must equal K_new"
        );

        // Pre-recovery row (K_old) AND rebind row (K_new) must verify Clean!
        {
            let conn = crate::db::open(&db_path).unwrap();
            let anchor = TrustAnchor::load_dir(&dir_path);
            let post_report = verify_sqlite_with(&conn, &anchor).unwrap();
            assert!(
                matches!(post_report.outcome(), Outcome::Clean),
                "post-recovery store must verify Clean: {:?}",
                post_report.outcome()
            );
        }

        // 3. A later `identity succeed` must pass without REFUSE_ROW_DRIFT (R-10).
        env.stdout.clear();
        run_action(
            &mut env,
            &dir_path,
            IdentityAction::Succeed {
                agent_id: Some(agent.to_string()),
            },
            true,
        )
        .expect("later identity succeed after recovery must pass without REFUSE_ROW_DRIFT");

        // 4. Direct-file tampering of the pre-recovery row is STILL detected as Defective.
        {
            let raw = rusqlite::Connection::open(&db_path).unwrap();
            raw.execute(
                "UPDATE memories SET content = 'tampered-after-recovery' WHERE id = ?1",
                [&pre_mem_id],
            )
            .unwrap();
            drop(raw);
            let conn = crate::db::open(&db_path).unwrap();
            let anchor = TrustAnchor::load_dir(&dir_path);
            let tampered = verify_sqlite_with(&conn, &anchor).unwrap();
            assert!(
                matches!(tampered.outcome(), Outcome::Defective { .. }),
                "tampered pre-recovery row must still be detected as Defective: {:?}",
                tampered.outcome()
            );
        }

        let marker = std::env::var_os(MARKER_ENV).expect("marker env");
        std::fs::write(marker, b"ran").expect("write marker");
    }

    const EXPECTED_NO_LINEAGE_SUFFIX_10118: &str = "run enroll-lineage first";
    const EXPECTED_PUBLIC_ONLY_SUFFIX_10118: &str = "is public-only — cannot sign a succession";
    const EXPECTED_NOT_HEAD_SUFFIX_10118: &str =
        "only the head key can hand the identity off (key-LOSS recovery lands in v1.0)";
    const ATTESTATION_FAILED_MARKER_10118: &str = "ATTESTATION_FAILED";

    fn lineage_row_count(db_path: &Path, agent_id: &str) -> i64 {
        let conn = crate::db::open(db_path).expect("open db for lineage count");
        conn.query_row(
            "SELECT COUNT(*) FROM agent_lineage WHERE agent_id = ?1",
            [agent_id],
            |r| r.get(0),
        )
        .expect("count agent_lineage rows")
    }

    fn signed_attestation_count(db_path: &Path) -> i64 {
        let conn = crate::db::open(db_path).expect("open db for attestation count");
        conn.query_row(
            "SELECT COUNT(*) FROM row_attestations WHERE signature IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .expect("count signed row_attestations")
    }

    fn seal_state_for(db_path: &Path) -> crate::storage::row_attest::seal::SealState {
        let anchor = crate::storage::row_attest::anchor::TrustAnchor::from_key_dir();
        crate::storage::row_attest::seal::path_for(&anchor, Some(db_path)).map_or(
            crate::storage::row_attest::seal::SealState::NotSealed,
            |p| crate::storage::row_attest::seal::read(&p),
        )
    }

    fn head_summary(db_path: &Path, agent_id: &str) -> Option<(u64, String)> {
        let conn = crate::db::open(db_path).expect("open db for lineage head");
        crate::db::lineage_head(&conn, agent_id)
            .expect("read lineage_head")
            .map(|(rec, _)| (rec.epoch, rec.successor_pubkey_b64))
    }

    /// #10118 — every succession precondition refusal (no lineage, public-only,
    /// not head) on `identity succeed` MUST return its own exact message before
    /// `arm_with_key`, leaving `agent_lineage` count, `lineage_head`, on-disk
    /// keypair, and signed `row_attestations` unchanged. A valid enrolled head
    /// still succeeds and arms row attestation (#10089).
    #[test]
    fn succeed_refusals_precede_attestation_arming_10118() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        let rec_b64 = keypair::generate("cold-suc-10118").unwrap().public_base64();

        // 1. No lineage enrolled.
        let agent_noln = "suc-noln-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_noln, "ai:test", &[]).unwrap();
        }
        let k0_noln = keypair::generate(agent_noln).unwrap();
        keypair::save(&k0_noln, &dir_path).unwrap();
        let signed_before = signed_attestation_count(&db_path);
        let seal_before = seal_state_for(&db_path);
        let err_noln = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some(agent_noln.to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_noln = format!("{err_noln:#}");
        assert!(
            msg_noln.contains(&format!(
                "no lineage enrolled for '{agent_noln}' — {EXPECTED_NO_LINEAGE_SUFFIX_10118}"
            )),
            "expected no-lineage refusal, got: {msg_noln}"
        );
        assert!(
            !msg_noln.contains(ATTESTATION_FAILED_MARKER_10118),
            "attestation must not mask no-lineage refusal: {msg_noln}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_noln), 0);
        assert_eq!(head_summary(&db_path, agent_noln), None);
        assert_eq!(signed_attestation_count(&db_path), signed_before);
        assert_eq!(seal_state_for(&db_path), seal_before);
        assert_eq!(
            keypair::load(agent_noln, &dir_path)
                .unwrap()
                .public
                .to_bytes(),
            k0_noln.public.to_bytes()
        );

        // 1b. PR #10130 r1 sec F1: registered agent whose pubkey IS bound to
        // the on-disk keypair, with NO lineage enrolled — so `arm_with_key`
        // would SUCCEED if invoked before `succession_preconditions`. Assert
        // the NO_LINEAGE refusal leaves signed attestations and the seal
        // untouched.
        let agent_noln_bound = "suc-noln-bound-10118";
        let k0_bound = keypair::generate(agent_noln_bound).unwrap();
        keypair::save(&k0_bound, &dir_path).unwrap();
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_noln_bound, "ai:test", &[]).unwrap();
            crate::db::bind_agent_pubkey_with_keypair(&conn, agent_noln_bound, &k0_bound).unwrap();
        }
        let signed_before_bound = signed_attestation_count(&db_path);
        let seal_before_bound = seal_state_for(&db_path);
        let err_noln_bound = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some(agent_noln_bound.to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_noln_bound = format!("{err_noln_bound:#}");
        assert!(
            msg_noln_bound.contains(&format!(
                "no lineage enrolled for '{agent_noln_bound}' — {EXPECTED_NO_LINEAGE_SUFFIX_10118}"
            )),
            "expected no-lineage refusal on bound-key fixture, got: {msg_noln_bound}"
        );
        assert!(
            !msg_noln_bound.contains(ATTESTATION_FAILED_MARKER_10118),
            "attestation must not mask no-lineage refusal on bound-key fixture: {msg_noln_bound}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_noln_bound), 0);
        assert_eq!(head_summary(&db_path, agent_noln_bound), None);
        assert_eq!(
            signed_attestation_count(&db_path),
            signed_before_bound,
            "refused succeed with bound key must not arm row attestation"
        );
        assert_eq!(
            seal_state_for(&db_path),
            seal_before_bound,
            "refused succeed with bound key must not advance the row-attestation seal"
        );
        assert_eq!(
            keypair::load(agent_noln_bound, &dir_path)
                .unwrap()
                .public
                .to_bytes(),
            k0_bound.public.to_bytes()
        );

        // 2. Public-only keypair on disk after enrolling lineage.
        let agent_pub = "suc-pub-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_pub, "ai:test", &[]).unwrap();
        }
        let k0_pub = keypair::generate(agent_pub).unwrap();
        keypair::save(&k0_pub, &dir_path).unwrap();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some(agent_pub.to_string()),
                        recovery_pubkey: Some(rec_b64.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        std::fs::remove_file(dir_path.join(format!("{agent_pub}.priv"))).unwrap();
        assert!(!keypair::load(agent_pub, &dir_path).unwrap().can_sign());
        let head_before_pub = head_summary(&db_path, agent_pub);
        let signed_before_pub = signed_attestation_count(&db_path);
        let err_pub = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some(agent_pub.to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_pub = format!("{err_pub:#}");
        assert!(
            msg_pub.contains(&format!(
                "keypair for '{agent_pub}' {EXPECTED_PUBLIC_ONLY_SUFFIX_10118}"
            )),
            "expected shared public-only refusal, got: {msg_pub}"
        );
        assert!(
            !msg_pub.contains(ATTESTATION_FAILED_MARKER_10118),
            "attestation must not mask public-only refusal: {msg_pub}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_pub), 1);
        assert_eq!(head_summary(&db_path, agent_pub), head_before_pub);
        assert_eq!(signed_attestation_count(&db_path), signed_before_pub);

        // 3. Keypair on disk is NOT the current lineage head.
        let agent_nothead = "suc-nothead-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_nothead, "ai:test", &[]).unwrap();
        }
        let k0_nh = keypair::generate(agent_nothead).unwrap();
        keypair::save(&k0_nh, &dir_path).unwrap();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some(agent_nothead.to_string()),
                        recovery_pubkey: Some(rec_b64.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let k_other = keypair::generate(agent_nothead).unwrap();
        keypair::save(&k_other, &dir_path).unwrap();
        let head_before_nh = head_summary(&db_path, agent_nothead);
        let signed_before_nh = signed_attestation_count(&db_path);
        let err_nh = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some(agent_nothead.to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_nh = format!("{err_nh:#}");
        assert!(
            msg_nh.contains(&format!(
                "signing keypair is not the current lineage head for '{agent_nothead}' — {EXPECTED_NOT_HEAD_SUFFIX_10118}"
            )),
            "expected not-head refusal, got: {msg_nh}"
        );
        assert!(
            !msg_nh.contains(ATTESTATION_FAILED_MARKER_10118),
            "attestation must not mask not-head refusal: {msg_nh}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_nothead), 1);
        assert_eq!(head_summary(&db_path, agent_nothead), head_before_nh);
        assert_eq!(signed_attestation_count(&db_path), signed_before_nh);
        assert_eq!(
            keypair::load(agent_nothead, &dir_path)
                .unwrap()
                .public
                .to_bytes(),
            k_other.public.to_bytes()
        );

        // 4. Enrolled head still succeeds and arms row attestation (#10089).
        let agent_ok = "suc-ok-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_ok, "ai:test", &[]).unwrap();
        }
        let k0_ok = keypair::generate(agent_ok).unwrap();
        keypair::save(&k0_ok, &dir_path).unwrap();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some(agent_ok.to_string()),
                        recovery_pubkey: Some(rec_b64.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Succeed {
                        agent_id: Some(agent_ok.to_string()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        assert_eq!(lineage_row_count(&db_path, agent_ok), 2);
        assert!(
            signed_attestation_count(&db_path) > 0,
            "valid succession must still arm row attestation (#10089)"
        );
    }

    /// #10118 — `identity register-recovery-key` MUST return the exact same
    /// three precondition refusals via the shared function, leaving lineage
    /// state and attestations untouched.
    #[test]
    fn register_recovery_key_refusals_match_shared_preconditions_10118() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        let rec_b64 = keypair::generate("cold-rec-10118").unwrap().public_base64();

        // 1. No lineage enrolled.
        let agent_noln = "rec-noln-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_noln, "ai:test", &[]).unwrap();
        }
        let k0 = keypair::generate(agent_noln).unwrap();
        keypair::save(&k0, &dir_path).unwrap();
        let signed_before = signed_attestation_count(&db_path);
        let err_noln = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::RegisterRecoveryKey {
                        agent_id: Some(agent_noln.to_string()),
                        recovery_pubkey: rec_b64.clone(),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_noln = format!("{err_noln:#}");
        assert!(
            msg_noln.contains(&format!(
                "no lineage enrolled for '{agent_noln}' — {EXPECTED_NO_LINEAGE_SUFFIX_10118}"
            )),
            "expected no-lineage refusal, got: {msg_noln}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_noln), 0);
        assert_eq!(head_summary(&db_path, agent_noln), None);
        assert_eq!(signed_attestation_count(&db_path), signed_before);

        // 2. Public-only keypair.
        let agent_pub = "rec-pub-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_pub, "ai:test", &[]).unwrap();
        }
        let k0_pub = keypair::generate(agent_pub).unwrap();
        keypair::save(&k0_pub, &dir_path).unwrap();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some(agent_pub.to_string()),
                        recovery_pubkey: Some(rec_b64.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        std::fs::remove_file(dir_path.join(format!("{agent_pub}.priv"))).unwrap();
        let head_before_pub = head_summary(&db_path, agent_pub);
        let err_pub = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::RegisterRecoveryKey {
                        agent_id: Some(agent_pub.to_string()),
                        recovery_pubkey: rec_b64.clone(),
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_pub = format!("{err_pub:#}");
        assert!(
            msg_pub.contains(&format!(
                "keypair for '{agent_pub}' {EXPECTED_PUBLIC_ONLY_SUFFIX_10118}"
            )),
            "expected public-only refusal, got: {msg_pub}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_pub), 1);
        assert_eq!(head_summary(&db_path, agent_pub), head_before_pub);
        assert_eq!(signed_attestation_count(&db_path), signed_before);

        // 3. Not current lineage head.
        let agent_nh = "rec-nothead-10118";
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, agent_nh, "ai:test", &[]).unwrap();
        }
        let k0_nh = keypair::generate(agent_nh).unwrap();
        keypair::save(&k0_nh, &dir_path).unwrap();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some(agent_nh.to_string()),
                        recovery_pubkey: Some(rec_b64.clone()),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let k_other = keypair::generate(agent_nh).unwrap();
        keypair::save(&k_other, &dir_path).unwrap();
        let head_before_nh = head_summary(&db_path, agent_nh);
        let err_nh = {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::RegisterRecoveryKey {
                        agent_id: Some(agent_nh.to_string()),
                        recovery_pubkey: rec_b64,
                    },
                },
                false,
                &mut out,
            )
            .unwrap_err()
        };
        let msg_nh = format!("{err_nh:#}");
        assert!(
            msg_nh.contains(&format!(
                "signing keypair is not the current lineage head for '{agent_nh}' — {EXPECTED_NOT_HEAD_SUFFIX_10118}"
            )),
            "expected not-head refusal, got: {msg_nh}"
        );
        assert_eq!(lineage_row_count(&db_path, agent_nh), 1);
        assert_eq!(head_summary(&db_path, agent_nh), head_before_nh);
        assert_eq!(signed_attestation_count(&db_path), signed_before);
    }

    /// #10118 — `fresh_env()` MUST produce a `0o700` key directory under
    /// `umask 0002` so `keypair::save` succeeds whatever the host umask.
    #[cfg(unix)]
    #[test]
    fn fresh_env_keypair_save_succeeds_under_umask_0002_10118() {
        use std::os::unix::fs::PermissionsExt as _;

        const ROLE_ENV: &str = "AI_MEMORY_TEST_IDENTITY_UMASK_10118_ROLE";
        const MARKER_ENV: &str = "AI_MEMORY_TEST_IDENTITY_UMASK_10118_MARKER";
        const TEST_PATH: &str =
            "cli::identity::tests::fresh_env_keypair_save_succeeds_under_umask_0002_10118";

        struct UmaskGuard(libc::mode_t);
        impl UmaskGuard {
            fn set(mask: libc::mode_t) -> Self {
                // SAFETY: `umask` has no preconditions and runs inside an
                // isolated single-test child process.
                let prev = unsafe { libc::umask(mask) };
                Self(prev)
            }
        }
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                // SAFETY: restores the prior process umask on normal return
                // and panic unwind.
                unsafe {
                    libc::umask(self.0);
                }
            }
        }

        let mode_of = |path: &Path| {
            std::fs::metadata(path)
                .expect("stat dir")
                .permissions()
                .mode()
                & 0o777
        };

        if std::env::var_os(ROLE_ENV).is_some() {
            let _umask = UmaskGuard::set(0o002);
            let control = tempfile::tempdir().expect("control tempdir");
            assert_eq!(
                mode_of(control.path()),
                0o775,
                "#10118 precondition: umask 0002 must yield 0775 for bare tempdir"
            );
            let (_env, dir) = fresh_env();
            assert_eq!(
                mode_of(dir.path()),
                0o700,
                "#10118: fresh_env() key dir must be mode 0700 under umask 0002"
            );
            let kp = keypair::generate("umask-0002-10118").expect("gen");
            keypair::save(&kp, dir.path())
                .expect("#10118: keypair::save must accept fresh_env() dir under umask 0002");
            let marker = std::env::var_os(MARKER_ENV).expect("marker env");
            std::fs::write(marker, b"ran").expect("write marker");
            return;
        }

        let scratch = crate::identity::test_key_dir::private_tempdir();
        let marker = scratch.path().join("child-ran");
        let status = std::process::Command::new(std::env::current_exe().expect("test exe"))
            .arg("--exact")
            .arg(TEST_PATH)
            .arg("--nocapture")
            .env(ROLE_ENV, "child")
            .env(MARKER_ENV, &marker)
            .status()
            .expect("spawn umask-0002 child");
        assert!(
            status.success(),
            "#10118: umask-0002 child run failed with {status}"
        );
        assert!(
            marker.exists(),
            "#10118: umask-0002 child must execute test body"
        );
    }

    /// Snapshot every regular file in `dir` as sorted `(name, bytes)` so tests
    /// can assert byte-for-byte identity of the entire trust anchor (#10110).
    fn snapshot_anchor_dir(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(dir).expect("read key dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let bytes = std::fs::read(&path).expect("read anchor file");
                out.insert(name, bytes);
            }
        }
        out
    }

    /// #10110 — importing a DIFFERENT key over a present key MUST be refused
    /// (naming `ai-memory identity succeed`), leave the key files, trust
    /// anchor, and database byte-identical (with unchanged row counts), and
    /// preserve verification of rows signed by the present key.
    #[test]
    fn import_refuses_different_key_and_preserves_anchor_and_signed_row_10110() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();

        // 1. Generate K0 for `alice`, register her, enroll lineage (binds K0),
        //    and write a row attested under K0.
        {
            let conn = crate::db::open(&db_path).unwrap();
            crate::db::register_agent(&conn, "alice", "ai:test", &[]).unwrap();
        }
        {
            let mut out = env.output();
            run(
                &db_path,
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
        let k0 = keypair::load("alice", &dir_path).unwrap();
        let recovery_b64 = keypair::generate("alice-recovery-10110")
            .unwrap()
            .public_base64();
        {
            let mut out = env.output();
            run(
                &db_path,
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::EnrollLineage {
                        agent_id: Some("alice".to_string()),
                        recovery_pubkey: Some(recovery_b64),
                    },
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        {
            let conn = crate::db::open(&db_path).unwrap();
            let txn = crate::storage::connection::WriteTxn::begin(&conn).unwrap();
            let armed = crate::storage::row_attest::sqlite::TxnArmed::arm_in_tx(
                txn,
                "alice",
                k0.private.as_ref().unwrap(),
            )
            .expect("arm connection with K0");
            crate::db::register_agent(armed.conn(), "alice-signed-row-10110", "ai:test", &[])
                .expect("write attested row under K0");
            armed.commit().expect("commit armed K0 write");
            let anchor = crate::storage::row_attest::anchor::TrustAnchor::load_dir(&dir_path);
            let report =
                crate::storage::row_attest::sqlite::verify_sqlite_with(&conn, &anchor).unwrap();
            assert_eq!(
                report.outcome(),
                crate::storage::row_attest::Outcome::Clean,
                "pre-import signed row must verify cleanly: {:?}",
                report.defects
            );
            assert!(
                report.tables["memories"].verified >= 2,
                "expected attested memories rows before import"
            );
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }

        // 2. Snapshot key files, full anchor directory, DB bytes, and row counts.
        let pub_path = dir_path.join("alice.pub");
        let priv_path = dir_path.join("alice.priv");
        let before_pub = std::fs::read(&pub_path).unwrap();
        let before_priv = std::fs::read(&priv_path).unwrap();
        let before_anchor = snapshot_anchor_dir(&dir_path);
        let before_db_bytes = std::fs::read(&db_path).unwrap();
        let (before_mem_rows, before_attest_rows): (i64, i64) = {
            let conn = crate::db::open(&db_path).unwrap();
            let m: i64 = conn
                .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
                .unwrap();
            let a: i64 = conn
                .query_row("SELECT COUNT(*) FROM row_attestations", [], |r| r.get(0))
                .unwrap();
            (m, a)
        };

        // 3. Stage a DIFFERENT keypair K1 and attempt both full and pub-only import.
        let k1 = keypair::generate("alice").unwrap();
        assert_ne!(k1.public.to_bytes(), k0.public.to_bytes());
        let staging = tempfile::TempDir::new().unwrap();
        let k1_pub = staging.path().join("k1.pub");
        let k1_priv = staging.path().join("k1.priv");
        std::fs::write(&k1_pub, k1.public.to_bytes()).unwrap();
        std::fs::write(&k1_priv, k1.private.as_ref().unwrap().to_bytes()).unwrap();

        for priv_arg in [Some(k1_priv.clone()), None] {
            let mode = if priv_arg.is_some() {
                "with-priv"
            } else {
                "pub-only"
            };
            let err = match {
                let mut out = env.output();
                run(
                    &db_path,
                    IdentityArgs {
                        key_dir: Some(dir_path.clone()),
                        action: IdentityAction::Import {
                            agent_id: "alice".to_string(),
                            public: k1_pub.clone(),
                            private: priv_arg,
                        },
                    },
                    false,
                    &mut out,
                )
            } {
                Err(e) => e,
                Ok(()) => panic!(
                    "#10110 ({mode}): importing a different key over a present key MUST be refused"
                ),
            };
            let msg = format!("{err:#}");
            assert!(
                msg.contains(IMPORT_REFUSED_DIFFERENT_KEY),
                "#10110 ({mode}): refusal must contain IMPORT_REFUSED_DIFFERENT_KEY; got: {msg}"
            );
        }

        // 4. Key files, full trust anchor, DB bytes, and row counts are byte-identical.
        assert_eq!(std::fs::read(&pub_path).unwrap(), before_pub);
        assert_eq!(std::fs::read(&priv_path).unwrap(), before_priv);
        assert_eq!(snapshot_anchor_dir(&dir_path), before_anchor);
        assert_eq!(std::fs::read(&db_path).unwrap(), before_db_bytes);
        {
            let conn = crate::db::open(&db_path).unwrap();
            let after_mem_rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
                .unwrap();
            let after_attest_rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM row_attestations", [], |r| r.get(0))
                .unwrap();
            assert_eq!(after_mem_rows, before_mem_rows);
            assert_eq!(after_attest_rows, before_attest_rows);

            // 5. The row signed by K0 still verifies cleanly against the anchor.
            let anchor = crate::storage::row_attest::anchor::TrustAnchor::load_dir(&dir_path);
            let report =
                crate::storage::row_attest::sqlite::verify_sqlite_with(&conn, &anchor).unwrap();
            assert_eq!(
                report.outcome(),
                crate::storage::row_attest::Outcome::Clean,
                "#10110: row signed by K0 must still verify after refused import: {:?}",
                report.defects
            );
        }
    }

    /// #10110 — importing into an empty home succeeds, and re-importing the
    /// IDENTICAL key (both full and pub-only) is a true no-op that does not
    /// rewrite existing key files on disk.
    #[test]
    fn import_identical_key_is_noop_and_fresh_empty_home_succeeds_10110() {
        let (mut env, dir) = fresh_env();
        let empty_home = dir.path().join("fresh-home");
        let k0 = keypair::generate("bob-10110").unwrap();
        let staging = tempfile::TempDir::new().unwrap();
        let k0_pub = staging.path().join("k0.pub");
        let k0_priv = staging.path().join("k0.priv");
        std::fs::write(&k0_pub, k0.public.to_bytes()).unwrap();
        std::fs::write(&k0_priv, k0.private.as_ref().unwrap().to_bytes()).unwrap();

        // 1. Fresh import into an empty home succeeds.
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(empty_home.clone()),
                    action: IdentityAction::Import {
                        agent_id: "bob-10110".to_string(),
                        public: k0_pub.clone(),
                        private: Some(k0_priv.clone()),
                    },
                },
                false,
                &mut out,
            )
            .expect("fresh import into empty home must succeed");
        }
        let loaded = keypair::load("bob-10110", &empty_home).unwrap();
        assert_eq!(loaded.public.to_bytes(), k0.public.to_bytes());
        assert!(loaded.can_sign());

        let pub_path = empty_home.join("bob-10110.pub");
        let priv_path = empty_home.join("bob-10110.priv");
        let before_anchor = snapshot_anchor_dir(&empty_home);
        #[cfg(unix)]
        let (before_pub_ino, before_priv_ino) = {
            use std::os::unix::fs::MetadataExt as _;
            (
                std::fs::metadata(&pub_path).unwrap().ino(),
                std::fs::metadata(&priv_path).unwrap().ino(),
            )
        };

        // 2. Identical re-import (both with --priv and pub-only) is a true no-op.
        for priv_arg in [Some(k0_priv.clone()), None] {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(empty_home.clone()),
                    action: IdentityAction::Import {
                        agent_id: "bob-10110".to_string(),
                        public: k0_pub.clone(),
                        private: priv_arg,
                    },
                },
                false,
                &mut out,
            )
            .expect("re-importing the identical key must succeed as a no-op");
            assert_eq!(snapshot_anchor_dir(&empty_home), before_anchor);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                assert_eq!(
                    std::fs::metadata(&pub_path).unwrap().ino(),
                    before_pub_ino,
                    "#10110: identical import must be a no-op and not rewrite .pub"
                );
                assert_eq!(
                    std::fs::metadata(&priv_path).unwrap().ino(),
                    before_priv_ino,
                    "#10110: identical import must be a no-op and not rewrite .priv"
                );
            }
        }
    }

    /// #10110 — fail closed when an existing `.pub` is corrupt/truncated or
    /// when an orphaned `.priv` belongs to a different key.
    #[test]
    fn import_refuses_corrupt_pub_and_different_orphan_priv_10110() {
        let (mut env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let k_new = keypair::generate("carol-10110").unwrap();
        let staging = tempfile::TempDir::new().unwrap();
        let k_pub = staging.path().join("c.pub");
        let k_priv = staging.path().join("c.priv");
        std::fs::write(&k_pub, k_new.public.to_bytes()).unwrap();
        std::fs::write(&k_priv, k_new.private.as_ref().unwrap().to_bytes()).unwrap();

        // 1. Corrupt existing `.pub` fails closed without overwriting.
        let bad_pub = dir_path.join("carol-10110.pub");
        std::fs::write(&bad_pub, b"truncated").unwrap();
        {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Import {
                        agent_id: "carol-10110".to_string(),
                        public: k_pub.clone(),
                        private: Some(k_priv.clone()),
                    },
                },
                false,
                &mut out,
            )
            .expect_err("#10110: corrupt existing .pub must fail closed");
        }
        assert_eq!(std::fs::read(&bad_pub).unwrap(), b"truncated");
        std::fs::remove_file(&bad_pub).unwrap();

        // 2. Orphan `.priv` of a different key fails closed with IMPORT_REFUSED_DIFFERENT_KEY.
        let k_other = keypair::generate("carol-10110").unwrap();
        let orphan_priv = dir_path.join("carol-10110.priv");
        let other_priv_bytes = k_other.private.as_ref().unwrap().to_bytes();
        std::fs::write(&orphan_priv, other_priv_bytes).unwrap();
        let err = {
            let mut out = env.output();
            run_nodb(
                IdentityArgs {
                    key_dir: Some(dir_path.clone()),
                    action: IdentityAction::Import {
                        agent_id: "carol-10110".to_string(),
                        public: k_pub,
                        private: Some(k_priv),
                    },
                },
                false,
                &mut out,
            )
        }
        .expect_err("#10110: different orphan .priv must be refused");
        assert!(
            format!("{err:#}").contains(IMPORT_REFUSED_DIFFERENT_KEY),
            "got: {err:#}"
        );
        assert_eq!(std::fs::read(&orphan_priv).unwrap(), other_priv_bytes);
        assert!(!bad_pub.exists());
    }

    fn count_ra10040_temp_triggers(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_temp_master \
             WHERE type = 'trigger' AND name LIKE 'ra10040_%'",
            [],
            |r| r.get(0),
        )
        .expect("count ra10040 temp triggers")
    }

    fn attest_fn_is_registered(conn: &rusqlite::Connection) -> bool {
        let sql = format!("SELECT {}()", crate::storage::row_attest::sqlite::ATTEST_FN);
        match conn.query_row(&sql, [], |_| Ok(())) {
            Ok(()) => true,
            Err(err) => !err.to_string().contains("no such function"),
        }
    }

    /// #10141 — source ratchet: production code outside
    /// `src/storage/row_attest/sqlite.rs` MUST NOT invoke unwrapped arming
    /// functions (`arm_with_key`, `arm_for_recovery_in_tx`, `row_attest::sqlite::arm`,
    /// `row_attest::sqlite::register`, or `create_scalar_function(ATTEST_FN`).
    /// Every production key-transition arming call must go through `TxnArmed`.
    #[test]
    fn source_ratchet_no_unwrapped_arming_calls_10141() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let src_root = manifest_dir.join("src");
        let allow_file = src_root.join("storage/row_attest/sqlite.rs");

        let forbidden = [
            "arm_with_key(",
            "arm_for_recovery_in_tx(",
            "row_attest::sqlite::arm(",
            "row_attest::sqlite::register(",
            "create_scalar_function(ATTEST_FN",
        ];

        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read_dir src") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let mut files = Vec::new();
        walk(&src_root, &mut files);
        files.sort();

        let mut violations = Vec::new();
        for path in files {
            if path == allow_file {
                continue;
            }
            let content = std::fs::read_to_string(&path).expect("read src file");
            let lines: Vec<&str> = content.lines().collect();
            let mut in_cfg_test_mod = false;
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed == "#[cfg(test)]"
                    && lines
                        .get(idx + 1)
                        .is_some_and(|next| next.trim().starts_with("mod "))
                {
                    in_cfg_test_mod = true;
                }
                if in_cfg_test_mod {
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                for pat in forbidden {
                    if trimmed.contains(pat) {
                        violations.push(format!(
                            "{}:{}: forbidden unwrapped arming call `{pat}`: {trimmed}",
                            path.strip_prefix(manifest_dir).unwrap_or(&path).display(),
                            idx + 1,
                        ));
                    }
                }
            }
        }

        assert!(
            violations.is_empty(),
            "production code contains unwrapped row-attestation arming calls outside TxnArmed:\n{}",
            violations.join("\n")
        );
    }

    /// #10141 — deterministic two-connection race on the `identity succeed`
    /// check-arm-append path (no sleeps; `busy_handler` + `Barrier`): when
    /// conn A commits K0 -> K1_A while conn B races, conn B MUST receive the
    /// exact `SUCCESSION_ERR_NOT_HEAD` refusal, its connection MUST NOT be left
    /// armed afterwards (zero `ra10040_*` temp triggers and `ATTEST_FN` not
    /// registered), signed attestations and the anchor seal MUST be unchanged,
    /// and no extra lineage row may be written.
    #[test]
    fn succeed_two_conn_race_refuses_not_head_and_leaves_conn_unarmed_10141() {
        use std::sync::{Arc, Barrier};

        let (env, dir_a) = fresh_env();
        let dir_a_path = dir_a.path().to_path_buf();
        let db_path = env.db_path.clone();
        let agent = "succeed-race-10141";

        let _env_lock = crate::test_support::env_lock();
        let _key_dir_guard = crate::test_support::EnvGuard::capture("AI_MEMORY_KEY_DIR");
        _key_dir_guard.set(dir_a_path.to_str().unwrap());

        let k0 = keypair::generate(agent).unwrap();
        keypair::save(&k0, &dir_a_path).unwrap();
        let cold = keypair::generate("cold-10141").unwrap();
        let conn_a = crate::db::open(&db_path).unwrap();
        crate::db::register_agent(&conn_a, agent, "ai:test", &[]).unwrap();
        crate::db::enroll_lineage(&conn_a, agent, &k0, Some(&cold.public_base64())).unwrap();

        // Separate key dir for process B holding the same K0.
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir_b = builder.tempdir().unwrap();
        keypair::save(&k0, dir_b.path()).unwrap();

        let signed_before = signed_attestation_count(&db_path);
        let seal_before = seal_state_for(&db_path);
        assert_eq!(signed_before, 0);
        assert_eq!(
            seal_before,
            crate::storage::row_attest::seal::SealState::NotSealed
        );

        let k1_a = keypair::generate(agent).unwrap();
        let entered_busy = Arc::new(Barrier::new(2));
        let a_committed = Arc::new(Barrier::new(2));
        let conn_b = crate::db::open(&db_path).unwrap();

        conn_a.execute_batch("BEGIN IMMEDIATE").unwrap();

        let dir_b_path = dir_b.path().to_path_buf();
        let entered_busy_b = Arc::clone(&entered_busy);
        let a_committed_b = Arc::clone(&a_committed);

        let handle_b = std::thread::spawn(move || {
            thread_local! {
                static RACE_BARRIERS: std::cell::RefCell<
                    Option<(Arc<Barrier>, Arc<Barrier>)>,
                > = const { std::cell::RefCell::new(None) };
            }
            fn race_busy_handler(_retries: i32) -> bool {
                RACE_BARRIERS.with(|slot| {
                    if let Some((entered, committed)) = slot.borrow_mut().take() {
                        entered.wait();
                        committed.wait();
                    }
                });
                true
            }
            RACE_BARRIERS.with(|slot| {
                *slot.borrow_mut() = Some((entered_busy_b, a_committed_b));
            });
            conn_b.busy_handler(Some(race_busy_handler)).unwrap();

            // Run the real production `succeed_on_conn` path on `conn_b`.
            let res = succeed_on_conn(&conn_b, &dir_b_path, agent).map(|_| ());
            let triggers_after = count_ra10040_temp_triggers(&conn_b);
            let fn_after = attest_fn_is_registered(&conn_b);
            (res, triggers_after, fn_after)
        });

        entered_busy.wait();
        conn_a.execute_batch("ROLLBACK").unwrap();
        let rec_a =
            crate::db::append_succession(&conn_a, agent, &k0, &k1_a.public_base64(), None).unwrap();
        assert_eq!(rec_a.epoch, 1);
        a_committed.wait();

        let (res_b, triggers_after, fn_after) = handle_b.join().unwrap();
        let err_b = res_b.expect_err("conn_b must lose succession race");
        let msg = format!("{err_b:#}");
        assert!(
            msg.contains(crate::db::SUCCESSION_ERR_NOT_HEAD),
            "conn_b must receive exact SUCCESSION_ERR_NOT_HEAD, got: {msg}"
        );
        assert_eq!(
            triggers_after, 0,
            "conn_b must have zero ra10040 temp triggers after refused succession"
        );
        assert!(
            !fn_after,
            "conn_b must not retain ATTEST_FN registration after refused succession"
        );
        assert_eq!(
            signed_attestation_count(&db_path),
            signed_before,
            "signed attestation count must be unchanged after refused race"
        );
        assert_eq!(
            seal_state_for(&db_path),
            seal_before,
            "anchor seal must be unchanged after refused race"
        );
        assert_eq!(lineage_row_count(&db_path, agent), 2);
        assert_eq!(
            head_summary(&db_path, agent),
            Some((1, k1_a.public_base64()))
        );
        assert_eq!(
            keypair::load(agent, dir_b.path())
                .unwrap()
                .public
                .to_bytes(),
            k0.public.to_bytes(),
            "dir_b keypair must remain K0 on refusal"
        );
    }

    /// #10141 — every early-return, refusal, error, and panic path AFTER
    /// `TxnArmed` arms the connection MUST roll back all writes & cutovers,
    /// leave the anchor seal untouched, and disarm/reconcile `conn`:
    /// (a) unarmed store + injected error after arm -> 0 temp triggers,
    ///     `ATTEST_FN` absent, 0 signed cutovers, `NotSealed`;
    /// (b) already-armed store (no session signer) + injected error after arm
    ///     -> `Fixed(K_old)` disarmed and restored to `ArmState::Refusing`
    ///     (subsequent write refused with `REFUSE_NO_SIGNER`);
    /// (c) invalid successor/recovery key refusal after arm -> rolled back &
    ///     disarmed;
    /// (d) panic unwind (`catch_unwind`) after arm -> `TxnArmed::Drop` rolls
    ///     back & disarms cleanly without aborting;
    /// (e) `TxnArmed` guard contract (standing order): dropping without commit
    ///     rolls back & disarms; committing advances seal & strips `Fixed` so
    ///     a subsequent write without a session signer refuses with
    ///     `REFUSE_NO_SIGNER`.
    #[test]
    fn succeed_early_return_error_panic_and_guard_contract_10141() {
        let (env, dir) = fresh_env();
        let dir_path = dir.path().to_path_buf();
        let db_path = env.db_path.clone();
        let agent = "early-return-10141";

        let _env_lock = crate::test_support::env_lock();
        let _key_dir_guard = crate::test_support::EnvGuard::capture("AI_MEMORY_KEY_DIR");
        _key_dir_guard.set(dir_path.to_str().unwrap());

        let k0 = keypair::generate(agent).unwrap();
        keypair::save(&k0, &dir_path).unwrap();
        let cold = keypair::generate("cold-er-10141").unwrap();
        let conn = crate::db::open(&db_path).unwrap();
        crate::db::register_agent(&conn, agent, "ai:test", &[]).unwrap();
        crate::db::enroll_lineage(&conn, agent, &k0, Some(&cold.public_base64())).unwrap();

        // (a) Unarmed store: injected error after arming inside `succeed_on_conn_with_hook`.
        let err = succeed_on_conn_with_hook(&conn, &dir_path, agent, |tx_conn| {
            // Confirm conn IS armed while inside the open WriteTxn!
            assert!(
                count_ra10040_temp_triggers(tx_conn) > 0,
                "triggers must be active inside TxnArmed"
            );
            assert!(attest_fn_is_registered(tx_conn));
            anyhow::bail!("injected early error after arm (#10141)")
        })
        .expect_err("injected error must propagate");
        assert!(
            format!("{err:#}").contains("injected early error after arm"),
            "got: {err:#}"
        );
        assert_eq!(
            count_ra10040_temp_triggers(&conn),
            0,
            "(a) unarmed conn must have 0 temp triggers after error rollback"
        );
        assert!(
            !attest_fn_is_registered(&conn),
            "(a) unarmed conn must not retain ATTEST_FN after error rollback"
        );
        assert_eq!(signed_attestation_count(&db_path), 0);
        assert_eq!(
            seal_state_for(&db_path),
            crate::storage::row_attest::seal::SealState::NotSealed
        );
        assert_eq!(lineage_row_count(&db_path, agent), 1);
        assert_eq!(
            keypair::load(agent, &dir_path).unwrap().public.to_bytes(),
            k0.public.to_bytes()
        );

        // (c) Refusal inside `append_succession_in_tx` (bad successor / bad recovery key)
        // after `TxnArmed::arm_for_succession` armed `conn`.
        for (succ, rec, label) in [
            ("not-valid-base64!!!", None, "invalid successor"),
            (
                &k0.public_base64(),
                Some("not-valid-rec!!!"),
                "invalid recovery",
            ),
        ] {
            let txn = crate::storage::connection::WriteTxn::begin(&conn).unwrap();
            let checked = crate::db::succession_preconditions_in_tx(&txn, agent, &k0).unwrap();
            let armed =
                crate::storage::row_attest::sqlite::TxnArmed::arm_for_succession(txn, &checked)
                    .unwrap();
            let res = crate::db::append_succession_in_tx(armed.txn(), checked, succ, rec);
            assert!(res.is_err(), "(c) {label} must refuse");
            drop(armed);
            assert_eq!(
                count_ra10040_temp_triggers(&conn),
                0,
                "(c) {label} drop must remove all temp triggers"
            );
            assert!(
                !attest_fn_is_registered(&conn),
                "(c) {label} drop must unregister ATTEST_FN"
            );
            assert_eq!(signed_attestation_count(&db_path), 0);
            assert_eq!(
                seal_state_for(&db_path),
                crate::storage::row_attest::seal::SealState::NotSealed
            );
        }

        // (d) Panic unwind after arming inside `succeed_on_conn_with_hook`.
        let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = succeed_on_conn_with_hook(&conn, &dir_path, agent, |_tx_conn| {
                panic!("simulated panic after TxnArmed (#10141)");
            });
        }));
        assert!(panic_res.is_err(), "(d) panic must unwind");
        assert!(
            conn.is_autocommit(),
            "(d) panic unwind must roll back WriteTxn back to autocommit"
        );
        assert_eq!(
            count_ra10040_temp_triggers(&conn),
            0,
            "(d) panic unwind must remove temp triggers"
        );
        assert!(
            !attest_fn_is_registered(&conn),
            "(d) panic unwind must unregister ATTEST_FN"
        );
        assert_eq!(signed_attestation_count(&db_path), 0);
        assert_eq!(
            seal_state_for(&db_path),
            crate::storage::row_attest::seal::SealState::NotSealed
        );

        // (e) Guard contract: commit arms & advances seal AND strips Fixed(K_old),
        // leaving a no-session-signer connection in `Refusing` posture so a
        // subsequent raw write refuses with `REFUSE_NO_SIGNER` (NOT silently
        // signed by K_old).
        {
            let txn = crate::storage::connection::WriteTxn::begin(&conn).unwrap();
            let armed = crate::storage::row_attest::sqlite::TxnArmed::arm_in_tx(
                txn,
                agent,
                k0.private.as_ref().unwrap(),
            )
            .unwrap();
            armed.commit().unwrap();
        }
        let signed_armed = signed_attestation_count(&db_path);
        assert!(
            signed_armed > 0,
            "(e) committed TxnArmed must sign cutovers"
        );
        assert!(
            matches!(
                seal_state_for(&db_path),
                crate::storage::row_attest::seal::SealState::Sealed(_)
            ),
            "(e) committed TxnArmed must advance anchor seal"
        );
        let probe_mem = crate::models::Memory {
            namespace: "probe-10141".to_string(),
            title: "must-refuse-no-signer".to_string(),
            content: "post-commit Fixed binding must be stripped".to_string(),
            ..crate::models::Memory::default()
        };
        let post_commit_err = crate::db::insert(&conn, &probe_mem)
            .expect_err("(e) post-commit conn with no session signer must refuse writes");
        assert!(
            format!("{post_commit_err:#}")
                .contains(crate::storage::row_attest::sqlite::REFUSE_NO_SIGNER),
            "(e) expected REFUSE_NO_SIGNER (proving Fixed(K_old) was stripped), got: {post_commit_err:#}"
        );

        // (b) Already-armed store + injected error after arming: MUST restore
        // `Refusing` posture (proving `Fixed(K_old)` was disarmed on rollback!).
        let seal_armed = seal_state_for(&db_path);
        let err_armed = succeed_on_conn_with_hook(&conn, &dir_path, agent, |_tx_conn| {
            anyhow::bail!("injected error on already-armed store (#10141)")
        })
        .expect_err("(b) injected error must propagate");
        assert!(format!("{err_armed:#}").contains("injected error on already-armed store"));
        assert_eq!(signed_attestation_count(&db_path), signed_armed);
        assert_eq!(seal_state_for(&db_path), seal_armed);
        assert_eq!(lineage_row_count(&db_path, agent), 1);
        let post_rollback_err = crate::db::insert(&conn, &probe_mem)
            .expect_err("(b) post-rollback armed conn must refuse writes with REFUSE_NO_SIGNER");
        assert!(
            format!("{post_rollback_err:#}")
                .contains(crate::storage::row_attest::sqlite::REFUSE_NO_SIGNER),
            "(b) Fixed(K_old) leaked across rollback! got: {post_rollback_err:#}"
        );
    }

    /// #10156 — prove that in a lib-test process with `AI_MEMORY_WITNESS_KEY_DIR`
    /// unset and a throwaway `HOME`, `witness_key_dir()` resolves to an isolated
    /// sandbox OUTSIDE `HOME` (never `<HOME>/.config/ai-memory/witness-keys`)
    /// and distinct from `default_key_dir()`.
    #[test]
    fn witness_key_dir_is_isolated_from_home_in_tests_10156() {
        const ROLE_ENV: &str = "AI_MEMORY_TEST_WITNESS_ISO_10156_ROLE";
        const FORBIDDEN_HOME_ENV: &str = "AI_MEMORY_TEST_WITNESS_ISO_10156_HOME";
        const TEST_PATH: &str = "cli::identity::tests::witness_key_dir_is_isolated_from_home_in_tests_10156";

        if std::env::var_os(ROLE_ENV).is_none() {
            let scratch = crate::identity::test_key_dir::private_tempdir();
            let fake_home = scratch.path().join("fake-home");
            std::fs::create_dir_all(&fake_home).unwrap();
            let output = std::process::Command::new(std::env::current_exe().expect("test exe"))
                .args(["--exact", TEST_PATH, "--nocapture"])
                .env("HOME", &fake_home)
                .env("XDG_CONFIG_HOME", fake_home.join(".config"))
                .env_remove("AI_MEMORY_WITNESS_KEY_DIR")
                .env_remove("AI_MEMORY_KEY_DIR")
                .env(FORBIDDEN_HOME_ENV, &fake_home)
                .env(ROLE_ENV, "child")
                .output()
                .expect("spawn child");
            assert!(
                output.status.success(),
                "child failed ({}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let forbidden_home =
            PathBuf::from(std::env::var_os(FORBIDDEN_HOME_ENV).expect("forbidden home env"));
        let resolved = crate::governance::audit::witness_key_dir().expect("witness_key_dir");
        assert!(
            !resolved.starts_with(&forbidden_home),
            "#10156: witness_key_dir() resolved under HOME: {} (HOME={})",
            resolved.display(),
            forbidden_home.display()
        );
        let key_dir = keypair::default_key_dir().expect("default_key_dir");
        assert_ne!(
            resolved, key_dir,
            "#10156: witness custody sandbox must be distinct from daemon key dir"
        );
    }

    /// #10156 — source ratchet pinning BOTH halves of witness custody isolation:
    /// (1) `src/governance/audit.rs::witness_key_dir` routes armed test processes
    ///     through `test_key_dir::armed_witness_sandbox()` and checks
    ///     `assert_witness_isolated`;
    /// (2) the three lineage CLI tests (`lineage_verbs_end_to_end`,
    ///     `lineage_text_surfaces_and_refusals`, `recovery_ceremony_cli_end_to_end`)
    ///     execute inside `run_in_hermetic_child`;
    /// (3) no test under `src/` points `AI_MEMORY_WITNESS_KEY_DIR` at a `HOME`
    ///     or `.config/ai-memory/witness-keys` path.
    #[test]
    fn source_ratchet_witness_custody_and_cli_identity_hermetic_10156() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

        // (1) Crate-wide guard in `witness_key_dir()`.
        let audit_src =
            std::fs::read_to_string(manifest_dir.join("src/governance/audit.rs")).unwrap();
        let fn_start = audit_src
            .find("pub fn witness_key_dir()")
            .expect("witness_key_dir must exist");
        let fn_slice = &audit_src[fn_start..fn_start + 1600.min(audit_src.len() - fn_start)];
        assert!(
            fn_slice.contains("armed_witness_sandbox()"),
            "#10156 ratchet: witness_key_dir() must delegate armed test processes to armed_witness_sandbox()"
        );
        assert!(
            fn_slice.contains("assert_witness_isolated"),
            "#10156 ratchet: witness_key_dir() must enforce assert_witness_isolated"
        );

        // (2) The three cli::identity lineage tests run via `run_in_hermetic_child`.
        let identity_src =
            std::fs::read_to_string(manifest_dir.join("src/cli/identity.rs")).unwrap();
        for test_name in [
            "fn lineage_verbs_end_to_end()",
            "fn lineage_text_surfaces_and_refusals()",
            "fn recovery_ceremony_cli_end_to_end()",
        ] {
            let start = identity_src
                .find(test_name)
                .unwrap_or_else(|| panic!("missing {test_name}"));
            let window = &identity_src[start..start + 600.min(identity_src.len() - start)];
            assert!(
                window.contains("run_in_hermetic_child("),
                "#10156 ratchet: {test_name} must execute inside run_in_hermetic_child(...)"
            );
        }

        // (3) No test under `src/` points WITNESS_KEY_DIR_ENV at HOME/.config.
        fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    walk_rs(&p, out);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk_rs(&manifest_dir.join("src"), &mut files);
        files.sort();
        let mut violations = Vec::new();
        for path in files {
            let content = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if (trimmed.contains("AI_MEMORY_WITNESS_KEY_DIR")
                    || trimmed.contains("WITNESS_KEY_DIR_ENV"))
                    && (trimmed.contains(".config/ai-memory/witness-keys")
                        || trimmed.contains("dirs::home_dir")
                        || trimmed.contains("dirs::config_dir"))
                {
                    violations.push(format!(
                        "{}:{}: {trimmed}",
                        path.strip_prefix(manifest_dir).unwrap_or(&path).display(),
                        idx + 1
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "#10156 ratchet: tests must not point witness custody at HOME/config:\n{}",
            violations.join("\n")
        );
    }
}
