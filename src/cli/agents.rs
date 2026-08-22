// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_agents` and `cmd_pending` migrations. See `cli::store` for the
//! design pattern.

use crate::cli::CliOutput;
use crate::cli::helpers::id_short;
use crate::models::field_names;
use crate::{db, identity, validate};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::Path;

#[derive(Args)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub action: Option<AgentsAction>,
}

#[derive(Subcommand)]
pub enum AgentsAction {
    /// List registered agents (default)
    List,
    /// Register or refresh an agent
    Register {
        /// Agent identifier
        #[arg(long)]
        agent_id: String,
        /// Agent type. Curated values: human, system, ai:claude-opus-4.6,
        /// ai:claude-opus-4.7, ai:codex-5.4, ai:grok-4.2. Any `ai:<name>`
        /// form is also accepted (e.g. `ai:gpt-5`, `ai:gemini-2.5`) —
        /// red-team #235.
        #[arg(long)]
        agent_type: String,
        /// Comma-separated capability tags
        #[arg(long, default_value = "")]
        capabilities: String,
    },
    /// Bind (or rotate) the Ed25519 public key used to attest an
    /// agent's signed writes (#626 Layer-3). The agent MUST already be
    /// registered. Re-binding overwrites the previous key in place.
    BindKey {
        /// Agent identifier (must be registered)
        #[arg(long)]
        agent_id: String,
        /// Base64-encoded Ed25519 public key (URL-safe-no-pad or
        /// standard padding accepted)
        #[arg(long)]
        pubkey: String,
    },
    /// Revoke the Ed25519 public key bound to an agent (#626 Layer-3).
    /// The agent reverts to the permissive *claimed* posture until a
    /// fresh key is bound. Idempotent.
    RevokeKey {
        /// Agent identifier (must be registered)
        #[arg(long)]
        agent_id: String,
    },
    /// v1.0.0 #2044 (#2032-A / H1 IDOR + M1 admin spoof) — enroll a per-agent
    /// HTTP api-key so an `X-Agent-Id: <agent>` on the HTTP surface must prove
    /// possession of THIS token (the server stores only `sha256(token)`; the
    /// raw token is never persisted). The daemon boot-loads the enrolled set,
    /// so RESTART the `serve` daemon after enrolling for it to take effect.
    /// Re-binding the same token rotates the mapping in place.
    BindApiKey {
        /// Agent identifier the presenting caller is bound to.
        #[arg(long)]
        agent_id: String,
        /// The per-agent api-key token. Callers present it as the `X-API-Key`
        /// header; only its SHA-256 digest is stored.
        #[arg(long)]
        token: String,
    },
    /// v1.0.0 #2095 — revoke (invalidate) EVERY enrolled per-agent HTTP api-key
    /// bound to `agent_id`. The PK is the token digest, so a leaked key can only
    /// be invalidated by revoking the agent's binding(s). RESTART the `serve`
    /// daemon after revoking (the enrolled map is boot-loaded).
    RevokeApiKey {
        /// Agent identifier whose api-key binding(s) to remove.
        #[arg(long)]
        agent_id: String,
    },
    /// v1.0.0 crypto-core (#1942, spec §2.3) — pre-enroll a per-instance
    /// sub-key certificate from a JSON file. The cert is verified under the
    /// principal's bound root key (`bind-key` first) BEFORE it is stored, so
    /// only a root-signed cert can be enrolled. The file carries the frozen
    /// bound fields + the principal-root signature:
    /// `{principal, instance_key_id, model_version_ref, not_before,
    /// not_after, cert_signature}` (bytes base64-encoded).
    EnrollSubkeyCert {
        /// Path to the JSON cert-envelope file.
        #[arg(long)]
        file: std::path::PathBuf,
    },
    /// v1.0.0 crypto-core (#1942, spec §2.3) — list persisted sub-key
    /// certificates (optionally for one principal).
    SubkeyCerts {
        /// Filter the inventory to a single principal (agent id). Omit to
        /// list EVERY persisted sub-key certificate on this node.
        ///
        /// #3017 — this is `--principal`, NOT `--agent-id`, and it is
        /// deliberately NOT env-backed. The clap `--agent-id` at
        /// `daemon_runtime::Cli` is `global = true, env = "AI_MEMORY_AGENT_ID"`,
        /// and clap propagates a matched global DOWN into every subcommand's
        /// `ArgMatches`, OVERWRITING a same-named subcommand-local arg. The
        /// certified posture always exports `AI_MEMORY_AGENT_ID`, so the
        /// node-wide cert inventory was silently filtered to that one id and
        /// an operator auditing per-instance sub-keys was told
        /// `{"count":0}` while the table held rows — a security-inventory
        /// FALSE NEGATIVE. A distinct arg id cannot be shadowed.
        #[arg(long = "principal", value_name = "AGENT_ID")]
        principal: Option<String>,
    },
}

#[derive(Args)]
pub struct PendingArgs {
    #[command(subcommand)]
    pub action: PendingAction,
}

#[derive(Subcommand)]
pub enum PendingAction {
    /// List pending actions (optionally filter by status).
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Approve a pending action by id.
    Approve {
        id: String,
        /// R40 signed approval, `<pubkey_b64>:<signature_b64>` (repeatable).
        /// REQUIRED when the pending was routed from a governance escalation
        /// (`requires_signed_approval`): an m-of-n Ed25519 quorum over enrolled
        /// approver keys must be met before the CLI operator can approve it.
        /// Each `<signature_b64>` signs
        /// `approvals::signed::approval_signing_bytes(id, Approve)`.
        #[arg(long = "approval", value_name = "PUBKEY_B64:SIG_B64")]
        approvals: Vec<String>,
    },
    /// Reject a pending action by id.
    Reject { id: String },
}

/// `agents` handler.
pub fn run_agents(
    db_path: &Path,
    args: AgentsArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    match args.action.unwrap_or(AgentsAction::List) {
        AgentsAction::List => {
            let agents = db::list_agents(&conn)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"count": agents.len(), "agents": agents})
                )?;
            } else if agents.is_empty() {
                writeln!(out.stdout, "no registered agents")?;
            } else {
                for a in &agents {
                    let caps = if a.capabilities.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", a.capabilities.join(","))
                    };
                    writeln!(
                        out.stdout,
                        "{}  type={}  registered={}  last_seen={}{}",
                        a.agent_id, a.agent_type, a.registered_at, a.last_seen_at, caps
                    )?;
                }
                writeln!(out.stdout, "{} registered agents", agents.len())?;
            }
        }
        AgentsAction::Register {
            agent_id,
            agent_type,
            capabilities,
        } => {
            validate::validate_agent_id(&agent_id)?;
            validate::validate_agent_type(&agent_type)?;
            let caps: Vec<String> = capabilities
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            validate::validate_capabilities(&caps)?;
            let id = db::register_agent(&conn, &agent_id, &agent_type, &caps)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        (field_names::REGISTERED): true,
                        "id": id,
                        "agent_id": agent_id,
                        (field_names::AGENT_TYPE): agent_type,
                        (field_names::CAPABILITIES): caps,
                    })
                )?;
            } else {
                writeln!(
                    out.stdout,
                    "registered {agent_id} (type={agent_type}, capabilities={})",
                    if caps.is_empty() {
                        "-".to_string()
                    } else {
                        caps.join(",")
                    }
                )?;
            }
        }
        AgentsAction::BindKey { agent_id, pubkey } => {
            validate::validate_agent_id(&agent_id)?;
            validate::validate_agent_pubkey_b64(&pubkey)?;
            let trimmed = pubkey.trim();
            db::bind_agent_pubkey(&conn, &agent_id, trimmed)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "bound": true,
                        "agent_id": agent_id,
                        (field_names::AGENT_PUBKEY): trimmed,
                    })
                )?;
            } else {
                writeln!(out.stdout, "bound pubkey for {agent_id}")?;
            }
        }
        AgentsAction::RevokeKey { agent_id } => {
            validate::validate_agent_id(&agent_id)?;
            db::revoke_agent_pubkey(&conn, &agent_id)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "revoked": true,
                        "agent_id": agent_id,
                    })
                )?;
            } else {
                writeln!(out.stdout, "revoked pubkey for {agent_id}")?;
            }
        }
        AgentsAction::BindApiKey { agent_id, token } => {
            validate::validate_agent_id(&agent_id)?;
            let trimmed = token.trim();
            if trimmed.is_empty() {
                anyhow::bail!("api-key token must not be empty");
            }
            let token_sha256 = crate::handlers::identity_binding::api_key_sha256_hex(trimmed);
            db::bind_agent_api_key(&conn, &agent_id, &token_sha256)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "bound": true,
                        "agent_id": agent_id,
                        "token_sha256": token_sha256,
                    })
                )?;
            } else {
                writeln!(
                    out.stdout,
                    "bound api-key for {agent_id} (sha256={token_sha256}); \
                     restart `ai-memory serve` for it to take effect"
                )?;
            }
        }
        AgentsAction::RevokeApiKey { agent_id } => {
            validate::validate_agent_id(&agent_id)?;
            let removed = db::revoke_agent_api_key(&conn, &agent_id)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "revoked": true,
                        "agent_id": agent_id,
                        "bindings_removed": removed,
                    })
                )?;
            } else {
                writeln!(
                    out.stdout,
                    "revoked {removed} api-key binding(s) for {agent_id}; \
                     restart `ai-memory serve` for it to take effect"
                )?;
            }
        }
        AgentsAction::EnrollSubkeyCert { file } => {
            enroll_subkey_cert(&conn, &file, json_out, out)?;
        }
        AgentsAction::SubkeyCerts { principal } => {
            let rows = db::list_subkey_certs(&conn, principal.as_deref())?;
            if json_out {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD;
                let certs: Vec<_> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            (field_names::PRINCIPAL): r.principal,
                            (field_names::INSTANCE_KEY_ID): b64.encode(&r.instance_key_id),
                            (field_names::MODEL_VERSION_REF): b64.encode(&r.model_version_ref),
                            (field_names::NOT_BEFORE): r.not_before,
                            (field_names::NOT_AFTER): r.not_after,
                            "revoked": r.revoked,
                            (field_names::CREATED_AT): r.created_at,
                        })
                    })
                    .collect();
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"count": rows.len(), "subkey_certs": certs})
                )?;
            } else if rows.is_empty() {
                writeln!(out.stdout, "no sub-key certificates")?;
            } else {
                for r in &rows {
                    writeln!(
                        out.stdout,
                        "{}  principal={}  window=[{}..{}]  revoked={}",
                        id_short(&r.id),
                        r.principal,
                        r.not_before,
                        r.not_after,
                        r.revoked
                    )?;
                }
                writeln!(out.stdout, "{} sub-key certificate(s)", rows.len())?;
            }
        }
    }
    Ok(())
}

/// Pre-enroll a sub-key certificate: parse the JSON envelope, verify it under
/// the principal's bound root key, and TOFU-persist it (#1942, spec §2.3).
fn enroll_subkey_cert(
    conn: &rusqlite::Connection,
    file: &Path,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let raw = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("read cert file {}: {e}", file.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("parse cert JSON: {e}"))?;
    let get_str = |k: &str| -> Result<String> {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("cert file missing string field `{k}`"))
    };
    let get_b64 = |k: &str| -> Result<Vec<u8>> {
        b64.decode(get_str(k)?.trim())
            .map_err(|e| anyhow::anyhow!("cert field `{k}` not base64: {e}"))
    };
    let principal = get_str(field_names::PRINCIPAL)?;
    validate::validate_agent_id(&principal)?;
    let instance_key_id = get_b64(field_names::INSTANCE_KEY_ID)?;
    let model_version_ref = get_b64(field_names::MODEL_VERSION_REF)?;
    let not_before = get_str(field_names::NOT_BEFORE)?;
    let not_after = get_str(field_names::NOT_AFTER)?;
    let cert_signature = get_b64(field_names::CERT_SIGNATURE)?;

    let root_b64 = db::agent_pubkey(conn, &principal)?.ok_or_else(|| {
        anyhow::anyhow!(
            "principal '{principal}' has no bound root key — run `ai-memory agents bind-key` first"
        )
    })?;
    let root = identity::keypair::decode_public_base64(&root_b64)
        .map_err(|e| anyhow::anyhow!("bound root key for '{principal}' is malformed: {e}"))?;
    let rec = identity::attest_v2::verify_and_record_cert(
        &root,
        &principal,
        &instance_key_id,
        &model_version_ref,
        &not_before,
        &not_after,
        &cert_signature,
    )
    .map_err(|e| anyhow::anyhow!("cert verification failed: {e}"))?;
    db::insert_subkey_cert(conn, &rec)?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "enrolled": true,
                "id": rec.id,
                "principal": rec.principal,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "enrolled sub-key cert {} for {principal}",
            id_short(&rec.id)
        )?;
    }
    Ok(())
}

/// Parse repeatable `--approval <pubkey_b64>:<signature_b64>` CLI specs into
/// R40 [`SignedApproval`](crate::approvals::signed::SignedApproval)s. The `:`
/// separator is unambiguous — it never occurs in standard OR url-safe base64.
fn parse_cli_approvals(specs: &[String]) -> Result<Vec<crate::approvals::signed::SignedApproval>> {
    specs
        .iter()
        .map(|spec| {
            let (pubkey, signature) = spec.split_once(':').ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --approval {spec:?}: expected <pubkey_b64>:<signature_b64>"
                )
            })?;
            Ok(crate::approvals::signed::SignedApproval {
                signer_pubkey_b64: pubkey.to_string(),
                signature_b64: signature.to_string(),
            })
        })
        .collect()
}

/// `pending` handler.
pub fn run_pending(
    db_path: &Path,
    args: PendingArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    match args.action {
        PendingAction::List { status, limit } => {
            let items = db::list_pending_actions(&conn, status.as_deref(), limit)?;
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"count": items.len(), "pending": items})
                )?;
            } else if items.is_empty() {
                writeln!(out.stdout, "no pending actions")?;
            } else {
                for item in &items {
                    writeln!(
                        out.stdout,
                        "[{}] {} ns={} action={} by={} ({})",
                        id_short(&item.id),
                        item.status,
                        item.namespace,
                        item.action_type,
                        item.requested_by,
                        item.requested_at
                    )?;
                }
                writeln!(out.stdout, "{} pending action(s)", items.len())?;
            }
        }
        PendingAction::Approve { id, approvals } => {
            use db::ApproveOutcome;
            validate::validate_id(&id)?;
            let agent = identity::resolve_agent_id(cli_agent_id, None)?;

            // #2991/#2355 — the CLI approve funnel routes through the SAME R40
            // signed-approval chokepoint as MCP + the four HTTP funnels, strictly
            // ABOVE the `approve_with_approver_type` + `execute_pending_action`
            // finalizer below. This is load-bearing on the CLI specifically: the
            // one-shot CLI process INTENTIONALLY does not install the
            // `GOVERNANCE_PRE_WRITE` execute-time backstop (operator-as-actor —
            // see `daemon_runtime::run` sqlite bootstrap), so this funnel gate is
            // the ONLY thing between a single operator and an unsigned
            // approve+execute of an escalation-routed (`requires_signed_approval`)
            // pending — exactly the unilateral single-operator approval R40
            // exists to stop. A rusqlite conn is in hand, so BOTH requirement
            // terms are supplied: the stored escalation flag AND the live
            // rule-engine namespace re-derivation.
            let snapshot = db::get_pending_action(&conn, &id)?;
            let stored_payload = snapshot
                .as_ref()
                .map_or(serde_json::Value::Null, |pa| pa.payload.clone());
            let namespace_requires = snapshot.as_ref().is_some_and(|pa| {
                crate::approvals::signed::namespace_requires_signed_approval(
                    &conn,
                    &pa.requested_by,
                    &pa.namespace,
                )
            });
            let presented = parse_cli_approvals(&approvals)?;
            // Single-use execution exemption, armed only on a MET signed quorum
            // and held across `execute_pending_action` (a no-op net on the CLI's
            // hook-less process, but kept identical to the other funnels).
            let mut _exemption_guard = None;
            match crate::approvals::signed::evaluate_signed_approval_gate(
                &stored_payload,
                &id,
                crate::approvals::Decision::Approve,
                &presented,
                namespace_requires,
            ) {
                crate::approvals::signed::GateVerdict::NotRequired => {}
                crate::approvals::signed::GateVerdict::Approved(quorum) => {
                    crate::approvals::signed::record_quorum_event(
                        &id,
                        crate::approvals::Decision::Approve,
                        &quorum,
                    );
                    _exemption_guard =
                        crate::approvals::signed::exemption_guard_for_pending(&id, &stored_payload);
                    // Quorum met — fall through to the approver-type finalizer.
                }
                crate::approvals::signed::GateVerdict::Pending {
                    distinct,
                    threshold,
                } => {
                    // Signatures accepted so far, m-of-n quorum not yet met.
                    if json_out {
                        writeln!(
                            out.stdout,
                            "{}",
                            serde_json::json!({
                                "approved": false,
                                "status": "pending",
                                "id": id,
                                (crate::approvals::signed::SIGNED_VOTES_FIELD): distinct,
                                (crate::approvals::signed::SIGNED_QUORUM_FIELD): threshold,
                                "reason": crate::approvals::signed::SIGNED_QUORUM_NOT_YET_MET,
                            })
                        )?;
                    } else {
                        writeln!(
                            out.stdout,
                            "signed approval recorded: {id} ({distinct}/{threshold} signers, \
                             quorum not yet met)"
                        )?;
                    }
                    return Ok(());
                }
                crate::approvals::signed::GateVerdict::Refused(e) => {
                    // Fail closed: missing-when-required / forged / unenrolled.
                    // `bail!` gives a clean refusal + nonzero exit (anyhow main),
                    // and — unlike `process::exit` — is unit-testable.
                    return Err(anyhow::anyhow!(
                        crate::approvals::signed::signed_approval_rejected(&e)
                    ));
                }
            }

            // #1796 (5-agent vote 4d3ea1c5) — CLI is operator-as-actor (single
            // operator); keep the Human-arm gate on the AI_MEMORY_AGENT_ID opt-in.
            match db::approve_with_approver_type(
                &conn,
                &id,
                &agent,
                db::ApproveSurface::LocalOperator,
            )? {
                ApproveOutcome::Approved => {
                    let executed = db::execute_pending_action(&conn, &id)?;
                    if json_out {
                        writeln!(
                            out.stdout,
                            "{}",
                            serde_json::json!({
                                "approved": true,
                                "id": id,
                                (field_names::DECIDED_BY): agent,
                                "executed": true,
                                "memory_id": executed,
                            })
                        )?;
                    } else {
                        writeln!(out.stdout, "approved + executed: {id} (by {agent})")?;
                    }
                }
                ApproveOutcome::Pending { votes, quorum } => {
                    if json_out {
                        writeln!(
                            out.stdout,
                            "{}",
                            serde_json::json!({
                                "approved": false,
                                "status": "pending",
                                "id": id,
                                "votes": votes,
                                "quorum": quorum,
                                "reason": crate::errors::msg::CONSENSUS_NOT_REACHED,
                            })
                        )?;
                    } else {
                        writeln!(
                            out.stdout,
                            "approval recorded: {id} ({votes}/{quorum} consensus, not yet met)"
                        )?;
                    }
                }
                // #1620 — typed not-found (was a Rejected string).
                ApproveOutcome::NotFound => {
                    anyhow::bail!(crate::errors::msg::pending_action_not_found(&id));
                }
                ApproveOutcome::Rejected(reason) => {
                    writeln!(
                        out.stderr,
                        "{}",
                        crate::errors::msg::approve_rejected(&reason)
                    )?;
                    std::process::exit(1);
                }
            }
        }
        PendingAction::Reject { id } => {
            validate::validate_id(&id)?;
            let agent = identity::resolve_agent_id(cli_agent_id, None)?;
            let ok = db::decide_pending_action(&conn, &id, false, &agent)?;
            if !ok {
                writeln!(
                    out.stderr,
                    "pending action not found or already decided: {id}"
                )?;
                std::process::exit(1);
            }
            if json_out {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({"rejected": true, "id": id, (field_names::DECIDED_BY): agent})
                )?;
            } else {
                writeln!(out.stdout, "rejected: {id} (by {agent})")?;
            }
        }
    }
    Ok(())
}

/// #2095 — per-agent HTTP api-key ENROLLMENT against the CONFIGURED SAL store.
///
/// Extracted from the `Command::Agents` dispatch in `daemon_runtime.rs` so the
/// (validate → hash → store → output, incl. json + error branches) logic lives
/// in one small, fully-unit-testable place instead of dragging the
/// `daemon_runtime.rs` monolith's per-module coverage floor. The caller
/// (`daemon_runtime.rs`) resolves the backend via `build_store_handle` and hands
/// the `Arc<dyn MemoryStore>` here; both sqlite and postgres route identically.
///
/// # Errors
///
/// Surfaces `validate_agent_id`, empty-token, and SAL `bind_agent_api_key`
/// failures.
#[cfg(feature = "sal")]
pub async fn run_bind_api_key(
    store: &std::sync::Arc<dyn crate::store::MemoryStore>,
    agent_id: &str,
    token: &str,
    json_out: bool,
) -> Result<()> {
    validate::validate_agent_id(agent_id)?;
    let trimmed = token.trim();
    if trimmed.is_empty() {
        anyhow::bail!("api-key token must not be empty");
    }
    let token_sha256 = crate::handlers::identity_binding::api_key_sha256_hex(trimmed);
    let ctx = crate::store::CallerContext::for_admin(crate::identity::sentinels::DAEMON_PRINCIPAL);
    store
        .bind_agent_api_key(&ctx, agent_id, &token_sha256)
        .await?;
    if json_out {
        println!(
            "{}",
            serde_json::json!({
                "bound": true,
                "agent_id": agent_id,
                "token_sha256": token_sha256,
            })
        );
    } else {
        println!(
            "bound api-key for {agent_id} (sha256={token_sha256}); \
             restart `ai-memory serve` for it to take effect"
        );
    }
    Ok(())
}

/// #2095 — per-agent HTTP api-key REVOCATION against the CONFIGURED SAL store.
/// Companion of [`run_bind_api_key`]; invalidates a leaked key (the PK is the
/// token digest, so revocation is by agent binding).
///
/// # Errors
///
/// Surfaces `validate_agent_id` + SAL `revoke_agent_api_key` failures.
#[cfg(feature = "sal")]
pub async fn run_revoke_api_key(
    store: &std::sync::Arc<dyn crate::store::MemoryStore>,
    agent_id: &str,
    json_out: bool,
) -> Result<()> {
    validate::validate_agent_id(agent_id)?;
    let ctx = crate::store::CallerContext::for_admin(crate::identity::sentinels::DAEMON_PRINCIPAL);
    let removed = store.revoke_agent_api_key(&ctx, agent_id).await?;
    if json_out {
        println!(
            "{}",
            serde_json::json!({
                "revoked": true,
                "agent_id": agent_id,
                "bindings_removed": removed,
            })
        );
    } else {
        println!(
            "revoked {removed} api-key binding(s) for {agent_id}; \
             restart `ai-memory serve` for it to take effect"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn test_agents_list_empty() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::List),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("no registered agents"));
    }

    #[test]
    fn test_agents_list_empty_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::List),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_agents_register_happy_path() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-1".to_string(),
                agent_type: "human".to_string(),
                capabilities: "alpha,beta".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("registered agent-1"));
    }

    #[test]
    fn test_agents_register_then_list() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let reg = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-2".to_string(),
                agent_type: "system".to_string(),
                capabilities: String::new(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, reg, false, &mut out).unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let list = AgentsArgs {
            action: Some(AgentsAction::List),
        };
        {
            let mut out = env.output();
            run_agents(&db, list, false, &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("agent-2"));
        assert!(s.contains("type=system"));
    }

    #[test]
    fn test_agents_register_invalid_agent_id() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: String::new(), // empty -> validation error
                agent_type: "human".to_string(),
                capabilities: String::new(),
            }),
        };
        let mut out = env.output();
        let res = run_agents(&db, args, false, &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_agents_default_action_is_list() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs { action: None };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("no registered agents"));
    }

    #[test]
    fn test_pending_list_empty() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = PendingArgs {
            action: PendingAction::List {
                status: None,
                limit: 100,
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("no pending actions"));
    }

    #[test]
    fn test_pending_list_empty_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = PendingArgs {
            action: PendingAction::List {
                status: Some("pending".to_string()),
                limit: 100,
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
    }

    // ---------- E1 coverage uplift: register-json + pending-with-items
    // + approve happy + reject happy + consensus pending. The
    // `process::exit` branches (Approve::Rejected, Reject not-found) stay
    // uncovered intentionally — they call `std::process::exit(1)` which
    // would terminate the test process.

    #[test]
    fn test_agents_register_json_output() {
        // Covers the `if json_out` arm inside Register (lines 112-123)
        // which is not exercised by `test_agents_register_happy_path`.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-json".to_string(),
                agent_type: "human".to_string(),
                capabilities: "x,y,z".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["registered"].as_bool().unwrap(), true);
        assert_eq!(v["agent_id"].as_str().unwrap(), "agent-json");
        assert_eq!(v["agent_type"].as_str().unwrap(), "human");
        // Capabilities round-trip as a JSON array of length 3.
        assert_eq!(v["capabilities"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_agents_register_empty_caps_human_text_dash() {
        // Hits the `if caps.is_empty()` true branch in the text-output
        // path (line 128 → "-").
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-no-caps".to_string(),
                agent_type: "system".to_string(),
                capabilities: String::new(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        // The "-" sentinel appears when capabilities is empty.
        assert!(env.stdout_str().contains("capabilities=-"));
    }

    #[test]
    fn test_agents_list_with_registered_agent_text_includes_caps() {
        // Drives the for-loop body (lines 82-94) — including the
        // `caps.is_empty() == false` branch where capabilities are
        // printed `[a,b]`.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let reg = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-with-caps".to_string(),
                agent_type: "ai:claude-opus-4.7".to_string(),
                capabilities: "alpha,beta".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, reg, false, &mut out).unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let list = AgentsArgs {
            action: Some(AgentsAction::List),
        };
        {
            let mut out = env.output();
            run_agents(&db, list, false, &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("agent-with-caps"));
        assert!(s.contains("type=ai:claude-opus-4.7"));
        assert!(s.contains("[alpha,beta]"));
        assert!(s.contains("1 registered agents"));
    }

    #[test]
    fn test_agents_list_json_with_items() {
        // Drives the JSON branch of list when there *are* agents
        // (lines 73-78) with a non-empty agents array.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let reg = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: "agent-jsonlist".to_string(),
                agent_type: "human".to_string(),
                capabilities: String::new(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, reg, false, &mut out).unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let list = AgentsArgs {
            action: Some(AgentsAction::List),
        };
        {
            let mut out = env.output();
            run_agents(&db, list, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 1);
        assert_eq!(
            v["agents"][0]["agent_id"].as_str().unwrap(),
            "agent-jsonlist"
        );
    }

    // ---- Pending list-with-items + decision paths -----------------

    /// Seed one `pending_actions` row directly via SQL. The CLI's
    /// `Approve` arm reads & writes through `db::*` helpers which
    /// validate this shape.
    fn seed_pending_action(
        db_path: &std::path::Path,
        id: &str,
        ns: &str,
        action_type: &str,
        requested_by: &str,
    ) {
        use rusqlite::params;
        let conn = db::open(db_path).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO pending_actions \
             (id, action_type, namespace, payload, requested_by, requested_at, status) \
             VALUES (?1, ?2, ?3, '{}', ?4, ?5, 'pending')",
            params![id, action_type, ns, requested_by, now],
        )
        .expect("insert pending_actions");
    }

    #[test]
    fn test_pending_list_text_with_items() {
        // Hits the for-loop body (lines 161-171) + count footer (line 173).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_pending_action(&db, "pa-1", "ns-x", "store", "test-agent");
        seed_pending_action(&db, "pa-2", "ns-y", "delete", "test-agent");
        let args = PendingArgs {
            action: PendingAction::List {
                status: None,
                limit: 100,
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("pa-1") || s.contains("pa-2"));
        assert!(s.contains("pending action"));
    }

    #[test]
    fn test_pending_list_json_with_items() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_pending_action(&db, "pa-json-1", "ns-x", "store", "test-agent");
        let args = PendingArgs {
            action: PendingAction::List {
                status: None,
                limit: 100,
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 1);
        assert!(v["pending"].is_array());
    }

    /// Seed a `delete`-shaped pending action whose memory_id is a real,
    /// existing memory. `execute_pending_action`'s delete arm reads
    /// `pa.memory_id` (the dedicated column, not the payload) and calls
    /// `db::delete`. With a valid target row, execution succeeds and the
    /// CLI's Approved arm reaches the "approved + executed" branch.
    fn seed_delete_pending(db_path: &std::path::Path, pa_id: &str, ns: &str) -> String {
        use rusqlite::params;
        let target = seed_memory_local(db_path, ns, &format!("t-{pa_id}"), "c");
        let conn = db::open(db_path).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO pending_actions \
             (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
             VALUES (?1, 'delete', ?2, ?3, '{}', 'test-agent', ?4, 'pending')",
            params![pa_id, target, ns, now],
        )
        .expect("seed pending");
        target
    }

    /// Seed an escalation-routed (`requires_signed_approval`) STORE pending, as
    /// the L1-6 producer would, into the CLI's sqlite DB. Returns the pending id.
    fn seed_escalated_store_pending_cli(
        db_path: &std::path::Path,
        ns: &str,
        content: &str,
    ) -> String {
        let conn = db::open(db_path).expect("db::open");
        let mem = crate::models::Memory {
            namespace: ns.to_string(),
            title: "cli-esc".to_string(),
            content: content.to_string(),
            metadata: serde_json::json!({ "agent_id": "ai:worker" }),
            ..crate::models::Memory::default()
        };
        crate::approvals::signed::route_escalation_to_approval_gate(
            &conn,
            crate::models::GovernedAction::Store,
            ns,
            None,
            "ai:worker",
            &serde_json::to_value(&mem).expect("memory to value"),
            "cli-esc-rule",
            "escalated for signed approval (cli test)",
        )
        .expect("route escalation")
    }

    /// #2991/#2355 — the CLI approve funnel enforces the R40 gate: an
    /// escalation-routed pending is REFUSED without a signed quorum (fail-closed
    /// nonzero exit) and NOT executed. Env-independent: with no key enrolled the
    /// verdict is `NoEnrolledApprovers`, with a concurrent test's key it is
    /// `NoSignatures` — either way `Refused`.
    #[test]
    fn cli_approve_refuses_escalated_pending_without_signatures() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pid = seed_escalated_store_pending_cli(&db, "cli-esc-ns", "cli-body");
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: pid.clone(),
                approvals: Vec::new(),
            },
        };
        let res = {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out)
        };
        assert!(
            res.is_err(),
            "an escalated pending must be REFUSED on the CLI without a signed quorum"
        );
        assert!(
            res.unwrap_err().to_string().contains("signed approval"),
            "the CLI refusal must name the signed-approval gate"
        );
        // The row must NOT have transitioned or executed.
        let conn = db::open(&db).expect("reopen");
        let row = db::get_pending_action(&conn, &pid)
            .expect("get_pending_action")
            .expect("row exists");
        assert_eq!(
            row.status, "pending",
            "a refused approve must not transition the row"
        );
    }

    /// #2991/#2355 — the CLI approve funnel ADMITS an escalation-routed pending
    /// once an m-of-n signed quorum is presented (approve + execute). Env-
    /// isolated: enrolls an approver key.
    #[test]
    fn cli_approve_admits_escalated_pending_with_met_quorum() {
        if crate::config::run_env_isolated_child_or_spawn(
            "cli::agents::tests::cli_approve_admits_escalated_pending_with_met_quorum",
        ) {
            return;
        }
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        unsafe {
            std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
            std::env::set_var(crate::approvals::signed::APPROVER_PUBKEYS_ENV, &pk_b64);
        }
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pid = seed_escalated_store_pending_cli(&db, "cli-esc-ns2", "cli-body-2");
        let msg = crate::approvals::signed::approval_signing_bytes(
            &pid,
            crate::approvals::Decision::Approve,
        );
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sk.sign(&msg).to_bytes());
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: pid.clone(),
                approvals: vec![format!("{pk_b64}:{sig_b64}")],
            },
        };
        let res = {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out)
        };
        assert!(
            res.is_ok(),
            "a met signed quorum must approve on the CLI: {res:?}"
        );
        assert!(
            env.stdout_str().contains("approved + executed"),
            "stdout must confirm approve+execute: {}",
            env.stdout_str()
        );
        let conn = db::open(&db).expect("reopen");
        let row = db::get_pending_action(&conn, &pid)
            .expect("get_pending_action")
            .expect("row exists");
        assert_eq!(
            row.status, "approved",
            "the row must transition to approved"
        );
        unsafe {
            std::env::remove_var(crate::approvals::signed::APPROVER_PUBKEYS_ENV);
        }
    }

    #[test]
    fn test_pending_approve_happy_text() {
        // Default namespace policy (no governance row) → approver = Human →
        // `approve_with_approver_type` writes `Approved` and the CLI's
        // Approved arm calls `execute_pending_action`. With action_type=delete
        // and a valid memory_id, the delete arm succeeds and we hit the
        // "approved + executed" line.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_delete_pending(&db, "pa-approve-1", "ns-app");
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: "pa-approve-1".to_string(),
                approvals: Vec::new(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        let s = env.stdout_str();
        assert!(
            s.contains("approved + executed: pa-approve-1"),
            "expected approved+executed line, got: {s}"
        );
    }

    #[test]
    fn test_pending_approve_happy_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_delete_pending(&db, "pa-approve-json", "ns-app2");
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: "pa-approve-json".to_string(),
                approvals: Vec::new(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["approved"].as_bool().unwrap(), true);
        assert_eq!(v["id"].as_str().unwrap(), "pa-approve-json");
        assert_eq!(v["decided_by"].as_str().unwrap(), "test-agent");
    }

    #[test]
    fn test_pending_reject_happy_text() {
        // Happy `Reject` text path (lines 226-245).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_pending_action(&db, "pa-reject-1", "ns-r", "store", "test-agent");
        let args = PendingArgs {
            action: PendingAction::Reject {
                id: "pa-reject-1".to_string(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, false, Some("test-agent"), &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("rejected: pa-reject-1"));
    }

    #[test]
    fn test_pending_reject_happy_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_pending_action(&db, "pa-reject-j", "ns-r", "store", "test-agent");
        let args = PendingArgs {
            action: PendingAction::Reject {
                id: "pa-reject-j".to_string(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, true, Some("test-agent"), &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["rejected"].as_bool().unwrap(), true);
        assert_eq!(v["id"].as_str().unwrap(), "pa-reject-j");
        assert_eq!(v["decided_by"].as_str().unwrap(), "test-agent");
    }

    /// Install a Consensus(2) governance policy on `namespace`. The
    /// policy lives inside a "standard" memory's metadata; we seed the
    /// memory then point `namespace_meta` at it.
    fn install_consensus_policy(db_path: &std::path::Path, namespace: &str, quorum: u32) {
        let conn = db::open(db_path).expect("db::open");
        let policy = serde_json::json!({
            "write": "approve",
            "promote": "any",
            "delete": "owner",
            "approver": {"consensus": quorum},
            "inherit": true,
        });
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = crate::models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String("test-agent".to_string()),
            );
            obj.insert("governance".to_string(), policy);
        }
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
            namespace: namespace.to_string(),
            title: format!("standard:{namespace}"),
            content: "policy standard".to_string(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let id = db::insert(&conn, &mem).expect("db::insert standard");
        db::set_namespace_standard(&conn, namespace, &id, None).expect("set_namespace_standard");
    }

    #[test]
    fn test_pending_approve_consensus_pending_branch() {
        // Drives the `ApproveOutcome::Pending { votes, quorum }` arm
        // (lines 199-219). Path:
        //   1. Register two agents so they qualify as consensus voters.
        //   2. Set a namespace standard whose policy demands Consensus(2).
        //   3. Seed a pending action under that namespace.
        //   4. Have agent A approve — quorum not met → Pending response.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();

        // Step 1: register voters.
        for who in ["voter-a", "voter-b"] {
            let reg = AgentsArgs {
                action: Some(AgentsAction::Register {
                    agent_id: who.to_string(),
                    agent_type: "human".to_string(),
                    capabilities: String::new(),
                }),
            };
            let mut out = env.output();
            run_agents(&db, reg, false, &mut out).expect("register voter");
        }
        env.stdout.clear();

        // Step 2: install a Consensus(2) policy via the standard
        // memory + namespace_meta path.
        install_consensus_policy(&db, "ns-cons", 2);

        // Step 3: seed a pending action.
        seed_pending_action(&db, "pa-cons-1", "ns-cons", "store", "voter-a");

        // Step 4: voter-a approves.
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: "pa-cons-1".to_string(),
                approvals: Vec::new(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, false, Some("voter-a"), &mut out).expect("approve voter-a");
        }
        // Text branch — "approval recorded".
        assert!(
            env.stdout_str().contains("approval recorded: pa-cons-1"),
            "expected `approval recorded` text, got: {}",
            env.stdout_str()
        );
    }

    #[test]
    fn test_pending_approve_consensus_pending_json() {
        // JSON variant of the same path (lines 200-212).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for who in ["voter-a", "voter-b"] {
            let reg = AgentsArgs {
                action: Some(AgentsAction::Register {
                    agent_id: who.to_string(),
                    agent_type: "human".to_string(),
                    capabilities: String::new(),
                }),
            };
            let mut out = env.output();
            run_agents(&db, reg, false, &mut out).expect("register voter");
        }
        env.stdout.clear();
        install_consensus_policy(&db, "ns-cons-j", 2);
        seed_pending_action(&db, "pa-cons-j", "ns-cons-j", "store", "voter-a");
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: "pa-cons-j".to_string(),
                approvals: Vec::new(),
            },
        };
        {
            let mut out = env.output();
            run_pending(&db, args, true, Some("voter-a"), &mut out).expect("approve voter-a");
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["approved"].as_bool().unwrap(), false);
        assert_eq!(v["status"].as_str().unwrap(), "pending");
        assert_eq!(v["quorum"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_pending_reject_invalid_id_validation_error() {
        // validate_id rejects an obviously-invalid id (empty / contains
        // disallowed chars). The CLI returns the error via `?`.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = PendingArgs {
            action: PendingAction::Reject { id: String::new() },
        };
        let mut out = env.output();
        let res = run_pending(&db, args, false, Some("test-agent"), &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_pending_approve_invalid_id_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = PendingArgs {
            action: PendingAction::Approve {
                id: String::new(),
                approvals: Vec::new(),
            },
        };
        let mut out = env.output();
        let res = run_pending(&db, args, false, Some("test-agent"), &mut out);
        assert!(res.is_err());
    }

    // ---- #626 Layer-3 (C5): bind-key / revoke-key CLI commands -----

    /// Register `agent_id` then return a fresh valid base64 Ed25519
    /// public key for it.
    fn register_and_key(env: &mut TestEnv, db: &std::path::Path, agent_id: &str) -> String {
        let reg = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: agent_id.to_string(),
                agent_type: "ai:claude-opus-4.7".to_string(),
                capabilities: String::new(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(db, reg, false, &mut out).expect("register");
        }
        env.stdout.clear();
        env.stderr.clear();
        crate::identity::keypair::generate(agent_id)
            .expect("generate keypair")
            .public_base64()
    }

    #[test]
    fn test_agents_bind_key_happy_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pk = register_and_key(&mut env, &db, "ai:curator");
        let args = AgentsArgs {
            action: Some(AgentsAction::BindKey {
                agent_id: "ai:curator".to_string(),
                pubkey: pk.clone(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("bound pubkey for ai:curator"));
        // The key is now retrievable via db::agent_pubkey.
        let conn = db::open(&db).unwrap();
        assert_eq!(db::agent_pubkey(&conn, "ai:curator").unwrap(), Some(pk));
    }

    #[test]
    fn test_agents_bind_key_happy_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pk = register_and_key(&mut env, &db, "ai:curator");
        let args = AgentsArgs {
            action: Some(AgentsAction::BindKey {
                agent_id: "ai:curator".to_string(),
                pubkey: pk.clone(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["bound"].as_bool().unwrap(), true);
        assert_eq!(v["agent_id"].as_str().unwrap(), "ai:curator");
        assert_eq!(v["agent_pubkey"].as_str().unwrap(), pk);
    }

    #[test]
    fn test_agents_bind_key_rotates_in_place() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let k1 = register_and_key(&mut env, &db, "ai:curator");
        let k2 = crate::identity::keypair::generate("ai:curator")
            .unwrap()
            .public_base64();
        assert_ne!(k1, k2);
        for k in [&k1, &k2] {
            let args = AgentsArgs {
                action: Some(AgentsAction::BindKey {
                    agent_id: "ai:curator".to_string(),
                    pubkey: k.clone(),
                }),
            };
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        assert_eq!(db::agent_pubkey(&conn, "ai:curator").unwrap(), Some(k2));
    }

    #[test]
    fn test_agents_bind_key_unregistered_is_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pk = crate::identity::keypair::generate("ai:ghost")
            .unwrap()
            .public_base64();
        let args = AgentsArgs {
            action: Some(AgentsAction::BindKey {
                agent_id: "ai:ghost".to_string(),
                pubkey: pk,
            }),
        };
        let mut out = env.output();
        let res = run_agents(&db, args, false, &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not registered"));
    }

    #[test]
    fn test_agents_bind_key_malformed_pubkey_is_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        register_and_key(&mut env, &db, "ai:curator");
        let args = AgentsArgs {
            action: Some(AgentsAction::BindKey {
                agent_id: "ai:curator".to_string(),
                pubkey: "not-a-valid-key".to_string(),
            }),
        };
        let mut out = env.output();
        let res = run_agents(&db, args, false, &mut out);
        assert!(res.is_err());
    }

    #[test]
    fn test_agents_revoke_key_happy_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pk = register_and_key(&mut env, &db, "ai:curator");
        // Bind then revoke.
        {
            let conn = db::open(&db).unwrap();
            db::bind_agent_pubkey(&conn, "ai:curator", &pk).unwrap();
        }
        let args = AgentsArgs {
            action: Some(AgentsAction::RevokeKey {
                agent_id: "ai:curator".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("revoked pubkey for ai:curator"));
        let conn = db::open(&db).unwrap();
        assert_eq!(db::agent_pubkey(&conn, "ai:curator").unwrap(), None);
    }

    #[test]
    fn test_agents_revoke_key_happy_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let pk = register_and_key(&mut env, &db, "ai:curator");
        {
            let conn = db::open(&db).unwrap();
            db::bind_agent_pubkey(&conn, "ai:curator", &pk).unwrap();
        }
        let args = AgentsArgs {
            action: Some(AgentsAction::RevokeKey {
                agent_id: "ai:curator".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["revoked"].as_bool().unwrap(), true);
        assert_eq!(v["agent_id"].as_str().unwrap(), "ai:curator");
    }

    #[test]
    fn test_agents_revoke_key_idempotent_without_bound_key() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        register_and_key(&mut env, &db, "ai:curator");
        // No key bound — revoke still succeeds.
        let args = AgentsArgs {
            action: Some(AgentsAction::RevokeKey {
                agent_id: "ai:curator".to_string(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("revoked pubkey for ai:curator"));
    }

    #[test]
    fn test_agents_revoke_key_unregistered_is_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::RevokeKey {
                agent_id: "ai:ghost".to_string(),
            }),
        };
        let mut out = env.output();
        let res = run_agents(&db, args, false, &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not registered"));
    }

    // Local seed helper — duplicated from cli::test_utils so we can
    // bind a specific id without changing the shared signature.
    fn seed_memory_local(
        db_path: &std::path::Path,
        ns: &str,
        title: &str,
        content: &str,
    ) -> String {
        crate::cli::test_utils::seed_memory(db_path, ns, title, content)
    }

    // ---- v1.0.0 crypto-core stage-3 (#1942): enroll-subkey-cert +
    //      subkey-certs CLI verbs. Fixtures mint a REAL root keypair, a
    //      sub-key, and a root-signed SubkeyCert via the crate's own
    //      identity APIs, then exercise the CLI against the artifact. -----

    /// Wide validity window — the enroll path (`verify_and_record_cert`)
    /// signature-verifies the cert but does NOT check the window (that is a
    /// write-time gate), so the exact bounds are immaterial for enrollment;
    /// a wide window keeps the fixture unambiguously well-formed.
    const CERT_NOT_BEFORE: &str = "2020-01-01T00:00:00Z";
    const CERT_NOT_AFTER: &str = "2030-01-01T00:00:00Z";

    /// Register `principal` then bind a freshly-generated Ed25519 root key,
    /// returning the root **signing** key so a test can mint a root-signed
    /// cert under it.
    fn register_and_bind_root(
        env: &mut TestEnv,
        db: &std::path::Path,
        principal: &str,
    ) -> ed25519_dalek::SigningKey {
        let reg = AgentsArgs {
            action: Some(AgentsAction::Register {
                agent_id: principal.to_string(),
                agent_type: "ai:claude-opus-4.7".to_string(),
                capabilities: String::new(),
            }),
        };
        {
            let mut out = env.output();
            run_agents(db, reg, false, &mut out).expect("register");
        }
        env.stdout.clear();
        env.stderr.clear();
        let root_kp = crate::identity::keypair::generate(principal).expect("gen root");
        {
            let conn = db::open(db).unwrap();
            db::bind_agent_pubkey(&conn, principal, &root_kp.public_base64()).expect("bind");
        }
        root_kp
            .private
            .expect("generated keypair carries a private key")
    }

    /// Build a cert-envelope JSON `Value` (the shape the CLI file carries),
    /// signed by `signer` over the frozen bound fields for `principal`.
    fn build_cert_json(
        signer: &ed25519_dalek::SigningKey,
        principal: &str,
        not_before: &str,
        not_after: &str,
    ) -> serde_json::Value {
        use base64::Engine as _;
        use ed25519_dalek::SigningKey;
        let b64 = base64::engine::general_purpose::STANDARD;
        let sub = SigningKey::from_bytes(&[0x22u8; 32]);
        let instance_key_id = sub.verifying_key().to_bytes().to_vec();
        let model_version_ref = vec![0xabu8; 32];
        let cert = crate::identity::subkey_cert::SubkeyCert {
            principal,
            instance_key_id: &instance_key_id,
            model_version_ref: &model_version_ref,
            not_before,
            not_after,
        };
        let sig = crate::identity::subkey_cert::sign_subkey_cert(signer, &cert);
        serde_json::json!({
            "principal": principal,
            "instance_key_id": b64.encode(&instance_key_id),
            "model_version_ref": b64.encode(&model_version_ref),
            "not_before": not_before,
            "not_after": not_after,
            "cert_signature": b64.encode(sig),
        })
    }

    /// Persist a cert file next to the test DB (inside the fixture tempdir)
    /// and return its path.
    fn write_cert_file(env: &TestEnv, name: &str, json: &serde_json::Value) -> std::path::PathBuf {
        let path = env.db_path.parent().expect("db has parent dir").join(name);
        std::fs::write(
            &path,
            serde_json::to_string(json).expect("serialize cert json"),
        )
        .expect("write cert file");
        path
    }

    #[test]
    fn test_enroll_subkey_cert_happy_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-happy.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(
            env.stdout_str().contains("enrolled sub-key cert"),
            "expected enrolled line, got: {}",
            env.stdout_str()
        );
        assert!(env.stdout_str().contains("ai:curator"));
        // Observable persistence: exactly one row for the principal.
        let conn = db::open(&db).unwrap();
        let certs = db::list_subkey_certs(&conn, Some("ai:curator")).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].principal, "ai:curator");
        assert!(!certs[0].revoked);
    }

    #[test]
    fn test_enroll_subkey_cert_happy_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-happy-json.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["enrolled"].as_bool().unwrap(), true);
        assert_eq!(v["principal"].as_str().unwrap(), "ai:curator");
        assert!(v["id"].as_str().unwrap().starts_with("b3:"));
    }

    #[test]
    fn test_enroll_subkey_cert_wrong_root_rejected_and_not_persisted() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Bind the real root, but sign the cert with an UNRELATED key.
        let _real_root = register_and_bind_root(&mut env, &db, "ai:curator");
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        let json = build_cert_json(&attacker, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-wrong-root.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("cert verification failed"),
            "expected verification failure, got: {err}"
        );
        // Nothing persisted on a rejected cert.
        let conn = db::open(&db).unwrap();
        assert!(db::list_subkey_certs(&conn, None).unwrap().is_empty());
    }

    #[test]
    fn test_enroll_subkey_cert_missing_root_binding_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Principal is a valid id but has NO bound root key (never bound).
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let json = build_cert_json(&signer, "ai:unbound", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-unbound.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("no bound root key"),
            "expected no-bound-root-key error, got: {err}"
        );
    }

    #[test]
    fn test_enroll_subkey_cert_malformed_bound_root_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Register, then bind a base64 string that decodes to the WRONG
        // length (not a 32-byte Ed25519 key) directly via db — bypasses the
        // CLI's bind-key validation so we can drive the decode-failure arm.
        let signer = register_and_bind_root(&mut env, &db, "ai:curator");
        {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD;
            let conn = db::open(&db).unwrap();
            db::bind_agent_pubkey(&conn, "ai:curator", &b64.encode([0u8; 10])).unwrap();
        }
        let json = build_cert_json(&signer, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-malformed-root.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("is malformed"),
            "expected malformed-root-key error, got: {err}"
        );
    }

    #[test]
    fn test_enroll_subkey_cert_invalid_principal_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // A principal with a space fails `validate_agent_id` BEFORE any db
        // lookup, so no registration is needed.
        let signer = ed25519_dalek::SigningKey::from_bytes(&[0x44u8; 32]);
        let json = build_cert_json(&signer, "bad principal!", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-bad-principal.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        assert!(res.is_err());
        // Nothing persisted.
        let conn = db::open(&db).unwrap();
        assert!(db::list_subkey_certs(&conn, None).unwrap().is_empty());
    }

    #[test]
    fn test_enroll_subkey_cert_missing_file_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let missing = env.db_path.parent().unwrap().join("does-not-exist.json");
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file: missing }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("read cert file"),
            "expected read-cert-file error, got: {err}"
        );
    }

    #[test]
    fn test_enroll_subkey_cert_bad_json_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let path = env.db_path.parent().unwrap().join("cert-bad-json.json");
        std::fs::write(&path, "{ this is not valid json ").unwrap();
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file: path }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("parse cert JSON"),
            "expected parse-json error, got: {err}"
        );
    }

    #[test]
    fn test_enroll_subkey_cert_missing_field_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let mut json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        // Drop a required string field.
        json.as_object_mut().unwrap().remove("model_version_ref");
        let file = write_cert_file(&env, "cert-missing-field.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("missing string field") && err.contains("model_version_ref"),
            "expected missing-field error, got: {err}"
        );
    }

    #[test]
    fn test_enroll_subkey_cert_field_not_base64_rejected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let mut json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        // Replace a base64 field with a non-base64 string.
        json["instance_key_id"] = serde_json::Value::String("%%%%not-base64%%%%".to_string());
        let file = write_cert_file(&env, "cert-not-b64.json", &json);
        let args = AgentsArgs {
            action: Some(AgentsAction::EnrollSubkeyCert { file }),
        };
        let res = {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out)
        };
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("not base64"),
            "expected not-base64 error, got: {err}"
        );
    }

    // ---- subkey-certs list/inspect verb --------------------------------

    #[test]
    fn test_subkey_certs_empty_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::SubkeyCerts { principal: None }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("no sub-key certificates"));
    }

    #[test]
    fn test_subkey_certs_empty_json() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = AgentsArgs {
            action: Some(AgentsAction::SubkeyCerts { principal: None }),
        };
        {
            let mut out = env.output();
            run_agents(&db, args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
        assert!(v["subkey_certs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_subkey_certs_populated_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-list-text.json", &json);
        {
            let mut out = env.output();
            run_agents(
                &db,
                AgentsArgs {
                    action: Some(AgentsAction::EnrollSubkeyCert { file }),
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
            run_agents(
                &db,
                AgentsArgs {
                    action: Some(AgentsAction::SubkeyCerts { principal: None }),
                },
                false,
                &mut out,
            )
            .unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("principal=ai:curator"), "got: {s}");
        assert!(s.contains("1 sub-key certificate(s)"), "got: {s}");
    }

    #[test]
    fn test_subkey_certs_populated_json_filtered_by_principal() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let root = register_and_bind_root(&mut env, &db, "ai:curator");
        let json = build_cert_json(&root, "ai:curator", CERT_NOT_BEFORE, CERT_NOT_AFTER);
        let file = write_cert_file(&env, "cert-list-json.json", &json);
        {
            let mut out = env.output();
            run_agents(
                &db,
                AgentsArgs {
                    action: Some(AgentsAction::EnrollSubkeyCert { file }),
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
            run_agents(
                &db,
                AgentsArgs {
                    action: Some(AgentsAction::SubkeyCerts {
                        principal: Some("ai:curator".to_string()),
                    }),
                },
                true,
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 1);
        let cert0 = &v["subkey_certs"][0];
        assert_eq!(cert0["principal"].as_str().unwrap(), "ai:curator");
        assert_eq!(cert0["revoked"].as_bool().unwrap(), false);
        // The instance_key_id round-trips as a base64 string.
        assert!(cert0["instance_key_id"].as_str().is_some());
        assert!(cert0["id"].as_str().unwrap().starts_with("b3:"));
    }

    // #2095 — the api-key enrollment/revocation SAL helpers (extracted from the
    // daemon_runtime dispatch). Exercises every branch: bind happy + json,
    // revoke happy + json, empty-token error, invalid-agent-id error, and the
    // round-trip that a bind is visible via the store lookup + revoke removes it.
    #[cfg(feature = "sal")]
    fn sal_store(db_path: &std::path::Path) -> std::sync::Arc<dyn crate::store::MemoryStore> {
        std::sync::Arc::new(
            crate::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"),
        )
    }

    #[cfg(feature = "sal")]
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    }

    #[cfg(feature = "sal")]
    #[test]
    fn run_bind_api_key_binds_and_is_looked_up_2095() {
        let env = TestEnv::fresh();
        let store = sal_store(&env.db_path);
        let rt = rt();
        rt.block_on(run_bind_api_key(&store, "alice", "alice-token", false))
            .expect("bind ok");
        // The digest is resolvable, and the raw token was never stored.
        let hash = crate::handlers::identity_binding::api_key_sha256_hex("alice-token");
        let resolved = rt
            .block_on(store.agent_id_for_api_key(&hash))
            .expect("resolve ok");
        assert_eq!(resolved.as_deref(), Some("alice"));
        // json branch.
        rt.block_on(run_bind_api_key(&store, "bob", "bob-token", true))
            .expect("bind json ok");
    }

    #[cfg(feature = "sal")]
    #[test]
    fn run_bind_api_key_empty_token_errors_2095() {
        let env = TestEnv::fresh();
        let store = sal_store(&env.db_path);
        let err = rt()
            .block_on(run_bind_api_key(&store, "alice", "   ", false))
            .expect_err("empty token must error");
        assert!(err.to_string().contains("token must not be empty"));
    }

    #[cfg(feature = "sal")]
    #[test]
    fn run_bind_api_key_invalid_agent_id_errors_2095() {
        let env = TestEnv::fresh();
        let store = sal_store(&env.db_path);
        // A whitespace-bearing agent id fails validate_agent_id.
        let err = rt()
            .block_on(run_bind_api_key(&store, "bad id", "tok", false))
            .expect_err("invalid agent id must error");
        assert!(!err.to_string().is_empty());
    }

    #[cfg(feature = "sal")]
    #[test]
    fn run_revoke_api_key_removes_binding_2095() {
        let env = TestEnv::fresh();
        let store = sal_store(&env.db_path);
        let rt = rt();
        rt.block_on(run_bind_api_key(&store, "carol", "carol-token", false))
            .expect("bind ok");
        rt.block_on(run_revoke_api_key(&store, "carol", false))
            .expect("revoke ok");
        let hash = crate::handlers::identity_binding::api_key_sha256_hex("carol-token");
        assert_eq!(
            rt.block_on(store.agent_id_for_api_key(&hash)).unwrap(),
            None,
            "revoked key no longer resolves"
        );
        // json branch (idempotent no-op revoke).
        rt.block_on(run_revoke_api_key(&store, "carol", true))
            .expect("revoke json ok");
    }

    #[cfg(feature = "sal")]
    #[test]
    fn run_revoke_api_key_invalid_agent_id_errors_2095() {
        let env = TestEnv::fresh();
        let store = sal_store(&env.db_path);
        let err = rt()
            .block_on(run_revoke_api_key(&store, "bad id", false))
            .expect_err("invalid agent id must error");
        assert!(!err.to_string().is_empty());
    }
}
