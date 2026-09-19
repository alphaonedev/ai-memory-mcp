// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator key hygiene against the selected SQLite or PostgreSQL registry.

use crate::identity::key_inventory::{self, Inventory};
use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct KeysArgs {
    /// Key directory to inspect (defaults to AI_MEMORY_KEY_DIR).
    #[arg(long, global = true)]
    pub key_dir: Option<PathBuf>,
    /// Registry store URL; also honors the configured store URL channels.
    #[arg(long, global = true)]
    pub store_url: Option<String>,
    #[command(subcommand)]
    pub action: KeysAction,
}

#[derive(Subcommand)]
pub enum KeysAction {
    /// #3717 — mint every key ROLE the declared deployment shape needs and
    /// that is ABSENT (recovery anchor, identity, daemon signer, at-rest wrap
    /// key with its recovery escrow, local TLS on the singleton shape,
    /// capability owner), repair a role whose private half survives, and
    /// REFUSE before any write when a private half is lost — never minting
    /// over what exists. Prints what to BACK UP and what to DISTRIBUTE.
    Init {
        /// Bind host the local TLS certificate must cover (singleton shape).
        #[arg(long)]
        host: Option<String>,
        /// Report the plan and the lists without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Mint the deployment RECOVERY keypair: its private half is written
        /// to this file (created 0600; move it OFF-NODE), its public half is
        /// enrolled in the key directory. Every at-rest key is escrowed under
        /// it. Refused when a recovery key is already enrolled.
        #[arg(long, value_name = "FILE")]
        recovery_key_out: Option<PathBuf>,
    },
    /// #3717 — the posture of every key role for the resolved agent id: the
    /// typed state per role, what is missing and the command that fixes it.
    /// Writes nothing.
    Status,
    /// #3717 — restore a LOST at-rest key (`<agent>.x25519.priv`) from its
    /// recovery escrow using the operator's off-node recovery private file.
    /// The sealed rows are untouched; they open again once the key is back.
    Recover {
        /// The recovery PRIVATE file `keys init --recovery-key-out` wrote
        /// (mode 0600). A file channel only — never argv.
        #[arg(long, value_name = "FILE")]
        recovery_key: PathBuf,
        /// The agent whose key to restore (default: the resolved agent id).
        #[arg(long, value_name = "AGENT_ID")]
        agent: Option<String>,
    },
    /// Preview orphan key files; deletion requires --yes.
    Prune {
        /// List candidates without removing files.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,
        /// Include enrolled public-only peer/guardian keys (deletion still requires --yes).
        #[arg(long)]
        include_public_only: bool,
        /// Remove selected unregistered regular key files.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(
    db: &Path,
    args: KeysArgs,
    json: bool,
    caller_agent_id: Option<&str>,
    app_config: &crate::config::AppConfig,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    let dir = args
        .key_dir
        .map_or_else(crate::identity::keypair::default_key_dir, Ok)?;
    let (yes, include_public_only) = match args.action {
        KeysAction::Init {
            host,
            dry_run,
            recovery_key_out,
        } => {
            return run_init(
                &dir,
                crate::keys::roles::PlanOptions {
                    recovery_key_out,
                    host,
                },
                dry_run,
                json,
                caller_agent_id,
                app_config,
                out,
            );
        }
        KeysAction::Status => return run_status(&dir, json, caller_agent_id, app_config, out),
        KeysAction::Recover {
            recovery_key,
            agent,
        } => {
            return run_recover(
                &dir,
                &recovery_key,
                agent.as_deref(),
                json,
                caller_agent_id,
                out,
            );
        }
        KeysAction::Prune {
            yes,
            include_public_only,
            ..
        } => (yes, include_public_only),
    };
    let result = inventory(
        db,
        args.store_url.as_deref(),
        &dir,
        yes,
        include_public_only,
        caller_agent_id,
    )?;
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({"dry_run": !yes, "inventory": result})
        )?;
    } else {
        for name in &result.orphan_files {
            writeln!(
                out.stdout,
                "{} {name}",
                if yes { "removed" } else { "orphan" }
            )?;
        }
        for name in &result.enrolled_public_keys {
            writeln!(
                out.stdout,
                "{} {name}",
                if yes && include_public_only {
                    "removed enrolled public key"
                } else {
                    "enrolled public key (not pruned)"
                }
            )?;
        }
        writeln!(
            out.stdout,
            "{} orphan files; {} enrolled public keys; {} protected; {} symlinks skipped",
            result.orphan_files.len(),
            result.enrolled_public_keys.len(),
            result.protected_files.len(),
            result.skipped_symlinks.len()
        )?;
        if !yes {
            writeln!(
                out.stdout,
                "Dry run: no files removed. Review before repeating with --yes."
            )?;
        }
    }
    Ok(())
}

/// Observe the posture for the RESOLVED agent id (the precedence chain boot
/// uses) under the DECLARED shape.
fn observe_for(
    dir: &Path,
    caller_agent_id: Option<&str>,
    app_config: &crate::config::AppConfig,
) -> Result<(
    crate::keys::roles::Posture,
    crate::config::shape::DeploymentShape,
)> {
    let agent_id = crate::identity::resolve_agent_id(caller_agent_id, None)?;
    let shape = app_config.effective_shape();
    let posture = crate::keys::roles::observe(dir, &agent_id, shape, app_config)?;
    Ok((posture, shape))
}

/// The word `keys init` prints for a planned action (dry run) or an
/// outcome (real run).
fn action_word(action: crate::keys::roles::Action) -> &'static str {
    use crate::keys::roles::Action;
    match action {
        Action::Mint => "would mint",
        Action::Repair => "would repair",
        Action::Present => "present",
        Action::NotRequired => "not required",
        Action::CannotMint => "CANNOT MINT HERE",
        Action::Refuse => "REFUSES",
        Action::OperatorSupplied => crate::keys::roles::WORD_OPERATOR_SUPPLIED,
    }
}

fn outcome_word(outcome: crate::keys::roles::MintOutcome) -> &'static str {
    use crate::keys::roles::MintOutcome;
    match outcome {
        MintOutcome::Present => "present",
        MintOutcome::Minted => "minted",
        MintOutcome::Repaired => "repaired",
        MintOutcome::NotRequired => "not required",
        MintOutcome::CannotMint => "CANNOT MINT HERE",
        MintOutcome::OperatorSupplied => crate::keys::roles::WORD_OPERATOR_SUPPLIED,
    }
}

/// #3717 — `ai-memory keys init [--host] [--dry-run] [--recovery-key-out]`.
///
/// Observes, plans (the ONE pure plan), then either prints the plan (dry
/// run) or executes it — which refuses BEFORE ANY WRITE on a lost private
/// half or a leaky directory — and prints the posture and the two lists.
#[allow(clippy::too_many_arguments)]
fn run_init(
    dir: &Path,
    opts: crate::keys::roles::PlanOptions,
    dry_run: bool,
    json: bool,
    caller_agent_id: Option<&str>,
    app_config: &crate::config::AppConfig,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    use crate::keys::roles::{self, Action};
    let (before, shape) = observe_for(dir, caller_agent_id, app_config)?;
    let plan = roles::plan(&before, &opts);
    let (words, rows): (Vec<(&'static str, String)>, Vec<serde_json::Value>) = if dry_run {
        if let Some(text) = roles::loose_text(&before) {
            bail!(text);
        }
        if plan.is_refused() {
            bail!(roles::refusal_text(&plan));
        }
        plan.steps
            .iter()
            .map(|s| {
                (
                    (action_word(s.action), s.reason.clone()),
                    serde_json::json!({"role": s.role, "action": s.action, "reason": s.reason}),
                )
            })
            .unzip()
    } else {
        roles::execute(&before, &plan, &opts)?
            .into_iter()
            .map(|o| {
                (
                    (outcome_word(o.outcome), o.reason.clone()),
                    serde_json::json!({"role": o.role, "outcome": o.outcome, "reason": o.reason}),
                )
            })
            .unzip()
    };
    let after = if dry_run {
        before
    } else {
        observe_for(dir, caller_agent_id, app_config)?.0
    };
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "dry_run": dry_run,
                "key_dir": after.key_dir,
                "agent_id": after.agent_id,
                "shape": after.shape,
                roles::FIELD_RECOVERY_ENROLLED: after.recovery_enrolled,
                "plan": plan.steps,
                "outcomes": rows,
                "roles": after.roles,
                "back_up": after.back_up(),
                "distribute": after.distribute(),
            })
        )?;
        return Ok(());
    }
    writeln!(
        out.stdout,
        "keys init{}: {} for `{}` under {}",
        if dry_run { " (dry run)" } else { "" },
        after.key_dir.display(),
        after.agent_id,
        shape.config_line()
    )?;
    for ((word, reason), step) in words.iter().zip(&plan.steps) {
        writeln!(
            out.stdout,
            "  {:<17} {word:<18} {reason}",
            step.role.label()
        )?;
        if matches!(step.action, Action::CannotMint) {
            if let Some(cmd) = &after.role(step.role).mint_command {
                writeln!(out.stdout, "  {:<17} fix: {cmd}", "")?;
            }
        }
    }
    print_lists(&after, out)
}

fn print_lists(after: &crate::keys::roles::Posture, out: &mut super::CliOutput<'_>) -> Result<()> {
    writeln!(out.stdout)?;
    writeln!(
        out.stdout,
        "BACK UP (private material and escrows — never copy to another host or agent):"
    )?;
    for p in after.back_up() {
        writeln!(out.stdout, "  {}", p.display())?;
    }
    writeln!(
        out.stdout,
        "DISTRIBUTE (public material — safe to hand to peers and clients):"
    )?;
    for p in after.distribute() {
        writeln!(out.stdout, "  {}", p.display())?;
    }
    let missing = after.missing_required();
    if !missing.is_empty() {
        writeln!(out.stdout)?;
        writeln!(out.stdout, "STILL MISSING (required, not complete here):")?;
        for r in missing {
            writeln!(out.stdout, "  {:<17} {}", r.id.label(), r.detail)?;
        }
    }
    Ok(())
}

/// #3717 — `ai-memory keys status`: the posture and the plan `keys init`
/// WOULD follow, writes nothing.
fn run_status(
    dir: &Path,
    json: bool,
    caller_agent_id: Option<&str>,
    app_config: &crate::config::AppConfig,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    use crate::keys::roles;
    let (posture, shape) = observe_for(dir, caller_agent_id, app_config)?;
    let plan = roles::plan(&posture, &roles::PlanOptions::default());
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "key_dir": posture.key_dir,
                roles::FIELD_KEY_DIR_MODE: posture.key_dir_mode,
                "agent_id": posture.agent_id,
                "shape": posture.shape,
                roles::FIELD_RECOVERY_ENROLLED: posture.recovery_enrolled,
                "roles": posture.roles,
                "plan": plan.steps,
                "missing_required": posture.missing_required().iter().map(|r| r.id).collect::<Vec<_>>(),
                "loose_files": posture.loose_files().iter().map(|f| &f.path).collect::<Vec<_>>(),
                "back_up": posture.back_up(),
                "distribute": posture.distribute(),
            })
        )?;
        return Ok(());
    }
    writeln!(
        out.stdout,
        "keys status: {} for `{}` under {}",
        posture.key_dir.display(),
        posture.agent_id,
        shape.config_line()
    )?;
    for (r, s) in posture.roles.iter().zip(&plan.steps) {
        writeln!(
            out.stdout,
            "  {:<17} {:<32} {}",
            r.id.label(),
            state_word(r),
            match s.action {
                roles::Action::Present | roles::Action::NotRequired => String::new(),
                _ => format!("[keys init: {}] ", action_word(s.action)),
            } + &r.detail
        )?;
    }
    if let Some(text) = roles::loose_text(&posture) {
        writeln!(out.stdout)?;
        writeln!(out.stdout, "{text}")?;
    }
    print_lists(&posture, out)
}

/// One word for a role's state, with the TLS leaf's expiry when present.
pub(crate) fn state_word(r: &crate::keys::roles::Role) -> String {
    use crate::keys::roles::{Need, Partial, RoleState};
    let base = match r.state {
        RoleState::Absent if r.need == Need::NotRequired => "absent (not required)",
        RoleState::Absent => "MISSING",
        RoleState::Complete => "present",
        RoleState::Partial(Partial::Recoverable) => "PARTIAL (recoverable)",
        RoleState::Partial(Partial::LostPrivate) => "PARTIAL (private half LOST)",
        RoleState::Partial(Partial::Unreadable) => "PARTIAL (unreadable)",
        RoleState::OperatorSupplied => crate::keys::roles::WORD_OPERATOR_SUPPLIED,
    };
    match r.expires_in_days {
        Some(d) if d < 0 => format!("{base}, EXPIRED {} day(s) ago", -d),
        Some(d) => format!("{base}, expires in {d} day(s)"),
        None => base.to_string(),
    }
}

/// #3717 — `ai-memory keys recover --recovery-key <file> [--agent <id>]`.
fn run_recover(
    dir: &Path,
    recovery_key: &Path,
    agent: Option<&str>,
    json: bool,
    caller_agent_id: Option<&str>,
    out: &mut super::CliOutput<'_>,
) -> Result<()> {
    use crate::encryption::escrow;
    let agent_id = match agent {
        Some(id) => {
            crate::validate::validate_agent_id_shape(id)?;
            id.to_string()
        }
        None => crate::identity::resolve_agent_id(caller_agent_id, None)?,
    };
    let secret = escrow::load_recovery_secret(recovery_key)?;
    let enrolled = escrow::load_recovery_pubkey(dir)?;
    if let Some(enrolled) = enrolled {
        let ours = x25519_dalek::PublicKey::from(&secret);
        if ours.as_bytes() != enrolled.as_bytes() {
            bail!(
                "the recovery private file {} is not the enrolled recovery key's private half \
                 ({}); nothing was written",
                recovery_key.display(),
                escrow::recovery_pub_path(dir).display()
            );
        }
    }
    let recovered = escrow::recover_private_from_escrow(&agent_id, dir, &secret)?;
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "agent_id": recovered.agent_id,
                "priv_path": recovered.priv_path,
                "pub_path": recovered.pub_path,
                "pub_rewritten": recovered.pub_rewritten,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "keys recover: restored {} from its escrow{}; the rows sealed under it open again",
            recovered.priv_path.display(),
            if recovered.pub_rewritten {
                " (public half re-derived)"
            } else {
                ""
            }
        )?;
    }
    Ok(())
}

/// Both doctor and prune resolve and read the same registry. Unknown backends,
/// unavailable registries and malformed rows fail closed, never as an empty set.
pub(crate) fn inventory(
    db: &Path,
    url: Option<&str>,
    dir: &Path,
    delete: bool,
    include_public_only: bool,
    caller_agent_id: Option<&str>,
) -> Result<Inventory> {
    // #3354 — the ledger is signed from its first row by the key of the
    // RESOLVED agent id (`AI_MEMORY_AGENT_ID`, else `host:<hostname>`), which
    // a ledger-writing verb generates on first use without registering the
    // id. That key is reserved by construction: pruning it would leave every
    // signed row without the key that signed it and hand the next writer a
    // fresh one. Resolve it the way boot does and protect it alongside the
    // registered ids — never re-derive the identity here.
    let signer = crate::identity::resolve_agent_id(caller_agent_id, None)?;
    let url = crate::store_url::resolve_store_url(url)?;
    if let Some(url) = &url {
        if crate::store_url::is_postgres_url(url) {
            #[cfg(feature = "sal-postgres")]
            return postgres(url, dir, delete, include_public_only, &signer);
            #[cfg(not(feature = "sal-postgres"))]
            bail!("PostgreSQL key registry requires the sal-postgres feature");
        }
    }
    let db = match url.as_deref() {
        None => db,
        Some(url) => Path::new(
            url.strip_prefix("sqlite://")
                .context("unsupported key registry store URL")?,
        ),
    };
    sqlite(db, dir, delete, include_public_only, &signer)
}

fn sqlite(
    db: &Path,
    dir: &Path,
    delete: bool,
    include_public_only: bool,
    signer: &str,
) -> Result<Inventory> {
    if !db.is_file() {
        bail!("key registry database does not exist; refusing key pruning");
    }
    let conn = if delete {
        crate::db::open_unmigrated(db)?
    } else {
        crate::db::open_read_only(db)?
    };
    // IMMEDIATE excludes concurrent registration until the filesystem operation
    // finishes. The read-only preview needs no writer reservation.
    conn.execute_batch(if delete { "BEGIN IMMEDIATE" } else { "BEGIN" })?;
    let metadata = {
        let mut statement = conn.prepare("SELECT metadata FROM memories WHERE namespace = ?1")?;
        statement
            .query_map([crate::models::AGENTS_NAMESPACE], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut ids = key_inventory::registered_ids(metadata)?;
    ids.insert(signer.to_owned());
    let result = key_inventory::inspect(dir, &ids, delete, include_public_only);
    conn.execute_batch("ROLLBACK")?;
    result
}

#[cfg(feature = "sal-postgres")]
fn postgres(
    url: &str,
    dir: &Path,
    delete: bool,
    include_public_only: bool,
    signer: &str,
) -> Result<Inventory> {
    super::doctor::run_pg_probe(|| async {
        use sqlx::Connection as _;
        let operation = async {
            let mut conn = sqlx::PgConnection::connect(url).await?;
            let mut tx = conn.begin().await?;
            if delete {
                // Protect the entire _agents population against insertion,
                // deletion and rename while pruning. No migrations or writes.
                sqlx::query("LOCK TABLE memories IN SHARE MODE")
                    .execute(&mut *tx)
                    .await?;
            }
            let metadata: Vec<String> =
                sqlx::query_scalar("SELECT metadata::text FROM memories WHERE namespace = $1")
                    .bind(crate::models::AGENTS_NAMESPACE)
                    .fetch_all(&mut *tx)
                    .await?;
            let mut ids = key_inventory::registered_ids(metadata)?;
            ids.insert(signer.to_owned());
            let result = key_inventory::inspect(dir, &ids, delete, include_public_only);
            tx.rollback().await?;
            result
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), operation)
            .await
            .context("key registry inspection timed out")?
    })?
}
