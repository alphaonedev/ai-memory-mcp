// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory audit` — operator-facing CLI for the security audit
//! trail (PR-5 of issue #487).
//!
//! Subcommands:
//! - `verify` — walk the configured audit log and assert the hash chain
//!   is intact. Exits non-zero on any mismatch with the precise line
//!   number and failure kind.
//! - `tail` — print recent audit events in JSON or text form.
//! - `path` — print the resolved audit log path. Useful for SIEM
//!   ingestion configuration scripts.

use crate::models::field_names;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::audit::{
    AuditEvent, resolve_audit_path, resolve_audit_path_with_override, verify_chain,
};
use crate::cli::CliOutput;
use crate::config::AppConfig;

#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub action: AuditAction,
    /// Override the audit log directory. Highest-priority layer in the
    /// resolution ladder (CLI > `AI_MEMORY_AUDIT_DIR` > `[audit] path`
    /// in config.toml > platform default). Refuses world-writable
    /// directories — see `docs/security/audit-trail.md`.
    #[arg(long, global = true, value_name = "PATH")]
    pub audit_dir: Option<std::path::PathBuf>,
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Verify the hash chain. Exits 0 on success, 2 on mismatch.
    Verify(VerifyArgs),
    /// Print the most recent N events (default 50).
    Tail(TailArgs),
    /// Print the resolved audit log path.
    Path,
    /// v0.6.4-009 — list rows from the in-DB `audit_log` table
    /// (capability expansions, future event types). Reads the SQLite
    /// audit_log table; orthogonal to the file-based hash-chained
    /// trail surfaced by `tail` / `verify`.
    Show(ShowArgs),
    /// v1.0.0 #1946 (A1) — the SANCTIONED-RESTORE ceremony. Emit ONE
    /// operator-signed `audit.restore_sanctioned` event committing
    /// `{old_head, new_head, gap, timestamp}` so a legitimate DR
    /// snapshot-restore is distinguishable from an attack rollback at
    /// the next `db::open`. The operator signature is the ONLY
    /// discriminator (at the byte level a DR restore IS a rollback).
    RestoreAttest(RestoreAttestArgs),
    /// v1.0.0 #2004 (spec §5.3) — the crypto-agility RE-ANCHOR ceremony.
    /// Countersign the CURRENT `signed_events` chain head under the enrolled
    /// suite and persist it as a signed `re_anchor` checkpoint, so enabling a
    /// stronger / PQ suite later causes zero record rewrites and every
    /// pre-break record stays attributable. Signed by the DISTINCT off-daemon
    /// audit-witness custody key (opt-in — a no-op when none is enrolled).
    ReAnchor(ReAnchorArgs),
    /// v1.0.0 #3016/#3067 — the SINGLE IDEMPOTENT node BRING-UP ceremony.
    ///
    /// A bare store-only migration (memories/links copied, the
    /// `signed_events` audit spine left EMPTY) is NON-certifiable / born
    /// DIRTY: under the certified (`asi-hard`) require-modes an empty spine
    /// convicts on the audit-head WITNESS and identity-LINEAGE verdicts, so
    /// `verify-audit-trail` exits 1. This command runs the EXISTING
    /// operator-ceremony enrollment (identity-lineage GENESIS + audit-head
    /// witness anchor) over the LOCAL sqlite store, then REFUSES to report
    /// the node certified until `verify-audit-trail` exits 0 — printing the
    /// exact remaining ceremony on a refusal.
    ///
    /// Idempotent: re-running a brought-up node re-emits no genesis (it
    /// already exists), the witness force-emit is a no-op at a re-emitted
    /// head, and it simply re-verifies. It NEVER copies or re-signs
    /// `signed_events` across a migration (a chain-identity/`db_id` fork is
    /// irreversible-if-wrong, #3067), and it mints NO distinct-custody trust
    /// — witness / recorder / judge / stopper keys stay operator custody;
    /// bring-up VERIFIES them and names any that are missing, it never forges
    /// them. The POSTGRES spine-write twin is deferred (like the pg
    /// re-anchor twin #2217); its verify GATE already has a pg twin.
    BootstrapNode(BootstrapNodeArgs),
}

#[derive(Args)]
pub struct ShowArgs {
    /// Restrict to capability-expansion events (today the only event
    /// type written to audit_log; reserves the option for future
    /// event types).
    #[arg(long)]
    pub capability_expansions: bool,
    /// Filter by exact principal (agent id). Deliberately NOT named
    /// `--agent-id` and NOT env-backed (#3017): clap's global
    /// `--agent-id` (`env = AI_MEMORY_AGENT_ID`) would otherwise
    /// overwrite this filter under the certified posture.
    #[arg(long = "principal", value_name = "AGENT_ID")]
    pub principal: Option<String>,
    /// Maximum rows to return (default 50, max 10000).
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Override the configured audit log path.
    #[arg(long)]
    pub path: Option<String>,
    /// Emit a JSON report instead of text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// v0.7.0 #697 — verify the **forensic** governance-decision log
    /// (Ed25519-signed, daily-rotated `forensic-<YYYY-MM-DD>.jsonl`)
    /// from the supplied ISO date forward. Walks every file at or
    /// after `<YYYY-MM-DD>` under the resolved forensic directory
    /// (`<audit_dir>/` by default; overridable via the global
    /// `--audit-dir` flag). Mutually exclusive with the default
    /// hash-chain verifier (which operates on the flat `audit.log`).
    #[arg(long, value_name = "ISO_DATE")]
    pub since: Option<String>,
    /// v0.7.0 #697 — agent_id whose Ed25519 public key is used to
    /// verify signatures on the forensic log. Defaults to the
    /// resolved daemon agent_id (same precedence as the rest of the
    /// CLI). Use the matching `--agent-id` if your daemon signs under
    /// a non-default identity.
    #[arg(long, value_name = "AGENT_ID")]
    pub forensic_agent_id: Option<String>,
}

#[derive(Args)]
pub struct TailArgs {
    /// Override the configured audit log path.
    #[arg(long)]
    pub path: Option<String>,
    /// Number of trailing lines to print. Default 50.
    #[arg(long, default_value_t = 50)]
    pub lines: usize,
    /// Filter by `actor.agent_id`.
    #[arg(long)]
    pub actor: Option<String>,
    /// Filter by `target.namespace`.
    #[arg(long)]
    pub namespace: Option<String>,
    /// Filter by `action`.
    #[arg(long)]
    pub action: Option<String>,
    /// Output format: `json` (default) or `text`.
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// v1.0.0 #1946 (A1) — arguments for `ai-memory audit restore-attest`.
#[derive(Args)]
pub struct RestoreAttestArgs {
    /// Actually SIGN + emit the sanction. Without `--sign` this is a
    /// dry-run that prints the `{old_head, new_head, gap}` it WOULD
    /// attest so an operator can review before committing.
    #[arg(long)]
    pub sign: bool,
    /// Operator key directory (holds `operator.key`/`operator.priv`).
    /// Defaults to the resolved key dir (`AI_MEMORY_KEY_DIR` → platform
    /// default). The operator key's private half signs the sanction.
    #[arg(long, value_name = "PATH")]
    pub key_dir: Option<std::path::PathBuf>,
    /// Emit a JSON summary instead of the human-readable line.
    #[arg(long)]
    pub json: bool,
}

/// v1.0.0 #2004 — arguments for `ai-memory audit re-anchor`.
#[derive(Args)]
pub struct ReAnchorArgs {
    /// Emit a JSON summary instead of the human-readable line.
    #[arg(long)]
    pub json: bool,
}

/// v1.0.0 #3016/#3067 — arguments for `ai-memory audit bootstrap-node`.
#[derive(Args)]
pub struct BootstrapNodeArgs {
    /// Agent identifier whose identity-lineage genesis anchors this node.
    /// Defaults to the resolved NHI daemon id (same precedence as the rest
    /// of the CLI).
    #[arg(long)]
    pub agent_id: Option<String>,
    /// Key storage directory holding the agent's Ed25519 keypair (the key
    /// that self-signs the lineage genesis). Defaults to `AI_MEMORY_KEY_DIR`
    /// → the platform key dir. Run `ai-memory identity generate` first.
    #[arg(long, value_name = "PATH")]
    pub key_dir: Option<std::path::PathBuf>,
    /// Base64 Ed25519 RECOVERY public key committed into the lineage genesis
    /// (#1949 — REQUIRED to enroll a NEW lineage so a stolen-and-lost key is
    /// recoverable). Not needed on an idempotent re-run of an
    /// already-enrolled node.
    #[arg(long, value_name = "PUBKEY_B64")]
    pub recovery_pubkey: Option<String>,
    /// v1.0.0 #3061 F3 — the store this node runs on, mirroring `serve`'s
    /// `--store-url`. Bring-up MUST target the SAME store `serve` opens, so
    /// this honours the identical resolution ladder
    /// (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` > this argv). A
    /// `postgres://` DSN here (or from those env channels) FAIL-CLOSES: the pg
    /// spine-write bring-up twin is deferred (#2217-class). Omit on a local
    /// sqlite node.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
    /// Emit a JSON summary instead of the human-readable lines.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory audit` entry point. Returns the desired process exit
/// code so the caller can surface a non-zero status from the top-level
/// dispatch without panicking.
///
/// v1.0.0 #3429 — `db_path` is the ONE store path the top-level parser
/// already resolved (`app_config.effective_db(&cli.db)` in
/// `daemon_runtime::run`), threaded in from the caller exactly like every
/// other subcommand (`wrap`, `governance`, …). The store-touching verbs
/// (`show`, `restore-attest`, `re-anchor`, `bootstrap-node`) take that
/// `&Path` and NOT an `&AppConfig`, so they structurally CANNOT re-resolve
/// a store of their own: the pre-fix `effective_db(DEFAULT_DB)` recompute
/// discarded a non-default `--db` / `AI_MEMORY_DB` (that helper only honours
/// a `cli_db` differing from the `"ai-memory.db"` literal) and both READ and
/// WROTE the config-resolved database instead — the same misfiling class
/// #1991 closed in `build_embedder` / `build_llm_client`.
pub fn run(
    db_path: &Path,
    args: AuditArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let audit_dir = args.audit_dir.clone();
    match args.action {
        AuditAction::Verify(v) => run_verify(&v, audit_dir.as_deref(), app_config, out),
        AuditAction::Tail(t) => run_tail(&t, audit_dir.as_deref(), app_config, out),
        AuditAction::Path => run_path(audit_dir.as_deref(), app_config, out),
        AuditAction::Show(s) => run_show(&s, db_path, out),
        AuditAction::RestoreAttest(r) => run_restore_attest(&r, db_path, out),
        AuditAction::ReAnchor(r) => run_re_anchor(&r, db_path, out),
        AuditAction::BootstrapNode(b) => run_bootstrap_node(&b, db_path, out),
    }
}

/// v1.0.0 #3016/#3067 — `ai-memory audit bootstrap-node`. See
/// [`AuditAction::BootstrapNode`] for the full contract. Returns the desired
/// process exit code: `0` once the node's audit spine verifies CLEAN
/// (certified-ready), `1` when the node is still born-dirty (the remaining
/// operator ceremony is printed). A hard error (DB open, keypair load, an
/// enrollment failure) propagates as `Err`.
fn run_bootstrap_node(
    args: &BootstrapNodeArgs,
    db_path: &Path,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    use anyhow::Context;

    // #3067 — bring-up WRITES the LOCAL sqlite `signed_events` spine only.
    // A postgres-backed node's spine-write twin is deferred (the pg
    // signed_events GENESIS/witness ceremony, tracked like the pg re-anchor
    // twin #2217). Its verify GATE already has a pg twin
    // (`verify_audit_trail_postgres`), so a pg node here FAIL-CLOSES.
    //
    // #3061 F2/F3 — resolve the store via the FULL ladder INCLUDING the
    // `--store-url` argv (`serve`'s channel), so a `serve --store-url pg://…`
    // node is not invisible here. FAIL-CLOSED on THREE dispositions:
    //   - Ok(Some(pg))  -> refuse (deferred pg twin, above).
    //   - Err(_)        -> refuse: the backend is INDETERMINATE (e.g. a
    //                      lax-perms STORE_URL_FILE), and we must never write
    //                      the local sqlite sidecar of an unknown store.
    //   - Ok(Some(sqlite://…)) / Ok(None) -> proceed (local sqlite bring-up).
    let refuse_pg = |out: &mut CliOutput<'_>, msg: &str, reason: &str| -> Result<i32> {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({
                    "bootstrap_node": false,
                    "certified_ready": false,
                    "reason": reason,
                })
            )?;
        }
        writeln!(out.stderr, "bootstrap-node: {msg}")?;
        Ok(1)
    };
    match crate::store_url::resolve_store_url(args.store_url.as_deref()) {
        Ok(Some(url)) if crate::store_url::is_postgres_url(&url) => {
            return refuse_pg(
                out,
                "the resolved store is POSTGRES. The pg signed_events spine-write bring-up twin \
                 is deferred (like the pg re-anchor twin #2217); refusing to certify rather than \
                 write the wrong (local sqlite) store. Run the pg node's operator enrollment \
                 ceremonies, then confirm with `ai-memory verify-audit-trail --store-url <dsn>` \
                 (exit 0).",
                "pg_spine_write_twin_deferred",
            );
        }
        Err(e) => {
            return refuse_pg(
                out,
                &format!(
                    "could not resolve the store URL, so the backend is INDETERMINATE; refusing \
                     to write the local sqlite store of an unknown backend (fail-closed): {e:#}"
                ),
                "store_url_indeterminate",
            );
        }
        Ok(_) => {} // sqlite:// URL or no URL — proceed with local sqlite bring-up.
    }

    let conn = crate::db::open(db_path)
        .with_context(|| format!("bootstrap-node: open db at {}", db_path.display()))?;

    let agent_id = crate::identity::resolve_agent_id(args.agent_id.as_deref(), None)
        .context("bootstrap-node: resolve agent_id")?;

    // ---- Step 1: identity-lineage GENESIS (idempotent) ----------------
    // `enroll_lineage` itself refuses a second genesis; we pre-check
    // `lineage_head` so a brought-up node re-runs cleanly WITHOUT needing
    // `--recovery-pubkey` again.
    let lineage_already = crate::db::lineage_head(&conn, &agent_id)
        .context("bootstrap-node: read lineage head")?
        .is_some();
    let lineage_action = if lineage_already {
        "already-enrolled"
    } else {
        let key_dir = match &args.key_dir {
            Some(p) => p.clone(),
            None => crate::identity::keypair::default_key_dir()
                .context("bootstrap-node: resolve key dir")?,
        };
        let kp = crate::identity::keypair::load(&agent_id, &key_dir).with_context(|| {
            format!(
                "bootstrap-node: load keypair for {agent_id} (run `ai-memory identity generate` \
                 first)"
            )
        })?;
        let recovery = args.recovery_pubkey.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "bootstrap-node: --recovery-pubkey <B64> is REQUIRED to enroll a NEW identity \
                 lineage (#1949) so a stolen-and-lost key is recoverable"
            )
        })?;
        crate::db::enroll_lineage(&conn, &agent_id, &kp, Some(recovery))
            .context("bootstrap-node: enroll identity-lineage genesis")?;
        "enrolled"
    };

    // ---- Step 2: audit-head WITNESS anchor (idempotent) ---------------
    // No-op when no witness custody key is enrolled (AI_MEMORY_WITNESS_KEY_DIR)
    // or the head is empty; a real emit is throttle-bypassing but at-head
    // idempotent. An unloadable-but-enrolled key surfaces as an Err.
    crate::signed_events::try_force_emit_audit_head_witness(&conn)
        .context("bootstrap-node: force-emit audit-head witness anchor")?;

    // ---- Step 3: verify GATE under the CERTIFIED require-modes ---------
    // MB1 (review, 2026-08-20): `verify_audit_trail` only DIRTIES a lane whose
    // require-mode is armed IN THIS PROCESS ENV. bootstrap-node arms none, so a
    // bare provisioning shell would verify a witness-less / role-separation-less
    // spine as `is_clean() == true` and FALSE-CERTIFY it. bootstrap-node IS the
    // spine-cert gate (serve does not re-verify at boot; #17 attests env, not
    // spine content), so its verdict is load-bearing and must reflect the
    // CERTIFIED asi-hard audit require-mode set, not the ambient env.
    //
    // FAIL-CLOSED: the node is CERTIFIED-READY only when ALL THREE certified
    // audit require-modes are armed in THIS process (so the verify actually
    // exercised the witness / role-separation / identity-lineage lanes) AND the
    // verify is clean under them. If the modes are not armed we CANNOT claim
    // certified — we name what to arm. If they are armed but the verify is
    // dirty we name the remaining ceremony. The success label names EXACTLY
    // which modes were armed for the verdict so an auditor sees the seam.
    let witness_armed = crate::governance::audit::require_witness_enabled();
    let role_armed = crate::governance::audit::require_role_separation_enabled();
    let lineage_armed = crate::identity::lineage::require_identity_lineage_enabled();
    let armed_modes: Vec<&str> = [
        witness_armed.then_some("witness"),
        role_armed.then_some("role_separation"),
        lineage_armed.then_some("identity_lineage"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let unarmed_modes: Vec<&str> = [
        (!witness_armed).then_some("AI_MEMORY_REQUIRE_WITNESS"),
        (!role_armed).then_some("AI_MEMORY_REQUIRE_ROLE_SEPARATION"),
        (!lineage_armed).then_some("AI_MEMORY_REQUIRE_IDENTITY_LINEAGE"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let all_modes_armed = unarmed_modes.is_empty();

    let report = crate::signed_events::verify_audit_trail(&conn, None, None)
        .context("bootstrap-node: verify_audit_trail over signed_events")?;
    let verify_clean = report.is_clean();
    let certified = verify_clean && all_modes_armed;

    // Refusal reasons (fail-closed), most-fundamental first.
    let remaining: Vec<String> = if certified {
        Vec::new()
    } else if !all_modes_armed {
        vec![format!(
            "the certified audit require-modes are NOT all armed in this process, so the verify \
             did not exercise every lane — cannot claim certified. Arm them (set \
             AI_MEMORY_SECURITY_PROFILE=asi-hard, or set {} =1) and re-run. Armed now: [{}].",
            unarmed_modes.join(" / "),
            armed_modes.join(", "),
        )]
    } else {
        bring_up_remaining(&report)
    };

    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "bootstrap_node": true,
                "backend": "sqlite",
                "db": db_path.display().to_string(),
                "agent_id": agent_id,
                "lineage_genesis": lineage_action,
                "armed_require_modes": armed_modes,
                "all_certified_modes_armed": all_modes_armed,
                "verify_clean": verify_clean,
                "certified_ready": certified,
                "remaining": remaining,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "ai-memory audit bootstrap-node (v1.0.0 #3016/#3067 — node bring-up ceremony)"
        )?;
        writeln!(out.stdout, "  db:              {}", db_path.display())?;
        writeln!(out.stdout, "  agent_id:        {agent_id}")?;
        writeln!(out.stdout, "  lineage-genesis: {lineage_action}")?;
        writeln!(
            out.stdout,
            "  witness-anchor:  force-emitted (no-op without an enrolled witness custody key)"
        )?;
        writeln!(
            out.stdout,
            "  armed modes:     [{}]",
            if armed_modes.is_empty() {
                "none".to_string()
            } else {
                armed_modes.join(", ")
            }
        )?;
        writeln!(out.stdout)?;
        if certified {
            writeln!(
                out.stdout,
                "  CERTIFIED-READY: verify-audit-trail is CLEAN under the certified audit \
                 require-modes [{}] (exit 0) — the audit spine satisfies every armed lane and \
                 this node is no longer born-dirty.",
                armed_modes.join(", ")
            )?;
        } else {
            writeln!(
                out.stderr,
                "  NOT CERTIFIED (exit 1) — this node is NOT certifiable until every item below \
                 clears:"
            )?;
            for r in &remaining {
                writeln!(out.stderr, "    - {r}")?;
            }
        }
    }

    Ok(i32::from(!certified))
}

/// Map the dirtying verdicts of a [`crate::signed_events::AuditTrailReport`]
/// to the EXACT remaining operator ceremony, so a bring-up REFUSAL names what
/// is left rather than a bare "dirty". Mirrors the `is_clean` predicate's
/// dirtying arms; every item is an operator action, never a silent auto-fix.
fn bring_up_remaining(report: &crate::signed_events::AuditTrailReport) -> Vec<String> {
    use crate::signed_events::{
        CauseBinding, HeadHashCheck, RoleSeparationCheck, RollbackCheck, TruncationCheck,
        WitnessCheck,
    };
    let mut v: Vec<String> = Vec::new();
    if !report.chain_intact {
        v.push(
            "signed_events hash chain is BROKEN — triage with `ai-memory verify-audit-trail`; \
             do NOT certify"
                .to_string(),
        );
    }
    if !report.sequence_gaps.is_empty() {
        v.push(
            "signed_events has sequence GAPS — triage with `ai-memory verify-audit-trail`; do \
             NOT certify"
                .to_string(),
        );
    }
    if matches!(report.truncation, TruncationCheck::Detected { .. }) {
        v.push(
            "audit tail TRUNCATION detected by the off-table anchor (a wipe-to-empty is \
             convicted) — do NOT certify"
                .to_string(),
        );
    }
    if matches!(report.head_hash, HeadHashCheck::Mismatch { .. }) {
        v.push(
            "audit head-hash MISMATCH (a same-length suffix rewrite at equal sequence) — do NOT \
             certify"
                .to_string(),
        );
    }
    if matches!(
        report.witness,
        WitnessCheck::Missing | WitnessCheck::Detected { .. } | WitnessCheck::Forged { .. }
    ) {
        v.push(
            "audit-head WITNESS anchor unsatisfied — enrol a witness custody key \
             (AI_MEMORY_WITNESS_KEY_DIR) and re-run bootstrap-node so the head anchor is emitted"
                .to_string(),
        );
    }
    if matches!(
        report.role_separation,
        RoleSeparationCheck::Missing
            | RoleSeparationCheck::Misconfigured { .. }
            | RoleSeparationCheck::Forged { .. }
    ) {
        v.push(
            "three-key ROLE SEPARATION unsatisfied — enrol DISTINCT recorder/judge/stopper \
             custody keys (AI_MEMORY_RECORDER_KEY_DIR / _JUDGE_KEY_DIR / _STOPPER_KEY_DIR); \
             bring-up VERIFIES role separation, it never mints these distinct-custody keys"
                .to_string(),
        );
    }
    if matches!(
        report.lineage,
        crate::identity::lineage::LineageCheck::Missing
            | crate::identity::lineage::LineageCheck::Forged { .. }
    ) {
        v.push(
            "identity LINEAGE unsatisfied — re-run bootstrap-node with --recovery-pubkey, or \
             repair the lineage chain"
                .to_string(),
        );
    }
    if matches!(
        report.rollback,
        RollbackCheck::Evidence { .. } | RollbackCheck::Missing
    ) {
        v.push(
            "ROLLBACK verdict unsatisfied (AI_MEMORY_REQUIRE_ROLLBACK_CHECK) — either a \
             wiped/rolled-back chain, or a missing head anchor; triage before certifying"
                .to_string(),
        );
    }
    if matches!(report.cause_binding, CauseBinding::Detected { .. }) {
        v.push(
            "cause-binding coverage incomplete (AI_MEMORY_REQUIRE_CAUSE_BINDING) — rows without \
             a bound cause_hash were detected"
                .to_string(),
        );
    }
    if v.is_empty() {
        v.push(
            "verify-audit-trail reported dirty — run `ai-memory verify-audit-trail --json` for \
             the full verdict set"
                .to_string(),
        );
    }
    v
}

#[cfg(test)]
mod bring_up_remaining_tests {
    //! v1.0.0 #3016/#3067 — exhaustive per-branch coverage of
    //! [`bring_up_remaining`] via synthetic [`AuditTrailReport`]s (the
    //! bring-up refusal path only reaches this fn when ALL certified
    //! require-modes are armed AND the verify is dirty — MB1 — so the
    //! truncation/head_hash/cause_binding/rollback branches are not otherwise
    //! exercised by the integration suite).
    use super::bring_up_remaining;
    use crate::identity::lineage::LineageCheck;
    use crate::signed_events::{
        AuditTrailReport, CauseBinding, HeadHashCheck, RoleSeparationCheck, RollbackCheck,
        SignatureCheck, TruncationCheck, WitnessCheck,
    };

    /// A fully CLEAN report — every lane at its non-dirtying variant.
    fn clean_report() -> AuditTrailReport {
        AuditTrailReport {
            total_events: 1,
            chain_intact: true,
            first_break_sequence: None,
            sequence_gaps: vec![],
            head_sequence: 1,
            since: None,
            truncation: TruncationCheck::NotDetected,
            witness: WitnessCheck::NotDetected,
            cause_binding: CauseBinding::NotDetected,
            signature_failures: vec![],
            role_separation: RoleSeparationCheck::NotDetected,
            lineage: LineageCheck::NotDetected,
            rollback: RollbackCheck::NotDetected,
            head_hash: HeadHashCheck::NotDetected,
            signature_check: SignatureCheck::Unenforced {
                checked: 0,
                unverified: 0,
            },
        }
    }

    #[test]
    fn clean_report_yields_the_fallback_only_when_forced() {
        // A clean report never reaches bring_up_remaining in production, but if
        // it did, it returns exactly the one honest fallback line (never empty).
        let r = clean_report();
        let out = bring_up_remaining(&r);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("reported dirty"));
    }

    #[test]
    fn each_dirty_verdict_names_its_own_remaining_ceremony() {
        // (mutation, substring the remaining list must contain)
        let cases: Vec<(Box<dyn Fn(&mut AuditTrailReport)>, &str)> = vec![
            (Box::new(|r| r.chain_intact = false), "chain is BROKEN"),
            (
                Box::new(|r| r.sequence_gaps = vec![(1, 3)]),
                "sequence GAPS",
            ),
            (
                Box::new(|r| {
                    r.truncation = TruncationCheck::Detected {
                        anchored_head: 5,
                        db_head: 2,
                    };
                }),
                "TRUNCATION",
            ),
            (
                Box::new(|r| {
                    r.head_hash = HeadHashCheck::Mismatch {
                        chain: "sqlite:signed_events".to_string(),
                        detail: "suffix rewrite".to_string(),
                    };
                }),
                "head-hash MISMATCH",
            ),
            (
                Box::new(|r| r.witness = WitnessCheck::Missing),
                "WITNESS anchor",
            ),
            (
                Box::new(|r| r.role_separation = RoleSeparationCheck::Missing),
                "ROLE SEPARATION",
            ),
            (
                Box::new(|r| r.lineage = LineageCheck::Missing),
                "identity LINEAGE",
            ),
            (
                Box::new(|r| r.rollback = RollbackCheck::Missing),
                "ROLLBACK",
            ),
            (
                Box::new(|r| {
                    r.cause_binding = CauseBinding::Detected {
                        rows_without_cause: 4,
                    };
                }),
                "cause-binding",
            ),
        ];
        for (mutate, needle) in cases {
            let mut r = clean_report();
            mutate(&mut r);
            let out = bring_up_remaining(&r);
            assert!(
                out.iter().any(|s| s.contains(needle)),
                "a dirty verdict must name {needle:?}; got {out:?}"
            );
            // A single dirty lane yields exactly ONE remaining item (never the
            // fallback), proving the branches are independent.
            assert_eq!(
                out.len(),
                1,
                "one dirty lane -> one remaining item: {out:?}"
            );
        }
    }
}

/// The chain label the sqlite-endpoint re-anchor ceremony anchors — printed
/// on every disposition so an operator on a POSTGRES-backed deployment (whose
/// pg `signed_events` chain has NO re-anchor twin yet — issue #2217, PR #2214
/// audit F2) can never mistake a local-sqlite anchor for a pg-chain ceremony.
const REANCHOR_CHAIN_LABEL: &str = "sqlite:signed_events";

/// v1.0.0 #2004 (spec §5.3) — the crypto-agility re-anchor ceremony for the
/// LOCAL sqlite `signed_events` chain (the pg twin is issue #2217). Reads the
/// current head, countersigns it under the enrolled suite with the
/// audit-witness custody key, and persists a signed `re_anchor` checkpoint.
/// The anchor is then RELOADED from the database (`checkpoints::get`, PR
/// #2214 audit F3 — the persisted row, never the in-memory copy) and
/// self-verified via the read-back path (K1-pinned to the enrolled witness
/// pubkey) so the operator sees the true ceremony round-trip.
fn run_re_anchor(args: &ReAnchorArgs, db_path: &Path, out: &mut CliOutput<'_>) -> Result<i32> {
    use crate::signed_events::ReAnchorOutcome;
    use anyhow::Context;
    let conn = crate::db::open(db_path)
        .with_context(|| format!("audit re-anchor: open db at {}", db_path.display()))?;
    let outcome =
        crate::signed_events::emit_reanchor_ceremony(&conn).context("emit re-anchor ceremony")?;
    // Opt-in no-ops (nothing enrolled / nothing to anchor) exit 0; an
    // UNLOADABLE enrolled key is a ceremony FAILURE (exit 1, distinct
    // reason — PR #2214 audit F4). Every disposition is EXPLICIT on
    // stdout in JSON mode — an automation invoking `--json` must never
    // have to distinguish "skipped" from "crashed" by an empty stdout.
    match &outcome {
        ReAnchorOutcome::Anchored(_) => {}
        skip @ (ReAnchorOutcome::SkippedNoCustody | ReAnchorOutcome::SkippedEmptyChain) => {
            let reason = skip.reason_tag().unwrap_or_default();
            if args.json {
                let obj = serde_json::json!({
                    "status": "skipped",
                    "reason": reason,
                    "db": db_path.display().to_string(),
                    "chain": REANCHOR_CHAIN_LABEL,
                });
                writeln!(out.stdout, "{obj}")?;
            }
            let guidance = if matches!(skip, ReAnchorOutcome::SkippedNoCustody) {
                "no audit-witness custody enrolled — enrol a signing key \
                 (AI_MEMORY_WITNESS_KEY_DIR) to run the ceremony"
            } else {
                "the signed_events chain is empty — nothing to anchor"
            };
            writeln!(
                out.stderr,
                "re-anchor SKIPPED ({reason}) on db {} (chain {REANCHOR_CHAIN_LABEL}): \
                 {guidance}",
                db_path.display()
            )?;
            return Ok(0);
        }
        fail @ ReAnchorOutcome::KeyUnloadable(detail) => {
            let reason = fail.reason_tag().unwrap_or_default();
            if args.json {
                let obj = serde_json::json!({
                    "status": "error",
                    "reason": reason,
                    "detail": detail,
                    "db": db_path.display().to_string(),
                    "chain": REANCHOR_CHAIN_LABEL,
                });
                writeln!(out.stdout, "{obj}")?;
            }
            writeln!(
                out.stderr,
                "re-anchor FAILED ({reason}): a witness key IS enrolled but could not be \
                 loaded ({detail}); repair the custody under AI_MEMORY_WITNESS_KEY_DIR — \
                 nothing was persisted"
            )?;
            return Ok(1);
        }
        // v1.0.0 #2242 — the pre-countersign verify found the chain DIRTY:
        // the ceremony REFUSES rather than blessing tampered history with a
        // fresh signed anchor. Distinct reason + non-zero exit (the #2214 F4
        // discipline: a refusal is a FAILURE the operator must see, never a
        // skip). Nothing was persisted.
        fail @ ReAnchorOutcome::RefusedChainDirty(detail) => {
            let reason = fail.reason_tag().unwrap_or_default();
            if args.json {
                let obj = serde_json::json!({
                    "status": "error",
                    "reason": reason,
                    "detail": detail,
                    "db": db_path.display().to_string(),
                    "chain": REANCHOR_CHAIN_LABEL,
                });
                writeln!(out.stdout, "{obj}")?;
            }
            writeln!(
                out.stderr,
                "re-anchor REFUSED ({reason}): the signed_events chain FAILED verification \
                 BEFORE countersigning ({detail}); run `ai-memory verify-audit-trail` to \
                 triage the tamper evidence — nothing was persisted"
            )?;
            return Ok(1);
        }
    }
    let ReAnchorOutcome::Anchored(cp) = outcome else {
        unreachable!("non-Anchored outcomes returned above");
    };
    let cp = *cp;
    // PR #2214 audit F3 — the self-verify must READ BACK the persisted row
    // (the same reload a fresh verifier performs), so a future insert /
    // row-decode defect corrupting `resolution` / `signature` /
    // `resolver_pubkey` is caught here, not just the in-memory struct.
    let persisted = crate::checkpoints::get(&conn, &cp.id)
        .with_context(|| format!("re-anchor: reload persisted anchor {}", cp.id))?;
    // THREE-STATE + fail-closed: a verify FAILURE (e.g. enrolment drift where
    // the enrolled pubkey does not match the custody signing key) MUST be
    // distinguishable from "no pubkey enrolled to pin against", and MUST
    // surface a non-zero exit so the operator sees a
    // persisted-but-unverifiable anchor, not a silent "ok".
    let readback = match persisted {
        None => ReadBack::RowMissing,
        Some(row) => match crate::governance::audit::load_enrolled_witness_pubkey()? {
            Some(vk) => match crate::governance::audit::verify_reanchor_checkpoint(&row, &vk) {
                Ok(_) => ReadBack::Pass,
                Err(e) => ReadBack::Fail(e),
            },
            None => ReadBack::NoPin,
        },
    };
    let exit = match readback {
        ReadBack::Pass | ReadBack::NoPin => 0,
        ReadBack::Fail(_) | ReadBack::RowMissing => 1,
    };
    if args.json {
        let mut obj = serde_json::json!({
            "status": if exit == 0 { "ok" } else { "verify_failed" },
            crate::cli::JSON_KEY_CHECKPOINT_ID: cp.id,
            "namespace": cp.namespace,
            "db": db_path.display().to_string(),
            "chain": REANCHOR_CHAIN_LABEL,
            "verified": matches!(readback, ReadBack::Pass),
            "readback": readback.machine_tag(),
        });
        if let ReadBack::Fail(e) = &readback {
            obj["error"] = serde_json::Value::String(e.tag().to_string());
        }
        writeln!(out.stdout, "{obj}")?;
    } else {
        let line = match &readback {
            ReadBack::Pass => "PASS".to_string(),
            ReadBack::NoPin => {
                "unverified (no enrolled witness pubkey — set AI_MEMORY_WITNESS_PUBKEY to K1-pin)"
                    .to_string()
            }
            ReadBack::RowMissing => {
                "FAILED (persisted anchor row could not be reloaded from the database)".to_string()
            }
            ReadBack::Fail(e) => format!(
                "FAILED ({}) — the persisted anchor did NOT verify against the enrolled \
                 witness pubkey; check AI_MEMORY_WITNESS_PUBKEY matches the custody signing key",
                e.tag()
            ),
        };
        writeln!(
            out.stdout,
            "re-anchor {}: crypto-agility ceremony anchor {} recorded (namespace {}, db {}, \
             chain {REANCHOR_CHAIN_LABEL}); read-back verify: {line}",
            if exit == 0 { "OK" } else { "WARN" },
            cp.id,
            cp.namespace,
            db_path.display()
        )?;
    }
    Ok(exit)
}

/// Disposition of the `audit re-anchor` self-verify READ-BACK (the persisted
/// row reloaded via `checkpoints::get`, PR #2214 audit F3). Distinguishes a
/// genuine K1 PASS, an absent enrolled pubkey (nothing to pin against — not a
/// failure), a reload miss (`RowMissing` — the insert claimed success but the
/// row cannot be read back; fail-closed, exit 1), and an actual verify
/// FAILURE (fail-closed, exit 1).
///
/// `NoPin` is DEFENSIVE in the current shared-custody layout: an emitted
/// ceremony implies `keypair::load` succeeded, which requires the same
/// `<label>.pub` the pubkey fallback reads, so post-emit the pin always
/// resolves (env or file). The variant is kept fail-safe against a future
/// divergence of the two loaders (e.g. a PQ key in separate custody) — if it
/// ever fires, the operator sees "unverified", never a silent `ok`.
enum ReadBack {
    Pass,
    NoPin,
    RowMissing,
    Fail(crate::governance::audit::ReAnchorCheckpointError),
}

impl ReadBack {
    /// Stable machine-readable tag for the JSON `readback` field.
    fn machine_tag(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::NoPin => "no_enrolled_pubkey",
            Self::RowMissing => "row_missing",
            Self::Fail(_) => "fail",
        }
    }
}

/// v1.0.0 #1946 (A1) — the sanctioned-restore ceremony. Reads the
/// off-table witness anchor high-water (`old_head`) + the surviving in-DB
/// head (`new_head`); with `--sign` it signs a `{old_head, new_head, gap,
/// timestamp}` record under the OPERATOR key and appends it to the
/// off-table sanction log so the open-time check clears the rollback
/// evidence for that DR window.
fn run_restore_attest(
    args: &RestoreAttestArgs,
    db_path: &Path,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    use anyhow::{Context, bail};
    let conn = crate::db::open(db_path)
        .with_context(|| format!("audit restore-attest: open db at {}", db_path.display()))?;
    let db_head: i64 = conn
        .query_row(crate::signed_events::CHAIN_HEAD_SQL, [], |row| row.get(0))
        .unwrap_or(0);
    // #2370 — this database's genesis-derived identity: scopes BOTH the
    // anchor high-water read below AND the signed sanction record, so the
    // ceremony can neither read a sibling database's anchors nor mint a
    // sanction replayable against one.
    let db_id = crate::signed_events::genesis_db_id(&conn).ok().flatten();
    let Some(old_head) = crate::governance::audit::read_head_anchor_high_water(db_id.as_deref())
    else {
        bail!(
            "no pinnable off-table head anchor to attest against — enrol a witness key \
             (AI_MEMORY_WITNESS_KEY_DIR + AI_MEMORY_WITNESS_PUBKEY) and let the daemon anchor a head first"
        );
    };
    let new_head = db_head;
    let gap = old_head.saturating_sub(new_head);
    if gap <= 0 {
        writeln!(
            out.stderr,
            "restore-attest: in-DB head ({new_head}) is not below the anchor ({old_head}) — \
             there is no rollback to sanction"
        )?;
        return Ok(0);
    }
    if !args.sign {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({
                    "status": "dry_run",
                    "old_head": old_head,
                    "new_head": new_head,
                    "gap": gap,
                })
            )?;
        } else {
            writeln!(
                out.stdout,
                "restore-attest (dry-run): would sanction restore old_head={old_head} \
                 new_head={new_head} gap={gap} — re-run with --sign to emit"
            )?;
        }
        return Ok(0);
    }
    let key_dir = match &args.key_dir {
        Some(p) => p.clone(),
        None => crate::identity::keypair::default_key_dir().context("resolve operator key dir")?,
    };
    let signing = crate::cli::rules::load_operator_signing_key_from_dir(&key_dir)
        .context("load operator signing key for restore-attest")?;
    let now = chrono::Utc::now().timestamp();
    let line = crate::governance::audit::sign_restore_sanction(
        old_head,
        new_head,
        now,
        &signing,
        db_id.as_deref(),
    )
    .context("sign restore sanction")?;
    crate::governance::audit::append_restore_sanction(&line)
        .context("append restore sanction to off-table log")?;
    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "status": "ok",
                "old_head": old_head,
                "new_head": new_head,
                "gap": gap,
                "timestamp": now,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "restore-attest OK: operator-signed sanction recorded — restore {old_head} -> \
             {new_head} (gap {gap}); the open-time rollback check will treat this DR window as cleared"
        )?;
    }
    Ok(0)
}

/// v0.6.4-009 — print rows from the `audit_log` SQLite table.
fn run_show(args: &ShowArgs, db_path: &Path, out: &mut CliOutput<'_>) -> Result<i32> {
    let conn = crate::db::open(db_path)?;
    let rows = crate::db::list_capability_expansions(&conn, args.limit, args.principal.as_deref())?;
    if args.json {
        let payload: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "agent_id": r.agent_id,
                    "event_type": r.event_type,
                    "requested_family": r.requested_family,
                    "granted": r.granted,
                    "attestation_tier": r.attestation_tier,
                    "timestamp": r.timestamp,
                })
            })
            .collect();
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(0);
    }
    if rows.is_empty() {
        writeln!(out.stdout, "audit_log: no rows")?;
        return Ok(0);
    }
    writeln!(
        out.stdout,
        "{:<25} {:<7} {:<12} {:<32} {:<6}",
        "timestamp", "granted", "family", "agent_id", "event"
    )?;
    for r in &rows {
        let aid = r.agent_id.as_deref().unwrap_or("<anonymous>");
        let fam = r.requested_family.as_deref().unwrap_or("-");
        writeln!(
            out.stdout,
            "{:<25} {:<7} {:<12} {:<32} {:<6}",
            r.timestamp,
            if r.granted { "ALLOW" } else { "DENY" },
            fam,
            aid,
            r.event_type
        )?;
    }
    Ok(0)
}

/// Resolve the audit log path honouring (in order): explicit per-subcommand
/// `--path` (legacy `VerifyArgs.path` / `TailArgs.path`), the global
/// `--audit-dir` flag, `AI_MEMORY_AUDIT_DIR`, `[audit] path` in
/// config.toml, and the platform default. Falls back to the loose
/// `resolve_audit_path` if any layer above produces an error so the
/// `audit path` subcommand can still print a useful answer when
/// `--audit-dir` is mistyped.
fn resolve_path(
    app_config: &AppConfig,
    cli_audit_dir: Option<&std::path::Path>,
    explicit_per_cmd: Option<&str>,
) -> std::path::PathBuf {
    if let Some(p) = explicit_per_cmd {
        return std::path::PathBuf::from(crate::audit::expand_tilde(p));
    }
    let cfg = app_config.effective_audit();
    if let Ok((p, _src)) = resolve_audit_path_with_override(cli_audit_dir, &cfg) {
        return p;
    }
    resolve_audit_path(&cfg)
}

fn run_verify(
    args: &VerifyArgs,
    cli_audit_dir: Option<&std::path::Path>,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    // v0.7.0 #697 — forensic verify (Ed25519-signed, daily-rotated)
    // takes priority when `--since` is supplied. The flat `audit.log`
    // verifier ignores the `--since` semantic by design (that log is
    // a single file).
    if let Some(since) = args.since.as_deref() {
        return run_forensic_verify(since, args, cli_audit_dir, app_config, out);
    }
    let path = resolve_path(app_config, cli_audit_dir, args.path.as_deref());
    if !path.exists() {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({
                    "status": "ok",
                    (field_names::TOTAL_LINES): 0,
                    "note": "audit log does not exist (audit may be disabled)",
                    "path": path.display().to_string(),
                })
            )?;
        } else {
            writeln!(
                out.stdout,
                "audit verify: log not present at {} — nothing to check",
                path.display()
            )?;
        }
        return Ok(0);
    }
    let report = verify_chain(&path)?;
    if let Some(failure) = &report.first_failure {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({
                    "status": "fail",
                    (field_names::TOTAL_LINES): report.total_lines,
                    "failure": {
                        "line_number": failure.line_number,
                        "kind": format!("{:?}", failure.kind),
                        "detail": failure.detail,
                    },
                    "path": path.display().to_string(),
                })
            )?;
        } else {
            writeln!(
                out.stderr,
                "audit verify FAIL at line {}: {:?} — {}",
                failure.line_number, failure.kind, failure.detail
            )?;
        }
        return Ok(2);
    }
    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "status": "ok",
                (field_names::TOTAL_LINES): report.total_lines,
                "path": path.display().to_string(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "audit verify OK: {} line(s) verified at {}",
            report.total_lines,
            path.display()
        )?;
    }
    Ok(0)
}

/// v0.7.0 #697 — forensic verify dispatch. Resolves the forensic
/// directory (default = same as the flat audit-log dir), loads the
/// daemon's Ed25519 public key, and walks every
/// `forensic-<YYYY-MM-DD>.jsonl` file at or after `--since`.
///
/// Exit codes mirror the flat verifier:
/// - `0` — chain intact (signed or unsigned)
/// - `2` — at least one row failed
fn run_forensic_verify(
    since: &str,
    args: &VerifyArgs,
    cli_audit_dir: Option<&std::path::Path>,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    // Forensic files live alongside the flat audit.log file — same
    // resolution ladder. Walk-up from the resolved audit log file to
    // its directory.
    let log_path = resolve_path(app_config, cli_audit_dir, args.path.as_deref());
    let dir = log_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Resolve the agent_id whose pubkey signs the forensic log. The
    // operator can override via `--forensic-agent-id` for off-default
    // signers (e.g. an HSM-rotated key). Falls back to the resolved
    // daemon agent_id.
    let agent_id = args
        .forensic_agent_id
        .clone()
        .or_else(|| crate::identity::resolve_agent_id(None, None).ok())
        .unwrap_or_else(|| "ai-memory".to_string());

    let public_key = crate::governance::audit::load_daemon_verifying_key(&agent_id).unwrap_or(None);

    let report = match crate::governance::audit::verify_since(&dir, since, public_key.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            if args.json {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::json!({
                        "status": "error",
                        "since": since,
                        "dir": dir.display().to_string(),
                        "error": e.to_string(),
                    })
                )?;
            } else {
                writeln!(
                    out.stderr,
                    "forensic verify error: {e} (dir={})",
                    dir.display()
                )?;
            }
            return Ok(2);
        }
    };

    if let Some(failure) = &report.first_failure {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({
                    "status": "fail",
                    (field_names::TOTAL_LINES): report.total_lines,
                    "unsigned_lines": report.unsigned_lines,
                    "failure": {
                        "file": failure.file.display().to_string(),
                        "line_number": failure.line_number,
                        "kind": format!("{:?}", failure.kind),
                        "detail": failure.detail,
                    },
                    "since": since,
                    "dir": dir.display().to_string(),
                })
            )?;
        } else {
            writeln!(
                out.stderr,
                "forensic verify FAIL at {}:{} — {:?}: {}",
                failure.file.display(),
                failure.line_number,
                failure.kind,
                failure.detail
            )?;
        }
        return Ok(2);
    }

    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "status": "ok",
                (field_names::TOTAL_LINES): report.total_lines,
                "unsigned_lines": report.unsigned_lines,
                "since": since,
                "dir": dir.display().to_string(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "forensic verify OK: {} line(s) verified since {} ({} unsigned) at {}",
            report.total_lines,
            since,
            report.unsigned_lines,
            dir.display()
        )?;
    }
    Ok(0)
}

fn run_tail(
    args: &TailArgs,
    cli_audit_dir: Option<&std::path::Path>,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let path = resolve_path(app_config, cli_audit_dir, args.path.as_deref());
    if !path.exists() {
        return Ok(0);
    }
    let f = fs::File::open(&path)?;
    let buf = BufReader::new(f);
    let mut keep: Vec<AuditEvent> = Vec::new();
    for line in buf.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<AuditEvent>(&line) else {
            continue;
        };
        if let Some(actor) = &args.actor
            && !ev.actor.agent_id.contains(actor)
        {
            continue;
        }
        if let Some(ns) = &args.namespace
            && ev.target.namespace != *ns
        {
            continue;
        }
        if let Some(action) = &args.action
            && ev.action.as_str() != action
        {
            continue;
        }
        keep.push(ev);
        if keep.len() > args.lines {
            keep.remove(0);
        }
    }
    let json_format = args.format != "text";
    for ev in &keep {
        if json_format {
            writeln!(out.stdout, "{}", serde_json::to_string(ev)?)?;
        } else {
            writeln!(
                out.stdout,
                "{} seq={} {} {} ns={} id={} outcome={:?}",
                ev.timestamp,
                ev.sequence,
                ev.actor.agent_id,
                ev.action.as_str(),
                ev.target.namespace,
                ev.target.memory_id,
                ev.outcome,
            )?;
        }
    }
    Ok(0)
}

fn run_path(
    cli_audit_dir: Option<&std::path::Path>,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let p = resolve_path(app_config, cli_audit_dir, None);
    writeln!(out.stdout, "{}", p.display())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditAction as AAct, AuditOutcome, CHAIN_HEAD_PREV_HASH, EventBuilder, actor, target_memory,
    };
    use crate::config::AuditConfig;
    use crate::models::Tier;

    fn write_chained_log(dir: &Path) -> std::path::PathBuf {
        // Build a 3-line chain by hand using the public API; we use
        // the audit module's `init` so emit() produces the lines.
        let path = dir.join("audit.log");
        // Reset the global sink across test runs by spinning a fresh
        // process is impossible; fall back to writing the lines
        // directly.
        let mut prev_hash = CHAIN_HEAD_PREV_HASH.to_string();
        let mut buf = String::new();
        for seq in 1..=3 {
            let ev = make_event(seq, &prev_hash);
            prev_hash = ev.self_hash.clone();
            buf.push_str(&serde_json::to_string(&ev).unwrap());
            buf.push('\n');
        }
        fs::write(&path, buf).unwrap();
        path
    }

    fn make_event(seq: u64, prev: &str) -> AuditEvent {
        let mut ev = AuditEvent {
            schema_version: crate::audit::SCHEMA_VERSION,
            timestamp: format!("2026-04-30T00:00:0{seq}+00:00"),
            sequence: seq,
            actor: actor("ai:test@host:pid-1", "host_fallback", None),
            action: AAct::Store,
            target: target_memory(
                format!("mem-{seq}"),
                "ns-x",
                Some("title".to_string()),
                Some(Tier::Mid.as_str().to_string()),
                None,
            ),
            outcome: AuditOutcome::Allow,
            auth: None,
            session_id: None,
            request_id: None,
            error: None,
            prev_hash: prev.to_string(),
            self_hash: String::new(),
        };
        // Recompute self_hash via the builder helper exposed
        // through serde round-trip in tests.
        let canonical = {
            let mut clone = ev.clone();
            clone.self_hash.clear();
            serde_json::to_string(&clone).unwrap()
        };
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let bytes = h.finalize();
        let mut s = String::with_capacity(64);
        for b in bytes.iter() {
            s.push_str(&format!("{b:02x}"));
        }
        ev.self_hash = s;
        ev
    }

    #[test]
    fn audit_verify_subcmd_reports_ok_for_valid_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig {
            audit: Some(AuditConfig {
                enabled: Some(true),
                path: Some(p.to_string_lossy().into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(p.to_string_lossy().into_owned()),
                json: true,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["total_lines"], 3);
    }

    #[test]
    fn audit_verify_subcmd_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        // Corrupt the second line.
        let mut body = fs::read_to_string(&p).unwrap();
        body = body.replacen("\"sequence\":2", "\"sequence\":99", 1);
        fs::write(&p, body).unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(p.to_string_lossy().into_owned()),
                json: true,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2, "tampering must produce non-zero exit");
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["status"], "fail");
    }

    #[test]
    fn audit_verify_subcmd_missing_log_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(tmp.path().join("nope.log").to_string_lossy().into_owned()),
                json: false,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("nothing to check"));
    }

    #[test]
    fn audit_path_subcmd_prints_resolved_path() {
        let cfg = AppConfig {
            audit: Some(AuditConfig {
                path: Some("/var/log/ai-memory/custom.log".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run_path(None, &cfg, &mut out).unwrap();
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("/var/log/ai-memory/custom.log"));
    }

    #[test]
    fn audit_path_subcmd_honours_audit_dir_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run_path(Some(tmp.path()), &cfg, &mut out).unwrap();
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(
            s.contains(tmp.path().to_string_lossy().as_ref()),
            "expected audit-dir override to surface in `audit path` output: {s}"
        );
        assert!(s.contains("audit.log"));
    }

    // Compile-time guardrail — make sure EventBuilder is visible from
    // this module (it's the public emit-API).
    #[allow(dead_code)]
    fn _builder_is_visible() {
        let _ = EventBuilder::new(
            AAct::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        );
    }

    // ------------------------------------------------------------------
    // PR-9e coverage uplift (issue #487): exercise the top-level `run`
    // dispatcher and the `run_tail` body. Pre-existing tests jumped
    // straight to `run_verify` / `run_path`; the audit dispatcher arm
    // for `audit tail` had no coverage at all.
    // ------------------------------------------------------------------

    #[test]
    fn audit_run_dispatches_to_verify_arm() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let args = AuditArgs {
            action: AuditAction::Verify(VerifyArgs {
                path: Some(p.to_string_lossy().into_owned()),
                json: true,
                since: None,
                forensic_agent_id: None,
            }),
            audit_dir: None,
        };
        // #3429 — the log-only verbs must not open ANY store: point the
        // threaded db path at a file that does not exist and assert it is
        // still absent afterwards.
        let never = tmp.path().join("must-not-open.db");
        let exit = run(&never, args, &cfg, &mut out).unwrap();
        assert_eq!(exit, 0);
        assert!(!never.exists(), "verify must not open a store");
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("\"status\":\"ok\""), "got: {s}");
    }

    #[test]
    fn audit_run_dispatches_to_tail_arm() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let args = AuditArgs {
            action: AuditAction::Tail(TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 10,
                actor: None,
                namespace: None,
                action: None,
                format: "json".to_string(),
            }),
            audit_dir: None,
        };
        let never = tmp.path().join("must-not-open.db");
        let exit = run(&never, args, &cfg, &mut out).unwrap();
        assert_eq!(exit, 0);
        assert!(!never.exists(), "tail must not open a store");
        let s = std::str::from_utf8(&stdout).unwrap();
        let count = s.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(count, 3, "expected 3 events from chain, got {count}: {s}");
    }

    #[test]
    fn audit_run_dispatches_to_path_arm() {
        let cfg = AppConfig {
            audit: Some(AuditConfig {
                path: Some("/var/log/ai-memory/from-run.log".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let args = AuditArgs {
            action: AuditAction::Path,
            audit_dir: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        let never = tmp.path().join("must-not-open.db");
        let exit = run(&never, args, &cfg, &mut out).unwrap();
        assert_eq!(exit, 0);
        assert!(!never.exists(), "path must not open a store");
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("from-run.log"), "got: {s}");
    }

    #[test]
    fn audit_tail_subcmd_returns_last_n_events_in_text_format() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 2,
                actor: None,
                namespace: None,
                action: None,
                format: "text".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        // Text format includes "seq=" prefix per line.
        assert!(s.contains("seq="), "expected text format: {s}");
        let count = s.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(count, 2, "lines arg must cap output at 2: {s}");
    }

    #[test]
    fn audit_tail_subcmd_emits_json_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 50,
                actor: None,
                namespace: None,
                action: None,
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        // First line must parse as JSON.
        let first = s.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(first).expect("json");
        assert_eq!(v["schema_version"], 1);
        assert!(v.get("self_hash").is_some());
    }

    #[test]
    fn audit_tail_subcmd_filters_by_actor() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 50,
                // Filter that does not match (write_chained_log uses
                // "ai:test@host:pid-1") — every event must be dropped.
                actor: Some("nope-not-in-log".to_string()),
                namespace: None,
                action: None,
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.is_empty(), "actor filter must drop all events: {s}");
    }

    #[test]
    fn audit_tail_subcmd_filters_by_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 50,
                actor: None,
                // Mismatched namespace — events use "ns-x" exactly.
                namespace: Some("not-ns-x".to_string()),
                action: None,
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        assert!(stdout.is_empty(), "namespace filter must drop everything");
    }

    #[test]
    fn audit_tail_subcmd_filters_by_action_string() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        // The chained log uses Store actions. Filter on "delete" — drop them.
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 50,
                actor: None,
                namespace: None,
                action: Some("delete".to_string()),
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        assert!(
            stdout.is_empty(),
            "action=delete must drop all store events"
        );
    }

    #[test]
    fn audit_tail_subcmd_returns_zero_when_log_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(
                    tmp.path()
                        .join("does-not-exist.log")
                        .to_string_lossy()
                        .into_owned(),
                ),
                lines: 50,
                actor: None,
                namespace: None,
                action: None,
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        assert!(stdout.is_empty());
    }

    #[test]
    fn audit_tail_subcmd_skips_malformed_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        // Append a malformed line; tail must skip it (continue) and
        // still emit the valid 3 events.
        let mut body = fs::read_to_string(&p).unwrap();
        body.push_str("not-valid-json\n\n");
        fs::write(&p, body).unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_tail(
            &TailArgs {
                path: Some(p.to_string_lossy().into_owned()),
                lines: 50,
                actor: None,
                namespace: None,
                action: None,
                format: "json".to_string(),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let count = s.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(
            count, 3,
            "must skip malformed line and keep the 3 good events"
        );
    }

    #[test]
    fn audit_verify_subcmd_missing_log_emits_json_when_flag_set() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(tmp.path().join("nope.log").to_string_lossy().into_owned()),
                // JSON-format the missing-log response: exercises the
                // `args.json` branch of the missing-log early return.
                json: true,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["total_lines"], 0);
        assert!(v["note"].as_str().unwrap().contains("does not exist"));
    }

    #[test]
    fn audit_verify_subcmd_text_failure_writes_to_stderr() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        // Tamper to force a verify failure.
        let mut body = fs::read_to_string(&p).unwrap();
        body = body.replacen("\"sequence\":2", "\"sequence\":99", 1);
        fs::write(&p, body).unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(p.to_string_lossy().into_owned()),
                // text path: writes failure to stderr instead of stdout
                json: false,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2);
        let serr = std::str::from_utf8(&stderr).unwrap();
        assert!(
            serr.contains("audit verify FAIL"),
            "expected text-format failure on stderr: {serr}"
        );
    }

    #[test]
    fn audit_verify_subcmd_text_success_writes_to_stdout() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_chained_log(tmp.path());
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(p.to_string_lossy().into_owned()),
                // text-format success path
                json: false,
                since: None,
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("audit verify OK"), "got: {s}");
        assert!(s.contains("3 line(s) verified"));
    }

    // ---- v0.6.4-009 — `audit show` SQLite audit_log subcommand ----

    fn show_args(json: bool, agent_id: Option<&str>) -> ShowArgs {
        ShowArgs {
            capability_expansions: false,
            principal: agent_id.map(str::to_string),
            limit: 50,
            json,
        }
    }

    fn cfg_for_db(p: &std::path::Path) -> AppConfig {
        AppConfig {
            db: Some(p.to_string_lossy().into_owned()),
            ..AppConfig::default()
        }
    }

    #[test]
    fn audit_show_emits_no_rows_message_on_empty_table() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_show(&show_args(false, None), tmp.path(), &mut out).unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("audit_log: no rows"), "got: {s}");
    }

    #[test]
    fn audit_show_renders_grant_and_deny_rows_in_text_format() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = crate::db::open(tmp.path()).unwrap();
        crate::db::record_capability_expansion(&conn, Some("alice"), "graph", true, None);
        crate::db::record_capability_expansion(&conn, Some("bob"), "power", false, None);
        drop(conn);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_show(&show_args(false, None), tmp.path(), &mut out).unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("ALLOW"), "missing ALLOW header in: {s}");
        assert!(s.contains("DENY"), "missing DENY header in: {s}");
        assert!(s.contains("alice"));
        assert!(s.contains("bob"));
        assert!(s.contains("graph"));
        assert!(s.contains("power"));
    }

    #[test]
    fn audit_show_emits_valid_json_when_flag_set() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = crate::db::open(tmp.path()).unwrap();
        crate::db::record_capability_expansion(&conn, Some("alice"), "graph", true, None);
        drop(conn);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_show(&show_args(true, None), tmp.path(), &mut out).unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).expect("--json must emit valid JSON");
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["agent_id"], "alice");
        assert_eq!(arr[0]["requested_family"], "graph");
        assert_eq!(arr[0]["granted"], true);
        assert_eq!(arr[0]["event_type"], "capability_expansion");
    }

    #[test]
    fn audit_show_filters_by_agent_id() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = crate::db::open(tmp.path()).unwrap();
        crate::db::record_capability_expansion(&conn, Some("alice"), "graph", true, None);
        crate::db::record_capability_expansion(&conn, Some("bob"), "power", false, None);
        drop(conn);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_show(&show_args(true, Some("alice")), tmp.path(), &mut out).unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1, "filter should leave only alice rows");
        assert_eq!(arr[0]["agent_id"], "alice");
    }

    /// #3429 — the ALLOWED path: `run` dispatches `show` against the store
    /// path threaded in from the top-level parser, EVEN WHEN the `AppConfig`
    /// in scope names a different one. Pre-fix `run_show` recomputed
    /// `effective_db(DEFAULT_DB)` and read `cfg`'s store instead.
    #[test]
    fn audit_run_dispatches_to_show_arm() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = dir.path().join("resolved.db");
        let from_config = dir.path().join("from-config.db");
        // Seed a row ONLY in the config-named store: if `show` read that one
        // it would render `alice`, and the resolved store would stay absent.
        {
            let conn = crate::db::open(&from_config).unwrap();
            crate::db::record_capability_expansion(&conn, Some("alice"), "graph", true, None);
        }
        let cfg = cfg_for_db(&from_config);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let args = AuditArgs {
            action: AuditAction::Show(show_args(false, None)),
            audit_dir: None,
        };
        let exit = run(&resolved, args, &cfg, &mut out).unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        assert!(s.contains("audit_log"), "got: {s}");
        assert!(
            !s.contains("alice"),
            "#3429: show must read the RESOLVED --db, not the config store: {s}"
        );
        assert!(
            resolved.exists(),
            "#3429: show must have opened the resolved --db"
        );
    }

    // ------------------------------------------------------------------
    // Coverage-uplift block (2026-05-19): exercise `run_forensic_verify`
    // dispatch (lines 215-216, 295-410) by hand-writing an empty
    // forensic directory + invoking `audit verify --since`. The substrate
    // helper `crate::governance::audit::verify_since` is already covered
    // by `governance::audit::tests`; the CLI wrapper's distinct paths
    // are dispatch + envelope/render arms.
    // ------------------------------------------------------------------

    #[test]
    fn audit_verify_with_since_dispatches_to_forensic_verify_json() {
        let tmp = tempfile::tempdir().unwrap();
        // Audit dir with NO forensic files — verify_since walks an
        // empty dir and returns Ok(report with total_lines=0, no
        // failures). The dispatch arm covers lines 215-216, 295-309,
        // 321-323, 380-391.
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        // Pass `path` pointed at a (non-existent) audit.log file
        // INSIDE the tempdir. resolve_path strips to the parent (the
        // tempdir) as the forensic-files directory.
        let exit = run_verify(
            &VerifyArgs {
                path: Some(tmp.path().join("audit.log").to_string_lossy().into_owned()),
                json: true,
                since: Some("2026-01-01".into()),
                forensic_agent_id: Some("ai:nobody-test".into()),
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["total_lines"], 0);
        assert_eq!(v["since"], "2026-01-01");
    }

    #[test]
    fn audit_verify_with_since_human_render_emits_summary_line() {
        // Non-JSON path through run_forensic_verify when the report
        // is OK and contains zero rows (no files exist). Covers
        // lines 392-401.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(tmp.path().join("audit.log").to_string_lossy().into_owned()),
                json: false,
                since: Some("2026-01-01".into()),
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 0);
        let s = std::str::from_utf8(&stdout).unwrap();
        // Human render starts with "forensic verify OK:".
        assert!(s.starts_with("forensic verify OK:"), "got: {s}");
        assert!(s.contains("0 line(s)"));
        assert!(s.contains("since 2026-01-01"));
    }

    #[test]
    fn audit_verify_with_since_returns_error_on_unparseable_date() {
        // Drives lines 323-345 — verify_since errors out on bad
        // date, the dispatch wraps the error into exit=2 + the
        // appropriate envelope.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = AppConfig::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let exit = run_verify(
            &VerifyArgs {
                path: Some(tmp.path().join("audit.log").to_string_lossy().into_owned()),
                json: true,
                since: Some("not-a-date".into()),
                forensic_agent_id: None,
            },
            None,
            &cfg,
            &mut out,
        )
        .unwrap();
        assert_eq!(exit, 2);
        let s = std::str::from_utf8(&stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["status"], "error");
        assert!(v["error"].as_str().unwrap().contains("parsing --since"));
    }
}

#[cfg(test)]
mod restore_attest_1946_tests {
    //! #1946 CLI-verb coverage: every arm of `run_restore_attest`.
    //! Witness env vars are process-global → serialised on the crate's
    //! key-dir env lock (the `governance::audit` test convention) and
    //! cleared before release.
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::governance::audit as witness;

    fn args(sign: bool, json: bool, key_dir: Option<std::path::PathBuf>) -> RestoreAttestArgs {
        RestoreAttestArgs {
            sign,
            key_dir,
            json,
        }
    }

    fn clear_witness_env() {
        unsafe {
            std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
            std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
        }
    }

    /// Seed the off-table anchor ABOVE the (empty) DB head by enrolling a
    /// witness key, appending rows, forcing an anchor emission, then
    /// re-opening a FRESH empty db path so `db_head < anchor`.
    fn seed_anchor_above_head(env: &TestEnv, witness_dir: &std::path::Path) {
        let kp = crate::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
        crate::identity::keypair::save(&kp, witness_dir).expect("save");
        unsafe {
            std::env::set_var(witness::WITNESS_KEY_DIR_ENV, witness_dir);
            std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
        }
        // Anchor from a THROWAWAY db that has rows; the TestEnv db stays empty.
        let anchor_db = witness_dir.join("anchor-seed.db");
        let conn = crate::db::open(&anchor_db).expect("open");
        for i in 0..3 {
            let ev = crate::signed_events::SignedEvent {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: "alice".to_string(),
                event_type: "memory_link.created".to_string(),
                payload_hash: crate::signed_events::payload_hash(format!("p-{i}").as_bytes()),
                signature: None,
                attest_level: "unsigned".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                ..crate::signed_events::SignedEvent::default()
            };
            crate::signed_events::append_signed_event(&conn, &ev).expect("append");
        }
        crate::signed_events::force_emit_audit_head_witness(&conn);
        let _ = env; // db_path deliberately untouched (head 0 < anchor)
    }

    #[test]
    fn no_anchor_bails_with_enrolment_hint() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let mut env = TestEnv::fresh();
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let err = run_restore_attest(&args(false, false, None), &db_path, &mut out)
            .expect_err("must bail without an anchor");
        assert!(
            err.to_string()
                .contains("no pinnable off-table head anchor"),
            "got: {err:#}"
        );
    }

    #[test]
    fn gap_zero_reports_no_rollback_and_exits_zero() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut env = TestEnv::fresh();
        // Anchor from the SAME db the CLI will read → head == anchor → gap 0.
        let kp = crate::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
        crate::identity::keypair::save(&kp, tmp.path()).expect("save");
        unsafe {
            std::env::set_var(witness::WITNESS_KEY_DIR_ENV, tmp.path());
            std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
        }
        {
            let conn = crate::db::open(&env.db_path).expect("open");
            let ev = crate::signed_events::SignedEvent {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: "alice".to_string(),
                event_type: "memory_link.created".to_string(),
                payload_hash: crate::signed_events::payload_hash(b"p"),
                signature: None,
                attest_level: "unsigned".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                ..crate::signed_events::SignedEvent::default()
            };
            crate::signed_events::append_signed_event(&conn, &ev).expect("append");
            crate::signed_events::force_emit_audit_head_witness(&conn);
        }
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let code = run_restore_attest(&args(false, false, None), &db_path, &mut out).expect("ok");
        assert_eq!(code, 0);
        drop(out);
        assert!(
            env.stderr_str().contains("no rollback to sanction"),
            "got: {}",
            env.stderr_str()
        );
        clear_witness_env();
    }

    #[test]
    fn dry_run_prints_gap_text_and_json_without_signing() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut env = TestEnv::fresh();
        seed_anchor_above_head(&env, tmp.path());
        let db_path = env.db_path.clone();
        {
            let mut out = env.output();
            let code =
                run_restore_attest(&args(false, false, None), &db_path, &mut out).expect("ok");
            assert_eq!(code, 0);
        }
        assert!(
            env.stdout_str().contains("dry-run") && env.stdout_str().contains("gap=3"),
            "got: {}",
            env.stdout_str()
        );
        env.stdout.clear();
        {
            let mut out = env.output();
            let code =
                run_restore_attest(&args(false, true, None), &db_path, &mut out).expect("ok");
            assert_eq!(code, 0);
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(v["status"], "dry_run");
        assert_eq!(v["old_head"], 3);
        assert_eq!(v["new_head"], 0);
        assert_eq!(v["gap"], 3);
        // Dry-run must NOT create a sanction log.
        assert!(
            !tmp.path().join("restore-sanctions.log").exists()
                || std::fs::read_to_string(tmp.path().join("restore-sanctions.log"))
                    .unwrap_or_default()
                    .is_empty(),
            "dry-run must not append a sanction"
        );
        clear_witness_env();
    }

    #[test]
    fn sign_missing_operator_key_errors() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut env = TestEnv::fresh();
        seed_anchor_above_head(&env, tmp.path());
        let db_path = env.db_path.clone();
        let empty_keys = tempfile::tempdir().expect("tmp2");
        let mut out = env.output();
        let err = run_restore_attest(
            &args(true, false, Some(empty_keys.path().to_path_buf())),
            &db_path,
            &mut out,
        )
        .expect_err("must fail without operator key");
        assert!(err.to_string().contains("operator"), "got: {err:#}");
        clear_witness_env();
    }

    #[test]
    fn sign_happy_path_appends_sanction_text_and_json() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let tmp = tempfile::tempdir().expect("tmp");
        let mut env = TestEnv::fresh();
        seed_anchor_above_head(&env, tmp.path());
        let op_dir = tempfile::tempdir().expect("tmp2");
        let op = crate::identity::keypair::generate(crate::cli::rules::OPERATOR_KEY_ID)
            .expect("gen operator");
        crate::identity::keypair::save(&op, op_dir.path()).expect("save operator");
        let db_path = env.db_path.clone();
        {
            let mut out = env.output();
            let code = run_restore_attest(
                &args(true, false, Some(op_dir.path().to_path_buf())),
                &db_path,
                &mut out,
            )
            .expect("sign ok");
            assert_eq!(code, 0);
        }
        assert!(
            env.stdout_str().contains("restore-attest OK"),
            "got: {}",
            env.stdout_str()
        );
        env.stdout.clear();
        {
            let mut out = env.output();
            let code = run_restore_attest(
                &args(true, true, Some(op_dir.path().to_path_buf())),
                &db_path,
                &mut out,
            )
            .expect("sign ok json");
            assert_eq!(code, 0);
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["gap"], 3);
        clear_witness_env();
    }
}

/// v1.0.0 #2004 — CLI-verb coverage for the `run_re_anchor` self-verify
/// read-back (the FIX-1 operator-visibility contract). The read-back is
/// THREE-STATE and fail-closed: a verify FAILURE (enrolment drift — the
/// enrolled `AI_MEMORY_WITNESS_PUBKEY` does not match the custody signing key
/// that produced the anchor) MUST surface a NON-ZERO exit + a visible FAILED
/// line, never a silent `ok` blamed on a "missing pubkey". Witness env vars
/// are process-global → serialised on the crate key-dir env lock.
#[cfg(test)]
mod reanchor_ceremony_2004_cli_tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;
    use crate::governance::audit as witness;

    fn clear_witness_env() {
        unsafe {
            std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
            std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
        }
    }

    /// Append `n` unsigned `signed_events` rows to the TestEnv db so the
    /// re-anchor ceremony has a non-empty chain head to countersign.
    fn append_rows(db_path: &std::path::Path, n: usize) {
        let conn = crate::db::open(db_path).expect("open db");
        for i in 0..n {
            let ev = crate::signed_events::SignedEvent {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: "alice".to_string(),
                event_type: "memory_link.created".to_string(),
                payload_hash: crate::signed_events::payload_hash(format!("p-{i}").as_bytes()),
                signature: None,
                attest_level: "unsigned".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                ..crate::signed_events::SignedEvent::default()
            };
            crate::signed_events::append_signed_event(&conn, &ev).expect("append");
        }
    }

    /// Enrol a witness signing key in `dir` and set the custody-dir env; the
    /// K1 pubkey env is set SEPARATELY by the caller (so the drift case can
    /// pin a DIFFERENT key than the one that signs).
    fn enrol_signing_key(dir: &std::path::Path) -> crate::identity::keypair::AgentKeypair {
        let kp = crate::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
        crate::identity::keypair::save(&kp, dir).expect("save");
        unsafe {
            std::env::set_var(witness::WITNESS_KEY_DIR_ENV, dir);
        }
        kp
    }

    #[test]
    fn re_anchor_readback_pass_exits_zero() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let mut env = TestEnv::fresh();
        append_rows(&env.db_path, 2);
        let kdir = tempfile::tempdir().expect("kdir");
        let kp = enrol_signing_key(kdir.path());
        // K1 pins the SAME key that signs → PASS.
        unsafe {
            std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
        }
        let db_path = env.db_path.clone();
        let code = {
            let mut out = env.output();
            run_re_anchor(&ReAnchorArgs { json: false }, &db_path, &mut out).expect("run")
        };
        assert_eq!(code, 0, "PASS read-back must exit 0: {}", env.stdout_str());
        assert!(
            env.stdout_str().contains("PASS"),
            "expected PASS line: {}",
            env.stdout_str()
        );
        clear_witness_env();
    }

    #[test]
    fn re_anchor_enrolment_drift_fails_closed_nonzero() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let mut env = TestEnv::fresh();
        append_rows(&env.db_path, 2);
        let kdir = tempfile::tempdir().expect("kdir");
        let _signer = enrol_signing_key(kdir.path());
        // ENROLMENT DRIFT: pin a DIFFERENT key than the custody signer. The
        // persisted anchor's resolver_pubkey is the signer's, so the K1 pin
        // fails — the ceremony persisted but is NOT verifiable.
        let other = crate::identity::keypair::generate("someone-else").expect("gen");
        unsafe {
            std::env::set_var(witness::WITNESS_PUBKEY_ENV, other.public_base64());
        }
        let db_path = env.db_path.clone();
        let code = {
            let mut out = env.output();
            run_re_anchor(&ReAnchorArgs { json: true }, &db_path, &mut out).expect("run")
        };
        assert_eq!(
            code,
            1,
            "enrolment drift must fail closed (exit 1): {}",
            env.stdout_str()
        );
        let v: serde_json::Value =
            serde_json::from_str(env.stdout_str().trim()).expect("json summary");
        assert_eq!(v["status"], "verify_failed");
        assert_eq!(v["verified"], false);
        assert_eq!(v["readback"], "fail");
        assert_eq!(v["error"], "reanchor_checkpoint_pubkey_not_enrolled");
        clear_witness_env();
    }

    /// Count of persisted re-anchor checkpoint rows in the TestEnv db —
    /// the "nothing was persisted" pin for skip / failure dispositions.
    fn reanchor_row_count(db_path: &std::path::Path) -> i64 {
        let conn = crate::db::open(db_path).expect("open db");
        conn.query_row(
            "SELECT COUNT(*) FROM checkpoints WHERE condition_type = ?1",
            [crate::models::ConditionType::ReAnchor.as_str()],
            |r| r.get(0),
        )
        .expect("count")
    }

    /// PR #2214 audit F4 — a PRESENT-but-broken custody (here: the `.pub`
    /// removed while the `.priv` remains — key material exists but
    /// `keypair::load` cannot load it) is a ceremony FAILURE, not a skip:
    /// exit 1, JSON `status=error` with the distinct
    /// `witness_key_unloadable` reason, stderr naming the custody lever,
    /// and NOTHING persisted. Pre-F4 this collapsed into the exit-0
    /// "skipped: enrol a key" path with guidance that was FALSE (a key IS
    /// enrolled).
    #[test]
    fn re_anchor_unloadable_custody_fails_closed_nonzero() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let mut env = TestEnv::fresh();
        append_rows(&env.db_path, 2);
        let kdir = tempfile::tempdir().expect("kdir");
        let _signer = enrol_signing_key(kdir.path());
        std::fs::remove_file(
            kdir.path()
                .join(format!("{}.pub", witness::WITNESS_KEY_LABEL)),
        )
        .expect("remove pub");
        let db_path = env.db_path.clone();
        let code = {
            let mut out = env.output();
            run_re_anchor(&ReAnchorArgs { json: true }, &db_path, &mut out).expect("run")
        };
        assert_eq!(
            code,
            1,
            "unloadable enrolled custody must fail closed: {}",
            env.stdout_str()
        );
        let v: serde_json::Value =
            serde_json::from_str(env.stdout_str().trim()).expect("json summary");
        assert_eq!(v["status"], "error");
        assert_eq!(v["reason"], "witness_key_unloadable");
        assert!(
            env.stderr_str().contains("AI_MEMORY_WITNESS_KEY_DIR"),
            "stderr must name the custody lever: {}",
            env.stderr_str()
        );
        assert_eq!(
            reanchor_row_count(&env.db_path),
            0,
            "no anchor may persist when the ceremony failed"
        );
        clear_witness_env();
    }

    /// Genuinely ABSENT custody (the dir does not exist — nothing enrolled)
    /// is the opt-in no-op: exit 0, an explicit machine-readable `skipped`
    /// JSON (never an empty stdout an automation would have to guess about),
    /// stderr naming the enrolment lever, nothing persisted.
    #[test]
    fn re_anchor_absent_custody_is_explicit_skip_not_fail() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_witness_env();
        let mut env = TestEnv::fresh();
        append_rows(&env.db_path, 2);
        // Point custody at a dir that does NOT exist (hermetic — never the
        // host's real default custody dir).
        let kdir = tempfile::tempdir().expect("kdir");
        unsafe {
            std::env::set_var(
                witness::WITNESS_KEY_DIR_ENV,
                kdir.path().join("does-not-exist"),
            );
        }
        let db_path = env.db_path.clone();
        let code = {
            let mut out = env.output();
            run_re_anchor(&ReAnchorArgs { json: true }, &db_path, &mut out).expect("run")
        };
        assert_eq!(
            code,
            0,
            "opt-in no-op is not a failure: {}",
            env.stdout_str()
        );
        let v: serde_json::Value =
            serde_json::from_str(env.stdout_str().trim()).expect("json summary");
        assert_eq!(v["status"], "skipped");
        assert_eq!(v["reason"], "witness_custody_absent");
        assert!(
            env.stderr_str().contains("AI_MEMORY_WITNESS_KEY_DIR"),
            "stderr must name the enrolment lever: {}",
            env.stderr_str()
        );
        assert_eq!(
            reanchor_row_count(&env.db_path),
            0,
            "no anchor may persist when the ceremony skipped"
        );
        clear_witness_env();
    }
}
