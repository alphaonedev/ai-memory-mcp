// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 7th-form closeout (issue #760) — `ai-memory governance
//! install-defaults` CLI subcommand.
//!
//! Bulk-activates the four seeded operator hard rules (R001-R004) that
//! migration `0024_v07_governance_rules.sql` lands at `enabled = 0`:
//!
//! | Rule | Kind             | Matcher                                       | Reason                                              |
//! |------|------------------|-----------------------------------------------|-----------------------------------------------------|
//! | R001 | filesystem_write | `{"glob":"/tmp/**"}`                          | No `/tmp` writes (project hard rule, #691).         |
//! | R002 | filesystem_write | `{"glob":"/var/tmp/**"}`                      | No `/var/tmp` writes.                                |
//! | R003 | filesystem_write | `{"glob":"/private/tmp/**"}`                  | No `/private/tmp` writes (macOS realpath of `/tmp`).|
//! | R004 | process_spawn    | `{"binary":"cargo","disk_free_min_gib":20}`   | Refuse `cargo` on low-disk (<20 GiB) host.          |
//!
//! ## Operator flow
//!
//! ```text
//!   $ ai-memory governance install-defaults
//!   The following seed rules will be enabled (R001-R004):
//!     R001  filesystem_write  /tmp/**           refuse
//!     R002  filesystem_write  /var/tmp/**       refuse
//!     R003  filesystem_write  /private/tmp/**   refuse
//!     R004  process_spawn     cargo (<20 GiB)   refuse
//!   Proceed? [y/N]: y
//!   Activated 4 rule(s).
//! ```
//!
//! ## Why not `rules enable` per-id?
//!
//! `ai-memory rules enable <id> --sign` is the per-rule path; it
//! requires the operator's Ed25519 key on disk and re-signs each row.
//! For the bootstrap step where the operator just wants the seeded
//! hard rules ON, `install-defaults` is a single confirmed batch.
//!
//! ## v1.0.0 #3430 — the enable goes through the SIGNED path
//!
//! This verb used to issue a raw `UPDATE governance_rules SET
//! enabled = 1` that "does NOT touch the signature column". That made
//! the documented seed ceremony
//! (`rules sign-seed` → `governance install-defaults --yes`) produce
//! four SILENTLY INERT rules: `sign-seed` commits `enabled` into the
//! canonical payload
//! ([`crate::governance::rules_store::canonical_bytes_for_signing`]),
//! so flipping `enabled` afterwards invalidated every signature and the
//! #1042 L1-6 load gate dropped all four rows — while this CLI printed
//! "Activated 4 rule(s)" and `rules check` answered `allow`.
//!
//! Now the activation routes through
//! [`crate::governance::rules_store::set_enabled_signed`] whenever an
//! `operator_signed` row is involved: the flip, the re-signature over
//! the POST-state, the operator-signed audit row and the policy-version
//! advance all land in ONE transaction. When the operator key cannot be
//! loaded the verb REFUSES before any write rather than neutering the
//! signature. Rows that are still `unsigned` in the pre-L1-6 posture (no
//! operator pubkey resolved anywhere) keep the plain flip — they are
//! enforced without a signature check there.
//!
//! Every line this verb prints reports the REAL enforcement state
//! ([`crate::governance::rules_store::enforcement_state`]), derived from
//! signature validity — never from the raw `enabled` column.
//!
//! ## Audit honesty
//!
//! Activating the rule is **mechanical at the harness hook boundary**
//! (per `src/governance/agent_action.rs` module docs). It is not a
//! "100% can't be bypassed" claim — see the audit-honest wording in
//! the agent_action module and `docs/governance/agent-action-rules.md`.

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::CliOutput;
use crate::governance::rules_store::{self, Rule, RuleEnforcement};

/// The four seed rule ids defined in migration `0024_v07_governance_rules.sql`.
/// Kept here as a typed constant so unit tests can iterate without
/// relying on the migration text.
pub const SEED_RULE_IDS: &[&str] = &["R001", "R002", "R003", "R004"];

/// CLI args for `ai-memory governance install-defaults`.
#[derive(Args, Debug, Clone)]
pub struct InstallDefaultsArgs {
    /// Skip the interactive `Proceed? [y/N]:` confirmation prompt.
    /// Required for non-interactive contexts (CI, scripts).
    #[arg(long)]
    pub yes: bool,

    /// Emit a JSON envelope instead of the human-readable summary.
    /// Stable wire shape: `{ "verb": "governance.install-defaults",
    /// "result": { "activated": [...], "missing": [...],
    /// "already_enabled": [...], "resigned": [...], "enforced": [...],
    /// "not_enforced": [{ "id": ..., "enforcement_state": ... }] } }`.
    #[arg(long)]
    pub json: bool,

    /// v1.0.0 #3430 — override the operator key directory used to
    /// re-sign the seed rows. Honors `AI_MEMORY_KEY_DIR` when omitted,
    /// matching `ai-memory rules --key-dir` so the documented ceremony
    /// (`rules sign-seed` → `governance install-defaults`) resolves the
    /// SAME key on both halves.
    #[arg(long, value_name = "PATH")]
    pub key_dir: Option<std::path::PathBuf>,
}

/// Outcome of the install-defaults run; surfaced both to the JSON
/// envelope and to the human summary line.
#[derive(Debug, Default, serde::Serialize)]
pub struct InstallDefaultsReport {
    /// Rule ids that flipped from `enabled = 0` to `enabled = 1`.
    pub activated: Vec<String>,
    /// Rule ids that were already enabled at the start.
    pub already_enabled: Vec<String>,
    /// Rule ids that were not present in the DB (migration skipped or
    /// row hand-deleted). Surfaced so the operator can investigate.
    pub missing: Vec<String>,
    /// v1.0.0 #3430 — ids whose operator signature was (re-)committed
    /// over the POST-state during this run, via the audited
    /// [`rules_store::set_enabled_signed`] transaction.
    pub resigned: Vec<String>,
    /// v1.0.0 #3430 — ids that were already enabled but INERT on entry
    /// (signature no longer verified) and were self-healed by this run.
    /// A non-empty list means a previous ceremony left dead rules
    /// behind.
    pub repaired: Vec<String>,
    /// v1.0.0 #3430 — the REAL post-state: ids the engine will actually
    /// evaluate, derived from
    /// [`rules_store::enforcement_state`], never from the raw `enabled`
    /// column.
    pub enforced: Vec<String>,
    /// v1.0.0 #3430 — seed rows left enabled-but-inert after this run.
    /// Non-empty is a hard failure: the verb reports it and exits
    /// non-zero rather than claiming the rules are active.
    pub not_enforced: Vec<InertSeedRule>,
}

/// v1.0.0 #3430 — one enabled-but-unenforced seed row, with the reason
/// the L1-6 gate drops it.
#[derive(Debug, serde::Serialize)]
pub struct InertSeedRule {
    /// The rule id (`R001`..`R004`).
    pub id: String,
    /// Stable token from [`RuleEnforcement::as_str`].
    pub enforcement_state: &'static str,
}

/// Dispatch entry called from the daemon-runtime `GovernanceAction`
/// match arm.
///
/// # Errors
///
/// Returns an error if the DB cannot be opened, the rule reads/writes
/// fail, the operator key needed to re-sign a signed seed row cannot be
/// loaded (#3430 — refused BEFORE any write), any seed row is left
/// enabled-but-inert after the run (#3430), or the JSON envelope cannot
/// be serialised. Declining the prompt is NOT an error — it returns
/// `Ok(())` after writing the abort line to stdout.
pub fn run(
    db_path: &std::path::Path,
    args: InstallDefaultsArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = rusqlite::Connection::open(db_path).with_context(|| {
        format!(
            "governance install-defaults: open db at {}",
            db_path.display()
        )
    })?;
    // v1.0.0 #2445 — raw-open WRITE funnel (the `enabled` activation).
    // Enabling authz rules against a schema this binary does not
    // understand is an authz-config write on an unknown-shape table.
    crate::storage::assert_schema_not_ahead(&conn, &db_path.display().to_string())?;

    // Confirm the four rules exist + grab their current state so we
    // can render the preview block and decide what to activate.
    // v1.0.0 #3430 — read through `rules_store` (which owns the
    // `governance_rules` SQL) instead of a private SELECT, so the
    // preview carries the `signature` column the enforcement-state
    // projection needs.
    let mut preview: Vec<Rule> = Vec::with_capacity(SEED_RULE_IDS.len());
    let mut missing: Vec<String> = Vec::new();
    for id in SEED_RULE_IDS {
        match rules_store::get(&conn, id)
            .with_context(|| format!("install-defaults: load seed rule {id}"))?
        {
            Some(row) => preview.push(row),
            None => missing.push((*id).to_string()),
        }
    }

    // v0.7.0 #1042 (Agent-6 #5) — when an operator pubkey is
    // resolved (env `AI_MEMORY_OPERATOR_PUBKEY` set OR
    // `operator.key.pub` present on disk), the engine's
    // `enforced_rule_passes` silently DROPS every row whose
    // `attest_level != "operator_signed"`. Pre-#1042 this CLI
    // happily activated the seeded R001-R004 rows (shipped at
    // `attest_level = "unsigned"`), printed "Activated 4 rule(s)",
    // and left the operator believing the rules were effective —
    // even though the engine would skip them at every wire-action.
    // The operator-visible message was MISLEADING.
    //
    // Post-#1042 we detect the misconfiguration BEFORE the
    // activation UPDATE and bail with a clear pointer to
    // `ai-memory rules sign-seed`. The operator has two recovery
    // paths:
    //   1. Run `ai-memory rules sign-seed --key <path>` first to
    //      upgrade the seed rows' attest_level to operator_signed.
    //      Then re-run `install-defaults` with the rules properly
    //      enrolled.
    //   2. Temporarily unset `AI_MEMORY_OPERATOR_PUBKEY` and
    //      remove any stored `operator.key.pub` to drop into the
    //      no-pubkey-resolved posture where `enforced_rule_passes`
    //      treats unsigned-enabled rows as enforceable. (Strongly
    //      discouraged — leaves the L1-6 bypass-impossibility
    //      story broken.)
    let operator_pubkey = rules_store::resolve_operator_pubkey();
    if operator_pubkey.is_some() {
        let unsigned_seed_rows: Vec<&Rule> = preview
            .iter()
            .filter(|r| r.attest_level != rules_store::OPERATOR_SIGNED_ATTEST_LEVEL)
            .collect();
        if !unsigned_seed_rows.is_empty() {
            let unsigned_ids: Vec<&str> =
                unsigned_seed_rows.iter().map(|r| r.id.as_str()).collect();
            anyhow::bail!(
                "governance install-defaults: refused (#1042) — operator pubkey is resolved \
                 (AI_MEMORY_OPERATOR_PUBKEY env or operator.key.pub on disk) but the \
                 following seed rule(s) are still attest_level=unsigned: {}. \
                 Activating them now would print 'Activated' but the engine's \
                 enforced_rule_passes() would silently drop every one at wire-action time. \
                 First run `ai-memory rules sign-seed --key <path-to-private-key>` to upgrade \
                 the seed rows to operator_signed, THEN re-run install-defaults.",
                unsigned_ids.join(", "),
            );
        }
    }

    // v1.0.0 #3430 — decide the write path BEFORE touching anything, and
    // refuse up front when the signed path is required but unavailable.
    //
    // A row carrying `attest_level = operator_signed` has a signature
    // that COMMITS to `enabled`. Flipping the column beneath it silently
    // invalidates the signature and the L1-6 load gate then drops the
    // rule — reported active, enforcing nothing. So the moment any seed
    // row is operator-signed, the activation MUST go through
    // `set_enabled_signed` (flip + re-sign of the post-state + signed
    // audit row + policy-version advance, one transaction), which needs
    // the operator private key.
    //
    // When no seed row is signed the substrate is in the pre-L1-6
    // bootstrap posture (the #1042 pre-flight above already refused the
    // pubkey-resolved case), where unsigned-enabled rows ARE enforced —
    // no key needed, no key loaded, and a fresh install with no operator
    // keypair still works exactly as documented.
    let needs_signed_path = preview
        .iter()
        .any(|r| r.attest_level == rules_store::OPERATOR_SIGNED_ATTEST_LEVEL);
    let signing_key = if needs_signed_path {
        let key_dir = crate::cli::rules::resolve_key_dir(args.key_dir.as_deref())?;
        Some(
            crate::cli::rules::load_operator_signing_key_from_dir(&key_dir).with_context(|| {
                format!(
                    "governance install-defaults: refused (#3430) — seed rule(s) are \
                     attest_level=operator_signed, so activating them requires re-signing the \
                     row with the operator key (the signature commits to `enabled`), but no \
                     operator key could be loaded from {}. Flipping `enabled` without the key \
                     would leave the rules reported-active but SILENTLY INERT. Provide the key \
                     (--key-dir / AI_MEMORY_KEY_DIR), or activate per-rule with \
                     `ai-memory rules enable --id <id> --sign`.",
                    key_dir.display()
                )
            })?,
        )
    } else {
        None
    };

    // Interactive prompt unless --yes / --json was supplied.
    if !args.yes {
        // JSON-mode callers MUST pass --yes; an interactive prompt on
        // a JSON path would corrupt the envelope. Refuse early.
        if args.json {
            anyhow::bail!("governance install-defaults: --json requires --yes (non-interactive)");
        }
        render_preview(out, &preview, &missing, operator_pubkey.as_ref())?;
        if !confirm_proceed(out)? {
            writeln!(out.stdout, "Aborted. No rules were activated.")?;
            return Ok(());
        }
    }

    let mut report = InstallDefaultsReport {
        missing: missing.clone(),
        ..Default::default()
    };
    for row in &preview {
        let state = rules_store::enforcement_state(row, operator_pubkey.as_ref());
        match (signing_key.as_ref(), state.is_enforced()) {
            // Already enabled AND genuinely enforced — nothing to do.
            (_, true) => report.already_enabled.push(row.id.clone()),
            // Signed posture: ONE audited, atomic transaction both
            // activates a disabled row and self-heals a row that a
            // previous raw-UPDATE ceremony left enabled-but-inert.
            (Some(key), false) => {
                let updated = rules_store::set_enabled_signed(
                    &conn,
                    &row.id,
                    true,
                    key,
                    crate::cli::rules::OPERATOR_KEY_ID,
                )
                .with_context(|| format!("install-defaults: signed enable for {}", row.id))?;
                if updated {
                    report.resigned.push(row.id.clone());
                    if row.enabled {
                        report.repaired.push(row.id.clone());
                    } else {
                        report.activated.push(row.id.clone());
                    }
                }
            }
            // Pre-L1-6 posture: no seed row is operator-signed and no
            // operator pubkey is resolved, so the plain flip is the
            // honest write — unsigned-enabled rows are enforced here.
            // `!row.enabled` is structurally guaranteed on this arm (an
            // enabled row IS enforced in that posture); asserting it
            // keeps `activated` honest — "flipped 0 -> 1" — if a future
            // change ever widens the arm, and leaves any such row to the
            // post-run verification below rather than mis-reporting it.
            (None, false) if !row.enabled => {
                if rules_store::set_enabled(&conn, &row.id, true)
                    .with_context(|| format!("install-defaults: enable {}", row.id))?
                {
                    report.activated.push(row.id.clone());
                }
            }
            (None, false) => {}
        }
    }

    // v1.0.0 #3430 — report the REAL post-state. Re-read every seed row
    // and re-derive enforcement from signature validity, so the summary
    // can never again claim "Activated 4" over four inert rows.
    for id in SEED_RULE_IDS {
        let Some(row) = rules_store::get(&conn, id).with_context(|| {
            format!("install-defaults: re-read seed rule {id} for verification")
        })?
        else {
            continue;
        };
        let state = rules_store::enforcement_state(&row, operator_pubkey.as_ref());
        if state.is_enforced() {
            report.enforced.push(row.id);
        } else {
            report.not_enforced.push(InertSeedRule {
                id: row.id,
                enforcement_state: state.as_str(),
            });
        }
    }

    if args.json {
        let envelope = serde_json::json!({
            "verb": "governance.install-defaults",
            "result": &report,
        });
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string(&envelope)
                .context("install-defaults: serialise JSON envelope")?
        )?;
    } else {
        writeln!(
            out.stdout,
            "Activated {} rule(s); {} already-enabled; {} missing.",
            report.activated.len(),
            report.already_enabled.len(),
            report.missing.len(),
        )?;
        if !report.activated.is_empty() {
            writeln!(out.stdout, "  activated: {}", report.activated.join(", "))?;
        }
        if !report.missing.is_empty() {
            writeln!(out.stdout, "  missing:   {}", report.missing.join(", "))?;
        }
        // v1.0.0 #3430 — the honest bottom line: what the ENGINE will
        // evaluate, not what the `enabled` column says.
        writeln!(
            out.stdout,
            "Enforcement (real state, verified against the operator signature): \
             {} enforced, {} inert.",
            report.enforced.len(),
            report.not_enforced.len(),
        )?;
        if !report.resigned.is_empty() {
            writeln!(out.stdout, "  re-signed: {}", report.resigned.join(", "))?;
        }
        if !report.repaired.is_empty() {
            writeln!(
                out.stdout,
                "  repaired:  {} (were enabled but INERT on entry)",
                report.repaired.join(", ")
            )?;
        }
        for inert in &report.not_enforced {
            writeln!(
                out.stdout,
                "  NOT ENFORCED: {} ({})",
                inert.id, inert.enforcement_state
            )?;
        }
    }

    // v1.0.0 #3430 — fail loudly rather than let a script believe the
    // seed ruleset is live. The report above has already been written
    // (JSON envelope included) so the operator sees WHICH rows are dead
    // and why; the non-zero exit is what stops a bootstrap pipeline.
    if !report.not_enforced.is_empty() {
        let detail: Vec<String> = report
            .not_enforced
            .iter()
            .map(|r| format!("{} ({})", r.id, r.enforcement_state))
            .collect();
        anyhow::bail!(
            "governance install-defaults: refused to report success (#3430) — the following \
             seed rule(s) are enabled but the L1-6 load gate will SILENTLY DROP them, so they \
             enforce nothing: {}. Re-run `ai-memory rules sign-seed --key <path>` with the key \
             whose public half the substrate resolves, then re-run install-defaults.",
            detail.join(", "),
        );
    }
    Ok(())
}

fn render_preview(
    out: &mut CliOutput<'_>,
    preview: &[Rule],
    missing: &[String],
    operator_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<()> {
    writeln!(
        out.stdout,
        "The following seed rules will be enabled (R001-R004):"
    )?;
    for row in preview {
        // v1.0.0 #3430 — the preview reports the REAL entry state. An
        // `already-on` row whose signature no longer verifies is INERT,
        // not on; saying "already-on" there is the lie this issue is
        // about.
        let state = match rules_store::enforcement_state(row, operator_pubkey) {
            RuleEnforcement::Disabled => "will-enable",
            RuleEnforcement::Enforced => "already-on",
            RuleEnforcement::SkippedUnsigned => "inert-unsigned/will-repair",
            RuleEnforcement::SkippedSignatureInvalid => "inert-badsig/will-repair",
        };
        writeln!(
            out.stdout,
            "  {:<5} {:<17} {:<32} {:<8} [{}]",
            row.id, row.kind, row.matcher, row.severity, state,
        )?;
    }
    if !missing.is_empty() {
        writeln!(
            out.stdout,
            "Warning: the following seed rule ids were not found in the DB: {}",
            missing.join(", ")
        )?;
        writeln!(
            out.stdout,
            "  (re-run `ai-memory schema-init` or check migration 0024 applied)"
        )?;
    }
    Ok(())
}

fn confirm_proceed(out: &mut CliOutput<'_>) -> Result<bool> {
    write!(out.stdout, "Proceed? [y/N]: ")?;
    out.stdout.flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("install-defaults: read stdin")?;
    let trimmed = answer.trim().to_ascii_lowercase();
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    /// Seed `db_path` with the `governance_rules` table + the four
    /// seeded rows at `enabled = 0`. Avoids pulling in the full
    /// migration ladder (which would also drag in fts5 / hnsw).
    fn seed_db_at(db_path: &std::path::Path) {
        let conn = rusqlite::Connection::open(db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS governance_rules (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 matcher TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 namespace TEXT NOT NULL DEFAULT '_global',
                 created_by TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned'
             );",
        )
        .unwrap();
        for (id, kind, matcher) in [
            ("R001", "filesystem_write", r#"{"glob":"/tmp/**"}"#),
            ("R002", "filesystem_write", r#"{"glob":"/var/tmp/**"}"#),
            ("R003", "filesystem_write", r#"{"glob":"/private/tmp/**"}"#),
            (
                "R004",
                "process_spawn",
                r#"{"binary":"cargo","disk_free_min_gib":20}"#,
            ),
        ] {
            conn.execute(
                "INSERT INTO governance_rules (id, kind, matcher, severity, reason, \
                 namespace, created_by, created_at, enabled, signature, attest_level) \
                 VALUES (?1, ?2, ?3, 'refuse', 'seed', '_global', 'system:seed', 0, 0, NULL, 'unsigned')",
                params![id, kind, matcher],
            )
            .unwrap();
        }
    }

    /// Build an `InstallDefaultsArgs` with `--yes` set so the prompt
    /// is skipped.
    fn yes_args() -> InstallDefaultsArgs {
        InstallDefaultsArgs {
            yes: true,
            json: false,
            key_dir: None,
        }
    }

    #[test]
    fn seed_rule_ids_is_the_canonical_four() {
        assert_eq!(SEED_RULE_IDS, &["R001", "R002", "R003", "R004"]);
    }

    /// Build a fresh on-disk DB in a scoped tempdir and seed it.
    fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("governance.db");
        seed_db_at(&db_path);
        (dir, db_path)
    }

    /// v0.7.0 #1042 lock — env-var manipulation in these tests races
    /// when run in parallel. Use a process-wide mutex to serialise.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Generate a fresh Ed25519 keypair and stuff the verifying key
    /// into `AI_MEMORY_OPERATOR_PUBKEY` so
    /// `resolve_operator_pubkey()` returns `Some(_)`. Returns a
    /// guard that clears the env var on drop.
    struct TestPubkeyGuard;
    impl Drop for TestPubkeyGuard {
        fn drop(&mut self) {
            // SAFETY: env mutation; the env_lock guard's lifetime
            // brackets the test region so no sibling test races.
            unsafe { std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY") };
        }
    }
    fn install_test_pubkey() -> TestPubkeyGuard {
        use base64::Engine;
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let pubkey_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
        // SAFETY: serialised via env_lock by caller.
        unsafe { std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", pubkey_b64) };
        TestPubkeyGuard
    }

    #[test]
    fn install_defaults_refuses_when_pubkey_resolved_seed_rows_unsigned_1042() {
        // v0.7.0 #1042 (Agent-6 #5) — when an operator pubkey is
        // resolved AND the seed rows are still attest_level=unsigned,
        // install-defaults refuses with a clear pointer to
        // `ai-memory rules sign-seed`. Pre-#1042 the command would
        // happily activate the rows + print "Activated 4 rule(s)"
        // even though the engine would silently drop every one.
        let _g = env_lock();
        let _pk = install_test_pubkey();
        let (_dir, db_path) = fresh_db();

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let result = run(&db_path, yes_args(), &mut out);
        let err = result
            .expect_err("#1042: install-defaults MUST refuse when pubkey + unsigned seed rows");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("operator pubkey is resolved")
                && msg.contains("attest_level=unsigned")
                && msg.contains("sign-seed"),
            "#1042: refusal MUST cite pubkey + unsigned + sign-seed remediation; got: {msg}"
        );
        // Confirm no rule was actually activated — the refusal must
        // fire BEFORE the UPDATE.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        for id in SEED_RULE_IDS {
            let enabled: i64 = conn
                .query_row(
                    "SELECT enabled FROM governance_rules WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                enabled, 0,
                "#1042: refusal MUST fire BEFORE the UPDATE — rule {id} must stay disabled"
            );
        }
    }

    #[test]
    fn install_defaults_flips_enabled_on_seeded_rows() {
        let _g = env_lock();
        // v0.7.0 #1042 — force resolve_operator_pubkey() to return
        // None for this test, so the dev-host pubkey gate doesn't
        // fire on hosts where ~/Library/Application Support/ai-memory/
        // operator.key.pub is staged.
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        // Sanity: confirm all four start disabled.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            for id in SEED_RULE_IDS {
                let enabled: i64 = conn
                    .query_row(
                        "SELECT enabled FROM governance_rules WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(enabled, 0, "rule {id} must start disabled");
            }
        }

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(&db_path, yes_args(), &mut out).unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        for id in SEED_RULE_IDS {
            let enabled: i64 = conn
                .query_row(
                    "SELECT enabled FROM governance_rules WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(enabled, 1, "rule {id} must be activated");
        }
        let stdout = String::from_utf8(so).unwrap();
        assert!(stdout.contains("Activated 4 rule(s)"));
    }

    #[test]
    fn install_defaults_idempotent_when_already_enabled() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        // Pre-flip all rows to enabled = 1.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE governance_rules SET enabled = 1 WHERE id IN ('R001','R002','R003','R004')",
                [],
            )
            .unwrap();
        }

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(&db_path, yes_args(), &mut out).unwrap();

        let stdout = String::from_utf8(so).unwrap();
        assert!(stdout.contains("Activated 0 rule(s)"));
        assert!(stdout.contains("4 already-enabled"));
    }

    /// v1.0.0 #3430 — the human summary must state the REAL enforcement
    /// posture, not just the raw `enabled` counts.
    #[test]
    fn install_defaults_human_render_states_real_enforcement_3430() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(&db_path, yes_args(), &mut out).unwrap();
        drop(out);

        let stdout = String::from_utf8(so).unwrap();
        assert!(stdout.contains("Activated 4 rule(s)"), "got: {stdout}");
        assert!(
            stdout.contains(
                "Enforcement (real state, verified against the operator signature): \
                             4 enforced, 0 inert."
            ),
            "#3430: the summary must report the engine's verdict; got: {stdout}"
        );
        assert!(
            !stdout.contains("NOT ENFORCED"),
            "no rule is inert in the pre-L1-6 posture; got: {stdout}"
        );
    }

    /// v1.0.0 #3430 — the JSON envelope carries the enforcement lists so
    /// a bootstrap script can gate on them.
    #[test]
    fn install_defaults_json_envelope_carries_enforcement_lists_3430() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(
            &db_path,
            InstallDefaultsArgs {
                yes: true,
                json: true,
                key_dir: None,
            },
            &mut out,
        )
        .unwrap();
        drop(out);
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(so).unwrap().trim()).expect("JSON envelope");
        let result = &v["result"];
        assert_eq!(result["enforced"].as_array().unwrap().len(), 4);
        assert!(result["not_enforced"].as_array().unwrap().is_empty());
        // Pre-L1-6 posture: no operator key was needed, so nothing was
        // re-signed and nothing was repaired.
        assert!(result["resigned"].as_array().unwrap().is_empty());
        assert!(result["repaired"].as_array().unwrap().is_empty());
    }

    /// v1.0.0 #3430 — `render_preview` must not call an inert row
    /// "already-on". Pre-#3430 an enabled row whose signature no longer
    /// verified rendered exactly like a healthy one.
    #[test]
    fn render_preview_flags_an_enabled_but_inert_row_3430() {
        use ed25519_dalek::Signer;
        let mut csprng = rand_core::OsRng;
        let signing = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = signing.verifying_key();

        // Sign R001 while disabled, then flip `enabled` beneath the
        // signature — the exact pre-#3430 corruption.
        let mut row = preview_rule("R001", r#"{"glob":"/tmp/**"}"#, false);
        row.attest_level = "operator_signed".into();
        let canonical = rules_store::canonical_bytes_for_signing(&row).unwrap();
        row.signature = Some(signing.sign(&canonical).to_bytes().to_vec());
        row.enabled = true;

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        render_preview(&mut out, std::slice::from_ref(&row), &[], Some(&pk)).unwrap();
        drop(out);
        let stdout = String::from_utf8(so).unwrap();
        assert!(
            stdout.contains("inert-badsig/will-repair"),
            "#3430: preview must not claim an inert row is already-on; got: {stdout}"
        );
        assert!(!stdout.contains("already-on"), "got: {stdout}");
    }

    #[test]
    fn install_defaults_reports_missing_rows() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        // Hand-delete R003.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM governance_rules WHERE id = 'R003'", [])
                .unwrap();
        }

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(&db_path, yes_args(), &mut out).unwrap();

        let stdout = String::from_utf8(so).unwrap();
        assert!(
            stdout.contains("1 missing") || stdout.contains("missing:   R003"),
            "stdout was: {stdout}",
        );
    }

    #[test]
    fn json_mode_emits_envelope() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(
            &db_path,
            InstallDefaultsArgs {
                yes: true,
                json: true,
                key_dir: None,
            },
            &mut out,
        )
        .unwrap();
        let stdout = String::from_utf8(so).unwrap();
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert_eq!(v["verb"], "governance.install-defaults");
        assert_eq!(v["result"]["activated"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn json_without_yes_refuses() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let (_dir, db_path) = fresh_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let err = run(
            &db_path,
            InstallDefaultsArgs {
                yes: false,
                json: true,
                key_dir: None,
            },
            &mut out,
        )
        .expect_err("expected refusal");
        assert!(
            err.to_string().contains("--json requires --yes"),
            "got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Coverage-uplift block (2026-05-19): exercise helper functions
    // (render_preview, load_seed_row) and additional run() branches that
    // the original 6 tests did not cover.
    // ------------------------------------------------------------------

    /// Build a preview-shaped [`Rule`] without touching SQLite.
    fn preview_rule(id: &str, matcher: &str, enabled: bool) -> Rule {
        Rule {
            id: id.into(),
            kind: "filesystem_write".into(),
            matcher: matcher.into(),
            severity: "refuse".into(),
            reason: "seed".into(),
            namespace: "_global".into(),
            created_by: "system:seed".into(),
            created_at: 0,
            enabled,
            signature: None,
            attest_level: "unsigned".into(),
        }
    }

    #[test]
    fn render_preview_emits_one_row_per_seeded_rule() {
        let preview = vec![
            preview_rule("R001", r#"{"glob":"/tmp/**"}"#, false),
            preview_rule("R002", r#"{"glob":"/var/tmp/**"}"#, true),
        ];
        let missing: Vec<String> = vec![];

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        // No operator pubkey resolved -> pre-L1-6 posture, so the
        // enabled row renders `already-on` exactly as before #3430.
        render_preview(&mut out, &preview, &missing, None).unwrap();
        drop(out);
        let stdout = String::from_utf8(so).unwrap();
        // Header line is present.
        assert!(stdout.contains("The following seed rules will be enabled"));
        // Both rule ids appear in the preview.
        assert!(stdout.contains("R001"));
        assert!(stdout.contains("R002"));
        // Disabled row prints "will-enable"; enabled row prints
        // "already-on" — both arms exercised.
        assert!(stdout.contains("will-enable"));
        assert!(stdout.contains("already-on"));
        // No "Warning" line — the missing list is empty.
        assert!(!stdout.contains("Warning"));
    }

    #[test]
    fn render_preview_emits_warning_block_when_missing_present() {
        let preview: Vec<Rule> = vec![];
        let missing = vec!["R003".to_string(), "R004".to_string()];

        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        render_preview(&mut out, &preview, &missing, None).unwrap();
        drop(out);
        let stdout = String::from_utf8(so).unwrap();
        // Warning + remediation lines fire.
        assert!(stdout.contains("Warning"));
        assert!(stdout.contains("R003"));
        assert!(stdout.contains("R004"));
        assert!(stdout.contains("re-run `ai-memory schema-init`"));
    }

    #[test]
    fn seed_row_load_returns_none_for_unknown_id() {
        let (_dir, db_path) = fresh_db();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let row = rules_store::get(&conn, "R999-nonexistent").unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn seed_row_load_returns_typed_row_with_disabled_default() {
        let (_dir, db_path) = fresh_db();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let row = rules_store::get(&conn, "R001").unwrap();
        let row = row.expect("R001 seeded");
        assert_eq!(row.id, "R001");
        assert_eq!(row.kind, "filesystem_write");
        assert_eq!(row.severity, "refuse");
        assert!(!row.enabled, "seeded rows ship at enabled = 0");
        assert_eq!(row.attest_level, "unsigned");
    }

    #[test]
    fn install_defaults_human_render_emits_activated_and_missing_lines() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        // Drives both `if !report.activated.is_empty()` and
        // `if !report.missing.is_empty()` writeln arms (lines ~173-178)
        // in a single run by hand-deleting one row before invoking run.
        let (_dir, db_path) = fresh_db();
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM governance_rules WHERE id = 'R002'", [])
                .unwrap();
        }
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(&db_path, yes_args(), &mut out).unwrap();
        drop(out);
        let stdout = String::from_utf8(so).unwrap();
        // Summary header with non-zero counts.
        assert!(stdout.contains("Activated 3 rule(s)"));
        assert!(stdout.contains("1 missing"));
        // Per-id "activated:" line fires when activated is non-empty.
        assert!(stdout.contains("  activated:"));
        // Per-id "missing:" line fires when missing is non-empty.
        assert!(stdout.contains("  missing:"));
        assert!(stdout.contains("R002"));
    }

    #[test]
    fn install_defaults_json_envelope_pins_wire_shape_when_partial_missing() {
        let _g = env_lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        // Hand-delete two rows, run with --json --yes, parse envelope.
        let (_dir, db_path) = fresh_db();
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "DELETE FROM governance_rules WHERE id IN ('R003','R004')",
                [],
            )
            .unwrap();
        }
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        run(
            &db_path,
            InstallDefaultsArgs {
                yes: true,
                json: true,
                key_dir: None,
            },
            &mut out,
        )
        .unwrap();
        drop(out);
        let stdout = String::from_utf8(so).unwrap();
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert_eq!(v["verb"], "governance.install-defaults");
        let result = &v["result"];
        // R001 + R002 activated; R003 + R004 missing.
        let activated = result["activated"].as_array().unwrap();
        assert_eq!(activated.len(), 2);
        let missing = result["missing"].as_array().unwrap();
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().any(|x| x == "R003"));
        assert!(missing.iter().any(|x| x == "R004"));
    }

    #[test]
    fn run_propagates_open_error_for_non_existent_db_with_unwritable_parent() {
        // db path under a non-existent directory cannot be opened —
        // exercises the with_context closure on Connection::open (lines
        // 101-106). The closure body fires only on the error path.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nonexistent-dir/missing.db");
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let err = run(&db_path, yes_args(), &mut out).expect_err("must fail");
        // The with_context closure runs and the formatted context is
        // attached to the error chain.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("governance install-defaults: open db at"),
            "expected context, got: {chain}"
        );
    }
}
