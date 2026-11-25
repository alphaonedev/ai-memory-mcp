// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory audit verify-rows` (#10040, vote V2-ROW-ATTEST-ANCHOR A-3):
//! run the row-attestation verifier against the deployment's trust anchor
//! and report its one outcome.
//!
//! Exit codes ([`crate::storage::row_attest::Outcome::exit_code`]): 0 clean,
//! 2 defective, 3 unanchored, 1 a hard error (the store cannot be opened or
//! read). An unanchored run never exits 0 and its JSON `outcome` is
//! `"unanchored"`, never `"clean"`: with no anchor no signature is checked,
//! and the verifier never falls back to a key held in the database.

use std::path::Path;

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::storage::row_attest::{AnchorStatus, Outcome, Report};

/// Exit code of a run that verified nothing (store not verifiable here).
pub const VERIFY_EXIT_ERROR: i32 = 1;

/// Arguments for `ai-memory audit verify-rows`.
#[derive(Args)]
pub struct VerifyRowsArgs {
    /// Emit a JSON report instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Run the verifier on `db_path` and print the report; returns the exit code.
///
/// # Errors
///
/// The store cannot be opened, or the verifier cannot read it.
pub fn run(args: &VerifyRowsArgs, db_path: &Path, out: &mut CliOutput<'_>) -> Result<i32> {
    // The verifier reads the sqlite store. A node whose resolved store is
    // postgres (or cannot be determined) is never reported from the local
    // sqlite file: that would certify a store that is not the one in use.
    let refusal = match crate::store_url::resolve_store_url(None) {
        Ok(Some(url)) if crate::store_url::is_postgres_url(&url) => Some((
            "postgres_store_not_verified",
            "the resolved store is postgres; this verifier reads the sqlite store only".to_string(),
        )),
        Ok(_) => None,
        Err(e) => Some((
            "store_indeterminate",
            format!("the store backend cannot be determined: {e:#}"),
        )),
    };
    if let Some((reason, detail)) = refusal {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                json!({"outcome": "error", "signatures_checked": false, "reason": reason, "detail": detail})
            )?;
        }
        writeln!(out.stderr, "audit verify-rows: {detail}")?;
        return Ok(VERIFY_EXIT_ERROR);
    }
    let conn = crate::db::open(db_path)?;
    let report = crate::storage::row_attest::sqlite::verify_sqlite(&conn)?;
    let outcome = report.outcome();
    if args.json {
        writeln!(out.stdout, "{}", report_json(&report, &outcome))?;
    } else {
        writeln!(out.stdout, "{}", report_line(&report, &outcome))?;
    }
    Ok(outcome.exit_code())
}

/// The JSON report: `outcome` is the machine name of [`Outcome`].
fn report_json(report: &Report, outcome: &Outcome) -> Value {
    let anchor = match &report.anchor {
        AnchorStatus::Anchored {
            source,
            layout_version,
            keys,
        } => json!({
            "status": "anchored",
            "source": source.display().to_string(),
            "layout_version": layout_version,
            "keys": keys.len(),
        }),
        AnchorStatus::Unanchored(why) => json!({
            "status": "unanchored",
            "reason": why.kind(),
            "detail": why.to_string(),
        }),
    };
    let tables: serde_json::Map<String, Value> = report
        .tables
        .iter()
        .map(|(name, t)| {
            (
                name.clone(),
                json!({"verified": t.verified, "attestations": t.attestations}),
            )
        })
        .collect();
    json!({
        "outcome": outcome.kind(),
        "signatures_checked": matches!(report.anchor, AnchorStatus::Anchored { .. }),
        "anchor": anchor,
        "defects": report.defects.len(),
        "first_defect": report.defects.first(),
        "unverified_memories": report.unverified_memories.len(),
        "tables": tables,
    })
}

/// The one-line text report.
fn report_line(report: &Report, outcome: &Outcome) -> String {
    match outcome {
        Outcome::Clean => format!(
            "row attestations: clean ({} tables verified against the trust anchor)",
            report.tables.len()
        ),
        Outcome::Unanchored(why) => format!(
            "row attestations: UNANCHORED ({}): {why}; no signature was checked",
            why.kind()
        ),
        Outcome::Defective { count, first } => {
            format!("row attestations: DEFECTIVE ({count} defects); first: {first}")
        }
    }
}
