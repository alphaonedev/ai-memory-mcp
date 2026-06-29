// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory verify-audit-trail` — verify the append-only
//! `signed_events` V-4 cross-row hash chain end-to-end and surface
//! any gaps for operator review.
//!
//! # v0.8.0 §22 Policy-Engine PE-8 (#697 / EPIC #1709)
//!
//! Sits alongside `verify-signed-events-chain` (the lower-level
//! sequence-scoped chain verifier) but targets the OPERATOR review
//! workflow: it scopes the report by RFC3339 `--since` timestamp (the
//! column an auditor actually has, not an opaque sequence number),
//! enumerates EVERY contiguity gap (not just the first break), and
//! still verifies the cross-row hash links across the `--since`
//! boundary so a windowed view never falsely reports the first
//! in-window row as a break.
//!
//! Reuses [`crate::signed_events::verify_audit_trail`], which in turn
//! reuses [`crate::signed_events::verify_chain`] — no chain crypto is
//! reimplemented at the CLI layer.
//!
//! ## Exit codes
//!
//! - `0` — chain intact and no sequence gaps (the all-clear).
//! - `1` — a chain break OR a sequence gap was detected (scriptable
//!   in CI, mirroring `verify-signed-events-chain`).
//!
//! ## Output formats
//!
//! - default — human-readable report on stdout.
//! - `--json` — the serialised
//!   [`crate::signed_events::AuditTrailReport`].

use anyhow::{Context, Result};
use std::path::Path;

use crate::cli::CliOutput;

/// Shared `.context` label for the report-write paths (pm-v3.1
/// literal de-dup — referenced at every `writeln!` site below).
const CTX_WRITE_AUDIT_REPORT: &str = "write audit-trail report";

/// Arguments for `ai-memory verify-audit-trail`.
#[derive(clap::Args, Debug)]
pub struct VerifyAuditTrailArgs {
    /// Scope the report to audit events at/after this RFC3339
    /// timestamp (e.g. `2026-06-17T00:00:00Z`). The cross-row hash
    /// chain is STILL verified across the window boundary, so the
    /// first in-window row is never falsely reported as a break.
    /// Omit to verify the entire table.
    #[arg(long, value_name = "TIMESTAMP")]
    pub since: Option<String>,

    /// Emit the machine-readable JSON report instead of the
    /// human-readable summary.
    #[arg(long)]
    pub json: bool,
}

/// Run the audit-trail verifier. Returns the desired process exit
/// code (0 when the chain is intact with no gaps, 1 otherwise).
///
/// # Errors
///
/// Returns the underlying `rusqlite`, serializer, or formatter error
/// if the DB open, chain walk, or report rendering fails.
pub fn run(db_path: &Path, args: &VerifyAuditTrailArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    let conn =
        crate::db::open(db_path).with_context(|| format!("open db at {}", db_path.display()))?;
    let report = crate::signed_events::verify_audit_trail(&conn, args.since.as_deref())
        .context("verify_audit_trail over signed_events")?;
    let clean = report.is_clean();

    if args.json {
        let json = serde_json::to_string_pretty(&report).context("serialize audit-trail report")?;
        writeln!(out.stdout, "{json}").context(CTX_WRITE_AUDIT_REPORT)?;
    } else if clean {
        writeln!(
            out.stdout,
            "verify-audit-trail OK: chain intact \u{2713} ({} event(s) checked, head sequence={})",
            report.total_events, report.head_sequence,
        )
        .context(CTX_WRITE_AUDIT_REPORT)?;
    } else {
        writeln!(
            out.stdout,
            "verify-audit-trail FAIL: chain integrity issue \u{2717} \
             ({} event(s) checked, head sequence={})",
            report.total_events, report.head_sequence,
        )
        .context(CTX_WRITE_AUDIT_REPORT)?;
        if let Some(seq) = report.first_break_sequence {
            writeln!(out.stdout, "  chain break first detected at sequence={seq}")
                .context(CTX_WRITE_AUDIT_REPORT)?;
        }
        // #1850 (CWE-354) — surface an off-table tail-truncation verdict.
        if let crate::signed_events::TruncationCheck::Detected {
            anchored_head,
            db_head,
        } = report.truncation
        {
            writeln!(
                out.stdout,
                "  tail truncation detected: off-table anchor head={anchored_head} \
                 but in-DB head={db_head} ({} trailing row(s) removed)",
                anchored_head - db_head,
            )
            .context(CTX_WRITE_AUDIT_REPORT)?;
        }
        for (from, to) in &report.sequence_gaps {
            if from == to {
                writeln!(out.stdout, "  sequence gap: {from} missing")
                    .context(CTX_WRITE_AUDIT_REPORT)?;
            } else {
                writeln!(out.stdout, "  sequence gap: {from}..={to} missing")
                    .context(CTX_WRITE_AUDIT_REPORT)?;
            }
        }
    }

    Ok(i32::from(!clean))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_events::{SignedEvent, append_signed_event, payload_hash};

    fn fixture_event(payload: &[u8]) -> SignedEvent {
        SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".to_string(),
            event_type: crate::signed_events::event_types::MEMORY_LINK_CREATED.to_string(),
            payload_hash: payload_hash(payload),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        }
    }

    fn temp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("verify-audit-trail-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("test.db");
        drop(crate::db::open(&path).expect("init db"));
        (dir, path)
    }

    #[test]
    fn empty_db_exits_zero_intact() {
        let (_dir, path) = temp_db();
        let args = VerifyAuditTrailArgs {
            since: None,
            json: true,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, &mut out).expect("run");
        assert_eq!(code, 0, "empty chain is trivially clean");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("\"chain_intact\": true"), "got: {s}");
        assert!(s.contains("\"total_events\": 0"), "got: {s}");
    }

    #[test]
    fn clean_chain_exits_zero_text() {
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            for i in 0..3 {
                append_signed_event(&conn, &fixture_event(format!("payload-{i}").as_bytes()))
                    .expect("append");
            }
        }
        let args = VerifyAuditTrailArgs {
            since: None,
            json: false,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, &mut out).expect("run");
        assert_eq!(code, 0, "3-row clean chain is clean; got code={code}");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("OK"), "got: {s}");
        assert!(s.contains("3 event(s) checked"), "got: {s}");
    }

    // Note: tamper / gap exit-code-1 paths require an `UPDATE` /
    // `DELETE signed_events` which would trip the
    // `append_only_invariant_no_mutators_in_src` H5 guard if written
    // from a `src/` file. They live in the integration test
    // `tests/verify_audit_trail_pe8.rs` instead (same split rationale
    // as `verify_signed_events.rs`).
}
