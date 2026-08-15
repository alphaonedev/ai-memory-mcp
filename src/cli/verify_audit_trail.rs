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

    /// v1.0.0 pg-parity PR-B — verify the audit chain against a
    /// POSTGRES store instead of the local sqlite `--db`. Accepts a
    /// `postgres://…` DSN (a `sqlite:///path` is also honored, opening
    /// that file rather than `--db`). When present, the exact `serve` /
    /// `curator` `--store-url` precedent applies: the non-argv
    /// `AI_MEMORY_STORE_URL_FILE` (a `0600` file, #1927) and
    /// `AI_MEMORY_STORE_URL` channels take precedence over this
    /// world-readable argv value. The exit-code + verdict contract is
    /// identical to the sqlite path (dirty → exit 1; the `K1`/`K2`
    /// require-mode flags such as `AI_MEMORY_REQUIRE_WITNESS` are still
    /// honored). Postgres requires a binary built with
    /// `--features sal-postgres`.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,

    /// v1.0.0 L4 (PR-3) — out-of-band AUDIT pin: the daemon audit key's PUBLIC
    /// verifying key as url-safe-no-pad base64 (32 raw bytes). When enrolled,
    /// every walked `signed_events` row must positively verify against this key
    /// (or the recorder pin); an unverifiable / stripped / DOWNGRADED row makes
    /// the report DIRTY (exit 1). Highest precedence over the
    /// `AI_MEMORY_AUDIT_PUBKEY` env var; NO on-disk fallback (a `.pub` beside the
    /// key an attacker already owns is not a trust anchor). Unset = the pin is
    /// unenrolled and signature coverage is INFORMATIONAL only (byte-identical
    /// legacy — rotated / restored / federated nodes do not regress). The value
    /// is resolved to a key in the binary's SYNCHRONOUS pre-runtime phase and
    /// threaded as a parameter — never re-published to the environment.
    #[arg(long, value_name = "BASE64")]
    pub audit_pubkey: Option<String>,
}

/// Run the audit-trail verifier. Returns the desired process exit
/// code (0 when the chain is intact with no gaps, 1 otherwise).
///
/// # Errors
///
/// Returns the underlying `rusqlite`, serializer, or formatter error
/// if the DB open, chain walk, or report rendering fails.
pub fn run(
    db_path: &Path,
    args: &VerifyAuditTrailArgs,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let conn =
        crate::db::open(db_path).with_context(|| format!("open db at {}", db_path.display()))?;
    let report =
        crate::signed_events::verify_audit_trail(&conn, args.since.as_deref(), audit_pubkey)
            .context("verify_audit_trail over signed_events")?;
    render(&report, args.json, out)
}

/// Render an already-computed [`crate::signed_events::AuditTrailReport`]
/// to `out` and return the process exit code (0 clean, 1 dirty). Split
/// out of [`run`] (v1.0.0 pg-parity PR-B) so the postgres `--store-url`
/// path ([`crate::store::postgres::PostgresStore::verify_audit_trail`]),
/// which produces the SAME report shape via the SAME shared verdict fns
/// (GATE K3 parity), renders BYTE-FOR-BYTE identically to the sqlite
/// path — the exit-code + output contract is defined once, here.
///
/// # Errors
///
/// Returns the serializer or formatter error if the JSON serialization
/// or report write fails.
pub fn render(
    report: &crate::signed_events::AuditTrailReport,
    json: bool,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let clean = report.is_clean();

    if json {
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
        // #1873 (CWE-354) — surface a same-length suffix rewrite the seq-only
        // truncation check misses (head-row canonical hash != anchored hash at
        // equal sequence). Unknown/NotDetected are silent (withhold / clean).
        if let crate::signed_events::HeadHashCheck::Mismatch { chain, detail } = &report.head_hash {
            writeln!(
                out.stdout,
                "  audit-head HASH mismatch on {chain} (same-length suffix rewrite): {detail}",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?;
        }
        // v1.0.0 L4 (PR-3) — surface an audit-pin signature-coverage failure.
        // Only `Unverified` (an audit pin IS enrolled and some walked row did
        // not positively verify) is dirty; Unenforced/Verified are silent.
        if let crate::signed_events::SignatureCheck::Unverified {
            checked,
            unverified,
        } = report.signature_check
        {
            writeln!(
                out.stdout,
                "  audit-signature coverage FAIL (AI_MEMORY_AUDIT_PUBKEY pin enrolled): \
                 {unverified} of {checked} walked row(s) did not verify against the pin \
                 (stripped / downgraded / forged / skip-class row)",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?;
        }
        // #1822 G5b — surface the INDEPENDENT dual-chain witness verdict (K1).
        match &report.witness {
            crate::signed_events::WitnessCheck::Detected {
                chain,
                witness_head,
                db_head,
            } => writeln!(
                out.stdout,
                "  witness truncation detected on {chain}: witness head={witness_head} \
                 but in-DB head={db_head} ({} row(s) removed)",
                witness_head - db_head,
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::WitnessCheck::Forged { detail } => {
                writeln!(
                    out.stdout,
                    "  witness anchor FORGED (K1 pin failed): {detail}"
                )
                .context(CTX_WRITE_AUDIT_REPORT)?;
            }
            crate::signed_events::WitnessCheck::Missing => writeln!(
                out.stdout,
                "  witness anchor MISSING but AI_MEMORY_REQUIRE_WITNESS is set (fail-closed)",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::WitnessCheck::Unknown
            | crate::signed_events::WitnessCheck::NotDetected => {}
        }
        // #1826 G9 — surface a three-key role-separation failure.
        match &report.role_separation {
            crate::signed_events::RoleSeparationCheck::Forged { detail } => writeln!(
                out.stdout,
                "  role-separation FORGED (three-key signing layer): {detail}"
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::RoleSeparationCheck::Misconfigured { detail } => {
                writeln!(out.stdout, "  role-separation MISCONFIGURED: {detail}")
                    .context(CTX_WRITE_AUDIT_REPORT)?
            }
            crate::signed_events::RoleSeparationCheck::Missing => writeln!(
                out.stdout,
                "  role-separation MISSING but AI_MEMORY_REQUIRE_ROLE_SEPARATION is set \
                 (fail-closed)",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::RoleSeparationCheck::Unknown
            | crate::signed_events::RoleSeparationCheck::NotDetected => {}
        }
        // #1828 G13 — surface an identity-lineage failure.
        match &report.lineage {
            crate::identity::lineage::LineageCheck::Forged { detail } => writeln!(
                out.stdout,
                "  identity-lineage FORGED (succession chain failed verification): {detail}"
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::identity::lineage::LineageCheck::Missing => writeln!(
                out.stdout,
                "  identity-lineage MISSING but AI_MEMORY_REQUIRE_IDENTITY_LINEAGE is set \
                 (fail-closed)",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            // v1.0.0 #1949 — chain verifies but is revoked (verdict-surface).
            crate::identity::lineage::LineageCheck::Revoked { detail, .. } => writeln!(
                out.stdout,
                "  identity-lineage REVOKED (chain still verifies; entries in the Suspect \
                 window are SUSPECT, not un-verified): {detail}"
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::identity::lineage::LineageCheck::Unknown
            | crate::identity::lineage::LineageCheck::NotDetected => {}
        }
        // v1.0.0 #1946 (A1) — surface the OFF-TABLE rollback-evidence verdict.
        match &report.rollback {
            crate::signed_events::RollbackCheck::Evidence {
                anchored_head,
                db_head,
            } => writeln!(
                out.stdout,
                "  ROLLBACK EVIDENCE (off-table anchor): witness-anchored head={anchored_head} \
                 but surviving in-DB head={db_head} ({} head(s) rolled back) — attest a \
                 sanctioned DR restore with `ai-memory restore-attest --sign`, else investigate",
                anchored_head - db_head,
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::RollbackCheck::Missing => writeln!(
                out.stdout,
                "  rollback check: no pinnable off-table anchor but \
                 AI_MEMORY_REQUIRE_ROLLBACK_CHECK is set (fail-closed)",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::RollbackCheck::Sanctioned {
                anchored_head,
                db_head,
            } => writeln!(
                out.stdout,
                "  rollback below the off-table anchor (head={anchored_head}, in-DB={db_head}) is \
                 OPERATOR-SANCTIONED (attested DR restore) — not dirty",
            )
            .context(CTX_WRITE_AUDIT_REPORT)?,
            crate::signed_events::RollbackCheck::Unknown
            | crate::signed_events::RollbackCheck::NotDetected
            | crate::signed_events::RollbackCheck::NotApplicable => {}
        }
        // #1822 G5b — surface a require-mode cause-binding coverage failure.
        if let crate::signed_events::CauseBinding::Detected { rows_without_cause } =
            report.cause_binding
        {
            writeln!(
                out.stdout,
                "  cause-binding required but {rows_without_cause} row(s) have no bound cause \
                 (AI_MEMORY_REQUIRE_CAUSE_BINDING is set; fail-closed)",
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
            store_url: None,
            audit_pubkey: None,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
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
            store_url: None,
            audit_pubkey: None,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
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
