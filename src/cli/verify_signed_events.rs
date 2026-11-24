// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory verify-signed-events-chain` — walk the SQL-side
//! `signed_events` cross-row hash chain (v34, #698 V-4 closeout) and
//! emit a structured chain-integrity report.
//!
//! Distinct from `verify-reflection-chain` (which walks the
//! reflects_on edges in `memory_links`) and from `audit verify`
//! (which walks the JSONL audit log under `<audit_dir>/audit.log`).
//! Three complementary verifiers, three load-bearing properties:
//!
//! - `verify-signed-events-chain` (this surface): the SQL-side
//!   cross-row hash chain on `signed_events`. Daemon-local
//!   tamper-evidence; auditor reads it directly from the database.
//! - `audit verify`: the on-disk JSONL chain. Portable evidence
//!   format for handoff to a SIEM.
//! - `verify-reflection-chain`: per-edge Ed25519 signatures on
//!   `reflects_on` links. Reflection ancestry attestation.
//!
//! ## Verifier (#10074, S-8)
//!
//! The walk verifies daemon signatures against the `--audit-pubkey` pin (or
//! `AI_MEMORY_AUDIT_PUBKEY`) when enrolled, else the in-process daemon key, so
//! every [`crate::signed_events::SignatureFailure`] class — including
//! `LegacyPayloadOnlyAfterCutoff` — is reachable from the command line.
//!
//! ## Legacy cutoff mint (#10074, S-3)
//!
//! `--mint-legacy-cutoff` is the ONE explicit operator order that mints the
//! legacy cutoff row (`3-agent vote (71472661) V1-SIGNED-EVENTS-FALLBACK`). No
//! boot, upgrade, migration or config path mints. The mint refuses when a
//! cutoff row or its off-table anchor already exists, when the chain is empty
//! or broken, or when any daemon row verifies under no form. With
//! `--store-url postgres://...` it mints on the postgres store.
//!
//! ## Exit codes
//!
//! - `0` — the chain holds and no row failed its signature check (or the
//!   cutoff was minted). Exit 0 is NOT "fully verified": agent-signed rows
//!   (#10105) are linkage-checked but their signatures are not verified by
//!   this walk; they are counted in `agent_signed_rows_not_verified`, and the
//!   JSON `fully_verified` field is `true` only when every walked row
//!   positively verified.
//! - `1` — chain break, or at least one row failed its signature check
//!   (an agent-signed row with a missing or malformed signature included),
//!   or the mint refused.
//!
//! ## Output formats
//!
//! - `--format text` (default) — one-line human report on stdout.
//! - `--format json` — machine-parseable report mirroring the
//!   [`crate::signed_events::ChainVerificationReport`] shape.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

use crate::cli::CliOutput;
use crate::signed_events::{LegacyCutoffMint, LegacyCutoffMinted};

/// Shared `.context` label for the chain-report write paths (#1558 batch 6).
const CTX_WRITE_CHAIN_REPORT: &str = "write chain report";

/// Arguments for `ai-memory verify-signed-events-chain`.
#[derive(clap::Args, Debug, Default)]
pub struct VerifySignedEventsChainArgs {
    /// Lower-bound sequence (exclusive). Rows with
    /// `sequence > since` are walked; rows at or below `since` are
    /// trusted as previously-verified. Default 0 (walk every row).
    #[arg(long, value_name = "SEQUENCE", default_value_t = 0)]
    pub since: i64,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// #10074 — the daemon verifying key (base64 Ed25519) to verify daemon
    /// signatures against; falls back to `AI_MEMORY_AUDIT_PUBKEY`, then the
    /// in-process daemon key.
    #[arg(long, value_name = "BASE64")]
    pub audit_pubkey: Option<String>,

    /// #10074 — explicit operator order: mint the single legacy cutoff row
    /// (once per database). Refuses when a cutoff or its anchor exists.
    #[arg(long)]
    pub mint_legacy_cutoff: bool,

    /// #10074 — with `--mint-legacy-cutoff` only: mint on this store
    /// (`postgres://...`). Verify a postgres store with
    /// `verify-audit-trail --store-url`.
    #[arg(long, value_name = "URL", requires = "mint_legacy_cutoff")]
    pub store_url: Option<String>,
}

/// JSON-serialised mirror of
/// [`crate::signed_events::ChainVerificationReport`]. We don't
/// derive `Serialize` on the original because it lives in a
/// non-CLI module; the CLI layer owns the wire shape.
#[derive(Debug, Serialize)]
pub struct ChainVerifyReportJson {
    pub rows_checked: u64,
    pub chain_break: Option<i64>,
    pub signature_failures: Vec<i64>,
    pub chain_holds: bool,
    /// Rows whose signature positively verified against an enrolled key.
    pub rows_positively_verified: u64,
    /// #10105 — agent-signed rows the walk linkage-checked but did NOT verify.
    pub agent_signed_rows_not_verified: u64,
    /// #10105 — agent-signed rows with a missing or malformed signature.
    pub agent_signature_defects: Vec<AgentSignatureDefectJson>,
    /// `true` only when the chain holds, no row failed, and EVERY walked row
    /// positively verified (so never while `agent_signed_rows_not_verified > 0`).
    pub fully_verified: bool,
}

/// #10105 — one agent-signed row defect on the JSON wire.
#[derive(Debug, Serialize)]
pub struct AgentSignatureDefectJson {
    pub sequence: i64,
    pub reason: &'static str,
}

/// #10105 — the text note for agent-signed rows this walk did not verify.
fn agent_rows_note(count: u64) -> String {
    format!(
        "verify-signed-events-chain NOTE: {count} agent-signed row(s) NOT verified by this \
         walk (chain linkage checked; the signature is owned by its domain verifier)"
    )
}

/// #10074 — the dispatch entry: the postgres mint when `--store-url` names a
/// postgres store, else [`run`] on the sqlite database.
///
/// # Errors
/// Propagates a store-url, connect, mint or render error.
pub async fn dispatch(
    db_path: &Path,
    args: &VerifySignedEventsChainArgs,
    app_config: &crate::config::AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    if args.mint_legacy_cutoff {
        let resolved = crate::store_url::resolve_store_url(args.store_url.as_deref())?;
        if let Some(url) = resolved.as_deref()
            && crate::store_url::is_postgres_url(url)
        {
            let minted = mint_postgres(url, app_config).await?;
            return render_mint(minted, out);
        }
    }
    run(db_path, args, audit_pubkey, out)
}

#[cfg(feature = "sal-postgres")]
async fn mint_postgres(
    url: &str,
    app_config: &crate::config::AppConfig,
) -> Result<LegacyCutoffMint> {
    let timeout = app_config
        .postgres_statement_timeout_secs
        .unwrap_or(crate::store::postgres::DEFAULT_STATEMENT_TIMEOUT_SECS);
    let store = crate::store::postgres::PostgresStore::connect_with_dim_and_timeout(
        url,
        crate::store::postgres::DEFAULT_EMBEDDING_DIM,
        timeout,
        app_config.resolve_pg_pool(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("connect postgres adapter for the legacy cutoff mint: {e}"))?;
    store
        .mint_legacy_cutoff()
        .await
        .map_err(|e| anyhow::anyhow!("mint legacy cutoff over postgres signed_events: {e}"))
}

#[cfg(not(feature = "sal-postgres"))]
#[allow(clippy::unused_async)]
async fn mint_postgres(
    url: &str,
    _app_config: &crate::config::AppConfig,
) -> Result<LegacyCutoffMint> {
    anyhow::bail!(
        "--store-url postgres:// requires the binary to be built with \
         --features sal-postgres; this binary was built without it (minting on {})",
        crate::url_display::store_url_display(url)
    )
}

/// Render a mint outcome; exit 0 on a minted cutoff or a repaired anchor
/// (#10104), 1 on a refusal.
fn render_mint(minted: LegacyCutoffMint, out: &mut CliOutput<'_>) -> Result<i32> {
    match minted {
        Ok(LegacyCutoffMinted::Minted(seq)) => {
            writeln!(
                out.stdout,
                "verify-signed-events-chain: minted the legacy cutoff row at sequence={seq}"
            )
            .context(CTX_WRITE_CHAIN_REPORT)?;
            Ok(0)
        }
        Ok(LegacyCutoffMinted::AnchorRepaired(seq)) => {
            writeln!(
                out.stdout,
                "verify-signed-events-chain: repaired the off-table anchor of the legacy cutoff \
                 row at sequence={seq}"
            )
            .context(CTX_WRITE_CHAIN_REPORT)?;
            Ok(0)
        }
        Err(refusal) => {
            writeln!(
                out.stderr,
                "verify-signed-events-chain: legacy cutoff mint refused: {refusal}"
            )
            .context(CTX_WRITE_CHAIN_REPORT)?;
            Ok(1)
        }
    }
}

/// Run the verifier (or, with `--mint-legacy-cutoff`, the sqlite mint).
/// Returns the desired process exit code: 0 when the chain holds and no row
/// failed its signature check, 1 otherwise.
///
/// # Errors
///
/// Returns the underlying `rusqlite` or formatter error if the SQL
/// query or the report rendering fails.
pub fn run(
    db_path: &Path,
    args: &VerifySignedEventsChainArgs,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let conn =
        crate::db::open(db_path).with_context(|| format!("open db at {}", db_path.display()))?;
    if args.mint_legacy_cutoff {
        let minted = crate::signed_events::mint_legacy_cutoff(&conn)
            .context("mint legacy cutoff over signed_events")?;
        return render_mint(minted, out);
    }
    let since = if args.since > 0 {
        Some(args.since)
    } else {
        None
    };
    let report = crate::signed_events::verify_chain(&conn, since, audit_pubkey)
        .context("verify_chain over signed_events")?;
    let holds = report.chain_holds();
    let clean = holds && report.signature_failures.is_empty();
    let fully_verified = clean && report.rows_positively_verified == report.rows_checked;

    match args.format.as_str() {
        "json" => {
            let wire = ChainVerifyReportJson {
                rows_checked: report.rows_checked,
                chain_break: report.chain_break,
                signature_failures: report.signature_failures.clone(),
                chain_holds: holds,
                rows_positively_verified: report.rows_positively_verified,
                agent_signed_rows_not_verified: report.agent_signed_rows_not_verified,
                agent_signature_defects: report
                    .agent_signature_defects
                    .iter()
                    .map(|&(sequence, f)| AgentSignatureDefectJson {
                        sequence,
                        reason: f.reason(),
                    })
                    .collect(),
                fully_verified,
            };
            let json = serde_json::to_string_pretty(&wire).context("serialize chain report")?;
            writeln!(out.stdout, "{json}").context(CTX_WRITE_CHAIN_REPORT)?;
        }
        _ => {
            // text — one-line summary on stdout.
            if clean {
                writeln!(
                    out.stdout,
                    "verify-signed-events-chain OK: {} row(s) walked, chain holds",
                    report.rows_checked,
                )
                .context(CTX_WRITE_CHAIN_REPORT)?;
            } else if holds {
                writeln!(
                    out.stdout,
                    "verify-signed-events-chain FAIL: {} row(s) failed the signature check \
                     at sequence(s) {:?} ({} row(s) walked)",
                    report.signature_failures.len(),
                    report.signature_failures,
                    report.rows_checked,
                )
                .context(CTX_WRITE_CHAIN_REPORT)?;
            } else {
                let where_ = report
                    .chain_break
                    .map_or_else(|| "<unknown>".to_string(), |s| s.to_string());
                writeln!(
                    out.stdout,
                    "verify-signed-events-chain FAIL: chain break at sequence={where_} \
                     ({} row(s) walked)",
                    report.rows_checked,
                )
                .context(CTX_WRITE_CHAIN_REPORT)?;
            }
            if report.agent_signed_rows_not_verified > 0 {
                writeln!(
                    out.stdout,
                    "{}",
                    agent_rows_note(report.agent_signed_rows_not_verified)
                )
                .context(CTX_WRITE_CHAIN_REPORT)?;
            }
            for &(seq, f) in &report.agent_signature_defects {
                writeln!(
                    out.stdout,
                    "verify-signed-events-chain DEFECT: sequence={seq} {}",
                    f.reason()
                )
                .context(CTX_WRITE_CHAIN_REPORT)?;
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
            .prefix("verify-signed-events-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("test.db");
        drop(crate::db::open(&path).expect("init db"));
        (dir, path)
    }

    #[test]
    fn empty_db_reports_zero_rows_chain_holds() {
        let (_dir, path) = temp_db();
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "json".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 0, "empty chain holds vacuously");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("\"chain_holds\": true"), "got: {s}");
        assert!(s.contains("\"rows_checked\": 0"), "got: {s}");
    }

    #[test]
    fn populated_db_reports_chain_ok() {
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            for i in 0..3 {
                append_signed_event(&conn, &fixture_event(format!("payload-{i}").as_bytes()))
                    .expect("append");
            }
        }
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "text".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 0, "3-row clean chain holds; got code={code}");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("OK"), "got: {s}");
        assert!(s.contains("3 row(s) walked"), "got: {s}");
    }

    // Note: The tampered-chain → exit-code-1 path is covered by the
    // integration test `tests/signed_events_chain_v34.rs::
    // tamper_in_middle_row_breaks_chain` (calling `verify_chain`
    // directly) and is intentionally NOT duplicated here — exercising
    // `UPDATE signed_events` from a `src/` file (even under `#[cfg(test)]`)
    // would trip the `append_only_invariant_no_mutators_in_src`
    // guard in `signed_events.rs`.

    // ----------------------------------------------------------------
    // C-3 coverage uplift — drive `since > 0` branch (line 80) and the
    // FAIL render path (lines 109-118). We trigger a chain break with
    // a raw INSERT that supplies a wrong sequence — pure INSERTs are
    // not flagged by the append-only invariant guard which scans for
    // UPDATE/DELETE only.
    // ----------------------------------------------------------------

    #[test]
    fn since_filter_excludes_lower_sequences() {
        // Drives the `since > 0` -> `Some(...)` arm at line 80.
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            for i in 0..3 {
                append_signed_event(&conn, &fixture_event(format!("p-{i}").as_bytes()))
                    .expect("append");
            }
        }
        let args = VerifySignedEventsChainArgs {
            since: 1,
            format: "json".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 0, "filtered chain still holds");
        let s = String::from_utf8(buf_out).expect("utf-8");
        // We skipped sequence=1, so 2 rows walked.
        assert!(s.contains("\"rows_checked\": 2"), "got: {s}");
    }

    #[test]
    fn broken_chain_text_format_reports_fail_with_sequence() {
        // Drives lines 99-118: the text-format FAIL branch with a real
        // chain break and the `where_` resolution from `chain_break`.
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            // Seed two clean rows.
            append_signed_event(&conn, &fixture_event(b"p-0")).expect("append-1");
            append_signed_event(&conn, &fixture_event(b"p-1")).expect("append-2");
            // Insert a tampered row that lies about its sequence to
            // create a gap. INSERT only — does not trip the append-only
            // mutator scan (UPDATE/DELETE).
            conn.execute(
                "INSERT INTO signed_events \
                 (id, agent_id, event_type, payload_hash, signature, attest_level, \
                  timestamp, prev_hash, sequence) \
                 VALUES (?1, ?2, ?3, ?4, NULL, 'unsigned', ?5, X'00', 99)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    "alice",
                    "memory_link.created",
                    payload_hash(b"p-99"),
                    chrono::Utc::now().to_rfc3339(),
                ],
            )
            .expect("raw INSERT tampered row");
        }
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "text".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 1, "chain break must produce exit code 1");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("FAIL"), "must say FAIL; got: {s}");
        assert!(
            s.contains("chain break at sequence="),
            "must surface break; got: {s}"
        );
    }

    #[test]
    fn broken_chain_json_format_carries_chain_break() {
        // Drives the JSON-format FAIL summary (the JSON arm
        // independent of holds=true/false).
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            append_signed_event(&conn, &fixture_event(b"p-0")).expect("append-1");
            conn.execute(
                "INSERT INTO signed_events \
                 (id, agent_id, event_type, payload_hash, signature, attest_level, \
                  timestamp, prev_hash, sequence) \
                 VALUES (?1, ?2, ?3, ?4, NULL, 'unsigned', ?5, X'00', 42)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    "alice",
                    "memory_link.created",
                    payload_hash(b"p-42"),
                    chrono::Utc::now().to_rfc3339(),
                ],
            )
            .expect("raw INSERT");
        }
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "json".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 1);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("\"chain_holds\": false"), "got: {s}");
        // chain_break carries the offending sequence (one of 2 or 42).
        assert!(s.contains("\"chain_break\":"), "got: {s}");
    }

    #[test]
    fn default_format_falls_back_to_text() {
        // The `_ =>` arm at line 99 fires for any non-`json` value —
        // including an empty string, "yaml", or the actual default
        // "text". Confirms the default-arm dispatch.
        let (_dir, path) = temp_db();
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "yaml-unrecognised".to_string(),
            ..VerifySignedEventsChainArgs::default()
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("OK"), "must hit text branch; got: {s}");
    }
}
