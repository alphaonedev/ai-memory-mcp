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
//! ## Exit codes
//!
//! - `0` — chain fully verified. The OK line states the coverage, including
//!   `unanchored_tail=N`: the rows above the last off-table anchor, whose
//!   removal is NOT detectable yet (no per-append signed head anchor exists).
//! - `1` — a finding: nothing that could be checked was found, or the chain
//!   does not hold (#9046 / #8741 / #9179). Absence is a finding, never a
//!   vacuous green; every finding prints one
//!   `verify-signed-events-chain FAIL: <reason>: <detail>` line on stderr
//!   (and, with `--format json`, a `status: "fail"` body with the same
//!   `reason` on stdout), carrying exactly one reason code:
//!   - [`REASON_STORE_IS_POSTGRES`] — a Postgres store is configured through
//!     a URL VALUE (`AI_MEMORY_STORE_URL`); a Postgres store is walked only
//!     when its URL comes from a `0600` URL FILE (`--store-url-file` or
//!     `AI_MEMORY_STORE_URL_FILE`), so the credential never sits in argv.
//!   - [`REASON_STORE_URL_UNRECOGNISED`] — the configured store URL is neither
//!     `postgres://` nor `sqlite://` (it is never ignored in favour of `--db`).
//!   - [`REASON_STORE_MISSING`] — the SQLite file does not exist (not created).
//!   - [`REASON_EMPTY_CHAIN`] — the store has no `signed_events` rows.
//!   - [`REASON_HEAD_BELOW_SINCE`] — the chain head is at or below `--since`,
//!     so the window holds no row to check.
//!   - [`REASON_CHAIN_BREAK`] — the cross-row chain does not hold.
//!   - [`REASON_TAIL_TRUNCATED`] — the off-table anchor head is above the
//!     in-DB head: trailing rows were removed.
//!   - [`REASON_SIGNATURE_FAILED`] / [`REASON_SELF_SIGNED_UNVERIFIABLE`] — a
//!     present row signature does not verify (#8852).
//!   - [`REASON_SIGNATURE_UNVERIFIED`] — an audit pin
//!     (`AI_MEMORY_AUDIT_PUBKEY`) is enrolled and a walked row did not
//!     positively verify against it (stripped / downgraded row, #8852).
//!
//! ## Output formats
//!
//! - `--format text` (default) — one-line human report on stdout.
//! - `--format json` — machine-parseable [`ChainVerifyReportJson`].

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::cli::CliOutput;

/// Shared `.context` label for the chain-report write paths (#1558 batch 6).
const CTX_WRITE_CHAIN_REPORT: &str = "write chain report";

/// Exit code for every finding (chain break or absence).
pub const EXIT_FINDING: i32 = 1;
/// Reason: a Postgres store is configured without a URL file (#9046, #9179).
pub const REASON_STORE_IS_POSTGRES: &str = "store_is_postgres";
/// Reason: the configured store URL has an unrecognised scheme (#9179 r1).
pub const REASON_STORE_URL_UNRECOGNISED: &str = "store_url_unrecognised";
/// Reason: the SQLite file does not exist (#9046).
pub const REASON_STORE_MISSING: &str = "store_missing";
/// Reason: the store holds no `signed_events` rows (#8741).
pub const REASON_EMPTY_CHAIN: &str = "empty_chain";
/// Reason: the chain head sequence is at or below `--since` (#9008, #9179 r1).
pub const REASON_HEAD_BELOW_SINCE: &str = "head_below_since";
/// Reason: the cross-row hash chain does not hold.
pub const REASON_CHAIN_BREAK: &str = "chain_break";
/// Reason: the off-table anchor head is above the in-DB head (#1850 sibling).
pub const REASON_TAIL_TRUNCATED: &str = "tail_truncated";
/// Reason: a present row signature does not verify (#8852).
pub const REASON_SIGNATURE_FAILED: &str = "signature_failed";
/// Reason: a `self_signed` link row whose observer key is not known (#9162).
pub const REASON_SELF_SIGNED_UNVERIFIABLE: &str = "self_signed_unverifiable";
/// Reason: an audit pin is enrolled and a walked row did not verify (#8852).
pub const REASON_SIGNATURE_UNVERIFIED: &str = "signature_unverified";

/// Arguments for `ai-memory verify-signed-events-chain`.
#[derive(clap::Args, Debug)]
pub struct VerifySignedEventsChainArgs {
    /// Lower-bound sequence (exclusive). Rows with
    /// `sequence > since` are walked; rows at or below `since` are
    /// trusted as previously-verified. Default 0 (walk every row). A
    /// negative value is refused.
    #[arg(
        long,
        value_name = "SEQUENCE",
        default_value_t = 0,
        value_parser = clap::value_parser!(i64).range(0..)
    )]
    pub since: i64,

    /// Output format: `text` (default) or `json`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// Read the store URL from this file (owner-only `0600`, the
    /// `AI_MEMORY_STORE_URL_FILE` rules). This is the only way to walk a
    /// Postgres store with this verb: a connection URL is never taken from
    /// argv, where any local user can read it. `sqlite:///path` opens that
    /// file instead of `--db`. Overrides `AI_MEMORY_STORE_URL_FILE`.
    #[arg(long, value_name = "PATH")]
    pub store_url_file: Option<PathBuf>,
}

impl VerifySignedEventsChainArgs {
    fn json(&self) -> bool {
        self.format == "json"
    }
}

/// JSON body of the report. `status` is `ok` or `fail`; on `fail`, `reason`
/// carries the one reason code. The four original fields keep their meaning.
#[derive(Debug, Default, Serialize)]
pub struct ChainVerifyReportJson {
    pub status: &'static str,
    pub reason: Option<&'static str>,
    pub detail: Option<String>,
    pub rows_checked: u64,
    pub chain_break: Option<i64>,
    pub signature_failures: Vec<i64>,
    pub chain_holds: bool,
    /// Walked rows that did not positively verify against a key.
    pub rows_unverified: u64,
    /// Rows above the last off-table anchor: their removal is not detectable.
    pub unanchored_tail: Option<i64>,
}

/// Where the chain lives, after the store URL channels are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStore {
    /// A SQLite file.
    Sqlite(PathBuf),
    /// A Postgres store whose URL came from a `0600` URL file.
    Postgres(String),
    /// Refused before anything is opened: (reason, detail).
    Refused(&'static str, String),
}

/// Map one store URL to a [`ChainStore`]. `from_file` is true when the URL
/// came from a URL file; a Postgres URL from any other channel is refused.
#[must_use]
pub fn classify_store_url(url: &str, from_file: bool) -> ChainStore {
    if crate::store_url::is_postgres_url(url) {
        if from_file {
            return ChainStore::Postgres(url.to_string());
        }
        return ChainStore::Refused(
            REASON_STORE_IS_POSTGRES,
            "the configured store is Postgres and its URL is not in a URL file; pass \
             --store-url-file or AI_MEMORY_STORE_URL_FILE (a 0600 file)"
                .to_string(),
        );
    }
    if let Some(path) = sqlite_store_url_to_path(url) {
        return ChainStore::Sqlite(PathBuf::from(path));
    }
    ChainStore::Refused(
        REASON_STORE_URL_UNRECOGNISED,
        format!(
            "the configured store URL {} is neither postgres:// nor sqlite:///path",
            crate::url_display::store_url_display(url)
        ),
    )
}

/// Resolve the store this verb walks (#9179 r1 sec F1 / code F10b). Order:
/// `--store-url-file`, then `AI_MEMORY_STORE_URL_FILE`, then
/// `AI_MEMORY_STORE_URL`, then `--db`. A configured URL is never ignored.
///
/// # Errors
///
/// Returns the URL-file error (missing file, mode wider than `0600`, empty).
pub fn resolve_store(db_path: &Path, args: &VerifySignedEventsChainArgs) -> Result<ChainStore> {
    let env_file = std::env::var(crate::store_url::STORE_URL_FILE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    if let Some(file) = args.store_url_file.clone().or(env_file) {
        let url = crate::store_url::store_url_from_file(&file)
            .with_context(|| format!("read the store URL file {}", file.display()))?;
        return Ok(classify_store_url(&url, true));
    }
    if let Ok(url) = std::env::var(crate::store_url::STORE_URL_ENV) {
        let url = url.trim();
        if !url.is_empty() {
            return Ok(classify_store_url(url, false));
        }
    }
    Ok(ChainStore::Sqlite(db_path.to_path_buf()))
}

/// Emit one finding in the absence shape and return [`EXIT_FINDING`]: JSON
/// body on stdout in JSON mode (#9179 r1 F10c), one FAIL line on stderr.
///
/// # Errors
///
/// Returns the serializer or writer error.
pub fn finding(
    out: &mut CliOutput<'_>,
    args: &VerifySignedEventsChainArgs,
    reason: &'static str,
    detail: &str,
) -> Result<i32> {
    if args.json() {
        let body = ChainVerifyReportJson {
            status: "fail",
            reason: Some(reason),
            detail: Some(detail.to_string()),
            ..ChainVerifyReportJson::default()
        };
        let json = serde_json::to_string_pretty(&body).context("serialize chain report")?;
        writeln!(out.stdout, "{json}").context(CTX_WRITE_CHAIN_REPORT)?;
    }
    writeln!(
        out.stderr,
        "verify-signed-events-chain FAIL: {reason}: {detail}"
    )
    .context(CTX_WRITE_CHAIN_REPORT)?;
    Ok(EXIT_FINDING)
}

/// The backend-neutral result of one chain walk, rendered once by
/// [`render_verdict`] so both backends share the verdict (K3 parity).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainVerdict {
    /// Highest `sequence` in the table.
    pub head: i64,
    /// Rows the walk visited.
    pub rows_checked: u64,
    /// Rows that positively verified against a key.
    pub rows_positively_verified: u64,
    /// First chain break, if any.
    pub chain_break: Option<i64>,
    /// Sequences whose present signature failed, with the reason code.
    pub signature_failures: Vec<(i64, &'static str)>,
    /// An audit pin is enrolled (every walked row must verify).
    pub pin_enrolled: bool,
    /// Head of the last trusted off-table anchor, if one exists.
    pub anchored_head: Option<i64>,
    /// Postgres: the walk covered the whole chain, not only `> since`.
    pub whole_chain: bool,
}

impl ChainVerdict {
    /// Rows above the last off-table anchor (every row when none exists).
    #[must_use]
    pub fn unanchored_tail(&self) -> i64 {
        self.head
            .saturating_sub(self.anchored_head.unwrap_or(0))
            .max(0)
    }

    /// The finding this verdict carries, or `None` when green. Checked in a
    /// fixed order so one input always gives one reason.
    #[must_use]
    pub fn finding(&self) -> Option<(&'static str, String)> {
        if let Some(seq) = self.chain_break {
            return Some((REASON_CHAIN_BREAK, format!("at sequence={seq}")));
        }
        if let Some(anchored) = self.anchored_head.filter(|a| *a > self.head) {
            return Some((
                REASON_TAIL_TRUNCATED,
                format!(
                    "off-table anchor head={anchored} but in-DB head={} (at least {} \
                     trailing row(s) removed)",
                    self.head,
                    anchored.saturating_sub(self.head)
                ),
            ));
        }
        if let Some((seq, reason)) = self.signature_failures.first() {
            return Some((
                reason,
                format!(
                    "{} row signature(s) do not verify; first at sequence={seq}",
                    self.signature_failures.len()
                ),
            ));
        }
        let unverified = self
            .rows_checked
            .saturating_sub(self.rows_positively_verified);
        if self.pin_enrolled && unverified > 0 {
            return Some((
                REASON_SIGNATURE_UNVERIFIED,
                format!(
                    "{unverified} of {} walked row(s) did not verify against the enrolled \
                     AI_MEMORY_AUDIT_PUBKEY pin (stripped / downgraded / unsigned row); \
                     note: {}",
                    self.rows_checked,
                    crate::governance::audit::UNSIGNED_PREFIX_LIMITATION
                ),
            ));
        }
        None
    }
}

/// Render a [`ChainVerdict`] and return the exit code (0 green, else
/// [`EXIT_FINDING`]).
///
/// # Errors
///
/// Returns the serializer or writer error.
pub fn render_verdict(
    v: &ChainVerdict,
    args: &VerifySignedEventsChainArgs,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    if v.head == 0 {
        return finding(
            out,
            args,
            REASON_EMPTY_CHAIN,
            "the store holds no signed_events rows",
        );
    }
    if args.since >= v.head {
        return finding(
            out,
            args,
            REASON_HEAD_BELOW_SINCE,
            &format!(
                "chain head sequence={} is at or below --since {}, so no row is checked",
                v.head, args.since
            ),
        );
    }
    let unverified = v.rows_checked.saturating_sub(v.rows_positively_verified);
    let verdict = v.finding();
    if args.json() {
        let body = ChainVerifyReportJson {
            status: if verdict.is_some() { "fail" } else { "ok" },
            reason: verdict.as_ref().map(|(r, _)| *r),
            detail: verdict.as_ref().map(|(_, d)| d.clone()),
            rows_checked: v.rows_checked,
            chain_break: v.chain_break,
            signature_failures: v.signature_failures.iter().map(|(s, _)| *s).collect(),
            chain_holds: v.chain_break.is_none(),
            rows_unverified: unverified,
            unanchored_tail: Some(v.unanchored_tail()),
        };
        let json = serde_json::to_string_pretty(&body).context("serialize chain report")?;
        writeln!(out.stdout, "{json}").context(CTX_WRITE_CHAIN_REPORT)?;
    } else if let Some((reason, detail)) = &verdict {
        writeln!(
            out.stdout,
            "verify-signed-events-chain FAIL: {reason}: {detail} ({} row(s) walked)",
            v.rows_checked,
        )
        .context(CTX_WRITE_CHAIN_REPORT)?;
    } else {
        let range = if v.whole_chain {
            format!(
                "sequence 1..={} (the Postgres walk covers the whole chain)",
                v.head
            )
        } else {
            format!("sequence {}..={}", args.since.saturating_add(1), v.head)
        };
        writeln!(
            out.stdout,
            "verify-signed-events-chain OK: {} row(s) walked, chain holds ({range}; \
             {unverified} row signature(s) not verified against a pin; unanchored_tail={} \
             (the newest rows above the last off-table anchor are not tail-protected yet: \
             their removal is not detected))",
            v.rows_checked,
            v.unanchored_tail(),
        )
        .context(CTX_WRITE_CHAIN_REPORT)?;
    }
    match verdict {
        None => Ok(0),
        Some((reason, detail)) => {
            writeln!(
                out.stderr,
                "verify-signed-events-chain FAIL: {reason}: {detail}"
            )
            .context(CTX_WRITE_CHAIN_REPORT)?;
            Ok(EXIT_FINDING)
        }
    }
}

/// Walk a SQLite store. Returns the exit code (0 green, else
/// [`EXIT_FINDING`]). `audit_pubkey` is the resolved `AI_MEMORY_AUDIT_PUBKEY`
/// pin: when enrolled, every walked row must verify against it (#8852).
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
    // `db::open` creates a missing file; check first so a typo is a finding,
    // not an empty chain that was just created.
    if !db_path.is_file() {
        return finding(
            out,
            args,
            REASON_STORE_MISSING,
            &format!("no database file at {}", db_path.display()),
        );
    }
    let conn =
        crate::db::open(db_path).with_context(|| format!("open db at {}", db_path.display()))?;
    let head: i64 = conn
        .query_row(crate::signed_events::CHAIN_HEAD_SQL, [], |row| row.get(0))
        .context("read signed_events chain head")?;
    let mut verdict = ChainVerdict {
        head,
        pin_enrolled: audit_pubkey.is_some(),
        ..ChainVerdict::default()
    };
    if head > 0 && args.since < head {
        let since = (args.since > 0).then_some(args.since);
        let report = crate::signed_events::verify_chain(&conn, since, audit_pubkey)
            .context("verify_chain over signed_events")?;
        let db_id = crate::signed_events::genesis_db_id(&conn).context("read genesis db id")?;
        verdict.rows_checked = report.rows_checked;
        verdict.rows_positively_verified = report.rows_positively_verified;
        verdict.chain_break = report.chain_break;
        verdict.signature_failures = report.signature_failure_reasons();
        // The SHARED truncation fold (Postgres twin parity): a raw anchor above
        // the head convicts; an anchor at or below it shrinks the reported
        // unanchored tail only when it authenticates (or no pin is enrolled).
        let raw_anchor =
            crate::governance::audit::last_audit_watermark(db_id.as_deref()).map(|(h, _)| h);
        let exonerate_ok = crate::governance::audit::audit_watermark_exoneration_authenticated(
            audit_pubkey,
            db_id.as_deref(),
        );
        let (truncation, trusted_anchor) =
            crate::signed_events::truncation_verdict(raw_anchor, head, exonerate_ok);
        verdict.anchored_head = match truncation {
            crate::signed_events::TruncationCheck::Detected { anchored_head, .. } => {
                Some(anchored_head)
            }
            _ => trusted_anchor,
        };
    }
    render_verdict(&verdict, args, out)
}

/// Map a Postgres [`crate::signed_events::AuditTrailReport`] (the Postgres
/// chain walk) to a [`ChainVerdict`] so both backends render once.
#[must_use]
pub fn verdict_from_audit_trail(
    report: &crate::signed_events::AuditTrailReport,
    pin_enrolled: bool,
) -> ChainVerdict {
    let rows_checked = u64::try_from(report.total_events).unwrap_or(u64::MAX);
    let unverified = match report.signature_check {
        crate::signed_events::SignatureCheck::Unverified { unverified, .. }
        | crate::signed_events::SignatureCheck::Unenforced { unverified, .. } => unverified,
        crate::signed_events::SignatureCheck::Verified { .. } => 0,
    };
    let anchored_head = match report.truncation {
        crate::signed_events::TruncationCheck::Detected { anchored_head, .. } => {
            Some(anchored_head)
        }
        _ => report.anchored_head,
    };
    ChainVerdict {
        head: report.head_sequence,
        rows_checked,
        rows_positively_verified: rows_checked.saturating_sub(unverified),
        chain_break: report.first_break_sequence,
        signature_failures: report.signature_failure_reasons(),
        pin_enrolled,
        anchored_head,
        whole_chain: true,
    }
}

/// Map a `sqlite://` store URL to its file path, the same way the daemon's
/// store binding does (`sqlite:///abs` gives `/abs`, `sqlite://rel` gives
/// `rel`). Returns `None` for any other scheme. Shared by `verify-audit-trail`
/// and `verify-signed-events-chain` so both open the file the daemon binds
/// (#9179 r1 security F1).
#[must_use]
pub fn sqlite_store_url_to_path(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("SQLITE://"))?;
    Some(
        path.strip_prefix('/')
            .map_or(path, |p| if p.starts_with('/') { p } else { path }),
    )
}

/// Open the Postgres SAL store for a verify verb with the no-embedder connect
/// precedent (`DEFAULT_EMBEDDING_DIM`, no auto-migrate). Shared by
/// `verify-audit-trail` and `verify-signed-events-chain` (#9179 r1).
#[cfg(feature = "sal-postgres")]
pub(crate) async fn connect_postgres_for_verify(
    url: &str,
    app_config: &crate::config::AppConfig,
    verb: &str,
) -> Result<crate::store::postgres::PostgresStore> {
    let timeout = app_config
        .postgres_statement_timeout_secs
        .unwrap_or(crate::store::postgres::DEFAULT_STATEMENT_TIMEOUT_SECS);
    // #1579 A3 (SECURITY) — never echo the credential.
    let display_url = crate::url_display::store_url_display(url);
    tracing::info!("{verb}: opening Postgres SAL store at {display_url}");
    crate::store::postgres::PostgresStore::connect_with_dim_and_timeout(
        url,
        crate::store::postgres::DEFAULT_EMBEDDING_DIM,
        timeout,
        app_config.resolve_pg_pool(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("connect postgres adapter for {verb}: {e}"))
}

/// `verify-signed-events-chain` (#9046, #9179 r1): resolve the store through
/// [`crate::cli::verify_signed_events::resolve_store`] and walk the backend it
/// names. Every refusal is a finding with a reason code, never a walk of
/// another store.
pub async fn run_command(
    db_path: &Path,
    a: &VerifySignedEventsChainArgs,
    app_config: &crate::config::AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<i32> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut so = stdout.lock();
    let mut se = stderr.lock();
    let mut out = CliOutput::from_std(&mut so, &mut se);
    match resolve_store(db_path, a)? {
        ChainStore::Sqlite(path) => run(&path, a, audit_pubkey, &mut out),
        ChainStore::Postgres(url) => {
            verify_signed_events_chain_postgres(&url, a, app_config, audit_pubkey, &mut out).await
        }
        ChainStore::Refused(reason, detail) => finding(&mut out, a, reason, &detail),
    }
}

/// Postgres arm of [`run_command`]: the Postgres chain
/// walk (`verify_audit_trail`, whole chain) mapped to the shared verdict.
#[cfg(feature = "sal-postgres")]
async fn verify_signed_events_chain_postgres(
    url: &str,
    a: &VerifySignedEventsChainArgs,
    app_config: &crate::config::AppConfig,
    audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let store = connect_postgres_for_verify(url, app_config, "verify-signed-events-chain").await?;
    let report = store
        .verify_audit_trail(None, audit_pubkey)
        .await
        .map_err(|e| anyhow::anyhow!("chain walk over postgres signed_events: {e}"))?;
    let verdict = verdict_from_audit_trail(&report, audit_pubkey.is_some());
    render_verdict(&verdict, a, out)
}

/// Fail-closed stub without `sal-postgres`: the Postgres store cannot be
/// walked by this binary, so it is the `store_is_postgres` finding.
#[cfg(not(feature = "sal-postgres"))]
#[allow(clippy::unused_async)]
async fn verify_signed_events_chain_postgres(
    url: &str,
    a: &VerifySignedEventsChainArgs,
    _app_config: &crate::config::AppConfig,
    _audit_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    finding(
        out,
        a,
        REASON_STORE_IS_POSTGRES,
        &format!(
            "the store URL file names a Postgres store ({}) and this binary was built \
             without --features sal-postgres",
            crate::url_display::store_url_display(url)
        ),
    )
}

/// Test fixture: append one unsigned link row so a dispatch test walks a
/// non-empty chain (an empty store is the `empty_chain` finding, #9179 r1 F6).
#[cfg(test)]
pub(crate) fn seed_one_unsigned_row_for_test(db_path: &Path) {
    let conn = crate::db::open(db_path).expect("open test db");
    crate::signed_events::append_signed_event(
        &conn,
        &crate::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".to_string(),
            event_type: crate::signed_events::event_types::MEMORY_LINK_CREATED.to_string(),
            payload_hash: crate::signed_events::payload_hash(b"p-0"),
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..crate::signed_events::SignedEvent::default()
        },
    )
    .expect("append test row");
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
    fn empty_db_is_an_empty_chain_finding_8741() {
        // #8741 — 0 rows is a finding, never a vacuous green.
        let (_dir, path) = temp_db();
        for format in ["json", "text"] {
            let args = VerifySignedEventsChainArgs {
                since: 0,
                format: format.to_string(),
                store_url_file: None,
            };
            let mut buf_out = Vec::<u8>::new();
            let mut buf_err = Vec::<u8>::new();
            let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
            let code = run(&path, &args, None, &mut out).expect("run");
            assert_eq!(code, EXIT_FINDING, "{format}: empty chain is a finding");
            let e = String::from_utf8(buf_err).expect("utf-8");
            assert!(e.contains(REASON_EMPTY_CHAIN), "{format}: got: {e}");
            let o = String::from_utf8(buf_out).expect("utf-8");
            if format == "json" {
                // #9179 r1 F10c — the absence finding is a JSON body on stdout.
                let v: serde_json::Value = serde_json::from_str(&o).expect("json body");
                assert_eq!(v["status"], "fail", "{format}: got: {o}");
                assert_eq!(v["reason"], REASON_EMPTY_CHAIN, "{format}: got: {o}");
            } else {
                assert!(
                    !o.contains("OK"),
                    "{format}: no green report on stdout: {o}"
                );
            }
        }
    }

    #[test]
    fn since_above_head_is_a_finding_9008() {
        let (_dir, path) = temp_db();
        {
            let conn = crate::db::open(&path).expect("open");
            append_signed_event(&conn, &fixture_event(b"p-0")).expect("append");
        }
        let args = VerifySignedEventsChainArgs {
            since: 5,
            format: "text".to_string(),
            store_url_file: None,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, EXIT_FINDING);
        let e = String::from_utf8(buf_err).expect("utf-8");
        assert!(e.contains(REASON_HEAD_BELOW_SINCE), "got: {e}");
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
            store_url_file: None,
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
            store_url_file: None,
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
            store_url_file: None,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 1, "chain break must produce exit code 1");
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("FAIL"), "must say FAIL; got: {s}");
        assert!(
            s.contains(&format!("FAIL: {REASON_CHAIN_BREAK}: at sequence=")),
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
            store_url_file: None,
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
        {
            let conn = crate::db::open(&path).expect("open");
            append_signed_event(&conn, &fixture_event(b"p-0")).expect("append");
        }
        let args = VerifySignedEventsChainArgs {
            since: 0,
            format: "yaml-unrecognised".to_string(),
            store_url_file: None,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, None, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("OK"), "must hit text branch; got: {s}");
    }

    fn args(since: i64, format: &str) -> VerifySignedEventsChainArgs {
        VerifySignedEventsChainArgs {
            since,
            format: format.to_string(),
            store_url_file: None,
        }
    }

    fn seeded_db(rows: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let (dir, path) = temp_db();
        let conn = crate::db::open(&path).expect("open");
        for i in 0..rows {
            append_signed_event(&conn, &fixture_event(format!("s-{i}").as_bytes()))
                .expect("append");
        }
        (dir, path)
    }

    fn run_capture(
        path: &Path,
        a: &VerifySignedEventsChainArgs,
        pin: Option<&ed25519_dalek::VerifyingKey>,
    ) -> (i32, String, String) {
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(path, a, pin, &mut out).expect("run");
        (
            code,
            String::from_utf8(buf_out).expect("utf-8"),
            String::from_utf8(buf_err).expect("utf-8"),
        )
    }

    /// #9179 r1 security F1 — every configured store URL is classified; none
    /// is ignored in favour of `--db`. Table over the scheme corpus.
    #[test]
    fn store_url_table_classifies_every_scheme_9179() {
        const CORPUS: &[(&str, bool, &str)] = &[
            ("postgres://u@h/db", false, REASON_STORE_IS_POSTGRES),
            ("postgresql://u@h/db", false, REASON_STORE_IS_POSTGRES),
            // The scheme sniff is case-sensitive, as in the daemon's store
            // binding, so an upper-case scheme is not a Postgres store there
            // either: it is refused as unrecognised, never walked as `--db`.
            ("POSTGRES://u@h/db", false, REASON_STORE_URL_UNRECOGNISED),
            ("postgres://u@h/db", true, "postgres"),
            ("sqlite:///var/other.db", false, "sqlite:/var/other.db"),
            ("sqlite:///var/other.db", true, "sqlite:/var/other.db"),
            ("sqlite://rel.db", false, "sqlite:rel.db"),
            ("bogus://h/x", false, REASON_STORE_URL_UNRECOGNISED),
            ("bogus://h/x", true, REASON_STORE_URL_UNRECOGNISED),
            ("mysql://h/db", false, REASON_STORE_URL_UNRECOGNISED),
            ("/plain/path.db", false, REASON_STORE_URL_UNRECOGNISED),
        ];
        for (url, from_file, want) in CORPUS {
            let got = match classify_store_url(url, *from_file) {
                ChainStore::Refused(reason, _) => reason.to_string(),
                ChainStore::Postgres(_) => "postgres".to_string(),
                ChainStore::Sqlite(p) => format!("sqlite:{}", p.display()),
            };
            assert_eq!(&got, want, "url={url} from_file={from_file}");
        }
    }

    /// #9179 r1 Decision 3 — `--store-url-file` names the store; a sqlite://
    /// URL in it opens that file, not `--db`.
    #[test]
    fn store_url_file_sqlite_opens_that_file_9179() {
        let (dir, other) = seeded_db(2);
        let url_file = dir.path().join("store.url");
        std::fs::write(&url_file, format!("sqlite://{}\n", other.display())).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        let mut a = args(0, "text");
        a.store_url_file = Some(url_file);
        let store = resolve_store(Path::new("/nonexistent/ignored.db"), &a).expect("resolve");
        assert_eq!(store, ChainStore::Sqlite(other.clone()));
    }

    /// #9179 r1 security F6 — `--since == head` checks no row: a finding.
    #[test]
    fn since_equal_to_head_is_head_below_since_9179() {
        let (_dir, path) = seeded_db(3);
        for format in ["text", "json"] {
            let (code, o, e) = run_capture(&path, &args(3, format), None);
            assert_eq!(code, EXIT_FINDING, "{format}");
            assert!(
                e.contains(&format!("FAIL: {REASON_HEAD_BELOW_SINCE}:")),
                "{format}: {e}"
            );
            assert!(!o.contains("OK"), "{format}: {o}");
        }
    }

    /// #9179 r1 security F6 / code F10a — a negative `--since` is refused at
    /// parse time with a value-validation error.
    #[test]
    fn negative_since_is_refused_by_clap_9179() {
        #[derive(clap::Parser, Debug)]
        struct T {
            #[command(flatten)]
            a: VerifySignedEventsChainArgs,
        }
        let err = <T as clap::Parser>::try_parse_from(["t", "--since=-1"]).expect_err("refused");
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let ok = <T as clap::Parser>::try_parse_from(["t", "--since", "0"]).expect("0 accepted");
        assert_eq!(ok.a.since, 0);
    }

    /// #8852 / #9179 r1 — with an audit pin enrolled every walked row must
    /// verify against it; unsigned rows are `signature_unverified`.
    #[test]
    fn pin_enrolled_unsigned_rows_are_signature_unverified_9179() {
        let (_dir, path) = seeded_db(2);
        let pin = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        for format in ["text", "json"] {
            let (code, o, e) = run_capture(&path, &args(0, format), Some(&pin));
            assert_eq!(code, EXIT_FINDING, "{format}");
            assert!(
                e.contains(&format!("FAIL: {REASON_SIGNATURE_UNVERIFIED}:")),
                "{format}: {e}"
            );
            if format == "json" {
                let v: serde_json::Value = serde_json::from_str(&o).expect("json");
                assert_eq!(v["status"], "fail", "{o}");
                assert_eq!(v["reason"], REASON_SIGNATURE_UNVERIFIED, "{o}");
                assert_eq!(v["rows_unverified"], 2, "{o}");
            }
        }
        // Without a pin the same chain is green and states its coverage.
        let (code, o, _) = run_capture(&path, &args(0, "text"), None);
        assert_eq!(code, 0, "{o}");
        assert!(o.contains("unanchored_tail=2"), "{o}");
    }

    /// #9179 r1 code F10c — the OK JSON carries status, coverage and the
    /// unverified-row count.
    #[test]
    fn ok_json_states_coverage_9179() {
        let (_dir, path) = seeded_db(3);
        let (code, o, _) = run_capture(&path, &args(0, "json"), None);
        assert_eq!(code, 0, "{o}");
        let v: serde_json::Value = serde_json::from_str(&o).expect("json");
        assert_eq!(v["status"], "ok", "{o}");
        assert_eq!(v["chain_holds"], true, "{o}");
        assert_eq!(v["unanchored_tail"], 3, "{o}");
        assert_eq!(v["rows_unverified"], 3, "{o}");
    }

    /// #9179 r1 — the shared verdict order: chain break first, then tail
    /// truncation, then a failed present signature, then pin coverage.
    #[test]
    fn verdict_order_is_fixed_9179() {
        let base = ChainVerdict {
            head: 5,
            rows_checked: 5,
            rows_positively_verified: 5,
            ..ChainVerdict::default()
        };
        assert_eq!(base.finding(), None);
        assert_eq!(base.unanchored_tail(), 5);
        let anchored = ChainVerdict {
            anchored_head: Some(4),
            ..base.clone()
        };
        assert_eq!(anchored.unanchored_tail(), 1);
        let cut = ChainVerdict {
            anchored_head: Some(9),
            ..base.clone()
        };
        assert_eq!(cut.finding().map(|f| f.0), Some(REASON_TAIL_TRUNCATED));
        let selfsig = ChainVerdict {
            signature_failures: vec![(3, REASON_SELF_SIGNED_UNVERIFIABLE)],
            ..base.clone()
        };
        assert_eq!(
            selfsig.finding().map(|f| f.0),
            Some(REASON_SELF_SIGNED_UNVERIFIABLE)
        );
        let broken = ChainVerdict {
            chain_break: Some(2),
            ..cut.clone()
        };
        assert_eq!(broken.finding().map(|f| f.0), Some(REASON_CHAIN_BREAK));
        let pinned = ChainVerdict {
            pin_enrolled: true,
            rows_positively_verified: 4,
            ..base
        };
        assert_eq!(
            pinned.finding().map(|f| f.0),
            Some(REASON_SIGNATURE_UNVERIFIED)
        );
    }
}
