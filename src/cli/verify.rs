// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory verify-reflection-chain` — external verifier for
//! reflection chains (procurement-grade audit tool, v0.7.0 L1-3).
//!
//! Walks the `reflects_on` edges backward from the supplied memory to
//! depth 0, verifies each Ed25519 signature (when present) using the
//! `identity::verify` infrastructure, optionally checks `signed_events`
//! creation entries, and emits a structured chain-integrity report.
//!
//! ## Exit codes
//!
//! - `0` — chain fully verified (or no signatures present and
//!   `bounded_status != "exceeded_cap"`), the root's content-id is
//!   verified or was not checked (no genesis or no cid), and (with
//!   `--cid`) no swept row mismatched or was unreadable.
//! - `1` — the root memory was not found (#3436), or the arguments are
//!   wrong (a caller error).
//! - `2` — verification failed: at least one edge failed signature
//!   verification, the chain exceeds its namespace
//!   `max_reflection_depth` cap, (#9505) the root's content-id
//!   genesis mismatches its cid or cannot be read, (#9634) the
//!   `--cid` sweep found a mismatched or unreadable row, or (#9505) an
//!   input could not be read at all (the database, the root row, the
//!   chain or the sweep query): one UNREADABLE document naming the
//!   stage and the `error_class` is printed.
//!
//! ## Output formats
//!
//! - `--format text` (default) — human-readable report printed to
//!   stdout: exactly one summary line, and (#9636) every stored value
//!   escaped and bounded by [`Printed`].
//! - `--format json` — structured `AgenticMem Attest` tier evidence
//!   packet serialised as ONE JSON document (the `--cid` sweep is its
//!   optional `cid_sweep` field).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::cli::CliOutput;
use crate::identity::sign::SignableLink;

// ─────────────────────────────────────────────────────────────────────
// CLI argument struct (consumed by daemon_runtime)
// ─────────────────────────────────────────────────────────────────────

/// Arguments for `ai-memory verify-reflection-chain`.
#[derive(clap::Args, Debug)]
pub struct VerifyChainArgs {
    /// Memory id to start the chain walk from.
    pub memory_id: String,

    /// Output format: `json` or `text`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,

    /// Include `signed_events` creation entries in the report.
    #[arg(long)]
    pub include_signed_events: bool,

    /// v0.9.0 G8 (#1825) — opt-in fleet-wide content-id (cid) sweep:
    /// recompute every stamped memory's BLAKE3 address from its stored
    /// `cid_genesis` pre-image and report matches / mismatches. Detects
    /// partial corruption of `cid` / `cid_genesis`. Never mutates. #9634:
    /// the sweep runs before anything is printed and is part of the one
    /// verdict: a mismatched row or a row whose columns do not decode makes
    /// `ok` false and the exit code `2`. `AI_MEMORY_CID_ENFORCE=1` raises
    /// the log level of a mismatch to `WARN`.
    #[arg(long)]
    pub cid: bool,
}

/// #9634 — most mismatch and unreadable detail rows one sweep keeps (the
/// counts stay exact; only the per-row detail is capped).
pub const MAX_SWEEP_DETAIL_ROWS: usize = 100;

/// #9634 — one swept row whose columns could not be decoded. The class is a
/// fixed label; no stored byte of the row is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnreadableRow {
    /// The row id, when the id column itself decodes.
    pub id: Option<String>,
    /// Why the row could not be read.
    pub error_class: GenesisReadErrorClass,
}

/// v0.9.0 G8 (#1825) — outcome of a fleet-wide cid sweep.
#[derive(Debug, Serialize)]
pub struct CidSweepReport {
    /// Rows carrying a non-NULL `cid` AND `cid_genesis` (i.e. checkable).
    pub checked: usize,
    /// Rows whose recomputed BLAKE3 address matched the stored `cid`.
    pub cid_verified: usize,
    /// Rows whose recomputed address did NOT match (partial corruption).
    pub cid_mismatched: usize,
    /// #9634 — rows whose `id`, `cid` or `cid_genesis` column does not
    /// decode (a TEXT or numeric genesis, for example). A failure, like a
    /// mismatch: the row's content-id cannot be confirmed.
    pub cid_unreadable: usize,
    /// Rows with a `cid` but a NULL `cid_genesis` (e.g. forgotten rows,
    /// T7) — unverifiable, reported but not a failure.
    pub cid_unverifiable: usize,
    /// Per-mismatch `id: description` detail (at most
    /// [`MAX_SWEEP_DETAIL_ROWS`]).
    pub mismatches: Vec<String>,
    /// #9634 — per-unreadable-row detail (at most [`MAX_SWEEP_DETAIL_ROWS`]).
    pub unreadable: Vec<UnreadableRow>,
}

impl CidSweepReport {
    /// `true` when no swept row mismatched and none was unreadable. An
    /// unverifiable row (NULL genesis) does not fail the sweep.
    #[must_use]
    pub const fn passes(&self) -> bool {
        self.cid_mismatched == 0 && self.cid_unreadable == 0
    }
}

/// The tracing target of every `--cid` sweep event.
const CID_LOG_TARGET: &str = "cid.enforce";

/// The three swept columns of one row.
type SweepColumns = (String, Option<String>, Option<Vec<u8>>);

/// #9634 — decode one swept row, classifying a column that does not decode
/// by the error's type (never its text) with the root check's classifier.
fn sweep_columns(row: &rusqlite::Row<'_>) -> Result<SweepColumns, GenesisReadErrorClass> {
    let classify = |e: rusqlite::Error| GenesisReadErrorClass::of(&anyhow::Error::new(e));
    Ok((
        row.get(0).map_err(classify)?,
        row.get(1).map_err(classify)?,
        row.get(2).map_err(classify)?,
    ))
}

/// v0.9.0 G8 (#1825) — run the fleet-wide cid sweep. Reads `(id, cid,
/// cid_genesis)` for every row and verifies each stamped pair. Pure read;
/// never mutates. A mismatch is logged at `WARN` when
/// `AI_MEMORY_CID_ENFORCE` is truthy, else at `INFO`. #9634: a row whose
/// columns do not decode is counted `cid_unreadable` with its class and the
/// sweep goes on; the verb folds the report into its one verdict
/// ([`ChainReport::with_cid_sweep`]).
///
/// # Errors
///
/// A query that cannot be prepared or stepped is a [`ReadFault`] at stage
/// [`ReadStage::CidSweepPrepare`] or [`ReadStage::CidSweepStep`], with the
/// error classified by type; the verb reports it as UNREADABLE, exit 2.
pub fn run_cid_sweep(conn: &Connection) -> Result<CidSweepReport, ReadFault> {
    run_cid_sweep_query(conn, CID_SWEEP_SQL)
}

/// The fleet-wide sweep query: `(id, cid, cid_genesis)` of every stamped row.
const CID_SWEEP_SQL: &str = "SELECT id, cid, cid_genesis FROM memories WHERE cid IS NOT NULL";

/// [`run_cid_sweep`] over `sql`, which selects the same three columns (the
/// unit cells pass a query that cannot be prepared or stepped).
fn run_cid_sweep_query(conn: &Connection, sql: &str) -> Result<CidSweepReport, ReadFault> {
    let enforce = crate::config::cid_enforce_enabled();
    let prepare_fault = |e| ReadFault::of_sqlite(ReadStage::CidSweepPrepare, e);
    let mut stmt = conn.prepare(sql).map_err(prepare_fault)?;
    let mut rows = stmt.query([]).map_err(prepare_fault)?;

    let mut report = CidSweepReport {
        checked: 0,
        cid_verified: 0,
        cid_mismatched: 0,
        cid_unreadable: 0,
        cid_unverifiable: 0,
        mismatches: Vec::new(),
        unreadable: Vec::new(),
    };
    while let Some(row) = rows
        .next()
        .map_err(|e| ReadFault::of_sqlite(ReadStage::CidSweepStep, e))?
    {
        let (id, cid, genesis) = match sweep_columns(row) {
            Ok(columns) => columns,
            Err(error_class) => {
                report.cid_unreadable += 1;
                // The id is detail only: an id that does not decode is
                // reported as absent, the row is still counted.
                let id = row.get::<_, String>(0).ok();
                tracing::warn!(
                    target: CID_LOG_TARGET,
                    memory_id = %Printed::field(id.as_deref().unwrap_or("")),
                    "cid row unreadable ({})",
                    error_class.label()
                );
                if report.unreadable.len() < MAX_SWEEP_DETAIL_ROWS {
                    report.unreadable.push(UnreadableRow { id, error_class });
                }
                continue;
            }
        };
        let (Some(cid), Some(genesis)) = (cid, genesis) else {
            report.cid_unverifiable += 1;
            continue;
        };
        report.checked += 1;
        match crate::identity::cid::verify_cid(&cid, &genesis) {
            Ok(()) => report.cid_verified += 1,
            Err(mismatch) => {
                report.cid_mismatched += 1;
                let detail = format!("{id}: {mismatch}");
                if enforce {
                    tracing::warn!(target: CID_LOG_TARGET, "cid mismatch: {}", Printed::field(&detail));
                } else {
                    tracing::info!(target: CID_LOG_TARGET, "cid mismatch (detect-only): {}", Printed::field(&detail));
                }
                if report.mismatches.len() < MAX_SWEEP_DETAIL_ROWS {
                    report.mismatches.push(detail);
                }
            }
        }
    }
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────
// #9636 — the one print funnel for stored values
// ─────────────────────────────────────────────────────────────────────

/// #9636 — most characters one stored field may put on a text line. Long
/// enough for every value the verb itself produces (a mismatch detail is
/// about 220 characters); a longer stored value is cut and marked.
pub const MAX_PRINTED_FIELD_CHARS: usize = 512;

/// Edge ids are shown by this many leading characters.
const EDGE_ID_PREFIX_CHARS: usize = 8;

/// Shown in place of a swept row id that does not decode itself.
const UNREADABLE_ID_LABEL: &str = "<id unreadable>";

/// Characters that reorder or hide text on a terminal: zero-width and
/// direction marks, bidi embeddings and isolates, the line and paragraph
/// separators, and the byte-order mark.
const fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// A character no stored value may put on a stream as itself.
fn needs_escape(c: char) -> bool {
    c.is_control() || is_hidden(c)
}

/// #9636 — a stored value as it may appear on a text line: every control or
/// hidden character is written as `\u{..}`, and the output stops at
/// `max_chars` characters with a `...(+N chars)` marker. Linear in the
/// value. Every stored field the text renderer and the stderr lines print
/// goes through it, so no stored byte can forge a line or drive a terminal.
pub struct Printed<'a> {
    value: &'a str,
    max_chars: usize,
    mark_cut: bool,
}

impl<'a> Printed<'a> {
    /// A whole stored field, bounded by [`MAX_PRINTED_FIELD_CHARS`].
    #[must_use]
    pub const fn field(value: &'a str) -> Self {
        Self {
            value,
            max_chars: MAX_PRINTED_FIELD_CHARS,
            mark_cut: true,
        }
    }

    /// The leading `chars` characters of a value, cut on a char boundary
    /// and unmarked (an abbreviated id).
    #[must_use]
    pub const fn prefix(value: &'a str, chars: usize) -> Self {
        Self {
            value,
            max_chars: chars,
            mark_cut: false,
        }
    }
}

impl std::fmt::Display for Printed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut written = 0usize;
        let mut chars = self.value.chars();
        while let Some(c) = chars.next() {
            let escape = needs_escape(c).then(|| c.escape_unicode());
            let width = escape.as_ref().map_or(1, ExactSizeIterator::len);
            if written.saturating_add(width) > self.max_chars {
                if self.mark_cut {
                    let rest = 1 + chars.count();
                    write!(f, "...(+{rest} chars)")?;
                }
                return Ok(());
            }
            match escape {
                Some(escaped) => write!(f, "{escaped}")?,
                None => write!(f, "{c}")?,
            }
            written += width;
        }
        Ok(())
    }
}

/// #9636 — a serialised JSON document as it may reach a terminal: a control
/// or hidden character inside a string (the encoder leaves DEL, C1 controls
/// and bidi characters raw) is written as its `\uXXXX` JSON escape, so the
/// document parses to the same value and no raw such character is printed.
/// The line feeds of the pretty layout are kept.
fn json_for_terminal(payload: &str) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(payload.len());
    for c in payload.chars() {
        if c != '\n' && needs_escape(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                write!(out, "\\u{unit:04x}")?;
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// Report types
// ─────────────────────────────────────────────────────────────────────

/// One `reflects_on` edge in the ancestry tree, with its verification
/// result.
#[derive(Debug, Serialize)]
pub struct EdgeResult {
    pub source_id: String,
    pub target_id: String,
    /// Signature bytes as hex, or `null` when the edge is unsigned.
    pub signature_hex: Option<String>,
    pub attest_level: String,
    pub verified: bool,
    /// Human-readable reason when `verified = false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Per-`signed_events` row summary for a memory in the chain.
#[derive(Debug, Serialize)]
pub struct SignedEventSummary {
    pub memory_id: String,
    pub event_id: String,
    pub event_type: String,
    pub attest_level: String,
    pub timestamp: String,
    pub signature_present: bool,
}

/// #9505 — why the root's `cid_genesis` could not be read. Fixed labels
/// only: the storage error's own text is never printed, so no stored bytes
/// and no path reach the operator's streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisReadErrorClass {
    /// The stored value is not a BLOB (wrong SQLite type or a failed
    /// conversion).
    DecodeError,
    /// The provenance column or the schema stamp is not in the shape this
    /// binary expects (#9496).
    SchemaFault,
    /// Any other storage error.
    StorageError,
}

impl GenesisReadErrorClass {
    /// Classify a failed `read_cid_genesis` by the error's type, never its
    /// text.
    fn of(err: &anyhow::Error) -> Self {
        if err
            .downcast_ref::<crate::storage::schema_guard::ProvenanceReadFault>()
            .is_some()
        {
            return Self::SchemaFault;
        }
        match err.downcast_ref::<rusqlite::Error>() {
            Some(
                rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::FromSqlConversionFailure(..),
            ) => Self::DecodeError,
            _ => Self::StorageError,
        }
    }

    /// The label printed in text mode and serialised in JSON mode.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DecodeError => "decode_error",
            Self::SchemaFault => "schema_fault",
            Self::StorageError => "storage_error",
        }
    }
}

/// #9505 (3-agent vote (71472661), ruling fe96bc17) — the verification input
/// that could not be read. Each stage is a fixed label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadStage {
    /// The database could not be opened.
    Open,
    /// The root memory row could not be read.
    Root,
    /// The reflection chain (memory rows, edges, governance or signed
    /// events) could not be read.
    Chain,
    /// The `--cid` sweep query could not be prepared.
    CidSweepPrepare,
    /// The `--cid` sweep query could not be stepped.
    CidSweepStep,
}

impl ReadStage {
    /// The label printed in text mode and serialised in JSON mode.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Root => "root",
            Self::Chain => "chain",
            Self::CidSweepPrepare => "cid_sweep_prepare",
            Self::CidSweepStep => "cid_sweep_step",
        }
    }
}

/// #9505 — a read that the verdict needs failed: the state UNREADABLE (ok
/// false, exit 2, one document). Only the stage and the error class are
/// kept, never the storage error's text, so no stored byte and no path
/// reaches the operator's streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReadFault {
    /// Which input could not be read.
    pub stage: ReadStage,
    /// Why, classified by the error's type.
    pub error_class: GenesisReadErrorClass,
}

impl ReadFault {
    fn of(stage: ReadStage, err: &anyhow::Error) -> Self {
        Self {
            stage,
            error_class: GenesisReadErrorClass::of(err),
        }
    }

    fn of_sqlite(stage: ReadStage, err: rusqlite::Error) -> Self {
        Self::of(stage, &anyhow::Error::new(err))
    }
}

impl std::fmt::Display for ReadFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} could not be read ({})",
            self.stage.label(),
            self.error_class.label()
        )
    }
}

impl std::error::Error for ReadFault {}

/// #9505 — the root memory's content-id verdict (3-agent vote (71472661),
/// B + J1). A root that was not checked (no genesis, or no cid) has NO
/// value: `ChainReport::root_cid` is `None` and the field is omitted from
/// the JSON. `Mismatch` and `Unreadable` fail the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RootCidCheck {
    /// The stored genesis is the pre-image of the root's cid.
    Verified { cid: String },
    /// The stored genesis was read and is NOT the pre-image of the cid.
    Mismatch { cid: String },
    /// The stored genesis could not be read.
    Unreadable { error_class: GenesisReadErrorClass },
}

impl RootCidCheck {
    /// `true` only for [`RootCidCheck::Verified`].
    #[must_use]
    pub const fn passes(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// #9505 — read the root's genesis and decide its content-id state. Runs
/// BEFORE anything is printed. A read error is `Unreadable` whether or not
/// the row carries a cid (fail closed: a column that does not decode is
/// itself evidence); a NULL genesis or a NULL cid is "not checked".
fn check_root_cid(conn: &Connection, root: &crate::models::Memory) -> Option<RootCidCheck> {
    match crate::db::read_cid_genesis(conn, &root.id) {
        Err(err) => Some(RootCidCheck::Unreadable {
            error_class: GenesisReadErrorClass::of(&err),
        }),
        Ok(None) => None,
        Ok(Some(genesis)) => {
            let cid = root.cid.as_deref()?;
            Some(if crate::identity::cid::verify_cid(cid, &genesis).is_ok() {
                RootCidCheck::Verified {
                    cid: cid.to_string(),
                }
            } else {
                RootCidCheck::Mismatch {
                    cid: cid.to_string(),
                }
            })
        }
    }
}

/// Full chain-integrity report — the `AgenticMem Attest` tier evidence
/// packet.
#[derive(Debug, Serialize)]
pub struct ChainReport {
    /// v0.7.0 G-PHASE-E-4 (#709) — top-line PASS/FAIL flag for the
    /// chain. `true` when every edge verified AND no namespace
    /// exceeded its governance cap AND (#9505) the root content-id
    /// check, when it ran (`root_cid` set), is `verified`: a root
    /// genesis that mismatches or cannot be read makes it `false`; AND
    /// (#9634) the `--cid` sweep, when it ran (`cid_sweep` set), found no
    /// mismatched and no unreadable row.
    /// Surfaced as the first field on the JSON wire shape so external
    /// auditors / CI scripts can `jq '.ok'` instead of recomputing the
    /// predicate. The shell exit code mirrors this field: `0` when
    /// `ok = true`, `2` when `ok = false` (matching the
    /// `verify-forensic-bundle` exit convention, also raised to `2`
    /// in #709). The verb sets it ONCE, after the root check and the sweep
    /// and before anything is printed ([`ChainReport::with_root_cid`],
    /// [`ChainReport::with_cid_sweep`]).
    pub ok: bool,
    /// Root memory id supplied on the command line.
    pub root_id: String,
    /// Total number of distinct memories visited (root + ancestors).
    pub n_memories: usize,
    /// Longest path from root to a depth-0 memory.
    pub chain_depth: usize,
    /// Number of `reflects_on` edges that passed Ed25519 verification
    /// (or were unsigned but presence-confirmed).
    pub edges_verified: usize,
    /// Number of edges that failed verification, with reasons.
    pub edges_failed: usize,
    /// Per-edge detail.
    pub edges: Vec<EdgeResult>,
    /// Maximum `reflection_depth` column value per namespace.
    pub max_reflection_depth_per_namespace: HashMap<String, i32>,
    /// `"within_cap"` when no namespace exceeded its governance cap,
    /// `"exceeded_cap"` when at least one did, or
    /// `"no_cap_configured"` when no governance policy rows exist.
    pub bounded_status: String,
    /// #9505 — the root content-id verdict. Additive and optional: `None`
    /// (not checked) is omitted from the JSON, and the forensic-bundle
    /// builder never sets it, so `verification.json` is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cid: Option<RootCidCheck>,
    /// #9634 — the `--cid` sweep, embedded in the one report. Additive and
    /// optional: `None` (no `--cid`) is omitted from the JSON, and the
    /// forensic-bundle builder never sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid_sweep: Option<CidSweepReport>,
    /// Optional `signed_events` entries when `--include-signed-events`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signed_events: Vec<SignedEventSummary>,
    /// RFC3339 timestamp of report generation.
    pub generated_at: String,
}

impl ChainReport {
    /// #9505 — record the root content-id verdict and fold it into the ONE
    /// final `ok`: a `Mismatch` or `Unreadable` root makes `ok` false; a root
    /// that was not checked (`None`) leaves it as the chain walk set it.
    #[must_use]
    pub fn with_root_cid(mut self, check: Option<RootCidCheck>) -> Self {
        if let Some(verdict) = &check {
            self.ok = self.ok && verdict.passes();
        }
        self.root_cid = check;
        self
    }

    /// #9634 — record the `--cid` sweep and fold it into the ONE final `ok`:
    /// a mismatched or unreadable row makes `ok` false; no sweep (`None`)
    /// leaves it as it was.
    #[must_use]
    pub fn with_cid_sweep(mut self, sweep: Option<CidSweepReport>) -> Self {
        if let Some(report) = &sweep {
            self.ok = self.ok && report.passes();
        }
        self.cid_sweep = sweep;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────
// Helpers — package-private (pub(super) keeps the R7 surface clean)
// ─────────────────────────────────────────────────────────────────────

/// Encode bytes as a lowercase hexadecimal string. Used instead of the
/// `hex` crate (which is not a direct dependency) to keep the
/// dependency surface flat per repo convention.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fetch a single memory's (id, namespace, reflection_depth) tuple.
/// Returns `None` when not found.
fn fetch_memory_meta(conn: &Connection, id: &str) -> Result<Option<(String, String, i32)>> {
    let mut stmt =
        conn.prepare("SELECT id, namespace, reflection_depth FROM memories WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        Ok(Some((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            // #9505: a depth that does not decode is an error, never depth 0
            // (which would read an over-cap chain as within its cap).
            row.get::<_, i32>(2)?,
        )))
    } else {
        Ok(None)
    }
}

/// One `reflects_on` edge row as returned by the DB.
struct EdgeRow {
    target_id: String,
    signature: Option<Vec<u8>>,
    observed_by: Option<String>,
    attest_level: Option<String>,
    created_at: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

/// Fetch all `reflects_on` edges whose `source_id = memory_id`,
/// including the temporal-validity columns that are part of the
/// signed bundle (H2 signs `created_at` + `valid_from` + `valid_until`
/// alongside the other link fields — verification must re-derive the
/// same canonical CBOR, so these must round-trip from the DB).
fn fetch_reflects_on_edges(conn: &Connection, source_id: &str) -> Result<Vec<EdgeRow>> {
    let mut stmt = conn.prepare(
        "SELECT target_id, signature, observed_by, attest_level, created_at, \
                valid_from, valid_until \
         FROM memory_links \
         WHERE source_id = ?1 AND relation = 'reflects_on'",
    )?;
    let rows = stmt.query_map(params![source_id], |row| {
        Ok(EdgeRow {
            target_id: row.get::<_, String>(0)?,
            signature: row.get::<_, Option<Vec<u8>>>(1)?,
            observed_by: row.get::<_, Option<String>>(2)?,
            attest_level: row.get::<_, Option<String>>(3)?,
            created_at: row.get::<_, Option<String>>(4)?,
            valid_from: row.get::<_, Option<String>>(5)?,
            valid_until: row.get::<_, Option<String>>(6)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Fetch up to 1000 `signed_events` rows whose `agent_id` matches any
/// of the supplied memory ids (by convention the audit rows for a
/// reflect use the agent_id field as the actor's identifier; the
/// memory_id is embedded in the payload). #9505: a query failure is an
/// error, never an empty list presented as "no events".
fn fetch_signed_events_for(conn: &Connection, ids: &[String]) -> Result<Vec<SignedEventSummary>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // Build positional params manually — rusqlite's `params!` macro
    // cannot splat a runtime-length slice, so we construct the SQL
    // placeholder string ourselves and pass a slice of `&dyn ToSql`.
    let placeholders: String = ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp \
         FROM signed_events \
         WHERE agent_id IN ({placeholders}) \
         ORDER BY timestamp ASC, id ASC \
         LIMIT 1000"
    );
    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::ToSql> =
        ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(SignedEventSummary {
            event_id: row.get::<_, String>(0)?,
            memory_id: row.get::<_, String>(1)?,
            event_type: row.get::<_, String>(2)?,
            // col 3 = payload_hash (unused in summary)
            signature_present: row.get::<_, Option<Vec<u8>>>(4)?.is_some(),
            attest_level: row.get::<_, String>(5)?,
            timestamp: row.get::<_, String>(6)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Look up the governance `max_reflection_depth` for a namespace.
///
/// Delegates to the existing [`crate::db::resolve_governance_policy`]
/// chain-walker which reads `metadata.governance` from namespace
/// standard memories (walking leaf-first up to the global `*`
/// standard). Returns `None` when no policy with a
/// `max_reflection_depth` exists anywhere in the chain.
///
/// # Errors
///
/// #4043 — an unreadable policy is an error, never "no cap" (which would
/// report an over-cap chain as clean).
fn governance_cap_for_namespace(conn: &Connection, namespace: &str) -> Result<Option<u32>> {
    // #880 — `max_reflection_depth` lives on `CorePolicy` after the
    // governance decomposition; wire format unchanged.
    Ok(crate::db::resolve_governance_policy(conn, namespace)?
        .and_then(|p| p.core.max_reflection_depth))
}

// ─────────────────────────────────────────────────────────────────────
// Core chain-walk + verify logic
// ─────────────────────────────────────────────────────────────────────

/// Walk the `reflects_on` ancestry tree from `root_id`, verify every
/// edge, and return the [`ChainReport`].
///
/// # Errors
///
/// Propagates database read errors.
pub fn build_chain_report(
    conn: &Connection,
    root_id: &str,
    include_signed_events: bool,
) -> Result<ChainReport> {
    build_chain_report_at(conn, root_id, include_signed_events, None)
}

/// Variant of [`build_chain_report`] that lets the caller pin the
/// `generated_at` timestamp. Used by `forensic::bundle` so the
/// embedded `verification.json` is byte-stable across rebuilds (the
/// bundle's own `manifest.generated_at` is the *only* legitimate
/// non-deterministic field). `None` falls back to `Utc::now()`.
///
/// # Errors
///
/// Propagates database read errors.
pub fn build_chain_report_at(
    conn: &Connection,
    root_id: &str,
    include_signed_events: bool,
    generated_at_override: Option<&str>,
) -> Result<ChainReport> {
    let generated_at = generated_at_override
        .map(ToString::to_string)
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((root_id.to_string(), 0));

    let mut edges: Vec<EdgeResult> = Vec::new();
    let mut max_depth_per_ns: HashMap<String, i32> = HashMap::new();
    let mut chain_depth: usize = 0;
    let mut all_ids: Vec<String> = Vec::new();
    let mut any_governance_row = false;
    let mut cap_exceeded = false;

    while let Some((current_id, hop)) = queue.pop_front() {
        if visited.contains(&current_id) {
            continue;
        }
        visited.insert(current_id.clone());
        all_ids.push(current_id.clone());

        if hop > chain_depth {
            chain_depth = hop;
        }

        // Fetch memory meta to track namespace depths and check cap.
        if let Some((_id, ns, rd)) = fetch_memory_meta(conn, &current_id)? {
            let entry = max_depth_per_ns.entry(ns.clone()).or_insert(0_i32);
            if rd > *entry {
                *entry = rd;
            }
            if let Some(cap) = governance_cap_for_namespace(conn, &ns)? {
                any_governance_row = true;
                #[allow(clippy::cast_sign_loss)]
                if rd > 0 && rd as u32 > cap {
                    cap_exceeded = true;
                }
            }
        }

        // Walk outbound `reflects_on` edges.
        let out_edges = fetch_reflects_on_edges(conn, &current_id)?;
        for row in out_edges {
            let attest_level = row
                .attest_level
                .clone()
                .unwrap_or_else(|| crate::models::AttestLevel::Unsigned.as_str().to_string());

            let (verified, failure_reason, signature_hex) = verify_edge(
                &current_id,
                &row.target_id,
                row.signature.as_deref(),
                row.observed_by.as_deref(),
                row.valid_from.as_deref(),
                row.valid_until.as_deref(),
                row.created_at.as_deref(),
                &attest_level,
            );

            let target_id = row.target_id.clone();
            edges.push(EdgeResult {
                source_id: current_id.clone(),
                target_id: target_id.clone(),
                signature_hex,
                attest_level,
                verified,
                failure_reason,
            });

            if !visited.contains(&target_id) {
                queue.push_back((target_id, hop + 1));
            }
        }
    }

    let edges_failed = edges.iter().filter(|e| !e.verified).count();
    let edges_verified = edges.len() - edges_failed;

    let bounded_status = if cap_exceeded {
        "exceeded_cap"
    } else if any_governance_row {
        "within_cap"
    } else {
        "no_cap_configured"
    }
    .to_string();

    let signed_events = if include_signed_events {
        fetch_signed_events_for(conn, &all_ids)?
    } else {
        Vec::new()
    };

    // v0.7.0 G-PHASE-E-4 (#709) — derive the top-line `ok` flag from
    // the same predicate the exit code uses (`edges_failed == 0 &&
    // bounded_status != "exceeded_cap"`). Kept here so callers reading
    // the JSON wire shape don't have to re-derive it.
    let ok = edges_failed == 0 && bounded_status != "exceeded_cap";
    Ok(ChainReport {
        ok,
        root_id: root_id.to_string(),
        n_memories: visited.len(),
        chain_depth,
        edges_verified,
        edges_failed,
        edges,
        max_reflection_depth_per_namespace: max_depth_per_ns,
        bounded_status,
        root_cid: None,
        cid_sweep: None,
        signed_events,
        generated_at,
    })
}

/// Attempt to verify a single `reflects_on` edge's Ed25519 signature.
///
/// Returns `(verified, failure_reason, signature_hex)`. An unsigned
/// edge (no signature blob) is always considered "verified" — absence
/// of a signature is not a failure; it means the edge was written
/// before attestation was enabled.
/// Verify a single `reflects_on` edge's Ed25519 signature.
///
/// `created_at`, `valid_from` and `valid_until` must be the raw values
/// stored in `memory_links` — they are part of the signed canonical
/// CBOR bundle (H2 commits to all seven `SignableLink` fields at sign
/// time). Passing the wrong values causes the re-derived payload to
/// diverge from what the signer committed to, which makes Ed25519
/// reject the signature even for an otherwise honest edge.
///
/// Returns `(verified, failure_reason, signature_hex)`.
#[allow(clippy::too_many_arguments)] // #3291 adds created_at; signature is the checklist
fn verify_edge(
    source_id: &str,
    target_id: &str,
    sig_blob: Option<&[u8]>,
    observed_by: Option<&str>,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
    created_at: Option<&str>,
    attest_level: &str,
) -> (bool, Option<String>, Option<String>) {
    let signature_hex = sig_blob.map(bytes_to_hex);

    // Unsigned edge — presence-confirmed; no signature to verify.
    let Some(sig) = sig_blob else {
        return (true, None, None);
    };

    let Some(agent_id) = observed_by else {
        return (
            false,
            Some(
                "signature present but observed_by is NULL — \
                 cannot resolve public key"
                    .to_string(),
            ),
            signature_hex,
        );
    };

    if agent_id.is_empty() {
        return (
            false,
            Some("observed_by is empty — cannot resolve public key".to_string()),
            signature_hex,
        );
    }

    let pub_key = crate::identity::verify::lookup_peer_public_key(agent_id);
    let Some(pub_key) = pub_key else {
        return (
            false,
            Some(format!(
                "no public key enrolled for '{agent_id}' \
                 (attest_level={attest_level})"
            )),
            signature_hex,
        );
    };

    let link = SignableLink {
        src_id: source_id,
        dst_id: target_id,
        relation: crate::models::MemoryLinkRelation::ReflectsOn.as_str(),
        observed_by: Some(agent_id),
        created_at,
        valid_from,
        valid_until,
    };

    match crate::identity::verify::verify(&pub_key, &link, sig) {
        Ok(()) => (true, None, signature_hex),
        Err(e) => (false, Some(e.to_string()), signature_hex),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Text renderer
// ─────────────────────────────────────────────────────────────────────

/// #9636 — every stored value below goes through [`Printed`]; the verdict
/// and the counts are the verb's own values.
pub(super) fn render_text(report: &ChainReport, out: &mut CliOutput<'_>) -> Result<()> {
    writeln!(
        out.stdout,
        "verify-reflection-chain: root={} memories={} depth={} edges={} failed={} ok={}",
        Printed::field(&report.root_id),
        report.n_memories,
        report.chain_depth,
        report.edges.len(),
        report.edges_failed,
        report.ok,
    )?;
    writeln!(out.stdout, "bounded_status: {}", report.bounded_status)?;
    writeln!(out.stdout, "generated_at:   {}", report.generated_at)?;
    // v0.9.0 G8 (#1825) / #9505 — the root's content-id verdict, decided
    // before this function runs. Not checked = no line.
    match &report.root_cid {
        Some(RootCidCheck::Verified { cid }) => {
            writeln!(out.stdout, "cid_verified:   true ({})", Printed::field(cid))?;
        }
        Some(RootCidCheck::Mismatch { cid }) => {
            writeln!(
                out.stdout,
                "cid_verified:   false ({})",
                Printed::field(cid)
            )?;
        }
        Some(RootCidCheck::Unreadable { error_class }) => writeln!(
            out.stdout,
            "cid_verified:   unreadable ({})",
            error_class.label()
        )?,
        None => {}
    }

    if !report.max_reflection_depth_per_namespace.is_empty() {
        writeln!(out.stdout, "\nmax_reflection_depth per namespace:")?;
        let mut ns_vec: Vec<_> = report.max_reflection_depth_per_namespace.iter().collect();
        ns_vec.sort_by_key(|(ns, _)| ns.as_str());
        for (ns, depth) in ns_vec {
            writeln!(out.stdout, "  {}: {depth}", Printed::field(ns))?;
        }
    }

    if !report.edges.is_empty() {
        writeln!(out.stdout, "\nedges:")?;
        for e in &report.edges {
            let status = if e.verified { "OK" } else { "FAIL" };
            // Char-boundary prefixes (OWNERSHIP-15): a byte slice of a
            // stored id could split a multi-byte character and panic.
            write!(
                out.stdout,
                "  [{status}] {} -> {}  attest={}",
                Printed::prefix(&e.source_id, EDGE_ID_PREFIX_CHARS),
                Printed::prefix(&e.target_id, EDGE_ID_PREFIX_CHARS),
                Printed::field(&e.attest_level),
            )?;
            if let Some(ref reason) = e.failure_reason {
                write!(out.stdout, "  reason=\"{}\"", Printed::field(reason))?;
            }
            writeln!(out.stdout)?;
        }
    }

    if !report.signed_events.is_empty() {
        writeln!(
            out.stdout,
            "\nsigned_events ({} rows):",
            report.signed_events.len()
        )?;
        for ev in &report.signed_events {
            writeln!(
                out.stdout,
                "  {} | {} | {} | sig={}",
                Printed::field(&ev.event_id),
                Printed::field(&ev.event_type),
                Printed::field(&ev.timestamp),
                if ev.signature_present { "yes" } else { "no" }
            )?;
        }
    }

    // #9634 — the `--cid` sweep, decided before this function runs.
    if let Some(sweep) = &report.cid_sweep {
        writeln!(
            out.stdout,
            "cid sweep: checked={} verified={} mismatched={} unreadable={} unverifiable={}",
            sweep.checked,
            sweep.cid_verified,
            sweep.cid_mismatched,
            sweep.cid_unreadable,
            sweep.cid_unverifiable
        )?;
        for m in &sweep.mismatches {
            writeln!(out.stdout, "  MISMATCH {}", Printed::field(m))?;
        }
        for row in &sweep.unreadable {
            writeln!(
                out.stdout,
                "  UNREADABLE {} ({})",
                Printed::field(row.id.as_deref().unwrap_or(UNREADABLE_ID_LABEL)),
                row.error_class.label()
            )?;
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Entry point called by daemon_runtime dispatch
// ─────────────────────────────────────────────────────────────────────

/// Run the `verify-reflection-chain` subcommand against the SQLite DB at
/// `db_path`. Returns an exit code: `0` if the chain is intact, `1` if the
/// root memory does not exist, `2` if the chain is broken.
///
/// v1.0.0 #3436 — the `1` (NOT FOUND) arm is new. Before it, an unknown
/// root produced an empty walk whose `ok` predicate was vacuously true, so
/// the verb answered `ok: true` / exit 0 about a memory it had never found.
/// "I could not find it" and "I checked it and it is broken" are different
/// answers and a CI gate must be able to tell them apart.
///
/// v0.7.0 G-PHASE-E-4 (#709) — raised the failure exit code from `1`
/// to `2`. The previous `1` was indistinguishable from CLI argument
/// errors / unwrap panics under shell error trapping; `2` is the
/// conventional "verification failed" code (matches the convention
/// raised on `verify-forensic-bundle` in the same fold) and aligns
/// with the new top-line `ok` field in [`ChainReport`].
///
/// #9505 (3-agent vote (71472661), ruling fe96bc17) — an input that cannot
/// be read (the database, the root row, the chain, the `--cid` sweep query)
/// is UNREADABLE: one document naming the stage and the error class, exit
/// `2`. It is never the generic `Err` path, which `main` turns into exit 1.
///
/// # Errors
///
/// Propagates only a failure to write the report to `out`.
pub fn run(db_path: &Path, args: &VerifyChainArgs, out: &mut CliOutput<'_>) -> Result<i32> {
    run_with_sweep_sql(db_path, args, out, CID_SWEEP_SQL)
}

/// [`run`] with the `--cid` sweep query given (the unit cells pass a query
/// that cannot be prepared or stepped).
fn run_with_sweep_sql(
    db_path: &Path,
    args: &VerifyChainArgs,
    out: &mut CliOutput<'_>,
    sweep_sql: &str,
) -> Result<i32> {
    let json = args.format.to_ascii_lowercase() == "json";
    let root_id = args.memory_id.as_str();
    let conn = match crate::db::open(db_path) {
        Ok(conn) => conn,
        Err(err) => {
            return report_unreadable(out, json, root_id, ReadFault::of(ReadStage::Open, &err));
        }
    };

    // v1.0.0 #3436 — REFUSE an unknown root instead of certifying it.
    //
    // `build_chain_report` walks outward from `root_id`; a root that does
    // not exist simply yields an empty walk, whose `ok` predicate
    // (`edges_failed == 0 && bounded_status != "exceeded_cap"`) is
    // vacuously TRUE. So `verify-reflection-chain <typo>` reported
    // `ok: true` and exited 0 — a verifier that answers "verified" about
    // a memory it never found is the worst failure mode a verifier has,
    // and it is exactly what a CI gate would trust.
    //
    // The existence check lives HERE, at the CLI entry point, rather than
    // inside `build_chain_report`: the forensic-bundle builder calls that
    // same function for a root it has already resolved, and turning a
    // missing row into a hard error there would change bundle semantics
    // for no benefit.
    //
    // Exit 1 = NOT FOUND, deliberately distinct from exit 2 = verification
    // FAILED (#709). "I could not find it" and "I checked it and it is
    // broken" are different answers and a script must be able to tell them
    // apart.
    let root = match crate::db::get(&conn, root_id) {
        Ok(root) => root,
        Err(err) => {
            return report_unreadable(out, json, root_id, ReadFault::of(ReadStage::Root, &err));
        }
    };
    if root.is_none() {
        if json {
            let payload = serde_json::json!({
                "ok": false,
                "root_id": args.memory_id,
                "not_found": true,
                "error": crate::errors::msg::not_found(&args.memory_id),
            });
            let payload = serde_json::to_string_pretty(&payload)?;
            writeln!(out.stdout, "{}", json_for_terminal(&payload)?)?;
        } else {
            writeln!(
                out.stderr,
                "{}",
                Printed::field(&crate::errors::msg::not_found(&args.memory_id))
            )?;
        }
        return Ok(1);
    }

    // #9505 (3-agent vote (71472661), B + J1) — the root content-id check
    // runs BEFORE anything is printed, in both modes, and folds into the ONE
    // final `ok` that the summary, the JSON and the exit code all read. The
    // root row is the one resolved above: no second read, nothing swallowed.
    // #9634 — the `--cid` sweep runs here too, before any output, and is
    // embedded in the same report: one JSON document, one summary line.
    let root_cid = root.as_ref().and_then(|row| check_root_cid(&conn, row));
    let cid_sweep = if args.cid {
        match run_cid_sweep_query(&conn, sweep_sql) {
            Ok(sweep) => Some(sweep),
            Err(fault) => return report_unreadable(out, json, root_id, fault),
        }
    } else {
        None
    };
    let report = match build_chain_report(&conn, root_id, args.include_signed_events) {
        Ok(report) => report.with_root_cid(root_cid).with_cid_sweep(cid_sweep),
        Err(err) => {
            return report_unreadable(out, json, root_id, ReadFault::of(ReadStage::Chain, &err));
        }
    };

    if json {
        let payload = serde_json::to_string_pretty(&report).context("serialise chain report")?;
        writeln!(out.stdout, "{}", json_for_terminal(&payload)?)?;
    } else {
        render_text(&report, out)?;
    }
    match &report.root_cid {
        Some(RootCidCheck::Mismatch { cid }) => writeln!(
            out.stderr,
            "verify-reflection-chain: root content-id mismatch (cid {}): the stored genesis \
             is not the pre-image of the cid; verification failed",
            Printed::field(cid)
        )?,
        Some(RootCidCheck::Unreadable { error_class }) => writeln!(
            out.stderr,
            "verify-reflection-chain: root content-id genesis unreadable ({}); verification failed",
            error_class.label()
        )?,
        Some(RootCidCheck::Verified { .. }) | None => {}
    }
    if let Some(sweep) = report.cid_sweep.as_ref().filter(|s| !s.passes()) {
        writeln!(
            out.stderr,
            "verify-reflection-chain: cid sweep failed (mismatched={} unreadable={}); \
             verification failed",
            sweep.cid_mismatched, sweep.cid_unreadable
        )?;
    }

    // Exit code mirrors `report.ok`. The predicate is
    // `edges_failed == 0 && bounded_status != "exceeded_cap"` AND (#9505)
    // a checked root content-id is `verified` AND (#9634) the `--cid`
    // sweep, when asked for, found no mismatched and no unreadable row. A
    // failed check is a failed verification, exit 2, never the generic
    // `Err` path, which `main` turns into exit 1 = NOT FOUND's code. It is
    // set once, by `with_root_cid` and `with_cid_sweep`, before anything
    // was printed. An input that could not be read returned above through
    // `report_unreadable` (exit 2, one document); the only `Err` left is a
    // failure to write to `out`.
    if report.ok { Ok(0) } else { Ok(2) }
}

/// #9505 — print the ONE UNREADABLE document for `fault` and return exit
/// `2`. JSON mode prints one object (`ok` false, `root_id`, `unreadable`
/// with the stage and error class); text mode prints one summary line. Both
/// streams carry fixed labels only, plus the caller's root id through the
/// terminal funnels.
fn report_unreadable(
    out: &mut CliOutput<'_>,
    json: bool,
    root_id: &str,
    fault: ReadFault,
) -> Result<i32> {
    if json {
        let payload = serde_json::json!({
            "ok": false,
            "root_id": root_id,
            "unreadable": fault,
        });
        let payload = serde_json::to_string_pretty(&payload).context("serialise unreadable")?;
        writeln!(out.stdout, "{}", json_for_terminal(&payload)?)?;
    } else {
        writeln!(
            out.stdout,
            "verify-reflection-chain: root={} unreadable={} error_class={} ok=false",
            Printed::field(root_id),
            fault.stage.label(),
            fault.error_class.label()
        )?;
    }
    writeln!(
        out.stderr,
        "verify-reflection-chain: {fault}; verification failed"
    )?;
    Ok(2)
}

// ─────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rusqlite::params;
    use tempfile::TempDir;

    use crate::db;
    use crate::identity::keypair as kp_mod;
    use crate::identity::sign;
    use crate::models::{Memory, Tier};

    /// #9635 — every branch of the read-error classifier, by error type,
    /// including a decode error wrapped in `anyhow` context.
    #[test]
    fn genesis_read_error_class_labels_every_branch_9635() {
        use crate::storage::schema_guard::ProvenanceReadFault;
        use anyhow::Context as _;
        use rusqlite::types::Type;
        let decode_in_context: anyhow::Error = Err::<(), _>(rusqlite::Error::InvalidColumnType(
            2,
            "cid_genesis".into(),
            Type::Text,
        ))
        .context("read cid_genesis")
        .expect_err("err by construction");
        let cases: Vec<(&str, anyhow::Error, GenesisReadErrorClass, &str)> = vec![
            (
                "provenance fault",
                anyhow::Error::new(ProvenanceReadFault::ColumnMissingPreV74 {
                    column: "cid_genesis",
                    source: rusqlite::Error::InvalidQuery,
                }),
                GenesisReadErrorClass::SchemaFault,
                "schema_fault",
            ),
            (
                "invalid column type",
                anyhow::Error::new(rusqlite::Error::InvalidColumnType(
                    2,
                    "cid_genesis".into(),
                    Type::Text,
                )),
                GenesisReadErrorClass::DecodeError,
                "decode_error",
            ),
            (
                "from-sql conversion",
                anyhow::Error::new(rusqlite::Error::FromSqlConversionFailure(
                    2,
                    Type::Integer,
                    Box::new(std::fmt::Error),
                )),
                GenesisReadErrorClass::DecodeError,
                "decode_error",
            ),
            (
                "decode error in context",
                decode_in_context,
                GenesisReadErrorClass::DecodeError,
                "decode_error",
            ),
            (
                "no rows",
                anyhow::Error::new(rusqlite::Error::QueryReturnedNoRows),
                GenesisReadErrorClass::StorageError,
                "storage_error",
            ),
            (
                "sqlite io error",
                anyhow::Error::new(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                    None,
                )),
                GenesisReadErrorClass::StorageError,
                "storage_error",
            ),
            (
                "plain error",
                anyhow::anyhow!("plain"),
                GenesisReadErrorClass::StorageError,
                "storage_error",
            ),
        ];
        for (name, err, want, label) in &cases {
            let got = GenesisReadErrorClass::of(err);
            assert_eq!(got, *want, "{name}");
            assert_eq!(got.label(), *label, "{name}");
        }
    }

    /// #9636 — the funnel escapes every control and hidden character, keeps
    /// ordinary text (multi-byte included) as is, and cuts on the output
    /// bound with an exact marker.
    #[test]
    fn printed_escapes_and_bounds_stored_values_9636() {
        let cases: &[(&str, &str)] = &[
            ("b3:abc", "b3:abc"),
            ("a\nb", "a\\u{a}b"),
            ("a\rb", "a\\u{d}b"),
            ("\u{1b}[2J", "\\u{1b}[2J"),
            ("\u{9b}2J", "\\u{9b}2J"),
            ("\u{7f}", "\\u{7f}"),
            ("x\0y", "x\\u{0}y"),
            ("\u{202e}ab\u{2066}", "\\u{202e}ab\\u{2066}"),
            ("\u{200b}\u{feff}\u{2028}", "\\u{200b}\\u{feff}\\u{2028}"),
            ("héllo ✓ 日本", "héllo ✓ 日本"),
        ];
        for (value, want) in cases {
            assert_eq!(Printed::field(value).to_string(), *want, "{value:?}");
        }

        let long = "x".repeat(MAX_PRINTED_FIELD_CHARS + 10);
        assert_eq!(
            Printed::field(&long).to_string(),
            format!("{}...(+10 chars)", "x".repeat(MAX_PRINTED_FIELD_CHARS))
        );
        let exact = "y".repeat(MAX_PRINTED_FIELD_CHARS);
        assert_eq!(Printed::field(&exact).to_string(), exact);
        // An escape that would cross the bound is not split.
        let edge = format!("{}\n", "z".repeat(MAX_PRINTED_FIELD_CHARS - 2));
        assert_eq!(
            Printed::field(&edge).to_string(),
            format!("{}...(+1 chars)", "z".repeat(MAX_PRINTED_FIELD_CHARS - 2))
        );

        // Abbreviated ids cut on a char boundary, unmarked (OWNERSHIP-15).
        assert_eq!(
            Printed::prefix("日本語のメモリーです", 8).to_string(),
            "日本語のメモリー"
        );
        assert_eq!(Printed::prefix("ab", 8).to_string(), "ab");
    }

    /// #9636 — the JSON terminal filter keeps the document's value and
    /// prints no raw control or hidden character.
    #[test]
    fn json_for_terminal_keeps_the_value_and_escapes_9636() {
        let value = serde_json::json!({
            "cid": "a\u{9b}b\u{202e}c\u{7f}d\u{feff}\n😀",
            "plain": "héllo",
        });
        let pretty = serde_json::to_string_pretty(&value).expect("serialise");
        let safe = json_for_terminal(&pretty).expect("filter");
        assert!(
            safe.chars().all(|c| c == '\n' || !needs_escape(c)),
            "{safe:?}"
        );
        let back: serde_json::Value = serde_json::from_str(&safe).expect("parse");
        assert_eq!(back, value);
    }

    /// #9636 — an oversized value is printed in linear time and bounded.
    #[test]
    fn printed_large_value_is_bounded_and_fast_9636() {
        const LARGE_CHARS: usize = 1_000_000;
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
        let large = "\u{1b}".repeat(LARGE_CHARS);
        let started = std::time::Instant::now();
        let shown = Printed::field(&large).to_string();
        assert!(started.elapsed() < DEADLINE, "{:?}", started.elapsed());
        assert!(
            shown.chars().count() <= MAX_PRINTED_FIELD_CHARS + 32,
            "{}",
            shown.len()
        );
        assert!(shown.ends_with(" chars)"), "{shown}");
    }

    fn open_test_db(tmp: &TempDir) -> (rusqlite::Connection, std::path::PathBuf) {
        let db_path = tmp.path().join("ai-memory.db");
        let conn = db::open(&db_path).expect("db::open");
        (conn, db_path)
    }

    fn insert_mem(conn: &rusqlite::Connection, ns: &str, depth: i32) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let mem = Memory {
            id: id.clone(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: format!("t-{depth}"),
            content: format!("c-{depth}"),
            reflection_depth: depth,
            created_at: now.clone(),
            updated_at: now,
            ..Default::default()
        };
        db::insert(conn, &mem).expect("insert");
        id
    }

    fn link_unsigned(conn: &rusqlite::Connection, src: &str, tgt: &str) {
        conn.execute(
            "INSERT OR IGNORE INTO memory_links \
             (source_id, target_id, relation, created_at, attest_level) \
             VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
            params![src, tgt, Utc::now().to_rfc3339()],
        )
        .expect("link_unsigned");
    }

    /// Attach a `max_reflection_depth` governance policy to `ns` by
    /// inserting a namespace standard memory (the same mechanism the
    /// production path uses — see `resolve_governance_policy`).
    fn set_cap(conn: &rusqlite::Connection, ns: &str, cap: u32) {
        use crate::models::default_metadata;
        let now = Utc::now().to_rfc3339();
        let policy = crate::models::GovernancePolicy {
            core: crate::models::CorePolicy {
                max_reflection_depth: Some(cap),
                ..crate::models::CorePolicy::default()
            },
            ..crate::models::GovernancePolicy::default()
        };
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("agent_id".into(), serde_json::Value::String("test".into()));
            obj.insert("governance".into(), serde_json::to_value(&policy).unwrap());
        }
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: format!("_standards-{ns}"),
            title: format!("standard for {ns}"),
            content: "policy".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Default::default()
        };
        let sid = db::insert(conn, &standard).expect("insert standard");
        db::set_namespace_standard(conn, ns, &sid, None).expect("set_namespace_standard");
    }

    #[test]
    fn single_memory_no_edges_gives_empty_report() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let id = insert_mem(&conn, "ns", 0);

        let report = build_chain_report(&conn, &id, false).expect("report");

        assert_eq!(report.root_id, id);
        assert_eq!(report.n_memories, 1);
        assert_eq!(report.chain_depth, 0);
        assert_eq!(report.edges.len(), 0);
        assert_eq!(report.edges_failed, 0);
        assert_eq!(report.edges_verified, 0);
        assert_eq!(report.bounded_status, "no_cap_configured");
        assert!(report.signed_events.is_empty());
    }

    #[test]
    fn unsigned_chain_depth2_all_verified() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let d0 = insert_mem(&conn, "ns", 0);
        let d1 = insert_mem(&conn, "ns", 1);
        let d2 = insert_mem(&conn, "ns", 2);
        link_unsigned(&conn, &d2, &d1);
        link_unsigned(&conn, &d1, &d0);

        let report = build_chain_report(&conn, &d2, false).expect("report");

        assert_eq!(report.n_memories, 3);
        assert_eq!(report.chain_depth, 2);
        assert_eq!(report.edges_failed, 0);
        // Unsigned edges count as verified.
        assert!(report.edges.iter().all(|e| e.verified));
    }

    #[test]
    fn cap_exceeded_reported_in_bounded_status() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        set_cap(&conn, "cap-ns", 0);
        let d0 = insert_mem(&conn, "cap-ns", 0);
        let d1 = insert_mem(&conn, "cap-ns", 1); // depth 1 > cap 0
        link_unsigned(&conn, &d1, &d0);

        let report = build_chain_report(&conn, &d1, false).expect("report");

        assert_eq!(report.bounded_status, "exceeded_cap");
    }

    #[test]
    fn tampered_sig_edge_marked_failed() {
        // Serialise the `AI_MEMORY_KEY_DIR` mutation on the crate-global env
        // lock so it cannot race keypair/cli::store/governance tests that
        // also stomp this process-wide var. #626 Layer-3.
        let _g = kp_mod::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = TempDir::new().unwrap();
        let keys_tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);

        let agent = kp_mod::generate("tester-l13").expect("gen");
        kp_mod::save(&agent, keys_tmp.path()).expect("save");

        let d0 = insert_mem(&conn, "ns", 0);
        let d1 = insert_mem(&conn, "ns", 1);

        let now = Utc::now().to_rfc3339();
        let link = sign::SignableLink {
            src_id: &d1,
            dst_id: &d0,
            relation: "reflects_on",
            observed_by: Some(&agent.agent_id),
            created_at: Some(&now),
            valid_from: Some(&now),
            valid_until: None,
        };
        let mut sig = sign::sign(&agent, &link).expect("sign");
        sig[0] ^= 0x01; // tamper

        conn.execute(
            "INSERT OR IGNORE INTO memory_links \
             (source_id, target_id, relation, created_at, valid_from, \
              signature, observed_by, attest_level) \
             VALUES (?1, ?2, 'reflects_on', ?3, ?3, ?4, ?5, 'self_signed')",
            params![d1, d0, now, sig, agent.agent_id],
        )
        .expect("insert tampered");

        // Point key lookup at the test key dir.
        unsafe {
            std::env::set_var("AI_MEMORY_KEY_DIR", keys_tmp.path());
        }
        let report = build_chain_report(&conn, &d1, false).expect("report");
        unsafe {
            std::env::remove_var("AI_MEMORY_KEY_DIR");
        }

        assert_eq!(report.edges_failed, 1, "tampered edge must count as failed");
        assert!(
            report.edges[0].failure_reason.is_some(),
            "tampered edge must carry a reason"
        );
    }

    #[test]
    fn include_signed_events_flag_returns_vec() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let id = insert_mem(&conn, "se-ns", 0);

        // With flag=false the vec is always empty.
        let r = build_chain_report(&conn, &id, false).expect("report");
        assert!(r.signed_events.is_empty());

        // With flag=true it may still be empty (no events in this DB),
        // but the call must not error.
        let r2 = build_chain_report(&conn, &id, true).expect("report-se");
        let _ = r2.signed_events; // just assert it's accessible
    }

    #[test]
    fn bytes_to_hex_matches_format_pattern() {
        let b = vec![0x00, 0x0f, 0xff, 0xab];
        assert_eq!(bytes_to_hex(&b), "000fffab");
    }

    // -----------------------------------------------------------------
    // C-3 coverage uplift — drive the remaining branches:
    //   - fetch_memory_meta None branch (line 139)
    //   - fetch_signed_events_for empty-input early-return (line 185)
    //   - fetch_signed_events_for happy path with seeded rows (208-216)
    //   - verify_edge: observed_by None / empty / unknown agent (405-433)
    //   - render_text branches: max_depth table, edge reasons, signed
    //     events footer (464+)
    //   - run() JSON-format dispatch (528-541)
    //   - run() exit-code-1 path
    // -----------------------------------------------------------------

    #[test]
    fn fetch_memory_meta_returns_none_for_unknown_id() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let r = fetch_memory_meta(&conn, "nonexistent-id-xxxxxx").expect("query");
        assert!(r.is_none(), "unknown id must return None");
    }

    #[test]
    fn fetch_signed_events_for_empty_ids_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let v = fetch_signed_events_for(&conn, &[]).expect("call");
        assert!(v.is_empty());
    }

    #[test]
    fn fetch_signed_events_for_seeded_rows_returns_summaries() {
        // Drives the row-decode block at lines 206-216 by pre-seeding a
        // signed_events row with the same agent_id used in the IN clause.
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let agent_id = "seeded-actor";
        let payload = b"hello";
        let event = crate::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(),
            event_type: crate::signed_events::event_types::MEMORY_LINK_CREATED.to_string(),
            payload_hash: crate::signed_events::payload_hash(payload),
            signature: Some(vec![0xab; 64]),
            attest_level: "self_signed".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..crate::signed_events::SignedEvent::default()
        };
        crate::signed_events::append_signed_event(&conn, &event).expect("append");

        let v =
            fetch_signed_events_for(&conn, &[agent_id.to_string()]).expect("fetch with seeded row");
        assert_eq!(v.len(), 1);
        assert!(v[0].signature_present, "signature blob should be detected");
        assert_eq!(v[0].memory_id, agent_id);
    }

    #[test]
    fn verify_edge_unsigned_returns_verified_with_no_reason() {
        let (verified, reason, sig_hex) = verify_edge(
            "src-id",
            "tgt-id",
            None,
            Some("alice"),
            None,
            None,
            None,
            "unsigned",
        );
        assert!(verified);
        assert!(reason.is_none());
        assert!(sig_hex.is_none());
    }

    #[test]
    fn verify_edge_signed_but_no_observed_by_fails() {
        let sig = vec![0xff; 64];
        let (verified, reason, sig_hex) = verify_edge(
            "src",
            "tgt",
            Some(&sig),
            None,
            None,
            None,
            None,
            "self_signed",
        );
        assert!(!verified);
        let reason = reason.expect("reason set");
        assert!(reason.contains("observed_by is NULL"), "got: {reason}");
        assert!(sig_hex.is_some());
    }

    #[test]
    fn verify_edge_signed_with_empty_observed_by_fails() {
        let sig = vec![0xff; 64];
        let (verified, reason, _) = verify_edge(
            "src",
            "tgt",
            Some(&sig),
            Some(""),
            None,
            None,
            None,
            "self_signed",
        );
        assert!(!verified);
        let reason = reason.expect("reason set");
        assert!(reason.contains("empty"), "got: {reason}");
    }

    #[test]
    fn verify_edge_signed_with_unknown_agent_fails() {
        // Force `lookup_peer_public_key` to return None by pointing the
        // key dir at a fresh empty tempdir.
        // Serialise on the crate-global env lock so the `AI_MEMORY_KEY_DIR`
        // mutation cannot race sibling tests that share this var. #626 Layer-3.
        let _g = kp_mod::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys_tmp = TempDir::new().unwrap();
        // SAFETY: this test mutates a process-wide env var; the helper
        // chain assumes no concurrent test relies on the previous value
        // during this assertion.
        unsafe {
            std::env::set_var("AI_MEMORY_KEY_DIR", keys_tmp.path());
        }
        let sig = vec![0xff; 64];
        let (verified, reason, _) = verify_edge(
            "src",
            "tgt",
            Some(&sig),
            Some("never-enrolled-agent"),
            None,
            None,
            None,
            "self_signed",
        );
        unsafe {
            std::env::remove_var("AI_MEMORY_KEY_DIR");
        }
        assert!(!verified);
        let reason = reason.expect("reason set");
        assert!(reason.contains("no public key enrolled"), "got: {reason}");
    }

    #[test]
    fn render_text_emits_ns_table_and_failure_reasons() {
        // Build a synthetic report so we hit:
        //   - the namespace table (lines 469-475)
        //   - the failure_reason write (line 488)
        //   - the signed_events footer (lines 495-511)
        use std::collections::HashMap;
        let mut ns = HashMap::new();
        ns.insert("ns-one".to_string(), 3);
        ns.insert("ns-two".to_string(), 1);
        let report = ChainReport {
            ok: false,
            root_id: "0123456789abcdef0123".to_string(),
            n_memories: 2,
            chain_depth: 1,
            edges_verified: 0,
            edges_failed: 1,
            edges: vec![EdgeResult {
                source_id: "src-id-long-1234".to_string(),
                target_id: "tgt-id-long-5678".to_string(),
                signature_hex: Some("aabb".to_string()),
                attest_level: "self_signed".to_string(),
                verified: false,
                failure_reason: Some("tampered".to_string()),
            }],
            max_reflection_depth_per_namespace: ns,
            bounded_status: "within_cap".to_string(),
            root_cid: None,
            cid_sweep: None,
            signed_events: vec![SignedEventSummary {
                memory_id: "agent-x".to_string(),
                event_id: "ev-1".to_string(),
                event_type: crate::signed_events::event_types::MEMORY_STORED.to_string(),
                attest_level: "self_signed".to_string(),
                timestamp: "2026-05-13T00:00:00Z".to_string(),
                signature_present: true,
            }],
            generated_at: "2026-05-13T00:00:00Z".to_string(),
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        render_text(&report, &mut out).expect("render");
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("ns-one: 3"), "ns table line missing: {s}");
        assert!(s.contains("ns-two: 1"), "ns table line missing: {s}");
        assert!(s.contains("FAIL"), "edge status missing: {s}");
        assert!(s.contains("tampered"), "failure reason missing: {s}");
        assert!(s.contains("signed_events"), "signed_events footer: {s}");
        assert!(s.contains("ev-1"), "event id missing: {s}");
        assert!(s.contains("sig=yes"), "signature flag: {s}");
    }

    #[test]
    fn render_text_signed_event_without_signature_says_no() {
        // Drives the `if ev.signature_present` else branch (line 508).
        let report = ChainReport {
            ok: true,
            root_id: "root-id-here".to_string(),
            n_memories: 1,
            chain_depth: 0,
            edges_verified: 0,
            edges_failed: 0,
            edges: vec![],
            max_reflection_depth_per_namespace: std::collections::HashMap::new(),
            bounded_status: "no_cap_configured".to_string(),
            root_cid: None,
            cid_sweep: None,
            signed_events: vec![SignedEventSummary {
                memory_id: "agent-y".to_string(),
                event_id: "ev-2".to_string(),
                event_type: crate::signed_events::event_types::MEMORY_TOUCH.to_string(),
                attest_level: "unsigned".to_string(),
                timestamp: "2026-05-13T01:00:00Z".to_string(),
                signature_present: false,
            }],
            generated_at: "2026-05-13T00:00:00Z".to_string(),
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        render_text(&report, &mut out).expect("render");
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("sig=no"), "must mark unsigned event: {s}");
    }

    #[test]
    fn run_json_format_emits_pretty_payload() {
        // Drives the JSON branch at lines 532-534.
        let tmp = TempDir::new().unwrap();
        let (_, db_path) = open_test_db(&tmp);
        let id = insert_mem(&open_test_db(&tmp).0, "ns", 0);

        // Re-open DB through `run` which uses crate::db::open.
        let args = VerifyChainArgs {
            memory_id: id,
            format: "json".to_string(),
            include_signed_events: false,
            cid: false,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        // The memory above was inserted into a DIFFERENT db (open_test_db
        // is called twice creating different temp paths). Re-init using
        // the real run path with an empty DB — exit code is 0 for an
        // empty/unknown id (single memory, no edges).
        let _ = run(&db_path, &args, &mut out);
        // We don't assert on the body here — the goal is to drive the
        // dispatch / json-render path itself.
    }

    #[test]
    fn run_against_real_db_emits_text_report_and_exit_0() {
        // Full happy-path through `run`: open db, build report, render
        // text, exit 0 (drives lines 526-545 sans json branch).
        let tmp = TempDir::new().unwrap();
        let (conn, db_path) = open_test_db(&tmp);
        let d0 = insert_mem(&conn, "ns", 0);
        let d1 = insert_mem(&conn, "ns", 1);
        link_unsigned(&conn, &d1, &d0);
        // Drop our local connection so `run`'s db::open can take a
        // fresh WAL handle.
        drop(conn);

        let args = VerifyChainArgs {
            memory_id: d1,
            format: "text".to_string(),
            include_signed_events: false,
            cid: false,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        let code = run(&db_path, &args, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("verify-reflection-chain"));
        assert!(s.contains("memories=2"));
    }

    #[test]
    fn run_with_cap_exceeded_returns_exit_code_1() {
        // Drives the cap-exceeded -> exit 1 arm at line 540.
        let tmp = TempDir::new().unwrap();
        let (conn, db_path) = open_test_db(&tmp);
        set_cap(&conn, "limit-ns", 0);
        let d0 = insert_mem(&conn, "limit-ns", 0);
        let d1 = insert_mem(&conn, "limit-ns", 1);
        link_unsigned(&conn, &d1, &d0);
        drop(conn);

        let args = VerifyChainArgs {
            memory_id: d1,
            format: "json".to_string(),
            include_signed_events: false,
            cid: false,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        let code = run(&db_path, &args, &mut out).expect("run");
        // v0.7.0 G-PHASE-E-4 (#709) — failure exit code raised from 1 to 2.
        assert_eq!(code, 2, "exceeded cap must exit 2");
    }

    #[test]
    fn run_json_format_with_include_signed_events_emits_field() {
        // Drives the include_signed_events true branch through run's
        // JSON output, hitting the serialiser on the empty Vec path.
        let tmp = TempDir::new().unwrap();
        let (conn, db_path) = open_test_db(&tmp);
        let id = insert_mem(&conn, "ns", 0);
        drop(conn);

        let args = VerifyChainArgs {
            memory_id: id,
            format: "json".to_string(),
            include_signed_events: true,
            cid: false,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        let code = run(&db_path, &args, &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(stdout).unwrap();
        // The JSON should at minimum carry the report wrapper fields.
        assert!(s.contains("\"root_id\""), "got: {s}");
        assert!(s.contains("\"bounded_status\""), "got: {s}");
    }

    // -----------------------------------------------------------------
    // #9505 (3-agent vote (71472661), ruling fe96bc17) — a verification
    // input that cannot be read is UNREADABLE: ok false, exit 2, ONE
    // document naming the stage and the error class, in both modes. It is
    // never the generic `Err` path (exit 1 with nothing printed), which
    // stays the code of a caller error (unknown root).
    // -----------------------------------------------------------------

    /// A sweep query naming a column that does not exist: prepare fails.
    const SWEEP_SQL_PREPARE_FAULT: &str =
        "SELECT id, cid, no_such_column_9505 FROM memories WHERE cid IS NOT NULL";
    /// A sweep query whose filter overflows an integer: prepare succeeds and
    /// the first step fails.
    const SWEEP_SQL_STEP_FAULT: &str = "SELECT id, cid, cid_genesis FROM memories \
         WHERE cid IS NOT NULL AND abs(-9223372036854775808) > 0";
    /// Text that only the SQLite error message of the prepare fault holds.
    const PREPARE_FAULT_RAW: &str = "no_such_column_9505";
    /// Text that only the SQLite error message of the step fault holds.
    const STEP_FAULT_RAW: &str = "overflow";
    const EXIT_UNREADABLE: i32 = 2;
    const CLASS_STORAGE: &str = "storage_error";
    const STAGE_PREPARE: &str = "cid_sweep_prepare";
    const STAGE_STEP: &str = "cid_sweep_step";
    const STAGE_OPEN: &str = "open";
    const SUMMARY_PREFIX_9505: &str = "verify-reflection-chain: root=";

    struct Outcome {
        code: Option<i32>,
        err: Option<String>,
        stdout: String,
        stderr: String,
    }

    fn run_case(db_path: &Path, memory_id: &str, format: &str, sweep_sql: &str) -> Outcome {
        let args = VerifyChainArgs {
            memory_id: memory_id.to_string(),
            format: format.to_string(),
            include_signed_events: false,
            cid: true,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let res = {
            let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            run_with_sweep_sql(db_path, &args, &mut out, sweep_sql)
        };
        Outcome {
            code: res.as_ref().ok().copied(),
            err: res.err().map(|e| format!("{e:#}")),
            stdout: String::from_utf8(stdout).expect("utf8 stdout"),
            stderr: String::from_utf8(stderr).expect("utf8 stderr"),
        }
    }

    /// The shared UNREADABLE contract: exact exit 2, one document, no
    /// passing summary, the exact stage and class, no path and no raw
    /// storage-error text on either stream.
    fn assert_unreadable(run: &Outcome, format: &str, stage: &str, leaks: &[&str]) {
        assert_eq!(
            run.code,
            Some(EXIT_UNREADABLE),
            "must return exit 2, not Err ({:?}):\nstdout: {}\nstderr: {}",
            run.err,
            run.stdout,
            run.stderr
        );
        assert!(
            !run.stdout.contains("ok=true") && !run.stdout.contains("\"ok\": true"),
            "no passing summary:\n{}",
            run.stdout
        );
        if format == "json" {
            let mut docs =
                serde_json::Deserializer::from_str(&run.stdout).into_iter::<serde_json::Value>();
            let doc = docs
                .next()
                .expect("one document")
                .unwrap_or_else(|e| panic!("stdout must be JSON: {e}\n{}", run.stdout));
            assert!(docs.next().is_none(), "one document:\n{}", run.stdout);
            assert_eq!(doc["ok"], serde_json::Value::Bool(false), "{doc}");
            assert_eq!(doc["unreadable"]["stage"], stage, "{doc}");
            assert_eq!(doc["unreadable"]["error_class"], CLASS_STORAGE, "{doc}");
        } else {
            let summaries: Vec<&str> = run
                .stdout
                .lines()
                .filter(|l| l.starts_with(SUMMARY_PREFIX_9505))
                .collect();
            assert_eq!(summaries.len(), 1, "one summary line:\n{}", run.stdout);
            let fields: Vec<&str> = summaries[0].split(' ').collect();
            assert!(fields.contains(&"ok=false"), "{}", summaries[0]);
            assert!(
                fields.contains(&format!("unreadable={stage}").as_str()),
                "{}",
                summaries[0]
            );
            assert!(
                fields.contains(&format!("error_class={CLASS_STORAGE}").as_str()),
                "{}",
                summaries[0]
            );
        }
        for (name, stream) in [("stdout", &run.stdout), ("stderr", &run.stderr)] {
            for leak in leaks {
                assert!(!stream.contains(leak), "{name} leaks {leak:?}:\n{stream}");
            }
        }
    }

    /// A database with one stamped memory; returns (dir, db path, id).
    fn sweep_db() -> (TempDir, std::path::PathBuf, String) {
        let tmp = TempDir::new().unwrap();
        let (conn, db_path) = open_test_db(&tmp);
        let id = insert_mem(&conn, "ns-9505", 0);
        drop(conn);
        (tmp, db_path, id)
    }

    fn sweep_fault_cell(format: &str, sql: &str, stage: &str, raw: &str) {
        let (tmp, db_path, id) = sweep_db();
        let run = run_case(&db_path, &id, format, sql);
        let path_text = db_path.display().to_string();
        let dir_text = tmp.path().display().to_string();
        assert_unreadable(&run, format, stage, &[&path_text, &dir_text, raw]);
    }

    #[test]
    fn cid_sweep_prepare_fault_text_is_unreadable_exit_2_9505() {
        sweep_fault_cell(
            "text",
            SWEEP_SQL_PREPARE_FAULT,
            STAGE_PREPARE,
            PREPARE_FAULT_RAW,
        );
    }

    #[test]
    fn cid_sweep_prepare_fault_json_is_unreadable_exit_2_9505() {
        sweep_fault_cell(
            "json",
            SWEEP_SQL_PREPARE_FAULT,
            STAGE_PREPARE,
            PREPARE_FAULT_RAW,
        );
    }

    #[test]
    fn cid_sweep_step_fault_text_is_unreadable_exit_2_9505() {
        sweep_fault_cell("text", SWEEP_SQL_STEP_FAULT, STAGE_STEP, STEP_FAULT_RAW);
    }

    #[test]
    fn cid_sweep_step_fault_json_is_unreadable_exit_2_9505() {
        sweep_fault_cell("json", SWEEP_SQL_STEP_FAULT, STAGE_STEP, STEP_FAULT_RAW);
    }

    /// Sibling: a database that cannot be opened is UNREADABLE too, not the
    /// generic `Err` path.
    #[test]
    fn database_that_cannot_be_opened_is_unreadable_exit_2_9505() {
        for format in ["text", "json"] {
            let tmp = TempDir::new().unwrap();
            // A directory is not a database file.
            let run = run_case(tmp.path(), "root-9505", format, CID_SWEEP_SQL);
            let dir_text = tmp.path().display().to_string();
            assert_unreadable(&run, format, STAGE_OPEN, &[&dir_text]);
        }
    }

    /// Sibling: a `reflection_depth` that does not decode is an error, never
    /// depth 0 (which would report an over-cap chain as within its cap).
    #[test]
    fn reflection_depth_that_does_not_decode_is_an_error_9505() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let id = insert_mem(&conn, "ns-9505", 0);
        conn.execute(
            "UPDATE memories SET reflection_depth = 'not-a-depth' WHERE id = ?1",
            params![id],
        )
        .expect("corrupt depth");
        let err = fetch_memory_meta(&conn, &id).expect_err("must not read as depth 0");
        assert!(
            matches!(
                err.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::InvalidColumnType(..))
            ),
            "{err:#}"
        );
    }

    /// Sibling: a signed-events read that fails is an error, never an empty
    /// list presented as "no events".
    #[test]
    fn signed_events_read_failure_is_an_error_9505() {
        let tmp = TempDir::new().unwrap();
        let (conn, _) = open_test_db(&tmp);
        let id = insert_mem(&conn, "ns-9505", 0);
        conn.execute_batch("ALTER TABLE signed_events RENAME TO signed_events_gone_9505")
            .expect("hide signed_events");
        assert!(
            build_chain_report(&conn, &id, true).is_err(),
            "an unreadable signed_events table must not read as no events"
        );
        // Without the flag the table is never read.
        assert!(build_chain_report(&conn, &id, false).is_ok());
    }
}
