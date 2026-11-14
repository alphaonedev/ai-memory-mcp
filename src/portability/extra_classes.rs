// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8908 — the five record classes `export --full` did not carry:
//! `checkpoints`, `routines`, `routine_runs`, `entity_aliases` and
//! `offloaded_blobs`.
//!
//! 3-agent vote (71472661): each class rides the `"2"` envelope as an
//! ADDITIVE array (`skip_serializing_if = "Vec::is_empty"`), so an old-shape
//! bundle keeps importing and the envelope keeps `deny_unknown_fields`.
//!
//! Class invariant: every row of these tables either rides `--full` and
//! round-trips byte-exact (every column, `BLOB`s through the shared
//! [`HexBytes`] codec), or is withheld by the export screen and named
//! in-band in the [`ExportWithholdLedger`] (P-3). An import never replaces a
//! destination row: a same-key row is kept, and a divergent one is counted
//! and warned (P-7, the #3151 disposition).
//!
//! The screens run on a SCREENING VIEW of each row: JSON-valued `TEXT`
//! columns are parsed so a key marker nested inside them (`private_key`, …)
//! is seen, and an offloaded blob is screened on its decompressed,
//! integrity-verified text (the `content_zstd` frame itself is opaque).

use std::collections::{BTreeSet, HashSet};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::export_scope::ExportWithholdLedger;
use crate::identity::sentinels::DAEMON_PRINCIPAL;
use crate::portability::hex_bytes::HexBytes;
use crate::portability::import::{ImportOptions, ImportReport};

/// Withhold class for a row whose screening view carries credential
/// material the secret screen detects. The row is WITHHELD, never redacted:
/// a redacted row would no longer carry its signed bytes (L2).
pub const CLASS_CREDENTIAL_MATERIAL: &str = "credential_material";

/// Withhold class for an offloaded blob whose stored frame fails its own
/// integrity check at the SOURCE (it cannot be screened, so it never rides).
pub const CLASS_BLOB_INTEGRITY_FAILED: &str = "offloaded_blob_integrity_failed";

/// Withhold class for a routine run whose routine the screen withheld (the
/// run cannot land without it: `routine_runs.routine_id` is a foreign key).
pub const CLASS_RUN_OF_WITHHELD_ROUTINE: &str = "routine_run_of_withheld_routine";

/// The shared refusal prefix of the import gates.
const REJECTED: &str = "portability import REJECTED (fail-closed)";

/// The by-id suffix every class reader appends to its `SELECT`.
const WHERE_BY_ID: &str = " WHERE id = ?1";

/// `select` narrowed to one row by id.
fn by_id_sql(select: &str) -> String {
    format!("{select}{WHERE_BY_ID}")
}

/// One `checkpoints` row, every column (migration 0051).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointDto {
    pub id: String,
    pub namespace: String,
    pub title: String,
    pub condition_type: String,
    pub condition: String,
    pub state: String,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_pubkey: Option<HexBytes>,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<i64>,
    pub metadata: String,
}

/// One `routines` row, every column (migration 0052).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineDto {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub template: String,
    pub parameters: String,
    pub state: String,
    pub created_by: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<HexBytes>,
    pub metadata: String,
}

/// One `routine_runs` row, every column (migration 0052).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineRunDto {
    pub id: String,
    pub routine_id: String,
    pub namespace: String,
    pub arguments: String,
    pub state: String,
    pub created_action_ids: String,
    pub started_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub metadata: String,
}

/// One `entity_aliases` row, every column (migration 0010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityAliasDto {
    pub entity_id: String,
    pub alias: String,
    pub created_at: String,
}

/// One `offloaded_blobs` row, every column (migration 0029). New persisted
/// shape frozen at GA (P-8/P-13): the frame must decompress within
/// [`crate::offload::MAX_DECOMPRESSED_BYTES`] and is committed by
/// `content_sha256` (and `ref_id`, its content address), which the importer
/// re-verifies before any write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffloadedBlobDto {
    pub ref_id: String,
    pub namespace: String,
    pub content_zstd: HexBytes,
    pub content_sha256: String,
    pub stored_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
    pub agent_id: String,
    pub signature_b64: String,
}

/// The five classes as they leave the export screen.
#[derive(Debug, Default)]
pub struct ExtraClasses {
    pub checkpoints: Vec<CheckpointDto>,
    pub routines: Vec<RoutineDto>,
    pub routine_runs: Vec<RoutineRunDto>,
    pub entity_aliases: Vec<EntityAliasDto>,
    pub offloaded_blobs: Vec<OffloadedBlobDto>,
}

/// Per-class row access: the explicit column list, the deterministic order,
/// the single-row probe and the no-overwrite insert.
trait ExtraRow: Sized + PartialEq + Serialize {
    /// The envelope array (and table) name.
    const CLASS: &'static str;
    /// `SELECT <every column> FROM <table>`.
    const SELECT: &'static str;
    /// The primary-key order the export walks.
    const ORDER_BY: &'static str;
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self>;
    /// The row's primary key, rendered for paths and warnings.
    fn key(&self) -> String;
    /// The destination row holding this row's primary key, if any.
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>>;
    /// `INSERT OR IGNORE`; returns the rows written (0 = key already held).
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize>;
}

impl ExtraRow for CheckpointDto {
    const CLASS: &'static str = crate::portability::envelope_parse::CLASS_CHECKPOINTS;
    const SELECT: &'static str = "SELECT id, namespace, title, condition_type, condition, state, \
         created_by, resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
         created_at, deadline_at, resolved_at, metadata FROM checkpoints";
    const ORDER_BY: &'static str = "id";
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            namespace: r.get(1)?,
            title: r.get(2)?,
            condition_type: r.get(3)?,
            condition: r.get(4)?,
            state: r.get(5)?,
            created_by: r.get(6)?,
            resolved_by: r.get(7)?,
            resolution: r.get(8)?,
            resolution_note: r.get(9)?,
            signature: r.get::<_, Option<Vec<u8>>>(10)?.map(HexBytes),
            resolver_pubkey: r.get::<_, Option<Vec<u8>>>(11)?.map(HexBytes),
            created_at: r.get(12)?,
            deadline_at: r.get(13)?,
            resolved_at: r.get(14)?,
            metadata: r.get(15)?,
        })
    }
    fn key(&self) -> String {
        self.id.clone()
    }
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>> {
        let sql = by_id_sql(Self::SELECT);
        conn.query_row(&sql, params![self.id], Self::from_row)
            .optional()
    }
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT OR IGNORE INTO checkpoints (id, namespace, title, condition_type, condition, \
             state, created_by, resolved_by, resolution, resolution_note, signature, \
             resolver_pubkey, created_at, deadline_at, resolved_at, metadata) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                self.id,
                self.namespace,
                self.title,
                self.condition_type,
                self.condition,
                self.state,
                self.created_by,
                self.resolved_by,
                self.resolution,
                self.resolution_note,
                self.signature.as_ref().map(|b| b.0.as_slice()),
                self.resolver_pubkey.as_ref().map(|b| b.0.as_slice()),
                self.created_at,
                self.deadline_at,
                self.resolved_at,
                self.metadata,
            ],
        )
    }
}

impl ExtraRow for RoutineDto {
    const CLASS: &'static str = crate::portability::envelope_parse::CLASS_ROUTINES;
    const SELECT: &'static str = "SELECT id, namespace, name, template, parameters, state, \
         created_by, created_at, frozen_at, signature, signer_pubkey, metadata FROM routines";
    const ORDER_BY: &'static str = "id";
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            namespace: r.get(1)?,
            name: r.get(2)?,
            template: r.get(3)?,
            parameters: r.get(4)?,
            state: r.get(5)?,
            created_by: r.get(6)?,
            created_at: r.get(7)?,
            frozen_at: r.get(8)?,
            signature: r.get::<_, Option<Vec<u8>>>(9)?.map(HexBytes),
            signer_pubkey: r.get::<_, Option<Vec<u8>>>(10)?.map(HexBytes),
            metadata: r.get(11)?,
        })
    }
    fn key(&self) -> String {
        self.id.clone()
    }
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>> {
        let sql = by_id_sql(Self::SELECT);
        conn.query_row(&sql, params![self.id], Self::from_row)
            .optional()
    }
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT OR IGNORE INTO routines (id, namespace, name, template, parameters, state, \
             created_by, created_at, frozen_at, signature, signer_pubkey, metadata) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                self.id,
                self.namespace,
                self.name,
                self.template,
                self.parameters,
                self.state,
                self.created_by,
                self.created_at,
                self.frozen_at,
                self.signature.as_ref().map(|b| b.0.as_slice()),
                self.signer_pubkey.as_ref().map(|b| b.0.as_slice()),
                self.metadata,
            ],
        )
    }
}

impl ExtraRow for RoutineRunDto {
    const CLASS: &'static str = crate::portability::envelope_parse::CLASS_ROUTINE_RUNS;
    const SELECT: &'static str = "SELECT id, routine_id, namespace, arguments, state, \
         created_action_ids, started_at, finished_at, error, metadata FROM routine_runs";
    const ORDER_BY: &'static str = "id";
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            routine_id: r.get(1)?,
            namespace: r.get(2)?,
            arguments: r.get(3)?,
            state: r.get(4)?,
            created_action_ids: r.get(5)?,
            started_at: r.get(6)?,
            finished_at: r.get(7)?,
            error: r.get(8)?,
            metadata: r.get(9)?,
        })
    }
    fn key(&self) -> String {
        self.id.clone()
    }
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>> {
        let sql = by_id_sql(Self::SELECT);
        conn.query_row(&sql, params![self.id], Self::from_row)
            .optional()
    }
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT OR IGNORE INTO routine_runs (id, routine_id, namespace, arguments, state, \
             created_action_ids, started_at, finished_at, error, metadata) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                self.id,
                self.routine_id,
                self.namespace,
                self.arguments,
                self.state,
                self.created_action_ids,
                self.started_at,
                self.finished_at,
                self.error,
                self.metadata,
            ],
        )
    }
}

impl ExtraRow for EntityAliasDto {
    const CLASS: &'static str = crate::portability::envelope_parse::CLASS_ENTITY_ALIASES;
    const SELECT: &'static str = "SELECT entity_id, alias, created_at FROM entity_aliases";
    const ORDER_BY: &'static str = "entity_id, alias";
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            entity_id: r.get(0)?,
            alias: r.get(1)?,
            created_at: r.get(2)?,
        })
    }
    fn key(&self) -> String {
        format!("{}/{}", self.entity_id, self.alias)
    }
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>> {
        let sql = format!("{} WHERE entity_id = ?1 AND alias = ?2", Self::SELECT);
        conn.query_row(&sql, params![self.entity_id, self.alias], Self::from_row)
            .optional()
    }
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT OR IGNORE INTO entity_aliases (entity_id, alias, created_at) \
             VALUES (?1, ?2, ?3)",
            params![self.entity_id, self.alias, self.created_at],
        )
    }
}

impl ExtraRow for OffloadedBlobDto {
    const CLASS: &'static str = crate::portability::envelope_parse::CLASS_OFFLOADED_BLOBS;
    const SELECT: &'static str = "SELECT ref_id, namespace, content_zstd, content_sha256, \
         stored_at, ttl_seconds, agent_id, signature_b64 FROM offloaded_blobs";
    const ORDER_BY: &'static str = "ref_id";
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            ref_id: r.get(0)?,
            namespace: r.get(1)?,
            content_zstd: HexBytes(r.get(2)?),
            content_sha256: r.get(3)?,
            stored_at: r.get(4)?,
            ttl_seconds: r.get(5)?,
            agent_id: r.get(6)?,
            signature_b64: r.get(7)?,
        })
    }
    fn key(&self) -> String {
        self.ref_id.clone()
    }
    fn existing(&self, conn: &Connection) -> rusqlite::Result<Option<Self>> {
        let sql = format!("{} WHERE ref_id = ?1", Self::SELECT);
        conn.query_row(&sql, params![self.ref_id], Self::from_row)
            .optional()
    }
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT OR IGNORE INTO offloaded_blobs (ref_id, namespace, content_zstd, \
             content_sha256, stored_at, ttl_seconds, agent_id, signature_b64) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.ref_id,
                self.namespace,
                self.content_zstd.0,
                self.content_sha256,
                self.stored_at,
                self.ttl_seconds,
                self.agent_id,
                self.signature_b64,
            ],
        )
    }
}

/// Every row of one class, in primary-key order (linear: one statement).
fn read_all<T: ExtraRow>(conn: &Connection) -> Result<Vec<T>> {
    let sql = format!("{} ORDER BY {}", T::SELECT, T::ORDER_BY);
    let mut stmt = conn
        .prepare(&sql)
        .with_context(|| format!("export --full: could not read {}", T::CLASS))?;
    let rows = stmt
        .query_map([], T::from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .with_context(|| format!("export --full: could not decode a {} row", T::CLASS))?;
    Ok(rows)
}

/// The screening view of one row: its envelope JSON, with every string leaf
/// that is itself a JSON object or array replaced by the parsed value (so a
/// key marker inside a JSON `TEXT` column is visible to the class screen).
fn screening_view<T: Serialize>(row: &T) -> Value {
    let mut v = serde_json::to_value(row).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut v {
        for leaf in map.values_mut() {
            if let Value::String(s) = leaf {
                let trimmed = s.trim_start();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                        *leaf = parsed;
                    }
                }
            }
        }
    }
    v
}

/// `true` when any string leaf of `view` carries credential material the
/// secret screen detects. No-op (always `false`) when screening is `off`.
fn carries_secret(view: &Value) -> bool {
    use crate::secret_screen::{ScreenOutcome, SecretScreenMode, screen, screen_mode};
    fn walk(v: &Value) -> bool {
        match v {
            Value::String(s) => matches!(screen(s), ScreenOutcome::Hit { .. }),
            Value::Array(items) => items.iter().any(walk),
            Value::Object(map) => map.values().any(walk),
            _ => false,
        }
    }
    screen_mode() != SecretScreenMode::Off && walk(view)
}

/// Withhold `key` under `class`: the id goes to the operator channel, the
/// class count goes in-band.
fn withhold(ledger: &mut ExportWithholdLedger, class_name: &str, key: String, class: &str) {
    tracing::warn!(
        "export boundary withheld a {class} {class_name} row fail-closed — {class_name}/{key}"
    );
    ledger.withheld_ids.push(format!("{class_name}/{key}"));
    *ledger
        .withheld_by_class
        .entry(class.to_string())
        .or_default() += 1;
}

/// Screen one row's view: the #3150 forbidden-class screen (signed refusal
/// row on a hit), then the secret screen. `Some(class)` = withhold.
fn screen_view(conn: &Connection, class_name: &str, key: &str, view: &Value) -> Option<String> {
    let path = format!("{class_name}/{key}.json");
    if let Some(class) =
        crate::export_taxonomy::screen_export_value_audited(conn, &path, DAEMON_PRINCIPAL, view)
    {
        return Some(class.as_str().to_string());
    }
    carries_secret(view).then(|| CLASS_CREDENTIAL_MATERIAL.to_string())
}

/// Read and screen every row of one plain class.
fn screen_class<T: ExtraRow>(
    conn: &Connection,
    ledger: &mut ExportWithholdLedger,
) -> Result<Vec<T>> {
    let mut kept = Vec::new();
    for row in read_all::<T>(conn)? {
        let key = row.key();
        match screen_view(conn, T::CLASS, &key, &screening_view(&row)) {
            Some(class) => withhold(ledger, T::CLASS, key, &class),
            None => kept.push(row),
        }
    }
    Ok(kept)
}

/// Read and screen the five classes for `export --full` (P-3). Each class is
/// screened fail-closed; withheld rows fold into the returned ledger delta
/// (merged by the caller into the export's ledger).
///
/// # Errors
///
/// A database fault reading a class (the export fails; nothing is emitted).
pub fn screen_extra_classes(conn: &Connection) -> Result<(ExtraClasses, ExportWithholdLedger)> {
    let mut ledger = ExportWithholdLedger::default();
    let checkpoints = screen_class::<CheckpointDto>(conn, &mut ledger)?;
    let routines = screen_class::<RoutineDto>(conn, &mut ledger)?;
    let kept_routines: HashSet<&str> = routines.iter().map(|r| r.id.as_str()).collect();
    let mut routine_runs = Vec::new();
    for run in screen_class::<RoutineRunDto>(conn, &mut ledger)? {
        if kept_routines.contains(run.routine_id.as_str()) {
            routine_runs.push(run);
        } else {
            withhold(
                &mut ledger,
                RoutineRunDto::CLASS,
                run.key(),
                CLASS_RUN_OF_WITHHELD_ROUTINE,
            );
        }
    }
    let entity_aliases = screen_class::<EntityAliasDto>(conn, &mut ledger)?;
    let mut offloaded_blobs = Vec::new();
    for blob in read_all::<OffloadedBlobDto>(conn)? {
        let key = blob.key();
        let verified = crate::offload::verify_offloaded_blob(
            &blob.ref_id,
            &blob.content_zstd.0,
            &blob.content_sha256,
        );
        let Ok(text) = verified else {
            withhold(
                &mut ledger,
                OffloadedBlobDto::CLASS,
                key,
                CLASS_BLOB_INTEGRITY_FAILED,
            );
            continue;
        };
        let mut view = screening_view(&blob);
        if let Value::Object(map) = &mut view {
            map.insert("content_zstd".into(), Value::String(text));
        }
        match screen_view(conn, OffloadedBlobDto::CLASS, &key, &view) {
            Some(class) => withhold(&mut ledger, OffloadedBlobDto::CLASS, key, &class),
            None => offloaded_blobs.push(blob),
        }
    }
    Ok((
        ExtraClasses {
            checkpoints,
            routines,
            routine_runs,
            entity_aliases,
            offloaded_blobs,
        },
        ledger,
    ))
}

/// What one no-overwrite insert did.
enum Landed {
    /// The row was written.
    Written,
    /// A byte-identical row already holds the key (idempotent re-import).
    Identical,
    /// A DIFFERENT row holds the key; the destination row is kept.
    Divergent,
}

/// Insert one row without ever replacing the destination's (P-7).
fn land<T: ExtraRow>(conn: &Connection, row: &T, report: &mut ImportReport) -> Result<Landed> {
    let key = row.key();
    let n = row
        .insert(conn)
        .with_context(|| format!("portability import: {} {key} insert failed", T::CLASS))?;
    if n > 0 {
        return Ok(Landed::Written);
    }
    let held = row
        .existing(conn)
        .with_context(|| format!("portability import: {} {key} probe failed", T::CLASS))?;
    if held.as_ref() == Some(row) {
        report.idempotent_rows_already_present += 1;
        return Ok(Landed::Identical);
    }
    let msg = format!(
        "{} {key}: the destination holds a different row under this key; destination row kept",
        T::CLASS
    );
    tracing::warn!(target: crate::portability::import::IMPORT_TRACE_TARGET, "{msg}");
    report.extra_classes_skipped_divergent += 1;
    report.warnings.push(msg);
    Ok(Landed::Divergent)
}

/// Apply the five classes inside the caller's import transaction.
///
/// Without `--trust-source` the owner columns (`checkpoints.created_by`,
/// `routines.created_by`, `offloaded_blobs.agent_id`) are restamped with the
/// caller's id, exactly like `metadata.agent_id` on the memory lanes. The
/// attested columns (`resolved_by`, signatures, public keys) cross verbatim:
/// an importer never re-signs and never re-attributes an attestation.
///
/// # Errors
///
/// A database fault, or a routine run whose routine neither the bundle nor
/// the destination holds; the caller rolls the whole import back.
pub fn import_extra_classes(
    conn: &Connection,
    env: &crate::portability::emit::ExportEnvelope,
    opts: &ImportOptions,
    report: &mut ImportReport,
) -> Result<()> {
    let owner = |claimed: &str| {
        if opts.trust_source {
            claimed.to_string()
        } else {
            opts.caller_agent_id.clone()
        }
    };
    for row in &env.checkpoints {
        let row = CheckpointDto {
            created_by: owner(&row.created_by),
            ..row.clone()
        };
        if matches!(land(conn, &row, report)?, Landed::Written) {
            report.checkpoints += 1;
        }
    }
    let mut unusable_routines: BTreeSet<&str> = BTreeSet::new();
    for row in &env.routines {
        let restamped = RoutineDto {
            created_by: owner(&row.created_by),
            ..row.clone()
        };
        match land(conn, &restamped, report)? {
            Landed::Written => report.routines += 1,
            Landed::Identical => {}
            Landed::Divergent => {
                unusable_routines.insert(row.id.as_str());
            }
        }
    }
    for row in &env.routine_runs {
        if unusable_routines.contains(row.routine_id.as_str()) {
            let msg = format!(
                "routine_runs {}: its routine {} is held by a different destination row; run \
                 not applied",
                row.id, row.routine_id
            );
            tracing::warn!(target: crate::portability::import::IMPORT_TRACE_TARGET, "{msg}");
            report.extra_classes_skipped_divergent += 1;
            report.warnings.push(msg);
            continue;
        }
        let present: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM routines WHERE id = ?1)",
                params![row.routine_id],
                |r| r.get(0),
            )
            .context("portability import: routine probe failed")?;
        if !present {
            bail!(
                "{REJECTED}: routine_runs {} names routine {} that neither the bundle nor this \
                 destination holds; NO rows were applied",
                row.id,
                row.routine_id
            );
        }
        if matches!(land(conn, row, report)?, Landed::Written) {
            report.routine_runs += 1;
        }
    }
    for row in &env.entity_aliases {
        if matches!(land(conn, row, report)?, Landed::Written) {
            report.entity_aliases += 1;
        }
    }
    for row in &env.offloaded_blobs {
        if let Err(e) = crate::offload::verify_offloaded_blob(
            &row.ref_id,
            &row.content_zstd.0,
            &row.content_sha256,
        ) {
            let msg = e.to_string();
            tracing::warn!(target: crate::portability::import::IMPORT_TRACE_TARGET, "{msg}");
            report.offloaded_blobs_refused += 1;
            report.warnings.push(msg);
            continue;
        }
        let row = OffloadedBlobDto {
            agent_id: owner(&row.agent_id),
            ..row.clone()
        };
        if matches!(land(conn, &row, report)?, Landed::Written) {
            report.offloaded_blobs += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_8908_screening_view_parses_json_text_columns() {
        let row = EntityAliasDto {
            entity_id: "e".into(),
            alias: "{\"private_key\":\"x\"}".into(),
            created_at: "t".into(),
        };
        let view = screening_view(&row);
        assert_eq!(view["alias"]["private_key"], "x");
        assert_eq!(
            crate::export_taxonomy::classify_export_value(&view).map(|c| c.as_str()),
            Some("private_key_material")
        );
    }

    #[test]
    fn issue_8908_dto_refuses_unknown_field() {
        let err = serde_json::from_value::<EntityAliasDto>(serde_json::json!({
            "entity_id": "e", "alias": "a", "created_at": "t", "extra": 1
        }))
        .expect_err("deny_unknown_fields");
        assert!(err.to_string().contains("unknown field `extra`"), "{err}");
    }
}
