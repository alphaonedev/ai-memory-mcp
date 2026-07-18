// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2064 — glue between the erasure bundle store and the sqlite archive
//! (cold-tier) table.
//!
//! # Shape (MANAGEABLE-AT-SCALE)
//!
//! - **Write side = paced, idempotent, resumable SWEEP** (the embedding-
//!   backfill pattern), NOT a hook inside the archive transaction: the
//!   sweep only ever reads COMMITTED `archived_memories` rows, so a rolled-
//!   back archive can never leave a resurrectable phantom bundle, and a
//!   crash mid-sweep simply resumes on the next tick. At most
//!   [`SWEEP_LIMIT_PER_TICK`] rows are bundled per gc tick (oldest-first —
//!   a monotone frontier), so there is no thundering herd.
//! - **Read side = reconstruct-on-read**: when an operator restores an
//!   archived id whose DB row is GONE (partial DB loss), the bundle is
//!   verified/reconstructed and the archived row re-inserted inside the
//!   caller's transaction, after which the NORMAL restore path (governance
//!   hook, collision check, cid re-mint) runs unchanged.
//! - **Destruction intent flows through**: the purge funnels remove the
//!   bundles of the rows they delete, so purged (e.g. forgotten-then-
//!   purged) content cannot be resurrected from the redundancy layer. This
//!   cleanup keys on the store DIRECTORY being present, not the enable
//!   flag, so disabling the feature never silently strands purged content.
//!
//! The archived DB row remains the durable source of truth; bundles are
//! derived, regenerable redundancy (North-Star: derived artifacts are
//! disposable). Payloads are a self-describing JSON snapshot of the raw
//! `archived_memories` column values (BLOBs base64-wrapped), so restore
//! tolerates additive schema drift: known columns re-insert, unknown ones
//! are skipped with a WARN, and the bundle records the schema version it
//! was minted under.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rusqlite::Connection;
use rusqlite::types::{Value, ValueRef};

use super::store::{ERASURE_TRACE_TARGET, ErasureStore};
use super::{ENV_ERASURE_DIR, erasure_cold_tier_enabled, resolve_erasure_params};
use crate::models::field_names::ARCHIVED_AT;

/// Max archived rows bundled per gc tick — the pacing bound. Backlogs
/// drain monotonically (oldest-first) across ticks instead of in one blast.
pub const SWEEP_LIMIT_PER_TICK: usize = 256;

/// Payload JSON: top-level key naming the source table.
const PAYLOAD_KEY_TABLE: &str = "table";
/// Payload JSON: top-level key for the minting schema version.
const PAYLOAD_KEY_SCHEMA_VERSION: &str = "schema_version";
/// Payload JSON: top-level key holding the column-name → value map.
const PAYLOAD_KEY_COLUMNS: &str = "columns";
/// Payload JSON: blob wrapper key (`{"$b64": "..."}`).
const PAYLOAD_KEY_B64: &str = "$b64";
/// The protected table.
const ARCHIVED_TABLE: &str = "archived_memories";

/// Report from one sweep pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepReport {
    /// Rows newly bundled this pass.
    pub bundled: usize,
    /// Rows already holding a current bundle (skipped).
    pub already_current: usize,
    /// Rows whose bundling failed (WARN-logged; retried next pass).
    pub failed: usize,
}

/// Resolve the bundle directory for this connection: `AI_MEMORY_ERASURE_DIR`
/// wins; otherwise a `<db-path>.erasure` sibling of the sqlite file. `None`
/// when neither resolves (in-memory DB with no env override).
#[must_use]
pub fn resolve_dir_for_conn(conn: &Connection) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(ENV_ERASURE_DIR) {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    match conn.path() {
        Some(p) if !p.is_empty() => Some(PathBuf::from(format!("{p}.erasure"))),
        _ => None,
    }
}

/// Open the store for an ENABLED cold tier.
///
/// # Errors
/// Fails LOUD when the feature is enabled but no bundle directory resolves
/// (an enabled redundancy layer that silently does nothing would be a lie),
/// or when the store root cannot be created.
pub fn store_for_conn(conn: &Connection) -> Result<Option<ErasureStore>> {
    if !erasure_cold_tier_enabled() {
        return Ok(None);
    }
    let Some(dir) = resolve_dir_for_conn(conn) else {
        anyhow::bail!(
            "erasure cold tier is enabled but no bundle directory resolves: set \
             {ENV_ERASURE_DIR} (required for non-file-backed databases)"
        );
    };
    let store = ErasureStore::open(dir, resolve_erasure_params()?)
        .map_err(|e| anyhow::anyhow!("erasure store open failed: {e}"))?;
    Ok(Some(store))
}

/// Open the store for CLEANUP purposes whenever the bundle directory exists
/// on disk, regardless of the enable flag — so purge (destruction intent)
/// always reaches bundles minted while the feature was on.
#[must_use]
pub fn store_if_dir_present(conn: &Connection) -> Option<ErasureStore> {
    let dir = resolve_dir_for_conn(conn)?;
    if !dir.is_dir() {
        return None;
    }
    match resolve_erasure_params() {
        Ok(params) => ErasureStore::open(dir, params).ok(),
        Err(_) => None,
    }
}

/// One paced sweep pass: bundle up to `limit` committed archived rows that
/// lack a current bundle, oldest `archived_at` first (a monotone frontier —
/// resumable and starvation-free).
///
/// A row whose existing bundle records a DIFFERENT `archived_at` is
/// re-bundled (the row was re-archived since); identical stamps skip.
///
/// # Errors
/// Only on the id-scan query itself; per-row bundling failures are counted
/// + WARN-logged and retried on the next pass (paced degrade, never abort).
pub fn sweep_archive_bundles(
    conn: &Connection,
    store: &ErasureStore,
    limit: usize,
) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    let mut stmt = conn
        .prepare("SELECT id, archived_at FROM archived_memories ORDER BY archived_at ASC")
        .context("erasure sweep: archive scan prepare")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .context("erasure sweep: archive scan")?;
    for row in rows {
        if report.bundled >= limit {
            break;
        }
        let (id, archived_at) = row.context("erasure sweep: archive scan row")?;
        if bundle_is_current(store, &id, archived_at.as_deref()) {
            report.already_current += 1;
            continue;
        }
        match bundle_one_row(conn, store, &id) {
            Ok(()) => report.bundled += 1,
            Err(e) => {
                report.failed += 1;
                tracing::warn!(
                    target: ERASURE_TRACE_TARGET,
                    bundle_id = %id,
                    "erasure sweep: bundling archived row failed (will retry next pass): {e:#}"
                );
            }
        }
    }
    Ok(report)
}

/// Cheap currency check: manifest present AND its recorded `archived_at`
/// matches the row's. (Payload-level verification happens on read.)
fn bundle_is_current(store: &ErasureStore, id: &str, archived_at: Option<&str>) -> bool {
    if !store.contains(id) {
        return false;
    }
    // Read just the manifest via get()? That would verify shards too —
    // too costly per tick. Compare the manifest meta stamp instead.
    match store.get_manifest_meta(id) {
        Some(meta) => meta.get(ARCHIVED_AT).and_then(|v| v.as_str()) == archived_at,
        None => false,
    }
}

/// Serialize one committed archived row into the self-describing payload.
fn archived_row_payload(conn: &Connection, id: &str) -> Result<(Vec<u8>, serde_json::Value)> {
    let mut stmt = conn
        .prepare("SELECT * FROM archived_memories WHERE id = ?1")
        .context("erasure payload: prepare")?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = stmt.query([id]).context("erasure payload: query")?;
    let row = rows
        .next()
        .context("erasure payload: row read")?
        .ok_or_else(|| anyhow::anyhow!("archived row {id} vanished during bundling"))?;
    let mut columns = serde_json::Map::new();
    let mut archived_at_meta = serde_json::Value::Null;
    for (i, name) in column_names.iter().enumerate() {
        let v = match row.get_ref(i).context("erasure payload: column read")? {
            ValueRef::Null => serde_json::Value::Null,
            ValueRef::Integer(n) => serde_json::Value::from(n),
            ValueRef::Real(x) => serde_json::Value::from(x),
            ValueRef::Text(t) => serde_json::Value::from(
                std::str::from_utf8(t).context("erasure payload: non-UTF-8 TEXT column")?,
            ),
            ValueRef::Blob(b) => serde_json::json!({
                PAYLOAD_KEY_B64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)
            }),
        };
        if name == ARCHIVED_AT {
            archived_at_meta = v.clone();
        }
        columns.insert(name.clone(), v);
    }
    let payload = serde_json::json!({
        PAYLOAD_KEY_TABLE: ARCHIVED_TABLE,
        PAYLOAD_KEY_SCHEMA_VERSION: crate::storage::current_schema_version_for_tests(),
        PAYLOAD_KEY_COLUMNS: columns,
    });
    let meta = serde_json::json!({
        ARCHIVED_AT: archived_at_meta,
        PAYLOAD_KEY_SCHEMA_VERSION: crate::storage::current_schema_version_for_tests(),
    });
    Ok((serde_json::to_vec(&payload)?, meta))
}

/// Bundle one committed archived row into the store.
fn bundle_one_row(conn: &Connection, store: &ErasureStore, id: &str) -> Result<()> {
    let (payload, meta) = archived_row_payload(conn, id)?;
    store
        .put(id, &payload, meta)
        .map_err(|e| anyhow::anyhow!("bundle write failed: {e}"))
}

/// Convert one payload JSON value back to a rusqlite [`Value`]. Refuses
/// (loud) anything outside the closed encoding produced by
/// [`archived_row_payload`] — never guesses at ambiguous data.
fn json_to_sql_value(name: &str, v: &serde_json::Value) -> Result<Value> {
    match v {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Real(f))
            } else {
                anyhow::bail!("column {name}: unrepresentable number {n}")
            }
        }
        serde_json::Value::String(s) => Ok(Value::Text(s.clone())),
        serde_json::Value::Object(map) => {
            let b64 = map
                .get(PAYLOAD_KEY_B64)
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow::anyhow!("column {name}: unrecognized object encoding"))?;
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .with_context(|| format!("column {name}: bad base64 blob"))?;
            Ok(Value::Blob(bytes))
        }
        other => anyhow::bail!("column {name}: unsupported payload value {other}"),
    }
}

/// Parse + sanity-check a bundle payload, returning the column map.
fn parse_payload(id: &str, payload: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>> {
    let v: serde_json::Value =
        serde_json::from_slice(payload).context("erasure restore: payload parse")?;
    if v.get(PAYLOAD_KEY_TABLE).and_then(|t| t.as_str()) != Some(ARCHIVED_TABLE) {
        anyhow::bail!("erasure restore: bundle {id} does not carry an {ARCHIVED_TABLE} row");
    }
    let columns = v
        .get(PAYLOAD_KEY_COLUMNS)
        .and_then(|c| c.as_object())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("erasure restore: bundle {id} lacks a columns map"))?;
    // Identity binding: the row's own id must match the bundle id (defense
    // against a renamed/moved bundle directory masquerading as another row).
    match columns.get("id").and_then(|x| x.as_str()) {
        Some(row_id) if row_id == id => Ok(columns),
        other => anyhow::bail!(
            "erasure restore: bundle {id} carries row id {other:?} — refusing mismatched identity"
        ),
    }
}

/// Re-insert an archived row from its verified bundle payload. Runs inside
/// the CALLER's transaction. Unknown (dropped) columns are skipped with a
/// WARN; known columns re-insert verbatim.
fn insert_archived_row_from_payload(conn: &Connection, id: &str, payload: &[u8]) -> Result<()> {
    let columns = parse_payload(id, payload)?;
    // Current live column set for additive-schema-drift tolerance.
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .context("erasure restore: table_info prepare")?;
    let live: std::collections::HashSet<String> = stmt
        .query_map([ARCHIVED_TABLE], |r| r.get::<_, String>(0))
        .context("erasure restore: table_info")?
        .collect::<std::result::Result<_, _>>()
        .context("erasure restore: table_info rows")?;
    let mut names: Vec<&str> = Vec::with_capacity(columns.len());
    let mut values: Vec<Value> = Vec::with_capacity(columns.len());
    for (name, v) in &columns {
        if !live.contains(name) {
            tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                column = %name,
                "erasure restore: bundle column absent from current schema — skipping"
            );
            continue;
        }
        names.push(name.as_str());
        values.push(json_to_sql_value(name, v)?);
    }
    if names.is_empty() {
        anyhow::bail!("erasure restore: bundle {id} has no columns matching the current schema");
    }
    let placeholders: Vec<String> = (1..=names.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "INSERT INTO {ARCHIVED_TABLE} ({}) VALUES ({})",
        names.join(", "),
        placeholders.join(", ")
    );
    conn.execute(&sql, rusqlite::params_from_iter(values))
        .context("erasure restore: archived row re-insert")?;
    Ok(())
}

/// Ownership predicate mirrored from the caller-scoped archive SQL (see
/// `storage::restore_archived_for_caller`): the caller owns the row, is its
/// inbox target, or the row is legacy-unowned.
fn payload_owned_by(columns: &serde_json::Map<String, serde_json::Value>, caller: &str) -> bool {
    let meta: serde_json::Value = columns
        .get("metadata")
        .and_then(|m| m.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let field = |key: &str| meta.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let agent = field("agent_id");
    agent == caller || field("target_agent_id") == caller || agent.is_empty()
}

/// Reconstruct-on-read: when the archived row for `id` is MISSING from the
/// DB but the (enabled) cold tier holds a verified bundle, re-insert the
/// row inside the caller's open transaction. Returns whether a row was
/// re-inserted. `caller`-scoped variants pass `Some(caller)` so a bundle
/// the caller does not own is NEVER materialized on their behalf.
///
/// # Errors
/// Propagates loud bundle verification failures (beyond-budget loss,
/// tamper, foreign codec) and insert failures — the caller's transaction
/// rolls back, leaving no partial state.
pub fn try_restore_archived_row_from_bundle(
    conn: &Connection,
    id: &str,
    caller: Option<&str>,
) -> Result<bool> {
    let Some(store) = store_for_conn(conn)? else {
        return Ok(false);
    };
    let Some(bundle) = store
        .get(id)
        .map_err(|e| anyhow::anyhow!("erasure reconstruct-on-read for {id} failed: {e}"))?
    else {
        return Ok(false);
    };
    let columns = parse_payload(id, &bundle.payload)?;
    if let Some(caller) = caller
        && !payload_owned_by(&columns, caller)
    {
        // Owner-scoped surface: an un-owned bundle is invisible, exactly
        // like an un-owned row (no existence oracle, no side effects).
        return Ok(false);
    }
    insert_archived_row_from_payload(conn, id, &bundle.payload)?;
    tracing::info!(
        target: ERASURE_TRACE_TARGET,
        bundle_id = %id,
        was_degraded = bundle.was_degraded,
        "erasure cold tier: archived row re-materialized from shards (reconstruct-on-read)"
    );
    Ok(true)
}

/// Best-effort bundle removal for purged archived rows (destruction
/// intent). Failures WARN — the DB purge already committed and a leftover
/// bundle is caught by the next purge — but are never silent.
pub fn remove_bundles_best_effort(conn: &Connection, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let Some(store) = store_if_dir_present(conn) else {
        return;
    };
    for id in ids {
        if let Err(e) = store.remove(id) {
            tracing::warn!(
                target: ERASURE_TRACE_TARGET,
                bundle_id = %id,
                "erasure cold tier: purged row's bundle removal failed: {e}"
            );
        }
    }
}

/// The gc-tick entry point: no-op when the cold tier is disabled; otherwise
/// one paced sweep pass.
///
/// # Errors
/// Propagates store-resolution and scan-level failures (per-row failures
/// are absorbed into the report).
pub fn gc_tick(conn: &Connection) -> Result<SweepReport> {
    let Some(store) = store_for_conn(conn)? else {
        return Ok(SweepReport::default());
    };
    sweep_archive_bundles(conn, &store, SWEEP_LIMIT_PER_TICK)
}
