// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 §25.3 S1 (D3-012, #1870) — sqlite-direct store helpers for the
//! `model_attestations` substrate + the attested-read predicate S2
//! consumes.
//!
//! Two write paths land rows:
//!
//! - [`record_loader_observed`] — TOFU, write-once (`INSERT … ON
//!   CONFLICT DO NOTHING`) at the substrate LLM boundary. `agent_id` is
//!   the empty string (no operator binding); this is a
//!   PROCESS-LIFETIME trusted-substrate self-report — the daemon
//!   observed which model IT was configured to call — NOT per-write
//!   cryptographic provenance. Coverage hard-caps ~40% (ROADMAP.md:1229):
//!   only substrate-invoked generation is attestable.
//! - [`enroll_operator_signed`] — an operator enrolls a family under an
//!   `agent_id`, Ed25519-signed, via `ai-memory model-attest enroll
//!   --sign`.
//!
//! The read predicate [`family_is_attested`] is the forgery-resistant
//! gate S2 uses: a reflection's family is ATTESTED only when its
//! metadata stamp says `loader_observed` AND a matching
//! `model_attestations` row actually exists. A caller who forges
//! `metadata.model_family_attest = "loader_observed"` via MCP with no
//! backing row reads as CLAIMED.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

/// Attestation level for a substrate-observed model family.
pub const ATTEST_LEVEL_LOADER_OBSERVED: &str = "loader_observed";
/// Attestation level for an operator-enrolled model family.
pub const ATTEST_LEVEL_OPERATOR_SIGNED: &str = "operator_signed";

/// One `model_attestations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelAttestation {
    /// UUID primary key.
    pub id: String,
    /// Resolved backend selector.
    pub provider: String,
    /// Verbatim resolved model string.
    pub model_ref: String,
    /// Provider digest when retrievable (TOFU); `None` otherwise.
    pub model_digest: Option<String>,
    /// Normalized family token.
    pub model_family: String,
    /// `loader_observed` | `operator_signed`.
    pub attest_level: String,
    /// Operator binding (`""` = none).
    pub agent_id: String,
    /// Operator Ed25519 signature (operator_signed rows only).
    pub signature: Option<Vec<u8>>,
    /// RFC3339 creation instant.
    pub created_at: String,
}

fn row_to_attestation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ModelAttestation> {
    Ok(ModelAttestation {
        id: row.get(0)?,
        provider: row.get(1)?,
        model_ref: row.get(2)?,
        model_digest: row.get(3)?,
        model_family: row.get(4)?,
        attest_level: row.get(5)?,
        agent_id: row.get(6)?,
        signature: row.get(7)?,
        created_at: row.get(8)?,
    })
}

/// TOFU write-once record of a substrate-observed model family. Idempotent
/// via `INSERT … ON CONFLICT DO NOTHING` against the
/// `(provider, model_ref, model_family, agent_id)` UNIQUE constraint —
/// a second construction of the same model is a no-op. `agent_id` is the
/// empty string (loader rows carry no operator binding).
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn record_loader_observed(
    conn: &Connection,
    provider: &str,
    model_ref: &str,
    model_family: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO model_attestations
             (id, provider, model_ref, model_digest, model_family,
              attest_level, agent_id, signature, created_at)
         VALUES (?1, ?2, ?3, NULL, ?4, ?5, '', NULL, ?6)
         ON CONFLICT DO NOTHING",
        params![
            uuid::Uuid::new_v4().to_string(),
            provider,
            model_ref,
            model_family,
            ATTEST_LEVEL_LOADER_OBSERVED,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .context("model_attest::record_loader_observed")?;
    Ok(())
}

/// Enroll an operator-signed model-family attestation under `agent_id`.
/// Write-once via the same UNIQUE constraint. Returns `true` when a row
/// was inserted, `false` when an identical enrollment already existed.
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn enroll_operator_signed(
    conn: &Connection,
    provider: &str,
    model_ref: &str,
    model_family: &str,
    agent_id: &str,
    signature: &[u8],
) -> Result<bool> {
    let affected = conn
        .execute(
            "INSERT INTO model_attestations
                 (id, provider, model_ref, model_digest, model_family,
                  attest_level, agent_id, signature, created_at)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT DO NOTHING",
            params![
                uuid::Uuid::new_v4().to_string(),
                provider,
                model_ref,
                model_family,
                ATTEST_LEVEL_OPERATOR_SIGNED,
                agent_id,
                signature,
                chrono::Utc::now().to_rfc3339(),
            ],
        )
        .context("model_attest::enroll_operator_signed")?;
    Ok(affected > 0)
}

/// List every attestation row, ordered by `(model_family, created_at)`
/// for deterministic CLI output.
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn list(conn: &Connection) -> Result<Vec<ModelAttestation>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, provider, model_ref, model_digest, model_family,
                    attest_level, agent_id, signature, created_at
             FROM model_attestations
             ORDER BY model_family ASC, created_at ASC, id ASC",
        )
        .context("model_attest::list: prepare")?;
    let rows = stmt
        .query_map([], row_to_attestation)
        .context("model_attest::list: query_map")?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("model_attest::list: row")?);
    }
    Ok(out)
}

/// `true` when at least one attestation row exists for `model_family`
/// (either loader-observed or operator-signed). The table existence is
/// probed first so a governance-less / pre-v78 connection returns
/// `false` rather than surfacing a "no such table" error.
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn family_row_exists(conn: &Connection, model_family: &str) -> Result<bool> {
    let table_present: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='model_attestations'",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("model_attest::family_row_exists: probe table")?;
    if table_present.is_none() {
        return Ok(false);
    }
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM model_attestations WHERE model_family = ?1 LIMIT 1",
            [model_family],
            |row| row.get(0),
        )
        .optional()
        .context("model_attest::family_row_exists")?;
    Ok(found.is_some())
}

/// v0.9.0 §25.3 S1 — the attested-read predicate. A memory's model
/// family is ATTESTED iff:
///
/// - (a) its metadata carries `model_family_attest = "loader_observed"`,
/// - (c) a matching `model_attestations` row exists for the stamped
///   `model_family`.
///
/// Condition (b) — that the writer identity is the curator's self-signed
/// keypair — is enforced upstream by the reflect path
/// (`attest_level='self_signed'` on the `reflects_on` edges) and is not
/// re-derivable from the metadata blob alone; this predicate pins (a)+(c),
/// which is the forgery gate: a caller who sets
/// `model_family_attest="loader_observed"` via MCP with NO backing
/// attestation row (or no family stamp) reads as CLAIMED.
///
/// Returns the attested family token when attested, `None` (CLAIMED)
/// otherwise.
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn attested_family_of(
    conn: &Connection,
    metadata: &serde_json::Value,
) -> Result<Option<String>> {
    let attest = metadata
        .get(crate::identity::META_KEY_MODEL_FAMILY_ATTEST)
        .and_then(serde_json::Value::as_str);
    let family = metadata
        .get(crate::identity::META_KEY_MODEL_FAMILY)
        .and_then(serde_json::Value::as_str);
    let (Some(attest), Some(family)) = (attest, family) else {
        return Ok(None);
    };
    if attest != crate::identity::ATTEST_MODEL_LOADER_OBSERVED {
        return Ok(None);
    }
    if family.is_empty() {
        return Ok(None);
    }
    if family_row_exists(conn, family)? {
        Ok(Some(family.to_string()))
    } else {
        // Forged / unbacked stamp → CLAIMED.
        Ok(None)
    }
}

/// `true` when `metadata` reads as ATTESTED per [`attested_family_of`].
///
/// # Errors
///
/// Propagates SQLite errors.
pub fn family_is_attested(conn: &Connection, metadata: &serde_json::Value) -> Result<bool> {
    Ok(attested_family_of(conn, metadata)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE model_attestations (
                 id TEXT NOT NULL PRIMARY KEY,
                 provider TEXT NOT NULL,
                 model_ref TEXT NOT NULL,
                 model_digest TEXT,
                 model_family TEXT NOT NULL,
                 attest_level TEXT NOT NULL
                     CHECK (attest_level IN ('loader_observed','operator_signed')),
                 agent_id TEXT NOT NULL DEFAULT '',
                 signature BLOB,
                 created_at TEXT NOT NULL,
                 UNIQUE (provider, model_ref, model_family, agent_id)
             );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn loader_observed_is_write_once_tofu() {
        let conn = fresh_conn();
        record_loader_observed(&conn, "ollama", "llama3.1:8b", "llama").unwrap();
        record_loader_observed(&conn, "ollama", "llama3.1:8b", "llama").unwrap();
        let rows = list(&conn).unwrap();
        assert_eq!(rows.len(), 1, "second construction is a no-op (TOFU)");
        assert_eq!(rows[0].attest_level, ATTEST_LEVEL_LOADER_OBSERVED);
        assert_eq!(
            rows[0].agent_id, "",
            "loader rows carry no operator binding"
        );
    }

    #[test]
    fn operator_enrollment_is_write_once() {
        let conn = fresh_conn();
        let sig = vec![9u8; 64];
        assert!(enroll_operator_signed(&conn, "xai", "grok-4", "grok", "ai:op", &sig).unwrap());
        assert!(
            !enroll_operator_signed(&conn, "xai", "grok-4", "grok", "ai:op", &sig).unwrap(),
            "identical enrollment is a no-op"
        );
        assert!(family_row_exists(&conn, "grok").unwrap());
    }

    #[test]
    fn attested_read_requires_both_stamp_and_row() {
        let conn = fresh_conn();
        // Stamp present but NO backing row → CLAIMED (the forgery pin).
        let forged = serde_json::json!({
            "model_family": "llama",
            "model_family_attest": "loader_observed"
        });
        assert!(
            !family_is_attested(&conn, &forged).unwrap(),
            "a loader_observed stamp with no backing row must read CLAIMED"
        );

        // Now land the backing row → ATTESTED.
        record_loader_observed(&conn, "ollama", "llama3.1:8b", "llama").unwrap();
        assert_eq!(
            attested_family_of(&conn, &forged).unwrap().as_deref(),
            Some("llama")
        );
    }

    #[test]
    fn claimed_stamp_never_attested() {
        let conn = fresh_conn();
        record_loader_observed(&conn, "ollama", "llama3.1:8b", "llama").unwrap();
        // attest level is "claimed" — even with a backing row, not attested.
        let claimed = serde_json::json!({
            "model_family": "llama",
            "model_family_attest": "claimed"
        });
        assert!(!family_is_attested(&conn, &claimed).unwrap());
        // missing stamp entirely
        let bare = serde_json::json!({ "model_family": "llama" });
        assert!(!family_is_attested(&conn, &bare).unwrap());
    }

    #[test]
    fn family_row_exists_false_without_table() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(!family_row_exists(&conn, "llama").unwrap());
    }
}
