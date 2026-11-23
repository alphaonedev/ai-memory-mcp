// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10011 - the attested-update entry point: persist a freshly minted
//! `attest_level` + `write_signature` pair onto ONE stored row.
//!
//! `db::update` never mints an attestation (#3420): a content change strips
//! it. A merge that the stdio session signer re-seals therefore writes the
//! new pair through this helper, in the SAME write transaction as the
//! content update, so the row is never committed with merged content and
//! no seal. The only caller is
//! [`crate::identity::session_signer::reseal_row_sync`], which signs over
//! the stored row and verifies the signature against the bound key before
//! it calls here; this helper is not a minting path for anyone else. Own
//! child module so `src/storage/mod.rs` stays under its qual_10 ceiling.

use anyhow::{Result, bail};
use rusqlite::{Connection, params};

/// Overwrite both attestation keys of one row's metadata. `?1` is the row
/// id, `?2` the attest level, `?3` the base64 signature.
const SQL_SET_ROW_ATTESTATION: &str = "UPDATE memories SET metadata = json_set(metadata, '$.attest_level', ?2, '$.write_signature', ?3) WHERE id = ?1";

/// The one row the statement must touch.
const EXPECTED_ROWS: usize = 1;

/// Persist `attest_level` and `write_signature` on row `id`.
///
/// The caller must hold (or the call must be inside) the write transaction
/// that wrote the row content, so the content and its seal commit together.
///
/// # Errors
///
/// The SQL error, or a refusal when the statement did not touch exactly one
/// row (the row vanished between the update and the seal).
pub fn set_row_attestation(
    conn: &Connection,
    id: &str,
    attest_level: &str,
    write_signature_b64: &str,
) -> Result<()> {
    let changed = conn.execute(
        SQL_SET_ROW_ATTESTATION,
        params![id, attest_level, write_signature_b64],
    )?;
    if changed != EXPECTED_ROWS {
        bail!("#10011: attested update touched {changed} rows, expected {EXPECTED_ROWS}");
    }
    Ok(())
}
