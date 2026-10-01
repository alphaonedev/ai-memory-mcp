// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4285 (5-agent vote 4d3ea1c5, memory 1c3e2889; reverses #1384) — the
//! postgres half of "a corrupt `metadata.governance` is a SEVERED level".
//!
//! The two governance chain walks in `postgres.rs` delegate the corrupt arm
//! here (`src/store/postgres.rs` is at its QUAL-10 budget; submodule over a
//! ceiling bump): a WARN with the same target and text the sqlite read emits,
//! and the census the doctor Critical and the boot WARN read.

use super::{PostgresStore, StoreResult, to_store_err};
use crate::storage::{
    CorruptStandard, StandardMetadata, classify_standard_metadata, classify_standard_metadata_value,
};

/// Backend label carried on the WARN / doctor section.
pub(crate) const BACKEND: &str = "postgres";

/// #4285 — classify one chain level for the POLICY walk: `(Some(policy), false)`
/// intact, `(None, true)` corrupt (WARN, SEVERED: the caller floors and keeps
/// walking), `(None, false)` no governance here.
pub(super) fn parse_level(
    namespace: &str,
    standard_id: &str,
    metadata: &serde_json::Value,
) -> (Option<crate::models::GovernancePolicy>, bool) {
    match classify_standard_metadata_value(metadata) {
        StandardMetadata::Policy(p, _) => (Some(*p), false),
        StandardMetadata::NoGovernance => (None, false),
        StandardMetadata::Corrupt(reason) => {
            crate::storage::warn_corrupt_standard(BACKEND, namespace, standard_id, &reason);
            (None, true)
        }
    }
}

/// #4285 — classify one chain level for the approval-depth walk (shared
/// classifier; WARN on a corrupt level, parity with the sqlite walk).
pub(super) fn level_state(
    namespace: &str,
    standard_id: &str,
    metadata: &serde_json::Value,
) -> crate::storage::ApprovalDepthLevelState {
    let class = classify_standard_metadata_value(metadata);
    if let StandardMetadata::Corrupt(reason) = &class {
        crate::storage::warn_corrupt_standard(BACKEND, namespace, standard_id, reason);
    }
    crate::storage::approval_depth_level_state(&class)
}

/// The census SQL: every bound standard that carries a non-null
/// `metadata.governance` blob (the classifier decides which are corrupt).
const SQL_CORRUPT_CENSUS: &str = "SELECT nm.namespace, m.id, m.metadata \
     FROM namespace_meta nm INNER JOIN memories m ON m.id = nm.standard_id \
     WHERE m.metadata -> 'governance' IS NOT NULL \
       AND jsonb_typeof(m.metadata -> 'governance') <> 'null' \
     ORDER BY nm.namespace ASC";

/// #4285 — every namespace (sorted) whose bound standard is corrupt, read
/// from any pool (the doctor probe builds its own one-connection pool).
///
/// # Errors
///
/// The sqlx failure (never reported as "none corrupt").
pub async fn list_corrupt_governance_standards_pg(
    pool: &sqlx::PgPool,
) -> Result<Vec<CorruptStandard>, sqlx::Error> {
    let rows: Vec<(String, String, serde_json::Value)> =
        sqlx::query_as(SQL_CORRUPT_CENSUS).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(ns, id, meta)| classify_standard_metadata(&ns, &id, &meta))
        .collect())
}

impl PostgresStore {
    /// #4285 — the corrupt-standard census for the boot WARN.
    ///
    /// # Errors
    ///
    /// A read fault.
    pub async fn corrupt_governance_standards(&self) -> StoreResult<Vec<CorruptStandard>> {
        list_corrupt_governance_standards_pg(&self.pool)
            .await
            .map_err(|e| to_store_err("corrupt governance standard census", e))
    }
}

impl PostgresStore {
    /// #4285 — boot WARN listing every corrupt governance standard. Best-effort
    /// by contract: a census fault is a WARN, never a connect failure.
    pub(super) async fn warn_corrupt_governance_standards_at_boot(&self) {
        match self.corrupt_governance_standards().await {
            Ok(c) => crate::storage::warn_corrupt_governance_standards(BACKEND, &c),
            Err(e) => tracing::warn!(
                error = %e,
                "corrupt governance standard census could not be read at connect (#4285)"
            ),
        }
    }
}
