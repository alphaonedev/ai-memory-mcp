// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4345 — the `ai-memory doctor` census of `approved` pending actions that
//! carry no EXECUTION MARKER.
//!
//! The federated approve-then-effect unit (#4025) stamps a durable marker once
//! an approved action's effect has landed. An `approved` row WITHOUT one is a
//! legacy gap: approved before the marker existed, or through a local surface
//! that still commits the approval before running the effect (#4172) and whose
//! execution then failed or was interrupted. Its effect cannot be proven
//! landed, so doctor counts it and WARNs on both backends: the SQLite count is
//! folded into the Governance section; PostgreSQL gets its own section (absent
//! on a SQLite deployment, so the section count there is unchanged).

use anyhow::Result;

use super::doctor::{ReportSection, Severity};

/// Report-section name.
pub const SECTION: &str = "Approved actions without execution marker (#4345)";

/// Operator-facing remedy appended to the WARN note.
const REMEDY: &str = "approved before the execution marker existed, or approved through a local \
     surface whose execution failed or was interrupted: inspect each row and re-run or \
     re-decide it; a federated redelivery of such a row is acknowledged but not verified";

/// The WARN note for `n` approved rows without a marker; `None` when `n == 0`.
#[must_use]
pub fn warning_note(n: u64) -> Option<String> {
    (n > 0).then(|| format!("{n} approved pending action(s) carry no execution marker: {REMEDY}"))
}

/// Build the (PostgreSQL) section from a census result for `backend`.
pub fn section(count: Result<u64>, backend: &str) -> ReportSection {
    let mut facts = vec![("backend".to_string(), backend.to_string())];
    match count {
        Err(e) => {
            facts.push(("error".into(), format!("{e:#}")));
            ReportSection {
                name: SECTION.into(),
                severity: Severity::Warning,
                facts,
                note: Some("the approved-without-marker census could not be read".into()),
            }
        }
        Ok(n) => {
            facts.push(("approved_without_marker".into(), n.to_string()));
            ReportSection {
                name: SECTION.into(),
                severity: if n == 0 {
                    Severity::Info
                } else {
                    Severity::Warning
                },
                facts,
                note: warning_note(n),
            }
        }
    }
}

/// The PostgreSQL census section; `None` on a SQLite deployment.
#[cfg(feature = "sal-postgres")]
pub(crate) fn postgres_section() -> Option<ReportSection> {
    let url = match crate::store_url::resolve_store_url(None) {
        Ok(Some(url)) if crate::store_url::is_postgres_url(&url) => url,
        _ => return None,
    };
    let census: Result<u64> = super::doctor::run_pg_probe(|| async move {
        let probe = async {
            let options = crate::store::postgres::dsn::connect_options(&url)?;
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(super::doctor::PG_PROBE_TIMEOUT)
                .connect_with(options)
                .await?;
            let n: i64 = sqlx::query_scalar(crate::storage::PG_COUNT_APPROVED_UNMARKED_SQL)
                .fetch_one(&pool)
                .await?;
            pool.close().await;
            Ok::<_, sqlx::Error>(u64::try_from(n).unwrap_or(0))
        };
        tokio::time::timeout(super::doctor::PG_PROBE_TIMEOUT, probe)
            .await
            .map_err(|_elapsed| anyhow::anyhow!(super::doctor::MSG_PG_PROBE_TIMEOUT))?
            .map_err(anyhow::Error::from)
    })
    .and_then(|inner| inner);
    Some(section(census, "postgres"))
}
