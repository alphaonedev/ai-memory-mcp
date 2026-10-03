// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4715 — the doctor's over-depth governance chain finding.
//!
//! #4477 refuses every governed operation under an explicit
//! `parent_namespace` chain past `GOVERNANCE_CHAIN_MAX_DEPTH`; #4492 stops a
//! NEW bind from creating one, but pre-#4477 data and imported rows can still
//! hold one. The doctor used to print only a depth histogram, so the chain
//! failed closed with no signal. This renders the census both backends read
//! through the one shared decision
//! (`governance::bind_chain_depth::over_depth_chains`): Critical, naming the
//! offending root namespaces and the shortening remedy. A census that could
//! not be read is Critical too, never "no over-depth chain" (ERRORS-19).

use anyhow::Result;

#[cfg(feature = "sal-postgres")]
use super::ReportSection;
use super::{Severity, append_note};
use crate::governance::bind_chain_depth::OverDepthChain;
use crate::governance::chain_depth::GOVERNANCE_CHAIN_MAX_DEPTH;

/// At most this many chains are named individually; the rest are counted.
const MAX_NAMED: usize = 20;

/// The postgres twin's section name (the sqlite finding lives in the
/// "Governance" section).
#[cfg(feature = "sal-postgres")]
pub(super) const SECTION_OVER_DEPTH_PG: &str = "Governance chain depth (#4715)";

/// Fold the census (or the fault that prevented it) into a section's
/// severity / facts / note.
pub(super) fn apply(
    census: Result<Vec<OverDepthChain>>,
    facts: &mut Vec<(String, String)>,
    severity: &mut Severity,
    note: &mut Option<String>,
) {
    let chains = match census {
        Ok(c) => c,
        Err(e) => {
            facts.push(("over_depth_chains".into(), "unreadable".into()));
            facts.push(("over_depth_chains_error".into(), format!("{e:#}")));
            *severity = Severity::Critical;
            append_note(
                note,
                "the over-depth governance chain census could not be read (#4715); chains past \
                 the maximum depth cannot be ruled out",
            );
            return;
        }
    };
    facts.push(("over_depth_chains".into(), chains.len().to_string()));
    if chains.is_empty() {
        return;
    }
    for c in chains.iter().take(MAX_NAMED) {
        facts.push((
            format!("over_depth::{}", c.root),
            format!("{} hops (maximum {GOVERNANCE_CHAIN_MAX_DEPTH})", c.hops),
        ));
    }
    let named: Vec<&str> = chains
        .iter()
        .take(MAX_NAMED)
        .map(|c| c.root.as_str())
        .collect();
    let more = chains.len().saturating_sub(MAX_NAMED);
    let tail = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    *severity = Severity::Critical;
    append_note(
        note,
        &format!(
            "{} explicit parent_namespace chain(s) exceed the maximum governance depth of \
             {GOVERNANCE_CHAIN_MAX_DEPTH}: [{}]{tail} — every governed operation under them is \
             refused (#4477). Shorten each chain to at most {GOVERNANCE_CHAIN_MAX_DEPTH} hops by \
             re-binding a namespace in it to a nearer parent (memory_namespace_set_standard \
             with `parent`) or clearing its parent.",
            chains.len(),
            named.join(", "),
        ),
    );
}

/// The postgres section. `None` on a SQLite deployment.
#[cfg(feature = "sal-postgres")]
pub(super) fn section_postgres() -> Option<ReportSection> {
    let url = match crate::store_url::resolve_store_url(None) {
        Ok(Some(url)) if crate::store_url::is_postgres_url(&url) => url,
        _ => return None,
    };
    // #4333 / #3705 — the same sslmode floor as the store funnel; a refusal
    // is the section's Critical fact and no socket opens.
    let options = match crate::store::postgres::dsn::floored_connect_options(&url) {
        Ok(o) => o,
        Err(refused) => {
            return Some(ReportSection {
                name: SECTION_OVER_DEPTH_PG.into(),
                severity: Severity::Critical,
                facts: vec![("error".into(), refused.to_string())],
                note: Some(
                    "the configured postgres store is below the transit-encryption floor \
                     (#3705): doctor REFUSED to connect — the daemon refuses the same DSN"
                        .into(),
                ),
            });
        }
    };
    let census: Result<Vec<OverDepthChain>> = super::run_pg_probe(move || async move {
        let probe = async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(super::PG_PROBE_TIMEOUT)
                .connect_with(options)
                .await?;
            let out = crate::store::postgres::list_over_depth_chains_pg(&pool).await;
            pool.close().await;
            out
        };
        tokio::time::timeout(super::PG_PROBE_TIMEOUT, probe)
            .await
            .map_err(|_elapsed| anyhow::anyhow!(super::MSG_PG_PROBE_TIMEOUT))?
            .map_err(anyhow::Error::from)
    })
    .and_then(|inner| inner);
    Some(section_from(census, "postgres"))
}

/// Render a census as its own section (the postgres path).
#[cfg(feature = "sal-postgres")]
pub(super) fn section_from(census: Result<Vec<OverDepthChain>>, backend: &str) -> ReportSection {
    let mut facts = vec![("backend".into(), backend.to_string())];
    let mut severity = Severity::Info;
    let mut note = None;
    apply(census, &mut facts, &mut severity, &mut note);
    ReportSection {
        name: SECTION_OVER_DEPTH_PG.into(),
        severity,
        facts,
        note,
    }
}
