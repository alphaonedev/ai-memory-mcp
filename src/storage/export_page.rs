// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3288 — sqlite half of the bounded, keyset-paged admin export.
//!
//! See [`crate::export_paging`] for the contract. This module holds only the
//! sqlite SQL: the page read, the per-range excluded counts, and the page's
//! incident edges with the endpoint positions [`crate::export_paging::plan_edge`]
//! needs. The walk order is `(created_at, id)` with sqlite's default `BINARY`
//! collation, which is byte order and so agrees with the postgres twin's
//! `id COLLATE "C"`. The keyset predicate and the `ORDER BY` compare the same
//! stored TEXT, so every row is visited exactly once whatever rendering its
//! `created_at` carries.
//!
//! Decrypt posture: the page read keeps [`crate::storage::export_all`]'s
//! FAIL-CLOSED mapper (`DecryptFailurePolicy::FailClosed`, #2383), so on this
//! backend an unopenable row fails the export exactly as it did before #3288
//! and `undecryptable` is always 0. Earlier-page counterparts re-read for the
//! edge survival check use the scan mapper: a counterpart that cannot be read
//! is simply not carried, and its edge is withheld and counted.

use std::collections::HashSet;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, ToSql};

use crate::export_paging::{
    EdgePlan, EndpointPos, ExportCursor, ExportExcludedCounts, ExportKey, ExportLinksPage,
    ExportMemoriesPage, ExportPageScope, close_page, counterpart_survives, counterparts_to_recheck,
    finalize_edges, plan_edge,
};
use crate::models::{LifecycleState, MemoryLink};

/// Expiry cutoff rendered the way [`crate::storage::export_all`] renders
/// `now`, so the page read applies the identical TEXT comparison.
fn as_of_text(as_of: DateTime<Utc>) -> String {
    as_of.to_rfc3339()
}

/// `true` when the named alias's row passes the export's SQL filters.
fn exportable_expr(alias: &str) -> String {
    format!(
        "CASE WHEN ({alias}.expires_at IS NULL OR {alias}.expires_at > :as_of) {lv} \
         THEN 1 ELSE 0 END",
        lv = crate::models::lifecycle_visible_clause(alias),
    )
}

/// Keyset position of `alias` relative to the page's lower bound (`:lc`,
/// `:li`): at or before it. Only emitted when the page has a lower bound.
fn at_or_before_lower(alias: &str) -> String {
    format!("({alias}.created_at < :lc OR ({alias}.created_at = :lc AND {alias}.id <= :li))")
}

/// Keyset position of `alias` strictly after the page's upper bound (`:uc`,
/// `:ui`). Only emitted when the page has an upper bound.
fn after_upper(alias: &str) -> String {
    format!("({alias}.created_at > :uc OR ({alias}.created_at = :uc AND {alias}.id > :ui))")
}

/// Read one page of the export walk.
///
/// # Errors
///
/// Propagates the sqlite error, and an undecryptable row (fail-closed, see
/// the module docs).
pub fn memories_page(
    conn: &Connection,
    cursor: Option<&ExportCursor>,
    limit: usize,
    as_of: DateTime<Utc>,
    namespace: Option<&str>,
) -> Result<ExportMemoriesPage> {
    let lv = crate::models::lifecycle_visible_clause("");
    let after = if cursor.is_some() {
        "AND (created_at > :lc OR (created_at = :lc AND id > :li))"
    } else {
        ""
    };
    // #3427 — the namespace scope is a WHERE predicate on the same query the
    // walk orders by, never a post-filter: a scoped page is exactly the
    // scoped rows in key order, and the page ceiling counts scoped rows.
    let ns = if namespace.is_some() {
        "AND namespace = :ns"
    } else {
        ""
    };
    let sql = format!(
        "SELECT * FROM memories \
         WHERE (expires_at IS NULL OR expires_at > :as_of) {lv} {after} {ns} \
         ORDER BY created_at ASC, id ASC \
         LIMIT :lim"
    );
    let as_of_s = as_of_text(as_of);
    let lim = i64::try_from(limit).context("export page limit exceeds i64")?;
    let ns_s = namespace.map(str::to_owned);
    let mut binds: Vec<(&str, &dyn ToSql)> = vec![
        (":as_of", &as_of_s as &dyn ToSql),
        (":lim", &lim as &dyn ToSql),
    ];
    if let Some(c) = cursor {
        binds.push((":lc", &c.after.created_at));
        binds.push((":li", &c.after.id));
    }
    if let Some(n) = &ns_s {
        binds.push((":ns", n));
    }
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(binds.as_slice(), |row| {
        let created_at: String = row.get(crate::models::field_names::CREATED_AT)?;
        let id: String = row.get("id")?;
        let mem = super::row_to_memory(row)?;
        Ok((ExportKey { created_at, id }, mem))
    })?;
    let mut page = ExportMemoriesPage::default();
    let mut last: Option<ExportKey> = None;
    for row in rows {
        let (key, mem) = row?;
        page.scope.raw_ids.push(key.id.clone());
        page.memories.push(mem);
        last = Some(key);
    }
    let lower = cursor.map(|c| c.after.clone());
    let (range, next) = close_page(
        lower,
        last,
        page.scope.raw_ids.len(),
        limit,
        as_of,
        namespace,
    );
    page.excluded = excluded_in_range(conn, &range, as_of, namespace)?;
    page.scope.range = range;
    page.scope.as_of = as_of;
    page.scope.namespace = namespace.map(str::to_owned);
    page.next_cursor = next;
    Ok(page)
}

/// Rows inside `range` that the export's SQL filters exclude.
fn excluded_in_range(
    conn: &Connection,
    range: &crate::export_paging::ExportPageRange,
    as_of: DateTime<Utc>,
    namespace: Option<&str>,
) -> Result<ExportExcludedCounts> {
    let mut preds: Vec<String> = Vec::new();
    let as_of_s = as_of_text(as_of);
    let q = LifecycleState::Quarantined.as_str();
    let t = LifecycleState::Tombstoned.as_str();
    let ns_s = namespace.map(str::to_owned);
    let mut binds: Vec<(&str, &dyn ToSql)> = vec![
        (":as_of", &as_of_s as &dyn ToSql),
        (":q", &q as &dyn ToSql),
        (":t", &t as &dyn ToSql),
    ];
    // #3427 — the excluded counts are scoped exactly like the page.
    if let Some(n) = &ns_s {
        preds.push("namespace = :ns".to_string());
        binds.push((":ns", n));
    }
    if let Some(l) = &range.lower {
        preds.push("(created_at > :lc OR (created_at = :lc AND id > :li))".to_string());
        binds.push((":lc", &l.created_at));
        binds.push((":li", &l.id));
    }
    if let Some(u) = &range.upper {
        preds.push("(created_at < :uc OR (created_at = :uc AND id <= :ui))".to_string());
        binds.push((":uc", &u.created_at));
        binds.push((":ui", &u.id));
    }
    let where_clause = if preds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", preds.join(" AND "))
    };
    let sql = format!(
        "SELECT \
            SUM(CASE WHEN lifecycle_state = :q THEN 1 ELSE 0 END), \
            SUM(CASE WHEN lifecycle_state = :t THEN 1 ELSE 0 END), \
            SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= :as_of THEN 1 ELSE 0 END) \
         FROM memories {where_clause}"
    );
    let counts = conn.query_row(&sql, binds.as_slice(), |r| {
        Ok((
            r.get::<_, Option<i64>>(0)?.unwrap_or(0),
            r.get::<_, Option<i64>>(1)?.unwrap_or(0),
            r.get::<_, Option<i64>>(2)?.unwrap_or(0),
        ))
    })?;
    Ok(ExportExcludedCounts {
        quarantined: usize::try_from(counts.0).unwrap_or(0),
        tombstoned: usize::try_from(counts.1).unwrap_or(0),
        expired: usize::try_from(counts.2).unwrap_or(0),
    })
}

/// The edges a page owns (see [`crate::export_paging`]). `survivors` is the
/// set of page rows the export confidentiality screen kept.
///
/// # Errors
///
/// Propagates the sqlite error.
pub fn links_page(
    conn: &Connection,
    scope: &ExportPageScope,
    survivors: &HashSet<String>,
) -> Result<ExportLinksPage> {
    if scope.raw_ids.is_empty() {
        return Ok(ExportLinksPage::default());
    }
    let ids_json = serde_json::to_string(&scope.raw_ids)?;
    let as_of_s = as_of_text(scope.as_of);
    let mut binds: Vec<(&str, &dyn ToSql)> = vec![
        (":ids", &ids_json as &dyn ToSql),
        (":as_of", &as_of_s as &dyn ToSql),
    ];
    let (s_before, t_before) = match &scope.range.lower {
        Some(l) => {
            binds.push((":lc", &l.created_at));
            binds.push((":li", &l.id));
            (at_or_before_lower("ms"), at_or_before_lower("mt"))
        }
        None => ("0".to_string(), "0".to_string()),
    };
    let (s_after, t_after) = match &scope.range.upper {
        Some(u) => {
            binds.push((":uc", &u.created_at));
            binds.push((":ui", &u.id));
            (after_upper("ms"), after_upper("mt"))
        }
        None => ("0".to_string(), "0".to_string()),
    };
    let sql = format!(
        "SELECT ml.source_id, ml.target_id, ml.relation, ml.created_at, \
                ml.signature, ml.observed_by, ml.valid_from, ml.valid_until, \
                ml.source_cid, ml.target_cid, \
                {s_before}, {s_after}, {s_exp}, {t_before}, {t_after}, {t_exp} \
         FROM memory_links ml \
         JOIN memories ms ON ms.id = ml.source_id \
         JOIN memories mt ON mt.id = ml.target_id \
         WHERE ml.source_id IN (SELECT value FROM json_each(:ids)) \
            OR ml.target_id IN (SELECT value FROM json_each(:ids)) \
         ORDER BY ml.source_id, ml.target_id, ml.relation",
        s_exp = exportable_expr("ms"),
        t_exp = exportable_expr("mt"),
    );
    let in_page: HashSet<&str> = scope.raw_ids.iter().map(String::as_str).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(binds.as_slice(), |row| {
        let link = super::export_link_from_row(row)?;
        let flag = |i: usize| -> rusqlite::Result<bool> { Ok(row.get::<_, i64>(i)? != 0) };
        Ok((
            link,
            [flag(10)?, flag(11)?, flag(12)?],
            [flag(13)?, flag(14)?, flag(15)?],
        ))
    })?;
    let mut planned: Vec<(MemoryLink, EdgePlan)> = Vec::new();
    for row in rows {
        let (link, s, t) = row?;
        let source = EndpointPos {
            in_page: in_page.contains(link.source_id.as_str()),
            before_page: s[0],
            after_page: s[1],
            exportable: s[2],
        };
        let target = EndpointPos {
            in_page: in_page.contains(link.target_id.as_str()),
            before_page: t[0],
            after_page: t[1],
            exportable: t[2],
        };
        let plan = plan_edge(&link, source, target);
        planned.push((link, plan));
    }
    let recheck = counterparts_to_recheck(&planned);
    let alive = surviving_counterparts(conn, &recheck, scope.as_of, scope.namespace.as_deref())?;
    Ok(finalize_edges(planned, survivors, &alive))
}

/// Re-read earlier-page endpoints and keep those the export still carries.
fn surviving_counterparts(
    conn: &Connection,
    ids: &[String],
    as_of: DateTime<Utc>,
    namespace: Option<&str>,
) -> Result<HashSet<String>> {
    let mut alive = HashSet::new();
    if ids.is_empty() {
        return Ok(alive);
    }
    let ids_json = serde_json::to_string(ids)?;
    let as_of_s = as_of_text(as_of);
    // #3427 — a counterpart outside the namespace scope is not carried by
    // the export, so it does not survive: its edge is withheld.
    let ns = if namespace.is_some() {
        "AND namespace = :ns"
    } else {
        ""
    };
    let sql = format!(
        "SELECT * FROM memories \
         WHERE id IN (SELECT value FROM json_each(:ids)) \
           AND (expires_at IS NULL OR expires_at > :as_of) {lv} {ns}",
        lv = crate::models::lifecycle_visible_clause(""),
    );
    let ns_s = namespace.map(str::to_owned);
    let mut binds: Vec<(&str, &dyn ToSql)> = vec![
        (":ids", &ids_json as &dyn ToSql),
        (":as_of", &as_of_s as &dyn ToSql),
    ];
    if let Some(n) = &ns_s {
        binds.push((":ns", n));
    }
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(binds.as_slice(), super::row_to_memory_scan)?;
    for row in rows {
        if let Some(mem) = row?
            && counterpart_survives(Some(&mem))
        {
            alive.insert(mem.id);
        }
    }
    Ok(alive)
}
