// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3288 — postgres half of the bounded, keyset-paged admin export.
//!
//! See [`crate::export_paging`] for the contract. Hosted beside
//! `src/store/postgres.rs` (QUAL-10 ceiling) as free functions over a
//! `PgPool`; the adapter passes its own row projection in as a function
//! pointer, the [`crate::store::postgres_parity::export_memories_keyset`]
//! pattern.
//!
//! Walk order is `(created_at, id COLLATE "C")` — the #1724 lesson: a
//! non-"C" server collation would make the byte-order keyset predicate and
//! the `ORDER BY` disagree and drop rows. `created_at` is `timestamptz`; the
//! cursor carries it as RFC 3339 with microseconds, which is postgres's
//! resolution, so the cursor round-trips the stored instant exactly.
//!
//! Decrypt posture: the page read uses the scan mapper
//! (`DecryptFailurePolicy::SkipRow`, as the pre-#3288 pg export did), so an
//! unopenable row is skipped and COUNTED in the page's `undecryptable`
//! rather than denying the whole backup. `AI_MEMORY_STRICT_DECRYPT_READS=1`
//! makes the mapper fail closed instead.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::export_paging::{
    EdgePlan, EndpointPos, ExportCursor, ExportExcludedCounts, ExportKey, ExportLinksPage,
    ExportMemoriesPage, ExportPageRange, ExportPageScope, close_page, counterpart_survives,
    counterparts_to_recheck, finalize_edges, plan_edge,
};
use crate::models::{LifecycleState, Memory, MemoryLink, field_names};
use crate::store::postgres::{
    MEMORY_READ_COLUMNS, READ_ATTEST_LEVEL, READ_CREATED_AT, READ_OBSERVED_BY, READ_RELATION,
    READ_SOURCE_ID, READ_TARGET_ID, READ_VALID_FROM, READ_VALID_UNTIL, to_store_err,
};
use crate::store::{StoreError, StoreResult};

/// Row projection supplied by the adapter (`PostgresStore::row_to_memory_scan`).
pub(crate) type MapRow = fn(&sqlx::postgres::PgRow) -> StoreResult<Option<Memory>>;

/// Render a `timestamptz` as the cursor's `created_at` component.
fn key_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Parse a cursor/range `created_at` component back into a `timestamptz`.
fn parse_key_ts(raw: &str) -> StoreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| StoreError::InvalidInput {
            detail: "export cursor was not minted by this backend".to_string(),
        })
}

/// A range bound decoded for binding: `(created_at, id)`.
type Bound = Option<(DateTime<Utc>, String)>;

fn decode_bound(key: Option<&ExportKey>) -> StoreResult<Bound> {
    key.map(|k| Ok((parse_key_ts(&k.created_at)?, k.id.clone())))
        .transpose()
}

/// Read one page of the export walk. `limit` rows at most.
///
/// # Errors
///
/// [`StoreError::InvalidInput`] for a cursor this backend did not mint; the
/// page-query error; any error the projection returns.
pub(crate) async fn export_memories_page(
    pool: &PgPool,
    cursor: Option<&ExportCursor>,
    limit: usize,
    as_of: DateTime<Utc>,
    map_row: MapRow,
) -> StoreResult<ExportMemoriesPage> {
    let lower = decode_bound(cursor.map(|c| &c.after))?;
    let lim = i64::try_from(limit).map_err(|_| StoreError::InvalidInput {
        detail: "export page limit exceeds i64".to_string(),
    })?;
    let after = if lower.is_some() {
        "AND (created_at > $3 OR (created_at = $3 AND id COLLATE \"C\" > $4::text))"
    } else {
        ""
    };
    let sql = format!(
        "SELECT {cols} FROM memories \
         WHERE (expires_at IS NULL OR expires_at > $1) {lv} {after} \
         ORDER BY created_at ASC, id COLLATE \"C\" ASC \
         LIMIT $2",
        cols = MEMORY_READ_COLUMNS,
        lv = crate::models::lifecycle_visible_clause(""),
    );
    let mut q = sqlx::query(&sql).bind(as_of).bind(lim);
    if let Some((ts, id)) = &lower {
        q = q.bind(*ts).bind(id.as_str());
    }
    let rows = q
        .fetch_all(pool)
        .await
        .map_err(|e| to_store_err("export page", e))?;
    let mut page = ExportMemoriesPage::default();
    let mut last: Option<ExportKey> = None;
    for r in &rows {
        let created: DateTime<Utc> = r
            .try_get(field_names::CREATED_AT)
            .map_err(|e| to_store_err("export page created_at", e))?;
        let id: String = r
            .try_get("id")
            .map_err(|e| to_store_err("export page id", e))?;
        // Every returned row joins the page's raw id set and moves the
        // cursor, even when the projection skips it: a skipped row must still
        // advance the walk or the next page would re-read it forever.
        page.scope.raw_ids.push(id.clone());
        match map_row(r)? {
            Some(m) => page.memories.push(m),
            None => page.undecryptable += 1,
        }
        last = Some(ExportKey {
            created_at: key_ts(created),
            id,
        });
    }
    if page.undecryptable > 0 {
        tracing::warn!(
            undecryptable = page.undecryptable,
            "export page: undecryptable rows skipped; reported in the page's `undecryptable` count"
        );
    }
    let (range, next) = close_page(
        cursor.map(|c| c.after.clone()),
        last,
        rows.len(),
        limit,
        as_of,
    );
    page.excluded = excluded_in_range(pool, &range, as_of).await?;
    page.scope.range = range;
    page.scope.as_of = as_of;
    page.next_cursor = next;
    Ok(page)
}

async fn excluded_in_range(
    pool: &PgPool,
    range: &ExportPageRange,
    as_of: DateTime<Utc>,
) -> StoreResult<ExportExcludedCounts> {
    let lower = decode_bound(range.lower.as_ref())?;
    let upper = decode_bound(range.upper.as_ref())?;
    let row = sqlx::query(
        "SELECT \
            COUNT(*) FILTER (WHERE lifecycle_state = $2) AS quarantined, \
            COUNT(*) FILTER (WHERE lifecycle_state = $3) AS tombstoned, \
            COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at <= $1) AS expired \
         FROM memories \
         WHERE ($4::timestamptz IS NULL \
                OR created_at > $4 OR (created_at = $4 AND id COLLATE \"C\" > $5::text)) \
           AND ($6::timestamptz IS NULL \
                OR created_at < $6 OR (created_at = $6 AND id COLLATE \"C\" <= $7::text))",
    )
    .bind(as_of)
    .bind(LifecycleState::Quarantined.as_str())
    .bind(LifecycleState::Tombstoned.as_str())
    .bind(lower.as_ref().map(|(t, _)| *t))
    .bind(lower.as_ref().map(|(_, i)| i.as_str()))
    .bind(upper.as_ref().map(|(t, _)| *t))
    .bind(upper.as_ref().map(|(_, i)| i.as_str()))
    .fetch_one(pool)
    .await
    .map_err(|e| to_store_err("export page excluded counts", e))?;
    let get = |col: &str| -> StoreResult<usize> {
        let n: i64 = row
            .try_get(col)
            .map_err(|e| to_store_err("export page excluded count", e))?;
        Ok(usize::try_from(n).unwrap_or(0))
    };
    Ok(ExportExcludedCounts {
        quarantined: get(field_names::QUARANTINED)?,
        tombstoned: get(field_names::TOMBSTONED)?,
        expired: get("expired")?,
    })
}

/// SQL boolean: `alias` passes the export's SQL filters at `$2`.
fn exportable_expr(alias: &str) -> String {
    format!(
        "(({alias}.expires_at IS NULL OR {alias}.expires_at > $2) {lv})",
        lv = crate::models::lifecycle_visible_clause(alias),
    )
}

/// The edges a page owns. `survivors` is the set of page rows the export
/// confidentiality screen kept.
///
/// # Errors
///
/// [`StoreError::InvalidInput`] for a range this backend did not mint; the
/// query error; any error the projection returns.
pub(crate) async fn export_links_page(
    pool: &PgPool,
    scope: &ExportPageScope,
    survivors: &HashSet<String>,
    map_row: MapRow,
) -> StoreResult<ExportLinksPage> {
    if scope.raw_ids.is_empty() {
        return Ok(ExportLinksPage::default());
    }
    let lower = decode_bound(scope.range.lower.as_ref())?;
    let upper = decode_bound(scope.range.upper.as_ref())?;
    let before = |a: &str| {
        format!(
            "($3::timestamptz IS NOT NULL AND ({a}.created_at < $3 \
             OR ({a}.created_at = $3 AND {a}.id COLLATE \"C\" <= $4::text)))"
        )
    };
    let after = |a: &str| {
        format!(
            "($5::timestamptz IS NOT NULL AND ({a}.created_at > $5 \
             OR ({a}.created_at = $5 AND {a}.id COLLATE \"C\" > $6::text)))"
        )
    };
    let sql = format!(
        "SELECT ml.source_id, ml.target_id, ml.relation, ml.created_at, \
                ml.valid_from, ml.valid_until, ml.observed_by, ml.signature, \
                ml.attest_level, \
                {sb} AS s_before, {sa} AS s_after, {se} AS s_exportable, \
                {tb} AS t_before, {ta} AS t_after, {te} AS t_exportable \
         FROM memory_links ml \
         JOIN memories ms ON ms.id = ml.source_id \
         JOIN memories mt ON mt.id = ml.target_id \
         WHERE ml.source_id = ANY($1::text[]) OR ml.target_id = ANY($1::text[]) \
         ORDER BY ml.source_id, ml.target_id, ml.relation",
        sb = before("ms"),
        sa = after("ms"),
        se = exportable_expr("ms"),
        tb = before("mt"),
        ta = after("mt"),
        te = exportable_expr("mt"),
    );
    let rows = sqlx::query(&sql)
        .bind(&scope.raw_ids)
        .bind(scope.as_of)
        .bind(lower.as_ref().map(|(t, _)| *t))
        .bind(lower.as_ref().map(|(_, i)| i.as_str()))
        .bind(upper.as_ref().map(|(t, _)| *t))
        .bind(upper.as_ref().map(|(_, i)| i.as_str()))
        .fetch_all(pool)
        .await
        .map_err(|e| to_store_err("export page links", e))?;
    let in_page: HashSet<&str> = scope.raw_ids.iter().map(String::as_str).collect();
    let flag = |r: &sqlx::postgres::PgRow, col: &str| -> StoreResult<bool> {
        r.try_get::<bool, _>(col)
            .map_err(|e| to_store_err("export page link flag", e))
    };
    let mut planned: Vec<(MemoryLink, EdgePlan)> = Vec::with_capacity(rows.len());
    for r in &rows {
        let link = pg_export_link_from_row(r)?;
        let source = EndpointPos {
            in_page: in_page.contains(link.source_id.as_str()),
            before_page: flag(r, "s_before")?,
            after_page: flag(r, "s_after")?,
            exportable: flag(r, "s_exportable")?,
        };
        let target = EndpointPos {
            in_page: in_page.contains(link.target_id.as_str()),
            before_page: flag(r, "t_before")?,
            after_page: flag(r, "t_after")?,
            exportable: flag(r, "t_exportable")?,
        };
        let plan = plan_edge(&link, source, target);
        planned.push((link, plan));
    }
    let recheck = counterparts_to_recheck(&planned);
    let alive = surviving_counterparts(pool, &recheck, scope.as_of, map_row).await?;
    Ok(finalize_edges(planned, survivors, &alive))
}

async fn surviving_counterparts(
    pool: &PgPool,
    ids: &[String],
    as_of: DateTime<Utc>,
    map_row: MapRow,
) -> StoreResult<HashSet<String>> {
    let mut alive = HashSet::new();
    if ids.is_empty() {
        return Ok(alive);
    }
    let sql = format!(
        "SELECT {cols} FROM memories \
         WHERE id = ANY($1::text[]) AND (expires_at IS NULL OR expires_at > $2) {lv}",
        cols = MEMORY_READ_COLUMNS,
        lv = crate::models::lifecycle_visible_clause(""),
    );
    let rows = sqlx::query(&sql)
        .bind(ids)
        .bind(as_of)
        .fetch_all(pool)
        .await
        .map_err(|e| to_store_err("export page counterparts", e))?;
    for r in &rows {
        let mem = map_row(r)?;
        if counterpart_survives(mem.as_ref())
            && let Some(m) = mem
        {
            alive.insert(m.id);
        }
    }
    Ok(alive)
}

/// Map a `memory_links` row (`source_id, target_id, relation, created_at,
/// valid_from, valid_until, observed_by, signature, attest_level`) into a
/// [`MemoryLink`]. The SSOT for the postgres link projection: `list_links`
/// (which backs the full `export_links`) and the paged export both call it.
///
/// # Errors
///
/// The column-read error.
pub(crate) fn pg_export_link_from_row(r: &sqlx::postgres::PgRow) -> StoreResult<MemoryLink> {
    let created_at: DateTime<Utc> = r
        .try_get::<DateTime<Utc>, _>(field_names::CREATED_AT)
        .map_err(|e| to_store_err(READ_CREATED_AT, e))?;
    let valid_from: Option<DateTime<Utc>> = r
        .try_get::<Option<DateTime<Utc>>, _>(field_names::VALID_FROM)
        .map_err(|e| to_store_err(READ_VALID_FROM, e))?;
    let valid_until: Option<DateTime<Utc>> = r
        .try_get::<Option<DateTime<Utc>>, _>(field_names::VALID_UNTIL)
        .map_err(|e| to_store_err(READ_VALID_UNTIL, e))?;
    let observed_by: Option<String> = r
        .try_get::<Option<String>, _>(field_names::OBSERVED_BY)
        .map_err(|e| to_store_err(READ_OBSERVED_BY, e))?;
    let signature: Option<Vec<u8>> = r
        .try_get::<Option<Vec<u8>>, _>("signature")
        .map_err(|e| to_store_err("read signature", e))?;
    let relation_str: String = r
        .try_get::<String, _>("relation")
        .map_err(|e| to_store_err(READ_RELATION, e))?;
    let attest_level: Option<String> = r
        .try_get::<Option<String>, _>(field_names::ATTEST_LEVEL)
        .map_err(|e| to_store_err(READ_ATTEST_LEVEL, e))?;
    Ok(MemoryLink {
        source_id: r
            .try_get::<String, _>("source_id")
            .map_err(|e| to_store_err(READ_SOURCE_ID, e))?,
        target_id: r
            .try_get::<String, _>("target_id")
            .map_err(|e| to_store_err(READ_TARGET_ID, e))?,
        // v0.7.0 fix campaign R1-M4 — parse closed-set relation. Unknown
        // values fall back to default so the read path never errors; the SQL
        // CHECK on the write side keeps new rows in the closed set.
        relation: crate::models::MemoryLinkRelation::from_str(&relation_str).unwrap_or_default(),
        created_at: created_at.to_rfc3339(),
        signature,
        observed_by,
        valid_from: valid_from.map(|t| t.to_rfc3339()),
        valid_until: valid_until.map(|t| t.to_rfc3339()),
        // v0.7.0 issue #860 — surface attest_level on the postgres read path
        // so the adapter matches the `memory_get_links` MCP tool docstring.
        attest_level,
        source_cid: None,
        target_cid: None,
    })
}
