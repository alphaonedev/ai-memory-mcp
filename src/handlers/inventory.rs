// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3343 — bounded inventory projections for admin stats/namespaces HTTP.
//!
//! `GET /api/v1/namespaces` and `GET /api/v1/stats` used to emit the full
//! namespace inventory (hundreds of entries after swarm runs). The payload
//! size, not the SQL scan, is what blew NHI context windows. These helpers
//! page/cap **after** the existing aggregate queries so curator/SAL
//! `list_namespaces()` stays complete, while the HTTP wire is bounded.

use crate::models::NamespaceCount;
use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default page size for `GET /api/v1/namespaces` when `limit` is omitted.
/// Unbounded was the #3343 bug; 50 keeps dashboards useful without dumping
/// the whole swarm inventory into an agent context.
pub(crate) const NAMESPACES_DEFAULT_LIMIT: usize = 50;

/// Default top-N for `stats.by_namespace` when `by_namespace_limit` is omitted.
pub(crate) const STATS_BY_NAMESPACE_DEFAULT_LIMIT: usize = 20;

/// Hard ceiling for `stats.by_namespace` (tiers stay uncapped — there are 3).
pub(crate) const STATS_BY_NAMESPACE_MAX_LIMIT: usize = 100;

/// Query string for `GET /api/v1/namespaces` (also forwarded from the
/// `?namespace=` dispatcher when that field is absent).
#[derive(Debug, Default, Deserialize)]
pub struct ListNamespacesQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Query string for `GET /api/v1/stats`.
#[derive(Debug, Default, Deserialize)]
pub struct StatsQuery {
    /// `1` / `true` / `yes` → totals (+ `by_tier`) only; omit `by_namespace`.
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub by_namespace_limit: Option<usize>,
}

/// Remainder folded out of a capped `by_namespace` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamespaceOthers {
    pub count: usize,
    pub namespaces: usize,
}

impl ListNamespacesQuery {
    pub(crate) fn resolved_limit(&self) -> usize {
        self.limit
            .unwrap_or(NAMESPACES_DEFAULT_LIMIT)
            .clamp(1, crate::storage::LIST_MAX_LIMIT)
    }

    pub(crate) fn resolved_offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }

    /// Hierarchical prefix: exact match or a descendant (`prefix/`…).
    pub(crate) fn prefix(&self) -> Option<&str> {
        self.prefix
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

impl StatsQuery {
    pub(crate) fn resolved_by_namespace_limit(&self) -> usize {
        self.by_namespace_limit
            .unwrap_or(STATS_BY_NAMESPACE_DEFAULT_LIMIT)
            .clamp(1, STATS_BY_NAMESPACE_MAX_LIMIT)
    }
}

/// Parse `?summary=`. Unknown values fail closed (400), per ERRORS-09.
pub(crate) fn parse_summary_flag(raw: Option<&str>) -> Result<bool, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(false),
        Some("1" | "true" | "yes") => Ok(true),
        Some("0" | "false" | "no") => Ok(false),
        Some(other) => Err(format!("invalid summary value: {other}")),
    }
}

/// 400 envelope when `prefix` fails `validate_namespace`.
pub(crate) fn invalid_prefix_response(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": format!("invalid prefix: {err}")})),
    )
        .into_response()
}

/// 400 envelope for an unrecognised `summary` flag.
pub(crate) fn invalid_summary_response(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": err.to_string()})),
    )
        .into_response()
}

pub(crate) fn matches_namespace_prefix(namespace: &str, prefix: &str) -> bool {
    namespace == prefix
        || namespace
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Filter by hierarchical `prefix`, then apply `offset`/`limit`.
/// Returns `(page, total_matching)` — `total` is pre-page cardinality so
/// clients can keep paging. PERF-16: the page vec is pre-sized.
pub(crate) fn page_namespaces(
    rows: Vec<NamespaceCount>,
    prefix: Option<&str>,
    limit: usize,
    offset: usize,
) -> (Vec<NamespaceCount>, usize) {
    let filtered: Vec<NamespaceCount> = match prefix {
        Some(prefix) => rows
            .into_iter()
            .filter(|r| matches_namespace_prefix(&r.namespace, prefix))
            .collect(),
        None => rows,
    };
    let total = filtered.len();
    let page_len = total.saturating_sub(offset).min(limit);
    let mut page = Vec::with_capacity(page_len);
    page.extend(filtered.into_iter().skip(offset).take(limit));
    (page, total)
}

/// Keep the densest `limit` namespaces; fold the rest into [`NamespaceOthers`].
/// Input is assumed count-desc (both sqlite and postgres `list_namespaces`
/// / `stats` already order that way). Totals of *memories* are not touched.
pub(crate) fn cap_namespace_counts(
    mut rows: Vec<NamespaceCount>,
    limit: usize,
) -> (Vec<NamespaceCount>, Option<NamespaceOthers>, usize) {
    let total_namespaces = rows.len();
    if total_namespaces <= limit {
        return (rows, None, total_namespaces);
    }
    let rest = rows.split_off(limit);
    let others = NamespaceOthers {
        count: rest.iter().map(|r| r.count).sum(),
        namespaces: rest.len(),
    };
    (rows, Some(others), total_namespaces)
}

/// Overlay pagination metadata onto the namespaces list envelope.
pub(crate) fn namespaces_envelope(
    page: Vec<NamespaceCount>,
    total: usize,
    limit: usize,
    offset: usize,
) -> Value {
    json!({
        (crate::models::field_names::NAMESPACES): page,
        "total": total,
        "limit": limit,
        "offset": offset,
        "truncated": offset + page.len() < total,
    })
}

/// Overlay the #3343 cap/`summary` fields onto an already-serialized stats
/// envelope (sqlite `Stats` serde or the postgres projector). Memory totals
/// stay whatever the backend already emitted.
pub(crate) fn overlay_stats_inventory(
    envelope: &mut Value,
    by_namespace: Vec<NamespaceCount>,
    others: Option<NamespaceOthers>,
    by_namespace_total: usize,
    summary: bool,
) {
    if summary {
        if let Some(obj) = envelope.as_object_mut() {
            obj.remove(crate::models::field_names::BY_NAMESPACE);
            obj.insert("summary".into(), json!(true));
            obj.remove("others");
            obj.remove("truncated");
            obj.remove("by_namespace_total");
        }
        return;
    }
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert(
            crate::models::field_names::BY_NAMESPACE.into(),
            json!(by_namespace),
        );
        obj.insert("by_namespace_total".into(), json!(by_namespace_total));
        match others {
            Some(o) => {
                obj.insert(
                    "others".into(),
                    json!({
                        "count": o.count,
                        (crate::models::field_names::NAMESPACE_COUNT): o.namespaces,
                    }),
                );
                obj.insert("truncated".into(), json!(true));
            }
            None => {
                obj.insert("truncated".into(), json!(false));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(name: &str, count: usize) -> NamespaceCount {
        NamespaceCount {
            namespace: name.to_string(),
            count,
        }
    }

    #[test]
    fn page_namespaces_limit_offset_and_total() {
        let rows = vec![ns("a", 3), ns("b", 2), ns("c", 1)];
        let (page, total) = page_namespaces(rows, None, 1, 1);
        assert_eq!(total, 3);
        assert_eq!(page, vec![ns("b", 2)]);
    }

    #[test]
    fn page_namespaces_prefix_is_hierarchical_not_string_prefix() {
        let rows = vec![
            ns("proj", 5),
            ns("proj/sub", 2),
            ns("project-x", 9),
            ns("other", 1),
        ];
        let (page, total) = page_namespaces(rows, Some("proj"), 50, 0);
        assert_eq!(
            total, 2,
            "project-x must not match hierarchical prefix proj"
        );
        assert_eq!(page, vec![ns("proj", 5), ns("proj/sub", 2)]);
    }

    #[test]
    fn cap_namespace_counts_top_n_plus_others() {
        let rows = vec![ns("a", 10), ns("b", 5), ns("c", 3), ns("d", 1)];
        let (top, others, total) = cap_namespace_counts(rows, 2);
        assert_eq!(total, 4);
        assert_eq!(top, vec![ns("a", 10), ns("b", 5)]);
        assert_eq!(
            others,
            Some(NamespaceOthers {
                count: 4,
                namespaces: 2
            })
        );
    }

    #[test]
    fn cap_namespace_counts_no_others_when_under_limit() {
        let rows = vec![ns("a", 1)];
        let (top, others, total) = cap_namespace_counts(rows, 20);
        assert_eq!(total, 1);
        assert_eq!(top.len(), 1);
        assert!(others.is_none());
    }

    #[test]
    fn parse_summary_flag_accepts_common_truthy_and_rejects_unknown() {
        assert!(!parse_summary_flag(None).unwrap());
        assert!(parse_summary_flag(Some("1")).unwrap());
        assert!(parse_summary_flag(Some("true")).unwrap());
        assert!(parse_summary_flag(Some("yes")).unwrap());
        assert!(!parse_summary_flag(Some("0")).unwrap());
        assert!(!parse_summary_flag(Some("false")).unwrap());
        assert!(parse_summary_flag(Some("maybe")).is_err());
    }

    #[test]
    fn overlay_stats_others_uses_namespace_count_wire_key() {
        let mut v = json!({"total": 4});
        overlay_stats_inventory(
            &mut v,
            vec![ns("a", 10), ns("b", 5)],
            Some(NamespaceOthers {
                count: 4,
                namespaces: 2,
            }),
            4,
            false,
        );
        assert_eq!(v["others"][crate::models::field_names::NAMESPACE_COUNT], 2);
        assert_eq!(v["others"]["count"], 4);
        assert!(
            v["others"]
                .get(crate::models::field_names::NAMESPACES)
                .is_none(),
            "others must not reuse the namespaces-list key: {v}"
        );
        assert_eq!(v["truncated"], true);
        assert_eq!(v["by_namespace_total"], 4);
    }

    #[test]
    fn overlay_stats_summary_drops_by_namespace() {
        let mut v = json!({
            "total": 9,
            "by_tier": [{"tier":"mid","count":9}],
            "by_namespace": [{"namespace":"a","count":9}],
        });
        overlay_stats_inventory(&mut v, vec![ns("a", 9)], None, 1, true);
        assert!(v.get("by_namespace").is_none());
        assert_eq!(v["summary"], true);
        assert_eq!(v["total"], 9);
    }

    #[test]
    fn resolved_limits_clamp() {
        let q = ListNamespacesQuery {
            limit: Some(0),
            offset: None,
            prefix: None,
        };
        assert_eq!(q.resolved_limit(), 1);
        let huge = ListNamespacesQuery {
            limit: Some(usize::MAX),
            offset: None,
            prefix: None,
        };
        assert_eq!(huge.resolved_limit(), crate::storage::LIST_MAX_LIMIT);
        let s = StatsQuery {
            summary: None,
            by_namespace_limit: Some(10_000),
        };
        assert_eq!(
            s.resolved_by_namespace_limit(),
            STATS_BY_NAMESPACE_MAX_LIMIT
        );
    }
}
