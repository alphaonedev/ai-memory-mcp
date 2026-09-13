// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3288 — the bounded, keyset-paged admin export.
//!
//! # The defect
//!
//! `GET /api/v1/export` read the WHOLE exportable corpus into one
//! `Vec<Memory>` (postgres walked keyset pages but pushed every page into the
//! same vector; sqlite ran one unbounded `SELECT`) and serialised it as ONE
//! JSON body, together with the WHOLE link table. On a multi-million-row
//! tenant that is an out-of-memory kill of the daemon, and for a postgres
//! deployment this route is the only backup path. Rows the decrypt projection
//! skipped were reported to the log only, so a partial body looked complete.
//!
//! # The contract (5-agent vote, `4d3ea1c5` protocol — see #3288)
//!
//! * **Paged mode** — `?limit=N` and/or `?cursor=<opaque>`. One request reads
//!   at most `N <= max_page_size` memory rows plus the graph edges that page
//!   OWNS (below), and returns `next_cursor` (`null` on the last page).
//! * **Legacy mode** — no paging parameter. The historical full body, but
//!   only while the corpus fits the page ceiling; past it the request is
//!   REFUSED with a typed `413` ([`crate::errors::error_codes::EXPORT_PAGING_REQUIRED`]).
//!   It never returns a partial body under the legacy shape, because a
//!   client that predates paging would store it as a complete backup.
//! * **Honesty** — every body carries the #2490 withheld ledger for the rows
//!   it covers, the count of rows the decrypt projection could not open
//!   (`undecryptable`), and `partial`. A paging client sums the per-page
//!   counts; the cursor carries position only, never accounting state.
//!
//! # Edge ownership
//!
//! Pages partition the key space `(created_at, id)` into consecutive ranges
//! `(lower, upper]`; the final page's range is open-ended. An edge is owned
//! by the page holding its LATER-keyed exported endpoint, so when a client
//! imports the pages in order every emitted edge's endpoints already exist.
//! The edge is emitted only when BOTH endpoints are carried by the export
//! (they pass the export filters, the decrypt projection and the
//! forbidden-class screen); otherwise it is counted in
//! `dangling_links_withheld` exactly once, on the page that owns it. Nothing
//! is buffered across requests. [`plan_edge`] is the pure decision.
//!
//! # Why the cursor is not signed
//!
//! The cursor is opaque (versioned JSON, base64url) and strictly validated,
//! but not MAC'd: every page re-runs the admin gate, and the only party that
//! can present a cursor is an admin already entitled to the whole corpus. A
//! forged cursor can make that admin skip rows of their own backup, nothing
//! more. The expiry cutoff `as_of` is pinned in the cursor so every page of
//! one walk applies the same retention boundary.

use std::collections::HashSet;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{Memory, MemoryLink};

/// Wire version of the cursor. A cursor minted by another version is refused
/// with a 400 rather than silently re-interpreted.
pub const CURSOR_VERSION: u8 = 1;

/// Upper bound on the encoded cursor. The payload is two short keys and a
/// timestamp; anything longer is not a cursor this server minted.
pub const MAX_CURSOR_BYTES: usize = 1024;

/// Upper bound on each key component inside a decoded cursor.
const MAX_CURSOR_KEY_BYTES: usize = 256;

/// Tolerated clock skew for a cursor's pinned `as_of`. A cutoff further in the
/// future than this was not minted by this server's clock.
const MAX_AS_OF_SKEW_SECS: i64 = 300;

/// Position of a row in the export walk: the `(created_at, id)` keyset tuple,
/// with `created_at` in the backend's own ordering domain (sqlite: the stored
/// TEXT; postgres: the `timestamptz` rendered to RFC 3339 microseconds, which
/// round-trips exactly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportKey {
    /// Backend-native `created_at` of the row.
    pub created_at: String,
    /// The row id (the unique tiebreak, compared byte-wise on both backends).
    pub id: String,
}

/// Resume point of a paged export: walk rows strictly after `after`, applying
/// the expiry cutoff `as_of` pinned when the walk started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportCursor {
    /// Last row key the previous page covered.
    pub after: ExportKey,
    /// Expiry cutoff of the whole walk.
    pub as_of: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    v: u8,
    c: String,
    i: String,
    a: String,
}

/// Why a presented cursor was refused (rendered into a 400 body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportCursorError(pub String);

impl std::fmt::Display for ExportCursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn key_component_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_CURSOR_KEY_BYTES && !s.chars().any(char::is_control)
}

impl ExportCursor {
    /// Encode as the opaque wire token.
    ///
    /// # Errors
    ///
    /// Only if JSON serialisation of the three strings fails, which it does
    /// not for valid UTF-8; the error is propagated rather than unwrapped.
    pub fn encode(&self) -> Result<String, ExportCursorError> {
        let wire = CursorWire {
            v: CURSOR_VERSION,
            c: self.after.created_at.clone(),
            i: self.after.id.clone(),
            a: self
                .as_of
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        };
        let bytes = serde_json::to_vec(&wire)
            .map_err(|e| ExportCursorError(format!("cursor encode failed: {e}")))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Decode and validate a wire token.
    ///
    /// # Errors
    ///
    /// Refuses anything this server could not have minted: oversize, not
    /// base64url, not the versioned JSON shape, an unknown version, empty or
    /// oversize or control-character key components, an unparseable cutoff,
    /// or a cutoff in the future beyond the skew allowance.
    pub fn decode(raw: &str, now: DateTime<Utc>) -> Result<Self, ExportCursorError> {
        if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES {
            return Err(ExportCursorError(format!(
                "cursor must be 1..={MAX_CURSOR_BYTES} bytes"
            )));
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw.as_bytes())
            .map_err(|_| ExportCursorError("cursor is not a valid export cursor".into()))?;
        let wire: CursorWire = serde_json::from_slice(&bytes)
            .map_err(|_| ExportCursorError("cursor is not a valid export cursor".into()))?;
        if wire.v != CURSOR_VERSION {
            return Err(ExportCursorError(format!(
                "cursor version {} is not supported (expected {CURSOR_VERSION})",
                wire.v
            )));
        }
        if !key_component_ok(&wire.c) || !key_component_ok(&wire.i) {
            return Err(ExportCursorError("cursor key is malformed".into()));
        }
        let as_of = DateTime::parse_from_rfc3339(&wire.a)
            .map_err(|_| ExportCursorError("cursor cutoff is malformed".into()))?
            .with_timezone(&Utc);
        if as_of > now + chrono::Duration::seconds(MAX_AS_OF_SKEW_SECS) {
            return Err(ExportCursorError("cursor cutoff is in the future".into()));
        }
        Ok(Self {
            after: ExportKey {
                created_at: wire.c,
                id: wire.i,
            },
            as_of,
        })
    }
}

/// How a request is served, resolved from its query parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportMode {
    /// No paging parameter: the historical full body, refused past `ceiling`.
    Legacy {
        /// Maximum rows the legacy body may carry.
        ceiling: usize,
        /// Expiry cutoff for this one-shot read.
        as_of: DateTime<Utc>,
    },
    /// One page of a keyset walk.
    Paged {
        /// Resume point (`None` = first page).
        cursor: Option<ExportCursor>,
        /// Rows per page.
        limit: usize,
        /// Expiry cutoff: the cursor's pinned one, or `now` on the first page.
        as_of: DateTime<Utc>,
    },
}

/// Why a request's paging parameters were refused (rendered into a 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportModeError {
    /// `limit` outside `1..=max_page_size`.
    LimitOutOfRange {
        /// The page ceiling in force.
        max: usize,
    },
    /// The cursor failed [`ExportCursor::decode`].
    Cursor(ExportCursorError),
}

/// Resolve the serving mode. `max_page_size` is the operator's page ceiling
/// (`AI_MEMORY_MAX_PAGE_SIZE`), which bounds both a page and the legacy body.
///
/// # Errors
///
/// [`ExportModeError`] for an out-of-range `limit` or an invalid cursor.
/// A limit above the ceiling is refused rather than clamped: the caller
/// learns the real ceiling instead of silently receiving a smaller page.
pub fn resolve_mode(
    limit: Option<usize>,
    cursor: Option<&str>,
    max_page_size: usize,
    now: DateTime<Utc>,
) -> Result<ExportMode, ExportModeError> {
    let max = max_page_size.max(1);
    if limit.is_none() && cursor.is_none() {
        return Ok(ExportMode::Legacy {
            ceiling: max,
            as_of: now,
        });
    }
    let limit = match limit {
        None => max,
        Some(n) if (1..=max).contains(&n) => n,
        Some(_) => return Err(ExportModeError::LimitOutOfRange { max }),
    };
    let cursor = cursor
        .map(|raw| ExportCursor::decode(raw, now))
        .transpose()
        .map_err(ExportModeError::Cursor)?;
    let as_of = cursor.as_ref().map_or(now, |c| c.as_of);
    Ok(ExportMode::Paged {
        cursor,
        limit,
        as_of,
    })
}

/// The key range one page covers: `(lower, upper]`. `upper == None` means the
/// range is open-ended (this is the last page).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportPageRange {
    /// Exclusive lower bound (`None` = start of the corpus).
    pub lower: Option<ExportKey>,
    /// Inclusive upper bound (`None` = end of the corpus).
    pub upper: Option<ExportKey>,
}

/// Rows inside a page's range that the export's SQL filters excluded
/// (reported, see [`crate::export_scope::ExportWithholdLedger`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExportExcludedCounts {
    /// `lifecycle_state = quarantined` rows.
    pub quarantined: usize,
    /// `lifecycle_state = tombstoned` rows.
    pub tombstoned: usize,
    /// Rows past their `expires_at` at the walk's cutoff.
    pub expired: usize,
}

/// What a page's link read needs to know about the page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportPageScope {
    /// The page's key range.
    pub range: ExportPageRange,
    /// Expiry cutoff of the walk.
    pub as_of: DateTime<Utc>,
    /// Ids of EVERY row the page query returned, including rows the decrypt
    /// projection then skipped.
    pub raw_ids: Vec<String>,
}

/// One page of memories, before the export confidentiality screen.
#[derive(Debug, Clone, Default)]
pub struct ExportMemoriesPage {
    /// Projected rows, in walk order.
    pub memories: Vec<Memory>,
    /// Rows returned by the query but skipped by the decrypt projection.
    pub undecryptable: usize,
    /// Rows in the range the SQL filters excluded.
    pub excluded: ExportExcludedCounts,
    /// Range, cutoff and raw ids, for [`plan_edge`] and the link read.
    pub scope: ExportPageScope,
    /// Resume point for the next page (`None` = walk complete).
    pub next_cursor: Option<ExportCursor>,
}

impl ExportMemoriesPage {
    /// Rows the page query returned (projected + undecryptable).
    #[must_use]
    pub fn raw_rows(&self) -> usize {
        self.scope.raw_ids.len()
    }
}

/// The edges one page owns, after the survival checks.
#[derive(Debug, Clone, Default)]
pub struct ExportLinksPage {
    /// Edges emitted with this page.
    pub links: Vec<MemoryLink>,
    /// Owned edges withheld because an endpoint is not carried by the export.
    pub dangling: usize,
}

/// Where an edge endpoint sits relative to the page being built. The first
/// flag is computed from [`ExportPageScope::raw_ids`]; the other three come
/// from the link query, evaluated with the same key order and the same
/// export filters as the page query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EndpointPos {
    /// The endpoint is one of the rows this page's query returned.
    pub in_page: bool,
    /// Its key is at or before the page's lower bound (an earlier page).
    pub before_page: bool,
    /// Its key is after the page's upper bound (a later page).
    pub after_page: bool,
    /// It passes the export's SQL filters at the walk's cutoff.
    pub exportable: bool,
}

/// The pure per-edge decision for one page. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgePlan {
    /// Neither endpoint is on this page: not this page's edge.
    NotIncident,
    /// A later page owns this edge.
    Defer,
    /// Owned here, and the counterpart is known not to be carried: withhold.
    Withhold,
    /// Owned here; emit iff the in-page endpoint(s) survived the screen.
    /// `counterpart` names an EARLIER-page endpoint whose survival must be
    /// re-established (re-read, projected, screened) first.
    Decide {
        /// In-page endpoint ids that must be in the screened survivor set.
        in_page: Vec<String>,
        /// Earlier-page endpoint to re-check, if any.
        counterpart: Option<String>,
    },
}

/// Decide what this page does with one incident edge.
#[must_use]
pub fn plan_edge(link: &MemoryLink, source: EndpointPos, target: EndpointPos) -> EdgePlan {
    match (source.in_page, target.in_page) {
        (false, false) => EdgePlan::NotIncident,
        (true, true) => {
            let mut in_page = vec![link.source_id.clone()];
            if link.target_id != link.source_id {
                in_page.push(link.target_id.clone());
            }
            EdgePlan::Decide {
                in_page,
                counterpart: None,
            }
        }
        (true, false) => plan_one_sided(&link.source_id, &link.target_id, target),
        (false, true) => plan_one_sided(&link.target_id, &link.source_id, source),
    }
}

fn plan_one_sided(in_page_id: &str, other_id: &str, other: EndpointPos) -> EdgePlan {
    if other.after_page && other.exportable {
        // The counterpart will be returned by a later page, which then sees
        // this endpoint as an earlier-page counterpart and owns the edge.
        return EdgePlan::Defer;
    }
    if !other.exportable {
        // Never carried by this walk (filtered out, in or beyond this range):
        // no later page will see the edge, so this page owns and withholds it.
        return EdgePlan::Withhold;
    }
    // Exportable and not after this page and not in it: an earlier page
    // carried it, unless the projection or screen dropped it there.
    EdgePlan::Decide {
        in_page: vec![in_page_id.to_string()],
        counterpart: Some(other_id.to_string()),
    }
}

/// Finish a page's edges: emit the planned edges whose endpoints all survived
/// and count the rest as withheld. `survivors` is the screened in-page set;
/// `counterpart_survivors` the earlier-page endpoints that re-checked alive.
#[must_use]
pub fn finalize_edges(
    planned: Vec<(MemoryLink, EdgePlan)>,
    survivors: &HashSet<String>,
    counterpart_survivors: &HashSet<String>,
) -> ExportLinksPage {
    let mut out = ExportLinksPage::default();
    for (link, plan) in planned {
        match plan {
            EdgePlan::NotIncident | EdgePlan::Defer => {}
            EdgePlan::Withhold => out.dangling += 1,
            EdgePlan::Decide {
                in_page,
                counterpart,
            } => {
                let alive = in_page.iter().all(|id| survivors.contains(id))
                    && counterpart
                        .as_ref()
                        .is_none_or(|id| counterpart_survivors.contains(id));
                if alive {
                    out.links.push(link);
                } else {
                    out.dangling += 1;
                }
            }
        }
    }
    out
}

/// Earlier-page endpoints a set of plans needs re-checked, de-duplicated.
#[must_use]
pub fn counterparts_to_recheck(planned: &[(MemoryLink, EdgePlan)]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (_, plan) in planned {
        if let EdgePlan::Decide {
            counterpart: Some(id),
            ..
        } = plan
            && seen.insert(id.clone())
        {
            out.push(id.clone());
        }
    }
    out
}

/// Whether a re-read earlier-page endpoint is still carried by the export:
/// the projection produced it (`Some`) and the forbidden-class screen keeps
/// it. The same screen the handler applies to in-page rows.
#[must_use]
pub fn counterpart_survives(projected: Option<&Memory>) -> bool {
    projected.is_some_and(|m| crate::export_taxonomy::classify_memory(m).is_none())
}

/// Build the page range and the next cursor from the rows a page query
/// returned. `fetched` is the number of rows returned; `limit` what was asked
/// for. A short page is the last page: its range is open-ended and there is
/// no next cursor.
#[must_use]
pub fn close_page(
    lower: Option<ExportKey>,
    last: Option<ExportKey>,
    fetched: usize,
    limit: usize,
    as_of: DateTime<Utc>,
) -> (ExportPageRange, Option<ExportCursor>) {
    match last {
        Some(last) if fetched >= limit => (
            ExportPageRange {
                lower,
                upper: Some(last.clone()),
            },
            Some(ExportCursor { after: last, as_of }),
        ),
        _ => (ExportPageRange { lower, upper: None }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-13T12:00:00Z")
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_default()
    }

    fn key(c: &str, i: &str) -> ExportKey {
        ExportKey {
            created_at: c.into(),
            id: i.into(),
        }
    }

    fn link(s: &str, t: &str) -> MemoryLink {
        MemoryLink {
            source_id: s.into(),
            target_id: t.into(),
            relation: crate::models::MemoryLinkRelation::default(),
            created_at: "2026-01-01T00:00:00Z".into(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    fn pos(in_page: bool, before: bool, after: bool, exportable: bool) -> EndpointPos {
        EndpointPos {
            in_page,
            before_page: before,
            after_page: after,
            exportable,
        }
    }

    #[test]
    fn cursor_round_trips_and_pins_the_cutoff() {
        let c = ExportCursor {
            after: key("2026-01-01T00:00:00.000001Z", "m-1"),
            as_of: now(),
        };
        let raw = c.encode().expect("encode");
        assert_eq!(ExportCursor::decode(&raw, now()), Ok(c));
    }

    #[test]
    fn cursor_decode_refuses_what_the_server_did_not_mint() {
        let n = now();
        assert!(ExportCursor::decode("", n).is_err());
        assert!(ExportCursor::decode(&"A".repeat(MAX_CURSOR_BYTES + 1), n).is_err());
        assert!(ExportCursor::decode("not base64 !!", n).is_err());
        let enc = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        // Unknown version.
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":2,"c":"x","i":"y","a":"2026-09-13T12:00:00Z"}"#),
                n
            )
            .is_err()
        );
        // Unknown field.
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":1,"c":"x","i":"y","a":"2026-09-13T12:00:00Z","n":0}"#),
                n
            )
            .is_err()
        );
        // Empty and control-character keys.
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":1,"c":"","i":"y","a":"2026-09-13T12:00:00Z"}"#),
                n
            )
            .is_err()
        );
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":1,"c":"x","i":"y\u0007","a":"2026-09-13T12:00:00Z"}"#),
                n
            )
            .is_err()
        );
        // Cutoff in the future beyond the skew allowance.
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":1,"c":"x","i":"y","a":"2026-09-14T12:00:00Z"}"#),
                n
            )
            .is_err()
        );
        // Within the skew allowance is accepted.
        assert!(
            ExportCursor::decode(
                &enc(r#"{"v":1,"c":"x","i":"y","a":"2026-09-13T12:01:00Z"}"#),
                n
            )
            .is_ok()
        );
    }

    #[test]
    fn mode_resolution() {
        let n = now();
        assert_eq!(
            resolve_mode(None, None, 1000, n),
            Ok(ExportMode::Legacy {
                ceiling: 1000,
                as_of: n
            })
        );
        assert_eq!(
            resolve_mode(Some(10), None, 1000, n),
            Ok(ExportMode::Paged {
                cursor: None,
                limit: 10,
                as_of: n
            })
        );
        assert_eq!(
            resolve_mode(Some(0), None, 1000, n),
            Err(ExportModeError::LimitOutOfRange { max: 1000 })
        );
        assert_eq!(
            resolve_mode(Some(1001), None, 1000, n),
            Err(ExportModeError::LimitOutOfRange { max: 1000 })
        );
        let pinned = n - chrono::Duration::hours(1);
        let raw = ExportCursor {
            after: key("c", "i"),
            as_of: pinned,
        }
        .encode()
        .expect("encode");
        // A cursor alone pages at the ceiling and keeps the pinned cutoff.
        assert_eq!(
            resolve_mode(None, Some(&raw), 1000, n),
            Ok(ExportMode::Paged {
                cursor: Some(ExportCursor {
                    after: key("c", "i"),
                    as_of: pinned
                }),
                limit: 1000,
                as_of: pinned
            })
        );
        assert!(matches!(
            resolve_mode(None, Some("garbage"), 1000, n),
            Err(ExportModeError::Cursor(_))
        ));
    }

    #[test]
    fn close_page_short_page_is_the_last() {
        let (range, next) = close_page(Some(key("a", "1")), Some(key("b", "2")), 3, 5, now());
        assert_eq!(range.upper, None);
        assert_eq!(next, None);
        let (range, next) = close_page(None, Some(key("b", "2")), 5, 5, now());
        assert_eq!(range.upper, Some(key("b", "2")));
        assert_eq!(next.map(|c| c.after), Some(key("b", "2")));
        let (range, next) = close_page(None, None, 0, 5, now());
        assert_eq!(range, ExportPageRange::default());
        assert_eq!(next, None);
    }

    #[test]
    fn both_endpoints_on_the_page_decide_on_the_screen() {
        let l = link("a", "b");
        let plan = plan_edge(
            &l,
            pos(true, false, false, true),
            pos(true, false, false, true),
        );
        let survivors: HashSet<String> = ["a".into()].into();
        let out = finalize_edges(vec![(l.clone(), plan.clone())], &survivors, &HashSet::new());
        assert_eq!((out.links.len(), out.dangling), (0, 1));
        let survivors: HashSet<String> = ["a".into(), "b".into()].into();
        let out = finalize_edges(vec![(l, plan)], &survivors, &HashSet::new());
        assert_eq!((out.links.len(), out.dangling), (1, 0));
    }

    #[test]
    fn self_loop_needs_only_its_one_row() {
        let l = link("a", "a");
        let plan = plan_edge(
            &l,
            pos(true, false, false, true),
            pos(true, false, false, true),
        );
        let survivors: HashSet<String> = ["a".into()].into();
        let out = finalize_edges(vec![(l, plan)], &survivors, &HashSet::new());
        assert_eq!((out.links.len(), out.dangling), (1, 0));
    }

    #[test]
    fn a_later_exportable_counterpart_defers_and_is_not_counted_here() {
        let l = link("a", "z");
        let plan = plan_edge(
            &l,
            pos(true, false, false, true),
            pos(false, false, true, true),
        );
        assert_eq!(plan, EdgePlan::Defer);
        let out = finalize_edges(vec![(l, plan)], &HashSet::new(), &HashSet::new());
        assert_eq!((out.links.len(), out.dangling), (0, 0));
    }

    #[test]
    fn a_counterpart_the_walk_never_carries_is_withheld_here_exactly_once() {
        // Later but filtered out: no later page will ever see the edge.
        let l = link("a", "q");
        assert_eq!(
            plan_edge(
                &l,
                pos(true, false, false, true),
                pos(false, false, true, false)
            ),
            EdgePlan::Withhold
        );
        // In range but filtered out (quarantined / expired).
        assert_eq!(
            plan_edge(
                &l,
                pos(true, false, false, true),
                pos(false, false, false, false)
            ),
            EdgePlan::Withhold
        );
        // Earlier but no longer exportable.
        assert_eq!(
            plan_edge(
                &l,
                pos(true, false, false, true),
                pos(false, true, false, false)
            ),
            EdgePlan::Withhold
        );
    }

    #[test]
    fn an_earlier_counterpart_is_rechecked() {
        // Target is the in-page endpoint; the source was on an earlier page.
        let l = link("e", "a");
        let plan = plan_edge(
            &l,
            pos(false, true, false, true),
            pos(true, false, false, true),
        );
        assert_eq!(
            plan,
            EdgePlan::Decide {
                in_page: vec!["a".into()],
                counterpart: Some("e".into())
            }
        );
        let planned = vec![(l.clone(), plan.clone()), (l.clone(), plan.clone())];
        assert_eq!(counterparts_to_recheck(&planned), vec!["e".to_string()]);
        let survivors: HashSet<String> = ["a".into()].into();
        let alive: HashSet<String> = ["e".into()].into();
        let out = finalize_edges(vec![(l.clone(), plan.clone())], &survivors, &alive);
        assert_eq!((out.links.len(), out.dangling), (1, 0));
        // The earlier endpoint was dropped by the screen on its own page.
        let out = finalize_edges(vec![(l, plan)], &survivors, &HashSet::new());
        assert_eq!((out.links.len(), out.dangling), (0, 1));
    }

    #[test]
    fn non_incident_edges_are_ignored() {
        let l = link("x", "y");
        assert_eq!(
            plan_edge(
                &l,
                pos(false, true, false, true),
                pos(false, false, true, true)
            ),
            EdgePlan::NotIncident
        );
    }

    #[test]
    fn counterpart_survival_uses_the_export_screen() {
        assert!(!counterpart_survives(None));
        let clean = Memory::default();
        assert!(counterpart_survives(Some(&clean)));
        let mut pem = Memory::default();
        pem.content =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
                .to_string();
        assert!(!counterpart_survives(Some(&pem)));
    }
}
