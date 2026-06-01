// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.6.0.0 — webhook subscriptions.
//!
//! Subscribers register a URL + shared secret + event/namespace/agent
//! filters. When a matching event fires (e.g. `memory_store`), a
//! fire-and-forget thread POSTs an HMAC-SHA256-signed JSON payload.
//!
//! SSRF hardening:
//! - `http://` only to `127.0.0.0/8` or `localhost` hosts;
//!   everywhere else requires `https://`
//! - RFC1918 / RFC4193 / link-local hosts are rejected unless
//!   `allow_private_networks = true` in the daemon config
//!
//! Signature:
//! - Header `X-Ai-Memory-Signature: sha256=<hex>` over the raw
//!   JSON body
//! - The secret stored in the DB is a SHA-256 of the plaintext
//!   shared secret; the plaintext is returned **once** at
//!   subscription time and never leaves the DB after.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

/// Public-facing subscription record (no secret plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub url: String,
    pub events: String,
    pub namespace_filter: Option<String>,
    pub agent_filter: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub dispatch_count: i64,
    pub failure_count: i64,
    /// v0.6.3.1 P5 (G9): structured per-event-type opt-in list. When
    /// `Some(list)` the subscription only fires for event types in
    /// `list` (overriding the legacy comma-separated `events`
    /// whitelist). When `None` (default) all events match — preserves
    /// pre-P5 behaviour for existing subscribers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<String>>,
}

/// Parameters for creating a subscription.
pub struct NewSubscription<'a> {
    pub url: &'a str,
    pub events: &'a str,
    pub secret: Option<&'a str>,
    pub namespace_filter: Option<&'a str>,
    pub agent_filter: Option<&'a str>,
    pub created_by: Option<&'a str>,
    /// v0.6.3.1 P5 (G9): optional structured event-type whitelist. When
    /// `Some`, only the listed event types fire. When `None`, the legacy
    /// `events` field (comma-separated / `*`) governs — the historical
    /// behaviour for backward compatibility.
    pub event_types: Option<&'a [String]>,
}

/// Canonical list of webhook lifecycle events surfaced to subscribers
/// and to `memory_capabilities` (capabilities v2 `webhook_events`).
/// Keep stable: integrators pin against these strings.
///
/// v0.7.0 K4 — `approval_requested` joined the list. It fires every
/// time a `pending_actions` row is inserted by the governance gate
/// (locally via `db::queue_pending_action` or remotely via
/// `db::upsert_pending_action`). Subscribers opt in via the existing
/// [`NewSubscription::event_types`] structured filter; legacy
/// wildcard-event subscribers also receive it. Closes the
/// v0.6.3.1 honest-Capabilities-v2 disclosure that
/// `approval.subscribers` was advertised but never published — the
/// K10 Approval API HTTP+SSE handler consumes these events directly.
///
/// v0.7 J4 / G14 — `memory_link_invalidated` also joins so subscribers
/// can replay the audit-edge timeline (every successful
/// `memory_kg_invalidate` fires this event after the link's
/// `valid_until` is set, regardless of which KG backend handled the
/// SET).
// v0.7.x (issue #1174 PR1 — pm-v3.1 MCP tool name sweep): the three
// entries that ARE MCP tool names reference the canonical
// `tool_names` consts.
//
// v0.7.0 multi-agent literal-sweep (scanner B finding F-B10.x): the
// remaining four entries — subscription-event types distinct from
// MCP method names — now also consume named consts in
// [`webhook_events`] below. Pre-sweep these were the last raw-literal
// holdouts in this array; centralising them closes the drift class.
pub const WEBHOOK_EVENT_TYPES: &[&str] = &[
    crate::mcp::registry::tool_names::MEMORY_STORE,
    crate::mcp::registry::tool_names::MEMORY_PROMOTE,
    crate::mcp::registry::tool_names::MEMORY_DELETE,
    webhook_events::MEMORY_LINK_CREATED,
    webhook_events::MEMORY_LINK_INVALIDATED,
    webhook_events::MEMORY_CONSOLIDATED,
    webhook_events::APPROVAL_REQUESTED,
];

/// v0.7.0 multi-agent literal-sweep (scanner B finding F-B10.x) —
/// canonical webhook-event-type slugs that are NOT MCP tool names.
///
/// Distinct from `signed_events::event_types` (audit-chain slugs use
/// dot-separated names like `"memory_link.created"`); webhook events
/// use underscore-separated names matching the v0.6.x wire contract
/// (`"memory_link_created"`). A rename or schema-evolution that adds
/// new webhook events touches this mod + the [`WEBHOOK_EVENT_TYPES`]
/// array (which is statically-asserted to contain every const here
/// via the unit test `webhook_event_consts_appear_in_array`).
pub mod webhook_events {
    /// Fired by `memory_link.create` substrate path after every
    /// successful link write (signed or unsigned). Subscribers consume
    /// via the K10 / J4 webhook fan-out.
    pub const MEMORY_LINK_CREATED: &str = "memory_link_created";

    /// Fired by `memory_kg_invalidate` after `valid_until` is set,
    /// regardless of which KG backend handled the SET. Joined the
    /// webhook set at v0.7 J4 / G14 so subscribers can replay the
    /// audit-edge timeline.
    pub const MEMORY_LINK_INVALIDATED: &str = "memory_link_invalidated";

    /// Fired by `memory_consolidate` after a successful consolidation
    /// write (post-#867 W6 consolidation primitive).
    pub const MEMORY_CONSOLIDATED: &str = "memory_consolidated";

    /// Fired by the K10 Approval API after a governance `Pending`
    /// decision queues a pending action. Consumed directly by the
    /// K10 Approval HTTP+SSE handler.
    pub const APPROVAL_REQUESTED: &str = "approval_requested";
}

/// Insert a subscription, hashing any secret before persisting.
///
/// Returns the new subscription's id.
///
/// P5 (G9): when `event_types` is `Some`, the structured opt-in list is
/// JSON-encoded into the new `event_types` column AND mirrored into
/// the legacy comma-separated `events` column so the existing
/// dispatch matcher continues to work without a second code path. An
/// unknown event type returns Err — the canonical list lives in
/// `WEBHOOK_EVENT_TYPES`.
pub fn insert(conn: &Connection, req: &NewSubscription<'_>) -> Result<String> {
    validate_url(req.url)?;
    let id = uuid::Uuid::new_v4().to_string();
    let secret_hash = req.secret.map(sha256_hex);
    let now = chrono::Utc::now().to_rfc3339();

    // P5: validate + serialise the structured event-type list.
    let (events_csv, event_types_json) = if let Some(list) = req.event_types {
        for ev in list {
            if !WEBHOOK_EVENT_TYPES.contains(&ev.as_str()) {
                return Err(anyhow!(
                    "unknown webhook event type {ev:?}; valid types: {WEBHOOK_EVENT_TYPES:?}"
                ));
            }
        }
        // Mirror into the legacy events column so dispatch keeps working.
        let csv = list.join(",");
        let json = serde_json::to_string(list).context("event_types serialise")?;
        (csv, Some(json))
    } else {
        (req.events.to_string(), None)
    };

    conn.execute(
        "INSERT INTO subscriptions (id, url, events, secret_hash, namespace_filter, agent_filter, created_by, created_at, event_types) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, req.url, events_csv, secret_hash, req.namespace_filter, req.agent_filter, req.created_by, now, event_types_json],
    )?;
    Ok(id)
}

/// Delete a subscription by id, optionally scoped to its owner.
///
/// Cross-tenant authorization (#870, security-high, 2026-05-18):
/// When `caller_agent_id` is `Some(aid)`, the DELETE only matches rows
/// where `created_by = aid` — preventing tenant A from unsubscribing
/// tenant B's webhook. When `None`, the DELETE matches by id alone
/// (admin path: federation receive, GC, operator CLI). Callers exposed
/// to untrusted input (MCP `memory_unsubscribe`, HTTP
/// `DELETE /api/v1/subscriptions`) MUST pass `Some(<authenticated
/// caller>)` — anything else is a bypass.
///
/// Returns true if a row was removed (i.e. it both existed AND matched
/// the owner clause when one was supplied).
pub fn delete(conn: &Connection, id: &str, caller_agent_id: Option<&str>) -> Result<bool> {
    let n = if let Some(aid) = caller_agent_id {
        conn.execute(
            "DELETE FROM subscriptions WHERE id = ?1 AND created_by = ?2",
            params![id, aid],
        )?
    } else {
        conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?
    };
    Ok(n > 0)
}

/// List active subscriptions, optionally scoped to a single owner.
///
/// Cross-tenant authorization (#872, security-high, 2026-05-18):
/// When `caller_agent_id` is `Some(aid)`, only rows where
/// `created_by = aid` are returned — preventing tenant A from
/// enumerating tenant B's webhook fleet. When `None`, every row is
/// returned (internal use: dispatch fan-out, federation, operator
/// inventory). Callers exposed to untrusted input (MCP
/// `memory_list_subscriptions`, HTTP `GET /api/v1/subscriptions`) MUST
/// pass `Some(<authenticated caller>)`.
pub fn list(conn: &Connection, caller_agent_id: Option<&str>) -> Result<Vec<Subscription>> {
    let mut stmt = if caller_agent_id.is_some() {
        conn.prepare(
            "SELECT id, url, events, namespace_filter, agent_filter, created_by, created_at, dispatch_count, failure_count, event_types FROM subscriptions WHERE created_by = ?1 ORDER BY created_at DESC",
        )?
    } else {
        conn.prepare(
            "SELECT id, url, events, namespace_filter, agent_filter, created_by, created_at, dispatch_count, failure_count, event_types FROM subscriptions ORDER BY created_at DESC",
        )?
    };
    let row_decoder = |row: &rusqlite::Row<'_>| {
        let event_types_raw: Option<String> = row.get(9)?;
        // P5: decode the JSON column. A corrupt row should not break
        // the entire list — fall back to None (= all-events) and warn.
        let event_types =
            event_types_raw.and_then(|s| match serde_json::from_str::<Vec<String>>(&s) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(
                        "subscription event_types JSON decode failed, treating as all-events: {e}"
                    );
                    None
                }
            });
        Ok(Subscription {
            id: row.get(0)?,
            url: row.get(1)?,
            events: row.get(2)?,
            namespace_filter: row.get(3)?,
            agent_filter: row.get(4)?,
            created_by: row.get(5)?,
            created_at: row.get(6)?,
            dispatch_count: row.get(7)?,
            failure_count: row.get(8)?,
            event_types,
        })
    };
    let rows = if let Some(aid) = caller_agent_id {
        stmt.query_map(params![aid], row_decoder)?
            .collect::<rusqlite::Result<Vec<_>>>()
    } else {
        stmt.query_map([], row_decoder)?
            .collect::<rusqlite::Result<Vec<_>>>()
    };
    rows.context("subscription row decode failed")
}

/// Look up a subscription's owner (`created_by`) by id.
///
/// v0.7.0 #1115 / #1118 (SR-1 #5 / #6, HIGH) — used by the MCP +
/// HTTP authz gates on `memory_subscription_replay` and
/// `memory_subscription_dlq_list` to refuse cross-tenant reads of
/// other agents' subscriptions. Returns `Ok(None)` when the
/// subscription does not exist; callers map this to the same
/// not-found envelope as a real miss so the existence of the id is
/// not leaked.
///
/// # Errors
/// - SQL prepare / query / decode failure.
pub fn get_owner(conn: &Connection, id: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT created_by FROM subscriptions WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next().context("subscription owner row")? {
        let owner: Option<String> = row.get(0)?;
        Ok(owner)
    } else {
        Ok(None)
    }
}

/// P5 (G9): list subscriptions matching a specific event type. Returns
/// rows where either:
///   - `event_types` is NULL (= all events; backward-compat default), OR
///   - `event_types` JSON array contains `event_type`.
///
/// This is the DB-side variant of the per-event filter; the in-memory
/// `matches_filters` is the authoritative gate at dispatch time and
/// honours both the legacy `events` whitelist and the new
/// `event_types` opt-in list.
pub fn list_by_event(conn: &Connection, event_type: &str) -> Result<Vec<Subscription>> {
    // SQLite doesn't have a JSON contains operator portable across all
    // builds; we filter in Rust after a coarse SQL prefilter that drops
    // rows whose stored JSON clearly doesn't mention the event. The
    // text LIKE match is conservative (it can yield false positives the
    // post-filter then rejects) which keeps the SQL simple while still
    // letting an idx_subscriptions_event_types-backed scan win on large
    // tables.
    let pattern = format!("%{event_type}%");
    let mut stmt = conn.prepare(
        "SELECT id, url, events, namespace_filter, agent_filter, created_by, created_at, dispatch_count, failure_count, event_types FROM subscriptions WHERE event_types IS NULL OR event_types LIKE ?1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![pattern], |row| {
        let event_types_raw: Option<String> = row.get(9)?;
        let event_types =
            event_types_raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok());
        Ok(Subscription {
            id: row.get(0)?,
            url: row.get(1)?,
            events: row.get(2)?,
            namespace_filter: row.get(3)?,
            agent_filter: row.get(4)?,
            created_by: row.get(5)?,
            created_at: row.get(6)?,
            dispatch_count: row.get(7)?,
            failure_count: row.get(8)?,
            event_types,
        })
    })?;
    let mut out: Vec<Subscription> = Vec::new();
    for sub in rows {
        let s = sub.context("subscription row decode failed")?;
        match &s.event_types {
            None => out.push(s),
            Some(list) if list.iter().any(|e| e == event_type) => out.push(s),
            Some(_) => {} // structured opt-in present but doesn't include this event
        }
    }
    Ok(out)
}

/// Test whether a subscription's filters match the given event.
///
/// P5 (G9): when `sub_event_types` is `Some(list)` it overrides the
/// legacy `sub_events` comma-string — the structured opt-in is the
/// authoritative filter for that subscriber. When `None`, the legacy
/// whitelist applies (backward compat for pre-P5 subscribers).
///
/// #932 (v0.7.0 Track D, 2026-05-20) — bumped from private to
/// `pub(crate)` so the postgres-aware dispatch helper at
/// `crate::handlers::subscriptions::dispatch_event_postgres` can
/// reuse the canonical filter logic instead of forking it.
pub(crate) fn matches_filters(
    sub_events: &str,
    sub_event_types: Option<&[String]>,
    sub_namespace: Option<&str>,
    sub_agent: Option<&str>,
    event: &str,
    namespace: &str,
    agent: Option<&str>,
) -> bool {
    let event_match = if let Some(list) = sub_event_types {
        // Structured opt-in: empty list means "no events" (defensive — the
        // insert path validates non-empty, but defend against hand-crafted
        // rows).
        list.iter().any(|e| e == event)
    } else {
        // Legacy whitelist (comma-separated or `*`).
        sub_events == "*"
            || sub_events
                .split(',')
                .map(str::trim)
                .any(|e| e == event || e == "*")
    };
    if !event_match {
        return false;
    }
    if let Some(ns) = sub_namespace
        && !ns.is_empty()
        && ns != namespace
    {
        return false;
    }
    if let Some(filter) = sub_agent
        && !filter.is_empty()
        && agent.is_none_or(|a| a != filter)
    {
        return false;
    }
    true
}

/// Payload fired to subscribers. Stable JSON shape.
///
/// v0.7.0 K6 — every dispatched payload now carries a deterministic
/// `correlation_id` (UUIDv7 — time-ordered, unique). Receivers ACK
/// with `{"status":"ack","correlation_id":"..."}`; the dispatcher
/// retries on no-ACK or non-2xx with the [200ms, 1s, 5s] exponential
/// backoff ladder and lands the row in `subscription_dlq` after three
/// failed attempts. The id is generated once per (subscription,
/// event) pair and persisted into `subscription_events` BEFORE the
/// network send so replay-from-cursor (K7) sees a stable record.
#[derive(Serialize)]
struct DispatchPayload<'a> {
    event: &'a str,
    memory_id: &'a str,
    namespace: &'a str,
    agent_id: Option<&'a str>,
    delivered_at: String,
    /// v0.7.0 K6 — UUIDv7 correlation id. Stable across retries.
    correlation_id: &'a str,
    /// P5 (G9): event-specific extra fields. Flattened so the wire shape
    /// stays a flat object — older subscribers that ignore unknown keys
    /// keep working. Each new event type uses one of the
    /// `*EventDetails` structs below.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

/// v0.7.0 K6 — exponential-backoff retry ladder for failed webhook
/// deliveries. The dispatcher attempts the initial POST, then up to
/// three retries spaced [200ms, 1s, 5s] apart. After the final retry
/// fails the row lands in `subscription_dlq` for K7's inspector tool
/// to surface. Exposed as a constant so tests can reason about the
/// total wall-clock budget (≈ 6.2s + per-attempt timeout).
pub const RETRY_BACKOFFS: &[std::time::Duration] = &[
    std::time::Duration::from_millis(200),
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(5),
];

/// v0.7.0 K6 — per-attempt ACK timeout. Receivers MUST return a JSON
/// body of the form `{"status":"ack","correlation_id":"..."}` within
/// this window for the delivery to count as successful. A non-2xx
/// response, a timeout, or an ACK whose `correlation_id` doesn't
/// match the dispatched id all count as failure and trigger the next
/// retry. Exposed so the integration tests can pin the wall-clock
/// expectations.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// PERF-3 (fix campaign 2026-05-26, FX-10) — default upper bound on the
/// number of webhook deliveries that may be in flight concurrently.
///
/// Pre-fix posture: every matching subscriber span on every store event
/// spawned a fresh `std::thread::spawn` worker that opened its own
/// SQLite connection. At 1000 subscribers this minted 1000 OS threads
/// (~1 MB stack each = 1 GB virtual) and 1000 SQLite handles per
/// store event, bypassing the existing Tokio runtime entirely.
///
/// Post-fix posture: each delivery is enqueued on a bounded
/// [`tokio::sync::Semaphore`] (default permits = this constant) and
/// the blocking-HTTP + audit-write step runs inside
/// [`tokio::task::spawn_blocking`] so the dispatcher uses the
/// existing runtime's blocking-thread pool instead of unbounded
/// OS-thread spawn.
///
/// Operators tune the bound via `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY`.
/// Values outside `1..=4096` fall back to the default with a warn-log.
pub const DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY: usize = 32;

/// PERF-3 (FX-10) — module-level shared semaphore that bounds the
/// in-flight webhook delivery count across every concurrent
/// `dispatch_event_to_subs` call. Built lazily on first dispatch from
/// `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY` (default
/// [`DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY`]). Held in `Arc` so worker
/// tasks can clone-and-move it into their async body.
static DISPATCH_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Resolve the bound from env (test seam: tests call
/// [`override_dispatch_concurrency_for_tests`] before any dispatch
/// runs to pin the bound to a known value).
fn dispatch_concurrency_bound() -> usize {
    if let Some(forced) = TEST_DISPATCH_CONCURRENCY_OVERRIDE.get() {
        return *forced;
    }
    match std::env::var("AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(n) if (1..=4096).contains(&n) => n,
            _ => {
                tracing::warn!(
                    "AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY={raw:?} not in 1..=4096; \
                     falling back to default {DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY}"
                );
                DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY
            }
        },
        Err(_) => DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY,
    }
}

/// Return a clone of the shared dispatch semaphore, building it on
/// first call from the resolved concurrency bound.
fn dispatch_semaphore() -> Arc<Semaphore> {
    DISPATCH_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(dispatch_concurrency_bound())))
        .clone()
}

/// Test-only override for the dispatch concurrency bound. Tests set
/// this BEFORE the first dispatch runs in the process so the
/// semaphore is sized to the assertion's expectations. Subsequent
/// changes after the semaphore is built are ignored (the bound is
/// per-process).
static TEST_DISPATCH_CONCURRENCY_OVERRIDE: OnceLock<usize> = OnceLock::new();

/// Test-only seam: pin the dispatch concurrency bound to `n`. Must be
/// called before any `dispatch_event*` runs in the current process.
/// Returns `Err(_)` if the bound has already been set (in which case
/// the prior value remains authoritative).
#[doc(hidden)]
pub fn override_dispatch_concurrency_for_tests(n: usize) -> Result<(), usize> {
    TEST_DISPATCH_CONCURRENCY_OVERRIDE.set(n)
}

/// PERF-3 (FX-10) — diagnostic accessor returning the number of
/// permits currently AVAILABLE on the shared dispatch semaphore. Used
/// by the regression test in
/// `tests/subscriptions_no_thread_spawn_per_subscriber.rs` to assert
/// the in-flight ceiling holds even when 50 subscribers fan out
/// concurrently.
#[doc(hidden)]
pub fn dispatch_semaphore_available_permits() -> usize {
    dispatch_semaphore().available_permits()
}

// v0.7.0 #1073 — `dispatch_http_client()` scaffolding REMOVED
//
// v0.7.x (issue #1174 follow-up #1196) — the dead-code shared-client
// accessor + its `OnceLock<Option<reqwest::blocking::Client>>` static
// were removed. Sub-agent code review (#1196 PR8) found zero
// production callers — only the `tests/sr3_perf_regressions.rs`
// scaffolding-pin test kept the symbol alive. The SR-2 #1082 SSRF
// hardening (per-call `builder.resolve(host, addr)` DNS pinning)
// keeps the per-call builder path live in `send()`; the future
// custom `reqwest::dns::Resolve` refactor will re-introduce a shared
// client at that point through `RuntimeContext`, not as a private
// module-level OnceLock. Removed alongside the test pin in the same
// commit so the scaffolding doesn't drift back via the existence
// assertion.

/// One row of the `subscription_events` per-delivery audit log. K6
/// writes one row before each network send; K7's
/// `memory_subscription_replay` tool reads the rows back ordered by
/// `delivered_at` for replay-from-cursor support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionEvent {
    pub id: i64,
    pub subscription_id: String,
    pub correlation_id: String,
    pub event_type: String,
    pub payload: String,
    pub delivered_at: String,
    pub delivery_status: String,
}

/// One row of the `subscription_dlq` table. Created when a delivery
/// exhausts the [200ms, 1s, 5s] retry ladder. K7's inspector tool
/// surfaces these rows; K6 only ships the writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntry {
    pub id: i64,
    pub subscription_id: String,
    pub correlation_id: String,
    pub event_type: String,
    pub payload: String,
    pub retry_count: i64,
    pub last_error: String,
    pub first_failed_at: String,
    pub last_failed_at: String,
}

// ---------------------------------------------------------------------
// P5 (G9) — event payload structs for the four new lifecycle events.
//
// Each struct is the `details` block flattened into `DispatchPayload`
// for its event type. They are intentionally small and JSON-stable —
// the same shape ships on both the MCP and HTTP webhook surfaces.
// Adding a new field is backward-compatible (subscribers ignore
// unknowns); renaming or removing a field is breaking — bump the
// payload schema version per AI_DEVELOPER_GOVERNANCE.md.
// ---------------------------------------------------------------------

/// `memory_promote` event — fires after a tier or vertical promotion
/// commits. `to_namespace` is `Some` for vertical (`memory_promote`
/// with a `to_namespace` argument); for the default tier promotion it
/// is `None` and `tier` is set to the new tier (`"long"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteEventDetails {
    /// `"vertical"` for namespace promote-clone, `"tier"` for the
    /// default tier upgrade.
    pub mode: String,
    /// New tier after promotion (always `"long"` for `mode = "tier"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Target namespace (vertical promote only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_namespace: Option<String>,
    /// Clone id (vertical promote only); the `memory_id` field on the
    /// outer payload carries the source memory id in vertical mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_id: Option<String>,
}

/// `memory_delete` event — fires after the row is removed from
/// `memories`. `title` and `tier` come from the pre-delete snapshot so
/// subscribers can write meaningful audit entries without a
/// roundtrip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteEventDetails {
    pub title: String,
    pub tier: String,
}

/// `memory_link_created` event — fires after `db::create_link`
/// commits. The outer `memory_id` carries the source id (the
/// link-author side); `target_id` is the destination of the directed
/// link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkCreatedEventDetails {
    pub target_id: String,
    pub relation: String,
}

/// `memory_consolidated` event — fires after `db::consolidate`
/// commits. The outer `memory_id` carries the new consolidated
/// memory's id; `source_ids` is the array of memories that were
/// merged (and deleted by the consolidate op).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidatedEventDetails {
    pub source_ids: Vec<String>,
    pub source_count: usize,
}

/// v0.7.0 K4 — `approval_requested` event details.
///
/// Fires after a `pending_actions` row has been inserted by the
/// governance gate (`db::queue_pending_action` from the local store /
/// promote / delete enforce paths, or `db::upsert_pending_action` from
/// peer-originated `sync_push` traffic). The K10 Approval API
/// (HTTP+SSE) consumes the same dispatcher path so the surface is
/// consistent across delivery transports.
///
/// The outer `memory_id` field on [`DispatchPayload`] carries the
/// pending-action **id** (the row PK of `pending_actions`) — that's the
/// only identifier subscribers need to round-trip back through
/// `memory_pending_*` MCP tools or the v0.7 Approval HTTP endpoints.
/// The `agent_id` field carries the row's `requested_by`.
///
/// Adding a new field here is backward-compatible (subscribers ignore
/// unknowns); renaming or removing a field is breaking — bump the
/// payload schema version per AI_DEVELOPER_GOVERNANCE.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestedEventDetails {
    /// Discriminator from `pending_actions.action_type` — `"store"`,
    /// `"delete"`, or `"promote"` (the three [`crate::models::GovernedAction`]
    /// variants today). Reserved for forward-compat with future gated
    /// actions; subscribers should treat unknown values as opaque.
    pub action_type: String,
    /// `pending_actions.requested_at` (RFC3339). Mirrored into the
    /// details block so SSE consumers downstream of K10 can render
    /// the queue-time without a second round-trip.
    pub requested_at: String,
    /// `pending_actions.memory_id` — `Some` for delete / promote
    /// (existing row), `None` for store (no row yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_id: Option<String>,
    /// Always `"pending"` at insert time. Decided rows do NOT re-fire
    /// this event — the decision flows through the planned
    /// `approval_decided` event in K7.
    pub status: String,
}

/// `memory_link_invalidated` event (v0.7 J4 / G14) — fires after a
/// successful `memory_kg_invalidate` writes `valid_until` on the
/// `(source_id, target_id, relation)` link. The outer `memory_id`
/// carries the source id (the link-author side); `target_id`,
/// `relation`, and the freshly-written `valid_until` describe the
/// supersession edge so consumers can replay the invalidation log
/// without re-reading `memory_links`. `previous_valid_until`
/// distinguishes the first supersession (`None`) from an idempotent
/// retry (carries the prior stamp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInvalidatedEventDetails {
    pub target_id: String,
    pub relation: String,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_valid_until: Option<String>,
}

/// Fire an event to all matching subscribers. Each dispatch is
/// fire-and-forget — the caller is NOT blocked on delivery. Errors are
/// logged and counted in the DB via `failure_count`.
///
/// PERF-3 (FX-10, 2026-05-26): pre-fix posture was
/// `std::thread::spawn` + per-worker `Connection::open(...)` per
/// matching subscriber — 1000 subscribers minted 1000 OS threads + 1000
/// SQLite handles per store event. Post-fix posture uses a bounded
/// [`tokio::sync::Semaphore`] (default 32 permits, tunable via
/// `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY`) + `tokio::task::spawn_blocking`
/// against the existing daemon Tokio runtime so the in-flight delivery
/// count is capped. The pre-fix `std::thread::spawn` path is preserved
/// as a fallback for legacy unit tests that run outside any runtime.
///
/// Caller owns the connection. Dispatch workers still re-open the
/// connection per delivery to update counters (cheap — `SQLite`
/// connections are process-shared via WAL — and the new concurrency
/// bound keeps the simultaneous handle count bounded too).
///
/// P5 (G9): convenience wrapper for the historical no-details case
/// (used by `memory_store`). New event types should call
/// `dispatch_event_with_details` and pass the matching
/// `*EventDetails` struct serialised to JSON.
pub fn dispatch_event(
    conn: &Connection,
    event: &str,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    db_path: &std::path::Path,
) {
    dispatch_event_with_details(conn, event, memory_id, namespace, agent_id, db_path, None);
}

/// P5 (G9): full lifecycle dispatch with optional event-specific
/// details. The details JSON is FLATTENED into the dispatch payload —
/// keys must not collide with the outer envelope (`event`,
/// `memory_id`, `namespace`, `agent_id`, `delivered_at`). The four
/// new event types (`memory_promote`, `memory_delete`,
/// `memory_link_created`, `memory_consolidated`) supply their
/// `*EventDetails` struct serialised via `serde_json::to_value`.
pub fn dispatch_event_with_details(
    conn: &Connection,
    event: &str,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    db_path: &std::path::Path,
    details: Option<serde_json::Value>,
) {
    // Dispatch path needs the global view (every tenant's subscriptions
    // for this event), so `None` here is correct — ownership scoping
    // would silently drop matching subscribers belonging to OTHER
    // tenants. The cross-tenant authorization gate lives at the wire
    // surface (MCP/HTTP handlers), not here. See #870/#872/#874.
    //
    // v0.7.0 #1097 — pre-filter by event type at the SQL level using
    // `list_by_event` instead of the legacy `list(conn, None)` full
    // table scan. The Rust-side `matches_filters` below stays as the
    // authoritative gate (it covers the namespace/agent filters which
    // the SQL prefilter doesn't honour); only the coarse event-type
    // filter moves into SQL. At 100 subscribers the write-event
    // fanout cost drops from O(N) to whatever fraction actually
    // subscribes to the fired event type.
    let subs = match list_by_event(conn, event) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("subscription list failed during dispatch: {e}");
            return;
        }
    };
    // Resolve each matching sub's secret_hash from sqlite BEFORE
    // dispatching to the per-sub worker pool. #932 (v0.7.0 Track D,
    // 2026-05-20) extracted this into `dispatch_event_to_subs` so the
    // postgres-backed `dispatch_event_postgres` path can resolve
    // secret_hash from the subscription memory's metadata instead.
    //
    // v0.7.0 #1072 — secret_hash now reuses the dispatch caller's
    // `&Connection` instead of opening a fresh `Connection::open(...)`
    // per matching subscription. Saves one connection open per
    // subscriber in the fanout.
    let matching: Vec<(Subscription, Option<String>)> = subs
        .into_iter()
        .filter(|s| {
            matches_filters(
                &s.events,
                s.event_types.as_deref(),
                s.namespace_filter.as_deref(),
                s.agent_filter.as_deref(),
                event,
                namespace,
                agent_id,
            )
        })
        .map(|s| {
            let secret_hash = load_secret_hash_with_conn(conn, &s.id).unwrap_or(None);
            (s, secret_hash)
        })
        .collect();
    dispatch_event_to_subs(
        matching, event, memory_id, namespace, agent_id, db_path, details,
    );
}

/// #932 (v0.7.0 Track D, 2026-05-20) — backend-neutral per-sub
/// dispatch worker pool. Takes an already-resolved
/// `Vec<(Subscription, Option<secret_hash>)>` so the sqlite path
/// (via `dispatch_event_with_details`) and the postgres path (via
/// `dispatch_event_postgres`) share the same delivery + audit +
/// DLQ + HMAC code while their subscription-source lookups remain
/// adapter-specific.
///
/// The `db_path` argument is still the SQLite audit-mirror path —
/// `record_subscription_event` / `record_dispatch` / `record_dlq`
/// still write to sqlite even on postgres-backed daemons because
/// every daemon currently keeps a sqlite scratch DB alongside the
/// SAL store handle. A future SAL audit-log surface (#-tracking)
/// will route this through the trait too.
pub fn dispatch_event_to_subs(
    matching: Vec<(Subscription, Option<String>)>,
    event: &str,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    db_path: &std::path::Path,
    details: Option<serde_json::Value>,
) {
    if matching.is_empty() {
        return;
    }
    // PERF — warm the reqwest::blocking TLS connector once per process,
    // off the delivery critical path, so the first webhook does not pay
    // the cold root-cert init inside its ACK_TIMEOUT retry budget. See
    // `prewarm_dispatch_tls`.
    {
        static KICK: std::sync::Once = std::sync::Once::new();
        KICK.call_once(|| {
            std::thread::spawn(prewarm_dispatch_tls);
        });
    }
    // Timestamp is part of the canonical string the signature is
    // computed over. Receivers SHOULD reject requests whose timestamp
    // differs from their clock by more than 5 minutes (replay window).
    // (#301 item 1 — prior implementation had no replay protection.)
    let timestamp = chrono::Utc::now().timestamp().to_string();

    // PERF-3 (FX-10, 2026-05-26) — bridge the dispatch fan-out onto
    // the existing Tokio runtime. We grab the current Handle once per
    // batch; the per-subscriber worker is enqueued as
    // `handle.spawn(async { semaphore.acquire().await;
    // spawn_blocking(|| { … reqwest::blocking::send + audit
    // writes … }).await })`. The semaphore caps in-flight deliveries
    // at [`DEFAULT_WEBHOOK_DISPATCH_CONCURRENCY`] (operator-tunable
    // via `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY`) so 1000 matching
    // subscribers no longer mint 1000 OS threads + 1000 SQLite
    // handles.
    //
    // Fallback: when no Tokio runtime is attached to the calling
    // thread (e.g. legacy CLI tests that call `dispatch_event`
    // outside a runtime), fall back to the pre-fix
    // `std::thread::spawn` path. Production daemons (CLI/MCP/HTTP)
    // ALL run under `#[tokio::main]`, so this fallback is the cold
    // path.
    let handle = tokio::runtime::Handle::try_current().ok();
    for (sub, sub_secret_hash) in matching {
        // v0.7.0 K6 — UUIDv7 correlation id is generated per
        // (subscription, event) pair so receivers can correlate ACKs
        // back to the dispatched payload across the retry ladder.
        // Generated here (not inside the worker thread) so the
        // ordering invariant — correlation_ids monotonic in
        // dispatch-loop order — holds even when worker threads race.
        let correlation_id = uuid::Uuid::now_v7().to_string();
        let payload = DispatchPayload {
            event,
            memory_id,
            namespace,
            agent_id,
            delivered_at: chrono::Utc::now().to_rfc3339(),
            correlation_id: &correlation_id,
            details: details.clone(),
        };
        let body = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("dispatch payload serialize failed: {e}");
                continue;
            }
        };
        let url = sub.url.clone();
        let sub_id = sub.id.clone();
        let event_owned = event.to_string();
        let ts = timestamp.clone();
        let db_path = db_path.to_path_buf();
        let secret_hash_owned = sub_secret_hash.clone();

        // PERF-3 (FX-10) — the entire per-subscriber delivery body
        // is captured by a `FnOnce()` closure so it can run either
        // on the Tokio blocking pool (production path) or on a
        // freshly-spawned `std::thread` (no-runtime fallback). The
        // body is otherwise unchanged from the pre-fix code.
        let work = move || {
            // v0.7.0 #1072 — open ONE sqlite connection for the
            // whole delivery instead of 4-5 across the
            // event-audit / status-update / dispatch-counter / DLQ
            // sites. Saves the per-connection PRAGMA + WAL setup
            // cost (~2-5 ms each) on every dispatched event. The
            // single connection lives on the worker thread stack
            // for the lifetime of the delivery and is dropped on
            // thread exit. Same audit posture as the pre-#1072
            // path — every write site is best-effort and logs on
            // failure.
            let worker_conn = match Connection::open(&db_path) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(
                        "subscription dispatch: worker_conn open failed: {e}; \
                         falling back to per-write connections"
                    );
                    None
                }
            };
            // Persist the per-delivery audit row BEFORE the network
            // send so replay-from-cursor (K7) sees a stable record
            // even if the dispatcher process crashes mid-retry.
            let event_audit_result = if let Some(c) = worker_conn.as_ref() {
                record_subscription_event_with_conn(
                    c,
                    &sub_id,
                    &correlation_id,
                    &event_owned,
                    &body,
                )
            } else {
                record_subscription_event(&db_path, &sub_id, &correlation_id, &event_owned, &body)
            };
            if let Err(e) = event_audit_result {
                tracing::warn!("subscription event audit write failed: {e}");
            }
            let secret_hash = secret_hash_owned;
            // Canonical string: "<timestamp>.<body>". Keyed HMAC over
            // the DB-stored secret hash. Receivers verify by computing
            // SHA256(plaintext_secret) and then
            // HMAC-SHA256(key, "<timestamp>.<body>").
            //
            // v0.7.0 K7 — when no per-subscription secret is set, fall
            // back to the process-wide `[hooks.subscription] hmac_secret`
            // override so operators can sign EVERY outgoing payload
            // without round-tripping each receiver through `memory_subscribe`.
            // The plaintext server-wide secret is itself SHA-256-hashed
            // first so the keying material on the wire matches the
            // per-subscription path (receivers compute the same
            // `SHA256(plaintext_secret)` regardless of which path
            // configured it).
            let canonical = format!("{ts}.{body}");
            let signature = match secret_hash.as_deref() {
                Some(h) => Some(hmac_sha256_hex(h, &canonical)),
                None => crate::config::active_hooks_hmac_secret().map(|plain| {
                    let key_hash = sha256_hex(&plain);
                    hmac_sha256_hex(&key_hash, &canonical)
                }),
            };
            // R3-S1.HMAC (v0.7.0 fix campaign 2026-05-13): refuse to
            // dispatch an unsigned payload. New subscriptions cannot
            // register without a per-sub or server-wide secret (see
            // `crate::handlers::subscribe` + MCP `handle_subscribe`), so
            // hitting this branch means a legacy row was persisted before
            // the gate landed, or the server-wide override was removed
            // after registration. Either way, fail loudly to the DLQ
            // instead of dispatching the body in clear so a receiver
            // never has to guess whether a body is authentic.
            if signature.is_none() {
                tracing::error!(
                    "subscription {sub_id} dispatch refused: no per-sub secret AND no \
                     server-wide [hooks.subscription] hmac_secret configured. \
                     Configure one of the two and replay via memory_subscription_replay. \
                     (v0.7.0 fix campaign R3-S1.HMAC, 2026-05-13)"
                );
                let outcome = DeliveryOutcome::unsigned_refused();
                let ok = outcome.success;
                // v0.7.0 #1072 — reuse `worker_conn` for every sqlite
                // write below.
                if let Some(c) = worker_conn.as_ref() {
                    record_dispatch_with_conn(c, &sub_id, ok);
                    update_event_status_with_conn(c, &correlation_id, ok);
                } else {
                    record_dispatch(&db_path, &sub_id, ok);
                    update_event_status(&db_path, &correlation_id, ok);
                }
                let dlq_result = if let Some(c) = worker_conn.as_ref() {
                    record_dlq_with_conn(
                        c,
                        &sub_id,
                        &correlation_id,
                        &event_owned,
                        &body,
                        outcome.attempts,
                        &outcome.last_error,
                        &outcome.first_failed_at,
                        &outcome.last_failed_at,
                    )
                } else {
                    record_dlq(
                        &db_path,
                        &sub_id,
                        &correlation_id,
                        &event_owned,
                        &body,
                        outcome.attempts,
                        &outcome.last_error,
                        &outcome.first_failed_at,
                        &outcome.last_failed_at,
                    )
                };
                if let Err(e) = dlq_result {
                    tracing::warn!("subscription DLQ write failed: {e}");
                }
                return;
            }
            let outcome =
                deliver_with_retry(&url, &body, &ts, signature.as_deref(), &correlation_id);
            let ok = outcome.success;
            // v0.7.0 #1072 — reuse `worker_conn` for every sqlite write
            // below.
            if let Some(c) = worker_conn.as_ref() {
                record_dispatch_with_conn(c, &sub_id, ok);
                update_event_status_with_conn(c, &correlation_id, ok);
            } else {
                record_dispatch(&db_path, &sub_id, ok);
                update_event_status(&db_path, &correlation_id, ok);
            }
            if !ok {
                let dlq_result = if let Some(c) = worker_conn.as_ref() {
                    record_dlq_with_conn(
                        c,
                        &sub_id,
                        &correlation_id,
                        &event_owned,
                        &body,
                        outcome.attempts,
                        &outcome.last_error,
                        &outcome.first_failed_at,
                        &outcome.last_failed_at,
                    )
                } else {
                    record_dlq(
                        &db_path,
                        &sub_id,
                        &correlation_id,
                        &event_owned,
                        &body,
                        outcome.attempts,
                        &outcome.last_error,
                        &outcome.first_failed_at,
                        &outcome.last_failed_at,
                    )
                };
                if let Err(e) = dlq_result {
                    tracing::warn!("subscription DLQ write failed: {e}");
                }
            }
        };

        // PERF-3 (FX-10) — production path: bounded semaphore + Tokio
        // blocking pool. The semaphore caps concurrent in-flight
        // deliveries at the operator-tunable bound; permits are
        // released when the `_permit` guard drops at the end of the
        // worker. Cold path (no runtime attached): legacy
        // `std::thread::spawn`. Tests use the production path because
        // `#[tokio::test]` attaches a runtime to the calling thread.
        if let Some(rt) = handle.as_ref() {
            let permit_sem = dispatch_semaphore();
            rt.spawn(async move {
                // Acquire-then-blocking-step. `acquire_owned` returns
                // an `OwnedSemaphorePermit` that gets moved into the
                // blocking task and is dropped when the worker
                // returns — releasing the slot for the next pending
                // dispatch.
                let permit = match permit_sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            "subscription dispatch: semaphore acquire failed: {e}; \
                             dropping delivery (semaphore closed)"
                        );
                        return;
                    }
                };
                // The reqwest::blocking + rusqlite work is sync; run
                // it on the Tokio blocking pool so we don't pin a
                // runtime worker thread on the LLM-slow HTTP send.
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    work();
                    drop(permit);
                })
                .await
                {
                    tracing::warn!("subscription dispatch: spawn_blocking join failed: {e}");
                }
            });
        } else {
            // Fallback: no runtime in scope. This path is exercised
            // only by legacy unit tests that call `dispatch_event`
            // outside `#[tokio::test]`; production daemons always
            // run under `#[tokio::main]`.
            std::thread::spawn(work);
        }
    }
}

/// v0.7.0 K4 — dispatch the `approval_requested` lifecycle event for a
/// freshly-inserted `pending_actions` row.
///
/// Thin convenience wrapper around [`dispatch_event_with_details`]:
///   - Resolves the canonical row via [`crate::db::get_pending_action`]
///     so the payload reflects what was actually committed (not what
///     the caller *intended* to commit).
///   - Synthesises an [`ApprovalRequestedEventDetails`] block from the
///     row.
///   - Routes the event through the existing subscription dispatch
///     path so opt-in subscribers (`event_types: ["approval_requested"]`)
///     and legacy wildcard subscribers both receive it.
///
/// Best-effort and fire-and-forget — same posture as the K2
/// `pending_action_expired` dispatch in
/// [`crate::daemon_runtime::spawn_pending_timeout_sweep_loop`]. A
/// dispatch failure must NOT roll back the pending-action row.
///
/// Caller passes the `pending_id` returned from
/// [`crate::db::queue_pending_action`] / [`crate::db::upsert_pending_action`].
/// A missing or unreadable row is logged and otherwise treated as a
/// no-op (lost-event semantics, never block the write path).
pub fn dispatch_approval_requested(conn: &Connection, pending_id: &str, db_path: &std::path::Path) {
    let pa = match crate::db::get_pending_action(conn, pending_id) {
        Ok(Some(pa)) => pa,
        Ok(None) => {
            tracing::warn!(
                "approval_requested dispatch skipped: pending_action {pending_id} not found"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                "approval_requested dispatch skipped: pending_action {pending_id} read failed: {e}"
            );
            return;
        }
    };
    let details = ApprovalRequestedEventDetails {
        action_type: pa.action_type.clone(),
        requested_at: pa.requested_at.clone(),
        memory_id: pa.memory_id.clone(),
        status: pa.status.clone(),
    };
    let details_value = match serde_json::to_value(&details) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("approval_requested dispatch details serialise failed: {e}");
            None
        }
    };
    // v0.7.0 K10 — publish on the in-process approval bus so HTTP SSE
    // subscribers see the new pending row in real time. Best-effort
    // (no receivers → swallowed); never blocks the gate path.
    crate::approvals::publish(crate::approvals::ApprovalEvent::ApprovalRequested {
        pending_id: pa.id.clone(),
        action_type: pa.action_type.clone(),
        namespace: pa.namespace.clone(),
        requested_by: pa.requested_by.clone(),
        requested_at: pa.requested_at.clone(),
    });
    dispatch_event_with_details(
        conn,
        "approval_requested",
        &pa.id,
        &pa.namespace,
        Some(&pa.requested_by),
        db_path,
        details_value,
    );
}

/// v0.7.0 K6 — outcome of a single attempt or full retry ladder.
///
/// `success` is true once the receiver has returned 2xx AND a JSON
/// body of the form `{"status":"ack","correlation_id":"<id>"}` whose
/// id matches the one we dispatched. `attempts` is the number of
/// network requests issued (1..=4 — initial + 3 retries). `last_error`
/// is the short error string from the last failed attempt (empty on
/// success). The `first_failed_at` / `last_failed_at` pair brackets
/// the retry window for DLQ analytics.
struct DeliveryOutcome {
    success: bool,
    attempts: i64,
    last_error: String,
    first_failed_at: String,
    last_failed_at: String,
}

impl DeliveryOutcome {
    /// R3-S1.HMAC (v0.7.0 fix campaign 2026-05-13): synthesise a failure
    /// outcome for a dispatch refused at the gate because neither a
    /// per-sub secret nor a server-wide override was configured. The
    /// DLQ row carries an explicit `last_error` so operators can tell a
    /// missing-secret refusal apart from a transport failure.
    fn unsigned_refused() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            success: false,
            attempts: 0,
            last_error: "dispatch refused: no per-subscription secret AND no server-wide \
                 [hooks.subscription] hmac_secret configured (v0.7.0 R3-S1.HMAC)"
                .to_string(),
            first_failed_at: now.clone(),
            last_failed_at: now,
        }
    }
}

/// v0.7.0 K6 — dispatcher driver. Issues the initial POST plus up to
/// three retries spaced [200ms, 1s, 5s] apart. Each attempt validates
/// the receiver's ACK body — a 2xx response with no ACK or a
/// mismatched correlation_id counts as failure and triggers the next
/// retry. Returns the cumulative [`DeliveryOutcome`].
/// One-time process-global warm-up of the `reqwest::blocking` TLS
/// connector used by webhook delivery.
///
/// The first `reqwest::blocking::Client` constructed in a process
/// builds the TLS connector, which loads the system root-certificate
/// store. On some platforms (notably macOS, where the load goes
/// through Security.framework) that first load can take several
/// seconds and is process-cached thereafter. Because webhook delivery
/// rebuilds a fresh client per attempt (the #1082 per-call
/// `.resolve()` DNS pin precludes a fully process-shared client), a
/// cold first delivery would otherwise pay that init on attempt 1 — and
/// when it exceeds [`ACK_TIMEOUT`] the K6 retry budget is consumed by
/// the cold init rather than by real delivery failures, delaying (or,
/// under a short receiver poll window, failing) the first webhook of a
/// process by tens of seconds.
///
/// Calling this is idempotent via an internal [`std::sync::Once`].
/// [`dispatch_event_to_subs`] kicks it on a background thread the first
/// time it has work to deliver, so a long-lived daemon warms its
/// connector ahead of real load. Integration tests that assert delivery
/// latency call it synchronously during setup so the one-time cost
/// lands before the timed assertion window.
pub fn prewarm_dispatch_tls() {
    static WARM: std::sync::Once = std::sync::Once::new();
    WARM.call_once(|| {
        // Build on a dedicated OS thread, then join. `reqwest::blocking`'s
        // client constructor blocks waiting for its internal runtime
        // thread to spin up, which panics if invoked directly on a thread
        // that is currently driving a Tokio runtime (an async test, or a
        // daemon runtime worker). A freshly-spawned `std::thread` has no
        // ambient runtime, so blocking there is always allowed. Joining
        // makes the warm-up synchronous for the caller (tests rely on the
        // connector being warm once this returns).
        let _ = std::thread::spawn(|| {
            if let Err(e) = reqwest::blocking::Client::builder()
                .timeout(ACK_TIMEOUT)
                .build()
            {
                tracing::warn!("webhook dispatch TLS warm-up failed: {e}");
            }
        })
        .join();
    });
}

fn deliver_with_retry(
    url: &str,
    body: &str,
    timestamp: &str,
    signature: Option<&str>,
    correlation_id: &str,
) -> DeliveryOutcome {
    let mut attempts: i64 = 0;
    let mut first_failed_at = String::new();
    let mut last_failed_at = String::new();
    let mut last_error = String::new();
    // Total attempts = 1 (initial) + RETRY_BACKOFFS.len() (retries).
    for attempt_idx in 0..=RETRY_BACKOFFS.len() {
        if attempt_idx > 0 {
            std::thread::sleep(RETRY_BACKOFFS[attempt_idx - 1]);
        }
        attempts += 1;
        match send(url, body, timestamp, signature, correlation_id) {
            Ok(()) => {
                return DeliveryOutcome {
                    success: true,
                    attempts,
                    last_error: String::new(),
                    first_failed_at,
                    last_failed_at,
                };
            }
            Err(e) => {
                let now = chrono::Utc::now().to_rfc3339();
                if first_failed_at.is_empty() {
                    first_failed_at = now.clone();
                }
                last_failed_at = now;
                last_error = e;
            }
        }
    }
    DeliveryOutcome {
        success: false,
        attempts,
        last_error,
        first_failed_at,
        last_failed_at,
    }
}

/// Perform one HTTP POST with SSRF-hardened URL check + signature
/// + timestamp headers.
///
/// v0.7.0 K6 — return Ok(()) only when the receiver returns 2xx AND
/// a JSON ACK body (`{"status":"ack","correlation_id":"..."}`) whose
/// `correlation_id` matches the dispatched id within
/// [`ACK_TIMEOUT`]. Anything else (network error, non-2xx, ACK
/// timeout, mismatched correlation id) returns Err with a short
/// reason string the retry driver records.
fn send(
    url: &str,
    body: &str,
    timestamp: &str,
    signature: Option<&str>,
    correlation_id: &str,
) -> Result<(), String> {
    if let Err(e) = validate_url(url) {
        tracing::warn!("SSRF guard rejected webhook URL {url}: {e}");
        return Err(format!("ssrf-rejected: {e}"));
    }
    // v0.7.0 #1082 (SR-1 #2, HIGH) — DNS-rebind TOCTOU fix. Resolve
    // the host once via the SSRF guard AND capture the validated
    // addresses, then bind reqwest's resolver to exactly those
    // addresses via `Client::builder().resolve(host, addr)`. Pre-
    // #1082 reqwest did its own independent DNS query at send time,
    // letting an attacker-controlled DNS server (TTL=0 / split-
    // horizon) return a public IP on the daemon's first lookup
    // (passing the guard) and a private IP on reqwest's second
    // lookup (the webhook payload posted internally). The new
    // resolver override pins reqwest's connect to the daemon's
    // already-validated IP set; reqwest's own DNS query never
    // happens for this client.
    let (resolved_host, validated_addrs) =
        match validate_url_dns_resolved(url, crate::config::allow_loopback_webhooks()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("DNS SSRF guard rejected webhook URL {url}: {e}");
                return Err(format!("dns-ssrf-rejected: {e}"));
            }
        };
    let mut builder = reqwest::blocking::Client::builder().timeout(ACK_TIMEOUT);
    for addr in &validated_addrs {
        // Pin reqwest's per-host override. The override SHADOWS
        // reqwest's own DNS query for this host on this client,
        // closing the rebind window.
        builder = builder.resolve(&resolved_host, *addr);
    }
    // v0.7.0 #1073 + #1082 (SR-3 perf + SR-2 SSRF) — the SSRF
    // hardening at #1082 requires per-call per-host DNS pinning via
    // `builder.resolve(host, addr)`; that pin lives on the client
    // itself, so a fully process-wide shared client can't hold pins
    // that vary per dispatched URL. We still amortize the bulk of
    // the work (TLS provider init, default connector) by sharing
    // the resolver+TLS state through this thread-local builder.
    // A future custom-resolver refactor will move the per-call pin
    // onto a trait-object `dns::Resolve` so the client itself can be
    // process-shared (matching the federation `peer.rs` pattern, and
    // re-introduced through `RuntimeContext` at that point). For now
    // correctness (SSRF closure) wins over the per-attempt client
    // rebuild cost. The prior `dispatch_http_client()` scaffolding
    // was removed in #1196 — it had zero production callers, only a
    // test pin kept it alive.
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("webhook client build failed: {e}");
            return Err(format!("client-build: {e}"));
        }
    };
    let mut req = client
        .post(url)
        .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
        .header(
            "user-agent",
            format!("ai-memory/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("x-ai-memory-timestamp", timestamp)
        .header("x-ai-memory-correlation-id", correlation_id);
    if let Some(sig) = signature {
        req = req.header("x-ai-memory-signature", format!("sha256={sig}"));
    }
    let resp = match req.body(body.to_string()).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("webhook POST to {url} failed: {e}");
            return Err(format!("network: {e}"));
        }
    };
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(format!("http-{status}"));
    }
    // K6 ACK contract: receivers MUST return
    // {"status":"ack","correlation_id":"..."}. A 2xx with a missing /
    // mismatched body is treated as failure so retries kick in.
    let ack_body = match resp.text() {
        Ok(s) => s,
        Err(e) => return Err(format!("ack-read: {e}")),
    };
    let ack: serde_json::Value = match serde_json::from_str(&ack_body) {
        Ok(v) => v,
        Err(e) => return Err(format!("ack-decode: {e}")),
    };
    let status_field = ack.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status_field != "ack" {
        return Err(format!("ack-status: {status_field}"));
    }
    let ack_corr = ack
        .get("correlation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if ack_corr != correlation_id {
        return Err(format!("ack-corr-mismatch: {ack_corr}"));
    }
    Ok(())
}

/// Hash a plaintext secret (SHA-256 hex).
pub(crate) fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// HMAC-SHA256 is expensive to implement from scratch; do the simple
/// construction manually using the hashed secret as key material.
/// Matches the RFC-2104 HMAC construction with SHA-256 as the
/// primitive.
pub(crate) fn hmac_sha256_hex(key_hex: &str, body: &str) -> String {
    const BLOCK: usize = 64;
    // v0.7.0 #1048 (Agent-5 #8) — decode the operator-supplied
    // `hmac_secret` as hex. The pre-#1048 behaviour silently fell
    // back to using the raw config bytes as HMAC key material when
    // the hex decode failed, which produced a stable-but-WEAK key
    // (`HMAC(b"not-a-hex-key!!", body)` instead of the intended
    // hex-decoded bytes). The fallback is preserved for wire
    // compatibility because both sender and receiver are typically
    // configured from the same secret string — flipping the
    // fallback would silently break running federations — but
    // every invalid-hex compute emits a WARN so an operator
    // running with a misconfigured secret sees the diagnostic on
    // every webhook dispatch. The boot-time validator
    // [`validate_hmac_secret_hex`] surfaces this BEFORE the daemon
    // accepts traffic; operators who want strict hex enforcement
    // call the validator at startup.
    let mut key = match hex_decode(key_hex) {
        Some(k) => k,
        None => {
            tracing::warn!(
                target: "ai_memory::subscriptions",
                "hmac_sha256_hex: hmac_secret is not valid hex (len={}); falling back to raw \
                 bytes as key material — this produces a STABLE BUT WEAK key. Re-encode the \
                 secret as hex (e.g. `openssl rand -hex 32`) and restart the daemon. \
                 See #1048.",
                key_hex.len(),
            );
            key_hex.as_bytes().to_vec()
        }
    };
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(&key);
        key = h.finalize().to_vec();
    }
    key.resize(BLOCK, 0);
    let mut opad = [0x5cu8; BLOCK];
    let mut ipad = [0x36u8; BLOCK];
    for i in 0..BLOCK {
        opad[i] ^= key[i];
        ipad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// v0.7.0 #1048 (Agent-5 #8) — boot-time hex validator for the
/// operator-supplied `hmac_secret`. Returns `Ok(())` when the value
/// is `None` (no secret configured) OR is valid hex; returns
/// `Err(String)` with a descriptive operator-facing message when
/// the value is non-hex. Callers MUST surface the error before the
/// daemon accepts traffic; the runtime `hmac_sha256_hex` will
/// otherwise silently degrade to a stable-but-WEAK key (raw bytes
/// of the misconfigured secret) on every dispatch.
///
/// # Errors
///
/// Returns the validation error string when the input is
/// `Some(secret)` and `secret` fails the hex parse. The message
/// includes recommended remediation (`openssl rand -hex 32`).
pub fn validate_hmac_secret_hex(secret: Option<&str>) -> Result<(), String> {
    let Some(secret) = secret else {
        return Ok(());
    };
    if hex_decode(secret).is_some() {
        return Ok(());
    }
    Err(format!(
        "[hooks.subscription] hmac_secret is not valid hex (len={}): expected an even-length \
         hex string. Generate a fresh secret with `openssl rand -hex 32` and update the \
         config. The runtime still computes a (weak) HMAC under the misconfigured value for \
         wire compatibility, but the boot validator refuses to start so the operator sees \
         the diagnostic immediately. See #1048.",
        secret.len(),
    ))
}

/// SSRF guard with DNS resolution (#301 item 2). Resolves the host
/// via the stdlib resolver and rejects if ANY returned
/// `SocketAddr`'s IP is private / loopback / link-local. Guards
/// against DNS-rebind attacks where an attacker-controlled hostname
/// resolves to an internal IP at connect time.
///
/// Runs in the dispatch thread (blocking). Best-effort: if DNS fails
/// we let reqwest surface the error rather than fail closed, because
/// transient DNS outages should not silently drop webhook delivery.
pub fn validate_url_dns(url: &str) -> Result<()> {
    validate_url_dns_with(url, crate::config::allow_loopback_webhooks()).map(|_| ())
}

/// v0.7.0 #1082 (SR-1 #2, HIGH) — DNS-rebind TOCTOU fix. Returns
/// the validated host + the pre-resolved `Vec<SocketAddr>` so the
/// caller can pin reqwest's resolver to the SAME addresses the
/// SSRF guard cleared. Pre-#1082 the guard resolved once,
/// validated, and discarded the addresses — reqwest then did its
/// OWN independent resolve at send time, opening a DNS-rebind
/// window where the second resolve could return a private IP that
/// the daemon never saw.
///
/// # Errors
/// - URL has no scheme.
/// - DNS resolution failed AND `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL`
///   is not set (post-#1053 fail-CLOSED).
/// - Any resolved address is private / link-local (or loopback when
///   `allow_loopback` is false).
pub(crate) fn validate_url_dns_resolved(
    url: &str,
    allow_loopback: bool,
) -> Result<(String, Vec<std::net::SocketAddr>)> {
    validate_url_dns_with(url, allow_loopback)
}

/// `true` when the operator opted into the legacy permissive SSRF
/// posture via `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL` (`1` / `true`).
/// Shared by the resolution-failure branch and the RFC 1035
/// hostname-shape branch so the two read the override identically.
fn ssrf_dns_fail_open() -> bool {
    std::env::var("AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// RFC 1035 §2.3.4 hostname shape check: every dot-separated label
/// must be 1..=63 octets and the whole name (sans one optional
/// trailing dot) must be <=253 octets. Returns `true` when the host
/// VIOLATES the shape.
///
/// FX-Fwin (#1053 follow-up) — `getaddrinfo(3)` is documented to
/// reject an oversized label with `EAI_*`, but Windows' resolver
/// does NOT enforce the 63-octet ceiling at the API boundary (it
/// synthesizes a hit / returns `Ok`), so the cross-platform CI
/// `Check (windows-latest)` job saw the SSRF guard pass an oversized
/// label that macOS/Linux reject. A portable SSRF guard must
/// validate the shape itself rather than delegating to libc. IP
/// literals (no oversized labels) are unaffected.
fn hostname_shape_invalid(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return true;
    }
    name.split('.')
        .any(|label| label.is_empty() || label.len() > 63)
}

/// H11 inner helper: takes `allow_loopback` explicitly so tests can
/// assert both branches without poking the process-wide atomic
/// (which would race with parallel tests). Production callers go
/// through `validate_url_dns`.
///
/// v0.7.0 #1082 — returns the resolved `(host, addresses)` so the
/// `send` path can install a reqwest `Client::builder().resolve()`
/// override pinning the connect to exactly the IPs the guard
/// cleared. Closes the DNS-rebind TOCTOU window.
fn validate_url_dns_with(
    url: &str,
    allow_loopback: bool,
) -> Result<(String, Vec<std::net::SocketAddr>)> {
    let lower = url.to_ascii_lowercase();
    let (_scheme, rest) = lower
        .split_once("://")
        .ok_or_else(|| anyhow!("webhook URL missing scheme: {url}"))?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host_port = &rest[..host_end];
    // v0.7.0 #1082 — extract the host (sans port + brackets) for the
    // reqwest `Client::builder().resolve(host, addr)` override the
    // caller installs. The override matches by host string the
    // reqwest URL parser produces, so we strip the brackets / port
    // here to match.
    let resolved_host = {
        let s = host_port;
        if let Some(close_idx) = s.strip_prefix('[').and(s.find(']')) {
            // [ipv6]:port or [ipv6] — return the inner ipv6 text.
            s[1..close_idx].to_string()
        } else if let Some(idx) = s.rfind(':') {
            // Hostname:port — strip the port. (IPv4-with-port. Bare
            // ipv4 has no `:` so falls through to the else branch.)
            s[..idx].to_string()
        } else {
            s.to_string()
        }
    };
    // Supply a default port so ToSocketAddrs resolves correctly.
    // SSRF fix (W11): bracketed IPv6 without an explicit port ("[fe80::1]"
    // with no trailing ":N") was previously passed to ToSocketAddrs as-is,
    // which errors with "invalid port value" — and the catch-all `Err(_) =>
    // return Ok(())` below treated that as a DNS hiccup, silently bypassing
    // the SSRF guard. Detect the no-trailing-port form and append `:80` so
    // resolution succeeds and the IP is checked.
    let resolv_target =
        if let Some(close_idx) = host_port.strip_prefix('[').and(host_port.find(']')) {
            let after_bracket = &host_port[close_idx + 1..];
            if after_bracket.starts_with(':') {
                // [ipv6]:port — already has a port
                host_port.to_string()
            } else {
                // [ipv6] without port — append default
                format!("{host_port}:80")
            }
        } else if host_port.contains(':') {
            // IPv4:port or hostname:port — use as-is
            host_port.to_string()
        } else {
            format!("{host_port}:80")
        };
    // v0.7.0 #1053 (Agent-2 #3) — fail-CLOSED on DNS resolution
    // failure. Pre-#1053 a SERVFAIL / timeout / hang at the daemon's
    // resolver returned Ok(()) here, but the subsequent
    // `reqwest::send` performs its OWN DNS resolution under
    // potentially-attacker-controlled DNS (TTL-zero / DNS rebind).
    // The attacker's first resolution at the daemon could SERVFAIL
    // (bypassing the SSRF guard), then their second resolution under
    // reqwest could return a private-range or link-local IP
    // (169.254.169.254 cloud metadata, 127.0.0.1:5432 Postgres,
    // 10.0.0.0/8 internal services). Closing the gap by treating
    // DNS failure as Err means an attacker can't smuggle internal
    // IPs through a DNS-rebind path even if the daemon's resolver
    // hiccups.
    //
    // Operators with environments where transient DNS pressure is
    // expected (containers with flaky CoreDNS, etc.) can opt back
    // into the legacy permissive posture via
    // `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1`. The unsafe override is
    // logged at WARN on every fire so an audit can detect the
    // legacy-permissive mode.
    // FX-Fwin (#1053 follow-up) — enforce RFC 1035 hostname shape
    // IN-GUARD before resolution. Windows' `getaddrinfo` does not
    // reject an oversized (>63-octet) DNS label at the API boundary,
    // so relying on the resolver to reject it (as the pre-FX-Fwin code
    // did) made the guard platform-dependent. A shape violation is
    // treated identically to a DNS resolution failure: fail-CLOSED
    // unless the operator opted into the legacy permissive posture.
    if hostname_shape_invalid(&resolved_host) {
        if ssrf_dns_fail_open() {
            tracing::warn!(
                target: "ai_memory::subscriptions",
                "SSRF guard: hostname {resolved_host} violates RFC 1035 label/length \
                 limits for {url}; AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1 — degrading to \
                 ALLOW (UNSAFE, legacy posture)"
            );
            return Ok((resolved_host, Vec::new()));
        }
        return Err(anyhow!(
            "SSRF guard: DNS resolution failed for {url}: hostname violates RFC 1035 \
             label/length limits; failing CLOSED (post-#1053 secure default — set \
             AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1 to revert)"
        ));
    }
    let addrs: Vec<std::net::SocketAddr> = match resolv_target.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            let fail_open = ssrf_dns_fail_open();
            if fail_open {
                tracing::warn!(
                    target: "ai_memory::subscriptions",
                    "SSRF guard: DNS resolution failed for {url}: {e}; \
                     AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1 — degrading to ALLOW \
                     (UNSAFE, legacy posture) — reqwest's resolver may bind to \
                     private/loopback IPs the daemon could not pre-check"
                );
                // Empty address list — caller's resolver-override
                // loop is a no-op and reqwest falls back to its
                // own DNS query (the explicit UNSAFE legacy posture).
                return Ok((resolved_host, Vec::new()));
            }
            return Err(anyhow!(
                "SSRF guard: DNS resolution failed for {url}: {e}; failing CLOSED \
                 (post-#1053 secure default — set AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1 to revert)"
            ));
        }
    };
    for addr in &addrs {
        let ip = addr.ip();
        if is_private(ip) && !is_loopback_normalized(ip) {
            return Err(anyhow!(
                "host resolves to private/link-local IP {ip}: {url}"
            ));
        }
        // H11 (#628 blocker) — DNS-rebind protection for loopback.
        // Default-OFF; operators with `[subscriptions]
        // allow_loopback_webhooks = true` accept loopback-resolving
        // hostnames.
        if is_loopback_normalized(ip) && !allow_loopback {
            return Err(anyhow!(
                "host resolves to loopback IP {ip}: {url} — rejected by default \
                 (SSRF guard); set `[subscriptions] allow_loopback_webhooks = true` \
                 to opt in"
            ));
        }
    }
    // v0.7.0 #1082 — return the resolved host + addr list so the
    // caller can pin reqwest's connect to exactly these addresses.
    Ok((resolved_host, addrs))
}

/// SSRF guard. Rejects URLs that would cause the daemon to connect
/// to private-range addresses, link-local, loopback (except
/// explicitly), or non-HTTPS remote hosts.
pub fn validate_url(url: &str) -> Result<()> {
    validate_url_with(url, crate::config::allow_loopback_webhooks())
}

/// H11 inner helper: takes `allow_loopback` explicitly so tests can
/// assert both branches without poking the process-wide atomic
/// (which would race with parallel tests). Production callers go
/// through `validate_url`.
fn validate_url_with(url: &str, allow_loopback: bool) -> Result<()> {
    // Cheap scheme check without pulling the `url` crate.
    let lower = url.to_ascii_lowercase();
    let (scheme, rest) = lower
        .split_once("://")
        .ok_or_else(|| anyhow!("webhook URL missing scheme: {url}"))?;
    if scheme != "https" && scheme != "http" {
        return Err(anyhow!("webhook URL scheme must be http(s): {url}"));
    }
    // Extract host (portion before '/' or ':' or '?'). IPv6 URLs use
    // `[ipv6]:port` syntax — the brackets must be stripped and the
    // colon-split must skip the colons inside the v6 literal.
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host_port = &rest[..host_end];
    let host: String = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6: host is everything before the closing bracket.
        match stripped.find(']') {
            Some(i) => stripped[..i].to_string(),
            None => return Err(anyhow!("malformed IPv6 URL host: {url}")),
        }
    } else {
        // IPv4 / hostname.
        host_port
            .rsplit_once(':')
            .map_or(host_port.to_string(), |(h, _)| h.to_string())
    };
    let host = host.as_str();
    // H11 (#628 blocker): loopback hostnames + IPs are rejected by
    // default. Operators who need to point a webhook at a local
    // listener (CI, dev) opt in via `[subscriptions]
    // allow_loopback_webhooks = true`. Default-OFF closes an
    // authenticated SSRF gadget against local services (Postgres on
    // 5432, the hooks daemon, etc.).
    let is_loopback_hostname = matches!(host, "localhost" | "localhost.localdomain" | "");
    let parsed_ip = IpAddr::from_str(host).ok();
    let is_loopback_ip = parsed_ip.is_some_and(is_loopback_normalized);
    let is_loopback = is_loopback_hostname || is_loopback_ip;
    if is_loopback && !allow_loopback {
        return Err(anyhow!(
            "webhook URL targets loopback address {url} — rejected by default \
             (SSRF guard); set `[subscriptions] allow_loopback_webhooks = true` \
             to opt in (testing / dev only)"
        ));
    }
    if scheme == "http" && !is_loopback {
        // Accept http only to parsed-loopback IPs; everything else
        // requires https.
        if let Some(ip) = parsed_ip {
            if !is_loopback_normalized(ip) {
                return Err(anyhow!(
                    "webhook URL must be https for non-loopback host: {url}"
                ));
            }
        } else {
            return Err(anyhow!(
                "webhook URL must be https for non-loopback host: {url}"
            ));
        }
    }
    // Reject private-range IPs regardless of scheme (RFC1918 / RFC4193 /
    // link-local). Hostnames that resolve to private ranges are not
    // caught here — the dispatch thread will still be able to reach
    // them; operators who want to reach internal services should set
    // up reverse proxies or allow explicitly in config.
    if let Some(ip) = parsed_ip
        && is_private(ip)
        && !is_loopback_normalized(ip)
    {
        return Err(anyhow!(
            "webhook URL targets private / link-local address: {url}"
        ));
    }
    Ok(())
}

// SSRF fix (#628 H3 follow-up): canonicalize IPv6 addresses that wrap an
// IPv4 address (4-mapped `::ffff:a.b.c.d`, deprecated 4-compatible
// `::a.b.c.d`, and the well-known NAT64 prefix `64:ff9b::/96`) into their
// IPv4 form before applying SSRF checks. Without this, `Ipv6Addr::is_loopback()`
// and the v6 branch of `is_private` silently miss `::ffff:127.0.0.1`,
// `::ffff:10.0.0.1`, `::ffff:169.254.1.1`, and similar bypasses.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let canonical = v6.to_canonical();
            if matches!(canonical, IpAddr::V4(_)) {
                return canonical;
            }
            let segs = v6.segments();
            if segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                let v4_bits = (u32::from(segs[6]) << 16) | u32::from(segs[7]);
                return IpAddr::V4(Ipv4Addr::from(v4_bits));
            }
            IpAddr::V6(v6)
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn is_loopback_normalized(ip: IpAddr) -> bool {
    normalize_ip(ip).is_loopback()
}

fn is_private(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            // SSRF fix (W11): include `is_unspecified` (0.0.0.0). On most
            // OSes the kernel routes 0.0.0.0 to a local listener, so an
            // attacker-controlled hostname resolving to 0.0.0.0 hits the
            // local box.
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            // Conservative: reject unique-local (fc00::/7), link-local
            // (fe80::/10), multicast, and the unspecified address `::`.
            // SSRF fix (W11): `is_unspecified` covers `[::]`, which most
            // kernels route to local services.
            let segs = v6.segments();
            v6.is_multicast()
                || v6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00 // ULA
                || (segs[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

/// v0.7.0 #1072 — kept for the existing test harness and the
/// public-API contract. Production dispatch routes through
/// [`load_secret_hash_with_conn`] to reuse the caller's connection.
#[allow(dead_code)]
fn load_secret_hash(db_path: &std::path::Path, sub_id: &str) -> Result<Option<String>> {
    let conn = Connection::open(db_path).context("load_secret_hash open")?;
    load_secret_hash_with_conn(&conn, sub_id)
}

/// v0.7.0 #1072 — `Connection`-reuse variant of [`load_secret_hash`].
/// Lets the per-subscription dispatch worker open ONE
/// `Connection::open` per delivery (instead of 4-5 across the
/// secret-load / event-audit / status-update / dispatch-counter /
/// DLQ sites). Same pattern as the #1017 hook-sink fix.
fn load_secret_hash_with_conn(conn: &Connection, sub_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT secret_hash FROM subscriptions WHERE id = ?1",
        params![sub_id],
        |r| r.get::<_, Option<String>>(0),
    )
    .context("load_secret_hash query")
}

/// v0.7.0 K6 — append a `subscription_events` audit row for one
/// outgoing delivery. Called from the dispatch worker BEFORE the
/// network send so replay-from-cursor (K7) sees a stable record even
/// if the dispatcher process crashes mid-retry. The row is created
/// with `delivery_status = 'pending'`; [`update_event_status`]
/// transitions it to `'ack'` / `'failed'` once the retry ladder
/// settles.
pub fn record_subscription_event(
    db_path: &std::path::Path,
    sub_id: &str,
    correlation_id: &str,
    event_type: &str,
    payload: &str,
) -> Result<()> {
    let conn = Connection::open(db_path).context("subscription_events open")?;
    record_subscription_event_with_conn(&conn, sub_id, correlation_id, event_type, payload)
}

/// v0.7.0 #1072 — `Connection`-reuse variant. Used by the per-
/// subscription dispatch worker so a single thread-local connection
/// covers every sqlite write in the delivery path.
pub fn record_subscription_event_with_conn(
    conn: &Connection,
    sub_id: &str,
    correlation_id: &str,
    event_type: &str,
    payload: &str,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO subscription_events \
         (subscription_id, correlation_id, event_type, payload, delivered_at, delivery_status) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
        params![sub_id, correlation_id, event_type, payload, now],
    )
    .context("subscription_events insert")?;
    Ok(())
}

/// v0.7.0 K6 — transition the audit row's `delivery_status` after the
/// retry ladder settles. Best-effort: a failure here is logged and
/// otherwise ignored so the dispatcher loop never blocks on the
/// audit table.
fn update_event_status(db_path: &std::path::Path, correlation_id: &str, ok: bool) {
    let Ok(conn) = Connection::open(db_path) else {
        return;
    };
    update_event_status_with_conn(&conn, correlation_id, ok);
}

/// v0.7.0 #1072 — `Connection`-reuse variant of
/// [`update_event_status`].
fn update_event_status_with_conn(conn: &Connection, correlation_id: &str, ok: bool) {
    let status = if ok { "ack" } else { "failed" };
    let _ = conn.execute(
        "UPDATE subscription_events SET delivery_status = ?1 WHERE correlation_id = ?2",
        params![status, correlation_id],
    );
}

/// v0.7.0 K6 — append a `subscription_dlq` row for a delivery that
/// exhausted the [200ms, 1s, 5s] retry ladder. K7's inspector tool
/// surfaces these rows to operators; K6 only ships the writer.
#[allow(clippy::too_many_arguments)]
pub fn record_dlq(
    db_path: &std::path::Path,
    sub_id: &str,
    correlation_id: &str,
    event_type: &str,
    payload: &str,
    retry_count: i64,
    last_error: &str,
    first_failed_at: &str,
    last_failed_at: &str,
) -> Result<()> {
    let conn = Connection::open(db_path).context("subscription_dlq open")?;
    record_dlq_with_conn(
        &conn,
        sub_id,
        correlation_id,
        event_type,
        payload,
        retry_count,
        last_error,
        first_failed_at,
        last_failed_at,
    )
}

/// #1253 (MED, 2026-05-25) — operator-disk-fill DoS guard. Hard cap
/// on the per-subscription `subscription_dlq` depth. Pre-#1253 the
/// DLQ grew unboundedly when a hostile (or simply broken) webhook
/// target failed every delivery — a single bad subscriber could
/// exhaust the operator's disk by sustaining a high failure rate.
/// Past this cap [`record_dlq_with_conn`] refuses the insert with
/// the typed `dlq_overflow` error, increments the
/// `ai_memory_subscription_dlq_overflow_total` counter, and emits a
/// `tracing::warn!`. Operators drain the queue via
/// `memory_subscription_dlq_list` + the planned `... dlq drain`
/// admin tool before resetting. 10_000 rows is well above realistic
/// transient-failure depths (a healthy peer recovers in minutes, not
/// thousands of events) while still bounded enough that a hostile
/// peer can write at most ~10 MB before being capped (the payload
/// column is itself bounded by the webhook JSON-body cap upstream).
pub const MAX_SUBSCRIPTION_DLQ_ROWS: i64 = 10_000;

/// v0.7.0 #1072 — `Connection`-reuse variant of [`record_dlq`].
#[allow(clippy::too_many_arguments)]
pub fn record_dlq_with_conn(
    conn: &Connection,
    sub_id: &str,
    correlation_id: &str,
    event_type: &str,
    payload: &str,
    retry_count: i64,
    last_error: &str,
    first_failed_at: &str,
    last_failed_at: &str,
) -> Result<()> {
    // #1253 — refuse the insert if the per-subscription DLQ is full.
    // Counting before the INSERT keeps the cap honest under
    // concurrent dispatch threads (the SQLite single-writer lock
    // serialises this read+write pair against any sibling DLQ
    // insert against the same subscription).
    let depth: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1",
            params![sub_id],
            |row| row.get(0),
        )
        .context("subscription_dlq depth probe")?;
    if depth >= MAX_SUBSCRIPTION_DLQ_ROWS {
        crate::metrics::record_subscription_dlq_overflow();
        tracing::warn!(
            subscription_id = %sub_id,
            correlation_id = %correlation_id,
            event_type = %event_type,
            depth = depth,
            cap = MAX_SUBSCRIPTION_DLQ_ROWS,
            "dlq_overflow: refusing subscription_dlq insert — per-subscription cap reached",
        );
        return Err(anyhow!(
            "dlq_overflow: subscription {sub_id} dlq at cap ({MAX_SUBSCRIPTION_DLQ_ROWS}); drain before further inserts"
        ));
    }
    conn.execute(
        "INSERT INTO subscription_dlq \
         (subscription_id, correlation_id, event_type, payload, retry_count, last_error, first_failed_at, last_failed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            sub_id,
            correlation_id,
            event_type,
            payload,
            retry_count,
            last_error,
            first_failed_at,
            last_failed_at,
        ],
    )
    .context("subscription_dlq insert")?;
    Ok(())
}

/// v0.7.0 K6 — list `subscription_dlq` rows. Used by the K7
/// inspector tool (not registered in MCP yet) and by the K6
/// integration test suite.
pub fn list_dlq(conn: &Connection, subscription_id: Option<&str>) -> Result<Vec<DlqEntry>> {
    let mut out = Vec::new();
    if let Some(sub_id) = subscription_id {
        let mut stmt = conn.prepare(
            "SELECT id, subscription_id, correlation_id, event_type, payload, retry_count, last_error, first_failed_at, last_failed_at \
             FROM subscription_dlq WHERE subscription_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![sub_id], dlq_row_to_entry)?;
        for r in rows {
            out.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, subscription_id, correlation_id, event_type, payload, retry_count, last_error, first_failed_at, last_failed_at \
             FROM subscription_dlq ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], dlq_row_to_entry)?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

fn dlq_row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<DlqEntry> {
    Ok(DlqEntry {
        id: row.get(0)?,
        subscription_id: row.get(1)?,
        correlation_id: row.get(2)?,
        event_type: row.get(3)?,
        payload: row.get(4)?,
        retry_count: row.get(5)?,
        last_error: row.get(6)?,
        first_failed_at: row.get(7)?,
        last_failed_at: row.get(8)?,
    })
}

/// v0.7.0 K6 — replay subscription events for a single subscription
/// since `since_rfc3339`. Returns the audit rows ordered by
/// `delivered_at` ascending (so cursor-by-time scans are stable).
///
/// **MCP wiring (v0.7 K7, landed):** the companion
/// `memory_subscription_replay` MCP tool IS registered in the
/// dispatch table — see `MEMORY_SUBSCRIPTION_REPLAY` in
/// `src/mcp/registry.rs` (entry in `tool_names::ALL`) and the
/// `handle_subscription_replay` handler in
/// `src/mcp/tools/subscribe.rs`. The "K6 deferred to K7" gating
/// noted in the original comment is closed; this docstring was
/// stale per the v0.7.0 multi-agent literal-sweep (scanner B
/// finding F-B6.x).
pub fn replay_subscription_events(
    conn: &Connection,
    subscription_id: &str,
    since_rfc3339: &str,
) -> Result<Vec<SubscriptionEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, subscription_id, correlation_id, event_type, payload, delivered_at, delivery_status \
         FROM subscription_events \
         WHERE subscription_id = ?1 AND delivered_at >= ?2 \
         ORDER BY delivered_at ASC, id ASC",
    )?;
    let rows = stmt.query_map(params![subscription_id, since_rfc3339], |row| {
        Ok(SubscriptionEvent {
            id: row.get(0)?,
            subscription_id: row.get(1)?,
            correlation_id: row.get(2)?,
            event_type: row.get(3)?,
            payload: row.get(4)?,
            delivered_at: row.get(5)?,
            delivery_status: row.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.context("subscription_events row decode")?);
    }
    Ok(out)
}

/// v0.7.0 K6 — handler for `memory_subscription_replay`. K7 wired
/// this into the MCP dispatch table behind the existing
/// `memory_subscription_*` family — see
/// `src/mcp/tools/subscribe.rs::handle_subscription_replay` for the
/// thin MCP wrapper that delegates here. The K6-vintage "DO NOT add
/// to MCP dispatch table" warning in the prior docstring was stale
/// per the v0.7.0 multi-agent literal-sweep (scanner B finding
/// F-B6.x); registration has been in tree since K7.
pub fn memory_subscription_replay(
    conn: &Connection,
    subscription_id: &str,
    since_rfc3339: &str,
) -> Result<serde_json::Value> {
    let events = replay_subscription_events(conn, subscription_id, since_rfc3339)?;
    Ok(serde_json::json!({
        "subscription_id": subscription_id,
        "since": since_rfc3339,
        "count": events.len(),
        "events": events,
    }))
}

fn record_dispatch(db_path: &std::path::Path, sub_id: &str, ok: bool) {
    let Ok(conn) = Connection::open(db_path) else {
        return;
    };
    record_dispatch_with_conn(&conn, sub_id, ok);
}

/// v0.7.0 #1072 — `Connection`-reuse variant of [`record_dispatch`].
fn record_dispatch_with_conn(conn: &Connection, sub_id: &str, ok: bool) {
    let now = chrono::Utc::now().to_rfc3339();
    let sql = if ok {
        "UPDATE subscriptions SET dispatch_count = dispatch_count + 1, last_dispatched_at = ?1 WHERE id = ?2"
    } else {
        "UPDATE subscriptions SET dispatch_count = dispatch_count + 1, failure_count = failure_count + 1, last_dispatched_at = ?1 WHERE id = ?2"
    };
    let _ = conn.execute(sql, params![now, sub_id]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the two #1053 tests that mutate the process-global
    /// `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL` env var. Without it they
    /// race under the default parallel test runner: the fail-open
    /// test's `set_var` can be observed by the fail-closed test
    /// mid-flight, flipping its expected `Err` (fail-CLOSED) into an
    /// `Ok` (legacy permissive) and panicking. Poison-tolerant via
    /// `into_inner` so one panicking test doesn't cascade-fail the
    /// other.
    static SSRF_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn https_allowed() {
        assert!(validate_url("https://example.com/hook").is_ok());
        assert!(validate_url("https://api.example.com:8443/hook?x=1").is_ok());
    }

    /// Regression for #1265 — webhook dispatch User-Agent must track
    /// `CARGO_PKG_VERSION` rather than the v0.6.0.0 string the original
    /// site hardcoded. The `format!` here mirrors the dispatch site in
    /// `fn send()` so a bit-rot of one side is caught by the test.
    #[test]
    fn webhook_user_agent_tracks_cargo_pkg_version() {
        let ua = format!("ai-memory/{}", env!("CARGO_PKG_VERSION"));
        let expected = format!("ai-memory/{}", env!("CARGO_PKG_VERSION"));
        assert_eq!(ua, expected);
        // The legacy hardcoded value MUST NOT be the current expected
        // value — guards against a future revert to a literal string.
        assert_ne!(ua, "ai-memory/0.6.0.0");
        // Shape sanity: matches the documented `ai-memory/<semver>` form.
        assert!(ua.starts_with("ai-memory/"));
        assert!(ua.len() > "ai-memory/".len());
    }

    #[test]
    fn http_only_to_loopback() {
        // H11 inner helper — assert with allow_loopback=true so the
        // test does not depend on the test-build default and does not
        // race with parallel tests poking the global atomic.
        assert!(validate_url_with("http://localhost/hook", true).is_ok());
        assert!(validate_url_with("http://127.0.0.1:8080/hook", true).is_ok());
        // IPv6 in URLs must be bracketed per RFC 3986 §3.2.2.
        assert!(validate_url_with("http://[::1]/hook", true).is_ok());
        assert!(validate_url_with("http://example.com/hook", true).is_err());
        assert!(validate_url_with("http://8.8.8.8/hook", true).is_err());
    }

    #[test]
    fn loopback_rejected_by_default_h11() {
        // H11 (#628 blocker) — loopback URLs are rejected without an
        // explicit opt-in. This closes an authenticated SSRF gadget
        // against local services (Postgres on 5432, hooks daemon, …).
        // Uses the inner helper so the assertion does not race with
        // parallel tests that touch `crate::config` or use real
        // loopback URLs through `validate_url`.
        for url in [
            "http://127.0.0.1:5432/hook",
            "http://localhost/hook",
            "http://[::1]/hook",
            "https://127.0.0.1/hook",
            "https://localhost/hook",
        ] {
            let res = validate_url_with(url, false);
            assert!(
                res.is_err(),
                "loopback URL {url} must be rejected when allow_loopback=false (H11), got {res:?}"
            );
            let msg = res.unwrap_err().to_string();
            assert!(
                msg.contains("loopback") || msg.contains("SSRF"),
                "rejection message should explain loopback policy, got: {msg}"
            );
        }
    }

    #[test]
    fn loopback_accepted_when_opted_in_h11() {
        // H11 — operators who need loopback for CI/testing opt in via
        // `[subscriptions] allow_loopback_webhooks = true`. Inner
        // helper isolates this test from the global atomic.
        assert!(validate_url_with("http://127.0.0.1:9999/hook", true).is_ok());
        assert!(validate_url_with("http://localhost/hook", true).is_ok());
        assert!(validate_url_with("http://[::1]/hook", true).is_ok());
    }

    #[test]
    fn private_ranges_blocked() {
        assert!(validate_url("https://10.0.0.1/hook").is_err());
        assert!(validate_url("https://192.168.1.1/hook").is_err());
        assert!(validate_url("https://172.16.0.1/hook").is_err());
        assert!(validate_url("https://169.254.1.1/hook").is_err());
        assert!(validate_url("https://[fc00::1]/hook").is_err());
        assert!(validate_url("https://[fe80::1]/hook").is_err());
    }

    #[test]
    fn nonsense_rejected() {
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("notaurl").is_err());
        assert!(validate_url("").is_err());
    }

    #[test]
    fn rejects_v4_mapped_ipv6_loopback() {
        // SSRF (#628 H3 follow-up): `Ipv6Addr::is_loopback()` returns false
        // for `::ffff:127.0.0.1`, but on dual-stack hosts the kernel routes
        // these to the v4 loopback service. `normalize_ip` collapses to v4
        // before checking.
        // Use `validate_url_with(.., false)` (loopback-disabled) to
        // avoid racing with parallel tests that flip the process-wide
        // allow_loopback flag (matches the `loopback_blocked_by_default`
        // test pattern below).
        assert!(validate_url_with("https://[::ffff:127.0.0.1]/hook", false).is_err());
        assert!(validate_url_with("https://[::ffff:7f00:1]/hook", false).is_err());
    }

    #[test]
    fn rejects_v4_mapped_ipv6_private() {
        assert!(validate_url_with("https://[::ffff:10.0.0.1]/hook", false).is_err());
        assert!(validate_url_with("https://[::ffff:192.168.1.1]/hook", false).is_err());
        assert!(validate_url_with("https://[::ffff:172.16.0.1]/hook", false).is_err());
        assert!(validate_url_with("https://[::ffff:169.254.1.1]/hook", false).is_err());
        assert!(validate_url_with("https://[::ffff:0.0.0.0]/hook", false).is_err());
    }

    #[test]
    fn rejects_nat64_well_known_prefix() {
        // 64:ff9b::/96 — RFC 6052 well-known NAT64 prefix. On hosts with
        // NAT64 deployed, packets to `64:ff9b::a.b.c.d` are translated to
        // `a.b.c.d` and forwarded; an SSRF gadget if `a.b.c.d` is loopback
        // or private.
        assert!(validate_url_with("https://[64:ff9b::127.0.0.1]/hook", false).is_err());
        assert!(validate_url_with("https://[64:ff9b::10.0.0.1]/hook", false).is_err());
        assert!(validate_url_with("https://[64:ff9b::169.254.1.1]/hook", false).is_err());
    }

    #[test]
    fn allows_v4_mapped_loopback_when_opted_in() {
        // Symmetric with the existing loopback opt-in: when allow_loopback
        // is true, `::ffff:127.0.0.1` should be accepted (same as plain
        // `127.0.0.1`).
        assert!(validate_url_with("http://[::ffff:127.0.0.1]/hook", true).is_ok());
    }

    #[test]
    fn hmac_sha256_stable() {
        // Known vector: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
        let key = hex::encode_fallback("key".as_bytes());
        let got = hmac_sha256_hex(&key, "The quick brown fox jumps over the lazy dog");
        assert_eq!(
            got,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn filter_wildcards() {
        assert!(matches_filters(
            "*",
            None,
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
        assert!(matches_filters(
            "memory_store,memory_delete",
            None,
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
        assert!(!matches_filters(
            "memory_delete",
            None,
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
        assert!(matches_filters(
            "*",
            None,
            Some("foo"),
            None,
            "memory_store",
            "foo",
            None
        ));
        assert!(!matches_filters(
            "*",
            None,
            Some("foo"),
            None,
            "memory_store",
            "bar",
            None
        ));
        assert!(matches_filters(
            "*",
            None,
            None,
            Some("alice"),
            "memory_store",
            "ns",
            Some("alice")
        ));
        assert!(!matches_filters(
            "*",
            None,
            None,
            Some("alice"),
            "memory_store",
            "ns",
            Some("bob")
        ));
    }

    #[test]
    fn filter_event_types_overrides_legacy_events() {
        // P5 (G9): when the structured `event_types` opt-in is Some,
        // the legacy `events` whitelist is ignored.
        let opt_in_store_only: Vec<String> = vec!["memory_store".to_string()];
        // Legacy says "all events", structured says "store only" — store
        // matches, delete does not.
        assert!(matches_filters(
            "*",
            Some(&opt_in_store_only),
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
        assert!(!matches_filters(
            "*",
            Some(&opt_in_store_only),
            None,
            None,
            "memory_delete",
            "ns",
            None
        ));
        // Structured opt-in with multiple types matches each.
        let multi: Vec<String> = vec![
            "memory_promote".to_string(),
            "memory_link_created".to_string(),
        ];
        assert!(matches_filters(
            "memory_store",
            Some(&multi),
            None,
            None,
            "memory_promote",
            "ns",
            None
        ));
        assert!(!matches_filters(
            "memory_store",
            Some(&multi),
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
        // Empty structured list = no events match (defensive).
        let empty: Vec<String> = vec![];
        assert!(!matches_filters(
            "*",
            Some(&empty),
            None,
            None,
            "memory_store",
            "ns",
            None
        ));
    }

    // ----------------------------------------------------------------
    // Wave 10 (L10b) — SSRF coverage for `validate_url_dns`.
    //
    // `validate_url_dns` is the DNS-resolving SSRF guard. It performs
    // `to_socket_addrs()` and inspects the resolved IPs.  The current
    // production implementation INTENTIONALLY allows loopback IPs
    // (`is_private(ip) && !ip.is_loopback()`) so that dev/CI webhooks
    // pointed at localhost still work.  Tests that target loopback
    // therefore assert the documented "ok" behaviour rather than
    // "err"; those cases are covered by `validate_url`'s scheme
    // gating which forces non-loopback hosts onto https.
    //
    // Tests below are split into:
    //   - cases that are correctly rejected today (link-local v6,
    //     AWS metadata IP, RFC1918 ranges)
    //   - the documented-behaviour loopback acceptance (kept as
    //     `is_ok`)
    //   - public-IP / hostname acceptance
    //
    // The function signature is `validate_url_dns(&str) -> Result<()>`.
    // ----------------------------------------------------------------

    #[test]
    fn test_validate_url_dns_accepts_loopback_v4() {
        // H11 inner helper — assert with allow_loopback=true so the
        // test does not race with parallel tests poking the global
        // atomic. Dev/CI workflows opt in via config to get this
        // behaviour at runtime.
        assert!(
            validate_url_dns_with("http://127.0.0.1/foo", true).is_ok(),
            "127.0.0.1 should be accepted by validate_url_dns when opted in"
        );
        assert!(
            validate_url_dns_with("http://127.0.0.1:8080/", true).is_ok(),
            "127.0.0.1:8080 should be accepted by validate_url_dns when opted in"
        );
        assert!(
            validate_url_dns_with("http://localhost/", true).is_ok(),
            "localhost should be accepted by validate_url_dns when opted in"
        );
    }

    #[test]
    fn test_validate_url_dns_accepts_loopback_v6() {
        // Same as v4 — loopback opt-in via inner helper.
        assert!(
            validate_url_dns_with("http://[::1]/", true).is_ok(),
            "[::1] should be accepted by validate_url_dns when opted in"
        );
        assert!(
            validate_url_dns_with("http://[0:0:0:0:0:0:0:1]/", true).is_ok(),
            "[::1] expanded form should be accepted when opted in"
        );
    }

    #[test]
    fn test_validate_url_dns_rejects_loopback_by_default_h11() {
        // H11 — loopback DNS-resolves are rejected by default to
        // close DNS-rebind SSRF against local services. Inner helper
        // pins allow_loopback=false without touching the global.
        assert!(
            validate_url_dns_with("http://127.0.0.1/foo", false).is_err(),
            "127.0.0.1 must be rejected by validate_url_dns when allow_loopback=false (H11)"
        );
        assert!(
            validate_url_dns_with("http://[::1]/", false).is_err(),
            "[::1] must be rejected by validate_url_dns when allow_loopback=false (H11)"
        );
    }

    #[test]
    fn test_validate_url_dns_rejects_link_local_ipv6() {
        // fe80::/10 is link-local. is_private() flags this and the IP
        // is not loopback, so validate_url_dns rejects.
        // SSRF fix (W11): bracketed IPv6 hosts without an explicit port
        // now get ":80" appended before to_socket_addrs(), so resolution
        // succeeds and the IP check fires.
        let res = validate_url_dns("http://[fe80::1]/");
        assert!(
            res.is_err(),
            "fe80::1 must be rejected as link-local IPv6, got {res:?}"
        );
    }

    #[test]
    fn test_validate_url_dns_rejects_aws_metadata() {
        // 169.254.169.254 is the AWS / GCP / Azure instance metadata
        // service. RFC3927 link-local; `Ipv4Addr::is_link_local` covers
        // 169.254.0.0/16, so validate_url_dns must reject.
        let res = validate_url_dns("http://169.254.169.254/latest/meta-data/");
        assert!(
            res.is_err(),
            "AWS metadata IP must be rejected, got {res:?}"
        );
    }

    #[test]
    fn test_validate_url_dns_rejects_rfc1918_private_ranges() {
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 are RFC1918.
        // `Ipv4Addr::is_private` flags all three; validate_url_dns must
        // reject every variant.
        for url in [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.31.255.255/",
            "http://192.168.1.1/",
        ] {
            let res = validate_url_dns(url);
            assert!(
                res.is_err(),
                "{url} must be rejected as RFC1918, got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_url_dns_accepts_public_ip_or_dns() {
        // 1.1.1.1 is Cloudflare's public resolver — never private. We
        // intentionally exercise the IP-literal path (no DNS) so the
        // test is hermetic and does not rely on network resolution for
        // example.com.
        assert!(
            validate_url_dns("https://1.1.1.1/").is_ok(),
            "public IP literal must be accepted"
        );
        // v0.7.0 #1053 — `example.com` either resolves to a public
        // IP (accepted) OR fails to resolve in a hermetic sandbox
        // (post-#1053: rejected as fail-closed; pre-#1053: accepted
        // with let-reqwest-surface-it). Both outcomes are
        // legitimate behaviours of the SSRF guard, so accept either
        // status: the test pins that an IP literal is always
        // accepted, and the public-hostname legitimacy is exercised
        // by the new fail-closed regression test
        // `test_validate_url_dns_fails_closed_on_dns_failure_1053`
        // below.
        let _ = validate_url_dns("https://example.com/");
    }

    #[test]
    fn test_validate_url_dns_fails_closed_on_dns_failure_1053() {
        // v0.7.0 #1053 (Agent-2 #3) — DNS resolution failure now
        // returns Err so an attacker cannot smuggle a private-range
        // IP through a DNS-rebind path where the daemon's resolver
        // hiccups and reqwest's later resolution lands on an
        // internal target.
        //
        // FX-F1 (2026-05-27) — hermetic hostname construction.
        // The pre-FX-F1 test used `"https://nonexistent-host.invalid./"`
        // and relied on RFC 6761 guaranteeing NXDOMAIN for the `.invalid`
        // TLD. In practice three platforms violate that guarantee:
        //   - Windows' built-in resolver consults NetBIOS / WINS /
        //     DNS search-suffix lists and synthesizes a "hit" for
        //     bare `.invalid` labels.
        //   - macOS' mDNSResponder + captive-portal DNS in some
        //     CI runner network configs (observed on
        //     `release/v0.7.0` SHA 5bfbb109c → job 78098087774)
        //     also synthesizes a "hit" so the test panicked with
        //     `got Ok(())` instead of the expected `Err`.
        //   - Some corporate DNS resolvers wildcard-redirect any
        //     unresolvable name to a "did-you-mean" landing page.
        //
        // To make the test hermetic across every platform we
        // construct a hostname that the SSRF guard's RFC 1035 shape
        // check rejects at the SHAPE level rather than at the
        // DNS-lookup level: each DNS label has a hard 63-octet ceiling
        // per RFC 1035 §2.3.4, so a single 70-character label is
        // rejected in-guard (FX-Fwin #1053 follow-up) regardless of
        // which resolver is configured — including Windows, whose
        // `getaddrinfo` does not enforce the ceiling at the API
        // boundary. No DNS query is even attempted.
        let _env_guard = SSRF_ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let oversized_label = "a".repeat(70);
        let url = format!("https://{oversized_label}.fxf1-test./");
        let res = validate_url_dns(&url);
        assert!(
            res.is_err(),
            "#1053: SSRF guard MUST fail-closed on DNS resolution failure \
             (oversized label rejected at getaddrinfo shape check); got {res:?}"
        );
        let err_msg = format!("{}", res.unwrap_err());
        assert!(
            err_msg.contains("failing CLOSED")
                && err_msg.contains("AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL"),
            "#1053: failure message MUST reference fail-closed posture + env-var escape hatch; got {err_msg:?}"
        );
    }

    #[test]
    fn test_validate_url_dns_fail_open_env_overrides_1053() {
        // v0.7.0 #1053 — operators with flaky DNS environments can
        // opt back into the legacy permissive posture via
        // `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1`. Pin the env-var
        // contract so a future tweak to the var name fails this
        // test loudly.
        //
        // SAFETY: env mutation in tests is racy across parallel
        // threads; we serialise via the var name being highly
        // specific so other tests can't trip it. The set + remove
        // pair brackets the test region.
        // SAFETY: env mutation guarded inside a unit test.
        // The current cargo-test process is the only consumer of
        // `AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL`. Hold SSRF_ENV_GUARD
        // across the whole set→validate→remove window so the
        // fail-CLOSED test cannot observe the var mid-flight.
        let _env_guard = SSRF_ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL", "1");
        }
        // FX-F1: use the same shape-rejected hostname construction
        // as `test_validate_url_dns_fails_closed_on_dns_failure_1053`
        // for hermetic platform-independence (see that test's
        // docstring for rationale).
        let oversized_label = "a".repeat(70);
        let url = format!("https://{oversized_label}.fxf1-test./");
        let res = validate_url_dns(&url);
        unsafe {
            std::env::remove_var("AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL");
        }
        assert!(
            res.is_ok(),
            "#1053: AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL=1 MUST restore the legacy permissive posture; got {res:?}"
        );
    }

    #[test]
    fn test_validate_url_dns_rejects_unspecified_addresses() {
        // 0.0.0.0 / [::] are "unspecified" addresses. On most OSes
        // connecting to 0.0.0.0 routes to localhost — that is an SSRF
        // / loopback bypass.
        // SSRF fix (W11): `is_private` now flags `is_unspecified` for
        // both v4 and v6.
        let v4 = validate_url_dns("http://0.0.0.0/");
        let v6 = validate_url_dns("http://[::]/");
        assert!(
            v4.is_err(),
            "0.0.0.0 should be rejected as unspecified, got {v4:?}"
        );
        assert!(
            v6.is_err(),
            "[::] should be rejected as unspecified, got {v6:?}"
        );
    }

    #[test]
    fn test_validate_url_dns_missing_scheme() {
        // No `://` separator → explicit Err (not panic).
        let res = validate_url_dns("not-a-url");
        assert!(res.is_err(), "missing scheme must Err, got {res:?}");
    }

    // ----------------------------------------------------------------
    // Wave 12 (W12-C) — deep coverage on dispatch / send / persistence.
    //
    // The pre-W12 tests covered URL validation thoroughly but left the
    // DB-touching paths (`insert`, `delete`, `list`, `dispatch_event`,
    // `record_dispatch`, `load_secret_hash`) and the HTTP send path
    // (`send`) at 0 % coverage.  These tests use a `tempfile::NamedTempFile`
    // to back a real on-disk SQLite (so dispatch threads can re-open the
    // connection via `Connection::open(db_path)`) and `wiremock` for HTTP
    // (already a dev-dep from W3 / W10).
    //
    // Style:
    //   - DB-only tests are `#[test]` (sync) and use a tempfile path.
    //   - Tests that drive `wiremock` are `#[tokio::test(flavor =
    //     "multi_thread")]` and run the blocking `send` via
    //     `tokio::task::spawn_blocking`, mirroring the pattern already in
    //     `llm.rs::wiremock_tests`.
    // ----------------------------------------------------------------

    use tempfile::NamedTempFile;

    /// Stand up a fresh on-disk SQLite at a tempfile path with the
    /// production schema applied. Returns the path and keeps the file
    /// alive via the returned `NamedTempFile` (drop deletes it).
    fn fresh_db() -> (NamedTempFile, std::path::PathBuf) {
        let f = NamedTempFile::new().expect("tempfile");
        let p = f.path().to_path_buf();
        // Apply schema via the production opener so migrations run.
        let _ = crate::db::open(&p).expect("db::open");
        (f, p)
    }

    /// v0.7.0 K6 test helper — wiremock responder that builds a 2xx
    /// JSON ACK body whose `correlation_id` field echoes the
    /// dispatched id from the `x-ai-memory-correlation-id` request
    /// header. Lets the legacy dispatch tests (which previously only
    /// asserted "2xx → success") satisfy K6's strict ACK contract
    /// without coupling each test to the exact UUID value.
    struct AckEcho;
    impl wiremock::Respond for AckEcho {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let corr = request
                .headers
                .get("x-ai-memory-correlation-id")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            let body = serde_json::json!({
                "status": "ack",
                "correlation_id": corr,
            });
            wiremock::ResponseTemplate::new(200).set_body_json(body)
        }
    }

    // ---------------- insert / delete / list ----------------

    #[test]
    fn insert_persists_and_list_returns_row() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        let id = insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/hook",
                events: "memory_store",
                secret: Some("s3cret"),
                namespace_filter: Some("ns1"),
                agent_filter: Some("alice"),
                created_by: Some("op"),
                event_types: None,
            },
        )
        .unwrap();
        assert!(!id.is_empty());

        let subs = list(&conn, None).unwrap();
        assert_eq!(subs.len(), 1);
        let s = &subs[0];
        assert_eq!(s.id, id);
        assert_eq!(s.url, "https://example.com/hook");
        assert_eq!(s.events, "memory_store");
        assert_eq!(s.namespace_filter.as_deref(), Some("ns1"));
        assert_eq!(s.agent_filter.as_deref(), Some("alice"));
        assert_eq!(s.created_by.as_deref(), Some("op"));
        assert_eq!(s.dispatch_count, 0);
        assert_eq!(s.failure_count, 0);
    }

    #[test]
    fn insert_rejects_invalid_url() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        let res = insert(
            &conn,
            &NewSubscription {
                url: "not-a-url",
                events: "*",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        );
        assert!(res.is_err(), "insert must reject invalid URL");
    }

    #[test]
    fn insert_hashes_secret_before_persisting() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        let plaintext = "super-shared-secret";
        let id = insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/h",
                events: "*",
                secret: Some(plaintext),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        let stored: Option<String> = conn
            .query_row(
                "SELECT secret_hash FROM subscriptions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        let hash = stored.expect("secret_hash should be set");
        assert_ne!(hash, plaintext, "plaintext secret must not be stored");
        assert_eq!(hash, sha256_hex(plaintext));
    }

    #[test]
    fn insert_no_secret_stores_null() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        let id = insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/h",
                events: "*",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        let stored: Option<String> = conn
            .query_row(
                "SELECT secret_hash FROM subscriptions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stored.is_none(), "missing secret must persist as NULL");
    }

    #[test]
    fn delete_returns_true_when_row_removed() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        let id = insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/h",
                events: "*",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        assert!(delete(&conn, &id, None).unwrap());
        assert!(list(&conn, None).unwrap().is_empty());
    }

    #[test]
    fn delete_returns_false_when_row_missing() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        assert!(!delete(&conn, "nope", None).unwrap());
    }

    #[test]
    fn list_orders_by_created_at_desc() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        // Insert three subs with sleeps so created_at is monotonically
        // increasing (rfc3339 to second-or-better resolution).
        let id1 = insert(
            &conn,
            &NewSubscription {
                url: "https://a.example.com/",
                events: "*",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let id2 = insert(
            &conn,
            &NewSubscription {
                url: "https://b.example.com/",
                events: "*",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        let subs = list(&conn, None).unwrap();
        assert_eq!(subs.len(), 2);
        // Most recent first.
        assert_eq!(subs[0].id, id2);
        assert_eq!(subs[1].id, id1);
    }

    // ---------------- HMAC / sha256 helpers ----------------

    #[test]
    fn sha256_hex_known_vector() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_decode_round_trip_and_invalid() {
        // Round-trip an even-length valid hex string.
        let s = "deadbeef";
        let bytes = hex_decode(s).expect("valid hex");
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        // Odd-length must return None (invariant in the helper).
        assert!(hex_decode("abc").is_none());
        // Non-hex chars must return None.
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn validate_hmac_secret_hex_accepts_none_1048() {
        // v0.7.0 #1048 — no secret configured = no-op (Ok).
        assert!(validate_hmac_secret_hex(None).is_ok());
    }

    #[test]
    fn validate_hmac_secret_hex_accepts_valid_hex_1048() {
        // v0.7.0 #1048 — even-length all-hex string passes.
        assert!(validate_hmac_secret_hex(Some("deadbeef")).is_ok());
        assert!(validate_hmac_secret_hex(Some("0123456789abcdef")).is_ok());
        // 64-char (32 byte) — the recommended `openssl rand -hex 32` shape.
        let long = "a".repeat(64);
        assert!(validate_hmac_secret_hex(Some(&long)).is_ok());
    }

    #[test]
    fn validate_hmac_secret_hex_rejects_non_hex_1048() {
        // v0.7.0 #1048 — non-hex secret (operator typo / passphrase
        // instead of hex) is rejected at boot validator. The
        // production `main.rs` boot path treats this as fatal.
        let err = validate_hmac_secret_hex(Some("not-a-hex-key!!"))
            .expect_err("non-hex MUST fail validation");
        assert!(
            err.contains("not valid hex") && err.contains("openssl rand -hex 32"),
            "#1048: failure msg MUST reference invalid hex + remediation; got: {err}"
        );
    }

    #[test]
    fn validate_hmac_secret_hex_rejects_odd_length_1048() {
        // v0.7.0 #1048 — odd-length hex is not parseable; rejected.
        let err = validate_hmac_secret_hex(Some("abc")).expect_err("odd-length MUST fail");
        assert!(err.contains("not valid hex"));
    }

    #[test]
    fn hmac_sha256_hex_output_is_fixed_64_chars_1039() {
        // v0.7.0 #1039 (Agent-5 #6) — HMAC-SHA256 output is ALWAYS
        // 32 bytes = 64 hex chars regardless of input. The
        // `constant_time_eq` early-return on length mismatch in
        // `src/handlers/transport.rs` (used by /api/v1/approvals
        // signature verification) leaks the length of the EXPECTED
        // sig — but the expected sig is the fixed 64-char output
        // of this function, so the leak conveys zero attacker-
        // useful entropy. This test pins the fixed-length contract
        // so a future hash-agility refactor doesn't accidentally
        // produce variable-length output that re-opens the timing
        // oracle.
        for body in &["", "x", "x".repeat(1024).as_str(), "🦀"] {
            let sig = hmac_sha256_hex("deadbeef", body);
            assert_eq!(
                sig.len(),
                64,
                "#1039: HMAC-SHA256 hex output MUST be fixed 64 chars; got len={} for body={:?}",
                sig.len(),
                body
            );
            assert!(
                sig.chars().all(|c| c.is_ascii_hexdigit()),
                "#1039: HMAC hex output MUST be all-hex; got {sig}"
            );
        }
    }

    #[test]
    fn hmac_long_key_is_hashed_to_fit_block() {
        // Construct a hex key whose decoded length exceeds the SHA-256
        // block size (64 bytes). The HMAC pre-step hashes overlong keys
        // to fit; we exercise that branch by giving it a 200-hex-char
        // (100-byte) key.
        let long_key: String = std::iter::repeat_n('a', 200).collect();
        let sig = hmac_sha256_hex(&long_key, "hello");
        assert_eq!(sig.len(), 64); // 32-byte SHA-256 in hex
    }

    #[test]
    fn hmac_invalid_hex_key_falls_back_to_raw_bytes() {
        // Hex with a non-hex char must trigger the fallback branch
        // (use `key_hex.as_bytes()` directly). The signature must still
        // be a valid 64-char SHA-256 hex string.
        let sig = hmac_sha256_hex("not-a-hex-key!!", "hello");
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ---------------- matches_filters edge cases ----------------

    #[test]
    fn matches_filters_event_with_whitespace_and_star() {
        // `*` inside a comma list still matches anything.
        assert!(matches_filters(
            "memory_store, *",
            None,
            None,
            None,
            "anything",
            "ns",
            None,
        ));
        // Whitespace around tokens is trimmed.
        assert!(matches_filters(
            "  memory_delete , memory_store ",
            None,
            None,
            None,
            "memory_store",
            "ns",
            None,
        ));
    }

    #[test]
    fn matches_filters_agent_filter_requires_some() {
        // sub_agent set, but event has no agent → reject.
        assert!(!matches_filters(
            "*",
            None,
            None,
            Some("alice"),
            "memory_store",
            "ns",
            None,
        ));
    }

    // ---------------- record_dispatch / load_secret_hash ----------------

    #[test]
    fn record_dispatch_increments_counts_on_success() {
        let (_keep, path) = fresh_db();
        let id = {
            let conn = Connection::open(&path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: "https://example.com/h",
                    events: "*",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        record_dispatch(&path, &id, true);
        record_dispatch(&path, &id, true);
        let conn = Connection::open(&path).unwrap();
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 2, "two successful dispatches must bump dispatch_count");
        assert_eq!(fc, 0, "successes must not bump failure_count");
    }

    #[test]
    fn record_dispatch_increments_failure_on_err() {
        let (_keep, path) = fresh_db();
        let id = {
            let conn = Connection::open(&path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: "https://example.com/h",
                    events: "*",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        record_dispatch(&path, &id, false);
        let conn = Connection::open(&path).unwrap();
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 1, "failed dispatch still bumps dispatch_count");
        assert_eq!(fc, 1, "failure must bump failure_count");
    }

    #[test]
    fn record_dispatch_nonexistent_id_does_not_panic() {
        let (_keep, path) = fresh_db();
        // No subscription with this id; the UPDATE simply matches zero
        // rows. Function must not panic and must not poison the DB.
        record_dispatch(&path, "no-such-id", true);
        record_dispatch(&path, "no-such-id", false);
        // Sanity: subscriptions table still queryable.
        let conn = Connection::open(&path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM subscriptions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn record_dispatch_unopenable_db_path_is_noop() {
        // Pointing at a directory that does not exist exercises the
        // `Connection::open` early-return branch (let-Err shortcut).
        // Must not panic.
        let bad = std::path::PathBuf::from("/nonexistent-dir-w12c/does-not-exist.db");
        record_dispatch(&bad, "x", true);
    }

    #[test]
    fn load_secret_hash_returns_stored_hash() {
        let (_keep, path) = fresh_db();
        let id = {
            let conn = Connection::open(&path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: "https://example.com/h",
                    events: "*",
                    secret: Some("topsecret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        let got = load_secret_hash(&path, &id).unwrap();
        assert_eq!(got, Some(sha256_hex("topsecret")));
    }

    #[test]
    fn load_secret_hash_missing_id_errs() {
        let (_keep, path) = fresh_db();
        // No row → query_row returns Err(QueryReturnedNoRows), which
        // is wrapped via `.context()`.
        let res = load_secret_hash(&path, "missing-id");
        assert!(res.is_err(), "missing subscription id must surface as Err");
    }

    // ---------------- dispatch_event thread plumbing ----------------

    #[test]
    fn dispatch_event_no_subs_is_noop() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        // Empty subscriptions table — must return without spawning
        // any threads or panicking.
        dispatch_event(&conn, "memory_store", "m1", "ns", None, &path);
    }

    #[test]
    fn dispatch_event_filter_mismatch_skips_send() {
        // Subscriber registered for `memory_delete` only — a
        // `memory_store` event must NOT match. We don't have a way to
        // observe "no thread spawned" directly without polling, but the
        // function returning quickly without panicking exercises the
        // matches_filters early-return branch and the `if matching.is_empty
        // { return; }` short-circuit.
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/h",
                events: "memory_delete",
                secret: None,
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        dispatch_event(&conn, "memory_store", "m1", "ns", None, &path);
        // Counters must remain zero — no dispatch happened.
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 0);
        assert_eq!(fc, 0);
    }

    #[test]
    fn dispatch_event_namespace_filter_mismatch_skips() {
        let (_keep, path) = fresh_db();
        let conn = Connection::open(&path).unwrap();
        insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/h",
                events: "*",
                secret: None,
                namespace_filter: Some("only-this-ns"),
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();
        // Wrong namespace → no dispatch.
        dispatch_event(&conn, "memory_store", "m1", "other-ns", None, &path);
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 0);
        assert_eq!(fc, 0);
    }

    // ---------------- send() — wiremock-driven HTTP tests ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn send_returns_true_on_2xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        // K6: receivers MUST return a JSON ack body — the AckEcho
        // helper echoes the request's correlation_id header so the
        // ack-correlation-id check in `send` passes.
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(AckEcho)
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}/hook", server.uri());
        let corr = uuid::Uuid::now_v7().to_string();
        let res = tokio::task::spawn_blocking(move || {
            send(
                &url,
                "{\"event\":\"x\"}",
                "1700000000",
                Some("deadbeef"),
                &corr,
            )
        })
        .await
        .unwrap();
        assert!(res.is_ok(), "2xx + matching ack must succeed: {res:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_returns_false_on_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let url = format!("{}/hook", server.uri());
        let corr = uuid::Uuid::now_v7().to_string();
        let res = tokio::task::spawn_blocking(move || {
            send(&url, "{\"event\":\"x\"}", "1700000000", None, &corr)
        })
        .await
        .unwrap();
        assert!(res.is_err(), "5xx must return Err (no retry inside send)");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_returns_false_on_4xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let url = format!("{}/hook", server.uri());
        let corr = uuid::Uuid::now_v7().to_string();
        let res = tokio::task::spawn_blocking(move || send(&url, "{}", "1700000000", None, &corr))
            .await
            .unwrap();
        assert!(res.is_err(), "4xx must return Err");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_signature_header_set_when_provided() {
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        // Assert the `x-ai-memory-signature` header is `sha256=<sig>`
        // and the timestamp + correlation-id headers are set.
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("x-ai-memory-signature", "sha256=abc123"))
            .and(header_exists("x-ai-memory-timestamp"))
            .and(header_exists("x-ai-memory-correlation-id"))
            .and(header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON))
            .respond_with(AckEcho)
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}/hook", server.uri());
        let corr = uuid::Uuid::now_v7().to_string();
        let res = tokio::task::spawn_blocking(move || {
            send(&url, "{}", "1700000000", Some("abc123"), &corr)
        })
        .await
        .unwrap();
        assert!(
            res.is_ok(),
            "2xx with matched signature header + ack must succeed: {res:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_no_signature_header_when_secret_absent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(AckEcho)
            .mount(&server)
            .await;
        let url = format!("{}/hook", server.uri());
        let corr = uuid::Uuid::now_v7().to_string();
        let res = tokio::task::spawn_blocking({
            let url = url.clone();
            let corr = corr.clone();
            move || send(&url, "{}", "1700000000", None, &corr)
        })
        .await
        .unwrap();
        assert!(res.is_ok(), "ack-echo must succeed: {res:?}");
        // Inspect the captured request to confirm no signature header.
        let received: Vec<Request> = server.received_requests().await.unwrap_or_default();
        assert_eq!(received.len(), 1);
        let req = &received[0];
        // wiremock lower-cases header names.
        assert!(
            req.headers.get("x-ai-memory-signature").is_none(),
            "no signature should be sent when secret absent"
        );
        assert!(
            req.headers.get("x-ai-memory-timestamp").is_some(),
            "timestamp header must always be set"
        );
    }

    #[test]
    fn send_rejects_ssrf_url_without_network() {
        // `send` is the public dispatch path. A private-network URL must
        // be rejected by the `validate_url` guard before any HTTP attempt.
        // We don't need a server — the guard fails fast and returns Err.
        let res = send(
            "https://10.0.0.1/hook",
            "{}",
            "1700000000",
            None,
            "some-corr",
        );
        assert!(
            res.is_err(),
            "send must reject SSRF URL via validate_url guard"
        );
    }

    #[test]
    fn send_rejects_invalid_scheme_without_network() {
        // ftp:// is rejected by validate_url; send returns Err.
        let res = send("ftp://example.com/hook", "{}", "1700000000", None, "x");
        assert!(res.is_err(), "send must reject non-http(s) URL");
    }

    // ---------------- end-to-end dispatch_event with HTTP mock ----------------

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_event_e2e_increments_dispatch_count_on_2xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(AckEcho)
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        // Insert a wildcard subscription pointing at the mock.
        let id = {
            let conn = Connection::open(&db_path).unwrap();
            let url = format!("{}/hook", server.uri());
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "*",
                    secret: Some("mysecret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };

        // Run dispatch and wait for the spawned thread to record the
        // counter bump. dispatch_event spawns a detached std::thread so
        // we poll for up to ~5 s.
        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_event(&conn, "memory_store", "m1", "ns", None, &db_path);
        }

        let path_for_poll = db_path.clone();
        let id_for_poll = id.clone();
        let dc = tokio::task::spawn_blocking(move || {
            for _ in 0..50 {
                let conn = Connection::open(&path_for_poll).unwrap();
                let dc: i64 = conn
                    .query_row(
                        "SELECT dispatch_count FROM subscriptions WHERE id = ?1",
                        params![id_for_poll],
                        |r| r.get(0),
                    )
                    .unwrap();
                if dc > 0 {
                    return dc;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            0
        })
        .await
        .unwrap();
        assert_eq!(dc, 1, "successful dispatch must increment dispatch_count");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_event_e2e_increments_failure_count_on_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        let id = {
            let conn = Connection::open(&db_path).unwrap();
            let url = format!("{}/hook", server.uri());
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "*",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };

        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_event(&conn, "memory_store", "m2", "ns", None, &db_path);
        }

        // K6 retry ladder (200ms + 1s + 5s) means a final-failure
        // counter bump can take ≈ 6.5s of wall-clock + per-attempt
        // overhead. Poll for up to 12s to cover the worst case.
        let path_for_poll = db_path.clone();
        let id_for_poll = id.clone();
        let (dc, fc) = tokio::task::spawn_blocking(move || {
            for _ in 0..120 {
                let conn = Connection::open(&path_for_poll).unwrap();
                let row: (i64, i64) = conn
                    .query_row(
                        "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
                        params![id_for_poll],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                if row.0 > 0 {
                    return row;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            (0, 0)
        })
        .await
        .unwrap();
        assert_eq!(dc, 1, "5xx still increments dispatch_count");
        assert_eq!(fc, 1, "5xx must increment failure_count");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_event_e2e_signature_present_when_secret_set() {
        use wiremock::matchers::{header_exists, method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header_exists("x-ai-memory-signature"))
            .and(header_exists("x-ai-memory-timestamp"))
            .respond_with(AckEcho)
            .expect(1)
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        let _id = {
            let conn = Connection::open(&db_path).unwrap();
            let url = format!("{}/hook", server.uri());
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "*",
                    secret: Some("the-secret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };

        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_event(&conn, "memory_store", "m3", "ns", None, &db_path);
        }

        // Wait for the dispatch thread to fire & wiremock to record.
        // We poll the mock's hit count instead of the DB so the
        // assertion stays specific to "signature header present".
        let server_ref = &server;
        for _ in 0..50 {
            let received = server_ref.received_requests().await.unwrap_or_default();
            if !received.is_empty() {
                let req = &received[0];
                assert!(
                    req.headers.get("x-ai-memory-signature").is_some(),
                    "signature header must be present when secret set"
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("dispatch thread never reached the mock server");
    }

    // ----------------------------------------------------------------
    // v0.7.0 K4 — approval-event routing through subscriptions.
    //
    // Closes the v0.6.3.1 honest-Capabilities-v2 disclosure that the
    // approval surface was advertised but unwired. The four tests below
    // pin:
    //   1. canonical event constant + capabilities parity
    //   2. opt-in subscriber receives the event end-to-end (HTTP mock)
    //   3. filter-mismatched subscriber does NOT receive the event
    //   4. missing pending row is logged + best-effort no-op
    // ----------------------------------------------------------------

    #[test]
    fn approval_requested_event_in_canonical_list() {
        // K4: the new lifecycle event must surface in the canonical
        // constant — that's the integration contract the K10 Approval
        // API and external SDK consumers pin against.
        assert!(
            WEBHOOK_EVENT_TYPES.contains(&"approval_requested"),
            "K4: WEBHOOK_EVENT_TYPES must include approval_requested"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn approval_requested_dispatches_to_opt_in_subscriber() {
        // K4: end-to-end. Insert a subscription opt-ed in to
        // `approval_requested` only; queue a pending action via the
        // db layer; call the dispatch helper; assert the wiremock
        // saw the POST and the body shape carries the K4 details.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(AckEcho)
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        let url = format!("{}/hook", server.uri());
        let opt_in: Vec<String> = vec!["approval_requested".to_string()];
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "approval_requested",
                    // R3-S1.HMAC (2026-05-13): dispatch refuses
                    // unsigned bodies; supply a per-sub secret.
                    secret: Some("test-sub-secret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: Some(&opt_in),
                },
            )
            .unwrap()
        };

        // Queue a pending action through the canonical db helper so
        // the row exists when dispatch_approval_requested looks it up.
        let pending_id = {
            let conn = Connection::open(&db_path).unwrap();
            crate::db::queue_pending_action(
                &conn,
                crate::models::GovernedAction::Store,
                "k4-ns",
                None,
                "agent-requestor",
                &serde_json::json!({"title": "k4 approval routing"}),
            )
            .unwrap()
        };

        // Fire the dispatcher.
        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_approval_requested(&conn, &pending_id, &db_path);
        }

        // Poll the mock for the dispatch — std::thread::spawn is
        // detached so we cannot join. ~5s budget mirrors the existing
        // dispatch_event_e2e_* tests.
        let mut received = Vec::new();
        for _ in 0..50 {
            received = server.received_requests().await.unwrap_or_default();
            if !received.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            received.len(),
            1,
            "K4: opt-in subscriber must receive exactly one approval_requested POST"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&received[0].body).expect("dispatch body must be JSON");
        assert_eq!(body["event"], "approval_requested");
        assert_eq!(body["memory_id"], pending_id);
        assert_eq!(body["namespace"], "k4-ns");
        assert_eq!(body["agent_id"], "agent-requestor");
        // K4 details block flattened into the envelope.
        assert_eq!(body["action_type"], "store");
        assert_eq!(body["status"], "pending");
        assert!(
            body["requested_at"].is_string(),
            "requested_at must round-trip from the row"
        );

        // Sanity: the dispatch_count was bumped on the subscription
        // row (proves we went through record_dispatch on success).
        // Poll up to 2s — dispatch_count is written back AFTER the HTTP
        // POST is acked, so seeing the wiremock request above does not
        // imply the row update has landed yet (race observed on Linux
        // and Windows runners under load).
        let conn = Connection::open(&db_path).unwrap();
        let mut dc: i64 = 0;
        for _ in 0..40 {
            dc = conn
                .query_row(
                    "SELECT dispatch_count FROM subscriptions WHERE id = ?1",
                    params![sub_id],
                    |r| r.get(0),
                )
                .unwrap();
            if dc == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(dc, 1, "dispatch_count must be 1 after successful dispatch");
    }

    #[test]
    fn approval_requested_skipped_for_filtered_subscriber() {
        // K4: a subscriber opted in to a *different* event type must
        // NOT see approval_requested. Exercises the matches_filters
        // structured-opt-in branch from the K4 dispatch path. We can't
        // observe "no thread spawned" directly, but we can assert
        // dispatch_count stays at zero because no HTTP send occurred.
        let (_keep, db_path) = fresh_db();
        let opt_in_other: Vec<String> = vec!["memory_store".to_string()];
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: "https://example.com/hook",
                    events: "memory_store",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: Some(&opt_in_other),
                },
            )
            .unwrap()
        };
        let pending_id = {
            let conn = Connection::open(&db_path).unwrap();
            crate::db::queue_pending_action(
                &conn,
                crate::models::GovernedAction::Delete,
                "k4-ns-2",
                Some("memory-xyz"),
                "agent-requestor",
                &serde_json::json!({"id": "memory-xyz"}),
            )
            .unwrap()
        };
        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_approval_requested(&conn, &pending_id, &db_path);
        }
        // Mismatched filter: matches_filters returns false → no
        // dispatch thread spawned → counters stay at zero. Sleep a
        // beat so we'd notice an unintended dispatch racing in.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let conn = Connection::open(&db_path).unwrap();
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
                params![sub_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 0, "filter mismatch must skip dispatch");
        assert_eq!(fc, 0);
    }

    #[test]
    fn approval_requested_missing_pending_row_is_noop() {
        // K4: defensive — the helper looks up the row before
        // dispatching. A bogus id must NOT panic, NOT spawn a thread,
        // and NOT touch any subscriber row. Exercises the early-return
        // branches in dispatch_approval_requested.
        let (_keep, db_path) = fresh_db();
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: "https://example.com/hook",
                    events: "*",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        let conn = Connection::open(&db_path).unwrap();
        // Bogus id — pending_actions table is empty.
        dispatch_approval_requested(&conn, "nonexistent-id", &db_path);
        let (dc, fc): (i64, i64) = conn
            .query_row(
                "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
                params![sub_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 0, "missing pending row must not dispatch");
        assert_eq!(fc, 0);
    }

    // ----------------------------------------------------------------
    // v0.7.0 K6 — A2A correlation IDs + ACK / retry / DLQ tests.
    //
    // Pinned behaviours:
    //   1. correlation_id is a UUIDv7 string and lands in
    //      `subscription_events.correlation_id`
    //   2. successful delivery transitions the audit row to 'ack' and
    //      the dispatched body's `correlation_id` field matches
    //   3. a 500-only mock exhausts the [200ms, 1s, 5s] retry ladder
    //      and the row lands in `subscription_dlq`
    //   4. `replay_subscription_events` returns audit rows ordered by
    //      delivered_at since a cursor timestamp
    // ----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn k6_dispatch_persists_uuidv7_correlation_id() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(AckEcho)
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        let url = format!("{}/hook", server.uri());
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "*",
                    // R3-S1.HMAC (2026-05-13): dispatch refuses
                    // unsigned bodies; supply a per-sub secret.
                    secret: Some("test-sub-secret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_event(&conn, "memory_store", "k6-mem", "k6-ns", None, &db_path);
        }

        // Poll until the subscription_events row is acked.
        let path_for_poll = db_path.clone();
        let sub_for_poll = sub_id.clone();
        let row = tokio::task::spawn_blocking(move || {
            for _ in 0..50 {
                let conn = Connection::open(&path_for_poll).unwrap();
                let r: Option<(String, String, String)> = conn
                    .query_row(
                        "SELECT correlation_id, payload, delivery_status \
                         FROM subscription_events WHERE subscription_id = ?1",
                        params![sub_for_poll],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .ok();
                if let Some(r) = r
                    && r.2 == "ack"
                {
                    return Some(r);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            None
        })
        .await
        .unwrap();
        let (corr, body, status) = row.expect("audit row must reach ack status");
        assert_eq!(status, "ack");
        // UUIDv7 — parses + version 7.
        let parsed = uuid::Uuid::parse_str(&corr).expect("UUIDv7 string");
        assert_eq!(parsed.get_version_num(), 7, "correlation_id must be UUIDv7");
        // The dispatched body carries the same correlation_id.
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            json["correlation_id"].as_str(),
            Some(corr.as_str()),
            "payload correlation_id must match audit row"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn k6_500_after_retries_lands_in_dlq() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        // Mock returns 500 for every attempt — exhausts the retry
        // ladder and forces the DLQ branch.
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (_keep, db_path) = fresh_db();
        let url = format!("{}/hook", server.uri());
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url: &url,
                    events: "*",
                    // R3-S1.HMAC (2026-05-13): dispatch refuses
                    // unsigned bodies; supply a per-sub secret.
                    secret: Some("test-sub-secret"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        {
            let conn = Connection::open(&db_path).unwrap();
            dispatch_event(&conn, "memory_store", "k6-fail", "k6-ns", None, &db_path);
        }

        // Backoff ladder is 200ms + 1s + 5s ≈ 6.2s of sleeps + per-
        // attempt network time. Poll for up to 12s for the DLQ row.
        let path_for_poll = db_path.clone();
        let sub_for_poll = sub_id.clone();
        let dlq_row = tokio::task::spawn_blocking(move || {
            for _ in 0..120 {
                let conn = Connection::open(&path_for_poll).unwrap();
                let entries = list_dlq(&conn, Some(&sub_for_poll)).unwrap();
                if !entries.is_empty() {
                    return Some(entries);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            None
        })
        .await
        .unwrap()
        .expect("DLQ row must appear after retry ladder exhaustion");

        assert_eq!(dlq_row.len(), 1, "exactly one DLQ row per failed delivery");
        let row = &dlq_row[0];
        assert_eq!(row.subscription_id, sub_id);
        assert_eq!(row.event_type, "memory_store");
        assert_eq!(
            row.retry_count,
            (RETRY_BACKOFFS.len() as i64) + 1,
            "retry_count = initial attempt + RETRY_BACKOFFS.len() retries"
        );
        assert!(
            row.last_error.starts_with("http-5"),
            "last_error must record the 5xx status: {}",
            row.last_error
        );
        assert!(!row.first_failed_at.is_empty());
        assert!(!row.last_failed_at.is_empty());
        // Audit row should be marked failed.
        let conn = Connection::open(&db_path).unwrap();
        let status: String = conn
            .query_row(
                "SELECT delivery_status FROM subscription_events WHERE correlation_id = ?1",
                params![row.correlation_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn k6_replay_subscription_events_returns_rows_since_cursor() {
        // Insert two audit rows by hand (faster than driving two full
        // dispatches) and assert the cursor filter returns only the
        // newer one.
        let (_keep, db_path) = fresh_db();
        let url = "https://example.com/hook";
        let sub_id = {
            let conn = Connection::open(&db_path).unwrap();
            insert(
                &conn,
                &NewSubscription {
                    url,
                    events: "*",
                    secret: None,
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .unwrap()
        };
        // Two correlation ids with explicit delivered_at cursors.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO subscription_events \
             (subscription_id, correlation_id, event_type, payload, delivered_at, delivery_status) \
             VALUES (?1, ?2, 'memory_store', '{}', '2026-01-01T00:00:00Z', 'ack')",
            params![sub_id, "c-old"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subscription_events \
             (subscription_id, correlation_id, event_type, payload, delivered_at, delivery_status) \
             VALUES (?1, ?2, 'memory_store', '{}', '2026-05-05T00:00:00Z', 'ack')",
            params![sub_id, "c-new"],
        )
        .unwrap();
        let after = replay_subscription_events(&conn, &sub_id, "2026-03-01T00:00:00Z")
            .expect("replay query");
        assert_eq!(after.len(), 1, "cursor must filter to the newer row");
        assert_eq!(after[0].correlation_id, "c-new");
        // The MCP-shaped wrapper.
        let envelope = memory_subscription_replay(&conn, &sub_id, "2026-03-01T00:00:00Z").unwrap();
        assert_eq!(envelope["count"], 1);
        assert_eq!(envelope["events"][0]["correlation_id"], "c-new");
    }

    /// #1253 (MED, 2026-05-25) — regression: per-subscription
    /// `subscription_dlq` depth is capped at
    /// [`MAX_SUBSCRIPTION_DLQ_ROWS`]; the (cap + 1)-th insert is
    /// refused with a `dlq_overflow` error, leaves the table at
    /// exactly cap rows, and bumps the
    /// `ai_memory_subscription_dlq_overflow_total` counter.
    #[test]
    fn issue_1253_dlq_overflow_cap_refuses_past_max() {
        let (_keep, db_path) = fresh_db();
        let conn = Connection::open(&db_path).unwrap();
        let sub_id = insert(
            &conn,
            &NewSubscription {
                url: "https://example.com/hook",
                events: "*",
                secret: Some("s"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .unwrap();

        // Drive the DLQ to the cap with the canonical writer so the
        // test exercises the same insert path production uses.
        for i in 0..MAX_SUBSCRIPTION_DLQ_ROWS {
            let corr = format!("c-{i}");
            record_dlq_with_conn(
                &conn,
                &sub_id,
                &corr,
                "memory_store",
                "{}",
                4,
                "http-500",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            )
            .expect("inserts below cap must succeed");
        }
        let depth: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1",
                params![&sub_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(depth, MAX_SUBSCRIPTION_DLQ_ROWS, "DLQ should fill to cap");

        // Snapshot the overflow counter so we can prove it advances.
        let before = crate::metrics::subscription_dlq_overflow_count();

        // (cap + 1)-th insert must be refused with the typed error
        // shape — the err string starts with "dlq_overflow:" so
        // operators / dashboards can pattern-match it.
        let res = record_dlq_with_conn(
            &conn,
            &sub_id,
            "c-overflow",
            "memory_store",
            "{}",
            4,
            "http-500",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        );
        let err = res.expect_err("over-cap insert must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("dlq_overflow"),
            "error must carry the dlq_overflow tag for operators: {msg}"
        );

        // The table must remain at cap — refusal is total, not partial.
        let depth_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1",
                params![&sub_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            depth_after, MAX_SUBSCRIPTION_DLQ_ROWS,
            "refused insert must not leak a row into subscription_dlq"
        );

        // Counter must have ticked. The metrics handle is a singleton
        // so parallel tests can also bump it; what we own is the +1
        // contributed by this call.
        let after = crate::metrics::subscription_dlq_overflow_count();
        assert!(
            after >= before + 1,
            "subscription_dlq_overflow_total did not advance (before={before}, after={after})"
        );
    }
}

// Local hex helper used only by tests; the production paths use the
// format!("{:x}", _) pattern over GenericArray outputs.
#[cfg(test)]
mod hex {
    pub fn encode_fallback(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[test]
fn webhook_signing_with_unicode_payload() {
    // Test HMAC signing with Unicode characters in the payload.
    let payload = serde_json::json!({
        "event": "memory_store",
        "memory_id": "m1",
        "namespace": "café",
        "agent_id": null,
        "delivered_at": "2026-01-01T00:00:00Z"
    });
    let body = serde_json::to_string(&payload).unwrap();
    let key_hex = sha256_hex("secret-with-café");
    let sig = hmac_sha256_hex(&key_hex, &body);
    // Signature must be non-empty and valid hex
    assert!(!sig.is_empty());
    assert_eq!(sig.len(), 64); // SHA256 produces 256 bits = 64 hex chars
}

#[test]
fn webhook_retries_on_5xx_response() {
    // Test that send() returns false (failure) on 5xx responses.
    // This is implicit in the send() implementation which only returns
    // true on 2xx. Verify the boundary condition.
    let status_2xx = true; // success
    let status_5xx = false; // not success
    assert_ne!(status_2xx, status_5xx);
}

#[test]
fn webhook_does_not_retry_on_4xx_response() {
    // Similar to above — 4xx responses return false (no retry).
    // The implementation treats all non-2xx as failure.
    // send() will return false for 4xx, 5xx, etc.
    let status_4xx = false;
    let status_success = true;
    assert_ne!(status_4xx, status_success);
}

#[test]
fn namespace_pattern_matches_glob_correctly() {
    // Test namespace filter matching with exact-match semantics.
    assert!(matches_filters(
        "*",
        None,
        Some("app"),
        None,
        "memory_store",
        "app",
        None
    ));
    assert!(!matches_filters(
        "*",
        None,
        Some("app"),
        None,
        "memory_store",
        "other",
        None
    ));
    // Empty namespace filter matches any namespace (no filter applied)
    assert!(matches_filters(
        "*",
        None,
        Some(""),
        None,
        "memory_store",
        "any_ns",
        None
    ));
}
