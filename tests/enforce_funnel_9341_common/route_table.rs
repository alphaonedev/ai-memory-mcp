// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9341 / #8502 / #8590 — the named route table shared by the behavioural
//! suite (`tests/enforce_identity_funnel_9341.rs`) and the structural scan
//! (`tests/enforce_identity_funnel_structural_9341.rs`).
//!
//! Every `(path constant, method)` registered in `build_router_with_timeout`
//! appears here exactly once with its class. The structural scan fails when
//! the router and this table disagree in either direction, so a new route
//! cannot land without a row (and without being covered by the funnel cell).

#![allow(dead_code)]

use ai_memory::handlers::routes;

/// The identity class of one registered route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    /// Outside the authority layer (`AUTHORITY_EXEMPT_*`): liveness / scrape
    /// probes carry no identity, and `/api/v1/sync/*` authenticates the PEER,
    /// so `X-Agent-Id` is not the principal there.
    Exempt,
    /// The handler serves a catalogue that never reads a principal. A caller
    /// with no `X-Agent-Id` is served; a NAMED unproven caller is still
    /// refused by the funnel (the invariant holds for every gated route).
    AnonymousAllowed,
    /// The handler (or its inner funnel) acts for, reads as, or authorises the
    /// caller principal. A named unproven caller is refused by the funnel.
    PrincipalRequired,
}

/// One row: the `routes::` constant name, its path, the HTTP method, the class.
#[derive(Clone, Copy, Debug)]
pub struct RouteRow {
    pub name: &'static str,
    pub path: &'static str,
    pub method: &'static str,
    pub class: RouteClass,
}

macro_rules! row {
    ($c:ident, $m:literal, $k:ident) => {
        RouteRow {
            name: stringify!($c),
            path: routes::$c,
            method: $m,
            class: RouteClass::$k,
        }
    };
}

/// Every registered HTTP route, in router order.
pub const ROUTE_TABLE: &[RouteRow] = &[
    row!(HEALTH, "get", Exempt),
    row!(MONITORING_STATUS, "get", Exempt),
    row!(MONITORING_METRICS, "get", Exempt),
    row!(METRICS_BARE, "get", Exempt),
    row!(METRICS, "get", Exempt),
    row!(MEMORIES, "get", PrincipalRequired),
    row!(MEMORIES, "post", PrincipalRequired),
    row!(ACTIONS_ID_TRANSITION, "post", PrincipalRequired),
    row!(SIGNALS, "post", PrincipalRequired),
    row!(CHECKPOINTS_ID_RESOLVE, "post", PrincipalRequired),
    row!(MEMORIES_BULK, "post", PrincipalRequired),
    row!(MEMORIES_ID, "get", PrincipalRequired),
    row!(MEMORIES_ID, "put", PrincipalRequired),
    row!(MEMORIES_ID, "delete", PrincipalRequired),
    row!(MEMORIES_ID_PROMOTE, "post", PrincipalRequired),
    row!(CAPTURE_TURN, "post", PrincipalRequired),
    row!(SEARCH, "get", PrincipalRequired),
    row!(RECALL, "get", PrincipalRequired),
    row!(RECALL, "post", PrincipalRequired),
    row!(FORGET, "post", PrincipalRequired),
    row!(CONSOLIDATE, "post", PrincipalRequired),
    row!(CONTRADICTIONS, "get", PrincipalRequired),
    row!(AUTO_TAG, "post", PrincipalRequired),
    row!(EXPAND_QUERY, "post", PrincipalRequired),
    row!(TOOLS_LIST, "get", AnonymousAllowed),
    row!(MEMORY_LOAD_FAMILY, "post", PrincipalRequired),
    row!(LINKS, "post", PrincipalRequired),
    row!(LINKS, "delete", PrincipalRequired),
    row!(LINKS_ID, "get", PrincipalRequired),
    row!(MEMORIES_ID_LINEAGE, "get", PrincipalRequired),
    row!(NAMESPACES, "get", PrincipalRequired),
    row!(NAMESPACES, "post", PrincipalRequired),
    row!(NAMESPACES, "delete", PrincipalRequired),
    row!(NAMESPACES_NS_STANDARD, "post", PrincipalRequired),
    row!(NAMESPACES_NS_STANDARD, "get", PrincipalRequired),
    row!(NAMESPACES_NS_STANDARD, "delete", PrincipalRequired),
    row!(TAXONOMY, "get", PrincipalRequired),
    row!(CHECK_DUPLICATE, "post", PrincipalRequired),
    row!(ENTITIES, "post", PrincipalRequired),
    row!(ENTITIES_BY_ALIAS, "get", PrincipalRequired),
    row!(KG_TIMELINE, "get", PrincipalRequired),
    row!(KG_INVALIDATE, "post", PrincipalRequired),
    row!(KG_QUERY, "post", PrincipalRequired),
    row!(KG_FIND_PATHS, "post", PrincipalRequired),
    row!(FIND_PATHS, "post", PrincipalRequired),
    row!(LINKS_VERIFY, "post", PrincipalRequired),
    row!(QUOTA_STATUS, "post", PrincipalRequired),
    row!(ADMIN_QUARANTINE, "get", PrincipalRequired),
    row!(ADMIN_QUARANTINE_ID_RELEASE, "post", PrincipalRequired),
    row!(STATS, "get", PrincipalRequired),
    row!(GC, "post", PrincipalRequired),
    row!(EXPORT, "get", PrincipalRequired),
    row!(IMPORT, "post", PrincipalRequired),
    row!(ARCHIVE, "get", PrincipalRequired),
    row!(ARCHIVE, "post", PrincipalRequired),
    row!(ARCHIVE, "delete", PrincipalRequired),
    row!(ARCHIVE_ID_RESTORE, "post", PrincipalRequired),
    row!(ARCHIVE_STATS, "get", PrincipalRequired),
    row!(AGENTS, "get", PrincipalRequired),
    row!(AGENTS, "post", PrincipalRequired),
    row!(AGENTS_ID_PUBKEY, "put", PrincipalRequired),
    row!(AGENTS_ID_PUBKEY_CHALLENGE, "post", PrincipalRequired),
    row!(AGENTS_ID_API_KEY, "post", PrincipalRequired),
    row!(AGENTS_ID_API_KEY_REVOKE, "post", PrincipalRequired),
    row!(PENDING, "get", PrincipalRequired),
    row!(PENDING_ID_APPROVE, "post", PrincipalRequired),
    row!(PENDING_ID_REJECT, "post", PrincipalRequired),
    row!(APPROVALS_PENDING_ID, "post", PrincipalRequired),
    row!(APPROVALS_STREAM, "get", PrincipalRequired),
    row!(SYNC_PUSH, "post", Exempt),
    row!(SYNC_SINCE, "get", Exempt),
    row!(CAPABILITIES, "get", AnonymousAllowed),
    row!(NOTIFY, "post", PrincipalRequired),
    row!(A2A, "post", PrincipalRequired),
    row!(AGENT_CARD, "get", AnonymousAllowed),
    row!(INBOX, "get", PrincipalRequired),
    row!(INBOX_STREAM, "get", PrincipalRequired),
    row!(SUBSCRIPTIONS, "post", PrincipalRequired),
    row!(SUBSCRIPTIONS, "delete", PrincipalRequired),
    row!(SUBSCRIPTIONS, "get", PrincipalRequired),
    row!(SESSION_START, "post", PrincipalRequired),
    row!(SKILL_REGISTER, "post", PrincipalRequired),
    row!(SKILL_LIST, "get", PrincipalRequired),
    row!(SKILL_ID, "get", PrincipalRequired),
    row!(SKILL_ID, "delete", PrincipalRequired),
    row!(SKILL_ID_RESOURCE, "get", PrincipalRequired),
    row!(SKILL_ID_EXPORT, "post", PrincipalRequired),
    row!(SKILL_ID_PROMOTE, "post", PrincipalRequired),
    row!(SKILL_ID_COMPOSE, "post", PrincipalRequired),
    row!(SKILL_ID_RETIRE, "post", PrincipalRequired),
    row!(SHARE, "post", PrincipalRequired),
    row!(MEMORY_SMART_LOAD, "post", PrincipalRequired),
    row!(MEMORY_REFLECT, "post", PrincipalRequired),
    row!(MEMORY_RECALL_OBSERVATIONS, "post", PrincipalRequired),
    row!(MEMORY_REFLECTION_ORIGIN, "post", PrincipalRequired),
    row!(MEMORY_DEPENDENTS_OF_INVALIDATED, "post", PrincipalRequired),
    row!(MEMORY_EXPORT_REFLECTION, "post", PrincipalRequired),
    row!(MEMORY_ATOMISE, "post", PrincipalRequired),
    row!(MEMORY_CALIBRATE_CONFIDENCE, "post", PrincipalRequired),
    row!(MEMORY_SWARM_REWIND, "post", PrincipalRequired),
    row!(MEMORY_VERIFY, "post", PrincipalRequired),
    row!(MEMORY_REPLAY, "post", PrincipalRequired),
    row!(MEMORY_SUBSCRIPTION_REPLAY, "post", PrincipalRequired),
    row!(MEMORY_SUBSCRIPTION_DLQ_LIST, "post", PrincipalRequired),
    row!(MEMORY_RULE_LIST, "post", PrincipalRequired),
    row!(MEMORY_CHECK_AGENT_ACTION, "post", PrincipalRequired),
];

/// The 15 routes the audit (`AUDIT-enforce-header-identity.md` section 2)
/// found outside every handler gate: `(routes:: constant, method)`.
pub const AUDIT_UNGATED_ROUTES: &[(&str, &str)] = &[
    ("MEMORIES", "post"),
    ("MEMORIES_BULK", "post"),
    ("CAPTURE_TURN", "post"),
    ("ACTIONS_ID_TRANSITION", "post"),
    ("SIGNALS", "post"),
    ("CHECKPOINTS_ID_RESOLVE", "post"),
    ("ENTITIES", "post"),
    ("LINKS_VERIFY", "post"),
    ("NOTIFY", "post"),
    ("SUBSCRIPTIONS", "post"),
    ("MEMORY_REFLECTION_ORIGIN", "post"),
    ("MEMORY_DEPENDENTS_OF_INVALIDATED", "post"),
    ("MEMORY_VERIFY", "post"),
    ("MEMORY_CALIBRATE_CONFIDENCE", "post"),
    ("MEMORY_RECALL_OBSERVATIONS", "post"),
];

/// The exempt route constants, by name (design point 3: probes and sync).
pub const EXEMPT_ROUTE_NAMES: &[&str] = &[
    "HEALTH",
    "MONITORING_STATUS",
    "MONITORING_METRICS",
    "METRICS_BARE",
    "METRICS",
    "SYNC_PUSH",
    "SYNC_SINCE",
];

/// The placeholder substituted for every `{param}` path segment.
pub const PATH_PARAM_PLACEHOLDER: &str = "00000000-0000-4000-8000-000000009341";

/// `path` with every `{param}` segment replaced by [`PATH_PARAM_PLACEHOLDER`].
#[must_use]
pub fn concrete_path(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                PATH_PARAM_PLACEHOLDER
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
