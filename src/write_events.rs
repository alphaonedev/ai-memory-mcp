// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3403 — the shared memory-write EVENT funnel.
//!
//! # The defect this closes
//!
//! `grep -rn dispatch_event src/cli/` returned ZERO hits. Seven MCP
//! tools dispatched a subscription/webhook event on every successful
//! write; not one CLI write verb did. A subscriber registered for
//! `memory_store` / `memory_delete` / `memory_promote` /
//! `memory_link_created` / `memory_consolidated` therefore saw MCP and
//! HTTP writes and was structurally blind to the byte-identical write
//! made through `ai-memory store|delete|promote|link|consolidate` — and
//! the CLI was inconsistent even with itself, because the two verbs that
//! are RE-EXPORTS of MCP handlers (`reflect`, `kg-invalidate`) dispatched
//! all along. A downstream index, replicator or alerting hook that trusts
//! the event stream to be a complete record of writes was silently wrong.
//!
//! # The control
//!
//! One typed emitter per lifecycle event, each binding — in ONE place —
//! the canonical event NAME to the canonical details TYPE and to
//! [`crate::subscriptions::dispatch_event_with_details`]. Surfaces call
//! [`store`] / [`delete`] / [`promote`] / [`link_created`] /
//! [`consolidated`]; no call site re-pairs a name with a details struct.
//! That makes three classes of drift unrepresentable rather than merely
//! discouraged:
//!
//! * a surface cannot invent or misspell an event name (the pre-#3403
//!   `handle_promote` already had it both ways — `tool_names::MEMORY_PROMOTE`
//!   in the vertical arm and a bare `"memory_promote"` literal in the tier
//!   arm);
//! * a surface cannot pair one event with another event's details block;
//! * a surface cannot forget the details block a subscriber's schema
//!   depends on.
//!
//! # Delivery is fire-and-forget — one-shot surfaces must DRAIN
//!
//! [`crate::subscriptions::dispatch_event_with_details`] hands each
//! matching subscriber to a bounded worker pool and returns immediately.
//! A long-lived daemon drains that pool at shutdown
//! ([`crate::subscriptions::drain_dispatches`]). A one-shot `ai-memory`
//! invocation exits milliseconds later, so it MUST drain too — otherwise
//! this fix would dispatch events that reliably die with the process,
//! which is the reports-success-doing-nothing class rather than a fix.
//! The CLI drains once, centrally, in the `daemon_runtime::run` epilogue.
//!
//! # Notify-class, never write-class
//!
//! Every function here is infallible and best-effort. The row is already
//! durable when it is called; a subscriber outage, a full DLQ or a missed
//! drain deadline must never turn a committed write into a reported
//! failure. Delivery is additionally recoverable: the per-delivery audit
//! row is persisted BEFORE the network send, so a K7 replay-from-cursor
//! can re-deliver what a process exit truncated.

use std::path::Path;

use rusqlite::Connection;

use crate::mcp::registry::tool_names;
use crate::subscriptions::{
    self, ConsolidatedEventDetails, DeleteEventDetails, LinkCreatedEventDetails,
    PromoteEventDetails, webhook_events,
};

/// Serialise a details struct for the dispatch envelope.
///
/// A serialisation failure is not a reason to drop the event: the
/// envelope (event, memory id, namespace, agent) is what identifies the
/// write, and the details block is an enrichment. Emitting the event
/// without details is a DEGRADE; dropping it entirely would be a hole in
/// the record.
fn details_of<T: serde::Serialize>(details: &T, event: &str) -> Option<serde_json::Value> {
    match serde_json::to_value(details) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(
                "write_events: {event} details failed to serialise ({e}) — dispatching the \
                 envelope without the details block rather than dropping the event"
            );
            None
        }
    }
}

/// `memory_store` — fires after the row is committed.
///
/// The only lifecycle event with no details struct: the envelope's
/// `memory_id` + `namespace` + `agent_id` already identify the write, and
/// subscribers that need the body read it back by id.
pub fn store(
    conn: &Connection,
    db_path: &Path,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
) {
    subscriptions::dispatch_event(
        conn,
        tool_names::MEMORY_STORE,
        memory_id,
        namespace,
        agent_id,
        db_path,
    );
}

/// `memory_delete` — fires AFTER the row is gone from `memories`.
///
/// `details` comes from the caller's PRE-delete snapshot; there is no row
/// left to read it from, which is exactly why the pairing belongs here
/// and not at each call site.
pub fn delete(
    conn: &Connection,
    db_path: &Path,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    details: &DeleteEventDetails,
) {
    subscriptions::dispatch_event_with_details(
        conn,
        tool_names::MEMORY_DELETE,
        memory_id,
        namespace,
        agent_id,
        db_path,
        details_of(details, tool_names::MEMORY_DELETE),
    );
}

/// `memory_promote` — fires after a tier upgrade or a vertical
/// promote-clone commits.
///
/// In vertical mode `memory_id` is the SOURCE id and the clone is named
/// by `details.clone_id`; subscribers discriminate on `details.mode`.
pub fn promote(
    conn: &Connection,
    db_path: &Path,
    memory_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    details: &PromoteEventDetails,
) {
    subscriptions::dispatch_event_with_details(
        conn,
        tool_names::MEMORY_PROMOTE,
        memory_id,
        namespace,
        agent_id,
        db_path,
        details_of(details, tool_names::MEMORY_PROMOTE),
    );
}

/// `memory_link_created` — fires after a directed edge is persisted.
///
/// `memory_id` is the SOURCE (link-author) side; the destination is
/// `details.target_id`.
pub fn link_created(
    conn: &Connection,
    db_path: &Path,
    source_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    details: &LinkCreatedEventDetails,
) {
    subscriptions::dispatch_event_with_details(
        conn,
        webhook_events::MEMORY_LINK_CREATED,
        source_id,
        namespace,
        agent_id,
        db_path,
        details_of(details, webhook_events::MEMORY_LINK_CREATED),
    );
}

/// `memory_consolidated` — fires after `db::consolidate` commits.
///
/// `memory_id` is the NEW consolidated row; `details.source_ids` are the
/// memories that were merged away.
pub fn consolidated(
    conn: &Connection,
    db_path: &Path,
    new_id: &str,
    namespace: &str,
    agent_id: Option<&str>,
    details: &ConsolidatedEventDetails,
) {
    subscriptions::dispatch_event_with_details(
        conn,
        webhook_events::MEMORY_CONSOLIDATED,
        new_id,
        namespace,
        agent_id,
        db_path,
        details_of(details, webhook_events::MEMORY_CONSOLIDATED),
    );
}

/// Resolve the owner an event should be attributed to from a memory's
/// `metadata.agent_id`.
///
/// Shared so the CLI verbs and the MCP twins read the owner out of the
/// same field with the same fallback (`None` — never a synthesised
/// principal, which would launder an unattributed write into an
/// attributed-looking event).
#[must_use]
pub fn owner_of(memory: &crate::models::Memory) -> Option<String> {
    memory
        .metadata
        .get(crate::mcp::param_names::AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Resolve the `(namespace, owner)` a `memory_link_created` event should
/// be attributed to, by reading the SOURCE memory.
///
/// A link row carries no namespace of its own, so the event envelope
/// borrows the source's. When the source is unreadable (a race with a
/// concurrent delete) this falls back to the default namespace and NO
/// owner: an edge that was really created is still worth reporting, and
/// inventing an owner would launder an unattributed write into an
/// attributed-looking event. Shared so the MCP and CLI link paths resolve
/// it identically.
#[must_use]
pub fn link_event_origin(conn: &Connection, source_id: &str) -> (String, Option<String>) {
    match crate::db::get(conn, source_id) {
        Ok(Some(mem)) => {
            let owner = owner_of(&mem);
            (mem.namespace, owner)
        }
        _ => (crate::DEFAULT_NAMESPACE.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The event NAME each emitter is bound to is the canonical
    /// constant — pinned so a rename of either side is caught here
    /// rather than by a subscriber that silently stops matching.
    #[test]
    fn emitters_are_bound_to_the_canonical_event_names_3403() {
        assert_eq!(tool_names::MEMORY_STORE, "memory_store");
        assert_eq!(tool_names::MEMORY_DELETE, "memory_delete");
        assert_eq!(tool_names::MEMORY_PROMOTE, "memory_promote");
        assert_eq!(webhook_events::MEMORY_LINK_CREATED, "memory_link_created");
        assert_eq!(webhook_events::MEMORY_CONSOLIDATED, "memory_consolidated");
    }

    /// A details struct that cannot serialise degrades to an
    /// envelope-only dispatch — never a dropped event.
    #[test]
    fn unserialisable_details_degrade_to_envelope_only_3403() {
        struct Boom;
        impl serde::Serialize for Boom {
            fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        assert!(details_of(&Boom, "memory_delete").is_none());
        assert!(
            details_of(
                &DeleteEventDetails {
                    title: "t".into(),
                    tier: "mid".into(),
                },
                "memory_delete"
            )
            .is_some()
        );
    }
}
