// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3631 — wake the LOCAL inbox bus when federation applies an inbox
//! row.
//!
//! `memory_notify` fans out through the quorum write, so the recipient's node
//! gets the durable row through the federation receive path (`/sync/push` or
//! the catch-up pull), never through `MemoryStore::notify`. Before #3631 those
//! paths published nothing to [`crate::inbox_wake`], so a recipient on the
//! peer host learned of the message only on its `<=60 s` backstop poll. This
//! module is the one place the receive paths ask "did this apply deliver a
//! message the recipient has not seen?" and, if so, publish the same
//! `agent_notified` wake the local notify funnels publish.
//!
//! # When a wake fires
//!
//! Only when ALL of these hold, so a skipped, superseded or replayed row never
//! wakes anyone:
//!
//! 1. the inbound row is a notify row (`source = "notify"`) in an inbox
//!    namespace (`_inbox/<agent>`, or the legacy `_messages/<agent>`) whose
//!    suffix is a valid, non-reserved agent id — checked before any read, so
//!    every other row costs nothing;
//! 2. the apply returned `Ok` and the row it resolved to is readable on the
//!    ordinary read lane afterwards (a forget-tombstoned drop or a quarantined
//!    row is not);
//! 3. that row is still a notify row in an inbox namespace;
//! 4. its `updated_at` moved past what the same row had BEFORE the apply (or
//!    there was no readable row before). A replay of a row this node already
//!    holds, and an older inbound that lost the newer-wins merge, leave
//!    `updated_at` where it was and wake nobody.
//!
//! A probe or read failure means no wake. That is the safe direction: the wake
//! is a hint, and the durable row plus the backstop poll still deliver.
//!
//! # What the wake carries
//!
//! Exactly what [`crate::write_events::agent_notified_wake`] carries for a
//! local notify: recipient, row id, namespace, sender and a DIGEST of the
//! body. The body itself is only handed over to be digested, so the #3578
//! content boundary holds by construction. The sender is the author recorded
//! on the inbound row after the receive path's attribution gate, and the wake
//! frame's `from` stays the reserved producer id (`wake_sink`), as it does for
//! every other wake.
//!
//! # Deliberately not covered
//!
//! `ai-memory sync-daemon` (`daemon_runtime::sync_cycle_once`) and the one-shot
//! `ai-memory sync` CLI also apply remote rows, but they run in their own
//! process, which installs no wake sink: a publish there would reach no hub.

use crate::models::Memory;

/// `source` stamped on every inbox row by both notify funnels
/// (`mcp::tools::notify` and the SAL `MemoryStore::notify` adapters).
const NOTIFY_SOURCE: &str = "notify";

/// Tracing target for probe/read failures on this path.
const TRACE_TARGET: &str = "federation.applied_wake";

/// What the receive path saw of an inbox row BEFORE applying an inbound
/// write. Only built for wake candidates; see [`is_candidate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreApply {
    /// `updated_at` of the readable local row the apply will land on (the
    /// same id, else the same `(title, namespace)`), `None` when there is
    /// none.
    prior_updated_at: Option<String>,
}

/// The recipient an inbox namespace belongs to, when it is a valid wire
/// agent id. Reserved ids (the hub producer, internal sentinels) are refused,
/// so federation cannot address a wake to them.
fn inbox_recipient(namespace: &str) -> Option<&str> {
    namespace
        .strip_prefix(crate::INBOX_NAMESPACE_PREFIX)
        .or_else(|| namespace.strip_prefix(crate::LEGACY_INBOX_NAMESPACE_PREFIX))
        .filter(|recipient| crate::validate::validate_agent_id(recipient).is_ok())
}

/// Whether `mem` is a notify row in an inbox namespace. Pure, so the receive
/// hot path pays nothing for every other row.
fn is_inbox_notify(mem: &Memory) -> bool {
    mem.source == NOTIFY_SOURCE && inbox_recipient(&mem.namespace).is_some()
}

/// Whether an inbound row could wake a recipient at all.
#[must_use]
pub(crate) fn is_candidate(inbound: &Memory) -> bool {
    is_inbox_notify(inbound)
}

/// Whether the row's `updated_at` moved past `prior`. Both sides are parsed as
/// instants rather than compared as strings, because the two backends render
/// the same instant differently. An unparseable value means "not provably
/// newer", which suppresses the wake.
fn advanced(prior: Option<&str>, post: &str) -> bool {
    let Some(prior) = prior else {
        return true;
    };
    match (
        chrono::DateTime::parse_from_rfc3339(prior),
        chrono::DateTime::parse_from_rfc3339(post),
    ) {
        (Ok(before), Ok(after)) => after > before,
        _ => false,
    }
}

/// The wake an applied row earns, or `None`. Pure: the decision is the same
/// on every backend, and only the reads that feed it differ.
fn wake_for<'a>(
    pre: &PreApply,
    inbound: &'a Memory,
    post: &'a Memory,
) -> Option<crate::write_events::AgentNotified<'a>> {
    if !post.lifecycle_state.is_recall_visible() || !is_inbox_notify(post) {
        return None;
    }
    if !advanced(pre.prior_updated_at.as_deref(), &post.updated_at) {
        return None;
    }
    let recipient = inbox_recipient(&post.namespace)?;
    let sender = inbound
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .filter(|sender| crate::validate::validate_agent_id(sender).is_ok())?;
    Some(crate::write_events::AgentNotified {
        recipient_agent_id: recipient,
        sender_agent_id: sender,
        inbox_row_id: &post.id,
        namespace: &post.namespace,
        content: &inbound.content,
    })
}

/// Publish the wake an applied row earns, if any.
fn publish(pre: &PreApply, inbound: &Memory, post: &Memory) {
    if let Some(event) = wake_for(pre, inbound, post) {
        crate::write_events::agent_notified_wake(&event);
    }
}

fn log_read_failed(stage: &str, id: &str, err: &dyn std::fmt::Display) {
    tracing::debug!(
        target: TRACE_TARGET,
        memory_id = %id,
        "{stage} read failed, no wake (the backstop poll still delivers): {err}"
    );
}

/// Sqlite probe, taken on the receive connection before the apply.
///
/// Returns `None` (no wake later) for a non-candidate row or a failed read.
#[must_use]
pub(crate) fn probe_sqlite(conn: &rusqlite::Connection, inbound: &Memory) -> Option<PreApply> {
    if !is_candidate(inbound) {
        return None;
    }
    let by_id = match crate::db::get(conn, &inbound.id) {
        Ok(row) => row,
        Err(e) => {
            log_read_failed("pre-apply", &inbound.id, &e);
            return None;
        }
    };
    let prior = match by_id {
        Some(row) => Some(row),
        None => {
            match crate::db::find_by_title_namespace(conn, &inbound.title, &inbound.namespace) {
                Ok(Some(id)) => match crate::db::get(conn, &id) {
                    Ok(row) => row,
                    Err(e) => {
                        log_read_failed("pre-apply", &id, &e);
                        return None;
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    log_read_failed("pre-apply", &inbound.id, &e);
                    return None;
                }
            }
        }
    };
    Some(PreApply {
        prior_updated_at: prior.map(|row| row.updated_at),
    })
}

/// Sqlite half after a successful apply that resolved to `applied_id`. The
/// apply has already committed (the receive funnels run no outer
/// transaction), so the row the wake names is durable.
pub(crate) fn fire_sqlite(
    conn: &rusqlite::Connection,
    pre: Option<PreApply>,
    inbound: &Memory,
    applied_id: &str,
) {
    let Some(pre) = pre else {
        return;
    };
    match crate::db::get(conn, applied_id) {
        Ok(Some(post)) => publish(&pre, inbound, &post),
        Ok(None) => {}
        Err(e) => log_read_failed("post-apply", applied_id, &e),
    }
}

/// Read one row through the SAL: `Ok(None)` when it is missing or not
/// readable on the ordinary read lane, `Err` on a store fault.
#[cfg(feature = "sal")]
async fn store_get(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    id: &str,
) -> Result<Option<Memory>, crate::store::StoreError> {
    match store.get(ctx, id).await {
        Ok(row) => Ok(Some(row)),
        Err(crate::store::StoreError::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// SAL probe (the postgres receive funnel and the SAL catch-up), taken before
/// the apply. `ctx` must read without visibility filtering (an admin context),
/// like the sqlite probe's `db::get`: an inbox row is private to its
/// recipient, so a sender-scoped read would miss a row already held and let a
/// replay wake again. The same holds for [`fire_store`].
#[cfg(feature = "sal")]
pub(crate) async fn probe_store(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    inbound: &Memory,
) -> Option<PreApply> {
    if !is_candidate(inbound) {
        return None;
    }
    let by_id = match store_get(store, ctx, &inbound.id).await {
        Ok(row) => row,
        Err(e) => {
            log_read_failed("pre-apply", &inbound.id, &e);
            return None;
        }
    };
    let prior = match by_id {
        Some(row) => Some(row),
        None => match store
            .find_by_title_namespace(&inbound.title, &inbound.namespace)
            .await
        {
            Ok(Some(id)) => match store_get(store, ctx, &id).await {
                Ok(row) => row,
                Err(e) => {
                    log_read_failed("pre-apply", &id, &e);
                    return None;
                }
            },
            Ok(None) => None,
            Err(e) => {
                log_read_failed("pre-apply", &inbound.id, &e);
                return None;
            }
        },
    };
    Some(PreApply {
        prior_updated_at: prior.map(|row| row.updated_at),
    })
}

/// SAL half after a successful apply that resolved to `applied_id`.
#[cfg(feature = "sal")]
pub(crate) async fn fire_store(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    pre: Option<PreApply>,
    inbound: &Memory,
    applied_id: &str,
) {
    let Some(pre) = pre else {
        return;
    };
    match store_get(store, ctx, applied_id).await {
        Ok(Some(post)) => publish(&pre, inbound, &post),
        Ok(None) => {}
        Err(e) => log_read_failed("post-apply", applied_id, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn notify_row(recipient: &str, updated_at: &str) -> Memory {
        Memory {
            id: "row-1".to_string(),
            namespace: crate::inbox_namespace(recipient),
            title: "subject".to_string(),
            content: "body".to_string(),
            source: NOTIFY_SOURCE.to_string(),
            created_at: "2026-09-01T00:00:00+00:00".to_string(),
            updated_at: updated_at.to_string(),
            metadata: json!({"agent_id": "ai:alice", "notify": true}),
            ..Default::default()
        }
    }

    const T0: &str = "2026-09-01T00:00:00+00:00";
    const T1: &str = "2026-09-01T00:00:01Z";

    #[test]
    fn a_fresh_inbox_row_wakes_its_recipient_3631() {
        let row = notify_row("ai:bob", T0);
        let pre = PreApply {
            prior_updated_at: None,
        };
        let ev = wake_for(&pre, &row, &row).expect("a fresh inbox row wakes");
        assert_eq!(ev.recipient_agent_id, "ai:bob");
        assert_eq!(ev.sender_agent_id, "ai:alice");
        assert_eq!(ev.inbox_row_id, "row-1");
        assert_eq!(ev.namespace, "_inbox/ai:bob");
    }

    #[test]
    fn the_legacy_inbox_prefix_still_names_the_recipient_3631() {
        assert_eq!(inbox_recipient("_messages/ai:bob"), Some("ai:bob"));
        assert_eq!(inbox_recipient("_inbox/ai:bob"), Some("ai:bob"));
        assert_eq!(inbox_recipient("team/ai:bob"), None);
        assert_eq!(inbox_recipient("_inbox/"), None);
    }

    #[test]
    fn a_replay_or_a_lost_merge_wakes_nobody_3631() {
        let row = notify_row("ai:bob", T0);
        // Same updated_at as before the apply: a replay, or an older inbound
        // that lost newer-wins. Rendered differently on purpose.
        let pre = PreApply {
            prior_updated_at: Some("2026-09-01T00:00:00Z".to_string()),
        };
        assert!(wake_for(&pre, &row, &row).is_none());
        // A newer local row than the post-apply row can only mean a clock
        // anomaly; it never wakes either.
        let pre = PreApply {
            prior_updated_at: Some(T1.to_string()),
        };
        assert!(wake_for(&pre, &row, &row).is_none());
    }

    #[test]
    fn a_newer_inbound_that_won_the_merge_wakes_3631() {
        let row = notify_row("ai:bob", T1);
        let pre = PreApply {
            prior_updated_at: Some(T0.to_string()),
        };
        assert!(wake_for(&pre, &row, &row).is_some());
    }

    #[test]
    fn non_notify_hidden_and_reserved_rows_wake_nobody_3631() {
        let pre = PreApply {
            prior_updated_at: None,
        };
        let mut other_source = notify_row("ai:bob", T0);
        other_source.source = "api".to_string();
        assert!(!is_candidate(&other_source));
        assert!(wake_for(&pre, &other_source, &other_source).is_none());

        let mut quarantined = notify_row("ai:bob", T0);
        quarantined.lifecycle_state = crate::models::LifecycleState::Quarantined;
        assert!(wake_for(&pre, &quarantined, &quarantined).is_none());

        let reserved = notify_row(crate::identity::sentinels::DAEMON_PRINCIPAL, T0);
        assert!(!is_candidate(&reserved));

        let mut forged_sender = notify_row("ai:bob", T0);
        forged_sender.metadata = json!({"agent_id": "../escape"});
        assert!(wake_for(&pre, &forged_sender, &forged_sender).is_none());

        let mut no_sender = notify_row("ai:bob", T0);
        no_sender.metadata = json!({});
        assert!(wake_for(&pre, &no_sender, &no_sender).is_none());
    }

    #[test]
    fn an_unparseable_timestamp_never_proves_newer_3631() {
        assert!(!advanced(Some("not-a-time"), T1));
        assert!(!advanced(Some(T0), "not-a-time"));
        assert!(advanced(None, "not-a-time"));
    }

    #[test]
    fn the_sqlite_probe_and_fire_follow_the_apply_3631() {
        let conn = crate::db::open(std::path::Path::new(":memory:")).expect("open");
        let recipient = "ai:bob-3631-unit";
        let mut rx = crate::inbox_wake::subscribe();

        let row = notify_row(recipient, T0);
        let pre = probe_sqlite(&conn, &row);
        assert_eq!(
            pre,
            Some(PreApply {
                prior_updated_at: None
            })
        );
        let id = crate::db::insert_if_newer(&conn, &row).expect("apply");
        fire_sqlite(&conn, pre, &row, &id);
        let woke = drain_for(&mut rx, recipient);
        assert_eq!(woke, vec![id.clone()], "one wake for the fresh row");

        // The same row again: probed as already held, so no second wake.
        let pre = probe_sqlite(&conn, &row);
        let again = crate::db::insert_if_newer(&conn, &row).expect("replay");
        fire_sqlite(&conn, pre, &row, &again);
        assert!(
            drain_for(&mut rx, recipient).is_empty(),
            "a replay wakes nobody"
        );

        // Not a candidate: never probed, never fired.
        let mut plain = notify_row(recipient, T0);
        plain.id = "row-2".to_string();
        plain.title = "plain".to_string();
        plain.source = "api".to_string();
        assert_eq!(probe_sqlite(&conn, &plain), None);
    }

    fn drain_for(
        rx: &mut tokio::sync::broadcast::Receiver<crate::inbox_wake::InboxEvent>,
        recipient: &str,
    ) -> Vec<String> {
        use tokio::sync::broadcast::error::TryRecvError;
        let mut ids = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(crate::inbox_wake::InboxEvent::AgentNotified {
                    recipient_agent_id,
                    inbox_row_id,
                    ..
                }) => {
                    if recipient_agent_id == recipient {
                        ids.push(inbox_row_id);
                    }
                }
                // Other tests share the process-wide bus; a lag only drops
                // THEIR frames from this receiver's view of the buffer.
                Err(TryRecvError::Lagged(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Closed) => return ids,
            }
        }
    }
}
