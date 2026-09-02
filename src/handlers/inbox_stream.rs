// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3465 — `GET /api/v1/inbox/stream`.
//!
//! The agent-facing push side of `memory_notify`. A recipient holds one
//! long-lived SSE connection and is woken the instant a notification
//! row commits, instead of polling `GET /api/v1/inbox` (the current
//! fleet polls every three minutes, spawning a CLI process per poll).
//!
//! Modelled on [`crate::handlers::approvals_sse`] — the same
//! `tokio::sync::broadcast` fan-out, the same `enforce_idor_identity`
//! gate at stream open, the same 15 s keepalive, the same synthetic
//! `lagged` frame on ring overflow — but fed from
//! [`crate::inbox_wake`] rather than the webhook lane, because a
//! recipient's wake latency must not sit behind the webhook lane's
//! 32-permit global semaphore and 1000-row subscription-scan cliff.
//!
//! # Identity binding is STRICTER than the approvals stream
//!
//! `approvals_sse` widens visibility through K9 `Allow` rules so a
//! designated approver can watch rows it may act on. An inbox has no
//! such delegate: the rows are scope=private agent-to-agent messages
//! and `GET /api/v1/inbox` / `memory_inbox` already refuse a caller
//! that asks for someone else's inbox (#1557). This stream holds the
//! same line — a caller receives wakes for its OWN inbox and nothing
//! else — so the push surface cannot become a way to observe an inbox
//! the pull surface would refuse.
//!
//! Fail-closed on an unresolved identity: an anonymous subscriber
//! (missing / unreadable `X-Agent-Id`, or a self-asserted `host:`
//! principal) gets a stream that never yields a frame, not a stream
//! that yields everything.
//!
//! # A wake is a hint, never the record
//!
//! Frames carry a content DIGEST, never the body. A woken client reads
//! its mail through the existing owner-gated inbox read. That is also
//! what makes a dropped frame safe: `lagged` degrades to "read your
//! inbox now", never to "a message was lost" — the durable row is the
//! record, the wake is only the prompt to go look at it.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;

use super::transport::AppState;

/// Predicate: may the SSE subscriber identified by `subscriber_agent`
/// see this wake?
///
/// Exactly one rule: the subscriber IS the recipient. No namespace
/// widening, no permission-rule delegation, no operator bypass — see
/// the module docs. An empty or `host:`-prefixed subscriber id is a
/// non-identity and sees nothing (`host:` is the SERVER-side fallback
/// principal from `identity::resolve_agent_id`; accepting it from a
/// client is the #628 P1 escalation this mirrors).
#[must_use]
pub fn inbox_wake_visible_to(
    subscriber_agent: &str,
    event: &crate::inbox_wake::InboxEvent,
) -> bool {
    if subscriber_agent.is_empty() || subscriber_agent.starts_with("host:") {
        return false;
    }
    event.recipient_agent_id() == subscriber_agent
}

/// `GET /api/v1/inbox/stream` — SSE wake stream for the caller's own
/// inbox.
///
/// Emits one `agent_notified` frame per committed notify to the
/// recipient (and to nobody else), plus a synthetic `lagged` frame when
/// this subscriber falls more than
/// [`crate::inbox_wake::INBOX_WAKE_BROADCAST_CAPACITY`] frames behind.
/// A keepalive comment every 15 s keeps intermediaries from reaping the
/// idle connection.
///
/// The identity decision is made ONCE, at open: the connection is
/// long-lived, so there is no per-frame re-resolution of a mutable
/// header. Under `enforce`, a merely-`Claimed` named principal is
/// refused `403 attested_identity_required` before any subscription
/// exists — `X-Agent-Id` is self-asserted while an api-key is only a
/// shared transport credential, so without this gate a shared-key
/// caller forging `X-Agent-Id: <victim>` would stream the victim's
/// wake metadata.
pub async fn inbox_sse(
    State(app): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration as StdDuration;
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

    // Per-agent-key identity gate at STREAM OPEN, BEFORE the
    // broadcast subscription is filtered by the self-asserted
    // `subscriber_agent` — the #2154 (#2032-A / H1 IDOR) control, same
    // shape and same status as `approvals_sse` and the gated
    // request/response inbox read. Fully inert under
    // zero-enrollment / advisory / off.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "inbox_stream",
    ) {
        return resp;
    }

    // Resolve the subscriber from the (middleware-bound) `X-Agent-Id`
    // header. An enrolled per-agent key has already been rebound to its
    // key-derived principal by `api_key_auth`, and under `enforce` the
    // gate above has already refused a merely-`Claimed` named
    // principal, so the value reaching the filter is the BOUND
    // principal. A `host:`-prefixed value is treated as anonymous and,
    // like an absent header, yields a stream that never emits.
    let subscriber_agent = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.starts_with("host:"))
        .unwrap_or("")
        .to_string();

    /// Bridges a `BroadcastStream<InboxEvent>` into the
    /// `Stream<Item = Result<Event, Infallible>>` axum's `Sse`
    /// requires. Frames for other recipients are dropped silently;
    /// `Lagged` becomes a synthetic `lagged` event so the client does
    /// one catch-up inbox read instead of silently missing mail;
    /// channel `Closed` ends the stream.
    struct InboxSseStream {
        inner: BroadcastStream<crate::inbox_wake::InboxEvent>,
        subscriber_agent: String,
    }

    impl Stream for InboxSseStream {
        type Item = Result<Event, std::convert::Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            loop {
                match Pin::new(&mut self.inner).poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Ready(Some(Ok(evt))) => {
                        if !inbox_wake_visible_to(&self.subscriber_agent, &evt) {
                            // Another agent's inbox: skip without
                            // surfacing anything at all — not even a
                            // "something happened" tick, which would
                            // leak the other tenant's notify rate.
                            continue;
                        }
                        let data = match serde_json::to_string(&evt) {
                            Ok(s) => s,
                            Err(e) => {
                                // Degrading to an empty body would be
                                // indistinguishable from a malformed
                                // frame; emit a typed `error` so the
                                // client re-syncs via GET /api/v1/inbox.
                                tracing::error!("inbox_sse: serialise InboxEvent failed: {e}");
                                return Poll::Ready(Some(Ok(Event::default()
                                    .event("error")
                                    .data(r#"{"error":"event_serialise_failed"}"#))));
                            }
                        };
                        return Poll::Ready(Some(Ok(Event::default()
                            .event(evt.event_name())
                            .data(data))));
                    }
                    Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(_n)))) => {
                        // The dropped count `n` spans EVERY tenant's
                        // wakes, so reporting it would let a subscriber
                        // fingerprint other agents' notify rates (the
                        // #628 P4 finding). Say only "you lagged"; the
                        // client re-syncs with an inbox read, for which
                        // the count is irrelevant.
                        let body = serde_json::json!({"lagged": true}).to_string();
                        return Poll::Ready(Some(Ok(Event::default().event("lagged").data(body))));
                    }
                }
            }
        }
    }

    let rx = crate::inbox_wake::subscribe();
    let stream = InboxSseStream {
        inner: BroadcastStream::new(rx),
        subscriber_agent,
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(StdDuration::from_secs(15)))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox_wake::InboxEvent;

    fn wake_for(recipient: &str) -> InboxEvent {
        InboxEvent::AgentNotified {
            seq: 1,
            recipient_agent_id: recipient.to_string(),
            correlation_id: "sha256:c".into(),
            inbox_row_id: "row-1".into(),
            namespace: format!("_messages/{recipient}"),
            sender_agent_id: "alice".into(),
            content_digest: "sha256:d".into(),
            notified_at: "2026-09-02T00:00:00Z".into(),
        }
    }

    /// ALLOWED: the recipient sees its own wake.
    #[test]
    fn recipient_sees_its_own_wake_3465() {
        assert!(inbox_wake_visible_to("bob", &wake_for("bob")));
    }

    /// DENIED: a different agent never sees it — an inbox has no
    /// delegate, unlike the approvals stream.
    #[test]
    fn other_agent_never_sees_another_inbox_wake_3465() {
        assert!(!inbox_wake_visible_to("mallory", &wake_for("bob")));
    }

    /// DENIED: an unresolved identity is fail-closed, not fail-open.
    #[test]
    fn anonymous_subscriber_sees_nothing_3465() {
        assert!(!inbox_wake_visible_to("", &wake_for("bob")));
    }

    /// DENIED: a self-asserted server-side `host:` principal is not an
    /// identity (the #628 P1 escalation class).
    #[test]
    fn host_prefixed_subscriber_sees_nothing_3465() {
        assert!(!inbox_wake_visible_to(
            "host:node-1",
            &wake_for("host:node-1")
        ));
        assert!(!inbox_wake_visible_to("host:node-1", &wake_for("bob")));
    }

    /// A prefix of the recipient id is not the recipient.
    #[test]
    fn prefix_of_recipient_is_not_the_recipient_3465() {
        assert!(!inbox_wake_visible_to("bo", &wake_for("bob")));
        assert!(!inbox_wake_visible_to("bobby", &wake_for("bob")));
    }

    /// The serialised frame carries the digest and NEVER a body field.
    #[test]
    fn frame_carries_no_body_3465() {
        let json = serde_json::to_string(&wake_for("bob")).expect("serialise");
        assert!(json.contains("content_digest"), "{json}");
        assert!(!json.contains("payload"), "{json}");
        assert!(!json.contains("content\":"), "{json}");
    }
}
