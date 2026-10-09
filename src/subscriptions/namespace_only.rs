// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4280 — namespace-only subscriptions are recorded, never delivered.
//!
//! `POST /api/v1/subscriptions` with `{agent_id, namespace}` and no `url`
//! (the S33 shape) stores an ordinary subscription row whose url is
//! synthesized as `https://localhost/_ns/<agent>/<namespace>`. Its consumer
//! reads the `subscription_events` audit rows through
//! `memory_subscription_replay`; there is no receiver. Before #4280 the
//! dispatcher treated the row like a webhook: every matching event also
//! attempted a delivery to the synthetic loopback URL, which the dispatch-time
//! SSRF guard refuses by default, leaving one un-actionable `subscription_dlq`
//! row per event (and, with `allow_loopback_webhooks`, a request to whatever
//! listens on the daemon host's port 443).
//!
//! The marker is the URL itself (5-agent vote (4d3ea1c5), 4-1 for the
//! reserved-prefix form over a persisted flag column): the prefix is RESERVED,
//! refused on every caller registration surface through
//! [`super::validate_url`], so only the synthesizer can produce it. Legacy
//! rows on both backends already carry it, so no migration or backfill is
//! needed, and a replicated postgres subscription row cannot carry a separate
//! flag that silences deliveries while still showing a real URL.
//!
//! The dispatcher writes the event's audit row with the terminal status
//! [`DELIVERY_STATUS_RECORDED`] ("never sent, by design") and spawns nothing:
//! no delivery attempt, no DLQ row, no dispatch counters.

use anyhow::{Context as _, Result, anyhow, ensure};
use rusqlite::{Connection, params};

/// The synthetic URL prefix of a namespace-only subscription.
pub const NAMESPACE_ONLY_URL_PREFIX: &str = "https://localhost/_ns/";

/// `subscription_events.delivery_status` of a namespace-only event: recorded
/// for replay, never sent. Terminal, like `ack` and `failed`.
pub const DELIVERY_STATUS_RECORDED: &str = "recorded";

/// The synthetic URL the S33 shape stores for `(agent, namespace)`.
#[must_use]
pub fn url_for(agent: &str, namespace: &str) -> String {
    format!("{NAMESPACE_ONLY_URL_PREFIX}{agent}/{namespace}")
}

/// `true` for a namespace-only row. Exact match on the synthesized form; a
/// look-alike falls through to the ordinary webhook path (and its SSRF guard).
#[must_use]
pub fn is_namespace_only_url(url: &str) -> bool {
    url.starts_with(NAMESPACE_ONLY_URL_PREFIX)
}

/// Registration-time refusal of the reserved prefix, in any letter case.
pub(super) fn refuse_reserved(url: &str) -> Result<()> {
    let reserved = url
        .get(..NAMESPACE_ONLY_URL_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(NAMESPACE_ONLY_URL_PREFIX));
    if reserved {
        return Err(anyhow!(
            "webhook URL prefix {NAMESPACE_ONLY_URL_PREFIX} is reserved for namespace-only \
             subscriptions; register one with {{agent_id, namespace}} and no url (#4280)"
        ));
    }
    Ok(())
}

/// Insert a namespace-only subscription. Only for the synthesizer: the URL
/// must be the synthesized form, which [`super::insert`] (the caller path)
/// refuses.
///
/// # Errors
/// When the URL is not a namespace-only URL, or the insert fails.
pub fn insert(conn: &Connection, req: &super::NewSubscription<'_>) -> Result<String> {
    ensure!(
        is_namespace_only_url(req.url),
        "not a namespace-only subscription URL"
    );
    super::insert_unvalidated(conn, req)
}

/// Write a namespace-only event's audit row, already settled.
pub(super) fn record_with_conn(
    conn: &Connection,
    sub_id: &str,
    correlation_id: &str,
    event_type: &str,
    payload: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO subscription_events \
         (subscription_id, correlation_id, event_type, payload, delivered_at, delivery_status) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            sub_id,
            correlation_id,
            event_type,
            payload,
            chrono::Utc::now().to_rfc3339(),
            DELIVERY_STATUS_RECORDED,
        ],
    )
    .context("subscription_events insert (namespace-only)")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_synthesized_url_is_recognised_and_reserved_4280() {
        let url = url_for("ai:alice", "team/eng");
        assert!(is_namespace_only_url(&url));
        assert!(refuse_reserved(&url).is_err());
        assert!(refuse_reserved("HTTPS://LOCALHOST/_NS/x").is_err());
        assert!(refuse_reserved("https://localhost/hook").is_ok());
        assert!(refuse_reserved("https://example.com/_ns/x").is_ok());
        assert!(!is_namespace_only_url("https://localhost:8443/_ns/x"));
    }
}
