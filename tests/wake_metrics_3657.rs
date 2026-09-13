// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3657 — wake counters that lived only in-process must scrape.
//!
//! The health-monitoring surface (#3646) owns exposition. This lane
//! dual-writes existing sink/hub/client counters onto the process-global
//! Prometheus registry so `GET /metrics` (and #3646's later gather) see
//! **drops by cause** and **backstop reliance**, never a single unlabeled
//! drops total.

use std::sync::Arc;

use ai_memory::inbox_wake::{InboxEvent, InboxWakeSink as _};
use ai_memory::metrics::{
    self, METRIC_WAKE_BACKSTOP_RELIANCE_TOTAL, METRIC_WAKE_DROPS_TOTAL, WakeDropCause,
};
use ai_memory::wake_hub::limits::WAKE_DIGEST_BYTES;
use ai_memory::wake_hub::metrics::HubMetrics;
use ai_memory::wake_hub::routing::Delivery;
use ai_memory::wake_sink::in_process::{InProcessWakeSink, WakeDelivery};
use ai_memory::wake_sink::{CONTENT_DIGEST_PREFIX, SinkMetrics};
use bytes::Bytes;

fn notified(recipient: &str) -> InboxEvent {
    let digest = format!("{CONTENT_DIGEST_PREFIX}{}", "ab".repeat(WAKE_DIGEST_BYTES));
    InboxEvent::AgentNotified {
        seq: 1,
        recipient_agent_id: recipient.into(),
        correlation_id: "sha256:corr".into(),
        inbox_row_id: "row-3657".into(),
        namespace: "_inbox/bob".into(),
        sender_agent_id: "ai:alice".into(),
        content_digest: digest,
        notified_at: "2026-09-12T00:00:00Z".into(),
    }
}

struct Scripted(Delivery);

impl WakeDelivery for Scripted {
    fn deliver_wake(&self, _recipient: &str, _frame: &Bytes, _inbox_row_id: &str) -> Delivery {
        self.0
    }
}

#[test]
fn overflow_scrapes_as_its_own_cause_3657() {
    let before = metrics::wake_drop_count(WakeDropCause::Overflow);
    let sink = InProcessWakeSink::new(Arc::new(Scripted(Delivery::Overflow)));
    sink.on_wake(&notified("bob"));
    assert_eq!(sink.metrics().snapshot().dropped_overflow, 1);
    assert!(metrics::wake_drop_count(WakeDropCause::Overflow) > before);
    let text = metrics::render();
    assert!(
        text.contains(&format!("{METRIC_WAKE_DROPS_TOTAL}{{cause=\"overflow\"}}")),
        "overflow scrape missing labeled series:\n{text}"
    );
    assert!(
        !text
            .lines()
            .any(|l| l.starts_with(&format!("{METRIC_WAKE_DROPS_TOTAL} "))
                && !l.contains("cause=")),
        "must not emit an unlabeled drops total:\n{text}"
    );
}

#[test]
fn hub_down_scrapes_as_its_own_cause_3657() {
    let before = metrics::wake_drop_count(WakeDropCause::HubDown);
    let m = SinkMetrics::default();
    m.dropped_hub_down();
    assert!(metrics::wake_drop_count(WakeDropCause::HubDown) > before);
    let text = metrics::render();
    assert!(
        text.contains(&format!("{METRIC_WAKE_DROPS_TOTAL}{{cause=\"hub_down\"}}")),
        "hub-down scrape missing labeled series:\n{text}"
    );
}

#[test]
fn hub_per_cause_drops_scrape_and_do_not_collapse_3657() {
    let before_q = metrics::wake_drop_count(WakeDropCause::RecipientQueueFull);
    let before_e = metrics::wake_drop_count(WakeDropCause::GlobalEgressFull);
    let hub = HubMetrics::default();
    hub.drop_recipient_queue_full();
    hub.drop_global_egress_full();
    hub.overflow();
    assert!(metrics::wake_drop_count(WakeDropCause::RecipientQueueFull) > before_q);
    assert!(metrics::wake_drop_count(WakeDropCause::GlobalEgressFull) > before_e);
    let text = metrics::render();
    assert!(text.contains("cause=\"recipient_queue_full\""), "{text}");
    assert!(text.contains("cause=\"global_egress_full\""), "{text}");
}

#[test]
fn backstop_reliance_is_its_own_series_3657() {
    let before = metrics::wake_backstop_reliance_count();
    metrics::inc_wake_backstop_reliance();
    assert!(metrics::wake_backstop_reliance_count() > before);
    let text = metrics::render();
    assert!(
        text.contains(METRIC_WAKE_BACKSTOP_RELIANCE_TOTAL),
        "backstop reliance missing from scrape:\n{text}"
    );
}

#[test]
fn every_published_cause_has_a_stable_label_3657() {
    assert_eq!(WakeDropCause::ALL.len(), 13);
    let mut seen = std::collections::BTreeSet::new();
    for cause in WakeDropCause::ALL {
        assert!(
            seen.insert(cause.as_label()),
            "duplicate label {}",
            cause.as_label()
        );
        assert!(!cause.as_label().is_empty());
        assert!(!cause.as_label().contains(' '));
    }
}

#[test]
fn hub_enqueue_refusal_labels_match_scrape_causes_3657() {
    use ai_memory::wake_hub::routing::EnqueueRefusal;
    assert_eq!(
        EnqueueRefusal::RecipientQueueFull.label(),
        WakeDropCause::RecipientQueueFull.as_label()
    );
    assert_eq!(
        EnqueueRefusal::GlobalEgressFull.label(),
        WakeDropCause::GlobalEgressFull.as_label()
    );
    assert_eq!(
        EnqueueRefusal::ChannelFull.label(),
        WakeDropCause::ChannelFull.as_label()
    );
}

/// #3657 — the two causes the audit named that had no series: a refused
/// (revoked / expired) delegation and an undecodable frame. Both must scrape
/// under their own label, never fold into `unknown` or a total.
#[test]
fn delegation_revoked_and_malformed_frame_scrape_as_their_own_causes_3657() {
    let before_d = metrics::wake_drop_count(WakeDropCause::DelegationRevoked);
    let before_m = metrics::wake_drop_count(WakeDropCause::MalformedFrame);
    let hub = HubMetrics::default();
    hub.drop_delegation_revoked();
    hub.denied_malformed();
    assert!(metrics::wake_drop_count(WakeDropCause::DelegationRevoked) > before_d);
    assert!(metrics::wake_drop_count(WakeDropCause::MalformedFrame) > before_m);
    let snap = hub.snapshot(0);
    assert_eq!(snap.drop_delegation_revoked, 1);
    assert_eq!(snap.denied_malformed, 1);
    let doc = snap.to_json();
    assert_eq!(doc["drops"]["delegation_revoked"], 1);
    assert_eq!(doc["drops"]["malformed_frame"], 1);
    let text = metrics::render();
    assert!(text.contains("cause=\"delegation_revoked\""), "{text}");
    assert!(text.contains("cause=\"malformed_frame\""), "{text}");
}

/// #3657 — "delivered" is measured at the hub writer, not inferred from a
/// route: `wakes_written` counts wake frames that reached a recipient
/// socket, and it dual-writes onto `ai_memory_wake_delivered_total`.
#[test]
fn hub_written_wakes_scrape_as_delivered_3657() {
    let before = metrics::wake_delivered_count();
    let hub = HubMetrics::default();
    hub.wake_written();
    assert_eq!(hub.snapshot(0).wakes_written, 1);
    assert_eq!(
        hub.snapshot(0).to_json()["traffic"]["wakes_written_total"],
        1
    );
    assert!(metrics::wake_delivered_count() > before);
    assert!(
        metrics::render().contains(metrics::METRIC_WAKE_DELIVERED_TOTAL),
        "delivered series missing from scrape"
    );
}

/// #3657 — the fallback gauge has four values and the one nobody observed is
/// `0`; a fresh registry must not read `hub live`.
#[test]
fn fallback_state_values_are_distinct_and_unobserved_is_zero_3657() {
    let values = [
        metrics::WAKE_FALLBACK_UNOBSERVED,
        metrics::WAKE_FALLBACK_HUB_LIVE,
        metrics::WAKE_FALLBACK_BACKSTOP,
        metrics::WAKE_FALLBACK_CONNECTING,
    ];
    let set: std::collections::BTreeSet<i64> = values.into_iter().collect();
    assert_eq!(set.len(), values.len(), "{values:?}");
    assert_eq!(metrics::WAKE_FALLBACK_UNOBSERVED, 0);
}
