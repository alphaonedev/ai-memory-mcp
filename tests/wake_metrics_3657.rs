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
    assert!(metrics::wake_drop_count(WakeDropCause::Overflow) >= before + 1);
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
    assert!(metrics::wake_drop_count(WakeDropCause::HubDown) >= before + 1);
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
    assert!(metrics::wake_drop_count(WakeDropCause::RecipientQueueFull) >= before_q + 1);
    assert!(metrics::wake_drop_count(WakeDropCause::GlobalEgressFull) >= before_e + 1);
    let text = metrics::render();
    assert!(text.contains("cause=\"recipient_queue_full\""), "{text}");
    assert!(text.contains("cause=\"global_egress_full\""), "{text}");
}

#[test]
fn backstop_reliance_is_its_own_series_3657() {
    let before = metrics::wake_backstop_reliance_count();
    metrics::inc_wake_backstop_reliance();
    assert!(metrics::wake_backstop_reliance_count() >= before + 1);
    let text = metrics::render();
    assert!(
        text.contains(METRIC_WAKE_BACKSTOP_RELIANCE_TOTAL),
        "backstop reliance missing from scrape:\n{text}"
    );
}

#[test]
fn every_published_cause_has_a_stable_label_3657() {
    assert_eq!(WakeDropCause::ALL.len(), 11);
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
