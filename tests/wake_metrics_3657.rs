// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3657 — the wake sink's counters reach the daemon's scrape surface.
//!
//! `src/wake_sink` counts every wake the installed sink saw, delivered,
//! coalesced or dropped (per cause), and `install_uds` / `install_in_process`
//! hand those counters back to their caller. Before #3657 the caller was
//! `serve`, which discarded the `Arc` (`src/wake_sink/boot.rs`), so the only
//! readers were library tests: an operator scraping `/metrics` could not tell
//! a quiet fleet from a hub that silently stopped waking anyone.
//!
//! This suite installs the ONE process-wide sink the real `install_in_process`
//! installs, publishes one wake the way every notify funnel does
//! (`write_events::agent_notified_wake`), and requires the sink's counters to
//! appear in `metrics::render()`, which is byte-for-byte the `/metrics` body
//! (`handlers::prometheus_metrics`).

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::wake_hub::limits::{
    DEFAULT_GLOBAL_EGRESS_BYTES, DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS,
    DEFAULT_RECIPIENT_QUEUE_BYTES, DEFAULT_RECIPIENT_QUEUE_FRAMES, EgressBudget,
};
use ai_memory::wake_hub::metrics::HubMetrics;
use ai_memory::wake_hub::pending::PendingStore;
use ai_memory::wake_hub::routing::Router;
use ai_memory::wake_sink::in_process::install_in_process;
use ai_memory::write_events::{AgentNotified, agent_notified_wake};

/// The series the scrape must carry once a sink is installed and one wake
/// has crossed it. The recipient never authenticated to the (empty) router,
/// so the one wake is a `dropped_unknown` — the exact outcome #3657 says an
/// operator could not see.
const EXPECTED_SERIES: [&str; 3] = [
    "ai_memory_wake_sink_active 1",
    "ai_memory_wake_sink_wakes_seen_total 1",
    "ai_memory_wake_sink_dropped_total{cause=\"unknown\"} 1",
];

/// Every other family the sink counts must be present too, at zero, so a
/// dashboard can draw the whole decision table from one scrape.
const EXPECTED_ZERO_SERIES: [&str; 10] = [
    "ai_memory_wake_sink_delivered_total 0",
    "ai_memory_wake_sink_written_total 0",
    "ai_memory_wake_sink_coalesced_total 0",
    "ai_memory_wake_sink_meta_shed_total 0",
    "ai_memory_wake_sink_dropped_total{cause=\"overflow\"} 0",
    "ai_memory_wake_sink_dropped_total{cause=\"unaddressable\"} 0",
    "ai_memory_wake_sink_dropped_total{cause=\"unencodable\"} 0",
    "ai_memory_wake_sink_dropped_total{cause=\"transport_full\"} 0",
    "ai_memory_wake_sink_dropped_total{cause=\"hub_down\"} 0",
    "ai_memory_wake_sink_dropped_total{cause=\"bus_lagged\"} 0",
];

fn empty_router() -> Arc<Router> {
    Arc::new(Router::new(
        DEFAULT_RECIPIENT_QUEUE_FRAMES,
        DEFAULT_RECIPIENT_QUEUE_BYTES,
        Arc::new(EgressBudget::new(DEFAULT_GLOBAL_EGRESS_BYTES)),
        PendingStore::new(DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS),
        Arc::new(HubMetrics::default()),
    ))
}

/// Before any sink is installed the gauge says so and NO counter is
/// rendered: a number nothing measured is never exposed as `0`.
fn assert_inactive_before_install(text: &str) {
    assert!(
        text.contains("ai_memory_wake_sink_active 0"),
        "/metrics must report an uninstalled wake sink as inactive:\n{text}"
    );
    assert!(
        !text.contains("ai_memory_wake_sink_wakes_seen_total"),
        "no sink, no counters: a value nothing measured must be absent, not 0:\n{text}"
    );
}

/// This is the ONE test in this binary that installs a process-wide sink;
/// `install_sink` deliberately refuses a second installation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_wake_through_the_installed_sink_is_visible_on_the_scrape_3657() {
    assert_inactive_before_install(&ai_memory::metrics::render());

    let metrics =
        install_in_process(empty_router()).expect("this binary installs exactly one sink");

    let recipient = format!("ai:scrape-{}", uuid::Uuid::new_v4());
    let namespace = ai_memory::inbox_namespace(&recipient);
    agent_notified_wake(&AgentNotified {
        recipient_agent_id: &recipient,
        sender_agent_id: "ai:alice",
        inbox_row_id: "row-3657",
        namespace: &namespace,
        content: "BODY-NEVER-ON-THE-WIRE-3657",
    });

    // The bus pump is a task: wait for the sink to have SEEN the wake, so the
    // scrape assertion below is about the bridge and never about timing.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metrics.snapshot().wakes_seen == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the installed sink never saw the published wake"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snap = metrics.snapshot();
    assert_eq!(snap.wakes_seen, 1, "{snap:?}");
    assert_eq!(snap.dropped_unknown, 1, "nobody is registered: {snap:?}");

    let text = ai_memory::metrics::render();
    for series in EXPECTED_SERIES {
        assert!(
            text.contains(series),
            "the sink counted it but /metrics does not show it (#3657): missing `{series}`\n\n{text}"
        );
    }
    for series in EXPECTED_ZERO_SERIES {
        assert!(
            text.contains(series),
            "/metrics must render every sink counter once a sink is installed: missing `{series}`\n\n{text}"
        );
    }
    assert!(
        !text.contains("BODY-NEVER-ON-THE-WIRE-3657"),
        "a scrape carries counts, never content"
    );
}
