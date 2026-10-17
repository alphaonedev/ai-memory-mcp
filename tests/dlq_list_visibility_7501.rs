// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7501: the operator view of the failed-lookup DLQ rows. An admin sees every
//! writer's rows and the anonymous ones; a non-admin sees only its own.
//!
//! Lives in its own test binary (not the lib tests) so it holds no
//! process-global identity-env window (check-test-env-lock arms (d)/(e)/(h)).

use ai_memory::mcp::handle_subscription_dlq_list_for;
use ai_memory::subscriptions::scan_failure::{ScanFailure, record_dispatch_scan_failure};
use serde_json::json;

fn seed(path: &std::path::Path) {
    for (ns, agent) in [
        ("team/ns0", Some("ai:alice")),
        ("team/ns1", None),
        ("team/ns2", Some("ai:carol")),
    ] {
        record_dispatch_scan_failure(
            path,
            &ScanFailure {
                event: "memory_store",
                memory_id: "mem-7501",
                namespace: ns,
                agent_id: agent,
                details: None,
            },
            "sqlite_error",
        );
    }
}

#[test]
fn dlq_list_admin_sees_every_failed_lookup_row_7501() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dlq.db");
    let conn = ai_memory::db::open(&path).expect("db::open");
    seed(&path);
    let admins = vec!["ai:root".to_string()];
    let resp = handle_subscription_dlq_list_for(&conn, &json!({}), "ai:root", &admins).expect("ok");
    assert_eq!(
        resp["count"].as_u64(),
        Some(3),
        "an admin sees other writers' rows and the anonymous row"
    );
}

#[test]
fn dlq_list_non_admin_non_owner_sees_none_7501() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dlq.db");
    let conn = ai_memory::db::open(&path).expect("db::open");
    seed(&path);
    let admins = vec!["ai:root".to_string()];
    let bob = handle_subscription_dlq_list_for(&conn, &json!({}), "ai:bob", &admins).expect("ok");
    assert_eq!(bob["count"].as_u64(), Some(0), "a non-owner sees nothing");
    let alice =
        handle_subscription_dlq_list_for(&conn, &json!({}), "ai:alice", &admins).expect("ok");
    assert_eq!(
        alice["count"].as_u64(),
        Some(1),
        "the owner sees only its own"
    );
}
