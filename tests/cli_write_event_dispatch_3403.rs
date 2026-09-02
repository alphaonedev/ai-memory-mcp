// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
//! v1.0.0 #3403 — every CLI write verb dispatches its subscription event.
//!
//! # The defect this closes
//!
//! `grep -rn dispatch_event src/cli/` returned ZERO hits. Seven MCP tools
//! dispatched a subscription/webhook event on every successful write; not
//! one CLI write verb did. A subscriber was therefore structurally blind
//! to `ai-memory store|delete|promote|link|consolidate` while seeing the
//! byte-identical MCP write — and the CLI disagreed with itself, because
//! the two verbs that are re-exports of MCP handlers (`reflect`,
//! `kg-invalidate`) dispatched all along.
//!
//! # What is asserted
//!
//! * **ALLOWED path** — a registered wildcard subscriber RECEIVES a
//!   `memory_store`, `memory_delete`, `memory_promote`,
//!   `memory_link_created` and `memory_consolidated` event, each driven
//!   through the real CLI verb entry point, each carrying the details
//!   block its MCP twin carries.
//! * **DENIED / filtered path** — a subscriber whose `event_types` opt-in
//!   list names only `memory_store` receives the CLI store event and NOT
//!   the CLI delete event. The fix must not make the CLI a firehose that
//!   bypasses the per-subscription filter.
//! * **Mechanical ledger** — every CLI write verb file routes through
//!   `crate::write_events`, no CLI file re-pairs an event name with a
//!   details struct itself, and the one-shot epilogue drains the
//!   fan-out. A future verb that dispatches nothing (or dispatches
//!   directly) fails here rather than silently going dark.
//!
//! # Backends
//!
//! CLI-only, and every CLI write verb is refused on a postgres store at
//! `refuse_pg_store` (#2572, pinned by
//! `tests/cli_write_verb_pg_refuse_ceiling_2572.rs`), so this funnel has a
//! single sqlite path by construction — there is no postgres twin to
//! cover.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ai_memory::cli::CliOutput;
use ai_memory::subscriptions::{self, NewSubscription};
use rusqlite::Connection;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ---------------------------------------------------------------------------
// harness (mirrors tests/webhook_coverage.rs)
// ---------------------------------------------------------------------------

fn fresh_env() -> (TempDir, PathBuf) {
    // H11 (#628) — loopback webhook URLs are rejected by default; wiremock
    // binds 127.0.0.1, so opt in for this test process.
    ai_memory::config::set_allow_loopback_webhooks(true);
    ai_memory::subscriptions::prewarm_dispatch_tls();
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("ai-memory.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    (dir, db_path)
}

fn fresh_mock_listener() -> std::net::TcpListener {
    let mut last_err = None;
    for _ in 0..5 {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => return l,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("#1201: failed to bind an ephemeral port for the mock: {last_err:?}");
}

/// Per-test listener + UUID-anchored path, so a straggler POST from a
/// concurrent test on a recycled port can never be miscounted (#1201).
async fn fresh_mock() -> (MockServer, String, String) {
    let server = MockServer::builder()
        .listener(fresh_mock_listener())
        .start()
        .await;
    let path_str = format!("/hook/{}", uuid::Uuid::new_v4().simple());
    Mock::given(method("POST"))
        .and(path(path_str.clone()))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let url = format!("{}{}", server.uri(), path_str);
    (server, path_str, url)
}

fn subscribe(db_path: &Path, url: &str, event_types: Option<&[String]>) {
    let conn = Connection::open(db_path).expect("open db");
    subscriptions::insert(
        &conn,
        &NewSubscription {
            url,
            events: "*",
            // Dispatch refuses unsigned bodies, so give the sub a secret.
            secret: Some("cli-3403-secret"),
            namespace_filter: None,
            agent_filter: None,
            created_by: Some("cli-3403"),
            event_types,
        },
    )
    .expect("insert subscription");
}

/// The SAME wait the one-shot CLI epilogue performs
/// (`daemon_runtime::run` → `subscriptions::drain_dispatches`), so this
/// test observes delivery the way the real process does rather than by
/// racing a timer.
async fn drain() {
    assert!(
        subscriptions::drain_dispatches(Duration::from_secs(30)).await,
        "the webhook fan-out must drain within the shutdown budget"
    );
}

async fn bodies_at(server: &MockServer, expected_path: &str) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == expected_path)
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
        .collect()
}

fn event_named<'a>(bodies: &'a [serde_json::Value], event: &str) -> Option<&'a serde_json::Value> {
    bodies.iter().find(|b| b["event"].as_str() == Some(event))
}

// ---------------------------------------------------------------------------
// CLI verb drivers
// ---------------------------------------------------------------------------

fn store_args(namespace: &str, title: &str, content: &str) -> ai_memory::cli::store::StoreArgs {
    ai_memory::cli::store::StoreArgs {
        tier: "mid".to_string(),
        namespace: Some(namespace.to_string()),
        title: title.to_string(),
        content: content.to_string(),
        tags: String::new(),
        priority: 5,
        confidence: None,
        source: "cli".to_string(),
        expires_at: None,
        ttl_secs: None,
        scope: None,
        kind: None,
        citations: None,
        source_uri: None,
        source_span: None,
        valid_from: None,
        valid_until: None,
        entity_id: None,
        sign: false,
        write_v2: None,
        capability: None,
        capability_file: None,
    }
}

/// Drive `ai-memory store` and return the stored id.
fn cli_store(db_path: &Path, namespace: &str, title: &str, content: &str) -> String {
    let cfg = ai_memory::config::AppConfig::default();
    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::store::run(
            db_path,
            store_args(namespace, title, content),
            true,
            &cfg,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli store");
    }
    let v: serde_json::Value =
        serde_json::from_slice(&so).expect("cli store must emit a JSON envelope");
    v["id"].as_str().expect("stored id").to_string()
}

// ---------------------------------------------------------------------------
// ALLOWED path — the subscriber receives each CLI-originated write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_store_reaches_a_subscriber_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    subscribe(&db, &url, None);

    let id = cli_store(&db, "cli-ev-store", "cli store title", "cli store body");
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    let ev = event_named(&bodies, "memory_store")
        .unwrap_or_else(|| panic!("no memory_store event reached the subscriber: {bodies:?}"));
    assert_eq!(ev["memory_id"].as_str(), Some(id.as_str()));
    assert_eq!(ev["namespace"].as_str(), Some("cli-ev-store"));
    assert_eq!(ev["agent_id"].as_str(), Some("ai:cli-3403"));
}

#[tokio::test]
async fn cli_delete_reaches_a_subscriber_with_the_pre_delete_snapshot_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    let id = cli_store(&db, "cli-ev-del", "cli delete title", "cli delete body");
    // Subscribe AFTER the seed store so only the delete event is in play.
    subscribe(&db, &url, None);

    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::crud::cmd_delete(
            &db,
            &ai_memory::cli::crud::DeleteArgs {
                id: id.clone(),
                capability: None,
                capability_file: None,
                hard: false,
            },
            true,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli delete");
    }
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    let ev = event_named(&bodies, "memory_delete")
        .unwrap_or_else(|| panic!("no memory_delete event reached the subscriber: {bodies:?}"));
    assert_eq!(ev["memory_id"].as_str(), Some(id.as_str()));
    assert_eq!(ev["namespace"].as_str(), Some("cli-ev-del"));
    // The details block is the pre-delete snapshot — the only record a
    // subscriber gets of a row that no longer exists.
    assert_eq!(ev["title"].as_str(), Some("cli delete title"));
    assert_eq!(ev["tier"].as_str(), Some("mid"));
}

#[tokio::test]
async fn cli_promote_reaches_a_subscriber_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    let id = cli_store(&db, "cli-ev-prom", "cli promote title", "cli promote body");
    subscribe(&db, &url, None);

    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::promote::cmd_promote(
            &db,
            &ai_memory::cli::promote::PromoteArgs {
                id: id.clone(),
                to_namespace: None,
                target_tier: None,
                capability: None,
                capability_file: None,
            },
            true,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli promote");
    }
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    let ev = event_named(&bodies, "memory_promote")
        .unwrap_or_else(|| panic!("no memory_promote event reached the subscriber: {bodies:?}"));
    assert_eq!(ev["memory_id"].as_str(), Some(id.as_str()));
    assert_eq!(ev["mode"].as_str(), Some("tier"));
    assert_eq!(ev["tier"].as_str(), Some("long"));
}

#[tokio::test]
async fn cli_link_reaches_a_subscriber_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    let src = cli_store(
        &db,
        "cli-ev-link",
        "cli link source",
        "cli link source body",
    );
    let dst = cli_store(
        &db,
        "cli-ev-link",
        "cli link target",
        "cli link target body",
    );
    subscribe(&db, &url, None);

    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::link::cmd_link(
            &db,
            &ai_memory::cli::link::LinkArgs {
                source_id: src.clone(),
                target_id: dst.clone(),
                relation: "related_to".to_string(),
            },
            true,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli link");
    }
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    let ev = event_named(&bodies, "memory_link_created").unwrap_or_else(|| {
        panic!("no memory_link_created event reached the subscriber: {bodies:?}")
    });
    // The envelope borrows the SOURCE memory's namespace + owner, exactly
    // as the MCP twin resolves it (shared `write_events::link_event_origin`).
    assert_eq!(ev["memory_id"].as_str(), Some(src.as_str()));
    assert_eq!(ev["namespace"].as_str(), Some("cli-ev-link"));
    assert_eq!(ev["target_id"].as_str(), Some(dst.as_str()));
    assert_eq!(ev["relation"].as_str(), Some("related_to"));
}

#[tokio::test]
async fn cli_consolidate_reaches_a_subscriber_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    let a = cli_store(&db, "cli-ev-cons", "cli cons a", "cli cons body a");
    let b = cli_store(&db, "cli-ev-cons", "cli cons b", "cli cons body b");
    subscribe(&db, &url, None);

    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::consolidate::run(
            &db,
            ai_memory::cli::consolidate::ConsolidateArgs {
                ids: format!("{a},{b}"),
                title: "cli consolidated".to_string(),
                summary: "merged by the cli consolidate verb".to_string(),
                namespace: Some("cli-ev-cons".to_string()),
            },
            true,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli consolidate");
    }
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    let ev = event_named(&bodies, "memory_consolidated").unwrap_or_else(|| {
        panic!("no memory_consolidated event reached the subscriber: {bodies:?}")
    });
    assert_eq!(ev["source_count"].as_u64(), Some(2));
    let sources: Vec<&str> = ev["source_ids"]
        .as_array()
        .expect("source_ids array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        sources.contains(&a.as_str()) && sources.contains(&b.as_str()),
        "{sources:?}"
    );
}

// ---------------------------------------------------------------------------
// DENIED path — the per-subscription filter still governs CLI events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_store_only_subscriber_does_not_receive_the_cli_delete_3403() {
    let (_dir, db) = fresh_env();
    let (server, hook_path, url) = fresh_mock().await;
    subscribe(&db, &url, Some(&["memory_store".to_string()]));

    let id = cli_store(
        &db,
        "cli-ev-filt",
        "cli filtered title",
        "cli filtered body",
    );
    let (mut so, mut se) = (Vec::new(), Vec::new());
    {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::crud::cmd_delete(
            &db,
            &ai_memory::cli::crud::DeleteArgs {
                id,
                capability: None,
                capability_file: None,
                hard: false,
            },
            true,
            Some("ai:cli-3403"),
            &mut out,
        )
        .expect("cli delete");
    }
    drain().await;

    let bodies = bodies_at(&server, &hook_path).await;
    assert!(
        event_named(&bodies, "memory_store").is_some(),
        "the opted-in event must still arrive: {bodies:?}"
    );
    assert!(
        event_named(&bodies, "memory_delete").is_none(),
        "wiring the CLI into the funnel must not bypass the per-subscription \
         event_types filter: {bodies:?}"
    );
}

// ---------------------------------------------------------------------------
// Mechanical ledger — the wiring cannot silently regress
// ---------------------------------------------------------------------------

/// Every CLI write verb, with the emitter its file must route through.
const CLI_WRITE_VERBS: &[(&str, &str)] = &[
    ("src/cli/store.rs", "write_events::store("),
    ("src/cli/crud.rs", "write_events::delete("),
    ("src/cli/promote.rs", "write_events::promote("),
    ("src/cli/link.rs", "write_events::link_created("),
    ("src/cli/consolidate.rs", "write_events::consolidated("),
];

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Strip the `#[cfg(test)]` module so a fixture never counts as a
/// production site. Same boundary heuristic as
/// `tests/atomise_funnel_ceiling_2984.rs`.
fn production_prefix(src: &str) -> String {
    let cut = src
        .find("\n#[cfg(test)]\nmod tests")
        .or_else(|| src.find("\n#[cfg(test)]\n#[path"))
        .unwrap_or(src.len());
    src[..cut]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_cli_write_verb_routes_through_the_shared_event_funnel_3403() {
    let mut missing = Vec::new();
    for (file, emitter) in CLI_WRITE_VERBS {
        if !production_prefix(&read(file)).contains(emitter) {
            missing.push(format!(
                "{file} no longer calls `{emitter}` — a CLI write verb that dispatches \
                 nothing is invisible to every subscriber while its MCP twin is not (#3403)."
            ));
        }
    }
    assert!(missing.is_empty(), "#3403:\n  - {}", missing.join("\n  - "));
}

#[test]
fn no_cli_file_re_pairs_an_event_name_with_a_details_struct_3403() {
    // The whole point of the funnel is that the name↔details binding
    // lives in ONE place. A CLI file calling the raw dispatcher would
    // reintroduce the per-site drift `handle_promote` already had (a
    // `tool_names::MEMORY_PROMOTE` arm next to a `"memory_promote"`
    // literal arm).
    let mut offenders = Vec::new();
    for entry in walk_rs(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/cli")) {
        let rel = entry
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&entry)
            .display()
            .to_string();
        let src = production_prefix(&std::fs::read_to_string(&entry).unwrap_or_default());
        if src.contains("subscriptions::dispatch_event") {
            offenders.push(rel);
        }
    }
    assert!(
        offenders.is_empty(),
        "#3403: these CLI files call the raw subscription dispatcher instead of \
         `crate::write_events::*`, which re-opens the per-site event-name/details \
         drift the funnel exists to prevent:\n  - {}",
        offenders.join("\n  - ")
    );
}

#[test]
fn the_one_shot_epilogue_drains_the_webhook_fan_out_3403() {
    // Delivery is fire-and-forget: without this the CLI would dispatch
    // events that reliably die with the process.
    let src = production_prefix(&read("src/daemon_runtime.rs"));
    assert!(
        src.contains("subscriptions::drain_dispatches("),
        "#3403: `daemon_runtime::run` must drain the webhook fan-out before a one-shot \
         `ai-memory <verb>` exits, or every CLI-dispatched event is lost at process exit."
    );
}

fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_rs(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}
