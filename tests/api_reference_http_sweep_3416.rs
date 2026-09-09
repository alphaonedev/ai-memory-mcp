// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3416 — `docs/API_REFERENCE.md` HTTP sweep: the live surface is the
//! SSOT, the doc must not invent fields or counts.
//!
//! Denied path (the 2026-09-02 HTTP-sweep findings, verified on
//! `origin/release/v1.0.0` = ff72014c):
//! - sqlite `GET /api/v1/stats` example claiming `total_memories` /
//!   `storage_backend` (sqlite serializes `Stats.total` and has no
//!   backend marker; postgres aliases `total_memories` + adds
//!   `storage_backend: "postgres"`)
//! - self-contradictory tool/route counts (103 advertised / 84 unique
//!   / 98 registrations / 80-unique-path) against
//!   `Profile::full().expected_tool_count()`,
//!   `EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT`,
//!   `EXPECTED_PRODUCTION_ROUTES_COUNT`
//! - `POST /api/v1/namespaces` documented as the S34/S35 query-string
//!   form when the handler reads namespace from the JSON body only
//!
//! Allowed path: the doc cites the SSOT consts, the sqlite stats
//! example uses `total`, postgres envelope is labelled as such, POST
//! collection form is body-only.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn api_reference() -> String {
    fs::read_to_string(repo_root().join("docs/API_REFERENCE.md"))
        .expect("read docs/API_REFERENCE.md")
}

fn sqlite_stats_example(doc: &str) -> &str {
    let marker = "SQLite example (the default daemon):";
    let start = doc.find(marker).expect("sqlite stats example marker") + marker.len();
    let rest = &doc[start..];
    let fence = rest.find("```json").expect("sqlite stats json fence");
    let body_start = fence + "```json".len();
    let body = &rest[body_start..];
    let end = body.find("```").expect("closing sqlite stats fence");
    body[..end].trim()
}

#[test]
fn api_reference_cites_ssot_route_and_tool_counts_3416() {
    let doc = api_reference();
    let routes = ai_memory::EXPECTED_PRODUCTION_ROUTES_COUNT;
    let paths = ai_memory::EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT;
    let tools = ai_memory::profile::Profile::full().expected_tool_count();

    assert_eq!(
        routes, 100,
        "SSOT moved; update this pin and the doc together"
    );
    assert_eq!(
        paths, 86,
        "SSOT moved; update this pin and the doc together"
    );
    assert_eq!(
        tools, 104,
        "SSOT moved; update this pin and the doc together"
    );

    assert!(
        doc.contains(&format!(
            "{paths} unique URL paths across {routes}\n> production route registrations"
        )) || doc.contains(&format!(
            "{paths} unique URL paths across {routes} production route registrations"
        )),
        "API_REFERENCE total-surface claim must cite UNIQUE={paths} ROUTES={routes}"
    );
    assert!(
        doc.contains(&format!("EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = {paths}")),
        "API_REFERENCE must pin UNIQUE_PATHS const to {paths}"
    );
    assert!(
        doc.contains(&format!("EXPECTED_PRODUCTION_ROUTES_COUNT = {routes}")),
        "API_REFERENCE must pin ROUTES const to {routes}"
    );
    assert!(
        doc.contains("104 advertised entries at `--profile full`"),
        "API_REFERENCE must cite the full-profile advertised-entry SSOT (104)"
    );

    // Denied: the three stale counts the sweep found.
    assert!(
        !doc.contains("EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT = 84"),
        "stale UNIQUE=84 pin must not survive"
    );
    assert!(
        !doc.contains("EXPECTED_PRODUCTION_ROUTES_COUNT = 98"),
        "stale ROUTES=98 pin must not survive"
    );
    assert!(
        !doc.contains("80-unique-path"),
        "stale 80-unique-path inventory claim must not survive"
    );
    assert!(
        !doc.contains("full is 103 and not 104"),
        "inverted 103-vs-104 disambiguation must not survive"
    );
}

#[test]
fn api_reference_stats_sqlite_example_uses_total_not_total_memories_3416() {
    let doc = api_reference();
    let example = sqlite_stats_example(&doc);
    assert!(
        example.contains("\"total\""),
        "sqlite stats example must serialize Stats.total, got:\n{example}"
    );
    assert!(
        !example.contains("total_memories"),
        "sqlite stats example must not invent total_memories, got:\n{example}"
    );
    assert!(
        !example.contains("storage_backend"),
        "sqlite stats example must not invent storage_backend, got:\n{example}"
    );
    assert!(
        doc.contains("storage_backend: \"postgres\"")
            || doc.contains("`storage_backend: \"postgres\"`")
            || doc.contains("\"storage_backend\": \"postgres\""),
        "postgres envelope must be documented as storage_backend=postgres"
    );
    assert!(
        doc.contains("Do not send\nor expect `\"storage_backend\": \"sqlite\"`")
            || doc.contains("Do not send or expect `\"storage_backend\": \"sqlite\"`"),
        "doc must deny the invented sqlite storage_backend marker"
    );
}

#[test]
fn api_reference_post_namespaces_is_body_only_3416() {
    let doc = api_reference();
    let heading = "### `POST /api/v1/namespaces` — set namespace standard (collection form)";
    let start = doc.find(heading).expect("POST collection heading");
    let rest = &doc[start..];
    let next = rest[heading.len()..]
        .find("\n### ")
        .map_or(rest.len(), |i| heading.len() + i);
    let section = &rest[..next];
    let section_lc = section.to_ascii_lowercase();
    assert!(
        section_lc.contains("json body") || section.contains("**JSON body**"),
        "POST collection form must say the namespace comes from the JSON body:\n{section}"
    );
    assert!(
        section.contains("not read on POST") || section_lc.contains("not read on post"),
        "POST collection form must disclose that ?namespace= is not read:\n{section}"
    );
    assert!(
        section.contains("400"),
        "POST collection form must document the missing-body 400:\n{section}"
    );
}
