// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2502 amend F2 — the peer-address serve wiring is STRUCTURALLY pinned.
//!
//! `auth_backoff_source` (`src/handlers/transport.rs`) reads the TCP peer IP
//! from the `ConnectInfo<SocketAddr>` request extension. That extension
//! exists only when the listener is built with
//! `into_make_service_with_connect_info`. The `None`-source arm passes
//! through to normal auth, so reverting a serve site to plain
//! `into_make_service` is silent-green at every refusal pin: no 429 ever
//! fires, no test fails, and the backoff is dead code in production while
//! every behavioral cell still passes. This gate walks the production serve
//! sites and refuses that revert, in the shape of the #3523 structural pins
//! (`tests/agent_id_seam_structural_3523.rs`).
//!
//! Scope is deliberately `src/daemon_runtime.rs` only: the
//! `src/test_support.rs` mock listener (`into_make_service`) is a test-only
//! TLS stub whose traffic must NOT acquire peer identities (injecting real
//! `ConnectInfo` there would arm the backoff inside unrelated suites that
//! present wrong keys through the mock).

use std::path::PathBuf;

/// Production serve wiring under test.
const DAEMON_RUNTIME: &str = "src/daemon_runtime.rs";
/// The wired listener constructor, verbatim as it appears at both sites.
const WIRED: &str = "into_make_service_with_connect_info::<std::net::SocketAddr>";
/// The bare constructor a revert would restore. A production `.serve(` site
/// carrying this (uncommented) is the silent-green revert this gate exists
/// to catch.
const BARE: &str = "into_make_service()";
/// How many wired serve sites the tree has today. If the serve topology
/// changes, update this number HERE — the count is the pin against a site
/// being deleted rather than reverted.
const EXPECTED_WIRED_SITES: usize = 2;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

/// Violation descriptions for the non-comment `.serve(` lines of `source`
/// whose construction is NOT the wired one. Pure over the buffer so the
/// detector cases below prove the predicate catches a revert rather than
/// passing vacuously on today's tree.
fn wiring_violations(rel: &str, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if is_comment_line(trimmed) || !line.contains(".serve(") {
            continue;
        }
        if line.contains(WIRED) {
            continue;
        }
        violations.push(format!("{rel}:{}: {}", index + 1, line.trim()));
    }
    violations
}

/// Count of the wired constructor on non-comment lines (the deletion pin).
fn wired_site_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !is_comment_line(trimmed) && line.contains(WIRED)
        })
        .count()
}

/// F2: both production serve sites wire the peer address into the router.
#[test]
fn both_serve_sites_wire_connect_info_2502() {
    let path = manifest_dir().join(DAEMON_RUNTIME);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let violations = wiring_violations(DAEMON_RUNTIME, &source);
    assert!(
        violations.is_empty(),
        "a production serve site lost its peer-address wiring (#2502 F2):\n  {}\n\n\
         `auth_backoff_source` reads the TCP peer IP from \
         `ConnectInfo<SocketAddr>`, which exists only under \
         `into_make_service_with_connect_info`. A bare `into_make_service` \
         reverts the backoff to dead code while every refusal pin stays \
         green (the None-source arm passes through). Restore the wired \
         constructor at the site above.",
        violations.join("\n  ")
    );
    assert_eq!(
        wired_site_count(&source),
        EXPECTED_WIRED_SITES,
        "{DAEMON_RUNTIME}: expected {EXPECTED_WIRED_SITES} wired serve sites; \
         a site was added or deleted — update EXPECTED_WIRED_SITES here and \
         confirm the new topology still wires the peer address."
    );
    let bare = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !is_comment_line(trimmed) && line.contains(BARE)
        })
        .count();
    assert_eq!(
        bare, 0,
        "{DAEMON_RUNTIME}: a bare `{BARE}` serve site — the silent-green          revert this gate exists to catch. Restore `{WIRED}` at the site above."
    );
}

/// Detector: a bare `into_make_service` serve site is flagged.
#[test]
fn detector_flags_a_bare_serve_site_2502() {
    let synthetic = "        .serve(app.into_make_service())\n";
    assert_eq!(wiring_violations("synthetic.rs", synthetic).len(), 1);
}

/// Detector: wired sites (and commented-out lines) are clean.
#[test]
fn detector_accepts_wired_and_commented_sites_2502() {
    let synthetic = concat!(
        "                    .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())\n",
        "                    // .serve(app.into_make_service())\n",
    );
    assert!(wiring_violations("synthetic.rs", synthetic).is_empty());
    assert_eq!(wired_site_count(synthetic), 1);
}
