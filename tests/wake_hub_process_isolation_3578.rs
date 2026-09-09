// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3578 item 3 — process-isolation contract in the shipped supervisor
//! units (the #3522 class: grep the files, prove the gate is load-bearing
//! with a denied fixture).
//!
//! The hub process must run as a DISTINCT user (`ai-memory-hub`), must not
//! be able to open the durable store (`InaccessiblePaths=/var/lib/ai-memory`),
//! and must not open a network socket (`RestrictAddressFamilies=AF_UNIX`,
//! no `--tcp` in the shipped `ExecStart`). TCP is an operator drop-in that
//! has to add BOTH the flag AND `AF_INET` — the shipped unit has neither.

use std::path::Path;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn trimmed_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim)
}

/// systemd directive lines: not comments, not section headers.
fn directives(unit: &str) -> impl Iterator<Item = &str> {
    trimmed_lines(unit).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
}

/// Violations of the hub systemd isolation contract. Empty = allowed.
fn hub_service_violations(unit: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    let has_hub_user = directives(unit).any(|l| l == "User=ai-memory-hub");
    let has_hub_group = directives(unit).any(|l| l == "Group=ai-memory-hub");
    let shares_daemon_user = directives(unit).any(|l| l == "User=ai-memory");
    let has_inaccessible = directives(unit).any(|l| l == "InaccessiblePaths=/var/lib/ai-memory");
    let has_af_unix = directives(unit).any(|l| l == "RestrictAddressFamilies=AF_UNIX");
    let opens_inet = directives(unit).any(|l| l.contains("AF_INET"));
    let ships_tcp = directives(unit).any(|l| l.contains("--tcp"));
    let writes_store = directives(unit).any(|l| l == "ReadWritePaths=/var/lib/ai-memory");
    if !has_hub_user {
        v.push("missing User=ai-memory-hub");
    }
    if !has_hub_group {
        v.push("missing Group=ai-memory-hub");
    }
    if shares_daemon_user {
        v.push("hub shares daemon user ai-memory");
    }
    if !has_inaccessible {
        v.push("missing InaccessiblePaths=/var/lib/ai-memory");
    }
    if !has_af_unix {
        v.push("missing RestrictAddressFamilies=AF_UNIX");
    }
    if opens_inet {
        v.push("shipped unit names AF_INET (TCP is drop-in only)");
    }
    if ships_tcp {
        v.push("shipped ExecStart passes --tcp");
    }
    if writes_store {
        v.push("hub ReadWritePaths includes the store directory");
    }
    v
}

fn hub_plist_violations(plist: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    if !plist.contains("<key>UserName</key>") {
        v.push("missing UserName key");
    }
    if !plist.contains("<string>ai-memory-hub</string>") {
        v.push("missing ai-memory-hub principal");
    }
    v
}

#[test]
fn shipped_hub_unit_is_process_isolated_3578() {
    let unit = read("packaging/systemd/ai-memory-wake-hub.service");
    let violations = hub_service_violations(&unit);
    assert!(
        violations.is_empty(),
        "shipped hub unit breaks the #3578 isolation contract: {violations:?}"
    );
    assert!(
        unit.contains("RuntimeDirectory=ai-memory-hub"),
        "hub runtime dir must be distinct from the daemon"
    );
}

#[test]
fn a_unit_that_shares_the_daemon_user_is_refused_3578() {
    // DENIED pin: the helper is load-bearing. A unit that looks like the
    // pre-#3578 shipped file (User=ai-memory, store reachable, no
    // InaccessiblePaths) must not pass.
    let pre_fix = "\
[Service]
User=ai-memory
Group=ai-memory
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/ai-memory
";
    let v = hub_service_violations(pre_fix);
    assert!(
        v.iter().any(|s| s.contains("shares daemon user")),
        "denied pin must catch User=ai-memory, got {v:?}"
    );
    assert!(
        v.iter().any(|s| s.contains("InaccessiblePaths")),
        "denied pin must catch a missing store jail, got {v:?}"
    );
}

#[test]
fn a_unit_that_opens_tcp_is_refused_3578() {
    let tcp = "\
User=ai-memory-hub
Group=ai-memory-hub
RestrictAddressFamilies=AF_UNIX AF_INET
ExecStart=/usr/bin/ai-memory wake-hub --tcp
InaccessiblePaths=/var/lib/ai-memory
";
    let v = hub_service_violations(tcp);
    assert!(
        v.iter().any(|s| s.contains("AF_INET")),
        "denied pin must catch AF_INET, got {v:?}"
    );
    assert!(
        v.iter().any(|s| s.contains("--tcp")),
        "denied pin must catch --tcp, got {v:?}"
    );
}

#[test]
fn shipped_hub_plist_names_the_distinct_user_3578() {
    let plist = read("scripts/templates/dev.alphaone.ai-memory.wake-hub.plist");
    let violations = hub_plist_violations(&plist);
    assert!(
        violations.is_empty(),
        "shipped hub plist breaks the #3578 isolation contract: {violations:?}"
    );
}

#[test]
fn a_plist_without_username_is_refused_3578() {
    let pre_fix = "\
<key>Label</key>
<string>dev.alphaone.ai-memory.wake-hub</string>
";
    let v = hub_plist_violations(pre_fix);
    assert!(
        v.iter().any(|s| s.contains("UserName")),
        "denied pin must catch a missing UserName, got {v:?}"
    );
}

#[test]
fn refresher_stays_the_store_opener_and_installs_as_the_hub_uid_3578() {
    let unit = read("packaging/systemd/ai-memory-wake-hub-refresh.service");
    assert!(
        trimmed_lines(&unit).any(|l| l == "User=ai-memory"),
        "refresher must keep User=ai-memory — it opens the store"
    );
    assert!(
        unit.contains("ExecStartPost=+/usr/bin/install -o ai-memory-hub"),
        "refresher must install(1) the snapshot as the hub uid (0600 owner check)"
    );
    assert!(
        unit.contains("/run/ai-memory-hub/hub-allow.json"),
        "refresher must land the snapshot where the hub unit reads it"
    );
}

/// systemd-sysusers `u` records (the NAME field). Comments and non-`u`
/// rows are skipped. `ai-memory` and `ai-memory-hub` are distinct names
/// (whitespace-split), so a prefix match cannot collapse them.
fn sysusers_user_names(conf: &str) -> Vec<&str> {
    trimmed_lines(conf)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("u"), Some(name)) => Some(name),
                _ => None,
            }
        })
        .collect()
}

fn sysusers_violations(conf: &str) -> Vec<&'static str> {
    let names = sysusers_user_names(conf);
    let mut v = Vec::new();
    if !names.contains(&"ai-memory") {
        v.push("missing u ai-memory");
    }
    if !names.contains(&"ai-memory-hub") {
        v.push("missing u ai-memory-hub");
    }
    v
}

#[test]
fn sysusers_file_names_both_users_3578() {
    let conf = read("packaging/systemd/ai-memory.sysusers.conf");
    let violations = sysusers_violations(&conf);
    assert!(
        violations.is_empty(),
        "sysusers fragment must name both users so the shipped units can start on a fresh host: {violations:?}"
    );
}

#[test]
fn a_sysusers_file_missing_the_hub_user_is_refused_3578() {
    // DENIED pin: a fragment that only creates the daemon user leaves
    // User=ai-memory-hub unknown and the hub unit cannot start.
    let only_daemon = "u ai-memory - \"ai-memory daemon\" /var/lib/ai-memory\n";
    let v = sysusers_violations(only_daemon);
    assert!(
        v.iter().any(|s| s.contains("ai-memory-hub")),
        "denied pin must catch a missing hub user, got {v:?}"
    );
    assert!(
        !v.contains(&"missing u ai-memory"),
        "denied pin must still accept the daemon user, got {v:?}"
    );
}
