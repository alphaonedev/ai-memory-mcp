// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Red guard for `CodeQL` `rust/cleartext-logging` alerts on test assertion
//! messages (#6593, #6594, #6595, #6596; same class as #6098, Refs #6163
//! #6351).
//!
//! Each alerted site is an `assert!`/`assert_eq!`/`panic!` whose FAILURE
//! MESSAGE interpolates a binding `CodeQL`'s taint model treats as sensitive
//! (a key-registry row list, a store outcome, a planted fixture credential,
//! a resolved principal, a sync result). The fix keeps every assertion
//! condition identical and changes only what the message prints.
//!
//! The guard reads each alerted source file as text, locates the site by its
//! stable message anchor (which must still exist, so an assertion cannot be
//! silently deleted to satisfy the guard), takes the statement that starts
//! at the anchor line, and fails if that statement still interpolates the
//! flagged binding.

use std::path::Path;

/// One alerted site: the file, a stable anchor that must stay in the
/// statement, and the interpolation that must no longer appear in it.
struct Site {
    file: &'static str,
    anchor: &'static str,
    forbidden: &'static str,
}

/// The statement text that starts at the line carrying `anchor`: that line
/// plus following lines up to and including the first line that ends a
/// statement (`;`) or closes a block (`}`).
fn statements_at(source: &str, anchor: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (start, line) in lines.iter().enumerate() {
        if !line.contains(anchor) {
            continue;
        }
        let mut text = String::new();
        for next in &lines[start..] {
            text.push_str(next);
            text.push('\n');
            let trimmed = next.trim_end();
            if trimmed.ends_with(';') || trimmed.trim_start() == "}" {
                break;
            }
        }
        found.push(text);
    }
    found
}

/// Returns one human-readable failure per site that is missing its anchor or
/// still interpolates the flagged binding. Messages name the file, anchor and
/// binding only, never any source value.
fn violations(sites: &[Site]) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for site in sites {
        let path = root.join(site.file);
        let Ok(source) = std::fs::read_to_string(&path) else {
            out.push(format!("{}: unreadable", site.file));
            continue;
        };
        let statements = statements_at(&source, site.anchor);
        if statements.is_empty() {
            out.push(format!(
                "{}: anchor `{}` not found (assertion removed?)",
                site.file, site.anchor
            ));
            continue;
        }
        for statement in &statements {
            if statement.contains(site.forbidden) {
                out.push(format!(
                    "{}: message at `{}` still interpolates `{}`",
                    site.file, site.anchor, site.forbidden
                ));
            }
        }
    }
    out
}

fn assert_clean(issue: &str, sites: &[Site]) {
    let bad = violations(sites);
    assert!(
        bad.is_empty(),
        "#{issue}: cleartext assertion-message sites remain:\n{}",
        bad.join("\n")
    );
}

const AGENT_API_KEY: &str = "tests/agent_api_key_admin_store_3474.rs";
const AUDIT_CAUSE: &str = "tests/audit_cause_binding_1822.rs";
const AUTHORITY: &str = "tests/authority_resolver_matrix_3549.rs";
const FED_CATCHUP: &str = "tests/federation_sync_push_catchup_sig_2297.rs";

/// #6593 — alerts 371-378: key-registry rows and revoke outcomes.
#[test]
fn cleartext_msgs_6593_agent_api_key_admin_store() {
    let sites = [
        Site {
            file: AGENT_API_KEY,
            anchor: "the last TWO key-holders",
            forbidden: "{snapshot",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "the first self-revoke must apply",
            forbidden: "{other",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "the second self-revoke must be refused",
            forbidden: "{other",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "must never be emptied by two concurrent self-revokes",
            forbidden: "{after",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "a revoke that leaves C enrolled must apply",
            forbidden: "{other",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "a no-op revoke must not be a refusal",
            forbidden: "{other",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "the last holder's revoke must be refused",
            forbidden: "{other",
        },
        Site {
            file: AGENT_API_KEY,
            anchor: "a refused re-bind must not add a row either",
            forbidden: "{listed",
        },
    ];
    assert_clean("6593", &sites);
}

/// #6594 — alert 152: the planted fixture credential.
#[test]
fn cleartext_msgs_6594_audit_cause_binding() {
    let sites = [Site {
        file: AUDIT_CAUSE,
        anchor: "secret_screen must detect the planted credential",
        forbidden: "{secret",
    }];
    assert_clean("6594", &sites);
}

/// #6595 — alert 176: the resolved anonymous principal.
#[test]
fn cleartext_msgs_6595_authority_resolver_matrix() {
    let sites = [Site {
        file: AUTHORITY,
        anchor: "assert!(a.is_anonymous(),",
        forbidden: "principal()",
    }];
    assert_clean("6595", &sites);
}

/// #6596 — alerts 153-154: the `sync_cycle_once` result.
#[test]
fn cleartext_msgs_6596_federation_sync_push_catchup_sig() {
    let sites = [
        Site {
            file: FED_CATCHUP,
            anchor: "so sync_cycle_once returns Ok",
            forbidden: "{res",
        },
        Site {
            file: FED_CATCHUP,
            anchor: "so sync_cycle_once MUST return Err",
            forbidden: "{res",
        },
    ];
    assert_clean("6596", &sites);
}

/// The guard itself is load-bearing: a planted leaking message is caught and
/// a missing anchor is reported.
#[test]
fn guard_detects_a_planted_leak_and_a_missing_anchor() {
    let leaking = "    assert!(ok, \"marker must hold: {value:?}\");\n";
    let statements = statements_at(leaking, "marker must hold");
    assert!(statements.iter().any(|s| s.contains("{value")));
    let clean = "    assert!(ok, \"marker must hold\");\n";
    assert!(
        statements_at(clean, "marker must hold")
            .iter()
            .all(|s| !s.contains("{value"))
    );
    assert!(statements_at(clean, "no such anchor").is_empty());
}
