// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Red guard for the code-scanning rule `rust/cleartext-logging` assertion-message sites
//! (#6597, #6598, #6599, #6600; class of #6098, cluster #6163).
//!
//! Each cell reads one alerted test source and fails while an assertion
//! failure message at the alerted site still interpolates the flagged
//! binding (a governance `Result`, an imported-metadata JSON value, or a
//! set-standard response). The assertion conditions themselves are not
//! inspected here; only the failure text is.

use std::path::Path;

/// One alerted site: the source file, a stable fragment of the assertion
/// message that locates the line, and the interpolation that must be gone.
struct Site {
    issue: u32,
    file: &'static str,
    locator: &'static str,
    banned: &'static str,
}

const BANNED_RES_DEBUG: &str = "{res:?}";

const SITES: &[Site] = &[
    // #6597 — alerts 155..158.
    Site {
        issue: 6597,
        file: "tests/governance_audit_verdict_2634.rs",
        locator: "non-owner bind must be refused",
        banned: BANNED_RES_DEBUG,
    },
    Site {
        issue: 6597,
        file: "tests/governance_audit_verdict_2634.rs",
        locator: "owner bind must be allowed",
        banned: BANNED_RES_DEBUG,
    },
    Site {
        issue: 6597,
        file: "tests/governance_audit_verdict_2634.rs",
        locator: "non-owner clear must be refused",
        banned: BANNED_RES_DEBUG,
    },
    Site {
        issue: 6597,
        file: "tests/governance_audit_verdict_2634.rs",
        locator: "owner clear must be allowed",
        banned: BANNED_RES_DEBUG,
    },
    // #6599 — alert 182.
    Site {
        issue: 6599,
        file: "tests/issue_1326_namespace_get_standard_governance.rs",
        locator: "set-side echo must include the field",
        banned: "{set_resp",
    },
    // #6600 — alerts 164, 165.
    Site {
        issue: 6600,
        file: "tests/ns_standard_parent_graft_2542.rs",
        locator: "a parent with no standard is unowned and must be allowed",
        banned: BANNED_RES_DEBUG,
    },
    Site {
        issue: 6600,
        file: "tests/ns_standard_parent_graft_2542.rs",
        locator: "same-principal parent graft must be allowed",
        banned: BANNED_RES_DEBUG,
    },
];

/// #6598 — alerts 159, 160, 180, 181: every `meta={meta}` message in the
/// import admin-gate test dumped the whole imported metadata object.
const IMPORT_FILE: &str = "tests/import_memories_admin_gate_956.rs";
const IMPORT_BANNED: &[&str] = &["{meta}", "{meta:?}", "{meta:#}"];

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn alerted_assertion_messages_do_not_interpolate_flagged_values_6597_6599_6600() {
    let mut failures = Vec::new();
    for (idx, site) in SITES.iter().enumerate() {
        let src = read(site.file);
        let hits: Vec<&str> = src
            .lines()
            .filter(|line| line.contains(site.locator))
            .collect();
        if hits.is_empty() {
            failures.push(format!(
                "site #{idx} (#{}): locator not found in {}",
                site.issue, site.file
            ));
            continue;
        }
        if hits.iter().any(|line| line.contains(site.banned)) {
            failures.push(format!(
                "site #{idx} (#{}): {} message still interpolates `{}`",
                site.issue, site.file, site.banned
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn import_admin_gate_messages_do_not_dump_metadata_6598() {
    let src = read(IMPORT_FILE);
    let offending: Vec<usize> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| IMPORT_BANNED.iter().any(|b| line.contains(b)))
        .map(|(n, _)| n + 1)
        .collect();
    assert!(
        offending.is_empty(),
        "#6598: {IMPORT_FILE} still dumps the metadata object at lines {offending:?}"
    );
}
