// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Found-in-testing docs gates, batch B (#4000-#4009).
//!
//! Each gate pins a published sentence that a QA false-claim sweep proved
//! untrue against the shipped code, and the corrected wording that replaced
//! it. A gate is RED on the carrier the sweep ran against (`57014b067`) and
//! GREEN once the text says what the code does. Where the fix changed code
//! or a Rust string (a boot line, `--help`, a tool schema), the behavioural
//! pin lives next to that code's existing tests; this binary only guards the
//! prose, so a later edit cannot quietly reintroduce the overclaim.
//!
//! Run: `( umask 022; cargo test --test fit_docs_b_false_claims_4000_4009 )`

use std::fs;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Collapse runs of whitespace (and HTML comment-span line prefixes) so a
/// phrase re-wrapped across lines still matches.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_absent(rel: &str, needle: &str, issue: &str) {
    let body = flat(&read(rel));
    assert!(
        !body.contains(needle),
        "{issue}: {rel} still publishes the false claim {needle:?}"
    );
}

fn assert_present(rel: &str, needle: &str, issue: &str) {
    let body = flat(&read(rel));
    assert!(
        body.contains(needle),
        "{issue}: {rel} must carry the corrected statement {needle:?}"
    );
}

/// #4001 — the key-refresh interval is a cadence, not an upper bound on a
/// revoked key's lifetime: a failed refresh keeps the previous key map.
#[test]
fn key_refresh_interval_is_not_called_a_revocation_bound_4001() {
    const ISSUE: &str = "#4001";
    for rel in [
        "docs/compliance/nsa-csi-mcp-security-mapping.md",
        "docs/compliance/nsa-csi-mcp.html",
        "docs/ADMIN_GUIDE.md",
        "CLAUDE.md",
        "src/handlers/identity_binding.rs",
        "src/cli/agents.rs",
        "src/store/mod.rs",
    ] {
        assert_absent(rel, "upper bound on how long a leaked", ISSUE);
        assert_absent(rel, "upper bound on how long a REVOKED key", ISSUE);
        assert_absent(rel, "worst-case revocation window: a key revoked", ISSUE);
        assert_absent(rel, "take effect within that window", ISSUE);
        assert_absent(rel, "takes effect within that window", ISSUE);
        assert_absent(rel, "live within the daemon's refresh window", ISSUE);
    }
    assert_present(
        "docs/compliance/nsa-csi-mcp-security-mapping.md",
        "the interval is **not** an upper bound on a revoked key's lifetime",
        ISSUE,
    );
    assert_present(
        "docs/ADMIN_GUIDE.md",
        "the interval is not an upper bound on a revoked key's lifetime",
        ISSUE,
    );
}

/// #4003 — federation mTLS is opt-in on both ends, and the listener
/// negotiates TLS 1.2 or 1.3; `SECURITY.md` must not call the transport
/// mutually authenticated without the qualifier.
#[test]
fn security_md_does_not_call_federation_mtls_unconditional_4003() {
    const ISSUE: &str = "#4003";
    assert_absent(
        "SECURITY.md",
        "The federation transport is mutually authenticated TLS",
        ISSUE,
    );
    assert_absent(
        "SECURITY.md",
        "rustls, TLS 1.3, mTLS fingerprint pinning",
        ISSUE,
    );
    assert_present("SECURITY.md", "it is opt-in on both ends", ISSUE);
    assert_present("SECURITY.md", "TLS 1.2 floor, TLS 1.3 preferred", ISSUE);
    // The qualifier must stay anchored to shipped code: the protocol list and
    // the opt-in server flag the sentence names must exist.
    assert_present(
        "src/tls.rs",
        "&[&rustls::version::TLS13, &rustls::version::TLS12];",
        ISSUE,
    );
    assert_present(
        "src/daemon_runtime.rs",
        "pub mtls_allowlist: Option<PathBuf>,",
        ISSUE,
    );
}

/// #4004 — W counts the local commit (`acks.len() + 1 >= w`), so `W=1`
/// needs no remote acknowledgement.
#[test]
fn quorum_writes_row_counts_the_local_commit_4004() {
    const ISSUE: &str = "#4004";
    assert_absent("docs/CLI_REFERENCE.md", "W (peer acks required)", ISSUE);
    assert_present(
        "docs/CLI_REFERENCE.md",
        "acknowledgements required **including the local commit**",
        ISSUE,
    );
    assert_present(
        "docs/CLI_REFERENCE.md",
        "`W=1` requires no remote acknowledgement",
        ISSUE,
    );
    assert_absent("docs/GLOSSARY.md", "`W` = how many peers must ack", ISSUE);
    assert_present("docs/GLOSSARY.md", "**counting the local commit**", ISSUE);
    // Anchor: the doc is only true while the tracker counts local + peers.
    assert_present(
        "src/replication.rs",
        "let total = self.acks.len() + 1;",
        ISSUE,
    );
}
