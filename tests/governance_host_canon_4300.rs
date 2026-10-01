// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4300 — governance `network_request` host rules must match the CANONICAL
//! host, not its byte spelling. Every cell drives the real evaluation funnel
//! (`check_agent_action` -> `RuleEngine::evaluate` -> `matcher_status`).
//!
//! Backend note: agent-action rules live only in the SQLite `governance_rules`
//! table (Postgres ships no such table, see `store/postgres.rs` v66), so the
//! evaluation funnel is single-backend; the daemon uses it identically on
//! both storage tiers.

use ai_memory::governance::agent_action::{AgentAction, Decision, check_agent_action};
use ai_memory::governance::rules_store::{self, Rule};
use ed25519_dalek::{Signer, SigningKey};

mod common;
use common::*;

// Same pattern as `tests/governance_a2a_rules.rs`: production
// `enforced_rule_passes` drops any rule whose `attest_level !=
// "operator_signed"` whenever `resolve_operator_pubkey()` returns a
// key (env var OR `~/Library/Application Support/ai-memory/operator
// .key.pub` on macOS). Tests install their own keypair via the env
// var (see `common::install_test_operator_key`) so the assertions
// hold regardless of host state.

fn fresh_conn() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE governance_rules (
             id TEXT PRIMARY KEY,
             kind TEXT NOT NULL,
             matcher TEXT NOT NULL,
             severity TEXT NOT NULL CHECK (severity IN ('refuse','warn','log','escalate')),
             reason TEXT NOT NULL,
             namespace TEXT NOT NULL DEFAULT '_global',
             created_by TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 1,
             signature BLOB,
             attest_level TEXT NOT NULL DEFAULT 'unsigned'
         );
         CREATE TABLE signed_events (
             id TEXT PRIMARY KEY,
             agent_id TEXT NOT NULL,
             event_type TEXT NOT NULL,
             payload_hash BLOB NOT NULL,
             signature BLOB,
             attest_level TEXT NOT NULL DEFAULT 'unsigned',
             timestamp TEXT NOT NULL,
             -- v34 (V-4 closeout, #698) — cross-row chain columns.
             prev_hash BLOB,
             sequence INTEGER, cause_hash BLOB
         );",
    )
    .unwrap();
    conn
}

fn add_rule(
    conn: &rusqlite::Connection,
    signing: &SigningKey,
    id: &str,
    kind: &str,
    matcher: &str,
    severity: &str,
) {
    let mut rule = Rule {
        id: id.into(),
        kind: kind.into(),
        matcher: matcher.into(),
        severity: severity.into(),
        reason: format!("{id}: test refusal"),
        namespace: "_global".into(),
        created_by: "test".into(),
        created_at: 0,
        enabled: true,
        signature: None,
        attest_level: "operator_signed".into(),
    };
    let canonical =
        rules_store::canonical_bytes_for_signing(&rule).expect("canonical_bytes_for_signing");
    rule.signature = Some(signing.sign(&canonical).to_bytes().to_vec());
    rules_store::insert(conn, &rule).unwrap();
}

fn refused(conn: &rusqlite::Connection, host: &str) -> bool {
    let action = AgentAction::NetworkRequest {
        host: host.into(),
        scheme: "https".into(),
    };
    matches!(
        check_agent_action(conn, "agent:t", &action).unwrap(),
        Decision::Refuse { .. }
    )
}

/// One in-memory rule store holding a single enabled, signed `refuse` rule.
/// The operator-key guard is process-global, so each test installs it ONCE
/// and passes the signing key here.
fn deny_with(signing: &SigningKey, host_pattern: &str) -> rusqlite::Connection {
    let conn = fresh_conn();
    let matcher = serde_json::json!({ "host": host_pattern }).to_string();
    add_rule(
        &conn,
        signing,
        "R-4300",
        "network_request",
        &matcher,
        "refuse",
    );
    conn
}

#[test]
fn issue_4300_case_variants_are_refused() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    for h in [
        "evil.example.com",
        "EVIL.example.com",
        "Evil.Example.COM",
        "EVIL.EXAMPLE.COM",
    ] {
        assert!(refused(&conn, h), "{h} must be refused");
    }
}

#[test]
fn issue_4300_trailing_root_dot_is_refused() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    assert!(refused(&conn, "evil.example.com."));
}

#[test]
fn issue_4300_mixed_case_and_trailing_dot_is_refused() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    assert!(refused(&conn, "EvIl.ExAmPlE.CoM."));
}

#[test]
fn issue_4300_rule_side_is_canonicalised_too() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "EVIL.Example.com.");
    for h in ["evil.example.com", "EVIL.example.com.", "evil.example.com."] {
        assert!(
            refused(&conn, h),
            "{h} must be refused by an upper-case/rooted rule"
        );
    }
}

#[test]
fn issue_4300_idn_form_matches_a_label_rule_and_back() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "xn--bcher-kva.example");
    assert!(refused(&conn, "b\u{fc}cher.example"));
    assert!(refused(&conn, "B\u{dc}CHER.example."));
    assert!(refused(&conn, "xn--bcher-kva.example"));
    let conn2 = deny_with(&signing, "b\u{fc}cher.example");
    assert!(refused(&conn2, "xn--bcher-kva.example"));
    assert!(refused(&conn2, "b\u{fc}cher.example"));
}

#[test]
fn issue_4300_homograph_does_not_over_match() {
    // Cyrillic `\u{435}` (looks like `e`) is a DIFFERENT host: its A-label is
    // not `evil.example.com`, so the rule must not fire on it.
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    assert!(!refused(&conn, "\u{435}vil.example.com"));
}

#[test]
fn issue_4300_whitespace_and_control_hosts_fail_closed() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    for h in [
        " evil.example.com",
        "evil.example.com ",
        "\tevil.example.com",
        "evil.example.com\n",
        "evil.exa\0mple.com",
        "evil..example.com",
        "",
    ] {
        assert!(
            refused(&conn, h),
            "malformed host {h:?} must be refused, never allowed"
        );
    }
}

#[test]
fn issue_4300_overlong_hosts_fail_closed() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil.example.com");
    assert!(refused(&conn, &format!("{}.example.com", "a".repeat(64))));
    assert!(refused(&conn, &vec!["a".repeat(60); 5].join(".")));
}

#[test]
fn issue_4300_invalid_host_does_not_trip_warn_only_policy() {
    let (signing, _g) = install_test_operator_key();
    let conn = fresh_conn();
    add_rule(
        &conn,
        &signing,
        "R-warn",
        "network_request",
        r#"{"host":"evil.example.com"}"#,
        "warn",
    );
    let action = AgentAction::NetworkRequest {
        host: " not a host".into(),
        scheme: "https".into(),
    };
    assert!(
        !matches!(
            check_agent_action(&conn, "agent:t", &action).unwrap(),
            Decision::Refuse { .. }
        ),
        "a warn rule must not be upgraded to a block by a malformed host"
    );
}

#[test]
fn issue_4300_ipv4_leading_zero_and_short_forms() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "127.0.0.1");
    for h in ["127.0.0.1", "127.000.000.001", "127.1", "127.0.0.1."] {
        assert!(
            refused(&conn, h),
            "{h} must canonicalise to 127.0.0.1 and be refused"
        );
    }
    assert!(!refused(&conn, "127.0.0.2"));
    let conn2 = deny_with(&signing, "127.000.000.001");
    assert!(refused(&conn2, "127.0.0.1"));
}

#[test]
fn issue_4300_ipv6_literal_forms() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "[::1]");
    for h in ["[::1]", "[0:0:0:0:0:0:0:1]", "::1", "[0000::0001]"] {
        assert!(refused(&conn, h), "{h} must canonicalise to [::1]");
    }
    assert!(!refused(&conn, "[::2]"));
}

#[test]
fn issue_4300_wildcard_depth_and_no_over_match() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "*.evil.example.com");
    // Any depth, any case, rooted or not.
    for h in [
        "a.evil.example.com",
        "A.B.Evil.Example.COM",
        "a.b.c.evil.example.com.",
    ] {
        assert!(refused(&conn, h), "{h} must match the wildcard");
    }
    // Controls: bare apex, suffix-spoof, prefix-spoof, other TLD.
    for h in [
        "evil.example.com",
        "notevil.example.com",
        "a.evil.example.com.evil.org",
        "evil.example.org",
        "good.example.com",
    ] {
        assert!(!refused(&conn, h), "{h} must NOT match the wildcard");
    }
}

#[test]
fn issue_4300_existing_correct_rules_keep_their_match_set() {
    // Exact lower-case rule: matches only its own host (no over-match).
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "malware.example");
    assert!(refused(&conn, "malware.example"));
    for h in [
        "good.example",
        "sub.malware.example",
        "malware.example.net",
        "malware.exampl",
    ] {
        assert!(!refused(&conn, h), "{h} must stay allowed");
    }
    // Pre-existing glob rule keeps its set.
    let conn2 = deny_with(&signing, "*.evil.test");
    assert!(refused(&conn2, "api.evil.test"));
    assert!(!refused(&conn2, "evil.test"));
    assert!(!refused(&conn2, "api.good.test"));
}

#[test]
fn issue_4300_uncanonicalisable_rule_pattern_is_inert_and_fails_closed() {
    // A pattern written with whitespace could never match any canonical host;
    // an enabled blocking rule like that must refuse (#3031), not allow.
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil .example.com");
    assert!(refused(&conn, "good.example.com"));
}

#[test]
fn issue_4300_write_time_validation_refuses_a_bad_host_pattern() {
    use ai_memory::governance::agent_action::validate_matcher_for_kind;
    assert!(
        validate_matcher_for_kind("network_request", &serde_json::json!({"host":"evil .com"}))
            .is_err()
    );
    assert!(
        validate_matcher_for_kind("network_request", &serde_json::json!({"host":"a..b"})).is_err()
    );
    assert!(
        validate_matcher_for_kind(
            "network_request",
            &serde_json::json!({"host":"EVIL.Example.com."})
        )
        .is_ok()
    );
    assert!(
        validate_matcher_for_kind(
            "network_request",
            &serde_json::json!({"host":"*.evil.example.com"})
        )
        .is_ok()
    );
}

// ---- security review of 6ec8c1831 (F1 regression, #4414 ports, #4415 mapped) --

fn refused_scheme(conn: &rusqlite::Connection, host: &str, scheme: &str) -> bool {
    let action = AgentAction::NetworkRequest {
        host: host.into(),
        scheme: scheme.into(),
    };
    matches!(
        check_agent_action(conn, "agent:t", &action).unwrap(),
        Decision::Refuse { .. }
    )
}

#[test]
fn issue_4300_idn_wildcard_in_label_is_refused_not_allowed() {
    use ai_memory::governance::agent_action::validate_matcher_for_kind;
    let (signing, _g) = install_test_operator_key();
    // Non-ASCII text sharing a label with `*` cannot be matched after
    // punycode: rejected at write time and inert (blocking => refuses) when
    // already stored. Refused on the carrier, ALLOWED on 6ec8c1831.
    for (rule, req) in [
        ("b\u{fc}*.example", "b\u{fc}cher.example"),
        ("b\u{fc}*.example", "xn--bcher-kva.example"),
        ("*b\u{fc}cher.example", "f\u{fc}b\u{fc}cher.example"),
    ] {
        assert!(
            validate_matcher_for_kind("network_request", &serde_json::json!({"host": rule}))
                .is_err(),
            "{rule:?} must be rejected at write time"
        );
        let conn = deny_with(&signing, rule);
        assert!(refused(&conn, req), "{rule:?} vs {req:?} must be refused");
    }
    // Whole-label wildcard next to an IDN label is fine and matches.
    let conn = deny_with(&signing, "*.b\u{fc}cher.example");
    assert!(refused(&conn, "a.B\u{dc}CHER.example"));
    assert!(refused(&conn, "a.xn--bcher-kva.example"));
}

#[test]
fn issue_4300_ascii_inlabel_wildcard_catches_unicode_and_a_label_hosts() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "evil*.com");
    for h in [
        "evil\u{fc}.com",
        "xn--evil-3ra.com",
        "evilcorp.com",
        "EVIL.com.",
    ] {
        assert!(refused(&conn, h), "{h:?} must be refused");
    }
    assert!(!refused(&conn, "good.com"));
    assert!(!refused(&conn, "notevil.com"));
}

#[test]
fn issue_4300_noncanonical_numeric_wildcard_pattern_is_rejected_and_inert() {
    use ai_memory::governance::agent_action::validate_matcher_for_kind;
    let (signing, _g) = install_test_operator_key();
    assert!(
        validate_matcher_for_kind("network_request", &serde_json::json!({"host":"0177.0.0.*"}))
            .is_err()
    );
    let conn = deny_with(&signing, "0177.0.0.*");
    assert!(
        refused(&conn, "127.0.0.1"),
        "inert blocking rule fails closed"
    );
    let conn = deny_with(&signing, "127.0.0.*");
    assert!(refused(&conn, "0x7f.0.0.9"));
    assert!(!refused(&conn, "128.0.0.1"));
}

#[test]
fn issue_4414_portless_rule_matches_any_port() {
    let (signing, _g) = install_test_operator_key();
    for (rule, req) in [
        ("example.com", "example.com:443"),
        ("example.com", "EXAMPLE.com.:0443"),
        ("*.example.com", "a.example.com:8443"),
        ("127.0.0.1", "127.0.0.1:80"),
        ("[::1]", "[::1]:80"),
    ] {
        let conn = deny_with(&signing, rule);
        assert!(refused(&conn, req), "{rule:?} must refuse {req:?}");
    }
    let conn = deny_with(&signing, "example.com");
    assert!(!refused(&conn, "other.com:443"));
}

#[test]
fn issue_4414_port_rule_needs_the_same_effective_port() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "example.com:443");
    assert!(refused(&conn, "EXAMPLE.COM.:443"));
    assert!(refused(&conn, "example.com:0443"));
    // Portless egress request: scheme default applies.
    assert!(refused_scheme(&conn, "example.com", "https"));
    assert!(!refused_scheme(&conn, "example.com", "http"));
    assert!(!refused(&conn, "example.com:8443"));
    assert!(!refused(&conn, "other.com:443"));
    let conn = deny_with(&signing, "example.com:8443");
    assert!(refused(&conn, "example.com:8443"));
    assert!(!refused_scheme(&conn, "example.com", "https"));
    // Unknown effective port: over-block rather than allow.
    assert!(refused_scheme(&conn, "example.com", "gopher"));
}

#[test]
fn issue_4414_malformed_rule_port_is_inert_and_refused_at_write_time() {
    use ai_memory::governance::agent_action::validate_matcher_for_kind;
    let (signing, _g) = install_test_operator_key();
    assert!(
        validate_matcher_for_kind("network_request", &serde_json::json!({"host":"evil.com:*"}))
            .is_err()
    );
    // Documented over-block: a stored inert blocking rule refuses everything.
    let conn = deny_with(&signing, "evil.com:*");
    assert!(refused(&conn, "good.com"));
}

#[test]
fn issue_4300_malformed_host_is_refused_by_an_unrelated_blocking_rule() {
    // Documented over-blocking: no allow-by-default for a host we cannot parse.
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "unrelated.example");
    assert!(refused(&conn, "bad host"));
    assert!(!refused(&conn, "fine.example"));
}

#[test]
fn issue_4415_ipv4_mapped_ipv6_matches_ipv4_both_directions() {
    let (signing, _g) = install_test_operator_key();
    let conn = deny_with(&signing, "127.0.0.1");
    for h in [
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "[::FFFF:7F00:1]:80",
    ] {
        assert!(refused(&conn, h), "{h:?} must be refused by an IPv4 rule");
    }
    assert!(
        !refused(&conn, "[::ffff:7f00:2]"),
        "other address stays allowed"
    );
    for rule in ["[::ffff:127.0.0.1]", "::ffff:7f00:1", "[::ffff:7f00:1]"] {
        let conn = deny_with(&signing, rule);
        assert!(
            refused(&conn, "127.0.0.1"),
            "{rule:?} must refuse 127.0.0.1"
        );
        assert!(refused(&conn, "[::ffff:127.0.0.1]"));
        assert!(!refused(&conn, "127.0.0.2"));
    }
}
