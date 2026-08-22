// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3031 — an ENABLED, operator-signed rule whose matcher cannot be
//! EVALUATED must FAIL CLOSED, not silently allow.
//!
//! ## The defect
//!
//! `matcher_applies` collapsed three distinct outcomes into `false`:
//!
//! 1. malformed matcher JSON (`serde_json::from_str` failed),
//! 2. a matcher carrying no key the rule's kind recognises
//!    (`--kind bash --matcher '{"totally_bogus_key":123}'`),
//! 3. a matcher that WAS evaluated and legitimately did not match.
//!
//! Only (3) means "this policy was consulted and did not fire". (1) and (2)
//! mean the policy is BROKEN — and returning `false` for them made an enabled,
//! signed, `severity=refuse` rule enforce NOTHING, with `rules check`
//! answering `allow` and `rules list` showing nothing amiss.
//!
//! ## The fix (two halves)
//!
//! - **Write time:** `ai-memory rules add` validates the per-kind matcher
//!   SCHEMA, so an inert rule cannot be minted through the supported path.
//! - **Evaluate time:** an enabled rule whose matcher is INERT and whose
//!   severity BLOCKS (`refuse` / `escalate`) now refuses the action and logs a
//!   loud `tracing::error!`. `warn` / `log` are non-blocking by definition, so
//!   an inert one is reported and skipped — upgrading them to a block would
//!   invent enforcement the operator never asked for.
//!
//! ## Documented-semantics note
//!
//! `match_read`'s doc states that for `read_action` "an empty / unrecognized
//! matcher matches nothing, so an operator can't accidentally deny every read
//! with a typo". That property is PRESERVED for non-blocking severities and
//! DELIBERATELY INVERTED for blocking ones: a typo that disables an intended
//! `refuse` is a silent security hole, and the North Star ranks
//! degrade-loudly above allow-silently. The typo is now also unmintable
//! through `rules add`.

use ai_memory::governance::agent_action::{
    AgentAction, Decision, MatcherStatus, RuleEngine, action_kinds, matcher_applies,
    matcher_status, rule_matcher_is_inert, validate_matcher_for_kind,
};
use ai_memory::governance::rules_store::Rule;

fn rule(id: &str, kind: &str, matcher: &str, severity: &str) -> Rule {
    Rule {
        id: id.to_string(),
        kind: kind.to_string(),
        matcher: matcher.to_string(),
        severity: severity.to_string(),
        reason: "operator reason".to_string(),
        namespace: "_global".to_string(),
        created_by: "ai:test".to_string(),
        created_at: 0,
        enabled: true,
        signature: None,
        attest_level: "operator_signed".to_string(),
    }
}

fn bash(command: &str) -> AgentAction {
    AgentAction::Bash {
        command: command.to_string(),
        cwd: None,
    }
}

/// The exact reproduction from the issue: an enabled, operator-signed
/// `refuse` bash rule with a kind-wrong matcher used to ALLOW every command.
#[test]
fn inert_refuse_rule_now_refuses_instead_of_allowing_3031() {
    let engine = RuleEngine::from_rules(vec![rule(
        "R-inert",
        action_kinds::BASH,
        r#"{"totally_bogus_key":123}"#,
        "refuse",
    )]);
    let decision = engine.evaluate("ai:test", &bash("anything at all"));
    assert!(
        decision.is_blocking(),
        "#3031: an enabled refuse rule that cannot be evaluated must BLOCK, not allow; \
         got {decision:?}"
    );
    match decision {
        Decision::Refuse { rule_id, reason } => {
            assert_eq!(rule_id, "R-inert");
            assert!(
                reason.contains("#3031"),
                "the refusal must explain WHY it fired without a matcher; got {reason}"
            );
            assert!(
                reason.starts_with("operator reason"),
                "the operator's own reason must be preserved first; got {reason}"
            );
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
}

/// Malformed matcher JSON is the same class of broken policy.
#[test]
fn malformed_matcher_json_on_a_refuse_rule_fails_closed_3031() {
    let engine = RuleEngine::from_rules(vec![rule(
        "R-malformed",
        action_kinds::BASH,
        "{not json",
        "refuse",
    )]);
    assert!(engine.evaluate("ai:test", &bash("ls")).is_blocking());

    // `escalate` also fails closed (`Decision::is_allowed()` is false).
    let engine = RuleEngine::from_rules(vec![rule(
        "R-escalate",
        action_kinds::BASH,
        "{not json",
        "escalate",
    )]);
    let d = engine.evaluate("ai:test", &bash("ls"));
    assert!(d.is_escalation() && !d.is_allowed(), "got {d:?}");
}

/// A NON-blocking inert rule must NOT be upgraded into a block — that would
/// invent enforcement the operator never requested.
#[test]
fn inert_warn_and_log_rules_do_not_become_blocking_3031() {
    for severity in ["warn", "log"] {
        let engine = RuleEngine::from_rules(vec![rule(
            "R-inert-nonblocking",
            action_kinds::BASH,
            r#"{"bogus":1}"#,
            severity,
        )]);
        let d = engine.evaluate("ai:test", &bash("ls"));
        assert_eq!(
            d,
            Decision::Allow,
            "an inert {severity} rule must stay non-blocking; got {d:?}"
        );
    }
}

/// A WELL-FORMED rule that simply does not match must still allow — the fix
/// must not turn every non-match into a refusal.
#[test]
fn well_formed_non_matching_rule_still_allows_3031() {
    let engine = RuleEngine::from_rules(vec![rule(
        "R-ok",
        action_kinds::BASH,
        r#"{"command_substring":"rm -rf"}"#,
        "refuse",
    )]);
    assert_eq!(engine.evaluate("ai:test", &bash("ls -la")), Decision::Allow);
    assert!(engine.evaluate("ai:test", &bash("rm -rf /")).is_blocking());
}

/// `matcher_status` distinguishes all three outcomes, and the public
/// `matcher_applies` keeps its historical "positively selected" meaning so
/// `count_matching_rules` stays honest.
#[test]
fn matcher_status_separates_inert_from_non_match_3031() {
    let inert = rule("a", action_kinds::BASH, r#"{"bogus":1}"#, "refuse");
    let miss = rule(
        "b",
        action_kinds::BASH,
        r#"{"command_substring":"rm -rf"}"#,
        "refuse",
    );
    let hit = miss.clone();
    assert_eq!(matcher_status(&inert, &bash("ls")), MatcherStatus::Inert);
    assert_eq!(
        matcher_status(&miss, &bash("ls")),
        MatcherStatus::DoesNotApply
    );
    assert_eq!(
        matcher_status(&hit, &bash("rm -rf /")),
        MatcherStatus::Applies
    );
    assert!(!matcher_applies(&inert, &bash("ls")));
    assert!(matcher_applies(&hit, &bash("rm -rf /")));
    assert!(rule_matcher_is_inert(&inert));
    assert!(!rule_matcher_is_inert(&miss));
}

/// Per-kind write-time schema validation: every kind's required key is
/// enforced, typos are rejected, and a kind this binary does not know is left
/// alone (forward compatibility with rules authored for a newer binary).
#[test]
fn per_kind_matcher_schema_validation_3031() {
    let ok = |kind: &str, m: &str| {
        validate_matcher_for_kind(kind, &serde_json::from_str(m).unwrap())
            .unwrap_or_else(|e| panic!("{kind} {m} should validate: {e}"));
    };
    let bad = |kind: &str, m: &str| {
        validate_matcher_for_kind(kind, &serde_json::from_str(m).unwrap())
            .expect_err(&format!("{kind} {m} must be refused"))
    };

    ok(action_kinds::BASH, r#"{"command_substring":"rm -rf"}"#);
    ok(action_kinds::BASH, r#"{"command_regex":"rm -rf"}"#);
    ok(action_kinds::FILESYSTEM_WRITE, r#"{"glob":"/tmp/**"}"#);
    ok(action_kinds::NETWORK_REQUEST, r#"{"host":"*.evil.test"}"#);
    ok(
        action_kinds::PROCESS_SPAWN,
        r#"{"binary":"cargo","disk_free_min_gib":20,"args_contain":"build"}"#,
    );
    ok(
        action_kinds::CUSTOM,
        r#"{"kind":"memory_write","namespace_glob":"secure/**","tier":"long"}"#,
    );
    ok(action_kinds::READ_ACTION, r#"{"all":true}"#);
    ok(action_kinds::READ_ACTION, r#"{"namespace":"secure/**"}"#);
    // Forward compatibility: an unknown kind is not judged.
    ok("some_future_kind", r#"{"whatever":1}"#);

    // A single-character typo would otherwise mint a silently inert rule.
    assert!(
        bad(action_kinds::BASH, r#"{"command_substrng":"rm -rf"}"#).contains("unrecognised key"),
    );
    assert!(bad(action_kinds::BASH, r#"{"totally_bogus_key":123}"#).contains("unrecognised key"));
    assert!(bad(action_kinds::BASH, "{}").contains("required key"));
    assert!(bad(action_kinds::FILESYSTEM_WRITE, r#"{"path":"/tmp"}"#).contains("unrecognised key"));
    assert!(
        bad(action_kinds::PROCESS_SPAWN, r#"{"args_contain":"build"}"#).contains("required key")
    );
    assert!(bad(action_kinds::READ_ACTION, "{}").contains("required key"));
    // A non-object body can never be evaluated either.
    assert!(bad(action_kinds::BASH, "[1,2,3]").contains("JSON OBJECT"));
}
