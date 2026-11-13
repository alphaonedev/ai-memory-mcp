// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The one K9 agent-pattern matcher (#8760).
//!
//! Every site that decides whether a `[[permissions.rules]]`
//! `agent_pattern` covers an agent id goes through this module:
//! [`super::Permissions::evaluate`] (rule selection for every op, every
//! surface, every backend) and the SSE approval-visibility filter
//! (`crate::handlers::approvals::sse_event_visible_to`).
//!
//! # Defect class closed
//!
//! The agent pattern used to be matched with the namespace glob, whose `*`
//! stops at `/`. A Deny written as `*` (the default) or `ai:*` therefore
//! refused `ai:plain` but let `ai:team/a` and every SPIFFE id through, and a
//! Deny on `ai:plain` let `AI:PLAIN` through. A pattern or id outside the
//! vocabulary was silently "no match", so the Deny was skipped.
//!
//! # Semantics (all valid id forms, all surfaces, both backends)
//!
//! * The id is classified once against the validator's shape
//!   ([`crate::validate::validate_agent_id_shape`]); the pattern against the
//!   same alphabet ([`crate::validate::is_agent_id_char`]) plus `*`, at most
//!   [`MAX_AGENT_PATTERN_LEN`] bytes, non-empty.
//! * `*` (and any run of `*`) matches any run of bytes, `/` included, as the
//!   [`super::PermissionRule`] docs have always promised for agent ids.
//!   Every other byte is a literal.
//! * Deny and Ask rules compare letters ASCII-case-insensitively, so no
//!   case spelling avoids them. Allow rules compare exactly, so one
//!   principal never inherits a grant written for another spelling.
//! * Fail closed: an id or a pattern that cannot be classified MATCHES every
//!   Deny / Ask rule and NO Allow rule, with a `tracing` line.
//!
//! `decision: fail-closed on unclassifiable over skip-the-rule, because a
//! skipped Deny is an allow.`
//!
//! Cost: `O(|pattern| * |id|)` per rule with `|id| <= 128` and
//! `|pattern| <= 1024`, no recursion, no backtracking.

use super::{PermissionRule, RuleDecision};

/// Longest `agent_pattern` the matcher classifies. Longer patterns are
/// unclassifiable (fail closed). Eight times the 128-byte id limit leaves
/// room for wildcards between every literal.
pub const MAX_AGENT_PATTERN_LEN: usize = 1024;

/// Longest prefix of an untrusted id or pattern quoted in a log line.
const LOG_VALUE_MAX_CHARS: usize = 128;

/// Why a pattern cannot be classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// The empty pattern.
    Empty,
    /// Longer than [`MAX_AGENT_PATTERN_LEN`] bytes.
    TooLong,
    /// A character outside the agent-id alphabet plus `*`.
    InvalidChar,
}

impl PatternError {
    /// Stable, log-safe reason text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty agent_pattern",
            Self::TooLong => "agent_pattern exceeds MAX_AGENT_PATTERN_LEN",
            Self::InvalidChar => {
                "agent_pattern has a character outside the agent-id alphabet and `*`"
            }
        }
    }
}

/// Classify `pattern` against the agent-pattern vocabulary.
///
/// # Errors
///
/// Returns the [`PatternError`] that makes the pattern unclassifiable.
pub fn classify_pattern(pattern: &str) -> Result<(), PatternError> {
    if pattern.is_empty() {
        return Err(PatternError::Empty);
    }
    if pattern.len() > MAX_AGENT_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    if pattern
        .chars()
        .any(|c| c != '*' && !crate::validate::is_agent_id_char(c))
    {
        return Err(PatternError::InvalidChar);
    }
    Ok(())
}

/// Debug-escaped, length-capped rendering of an untrusted value for a log
/// line (no raw control bytes or terminal escapes reach the log).
fn log_value(value: &str) -> String {
    let head: String = value.chars().take(LOG_VALUE_MAX_CHARS).collect();
    format!("{head:?}")
}

/// The authenticated caller as the rule matcher sees it: the id, and
/// whether it is a classifiable agent id. Build it once per decision with
/// [`AgentPrincipal::classify`], then test every rule with
/// [`AgentPrincipal::matches`].
#[derive(Debug, Clone, Copy)]
pub struct AgentPrincipal<'a> {
    id: &'a str,
    classified: bool,
}

impl<'a> AgentPrincipal<'a> {
    /// Classify `agent_id` once. An id the validator would refuse is kept
    /// as unclassifiable (it matches every Deny / Ask and no Allow) and a
    /// warning is logged.
    #[must_use]
    pub fn classify(agent_id: &'a str) -> Self {
        let classified = crate::validate::validate_agent_id_shape(agent_id).is_ok();
        if !classified {
            tracing::warn!(
                target: super::GOVERNANCE_GATE_TRACE_TARGET,
                id_len = agent_id.len(),
                id = %log_value(agent_id),
                "#8760: caller agent id is unclassifiable; every Deny/Ask \
                 permission rule applies to it and no Allow rule does"
            );
        }
        Self {
            id: agent_id,
            classified,
        }
    }

    /// Whether the id passed the validator's shape check.
    #[must_use]
    pub const fn is_classified(&self) -> bool {
        self.classified
    }

    /// Does a rule with `pattern` and `decision` apply to this principal?
    #[must_use]
    pub fn matches(&self, pattern: &str, decision: RuleDecision) -> bool {
        let restrictive = !matches!(decision, RuleDecision::Allow);
        if !self.classified {
            return restrictive;
        }
        if let Err(reason) = classify_pattern(pattern) {
            tracing::debug!(
                target: super::GOVERNANCE_GATE_TRACE_TARGET,
                reason = reason.as_str(),
                pattern = %log_value(pattern),
                restrictive,
                "#8760: unclassifiable agent_pattern fails closed"
            );
            return restrictive;
        }
        agent_glob(pattern.as_bytes(), self.id.as_bytes(), restrictive)
    }
}

/// One-shot form of [`AgentPrincipal::classify`] + [`AgentPrincipal::matches`].
#[must_use]
pub fn agent_pattern_matches(pattern: &str, agent_id: &str, decision: RuleDecision) -> bool {
    AgentPrincipal::classify(agent_id).matches(pattern, decision)
}

/// Log every rule whose `agent_pattern` is unclassifiable, once, when the
/// rule set is installed (the per-decision path only logs at `debug`).
pub(crate) fn warn_unclassifiable_patterns(rules: &[PermissionRule]) {
    for (index, rule) in rules.iter().enumerate() {
        if let Err(reason) = classify_pattern(&rule.agent_pattern) {
            tracing::warn!(
                target: super::GOVERNANCE_GATE_TRACE_TARGET,
                rule_index = index,
                reason = reason.as_str(),
                pattern = %log_value(&rule.agent_pattern),
                pattern_len = rule.agent_pattern.len(),
                decision = ?rule.decision,
                "#8760: permission rule agent_pattern is unclassifiable; \
                 as Deny/Ask it applies to every caller, as Allow to none"
            );
        }
    }
}

/// Dynamic program over (pattern byte, id offset). `*` runs match any
/// bytes; `fold` compares ASCII letters case-insensitively.
fn agent_glob(pat: &[u8], val: &[u8], fold: bool) -> bool {
    // `reach[j]` == "the pattern prefix consumed so far matches val[..j]".
    let mut reach = vec![false; val.len() + 1];
    reach[0] = true;
    let mut next = vec![false; val.len() + 1];
    let mut p = 0usize;
    while p < pat.len() {
        if pat[p] == b'*' {
            while p < pat.len() && pat[p] == b'*' {
                p += 1;
            }
            let mut seen = false;
            for (slot, &hit) in next.iter_mut().zip(reach.iter()) {
                seen |= hit;
                *slot = seen;
            }
        } else {
            let literal = pat[p];
            p += 1;
            next[0] = false;
            for j in 1..=val.len() {
                let byte = val[j - 1];
                let same = if fold {
                    byte.eq_ignore_ascii_case(&literal)
                } else {
                    byte == literal
                };
                next[j] = reach[j - 1] && same;
            }
        }
        std::mem::swap(&mut reach, &mut next);
        if !reach.iter().any(|r| *r) {
            return false;
        }
    }
    reach[val.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY: RuleDecision = RuleDecision::Deny;
    const ALLOW: RuleDecision = RuleDecision::Allow;
    const ASK: RuleDecision = RuleDecision::Ask;

    #[test]
    fn star_crosses_slash_for_every_decision() {
        for d in [DENY, ALLOW, ASK] {
            assert!(agent_pattern_matches("*", "ai:team/a", d));
            assert!(agent_pattern_matches("ai:*", "ai:team/a/b", d));
            assert!(agent_pattern_matches(
                "spiffe://*",
                "spiffe://example.org/ns/a",
                d
            ));
            assert!(agent_pattern_matches("ai:*/b", "ai:team/a/b", d));
            assert!(!agent_pattern_matches("ai:*/c", "ai:team/a/b", d));
        }
    }

    #[test]
    fn case_folds_for_deny_and_ask_only() {
        assert!(agent_pattern_matches("ai:plain", "AI:PLAIN", DENY));
        assert!(agent_pattern_matches("AI:*", "ai:plain", ASK));
        assert!(!agent_pattern_matches("ai:plain", "AI:PLAIN", ALLOW));
        assert!(agent_pattern_matches("ai:plain", "ai:plain", ALLOW));
    }

    #[test]
    fn unclassifiable_id_fails_closed() {
        for id in ["", "ai:a b", "ai:%2F", "ai:*", "/x", "ai:../x", "ai:\u{e9}"] {
            let principal = AgentPrincipal::classify(id);
            assert!(!principal.is_classified(), "{id:?}");
            assert!(principal.matches("zz-never", DENY), "{id:?}");
            assert!(principal.matches("zz-never", ASK), "{id:?}");
            assert!(!principal.matches("*", ALLOW), "{id:?}");
        }
    }

    #[test]
    fn unclassifiable_pattern_fails_closed() {
        let too_long = "*".repeat(MAX_AGENT_PATTERN_LEN + 1);
        for (pattern, want) in [
            ("", PatternError::Empty),
            (too_long.as_str(), PatternError::TooLong),
            ("ai:%", PatternError::InvalidChar),
            ("ai:?", PatternError::InvalidChar),
            ("ai:[a]", PatternError::InvalidChar),
        ] {
            assert_eq!(classify_pattern(pattern), Err(want));
            assert!(agent_pattern_matches(pattern, "ai:plain", DENY));
            assert!(!agent_pattern_matches(pattern, "ai:plain", ALLOW));
        }
        let at_limit = "*".repeat(MAX_AGENT_PATTERN_LEN);
        assert_eq!(classify_pattern(&at_limit), Ok(()));
    }

    #[test]
    fn literal_bytes_are_exact_outside_case() {
        assert!(!agent_pattern_matches("ai:team.a", "ai:team/a", DENY));
        assert!(!agent_pattern_matches("ai:plain", "ai:plain2", DENY));
        assert!(!agent_pattern_matches("ai:plain2", "ai:plain", DENY));
    }

    #[test]
    fn log_value_escapes_and_caps() {
        let rendered = log_value("a\nb\u{1b}[31m");
        assert!(!rendered.contains('\n') && !rendered.contains('\u{1b}'));
        let long = "q".repeat(LOG_VALUE_MAX_CHARS * 4);
        assert!(log_value(&long).len() <= LOG_VALUE_MAX_CHARS + 2);
    }
}
