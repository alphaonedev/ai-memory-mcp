// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3200 — the ONE boolean env-token grammar.
//!
//! Before #3200 the binary carried more than fifty hand-written boolean
//! parsers in seven shapes (`1|true` only, exact `"1"`, the house
//! `1|true|yes|on`, case-sensitive and case-insensitive variants, trimmed and
//! untrimmed). Two readers of the same knob could disagree, and an `asi-hard`
//! floor could accept a token its live reader ignored (#3618, #3619). The
//! result was a control that reported ON while it was OFF: under `asi-hard`,
//! `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=yes` met the floor and still let an
//! unsigned CLI store land.
//!
//! This module is the single parser. It is deliberately tiny and PURE: every
//! function here maps a token to a verdict without reading the environment,
//! so the grammar is proven by table tests and the env readers built on it
//! cannot drift from it.
//!
//! ## The grammar
//!
//! Tokens are trimmed and compared case-insensitively.
//!
//! | Token | Verdict |
//! |---|---|
//! | `1`, `true`, `yes`, `on` | [`FlagToken::True`] |
//! | `0`, `false`, `no`, `off` | [`FlagToken::False`] |
//! | absent, empty, whitespace-only | [`FlagToken::Unset`] |
//! | anything else | [`FlagToken::Unrecognised`] |
//!
//! Empty counts as UNSET, never unrecognised. `enforce_at_boot` pins a
//! permissive `asi-hard` knob by writing the empty string, and an unexpanded
//! `${VAR}` in a compose file renders as empty: neither may read as a typo.
//!
//! ## Unrecognised tokens fail closed by polarity
//!
//! A value outside the grammar is never silently read as "off" (the #131 /
//! FBL-14 rule: an unrecognised token must never widen a security control).
//! [`resolve`] maps it to the SECURE side of the knob's [`Polarity`]:
//! a [`Polarity::Mandate`] (truthy tightens) reads ON, a [`Polarity::Hatch`]
//! (truthy loosens) reads OFF.

/// The four-way verdict for one boolean env token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagToken {
    /// `1` / `true` / `yes` / `on` (trimmed, case-insensitive).
    True,
    /// `0` / `false` / `no` / `off` (trimmed, case-insensitive).
    False,
    /// Absent, empty, or whitespace-only.
    Unset,
    /// Any other value: a typo or a token outside the grammar.
    Unrecognised,
}

/// Which way a boolean knob moves a control when it is truthy. Decides the
/// fail-closed reading of an unrecognised token in [`resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// Truthy TIGHTENS a control (e.g. `AI_MEMORY_REQUIRE_TLS`). An
    /// unrecognised token reads ON.
    Mandate,
    /// Truthy LOOSENS a control (e.g. `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK`).
    /// An unrecognised token reads OFF.
    Hatch,
}

/// Classify one raw token. `None` is an absent variable.
#[must_use]
pub fn parse(value: Option<&str>) -> FlagToken {
    let Some(raw) = value else {
        return FlagToken::Unset;
    };
    let token = raw.trim();
    if token.is_empty() {
        return FlagToken::Unset;
    }
    if ["1", "true", "yes", "on"]
        .iter()
        .any(|t| token.eq_ignore_ascii_case(t))
    {
        FlagToken::True
    } else if ["0", "false", "no", "off"]
        .iter()
        .any(|t| token.eq_ignore_ascii_case(t))
    {
        FlagToken::False
    } else {
        FlagToken::Unrecognised
    }
}

/// `true` only for a token in the truthy half of the grammar.
#[must_use]
pub fn is_truthy(value: &str) -> bool {
    parse(Some(value)) == FlagToken::True
}

/// `true` only for a token in the falsy half of the grammar.
#[must_use]
pub fn is_falsy(value: &str) -> bool {
    parse(Some(value)) == FlagToken::False
}

/// The explicit env value of a knob, or `None` when it is unset.
///
/// A recognised token maps to its boolean. An unrecognised token maps to the
/// secure side of `polarity` (a mandate reads ON, a hatch reads OFF). Callers
/// with a config or compiled-default layer fall through on `None`.
#[must_use]
pub fn resolve(value: Option<&str>, polarity: Polarity) -> Option<bool> {
    match parse(value) {
        FlagToken::True => Some(true),
        FlagToken::False => Some(false),
        FlagToken::Unset => None,
        FlagToken::Unrecognised => Some(polarity == Polarity::Mandate),
    }
}

/// [`resolve`] with a compiled default for the unset case.
#[must_use]
pub fn resolve_or(value: Option<&str>, polarity: Polarity, default: bool) -> bool {
    resolve(value, polarity).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUTHY: &[&str] = &[
        "1", "true", "TRUE", "True", "yes", "YES", "on", "On", " 1", "true ",
    ];
    const FALSY: &[&str] = &[
        "0", "false", "FALSE", "no", "No", "off", "OFF", " 0 ", "\tfalse",
    ];
    const UNSET: &[&str] = &["", " ", "\t", "\n"];
    const UNRECOGNISED: &[&str] = &["maybe", "2", "enable", "y", "n", "t", "1 1", "truee", "on!"];

    #[test]
    fn grammar_table_classifies_every_token_3200() {
        for t in TRUTHY {
            assert_eq!(parse(Some(t)), FlagToken::True, "{t:?}");
            assert!(is_truthy(t), "{t:?}");
            assert!(!is_falsy(t), "{t:?}");
        }
        for t in FALSY {
            assert_eq!(parse(Some(t)), FlagToken::False, "{t:?}");
            assert!(is_falsy(t), "{t:?}");
            assert!(!is_truthy(t), "{t:?}");
        }
        for t in UNSET {
            assert_eq!(parse(Some(t)), FlagToken::Unset, "{t:?}");
        }
        assert_eq!(parse(None), FlagToken::Unset);
        for t in UNRECOGNISED {
            assert_eq!(parse(Some(t)), FlagToken::Unrecognised, "{t:?}");
            assert!(!is_truthy(t) && !is_falsy(t), "{t:?}");
        }
    }

    #[test]
    fn unrecognised_fails_closed_by_polarity_3200() {
        for t in UNRECOGNISED {
            assert_eq!(resolve(Some(t), Polarity::Mandate), Some(true), "{t:?}");
            assert_eq!(resolve(Some(t), Polarity::Hatch), Some(false), "{t:?}");
        }
    }

    #[test]
    fn unset_falls_through_and_recognised_tokens_win_3200() {
        for polarity in [Polarity::Mandate, Polarity::Hatch] {
            for t in UNSET {
                assert_eq!(resolve(Some(t), polarity), None, "{t:?}");
                assert!(resolve_or(Some(t), polarity, true));
                assert!(!resolve_or(Some(t), polarity, false));
            }
            assert_eq!(resolve(None, polarity), None);
            for t in TRUTHY {
                assert!(resolve_or(Some(t), polarity, false), "{t:?}");
            }
            for t in FALSY {
                assert!(!resolve_or(Some(t), polarity, true), "{t:?}");
            }
        }
    }
}
