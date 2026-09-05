// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#3512](https://github.com/alphaonedev/ai-memory-mcp/issues/3512) —
//! every CLI value argument that carries URL-safe base64 must accept a value
//! whose FIRST BYTE is `-` or `_`.
//!
//! # The defect
//!
//! The URL-safe base64 alphabet (RFC 4648 §5) includes `-` and `_`, so a
//! freshly generated key begins with `-` roughly one time in 64. Passed in the
//! two-token form (`--recovery-pubkey <value>`), clap read that leading `-` as
//! the start of another FLAG and refused the whole invocation with
//! `unexpected argument '-3' found`. That surfaced as a ~1/6 flake in
//! `tests/audit_cli_honors_db_3429.rs` (the test generates a fresh key on every
//! run and re-rolls the dice each time), but the flake was the SYMPTOM: the
//! defect is a product one, and an operator whose key happens to start with `-`
//! is refused by `audit bootstrap-node` with no hint of why.
//!
//! # What this pins
//!
//! #3512 asks for a pin that feeds a value starting with `-` AND one starting
//! with `_`. `_` is the control: it is in the same alphabet and was NEVER
//! broken, so a rule that "fixed" the `-` case by mangling leading punctuation
//! generally would fail here. Every argument is exercised in BOTH accepted
//! forms — the two-token `--flag value` (the shape that broke) and the
//! `--flag=value` shape scripts should prefer — and the parsed value is
//! asserted to round-trip BYTE-FOR-BYTE, because a parse that merely
//! "succeeds" while dropping or truncating the leading character would be a
//! worse defect than the refusal it replaced.
//!
//! The coverage set is derived from the grep that closes the issue's "audit
//! every `#[arg]` that takes base64/ids for the same hazard" clause: every
//! `value_name` in `src/cli/` that is `PUBKEY_B64`, `CHALLENGE_B64`, or
//! `PUBKEY_B64:SIG_B64` (10 arguments across `audit`, `identity` and `agents`).
//! `tests/cli_subcommand_count_invariant.rs` guards the subcommand surface;
//! this guards the VALUE grammar of that surface.

use ai_memory::daemon_runtime::Cli;
use clap::Parser as _;

/// Values whose first byte is the hazardous one. `-` is the defect; `_` is the
/// same-alphabet control that must never have been affected.
const HAZARDOUS_VALUES: &[&str] = &[
    "-3qYb2VjcmV0LWtleS1tYXRlcmlhbA",
    "_3qYb2VjcmV0LWtleS1tYXRlcmlhbA",
];

/// A composite `<pubkey_b64>:<sig_b64>` value whose FIRST half starts with the
/// hazardous byte — the shape `--attestation` / `--approval` take.
fn composite(value: &str) -> String {
    format!("{value}:c2lnbmF0dXJlLWJ5dGVz")
}

/// Every `(argv-prefix, flag)` pair carrying a URL-safe-base64 value.
///
/// The argv prefix is everything up to (but not including) the flag under
/// test, including any OTHER required argument of that subcommand, so each row
/// is a complete, parseable invocation once the flag and its value are
/// appended.
fn base64_value_args() -> Vec<(Vec<&'static str>, &'static str, bool)> {
    vec![
        // (argv before the flag, flag, is_composite)
        (
            vec!["ai-memory", "audit", "bootstrap-node"],
            "--recovery-pubkey",
            false,
        ),
        (
            vec!["ai-memory", "identity", "enroll-lineage"],
            "--recovery-pubkey",
            false,
        ),
        (
            vec!["ai-memory", "identity", "register-recovery-key"],
            "--recovery-pubkey",
            false,
        ),
        (
            vec!["ai-memory", "identity", "recover-prepare"],
            "--successor-pubkey",
            false,
        ),
        (
            vec![
                "ai-memory",
                "identity",
                "recover-prepare",
                "--successor-pubkey",
                "c3VjY2Vzc29y",
            ],
            "--recovery-pubkey",
            false,
        ),
        (
            vec!["ai-memory", "identity", "sign-recovery"],
            "--challenge",
            false,
        ),
        (
            vec![
                "ai-memory",
                "identity",
                "recover",
                "--not-before",
                "2026-09-05T00:00:00Z",
            ],
            "--successor-pubkey",
            false,
        ),
        (
            vec![
                "ai-memory",
                "identity",
                "recover",
                "--not-before",
                "2026-09-05T00:00:00Z",
                "--successor-pubkey",
                "c3VjY2Vzc29y",
            ],
            "--recovery-pubkey",
            false,
        ),
        (
            vec![
                "ai-memory",
                "identity",
                "recover",
                "--not-before",
                "2026-09-05T00:00:00Z",
                "--successor-pubkey",
                "c3VjY2Vzc29y",
            ],
            "--attestation",
            true,
        ),
        // `pending` is its OWN top-level command (`Command::Pending`), not a
        // verb under `agents` — its args type merely lives in `cli::agents`.
        (
            vec!["ai-memory", "pending", "approve", "pending-id-1"],
            "--approval",
            true,
        ),
    ]
}

/// Every base64 value argument parses in the TWO-TOKEN form with a value whose
/// first byte is `-` (the #3512 defect) or `_` (the same-alphabet control).
///
/// Pre-fix this failed with clap's `unexpected argument '-3' found` on every
/// `-`-leading row.
#[test]
fn base64_value_args_accept_a_leading_hyphen_in_the_two_token_form_3512() {
    let mut checked = 0_usize;
    for (prefix, flag, is_composite) in base64_value_args() {
        for value in HAZARDOUS_VALUES {
            let owned = if is_composite {
                composite(value)
            } else {
                (*value).to_owned()
            };
            let mut argv: Vec<String> = prefix.iter().map(|s| (*s).to_owned()).collect();
            argv.push((*flag).to_owned());
            argv.push(owned.clone());

            let parsed = Cli::try_parse_from(&argv);
            assert!(
                parsed.is_ok(),
                "#3512: `{} {owned}` must parse in the two-token form; clap said: {}",
                flag,
                parsed.err().map_or_else(String::new, |e| e.to_string())
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        base64_value_args().len() * HAZARDOUS_VALUES.len(),
        "every argument must be exercised with every hazardous value"
    );
}

/// The same arguments in the `--flag=value` form, which is what scripts should
/// use: `allow_hyphen_values` makes an option with an OMITTED value swallow the
/// next flag, so the `=` form stays the safer shape even now.
#[test]
fn base64_value_args_accept_a_leading_hyphen_in_the_equals_form_3512() {
    for (prefix, flag, is_composite) in base64_value_args() {
        for value in HAZARDOUS_VALUES {
            let owned = if is_composite {
                composite(value)
            } else {
                (*value).to_owned()
            };
            let mut argv: Vec<String> = prefix.iter().map(|s| (*s).to_owned()).collect();
            argv.push(format!("{flag}={owned}"));

            let parsed = Cli::try_parse_from(&argv);
            assert!(
                parsed.is_ok(),
                "#3512: `{flag}={owned}` must parse; clap said: {}",
                parsed.err().map_or_else(String::new, |e| e.to_string())
            );
        }
    }
}

/// A parse that SUCCEEDS while dropping or truncating the leading byte would
/// be worse than the refusal it replaced — a silently wrong key is a
/// data-integrity problem, a refusal is merely an outage. Pin the round-trip
/// on the argument the #3512 report names, in both forms.
#[test]
fn a_hyphen_leading_recovery_pubkey_round_trips_byte_for_byte_3512() {
    use ai_memory::daemon_runtime::Command;

    for value in HAZARDOUS_VALUES {
        for argv in [
            vec![
                "ai-memory".to_owned(),
                "audit".to_owned(),
                "bootstrap-node".to_owned(),
                "--recovery-pubkey".to_owned(),
                (*value).to_owned(),
            ],
            vec![
                "ai-memory".to_owned(),
                "audit".to_owned(),
                "bootstrap-node".to_owned(),
                format!("--recovery-pubkey={value}"),
            ],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("parses");
            let Command::Audit(audit) = cli.command else {
                panic!("expected the audit subcommand for {argv:?}");
            };
            let ai_memory::cli::audit::AuditAction::BootstrapNode(args) = audit.action else {
                panic!("expected bootstrap-node for {argv:?}");
            };
            assert_eq!(
                args.recovery_pubkey.as_deref(),
                Some(*value),
                "#3512: the key must survive parsing byte-for-byte ({argv:?})"
            );
        }
    }
}
