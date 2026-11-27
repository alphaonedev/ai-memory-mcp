// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10176: the run-time refusal every `proptest!` block of this repository
//! opens with, `#![proptest_config(proptest_guarded(..))]`.
//!
//! proptest's `fork` and `timeout` features are on in `Cargo.lock` (through
//! `rusty-fork` and `wait-timeout`). With either one enabled for a block,
//! proptest runs each case in a child process that re-runs the test binary,
//! and that child is started by proptest's own code, outside the #10176
//! sandbox and outside both source layers. The two switches are the
//! `Config` fields `fork` and `timeout` and the environment variables
//! `PROPTEST_FORK` and `PROPTEST_TIMEOUT`, which proptest reads when the
//! block runs (`contextualize_config`). [`proptest_guarded`] refuses all four:
//! it panics with an exact message when either variable holds anything but
//! the one value proven to leave the switch off, and asserts that the config
//! it returns, after proptest's own reading of the environment, has both
//! switches off.
//!
//! Included by `#[path]` from `src/test_support.rs` (the lib-test proptest
//! blocks), from each proptest integration test and from
//! `tests/process_start_census_10176.rs` (the refusal table).

#![allow(dead_code)]

use std::ffi::OsStr;

use proptest::test_runner::Config;

/// The variable that switches proptest's fork mode on.
pub const FORK_VAR: &str = "PROPTEST_FORK";
/// The variable that sets proptest's per-case timeout (non-zero forks).
pub const TIMEOUT_VAR: &str = "PROPTEST_TIMEOUT";
/// The one value of [`FORK_VAR`] proven to leave fork mode off.
pub const FORK_OFF: &str = "false";
/// The one value of [`TIMEOUT_VAR`] proven to leave the timeout off.
pub const TIMEOUT_OFF: &str = "0";
/// The longest part of a refused value a message shows, in chars.
pub const SHOWN_MAX_CHARS: usize = 64;

/// Why a proptest environment variable is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvRefusal {
    /// The value proptest parses as "on" (`true`, or a non-zero timeout).
    Enables { name: &'static str, shown: String },
    /// A value that is not the proven "off" value (proptest would warn and
    /// keep its default, which is not proven here either).
    Unproven {
        name: &'static str,
        shown: String,
        off: &'static str,
    },
    /// The value is not UTF-8.
    Unreadable { name: &'static str },
}

impl std::fmt::Display for EnvRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enables { name, shown } => write!(
                f,
                "{name}={shown} makes proptest run each case in a child process that re-runs this test binary outside the #10176 sandbox; unset it"
            ),
            Self::Unproven { name, shown, off } => write!(
                f,
                "{name}={shown} is not a value proven to leave proptest's fork and timeout off (unset, or exactly {off:?}); unset it (#10176)"
            ),
            Self::Unreadable { name } => {
                write!(
                    f,
                    "{name} holds bytes that are not UTF-8; unset it (#10176)"
                )
            }
        }
    }
}

/// The refused value as shown in a message: at most [`SHOWN_MAX_CHARS`]
/// chars (cut on a char boundary), Debug-quoted so control characters and
/// quotes are escaped.
fn shown(text: &str) -> String {
    let cut: String = text.chars().take(SHOWN_MAX_CHARS).collect();
    if cut.len() < text.len() {
        format!("{cut:?}...")
    } else {
        format!("{cut:?}")
    }
}

/// The verdict for one variable: `None` when the value is unset or the
/// proven "off" value; every other value is refused.
#[must_use]
pub fn env_refusal(name: &'static str, value: Option<&OsStr>) -> Option<EnvRefusal> {
    let off = match name {
        FORK_VAR => FORK_OFF,
        TIMEOUT_VAR => TIMEOUT_OFF,
        // A name this guard does not know has no proven "off" value.
        _ => "",
    };
    let value = value?;
    let Some(text) = value.to_str() else {
        return Some(EnvRefusal::Unreadable { name });
    };
    if !off.is_empty() && text == off {
        return None;
    }
    let enables = match name {
        // proptest parses these with `bool::from_str` and `u32::from_str`.
        FORK_VAR => text == "true",
        TIMEOUT_VAR => text.parse::<u32>().is_ok_and(|n| n != 0),
        _ => false,
    };
    let shown = shown(text);
    if enables {
        Some(EnvRefusal::Enables { name, shown })
    } else {
        Some(EnvRefusal::Unproven { name, shown, off })
    }
}

/// Refuses the two proptest variables in this process's environment and
/// returns `cfg` with fork and timeout proven off. Panics with the exact
/// refusal otherwise (a test-only entry: the panic fails the block).
#[must_use]
pub fn proptest_guarded(cfg: Config) -> Config {
    for name in [FORK_VAR, TIMEOUT_VAR] {
        if let Some(refusal) = env_refusal(name, std::env::var_os(name).as_deref()) {
            panic!("#10176: {refusal}");
        }
    }
    let effective = proptest::test_runner::contextualize_config(cfg.clone());
    for (which, c) in [("given", &cfg), ("effective", &effective)] {
        assert!(
            !c.fork(),
            "#10176: the {which} proptest config has fork on; a forked case re-runs this test binary outside the sandbox"
        );
        assert_eq!(
            c.timeout(),
            0,
            "#10176: the {which} proptest config has a timeout; a timed case re-runs this test binary outside the sandbox"
        );
    }
    cfg
}
