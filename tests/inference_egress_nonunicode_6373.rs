// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6373 / #6402 (WP-EGRESS #6053) — a SET-but-non-UTF-8
//! `AI_MEMORY_INFERENCE_EGRESS` must fail CLOSED, not resolve to `Allow`.
//!
//! `resolve_inference_egress_mode` failed closed to `Deny` for an
//! unrecognised UTF-8 value but mapped every `env::var` error to `Allow`,
//! including `VarError::NotUnicode`: an operator who SET the knob (to a
//! value that is not valid UTF-8) got the widest posture. Only `NotPresent`
//! keeps the legacy `Allow` default (per ERRORS-19).
//!
//! This binary holds exactly one test so the process-env edit is not racy.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use ai_memory::egress::{ENV_INFERENCE_EGRESS, InferenceEgressMode, resolve_inference_egress_mode};

#[test]
fn non_utf8_inference_egress_value_fails_closed_to_deny_6373() {
    // SAFETY: the only test in this binary; no concurrent env access.
    unsafe { std::env::remove_var(ENV_INFERENCE_EGRESS) };
    assert_eq!(
        resolve_inference_egress_mode(),
        InferenceEgressMode::Allow,
        "control: an UNSET knob keeps the legacy Allow default"
    );

    let invalid = OsString::from_vec(vec![0x64, 0x65, 0x6e, 0x79, 0xff, 0xfe]);
    assert!(invalid.to_str().is_none(), "fixture: not valid UTF-8");
    // SAFETY: as above.
    unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, &invalid) };
    assert_eq!(
        resolve_inference_egress_mode(),
        InferenceEgressMode::Deny,
        "#6373: a set-but-non-UTF-8 value must fail closed to Deny"
    );
}
