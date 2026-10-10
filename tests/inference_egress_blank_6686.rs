// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6686 (WP-EGRESS #6053) — a SET-but-blank `AI_MEMORY_INFERENCE_EGRESS`
//! (empty or whitespace-only) must fail CLOSED to `Deny`, not resolve to the
//! `Allow` default. Only an UNSET knob keeps the legacy default.
//!
//! `parse` trimmed first and then mapped `""` to `Allow`, so a templating slip
//! (`AI_MEMORY_INFERENCE_EGRESS=`) silently chose the widest posture while the
//! docstring said "set at all = restriction intent". 3-agent vote (6def5ab6):
//! fail closed.
//!
//! This binary holds exactly one test so the process-env edits are not racy.

use ai_memory::egress::{ENV_INFERENCE_EGRESS, InferenceEgressMode, resolve_inference_egress_mode};

#[test]
fn blank_inference_egress_value_fails_closed_to_deny_6686() {
    // SAFETY: the only test in this binary; no concurrent env access.
    unsafe { std::env::remove_var(ENV_INFERENCE_EGRESS) };
    assert_eq!(
        resolve_inference_egress_mode(),
        InferenceEgressMode::Allow,
        "control: an UNSET knob keeps the legacy Allow default"
    );
    for blank in ["", " ", "   ", "\t", "\n", " \t \n"] {
        // SAFETY: as above.
        unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, blank) };
        assert_eq!(
            resolve_inference_egress_mode(),
            InferenceEgressMode::Deny,
            "#6686: a set-but-blank value ({blank:?}) must fail closed to Deny"
        );
    }
    // Controls: a padded or upper/mixed-case explicit token is still honoured
    // (trim and ASCII case-folding stay; N13).
    for ok in [" allow ", " ALLOW ", "Allow"] {
        // SAFETY: as above.
        unsafe { std::env::set_var(ENV_INFERENCE_EGRESS, ok) };
        assert_eq!(
            resolve_inference_egress_mode(),
            InferenceEgressMode::Allow,
            "control: the explicit token {ok:?} is still Allow"
        );
    }
}
