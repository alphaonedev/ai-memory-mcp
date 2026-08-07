// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// #2758 (R-203) — regression pins for the removal of the three
// present-but-production-UNFIRED governance hooks: `pre_recall`,
// `pre_search`, and `pre_transcript_store`.
//
// Class: advertised-vs-real governance-gate-integrity (same as #2637's
// `pre_archive`). Recall and search are pure read paths (recall mutates
// zero rows since #1869/#1953) so a pre-READ gate has no destructive op
// to gate; and `crate::transcripts::store` has no production write path.
// A present-but-unfired governance hook is a FALSE ENFORCEMENT claim —
// the substrate must not advertise an enforcement point that never fires.
//
// PRE-FIX these assertions FAIL: the three snake_case tokens DID
// deserialize into live `HookEvent` variants, `HOOK_EVENTS_COUNT` was 26,
// and a `[hooks].required_events = ["pre_recall"]` declaration parsed
// cleanly. POST-FIX the tokens are rejected by serde (so the presence
// surface no longer lists a non-event and a `required_events` entry
// naming one fails to parse loudly), and the count is 23.

use ai_memory::config::HOOK_EVENTS_COUNT;
use ai_memory::hooks::events::HookEvent;

/// The three removed tokens must NOT deserialize into any live
/// `HookEvent` variant. This is the mechanism by which a
/// `[hooks].required_events` entry naming one now fails to parse loudly
/// (the field is `Option<Vec<HookEvent>>`), and by which the advertised
/// hook surface stops CLAIMING an enforcement it does not have.
#[test]
fn removed_pre_event_tokens_no_longer_deserialize_2758() {
    for token in [
        "\"pre_recall\"",
        "\"pre_search\"",
        "\"pre_transcript_store\"",
    ] {
        let parsed: Result<HookEvent, _> = serde_json::from_str(token);
        assert!(
            parsed.is_err(),
            "{token} must NOT deserialize into a live HookEvent variant after #2758 \
             (a present-but-unfired governance hook is a false enforcement claim)"
        );
    }
}

/// The retained `post_*` NOTIFY siblings must still deserialize — #2758
/// removed only the three never-fired `pre_*` events, not the read/notify
/// events that legitimately fire.
#[test]
fn retained_post_event_tokens_still_deserialize_2758() {
    for token in [
        "\"post_recall\"",
        "\"post_search\"",
        "\"post_transcript_store\"",
    ] {
        let parsed: Result<HookEvent, _> = serde_json::from_str(token);
        assert!(
            parsed.is_ok(),
            "{token} is a retained notify event and must still deserialize"
        );
    }
}

/// The compile-time variant count SSOT drops 26 -> 23 (#2637 had taken it
/// 27 -> 26 by removing `pre_archive`).
#[test]
fn hook_events_count_is_23_after_2758() {
    assert_eq!(
        HOOK_EVENTS_COUNT, 23,
        "HOOK_EVENTS_COUNT must be 23 after #2758 removed pre_recall + pre_search \
         + pre_transcript_store (was 26 after #2637 removed pre_archive)"
    );
}

/// A `[hooks].required_events` declaration naming a removed event fails to
/// parse loudly — the substrate refuses to advertise a required enforcement
/// point that cannot fire (the issue's stated acceptance for the remove arm).
#[test]
fn required_events_naming_removed_event_fails_to_parse_2758() {
    // `HooksConfig.required_events` is `Option<Vec<HookEvent>>`; a config
    // naming `pre_recall` must not silently parse to an empty / partial set.
    let parsed: Result<Vec<HookEvent>, _> = serde_json::from_str(r#"["pre_store","pre_recall"]"#);
    assert!(
        parsed.is_err(),
        "a required_events list naming the removed pre_recall event must fail \
         to parse loudly rather than advertise a non-firing required gate"
    );
}
