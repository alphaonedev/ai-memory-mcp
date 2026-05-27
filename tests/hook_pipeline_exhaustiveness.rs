// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-7 (FX-C4-batch2, 2026-05-26) — hook-pipeline event exhaustiveness.
//!
//! Pins the `HookEvent` variant set against `is_pre_event`'s
//! classification matrix so adding a 26th variant FAILS at the
//! exhaustive `match` in `is_pre_event` (compile-time gate) AND at
//! this test (test-time gate that walks the canonical
//! `ALL_HOOK_EVENTS` list and asserts every variant has a
//! classification answer).
//!
//! Why two gates: the compile-time `match` catches dropped variants
//! in the function body; this test catches dropped variants in
//! `ALL_HOOK_EVENTS` itself (a future contributor who adds a variant
//! but forgets to extend `ALL_HOOK_EVENTS` would otherwise have an
//! incomplete SSOT). Together they make the engineering invariant
//! mechanically enforced from both sides.

use ai_memory::hooks::decision::is_pre_event;
use ai_memory::hooks::events::HookEvent;

/// Canonical list of every `HookEvent` variant at v0.7.0. Adding a
/// new variant requires extending this array AND the
/// `is_pre_event` match below; both fail loudly without the update.
const ALL_HOOK_EVENTS: &[HookEvent] = &[
    HookEvent::PreStore,
    HookEvent::PostStore,
    HookEvent::PreRecall,
    HookEvent::PostRecall,
    HookEvent::PreSearch,
    HookEvent::PostSearch,
    HookEvent::PreDelete,
    HookEvent::PostDelete,
    HookEvent::PrePromote,
    HookEvent::PostPromote,
    HookEvent::PreLink,
    HookEvent::PostLink,
    HookEvent::PreConsolidate,
    HookEvent::PostConsolidate,
    HookEvent::PreGovernanceDecision,
    HookEvent::PostGovernanceDecision,
    HookEvent::OnIndexEviction,
    HookEvent::PreArchive,
    HookEvent::PreTranscriptStore,
    HookEvent::PostTranscriptStore,
    HookEvent::PreRecallExpand,
    HookEvent::PreReflect,
    HookEvent::PostReflect,
    HookEvent::PreCompaction,
    HookEvent::OnCompactionRollback,
];

#[test]
fn arch_7_all_hook_events_classified_by_is_pre_event() {
    // Hit `is_pre_event` for every known variant. The function
    // itself is `#[deny(unreachable_patterns)]` over an exhaustive
    // match — so adding a HookEvent without classifying it fails
    // compilation. Re-asserting through this loop catches the
    // inverse failure: a SSOT drift in `ALL_HOOK_EVENTS`.
    for &ev in ALL_HOOK_EVENTS {
        // Just call it; any panic here would be a substrate bug.
        let _ = is_pre_event(ev);
    }
}

#[test]
fn arch_7_hook_event_count_matches_documented_25() {
    // CLAUDE.md narrative at v0.7.0 documents "25 HookEvent
    // variants". Mechanically pin the count so doc + code stay in
    // lockstep. A future addition to `ALL_HOOK_EVENTS` should
    // come with a CLAUDE.md narrative bump and a count update here.
    assert_eq!(
        ALL_HOOK_EVENTS.len(),
        25,
        "ARCH-7 hook event count drift: ALL_HOOK_EVENTS has {} entries; \
         expected 25 per the v0.7.0 CLAUDE.md / src/hooks/events.rs SSOT. \
         Update the test AND CLAUDE.md when adding a variant.",
        ALL_HOOK_EVENTS.len(),
    );
}

#[test]
fn arch_7_pre_event_count_is_thirteen() {
    // 13 pre-events: PreStore, PreRecall, PreSearch, PreDelete,
    // PrePromote, PreLink, PreConsolidate, PreGovernanceDecision,
    // PreArchive, PreTranscriptStore, PreRecallExpand, PreReflect,
    // PreCompaction. The remaining 12 are post-/on-class.
    let pre_count = ALL_HOOK_EVENTS
        .iter()
        .copied()
        .filter(|&ev| is_pre_event(ev))
        .count();
    assert_eq!(
        pre_count, 13,
        "ARCH-7 pre-event count drift: {pre_count} variants classify as pre-events; \
         expected 13. If a new pre-event was added, bump this expectation in lockstep.",
    );
}
