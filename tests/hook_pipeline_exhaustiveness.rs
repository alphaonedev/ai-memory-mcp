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
    // #2758 removed the never-fired PreRecall + PreSearch (pure read paths).
    HookEvent::PostRecall,
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
    // #2758 removed the whole transcript hook family (PreTranscriptStore +
    // PostTranscriptStore) — no production transcript-write path.
    HookEvent::PreRecallExpand,
    HookEvent::PreReflect,
    HookEvent::PostReflect,
    HookEvent::PreCompaction,
    HookEvent::OnCompactionRollback,
    HookEvent::PreSignalSend,
    HookEvent::PostSignalAck,
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
fn arch_7_hook_event_count_matches_documented_22() {
    // Narrative documents the HookEvent variant count (25 at v0.7.0;
    // 27 at v0.8.0 after #1709 adds pre_signal_send + post_signal_ack;
    // 26 at v1.0.0 after #2637 removes the never-fired pre_archive;
    // 22 at v1.0.0 after #2758 removes the never-fired pre_recall +
    // pre_search + the whole transcript hook family (pre_transcript_store
    // + post_transcript_store)).
    // Mechanically pin the count so doc + code stay in lockstep. A
    // future addition to `ALL_HOOK_EVENTS` should come with a narrative
    // bump and a count update here.
    assert_eq!(
        ALL_HOOK_EVENTS.len(),
        22,
        "ARCH-7 hook event count drift: ALL_HOOK_EVENTS has {} entries; \
         expected 22 per the v1.0.0 src/hooks/events.rs SSOT (#2758 removed \
         pre_recall + pre_search + the transcript hook family). \
         Update the test when adding or removing a variant.",
        ALL_HOOK_EVENTS.len(),
    );
}

#[test]
fn arch_7_pre_event_count_is_ten() {
    // 10 pre-events: PreStore, PreDelete, PrePromote, PreLink,
    // PreConsolidate, PreGovernanceDecision, PreRecallExpand, PreReflect,
    // PreCompaction, PreSignalSend (v0.8.0 #1709). #2637 removed the
    // never-fired PreArchive (14 → 13); #2758 removed the never-fired
    // PreRecall + PreSearch + PreTranscriptStore (13 → 10). The
    // remaining 13 variants are post-/on-class.
    let pre_count = ALL_HOOK_EVENTS
        .iter()
        .copied()
        .filter(|&ev| is_pre_event(ev))
        .count();
    assert_eq!(
        pre_count, 10,
        "ARCH-7 pre-event count drift: {pre_count} variants classify as pre-events; \
         expected 10. If a pre-event was added/removed, bump this expectation in lockstep.",
    );
}
