// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2427](https://github.com/alphaonedev/ai-memory-mcp/issues/2427) +
//! [#2596](https://github.com/alphaonedev/ai-memory-mcp/issues/2596) — two
//! arms that DISCARD something and used to say nothing about it.
//!
//! Both fixes are observability restorations: the discard itself is unchanged
//! (and, in both cases, defensible), while the SILENCE was not. An operator
//! cannot debug a control that evaporates or a webhook that never fires if the
//! only evidence is an absence. These cells pin the disposition at the source,
//! which is the level the defect lived at — a `tracing` capture would pin the
//! message text, not the fact that the arm is distinguishable from `Allow` /
//! from a successful lookup.
//!
//! **R-203 fail-at-parent.** Neither cell references a symbol introduced by
//! the fix (both read source text), so this file compiles unchanged at the
//! parent commit and FAILS there.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

fn read_src(rel: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Span from `needle` to the first line that closes a top-level item.
fn span_from(src: &str, needle: &str, end_marker: &str) -> String {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("missing: {needle}"));
    let rest = &src[start..];
    let end = rest
        .find(end_marker)
        .map_or(rest.len(), |i| i + end_marker.len());
    rest[..end].to_string()
}

// ---------------------------------------------------------------------------
// #2427 — the pre-event gate must not fold ModifiedAllow into Allow.
// ---------------------------------------------------------------------------

/// A hook returning `{"action":"modify","delta":{…}}` on a pre-event gate is
/// parsed, chained, and then DROPPED — the original content persists. That is
/// a governance-bypass SHAPE (a declared control the substrate will never
/// honour), and the #1752 signal path four lines away already warned about
/// exactly this case. Folding `ModifiedAllow(_)` into the `Allow` arm makes
/// the two indistinguishable, which is precisely what hid it.
#[test]
fn pre_event_gate_does_not_fold_modified_allow_into_allow_2427() {
    let src = read_src("src/mcp/mod.rs");
    let body = span_from(
        &src,
        "pub(crate) fn consult_pre_event_gate(",
        "\n/// #2390 (N9)",
    );
    assert!(
        !body.contains("ChainResult::Allow | ChainResult::ModifiedAllow(_)"),
        "a discarded hook delta must be distinguishable from a plain Allow:\n{body}"
    );
    assert!(
        body.contains("ChainResult::ModifiedAllow"),
        "the arm must still be handled explicitly:\n{body}"
    );
    assert!(
        body.contains("tracing::warn!"),
        "the discard must be surfaced, matching the #1752 signal path:\n{body}"
    );

    // The public wire vocabulary has to say which sites discard the delta —
    // `Modify` is part of the `#[serde(tag = "action")]` hook contract, so an
    // inert-but-advertised return is a documentation defect on a public API.
    let decision = read_src("src/hooks/decision.rs");
    let modify_doc = span_from(
        &decision,
        "    /// Rewrite the in-flight payload",
        "Modify(ModifyPayload),",
    );
    assert!(
        modify_doc.contains("#2427"),
        "HookDecision::Modify must document where the delta is NOT applied:\n{modify_doc}"
    );
}

// ---------------------------------------------------------------------------
// #2596 — a skipped memory_link_created dispatch must be audible.
// ---------------------------------------------------------------------------

/// The postgres link path anchors the `memory_link_created` webhook on a
/// full-row `get` of the source memory, and every failure mapped to
/// `Err(_) => (None, None)` — which suppresses the dispatch. Under
/// `AI_MEMORY_ENCRYPT_AT_REST` a source row whose envelope will not open fails
/// that `FailClosed` read on EVERY attempt, so a subscriber loses the event
/// permanently with no signal anywhere. The link itself committed, which is
/// why the failure is invisible from the response.
#[test]
fn link_dispatch_anchor_failure_is_warned_not_swallowed_2596() {
    let src = read_src("src/handlers/links.rs");
    let start = src
        .find("let (link_namespace, link_owner) = match app.store.get(&ctx, &source_id).await")
        .expect("the link-dispatch anchor lookup must exist");
    let arm = &src[start..(start + 2400).min(src.len())];
    assert!(
        !arm.contains("Err(_) => (None, None)"),
        "a suppressed webhook dispatch must name its cause, not swallow the error:\n{arm}"
    );
    assert!(
        arm.contains("tracing::warn!"),
        "the skipped dispatch must be logged with the error:\n{arm}"
    );
    assert!(
        arm.contains("#2596"),
        "the WARN must be traceable to the finding it closes:\n{arm}"
    );
}
