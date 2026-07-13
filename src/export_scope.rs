// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1944 (`B_WARN` de-silencing, 2×5 vote `woaiwndla` / `4d3ea1c5`) — SSOT
//! for the `ai-memory export` scope markers.
//!
//! ## Why this module exists
//!
//! The JSON `ai-memory export` command (`src/cli/io.rs::export`) and its
//! HTTP sibling (`src/handlers/admin.rs::export_memories`) emit
//! `{memories, links, count, exported_at}` — a **memories + links
//! convenience view**. They silently OMIT the substrate's tamper-evidence
//! and governance spine (governance rules, the append-only revision log,
//! forget tombstones, derivation lineage, per-write attestations, and the
//! signed-events audit chain). The lossless, integrity-preserving
//! portability path is `ai-memory backup` (SQLite `VACUUM INTO`); the
//! signed crypto spine is separately exportable via
//! `ai-memory export-forensic-bundle`.
//!
//! The ratified fix is a **de-silencing hedge**, NOT the full v2-envelope
//! exporter (that defers to v1.x, see `docs/spec/PORTABILITY-V2.md`
//! §V2-7): a stderr WARN plus additive, non-breaking in-payload markers so
//! a pipe-to-file consumer — which never sees the stderr WARN — still
//! learns the export is scope-limited. This module is the single source of
//! truth for the marker values so the CLI, the HTTP handler, and the
//! regression test cannot drift.
//!
//! The serialization core (`storage::export_all` / `export_links`) is
//! deliberately untouched — B is a de-silencing hedge layered on top of
//! the export, not a change to what the export contains.

/// Value of the additive `export_scope` marker — the record scope the JSON
/// convenience export actually carries.
pub const SCOPE_MEMORIES_LINKS: &str = "memories+links";

/// Value of the additive `portability_complete` marker. Always `false` for
/// the JSON export: it does NOT round-trip the integrity spine and is NOT
/// the portability path.
pub const PORTABILITY_COMPLETE: bool = false;

/// The signed / governance record classes the JSON convenience export
/// OMITS, surfaced verbatim in the additive `excludes` payload marker and
/// named in the stderr WARN. Each is a distinct tamper-evidence or
/// governance spine class the `backup` (lossless) path preserves.
pub const OMITTED_SIGNED_CLASSES: &[&str] = &[
    "governance",
    "revisions",
    "tombstones",
    "lineage",
    "attestations",
    // The audit chain's canonical name — reuse the chain-name SSOT rather
    // than a fresh `"signed_events"` literal (pm-v3.1 hardcoded-literal gate).
    crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS,
];

/// The lossless, integrity-preserving portability verb an operator should
/// use instead of `export` when they need a faithful round-trip.
pub const LOSSLESS_PORTABILITY_CMD: &str = "ai-memory backup";

/// The verb that exports the signed crypto spine (signed events et al.) as
/// a separate signed tar.
pub const FORENSIC_SPINE_CMD: &str = "ai-memory export-forensic-bundle";

/// Prominent stderr WARN emitted by every JSON-export surface (#1944).
///
/// Written to **stderr only** — never stdout — so a piped
/// `export > corpus.json` stays valid JSON. Names the omitted signed
/// classes, states the memories + links convenience scope, and directs the
/// operator to the lossless `backup` path (and the forensic-bundle verb for
/// the signed spine). Only references commands that actually exist.
pub const EXPORT_SCOPE_WARN: &str = concat!(
    "WARNING: `ai-memory export` is a memories+links CONVENIENCE view, NOT the ",
    "portability path. It OMITS the tamper-evidence + governance spine. For ",
    "integrity-preserving, lossless portability use `ai-memory backup` (SQLite ",
    "VACUUM INTO); the signed crypto spine is separately exportable via ",
    "`ai-memory export-forensic-bundle`. See docs/spec/PORTABILITY-V2.md."
);

/// The full stderr WARN written by the JSON-export surfaces — the prose
/// [`EXPORT_SCOPE_WARN`] plus the canonical omitted-class token list drawn
/// from [`OMITTED_SIGNED_CLASSES`], so the human-readable warning names the
/// exact classes the `excludes` payload marker carries (single source of
/// truth — the class list cannot drift between the two).
#[must_use]
pub fn export_scope_warn() -> String {
    format!(
        "{EXPORT_SCOPE_WARN} Omitted signed classes: {}.",
        OMITTED_SIGNED_CLASSES.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_classes_are_the_six_spine_classes() {
        // Pins the closed set so a future exporter change is a deliberate
        // edit here, not a silent drift. Non-tautological: asserts the
        // membership, count, and de-dup of the omitted-class SSOT.
        assert_eq!(OMITTED_SIGNED_CLASSES.len(), 6);
        for class in [
            "governance",
            "revisions",
            "tombstones",
            "lineage",
            "attestations",
            crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS,
        ] {
            assert!(
                OMITTED_SIGNED_CLASSES.contains(&class),
                "spine class {class} must be named in the export excludes marker"
            );
        }
    }

    #[test]
    fn warn_only_names_commands_that_exist() {
        // The WARN must reference `backup` + `export-forensic-bundle` (both
        // real subcommands) and MUST NOT invent a command.
        let warn = export_scope_warn();
        assert!(warn.contains("ai-memory backup"));
        assert!(warn.contains("ai-memory export-forensic-bundle"));
        assert!(
            !PORTABILITY_COMPLETE,
            "JSON export is never portability-complete"
        );
        assert_eq!(SCOPE_MEMORIES_LINKS, "memories+links");
    }

    #[test]
    fn warn_names_every_omitted_class_from_the_ssot() {
        // The human-readable WARN must name the exact class tokens the
        // `excludes` payload marker carries (SSOT-driven, no drift).
        let warn = export_scope_warn();
        for class in OMITTED_SIGNED_CLASSES {
            assert!(
                warn.contains(class),
                "WARN must name omitted spine class {class}; got: {warn}"
            );
        }
    }
}
