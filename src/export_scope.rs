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
///
/// v1.0.0 #2490 — `archived_memories` + `namespace_meta` were added. They
/// were ALREADY omitted by both export modes (`export_all` reads only the
/// live `memories` table; neither exporter reads `namespace_meta` at all),
/// but the marker did not say so, so the artifact asserted a scope it did
/// not have. Naming them is a truthfulness fix using the mechanism that
/// already ships, not a behaviour change.
pub const OMITTED_SIGNED_CLASSES: &[&str] = &[
    "governance",
    "revisions",
    "tombstones",
    "lineage",
    "attestations",
    // The audit chain's canonical name — reuse the chain-name SSOT rather
    // than a fresh `"signed_events"` literal (pm-v3.1 hardcoded-literal gate).
    crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS,
    OMITTED_CLASS_ARCHIVED_MEMORIES,
    OMITTED_CLASS_NAMESPACE_META,
];

/// v1.0.0 #2490 — the archive table. Neither `export` nor `export --full`
/// reads it, so archived rows do NOT round-trip through either artifact.
pub const OMITTED_CLASS_ARCHIVED_MEMORIES: &str = "archived_memories";

/// v1.0.0 #2490 — the per-namespace governance-standard binding table.
/// Neither export mode reads it.
pub const OMITTED_CLASS_NAMESPACE_META: &str = "namespace_meta";

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

/// v1.0.0 #2490 — the machine-readable accounting of everything an export
/// did NOT faithfully carry.
///
/// # Why this exists
///
/// `ai-memory export` reported `count` = the number of rows it emitted and
/// exited 0, which is self-CONSISTENT and therefore undetectable from the
/// artifact alone: a corpus of 3 live memories whose PEM-bearing row is
/// dropped by the fail-closed forbidden-class gate
/// ([`crate::export_taxonomy::screen_memories_for_export`]) and whose
/// credential-bearing row is content-mutated by the secret screen emits
/// `count: 2` with no signal of either. The operator holding that file has
/// a backup that lies about completeness, and discovers it at restore time —
/// the one moment it cannot be fixed (#2490, the #2444 false-success class).
///
/// # Confidentiality boundary on the ids
///
/// [`Self::withheld_ids`] and [`Self::redacted_ids`] are for the OPERATOR
/// channel (stderr + the signed audit row) and MUST NOT be written into the
/// export artifact. The forbidden-class gate is an EXPORT-boundary control
/// only — no read surface consults it — so publishing "these ids carry
/// private key material" INTO the portable artifact would hand whoever holds
/// it a precise index into the source corpus's key material, reachable via
/// any other surface. The artifact carries COUNTS and a class histogram
/// (5-agent vote 4d3ea1c5, security-lens objection O3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportWithholdLedger {
    /// Ids DROPPED by the forbidden-class gate. Operator channel only.
    pub withheld_ids: Vec<String>,
    /// `class token -> count` histogram of the drops. Safe in-band.
    pub withheld_by_class: std::collections::BTreeMap<String, usize>,
    /// Ids whose content/title/tags/metadata were MUTATED by the secret
    /// screen. Operator channel only.
    pub redacted_ids: Vec<String>,
    /// Live rows the SQL-level lifecycle allow-list excluded BEFORE the
    /// screen ran, because they are `quarantined` (#1948). These are real
    /// data withheld from the artifact, so they count toward "partial".
    ///
    /// #2490 vote objection O4: a `withheld` count derived only from the
    /// screen would report `0` on a corpus running
    /// `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED=1`, because
    /// [`crate::storage::export_all`] applies
    /// [`crate::models::lifecycle_visible_clause`] IN SQL and those rows
    /// never reach the screen at all.
    pub quarantined: usize,
    /// Live rows excluded as `tombstoned`. Reported, but NOT counted as
    /// partial: a tombstone IS the erasure receipt, so omitting it from a
    /// portable copy is the intended behaviour, not loss.
    pub tombstoned: usize,
    /// Live rows excluded because `expires_at` has passed. Reported, not
    /// counted as partial — expiry is intended.
    pub expired: usize,
}

impl ExportWithholdLedger {
    /// Total rows the confidentiality gate DROPPED.
    #[must_use]
    pub fn withheld_total(&self) -> usize {
        self.withheld_ids.len()
    }

    /// Rows whose stored bytes were ALTERED before serialization.
    #[must_use]
    pub fn redacted_total(&self) -> usize {
        self.redacted_ids.len()
    }

    /// `true` when the artifact is NOT a faithful copy of the live corpus:
    /// a forbidden-class drop or a quarantined row was withheld.
    ///
    /// Redaction is deliberately NOT partial here (4-1 on D4): a redacted
    /// row is PRESENT in the artifact, the drop is mode-dependent
    /// (`AI_MEMORY_SECRET_SCREEN_MODE`) and steady-state on any corpus
    /// holding one legacy credential row, and making it non-zero would
    /// create pressure to disable the screen globally — which also disables
    /// the pre-WRITE credential screen on every surface, a strictly worse
    /// outcome. The restore-side corruption it would cause is instead
    /// blocked at import (`crate::cli::io`'s redaction-overwrite refusal).
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.withheld_total() > 0 || self.quarantined > 0
    }

    /// The in-band, machine-readable marker for the v1 JSON export.
    /// COUNTS + class histogram only — never ids (see the type docs).
    #[must_use]
    pub fn in_band_marker(&self) -> serde_json::Value {
        use crate::models::field_names as f;
        serde_json::json!({
            (f::WITHHELD): self.withheld_total(),
            (f::WITHHELD_BY_CLASS): self.withheld_by_class,
            (f::QUARANTINED): self.quarantined,
            (f::REDACTED): self.redacted_total(),
            (f::TOMBSTONED): self.tombstoned,
            (f::EXPIRED): self.expired,
        })
    }

    /// The ONE structured stderr line a fleet controller parses. Carries the
    /// ids (operator channel) under a stable `event` key so 10^6 nodes
    /// aggregate without regexing prose.
    #[must_use]
    pub fn stderr_report_line(&self, source_db: &str, exported: usize) -> String {
        use crate::models::field_names as f;
        serde_json::json!({
            "event": EXPORT_REPORT_EVENT,
            "source_db": source_db,
            "exported": exported,
            (f::WITHHELD): self.withheld_total(),
            (f::WITHHELD_BY_CLASS): self.withheld_by_class,
            (f::WITHHELD_IDS): self.withheld_ids,
            (f::QUARANTINED): self.quarantined,
            (f::REDACTED): self.redacted_total(),
            (f::REDACTED_IDS): self.redacted_ids,
            (f::TOMBSTONED): self.tombstoned,
            (f::EXPIRED): self.expired,
            "partial": self.is_partial(),
        })
        .to_string()
    }
}

/// Stable `event` key of the structured stderr export report (#2490).
pub const EXPORT_REPORT_EVENT: &str = "export_report";

/// Process exit code for "the artifact WAS written and is internally valid,
/// but it is INCOMPLETE" (#2490).
///
/// Deliberately distinct from `1`. The universal backup idiom
/// `ai-memory export > out.tmp && mv out.tmp out` deletes the partial
/// artifact on ANY non-zero status, and plain `1` also collapses "your
/// backup is incomplete" into the same bucket as "the process crashed" — so
/// a fleet controller could not tell an incomplete-but-usable artifact from
/// no artifact at all. A distinct code lets an orchestrator branch:
/// `case $rc in 0) ok;; 3) partial;; *) failed;; esac`
/// (5-agent vote 4d3ea1c5, fleet-lens objection O5).
pub const EXIT_EXPORT_INCOMPLETE: i32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_classes_are_the_six_spine_classes() {
        // Pins the closed set so a future exporter change is a deliberate
        // edit here, not a silent drift. Non-tautological: asserts the
        // membership, count, and de-dup of the omitted-class SSOT.
        // v1.0.0 #2490 raised 6 -> 8 (archived_memories + namespace_meta).
        assert_eq!(OMITTED_SIGNED_CLASSES.len(), 8);
        for class in [
            "governance",
            "revisions",
            "tombstones",
            "lineage",
            "attestations",
            crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS,
            OMITTED_CLASS_ARCHIVED_MEMORIES,
            OMITTED_CLASS_NAMESPACE_META,
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
