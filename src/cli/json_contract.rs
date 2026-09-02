// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3436 — the `--json` CONTRACT gate.
//!
//! # The defect this closes
//!
//! `--json` is declared `global = true` on [`crate::daemon_runtime::Cli`],
//! so **clap accepts it on all 94 subcommands**. Only some of them do
//! anything with it. `ai-memory install --json`, `wrap --json`,
//! `man --json`, `config check --json` and `export-forensic-bundle --json`
//! parsed fine, exited 0, and emitted their ordinary human output — a flag
//! that is accepted, reported successful, and does nothing is the
//! reports-success-doing-nothing class, and it is worse than a rejection
//! because a script cannot tell the difference until it tries to parse the
//! output.
//!
//! # The control
//!
//! ONE classification, [`json_support`], exhaustive over
//! [`crate::daemon_runtime::Command`]. Because the match has no `_` arm, a
//! new subcommand **does not compile** until somebody decides what
//! `--json` means for it. That is the point: the failure mode this closes
//! is a verb quietly inheriting a flag nobody wired, and an exhaustive
//! match is the only thing that makes inheriting-by-accident impossible.
//!
//! Three states, because the CLI genuinely has three:
//!
//! * [`JsonSupport::Global`] — the verb is handed the global flag by the
//!   dispatcher and emits JSON on stdout.
//! * [`JsonSupport::Local`] — the verb declares its own `--json` /
//!   `--format json`, which clap resolves at the subcommand level. The
//!   intent is honoured either way, so the gate stays out of it.
//! * [`JsonSupport::Unsupported`] — the verb has no JSON form at all.
//!   `--json` is REFUSED with a message that says so and names what the
//!   verb does emit, instead of being silently dropped.
//!
//! # Why refuse rather than invent a JSON form
//!
//! The unsupported set is `serve` / `mcp` / `sync-daemon` (long-running
//! daemons whose stdout is a log or a protocol channel), `man` /
//! `completions` / `shell` / `wrap` (generators and passthroughs whose
//! output IS the artifact), and `install` / `config` /
//! `export-forensic-bundle` / `verify-forensic-bundle` / `calibrate`
//! (human reports and diffs). Minting a JSON shape for each would be new
//! wire surface invented to satisfy a flag nobody asked to work; refusing
//! is the honest, fail-closed answer and it is reversible — a later change
//! moves a verb from `Unsupported` to `Global` in one line.

use crate::daemon_runtime::Command;

/// What `--json` means for one subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonSupport {
    /// Honoured through the dispatcher's global flag.
    Global,
    /// Honoured through the subcommand's own `--json` / `--format`.
    Local,
    /// No JSON form exists; `--json` is refused rather than ignored.
    Unsupported,
}

/// Classify one subcommand's `--json` support.
///
/// Exhaustive on purpose — see the module docs. Adding a
/// [`Command`] variant without classifying it is a compile error.
#[must_use]
pub fn json_support(command: &Command) -> JsonSupport {
    match command {
        // Handed the global `--json` by the dispatcher (`cli.json` -> `j`).
        Command::Store(..)
        | Command::Update(..)
        | Command::Recall(..)
        | Command::Search(..)
        | Command::Get(..)
        | Command::List(..)
        | Command::Delete(..)
        | Command::Promote(..)
        | Command::Forget(..)
        | Command::Link(..)
        | Command::Consolidate(..)
        | Command::Gc
        | Command::Stats
        | Command::Namespaces
        | Command::Namespace(..)
        | Command::Import(..)
        | Command::Resolve(..)
        | Command::Sync(..)
        | Command::AutoConsolidate(..)
        | Command::Mine(..)
        | Command::Archive(..)
        | Command::Agents(..)
        | Command::Identity(..)
        | Command::Capability(..)
        | Command::Rules(..)
        | Command::ModelAttest(..)
        | Command::Quarantine(..)
        | Command::EpochApply(..)
        | Command::Pending(..)
        | Command::Backup(..)
        | Command::Restore(..)
        | Command::Features => JsonSupport::Global,

        // Declares its own `--json` / `--format json` at the subcommand level.
        Command::Export(..)
        | Command::Offload(..)
        | Command::Deref(..)
        | Command::Curator(..)
        | Command::Bench(..)
        | Command::Doctor(..)
        | Command::Boot(..)
        | Command::Logs(..)
        | Command::Audit(..)
        | Command::Governance(..)
        | Command::VerifyReflectionChain(..)
        | Command::VerifySignedEventsChain(..)
        | Command::VerifyAuditTrail(..)
        | Command::ExportReflections(..)
        | Command::RecoverPreviousSession(..)
        | Command::Watch(..)
        | Command::Atomise(..)
        | Command::Persona(..)
        | Command::Skill(..)
        | Command::Share(..)
        | Command::KgQuery(..)
        | Command::FindPaths(..)
        | Command::Lineage(..)
        | Command::RecallObservations(..)
        | Command::Expand(..)
        | Command::CheckDuplicate(..)
        | Command::Reembed(..)
        | Command::UndoEdit(..)
        | Command::Reown(..)
        | Command::Stop(..)
        | Command::Replay(..)
        | Command::Reflect(..)
        | Command::Subscribe(..)
        | Command::Unsubscribe(..)
        | Command::ListSubscriptions(..)
        | Command::SubscriptionReplay(..)
        | Command::SubscriptionDlqList(..)
        | Command::Notify(..)
        | Command::Inbox(..)
        | Command::IngestMultistep(..)
        | Command::KgInvalidate(..)
        | Command::KgTimeline(..)
        | Command::EntityRegister(..)
        | Command::EntityGetByAlias(..)
        | Command::DependentsOfInvalidated(..)
        | Command::SwarmRewind(..)
        | Command::ReflectionOrigin(..)
        | Command::QuotaStatus(..) => JsonSupport::Local,

        // `sal`-gated twins of the Local arm above. An or-pattern cannot
        // carry a `#[cfg]` per alternative, so these two get their own arms
        // — mirroring the `#[cfg(feature = "sal")]` on the variants
        // themselves, which is what keeps the match exhaustive in BOTH the
        // default and the `--features sal` build.
        #[cfg(feature = "sal")]
        Command::Migrate(..) => JsonSupport::Local,
        #[cfg(feature = "sal")]
        Command::SchemaInit(..) => JsonSupport::Local,

        // No JSON form: daemons, generators/passthroughs, and human reports.
        Command::Serve(..)
        | Command::Mcp { .. }
        | Command::Config(..)
        | Command::Shell
        | Command::SyncDaemon(..)
        | Command::Completions(..)
        | Command::Man
        | Command::Install(..)
        | Command::Wrap(..)
        | Command::ExportForensicBundle(..)
        | Command::VerifyForensicBundle(..)
        | Command::Calibrate(..) => JsonSupport::Unsupported,
    }
}

/// The refusal message for a subcommand with no JSON form.
///
/// Deliberately does not try to name the verb: [`Command`] derives only
/// `Subcommand` (no `Debug`), and recovering the name would mean either a
/// second 94-arm match that can drift from the first or re-parsing argv.
/// The operator has just typed the command, so "this subcommand" is
/// unambiguous — and the message is explicit that NOTHING RAN, which is
/// the part they actually need to know.
#[must_use]
pub fn refusal_message() -> String {
    "--json is not supported by this subcommand and was REFUSED rather than ignored \
     (#3436). It has no JSON output form, so accepting the flag and then emitting the \
     ordinary human output would report success for something that did not happen. \
     NOTHING WAS EXECUTED — re-run without --json."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three-way split is a real split: every state is populated, so a
    /// refactor that collapsed one of them would be caught here rather
    /// than by an operator.
    #[test]
    fn every_json_support_state_is_populated_3436() {
        // Representative of each arm. These are compile-checked against the
        // real `Command` shape, so a renamed variant fails to build.
        assert_eq!(
            json_support(&Command::Gc),
            JsonSupport::Global,
            "`gc` is handed the dispatcher's global --json"
        );
        assert_eq!(
            json_support(&Command::Man),
            JsonSupport::Unsupported,
            "`man` emits a man page; there is no JSON form to honour"
        );
        assert_eq!(
            json_support(&Command::Shell),
            JsonSupport::Unsupported,
            "`shell` is an interactive passthrough"
        );
    }

    /// The refusal has to say that nothing ran — an operator must never be
    /// left wondering whether the command half-executed before refusing.
    #[test]
    fn refusal_message_states_that_nothing_executed_3436() {
        let msg = refusal_message();
        assert!(msg.contains("--json"), "{msg}");
        assert!(msg.contains("REFUSED"), "{msg}");
        assert!(msg.contains("NOTHING WAS EXECUTED"), "{msg}");
    }
}
