// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! CLI command modules. Wave 5a (v0.6.3) extracted these out of
//! `main.rs` so each handler can be unit-tested by capturing output
//! into a `Vec<u8>` via `CliOutput` instead of literal `println!`s.
//!
//! ## Public surface
//!
//! - `CliOutput` (re-exported at `cli::CliOutput`): output abstraction.
//! - `helpers::{id_short, auto_namespace, human_age}`: pure helpers.
//! - `store::run`, `update::run`, `io::{export, import, mine}`:
//!   handler entry points called by `main.rs`'s dispatch arm.
//!
//! Each handler takes `&mut CliOutput<'_>` and routes every emit
//! through `writeln!` so tests can assert on captured bytes.

pub mod agents;
pub mod archive;
pub mod audit;
pub mod backup;
pub mod boot;
/// v0.9.0 G10.1 (#1827) — macaroon capability-token lifecycle
/// (`keygen` / `mint` / `attenuate` / `inspect` / `verify`).
pub mod capability;
/// v0.7.0 QW-1 — new-format CLI command modules (return exit codes
/// rather than calling `process::exit`).
pub mod commands;
pub mod consolidate;
pub mod crud;
pub mod curator;
pub mod doctor;
pub mod epoch_apply;
/// v0.7.0 L2-5 (issue #670) — `ai-memory export-forensic-bundle` and
/// `ai-memory verify-forensic-bundle` subcommands.
pub mod export;
pub mod forget;
pub mod gc;
pub mod governance;
/// v0.7.0 issue #863 — `ai-memory governance check-action` subcommand.
/// Shell-side parity for the MCP tool `memory_check_agent_action` so
/// operators can dry-run a substrate rule from a terminal without
/// driving JSON-RPC over stdio.
pub mod governance_check_action;
/// v0.7.0 7th-form (issue #760) — `ai-memory governance install-defaults`
/// subcommand. Bulk-flip seed rules R001-R004 to `enabled = 1` after
/// operator confirmation (interactive prompt; `--yes` overrides).
pub mod governance_install_defaults;
pub mod governance_migrate;
pub mod helpers;
pub mod identity;
pub mod install;
pub mod io;
pub mod io_writer;
pub mod link;
pub mod logs;
pub mod model_attest;
/// v0.7.0 (issue #800) — `ai-memory namespace` subcommand. CRUD over
/// the per-namespace standard policy memory pointer. Closes Crack 1
/// from the Batman Mode acceptance review by giving operators a
/// first-class CLI verb instead of forcing them into an MCP-stdio
/// JSON-RPC dance just to bind a `GovernancePolicy` to a namespace.
pub mod namespace;
/// v0.7.0 QW-3 — `ai-memory offload` / `ai-memory deref` subcommands.
/// Substrate-only wrappers over `crate::offload::ContextOffloader`.
pub mod offload;
/// v1.0.0 #3402 — the CLI store surface's post-insert namespace-policy
/// wiring. Makes `ai-memory store` a caller of the ONE shared
/// auto-atomisation funnel the MCP twin uses, instead of a parallel path
/// that silently dropped the atomisation half of a namespace standard.
pub mod post_store;
pub mod promote;
/// v1.0.0 #2402 — `ai-memory quarantine list | release <id>`: the operator
/// route OUT of the #1948 federation quarantine, which #1948 advertised and
/// shipped with no caller. `list` is read-only and projects identifying
/// metadata only; `release` appends a `memory.dequarantined` signed audit row
/// in the same transaction as the state change.
pub mod quarantine;
pub mod recall;
/// v0.8.0 #1709/#1720 WS-B B2 — `ai-memory reown` subcommand. Rewrite
/// the `metadata.agent_id` ownership stamp on a namespace's memories
/// BEFORE enabling `scope=private` visibility filtering (avoids
/// operator self-lockout). Additive admin tool; no MCP/HTTP surface.
pub mod reown;
/// v0.7.0 (issue #691) — `ai-memory rules` subcommand. CRUD for the
/// substrate-level agent-action rules engine. Mutation verbs (add /
/// enable / disable / remove) require the operator keypair on disk.
pub mod rules;
#[cfg(feature = "sal")]
pub mod schema_init;
pub mod search;
pub mod serve_banner;
/// v0.7.0 #1095 — `ai-memory share` subcommand. Closes the SR-4
/// three-surface-parity gap by shipping the CLI counterpart to the
/// MCP tool `memory_share` and the HTTP route `POST /api/v1/share`.
/// All three surfaces dispatch through the same substrate primitive
/// (`crate::mcp::tools::share::handle_share`).
pub mod share;
pub mod shell;
pub mod stop;
pub mod store;
pub mod sync;
pub mod update;
pub mod verify;
pub mod verify_audit_trail;
pub mod verify_signed_events;
/// v1.0.0 #3467 (EPIC #3466) — `ai-memory wake-hub` subcommand. CLI surface
/// for the same-host, CONTENT-FREE agent wake plane
/// ([`crate::wake_hub`]). Opt-in: never runs unless explicitly invoked, holds
/// no durable truth, and exposes NO flag that could substitute a permissive
/// identity verifier.
pub mod wake_hub;
/// v1.0.0 #1978 — `ai-memory watch` subcommand. CLI surface for the L3
/// substrate poll-based filesystem-watcher capture daemon
/// (`crate::recover::watcher`). Opt-in; mirrors the `curator`
/// `--once` / `--daemon` split.
pub mod watch;
pub mod wrap;

#[cfg(test)]
pub mod test_utils;

// Convenience re-export so callers can `use ai_memory::cli::CliOutput`
// without a deeper path.
pub use io_writer::CliOutput;

/// Shared CLI JSON-report key naming the checkpoint a command persisted or
/// verified (`epoch-apply`, `audit re-anchor`). Named per the pm-v3.1
/// no-hardcoded-literals gate. DELIBERATELY DISTINCT from the frozen
/// `canonical_cbor_checkpoint_resolution` CBOR key in
/// [`crate::identity::sign`] — the signed-bytes wire format must never
/// couple to a CLI report key (renaming a report field must not be able to
/// break frozen signed bytes).
pub(crate) const JSON_KEY_CHECKPOINT_ID: &str = "checkpoint_id";
