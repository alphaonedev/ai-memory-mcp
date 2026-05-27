// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-1 — new-format CLI command modules.
//!
//! Modules under this directory follow the `pub fn run(db, args,
//! out) -> Result<i32>` shape that returns an exit code (rather than
//! exiting the process from inside the handler). The convention
//! matches `src/cli/export.rs` (forensic bundle) so the dispatch arm
//! in `daemon_runtime::run` stays a one-liner.

/// v0.7.0 WT-1-F — `ai-memory atomise` CLI subcommand.
pub mod atomise;
/// v0.7.x (#1146) — `ai-memory config <subcommand>` CLI surface.
pub mod config;
pub mod export_reflections;
// v0.7.0 QW-2 — Persona-as-artifact CLI surface. `ai-memory persona
// <entity_id> [--namespace NS] [--regenerate] [--json]`.
pub mod persona;
// v0.7.0 Form 5 (issue #758) — `ai-memory calibrate confidence
// --from-shadow [--days N] [--output-format json|table]`. Reads
// `confidence_shadow_observations` and emits per-(namespace, source)
// baselines.
pub mod calibrate_confidence;
// v0.7.0 Cluster E API-2 (issue #767) — `ai-memory skill <subcommand>`
// CLI parity for the 7 L1-5 Agent Skills MCP tools. Each subcommand
// dispatches into the same substrate handler the MCP `tools/call`
// dispatch uses, so no new business logic lands here.
pub mod skill;
// v0.7.0 ARCH-3 / FX-12 — CLI parity build-out for MCP tools without
// a direct CLI subcommand counterpart. Each new module dispatches into
// the same substrate primitive the MCP tool consumes, guaranteeing
// wire envelope parity across MCP / HTTP / CLI. See
// `docs/v0.7.0/arch-3-mcp-cli-parity-audit.md` for the full audit.
pub mod check_duplicate;
pub mod find_paths;
pub mod kg_query;
pub mod recall_observations;
pub mod replay;
// v0.7.0 ARCH-3 / FX-C3 (batch2) — closing the 16 remaining
// applicable deferrals from the FX-12 audit. Each module wires a
// thin clap arg-parser + output formatter that dispatches into the
// same substrate primitive the MCP tool consumes. Wire envelope is
// byte-equal across MCP / HTTP / CLI. See
// `docs/v0.7.0/arch-3-mcp-cli-parity-audit.md` for the marked-off
// audit rows.
pub mod dependents_of_invalidated;
pub mod entity_get_by_alias;
pub mod entity_register;
pub mod inbox;
pub mod ingest_multistep;
pub mod kg_invalidate;
pub mod kg_timeline;
pub mod list_subscriptions;
pub mod notify;
pub mod quota_status;
pub mod reflect;
pub mod reflection_origin;
pub mod subscribe;
pub mod subscription_dlq_list;
pub mod subscription_replay;
pub mod unsubscribe;
