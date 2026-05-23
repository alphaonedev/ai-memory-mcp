// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP handler module index. Per-domain handler code lives in the
//! sibling sub-modules; this file is the public-facing re-export
//! surface plus the inline test scaffolding.
//!
//! Issue #650 history: the original `src/handlers.rs` was an 18 574-line
//! monolith. The first split (commit `7f3f676`) carved off
//! `federation_receive`, `hook_subscribers`, `http`, and `transport`.
//! The follow-up split (2026-05-18) closed the remaining ≤1200 LOC cap
//! by extracting per-domain modules for the four still-oversize files
//! (`http`, `transport`, `federation_receive`, `hook_subscribers`,
//! `power`) into focused siblings.
//!
//! Sub-modules:
//!
//! - [`transport`]   — `AppState`, `Db`, `JsonOrBadRequest`, auth
//!   middleware, shared constants (`MAX_BULK_SIZE`,
//!   `BULK_FANOUT_CONCURRENCY`), low-level helpers, health, metrics.
//! - [`postgres_gate`] — `#[cfg(feature = "sal")]` postgres
//!   route-matrix + middleware + `store_err_to_response` sanitiser.
//! - [`http`]        — `maybe_auto_tag` + `maybe_detect_conflicts` +
//!   `ConflictReport` (the LLM hooks the create path consumes).
//! - [`create`]      — `POST /api/v1/memories` create-path orchestrator
//!   + six stage helpers + postgres branch.
//! - [`memories`]    — memory CRUD (`get`/`update`/`delete`/`promote`).
//! - [`memories_query`] — list / search / forget / bulk_create.
//! - [`federation_receive`] — federation receive-side `sync_push` body +
//!   helpers (clock skew, quota attribution, peer-id extraction).
//! - [`federation_signing_check`] — `#[cfg(feature = "sal")]`
//!   `sync_push_via_store` postgres-receive branch + per-message
//!   Ed25519 signature verification (#791).
//! - [`federation_sync_since`] — federation `/sync/since` GET pull.
//! - [`hook_subscribers`]   — inbox + namespace standard handlers +
//!   session-start.
//! - [`subscriptions`] — notify + subscribe + unsubscribe +
//!   list_subscriptions.
//! - [`power`]       — taxonomy / contradictions / list_namespaces /
//!   check_duplicate (non-LLM power-tier reads).
//! - [`power_consolidation`] — consolidate + auto_tag + expand_query +
//!   load_family (LLM-backed power-tier writes).
//! - [`errors`]      — issue #851 HTTP error-sanitization helpers.
//! - [`system`]      — `/api/v1/capabilities` and system reads.
//! - [`parity`]      — cross-cutting HTTP-parity helpers.
//! - [`approvals`]   — v0.7.0 K10 approval API.

pub mod accept_provenance;
pub mod admin;
pub mod admin_role;
pub mod approvals;
pub mod archive;
pub mod create;
pub mod errors;
pub mod federation_receive;
pub mod federation_signing_check;
pub mod federation_sync_since;
pub mod governance;
pub mod hook_subscribers;
pub mod http;
pub mod kg;
pub mod links;
pub mod memories;
pub mod memories_query;
pub mod parity;
pub mod postgres_gate;
pub mod power;
pub mod power_consolidation;
pub mod recall;
/// v0.7.0 #1111 — 14 missing HTTP routes for the MCP-only tools the
/// SR-4 three-surface-parity audit flagged. Each handler is a thin
/// wrapper around the existing `crate::mcp::handle_<name>` substrate
/// primitive; wire envelopes are byte-equal across the two surfaces.
pub mod route_1111;
pub mod share;
pub mod skills;
pub mod subscriptions;
pub mod system;
pub mod transport;

// Re-export the public-facing handler surface so external callers
// (router wiring in `src/lib.rs`, integration tests) can still
// reference `handlers::<name>` without knowing which sub-module the
// item came from. Wire compatibility is preserved verbatim.
pub use admin::*;
pub use admin_role::*;
pub use approvals::*;
pub use archive::*;
pub use create::*;
pub use errors::*;
pub use federation_receive::*;
pub use federation_sync_since::*;
pub use governance::*;
pub use hook_subscribers::*;
pub use http::*;
pub use kg::*;
pub use links::*;
pub use memories::*;
pub use memories_query::*;
pub(crate) use parity::*;
#[cfg(feature = "sal")]
pub use postgres_gate::*;
pub use power::*;
pub use power_consolidation::*;
pub use recall::*;
pub use route_1111::*;
pub use share::*;
pub use skills::*;
pub use subscriptions::*;
pub use system::*;
pub use transport::*;

// Inline test scaffold (`#[cfg(test)] mod tests`) preserved verbatim
// from the pre-split mod.rs body. Tracked for future per-domain
// decomposition into `tests/handlers_<domain>.rs` integration test
// crates; the move-out is gated on exposing a stable `AppState`
// constructor helper from production code so tests outside the crate
// can build it without re-inventing fixture wiring (see #650 follow-up).
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
