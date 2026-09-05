// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Phase-1 pg-parity remediation (5-agent vote `4d3ea1c5`, Option B+) —
//! the CLAIMS-PARITY ANTI-REGRESSION GATE.
//!
//! ## Why this test exists
//!
//! The postgres surface gate (`postgres_endpoint_supported`,
//! `src/handlers/postgres_gate.rs`) is a HAND-MAINTAINED allow-list. A
//! route reaches a postgres-backed daemon's handler ONLY if it appears
//! there; everything else is shielded by a fail-closed 501 so an
//! un-migrated handler can never silently fall through to the empty
//! in-memory scratch SQLite `app.db` and read/write the WRONG database
//! (data corruption / loss, invisible to green CI).
//!
//! The v1.0 cert audit found the register's advertised pg-supported
//! count (56), the audit's count (73), and the SSOT total (94/80) all
//! disagreed — because a hand-maintained allow-list drifts silently
//! against the router. **That silent drift IS the omission class this
//! gate closes.** It converts every future edit to the allow-list (or
//! to the router) into a change this test flags, forcing an explicit,
//! reviewed update to the pinned inventory below — at which point a
//! reviewer must confirm the opened route's handler genuinely dispatches
//! to `app.store` (the pg SAL) and never `app.db.lock()`, per the
//! BINDING SAFETY INVARIANT.
//!
//! ## What it pins
//!
//! 1. **Source-level membership freeze** — the exact set of route-const
//!    and path-matcher names the allow-list references. A silent
//!    add/remove of a match arm fails here.
//! 2. **Runtime inventory + count** — over every registered production
//!    route, the authoritative pg-supported count and the exact
//!    fully-501 inventory. A route that gains/loses pg support fails
//!    here.
//! 3. **Structural subset** — every pg-supported (method, path) is a
//!    registered route (a supported-but-unregistered tuple would be a
//!    501-vs-404 wire-truthfulness violation).
//!
//! ## Companion control
//!
//! Freezing membership is HALF the control. The other half is the
//! per-opened-route PROOF-OF-DISPATCH integration test (drive the route
//! against a live pg daemon whose scratch sqlite is empty; assert a row
//! written via pg is returned — proving SAL dispatch, not a scratch
//! read). See `tests/serve_postgres_extended.rs` and the reflect /
//! reflection_origin / recall_observations proof tests. This gate makes
//! the inventory reviewable; those tests make each entry behaviourally
//! true.

// This gate's value is the prose: the doc comments ARE the reviewable,
// authoritative pg-supported inventory + the binding-safety rationale.
// Relax the doc-STYLE pedantic lints (identifier backticks / list
// indentation) here — the prose is intentional and human-facing. These
// allows sit BEFORE the `#![cfg]` so they still apply to the crate-level
// `//!` module docs on a non-sal build (e.g. the vectorlite CI leg),
// where `#![cfg(feature = "sal")]` empties the crate but the module docs
// are still linted.
#![allow(
    clippy::doc_markdown,
    clippy::doc_overindented_list_items,
    clippy::doc_lazy_continuation
)]
#![cfg(feature = "sal")]

use axum::http::Method;
use std::collections::BTreeSet;

use ai_memory::handlers::routes;
use ai_memory::handlers::{path_is_registered_route, postgres_endpoint_supported};

/// Every production `/api/v1` URL-path const, referenced by name so a
/// renamed/removed const breaks compilation here (router SSOT binding).
/// This IS the 80-unique-path inventory the CLAUDE.md architecture note
/// pins; keep it in lockstep with `src/handlers/routes.rs`.
fn all_registered_paths() -> Vec<&'static str> {
    vec![
        routes::ACTIONS_ID_TRANSITION,
        // v1.0.0 #2402 — the operator quarantine route-OUT pair.
        routes::ADMIN_QUARANTINE,
        routes::ADMIN_QUARANTINE_ID_RELEASE,
        routes::AGENTS,
        routes::AGENTS_ID_PUBKEY,
        // v1.0.0 #3464 — the proof-of-possession bind challenge.
        routes::AGENTS_ID_PUBKEY_CHALLENGE,
        routes::APPROVALS_PENDING_ID,
        routes::APPROVALS_STREAM,
        routes::ARCHIVE,
        routes::ARCHIVE_ID_RESTORE,
        routes::ARCHIVE_STATS,
        routes::AUTO_TAG,
        routes::CAPABILITIES,
        routes::CAPTURE_TURN,
        routes::CHECK_DUPLICATE,
        routes::CHECKPOINTS_ID_RESOLVE,
        routes::CONSOLIDATE,
        routes::CONTRADICTIONS,
        routes::ENTITIES,
        routes::ENTITIES_BY_ALIAS,
        routes::EXPAND_QUERY,
        routes::EXPORT,
        routes::FIND_PATHS,
        routes::FORGET,
        routes::GC,
        routes::HEALTH,
        routes::IMPORT,
        routes::INBOX,
        // v1.0.0 #3465 — agent-facing inbox wake SSE stream.
        routes::INBOX_STREAM,
        routes::KG_FIND_PATHS,
        routes::KG_INVALIDATE,
        routes::KG_QUERY,
        routes::KG_TIMELINE,
        routes::LINKS,
        routes::LINKS_ID,
        routes::LINKS_VERIFY,
        routes::MEMORIES,
        routes::MEMORIES_BULK,
        routes::MEMORIES_ID,
        routes::MEMORIES_ID_LINEAGE,
        routes::MEMORIES_ID_PROMOTE,
        routes::MEMORY_ATOMISE,
        routes::MEMORY_CALIBRATE_CONFIDENCE,
        routes::MEMORY_CHECK_AGENT_ACTION,
        routes::MEMORY_DEPENDENTS_OF_INVALIDATED,
        routes::MEMORY_EXPORT_REFLECTION,
        routes::MEMORY_LOAD_FAMILY,
        routes::MEMORY_RECALL_OBSERVATIONS,
        routes::MEMORY_REFLECT,
        routes::MEMORY_REFLECTION_ORIGIN,
        routes::MEMORY_REPLAY,
        routes::MEMORY_RULE_LIST,
        routes::MEMORY_SMART_LOAD,
        routes::MEMORY_SUBSCRIPTION_DLQ_LIST,
        routes::MEMORY_SUBSCRIPTION_REPLAY,
        routes::MEMORY_VERIFY,
        routes::METRICS,
        routes::METRICS_BARE,
        routes::NAMESPACES,
        routes::NAMESPACES_NS_STANDARD,
        routes::NOTIFY,
        routes::PENDING,
        routes::PENDING_ID_APPROVE,
        routes::PENDING_ID_REJECT,
        routes::QUOTA_STATUS,
        routes::RECALL,
        routes::SEARCH,
        routes::SESSION_START,
        routes::SHARE,
        routes::SIGNALS,
        routes::SKILL_ID,
        routes::SKILL_ID_COMPOSE,
        routes::SKILL_ID_EXPORT,
        routes::SKILL_ID_PROMOTE,
        routes::SKILL_ID_RESOURCE,
        routes::SKILL_ID_RETIRE,
        routes::SKILL_LIST,
        routes::SKILL_REGISTER,
        routes::STATS,
        routes::SUBSCRIPTIONS,
        routes::SYNC_PUSH,
        routes::SYNC_SINCE,
        routes::TAXONOMY,
        routes::TOOLS_LIST,
    ]
}

const METHODS: [Method; 4] = [Method::GET, Method::POST, Method::PUT, Method::DELETE];

/// The AUTHORITATIVE pg-supported inventory (2026-08-09, Phase-1 vote
/// `4d3ea1c5`): of the 82 unique production URL paths, exactly these 18
/// are FULLY fail-closed (no HTTP method reaches a postgres-backed
/// handler). Each is honest-v1.x-rescoped OR verified app.db-bound /
/// SAL-less:
///   - 8 skill routes — no pg skills table (`migrate_v82` no-op).
///   - `/api/v1/find_paths` — bare alias; operators use `/api/v1/kg/find_paths`.
///   - `/api/v1/share` — openable via SAL get+store, but the pg source-read
///     CallerContext is a T3 authz posture choice (deferred to a vote).
///   - route_1111 family that is verified app.db-bound (calls `app.db.lock()`
///     with no pg branch) or has NO SAL trait method:
///       memory_atomise, memory_calibrate_confidence, memory_smart_load,
///       memory_subscription_replay,
///       memory_subscription_dlq_list  (do-not-touch honest-v1.x set);
///       memory_rule_list + memory_check_agent_action (postgres ships NO
///         `governance_rules` table — a ~300+ LOC new-table gap the vote
///         explicitly refused to rush into the cert window).
/// 2026-08-29 (#3064): `memory_verify` LEFT this set — SAL
/// `verify_link` + `signed_at` on `VerifyLinkReport`.
/// 2026-08-29 (#3064 batch B): `memory_dependents_of_invalidated` LEFT
/// this set — SAL `list_dependents_of_invalidated` + `lineage_descendants`.
/// 2026-08-29 (#3064 batch C): `memory_export_reflection` LEFT this set —
/// SAL `get` + `list_outbound_reflects_on`.
/// 2026-08-29 (#3064 batch D): `memory_replay` LEFT this set —
/// SAL `replay_transcript_union` + `fetch_transcript_content`
/// (pg `memory_transcripts` / `memory_transcript_links` v22/v24).
/// 2026-09-05 (#3064 lane L-PGP family F1): `/api/v1/find_paths` LEFT
/// this set. It is a bare ALIAS: `src/lib.rs` routes it to the SAME
/// handler as the already-pg-supported `/api/v1/kg/find_paths`
/// (`handlers::kg_find_paths`, SAL `MemoryStore::find_paths`), so the
/// 501 was an allow-list omission, not a missing SAL method.
/// Opening ANY of these requires proving SAL dispatch first (see the
/// module doc) and updating this list with justification.
fn expected_fully_501_paths() -> BTreeSet<&'static str> {
    [
        routes::SHARE,
        routes::MEMORY_ATOMISE,
        routes::MEMORY_CALIBRATE_CONFIDENCE,
        routes::MEMORY_CHECK_AGENT_ACTION,
        routes::MEMORY_RULE_LIST,
        routes::MEMORY_SMART_LOAD,
        routes::MEMORY_SUBSCRIPTION_DLQ_LIST,
        routes::MEMORY_SUBSCRIPTION_REPLAY,
        routes::SKILL_ID,
        routes::SKILL_ID_COMPOSE,
        routes::SKILL_ID_EXPORT,
        routes::SKILL_ID_PROMOTE,
        routes::SKILL_ID_RESOURCE,
        routes::SKILL_ID_RETIRE,
        routes::SKILL_LIST,
        routes::SKILL_REGISTER,
    ]
    .into_iter()
    .collect()
}

/// Authoritative counts pinned 2026-08-09 (Phase-1). Bump in lockstep
/// with a dated justification when the allow-list legitimately changes.
// 2026-08-22 (#2402) — bumped 59 -> 61 pg-supported / 80 -> 82 total: the two
// operator quarantine route-OUT paths (`GET /api/v1/admin/quarantine`,
// `POST /api/v1/admin/quarantine/{id}/release`). Both are pg-SUPPORTED and the
// BINDING SAFETY INVARIANT is met by construction: each handler takes the
// `StorageBackend::Postgres` branch and dispatches to `app.store`
// (`MemoryStore::list_quarantined` / `operator_dequarantine`, both implemented
// by `PostgresStore`), never `app.db.lock()`. Proof-of-dispatch:
// `tests/quarantine_operator_surface_2402.rs::
// postgres_operator_quarantine_surface_parity_2402` drives both verbs against a
// live postgres and asserts the row AND its `memory.dequarantined` signed-chain
// audit row land on that backend. The fully-501 inventory is unchanged.
// 2026-08-29 (#3064) — bumped 61 -> 62 pg-supported / 21 -> 20 fully-501:
// `POST /api/v1/memory_verify` now SAL-dispatches to `MemoryStore::verify_link`
// (PostgresStore impl already existed). MCP `signed_at` is
// `VerifyLinkReport::signed_at` (link valid_from). Never `app.db.lock()`.
// 2026-08-29 (#3064 batch B) — bumped 62 -> 63 / 20 -> 19:
// `POST /api/v1/memory_dependents_of_invalidated` SAL-dispatches to
// `list_dependents_of_invalidated` (+ `lineage_descendants` when
// `transitive`). Never `app.db.lock()`.
// 2026-08-29 (#3064 batch C) — bumped 63 -> 64 / 19 -> 18:
// `POST /api/v1/memory_export_reflection` SAL-dispatches to `get` +
// `list_outbound_reflects_on`. Never `app.db.lock()`.
// 2026-08-29 (#3064 batch D) — bumped 64 -> 65 / 18 -> 17:
// `POST /api/v1/memory_replay` SAL-dispatches to
// `replay_transcript_union` + `fetch_transcript_content`. Never
// `app.db.lock()`.
// v1.0.0 #3464 — +1: `/api/v1/agents/{id}/pubkey/challenge`, the
// proof-of-possession bind challenge. Storage-free (it mints a nonce into the
// in-process challenge store), so there is no `app.db` scratch-read hazard;
// refusing it on postgres would make key enrollment unreachable on that
// backend.
// 2026-09-05 (#3465) — bumped 66 -> 67 / 83 -> 84 (501 count unchanged):
// `GET /api/v1/inbox/stream` is a NEW route AND pg-supported. It is
// backend-blind: it reads NOTHING from either store — it fans out the
// in-process `inbox_wake` broadcast bus, which BOTH SAL adapters
// publish to from their `notify` impl. Never `app.db.lock()`, never
// `app.store` either.
// 2026-09-05 (#3064 lane L-PGP family F1) — bumped 66 -> 67 pg-supported /
// 17 -> 16 fully-501: `POST /api/v1/find_paths`. The BINDING SAFETY INVARIANT
// is met by construction rather than by a new port — `src/lib.rs` wires this
// path and `routes::KG_FIND_PATHS` to the SAME `handlers::kg_find_paths`
// handler, which takes the `StorageBackend::Postgres` branch into
// `MemoryStore::find_paths` and never `app.db.lock()`. The alias was refused
// only because it was absent from `postgres_endpoint_supported`, which made a
// postgres daemon 501 a route whose supported twin it already serves.
// Proof-of-dispatch: `tests/pg_parity_3064.rs::
// f1_find_paths_alias_matches_kg_find_paths_on_both_backends`.
const EXPECTED_PG_SUPPORTED_UNIQUE_PATHS: usize = 68;
const EXPECTED_FULLY_501_PATHS: usize = 16;
const EXPECTED_TOTAL_UNIQUE_PATHS: usize = 84;

/// Source-level membership freeze: the exact route-const + path-matcher
/// names the allow-list body references. A silent match-arm add/remove
/// (the drift class that produced the audit's count disagreement) fails
/// here until this SSOT is updated — forcing a reviewed edit.
const EXPECTED_ALLOWLIST_CONSTS: &[&str] = &[
    // v1.0.0 #2402 — operator quarantine inspect (the release half is a
    // path-parameter route, frozen as a helper below).
    "ADMIN_QUARANTINE",
    "AGENTS",
    "APPROVALS_STREAM",
    "ARCHIVE",
    "ARCHIVE_STATS",
    "AUTO_TAG",
    "CAPABILITIES",
    "CAPTURE_TURN",
    "CHECK_DUPLICATE",
    "CONSOLIDATE",
    "CONTRADICTIONS",
    "ENTITIES",
    "ENTITIES_BY_ALIAS",
    "EXPAND_QUERY",
    "EXPORT",
    // #3064 family F1 — the bare `/api/v1/find_paths` alias (same handler as
    // the already-frozen `KG_FIND_PATHS`).
    "FIND_PATHS",
    "FORGET",
    "GC",
    "HEALTH",
    "IMPORT",
    "INBOX",
    // v1.0.0 #3465 — agent-facing inbox wake SSE stream.
    "INBOX_STREAM",
    "KG_FIND_PATHS",
    "KG_INVALIDATE",
    "KG_QUERY",
    "KG_TIMELINE",
    "LINKS",
    "LINKS_VERIFY",
    "MEMORIES",
    "MEMORIES_BULK",
    "MEMORY_DEPENDENTS_OF_INVALIDATED",
    "MEMORY_EXPORT_REFLECTION",
    "MEMORY_LOAD_FAMILY",
    "MEMORY_RECALL_OBSERVATIONS",
    "MEMORY_REFLECT",
    "MEMORY_REFLECTION_ORIGIN",
    "MEMORY_REPLAY",
    "MEMORY_VERIFY",
    "METRICS",
    "METRICS_BARE",
    "NAMESPACES",
    "NOTIFY",
    "PENDING",
    "QUOTA_STATUS",
    "RECALL",
    "SEARCH",
    "SESSION_START",
    "SIGNALS",
    "STATS",
    "SUBSCRIPTIONS",
    "SYNC_PUSH",
    "SYNC_SINCE",
    "TAXONOMY",
    "TOOLS_LIST",
];

const EXPECTED_ALLOWLIST_HELPERS: &[&str] = &[
    "actions_transition_path",
    // v1.0.0 #2402 — /api/v1/admin/quarantine/{id}/release
    "admin_quarantine_release_path",
    "agents_pubkey_challenge_path",
    "agents_pubkey_path",
    "approvals_decide_path",
    "archive_restore_path",
    "checkpoints_resolve_path",
    "links_id_path",
    "memory_id_path",
    "memory_lineage_path",
    "memory_promote_path",
    "namespace_standard_delete_path",
    "namespace_standard_post_path",
    "pending_decide_path",
];

/// Extract the body of `postgres_endpoint_supported` from the on-disk
/// source and return the sets of route-const + path-matcher names it
/// references.
fn allowlist_referenced_names() -> (BTreeSet<String>, BTreeSet<String>) {
    let src = include_str!("../src/handlers/postgres_gate.rs");
    let start = src
        .find("pub fn postgres_endpoint_supported")
        .expect("postgres_endpoint_supported present");
    // The fn body ends at the next top-level `\npub fn ` after the start.
    let rest = &src[start..];
    let end = rest[1..].find("\npub fn ").map_or(rest.len(), |i| i + 1);
    let body = &rest[..end];

    let mut consts = BTreeSet::new();
    let mut helpers = BTreeSet::new();
    // routes::CONST references.
    let bytes = body.as_bytes();
    let needle = b"routes::";
    let mut i = 0;
    while let Some(p) = find_sub(&bytes[i..], needle) {
        let s = i + p + needle.len();
        let mut e = s;
        while e < bytes.len() && (bytes[e].is_ascii_alphanumeric() || bytes[e] == b'_') {
            e += 1;
        }
        if e > s {
            consts.insert(body[s..e].to_string());
        }
        i = e;
    }
    // `foo_path(` matcher references.
    for (idx, _) in body.match_indices("_path(") {
        // walk backwards to the start of the identifier
        let mut s = idx;
        while s > 0 {
            let c = bytes[s - 1];
            if c.is_ascii_alphanumeric() || c == b'_' {
                s -= 1;
            } else {
                break;
            }
        }
        let ident = &body[s..idx + "_path".len()];
        // Only accept a plain call (identifier immediately followed by
        // "_path("); exclude any `::`-qualified path helper (there are
        // none, but be defensive).
        if !ident.is_empty() && ident.ends_with("_path") {
            helpers.insert(ident.to_string());
        }
    }
    (consts, helpers)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn allowlist_membership_is_frozen_at_source() {
    let (consts, helpers) = allowlist_referenced_names();
    let expected_consts: BTreeSet<String> = EXPECTED_ALLOWLIST_CONSTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let expected_helpers: BTreeSet<String> = EXPECTED_ALLOWLIST_HELPERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    assert_eq!(
        consts,
        expected_consts,
        "postgres_endpoint_supported allow-list route-const membership drifted.\n\
         The hand-maintained gate lagging the router IS the omission class that \
         produced the v1.0 pg-parity 501s. If you INTENTIONALLY opened/closed a \
         route, update EXPECTED_ALLOWLIST_CONSTS + the pinned counts below WITH a \
         dated justification, and prove the opened handler dispatches to app.store \
         (never app.db.lock()) via a proof-of-dispatch test.\n\
         added-in-source: {:?}\nremoved-from-source: {:?}",
        consts.difference(&expected_consts).collect::<Vec<_>>(),
        expected_consts.difference(&consts).collect::<Vec<_>>(),
    );
    assert_eq!(
        helpers,
        expected_helpers,
        "postgres_endpoint_supported path-matcher membership drifted; \
         see the message above.\nadded: {:?}\nremoved: {:?}",
        helpers.difference(&expected_helpers).collect::<Vec<_>>(),
        expected_helpers.difference(&helpers).collect::<Vec<_>>(),
    );
}

#[test]
fn pg_supported_inventory_and_counts_are_pinned() {
    let paths = all_registered_paths();
    assert_eq!(
        paths.len(),
        EXPECTED_TOTAL_UNIQUE_PATHS,
        "unique production path count drifted from the routes.rs SSOT"
    );

    let mut supported_paths: BTreeSet<&'static str> = BTreeSet::new();
    let mut fully_501: BTreeSet<&'static str> = BTreeSet::new();

    for &path in &paths {
        let any_supported = METHODS.iter().any(|m| postgres_endpoint_supported(m, path));
        // Structural subset: a pg-supported PATH must be a registered route
        // (under some method), else the gate would fabricate a 501 for an
        // unrouted path — a 404-vs-501 wire-truthfulness violation (#1410).
        // Checked at the PATH level because the metadata early-returns
        // (health/capabilities/metrics) are intentionally method-agnostic
        // while only their GET form is registered.
        if any_supported {
            assert!(
                METHODS.iter().any(|m| path_is_registered_route(m, path)),
                "{path} is pg-supported but is NOT a registered route under any \
                 method (postgres_endpoint_supported / path_is_registered_route drift)"
            );
            supported_paths.insert(path);
        } else {
            fully_501.insert(path);
        }
    }

    assert_eq!(
        fully_501,
        expected_fully_501_paths(),
        "the fully-501 (not pg-supported) path inventory drifted.\n\
         unexpectedly-501: {:?}\nunexpectedly-supported: {:?}\n\
         Update expected_fully_501_paths() + the counts WITH justification, and \
         prove SAL dispatch for any newly-opened route.",
        fully_501
            .difference(&expected_fully_501_paths())
            .collect::<Vec<_>>(),
        expected_fully_501_paths()
            .difference(&fully_501)
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        fully_501.len(),
        EXPECTED_FULLY_501_PATHS,
        "fully-501 path count drifted"
    );
    assert_eq!(
        supported_paths.len(),
        EXPECTED_PG_SUPPORTED_UNIQUE_PATHS,
        "pg-supported unique-path count drifted"
    );
    assert_eq!(
        supported_paths.len() + fully_501.len(),
        EXPECTED_TOTAL_UNIQUE_PATHS,
        "supported + fully-501 must partition the full path set"
    );
}

/// The route_1111 routes that ARE pg-supported (SAL-backed with a
/// verified `StorageBackend::Postgres` branch dispatching to
/// `app.store.{reflect,get_reflection_origin,list_recall_observations,verify_link}`)
/// must stay supported — a regression that dropped them would silently
/// 501 a working pg surface.
#[test]
fn already_open_sal_route_1111_routes_stay_supported() {
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_REFLECT
    ));
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_REFLECTION_ORIGIN
    ));
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_RECALL_OBSERVATIONS
    ));
    // #3064 — memory_verify now SAL-dispatches on postgres.
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_VERIFY
    ));
    // #3064 batch B — dependents now SAL-dispatches on postgres.
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_DEPENDENTS_OF_INVALIDATED
    ));
    // #3064 batch C — export_reflection now SAL-dispatches on postgres.
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_EXPORT_REFLECTION
    ));
    // #3064 batch D — replay now SAL-dispatches on postgres.
    assert!(postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_REPLAY
    ));
    // Conversely, the verified app.db-bound / SAL-less siblings must stay
    // fail-closed (opening them would convert a safe 501 into a silent
    // scratch-sqlite read/write on a pg daemon).
    assert!(!postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_RULE_LIST
    ));
    assert!(!postgres_endpoint_supported(
        &Method::POST,
        routes::MEMORY_CHECK_AGENT_ACTION
    ));
    assert!(!postgres_endpoint_supported(&Method::POST, routes::SHARE));
}
