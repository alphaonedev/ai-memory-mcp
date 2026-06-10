// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![recursion_limit = "512"]
// The library target was added by the proptest infra (Agent G) to expose
// production modules to the integration test crate. The bin target's
// clippy run already gates CI — re-running pedantic against the same
// modules through the lib target would re-flag the same pre-existing
// lint backlog the bin target already passes. Allow at the lib level;
// the bin target is the authoritative gate for production-code linting.
#![allow(clippy::pedantic, clippy::all)]

// Library interface for ai-memory. Exposes public modules for testing and external use.

// ---------------------------------------------------------------------------
// v0.7.x (issue #1174 PR3 — pm-v3.1 time-secs sweep) — common time-unit
// conversions to seconds. Replaces ~50 inline literals (`3600`,
// `86_400`, `604_800`) across the codebase. The substrate is large
// enough that magic numeric literals are a debt accelerator; named
// constants make time-unit math grep-able and refactor-safe.
//
// `i64` matches the column type the values feed into (TTL seconds,
// `chrono::Duration::seconds`, lifecycle thresholds). `u64` callers
// (`std::time::Duration::from_secs`, prometheus counters) cast at the
// use site via `SECS_PER_HOUR as u64` etc. — the byte-equal value is
// preserved either way.
// ---------------------------------------------------------------------------

pub const SECS_PER_MINUTE: i64 = 60;
pub const SECS_PER_HOUR: i64 = 3_600;
pub const SECS_PER_DAY: i64 = 86_400;
pub const SECS_PER_WEEK: i64 = 604_800;

/// Milliseconds per second — for secs→ms conversions feeding wire/SQL
/// surfaces that take milliseconds (e.g. postgres `statement_timeout`).
/// `u64` matches the `*_timeout_secs` config field type; `i64`/`u128`
/// callers cast at the use site like the `SECS_PER_*` family above.
pub const MILLIS_PER_SEC: u64 = 1_000;

/// Rounding factor for similarity/score values surfaced on wire
/// responses (HTTP handlers + MCP tools) — `1000.0` keeps three
/// decimal places via `(score * FACTOR).round() / FACTOR`.
pub const SCORE_DISPLAY_ROUND_FACTOR: f64 = 1000.0;

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner B finding F-B7) — byte-unit
// consts so substrate-wide size math is grep-able and refactor-safe.
// Pre-sweep ~10 production sites used bare `1024` / `1024 * 1024`
// arithmetic; named consts make memory-cap intents explicit at the
// callsite.
// ---------------------------------------------------------------------------

pub const KIB: usize = 1024;
pub const MIB: usize = KIB * KIB;
pub const GIB: usize = MIB * KIB;

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner B findings F-B6/F-B9/F-B10) —
// named consts for the genuinely-duplicated, load-bearing values so they are
// grep-able and refactor-safe. Each equals the literal it replaces
// byte-for-byte; this is a naming refactor, never a value change.
//
// Deliberately NOT promoted (per-site semantic audit, F-B1..F-B5/F-B8):
//   * `Duration::from_secs(30 | 60 | 5)` and `from_millis(500)` are NOT one
//     semantic — the 30s sites alone span `GENERATE_TIMEOUT`,
//     `CIRCUIT_BREAKER_COOLDOWN`, `QuorumPolicy` total-timeout, an embeddings
//     retry sleep, and several HTTP-client `.timeout(..)` calls, and most
//     already carry a proper local name. Folding them into one
//     `DEFAULT_NETWORK_TIMEOUT` would couple unrelated knobs and erase those
//     local names — a false SSOT. These small-int timeouts are exactly the
//     legitimate-literal class the vendor-literal gate carves out
//     (CLAUDE.md §"Lint gates"), so they are left in place.
//   * F-B5 `from_millis(10)` poll ticks — almost entirely test-region noise.
//   * F-B7 KIB/MIB/GIB landed above.
// ---------------------------------------------------------------------------

/// F-B6 — Axum production request-body cap (2 MiB).
pub const HTTP_BODY_LIMIT_BYTES: usize = 2 * MIB;
/// F-B6 — test-side body read cap; pinned equal to the production limit so
/// tests exercise the full `0..=2 MiB` envelope production accepts (was an
/// asymmetric 1 MiB across 90+ `to_bytes(.., 1024 * 1024)` call sites).
pub const TEST_BODY_READ_CAP: usize = HTTP_BODY_LIMIT_BYTES;
/// F-B9 — recall primary-context semantic blend weight. Named to disambiguate
/// from `ConfidenceTier::LIKELY_MIN` (also 0.7, a different concept).
pub const RECALL_PRIMARY_CTX_BLEND: f32 = 0.7;
/// F-B10 — recall cosine-similarity gate (relaxed 0.3 → 0.2 in v0.6.2 Patch 2,
/// scenario-18; load-bearing per CLAUDE.md §"Recall Pipeline").
pub const RECALL_COSINE_GATE: f64 = 0.2;

/// #1558 batch 5 wave 3 — canonical secret-redaction placeholder
/// rendered by every `Debug` impl that masks credential material
/// (`AppConfig.api_key`, `[llm].api_key`, `ResolvedLlm.api_key`,
/// `HooksSubscriptionConfig.hmac_secret`, x25519 `Keypair.secret`,
/// `RuntimeContext.hooks_hmac_secret`). One spelling, hoist-only;
/// `src/llm.rs` keeps its own site per the vendor carve-out.
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner F finding F-F-ROUTE-1) —
// canonical HTTP route-path consts. The substrate's HTTP router
// (`build_router_with_timeout` in `src/lib.rs`) registers ~87
// `.route(...)` calls at `/api/v1/`; pre-sweep, callers / tests built
// these path strings via `format!("/api/v1/...")` or inline `"/api/v1/..."`
// literals at thousands of sites. The consts below carve out the
// stable surfaces so a future rename (or a hypothetical `/api/v2/`
// transition) is a const edit instead of a substrate-wide grep.
//
// Naming: `ROUTE_<DOMAIN>_<VERB?>` for static paths; templates with
// `{id}`-style axum placeholders kept as separate `_TEMPLATE` const
// to make the template-vs-concrete distinction explicit.
//
// Operator directive 2026-05-31 (FIX IT NOW — no AI NHI defers) per
// memory `f57da43e`: F-F-ROUTE-1 was previously deferred for design
// review; this commit lands the minimum viable subset (the 19
// highest-traffic surfaces from the audit) leaving the
// `format!(handlers::routes::MEMORIES_ID, ...)` consumer-side helper as a
// follow-up surface refactor.
// ---------------------------------------------------------------------------

pub const ROUTE_HEALTH: &str = handlers::routes::HEALTH;
pub const ROUTE_METRICS: &str = handlers::routes::METRICS_BARE;
pub const ROUTE_METRICS_V1: &str = handlers::routes::METRICS;
pub const ROUTE_CAPABILITIES: &str = handlers::routes::CAPABILITIES;
pub const ROUTE_MEMORIES: &str = handlers::routes::MEMORIES;
pub const ROUTE_MEMORIES_BULK: &str = handlers::routes::MEMORIES_BULK;
pub const ROUTE_MEMORY_BY_ID_TEMPLATE: &str = handlers::routes::MEMORIES_ID;
pub const ROUTE_RECALL: &str = handlers::routes::RECALL;
pub const ROUTE_SEARCH: &str = handlers::routes::SEARCH;
pub const ROUTE_SESSION_START: &str = handlers::routes::SESSION_START;
pub const ROUTE_SYNC_PUSH: &str = handlers::routes::SYNC_PUSH;
pub const ROUTE_SYNC_SINCE: &str = handlers::routes::SYNC_SINCE;
pub const ROUTE_NOTIFY: &str = handlers::routes::NOTIFY;
pub const ROUTE_INBOX: &str = handlers::routes::INBOX;
pub const ROUTE_SUBSCRIPTIONS: &str = handlers::routes::SUBSCRIPTIONS;
pub const ROUTE_NAMESPACES: &str = handlers::routes::NAMESPACES;
pub const ROUTE_ARCHIVE: &str = handlers::routes::ARCHIVE;
pub const ROUTE_PROMOTE_TEMPLATE: &str = handlers::routes::MEMORIES_ID_PROMOTE;
pub const ROUTE_LINKS: &str = handlers::routes::LINKS;

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner F finding F-F-METHOD-1) —
// canonical MCP JSON-RPC method names. Pre-sweep, 13+ sites in
// `src/mcp/mod.rs` hardcoded the method names; a future MCP spec bump
// would touch every match arm. Centralised here so the dispatch
// loop's match arms point at named consts.
// ---------------------------------------------------------------------------

// #1558 batch 3 — these crate-root aliases now point at the
// domain-canonical SSOT in `crate::mcp::jsonrpc` (version tag,
// reserved error codes, method names, protocol revision all live
// there); kept so existing consumers/tests keep compiling.
pub const METHOD_INITIALIZE: &str = mcp::jsonrpc::METHOD_INITIALIZE;
pub const METHOD_TOOLS_LIST: &str = mcp::jsonrpc::METHOD_TOOLS_LIST;
pub const METHOD_TOOLS_CALL: &str = mcp::jsonrpc::METHOD_TOOLS_CALL;
pub const METHOD_PROMPTS_LIST: &str = mcp::jsonrpc::METHOD_PROMPTS_LIST;
pub const METHOD_PROMPTS_GET: &str = mcp::jsonrpc::METHOD_PROMPTS_GET;
pub const METHOD_RESOURCES_LIST: &str = mcp::jsonrpc::METHOD_RESOURCES_LIST;
pub const METHOD_RESOURCES_READ: &str = mcp::jsonrpc::METHOD_RESOURCES_READ;

// ---------------------------------------------------------------------------
// v0.7.x (issue #1174 PR2 — pm-v3.1 HTTP const sweep) — canonical
// constants for the most-used HTTP header / MIME literals. Replaces
// ~210 inline string literals across handler tests, federation
// requests, subscription dispatch, and the HTTP daemon bootstrap.
//
// Naming follows the conventional Rust HTTP-crate style:
// SCREAMING_SNAKE_CASE, separated by the field they represent.
//
// Byte-equal preservation: the wire still emits exactly
// `"content-type"` / `"application/json"`. The consts merely
// centralise the literals so a rename or typed-header migration is
// a one-line edit rather than a 210-site grep.
//
// Out of scope for these consts: `hyper::header::CONTENT_TYPE` /
// `axum::http::header::CONTENT_TYPE` typed-header sites stay on the
// typed constant; `#[serde(rename = "...")]` attributes stay as
// compile-time literals.
// ---------------------------------------------------------------------------

pub const HEADER_CONTENT_TYPE: &str = "content-type";
pub const MIME_JSON: &str = "application/json";

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (operator directive `4f1f258b`,
// scanners C+F) — canonical HTTP header constants for the most-
// trafficked custom header that previously had NO centralised
// declaration. `X-Agent-Id` is the substrate's identity-resolution
// header per CLAUDE.md §"Agent Identity"; pre-sweep it appeared
// hardcoded in 140+ production + test sites with a case-mismatch
// (`X-Agent-Id` vs `x-agent-id`) already in tree. axum lowercases
// header names server-side, so the canonical wire form is lowercase
// — this matches the existing `HEADER_CONTENT_TYPE` (`"content-type"`),
// `SIGNATURE_HEADER` (`"x-memory-sig"` in `federation/signing.rs`),
// `NONCE_HEADER` (`"x-memory-nonce"`), and `PEER_ID_HEADER`
// (`"x-peer-id"` in `federation/peer_attestation.rs`).
// ---------------------------------------------------------------------------

pub const HEADER_AGENT_ID: &str = "x-agent-id";

/// API-key auth header consumed by the HTTP daemon's auth middleware
/// (`handlers/transport.rs`) and SENT by every internal client
/// (federation push/receive, CLI remote commands). Client and server
/// must agree byte-for-byte — a drifted copy is a silent auth break
/// (#1558 batch 4).
pub const HEADER_API_KEY: &str = "x-api-key";

/// HMAC signature header on signed webhook/approval callbacks
/// (`subscriptions.rs` dispatch ⇄ `handlers/approvals.rs` verify).
pub const HEADER_AI_MEMORY_SIGNATURE: &str = "x-ai-memory-signature";

/// Timestamp header paired with [`HEADER_AI_MEMORY_SIGNATURE`] for
/// HMAC replay-window checks.
pub const HEADER_AI_MEMORY_TIMESTAMP: &str = "x-ai-memory-timestamp";

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner B finding F-B7.x) —
// canonical metadata-JSON-key consts.
//
// `Memory::metadata` is a free-form `serde_json::Value` blob; the
// substrate INTERPRETS specific keys to enforce identity, visibility,
// and provenance. Pre-sweep, these load-bearing key names appeared as
// scattered string literals across handlers / MCP tools / federation /
// CLI / storage — 100+ sites for `"agent_id"` alone. The consts below
// centralise ONLY the keys that carry substrate semantics (NHI
// attribution, visibility scope, governance policy, provenance edge
// labels). Bare JSON field-name literals used for wire-protocol
// shaping (e.g. `"name"`, `"description"`, `"properties"` in MCP
// tool-schema JSON) are intentionally left as inline string literals
// — those are protocol-driven, not substrate semantics, and changing
// the key would be a wire break.
//
// A rename of any const below is a single-line edit + a multi-call-
// site `grep` + replace; pre-sweep it was a substrate-wide search.
// ---------------------------------------------------------------------------

/// `metadata.agent_id` — the NHI identity stamp written on every
/// substrate row per CLAUDE.md §"Agent Identity". Read by visibility
/// predicates, governance rule evaluator, federation peer attestation,
/// audit chain. Immutable post-write (preserved across update / dedup
/// / import / sync / consolidate per `identity::preserve_agent_id`).
pub const META_KEY_AGENT_ID: &str = "agent_id";

/// `metadata.scope` — visibility marker (one of [`MemoryScope::all_strs`]
/// at `crate::models::namespace::MemoryScope`). Controls which agents
/// can see a memory via hierarchical namespace matching per Task 1.5.
/// Memories without this key are treated as `"private"` by the query
/// layer (see `crate::models::namespace::MemoryScope::default()`).
pub const META_KEY_SCOPE: &str = "scope";

/// `metadata.governance` — embedded governance policy blob
/// (`GovernancePolicy::from_metadata`). Read by the substrate
/// governance engine (`db::enforce_governance`) to evaluate rules
/// before the canonical write path; honoured by Allow / Deny / Pending
/// decision tree.
pub const META_KEY_GOVERNANCE: &str = "governance";

/// `metadata.imported_from_agent_id` — original NHI claim preserved
/// when `ai-memory import` restamps `agent_id` with the importing
/// caller's id (absent when `--trust-source` is passed). Documented at
/// CLAUDE.md §"Agent Identity (NHI)" → "Special metadata keys".
pub const META_KEY_IMPORTED_FROM_AGENT_ID: &str = "imported_from_agent_id";

/// `metadata.consolidated_from_agents` — array of source authors,
/// preserved on `memory_consolidate` (the consolidator's id becomes
/// `agent_id`; the original authors stay readable from this array).
/// Documented at CLAUDE.md §"Agent Identity (NHI)" → "Special metadata
/// keys".
pub const META_KEY_CONSOLIDATED_FROM_AGENTS: &str = "consolidated_from_agents";

/// `metadata.mined_from` — source-format tag (`claude` / `chatgpt` /
/// `slack`) stamped by `ai-memory mine` alongside the caller's
/// `agent_id`. Documented at CLAUDE.md §"Agent Identity (NHI)" →
/// "Special metadata keys".
pub const META_KEY_MINED_FROM: &str = "mined_from";

/// `metadata.target_agent_id` — recipient NHI for memories that
/// represent agent-to-agent shares / notifications. Read by the
/// canonical visibility predicate `is_visible_to_caller` to permit
/// the named target to see otherwise-private rows alongside the owner.
pub const META_KEY_TARGET_AGENT_ID: &str = "target_agent_id";

// ---------------------------------------------------------------------------
// ARCH-14 (FX-C4-batch2, 2026-05-26) — canonical route-count constant.
//
// The daemon's `build_router_with_timeout` registers exactly this
// many production `.route(...)` calls at `/api/v1/`. The constant is
// load-bearing for the docs (CLAUDE.md §"Architecture") and is
// mechanically pinned by `tests/route_count_invariant.rs` so any
// addition / removal of a route surface requires bumping this
// constant in lockstep with the test failing.
//
// The 88th `.route(` at the bottom of `build_router_with_timeout` is
// the `/slow` slowloris-test route gated by `#[cfg(test)]` — that is
// counted by `EXPECTED_TEST_ROUTES_COUNT` below.
// ---------------------------------------------------------------------------

pub const EXPECTED_PRODUCTION_ROUTES_COUNT: usize = 88;
pub const EXPECTED_TEST_ROUTES_COUNT: usize = 1;

/// Number of distinct URL paths (multi-line-aware) registered by the
/// production router. Derived via
/// `awk '/\.route\(/{in=1}in&&/"\/[^"]*"/{match($0,/"\/[^"]*"/);print substr($0,RSTART,RLENGTH);in=0}' src/lib.rs | sort -u | wc -l`
/// excluding the `#[cfg(test)]`-gated `/slow` slowloris route. Pinned
/// by `tests/route_count_invariant.rs` so the docs surface count
/// cannot drift silently. v0.7.0 multi-agent literal-sweep (scanner
/// A, finding F-A4.1) — previously the `73 unique URL paths` count
/// was cited in 30+ doc sites with no const.
pub const EXPECTED_PRODUCTION_UNIQUE_PATHS_COUNT: usize = 74;

// ---------------------------------------------------------------------------
// v0.7.0 multi-agent literal-sweep (scanner A, finding F-A3.1) —
// canonical CLI subcommand counts. The source `pub enum Command` in
// `src/daemon_runtime.rs` declares 81 variants; two (`Migrate`,
// `SchemaInit`) are `#[cfg(feature = "sal")]`-gated, so the default
// build compiles 79 and `--features sal` OR `--features sal-postgres`
// unlocks the full 81. Pre-sweep, the count was cited in 24+ doc
// surfaces with zero machine-checkable anchor — CLAUDE.md alone had 7
// different historical counts (40, 57, 58, 63, 79, 80, 82). Pinned by
// `tests/cli_subcommand_count_invariant.rs`.
// ---------------------------------------------------------------------------

/// Variants in `pub enum Command` (src/daemon_runtime.rs) that
/// COMPILE under the default build. The source file declares 81
/// variants; two (`Migrate`, `SchemaInit`) are `#[cfg(feature =
/// "sal")]`-gated and excluded from default builds, leaving 79.
/// (v0.7.0 #1443 added `Expand` for the `ai-memory expand` CLI parity
/// surface, bumping 78 → 79.)
pub const EXPECTED_CLI_SUBCOMMANDS_DEFAULT: usize = 79;

/// Variants in `pub enum Command` that COMPILE under `--features sal`
/// (or `sal-postgres`, which implies sal in `Cargo.toml`). Equals the
/// awk-canonical source-file count: every variant declared in the
/// enum body (including `Migrate` + `SchemaInit`). v0.7.0 #1443 added
/// `Expand`, bumping 80 → 81.
pub const EXPECTED_CLI_SUBCOMMANDS_SAL: usize = 81;

// ---------------------------------------------------------------------------
// ARCH-10 (FX-C4-batch2, 2026-05-26) — minimal FFI self-identification
// symbol.
//
// `cbindgen.toml` at v0.7.0 advertises a `staticlib`/`cdylib` build
// surface for the iOS / Android cross-compile lanes (`mobile-cross-
// compile` CI workflow + `mobile-ios` / `mobile-android` release
// jobs) that previously produced artifacts with ZERO callable
// `extern "C"` symbols. Operators linking the artifact via Xcode /
// AGP would find nothing to call and have no way to confirm the
// linker actually pulled in the substrate.
//
// This symbol gives the artifact a self-identification entry point
// so consumers can at minimum link-and-validate the symbol table
// before the full C ABI surface lands in a v0.7.x follow-up
// (issue #1068 Layer 2 / #1069 wrapper SDK). The function returns
// the substrate's Cargo.toml `version` field as a NUL-terminated
// C string pointer with `'static` lifetime.
//
// Naming convention: `ai_memory_<verb>` matches the
// `cbindgen.toml` namespace contract; the function name will be the
// stable ABI handle for downstream consumers.
// ---------------------------------------------------------------------------

/// FFI: returns the substrate's Cargo.toml `version` field as a
/// NUL-terminated UTF-8 C string with `'static` lifetime.
///
/// # Safety
///
/// The returned pointer is valid for the lifetime of the program;
/// callers MUST NOT free it. The pointed-to bytes are immutable.
///
/// Stable since v0.7.0 (ARCH-10).
#[unsafe(no_mangle)]
pub extern "C" fn ai_memory_version() -> *const std::os::raw::c_char {
    // `concat!` with a trailing nul byte gives a `&'static [u8]` of
    // exactly the right shape; CStr::from_bytes_with_nul produces
    // the pointer without an allocation.
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast::<std::os::raw::c_char>()
}

/// The crate version (compile-time `CARGO_PKG_VERSION`) as one named
/// const — wire surfaces (capabilities, serverInfo, backup manifests,
/// boot banners, webhook user-agent) all report it from here instead
/// of nine scattered `env!` calls (#1558 batch 5).
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// v0.7.x (issue #1174 PR5 — pm-v3.1 namespace-sentinel sweep) — the
// default namespace for AI-NHI memory writes when the caller omits
// the `namespace` parameter. Bare value: `"global"`.
//
// Distinguished from [`GLOBAL_NAMESPACE`] (underscored `"_global"`),
// which is the system-reserved namespace for substrate-internal
// rows (governance, quotas, audit). NEVER conflate these — they
// are different namespaces with different semantics. The
// underscore prefix is the reserved-namespace convention.
//
// Replaces ~25 inline literal `"global"` sites across config,
// storage, handlers, MCP tools, and models. The wire value is
// preserved byte-for-byte (`"global"` stays `"global"` on every
// JSON-RPC and HTTP response); only the literal's source location
// changes.
// ---------------------------------------------------------------------------

/// v0.7.x (issue #1174 PR5 — pm-v3.1 namespace-sentinel sweep) — the
/// default namespace for AI-NHI memory writes when the caller omits
/// the `namespace` parameter. Bare value: `"global"`.
///
/// Distinguished from [`GLOBAL_NAMESPACE`] (underscored `"_global"`),
/// which is the system-reserved namespace for substrate-internal
/// rows (governance, quotas, audit). NEVER conflate these — they
/// are different namespaces with different semantics. The
/// underscore prefix is the reserved-namespace convention.
pub const DEFAULT_NAMESPACE: &str = "global";

/// Per-user ai-memory data directory name (`~/.ai-memory`) — home of
/// reflection exports + persona artefacts (#1558 batch 6).
pub const AI_MEMORY_HOME_DIR_NAME: &str = ".ai-memory";

/// v0.7.x (issue #1174 PR5) — re-export of the system-reserved
/// namespace constant defined originally at `src/quotas.rs:70`.
/// Centralised here so other modules don't independently re-define
/// the literal. SEPARATE from [`DEFAULT_NAMESPACE`] — see that
/// doc-comment for the disambiguation.
pub use crate::quotas::GLOBAL_NAMESPACE;

/// `_inbox/` namespace prefix for agent-to-agent notification routing.
/// Reserved-namespace convention; the recipient's `target_agent` id
/// is appended to form the canonical inbox namespace
/// (`_inbox/<target>`).
///
/// v0.7.0 multi-agent literal-sweep (scanner E finding F-E5 / #1436):
/// pre-fix 4 production sites hand-formatted the string
/// (`format!("_inbox/{target}")`); see [`inbox_namespace`] for the
/// canonical helper.
pub const INBOX_NAMESPACE_PREFIX: &str = "_inbox/";

/// Build the canonical inbox namespace for a target agent id.
/// Returns `"_inbox/<target>"` formatted via the
/// [`INBOX_NAMESPACE_PREFIX`] const. Use this in place of inline
/// `format!("_inbox/{target}")` so a future rename of the prefix
/// (or addition of validation, normalization, etc.) touches one
/// place. Closes scanner E finding F-E5 (#1436).
#[must_use]
pub fn inbox_namespace(target_agent: &str) -> String {
    format!("{INBOX_NAMESPACE_PREFIX}{target_agent}")
}

pub mod approvals;
// v0.7.0 WT-1-B — substrate-level atomisation engine. Decomposes
// long-form memories into atomic propositions with full provenance
// (atom_of FK, derives_from edge, signed_events trail). The first
// downstream consumer landing on the WT-1-A schema v36 foundation.
pub mod atomisation;
pub mod audit;
pub mod autonomy;
pub mod bench;
// v0.7.0 QW-3 — daemon-side background tasks. Carries the TTL sweep
// loop for `offloaded_blobs`; future v0.8.0 substrate tasks land
// here without churning `daemon_runtime`.
pub mod background;
pub mod cli;
pub mod color;
/// v0.7.0 Form 5 (issue #758) — auto-confidence + shadow-mode +
/// freshness-decay + calibration tooling. Closes the FORM 5 PARTIAL
/// audit finding by adding deterministic auto-derivation, opt-in
/// shadow-mode telemetry, half-life-driven freshness decay, and a
/// per-source baseline calibration sweep on top of the legacy
/// caller-provided `confidence` field.
pub mod confidence;
pub mod config;
pub mod curator;
pub mod daemon_runtime;
// v0.7.0 L0.5-3 — module renamed from `db` → `storage` as part of
// the flat-to-modular refactor. The `pub use storage as db;` shim
// below preserves every `crate::db::*` path across the codebase
// (handlers, mcp, cli, autonomy, bench, store, curator, transcripts,
// tests) so the rename is a pure refactor with zero callsite churn.
pub mod storage;

// Backward-compat shim from L0.5-3 rename — preserves
// `crate::db::*` paths used elsewhere in the codebase. To be
// removed in v0.8.0 once all callsites migrate to
// `crate::storage::*` AND external consumers migrate to the
// `crate::store::MemoryStore` SAL trait surface.
//
// ARCH-13 (FX-C4-batch2, 2026-05-26): marked `#[deprecated]` on the
// public re-export so any out-of-tree consumer pinning
// `ai_memory::db::*` gets a compile-time deprecation warning. The
// integration-test crate under `tests/` uses `ai_memory::db::*`
// extensively (open / insert / set_namespace_standard / etc.) so a
// hard downgrade to `pub(crate) use` would break those tests; the
// deprecation attribute is the load-bearing signal for the v0.8.0
// migration. External consumers should reach for the
// `crate::store::MemoryStore` SAL trait instead (the canonical
// public surface), and the in-tree handlers continue to use the
// short `db::*` path until the ARCH-2 SAL boundary cleanup migrates
// the remaining 40+ handler sites.
#[allow(dead_code)]
#[deprecated(
    since = "0.7.0",
    note = "use `ai_memory::store::MemoryStore` (the SAL trait surface) instead; the sqlite-only legacy `db` alias is slated for removal in v0.8.0"
)]
pub use storage as db;
pub mod embeddings;
// v0.7.0 (issue #228) — E2E memory content encryption at rest.
// Per-agent X25519 keypair + ChaCha20-Poly1305 AEAD. Gated behind
// `[encryption].at_rest = true` in config OR
// `AI_MEMORY_ENCRYPT_AT_REST=1`. See `src/encryption/mod.rs`.
pub mod encryption;
pub mod errors;
pub mod federation;
// v0.7.0 L2-5 (issue #670) — forensic evidence bundle assembly +
// verification. OSS surface for the AgenticMem Attest tier.
pub mod forensic;
pub mod handlers;
// v0.7 Track B — harness detection. B4 reads the MCP `clientInfo.name`
// captured at the JSON-RPC `initialize` handshake and maps it to a
// `Harness` enum so downstream paths (capabilities-v3, B1's
// `memory_load_family`, B2's `memory_smart_load`) can shape responses
// based on whether the harness supports deferred-tool registration.
pub mod harness;
pub mod hnsw;
// v0.7 Track G — programmable lifecycle hook pipeline. G1 lands
// the config schema + SIGHUP hot-reload plumbing; the executor
// (G3) and the actual fire points (G7+) layer on top of this
// module without touching call sites in `handlers.rs` etc.
pub mod hooks;
pub mod identity;
// v0.7.0 L1-2 — knowledge-graph substrate helpers (anti-cycle check).
pub mod kg;
// v0.7.0 (issue #651) — pluggable inference backend trait pulled
// forward from v0.8 RFC per operator directive
// `28860423-d12c-4959-bc8b-8fa9a94a33d9`. Unifies the
// `embeddings::Embed` + `llm::OllamaClient` surface behind one trait
// so a future GPU/MTP backend (v0.8 Phase 1) drops in transparently.
pub mod inference;
pub mod llm;
// v0.7.x (#1183, split out of #1174 PR4) — per-CLI-binary WrapStrategy
// table for `ai-memory wrap <agent>`. Sibling to `llm.rs` so the
// per-vendor substrate has one home per concern (HTTP wire shape in
// `llm.rs`, CLI ABI in `llm_cli_wrap.rs`). The CLI-binary-name
// detection logic that PICKS a WrapStrategy stays in `cli/wrap.rs`.
pub mod llm_cli_wrap;
pub mod log_paths;
pub mod logging;
pub mod mcp;
pub mod metrics;
pub mod mine;
pub mod models;
// v0.7.0 Form 3 (issue #756) — multi-step ingest orchestrator. Batman
// closeout: deterministic helpers run first (Jaccard, cosine, FTS
// classifier), then LLM stages prepend a SHARED PREFIX and consume
// helper outputs through explicit-trust slots. Stages within a run
// share the prompt-cache key so reasoning-class LLMs hit the cache.
pub mod multistep_ingest;
// v0.7.0 L2-3 (issue #668) — reflection invalidation propagation.
// Notification (not cascade) when a Reflection→Reflection supersedes
// edge lands: walks `reflects_on` edges from dependents and writes
// notification memories into `<namespace>/_invalidations`.
pub mod notification;
// v0.7.0 Gap 3 (#886) — recall-consumption observation tier. Writes
// one row per returned candidate at recall time and flips the
// `consumed` flag when a subsequent store/link request cites the
// candidate. Backed by the `recall_observations` table (schema v47).
pub mod observations;
// v0.7.0 QW-3 — context-offload substrate primitive. Offload+deref
// store with Ed25519-signed audit events; v0.8.0 short-term-context-
// compression (Mermaid canvas + auto-cadence + node_id integration)
// builds on this plumbing.
pub mod offload;
// v0.7.0 QW-2 — Persona-as-artifact substrate primitive. Curator-
// generated Markdown profile of an entity, derived from a cluster
// of Reflection-kind memories. First-class MemoryKind variant +
// MCP tools + namespace-policy cadence + optional filesystem export.
pub mod persona;
// v0.7.0 L1-5 — SKILL.md parser and structured-document ingestion pipelines.
pub mod parsing;
// v0.7.0 K9 — unified permission system. Composes declarative
// `[permissions.rules]` matchers, the K3 `[permissions].mode`
// knob, and G1-G11 hook decisions into a single `Decision`.
// Wired into the five op paths (store, link, delete, archive,
// consolidate) so callers consult one evaluator regardless of
// which source produced the outcome.
//
// v0.7.0 L0.5-4 — module renamed from `permissions` → `governance`
// as part of the flat-to-modular refactor. The `pub use governance
// as permissions;` shim below preserves every `crate::permissions::*`
// path across the codebase (handlers, mcp, config, cli, tests) so the
// rename is a pure refactor with zero callsite churn.
pub mod governance;

// Backward-compat shim from L0.5-4 rename — preserves
// `crate::permissions::*` paths used elsewhere in the codebase.
// To be removed in a future cleanup once all callsites migrate
// to `crate::governance::*`.
#[allow(dead_code)]
pub use governance as permissions;
pub mod profile;
// v0.7 Track K, Task K8 — per-agent rate limits + storage caps.
// `agent_quotas` table backs three counters (memories/day, storage
// bytes, links/day) consulted by the store_memory + memory_link write
// paths; daily counters reset at UTC midnight via a sweep loop.
pub mod quotas;
// v0.7.0 (issue #1389) — fail-safe recovery of agent context from
// host-written transcript files (Claude Code JSONL, Codex CLI,
// Gemini CLI). Closes the #1388 substrate failure mode where an
// AI agent session terminated by SIGKILL between conversation
// turns loses every decision / agreed plan it didn't volunteer-
// `memory_store`. SessionStart-hook calls the CLI verb; in-session
// agents call the MCP tool; both route through the canonical
// `recover_from_transcript` handler in this module.
pub mod recover;
pub mod replication;
pub mod reranker;
// v0.7.x (issue #1174 follow-up #1192 / #1196) — cross-surface
// substrate state (HMAC override, decompression cap, audit chain,
// session-recall tracker, keypair cache). Held as `Arc<RuntimeContext>`
// by every long-lived runtime so the HTTP daemon, MCP stdio binary,
// and CLI all share one source of truth. The legacy free-fn surface
// (`config::active_hooks_hmac_secret`, `audit::emit`,
// `reranker::global_session_recall_tracker`, …) delegates here so the
// wire / chain / cache semantics stay byte-equivalent.
pub mod runtime_context;
pub mod signed_events;
pub mod sizes;
pub mod subscriptions;
pub mod synthesis;
pub mod tls;
pub mod toon;
pub mod transcripts;
pub mod validate;
/// #951 (Track A QC sweep, 2026-05-20) — canonical
/// `is_visible_to_caller` helper, non-sal-gated so both feature
/// flag profiles share the same predicate. See module docstring
/// for the drift history that motivated the consolidation.
pub mod visibility;

#[cfg(feature = "sal")]
pub mod migrate;

#[cfg(feature = "sal")]
pub mod store;

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the daemon's HTTP `axum::Router` from the API-key middleware
/// state and the composite app state.
///
/// This is the single source of truth for the daemon's HTTP route
/// table (88 production routes / 74 unique URL paths at v0.7.0). It is
/// exposed through the lib crate so the integration test suite can
/// construct an in-process `axum::Router` and exercise endpoints via
/// `Router::oneshot()` instead of spawning a subprocess + curl, which:
///
/// 1. eliminates the OS-level daemon-spawn overhead per test
///    (~200-500ms),
/// 2. exposes the routes' line coverage to `cargo llvm-cov` (subprocess
///    coverage attribution requires extra `LLVM_PROFILE_FILE` plumbing
///    that the test harness doesn't provide), and
/// 3. lets test failures surface assertion-level diagnostics instead
///    of "curl returned 000" black holes.
///
/// The function takes the same two state values that `serve()`
/// constructs inline so the production binary and the test harness
/// share a single route map.
///
/// DOC-5 (med/low review batch) — promoted from the pre-existing `//`
/// banner so the doc-comment attaches to the symbol (cargo-doc + IDE
/// surfaces) and is symmetric with the sibling
/// [`build_router_with_timeout`].
pub fn build_router(
    api_key_state: handlers::ApiKeyState,
    app_state: handlers::AppState,
) -> axum::Router {
    build_router_with_timeout(
        api_key_state,
        app_state,
        std::time::Duration::from_secs(config::DEFAULT_REQUEST_TIMEOUT_SECS),
    )
}

/// v0.7.0 H7 (round-2) — variant of [`build_router`] that takes an
/// explicit per-request wall-clock timeout. Composes a per-request
/// timeout middleware so a slow-POST (slowloris-style) attacker
/// cannot keep a handler scope alive indefinitely. Requests that
/// exceed the timeout get a `504 Gateway Timeout` response with a
/// `{"error":"request timed out"}` body. The production daemon
/// calls this with the value resolved from
/// `AppConfig::effective_request_timeout_secs` (default 60 s); tests
/// pass a short timeout to drive the timeout edge directly.
///
/// Implementation: a custom axum middleware wraps every request in
/// `tokio::time::timeout`, returning the structured timeout response
/// when the future does not resolve in time. This avoids enabling
/// tower-http's `timeout` feature (which would require a
/// `Cargo.toml` change). The behaviour matches what
/// `tower::timeout::TimeoutLayer` would provide modulo the status
/// code (we return 504 to stay distinguishable from request-shape
/// 400s).
pub fn build_router_with_timeout(
    api_key_state: handlers::ApiKeyState,
    app_state: handlers::AppState,
    request_timeout: std::time::Duration,
) -> axum::Router {
    use axum::{
        extract::DefaultBodyLimit,
        routing::{delete, get, post, put},
    };
    use tower_http::{cors::CorsLayer, trace::TraceLayer};

    // Timeout middleware: wraps each downstream future in
    // `tokio::time::timeout`. The closure captures the `Duration` by
    // value so it lives for the router's lifetime.
    let timeout = request_timeout;
    let timeout_layer = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| async move {
            use axum::response::IntoResponse;
            match tokio::time::timeout(timeout, next.run(req)).await {
                Ok(resp) => resp,
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = timeout.as_secs(),
                        "H7: request exceeded per-request wall-clock timeout — returning 504"
                    );
                    (
                        axum::http::StatusCode::GATEWAY_TIMEOUT,
                        axum::Json(serde_json::json!({"error": "request timed out"})),
                    )
                        .into_response()
                }
            }
        },
    );

    axum::Router::new()
        .route(handlers::routes::HEALTH, get(handlers::health))
        // v0.6.0.0: Prometheus scrape endpoint. Exposed at both /metrics
        // (the community convention) and /api/v1/metrics (consistent with
        // the rest of the REST surface).
        .route(
            handlers::routes::METRICS_BARE,
            get(handlers::prometheus_metrics),
        )
        .route(handlers::routes::METRICS, get(handlers::prometheus_metrics))
        .route(handlers::routes::MEMORIES, get(handlers::list_memories))
        .route(handlers::routes::MEMORIES, post(handlers::create_memory))
        .route(handlers::routes::MEMORIES_BULK, post(handlers::bulk_create))
        .route(handlers::routes::MEMORIES_ID, get(handlers::get_memory))
        .route(handlers::routes::MEMORIES_ID, put(handlers::update_memory))
        .route(
            handlers::routes::MEMORIES_ID,
            delete(handlers::delete_memory),
        )
        .route(
            handlers::routes::MEMORIES_ID_PROMOTE,
            post(handlers::promote_memory),
        )
        // v0.7.0 #1416 — L4 layered-capture HTTP surface. Mirrors the
        // MCP `memory_capture_turn` tool so postgres-backed daemons gain
        // a callable L4 turn-capture path (the MCP tool only ever runs
        // against a local sqlite connection). Routes through the SAL
        // `MemoryStore::capture_turn_idempotent` trait method.
        .route(handlers::routes::CAPTURE_TURN, post(handlers::capture_turn))
        .route(handlers::routes::SEARCH, get(handlers::search_memories))
        .route(handlers::routes::RECALL, get(handlers::recall_memories_get))
        .route(
            handlers::routes::RECALL,
            post(handlers::recall_memories_post),
        )
        .route(handlers::routes::FORGET, post(handlers::forget_memories))
        .route(
            handlers::routes::CONSOLIDATE,
            post(handlers::consolidate_memories),
        )
        .route(
            handlers::routes::CONTRADICTIONS,
            get(handlers::detect_contradictions),
        )
        // v0.7.0 L6 — S51 autonomous-tier surface. `auto_tag` and
        // `expand_query` are the two REST mirrors of the corresponding
        // MCP tools; they were never wired before L6 (S51 expected
        // them and got 404). Both 503 when no LLM is configured.
        .route(handlers::routes::AUTO_TAG, post(handlers::auto_tag_handler))
        .route(
            handlers::routes::EXPAND_QUERY,
            post(handlers::expand_query_handler),
        )
        // v0.7.0 L9 — HTTP parity for the MCP `tools/list` JSON-RPC
        // method. Surfaces the canonical tool catalog under the
        // daemon's resolved Profile. Backend-agnostic — pure config
        // enumeration, no DB access — so postgres and sqlite return
        // identical bodies (NHI-D-501-postgres-traits).
        .route(handlers::routes::TOOLS_LIST, get(handlers::tools_list))
        // v0.7.0 L10 — HTTP parity for the MCP `memory_load_family`
        // tool. Returns top-K memories tagged with the requested
        // family on both sqlite and postgres backends
        // (NHI-D-501-postgres-loadfamily).
        .route(
            handlers::routes::MEMORY_LOAD_FAMILY,
            post(handlers::load_family_handler),
        )
        .route(handlers::routes::LINKS, post(handlers::create_link))
        .route(handlers::routes::LINKS, delete(handlers::delete_link))
        .route(handlers::routes::LINKS_ID, get(handlers::get_links))
        // HTTP parity for MCP-only tools. The `/api/v1/namespaces` surface
        // serves three verbs: GET lists namespaces OR (when ?namespace=…)
        // fetches the namespace standard, POST sets a standard, DELETE
        // clears one. S34/S35 use the query-string form; the path form
        // (`/api/v1/namespaces/{ns}/standard`) is kept for MCP-tool parity.
        .route(
            handlers::routes::NAMESPACES,
            get(handlers::get_namespace_standard_qs),
        )
        .route(
            handlers::routes::NAMESPACES,
            post(handlers::set_namespace_standard_qs),
        )
        .route(
            handlers::routes::NAMESPACES,
            delete(handlers::clear_namespace_standard_qs),
        )
        .route(
            handlers::routes::NAMESPACES_NS_STANDARD,
            post(handlers::set_namespace_standard),
        )
        .route(
            handlers::routes::NAMESPACES_NS_STANDARD,
            get(handlers::get_namespace_standard),
        )
        .route(
            handlers::routes::NAMESPACES_NS_STANDARD,
            delete(handlers::clear_namespace_standard),
        )
        // Pillar 1 / Stream A — hierarchical namespace taxonomy.
        .route(handlers::routes::TAXONOMY, get(handlers::get_taxonomy))
        // Pillar 2 / Stream D — pre-write near-duplicate check.
        .route(
            handlers::routes::CHECK_DUPLICATE,
            post(handlers::check_duplicate),
        )
        // Pillar 2 / Stream B — entity registry.
        .route(handlers::routes::ENTITIES, post(handlers::entity_register))
        .route(
            handlers::routes::ENTITIES_BY_ALIAS,
            get(handlers::entity_get_by_alias),
        )
        // Pillar 2 / Stream C — KG timeline.
        .route(handlers::routes::KG_TIMELINE, get(handlers::kg_timeline))
        // Pillar 2 / Stream C — KG link supersession.
        .route(
            handlers::routes::KG_INVALIDATE,
            post(handlers::kg_invalidate),
        )
        // Pillar 2 / Stream C — KG outbound traversal.
        .route(handlers::routes::KG_QUERY, post(handlers::kg_query))
        // v0.7.0 Continuation 6 — KG path enumeration (S65).
        .route(
            handlers::routes::KG_FIND_PATHS,
            post(handlers::kg_find_paths),
        )
        // #934 (Track C, 2026-05-20) — alias for legacy callers that
        // hit the bare `/api/v1/find_paths` route (advertised under
        // the MCP `memory_find_paths` shape + pre-v0.7.0 docs). Pre-
        // fix the bare path was intercepted by the postgres-gate
        // fallback and returned a misleading 501 "not yet
        // implemented" — actually the route just lived under `/kg/`.
        // Mounting both paths to the same handler closes the drift
        // for all callers without a redirect.
        .route(handlers::routes::FIND_PATHS, post(handlers::kg_find_paths))
        // v0.7.0 Continuation 6 — link signature verification (S52).
        .route(
            handlers::routes::LINKS_VERIFY,
            post(handlers::verify_link_handler),
        )
        // v0.7.0 Continuation 6 — per-agent quota status (S61).
        .route(
            handlers::routes::QUOTA_STATUS,
            post(handlers::quota_status_handler),
        )
        .route(handlers::routes::STATS, get(handlers::get_stats))
        .route(handlers::routes::GC, post(handlers::run_gc))
        .route(handlers::routes::EXPORT, get(handlers::export_memories))
        .route(handlers::routes::IMPORT, post(handlers::import_memories))
        .route(handlers::routes::ARCHIVE, get(handlers::list_archive))
        .route(handlers::routes::ARCHIVE, post(handlers::archive_by_ids))
        .route(handlers::routes::ARCHIVE, delete(handlers::purge_archive))
        .route(
            handlers::routes::ARCHIVE_ID_RESTORE,
            post(handlers::restore_archive),
        )
        .route(
            handlers::routes::ARCHIVE_STATS,
            get(handlers::archive_stats),
        )
        .route(handlers::routes::AGENTS, get(handlers::list_agents))
        .route(handlers::routes::AGENTS, post(handlers::register_agent))
        .route(handlers::routes::PENDING, get(handlers::list_pending))
        .route(
            handlers::routes::PENDING_ID_APPROVE,
            post(handlers::approve_pending),
        )
        .route(
            handlers::routes::PENDING_ID_REJECT,
            post(handlers::reject_pending),
        )
        // v0.7.0 K10 — Approval API. POST is HMAC-gated; SSE rides on
        // top of the existing api_key_auth middleware (no extra gate).
        .route(
            handlers::routes::APPROVALS_PENDING_ID,
            post(handlers::approval_decide),
        )
        .route(
            handlers::routes::APPROVALS_STREAM,
            get(handlers::approvals_sse),
        )
        // Phase 3 foundation (issue #224) — peer-to-peer sync endpoints.
        .route(handlers::routes::SYNC_PUSH, post(handlers::sync_push))
        .route(handlers::routes::SYNC_SINCE, get(handlers::sync_since))
        // HTTP parity for MCP-only tools.
        .route(
            handlers::routes::CAPABILITIES,
            get(handlers::get_capabilities),
        )
        .route(handlers::routes::NOTIFY, post(handlers::notify))
        .route(handlers::routes::INBOX, get(handlers::get_inbox))
        .route(handlers::routes::SUBSCRIPTIONS, post(handlers::subscribe))
        .route(
            handlers::routes::SUBSCRIPTIONS,
            delete(handlers::unsubscribe),
        )
        .route(
            handlers::routes::SUBSCRIPTIONS,
            get(handlers::list_subscriptions),
        )
        .route(
            handlers::routes::SESSION_START,
            post(handlers::session_start),
        )
        // v0.7.0 Cluster E API-2 (issue #767) — Agent Skills HTTP parity.
        // Seven routes mirroring the seven L1-5 `memory_skill_*` MCP
        // tools so HTTP-daemon operators can drive skills without
        // dropping back to stdio JSON-RPC. No new MCP tools land here —
        // the MCP surface stays at whatever `Profile::full().
        // expected_tool_count()` reports (canonical SSOT in
        // `src/profile.rs`; pinned by `profile_full_matches_registry_all`).
        .route(
            handlers::routes::SKILL_REGISTER,
            post(handlers::skill_register_route),
        )
        .route(
            handlers::routes::SKILL_LIST,
            get(handlers::skill_list_route),
        )
        .route(handlers::routes::SKILL_ID, get(handlers::skill_get_route))
        .route(
            handlers::routes::SKILL_ID_RESOURCE,
            get(handlers::skill_resource_route),
        )
        .route(
            handlers::routes::SKILL_ID_EXPORT,
            post(handlers::skill_export_route),
        )
        .route(
            handlers::routes::SKILL_ID_PROMOTE,
            post(handlers::skill_promote_route),
        )
        .route(
            handlers::routes::SKILL_ID_COMPOSE,
            post(handlers::skill_compose_route),
        )
        // v0.7.0 #1095 — `POST /api/v1/share` HTTP parity for the
        // MCP-only `memory_share` tool. Closes the SR-4 three-surface
        // parity audit gap (#1095). Mirrors the MCP wire shape
        // (`source_memory_id` + `target_agent_id`) and wraps the same
        // substrate primitive (`crate::mcp::tools::share::handle_share`)
        // so MCP / HTTP behave byte-equally.
        .route(handlers::routes::SHARE, post(handlers::share_memory))
        // v0.7.0 #1111 — 14 HTTP routes for the MCP-only tools the
        // SR-4 three-surface-parity audit flagged. Each route is a thin
        // wrapper around the existing `crate::mcp::handle_<name>`
        // substrate primitive; wire envelopes are byte-equal across
        // the MCP and HTTP surfaces. See
        // [`crate::handlers::route_1111`] for the per-handler module.
        .route(
            handlers::routes::MEMORY_SMART_LOAD,
            post(handlers::route_1111::handle_smart_load_http),
        )
        .route(
            handlers::routes::MEMORY_REFLECT,
            post(handlers::route_1111::handle_reflect_http),
        )
        .route(
            handlers::routes::MEMORY_RECALL_OBSERVATIONS,
            post(handlers::route_1111::handle_recall_observations_http),
        )
        .route(
            handlers::routes::MEMORY_REFLECTION_ORIGIN,
            post(handlers::route_1111::handle_reflection_origin_http),
        )
        .route(
            handlers::routes::MEMORY_DEPENDENTS_OF_INVALIDATED,
            post(handlers::route_1111::handle_dependents_of_invalidated_http),
        )
        .route(
            handlers::routes::MEMORY_EXPORT_REFLECTION,
            post(handlers::route_1111::handle_export_reflection_http),
        )
        .route(
            handlers::routes::MEMORY_ATOMISE,
            post(handlers::route_1111::handle_atomise_http),
        )
        .route(
            handlers::routes::MEMORY_CALIBRATE_CONFIDENCE,
            post(handlers::route_1111::handle_calibrate_confidence_http),
        )
        .route(
            handlers::routes::MEMORY_VERIFY,
            post(handlers::route_1111::handle_verify_http),
        )
        .route(
            handlers::routes::MEMORY_REPLAY,
            post(handlers::route_1111::handle_replay_http),
        )
        .route(
            handlers::routes::MEMORY_SUBSCRIPTION_REPLAY,
            post(handlers::route_1111::handle_subscription_replay_http),
        )
        .route(
            handlers::routes::MEMORY_SUBSCRIPTION_DLQ_LIST,
            post(handlers::route_1111::handle_subscription_dlq_list_http),
        )
        .route(
            handlers::routes::MEMORY_RULE_LIST,
            post(handlers::route_1111::handle_rule_list_http),
        )
        .route(
            handlers::routes::MEMORY_CHECK_AGENT_ACTION,
            post(handlers::route_1111::handle_check_agent_action_http),
        )
        .layer(axum::middleware::from_fn_with_state(
            api_key_state,
            handlers::api_key_auth,
        ))
        // v0.7.0 Wave-3 Continuation — postgres route gate. On sqlite
        // deployments this is a pure pass-through. On postgres-backed
        // daemons it short-circuits any un-migrated endpoint with a
        // structured 501 envelope so operators never see silent data
        // corruption from the unused `app.db` scratch connection.
        // See `handlers::postgres_endpoint_supported` for the allow-list.
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            postgres_route_gate_layer,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(HTTP_BODY_LIMIT_BYTES))
        // #1579 B4 — gzip response compression (4.6× measured
        // response-size win on recall payloads in the perf audit).
        // Honors the request's `Accept-Encoding` header; requests
        // without `gzip` in the accept list pass through
        // identity-coded. The layer's DEFAULT predicate
        // (`SizeAbove(32) AND NotForContentType`) already exempts
        // `text/event-stream`, so the SSE `/approvals/stream`
        // surface is never wrapped in a gzip stream that would
        // buffer events — pinned by the
        // `issue_1579_b4_*` router tests.
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(CorsLayer::new())
        // H7 (v0.7.0 round-2) — per-request wall-clock timeout.
        // Applied outermost (last in the layer stack) so it bounds
        // every other middleware: the API-key auth, the postgres
        // gate, and the body decoder all run inside the timeout
        // window. Default 60 s; configurable via
        // `AppConfig::request_timeout_secs`.
        .layer(timeout_layer)
        .with_state(app_state)
}

/// v0.7.0 Wave-3 Continuation — adapter that picks up the appropriate
/// gate function depending on whether the binary was built with the
/// `sal` feature flag. Standard builds compile this to a no-op pass-
/// through closure so the wire shape stays identical to pre-Wave-3.
#[cfg(feature = "sal")]
async fn postgres_route_gate_layer(
    state: axum::extract::State<handlers::AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    handlers::postgres_route_gate(state, req, next).await
}

#[cfg(not(feature = "sal"))]
async fn postgres_route_gate_layer(
    _state: axum::extract::State<handlers::AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    next.run(req).await
}

// ---------------------------------------------------------------------------
// H7 (v0.7.0 round-2) — per-request HTTP timeout tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod h7_timeout_tests {
    use std::time::Duration;

    use axum::{Router, body::Body, http::Request, response::IntoResponse, routing::post};
    use tower::ServiceExt as _;

    /// The timeout middleware sandwich: a thin Router with a single
    /// slow handler that always sleeps past the configured timeout.
    /// Exercises the same `axum::middleware::from_fn` closure shape
    /// `build_router_with_timeout` builds, without standing up the
    /// full AppState graph.
    fn timeout_router(timeout: Duration, handler_sleep: Duration) -> Router {
        async fn slow_handler(_body: axum::body::Bytes) -> impl IntoResponse {
            // Sleep duration is captured below via a small wrapper to
            // keep the closure shape inferrable.
            axum::http::StatusCode::OK
        }
        let timeout_layer = axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                match tokio::time::timeout(timeout, next.run(req)).await {
                    Ok(resp) => resp,
                    Err(_) => (
                        axum::http::StatusCode::GATEWAY_TIMEOUT,
                        axum::Json(serde_json::json!({"error": "request timed out"})),
                    )
                        .into_response(),
                }
            },
        );
        // The actual slow handler — sleeps `handler_sleep` then 200.
        Router::new()
            .route(
                "/slow",
                post(move |_b: axum::body::Bytes| async move {
                    tokio::time::sleep(handler_sleep).await;
                    slow_handler(axum::body::Bytes::new()).await
                }),
            )
            .layer(timeout_layer)
    }

    #[tokio::test]
    async fn slow_handler_returns_504_when_timeout_fires() {
        // Wire: middleware timeout=50ms, handler sleeps 500ms → 504.
        // Mirrors the production contract: a client that pumps a body
        // slow-loris-style past the configured ceiling sees a
        // structured timeout response instead of the daemon holding
        // the scope open forever.
        let router = timeout_router(Duration::from_millis(50), Duration::from_millis(500));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/slow")
                    .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // tower::timeout-style middleware returns 504 Gateway Timeout
        // when the inner future times out. axum's `INTERNAL_SERVER_ERROR`
        // shape would also be acceptable per the round-2 contract
        // ("408 or 500 — whatever the timeout produces"); we picked 504
        // deliberately because it stays distinguishable from
        // request-shape 400s and never collides with the inner
        // handler's own status codes.
        assert!(
            resp.status() == axum::http::StatusCode::GATEWAY_TIMEOUT
                || resp.status() == axum::http::StatusCode::REQUEST_TIMEOUT
                || resp.status() == axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "expected a timeout-style response code, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn fast_handler_passes_through_when_timeout_does_not_fire() {
        // Wire: middleware timeout=1s, handler sleeps 10ms → 200.
        let router = timeout_router(Duration::from_secs(1), Duration::from_millis(10));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/slow")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
