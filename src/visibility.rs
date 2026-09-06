// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #951 (Track A QC sweep, 2026-05-20) — single canonical
//! `is_visible_to_caller` helper, available on both `sal` and
//! non-sal builds.
//!
//! Pre-#951 the same visibility check was inlined / duplicated in
//! at least 3 sites:
//! - `src/store/mod.rs::is_visible_to_caller` (sal-gated; canonical)
//! - `src/handlers/memories_query.rs::is_visible_to_caller`
//!   (handler-local duplicate; DRIFT — missing the
//!   `metadata.target_agent_id` inbox carve-out)
//! - `src/handlers/memories.rs::get_memory` (inline gate per #927;
//!   couldn't import the canonical version because `crate::store`
//!   is `#[cfg(feature = "sal")]`-gated)
//!
//! Moving the helper here (not gated) lets the sqlite-only build,
//! the sal-only build, and the sal-postgres build all share the
//! same predicate so future scope semantics can change once and
//! land everywhere.
//!
//! Semantics (load-bearing — DO NOT drift):
//!   `is_visible_to_caller(mem, caller)` returns true iff the memory's
//!   `metadata.scope` grants `caller` (an agent id, which IS the agent's
//!   namespace prefix per `src/identity/mod.rs`) visibility:
//!     - `collective` scope → visible to every caller;
//!     - `team` / `unit` / `org` scope → visible ONLY when the memory's
//!       namespace falls within the caller's team / unit / org subtree
//!       (`#1921`, CWE-863 — pre-fix these were treated as
//!       world-readable, leaking every non-private row cross-tenant on
//!       the list/get/kg paths that use this predicate as the sole scope
//!       gate);
//!     - `private` scope (also the default for rows without the field,
//!       per the CLAUDE.md NHI contract) → visible iff
//!       `metadata.agent_id == caller` (owner) OR
//!       `metadata.target_agent_id == caller` (inbox carve-out: the
//!       sender stamps `target_agent_id` on a private-by-default
//!       `_inbox/<recipient>` row so the recipient can read their own
//!       inbox even though the row is scope=private under the sender's
//!       ownership);
//!     - the CLOSED legacy/internal token set [`LEGACY_BROAD_SCOPES`]
//!       (currently exactly `"shared"`) → visible (broadly). This is the
//!       documented shareable-shape posture the federation projection
//!       lane relies on (`#948` / `#978` — a `scope=shared` row projects
//!       to any allowlisted peer) and the marker the substrate itself
//!       stamps on `_standard:<ns>` governance-policy placeholder rows;
//!     - **#2633** — any OTHER unrecognised token (a typo: `"privat"`,
//!       `"sharedd"`, `"Private"`) → treated exactly as an ABSENT scope
//!       key, i.e. owner-keyed private. Pre-#2633 this arm returned
//!       `true` unconditionally, so a one-character misspelling made a
//!       row world-readable while the correctly-spelled `"private"` and
//!       the ABSENT key both kept it owner-only — one character apart,
//!       opposite postures.
//!
//! #1921 scope note: the private-owner fix (#1720) and the
//! collective broad-visibility semantics are unchanged; the #1921
//! behavioural change was that team/unit/org became subtree-restricted
//! (was: world-readable). #2633 additionally narrows the unrecognised-token
//! arm to the absent-key default.

use crate::models::Memory;

/// #2633 — the CLOSED set of scope tokens that are NOT members of
/// [`crate::models::namespace::MemoryScope`] but ARE still honoured as
/// broadly-visible on the in-process read path.
///
/// **Why a const slice here rather than a sixth `MemoryScope` variant.**
/// A 3x3 adversarial vote (9 lenses, `4d3ea1c5` protocol; Q1 Option B,
/// 8-1) rejected reifying `shared` as an enum variant because
/// [`crate::models::namespace::MemoryScope::from_str`] is NOT
/// visibility-private — `crate::governance::refusal::required_scope_refusal`
/// funnels through it and coerces an unparseable token to `Private`, so a
/// parsing `Shared` variant flips every `scope:"shared"` write from
/// SATISFYING a `required_scope = private` policy to being REFUSED by it.
/// The rows that carry `scope:"shared"` are the `_standard:<ns>`
/// governance-policy placeholders (`crate::handlers::hook_subscribers`
/// first-write + ownership-restamp, and `crate::mcp::tools::namespace`
/// set-standard restamp), i.e. the policy CARRIER itself — so the enum
/// route bricks `set_standard` in exactly the namespaces that pin a
/// required scope. It would also make `"shared"` serde-reachable as a
/// `CorePolicy::required_scope` value, widening a v1.0.0 public contract.
///
/// Keeping the legacy token out of the enum confines this defect's fix to
/// the read predicate that actually has it, changes ZERO SSOT pins
/// (`MemoryScope::COUNT`, `all()`, `all_strs()`, `VALID_SCOPES` and the
/// "5 visibility scopes" docs narrative all stay as-is), and leaves
/// `crate::storage::is_visible` + the SQL `visibility_clause` byte-identical.
///
/// **This is still a closed set** — that is the whole point of #2633. The
/// catch-all below it denies (falls back to owner-keyed private); only the
/// tokens enumerated here are honoured broadly.
pub const LEGACY_BROAD_SCOPES: &[&str] = &["shared"];

/// `true` when `scope` is a member of the closed [`LEGACY_BROAD_SCOPES`] set.
#[must_use]
pub fn is_legacy_broad_scope(scope: &str) -> bool {
    LEGACY_BROAD_SCOPES.contains(&scope)
}

/// Returns `true` when the caller is entitled to see the memory.
///
/// Per #951 this is the **single canonical** implementation — every
/// handler, MCP tool, and SAL adapter that needs an in-process
/// visibility check should call this rather than re-implementing
/// the predicate. Drift between copies is a real defect (the
/// pre-#951 inline copy in `handlers/memories_query.rs` was missing
/// the inbox carve-out, which would have surfaced the day a private
/// inbox row hit a list+filter path).
#[must_use]
pub fn is_visible_to_caller(mem: &Memory, caller: &str) -> bool {
    is_visible_by_fields(&mem.id, &mem.namespace, &mem.metadata, caller)
}

/// #2633 — the field-level form of [`is_visible_to_caller`], for the one call
/// site that holds a row's `(id, namespace, metadata)` but not a full
/// [`Memory`]: the postgres `find_paths` path-traversal filter, which reads
/// `SELECT id, namespace, metadata` per graph node.
///
/// That site previously carried an INLINE re-implementation
/// (`if scope != "private" { true } else { owner == caller }`) whose comment
/// claimed parity with this predicate. It had drifted twice: it never received
/// the #1921 subtree restriction (so `team` / `unit` / `org` rows were
/// world-readable on the postgres kg path long after every other read path was
/// narrowed), and it carried the #2633 "unknown ⇒ widest posture" widening.
/// Routing it through this function converges it — which is the #951 rule the
/// module doc opens with: drift between copies of this predicate is a real
/// defect, and a copy that only LOOKS canonical is the worst kind.
///
/// `id` is used only for the unrecognised-token WARN.
#[must_use]
pub fn is_visible_by_fields(
    id: &str,
    namespace: &str,
    metadata: &serde_json::Value,
    caller: &str,
) -> bool {
    // #1921 (CWE-863, tenant-isolation) — enforce the scope hierarchy so
    // team/unit/org memories are visible ONLY to callers in the matching
    // namespace SUBTREE, instead of the pre-fix `scope != "private" =>
    // return true` short-circuit that treated team/unit/org as world-
    // readable. This is the SOLE scope gate on the list/get/kg paths that
    // never invoke the SQL `visibility_clause`, so the leak was a full-
    // content cross-tenant disclosure of every team/unit/org row in a
    // victim's subtree.
    //
    // The change is SURGICAL — only the team/unit/org arms move from
    // "always true" to a `matches_subtree` check (mirroring
    // `crate::storage::is_visible`). `collective` stays world-readable (it
    // is DESIGNED that way), and `private` stays owner-keyed (#1720).
    //
    // #2633 (CWE-863, FBL-14) — the unrecognised-token arm below was
    // `Some(None) => true`: "present but unknown ⇒ WIDEST posture". Any
    // writer who could put an arbitrary string into `metadata.scope`,
    // INCLUDING BY TYPO (`"privat"`, `"sharedd"`, `"Private"`), made the
    // row world-readable on every non-SQL read path — and on postgres this
    // predicate is the ONLY scope gate (`PostgresStore` has no SQL
    // `visibility_clause`; it filters in Rust through this function). A row
    // with NO scope key defaulted to private and a row with a MISSPELLED
    // one was public: one character apart, opposite postures.
    //
    // The house rule is the opposite — an unrecognised token takes the
    // NARROWEST posture (`receive_auth::env_flag_default_on` keeps the
    // secure default; `AI_MEMORY_INFERENCE_EGRESS` WARNs and fails closed
    // to `deny` on a typo). The arm is now a CLOSED set: the legitimate
    // `#948`/`#978` federation shareable token stays broadly visible via
    // `LEGACY_BROAD_SCOPES`, and everything else falls through to the
    // ABSENT-key default.
    //
    // Disposition is `private_visible`, NOT a bare `false`: the narrowest
    // posture that closes the cross-tenant hole still lets the row's OWN
    // owner (and an inbox target) read it, so a typo costs the writer a
    // warning and their row's reach — never access to their own data.
    // Fail-closed to `false` would make a misspelled row unreachable by
    // anyone, including the one principal who can fix it.
    use crate::models::namespace::MemoryScope;
    let scope_str = metadata
        .get(crate::META_KEY_SCOPE)
        .and_then(serde_json::Value::as_str);
    match scope_str.map(MemoryScope::from_str) {
        // Field absent → default private (owner-keyed).
        None => private_visible(namespace, metadata, caller),
        // Present but not a `MemoryScope`: the closed legacy set is honoured
        // broadly; every other token degrades to the absent-key default.
        Some(None) => {
            let raw = scope_str.unwrap_or_default();
            if is_legacy_broad_scope(raw) {
                true
            } else {
                tracing::warn!(
                    target: "visibility.unknown_scope",
                    memory_id = %id,
                    namespace = %namespace,
                    scope = %raw,
                    "unrecognised metadata.scope token; treating as private (#2633). \
                     Valid scopes: {}",
                    crate::models::namespace::VALID_SCOPES.join(", ")
                );
                private_visible(namespace, metadata, caller)
            }
        }
        Some(Some(MemoryScope::Private)) => private_visible(namespace, metadata, caller),
        // Visible to every authenticated caller, regardless of namespace.
        Some(Some(MemoryScope::Collective)) => true,
        // #1921 — subtree-restricted: the memory's namespace must fall
        // within the caller's team / unit / org ancestor. `caller` is the
        // agent id, which IS the agent's namespace prefix. A missing
        // ancestor (the caller's namespace is too shallow, or `caller` is
        // a synthetic `anonymous:req-…` id with no `/`) → deny.
        Some(Some(MemoryScope::Team)) => scope_subtree_visible(namespace, caller, 1),
        Some(Some(MemoryScope::Unit)) => scope_subtree_visible(namespace, caller, 2),
        Some(Some(MemoryScope::Org)) => scope_subtree_visible(namespace, caller, 3),
    }
}

/// Owner / inbox-target check for a `scope=private` (or default) row.
fn private_visible(namespace: &str, metadata: &serde_json::Value, caller: &str) -> bool {
    let owner = metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if owner == caller {
        return true;
    }
    let target = metadata
        .get(crate::META_KEY_TARGET_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    target == caller
        || (namespace.strip_prefix(crate::LEGACY_INBOX_NAMESPACE_PREFIX) == Some(caller)
            && !metadata
                .as_object()
                .is_some_and(|m| m.contains_key(crate::META_KEY_TARGET_AGENT_ID))
            && metadata
                .get("recipient_agent_id")
                .and_then(serde_json::Value::as_str)
                == Some(caller))
}

/// #1921 — subtree gate for `team` / `unit` / `org` scope. `ancestor_idx`
/// selects the caller's team (1), unit (2), or org (3) namespace ancestor
/// (index 0 is the caller's own namespace / private position). The memory
/// is visible iff its namespace equals, or is nested under, that ancestor.
/// Mirrors `crate::storage::is_visible` + `matches_subtree` exactly.
fn scope_subtree_visible(namespace: &str, caller: &str, ancestor_idx: usize) -> bool {
    let ancestors = crate::models::namespace_ancestors(caller);
    let Some(prefix) = ancestors.get(ancestor_idx) else {
        return false;
    };
    namespace == *prefix || namespace.starts_with(&format!("{prefix}/"))
}

/// #1786 — ownership predicate for MUTATION gating (delete / update / promote /
/// link). Returns `true` when `caller` may MUTATE `mem`. This is the canonical
/// twin of the HTTP `handlers::parity::require_caller_owns_memory` gate, lifted
/// here so the MCP mutation surface (which calls raw `db::*` and historically
/// skipped the owner check that HTTP + the postgres SAL enforce) inherits the
/// IDENTICAL, deliberately LENIENT, single-tenant-safe semantics:
///
///   * an UNSTAMPED row (no `agent_id`) is mutable by anyone — legacy / unowned
///     rows are not locked out (this is what keeps the single-operator default,
///     where rows may carry no stamp, working);
///   * a SELF-OWNED row (`agent_id == caller`) is mutable;
///   * the `daemon` principal bypasses (curator / internal);
///   * when `allow_inbox`, the inbox recipient (`target_agent_id == caller`)
///     may mutate (mirrors the HTTP delete-side `allow_inbox=true`).
///
/// Only a row owned by a DIFFERENT, named agent is refused — closing the
/// cross-owner MCP mutation gap (#1786) without breaking the single-tenant
/// default. NOTE: `agent_id` is a CLAIMED identity, so this gate's strength is
/// bounded by caller attestation (#48) — it closes the unstamped/cross-id gap,
/// not impersonation by a caller who claims the owner's id.
#[must_use]
pub fn caller_owns_for_mutation(mem: &Memory, caller: &str, allow_inbox: bool) -> bool {
    let owner = mem
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if owner.is_empty() || owner == caller || caller == crate::identity::sentinels::DAEMON_PRINCIPAL
    {
        return true;
    }
    if allow_inbox {
        let target = mem
            .metadata
            .get(crate::META_KEY_TARGET_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !target.is_empty() && target == caller {
            return true;
        }
    }
    false
}

/// v1.0.0 #3348 — SUBSTRATE-OWNED namespace prefixes. Rows here are written by
/// the substrate itself on behalf of a specific agent (a message delivered to
/// one recipient, a registry entry, a curator self-report) — they are
/// bookkeeping, never a caller's own knowledge.
///
/// The list is CLOSED and lives here, in the visibility SSOT, rather than being
/// re-derived per read surface: #3348 was reported because `recall`, `search`
/// and `boot` each made their own decision and all three defaulted to "return
/// everything". One predicate means a new read surface inherits the posture
/// instead of re-litigating it.
///
/// Deliberately EXCLUDED: `_shared/<from>-><to>`. That is the `ai-memory share`
/// DELIVERY destination — a user-facing feature whose whole point is that the
/// recipient recalls the row ambiently. Confining it is a separate question from
/// #3348 (which is about substrate bookkeeping leaking), and silently breaking
/// `share` to close an unreported hole would be the wrong trade.
pub const SUBSTRATE_NAMESPACE_PREFIXES: &[&str] = &[
    crate::LEGACY_INBOX_NAMESPACE_PREFIX,
    "_inbox/",
    "_curator/",
    "_subscriptions/",
    "_standard:",
];

/// v1.0.0 #3348 — substrate-owned namespaces with no trailing separator.
pub const SUBSTRATE_NAMESPACES_EXACT: &[&str] = &["_agents", "_agent_sessions", "_standards"];

/// v1.0.0 #3345 — every entry of the two substrate lists must be safe to
/// splice into a SQL string literal, because [`SQL_AND_NOT_SUBSTRATE`] builds
/// its predicate from them at process start. The lists are compile-time
/// constants (no caller ever extends them at runtime), so this is checked
/// STRUCTURALLY at compile time rather than defended against at query time:
/// a future entry carrying a quote, a backslash, or a `%`/`_` LIKE
/// metacharacter fails the build instead of emitting malformed — or silently
/// over-matching — SQL on both backends (ERRORS-09: make the illegal state
/// unrepresentable rather than validated).
///
/// The allowed alphabet is exactly what the current namespaces use: ASCII
/// alphanumerics plus `_ / : - .`.
const fn substrate_entries_are_sql_literal_safe(list: &[&str]) -> bool {
    let mut i = 0;
    while i < list.len() {
        let bytes = list[i].as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut j = 0;
        while j < bytes.len() {
            let c = bytes[j];
            if !(c.is_ascii_alphanumeric()
                || c == b'_'
                || c == b'/'
                || c == b':'
                || c == b'-'
                || c == b'.')
            {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    substrate_entries_are_sql_literal_safe(SUBSTRATE_NAMESPACE_PREFIXES),
    "SUBSTRATE_NAMESPACE_PREFIXES entry is not safe to splice into SQL (#3345)"
);
const _: () = assert!(
    substrate_entries_are_sql_literal_safe(SUBSTRATE_NAMESPACES_EXACT),
    "SUBSTRATE_NAMESPACES_EXACT entry is not safe to splice into SQL (#3345)"
);

/// The unqualified column every [`SQL_AND_NOT_SUBSTRATE`] call site selects
/// from (`memories.namespace`, never aliased at these sites).
pub const SQL_NAMESPACE_COLUMN: &str = "namespace";

/// v1.0.0 #3345 — the SQL form of [`is_substrate_namespace`], as a trailing
/// ` AND NOT (...)` fragment over an unqualified `namespace` column.
///
/// ## Why a SQL twin of a Rust predicate exists at all
///
/// #3348 withheld substrate rows from every ambient READ. It could do that in
/// Rust because every read funnel materialises its rows first. The embedding
/// backfill cannot: it is a `SELECT ... WHERE embedding IS NULL LIMIT n` whose
/// whole job is to choose which rows to spend money on, so a Rust-side filter
/// applied after the scan would still hand the substrate rows to the embedder
/// on the next page — the posture has to be IN the predicate, and therefore in
/// SQL.
///
/// Derived from the SAME two const lists [`is_substrate_namespace`] reads, so
/// a namespace added to the substrate SSOT inherits the no-embed posture with
/// no second list to keep in sync. The compile-time
/// [`substrate_entries_are_sql_literal_safe`] assertions above are what make
/// the splice sound.
///
/// ## Portability
///
/// `substr(col, 1, n)` and `IN (...)` are the intersection of SQLite and
/// PostgreSQL, so ONE fragment serves both backends. Deliberately NOT
/// `LIKE '_curator/%'`: `_` is a single-character LIKE WILDCARD in both
/// engines, so the obvious spelling would also match `Xcurator/…` — the exact
/// class of silent over-match that would withhold an ordinary caller namespace
/// from the embedder and quietly degrade that caller's recall.
///
/// ## Sargability
///
/// The fragment is a function-of-column predicate and therefore not index-
/// seekable, by design: it is always ANDed onto an already-selective
/// `embedding IS NULL` scan whose result set is exactly what it shrinks. The
/// cost it adds is one `substr` per candidate row; the cost it removes is a
/// paid embedding call per substrate row.
pub static SQL_AND_NOT_SUBSTRATE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| substrate_exclusion_sql(SQL_NAMESPACE_COLUMN));

/// v1.0.0 #3345 — the POSITIVE SQL twin of [`is_substrate_namespace`]: a bare
/// boolean expression over an unqualified `namespace` column, true exactly for
/// the rows that predicate accepts. [`SQL_AND_NOT_SUBSTRATE`] is its negation;
/// the count surfaces (`stats.substrate`) use it directly, so "hidden from the
/// embedder" and "counted as substrate" can never describe different row sets.
pub static SQL_IS_SUBSTRATE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| substrate_match_sql(SQL_NAMESPACE_COLUMN));

/// v1.0.0 #3345 — build the substrate-matching boolean expression for
/// `column`. Public for the truth-table tests and for any future call site
/// that qualifies the column differently; production reads the cached
/// [`SQL_IS_SUBSTRATE`] / [`SQL_AND_NOT_SUBSTRATE`].
#[must_use]
pub fn substrate_match_sql(column: &str) -> String {
    let exact = SUBSTRATE_NAMESPACES_EXACT
        .iter()
        .map(|ns| format!("'{ns}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut clauses = Vec::with_capacity(SUBSTRATE_NAMESPACE_PREFIXES.len() + 1);
    clauses.push(format!("{column} IN ({exact})"));
    for prefix in SUBSTRATE_NAMESPACE_PREFIXES {
        clauses.push(format!(
            "substr({column}, 1, {len}) = '{prefix}'",
            len = prefix.len()
        ));
    }
    clauses.join(" OR ")
}

/// v1.0.0 #3345 — build the ` AND NOT (...)` substrate-exclusion fragment for
/// `column`, as the negation of [`substrate_match_sql`].
#[must_use]
pub fn substrate_exclusion_sql(column: &str) -> String {
    format!(" AND NOT ({})", substrate_match_sql(column))
}

/// v1.0.0 #3507 — bound-parameter dialect for a visibility SQL fragment that
/// BOTH backends splice into their own queries.
///
/// The visibility predicate itself (`crate::storage::visibility_clause`) is
/// engine-agnostic: it reads only the `scope_idx` / `agent_id_idx` /
/// `target_agent_id_idx` generated columns and `namespace`, all of which are
/// declared with the SAME projection expressions in the sqlite migration
/// ladder (v10 / v14 / v67) and in `src/store/postgres_schema.sql`. The one
/// thing that is NOT portable is how a bound parameter is spelled, so that —
/// and only that — is what this enum selects. Keeping ONE generator with a
/// dialect knob is the #951 rule applied to SQL: a second, hand-written pg
/// copy of the predicate is exactly the drift this project treats as a defect.
///
/// `Postgres` renders an explicit `::text` cast because a bare `$n` in an
/// `IS NULL` / `replace(...)` position gives the planner no type to infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlParamStyle {
    /// `?n` — SQLite / `rusqlite` positional parameters.
    Sqlite,
    /// `$n::text` — PostgreSQL / `sqlx` numbered parameters.
    Postgres,
}

impl SqlParamStyle {
    /// Render bound TEXT parameter number `n` in this dialect.
    #[must_use]
    pub fn text_param(self, n: usize) -> String {
        match self {
            Self::Sqlite => format!("?{n}"),
            Self::Postgres => format!("${n}::text"),
        }
    }
}

/// v1.0.0 #3348 — is `ns` a substrate-owned namespace?
#[must_use]
pub fn is_substrate_namespace(ns: &str) -> bool {
    SUBSTRATE_NAMESPACES_EXACT.contains(&ns)
        || SUBSTRATE_NAMESPACE_PREFIXES
            .iter()
            .any(|p| ns.starts_with(p))
}

/// v1.0.0 #3348 — did the request EXPLICITLY name a substrate namespace?
///
/// An explicit namespace is the opt-in: `ai-memory inbox` and
/// `recall --namespace _messages/ai:me` both name the namespace they want, so
/// they keep working. An UNSCOPED read (`namespace = None`) never reaches
/// substrate rows.
#[must_use]
pub fn substrate_namespace_requested(requested: Option<&str>) -> bool {
    requested.is_some_and(is_substrate_namespace)
}

/// v1.0.0 #3345 — the LISTING form of [`substrate_namespace_requested`].
///
/// A namespace listing (`GET /api/v1/namespaces?prefix=…`) is filtered by a
/// HIERARCHICAL prefix rather than an exact namespace, so the opt-in has to
/// recognise a prefix that leads INTO substrate space as well as one that
/// names it: `?prefix=_curator` must reach `_curator/reports` exactly as
/// `?prefix=_curator/reports` does, or the opt-in would be a trap that
/// silently returns an empty page for a perfectly reasonable request.
///
/// An EMPTY prefix is not an opt-in — every namespace has it as an ancestor,
/// so honouring it would re-open the ambient listing this closes.
#[must_use]
pub fn substrate_listing_requested(prefix: Option<&str>) -> bool {
    prefix.is_some_and(|p| {
        !p.is_empty()
            && (is_substrate_namespace(p)
                || SUBSTRATE_NAMESPACE_PREFIXES
                    .iter()
                    .any(|sp| sp.starts_with(p))
                || SUBSTRATE_NAMESPACES_EXACT
                    .iter()
                    .any(|ns| ns.starts_with(p)))
    })
}

/// v1.0.0 #3348 — the canonical read-surface predicate. Every ambient read
/// funnel (`recall`, `search`, `list`, `boot`/`session_start`, on BOTH backends)
/// routes through this instead of applying [`is_visible_to_caller`] only when a
/// caller happens to be resolvable.
///
/// ## The defect this closes
///
/// `caller: Option<&str>` carried a "`None` = single-tenant, trust ALL rows"
/// contract, and every read funnel implemented it as
/// `match caller { Some(c) => filter, None => passthrough }`. On a SHARED store
/// (the dogfood setup: three agents, one sqlite file) that made an unscoped
/// `recall` return every other agent's `_messages/<them>` inbox mail and the
/// `_agents` registry, ranked above the operator's own memories — a cross-agent
/// disclosure of A2A traffic dressed up as ordinary memories.
///
/// ## The posture
///
/// - A substrate row NEVER surfaces on an UNSCOPED read, whatever its scope.
///   This is what closes the `_agents` half: those rows can legitimately carry a
///   broad scope, so the scope predicate alone would still return them.
/// - Once the request names the substrate namespace explicitly, the row is
///   subject to the ordinary [`is_visible_to_caller`] gate, so a caller still
///   only sees their own mail.
/// - Past the ambient gate the historical contract is BYTE-IDENTICAL: `None`
///   still trusts all, `Some(c)` still applies the canonical predicate. Only
///   the AMBIENT reach of substrate namespaces changes, so single-tenant
///   deployments and every ordinary namespace behave exactly as before.
///
/// The opt-in the issue asks for is satisfied by NAMING the namespace, which
/// needs no new knob (and therefore no MCP-schema / param-census / docs SSOT
/// churn). An operator-wide `--include-system` override would lift exactly the
/// first check below and nothing else — the per-row [`is_visible_to_caller`]
/// gate is never lifted, by anyone.
#[must_use]
pub fn is_readable_on_query(
    mem: &Memory,
    caller: Option<&str>,
    requested_namespace: Option<&str>,
) -> bool {
    if is_substrate_namespace(&mem.namespace) && !substrate_namespace_requested(requested_namespace)
    {
        return false;
    }
    // Past the ambient gate the historical contract is unchanged: `Some(c)`
    // applies the canonical predicate, `None` is the documented single-tenant
    // trust-all posture.
    //
    // An earlier draft ALSO denied substrate rows to a `None` caller here.
    // That broke `ai-memory inbox` for every single-tenant operator: with no
    // `AI_MEMORY_AGENT_ID` set there is no caller to match `target_agent_id`
    // against, so naming your OWN inbox returned nothing. Caught by
    // `cli::boot::tests::boot_fetch_honours_an_explicit_inbox_namespace_3348`.
    //
    // RESIDUAL, stated rather than hidden: on a SHARED store with no configured
    // identity, explicitly naming `_messages/<someone-else>` still returns their
    // mail. That is the pre-existing `caller == None` trust-all contract
    // (#951/#1720), not something #3348 introduces, and narrowing it would
    // change every read surface for single-tenant deployments. #3348 closes the
    // AMBIENT disclosure — the one that needed no knowledge of the victim and
    // fired on a bare `recall`.
    match caller {
        Some(c) => is_visible_to_caller(mem, c),
        None => true,
    }
}

#[cfg(test)]
mod substrate_visibility_3348_tests {
    //! v1.0.0 #3348 — the substrate-namespace read posture.
    //!
    //! Reported on a shared sqlite store used by three agents: an unscoped
    //! `ai-memory recall` returned rows from `_messages/ai:fable`,
    //! `_messages/grok-build` and `_messages/ai:grok@pop-os` — other agents'
    //! A2A inbox mail — ranked ABOVE the operator's own memory, and
    //! `--as-agent <other>` additionally returned `_agents` registry rows.
    //!
    //! Every assertion here FAILS against the pre-#3348 predicate, which had
    //! no substrate notion at all and treated `caller == None` as trust-all.
    use super::*;
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use serde_json::json;

    fn row(namespace: &str, metadata: serde_json::Value) -> Memory {
        Memory {
            id: "m-3348".to_string(),
            tier: Tier::Long,
            namespace: namespace.to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: "2026-09-03T00:00:00Z".to_string(),
            updated_at: "2026-09-03T00:00:00Z".to_string(),
            metadata,
            memory_kind: MemoryKind::Observation,
            confidence_source: ConfidenceSource::CallerProvided,
            version: 1,
            ..Memory::default()
        }
    }

    /// A message delivered to `ai:other`: private by default, owned by the
    /// sender, addressed to the recipient via `target_agent_id`.
    fn inbox_row(recipient: &str) -> Memory {
        row(
            &format!("_messages/{recipient}"),
            json!({"agent_id": "ai:sender", "target_agent_id": recipient}),
        )
    }

    #[test]
    fn substrate_namespaces_are_recognised_3348() {
        for ns in [
            "_messages/ai:fable",
            "_messages/grok-build",
            "_inbox/ai:me",
            "_curator/reports",
            "_curator/rollback",
            "_subscriptions/ai:me",
            "_standard:proj/ns",
            "_agents",
            "_agent_sessions",
            "_standards",
        ] {
            assert!(
                is_substrate_namespace(ns),
                "#3348: `{ns}` is substrate bookkeeping, not a caller's knowledge"
            );
        }
        for ns in [
            "ai-memory-mcp",
            "fable-grok",
            "proj/team",
            // `_shared/<from>-><to>` is the `ai-memory share` DELIVERY
            // destination — a user-facing feature whose whole point is that the
            // recipient recalls the row ambiently. Deliberately NOT substrate.
            "_shared/ai:a->ai:b",
        ] {
            assert!(
                !is_substrate_namespace(ns),
                "#3348: `{ns}` must keep the ordinary read posture"
            );
        }
    }

    /// THE REPORTED DEFECT — an unscoped read with no resolvable identity used
    /// to return every row. Other agents' inbox mail must not surface.
    #[test]
    fn unscoped_read_withholds_other_agents_inbox_mail_3348() {
        let mail = inbox_row("ai:other");
        assert!(
            !is_readable_on_query(&mail, None, None),
            "#3348: an UNSCOPED recall/search/boot must not return `_messages/*` \
             mail addressed to somebody else — pre-fix `caller == None` meant \
             trust-all and this row ranked above the operator's own memories"
        );
        assert!(
            !is_readable_on_query(&mail, Some("ai:me"), None),
            "#3348: naming an identity does not make another agent's mail an \
             ambient result either"
        );
        // The ambient gate is what #3348 closes. Past it the historical
        // `caller == None` trust-all contract is deliberately unchanged — see
        // the RESIDUAL note on `is_readable_on_query`.
        assert!(
            is_readable_on_query(&mail, None, Some("_messages/ai:other")),
            "#3348 deliberately does NOT narrow the pre-existing single-tenant \
             trust-all posture for an explicitly named namespace; narrowing it \
             would break `ai-memory inbox` wherever AI_MEMORY_AGENT_ID is unset"
        );
    }

    /// The `_agents` half: a registry row can legitimately carry a BROAD scope,
    /// so the scope predicate alone would still return it. The substrate rule
    /// is what closes this.
    #[test]
    fn unscoped_read_withholds_registry_rows_even_when_collective_3348() {
        let registry = row(
            "_agents",
            json!({"agent_id": "ai:sender", "scope": "collective"}),
        );
        assert!(
            is_visible_to_caller(&registry, "ai:anyone"),
            "precondition: the scope predicate alone WOULD return this row"
        );
        assert!(
            !is_readable_on_query(&registry, Some("ai:anyone"), None),
            "#3348: `--as-agent <other>` returned `_agents` registry rows as \
             ordinary memories; a broad scope must not make substrate \
             bookkeeping ambient"
        );
    }

    /// Naming the namespace is the opt-in — this is how `ai-memory inbox` and
    /// `recall --namespace _messages/ai:me` keep working.
    #[test]
    fn explicit_substrate_namespace_returns_your_own_mail_3348() {
        let mine = inbox_row("ai:me");
        assert!(
            is_readable_on_query(&mine, Some("ai:me"), Some("_messages/ai:me")),
            "#3348: the recipient reading their OWN inbox by name must still work"
        );
    }

    /// The opt-in lifts the AMBIENT exclusion only. The per-row owner/inbox
    /// gate is never lifted, so naming someone else's inbox returns nothing.
    #[test]
    fn explicit_substrate_namespace_still_confines_to_the_addressee_3348() {
        let theirs = inbox_row("ai:other");
        assert!(
            !is_readable_on_query(&theirs, Some("ai:me"), Some("_messages/ai:other")),
            "#3348: naming another agent's inbox namespace must NOT hand over \
             their mail — the canonical owner/inbox predicate still applies"
        );
    }

    /// Ordinary namespaces keep the historical contract BYTE-FOR-BYTE, so a
    /// single-tenant deployment sees no behaviour change from #3348.
    #[test]
    fn ordinary_namespaces_keep_the_historical_posture_3348() {
        let private_row = row("ai-memory-mcp", json!({"agent_id": "ai:someone"}));
        assert!(
            is_readable_on_query(&private_row, None, None),
            "#3348 must not change the single-tenant `caller == None` trust-all \
             posture for ordinary namespaces"
        );
        assert!(
            !is_readable_on_query(&private_row, Some("ai:other"), None),
            "#3348 must not weaken the #1720 owner-keyed private gate either"
        );
        assert!(
            is_readable_on_query(&private_row, Some("ai:someone"), None),
            "the owner still reads their own row"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConfidenceSource, Memory, MemoryKind, Tier};
    use serde_json::json;

    fn mem_with_metadata(metadata: serde_json::Value) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "test-id".to_string(),
            tier: Tier::Long,
            namespace: "test-ns".to_string(),
            title: "test".to_string(),
            content: "test".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-05-20T00:00:00Z".to_string(),
            updated_at: "2026-05-20T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    #[test]
    fn private_default_owner_can_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice"}));
        assert!(is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn private_default_non_owner_cannot_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice"}));
        assert!(!is_visible_to_caller(&m, "bob"));
    }

    #[test]
    fn explicit_private_owner_can_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "private"}));
        assert!(is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn explicit_private_non_owner_cannot_see() {
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "private"}));
        assert!(!is_visible_to_caller(&m, "bob"));
    }

    #[test]
    fn shared_scope_anyone_can_see() {
        // #1921 — an UNKNOWN / legacy scope string ("shared") stays broadly
        // visible: this is the documented federation shareable-shape posture
        // (#948 / #978, `scope=shared` projects to any allowlisted peer).
        // #1921 deliberately does NOT tighten this arm — only team/unit/org
        // move to subtree enforcement.
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "shared"}));
        assert!(is_visible_to_caller(&m, "bob"));
        assert!(is_visible_to_caller(&m, "carol"));
    }

    #[test]
    fn collective_scope_anyone_can_see() {
        // `collective` is the ONLY scope that is genuinely world-readable.
        let m = mem_with_metadata(json!({"agent_id": "alice", "scope": "collective"}));
        assert!(is_visible_to_caller(&m, "bob"));
        assert!(is_visible_to_caller(&m, "carol"));
    }

    // ---- #1921 ADVERSARIAL: team/unit/org are subtree-restricted -------
    //
    // Reproduces the CWE-863 exploit: a co-tenant caller in a DIFFERENT
    // namespace subtree lists/gets a victim's team/unit/org-scoped row.
    // Pre-fix `is_visible_to_caller` returned `true` unconditionally for
    // these scopes; post-fix the cross-subtree caller is DENIED while the
    // in-subtree caller is still allowed.

    #[test]
    fn team_scope_blocks_cross_subtree_caller_1921() {
        let m = mem_with_metadata(json!({"agent_id": "victimorg/unitB/teamC/x", "scope": "team"}));
        // The row lives in the victim's team namespace.
        let m = Memory {
            namespace: "victimorg/unitB/teamC/x".to_string(),
            ..m
        };
        // Attacker in an unrelated subtree: BLOCKED (was leaked pre-fix).
        assert!(
            !is_visible_to_caller(&m, "attackerorg/unitZ/teamZ/a"),
            "#1921: cross-subtree caller must NOT see a team-scoped row"
        );
        // A peer inside the SAME team subtree: allowed (legit team read).
        assert!(
            is_visible_to_caller(&m, "victimorg/unitB/teamC/y"),
            "#1921: same-team caller retains legitimate visibility"
        );
    }

    #[test]
    fn unit_and_org_scope_block_cross_subtree_caller_1921() {
        let base = mem_with_metadata(json!({"agent_id": "victimorg/unitB/teamC/x"}));
        let unit_row = Memory {
            namespace: "victimorg/unitB/teamC/x".to_string(),
            metadata: json!({"agent_id": "victimorg/unitB/teamC/x", "scope": "unit"}),
            ..base.clone()
        };
        let org_row = Memory {
            namespace: "victimorg/unitB/teamC/x".to_string(),
            metadata: json!({"agent_id": "victimorg/unitB/teamC/x", "scope": "org"}),
            ..base
        };
        // Different org entirely → BLOCKED for both unit and org scope.
        assert!(!is_visible_to_caller(&unit_row, "attackerorg/u/t/a"));
        assert!(!is_visible_to_caller(&org_row, "attackerorg/u/t/a"));
        // Same unit, different team → unit + org scope visible.
        assert!(is_visible_to_caller(&unit_row, "victimorg/unitB/teamD/z"));
        assert!(is_visible_to_caller(&org_row, "victimorg/unitX/teamY/z"));
        // Anonymous synthetic id (no `/`) → no ancestors → fail-closed.
        assert!(!is_visible_to_caller(&unit_row, "anonymous:req-abc123"));
        assert!(!is_visible_to_caller(&org_row, "anonymous:req-abc123"));
    }

    #[test]
    fn inbox_target_can_see_private_row() {
        // Inbox carve-out: sender stamps target_agent_id; recipient
        // reads their own inbox even though scope=private under
        // sender's ownership.
        let m = mem_with_metadata(json!({
            "agent_id": "alice",
            "scope": "private",
            "target_agent_id": "bob"
        }));
        assert!(is_visible_to_caller(&m, "bob"));
        // Non-target non-owner still blocked.
        assert!(!is_visible_to_caller(&m, "carol"));
    }

    #[test]
    fn empty_owner_blocks_named_caller() {
        // Legacy unowned (no agent_id) scope=private rows are NOT
        // visible to a named caller — the empty `owner` string
        // doesn't match "alice", so the predicate denies. (Higher-
        // level handler code interprets empty owner as
        // "unowned-legacy" and may treat that as claimable, but
        // the predicate itself is strict-equality.)
        let m = mem_with_metadata(json!({"scope": "private"}));
        assert!(!is_visible_to_caller(&m, "alice"));
    }

    #[test]
    fn empty_owner_visible_to_empty_caller_edge_case() {
        // The "" == "" equality is a degenerate edge case — handler
        // callers always synthesize a non-empty principal
        // (`anonymous:req-<uuid>` or X-Agent-Id), so this branch
        // would only fire on a misconfigured caller chain. Document
        // the behavior so a future refactor doesn't tighten it
        // without understanding the call-site contract.
        let m = mem_with_metadata(json!({"scope": "private"}));
        assert!(is_visible_to_caller(&m, ""));
    }

    #[test]
    fn caller_owns_for_mutation_1786() {
        // Unstamped row → ANYONE may mutate (single-tenant-safe: legacy/unowned
        // rows are not locked out). This is the deliberate lenience that keeps
        // the single-operator default working.
        let unstamped = mem_with_metadata(json!({}));
        assert!(caller_owns_for_mutation(&unstamped, "ai:alice", false));

        // Self-owned → ok; cross-owner → REFUSED (the gap #1786 closes).
        let alice = mem_with_metadata(json!({"agent_id": "ai:alice"}));
        assert!(caller_owns_for_mutation(&alice, "ai:alice", false));
        assert!(!caller_owns_for_mutation(&alice, "ai:bob", false));

        // Daemon principal bypasses (curator / internal mutations).
        assert!(caller_owns_for_mutation(
            &alice,
            crate::identity::sentinels::DAEMON_PRINCIPAL,
            false
        ));

        // Inbox carve-out applies ONLY when allow_inbox=true (delete-side).
        let inbox = mem_with_metadata(json!({
            "agent_id": "ai:alice",
            "target_agent_id": "ai:bob"
        }));
        assert!(
            !caller_owns_for_mutation(&inbox, "ai:bob", false),
            "no inbox carve-out without allow_inbox"
        );
        assert!(
            caller_owns_for_mutation(&inbox, "ai:bob", true),
            "inbox recipient may mutate with allow_inbox"
        );
    }
}

#[cfg(test)]
mod legacy_inbox_3401_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_recipient_is_bound_to_namespace_and_cannot_override_target_3401() {
        let mut memory = Memory {
            namespace: "_messages/ai:recipient".into(),
            metadata: json!({"agent_id": "ai:sender", "recipient_agent_id": "ai:recipient"}),
            ..Default::default()
        };
        assert!(is_visible_to_caller(&memory, "ai:recipient"));
        assert!(!is_visible_to_caller(&memory, "ai:other"));
        assert!(!is_readable_on_query(&memory, Some("ai:recipient"), None));
        assert!(is_readable_on_query(
            &memory,
            Some("ai:recipient"),
            Some("_inbox/ai:recipient")
        ));
        memory.namespace = "ordinary".into();
        assert!(!is_visible_to_caller(&memory, "ai:recipient"));
        memory.namespace = "_messages/ai:recipient".into();
        memory.metadata[crate::META_KEY_TARGET_AGENT_ID] = json!("ai:other");
        assert!(!is_visible_to_caller(&memory, "ai:recipient"));
    }
}

#[cfg(test)]
mod substrate_sql_3345_tests {
    //! v1.0.0 #3345 — the SQL twin of [`super::is_substrate_namespace`] must
    //! accept EXACTLY the namespaces the Rust predicate accepts.
    //!
    //! The failure this pins is not hypothetical: the obvious spelling
    //! (`namespace LIKE '_curator/%'`) silently over-matches, because `_` is a
    //! single-character LIKE wildcard in both SQLite and PostgreSQL — it would
    //! also match `Xcurator/…`, withholding an ordinary caller's namespace from
    //! the embedder and quietly degrading their recall to keyword-only.

    use super::{
        SQL_AND_NOT_SUBSTRATE, SQL_IS_SUBSTRATE, is_substrate_namespace,
        substrate_listing_requested,
    };

    /// A corpus that spans every substrate shape plus the near-misses that a
    /// wildcard or a bare `starts_with` would wrongly capture.
    const CORPUS: &[&str] = &[
        "_curator/reports",
        "_curator/reports/daily",
        "_curator/rollback",
        "_messages/ai:carol",
        "_inbox/ai:carol",
        "_subscriptions/ai:carol",
        "_standard:proj",
        "_agents",
        "_agent_sessions",
        "_standards",
        // Near-misses — every one of these is an ORDINARY namespace.
        "Xcurator/reports",
        "acurator/reports",
        "_curator",
        "_agentsx",
        "_shared/alice->bob",
        "proj/notes",
        "team/_messages",
        "global",
    ];

    #[test]
    fn the_sql_predicate_matches_the_rust_predicate_row_for_row() {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        conn.execute("CREATE TABLE memories (namespace TEXT NOT NULL)", [])
            .expect("create");
        for ns in CORPUS {
            conn.execute("INSERT INTO memories (namespace) VALUES (?1)", [ns])
                .expect("insert");
        }

        let mut stmt = conn
            .prepare(&format!(
                "SELECT namespace FROM memories WHERE {} ORDER BY namespace",
                *SQL_IS_SUBSTRATE
            ))
            .expect("prepare match");
        let sql_matched: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");

        let mut rust_matched: Vec<String> = CORPUS
            .iter()
            .filter(|ns| is_substrate_namespace(ns))
            .map(|ns| (*ns).to_string())
            .collect();
        rust_matched.sort();

        assert_eq!(
            sql_matched, rust_matched,
            "#3345: the SQL and Rust forms of the substrate posture must not drift"
        );
        assert!(
            !sql_matched.iter().any(|ns| ns == "Xcurator/reports"),
            "#3345: `_` must not behave as a LIKE wildcard — an ordinary namespace \
             one character away from a substrate one must stay embeddable"
        );
    }

    #[test]
    fn the_exclusion_fragment_is_the_exact_complement() {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        conn.execute("CREATE TABLE memories (namespace TEXT NOT NULL)", [])
            .expect("create");
        for ns in CORPUS {
            conn.execute("INSERT INTO memories (namespace) VALUES (?1)", [ns])
                .expect("insert");
        }
        // The fragment is written to be ANDed onto an existing WHERE clause.
        let kept: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM memories WHERE 1 = 1{}",
                    *SQL_AND_NOT_SUBSTRATE
                ),
                [],
                |r| r.get(0),
            )
            .expect("count");
        let expected = i64::try_from(
            CORPUS
                .iter()
                .filter(|ns| !is_substrate_namespace(ns))
                .count(),
        )
        .expect("fits i64");
        assert_eq!(
            kept, expected,
            "#3345: the exclusion fragment must keep exactly the non-substrate rows"
        );
    }

    #[test]
    fn a_listing_prefix_opts_in_by_naming_or_leading_into_substrate_space() {
        assert!(substrate_listing_requested(Some("_curator/reports")));
        assert!(
            substrate_listing_requested(Some("_curator")),
            "an ANCESTOR prefix must opt in, or `?prefix=_curator` is a trap \
             that returns an empty page"
        );
        assert!(substrate_listing_requested(Some("_agents")));
        assert!(!substrate_listing_requested(Some("proj")));
        assert!(
            !substrate_listing_requested(Some("")),
            "an empty prefix is an ancestor of everything — honouring it would \
             re-open the ambient listing this closes"
        );
        assert!(!substrate_listing_requested(None));
    }
}

#[cfg(test)]
mod sql_param_style_3507_tests {
    //! v1.0.0 #3507 — the ONE visibility-clause generator serves both
    //! backends, and only the parameter dialect differs.
    //!
    //! Two properties are load-bearing and neither is obvious from reading
    //! the generator:
    //!
    //! 1. the SQLite rendering is BYTE-IDENTICAL to the pre-#3507 literal, so
    //!    adding the dialect knob cannot have silently changed what `recall`,
    //!    `search`, `list` and the source-uri paths admit;
    //! 2. the PostgreSQL rendering differs from it ONLY by substituting `?n`
    //!    with `$n::text` — if a future edit spelled the pg predicate
    //!    differently in any other way, the two backends would start
    //!    disagreeing about visibility, which is the #951 drift this crate
    //!    treats as a defect.

    use super::SqlParamStyle;

    /// The verbatim pre-#3507 SQLite rendering for `(start = 4, caller = 8,
    /// alias = "m")` — the shape `crate::storage::list_by_source_uri` binds.
    /// Frozen as a literal on purpose: deriving it from the generator would
    /// make the assertion a tautology.
    const FROZEN_SQLITE_4_8_M: &str = "AND (\
            ?4 IS NULL \
            OR m.scope_idx = 'collective' \
            OR (m.scope_idx = 'private' AND ?8 IS NOT NULL AND (m.agent_id_idx = ?8 OR m.target_agent_id_idx = ?8)) \
            OR (m.scope_idx = 'team' AND ?5 IS NOT NULL AND (m.namespace = ?5 OR m.namespace LIKE replace(replace(?5, '%', '\\%'), '_', '\\_') || '/%' ESCAPE '\\')) \
            OR (m.scope_idx = 'unit' AND ?6 IS NOT NULL AND (m.namespace = ?6 OR m.namespace LIKE replace(replace(?6, '%', '\\%'), '_', '\\_') || '/%' ESCAPE '\\')) \
            OR (m.scope_idx = 'org'  AND ?7  IS NOT NULL AND (m.namespace = ?7  OR m.namespace LIKE replace(replace(?7, '%', '\\%'), '_', '\\_') || '/%' ESCAPE '\\'))\
        )";

    #[test]
    fn sqlite_rendering_is_byte_identical_to_the_pre_3507_literal() {
        assert_eq!(
            crate::storage::visibility_clause(SqlParamStyle::Sqlite, 4, 8, "m"),
            FROZEN_SQLITE_4_8_M,
            "#3507: the dialect knob must not have changed the SQLite predicate — \
             every existing recall/search/list call site renders through it"
        );
    }

    #[test]
    fn postgres_rendering_differs_only_in_parameter_dialect() {
        let sqlite = crate::storage::visibility_clause(SqlParamStyle::Sqlite, 4, 8, "m");
        let postgres = crate::storage::visibility_clause(SqlParamStyle::Postgres, 4, 8, "m");
        assert_ne!(sqlite, postgres, "the two dialects must not be identical");
        // Rewrite the sqlite form into the pg dialect and demand equality.
        // Highest index first so `?4` cannot be rewritten before `?8`.
        let mut rewritten = sqlite;
        for n in (4..=8).rev() {
            rewritten = rewritten.replace(&format!("?{n}"), &format!("${n}::text"));
        }
        assert_eq!(
            rewritten, postgres,
            "#3507: the postgres predicate must differ from the sqlite one ONLY by \
             the bound-parameter spelling — any other divergence makes the two \
             backends disagree about who can read what"
        );
    }

    #[test]
    fn text_param_renders_each_dialect() {
        assert_eq!(SqlParamStyle::Sqlite.text_param(3), "?3");
        assert_eq!(SqlParamStyle::Postgres.text_param(3), "$3::text");
    }
}
