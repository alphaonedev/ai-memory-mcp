// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3124 — the ONE cross-backend definition of an **unstamped**
//! (legacy-unowned) memory row, and the ONE knob that decides whether a
//! caller-scoped MUTATION of such a row is admitted.
//!
//! ## Why this module exists
//!
//! Before #3124 the two backends disagreed on what a row with no ownership
//! stamp means for a caller-scoped mutation. Postgres refused it on its trait
//! `update` / `delete` / If-Match `PUT` / `archive_by_ids` (#1412 / #1628);
//! sqlite admitted it on every funnel (the documented legacy-unowned
//! carve-out), and even the definition of "unstamped" differed — the sqlite
//! Rust gates read `metadata.agent_id` through `as_str()` (a NON-string owner
//! counted as unstamped and was mutable by anyone), while the sqlite SQL arms
//! and every postgres `->>` probe counted the same row as owned.
//!
//! The T9 5-agent vote on #3124 (3–2 APPROVE migrate-then-refuse, with binding
//! dissent constraints) and #3115's 3-0 "a parity PR restores each backend"
//! ruling fix the shape implemented here:
//!
//! 1. **One definition** ([`OwnerStamp::of`]): a row is *stamped* iff
//!    `metadata.agent_id` is a NON-EMPTY JSON STRING. A missing key, JSON
//!    `null` and `""` are *unstamped*. A present NON-string value is
//!    *malformed*: it is never an owner a caller can match, and it is never
//!    admitted as unstamped either — so a malformed row is mutable by nobody
//!    but the admin lanes on BOTH backends (fail-closed; never a loosening).
//! 2. **One knob** ([`ENV_UNSTAMPED_MUTATION`], [`UnstampedMutationMode`]):
//!    `warn` (the default) changes NO funnel's allow/refuse outcome on either
//!    backend — postgres keeps refusing where #1628 refuses, so the default is
//!    never a fail-open relaxation — and every mutation it DOES admit on an
//!    unstamped row emits a structured WARN (`target: authz.unstamped`) plus
//!    the `ai_memory_unstamped_mutation_allowed_total{backend,funnel}` counter.
//!    `refuse` refuses an unstamped row on EVERY caller-scoped mutation funnel
//!    of both backends. Any other token REFUSES boot ([`validate_boot_token`],
//!    Conductor ruling condition 1); a library caller that skips the boot
//!    check still resolves it to `refuse` (an unrecognised token must never
//!    silently widen a security control — the #131 / FBL-14 rule).
//!    `asi-hard` pins `refuse`.
//!
//! The migration path the vote requires is operator-driven: `ai-memory doctor`
//! counts unstamped + malformed rows, the operator re-owns them with
//! `ai-memory reown`, and the compiled default flips to `refuse` in v1.x once
//! the census reads 0. Nothing here stamps a row automatically — inventing an
//! owner would be a lie about authorship (vote constraint 1).
//!
//! Admin / operator lanes (`CallerContext::bypass_visibility`) never reach
//! this module: they are not caller-scoped mutations.
//!
//! ## What is deliberately NOT here
//!
//! READ paths keep their pre-#3124 predicate ([`crate::visibility`]'s
//! archive-listing twin); this module governs mutation admission only.

use serde_json::Value;

use crate::storage::schema_guard::{BACKEND_POSTGRES, BACKEND_SQLITE};

/// Env knob selecting the unstamped-row mutation posture.
pub const ENV_UNSTAMPED_MUTATION: &str = "AI_MEMORY_UNSTAMPED_MUTATION";

/// `tracing` target for every unstamped-row admission / refusal record.
pub const TRACE_TARGET: &str = "authz.unstamped";

/// Wire token for [`UnstampedMutationMode::Warn`].
pub const MODE_WARN: &str = "warn";
/// Wire token for [`UnstampedMutationMode::Refuse`].
pub const MODE_REFUSE: &str = "refuse";

/// Backend label for the sqlite adapter (the schema-guard SSOT spelling).
pub const BACKEND_LABEL_SQLITE: &str = BACKEND_SQLITE;
/// Backend label for the postgres adapter (the schema-guard SSOT spelling).
pub const BACKEND_LABEL_POSTGRES: &str = BACKEND_POSTGRES;

/// The closed set of mutation-funnel labels carried on the counter. Closed so
/// the metric's label cardinality is bounded by the source, never by traffic.
pub mod funnel {
    /// Memory update (trait `update`, HTTP `PUT`, MCP `memory_update`).
    pub const UPDATE: &str = "update";
    /// Memory delete (trait `delete`, HTTP `DELETE`, MCP `memory_delete`).
    pub const DELETE: &str = "delete";
    /// Promote (tier / namespace promotion).
    pub const PROMOTE: &str = "promote";
    /// Link creation (source-owner gate).
    pub const LINK: &str = "link";
    /// Link deletion.
    pub const UNLINK: &str = "unlink";
    /// Archive (live row → cold storage).
    pub const ARCHIVE: &str = "archive";
    /// Archive restore (cold storage → live row).
    pub const RESTORE: &str = "restore";
    /// Owner-scoped forget by filter.
    pub const FORGET: &str = "forget";
    /// Consolidation (source admission + synthesis pool).
    pub const CONSOLIDATE: &str = "consolidate";
    /// Knowledge-graph edge invalidation.
    pub const KG_INVALIDATE: &str = "kg_invalidate";
    /// Auto-tag (rewrites the row's tags).
    pub const AUTO_TAG: &str = "auto_tag";
    /// Share (cross-agent delivery of a source row).
    pub const SHARE: &str = "share";
    /// Swarm rewind (root-row gate).
    pub const SWARM_REWIND: &str = "swarm_rewind";
    /// Store-time synthesis pool (supersede / merge candidates).
    pub const SYNTHESIS: &str = "synthesis";
}

/// Where a mutation decision is taken: the backend + funnel labels carried on
/// the #3124 observability counter. `const` constructors so call sites name
/// their site as a compile-time constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationSite {
    /// Backend label ([`BACKEND_LABEL_SQLITE`] / [`BACKEND_LABEL_POSTGRES`]).
    pub backend: &'static str,
    /// Funnel label (one of the [`funnel`] consts).
    pub funnel: &'static str,
}

impl MutationSite {
    /// A site on an explicit backend label (e.g. `StorageBackend::as_str()`).
    #[must_use]
    pub const fn new(backend: &'static str, funnel: &'static str) -> Self {
        Self { backend, funnel }
    }

    /// A sqlite-backend site.
    #[must_use]
    pub const fn sqlite(funnel: &'static str) -> Self {
        Self::new(BACKEND_LABEL_SQLITE, funnel)
    }

    /// A postgres-backend site.
    #[must_use]
    pub const fn postgres(funnel: &'static str) -> Self {
        Self::new(BACKEND_LABEL_POSTGRES, funnel)
    }
}

/// The ownership stamp carried by a row's `metadata.agent_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerStamp<'a> {
    /// A non-empty JSON string — the row's provable owner.
    Stamped(&'a str),
    /// Missing key, JSON `null`, or `""` — no owner was ever recorded.
    Unstamped,
    /// A present, NON-string value (number, bool, object, array). Never an
    /// owner a caller can match, never admitted as unstamped (fail-closed).
    Malformed,
}

impl<'a> OwnerStamp<'a> {
    /// Classify a row's `metadata` object (the one Rust-side definition).
    #[must_use]
    pub fn of(metadata: &'a Value) -> Self {
        match metadata.get(crate::META_KEY_AGENT_ID) {
            None | Some(Value::Null) => Self::Unstamped,
            Some(Value::String(s)) if s.is_empty() => Self::Unstamped,
            Some(Value::String(s)) => Self::Stamped(s.as_str()),
            Some(_) => Self::Malformed,
        }
    }

    /// Classify the postgres pair `(jsonb_typeof(metadata->'agent_id'),
    /// metadata->>'agent_id')` — see [`PG_OWNER_TYPE_SQL`]. Identical
    /// verdicts to [`Self::of`] over the same JSON.
    #[must_use]
    pub fn of_pg(json_type: Option<&str>, text: Option<&'a str>) -> Self {
        match json_type {
            None | Some("null") => Self::Unstamped,
            Some("string") => match text {
                Some(s) if !s.is_empty() => Self::Stamped(s),
                _ => Self::Unstamped,
            },
            Some(_) => Self::Malformed,
        }
    }

    /// `true` for [`Self::Unstamped`] only (a malformed row is NOT unstamped).
    #[must_use]
    pub fn is_unstamped(&self) -> bool {
        matches!(self, Self::Unstamped)
    }

    /// `true` iff the row is stamped with exactly `caller`.
    #[must_use]
    pub fn is_owned_by(&self, caller: &str) -> bool {
        matches!(self, Self::Stamped(owner) if *owner == caller)
    }

    /// The owner string for refusal envelopes / logs: the stamp, `""` for an
    /// unstamped row (the pre-#3124 wire shape), or [`MALFORMED_OWNER_LABEL`].
    #[must_use]
    pub fn owner_for_display(&self) -> &'a str {
        match self {
            Self::Stamped(owner) => owner,
            Self::Unstamped => "",
            Self::Malformed => MALFORMED_OWNER_LABEL,
        }
    }
}

/// Display label for a malformed (non-string) owner stamp in refusal
/// envelopes and logs. Angle-bracketed so it can never collide with a valid
/// agent id (`validate_agent_id` rejects `<`).
pub const MALFORMED_OWNER_LABEL: &str = "<malformed agent_id>";

/// The unstamped-row mutation posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnstampedMutationMode {
    /// Default: every funnel keeps its pre-#3124 outcome; admissions WARN.
    Warn,
    /// Refuse an unstamped row on every caller-scoped mutation funnel.
    Refuse,
}

impl UnstampedMutationMode {
    /// Parse one token. `None` = unset/blank (→ the compiled default);
    /// an unrecognised token → [`Self::Refuse`] (FBL-14: never widen). Boot
    /// refuses such a token outright ([`validate_boot_token`]); this arm is
    /// the fail-closed floor for a caller that skipped the boot check.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
            return Self::Warn;
        };
        // `refuse` and every unrecognised token resolve to Refuse — the
        // FBL-14 rule: a typo of either intent must never widen the gate.
        if raw.eq_ignore_ascii_case(MODE_WARN) {
            Self::Warn
        } else {
            Self::Refuse
        }
    }

    /// The canonical wire token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => MODE_WARN,
            Self::Refuse => MODE_REFUSE,
        }
    }

    /// `true` for [`Self::Refuse`].
    #[must_use]
    pub fn refuses(self) -> bool {
        matches!(self, Self::Refuse)
    }
}

/// `true` when `raw` is a token the resolver recognises (used by `doctor` to
/// report an unrecognised value that was resolved fail-closed to `refuse`).
#[must_use]
pub fn is_recognised_token(raw: &str) -> bool {
    let raw = raw.trim();
    raw.is_empty() || raw.eq_ignore_ascii_case(MODE_WARN) || raw.eq_ignore_ascii_case(MODE_REFUSE)
}

/// Boot-time grammar check for [`ENV_UNSTAMPED_MUTATION`] (Conductor ruling on
/// #3124, condition 1 — a mandate-class knob). The knob accepts exactly `warn`
/// | `refuse` (trimmed, case-insensitive; empty / unset = `warn`); any other
/// token, or a non-UTF-8 value, REFUSES boot naming the knob, the token and
/// the grammar. Called from the binary's pre-runtime phase for every verb but
/// `doctor` (which must stay runnable to diagnose the refusal). A library
/// caller that never runs this check still fails CLOSED: [`mode`] resolves an
/// unrecognised token to `refuse`.
///
/// # Errors
///
/// The value is set but is not a recognised token.
pub fn validate_boot_token() -> anyhow::Result<()> {
    match std::env::var(ENV_UNSTAMPED_MUTATION) {
        Ok(raw) if !is_recognised_token(&raw) => Err(anyhow::anyhow!(
            "{ENV_UNSTAMPED_MUTATION}={raw:?} is not a recognised value: accepted \
             {MODE_WARN} | {MODE_REFUSE} (case-insensitive; empty or unset = {MODE_WARN}) — \
             refusing to boot rather than guess the unstamped-row mutation posture (#3124)"
        )),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow::anyhow!(
            "{ENV_UNSTAMPED_MUTATION} is set to a non-UTF-8 value: accepted {MODE_WARN} | \
             {MODE_REFUSE} — refusing to boot (#3124)"
        )),
        _ => Ok(()),
    }
}

/// Resolve the process posture from [`ENV_UNSTAMPED_MUTATION`]. Read per call
/// (a mutation, never a hot read path) so an `asi-hard` boot pin and a test's
/// scoped env are both honoured without a seeding funnel to forget.
#[must_use]
pub fn mode() -> UnstampedMutationMode {
    UnstampedMutationMode::parse(std::env::var(ENV_UNSTAMPED_MUTATION).ok().as_deref())
}

/// The ONE admission decision for an UNSTAMPED row on a caller-scoped
/// mutation funnel whose pre-#3124 contract admitted it.
///
/// `warn` → `true`, with the WARN + counter; `refuse` → `false`, with a WARN
/// naming the refusal. Funnels that already refused an unstamped row before
/// #3124 (the postgres #1628 set) do not call this — they refuse in both modes.
#[must_use]
pub fn admit_unstamped(site: MutationSite, id: &str, caller: &str) -> bool {
    admit_unstamped_rows(site, id, caller, 1, mode())
}

/// The ONE ownership decision for a caller-scoped mutation of a row whose
/// `metadata` is `metadata`, on a funnel whose pre-#3124 contract admitted
/// unstamped rows (every sqlite funnel; the lenient postgres funnels):
///
/// * stamped with `caller` → admitted;
/// * `allow_inbox` and `metadata.target_agent_id == caller` on a row that is
///   NOT unstamped → admitted (the addressed recipient; an unstamped row is
///   not an addressed inbox row — the #1628 shape);
/// * unstamped → [`admit_unstamped`] (the knob);
/// * anything else (another owner, a malformed stamp) → refused.
///
/// Per-site pass-throughs that pre-date #3124 (the sqlite `daemon` principal)
/// stay at the call site; admin lanes never reach here.
#[must_use]
pub fn metadata_admits_mutation(
    metadata: &Value,
    id: &str,
    caller: &str,
    allow_inbox: bool,
    site: MutationSite,
) -> bool {
    metadata_admits_mutation_with_mode(metadata, id, caller, allow_inbox, site, mode())
}

/// [`metadata_admits_mutation`] under an explicit `mode` — the seam that lets
/// unit tests pin BOTH postures without mutating the process environment.
#[must_use]
pub fn metadata_admits_mutation_with_mode(
    metadata: &Value,
    id: &str,
    caller: &str,
    allow_inbox: bool,
    site: MutationSite,
    mode: UnstampedMutationMode,
) -> bool {
    if OwnerStamp::of(metadata).is_unstamped() {
        return admit_unstamped_rows(site, id, caller, 1, mode);
    }
    metadata_would_admit(metadata, caller, allow_inbox, mode)
}

/// The ONE predicate specialised to a link DELETE, whose authority is
/// symmetric (either endpoint's owner may sever the edge):
///
/// * the caller owns the SOURCE (stamped), or is the inbox recipient of a
///   stamped source → admitted;
/// * the caller owns the TARGET (stamped) → admitted;
/// * the source is UNSTAMPED and either the caller is its addressed
///   recipient or the target is unstamped / missing → an unstamped admission,
///   decided by [`admit_unstamped`] (the pre-#3124 outcome under `warn`);
/// * anything else → refused.
///
/// `target_metadata` is `None` when the target row does not exist.
#[must_use]
pub fn unlink_admitted(
    source_metadata: &Value,
    target_metadata: Option<&Value>,
    source_id: &str,
    caller: &str,
    site: MutationSite,
) -> bool {
    let source = OwnerStamp::of(source_metadata);
    let target = target_metadata.map(OwnerStamp::of);
    let addressed_to_caller = source_metadata
        .get(crate::META_KEY_TARGET_AGENT_ID)
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty() && t == caller);
    if source.is_owned_by(caller)
        || (addressed_to_caller && !source.is_unstamped())
        || target.is_some_and(|t| t.is_owned_by(caller))
    {
        return true;
    }
    let target_unstamped = target.is_none_or(|t| t.is_unstamped());
    if source.is_unstamped() && (addressed_to_caller || target_unstamped) {
        return admit_unstamped(site, source_id, caller);
    }
    false
}

/// The side-effect-free form of the ONE predicate: the same verdict as
/// [`metadata_admits_mutation_with_mode`] with no WARN and no counter. For a
/// PRE-check whose admission the funnel re-decides (and reports) later — the
/// erasure bundle materialisation ahead of the restore gate — so one mutation
/// is never counted twice.
#[must_use]
pub fn metadata_would_admit(
    metadata: &Value,
    caller: &str,
    allow_inbox: bool,
    mode: UnstampedMutationMode,
) -> bool {
    let stamp = OwnerStamp::of(metadata);
    if stamp.is_owned_by(caller) {
        return true;
    }
    if stamp.is_unstamped() {
        return !mode.refuses();
    }
    allow_inbox
        && metadata
            .get(crate::META_KEY_TARGET_AGENT_ID)
            .and_then(Value::as_str)
            .is_some_and(|target| !target.is_empty() && target == caller)
}

/// Bulk form of [`admit_unstamped`] for the SQL-arm funnels (forget by
/// filter): the caller resolves `mode` ONCE, builds its SQL with
/// [`sqlite_unstamped_arm`] from the same `mode`, and reports how many
/// unstamped rows the statement admitted. `rows == 0` records nothing.
#[must_use]
pub fn admit_unstamped_rows(
    site: MutationSite,
    target: &str,
    caller: &str,
    rows: u64,
    mode: UnstampedMutationMode,
) -> bool {
    if rows == 0 {
        return !mode.refuses();
    }
    let MutationSite { backend, funnel } = site;
    match mode {
        UnstampedMutationMode::Warn => {
            tracing::warn!(
                target: TRACE_TARGET,
                backend,
                funnel,
                subject = target,
                caller,
                rows,
                "caller-scoped mutation admitted on {rows} UNSTAMPED (legacy-unowned) row(s); \
                 set {ENV_UNSTAMPED_MUTATION}={MODE_REFUSE} after re-owning them \
                 (`ai-memory doctor` counts them, `ai-memory reown` claims them)"
            );
            crate::metrics::inc_unstamped_mutation_allowed(backend, funnel, rows);
            true
        }
        UnstampedMutationMode::Refuse => {
            tracing::warn!(
                target: TRACE_TARGET,
                backend,
                funnel,
                subject = target,
                caller,
                rows,
                "caller-scoped mutation REFUSED on {rows} UNSTAMPED (legacy-unowned) row(s) \
                 under {ENV_UNSTAMPED_MUTATION}={MODE_REFUSE}"
            );
            false
        }
    }
}

/// Stable refusal reason for an unstamped row under `refuse` (and on the
/// postgres funnels that refuse it in both modes).
pub const REASON_UNSTAMPED_REFUSED: &str = "memory carries no ownership stamp (metadata.agent_id); \
     a caller-scoped mutation of an unstamped row is refused — re-own it with `ai-memory reown`";

/// Stable refusal reason for a malformed (non-string) owner stamp.
pub const REASON_MALFORMED_OWNER: &str = "memory carries a malformed ownership stamp \
     (metadata.agent_id is not a string); it is mutable only through the operator lanes";

/// sqlite SQL disjunct admitting UNSTAMPED rows (missing / JSON null / `""`)
/// for the metadata column `col` (`metadata` or `m.metadata`), prefixed with
/// ` OR `. Empty under [`UnstampedMutationMode::Refuse`], so the surrounding
/// owner predicate collapses to "owned by the caller". A NON-string owner is
/// never admitted: `json_extract` yields the non-text value, which is neither
/// `NULL` nor `''` and never equals a text caller parameter.
#[must_use]
pub fn sqlite_unstamped_arm(col: &str, mode: UnstampedMutationMode) -> String {
    if mode.refuses() {
        String::new()
    } else {
        format!(" OR {}", sqlite_unstamped_predicate(col))
    }
}

/// sqlite predicate: `col`'s `metadata.agent_id` is UNSTAMPED.
#[must_use]
pub fn sqlite_unstamped_predicate(col: &str) -> String {
    format!("(json_extract({col},'$.agent_id') IS NULL OR json_extract({col},'$.agent_id') = '')")
}

/// sqlite predicate: `col`'s `metadata.agent_id` is MALFORMED (present, non-string).
#[must_use]
pub fn sqlite_malformed_predicate(col: &str) -> String {
    format!("(COALESCE(json_type({col},'$.agent_id'),'null') NOT IN ('text','null'))")
}

/// postgres SELECT-list pair feeding [`OwnerStamp::of_pg`]:
/// `jsonb_typeof(metadata->'agent_id'), metadata->>'agent_id'`.
pub const PG_OWNER_TYPE_SQL: &str = "jsonb_typeof(metadata->'agent_id')";

/// postgres predicate: `metadata.agent_id` is UNSTAMPED (missing / JSON null / `''`).
pub const PG_UNSTAMPED_PREDICATE: &str =
    "(metadata->>'agent_id' IS NULL OR metadata->>'agent_id' = '')";

/// postgres predicate: `metadata.agent_id` is MALFORMED (present, non-string).
pub const PG_MALFORMED_PREDICATE: &str =
    "(COALESCE(jsonb_typeof(metadata->'agent_id'),'null') NOT IN ('string','null'))";

/// v1.0.0 #3124 — the unstamped-owner census `ai-memory doctor` reports on
/// BOTH backends (vote constraint 2): how many LIVE rows are unstamped
/// (re-own candidates) and how many carry a malformed (non-string) stamp, plus
/// the unstamped rows sitting in the archive (restore targets).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnstampedCensus {
    /// Live rows with a missing / null / `""` `metadata.agent_id`.
    pub unstamped: u64,
    /// Live rows whose `metadata.agent_id` is present but not a string.
    pub malformed: u64,
    /// Archived rows with a missing / null / `""` `metadata.agent_id`.
    pub archived_unstamped: u64,
}

/// sqlite census query — served by the `agent_id_idx` generated column for
/// the live unstamped count (`NULL` also covers unparseable metadata, which no
/// caller can prove it owns either).
pub const SQLITE_CENSUS_SQL: &str = "SELECT \
     (SELECT COUNT(*) FROM memories WHERE agent_id_idx IS NULL OR agent_id_idx = ''), \
     (SELECT COUNT(*) FROM memories WHERE typeof(agent_id_idx) NOT IN ('text', 'null')), \
     (SELECT COUNT(*) FROM archived_memories \
        WHERE json_extract(metadata, '$.agent_id') IS NULL \
           OR json_extract(metadata, '$.agent_id') = '')";

/// postgres census query — the same three counts over the same definition.
pub const PG_CENSUS_SQL: &str = "SELECT \
     (SELECT count(*) FROM memories WHERE agent_id_idx IS NULL OR agent_id_idx = ''), \
     (SELECT count(*) FROM memories \
        WHERE COALESCE(jsonb_typeof(metadata->'agent_id'), 'null') NOT IN ('string', 'null')), \
     (SELECT count(*) FROM archived_memories \
        WHERE metadata->>'agent_id' IS NULL OR metadata->>'agent_id' = '')";

/// Run [`SQLITE_CENSUS_SQL`].
///
/// # Errors
///
/// Propagates the query failure (a failed census is never reported as 0).
pub fn sqlite_census(conn: &rusqlite::Connection) -> rusqlite::Result<UnstampedCensus> {
    conn.query_row(SQLITE_CENSUS_SQL, [], |r| {
        let count = |i: usize| -> rusqlite::Result<u64> {
            let n: i64 = r.get(i)?;
            Ok(u64::try_from(n).unwrap_or(0))
        };
        Ok(UnstampedCensus {
            unstamped: count(0)?,
            malformed: count(1)?,
            archived_unstamped: count(2)?,
        })
    })
}

/// Operator remedy named by the doctor census.
pub const CENSUS_REMEDY: &str = "re-own them to the principal you actually call as with `ai-memory reown` \
     (review with `--dry-run` first); set AI_MEMORY_UNSTAMPED_MUTATION=refuse once this census reads 0";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn owner_stamp_one_definition_3124() {
        assert_eq!(OwnerStamp::of(&json!({})), OwnerStamp::Unstamped);
        assert_eq!(
            OwnerStamp::of(&json!({"agent_id": null})),
            OwnerStamp::Unstamped
        );
        assert_eq!(
            OwnerStamp::of(&json!({"agent_id": ""})),
            OwnerStamp::Unstamped
        );
        assert_eq!(
            OwnerStamp::of(&json!({"agent_id": 123})),
            OwnerStamp::Malformed
        );
        assert_eq!(
            OwnerStamp::of(&json!({"agent_id": {"x": 1}})),
            OwnerStamp::Malformed
        );
        assert_eq!(
            OwnerStamp::of(&json!({"agent_id": "ai:a"})),
            OwnerStamp::Stamped("ai:a")
        );
        // Non-object metadata carries no stamp.
        assert_eq!(OwnerStamp::of(&json!("x")), OwnerStamp::Unstamped);
    }

    #[test]
    fn pg_classification_matches_json_classification_3124() {
        assert_eq!(OwnerStamp::of_pg(None, None), OwnerStamp::Unstamped);
        assert_eq!(OwnerStamp::of_pg(Some("null"), None), OwnerStamp::Unstamped);
        assert_eq!(
            OwnerStamp::of_pg(Some("string"), Some("")),
            OwnerStamp::Unstamped
        );
        assert_eq!(
            OwnerStamp::of_pg(Some("number"), Some("123")),
            OwnerStamp::Malformed
        );
        assert_eq!(
            OwnerStamp::of_pg(Some("string"), Some("ai:a")),
            OwnerStamp::Stamped("ai:a")
        );
    }

    #[test]
    fn malformed_owner_never_matches_a_caller_3124() {
        let meta = json!({"agent_id": 123});
        let stamp = OwnerStamp::of(&meta);
        assert!(!stamp.is_owned_by("123"));
        assert!(!stamp.is_unstamped());
        assert_eq!(stamp.owner_for_display(), MALFORMED_OWNER_LABEL);
        assert!(crate::validate::validate_agent_id(MALFORMED_OWNER_LABEL).is_err());
    }

    #[test]
    fn mode_grammar_fails_closed_3124() {
        assert_eq!(
            UnstampedMutationMode::parse(None),
            UnstampedMutationMode::Warn
        );
        assert_eq!(
            UnstampedMutationMode::parse(Some("  ")),
            UnstampedMutationMode::Warn
        );
        assert_eq!(
            UnstampedMutationMode::parse(Some("WARN")),
            UnstampedMutationMode::Warn
        );
        assert_eq!(
            UnstampedMutationMode::parse(Some("refuse")),
            UnstampedMutationMode::Refuse
        );
        // FBL-14: an unrecognised token never widens.
        assert_eq!(
            UnstampedMutationMode::parse(Some("allow")),
            UnstampedMutationMode::Refuse
        );
        assert_eq!(
            UnstampedMutationMode::parse(Some("0")),
            UnstampedMutationMode::Refuse
        );
        assert!(is_recognised_token("Refuse"));
        assert!(!is_recognised_token("off"));
    }

    #[test]
    fn sqlite_arm_collapses_under_refuse_3124() {
        assert!(sqlite_unstamped_arm("metadata", UnstampedMutationMode::Refuse).is_empty());
        let arm = sqlite_unstamped_arm("m.metadata", UnstampedMutationMode::Warn);
        assert!(arm.starts_with(" OR "));
        assert!(arm.contains("json_extract(m.metadata,'$.agent_id') IS NULL"));
    }

    #[test]
    fn sqlite_predicates_agree_with_rust_classifier_3124() {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        let unstamped = sqlite_unstamped_predicate("?1");
        let malformed = sqlite_malformed_predicate("?1");
        let sql = format!("SELECT {unstamped}, {malformed}");
        for meta in [
            json!({}),
            json!({"agent_id": null}),
            json!({"agent_id": ""}),
            json!({"agent_id": 7}),
            json!({"agent_id": true}),
            json!({"agent_id": ["a"]}),
            json!({"agent_id": "ai:a"}),
        ] {
            let (u, m): (bool, bool) = conn
                .query_row(&sql, [meta.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))
                .expect("predicate query");
            let stamp = OwnerStamp::of(&meta);
            assert_eq!(u, stamp.is_unstamped(), "unstamped verdict for {meta}");
            assert_eq!(
                m,
                stamp == OwnerStamp::Malformed,
                "malformed verdict for {meta}"
            );
        }
    }
}
