// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP archive management handlers (list, restore, purge, stats, gc).

use crate::db;
use crate::mcp::param_names;
use crate::models::field_names;
use serde_json::{Value, json};
pub(super) fn handle_archive_list(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let namespace = params["namespace"].as_str();
    let limit = params["limit"]
        .as_u64()
        .map_or(crate::storage::ARCHIVE_DEFAULT_PAGE_LIMIT, |v| {
            usize::try_from(v).unwrap_or(usize::MAX)
        });
    let offset = usize::try_from(params["offset"].as_u64().unwrap_or(0)).unwrap_or(usize::MAX);
    let items = db::list_archived(
        conn,
        namespace,
        limit.min(crate::storage::LIST_MAX_LIMIT),
        offset,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({"archived": items, "count": items.len()}))
}

pub(super) fn handle_archive_restore(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    let restored = db::restore_archived(conn, id).map_err(|e| e.to_string())?;
    if !restored {
        return Err(crate::errors::msg::NOT_FOUND_IN_ARCHIVE.into());
    }
    Ok(json!({"restored": true, "id": id}))
}

pub(super) fn handle_archive_purge(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let older_than_days = params[param_names::OLDER_THAN_DAYS].as_i64();

    // #913 (security-medium / SOC2, 2026-05-19) — admin/destructive
    // state-change audit. Archive purge permanently deletes archived
    // memories; emit the forensic-chain row BEFORE the storage write
    // so the audit trail captures intent regardless of downstream
    // permission-gate / storage outcome. Mirrors the #911 HTTP
    // `purge_archive` fix.
    // #3171 — `agent_id` selects WHOSE archive is purged
    // (`purge_archive_for_caller`) and `as_admin` escalates to EVERY owner's,
    // both from UNDECLARED wire params on an IRREVERSIBLE bulk delete. Bind the
    // caller-scoped subject to the enforced-read caller under the multi-tenant
    // posture so a caller cannot purge another owner's archive by naming them;
    // the single-operator default is unchanged. Resolved ONCE and reused below
    // (pre-fix the same param was resolved twice with different failure modes —
    // `unwrap_or_else(ANONYMOUS_INVALID)` here and `?` in the K9 block).
    let caller = match crate::identity::resolve_governance_subject(
        params[param_names::AGENT_ID].as_str(),
        None,
        "purge the archive",
    ) {
        Ok(c) => c,
        Err(e) => {
            // #3171 — a REFUSED subject is a security event, and #913's remit
            // is that the forensic chain captures INTENT regardless of the
            // downstream outcome. Chain a `refuse` row (attributed to the
            // enforced-read caller, never to the id the request asserted)
            // before returning, so an attempt to purge another owner's archive
            // is not the one archive-purge call that leaves no trace.
            crate::governance::audit::record_decision(
                &crate::identity::resolve_read_visibility_caller()
                    .unwrap_or_else(|| crate::identity::sentinels::ANONYMOUS_INVALID.to_string()),
                "refuse",
                crate::governance::action_labels::ARCHIVE_PURGE,
                "",
                json!({
                    (field_names::OLDER_THAN_DAYS): older_than_days,
                    "reason": e.to_string(),
                }),
            );
            return Err(e.to_string());
        }
    };
    // #936 (security-critical, 2026-05-20) — MCP-side owner gate.
    // The MCP entry is a second attack surface for the same gap the
    // HTTP `purge_archive` handler had: pre-#936 the dispatch reached
    // `db::purge_archive` with no caller, deleting every owner's
    // archived rows. The MCP tool surface gets the same posture as
    // the HTTP handler: owner-scoped by default; cross-tenant wipe
    // requires the explicit `as_admin: true` parameter (no separate
    // MCP-side admin-config block today — operators use either the
    // CLI or the HTTP admin allowlist for cross-tenant deletes).
    // #3171 — `as_admin` is the cross-tenant escalation switch on an
    // irreversible purge, so a present-but-non-boolean value must not silently
    // take the caller-scoped branch either (fail loudly, the `dry_run` rule).
    let as_admin =
        crate::mcp::param_guard::optional_bool(params, param_names::AS_ADMIN)?.unwrap_or(false);
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        crate::governance::action_labels::ARCHIVE_PURGE,
        "",
        json!({
            (field_names::OLDER_THAN_DAYS): older_than_days,
            (field_names::OWNER_SCOPE): if as_admin { "admin" } else { "caller" },
        }),
    );

    // v0.7.0 K9 — unified permission pipeline (archive-side).
    // Archive purge is a destructive across-namespace operation; we
    // evaluate against the global namespace + caller's agent_id.
    // Operators can still scope rules via `namespace_pattern = "**"`.
    {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let agent_id = caller.clone();
        let ctx = PermissionContext {
            op: Op::MemoryArchive,
            namespace: crate::DEFAULT_NAMESPACE.to_string(),
            agent_id,
            payload: json!({
                (field_names::OLDER_THAN_DAYS): older_than_days,
                "as_admin": as_admin,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    "archive",
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": "archive",
                }));
            }
        }
    }

    let purged = if as_admin {
        db::purge_archive(conn, older_than_days).map_err(|e| e.to_string())?
    } else {
        db::purge_archive_for_caller(conn, &caller, older_than_days).map_err(|e| e.to_string())?
    };
    Ok(json!({
        "purged": purged,
        (field_names::OWNER_SCOPE): if as_admin { "admin" } else { "caller" },
    }))
}

pub(super) fn handle_archive_stats(conn: &rusqlite::Connection) -> Result<Value, String> {
    db::archive_stats(conn).map_err(|e| e.to_string())
}

/// #3204 item 7 — the three gates a real `memory_gc` sweep must clear, in the
/// same order and with the same semantics `handle_archive_purge` uses.
///
/// 1. **K9 permission rules.** Evaluated against the resolved caller. The op is
///    chosen by DISPOSITION: an archiving sweep is `MemoryArchive` (a
///    recoverable move, same op as the archive family); a non-archiving sweep
///    is `MemoryDelete`, because that is exactly what it is. Rules are
///    namespace-scoped and a sweep is substrate-wide, so it is evaluated at the
///    default namespace and operators scope with `namespace_pattern = "**"` —
///    the `handle_archive_purge` convention.
/// 2. **Namespace governance — DESTRUCTIVE sweeps only.** A sweep cannot honour
///    a per-namespace `delete` policy row-by-row, so it applies the #1849 rule
///    for a namespace-less bulk delete: if ANY namespace holding reapable rows
///    carries a non-`Any` `delete` level, REFUSE the whole sweep and direct the
///    operator at the scoped path. Otherwise a `delete: Approve` legal-hold is
///    no defence at all — the held rows simply expire and vanish on the next
///    tick, with no approval and no trace.
///
///    This applies ONLY when `archive` is false. An archiving sweep MOVES the
///    row to `archived_memories`, where `memory_archive_restore` recovers it,
///    so the governed content still exists and the hold is not defeated;
///    refusing there would strand expired rows in every deployment that has any
///    delete-governed namespace, which is a reliability cost with no integrity
///    benefit. (The archive path's link-cascade loss is #3161 — the memory TEXT
///    survives, which is the durable truth; the edges are derived.)
/// 3. **Forensic capture.** An `allow` decision chained BEFORE the write, so
///    the trail records intent regardless of the storage outcome (#913).
///
/// Deliberate deviation from the sibling: a `Decision::Ask` REFUSES here rather
/// than returning the success-shaped `{status:"ask"}` envelope
/// `handle_archive_purge` returns. A success-shaped body on an unperformed
/// destructive op is itself a #3171 finding; on a sweep with no per-call
/// approval channel, refusing is the only fail-closed answer.
///
/// # Errors
/// A governance-refusal message when a rule denies, when a reapable namespace
/// is delete-governed, or the stringified storage error on the namespace probe.
fn gate_gc_sweep(conn: &rusqlite::Connection, archive: bool) -> Result<(), String> {
    use crate::permissions::{Op, PermissionContext, Permissions};
    let caller = crate::identity::resolve_agent_id(None, None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());
    let op = if archive {
        Op::MemoryArchive
    } else {
        Op::MemoryDelete
    };
    let ctx = PermissionContext {
        op,
        namespace: crate::DEFAULT_NAMESPACE.to_string(),
        agent_id: caller.clone(),
        payload: json!({ "archived": archive }),
    };
    match Permissions::evaluate(&ctx, &[]) {
        crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
        crate::permissions::Decision::Deny(reason) => {
            return Err(crate::governance::deny_message(
                "gc",
                crate::governance::DenyGate::PermissionRule,
                &reason,
            ));
        }
        crate::permissions::Decision::Ask(prompt) => {
            return Err(crate::governance::deny_message(
                "gc",
                crate::governance::DenyGate::PermissionRule,
                &prompt,
            ));
        }
    }

    // #1849-shaped governance guard on the DESTRUCTIVE disposition only (see
    // the doc comment). The predicate is the SAME one `db::gc` sweeps with
    // (`SQL_GC_EXPIRED_CHUNK_IDS`), so the governed-namespace probe can never
    // miss a namespace the sweep would reap.
    if archive {
        crate::governance::audit::record_decision(
            &caller,
            "allow",
            crate::mcp::registry::tool_names::MEMORY_GC,
            "",
            json!({ "archived": true }),
        );
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT namespace FROM memories \
             WHERE expires_at IS NOT NULL AND expires_at < ?1",
        )
        .map_err(|e| e.to_string())?;
    let namespaces: Vec<String> = stmt
        .query_map(rusqlite::params![now], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(|e| e.to_string())?;
    for ns in &namespaces {
        if db::resolve_governance_policy(conn, ns)
            .is_some_and(|p| !matches!(p.core.delete, crate::models::GovernanceLevel::Any))
        {
            crate::governance::audit::record_decision(
                &caller,
                "refuse",
                crate::mcp::registry::tool_names::MEMORY_GC,
                ns,
                json!({ "archived": archive }),
            );
            return Err(crate::governance::deny_message(
                "gc",
                crate::governance::DenyGate::Governance,
                &format!(
                    "namespace '{ns}' holds expired rows and carries a non-permissive \
                     delete policy; a substrate-wide gc cannot honour it — reap that \
                     namespace through the governed per-memory delete instead"
                ),
            ));
        }
    }

    crate::governance::audit::record_decision(
        &caller,
        "allow",
        crate::mcp::registry::tool_names::MEMORY_GC,
        "",
        json!({ "archived": archive, "governed_namespaces_checked": namespaces.len() }),
    );
    Ok(())
}

pub(super) fn handle_gc(
    conn: &rusqlite::Connection,
    params: &Value,
    archive: bool,
) -> Result<Value, String> {
    // #2308 (FBL-04) — fold-before-gc on the MCP `memory_gc` surface.
    // MCP stdio spawns no fold loop, so pending recall-driven TTL
    // floor-extensions (#1869 pure recall) are applied here BEFORE
    // both branches: the dry-run count then matches post-fold reality
    // (a recalled-but-extended row is not counted as reapable), and
    // the real sweep never reaps a row whose folded expiry is in the
    // future (silent crypto-erasure when `archive` is false).
    // Best-effort: WARN on error, degrade to the pre-fold posture.
    // `db::gc` folds again as the structural backstop (cheap
    // has-unfolded fast-path no-op).
    if let Err(e) = db::fold_recall_accesses(conn, crate::SECS_PER_HOUR, crate::SECS_PER_DAY) {
        tracing::warn!("recall-access fold failed (pre-gc, memory_gc): {e}");
    }
    // #3171 — same SAFETY-flag shape as `memory_forget` (see there): a
    // present-but-non-boolean `dry_run` used to run a REAL sweep.
    let dry_run =
        crate::mcp::param_guard::optional_bool(params, param_names::DRY_RUN)?.unwrap_or(false);

    // ── #3204 item 7 — gate the SWEEP ────────────────────────────────────
    // `memory_gc` was the one destructive MCP tool that reached the substrate
    // with NO permission gate, NO governance consult and NO forensic row,
    // while its sibling `handle_archive_purge` (above) carries all three. It
    // deletes across EVERY namespace and EVERY owner, and with `archive_on_gc`
    // off that delete is a permanent hard-delete + crypto-erase — strictly
    // more destructive than the purge that IS gated. The gates below run only
    // for a real sweep; `dry_run` is a pure count and stays ungated so an
    // operator can always SEE what would be reaped.
    if !dry_run {
        gate_gc_sweep(conn, archive)?;
    }

    if dry_run {
        // Just count expired without deleting
        let now = chrono::Utc::now().to_rfc3339();
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE expires_at IS NOT NULL AND expires_at < ?1",
                rusqlite::params![now],
                |r| r.get(0),
            )
            .unwrap_or(0);
        // #3171 — surface `archived` on BOTH shapes. The tool advertises
        // "archives first", but that is conditional on the daemon's
        // `archive_on_gc` setting: with it OFF the sweep is a permanent
        // hard-delete + crypto-erase, and the pre-fix response gave the
        // caller NO way to tell a recoverable move from an unrecoverable
        // erase. (The archive path's own link-cascade loss is #3161, not
        // fixed here — see the tool docs.)
        return Ok(json!({"collected": count, "dry_run": true, "archived": archive}));
    }
    let count = db::gc(conn, archive).map_err(|e| e.to_string())?;
    Ok(json!({"collected": count, "dry_run": false, "archived": archive}))
}

// --- D1.5 (#986): per-tool McpTool impls for the 4 archive-family tools ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_archive_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ArchiveListRequest {
    /// Namespace filter.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Default 50, max 1000.
    #[serde(default)]
    pub limit: Option<i64>,

    /// Pagination offset.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_archive_list`.
#[allow(dead_code)]
pub struct ArchiveListTool;

impl McpTool for ArchiveListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ARCHIVE_LIST
    }
    fn description() -> &'static str {
        "List archived (expired) memories."
    }
    fn docs() -> &'static str {
        "List archived memories. Filter by namespace; paginate via offset/limit."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ArchiveListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Archive.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_archive_purge`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ArchivePurgeRequest {
    /// Only purge entries older than N days (0..=36500).
    #[serde(default)]
    pub older_than_days: Option<i64>,

    /// #3171 — the owner whose archived rows are purged. DEFAULT SCOPE IS
    /// CALLER-ONLY (#936): omitting this purges only the resolved caller's
    /// archive, never every owner's. Bound to the caller under the
    /// multi-tenant posture.
    #[serde(default)]
    pub agent_id: Option<String>,

    /// #3171 — CROSS-TENANT escalation (#936): `true` purges EVERY owner's
    /// archived rows, not just the caller's. Irreversible. Default `false`.
    #[serde(default)]
    pub as_admin: Option<bool>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_archive_purge`.
#[allow(dead_code)]
pub struct ArchivePurgeTool;

impl McpTool for ArchivePurgeTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ARCHIVE_PURGE
    }
    fn description() -> &'static str {
        "Permanently delete archived memories."
    }
    fn docs() -> &'static str {
        "Purge archive. Scope via older_than_days (0..=36500). Unrecoverable. #3171: the DEFAULT SCOPE IS \
         CALLER-ONLY — only the resolved caller's archived rows are purged; `as_admin: true` \
         escalates to EVERY owner's. A governance Ask rule returns a SUCCESS-SHAPED \
         `{status:\"ask\"}` envelope with NOTHING purged — check `status`, not just the \
         absence of an error."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ArchivePurgeRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Archive.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_archive_restore`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ArchiveRestoreRequest {
    /// Archived memory id.
    pub id: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_archive_restore`.
#[allow(dead_code)]
pub struct ArchiveRestoreTool;

impl McpTool for ArchiveRestoreTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ARCHIVE_RESTORE
    }
    fn description() -> &'static str {
        "Restore an archived memory back to the active store."
    }
    fn docs() -> &'static str {
        "Restore archived row; expires_at cleared."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ArchiveRestoreRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Archive.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_archive_stats`.
/// Legacy schema is `properties: {}` — empty struct.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ArchiveStatsRequest {}

/// v0.7.0 #972 D1.6 (#987) — request body for `memory_gc`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct GcRequest {
    /// Preview without deleting.
    #[serde(default)]
    pub dry_run: Option<bool>,
}

/// v0.7.0 #972 D1.6 (#987) — `McpTool` impl for `memory_gc`.
#[allow(dead_code)]
pub struct GcTool;

impl McpTool for GcTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_GC
    }
    fn description() -> &'static str {
        "Trigger garbage collection on expired memories (archives first WHEN ENABLED)."
    }
    fn docs() -> &'static str {
        "GC expired memories. Archives first when archive_on_gc is on (default); with it OFF \
         this is a PERMANENT hard-delete + crypto-erase with no recoverable copy. #3171: the \
         response carries `archived` so a caller can tell a recoverable move from an \
         unrecoverable erase — do not infer it from the tool name. The sweep is \
         SUBSTRATE-WIDE and ungated (every namespace, every owner) and also prunes the \
         recall_observations ledger and expired signals. Per #3161 the gc archive path does \
         not archive link edges, so edges of archived rows are lost. dry_run previews."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<GcRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Lifecycle.name()
    }
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_archive_stats`.
#[allow(dead_code)]
pub struct ArchiveStatsTool;

impl McpTool for ArchiveStatsTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_ARCHIVE_STATS
    }
    fn description() -> &'static str {
        "Show archive statistics (total count and per-namespace breakdown)."
    }
    fn docs() -> &'static str {
        "Archive total + per-namespace counts."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ArchiveStatsRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Archive.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for the 4 archive-family tools.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn archive_list_parity_986() {
        let derived = derived_props_for::<ArchiveListRequest>();
        assert_property_set_parity("memory_archive_list", &derived);
        assert_descriptions_match("memory_archive_list", &derived);
    }

    #[test]
    fn archive_list_tool_metadata_986() {
        assert_eq!(ArchiveListTool::name(), "memory_archive_list");
        assert_eq!(ArchiveListTool::family(), "archive");
    }

    #[test]
    fn archive_purge_parity_986() {
        let derived = derived_props_for::<ArchivePurgeRequest>();
        assert_property_set_parity("memory_archive_purge", &derived);
        assert_descriptions_match("memory_archive_purge", &derived);
    }

    #[test]
    fn archive_purge_tool_metadata_986() {
        assert_eq!(ArchivePurgeTool::name(), "memory_archive_purge");
        assert_eq!(ArchivePurgeTool::family(), "archive");
    }

    #[test]
    fn archive_restore_parity_986() {
        let derived = derived_props_for::<ArchiveRestoreRequest>();
        assert_property_set_parity("memory_archive_restore", &derived);
        assert_descriptions_match("memory_archive_restore", &derived);
    }

    #[test]
    fn archive_restore_tool_metadata_986() {
        assert_eq!(ArchiveRestoreTool::name(), "memory_archive_restore");
        assert_eq!(ArchiveRestoreTool::family(), "archive");
    }

    #[test]
    fn archive_stats_parity_986() {
        let derived = derived_props_for::<ArchiveStatsRequest>();
        assert_property_set_parity("memory_archive_stats", &derived);
        assert_descriptions_match("memory_archive_stats", &derived);
    }

    #[test]
    fn archive_stats_tool_metadata_986() {
        assert_eq!(ArchiveStatsTool::name(), "memory_archive_stats");
        assert_eq!(ArchiveStatsTool::family(), "archive");
    }
}

#[cfg(test)]
mod d1_6_987_tests {
    //! D1.6 (#987) — schema parity for `memory_gc`.
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn gc_parity_987() {
        let derived = derived_props_for::<GcRequest>();
        assert_property_set_parity("memory_gc", &derived);
        assert_descriptions_match("memory_gc", &derived);
    }

    #[test]
    fn gc_tool_metadata_987() {
        assert_eq!(GcTool::name(), "memory_gc");
        assert_eq!(GcTool::family(), "lifecycle");
    }
}

// ---- C-5 (#699): unit coverage for the `pub(super)` handlers. The MCP
// dispatch layer covers most happy paths; these target the missing-`id`,
// invalid-id and "not in archive" branches plus the gc dry-run vs.
// actual-run split that the lib-tier path under-exercises (currently
// 91.02%). ----
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open_conn() -> rusqlite::Connection {
        crate::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn handle_archive_restore_missing_id_errors() {
        // Hits the `id is required` branch on line 24.
        let conn = open_conn();
        let err = handle_archive_restore(&conn, &json!({})).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    #[test]
    fn handle_archive_restore_invalid_id_maps_validator_error() {
        // Covers `validate_id(...).map_err(...)` on line 25.
        let conn = open_conn();
        let err = handle_archive_restore(&conn, &json!({"id": "not-a-valid-uuid"})).unwrap_err();
        assert!(!err.is_empty(), "expected non-empty validator error");
    }

    #[test]
    fn handle_archive_restore_unknown_uuid_returns_not_found() {
        // Well-formed UUID but no row exists → line 28 "not found in archive".
        let conn = open_conn();
        let err = handle_archive_restore(
            &conn,
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn handle_archive_list_default_paging_returns_empty() {
        // Exercises `params["limit"].as_u64().unwrap_or(50)` and
        // `params["offset"].as_u64().unwrap_or(0)` defaults on lines 13-14.
        let conn = open_conn();
        let result = handle_archive_list(&conn, &json!({})).expect("list ok");
        assert_eq!(result["count"], 0);
        assert!(result["archived"].is_array());
    }

    #[test]
    fn handle_archive_stats_returns_object() {
        // Covers the `archive_stats(...).map_err(...)` happy path
        // (line 73) on an empty DB. The stats schema is an object.
        let conn = open_conn();
        let result = handle_archive_stats(&conn).expect("stats ok");
        assert!(
            result.is_object(),
            "archive_stats must return a JSON object on empty DB, got: {result}"
        );
    }

    #[test]
    fn handle_gc_dry_run_on_empty_db_returns_zero() {
        // Covers the `dry_run = true` branch on lines 82-92.
        let conn = open_conn();
        let result = handle_gc(&conn, &json!({"dry_run": true}), false).expect("gc dry-run ok");
        assert_eq!(result["collected"], 0);
        assert_eq!(result["dry_run"], true);
    }

    #[test]
    fn handle_gc_actual_run_on_empty_db_returns_zero() {
        // Covers the actual-gc branch on lines 94-95 with archive=true.
        let conn = open_conn();
        let result = handle_gc(&conn, &json!({"dry_run": false}), true).expect("gc run ok");
        assert_eq!(result["collected"], 0);
        assert_eq!(result["dry_run"], false);
    }

    #[test]
    fn handle_gc_2308_folds_pending_extension_before_dry_run_and_real_gc() {
        // #2308 (FBL-04) regression — the MCP `memory_gc` surface must
        // apply pending recall-driven TTL floor-extensions BEFORE both
        // the dry-run count and the real sweep. Two short-tier rows
        // whose BASE 6h TTL already lapsed; only one was recalled
        // (pure recall → an unfolded `recall_observations` row whose
        // per-access short-tier extension, observed_at + 1h, pushes
        // its real expiry into the future).
        let conn = open_conn();
        let created = (chrono::Utc::now() - chrono::Duration::hours(7)).to_rfc3339();
        let lapsed = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
        for id in ["fbl04-recalled", "fbl04-control"] {
            conn.execute(
                "INSERT INTO memories (id, tier, namespace, title, content, created_at, \
                                       updated_at, expires_at) \
                 VALUES (?1, 'short', 'fbl04', ?1, 'c', ?2, ?2, ?3)",
                rusqlite::params![id, created, lapsed],
            )
            .unwrap();
        }
        crate::observations::record_recall(
            &conn,
            "fbl04-mcp-r1",
            &[crate::observations::Candidate {
                memory_id: "fbl04-recalled",
                retriever: "fts5",
                rank: 1,
                score: 0.5,
            }],
        )
        .unwrap();

        // Dry-run counts POST-fold reality: only the un-recalled
        // control row is reapable (pre-#2308 this counted 2).
        let dry = handle_gc(&conn, &json!({"dry_run": true}), false).expect("gc dry-run ok");
        assert_eq!(dry["dry_run"], true);
        assert_eq!(dry["collected"], 1, "dry-run must match post-fold reality");
        let exists = |id: &str| -> i64 {
            conn.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap()
        };
        assert_eq!(exists("fbl04-recalled"), 1, "dry-run deletes nothing");
        assert_eq!(exists("fbl04-control"), 1, "dry-run deletes nothing");

        // Real run reaps ONLY the control row; the recalled row's
        // folded extension keeps it alive (pre-#2308 it was reaped —
        // silent crypto-erasure with archive=false).
        let real = handle_gc(&conn, &json!({}), false).expect("gc run ok");
        assert_eq!(real["dry_run"], false);
        assert_eq!(real["collected"], 1);
        assert_eq!(
            exists("fbl04-recalled"),
            1,
            "recalled row survived memory_gc: its TTL extension was folded before eviction"
        );
        assert_eq!(
            exists("fbl04-control"),
            0,
            "control row expired as scheduled"
        );
    }

    /// #3204 item 7 — a DESTRUCTIVE sweep must refuse when any namespace
    /// holding expired rows carries a non-`Any` `delete` policy. Pre-fix
    /// `memory_gc` reached the substrate with no governance consult, so a
    /// `delete: Approve` legal-hold was no defence: held rows simply
    /// expired and vanished. `dry_run` stays ungated; an archiving sweep
    /// stays recoverable via `memory_archive_restore` and is exempt.
    #[test]
    fn gc_destructive_sweep_refuses_delete_governed_namespace_3204() {
        use crate::models::{
            CorePolicy, GovernanceLevel, GovernancePolicy, Memory, MemoryKind, Tier,
            default_metadata,
        };
        let conn = open_conn();
        let ns = "gov-gc-approve-3204";
        let policy = GovernancePolicy {
            core: CorePolicy {
                delete: GovernanceLevel::Approve,
                ..CorePolicy::default()
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("agent_id".into(), json!("ai:alice"));
            obj.insert("governance".into(), serde_json::to_value(&policy).unwrap());
        }
        let standard = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: format!("_standards-{ns}"),
            title: format!("std-{ns}"),
            content: "policy".into(),
            tags: vec![],
            priority: 9,
            confidence: 1.0,
            source: "test".into(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now.clone(),
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let sid = db::insert(&conn, &standard).expect("insert standard");
        db::set_namespace_standard(&conn, ns, &sid, None).expect("bind");

        let lapsed = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, \
                                   updated_at, expires_at) \
             VALUES ('gc-held-3204', 'short', ?1, 'held', 'c', ?2, ?2, ?3)",
            rusqlite::params![ns, now, lapsed],
        )
        .unwrap();

        let dry = handle_gc(&conn, &json!({"dry_run": true}), false).expect("dry-run ungated");
        assert_eq!(dry["collected"], 1);
        assert_eq!(dry["dry_run"], true);

        let err = handle_gc(&conn, &json!({}), false)
            .expect_err("destructive sweep must refuse a delete-governed namespace");
        assert!(
            err.contains("governance") || err.contains("delete policy") || err.contains(ns),
            "got: {err}"
        );
        let still: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = 'gc-held-3204'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            still, 1,
            "held row must survive a refused destructive sweep"
        );

        // Archiving is recoverable; the hold is not defeated, so the
        // documented exemption lets the move proceed.
        let archived = handle_gc(&conn, &json!({}), true).expect("archiving sweep exempt");
        assert_eq!(archived["archived"], true);
        assert_eq!(archived["collected"], 1);
    }

    #[test]
    fn handle_archive_purge_default_no_filter_succeeds_on_empty_db() {
        // Covers the `older_than_days` None path on line 37, and the
        // permission-Allow happy path (lines 53-54), and the
        // `purge_archive(...)` success branch on lines 68-69.
        let conn = open_conn();
        let result = handle_archive_purge(&conn, &json!({})).expect("purge ok");
        let purged = &result["purged"];
        // Single-branch numeric assertion so the `||` short-circuit
        // doesn't leave the right side unexercised.
        assert!(
            purged.is_number(),
            "expected numeric `purged`, got: {purged}"
        );
    }

    #[test]
    fn archive_purge_refuses_huge_days_and_allows_maximum_3384() {
        let conn = open_conn();
        let err = handle_archive_purge(
            &conn,
            &json!({"older_than_days": i64::MAX, "agent_id": "ai:archive-owner"}),
        )
        .expect_err("huge archive cutoff must be refused without panicking");
        assert!(err.contains("must not exceed 36500"), "got: {err}");

        let value = handle_archive_purge(
            &conn,
            &json!({
                "older_than_days": crate::validate::MAX_DURATION_DAYS,
                "agent_id": "ai:archive-owner",
            }),
        )
        .expect("maximum bounded cutoff remains valid");
        assert_eq!(value["purged"].as_u64(), Some(0));
    }
}
