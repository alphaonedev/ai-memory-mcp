// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP archive management handlers (list, restore, purge, stats, gc).

use crate::db;
use crate::mcp::param_names;
use crate::models::field_names;
use serde_json::{Value, json};
/// #3382: query visibility and archive ownership constrain every visible page.
/// Substrate rows require an explicit namespace even without a caller. The
/// checked `as_admin` escalation is reserved for #3455; no bypass is added here.
pub(super) fn handle_archive_list(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let namespace = params["namespace"].as_str();
    let limit = params["limit"]
        .as_u64()
        .map_or(crate::storage::ARCHIVE_DEFAULT_PAGE_LIMIT, |v| {
            usize::try_from(v).unwrap_or(usize::MAX)
        });
    let offset = usize::try_from(params["offset"].as_u64().unwrap_or(0)).unwrap_or(usize::MAX);
    let items = db::list_archived_scoped(
        conn,
        namespace,
        caller,
        limit.min(crate::storage::LIST_MAX_LIMIT),
        offset,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({"archived": items, "count": items.len()}))
}

/// #3382: route restore through the caller-gated storage twin. A refused id
/// has the same error as an absent one. The single-operator restore is retained.
pub(super) fn handle_archive_restore(
    conn: &rusqlite::Connection,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    let restored = match caller {
        Some(c) => db::restore_archived_for_caller(conn, id, c),
        None => db::restore_archived(conn, id),
    }
    .map_err(|e| e.to_string())?;
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
    crate::identity::resolve_mcp_read_visibility_caller().map_err(|error| error.to_string())?;
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
    // #3383 — the irreversible cross-owner escalation requires the boot
    // allowlist and the resolved caller; an empty list admits nobody.
    let as_admin =
        crate::mcp::param_guard::optional_bool(params, param_names::AS_ADMIN)?.unwrap_or(false);
    if as_admin && !crate::identity::is_admin_agent(&caller) {
        crate::governance::audit::record_decision(
            &caller,
            "refuse",
            crate::governance::action_labels::ARCHIVE_PURGE,
            "",
            json!({
                (field_names::OLDER_THAN_DAYS): older_than_days,
                (field_names::OWNER_SCOPE): "admin",
                "reason": "as_admin requires membership of the operator-configured \
                           [admin].agent_ids allowlist",
            }),
        );
        return Err(crate::governance::deny_message(
            "archive",
            crate::governance::DenyGate::Governance,
            "as_admin purges EVERY owner's archived rows and requires the caller to appear in \
             the operator-configured [admin].agent_ids allowlist (or \
             AI_MEMORY_ADMIN_AGENT_IDS); omit as_admin to purge your own archive",
        ));
    }
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

/// MCP `memory_archive_stats`.
///
/// v1.0.0 #3382 — owner-scoped for the same reason as `memory_archive_list`:
/// the per-namespace breakdown is corpus-shape metadata that tells any caller
/// which OTHER tenants hold archived rows and how many. The HTTP twin has been
/// `require_admin`-gated since #943; this surface had no gate at all.
///
/// The `as_admin` escalation is carved out to #3455 for the same reason as
/// `handle_archive_list` above (it needs #3383's allowlist predicate).
pub(super) fn handle_archive_stats(
    conn: &rusqlite::Connection,
    caller: Option<&str>,
) -> Result<Value, String> {
    db::archive_stats_scoped(conn, caller).map_err(|e| e.to_string())
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
fn gate_gc_sweep(
    conn: &rusqlite::Connection,
    archive: bool,
    caller: &str,
    owner: Option<&str>,
) -> Result<(), String> {
    use crate::permissions::{Op, PermissionContext, Permissions};
    let op = if archive {
        Op::MemoryArchive
    } else {
        Op::MemoryDelete
    };
    let ctx = PermissionContext {
        op,
        namespace: crate::DEFAULT_NAMESPACE.to_string(),
        agent_id: caller.to_string(),
        payload: json!({ "archived": archive, (field_names::OWNER_SCOPE): owner }),
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
    // the doc comment). The predicate is the SAME one `db::gc_for_caller`
    // sweeps with, so the governed-namespace probe can never
    // miss a namespace the sweep would reap.
    if archive {
        crate::governance::audit::record_decision(
            caller,
            "allow",
            crate::mcp::registry::tool_names::MEMORY_GC,
            "",
            json!({ "archived": true, (field_names::OWNER_SCOPE): owner }),
        );
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT DISTINCT namespace FROM memories WHERE {}",
            db::SQL_GC_EXPIRED_WHERE,
        ))
        .map_err(|e| e.to_string())?;
    let namespaces: Vec<String> = stmt
        .query_map(rusqlite::params![now, owner], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(|e| e.to_string())?;
    for ns in &namespaces {
        if db::resolve_governance_policy(conn, ns)
            .is_some_and(|p| !matches!(p.core.delete, crate::models::GovernanceLevel::Any))
        {
            crate::governance::audit::record_decision(
                caller,
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
        caller,
        "allow",
        crate::mcp::registry::tool_names::MEMORY_GC,
        "",
        json!({ "archived": archive, (field_names::OWNER_SCOPE): owner, "governed_namespaces_checked": namespaces.len() }),
    );
    Ok(())
}

pub(super) fn handle_gc(
    conn: &rusqlite::Connection,
    params: &Value,
    archive: bool,
) -> Result<Value, String> {
    // #3383 — resolve before folding or any other side effect. A configured
    // but unusable identity must never select the unrestricted sweep.
    let enforced =
        crate::identity::resolve_mcp_read_visibility_caller().map_err(|error| error.to_string())?;
    let single_operator = enforced.is_none();
    let caller = match enforced {
        Some(caller) => caller,
        None => crate::identity::resolve_agent_id(None, None).map_err(|error| error.to_string())?,
    };
    let owner =
        (!single_operator && !crate::identity::is_admin_agent(&caller)).then_some(caller.as_str());
    let dry_run =
        crate::mcp::param_guard::optional_bool(params, param_names::DRY_RUN)?.unwrap_or(false);
    if !dry_run {
        gate_gc_sweep(conn, archive, &caller, owner)?;
    }
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
    if dry_run {
        // Just count expired without deleting
        let now = chrono::Utc::now().to_rfc3339();
        let count: usize = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM memories WHERE {}",
                    db::SQL_GC_EXPIRED_WHERE
                ),
                rusqlite::params![now, owner],
                |r| r.get(0),
            )
            .map_err(|error| error.to_string())?;
        // #3171 — surface `archived` on BOTH shapes. The tool advertises
        // "archives first", but that is conditional on the daemon's
        // `archive_on_gc` setting: with it OFF the sweep is a permanent
        // hard-delete + crypto-erase, and the pre-fix response gave the
        // caller NO way to tell a recoverable move from an unrecoverable
        // erase. (The archive path's own link-cascade loss is #3161, not
        // fixed here — see the tool docs.)
        return Ok(json!({"collected": count, "dry_run": true, "archived": archive}));
    }
    let count = db::gc_for_caller(conn, archive, owner).map_err(|e| e.to_string())?;
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
        "Purge archive. Scope via older_than_days. Unrecoverable. #3171: the DEFAULT SCOPE IS \
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
        // v1.0.0 #3382 truth-fix: restore PRESERVES the archived row's
        // `original_expires_at` (see `storage::canonical_archived_expiry`); it
        // has never cleared it. The false claim mattered: an operator reading
        // it would not expect a TTL-archived row to be re-collected by the very
        // next gc tick. Say what actually happens.
        "Restore archived row; expires_at is PRESERVED, not cleared (a TTL-archived row is \
         reapable again at once — patch it via memory_update)."
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
        let err = handle_archive_restore(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    #[test]
    fn handle_archive_restore_invalid_id_maps_validator_error() {
        // Covers `validate_id(...).map_err(...)` on line 25.
        let conn = open_conn();
        let err =
            handle_archive_restore(&conn, &json!({"id": "not-a-valid-uuid"}), None).unwrap_err();
        assert!(!err.is_empty(), "expected non-empty validator error");
    }

    #[test]
    fn handle_archive_restore_unknown_uuid_returns_not_found() {
        // Well-formed UUID but no row exists → line 28 "not found in archive".
        let conn = open_conn();
        let err = handle_archive_restore(
            &conn,
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
        )
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn handle_archive_list_default_paging_returns_empty() {
        // Exercises `params["limit"].as_u64().unwrap_or(50)` and
        // `params["offset"].as_u64().unwrap_or(0)` defaults on lines 13-14.
        let conn = open_conn();
        let result = handle_archive_list(&conn, &json!({}), None).expect("list ok");
        assert_eq!(result["count"], 0);
        assert!(result["archived"].is_array());
    }

    #[test]
    fn handle_archive_stats_returns_object() {
        // Covers the `archive_stats(...).map_err(...)` happy path
        // (line 73) on an empty DB. The stats schema is an object.
        let conn = open_conn();
        let result = handle_archive_stats(&conn, None).expect("stats ok");
        assert!(
            result.is_object(),
            "archive_stats must return a JSON object on empty DB, got: {result}"
        );
    }

    /// v1.0.0 #3382 — insert a row owned by `agent_id` and ARCHIVE it,
    /// returning its id.
    fn seed_archived(conn: &rusqlite::Connection, ns: &str, title: &str, agent_id: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("archived body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": agent_id, "scope": "private"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
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
        let id = crate::db::insert(conn, &mem).expect("insert");
        assert!(
            crate::db::archive_memory(conn, &id, Some("test")).expect("archive"),
            "seed row must archive"
        );
        id
    }

    /// v1.0.0 #3382 (DENIED direction) — `memory_archive_list` no longer hands
    /// one tenant another tenant's archived title, content and
    /// `metadata.agent_id`.
    #[test]
    fn archive_list_is_owner_scoped_3382() {
        let conn = open_conn();
        seed_archived(&conn, "alice/notes", "alice-archived-secret", "ai:alice");
        seed_archived(&conn, "bob/notes", "bob-archived", "ai:bob");

        let out = handle_archive_list(&conn, &json!({}), Some("ai:bob")).expect("list ok");
        assert_eq!(out["count"], json!(1), "got: {out}");
        let rendered = out.to_string();
        assert!(
            !rendered.contains("alice-archived-secret") && !rendered.contains("ai:alice"),
            "another owner's archived row leaked: {rendered}"
        );
        assert!(rendered.contains("bob-archived"), "own row missing: {out}");
    }

    /// #3382 — the aggregate is corpus-shape metadata and is scoped the same
    /// way the listing is.
    #[test]
    fn archive_stats_is_owner_scoped_3382() {
        let conn = open_conn();
        seed_archived(&conn, "alice/notes", "alice-archived-secret", "ai:alice");
        seed_archived(&conn, "bob/notes", "bob-archived", "ai:bob");

        let out = handle_archive_stats(&conn, Some("ai:bob")).expect("stats ok");
        assert_eq!(out["archived_total"], json!(1), "got: {out}");
        let by_ns = out["by_namespace"].as_array().expect("by_namespace array");
        assert_eq!(by_ns.len(), 1, "got: {out}");
        assert_eq!(by_ns[0]["namespace"], json!("bob/notes"), "got: {out}");
    }

    /// #3382 (DENIED direction) — a non-owner cannot pull another owner's
    /// archived row back into the live working set, and the refusal is the
    /// SAME message an absent id produces (no archived-id oracle).
    #[test]
    fn archive_restore_refuses_non_owner_3382() {
        let conn = open_conn();
        let alice = seed_archived(&conn, "alice/notes", "alice-archived-secret", "ai:alice");

        let err = handle_archive_restore(&conn, &json!({"id": alice.clone()}), Some("ai:bob"))
            .expect_err("non-owner restore must be refused");
        assert_eq!(err, crate::errors::msg::NOT_FOUND_IN_ARCHIVE, "got: {err}");
        // Fail CLOSED: the row stays archived and never becomes live.
        let live: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1",
                rusqlite::params![alice],
                |r| r.get(0),
            )
            .expect("count live");
        assert_eq!(live, 0, "a refused restore must not resurrect the row");
        let archived: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
                rusqlite::params![alice],
                |r| r.get(0),
            )
            .expect("count archived");
        assert_eq!(archived, 1, "a refused restore must not consume the row");
    }

    /// #3382 (ALLOWED direction) — the OWNER still restores their own archived
    /// row. The gate must not cost the legitimate path.
    #[test]
    fn archive_restore_allows_owner_3382() {
        let conn = open_conn();
        let alice = seed_archived(&conn, "alice/notes", "alice-archived-secret", "ai:alice");

        let out = handle_archive_restore(&conn, &json!({"id": alice.clone()}), Some("ai:alice"))
            .expect("owner restore must succeed");
        assert_eq!(out["restored"], json!(true));
        assert!(
            crate::db::get(&conn, &alice)
                .expect("get")
                .is_some_and(|m| m.title == "alice-archived-secret"),
            "owner restore must put the row back"
        );
    }

    /// #3382 — the single-operator default (`caller == None`, no
    /// `AI_MEMORY_AGENT_ID`) is byte-for-byte unchanged on all three verbs.
    #[test]
    fn archive_reads_unscoped_for_single_operator_3382() {
        let conn = open_conn();
        let alice = seed_archived(&conn, "alice/notes", "alice-archived-secret", "ai:alice");
        seed_archived(&conn, "bob/notes", "bob-archived", "ai:bob");

        assert_eq!(
            handle_archive_list(&conn, &json!({}), None).expect("list ok")["count"],
            json!(2)
        );
        assert_eq!(
            handle_archive_stats(&conn, None).expect("stats ok")["archived_total"],
            json!(2)
        );
        handle_archive_restore(&conn, &json!({"id": alice}), None).expect("operator restore");
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

// #3383: caller overrides are confined to a cfg(test) module outside src/.
#[cfg(test)]
#[path = "../../../tests/unit/archive_gc_3383.rs"]
mod gc_tests_3383;
