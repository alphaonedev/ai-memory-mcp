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
//!     - any UNKNOWN / legacy scope string (e.g. "shared") → visible
//!       (broadly). This is the documented shareable-shape posture the
//!       federation projection lane relies on (`#948` / `#978` — a
//!       `scope=shared` row projects to any allowlisted peer). #1921
//!       DELIBERATELY does NOT tighten this arm: the CWE-863 exploit it
//!       closes is the team/unit/org SUBTREE disclosure, and failing
//!       unknown scopes closed would break legitimate federation
//!       sharing. An owner making their OWN row broadly readable leaks
//!       no other tenant's data.
//!
//! #1921 scope note: the private-owner fix (#1720) and the
//! collective/unknown broad-visibility semantics are unchanged; the ONLY
//! behavioural change is that team/unit/org are now subtree-restricted
//! (was: world-readable).

use crate::models::Memory;

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
    // is DESIGNED that way), `private` stays owner-keyed (#1720), and any
    // UNKNOWN / legacy scope string (e.g. "shared") stays broadly visible
    // — that is the documented federation shareable-shape posture the
    // `/sync/since` projection lane relies on (#948 / #978). Failing
    // unknown scopes closed would break legitimate federation sharing, so
    // #1921 leaves that arm untouched (an owner broadening their OWN row
    // leaks no other tenant's data).
    use crate::models::namespace::MemoryScope;
    let scope_str = mem
        .metadata
        .get(crate::META_KEY_SCOPE)
        .and_then(serde_json::Value::as_str);
    match scope_str.map(MemoryScope::from_str) {
        // Field absent → default private (owner-keyed).
        None => private_visible(mem, caller),
        // Present but unknown / legacy (e.g. "shared") → broadly visible
        // (federation shareable shape; pre-#1921 behaviour preserved).
        Some(None) => true,
        Some(Some(MemoryScope::Private)) => private_visible(mem, caller),
        // Visible to every authenticated caller, regardless of namespace.
        Some(Some(MemoryScope::Collective)) => true,
        // #1921 — subtree-restricted: the memory's namespace must fall
        // within the caller's team / unit / org ancestor. `caller` is the
        // agent id, which IS the agent's namespace prefix. A missing
        // ancestor (the caller's namespace is too shallow, or `caller` is
        // a synthetic `anonymous:req-…` id with no `/`) → deny.
        Some(Some(MemoryScope::Team)) => scope_subtree_visible(mem, caller, 1),
        Some(Some(MemoryScope::Unit)) => scope_subtree_visible(mem, caller, 2),
        Some(Some(MemoryScope::Org)) => scope_subtree_visible(mem, caller, 3),
    }
}

/// Owner / inbox-target check for a `scope=private` (or default) row.
fn private_visible(mem: &Memory, caller: &str) -> bool {
    let owner = mem
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if owner == caller {
        return true;
    }
    let target = mem
        .metadata
        .get(crate::META_KEY_TARGET_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    target == caller
}

/// #1921 — subtree gate for `team` / `unit` / `org` scope. `ancestor_idx`
/// selects the caller's team (1), unit (2), or org (3) namespace ancestor
/// (index 0 is the caller's own namespace / private position). The memory
/// is visible iff its namespace equals, or is nested under, that ancestor.
/// Mirrors `crate::storage::is_visible` + `matches_subtree` exactly.
fn scope_subtree_visible(mem: &Memory, caller: &str, ancestor_idx: usize) -> bool {
    let ancestors = crate::models::namespace_ancestors(caller);
    let Some(prefix) = ancestors.get(ancestor_idx) else {
        return false;
    };
    mem.namespace == *prefix || mem.namespace.starts_with(&format!("{prefix}/"))
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
