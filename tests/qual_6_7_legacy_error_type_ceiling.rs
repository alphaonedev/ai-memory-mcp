// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! QUAL-6 + QUAL-7 (FX-C4-batch2, 2026-05-26) — `Result<Value,
//! String>` / `Result<(), String>` legacy ceiling.
//!
//! The v0.7.0 v2 review identified 81 `Result<Value, String>`
//! signatures in `src/mcp/tools/` (QUAL-6) and 6+ `Result<(),
//! String>` legacy validation helpers in `src/subscriptions.rs` /
//! `src/config.rs` / `src/atomisation/curator.rs` /
//! `src/daemon_runtime.rs` (QUAL-7). Both shapes collapse typed
//! errors into a single `String` bucket, losing HTTP-status /
//! audit-event / structured-trace context at the layer transition.
//!
//! Full migration of every handler is a multi-PR Wave-3 candidate;
//! what we lock in here is the CEILING — a future commit cannot
//! add NEW `Result<Value, String>` / `Result<(), String>`
//! signatures without explicitly raising the ceiling, which
//! surfaces the regression in code review.
//!
//! When a handler family migrates to `MemoryError` / `StoreError`,
//! the contributor lowers the ceiling in the same commit so the
//! discipline ratchets toward zero.

use std::fs;
use std::path::Path;

/// Walk a directory recursively for .rs files (matches the
/// pattern in `feature_flag_audit_arch_11.rs`).
fn walk_rs(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}

fn count_matches(root: &Path, needle: &str) -> usize {
    let files = walk_rs(root);
    let mut count = 0usize;
    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        // Count needle occurrences across the file. Each match
        // counts once; consecutive overlapping matches (e.g.
        // accidental nesting) are not expected and would inflate
        // the count, which is the right direction for the ceiling
        // gate.
        let mut idx = 0;
        while let Some(found) = content[idx..].find(needle) {
            count += 1;
            idx += found + needle.len();
        }
    }
    count
}

/// QUAL-6 ceiling: 81 sites at v2-review time + slack for in-batch
/// additions. Tighten in lockstep with handler-family migration.
///
/// 2026-06-16 — raised 90 → 96 for the v0.8.0 #1709 Pillar-1
/// coordination handler family in `src/mcp/tools/action.rs`: the 8
/// `memory_action_*` + `memory_lease_*` MCP handlers each return
/// `Result<Value, String>` to match the uniform `McpTool` dispatch
/// contract (`DispatchFn = fn(&ToolDispatchCtx) -> Result<Value,
/// String>`) that every one of the ~81 existing handlers already
/// uses. Adopting `MemoryError`/anyhow for this family alone would
/// make it inconsistent with the established surface and require
/// changing the shared dispatch signature — a separate migration, not
/// a per-tool choice. Net acknowledged addition: +6 (4 lease handlers
/// landed this batch; +2 slack).
///
/// 2026-06-16 — raised 96 → 101 for the v0.8.0 #1709 Pillar-1
/// signed-signal handler family in `src/mcp/tools/signal.rs`: the 5
/// `memory_signal_*` MCP handlers (send/read/inbox/thread/ack) each
/// return `Result<Value, String>` for the same uniform `McpTool`
/// dispatch-contract reason as the action/lease family above. Net
/// acknowledged addition: +5.
///
/// 2026-06-16 — raised 101 → 105 for the v0.8.0 #1709 Pillar-1
/// attested-checkpoint handler family in `src/mcp/tools/checkpoint.rs`:
/// the 4 `memory_checkpoint_*` MCP handlers (create/resolve/query/verify)
/// each return `Result<Value, String>` for the same uniform `McpTool`
/// dispatch-contract reason as the action/lease/signal families above.
/// Net acknowledged addition: +4.
///
/// 2026-06-16 — raised 105 → 110 for the v0.8.0 #1709 Pillar-1 routine
/// handler family in `src/mcp/tools/routine.rs`: the 5 `memory_routine_*`
/// MCP handlers (create/freeze/run/status/list) each return
/// `Result<Value, String>` for the same uniform `McpTool`
/// dispatch-contract reason as the action/lease/signal/checkpoint
/// families above. Net acknowledged addition: +5.
///
/// 2026-06-16 — raised 110 → 112 for the v0.8.0 #1709 §11.4 Pillar-1
/// FRONTIER surface in `src/mcp/tools/action.rs`: the 2 new
/// `memory_action_frontier` + `memory_action_next` MCP handlers each
/// return `Result<Value, String>` for the same uniform `McpTool`
/// dispatch-contract reason as the action/lease/signal families above.
/// Net acknowledged addition: +2.
///
/// 2026-06-22 — raised 112 → 114 for the #1718 Commit C3 MCP→HTTP
/// federation-forward bridge in `src/mcp/tools/store/transport.rs`: the 2 new
/// `forward_action_transition_to_http` + `forward_signal_send_to_http` helpers
/// each return `Result<Value, String>` to match the established
/// `forward_store_to_http` (#318) forward-family contract (the value flows
/// straight back into the `Result<Value, String>` MCP dispatch envelope).
/// Net acknowledged addition: +2.
/// 2026-07-15 — raised 114 → 116 for the #2024 skill retire/unretire/purge
/// lifecycle: the 2 new `handle_skill_retire` + `handle_skill_delete` handlers
/// each return `Result<Value, String>` to match the established skill-family
/// contract (`handle_skill_get`/`_list`/`_resource`/`_register`/`_export`/
/// `_compositional_context` all return `Result<Value, String>` — extending a
/// uniformly-String family, not seeding a new one). Net acknowledged: +2.
// 2026-08-07 (#2721 / CB-19) — raised 116 -> 119 for the reserved-principal
// wire-hardening split of `handle_namespace_set_standard` in
// `src/mcp/tools/namespace.rs` into the wire handler + the trusted in-process
// entry `handle_namespace_set_standard_trusted` + the shared
// `handle_namespace_set_standard_inner`, each returning `Result<Value, String>`
// for signature parity with the surrounding namespace-standard handler family
// (get/clear also `Result<Value, String>`). No new error contract; measured
// count is 119. Net acknowledged: +3.
// 2026-08-16 (#2983-#2987) — raised 119 -> 120 for the TEST-ONLY shim
// `handle_store` in `src/mcp/tools/store/tests.rs`. `handle_store` gained the
// `AtomiseWiring` parameter that replaces the abolished process-global
// dispatch (#2983); the shim supplies the empty default wiring to that file's
// 79 pre-existing fixtures, whose subject matter (parse / conflict /
// governance / envelope) is unrelated to atomisation. It MUST mirror the
// production signature, so it is `Result<Value, String>` by construction. No
// production handler was added and no new error contract exists — the
// atomisation-specific behaviour is asserted with an INJECTED curator by
// `tests/batman_atomise_wiring_2983.rs` and the hook's own unit suite.
// Net acknowledged: +1 (test-only).
// 2026-08-18 (#3040) — raised 120 -> 121 for the `handle_list_capped` inner
// helper split out of `handle_list` in `src/mcp/tools/list.rs`. The MCP list
// path now honors the operator `AI_MEMORY_MAX_PAGE_SIZE` page-size cap (parity
// with the HTTP `AppState.max_page_size` OOM guard); the cap is threaded as an
// explicit `page_cap` param to the inner helper so it is unit-testable without
// mutating the process-global. The helper MUST mirror the existing
// `Result<Value, String>` MCP-dispatch envelope of `handle_list`, so it is that
// type by construction — no new error contract. Net acknowledged: +1.
// 2026-08-22 (#3171 MCP tool-contract audit, rebased onto #3040) — raised
// 121 -> 124 for the reserved-principal wire-hardening split of
// `handle_namespace_clear_standard` into the wire handler + the trusted
// in-process entry `handle_namespace_clear_standard_trusted` + the shared
// `handle_namespace_clear_standard_inner` (+ `resolve_namespace_standard_caller`
// `Result<String, String>`). Exact #2721/CB-19 split the SET twin already
// carries. Measured 123 on the pre-#3040 branch; +1 for handle_list_capped
// already in 121. Net acknowledged: +3.
// 2026-09-02 (#3356) — raised 124 -> 125 for
// `handle_inbox_with_policy` in `src/mcp/tools/notify.rs`. The helper makes the
// MCP caller-isolation policy explicit and testable while the pre-existing
// `handle_inbox` entry point preserves trusted in-process CLI/hook behaviour.
// Both feed the established MCP inbox handler family and therefore retain its
// `Result<Value, String>` boundary. Net acknowledged: +1.
// 2026-09-02 (#3386 kg-query visibility) — raised 125 -> 127 for the two
// traversal paths split out of `handle_kg_query`: `kg_query_by_source_uri`
// and `kg_query_from_source` (`src/mcp/tools/kg_query.rs`). These add NO new
// legacy-typed surface — they are extractions of that one handler's own body,
// carrying its existing `Result<Value, String>` MCP envelope so the shared
// `namespace` / `as_agent` / bounds gate sits visibly above both paths and
// neither path can drift from it. The handler was 134 code lines after the fix
// (over `clippy::too_many_lines`); the split is what keeps it at 28. Stacks on
// the #3356 +1 above rather than replacing it. Never lower.
const QUAL_6_CEILING: usize = 127;

/// QUAL-7 ceiling: 6+ sites at v2-review time + slack. Raised
/// 25 → 26 for the #1455 fail-CLOSED governance pair in
/// `src/daemon_runtime.rs`
/// (`governance_consultation_unavailable` + its testable
/// `_inner`): both return `Result<(), String>` because they feed
/// the storage / wire-check hook closures whose boundary type IS
/// `Fn(&_) -> Result<(), String>`. The split is deliberate (the
/// `_inner` seam lets the secure-default vs. operator-override
/// verdict be unit-tested without env mutation), so collapsing it
/// to dodge the ratchet would be a regression. Net acknowledged
/// addition: +1.
///
/// 2026-06-12 — raised 26 → 29 for the GA uniform-90 coverage
/// campaign's in-file `#[cfg(test)]` mock impl of the
/// `FederationDlqStore` trait in `src/federation/push_dlq.rs`
/// (the replay-closure seam). The trait's methods
/// (`mark_dlq_row_replayed` / `bump_dlq_attempt` / the take-closure)
/// are deliberately `Result<(), String>` — the same documented
/// closure-framework carve-out as the `daemon_runtime` pair above —
/// so the test mock that exercises the postgres/sqlite replay arms
/// MUST match the trait signature. These 3 sites are test-only and
/// unavoidable; no new production string-error contract was added
/// (the trait pre-existed). Net acknowledged addition: +3.
///
/// 2026-06-20 (#1544) — raised 29 → 33 for the new
/// `FederationDlqSink::note_dlq_throttled` method (refresh `last_error`
/// without bumping `attempt_count` on a 429 throttle). It MUST match the
/// trait's existing `Result<(), String>` convention — the same documented
/// closure-framework carve-out as `mark_dlq_row_replayed` /
/// `bump_dlq_attempt` above — so the trait decl + the sqlite + postgres +
/// test-mock impls add 4 sites. No new error contract; the legacy String
/// shape is required for signature parity with the pre-existing trait.
/// Net acknowledged addition: +4.
///
/// 2026-06-29 (#1849 security review) — raised 33 → 34 for the factored
/// `forget_governance_gate_one_ns` helper in `src/mcp/tools/forget.rs`, which
/// returns `Result<(), String>` to match the existing forget-gate
/// `deny_message` convention it was extracted from (the per-namespace gate the
/// namespace-less bulk-forget branch now reuses). Signature parity with the
/// pre-existing single-namespace gate; no new error contract. Net: +1.
// 2026-07-07 (#1885) — raised 34 → 35 for the MCP pre-event enforcement gate
// helper `consult_pre_event_gate` in `src/mcp/mod.rs`, which returns
// `Result<(), String>` to match the surrounding MCP dispatch convention (its
// `Err` propagates via `?` straight into the `Result<Value, String>`
// `handle_store` / dispatch handlers it gates). Signature parity; no new
// error contract. Net: +1.
// 2026-07-07 (#1923 security review) — raised 35 → 37 for the two folder_path
// import-jail helpers added to `src/mcp/tools/skill_register.rs`:
// `reject_symlink_escape` and `ImportBudget::charge`. Both return
// `Result<(), String>` for signature parity with the surrounding
// `handle_skill_register` / `collect_resources` String-error surface they feed
// via `?` (the enclosing handler is `Result<Value, String>`). No new error
// contract — the same String shape the skill-register path already uses. Net: +2.
// 2026-07-24 (#2356 W1A6-03 PE-1) — raised 37 → 38 for
// `mcp::consult_pre_governance_decision_gate`: signature parity with the
// `consult_pre_event_gate` dispatch surface it wraps (the enclosing MCP
// handlers are `Result<Value, String>`; the HTTP twin maps the String to a
// typed 503 at the boundary). No new error contract. Net: +1.
// 2026-08-16 (#2998 coordination-plane hardening) — raised 38 → 40 for the two
// `src/coordination_guard.rs` input-guard helpers `require_namespace` /
// `require_payload_size` (plus `require_text`), which feed the String-error MCP
// coordination create handlers (`handle_action_create` / `handle_signal_send` /
// `handle_checkpoint_create` / `handle_routine_create`) via `?` (each enclosing
// handler is `Result<Value, String>`). No new error contract — the same String
// shape the coordination handlers already use. Measured 40.
// 2026-08-20 (#2542 GA Wave-2 namespace-standard chain graft) — raised 40 → 42
// for the two namespace-standard parent-graft authorization helpers
// `authorize_namespace_standard_parent` / `authorize_namespace_standard_owner`
// in `src/mcp/tools/namespace.rs`. They mirror the SHIPPED sibling
// `authorize_namespace_standard_bind` (already `Result<(), String>`): the String
// refusal flows verbatim into the HTTP 403 body AND the forensic audit record on
// the local `set_standard` funnels, so no new error contract is introduced.
// A MemoryError migration of the whole namespace-standard authorization cluster
// is a separate follow-up. Measured 42.
// 2026-08-21 (#2991 GA Wave-2 approval chokepoint) — raised 42 → 43 for the L1-6
// escalate PRODUCER helper `daemon_runtime::route_or_block_escalated_write`
// (`Result<(), String>`: the String refusal flows into the fail-closed block).
// Measured 43.
// 2026-08-22 (#3204 item 7) — raised 43 -> 44 for `gate_gc_sweep` in
// `src/mcp/tools/archive.rs`, the three-gate guard (K9 permission rules +
// the #1849 bulk-delete governance rule + the forensic `allow` row) that
// `memory_gc` was missing entirely. `Result<(), String>` because its refusal
// flows verbatim into the enclosing `handle_gc`'s `Result<Value, String>` via
// `?`, exactly like the sibling gates in `handle_archive_purge`. No new error
// contract. Measured 44.
// 2026-08-25 (#3223 rebase onto ecce0a86) — raised 44 -> 45 for
// `governance::agent_action::validate_matcher_for_kind` (#3031 fail-closed
// matchers). Same `Result<(), String>` contract as `validate_command_substring`
// (operator-facing write-time validator, rendered verbatim by `rules add`).
// Floors never fall: #3204's `gate_gc_sweep` and #3031's matcher validator
// are independent adds. Measured after rebase.
// 2026-08-26 (#3239 rebase onto e9bf9dea) — raised 45 → 47 for the two
// #3173 mutate-site helpers `assert_caller_may_mutate` /
// `assert_caller_may_mutate_all` in `src/mcp/tools/store/synthesis.rs`.
// They return `Result<(), String>` so a cross-owner refusal flows verbatim
// into the MCP `handle_store` `Result<Value, String>` envelope
// (`CALLER_DOES_NOT_OWN_MEMORY`) — the same String-refusal contract as
// the rest of the store handler, not a new error type. Independent of
// #3204/#3223; never lower. Re-measure after this rebase.
//
// 2026-08-30: re-measured to the actual count (48) — the pin was stale at
// 47 while the tree held 48 `Result<(), String>` occurrences (pre-existing,
// present since before this release-dev cycle; `assert_age_id_safe` etc.
// are legacy helpers). Corrected to reflect reality; FOLLOW-UP: migrate one
// legacy String-error helper to `anyhow`/`MemoryError` to ratchet back to 47.
const QUAL_7_CEILING: usize = 48;

#[test]
fn qual_6_result_value_string_count_below_ceiling() {
    // QUAL-6: production MCP handlers under `src/mcp/tools/` carry
    // 81 `Result<Value, String>` signatures at v2-review time. The
    // ceiling locks this in so a regression that adds a NEW
    // legacy-typed handler fails the gate.
    let count = count_matches(Path::new("src/mcp/tools"), "Result<Value, String>");
    assert!(
        count <= QUAL_6_CEILING,
        "QUAL-6: src/mcp/tools/ has {count} `Result<Value, String>` signatures \
         (ceiling {QUAL_6_CEILING}). New handlers MUST use `MemoryError` (typed) \
         or anyhow::Error (untyped). Lower the ceiling when migrating an existing \
         family.",
    );
}

#[test]
fn qual_7_result_unit_string_count_below_ceiling() {
    // QUAL-7: 6+ `Result<(), String>` validation helpers across
    // src/subscriptions.rs / src/config.rs / src/atomisation /
    // src/daemon_runtime. Pin the count.
    let count = count_matches(Path::new("src"), "Result<(), String>");
    assert!(
        count <= QUAL_7_CEILING,
        "QUAL-7: `Result<(), String>` count in src/ = {count} (ceiling {QUAL_7_CEILING}). \
         New validation helpers should return `Result<(), MemoryError>` or anyhow. \
         Lower the ceiling when migrating.",
    );
}
