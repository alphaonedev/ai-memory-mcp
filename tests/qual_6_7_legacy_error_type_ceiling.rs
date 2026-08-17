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
const QUAL_6_CEILING: usize = 120;

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
const QUAL_7_CEILING: usize = 38;

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
