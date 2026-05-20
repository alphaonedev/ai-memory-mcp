# Section 4 — Governance Enforcement + Audit + Forensic Chain

**Specialist:** S4 (governance / audit / forensic chain)
**Base SHA:** `b4ba16c8cfcfab459e08e1115518aaf8b273b407`
**Branch:** `local/install-815-816`
**Tool stack used:** grep + Read (LSP unavailable in this worktree; CLAUDE.md notes rust-analyzer is a per-developer setup, not preinstalled here).

## D.1 — Every write path → check_agent_action OR forensic-logged bypass

**PASS.** Substrate memory writes funnel through three insert variants in `src/storage/mod.rs` (`insert` L567, `insert_with_conflict` L786, `insert_if_newer` L5562); every one calls `consult_governance_pre_write(mem)` BEFORE the SQL write (`src/storage/mod.rs:114-130`). The `GOVERNANCE_PRE_WRITE` OnceLock is installed at daemon boot in `src/daemon_runtime.rs:2293-2371` and resolves to `check_agent_action_deferred` against an `AgentAction::Custom { custom_kind: "memory_write" }` envelope, so every HTTP/MCP write of a `Memory` is gated.

Daemon-side wire-points for the four substrate-external kinds (`Bash`, `FilesystemWrite`, `NetworkRequest`, `ProcessSpawn`) consult `crate::governance::wire_check::check` from six callsites: `src/llm.rs:425`, `src/mcp/tools/skill_export.rs:{162,209}`, `src/federation/sync.rs:71`, `src/hooks/executor.rs:{521,905}`. The hook is installed in `daemon_runtime.rs:2386-…` and resolves to `check_agent_action_no_audit` plus a forensic emit.

**Write-path tally (substrate-external + memory-write scope of S4):** 3 storage::insert callsites + 6 wire_check callsites = 9 audited paths; 0 documented missing-gate defects in the scope spec.

**Out-of-scope-but-noted bypasses (intentional design):** `memory_delete`, `forget`, `link`/`unlink`, `approve_pending`/`reject_pending`, `agent_register`, `restore_archive`, `consolidate`, `skill_register` are substrate-INTERNAL self-management operations and bypass `check_agent_action` by design. They DO write to the `audit_log` table via `crate::audit::AuditAction::{Store, Delete, Link, Approve, Reject}`. They are not policy-engine targets — the engine is scoped to the FIVE outside-world `AgentAction` kinds. Verified via `grep -rn 'AuditAction::' src/handlers/`.

## D.2 — Decision → audit_log + signed forensic log completeness

**PASS.** `check_agent_action` is symmetric: every call emits `emit_check_event` → `signed_events` row (`agent_action.rs:670-702`) AND `emit_forensic_decision` → daily `forensic-YYYY-MM-DD.jsonl` (`agent_action.rs:646-668`). Both fire on Allow/Refuse/Warn — no decision class is one-sink-only. The `_no_audit` variant intentionally skips the `signed_events` write to dodge re-entrant SQLite deadlock when called from inside `storage::insert`; the deferred-audit queue (D.4) restores the chain-log property for the refusal class on that path.

The handler-level `audit_log` table is a separate, broader-purpose audit surface (capability expansion, Store/Link/Approve/Reject events) — distinct from the governance-decision chain. Both are present and exercised.

## D.3 — Operator rule signing

**PASS.** `src/governance/rules_store.rs::list_enabled_by_kind` runs every loaded row through `enforced_rule_passes` (L200-242). Matrix: pubkey present + `operator_signed` + sig verifies → enforce; pubkey present + sig fails → tracing::error + SKIP (does not crash); pubkey present + `unsigned` → tracing::warn + SKIP; pubkey absent → pre-L1-6 mode passes every enabled row (activation cliff). Tests at L726-880 pin the matrix: `verify_rule_signature_fails_on_enabled_flip`, `_on_matcher_tamper`, `_under_wrong_key`, `_on_missing_signature`. Tampering ANY of `{id, kind, matcher, severity, reason, namespace, created_by, enabled, attest_level}` invalidates the sig because all are in the canonical bytes (L726-740 test scope). INSERT path does not block unsigned rows — operator workflow is insert-then-sign via `update_signature` + the `ai-memory rules sign-seed` CLI. Verified the `rule_list` MCP tool is read-only (issue #691 design revision 2026-05-13) so the only mutation paths are CLI/HTTP, both of which verify operator authority before reaching the SQL.

## D.4 — Deferred audit queue panic recovery

**SHIP-WITH-CAVEAT.** `src/governance/deferred_audit.rs::spawn_supervised_drainer` (L675-725) catches `JoinHandle::is_panic()`, bumps the `drainer_panics` metric (L698), and emits a `tracing::error!` with operator-action instructions (L699-706). The receiver is then DROPPED — the supervisor does NOT respawn the drainer, because the receiver is moved into the panicked task and is unrecoverable today (L707-714, explicit `let _ = max_restarts;`). Subsequent `submit` attempts to the closed channel land in the `send_failures` metric (D.2 send-failure path). The `max_restarts` parameter is preserved for a future buffering scheme that can survive a drainer panic.

**Why this is SHIP-with-caveat, not a blocker:** the loss is observable (metric + ERROR log + operator instruction) and the audit row that DID survive (the in-flight refusal that triggered the panic) is the only audit-chain hazard; future refusals submitted after the panic are recorded as `send_failures` rather than silently dropped. The DLQ at `signed_events_dlq` (drainer-side) catches the OTHER failure mode (SQLite UNIQUE-race retry exhaustion, `APPEND_UNIQUE_RACE_MAX_RETRIES = 5`). The "audit row silently lost" property is **never** observed — every failure leaves a metric and a log artifact. The "supervisor restarts after panic" semantic the prompt asked about is **not implemented**; the code comments the gap honestly.

**Recommendation (non-blocking, post-v0.7.0):** implement the buffered-restart pattern so the `max_restarts` parameter becomes load-bearing. Tests `supervisor_records_panic_metric_on_drainer_panic` (L1041) + `supervisor_graceful_shutdown_drains_buffered_events` (L1078) pin the current contract.

## D.5 — Forensic export bundle integrity

**PASS.** `src/forensic/bundle.rs::verify` (L1111-1219) round-trips: per-file SHA-256 recompute (L1149-1152) populates `tampered_files`; missing files (L1157-1161) populate `missing_files`; manifest signature verify via `pubkey.verify_strict` (L1184-1187) sets `signature_status::{Verified, Failed, UnknownSigner}`; every `edges/*.json` envelope re-verifies its Ed25519 signature via `verify_edge_envelope` (L1226-1252). Top-level `ok` rolls failures: `report.ok = tampered.is_empty() && missing.is_empty() && chain_edges_failed.is_empty() && !matches!(signature_status, Failed)` (L1213-1216). Manifest holds per-file `path:size:sha256` (L137, L654) and `canonical_signed_bytes` (L647) defines the stable signing input.

## D.6 — governance::audit chain hash verification

**PASS.** `src/governance/audit.rs::verify_since` (L299-430) is correct:

- Loop 1 (file date < cutoff, L310-325): advances `prev_hash = row.self_hash()` per row, no signature verify. This is intentional — the cutoff lets an auditor verify a partial slice; rows prior to the cutoff serve only as seed for the chain head at the cutoff line. They CANNOT be silently tampered without breaking the chain at the first verified row, because Loop 2's first iteration checks `row.prev_hash != prev_hash` (L357) against the value Loop 1 carried in.
- Loop 2 (file date >= cutoff, L327-422): per-row verify + chain continuity check + base64 decode + signature length check + `pk.verify(&canonical, &sig)`. Failure modes are mutually exclusive (`Parse | ChainBreak | Signature`); the first failure short-circuits with `Ok(VerifyReport { first_failure: Some(…) })`.

CI pin: tests `record_then_verify_signed_chain`, `tampering_detected_by_verify`, `unsigned_rows_counted_not_failed`, `cross_thread_bleed_is_reproducible_without_lock_then_recovered_by_fresh_init` (L564-770) all live in `#[cfg(test)] mod` so `cargo test` runs them.

## D.7 — Cross-tenant rule scoping

**PASS-by-design.** Rules are global to the substrate, not per-tenant. `Rule.namespace` defaults to `_global` and the SQL filter in `list_enabled_by_kind` is `WHERE kind = ?1 AND enabled = 1` (L172-178) — no namespace filter, no agent filter. `RuleEngine::evaluate(_agent_id, action)` ignores `agent_id` (L540, underscore prefix; doc-comment L536-538 notes the field is threaded for future per-agent matchers but unused today). This is the intended architecture: operator-authored rules are substrate-level policy, not tenant policy. No cross-tenant leak is possible because there is no per-tenant rule space; all rules apply to all actions of matching kind. The agent_id IS carried through to the audit row (`emit_check_event` L692, `emit_forensic_decision` L662) so per-agent attribution survives.

## Ship-blockers

**None.** The supervisor-no-respawn behavior (D.4) is honestly documented and observable; it is not a silent loss. Recommend a future-revision buffering pattern but do not gate v0.7.0 on it.

## Verdict

**SHIP.**
