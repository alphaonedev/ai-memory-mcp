# CI time facts, November 2026 (#9710)

Measured on 2026-11-20 (`date -u`: Fri Nov 20 16:29:18 UTC 2026). Measurement only: no workflow, `Cargo.toml`,
`Cargo.lock` or `.cargo` file changed. Every figure names its command and its run or job ids. A figure that could
not be measured says "not measured" with the error.

## 1. Where the minutes of a test job go

Command: `python3 -I scripts/ci/measure_ci_time.py --repo alphaonedev/ai-memory-mcp --branch chain/promo6-ssh-r2 --json-out <file>`
(the last 10 green runs of ci.yml and of coverage.yml on that branch; gh GET calls only). Values are seconds,
median (min-max). n is 10 for every column except queue.

Queue is `started_at - created_at` of the job. A job carried over from an earlier attempt has `started_at` before
`created_at`; its queue is "not measurable" and is left out, so queue has n = 8 or 9 on those rows. Compile and test
share one step (`Run tests (impact-aware)`, `Generate coverage JSON`): compile is the first cargo
`Finished ... target(s) in <duration>` line inside the step plus any separate prebuild step, test is the rest of the
step wall time. For the linux-fed enterprise-fed leg the "test" figure includes the host-semaphore wait inside the
step (up to 3600 s) and any later cargo invocation. A compile of 1 s is a warm cache or a cargo skip.

| Job | Runner kind | Queue | Setup/cache | Compile | Test | Post | Total |
|---|---|---|---|---|---|---|---|
| ci.yml Check (linux-fed,enterprise-fed) | self-hosted Linux | 189 (1-2438) n=9 | 66 (21-959) | 2975 (1-6442) | 3775 (1008-7285) | 8 (4-56) | 7318 (1059-10739) |
| ci.yml Check (macos-fed,enterprise-fed) | macos-fed | 1990 (598-2433) n=8 | 20 (18-25) | 512 (181-832) | 2070 (319-2440) | 4 (2-4) | 2624 (553-3301) |
| ci.yml Check (macos-fed,sqlite) | macos-fed | 1 (1-3) n=8 | 8 (5-73) | 368 (155-549) | 1564 (421-1939) | 2 (1-4) | 1988 (597-2430) |
| ci.yml Check (ubuntu-latest,sqlite) | hosted | 2 (1-2) n=9 | 160 (115-188) | 1952 (1190-2572) | 1529 (309-2020) | 356 (12-449) | 3774 (1942-5188) |
| coverage.yml Per-Module Coverage Thresholds | hosted | 3 (1-7) n=10 | 192 (148-237) | 999 (835-1073) | 3924 (2631-4277) | 26 (18-77) | 5164 (3695-5580) |

ci.yml run ids, newest first: 43787761690, 43754672049, 43726986530, 43699071569, 43671113552, 42455028843,
42404345563, 42389131152, 42381644290, 42363891711.
coverage.yml run ids: 43787761588, 43754671906, 43726986507, 43699071556, 43671113588, 43401706402, 42455028967,
42404345599, 42389131185, 42381644438.
The per-run rows (job ids, head shas) are in the script's `--json-out` file; the unit test is
`scripts/ci/tests/test_measure_ci_time_9710.py` (hand-written fixture).

## 2. cargo-nextest against `cargo test`, sqlite suite, one build

Host: the f1 macOS node. `uptime` before the first compile showed load1 6 to 10 (below the 30 limit);
load1 after each run is in the table. Environment: `CARGO_TARGET_DIR=<lane dir> CARGO_PROFILE_DEV_DEBUG=0
CARGO_PROFILE_TEST_DEBUG=0 AI_MEMORY_NO_CONFIG=1`. cargo 1.99.1; cargo-nextest 0.9.152 (crates.io, built with
`cargo install cargo-nextest --locked --version 0.9.152 --root <tools dir>`, outside the repository).

Targets (same for every command): `--lib` plus `--test` for the 10 integration binaries with the longest `finished in`
time in job 133082849450 (Check macos-fed,sqlite, ci.yml run 43787761690, ranked with
`measure_ci_time.py --rank-job 133082849450`): tls_serve_helper_8293, mcp_signal_drain_4347, recall_observability,
file_sink_warn_3650, l07_3_chunk_d_http_surface, federation_catchup_posture_3582, bulk_post_commit_stages_2724,
e2_post_ship_dry_run, integration, federation_inbox_wake_3631. Never `cargo build --tests`, never a bare `cargo test`.

| Step | Command (after the targets are added) | Wall | rc | load1 after | Tests |
|---|---|---|---|---|---|
| build (cold) | `cargo test --no-run` | 135.7 s | 0 | not recorded | n/a |
| cargo test run 1 | `cargo test --no-fail-fast` | 786.2 s | 0 | 7.4 | 9802 passed, 0 failed, 2 ignored |
| cargo test run 2 | `cargo test --no-fail-fast` | 753.4 s | 0 | 7.6 | 9802 passed, 0 failed, 2 ignored |
| nextest run 1 | `cargo nextest run --no-fail-fast` | 263.7 s (nextest summary 261.5 s) | 100 | 18.1 | 9796 run: 9704 passed, 92 failed, 2 skipped |
| nextest run 2 | `cargo nextest run --no-fail-fast` | 268.7 s | 100 | 17.0 | 9796 run: 9694 passed, 102 failed, 2 skipped |

Target directory after the compile: `du -sh` 6.3G (6.2G after the runs); removed at the end.

Test counts. `cargo test -- --list` prints 9798 `: test` lines (the per-binary `N tests` headers add up to 9797: 9366 lib plus 431), of which 2 are `#[ignore]`d:
`audit::verify_snapshot_4332_tests::verify_in_a_loop_never_starves_audited_writes_4332` and
`reranker::issue_1597_tests::issue_1597_neural_rerank_timing_evidence`. `cargo nextest list` shows 9796 and nextest
reports those 2 as skipped. The `test result:` lines of the cargo test log add up to 9802 passed, 4 more than the list; the
cause was not isolated (not measured: no per-binary reconciliation of the `test result:` lines).

### Tests that fail only under nextest (process per test)

Under `cargo test` 0 tests failed in both runs. Under nextest 131 distinct tests failed in at least one of two runs, 63 in
both. Every failure message that was read names the same cause: `#3354: refusing to start a ledger-writing command as
host:<name>: no signing key for that id is loadable and one could not be generated (no key was loadable after the
ensure step)`, plus the follow-on `invalid JSON response` and `status.success()` assertions. The failing set changes
between runs, which a per-test isolation difference would not do. Probes on the same build:

| Command | Result |
|---|---|
| `cargo nextest run --test integration test_link_creation` (alone) | 1 passed |
| `cargo nextest run --test integration test_link_creation test_budget_truncates_to_fit test_boundary_confidence_one` | 0 passed, 3 failed (2.4 s) |
| the same three tests with `-j 1` | 3 passed (3.9 s) |

The tests pass alone and one at a time and fail when several nextest processes start together, so the measured
mechanism is concurrent first-start generation of the per-host signing key (`src/governance/audit.rs`, the #3354
refusal). Under `cargo test` the tests of one binary share a process. The cause in the code was not traced further.

Failed in both nextest runs (63; `L:` = lib, `I:` = the `integration` binary):

```
L:cli::store::tests::store_sign_with_allow_claimed_stores_claimed_and_warns_3409,
L:cli::store::tests::store_sign_with_bound_key_is_agent_attested_3409,
L:cli::store::tests::store_sign_without_bound_key_refuses_3409,
L:cli::store::tests::test_store_sign_with_bound_key_stamps_agent_attested,
L:federation::tests::post_and_classify_id_drift_does_not_retry,
L:federation::tests::post_and_classify_persistent_fail_concatenates_both_reasons,
L:federation::tests::success_with_clean_or_absent_report_stays_ack,
L:federation::tests::success_with_skipped_items_is_not_ack,
L:federation::tests::success_with_unsupported_on_postgres_is_not_ack,
L:handlers::tests::http_bulk_create_fans_out_with_federation,
I:test_agentid_visible_in_toon_and_json,
I:test_approver_consensus_same_agent_does_not_double_count,
I:test_approver_consensus_threshold_auto_executes,
I:test_approver_delete_consensus_executes_delete, I:test_approver_human_any_approver_accepted,
I:test_boundary_priority_max, I:test_boundary_priority_min,
I:test_budget_one_returns_overflow_memory, I:test_budget_preserves_rank_order,
I:test_budget_response_includes_metadata, I:test_budget_truncates_to_fit,
I:test_budget_unlimited_returns_all, I:test_consensus_unregistered_voter_rejected,
I:test_enforce_owner_blocks_non_owner_delete, I:test_enforce_pending_list_and_approve,
I:test_enforce_pending_reject_status, I:test_enforce_registered_allows_registered,
I:test_enforce_registered_blocks_unregistered, I:test_import_roundtrip_count_match,
I:test_inherit_4_level_chain, I:test_inherit_deep_namespace_8_levels, I:test_inherit_global_only,
I:test_inherit_missing_intermediates_skipped, I:test_inherit_preserves_3_level_flat_behavior,
I:test_inherit_recall_auto_prepends_chain, I:test_link_creation,
I:test_mcp_agent_register_and_list, I:test_mcp_dedup_replaces_metadata, I:test_mcp_initialize,
I:test_mcp_missing_tool_name, I:test_mcp_namespace_standard_auto_prepend, I:test_mcp_prompts_list,
I:test_mcp_recall_default_toon, I:test_mcp_store_and_recall, I:test_mcp_store_with_metadata,
I:test_mcp_update_metadata, I:test_mcp_update_preserves_agent_id,
I:test_mine_stamps_caller_agent_id, I:test_namespace_auto_detect_parent,
I:test_namespace_isolation, I:test_namespace_standard_cascade_on_delete,
I:test_recall_fold_no_longer_auto_promotes, I:test_recall_priority_order,
I:test_scope_collective_always_visible,
I:test_scope_flat_namespace_owner_sees_own_private_plus_collective,
I:test_scope_invalid_rejected_at_store, I:test_scope_missing_treated_as_private,
I:test_scope_no_as_agent_returns_all, I:test_scope_org_visible_across_whole_org,
I:test_scope_search_respects_owner, I:test_scope_team_visible_in_parent_subtree,
I:test_stats_accuracy, I:test_ttl_assignment
```

Failed in exactly one of the two runs (68):

```
I:http_namespace_standard_query_string_set_get_clear, I:http_notify_rejects_missing_payload,
I:test_agentid_dedup_preserves_original, I:test_agentid_search_filter,
I:test_agentid_update_preserves_provenance, I:test_agentid_validator_rejects_bad_input,
I:test_agents_list_uses_reserved_namespace,
I:test_approver_agent_rejected_not_counted_for_consensus,
I:test_approver_agent_rejects_wrong_caller, I:test_approver_consensus_below_threshold_pending,
I:test_boundary_confidence_one, I:test_boundary_confidence_zero, I:test_boundary_max_title_length,
I:test_budget_explicit_zero_returns_empty, I:test_budget_mcp_tool_schema_and_response,
I:test_budget_touch_only_surviving, I:test_cli_bench_emits_json_with_eight_results_report_only,
I:test_cli_prefix_id_resolution, I:test_cli_smoke_canonical_paths, I:test_cli_store_and_recall,
I:test_cli_sync_dry_run_writes_nothing, I:test_cli_validate_id_rejects_invalid,
I:test_consensus_case_insensitive_dedup_when_variants_registered,
I:test_consensus_case_variant_rejected_if_only_lowercase_registered,
I:test_consolidate_attributes_to_consolidator,
I:test_consolidate_stamps_curator_derived_provenance_1633, I:test_enforce_any_allows_store,
I:test_enforce_approve_queues_pending, I:test_enforce_mcp_pending_tools,
I:test_enforce_owner_allows_self_delete, I:test_enforce_promote_with_approve_policy,
I:test_export_includes_links, I:test_forget_by_pattern,
I:test_governance_inherit_path_surfaces_per_level, I:test_governance_set_and_get_roundtrip,
I:test_health_endpoint, I:test_hier_recall_2_level_ancestor_only,
I:test_hier_recall_budget_applied_after_proximity, I:test_hier_recall_flat_namespace_unchanged,
I:test_hier_recall_proximity_boost_ranks_closest_first,
I:test_hier_recall_returns_ancestor_memories, I:test_hier_recall_touches_only_ancestor_matches,
I:test_import_export_roundtrip, I:test_import_restamps_agent_id_by_default,
I:test_import_trust_source_preserves_agent_id, I:test_inherit_default_omits_chain,
I:test_inherit_no_standards_returns_empty, I:test_mcp_prompts_get_recall_first, I:test_mcp_stats,
I:test_mcp_store_invalid_metadata_defaults_to_empty, I:test_mcp_tools_list,
I:test_mcp_unknown_tool, I:test_promote_command, I:test_reject_oversized_content,
I:test_scope_private_visible_only_to_owner, I:test_scope_unit_visible_in_grandparent_subtree,
I:test_search_with_since_future, I:test_serve_mtls_fingerprint_allowlist_accepts_only_known_peer,
I:test_serve_native_tls_health_probe, I:test_sync_daemon_mesh_propagates_memory_between_peers,
I:test_tier_downgrade_rejected, I:test_tier_upgrade_allowed, I:test_unicode_handling,
I:test_visibility_wildcard_percent_smuggling_blocked,
I:test_visibility_wildcard_underscore_smuggling_blocked,
I:test_vpromote_clones_to_ancestor_and_links, I:test_vpromote_flat_namespace_cannot_promote,
I:test_vpromote_rejects_non_ancestor
```

## 3. Larger GitHub-hosted runners (gh GET only, nothing created)

| Endpoint (GET) | Status |
|---|---|
| `users/alphaonedev` | 200, `type` is `User` |
| `orgs/alphaonedev` | 404 Not Found |
| `orgs/alphaonedev/actions/runner-groups` | 404 |
| `orgs/alphaonedev/actions/hosted-runners` | 404 |
| `orgs/alphaonedev/actions/hosted-runners/machine-sizes` | 404 |
| `orgs/alphaonedev/actions/hosted-runners/images/github-owned` | 404 |
| `orgs/alphaonedev/actions/runners` | 404 |
| `users/alphaonedev/actions/runners` | 404 |
| `repos/alphaonedev/ai-memory-mcp/actions/runners` | 200, 9 self-hosted runners (below) |
| `repos/alphaonedev/ai-memory-mcp/actions/permissions` | 200, `enabled` true, `allowed_actions` all |
| `orgs/alphaonedev/settings/billing/usage` | 404 |
| `users/alphaonedev/settings/billing/usage` | 403 "Resource not accessible by personal access token" |
| `users/alphaonedev/settings/billing/actions` | 403 |
| `users/alphaonedev/settings/billing/premium_request/usage` | 403 |

Repository runners: 9 self-hosted. macOS ARM64 label `macos-fed`: 5 (3 online, 2 offline). Linux X64 label
`linux-fed`: 4, all online. (Names and labels only; no secret was read.)

Owner and larger runners. The owner `alphaonedev` is a `User` account (no organization exists at that name), so the
org hosted-runner endpoints return 404 and the larger-runner API was not reachable: "not measured: HTTP 404 on every
`orgs/alphaonedev/actions/hosted-runners*` endpoint". the GitHub Docs
"Billing" reference page for Actions runner rates (docs.github.com, read 2026-11-20 through a page fetch) states
"Larger runners are only available for organizations and enterprises using the GitHub Team or GitHub Enterprise Cloud
plans". The page shows no last-updated date, so per-minute prices are "price not read". Plan name of the account:
not measured (`GET user` returned no `plan` field for this token).

## 4. What the numbers say

1. Queue wait for ci.yml Check (macos-fed,enterprise-fed) has median 1990 s (598-2433, n=8); every other measured job has a median queue of 189 s or less.
2. ci.yml Check (ubuntu-latest,sqlite) compile has median 1952 s against 368 s for Check (macos-fed,sqlite), which runs the same sqlite leg.
3. ci.yml Check (linux-fed,enterprise-fed) total has median 7318 s (1059-10739), against 1988 s for Check (macos-fed,sqlite) and 2624 s for Check (macos-fed,enterprise-fed).
4. On one build, nextest took 263.7 s and 268.7 s against 786.2 s and 753.4 s for `cargo test`, and 92 and 102 tests failed under nextest against 0 under `cargo test`; 63 failed in both runs.
5. coverage.yml Per-Module Coverage Thresholds has median total 5164 s, of which 3924 s is the test part of the llvm-cov step.
