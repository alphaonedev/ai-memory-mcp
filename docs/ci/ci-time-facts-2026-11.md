# CI time facts, November 2026 (#9710)

Measured on 2026-11-20 (`date -u`: Fri Nov 20 16:29:18 UTC 2026); section 2 was re-read from the stored logs at
2026-11-20T22:48:42Z UTC (below). Measurement only: no workflow, `Cargo.toml`,
`Cargo.lock` or `.cargo` file changed. Every number of section 1, and every time and count of the section 2 tables and
of its test-count paragraph (including the `9365 filtered out` figure and the two ignored test names), is printed by
`scripts/ci/measure_ci_time.py` from a named source (the GitHub jobs API for section 1, the stored benchmark logs for
section 2) at the time named in its section. In section 2 the script prints the counts of the two fail-name lists (63
in both, 131 in either) but not the names; the names were compared with the `FAIL` names of `nextest-1.log` and
`nextest-2.log` and match. The host, tool versions, target list and probe command lines of section 2 are not script
output. A figure the script could not measure says "not measured" with the reason, and the script exits 7 instead of 0
when any stored log is not measured. The numbers of section 3 are gh GET statuses, listed with their endpoints.

## 1. Where the minutes of a test job go

Command: `python3 -I scripts/ci/measure_ci_time.py --repo alphaonedev/ai-memory-mcp --branch chain/promo6-ssh-r2 --json-out <file>`
(the last 10 green runs of ci.yml and of coverage.yml on that branch; gh GET calls only). Values are seconds,
median (min-max). n is 10 for every column except queue.

Queue is `started_at - created_at` of the job. A job carried over from an earlier attempt has `started_at` before
`created_at`; its queue is "not measurable" and is left out, so queue has n = 8 or 9 on those rows. Compile and test
share one step (`Run tests (impact-aware)`, `Generate coverage JSON`): compile is the first cargo
`Finished ... target(s) in <duration>` line inside the step plus any separate prebuild step, test is the rest of the
step wall time. Link time is inside the compile figure and is not split out: cargo prints one `Finished` time for
compile and link together, so the compile / link / test-run split of the issue is a compile-with-link / test-run split.
A row whose timestamps are missing or inconsistent is `unmeasured` (named reason, footer line under the table) and is
left out of every median; the table below has 0 such cells (`unmeasured: 0 cells in 0 of 50 rows`). For the linux-fed enterprise-fed leg the "test" figure includes the host-semaphore wait inside the
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

Host: the f1 macOS node. Environment: `CARGO_TARGET_DIR=<lane dir> CARGO_PROFILE_DEV_DEBUG=0
CARGO_PROFILE_TEST_DEBUG=0 AI_MEMORY_NO_CONFIG=1`. cargo 1.99.1; cargo-nextest 0.9.152 (crates.io, built with
`cargo install cargo-nextest --locked --version 0.9.152 --root <tools dir>`, outside the repository).

Source of every number in this section: the stored logs of the benchmark lane (`ci-9710-time-facts`, directory
`.local-runs/bench`: `compile.log`, `cglist.log`, `nxlist.log`, `cargotest-1.log`, `cargotest-2.log`, `nextest-1.log`,
`nextest-2.log`, `nextest-solo1.log`, `nextest-solo.log`, `nextest-solo-j1.log`), read by
`python3 -I scripts/ci/measure_ci_time.py --repo <owner/repo> --branch <branch> --bench-dir <dir>` at
2026-11-20T22:48:42Z UTC. The script prints each log's write time, so the figure is tied to the file it came from. The
logs are on the node that ran the lane, not in the repository; rerun the command on that directory to reproduce every
figure below. The wall-clock times (`135.7`, `786.2`, `753.4`, `263.7`, `268.7` s) and the `load1` readings the first
version of this section carried came from a scratch timer whose output was not stored; no log holds them, the script
cannot reproduce them, and they are dropped. Their replacement is the time each tool printed into its own log: cargo's
`Finished` line, the sum of cargo's `finished in` lines, and the nextest `Summary` time. The host load during the runs
is "not measured: no `uptime` output was stored".

Targets (same for every command): `--lib` plus `--test` for the 10 integration binaries with the longest `finished in`
time in job 133082849450 (Check macos-fed,sqlite, ci.yml run 43787761690, ranked with
`measure_ci_time.py --rank-job 133082849450`): tls_serve_helper_8293, mcp_signal_drain_4347, recall_observability,
file_sink_warn_3650, l07_3_chunk_d_http_surface, federation_catchup_posture_3582, bulk_post_commit_stages_2724,
e2_post_ship_dry_run, integration, federation_inbox_wake_3631. Never `cargo build --tests`, never a bare `cargo test`.

| Step | Command (after the targets are added) | Time the tool printed | Tests |
|---|---|---|---|
| build (cold) | `cargo test --no-run` | cargo `Finished` 135 s (`compile.log`, 2m 15s) | n/a |
| cargo test run 1 | `cargo test --no-fail-fast` | sum of 11 `finished in` lines 781.3 s (`cargotest-1.log`) | top level: 9796 passed, 0 failed, 2 ignored |
| cargo test run 2 | `cargo test --no-fail-fast` | sum of 11 `finished in` lines 752.5 s (`cargotest-2.log`) | top level: 9796 passed, 0 failed, 2 ignored |
| nextest run 1 | `cargo nextest run --no-fail-fast` | Summary 261.5 s (`nextest-1.log`) | 9796 run: 9704 passed, 92 failed, 2 skipped |
| nextest run 2 | `cargo nextest run --no-fail-fast` | Summary 268.2 s (`nextest-2.log`) | 9796 run: 9694 passed, 102 failed, 2 skipped |

The sum of `finished in` lines is the test-run time inside cargo test summed over its 11 binaries; it is not the
wall time of the command, which includes link and start-up. The wall of the command was not stored (see above), so a
cargo test against nextest wall comparison is "not measured"; the printed times are the nearest measured figure.

Test counts, reconciled by the script for both cargo test logs. `cargo test -- --list` (`cglist.log`) prints 9798
`: test` lines, of which 2 are `#[ignore]`d:
`audit::verify_snapshot_4332_tests::verify_in_a_loop_never_starves_audited_writes_4332` and
`reranker::issue_1597_tests::issue_1597_neural_rerank_timing_evidence`. The per-binary `running N tests` headers of each cargo test log sum to
9798, the same number. Each log has 11 top-level `test result:` rows (9796 passed, 0 failed, 2 ignored) and 6 more
`test result:` rows with `1 passed ... 9365 filtered out`: a child process that a lib test starts prints its own
`running 1 test` block and result row into the lib test output. Counting the 6 nested rows as if they were binaries gives 9802 passed, 4
above the list (6 nested passed minus 2 ignored = 4). The earlier "9802 passed" figure was that over-count, not 4 tests that the list
lacks. `cargo nextest list` (`nxlist.log`) shows 9796 and nextest runs 9796 and reports 2 skipped, so nextest run plus
skipped equals the cargo list (9798).

### Tests that fail only under nextest (process per test)

Under `cargo test` 0 tests failed in both runs. Under nextest 131 distinct tests failed in at least one of two runs, 63 in
both (the script's `nextest fail sets over runs 1 and 2` line, from the distinct `FAIL` names of `nextest-1.log` and
`nextest-2.log`; each log's distinct-name count equals its Summary failed count, 92 and 102). Every failure message that was read names the same cause: `#3354: refusing to start a ledger-writing command as
host:<name>: no signing key for that id is loadable and one could not be generated (no key was loadable after the
ensure step)`, plus the follow-on `invalid JSON response` and `status.success()` assertions. The failing set changes
between runs (two runs only; the failing sets were compared, not repeated further). Probes on the same build, one run
of each command (n = 1):

| Command | Result |
|---|---|
| `cargo nextest run --test integration test_link_creation` (alone; `nextest-solo1.log`) | 1 passed (Summary 2.0 s) |
| `cargo nextest run --test integration test_link_creation test_budget_truncates_to_fit test_boundary_confidence_one` (`nextest-solo.log`) | 0 passed, 3 failed (Summary 1.7 s) |
| the same three tests with `-j 1` (`nextest-solo-j1.log`) | 3 passed (Summary 3.4 s) |

The tests pass alone and one at a time and fail when several nextest processes start together. This is consistent with
a hypothesis, not a traced cause: concurrent first-start generation of the per-host signing key
(`src/governance/audit.rs`, the #3354 refusal), where under `cargo test` the tests of one binary share a process. The
hypothesis rests on this one 3-test probe and on the failing set changing between two runs. Not traced; trace in #9719.

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

Owner and larger runners: none usable, the owner is a User account. Proof, from the table above:
`users/alphaonedev` returns 200 with `type` `User`, `orgs/alphaonedev` returns 404 Not Found, and every
`orgs/alphaonedev/actions/hosted-runners*` endpoint (`hosted-runners`, `hosted-runners/machine-sizes`,
`hosted-runners/images/github-owned`) returns 404, so no organization exists at that name and the larger-runner API
has nothing to answer. The GitHub Docs "Billing" reference page for Actions runner rates (docs.github.com, read
2026-11-20 through a page fetch) states "Larger runners are only available for organizations and enterprises using the
GitHub Team or GitHub Enterprise Cloud plans", which a User account is not. No further probe is made. Per-minute prices
are therefore not needed and not read, and the plan name of the account is not measured (`GET user` returned no `plan`
field for this token).

## 4. What the numbers say

1. Queue wait for ci.yml Check (macos-fed,enterprise-fed) has median 1990 s (598-2433, n=8); every other measured job has a median queue of 189 s or less.
2. ci.yml Check (ubuntu-latest,sqlite) compile has median 1952 s against 368 s for Check (macos-fed,sqlite), which runs the same sqlite leg.
3. ci.yml Check (linux-fed,enterprise-fed) total has median 7318 s (1059-10739), against 1988 s for Check (macos-fed,sqlite) and 2624 s for Check (macos-fed,enterprise-fed).
4. On one build, nextest printed a Summary of 261.5 s and 268.2 s against cargo test's summed `finished in` times of 781.3 s and 752.5 s, and 92 and 102 tests failed under nextest against 0 under `cargo test`; 63 failed in both runs. The wall time of each command was not stored, so the comparison is of the times the tools printed, not of wall clocks.
5. coverage.yml Per-Module Coverage Thresholds has median total 5164 s, of which 3924 s is the test part of the llvm-cov step.
