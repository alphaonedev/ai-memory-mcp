//! Key-dir bind guard (#9730, #9803).
//!
//! What the checks do:
//! - Every tracked `.rs` file is lexed: comments are skipped; string, raw,
//!   byte and C string literals are decoded; delimiters are matched. Each token
//!   gets a site: the `fn`, `mod`, `trait`, `struct`, `enum`, `impl` and
//!   `macro_rules!` items around it and the `const`, `static` or `use`
//!   statement it is in, joined with `::` (`<file root>` when there is none).
//! - An identifier equal to the key-dir variable name, its constant or the
//!   bind helper, and a string literal that holds one of them as a name, is
//!   refused unless `ALLOWED_SITES` has a row with that exact file and site.
//!   A string literal that names one in prose (it has whitespace, is not
//!   only the name, and the name is not after `$` or `{` or before `=`) is not
//!   refused.
//! - A string literal or identifier that holds a piece of the variable name is
//!   refused unless `ALLOWED_FRAGMENTS` has a row with that file, site and text.
//!   The text is the identifier, or the words of the literal that hold a piece,
//!   joined with one space (for example the name of a sibling variable).
//! - A file is refused as unclassifiable when it is not UTF-8, is over
//!   `MAX_SOURCE_BYTES`, has an unterminated literal or comment, an unbalanced,
//!   mismatched or unclosed delimiter, nesting over `MAX_NESTING`, an impl
//!   header over `MAX_HEADER_CHARS`, an invalid escape or a stray quote, or
//!   needs more lexer steps than its step ceiling.
//! - A tracked file that is not `.rs` and holds one of the three names is
//!   refused unless its kind is a row of `LEFT_OUT`.
//! - A row of any table that matches nothing is a failure.
//!
//! siblings: src/identity/keypair.rs:173 (the constant), src/identity/keypair.rs:181
//! (its reader), src/identity/test_key_dir.rs:179-193 (`bind_key_dir_env`,
//! `set_key_dir_env`, callers `install` at :108 and the #3584 test at :329),
//! src/cli/store.rs:1280 (the bind helper and its callers in `mod tests`).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

/// The synthetic file name the allow and deny tables are checked under.
const SYN_FILE: &str = "src/synthetic_9730.rs";
/// Lines in the size-bound input.
const SIZE_LINES: usize = 100_000;
/// Wall-clock ceiling for one check of the size-bound input.
const SIZE_WALL_CLOCK_CEILING: Duration = Duration::from_secs(30);
/// A step ceiling far below what any input needs.
const TINY_STEP_CEILING: u64 = 8;

/// The key-dir variable name, built so this file does not spell it.
fn var_token() -> String {
    ["AI", "MEMORY", "KEY", "DIR"].join("_")
}

/// The name of the constant that holds the variable name.
fn const_token() -> String {
    ["KEY", "DIR", "ENV"].join("_")
}

/// The name of the test bind helper.
fn call_token() -> String {
    ["bind", "key", "dir"].join("_")
}

/// The variable name without its `AI_MEMORY_` prefix.
fn frag_token() -> String {
    ["KEY", "DIR"].join("_")
}

/// The variable name without its `_DIR` suffix.
fn prefix_token() -> String {
    ["AI", "MEMORY", "KEY"].join("_")
}

/// Expands the placeholders used in the tables below.
fn expand(template: &str) -> String {
    template
        .replace("@F@", &format!("#9730 guard: {SYN_FILE}"))
        .replace("@V@", &var_token())
        .replace("@C@", &const_token())
        .replace("@B@", &call_token())
        .replace("@K@", &frag_token())
        .replace("@P@", &prefix_token())
}

/// One allowed site: a file and the exact site path inside it.
struct SiteRow {
    file: &'static str,
    site: &'static str,
    reason: &'static str,
}

/// One allowed fragment: a file, a site and the exact words that hold a piece.
struct FragmentRow {
    file: &'static str,
    site: &'static str,
    text: &'static str,
    reason: &'static str,
}

/// One kind of non-Rust tracked file that may hold the names.
struct LeftOutRow {
    kind: &'static str,
    reason: &'static str,
}

/// The one definition of the variable name.
const DEFINE: &str = "the public constant that defines the variable name for the crate";
/// The production reader of the variable.
const READER: &str = "the production reader of the override in the key-dir resolver";
/// The shared test bind helpers.
const HELPER: &str = "the shared test bind helper: it binds the variable to the isolated sandbox and restores the prior value";
/// The helper's own test.
const HELPER_TEST: &str = "the test of the shared bind helper; it reads the variable to prove the prior value is restored after a panic";
/// The `mod tests` bind helper of `src/cli/store.rs`.
const STORE_BIND: &str = "the store tests' bind helper: it returns a guard that sets the variable and restores it on drop";
/// A caller of the store tests' bind helper.
const STORE_CALLER: &str = "binds the key dir through the store tests' helper; a count-preserving swap moves the call to another site and is refused";
/// A child-process environment.
const CHILD: &str = "sets or removes the variable on a child Command only; the test process environment is not changed";
/// Process-wide binds in a test.
const PROCESS: &str = "sets, removes or reads the variable in the test process itself, in a test or its setup function; the site is pinned so a new process-wide bind elsewhere is refused";
/// A multi-variable env guard.
const MULTI: &str = "a pair handed to the file's multi-variable env guard, which sets the variable and restores the prior value on drop";
/// A closed list of names a child gets.
const NAMES: &str = "the closed, sorted list of variable names a child fixture gets; the test pins the child env to it";
/// The one alias constant of the tree.
const ALIAS: &str = "the one alias constant of the variable name in the tree; its uses in this file are pinned by site, and an alias anywhere else is refused";
/// A sibling custody variable.
const SIBLING: &str = "names a sibling custody variable (witness, recorder, judge or stopper); it is a different variable and binds no agent key dir";
/// A guard that refuses the prefix.
const PREFIX_GUARD: &str = "a test guard that refuses any child env name with the prefix; it reads the name and binds nothing";
/// Docs.
const DOCS: &str = "documentation that names the variable for operators; it sets nothing";
/// Data and evidence files.
const DATA: &str =
    "recorded data or evidence that names the variable; nothing reads it as configuration";
/// Review records.
const REVIEW_DATA: &str =
    "a review record that names the variable; nothing reads it as configuration";
/// Python and shell tooling.
const TOOLING: &str = "a Python or shell script outside the Rust test tree: it sets the variable for a process it starts, or checks how tests bind it";
/// Deploy and CI configuration.
const DEPLOY: &str =
    "deploy or CI configuration that sets the variable for a daemon or a job it starts";
/// The batman-mode Dockerfile.
const BATMAN_DOCKERFILE: &str =
    "the batman-mode Dockerfile; it sets the variable for the container daemon";

/// Every Rust site that may spell a key-dir name, by file and exact site.
const ALLOWED_SITES: &[SiteRow] = &[
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod tests::fn cli_link_signs_edge_when_keypair_present_parity_3036",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod tests::fn cli_link_warns_on_non_notfound_keypair_error_3051",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn @B@",
        reason: STORE_BIND,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn env_var_guard_restores_previous_value_on_drop",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn store_sign_with_allow_claimed_stores_claimed_and_warns_3409",
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn store_sign_with_bound_key_is_agent_attested_3409",
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn store_sign_without_bound_key_refuses_3409",
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn test_store_sign_with_bound_key_stamps_agent_attested",
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod tests::fn test_store_sign_without_local_keypair_errors",
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/verify.rs",
        site: "mod tests::fn tampered_sig_edge_marked_failed",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/verify.rs",
        site: "mod tests::fn verify_edge_signed_with_unknown_agent_fails",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/config.rs",
        site: "mod tests::fn load_capability_config_is_a_closed_allowlist_that_only_shrinks",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/enterprise_federation_posture.rs",
        site: "mod tests::fn audit_signing_disarmed_fails_check_19",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod tests::fn load_daemon_keys_return_none_when_no_keypair_for_agent",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod tests::fn load_daemon_signing_key_returns_none_when_dir_missing",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod tests::fn load_daemon_verifying_key_returns_none_when_dir_missing",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod tests::fn resolve_operator_pubkey_reads_keygen_layout_from_key_dir",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod tests::fn resolve_operator_pubkey_reads_legacy_raw_layout_from_key_dir",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod tests::impl Drop for KeyDirEnvGuard::fn drop",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod tests::impl KeyDirEnvGuard::fn set",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "const @C@",
        reason: DEFINE,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "fn key_dir_env_override",
        reason: READER,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod tests::fn default_key_dir_ends_in_ai_memory_keys",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod tests::fn default_key_dir_honours_env_override",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "fn @B@_env",
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "fn set_key_dir_env",
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "impl Drop for KeyDirEnvBind::fn drop",
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod tests::fn key_dir_env_bind_restores_prior_on_panic_3584",
        reason: HELPER_TEST,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod tests::fn handle_verify_self_signed_link_verifies_and_populates_signed_fields",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod tests::fn handle_verify_signed_link_without_local_pubkey_reports_stored_attest_and_unverified",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod tests::fn handle_verify_tampered_signature_returns_false_and_keeps_stored_level_3021",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod handler_tests::fn epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007_3368",
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod handler_tests::fn epoch_advance_resolve_without_enrolled_sig_stays_unsigned_3007",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn embedder_offline_empty_cache_reports_fallback_miss_not_coldfetch_3788",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn spawn_daemon",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn spawn_mcp_full",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_default_permissive_lands_unsigned_store_claimed_1985",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_opt_out_zero_lands_unsigned_store_claimed_1751",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_require_attestation_rejects_unsigned_store",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/archive_on_gc_config_3385.rs",
        site: "fn cli_gc_honours_v2_archive_policy_3385",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/as_agent_read_visibility_3499.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/audit_cli_honors_db_3429.rs",
        site: "impl Sandbox::fn run",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/authority_boundary_3549.rs",
        site: "fn spawn_mcp",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/bind_api_key_token_file_3781.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/boot_posture_banner_2908.rs",
        site: "fn serve_boot_lines",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/capture_turn_identity_3393.rs",
        site: "impl Mcp::fn start",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_stdout_hygiene_behaviour_3436.rs",
        site: "fn run",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_store_sign_unbound_3409.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_verify_chain.rs",
        site: "fn signed_valid_chain_exits_0",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_verify_chain.rs",
        site: "fn tampered_signature_exits_nonzero",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/mcp_stdio_child.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/tls_serve.rs",
        site: "fn try_spawn_serve_once",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/config_show_effective_3715.rs",
        site: "fn command_with_config",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/conformance_export_roundtrip_2030.rs",
        site: "fn build_fixture_envelope",
        reason: MULTI,
    },
    SiteRow {
        file: "tests/cov_fupb_fed_signing.rs",
        site: "fn clear_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_fupb_fed_signing.rs",
        site: "fn enrol_peer_key",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn clear_fed_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn enroll_peer",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_applies_action_transition_sqlite",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_replayed_action_transition_refused_1805",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_sig_present_no_enrolled_key_refuses_401",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_since_sig_present_no_enrolled_key_refuses_401",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn clear_fed_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn enroll_peer",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn pg_sync_push_via_store_applies_action_transition",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/credential_to_sink_3711.rs",
        site: "fn run_bin",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/deployment_shape_posture_3700.rs",
        site: "fn command_with_config",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/deployment_shape_posture_3700_pg.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_cli.rs",
        site: "fn ai_memory",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_over_depth_4715.rs",
        site: "fn ai_memory",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_pg_floor_4333.rs",
        site: "fn doctor_json_env",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_posture_exit_code_3003.rs",
        site: "fn armed_failing_cmd",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_synchronous_posture_3553.rs",
        site: "fn bare_cmd",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/encryption_key_absent_3718_head.rs",
        site: "fn cmd",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/export_import_roundtrip_3405.rs",
        site: "fn ai_memory",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/export_import_roundtrip_3405.rs",
        site: "fn cli_children_use_the_sandboxed_key_dir_and_leave_home_clean_7232",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/fed_checkpoint_lane_3075_pg.rs",
        site: "fn reset_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_1566_embed_ship.rs",
        site: "fn signature_covers_shipped_vector_tamper_yields_401",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_1936_checkpoint_fed.rs",
        site: "fn reset_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_bulk_catchup_governed_egress_3148.rs",
        site: "fn refuse_rule_blocks_the_bulk_catchup_lane_and_emits_governance_check",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_checkpoint_ns_scope_2708.rs",
        site: "fn reset_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_nonce_replay_922.rs",
        site: "fn setup",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_peer_posture_3582.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/federation_signal_authorship_1843.rs",
        site: "fn clear_all_env",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_signal_authorship_1843.rs",
        site: "fn strict_mode_requires_enrolled_author_key_1843",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_push_catchup_sig_2297.rs",
        site: "fn push_signed_is_accepted_2297",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_push_catchup_sig_2297.rs",
        site: "fn push_unsigned_is_refused_2297",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_since_sig_1031.rs",
        site: "fn setup",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_since_sig_1031.rs",
        site: "fn sync_since_mtls_bypass_still_requires_signature_under_require_sig_1040",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/file_sink_warn_3650.rs",
        site: "fn isolated_command_3650",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_cross_process_4304.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_exit_drain_4319.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_outage_pg_4199.rs",
        site: "fn serve",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_tail_4199.rs",
        site: "fn purge_with_deadline",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_tail_4199.rs",
        site: "fn run_with_env",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/g3_postgres_verify_link_signature_roundtrip.rs",
        site: "fn ephemeral_keypair",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/g_phase_e_4_verify_exit_codes.rs",
        site: "fn reflection_chain_tampered_signature_exits_2_and_ok_false",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_egress_port_4414.rs",
        site: "fn issue_4414_port_rules_enforce_on_the_real_egress_sinks",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_seed_ceremony_3430.rs",
        site: "impl Drop for KeyDirGuard::fn drop",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_seed_ceremony_3430.rs",
        site: "impl KeyDirGuard::fn set",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/h2_invalidate_link_signed.rs",
        site: "fn setup",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/identity_e2e.rs",
        site: "fn setup",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/identity_generate_not_preempted_3743.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/inbox_notify_cli_pg_refusal_3730.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/integration.rs",
        site: "fn cmd",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_guard_not_in_binary_3516.rs",
        site: "fn operator_cmd",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn guarded_child_without_override_uses_the_shared_sandbox_instead_of_home",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn install_neutralises_ambient_key_dir_3584",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn resolver_panics_under_temporary_home_and_accepts_isolated_override",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn resolver_rejects_a_symlink_alias_into_temporary_home",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/keys_escrow_recovery_3717.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/keys_prune_3355.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/logging_pipeline_3651.rs",
        site: "fn run_with_section",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_format_refusal_3803.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_governance_pre_action_1685.rs",
        site: "fn spawn_mcp",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_governance_pre_write_hook_1583.rs",
        site: "fn spawn_mcp",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_signal_drain_4347.rs",
        site: "fn spawn_mcp",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/memory_verify.rs",
        site: "fn setup",
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/migrate_no_create_3435.rs",
        site: "fn run",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/notify_inbox_no_overwrite_3639.rs",
        site: "fn ai_memory",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/portability_export_completeness_2571.rs",
        site: "fn archived_memory_import_seals_content_at_rest_when_encryption_enabled_2571_f2",
        reason: MULTI,
    },
    SiteRow {
        file: "tests/posture_control15_pg_resolution_3106.rs",
        site: "fn run_bin",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/retired_provider_aliases.rs",
        site: "fn product_command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/routine_run_authorization_3506.rs",
        site: "impl Mcp::fn start",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/secret_screen_g29.rs",
        site: "fn spawn_mcp",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/signed_events_fresh_store_signs_3354.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/signed_events_fresh_store_signs_3354_pg.rs",
        site: "fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/skill_promote_visibility_3551/mod.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/skill_scope_integrity_8832_8834.rs",
        site: "const ENV_@K@",
        reason: ALIAS,
    },
    SiteRow {
        file: "tests/store_url_ambiguous_userinfo_6096.rs",
        site: "fn config_show_effective_redacts_a_case_variant_store_scheme_6102",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/store_url_ambiguous_userinfo_6096.rs",
        site: "fn run_bin",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/tls_verbs_3709.rs",
        site: "fn command_with_config",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/toon_meta_budget_3802.rs",
        site: "impl Fixture::fn command",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/transit_encryption_3705.rs",
        site: "fn command_with_config",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/transit_floor_unverifiable_4434.rs",
        site: "fn run",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/url_allowlist_render_3667.rs",
        site: "fn run_bin",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "const HUB_ENV_NAMES",
        reason: NAMES,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "const SINK_ENV_NAMES",
        reason: NAMES,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "fn hub_env",
        reason: CHILD,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "fn sink_env",
        reason: CHILD,
    },
];

/// Every literal or identifier that may hold a piece of the variable name.
const ALLOWED_FRAGMENTS: &[FragmentRow] = &[
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "fn bring_up_remaining",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "fn bring_up_remaining",
        text: "AI_MEMORY_RECORDER_@K@ _JUDGE_@K@ _STOPPER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "fn run_re_anchor",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "fn run_restore_attest",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod reanchor_ceremony_2004_cli_tests::fn re_anchor_unloadable_custody_fails_closed_nonzero",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod reanchor_ceremony_2004_cli_tests::fn re_anchor_absent_custody_is_explicit_skip_not_fail",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "fn last_audit_watermark",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "const WITNESS_@C@",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "const RECORDER_@C@",
        text: "AI_MEMORY_RECORDER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "const JUDGE_@C@",
        text: "AI_MEMORY_JUDGE_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "const STOPPER_@C@",
        text: "AI_MEMORY_STOPPER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/boot_posture_banner_2908.rs",
        site: "fn serve_boot_lines",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/boot_posture_banner_2908.rs",
        site: "fn cli_one_shot_still_installs_no_console_subscriber_2908",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/conformance_export_roundtrip_2030.rs",
        site: "fn build_fixture_envelope",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/qual_wake_hub_zero_authority_3578.rs",
        site: "fn violations",
        text: "@P@",
        reason: PREFIX_GUARD,
    },
    FragmentRow {
        file: "tests/security_profile_dispatch_1961.rs",
        site: "fn asi_hard_engaged_pins_rollback_check_and_refuses_open_on_wiped_db",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/security_profile_dispatch_1961.rs",
        site: "fn asi_hard_cold_boot_fresh_db_boots_clean_2942",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
];

/// Every non-Rust file kind that may hold a key-dir name.
const LEFT_OUT: &[LeftOutRow] = &[
    LeftOutRow {
        kind: "batman-active",
        reason: BATMAN_DOCKERFILE,
    },
    LeftOutRow {
        kind: "csv",
        reason: REVIEW_DATA,
    },
    LeftOutRow {
        kind: "html",
        reason: DOCS,
    },
    LeftOutRow {
        kind: "json",
        reason: DATA,
    },
    LeftOutRow {
        kind: "md",
        reason: DOCS,
    },
    LeftOutRow {
        kind: "py",
        reason: TOOLING,
    },
    LeftOutRow {
        kind: "sh",
        reason: TOOLING,
    },
    LeftOutRow {
        kind: "tpl",
        reason: DEPLOY,
    },
    LeftOutRow {
        kind: "tsv",
        reason: REVIEW_DATA,
    },
    LeftOutRow {
        kind: "yml",
        reason: DEPLOY,
    },
];

/// The expanded tables the scanner reads.
#[derive(Default)]
pub struct Tables {
    pub sites: Vec<(String, String)>,
    pub fragments: Vec<(String, String, String)>,
    pub left_out: Vec<String>,
}

/// The rows a run matched, by index into `Tables`.
#[derive(Default)]
pub struct Used {
    pub sites: BTreeSet<usize>,
    pub fragments: BTreeSet<usize>,
    pub left_out: BTreeSet<usize>,
}

fn tree_tables() -> Tables {
    Tables {
        sites: ALLOWED_SITES
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site)))
            .collect(),
        fragments: ALLOWED_FRAGMENTS
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site), expand(r.text)))
            .collect(),
        left_out: LEFT_OUT.iter().map(|r| r.kind.to_owned()).collect(),
    }
}

/// The allowed sites of the synthetic file the allow and deny rows use.
fn syn_tables() -> Tables {
    Tables {
        sites: [
            "fn allowed_reader",
            "fn allowed_caller",
            "fn @B@",
            "const @C@",
        ]
        .iter()
        .map(|s| (SYN_FILE.to_owned(), expand(s)))
        .collect(),
        ..Tables::default()
    }
}

mod scan {
    use std::path::Path;
    use std::process::Command;

    use super::{Tables, Used, call_token, const_token, frag_token, var_token};

    /// Largest source file the lexer reads.
    pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
    /// Deepest delimiter nesting the lexer follows.
    pub const MAX_NESTING: usize = 256;
    /// Longest impl header the site path takes.
    pub const MAX_HEADER_CHARS: usize = 256;
    /// Lexer steps allowed per source byte.
    pub const STEPS_PER_BYTE: u64 = 4;
    /// Lexer steps allowed on top of the per-byte budget.
    pub const STEP_SLACK: u64 = 1024;
    /// Prefix lengths of the variable name that count as a fragment.
    const PREFIX_FRAGMENT_LENS: std::ops::RangeInclusive<usize> = 11..=16;
    /// Start offsets of the variable name whose suffix counts as a fragment.
    const SUFFIX_FRAGMENT_STARTS: std::ops::RangeInclusive<usize> = 1..=10;
    const FILE_ROOT: &str = "<file root>";

    /// The step ceiling for a source of `len` bytes.
    pub fn step_ceiling(len: usize) -> u64 {
        u64::try_from(len)
            .unwrap_or(u64::MAX)
            .saturating_mul(STEPS_PER_BYTE)
            .saturating_add(STEP_SLACK)
    }

    struct Names {
        var: String,
        constant: String,
        call: String,
        frag: String,
        ident_fragments: Vec<String>,
    }

    impl Names {
        fn new() -> Self {
            let var = var_token();
            let mut ident_fragments: Vec<String> =
                PREFIX_FRAGMENT_LENS.map(|n| var[..n].to_owned()).collect();
            ident_fragments.extend(SUFFIX_FRAGMENT_STARTS.map(|p| var[p..].to_owned()));
            Self {
                var,
                constant: const_token(),
                call: call_token(),
                frag: frag_token(),
                ident_fragments,
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Ident,
        RawIdent,
        Str,
        Lifetime,
        Char,
        Number,
        Punct,
    }

    struct Tok {
        kind: Kind,
        text: String,
        line: usize,
    }

    enum Stop {
        Bad { line: usize, what: String },
        Steps,
    }

    fn bad(line: usize, what: impl Into<String>) -> Stop {
        Stop::Bad {
            line,
            what: what.into(),
        }
    }

    fn is_ident_start(c: char) -> bool {
        c.is_alphabetic() || c == '_'
    }

    fn is_word(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    struct Meter {
        steps: u64,
        ceiling: u64,
    }

    impl Meter {
        fn tick(&mut self) -> Result<(), Stop> {
            self.steps = self.steps.saturating_add(1);
            if self.steps > self.ceiling {
                return Err(Stop::Steps);
            }
            Ok(())
        }
    }

    struct Lexer<'m> {
        chars: Vec<char>,
        pos: usize,
        line: usize,
        meter: &'m mut Meter,
        toks: Vec<Tok>,
    }

    impl Lexer<'_> {
        fn peek(&self, k: usize) -> Option<char> {
            self.chars.get(self.pos + k).copied()
        }

        fn bump(&mut self) -> Result<Option<char>, Stop> {
            self.meter.tick()?;
            let c = self.peek(0);
            if let Some(ch) = c {
                self.pos += 1;
                if ch == '\n' {
                    self.line += 1;
                }
            }
            Ok(c)
        }

        fn push(&mut self, kind: Kind, text: String, line: usize) {
            self.toks.push(Tok { kind, text, line });
        }

        fn run(mut self) -> Result<Vec<Tok>, Stop> {
            while let Some(c) = self.peek(0) {
                let line = self.line;
                if c.is_whitespace() {
                    self.bump()?;
                } else if c == '/' && self.peek(1) == Some('/') {
                    while self.peek(0).is_some_and(|ch| ch != '\n') {
                        self.bump()?;
                    }
                } else if c == '/' && self.peek(1) == Some('*') {
                    self.block_comment(line)?;
                } else if c == '"' {
                    self.bump()?;
                    let s = self.quoted(line)?;
                    self.push(Kind::Str, s, line);
                } else if c == '\'' {
                    self.bump()?;
                    self.quote_or_lifetime(line)?;
                } else if is_ident_start(c) {
                    self.word_token(line)?;
                } else if c.is_ascii_digit() {
                    let n = self.number()?;
                    self.push(Kind::Number, n, line);
                } else {
                    self.bump()?;
                    if c == ':' && self.peek(0) == Some(':') {
                        self.bump()?;
                        self.push(Kind::Punct, "::".to_owned(), line);
                    } else {
                        self.push(Kind::Punct, c.to_string(), line);
                    }
                }
            }
            Ok(self.toks)
        }

        fn block_comment(&mut self, line: usize) -> Result<(), Stop> {
            self.bump()?;
            self.bump()?;
            let mut depth = 1usize;
            loop {
                match self.bump()? {
                    None => return Err(bad(line, "unterminated block comment")),
                    Some('/') if self.peek(0) == Some('*') => {
                        self.bump()?;
                        depth += 1;
                    }
                    Some('*') if self.peek(0) == Some('/') => {
                        self.bump()?;
                        depth -= 1;
                        if depth == 0 {
                            return Ok(());
                        }
                    }
                    Some(_) => {}
                }
            }
        }

        fn word(&mut self) -> Result<String, Stop> {
            let mut w = String::new();
            while let Some(c) = self.peek(0).filter(|c| is_word(*c)) {
                self.bump()?;
                w.push(c);
            }
            Ok(w)
        }

        fn number(&mut self) -> Result<String, Stop> {
            let mut n = String::new();
            while let Some(c) = self.peek(0) {
                let fraction = c == '.' && self.peek(1).is_some_and(|d| d.is_ascii_digit());
                if !(is_word(c) || fraction) {
                    break;
                }
                self.bump()?;
                n.push(c);
            }
            Ok(n)
        }

        fn word_token(&mut self, line: usize) -> Result<(), Stop> {
            let w = self.word()?;
            match (w.as_str(), self.peek(0), self.peek(1)) {
                ("r", Some('#'), Some(n)) if is_ident_start(n) => {
                    self.bump()?;
                    let name = self.word()?;
                    self.push(Kind::RawIdent, name, line);
                }
                ("r" | "br" | "cr", Some('"' | '#'), _) => {
                    let s = self.raw(line)?;
                    self.push(Kind::Str, s, line);
                }
                ("b" | "c", Some('"'), _) => {
                    self.bump()?;
                    let s = self.quoted(line)?;
                    self.push(Kind::Str, s, line);
                }
                ("b", Some('\''), _) => {
                    self.bump()?;
                    self.quote_or_lifetime(line)?;
                }
                _ => self.push(Kind::Ident, w, line),
            }
            Ok(())
        }

        fn raw(&mut self, line: usize) -> Result<String, Stop> {
            let mut hashes = 0usize;
            while self.peek(0) == Some('#') {
                self.bump()?;
                hashes += 1;
            }
            if self.peek(0) != Some('"') {
                return Err(bad(line, "malformed raw string literal"));
            }
            self.bump()?;
            let mut out = String::new();
            loop {
                match self.bump()? {
                    None => return Err(bad(line, "unterminated raw string literal")),
                    Some('"') if (0..hashes).all(|k| self.peek(k) == Some('#')) => {
                        for _ in 0..hashes {
                            self.bump()?;
                        }
                        return Ok(out);
                    }
                    Some(ch) => out.push(ch),
                }
            }
        }

        fn quoted(&mut self, line: usize) -> Result<String, Stop> {
            let mut buf = Vec::new();
            loop {
                match self.bump()? {
                    None => return Err(bad(line, "unterminated string literal")),
                    Some('"') => return Ok(String::from_utf8_lossy(&buf).into_owned()),
                    Some('\\') => self.escape(&mut buf, line)?,
                    Some(ch) => push_char(&mut buf, ch),
                }
            }
        }

        fn hex_digit(&mut self) -> Result<Option<u32>, Stop> {
            match self.peek(0).and_then(|c| c.to_digit(16)) {
                Some(d) => {
                    self.bump()?;
                    Ok(Some(d))
                }
                None => Ok(None),
            }
        }

        fn escape(&mut self, buf: &mut Vec<u8>, line: usize) -> Result<(), Stop> {
            let here = self.line;
            let Some(c) = self.bump()? else {
                return Err(bad(line, "unterminated string literal"));
            };
            let simple = match c {
                'n' => Some('\n'),
                'r' => Some('\r'),
                't' => Some('\t'),
                '\\' => Some('\\'),
                '0' => Some('\0'),
                '\'' => Some('\''),
                '"' => Some('"'),
                _ => None,
            };
            if let Some(ch) = simple {
                push_char(buf, ch);
                return Ok(());
            }
            let invalid = || bad(here, format!("invalid escape `\\{c}`"));
            match c {
                'x' => {
                    let (Some(hi), Some(lo)) = (self.hex_digit()?, self.hex_digit()?) else {
                        return Err(invalid());
                    };
                    let byte = u8::try_from(hi * 16 + lo).map_err(|_| invalid())?;
                    buf.push(byte);
                }
                'u' => {
                    if self.peek(0) != Some('{') {
                        return Err(invalid());
                    }
                    self.bump()?;
                    let mut value = 0u32;
                    let mut digits = 0usize;
                    while let Some(d) = self.hex_digit()? {
                        digits += 1;
                        if digits > 6 {
                            return Err(invalid());
                        }
                        value = value * 16 + d;
                    }
                    if digits == 0 || self.peek(0) != Some('}') {
                        return Err(invalid());
                    }
                    self.bump()?;
                    let ch = char::from_u32(value).ok_or_else(invalid)?;
                    push_char(buf, ch);
                }
                '\n' => self.skip_continuation()?,
                '\r' if self.peek(0) == Some('\n') => self.skip_continuation()?,
                _ => return Err(invalid()),
            }
            Ok(())
        }

        fn skip_continuation(&mut self) -> Result<(), Stop> {
            while self.peek(0).is_some_and(char::is_whitespace) {
                self.bump()?;
            }
            Ok(())
        }

        fn quote_or_lifetime(&mut self, line: usize) -> Result<(), Stop> {
            match (self.peek(0), self.peek(1)) {
                (Some('\\'), _) => {
                    self.bump()?;
                    let mut buf = Vec::new();
                    self.escape(&mut buf, line)?;
                    if self.peek(0) != Some('\'') {
                        return Err(bad(line, "unterminated character literal"));
                    }
                    self.bump()?;
                    self.push(Kind::Char, String::from_utf8_lossy(&buf).into_owned(), line);
                }
                (Some(c), Some('\'')) => {
                    self.bump()?;
                    self.bump()?;
                    self.push(Kind::Char, c.to_string(), line);
                }
                (Some(c), _) if is_ident_start(c) => {
                    let w = self.word()?;
                    self.push(Kind::Lifetime, w, line);
                }
                _ => return Err(bad(line, "stray `'`")),
            }
            Ok(())
        }
    }

    fn push_char(buf: &mut Vec<u8>, ch: char) {
        let mut tmp = [0u8; 4];
        buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
    }

    struct Frame {
        label: String,
        depth: usize,
        statement: bool,
    }

    struct Pending {
        label: String,
        depth: usize,
        any_open: bool,
    }

    struct Delim {
        open: char,
        line: usize,
        frame: bool,
    }

    enum Hit {
        Use {
            line: usize,
            name: String,
            string: bool,
            site: String,
        },
        Fragment {
            line: usize,
            string: bool,
            site: String,
            text: String,
        },
    }

    struct Walker<'a, 'm> {
        toks: &'a [Tok],
        names: &'a Names,
        meter: &'m mut Meter,
        frames: Vec<Frame>,
        pending: Option<Pending>,
        delims: Vec<Delim>,
        hits: Vec<Hit>,
    }

    fn is_name(t: Option<&Tok>) -> Option<&Tok> {
        t.filter(|t| matches!(t.kind, Kind::Ident | Kind::RawIdent))
    }

    fn is_punct(t: Option<&Tok>, p: &str) -> bool {
        t.is_some_and(|t| t.kind == Kind::Punct && t.text == p)
    }

    fn display(t: &Tok) -> String {
        match t.kind {
            Kind::Str => format!("\"{}\"", t.text),
            Kind::Lifetime => format!("'{}", t.text),
            Kind::Char => format!("'{}'", t.text),
            Kind::RawIdent => format!("r#{}", t.text),
            Kind::Ident | Kind::Number | Kind::Punct => t.text.clone(),
        }
    }

    fn closer_of(open: char) -> char {
        match open {
            '(' => ')',
            '[' => ']',
            _ => '}',
        }
    }

    impl Walker<'_, '_> {
        fn walk(mut self) -> Result<Vec<Hit>, Stop> {
            for i in 0..self.toks.len() {
                self.meter.tick()?;
                let tok = &self.toks[i];
                match tok.kind {
                    Kind::Punct => self.punct(tok)?,
                    Kind::Ident => {
                        self.keyword(i)?;
                        self.ident(tok);
                    }
                    Kind::RawIdent => self.ident(tok),
                    Kind::Str => self.string(tok),
                    Kind::Lifetime | Kind::Char | Kind::Number => {}
                }
            }
            if let Some(d) = self.delims.last() {
                return Err(bad(d.line, format!("unclosed `{}`", d.open)));
            }
            Ok(self.hits)
        }

        fn site(&self) -> String {
            let mut parts: Vec<&str> = self.frames.iter().map(|f| f.label.as_str()).collect();
            if let Some(p) = &self.pending {
                parts.push(&p.label);
            }
            if parts.is_empty() {
                FILE_ROOT.to_owned()
            } else {
                parts.join("::")
            }
        }

        fn statement_at(&self, depth: usize) -> bool {
            self.frames
                .last()
                .is_some_and(|f| f.statement && f.depth == depth)
        }

        fn keyword(&mut self, i: usize) -> Result<(), Stop> {
            if self.pending.is_some() {
                return Ok(());
            }
            let depth = self.delims.len();
            let toks = self.toks;
            let kw = toks[i].text.as_str();
            let next = toks.get(i + 1);
            match kw {
                "fn" | "mod" | "trait" | "struct" | "enum" => {
                    if let Some(name) = is_name(next) {
                        self.pending = Some(Pending {
                            label: format!("{kw} {}", name.text),
                            depth,
                            any_open: false,
                        });
                    }
                }
                "macro_rules" => {
                    if let (true, Some(name)) = (is_punct(next, "!"), is_name(toks.get(i + 2))) {
                        self.pending = Some(Pending {
                            label: format!("macro_rules! {}", name.text),
                            depth,
                            any_open: true,
                        });
                    }
                }
                "impl" => {
                    let label = self.impl_header(i)?;
                    self.pending = Some(Pending {
                        label,
                        depth,
                        any_open: false,
                    });
                }
                "const" | "static" if !self.statement_at(depth) => {
                    let mut j = i + 1;
                    if kw == "static" && is_name(toks.get(j)).is_some_and(|t| t.text == "mut") {
                        j += 1;
                    }
                    if let (Some(name), true) =
                        (is_name(toks.get(j)), is_punct(toks.get(j + 1), ":"))
                    {
                        self.frames.push(Frame {
                            label: format!("{kw} {}", name.text),
                            depth,
                            statement: true,
                        });
                    }
                }
                "use" if !self.statement_at(depth) => self.frames.push(Frame {
                    label: "use".to_owned(),
                    depth,
                    statement: true,
                }),
                _ => {}
            }
            Ok(())
        }

        fn impl_header(&mut self, i: usize) -> Result<String, Stop> {
            let line = self.toks[i].line;
            let mut label = String::from("impl");
            let mut chars = label.len();
            let mut nest = 0usize;
            for t in &self.toks[i + 1..] {
                self.meter.tick()?;
                if t.kind == Kind::Punct {
                    match t.text.as_str() {
                        "{" | ";" if nest == 0 => break,
                        "(" | "[" | "{" => nest += 1,
                        ")" | "]" | "}" => {
                            if nest == 0 {
                                break;
                            }
                            nest -= 1;
                        }
                        _ => {}
                    }
                }
                let shown = display(t);
                chars = chars.saturating_add(1 + shown.chars().count());
                if chars > MAX_HEADER_CHARS {
                    return Err(bad(
                        line,
                        format!("impl header longer than {MAX_HEADER_CHARS} characters"),
                    ));
                }
                label.push(' ');
                label.push_str(&shown);
            }
            Ok(label)
        }

        fn punct(&mut self, tok: &Tok) -> Result<(), Stop> {
            let Some(c) = tok
                .text
                .chars()
                .next()
                .filter(|_| tok.text.chars().count() == 1)
            else {
                return Ok(());
            };
            match c {
                '{' | '(' | '[' => {
                    let depth = self.delims.len();
                    if depth >= MAX_NESTING {
                        return Err(bad(
                            tok.line,
                            format!("nesting deeper than {MAX_NESTING} delimiters"),
                        ));
                    }
                    let activate = self
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.depth == depth && (p.any_open || c == '{'));
                    if activate && let Some(p) = self.pending.take() {
                        self.frames.push(Frame {
                            label: p.label,
                            depth,
                            statement: false,
                        });
                    }
                    self.delims.push(Delim {
                        open: c,
                        line: tok.line,
                        frame: activate,
                    });
                }
                '}' | ')' | ']' => {
                    let Some(d) = self.delims.pop() else {
                        return Err(bad(tok.line, format!("unbalanced `{c}`")));
                    };
                    if closer_of(d.open) != c {
                        return Err(bad(
                            tok.line,
                            format!("mismatched delimiter: `{}` closed by `{c}`", d.open),
                        ));
                    }
                    let depth = self.delims.len();
                    while self
                        .frames
                        .last()
                        .is_some_and(|f| f.statement && f.depth > depth)
                    {
                        self.frames.pop();
                    }
                    if d.frame {
                        self.frames.pop();
                    }
                    if self.pending.as_ref().is_some_and(|p| p.depth > depth) {
                        self.pending = None;
                    }
                }
                ';' => {
                    let depth = self.delims.len();
                    if self.statement_at(depth) {
                        self.frames.pop();
                    }
                    if self.pending.as_ref().is_some_and(|p| p.depth == depth) {
                        self.pending = None;
                    }
                }
                _ => {}
            }
            Ok(())
        }

        fn use_hit(&mut self, tok: &Tok, name: &str, string: bool) {
            let site = self.site();
            self.hits.push(Hit::Use {
                line: tok.line,
                name: name.to_owned(),
                string,
                site,
            });
        }

        fn fragment_hit(&mut self, tok: &Tok, string: bool, text: String) {
            let site = self.site();
            self.hits.push(Hit::Fragment {
                line: tok.line,
                string,
                site,
                text,
            });
        }

        fn ident(&mut self, tok: &Tok) {
            let names = self.names;
            if tok.text == names.var {
                self.use_hit(tok, &names.var, false);
            } else if tok.text == names.constant {
                self.use_hit(tok, &names.constant, false);
            } else if tok.text == names.call {
                self.use_hit(tok, &names.call, false);
            } else if names.ident_fragments.contains(&tok.text) {
                self.fragment_hit(tok, false, tok.text.clone());
            }
        }

        fn string(&mut self, tok: &Tok) {
            let names = self.names;
            for name in [&names.var, &names.constant, &names.call] {
                for (at, _) in tok.text.match_indices(name.as_str()) {
                    let before = tok.text[..at].chars().next_back();
                    let after = tok.text[at + name.len()..].chars().next();
                    if before.is_some_and(is_word) || after.is_some_and(is_word) {
                        continue;
                    }
                    if !is_mention(&tok.text, name, before, after) {
                        self.use_hit(tok, name, true);
                    }
                }
            }
            let words = fragment_words(&tok.text, names);
            if !words.is_empty() {
                self.fragment_hit(tok, true, words);
            }
        }
    }

    /// The words of a literal (runs of word characters) that hold a piece of
    /// the variable name, joined with one space. A piece ends at a word end, so
    /// each piece lies inside one word and this finds the same literals as
    /// checking the whole text.
    fn fragment_words(text: &str, names: &Names) -> String {
        text.split(|c: char| !is_word(c))
            .filter(|word| !word.is_empty() && holds_fragment(word, names))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A name in prose: the literal has whitespace, is more than the name, and
    /// the name is not a shell expansion or an assignment target.
    fn is_mention(text: &str, name: &str, before: Option<char>, after: Option<char>) -> bool {
        text.chars().any(char::is_whitespace)
            && text.trim() != name
            && !matches!(before, Some('$' | '{'))
            && after != Some('=')
    }

    /// A piece of the variable name that ends a name and is not part of a
    /// whole occurrence of it.
    fn holds_fragment(text: &str, names: &Names) -> bool {
        let whole: Vec<usize> = text
            .match_indices(names.var.as_str())
            .map(|(at, _)| at)
            .collect();
        let covered = |at: usize, len: usize| {
            let idx = whole.partition_point(|&w| w <= at);
            idx > 0 && at + len <= whole[idx - 1] + names.var.len()
        };
        let ends_name = |end: usize| text[end..].chars().next().is_none_or(|c| !is_word(c));
        let mut pieces = vec![names.frag.as_str()];
        pieces.extend(PREFIX_FRAGMENT_LENS.map(|n| &names.var[..n]));
        pieces.iter().any(|piece| {
            text.match_indices(piece)
                .any(|(at, _)| ends_name(at + piece.len()) && !covered(at, piece.len()))
        })
    }

    fn classify(text: &str, ceiling: u64) -> Result<Vec<Hit>, Stop> {
        let mut meter = Meter { steps: 0, ceiling };
        let toks = Lexer {
            chars: text.chars().collect(),
            pos: 0,
            line: 1,
            meter: &mut meter,
            toks: Vec::new(),
        }
        .run()?;
        let names = Names::new();
        Walker {
            toks: &toks,
            names: &names,
            meter: &mut meter,
            frames: Vec::new(),
            pending: None,
            delims: Vec::new(),
            hits: Vec::new(),
        }
        .walk()
    }

    fn allowed_site(tables: &Tables, file: &str, site: &str) -> Option<usize> {
        tables
            .sites
            .iter()
            .position(|(f, s)| f == file && s == site)
    }

    /// The findings of one Rust source file.
    pub fn check_file(
        file: &str,
        bytes: &[u8],
        tables: &Tables,
        ceiling: u64,
        used: &mut Used,
    ) -> Vec<String> {
        if bytes.len() > MAX_SOURCE_BYTES {
            return vec![format!(
                "#9730 guard: {file} is {} bytes, over the {MAX_SOURCE_BYTES} byte cap; the guard cannot classify it",
                bytes.len()
            )];
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return vec![format!(
                "#9730 guard: {file} is not UTF-8; the guard cannot classify it"
            )];
        };
        let hits = match classify(text, ceiling) {
            Ok(hits) => hits,
            Err(Stop::Bad { line, what }) => {
                return vec![format!(
                    "#9730 guard: {file}:{line}: {what}; the guard cannot classify this file"
                )];
            }
            Err(Stop::Steps) => {
                return vec![format!(
                    "#9730 guard: {file}: step ceiling {ceiling} exceeded; the guard cannot classify it"
                )];
            }
        };
        let mut out = Vec::new();
        for hit in hits {
            match hit {
                Hit::Use {
                    line,
                    name,
                    string,
                    site,
                } => {
                    if let Some(row) = allowed_site(tables, file, &site) {
                        used.sites.insert(row);
                    } else {
                        let kind = if string { "string" } else { "identifier" };
                        out.push(format!(
                            "#9730 guard: {file}:{line}: `{name}` {kind} at `{site}` is outside the allowed sites"
                        ));
                    }
                }
                Hit::Fragment {
                    line,
                    string,
                    site,
                    text,
                } => {
                    let row = tables
                        .fragments
                        .iter()
                        .position(|(f, s, t)| f == file && *s == site && *t == text);
                    if let Some(row) = row {
                        used.fragments.insert(row);
                    } else {
                        let what = if string {
                            "a string literal"
                        } else {
                            "an identifier"
                        };
                        out.push(format!(
                            "#9730 guard: {file}:{line}: {what} holds a fragment of the key-dir variable name at `{site}`; the guard cannot classify it"
                        ));
                    }
                }
            }
        }
        out
    }

    /// The kind of a non-Rust file: its extension, or its name when it has none.
    fn kind_of(file: &str) -> &str {
        let base = file.rsplit('/').next().unwrap_or(file);
        base.rsplit_once('.').map_or(base, |(_, ext)| ext)
    }

    /// The findings of one tracked file that is not Rust source.
    pub fn check_other(file: &str, bytes: &[u8], tables: &Tables, used: &mut Used) -> Vec<String> {
        let names = [var_token(), const_token(), call_token()];
        let holds = names.iter().any(|n| {
            let needle = n.as_bytes();
            bytes.windows(needle.len()).any(|w| w == needle)
        });
        if !holds {
            return Vec::new();
        }
        let kind = kind_of(file);
        if let Some(row) = tables.left_out.iter().position(|k| k == kind) {
            used.left_out.insert(row);
            return Vec::new();
        }
        vec![format!(
            "#9730 guard: {file} holds a key-dir spelling and its kind {kind} is not in LEFT_OUT"
        )]
    }

    /// One message per table row that no file matched.
    pub fn unused_rows(tables: &Tables, used: &Used) -> Vec<String> {
        let mut out = Vec::new();
        for (i, (file, site)) in tables.sites.iter().enumerate() {
            if !used.sites.contains(&i) {
                out.push(format!(
                    "#9730 guard: allowed site {file} `{site}` matches nothing; remove the row"
                ));
            }
        }
        for (i, (file, site, _)) in tables.fragments.iter().enumerate() {
            if !used.fragments.contains(&i) {
                out.push(format!(
                    "#9730 guard: allowed fragment {file} `{site}` matches nothing; remove the row"
                ));
            }
        }
        for (i, kind) in tables.left_out.iter().enumerate() {
            if !used.left_out.contains(&i) {
                out.push(format!(
                    "#9730 guard: left-out kind {kind} matches no tracked file; remove the row"
                ));
            }
        }
        out
    }

    /// The findings of every tracked file under `root`.
    pub fn check_tree(root: &Path, tables: &Tables) -> Vec<String> {
        let listing = match Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-files", "-z"])
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            Ok(o) => return vec![format!("#9730 guard: git ls-files failed: {}", o.status)],
            Err(e) => return vec![format!("#9730 guard: git ls-files failed: {e}")],
        };
        let mut out = Vec::new();
        let mut used = Used::default();
        let mut rust_files = 0usize;
        for raw in listing.split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let Ok(name) = std::str::from_utf8(raw) else {
                out.push(format!(
                    "#9730 guard: {} is not UTF-8; the guard cannot classify it",
                    String::from_utf8_lossy(raw)
                ));
                continue;
            };
            let path = root.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {}
                Ok(_) => {
                    out.push(format!(
                        "#9730 guard: {name} is not a regular file; the guard cannot classify it"
                    ));
                    continue;
                }
                Err(e) => {
                    out.push(format!("#9730 guard: {name} cannot be read: {e}"));
                    continue;
                }
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    out.push(format!("#9730 guard: {name} cannot be read: {e}"));
                    continue;
                }
            };
            // Any case of the extension is lexed as Rust: `#[path]` can name it.
            let is_rust = Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
            if is_rust {
                rust_files += 1;
                let ceiling = step_ceiling(bytes.len());
                out.extend(check_file(name, &bytes, tables, ceiling, &mut used));
            } else {
                out.extend(check_other(name, &bytes, tables, &mut used));
            }
        }
        if rust_files == 0 {
            out.push(
                "#9730 guard: git ls-files listed no .rs file; the guard cannot run".to_owned(),
            );
        }
        out.extend(unused_rows(tables, &used));
        out
    }
}

/// One row of the allow or deny table.
struct Case {
    name: &'static str,
    source: Vec<u8>,
    expected: Vec<String>,
}

fn case(name: &'static str, source: &str, expected: &[&str]) -> Case {
    Case {
        name,
        source: expand(source).into_bytes(),
        expected: expected.iter().map(|e| expand(e)).collect(),
    }
}

fn run_case(c: &Case) -> Vec<String> {
    scan::check_file(
        SYN_FILE,
        &c.source,
        &syn_tables(),
        scan::step_ceiling(c.source.len()),
        &mut Used::default(),
    )
}

/// Every spelling the guard must refuse, one row each, with the whole message.
#[allow(clippy::too_many_lines)]
fn deny_rows() -> Vec<Case> {
    let mut rows = vec![
        case(
            "direct read",
            r#"fn forbidden() { let _ = std::env::var("@V@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "alias constant in a forbidden fn",
            r#"fn forbidden() { const K: &str = "@V@"; let _ = std::env::var(K); }"#,
            &["@F@:1: `@V@` string at `fn forbidden::const K` is outside the allowed sites"],
        ),
        case(
            "alias constant in an allowed fn",
            r#"fn allowed_reader() { const K: &str = "@V@"; let _ = std::env::var(K); }"#,
            &["@F@:1: `@V@` string at `fn allowed_reader::const K` is outside the allowed sites"],
        ),
        case(
            "alias of the constant",
            "const K: &str = @C@;",
            &["@F@:1: `@C@` identifier at `const K` is outside the allowed sites"],
        ),
        case(
            "alias static",
            r#"static K: &str = "@V@";"#,
            &["@F@:1: `@V@` string at `static K` is outside the allowed sites"],
        ),
        case(
            "re-export of the constant",
            "pub use crate::identity::keypair::@C@;",
            &["@F@:1: `@C@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "re-export of the constant under another name",
            "pub use crate::identity::keypair::@C@ as K;",
            &["@F@:1: `@C@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "use alias of the helper",
            "use super::@B@ as kd;",
            &["@F@:1: `@B@` identifier at `use` is outside the allowed sites"],
        ),
        case(
            "call moved to a forbidden fn",
            "fn forbidden(p: &Path) { let _g = @B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "path-qualified call",
            "fn forbidden(p: &Path) { let _g = crate::cli::store::tests::@B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "path-qualified constant",
            "fn forbidden() { let _ = std::env::var(crate::identity::keypair::@C@); }",
            &["@F@:1: `@C@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "call split across lines",
            "fn forbidden(p: &Path) {\n    let _g = @B@\n        (p);\n}\n",
            &["@F@:2: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "string continued across lines",
            "fn forbidden() {\n    let _ = std::env::var(\"AI_MEMORY_\\\n        @K@\");\n}\n",
            &["@F@:2: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "hex escape",
            r#"fn forbidden() { let _ = std::env::var("\x41I_MEMORY_@K@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "unicode escape",
            r#"fn forbidden() { let _ = std::env::var("\u{41}I_MEMORY_@K@"); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "concat! of two pieces",
            r#"fn forbidden() { let _ = std::env::var(concat!("AI_MEMORY_", "@K@")); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "two pieces joined with +",
            r#"fn forbidden() { let k = "@P@".to_owned() + "_DIR"; let _ = std::env::var(k); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "format! of two pieces",
            r#"fn forbidden() { let _ = std::env::var(format!("{}{}", "@P@_D", "IR")); }"#,
            &[
                "@F@:1: a string literal holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "stringify! of a piece",
            r#"fn forbidden() { let _ = std::env::var(concat!("AI_MEMORY_", stringify!(@K@))); }"#,
            &[
                "@F@:1: an identifier holds a fragment of the key-dir variable name at `fn forbidden`; the guard cannot classify it",
            ],
        ),
        case(
            "stringify! of the whole name",
            "fn forbidden() { let _ = std::env::var(stringify!(@V@)); }",
            &["@F@:1: `@V@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "let alias",
            r#"fn forbidden() { let k = "@V@"; let _ = std::env::var(k); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "fn pointer to the helper",
            "fn forbidden(p: &Path) { let f = @B@; let _g = f(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "env guard set with the name",
            r#"fn forbidden(p: &Path) { let _g = <EnvVarGuard>::set("@V@", p); }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "macro_rules body",
            "macro_rules! m { ($p:expr) => { @B@($p) }; }",
            &["@F@:1: `@B@` identifier at `macro_rules! m` is outside the allowed sites"],
        ),
        case(
            "raw identifier",
            "fn forbidden(p: &Path) { let _g = r#@B@(p); }",
            &["@F@:1: `@B@` identifier at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "raw string",
            "fn forbidden() { let _ = std::env::var(r#\"@V@\"#); }",
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "byte string",
            r#"fn forbidden() { let _ = b"@V@"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "C string",
            r#"fn forbidden() { let _ = c"@V@"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "constant name in a string",
            r#"fn forbidden() { let _ = "@C@"; }"#,
            &["@F@:1: `@C@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "shell expansion",
            r#"fn forbidden() { let _ = "echo $@V@ now"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "braced shell expansion",
            r#"fn forbidden() { let _ = "${@V@}"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "shell assignment",
            r#"fn forbidden() { let _ = "@V@=/x cmd"; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "name with trailing blank",
            r#"fn forbidden() { let _ = "@V@ "; }"#,
            &["@F@:1: `@V@` string at `fn forbidden` is outside the allowed sites"],
        ),
        case(
            "fn nested in an allowed fn",
            r#"fn allowed_reader() { fn inner() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `fn allowed_reader::fn inner` is outside the allowed sites"],
        ),
        case(
            "impl method with an allowed name",
            r#"struct Holder; impl Holder { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &[
                "@F@:1: `@V@` string at `impl Holder::fn allowed_reader` is outside the allowed sites",
            ],
        ),
        case(
            "trait default method with an allowed name",
            r#"trait T { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `trait T::fn allowed_reader` is outside the allowed sites"],
        ),
        case(
            "mod nest with an allowed name",
            r#"mod m { fn allowed_reader() { let _ = std::env::var("@V@"); } }"#,
            &["@F@:1: `@V@` string at `mod m::fn allowed_reader` is outside the allowed sites"],
        ),
        case(
            "unterminated string",
            r#"fn f() { let s = "abc; }"#,
            &["@F@:1: unterminated string literal; the guard cannot classify this file"],
        ),
        case(
            "unterminated block comment",
            "fn f() {}\n/* abc",
            &["@F@:2: unterminated block comment; the guard cannot classify this file"],
        ),
        case(
            "unterminated raw string",
            "fn f() { let s = r#\"abc; }",
            &["@F@:1: unterminated raw string literal; the guard cannot classify this file"],
        ),
        case(
            "malformed raw string",
            "fn f() { let s = r#!; }",
            &["@F@:1: malformed raw string literal; the guard cannot classify this file"],
        ),
        case(
            "unterminated character literal",
            r"fn f() { let c = '\n; }",
            &["@F@:1: unterminated character literal; the guard cannot classify this file"],
        ),
        case(
            "unbalanced closer",
            "fn f() {}\n}",
            &["@F@:2: unbalanced `}`; the guard cannot classify this file"],
        ),
        case(
            "mismatched delimiter",
            "fn f() { (] }",
            &[
                "@F@:1: mismatched delimiter: `(` closed by `]`; the guard cannot classify this file",
            ],
        ),
        case(
            "unclosed delimiter",
            "fn f() {\n",
            &["@F@:1: unclosed `{`; the guard cannot classify this file"],
        ),
        case(
            "invalid escape",
            r#"fn f() { let s = "\q"; }"#,
            &["@F@:1: invalid escape `\\q`; the guard cannot classify this file"],
        ),
        case(
            "stray quote",
            "fn f() { let c = ' ; }",
            &["@F@:1: stray `'`; the guard cannot classify this file"],
        ),
    ];
    rows.push(Case {
        name: "nesting over the ceiling",
        source: format!(
            "{}{}",
            "{".repeat(scan::MAX_NESTING + 1),
            "}".repeat(scan::MAX_NESTING + 1)
        )
        .into_bytes(),
        expected: vec![expand(&format!(
            "@F@:1: nesting deeper than {} delimiters; the guard cannot classify this file",
            scan::MAX_NESTING
        ))],
    });
    rows.push(Case {
        name: "impl header over the ceiling",
        source: format!("impl {} {{}}", "A".repeat(scan::MAX_HEADER_CHARS)).into_bytes(),
        expected: vec![expand(&format!(
            "@F@:1: impl header longer than {} characters; the guard cannot classify this file",
            scan::MAX_HEADER_CHARS
        ))],
    });
    rows.push(Case {
        name: "not UTF-8",
        source: vec![b'f', b'n', 0xff],
        expected: vec![expand("@F@ is not UTF-8; the guard cannot classify it")],
    });
    let over = scan::MAX_SOURCE_BYTES + 1;
    rows.push(Case {
        name: "over the byte cap",
        source: vec![b' '; over],
        expected: vec![expand(&format!(
            "@F@ is {over} bytes, over the {} byte cap; the guard cannot classify it",
            scan::MAX_SOURCE_BYTES
        ))],
    });
    rows
}

/// Spellings the guard must let through, one row each.
fn allow_rows() -> Vec<Case> {
    vec![
        case(
            "allowed reader",
            r#"fn allowed_reader() -> Option<String> { std::env::var("@V@").ok() }"#,
            &[],
        ),
        case(
            "allowed caller",
            "fn allowed_caller(p: &Path) { let _g = @B@(p); }",
            &[],
        ),
        case(
            "helper definition",
            r#"fn @B@(p: &Path) -> EnvVarGuard { EnvVarGuard::set("@V@", p.as_os_str()) }"#,
            &[],
        ),
        case(
            "constant definition",
            r#"pub const @C@: &str = "@V@";"#,
            &[],
        ),
        case("line comment", "// @V@ @C@ @B@\nfn forbidden() {}", &[]),
        case(
            "nested block comment",
            "/* a /* @V@ */ @B@ */ fn forbidden() {}",
            &[],
        ),
        case("doc comment", "/// reads @V@\nfn forbidden() {}", &[]),
        case(
            "prose panic string",
            r#"fn forbidden() { panic!("set @V@ to a directory first"); }"#,
            &[],
        ),
        case(
            "prose string",
            r#"fn forbidden() { let _ = "the @V@ variable is read by default_key_dir"; }"#,
            &[],
        ),
        case(
            "closure in an allowed fn",
            r#"fn allowed_reader() { let f = || std::env::var("@V@"); let _ = f(); }"#,
            &[],
        ),
        case(
            "longer variable with the same prefix",
            r#"fn forbidden() { let _ = std::env::var("@P@_PASSPHRASE"); }"#,
            &[],
        ),
        case(
            "identifier with the piece inside a longer name",
            "fn forbidden() { let @K@_BIND = 1; let _ = @K@_BIND; }",
            &[],
        ),
        case(
            "lifetimes and a quote character",
            "fn forbidden<'a>(x: &'a str) -> char { let _ = x; '\"' }",
            &[],
        ),
    ]
}

fn report(failures: &[String]) -> String {
    failures.join("\n")
}

#[test]
fn deny_rows_are_refused_with_their_exact_message_9730() {
    let mut failures = Vec::new();
    for c in deny_rows() {
        let got = run_case(&c);
        if got != c.expected {
            failures.push(format!(
                "deny row `{}`: expected {:?}, got {:?}",
                c.name, c.expected, got
            ));
        }
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn allow_rows_pass_9730() {
    let mut failures = Vec::new();
    for c in allow_rows() {
        let got = run_case(&c);
        if got != c.expected {
            failures.push(format!("allow row `{}`: got {:?}", c.name, got));
        }
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

/// Round-3 finding 2: an alias constant is a route with no built name.
#[test]
fn alias_constant_route_is_refused_9730() {
    let source = expand(r#"fn forbidden() { const K: &str = "@V@"; let _ = std::env::var(K); }"#);
    let got = scan::check_file(
        "src/cli/store.rs",
        source.as_bytes(),
        &tree_tables(),
        scan::step_ceiling(source.len()),
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![expand(
            "#9730 guard: src/cli/store.rs:1: `@V@` string at `fn forbidden::const K` is outside the allowed sites"
        )]
    );
}

/// Round-3 finding 1: a call moved from an allowed fn to a forbidden fn in the
/// same file keeps every per-file count; the guard refuses it by location.
#[test]
fn count_preserving_swap_is_refused_9730() {
    let file = "src/cli/store.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    let text = std::fs::read_to_string(&path).expect("read src/cli/store.rs");
    let moved = expand("        let _kd = @B@(key_dir.path());");
    let anchor = "    fn read_back_persisted_errors_when_row_is_missing_3025() {";
    let mut lines: Vec<&str> = text.lines().collect();
    let from = lines
        .iter()
        .position(|l| *l == moved)
        .expect("the first bound call in src/cli/store.rs");
    lines.remove(from);
    let to = lines
        .iter()
        .position(|l| *l == anchor)
        .expect("the anchor fn in src/cli/store.rs")
        + 1;
    lines.insert(to, &moved);
    let mutated = lines.join("\n");
    let tables = tree_tables();
    let before = scan::check_file(
        file,
        text.as_bytes(),
        &tables,
        scan::step_ceiling(text.len()),
        &mut Used::default(),
    );
    assert!(before.is_empty(), "{}", report(&before));
    let got = scan::check_file(
        file,
        mutated.as_bytes(),
        &tables,
        scan::step_ceiling(mutated.len()),
        &mut Used::default(),
    );
    let line = to + 1;
    assert_eq!(
        got,
        vec![expand(&format!(
            "#9730 guard: {file}:{line}: `@B@` identifier at `mod tests::fn read_back_persisted_errors_when_row_is_missing_3025` is outside the allowed sites"
        ))]
    );
}

#[test]
fn size_bound_holds_on_100k_lines_9730() {
    let mut source = String::new();
    for n in 0..SIZE_LINES {
        let _ = writeln!(
            source,
            "fn prose_{n}() {{ let _ = \"where the key directory is bound, line {n}\"; }}"
        );
    }
    source.push_str(&expand(
        r#"fn forbidden() { let _ = std::env::var("@V@"); }"#,
    ));
    let start = Instant::now();
    let got = scan::check_file(
        SYN_FILE,
        source.as_bytes(),
        &syn_tables(),
        scan::step_ceiling(source.len()),
        &mut Used::default(),
    );
    let took = start.elapsed();
    let line = SIZE_LINES + 1;
    assert_eq!(
        got,
        vec![expand(&format!(
            "@F@:{line}: `@V@` string at `fn forbidden` is outside the allowed sites"
        ))]
    );
    assert!(
        took <= SIZE_WALL_CLOCK_CEILING,
        "#9730 guard: {SIZE_LINES} lines took {took:?}, over {SIZE_WALL_CLOCK_CEILING:?}"
    );
}

#[test]
fn step_ceiling_is_a_finding_9730() {
    let source = expand(r#"fn forbidden() { let _ = std::env::var("@V@"); }"#);
    let got = scan::check_file(
        SYN_FILE,
        source.as_bytes(),
        &syn_tables(),
        TINY_STEP_CEILING,
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![expand(&format!(
            "@F@: step ceiling {TINY_STEP_CEILING} exceeded; the guard cannot classify it"
        ))]
    );
}

#[test]
fn stale_rows_are_failures_9730() {
    let tables = Tables {
        sites: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned())],
        fragments: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned(), prefix_token())],
        left_out: vec!["md".to_owned()],
    };
    let mut used = Used::default();
    let source = b"fn nowhere() {}";
    let mut got = scan::check_file(
        SYN_FILE,
        source,
        &tables,
        scan::step_ceiling(source.len()),
        &mut used,
    );
    got.extend(scan::unused_rows(&tables, &used));
    assert_eq!(
        got,
        vec![
            format!(
                "#9730 guard: allowed site {SYN_FILE} `fn nowhere` matches nothing; remove the row"
            ),
            format!(
                "#9730 guard: allowed fragment {SYN_FILE} `fn nowhere` matches nothing; remove the row"
            ),
            "#9730 guard: left-out kind md matches no tracked file; remove the row".to_owned(),
        ]
    );
}

#[test]
fn other_kinds_need_a_left_out_row_9730() {
    let text = expand("set @V@ before the run\n");
    let none = Tables::default();
    let got = scan::check_other(
        "docs/notes.md",
        text.as_bytes(),
        &none,
        &mut Used::default(),
    );
    assert_eq!(
        got,
        vec![
            "#9730 guard: docs/notes.md holds a key-dir spelling and its kind md is not in LEFT_OUT"
                .to_owned()
        ]
    );
    let md = Tables {
        left_out: vec!["md".to_owned()],
        ..Tables::default()
    };
    let mut used = Used::default();
    let got = scan::check_other("docs/notes.md", text.as_bytes(), &md, &mut used);
    assert!(got.is_empty(), "{}", report(&got));
    assert_eq!(scan::unused_rows(&md, &used), Vec::<String>::new());
}

#[test]
fn every_row_has_a_reason_9730() {
    let mut missing: Vec<String> = Vec::new();
    for r in ALLOWED_SITES {
        if r.reason.trim().is_empty() {
            missing.push(format!("{} `{}`", r.file, expand(r.site)));
        }
    }
    for r in ALLOWED_FRAGMENTS {
        if r.reason.trim().is_empty() || r.text.is_empty() {
            missing.push(format!("{} `{}`", r.file, expand(r.site)));
        }
    }
    for r in LEFT_OUT {
        if r.reason.trim().is_empty() {
            missing.push(r.kind.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "rows without a reason: {}",
        report(&missing)
    );
}

#[test]
fn tracked_tree_holds_no_key_dir_route_outside_the_allowed_sites_9730() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let got = scan::check_tree(root, &tree_tables());
    assert!(got.is_empty(), "{}", report(&got));
}
