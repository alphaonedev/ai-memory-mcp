// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10176: the process-start census, the part of layer 2 that does not
//! depend on what the clippy jobs compile.
//!
//! Layer 1 (`clippy.toml` `disallowed-methods`) sees only code a clippy job
//! compiles: code under `cfg(target_os = "macos")`, `cfg(windows)` or any other
//! cfg the Linux CI jobs leave out is never linted. This census reads every
//! `.rs` file of the whole tree as tokens, under every cfg, and holds:
//!
//! * B: every process-start site (a `Command` constructor, a `Command`
//!   alias, a chokepoint call, a libc start or loader name) is counted per file
//!   against [`START_ROWS`], exact in both directions, and every site outside a
//!   nested package carries `#[expect(clippy::disallowed_methods)]` (or an
//!   `allow`) on its statement, an enclosing item or block, or the file. A
//!   `use` that imports a libc start name, a libc group or glob, or renames
//!   libc is refused outright, and so is any `nix ::` path.
//! * A1: every `proptest!` block opens with
//!   `#![proptest_config(proptest_guarded(..))]`, every form that can switch
//!   proptest's fork or timeout on is an exact row of [`A1_ROWS`], and every
//!   file of any type that names a proptest environment variable is an exact
//!   row of [`ENV_ROWS`].
//! * A2: every `Cargo.lock` crate that can start a process or re-run the test
//!   binary is a row of [`LOCK_ROWS`] at its exact versions, and every name of
//!   [`PROCESS_NAMES`] is absent from the lock or has a row.
//! * A3: the run-time refusal of `tests/common/proptest_guard.rs`, as a table.
//! * C: the libc families of [`LIBC_FAMILIES`] (libc 0.2.191) against the
//!   `clippy.toml` entries, exact in both directions.
//!
//! * R3 (round 3, deny by default): every identifier token of a watched
//!   process, libc, nix or proptest name, and of every name bound to one, is
//!   counted per file against `TOKEN_ROWS` under any cfg, in any macro body and
//!   by any path; every form the census does not model (an impl header naming
//!   a watched name, a watched path before `$`, a glob import of one, a pasted
//!   identifier, inline assembly, an extern block) is a row of `SHAPE_ROWS`;
//!   every macro of the proptest family that runs cases outside a guarded
//!   `proptest!` block is red, and so is a second `proptest_guarded` or a
//!   `proptest_guard` module that is not `tests/common/proptest_guard.rs`; a
//!   silence under `cfg_attr` counts only for a predicate of
//!   [`ACCEPTED_PREDICATES`] (none); every environment name that is not one
//!   literal or one named constant is a row of `ENV_NAME_ROWS`, and a proptest
//!   variable name joined by `concat!` counts against [`ENV_ROWS`]. The tables
//!   are in `tests/common/census_rows_10176.rs`.
//!
//! * R4 (#10286-#10290, deny by default): every watched site of every file
//!   (a watched token, a `use` that brings `env` or one of its functions in
//!   under any name, an env reach whose name is not one literal or one
//!   constant) is pinned by content in `SITE_ROWS`
//!   (`tests/common/census_sites_10286.rs`, see
//!   `tests/common/census_pins_10286.rs` for what a pin proves); every macro
//!   form that can carry a watched name past the token scan (a metavariable
//!   in macro, type or path position, a macro whose arguments name a watched,
//!   runner or env name, a proc or declarative macro, a redefined or renamed
//!   std macro) is a row of `MACRO_ROWS` (`tests/common/census_macros_10287.rs`);
//!   every `Cargo.toml` of the tree is parsed and a rename, patch, replace or
//!   target name of a watched crate is red, and so is a manifest the parser
//!   cannot read (`tests/common/census_cargo_10289.rs`). The row tables are
//!   written by `scripts/ci/census_rows_10286.py`, which shares no code with
//!   this census; its `--check` mode is red when a table differs from a
//!   fresh scan.
//!
//! The fork config (A1, #10287): every file is read for the fork and timeout
//! forms, whether or not it names proptest, and a proptest `Config` bound to
//! another name (`as` or `type`) is itself a form, so a `Config` literal with
//! fork or timeout on outside a guarded `proptest!` block is red unless it is
//! an exact row of [`A1_ROWS`]. What this census does not see: the value of an
//! environment name built at run time; such a name is red where it is passed
//! (`ENV_NAME_ROWS` and its site pin), and the run-time refusal (A3) is the
//! guard on its value. Code of a dependency is not read; A2 is the reasoned
//! list of those crates.

#[path = "common/census_assert_cmd_10314.rs"]
mod census_assert_cmd;
#[path = "common/census_cargo_10289.rs"]
mod census_cargo;
#[path = "common/census_closure_10304.rs"]
mod census_closure;
#[path = "common/census_config_10301.rs"]
mod census_config;
#[path = "common/census_consts_10299.rs"]
mod census_consts;
#[path = "common/census_env_name_10299.rs"]
mod census_env_name;
#[path = "common/census_include_10300.rs"]
mod census_include;
#[path = "common/census_macros_10287.rs"]
mod census_macros;
#[path = "common/census_pins_10286.rs"]
mod census_pins;
#[path = "common/census_r4_red_10286.rs"]
mod census_r4_red;
#[path = "common/census_r4_tests_10286.rs"]
mod census_r4_tests;
#[path = "common/census_rows_10176.rs"]
mod census_rows;
#[path = "common/census_sites_10286.rs"]
mod census_sites;
#[path = "common/census_stmt_10303.rs"]
mod census_stmt;
#[path = "common/proptest_guard.rs"]
mod proptest_guard;
#[path = "common/rust_lex.rs"]
mod rust_lex;

use census_pins::Prep;
use census_rows::{ENV_NAME_ROWS, SHAPE_ROWS, TOKEN_ROWS};
use census_sites::SITE_ROWS;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use proptest_guard::{
    EnvRefusal, FORK_OFF, FORK_VAR, SHOWN_MAX_CHARS, TIMEOUT_OFF, TIMEOUT_VAR, env_refusal,
    proptest_guarded,
};
use rust_lex::{Lexed, Tok, group_end, is_ident_tok, lex};

/// Top-level directories never read, each with its reason.
const SKIPPED: &[(&str, &str)] = &[
    ("target", "cargo build output, generated, never tracked"),
    (".git", "git object store, not source"),
    (
        ".local-runs",
        "gitignored agent scratch (project no-tmp rule)",
    ),
    (".codegraph", "gitignored navigation index"),
    (
        "node_modules",
        "gitignored JavaScript dependencies of the site tooling",
    ),
];

// ---------------------------------------------------------------- B: starts

/// The chokepoint and cargo-binary names that are a site wherever they appear
/// outside a `use` or a `fn` definition. `cargo_bin` and `cargo_bin_cmd` are
/// the `assert_cmd` constructor, trait method and macros (#10314); a
/// `Command ::` or `<alias> ::` start through `cargo_bin` is one site.
const DIRECT: &[&str] = &[
    "audited_command",
    "audited_tokio_command",
    "CommandCargoExt",
    "cargo_bin",
    "cargo_bin_cmd",
];

/// Names whose renaming with `as` is a site (an alias hides later calls).
const ALIASED: &[&str] = &[
    "Command",
    "CommandExt",
    "libc",
    "audited_command",
    "audited_tokio_command",
    "CommandCargoExt",
    "cargo_bin",
    "cargo_bin_cmd",
];

/// The refusal for a site with no silence attribute in reach.
fn uncovered(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)"
    )
}

/// The refusal for a `use` that hides a libc start from layer 2.
fn libc_use(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: a use that imports a process-start libc name, a libc group or glob, or renames libc hides the later call from layer 2; call it as libc::<name> under an expect (#10176)"
    )
}

/// The refusal for a `nix` path.
fn nix_path(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: a nix path; nix has no clippy.toml entry, so a process start through it is not guarded; call std or libc under an expect (#10176)"
    )
}

/// Process-start sites per file, every `.rs` file of the whole tree, under
/// every cfg. Counted from `py/count_starts.py`, the independent lexer of lane
/// fix-10226-r2, at the head of the fix push; never derived from this file.
const START_ROWS: &[(&str, usize)] = &[
    // START_ROWS_BEGIN
    ("benches/harness_bench.rs", 3),
    ("benches/recall.rs", 9),
    ("src/cli/doctor.rs", 1),
    ("src/cli/helpers.rs", 1),
    ("src/cli/wake_listen.rs", 1),
    ("src/cli/wrap.rs", 3),
    ("src/encryption/mod.rs", 1),
    ("src/governance/audit.rs", 1),
    ("src/governance/deferred_audit.rs", 3),
    ("src/hooks/executor.rs", 5),
    ("src/spawn_audit.rs", 6),
    ("src/test_support.rs", 1),
    ("tests/acceptance/acceptance_nhi_sqlite.rs", 3),
    ("tests/agent_attestation_integrity.rs", 3),
    ("tests/archive_mcp_scope_3382.rs", 1),
    ("tests/archive_mcp_scope_3383.rs", 1),
    ("tests/archive_on_gc_config_3385.rs", 1),
    ("tests/as_agent_read_visibility_3499.rs", 1),
    ("tests/audit_cli_honors_db_3429.rs", 1),
    ("tests/audit_signature_pin_l4.rs", 1),
    ("tests/authority_boundary_3549.rs", 1),
    ("tests/b3_precompute_doesnt_block_serve.rs", 3),
    ("tests/backup_fail_closed_2444.rs", 1),
    ("tests/backup_never_migrates_4207.rs", 1),
    ("tests/backup_zeroed_stamp_4323.rs", 1),
    ("tests/bench_verified_dispatch_1961.rs", 1),
    ("tests/bind_api_key_token_file_3781.rs", 1),
    ("tests/boot_fail_closed_config_3166.rs", 1),
    ("tests/boot_lifecycle.rs", 1),
    ("tests/boot_posture_banner_2908.rs", 2),
    ("tests/boot_primitive_contract.rs", 1),
    ("tests/capture_turn_cli_3587.rs", 2),
    ("tests/capture_turn_identity_3393.rs", 1),
    ("tests/child_stdin_write_report_8734.rs", 2),
    ("tests/cli/export_reflections.rs", 5),
    ("tests/cli_governance_check_action.rs", 1),
    ("tests/cli_install_capture_hook_3587.rs", 3),
    ("tests/cli_install_pretool_hook.rs", 5),
    ("tests/cli_integration.rs", 7),
    ("tests/cli_new_subcommands_smoke.rs", 11),
    ("tests/cli_new_subcommands_smoke_batch2.rs", 23),
    ("tests/cli_schema_init.rs", 1),
    ("tests/cli_serve_help_text.rs", 2),
    ("tests/cli_stdout_hygiene_behaviour_3436.rs", 1),
    ("tests/cli_stopper_anchor_race_4044.rs", 1),
    ("tests/cli_store_sign_unbound_3409.rs", 1),
    ("tests/cli_verify_chain.rs", 1),
    ("tests/cli_write_verb_pg_refuse_ceiling_2572.rs", 3),
    ("tests/common/mcp_stdio_child.rs", 1),
    ("tests/common/tls_serve.rs", 1),
    ("tests/config_auto_tag_endpoint_3808_3819.rs", 2),
    ("tests/config_show_effective_3715.rs", 1),
    ("tests/conformance_readers.rs", 2),
    ("tests/contaminated_stamp_authz_sqlite_item3_f1.rs", 2),
    ("tests/coverage_uplift_3885.rs", 3),
    ("tests/credential_to_sink_3711.rs", 1),
    ("tests/deployment_shape_posture_3700.rs", 1),
    ("tests/deployment_shape_posture_3700_pg.rs", 1),
    ("tests/dispatch_integration.rs", 2),
    ("tests/doctor_cli.rs", 1),
    ("tests/doctor_over_depth_4715.rs", 1),
    ("tests/doctor_pg_floor_4333.rs", 2),
    ("tests/doctor_posture_exit_code_3003.rs", 1),
    ("tests/doctor_synchronous_posture_3553.rs", 1),
    ("tests/e1_orchestration_dry_run.rs", 2),
    ("tests/e2_post_ship_dry_run.rs", 4),
    ("tests/egress_audit_honors_db_1991.rs", 1),
    ("tests/embed_lane_egress_gap_3933.rs", 1),
    ("tests/encryption_key_absent_3718_head.rs", 1),
    ("tests/entrypoint_toml_escape_3197.rs", 1),
    ("tests/export_import_false_success_2490.rs", 1),
    ("tests/export_import_roundtrip_3405.rs", 1),
    ("tests/export_scope_desilence_1944.rs", 1),
    ("tests/federation_erasure_replication_2446.rs", 1),
    ("tests/federation_peer_posture_3582.rs", 2),
    ("tests/file_sink_warn_3650.rs", 1),
    ("tests/forensic/bundle_test.rs", 1),
    ("tests/forensic_cross_process_4304.rs", 1),
    ("tests/forensic_exit_drain_4319.rs", 1),
    ("tests/forensic_outage_pg_4199.rs", 1),
    ("tests/forensic_tail_4199.rs", 3),
    ("tests/g11_auto_link_detector.rs", 2),
    ("tests/governance_storage_insert_hook.rs", 4),
    ("tests/health_metrics_constant_cost_2579_2583.rs", 1),
    ("tests/identity_generate_not_preempted_3743.rs", 1),
    ("tests/inbox_drain_not_touch_3730.rs", 2),
    ("tests/inbox_notify_cli_pg_refusal_3730.rs", 1),
    ("tests/inference_egress_dispatch_1963.rs", 1),
    ("tests/install_upgrade_4077_4084.rs", 1),
    ("tests/integration.rs", 14),
    (
        "tests/issue_1317_cli_reflect_wire_layer_preserves_caller_metadata.rs",
        1,
    ),
    ("tests/issue_1590_default_namespace_write_paths.rs", 1),
    ("tests/key_dir_guard_not_in_binary_3516.rs", 1),
    ("tests/key_dir_isolation_3355.rs", 4),
    ("tests/keypair_write_crash_injection_3146.rs", 1),
    ("tests/keys_escrow_recovery_3717.rs", 1),
    ("tests/keys_prune_3355.rs", 1),
    ("tests/lifecycle_hidden_rows_unit1_3691_3693_3626.rs", 1),
    ("tests/link_substrate_visibility_3498.rs", 2),
    ("tests/logging_pipeline_3651.rs", 1),
    ("tests/mcp_format_refusal_3803.rs", 1),
    ("tests/mcp_governance_pre_action_1685.rs", 1),
    ("tests/mcp_governance_pre_write_hook_1583.rs", 1),
    ("tests/mcp_integration.rs", 1),
    ("tests/mcp_signal_drain_4347.rs", 3),
    ("tests/mcp_stdio_session_signer_9926.rs", 1),
    ("tests/mcp_write_seals_10012.rs", 1),
    ("tests/migrate_no_create_3435.rs", 1),
    ("tests/no_openssl_sys_android_1070.rs", 1),
    ("tests/notify_inbox_no_overwrite_3639.rs", 1),
    ("tests/pg_isolate_helper_6383.rs", 2),
    ("tests/pgvector_preflight_3264.rs", 1),
    ("tests/posture_control15_pg_resolution_3106.rs", 1),
    ("tests/power_loss_durability.rs", 1),
    ("tests/recall_stderr_lock_deadlock_4284.rs", 1),
    ("tests/recipe_contract.rs", 3),
    ("tests/recipient_gate_derived_from_namespace_3730.rs", 1),
    ("tests/record_stop_cli_dispatch_1955.rs", 1),
    ("tests/reembed_cli_1598.rs", 1),
    ("tests/repair_text_cli_parse_9557.rs", 3),
    ("tests/retired_provider_aliases.rs", 1),
    ("tests/routine_run_authorization_3506.rs", 2),
    ("tests/row_attestations_10040.rs", 2),
    ("tests/secret_screen_g29.rs", 2),
    ("tests/security_profile_dispatch_1961.rs", 1),
    ("tests/security_profile_prerun_2386.rs", 1),
    ("tests/serve_postgres_continuation2.rs", 1),
    ("tests/serve_store_url_explicit_3431.rs", 1),
    ("tests/signed_events_fresh_store_signs_3354.rs", 1),
    ("tests/signed_events_fresh_store_signs_3354_pg.rs", 1),
    ("tests/skill_promote_test.rs", 3),
    ("tests/skill_promote_visibility_3551/mod.rs", 1),
    ("tests/skill_test.rs", 1),
    ("tests/spawn_audit_gate_1937.rs", 1),
    ("tests/spawn_gate_pins_10176.rs", 10),
    ("tests/sqlite_write_txn_immediate_gate_5084.rs", 1),
    ("tests/stop_signal_8193.rs", 1),
    ("tests/store_url_ambiguous_userinfo_6096.rs", 2),
    ("tests/store_url_fail_closed_2679.rs", 5),
    ("tests/symlink_follow_8950.rs", 2),
    ("tests/tls_serve_helper_8293.rs", 1),
    ("tests/tls_verbs_3709.rs", 1),
    ("tests/toon_meta_budget_3802.rs", 1),
    ("tests/transcript_extractor.rs", 5),
    ("tests/transit_encryption_3705.rs", 2),
    ("tests/transit_floor_unverifiable_4434.rs", 1),
    ("tests/unstamped_policy_3124.rs", 3),
    ("tests/url_allowlist_render_3667.rs", 1),
    ("tests/verify_audit_trail_store_url_prb.rs", 1),
    ("tests/verify_chain_genesis_exit_code_9505.rs", 2),
    ("tests/wake_hub_readonly_modes_9562.rs", 3),
    ("tests/write_receipts_cli_mcp_3555.rs", 1),
    ("tools/post-ship-converge/src/main.rs", 6),
    ("tools/t0-orchestrate/src/main.rs", 2),
    ("vendor/paste/build.rs", 1),
    // START_ROWS_END
];

/// Sites in a nested package (a directory below the root holding a
/// `Cargo.toml`): no clippy job lints them, so they need a reason, not an
/// expectation.
const OUTSIDE_LAYER_ONE: &[(&str, usize, &str)] = &[
    (
        "tools/post-ship-converge/src/main.rs",
        6,
        "operator tool, its own package; runs gh and git, binaries not built from this repo",
    ),
    (
        "tools/t0-orchestrate/src/main.rs",
        2,
        "operator tool, its own package; runs the released ai-memory binary and git",
    ),
    (
        "vendor/paste/build.rs",
        1,
        "vendored paste build script: runs `rustc --version` at build time (built through [patch.crates-io] in Cargo.toml, never linted by clippy)",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `Command` [`>`] `::` (`new` | `cargo_bin`)
    CommandPath,
    /// a name of [`DIRECT`]
    Direct,
    /// a name of [`ALIASED`] followed by `as`
    Renamed { libc: bool },
    /// `libc` `::` a start or loader name
    LibcName,
    /// `libc` `::` (`{` | `*`)
    LibcGroup,
    /// `type X = .. Command ..;`
    TypeAlias,
    /// `<alias of Command>` `::` (`new` | `cargo_bin`)
    AliasCall,
}

#[derive(Debug, Clone, Copy)]
struct Start {
    at: usize,
    line: usize,
    kind: Kind,
}

fn tok(toks: &[Lexed], k: usize) -> Option<&Tok> {
    toks.get(k).map(|t| &t.tok)
}

fn is_p(toks: &[Lexed], k: usize, c: char) -> bool {
    matches!(tok(toks, k), Some(Tok::Punct(p)) if *p == c)
}

fn ident(toks: &[Lexed], k: usize) -> Option<&str> {
    match tok(toks, k) {
        Some(Tok::Ident(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn is_sep(toks: &[Lexed], k: usize) -> bool {
    matches!(tok(toks, k), Some(Tok::PathSep))
}

fn is_ctor(toks: &[Lexed], k: usize) -> bool {
    matches!(ident(toks, k), Some("new" | "cargo_bin"))
}

/// The in-set of [`LIBC_FAMILIES`]: the libc names that are a site.
fn libc_start_names() -> BTreeSet<&'static str> {
    LIBC_FAMILIES
        .iter()
        .filter(|(_, v, _)| *v == Verdict::In)
        .map(|(n, _, _)| *n)
        .collect()
}

/// The names bound to `Command` in this file: `Command as X` and
/// `type X = .. Command ..;`.
fn aliases_in(toks: &[Lexed]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for k in 0..toks.len() {
        if ident(toks, k) == Some("Command")
            && ident(toks, k + 1) == Some("as")
            && let Some(name) = ident(toks, k + 2).filter(|n| *n != "_")
        {
            out.insert(name.to_string());
        }
        if ident(toks, k) == Some("type")
            && let Some(name) = ident(toks, k + 1)
            && type_alias_end(toks, k).is_some()
        {
            out.insert(name.to_string());
        }
    }
    out
}

/// For a `type` at `k`: the index of the `Command` after its `=`, before
/// the next `;`, `{` or `}`.
fn type_alias_end(toks: &[Lexed], k: usize) -> Option<usize> {
    ident(toks, k + 1)?;
    let mut seen_eq = false;
    for m in k + 2..toks.len() {
        match tok(toks, m) {
            Some(Tok::Punct(';' | '{' | '}')) => return None,
            Some(Tok::Punct('=')) => seen_eq = true,
            Some(Tok::Ident(s)) if seen_eq && s == "Command" => return Some(m),
            _ => {}
        }
    }
    None
}

/// Every site of the token stream.
fn starts(toks: &[Lexed], aliases: &BTreeSet<String>, libc_names: &BTreeSet<&str>) -> Vec<Start> {
    let mut out = Vec::new();
    // The constructor token of each `Command ::` / `<alias> ::` start: a
    // `cargo_bin` there is the same start, never a second Direct (#10314).
    let mut ctors: BTreeSet<usize> = BTreeSet::new();
    for k in 0..toks.len() {
        let Some(val) = ident(toks, k) else { continue };
        let line = toks[k].line;
        let mut push = |kind| out.push(Start { at: k, line, kind });
        let j = if val == "Command" && is_p(toks, k + 1, '>') {
            k + 2
        } else {
            k + 1
        };
        if val == "Command" && is_sep(toks, j) && is_ctor(toks, j + 1) {
            push(Kind::CommandPath);
            ctors.insert(j + 1);
        }
        if DIRECT.contains(&val) && !ctors.contains(&k) {
            push(Kind::Direct);
        }
        if ALIASED.contains(&val) && ident(toks, k + 1) == Some("as") {
            push(Kind::Renamed {
                libc: val == "libc",
            });
        }
        if val == "libc" && is_sep(toks, k + 1) {
            if ident(toks, k + 2).is_some_and(|n| libc_names.contains(n)) {
                push(Kind::LibcName);
            }
            if is_p(toks, k + 2, '{') || is_p(toks, k + 2, '*') {
                push(Kind::LibcGroup);
            }
        }
        if val == "type" && type_alias_end(toks, k).is_some() {
            push(Kind::TypeAlias);
        }
        if aliases.contains(val) && is_sep(toks, k + 1) && is_ctor(toks, k + 2) {
            push(Kind::AliasCall);
            ctors.insert(k + 2);
        }
    }
    out
}

/// Whether the attribute opened by the `#` at `k` (`#[..]` or `#![..]`)
/// expects or allows `clippy::disallowed_methods`; returns the index of its
/// `[` too. Under a `cfg_attr` the silence counts only when every predicate
/// is in `accepted` (#10176 R9: `cfg_attr(any(), ..)` is never true).
fn silence_attr(toks: &[Lexed], k: usize, accepted: &[&str]) -> Option<(usize, bool)> {
    if !is_p(toks, k, '#') {
        return None;
    }
    let open = if is_p(toks, k + 1, '!') { k + 2 } else { k + 1 };
    if !is_p(toks, open, '[') {
        return None;
    }
    let end = group_end(toks, open).min(toks.len());
    let body = &toks[open..end];
    let level = body
        .iter()
        .any(|t| is_ident_tok(t, "expect") || is_ident_tok(t, "allow"));
    let lint = body.windows(3).any(|w| {
        is_ident_tok(&w[0], "clippy")
            && matches!(w[1].tok, Tok::PathSep)
            && is_ident_tok(&w[2], "disallowed_methods")
    });
    Some((open, level && lint && predicates_accepted(body, accepted)))
}

/// [`coverage_with`] under the census's [`ACCEPTED_PREDICATES`].
fn coverage(toks: &[Lexed]) -> Vec<bool> {
    coverage_with(toks, ACCEPTED_PREDICATES)
}

/// Per token: whether a silence attribute is in reach (its statement or
/// item prefix, an enclosing item or block, the block's inner attributes,
/// or the file's inner attributes). One forward pass, linear in the tokens.
fn coverage_with(toks: &[Lexed], accepted: &[&str]) -> Vec<bool> {
    let mut file_inner = false;
    let mut k = 0;
    while is_p(toks, k, '#') && is_p(toks, k + 1, '!') {
        let Some((open, sil)) = silence_attr(toks, k, accepted) else {
            break;
        };
        file_inner |= sil;
        k = group_end(toks, open) + 1;
    }
    let mut out = vec![false; toks.len()];
    let mut stack: Vec<bool> = Vec::new();
    let mut seg = false;
    for (k, slot) in out.iter_mut().enumerate() {
        let block = stack.last().copied().unwrap_or(file_inner);
        if let Some((_, true)) = silence_attr(toks, k, accepted) {
            seg = true;
        }
        *slot = seg || block;
        match tok(toks, k) {
            Some(Tok::Punct('{')) => {
                let mut inner = false;
                let mut m = k + 1;
                while is_p(toks, m, '#') && is_p(toks, m + 1, '!') {
                    let Some((open, sil)) = silence_attr(toks, m, accepted) else {
                        break;
                    };
                    inner |= sil;
                    m = group_end(toks, open) + 1;
                }
                stack.push(seg || block || inner);
                seg = false;
            }
            Some(Tok::Punct('}')) => {
                stack.pop();
                seg = false;
            }
            Some(Tok::Punct(';')) => seg = false,
            _ => {}
        }
    }
    out
}

/// Per token: whether it is inside a `use` declaration.
fn use_spans(toks: &[Lexed]) -> Vec<bool> {
    let mut out = vec![false; toks.len()];
    let mut k = 0;
    while k < toks.len() {
        let starts_use = ident(toks, k) == Some("use")
            && (k == 0
                || ident(toks, k - 1) == Some("pub")
                || matches!(
                    tok(toks, k - 1),
                    Some(Tok::Punct(';' | '{' | '}' | ']' | ')'))
                ));
        if !starts_use {
            k += 1;
            continue;
        }
        let end = (k..toks.len())
            .find(|&m| is_p(toks, m, ';'))
            .unwrap_or(toks.len());
        if !(k..end).any(|m| is_p(toks, m, '(')) {
            for slot in &mut out[k..end] {
                *slot = true;
            }
        }
        k = end.max(k + 1);
    }
    out
}

/// The B findings of one file: uncovered sites, libc uses and nix paths.
/// `outside` is true for a file of a nested package (no coverage needed).
fn start_findings(rel: &str, toks: &[Lexed], sites: &[Start], outside: bool) -> Vec<String> {
    let cover = coverage(toks);
    let in_use = use_spans(toks);
    let mut out = Vec::new();
    for s in sites {
        let libc_kind = matches!(
            s.kind,
            Kind::LibcName | Kind::LibcGroup | Kind::Renamed { libc: true }
        );
        if in_use[s.at] {
            if libc_kind {
                out.push(libc_use(rel, s.line));
            }
            continue;
        }
        let defined = s.at > 0 && ident(toks, s.at - 1) == Some("fn");
        if outside || defined || s.kind == Kind::TypeAlias || cover[s.at] {
            continue;
        }
        out.push(uncovered(rel, s.line));
    }
    for k in 0..toks.len() {
        if ident(toks, k) == Some("nix") && is_sep(toks, k + 1) {
            out.push(nix_path(rel, toks[k].line));
        }
    }
    out
}

// ---------------------------------------------------------------- A1: proptest

/// The finding for a `proptest!` block that is not guarded.
fn unguarded_block(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: a proptest! block that does not open with #![proptest_config(proptest_guarded(..))]; its cases could fork outside the sandbox (#10176)"
    )
}

/// The finding for one form that can switch fork or timeout on.
fn fork_form(rel: &str, line: usize, what: &str) -> String {
    format!(
        "{rel}:{line}: {what}; a proptest config with fork or timeout on re-runs this test binary outside the sandbox (#10176)"
    )
}

const FORM_FIELD: &str = "a fork or timeout field in a proptest Config literal";
const FORM_UPDATE: &str = "a proptest Config update from a base that is not Config::default()";
const FORM_BUILDER: &str = "with_fork or with_timeout on a proptest Config";
const FORM_ASSIGN: &str = "an assignment to a proptest config's fork or timeout";
const FORM_FIELD_WRITE: &str = "a field form of fork or timeout (a literal or pattern field outside a proptest Config literal, field shorthand, a compound assignment or a &mut borrow)";
const FORM_META_FIELD: &str = "a macro metavariable in field position (a literal or pattern field, an assignment, a compound assignment or a &mut borrow), which may name fork or timeout";
const FORM_RUNNER: &str = "TestRunner, rusty_fork, wait_timeout or property_test, which run cases outside a guarded proptest! block";
const FORM_RENAME: &str = "proptest renamed with as, which hides its blocks from this scan";
const FORM_CONFIG_NAME: &str =
    "a proptest Config bound to another name (as or type), which hides its literals from this scan";

/// The names a proptest config literal is read under, before renames.
const CONFIG_SEED: &[&str] = &["Config", "ProptestConfig"];

/// Idents that run cases without a guarded block.
const RUNNER_IDENTS: &[&str] = &[
    "TestRunner",
    "rusty_fork",
    "rusty_fork_test",
    "wait_timeout",
    "property_test",
];

/// Files allowed to hold A1 forms, with the exact count and the reason.
/// Every file is read (#10287), so a name that only spells like a proptest
/// form is a row too, with the reason it is not one.
const A1_ROWS: &[(&str, usize, &str)] = &[
    (
        "loadtest/src/main.rs",
        2,
        "the load generator's own Config struct has a request timeout field; it is not proptest's Config and the crate has no proptest dependency",
    ),
    (
        "src/cli/commands/inbox.rs",
        5,
        "the CLI's own InboxArgs struct has a --timeout field for the inbox wait (#10312 field forms); its unit tests build it, it is not proptest's Config",
    ),
    (
        "src/reranker.rs",
        1,
        "candle's bert Config imported as BertConfig; a model config, not proptest's Config",
    ),
    (
        "tests/common/atomise_gate.rs",
        1,
        "Condvar::wait_timeout on a std mutex guard; a lock wait with a deadline, not the wait_timeout crate",
    ),
    (
        "tests/process_start_census_10176.rs",
        2,
        "the A3 table proves proptest_guarded refuses a Config with fork on and one with a timeout",
    ),
];

/// Whether the `proptest !` at `k` opens a guarded block.
fn guarded_block(toks: &[Lexed], k: usize) -> bool {
    let open = k + 2;
    if !is_p(toks, open, '{') {
        return false;
    }
    let head = open + 1;
    if !(is_p(toks, head, '#')
        && is_p(toks, head + 1, '!')
        && is_p(toks, head + 2, '[')
        && ident(toks, head + 3) == Some("proptest_config")
        && is_p(toks, head + 4, '('))
    {
        return false;
    }
    let mut m = head + 5;
    let mut last = None;
    while let Some(t) = tok(toks, m) {
        match t {
            Tok::Ident(s) => last = Some(s.as_str()),
            Tok::PathSep => {}
            _ => break,
        }
        m += 1;
    }
    last == Some("proptest_guarded") && is_p(toks, m, '(')
}

/// Whether the tokens from `a` (after `..`) to the `}` at `end` are exactly
/// `[path ::] (Config | ProptestConfig) :: default ( )`.
fn default_base(toks: &[Lexed], a: usize, end: usize) -> bool {
    let Some(tail) = toks.get(a..end) else {
        return false;
    };
    let tail: Vec<&Tok> = tail.iter().map(|t| &t.tok).collect();
    let Some(head) = tail.len().checked_sub(5) else {
        return false;
    };
    matches!(tail[head], Tok::Ident(s) if s == "Config" || s == "ProptestConfig")
        && matches!(tail[head + 1], Tok::PathSep)
        && matches!(tail[head + 2], Tok::Ident(s) if s == "default")
        && matches!(tail[head + 3], Tok::Punct('('))
        && matches!(tail[head + 4], Tok::Punct(')'))
        && head % 2 == 0
        && tail[..head]
            .chunks(2)
            .all(|c| matches!(c, [Tok::Ident(_), Tok::PathSep]))
}

/// The A1 findings of every file (#10287: no file is skipped for not naming
/// proptest): unguarded blocks first (never allowlisted), then the fork and
/// timeout forms. `config` is the closure of [`CONFIG_SEED`]; a literal of
/// any of its names is read, and every binding of a seed name to another
/// name is itself a form.
fn proptest_findings(
    rel: &str,
    p: &Prep<'_>,
    config: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let toks = p.toks;
    let (mut blocks, mut forms) = (Vec::new(), Vec::new());
    let mut seeds = vec![0usize; toks.len() + 1];
    for (k, t) in toks.iter().enumerate() {
        let hit = matches!(&t.tok, Tok::Ident(s) if CONFIG_SEED.contains(&s.as_str()));
        seeds[k + 1] = seeds[k] + usize::from(hit);
    }
    for k in 0..toks.len() {
        let line = toks[k].line;
        let Some(val) = ident(toks, k) else { continue };
        if val == "proptest" && is_p(toks, k + 1, '!') && !guarded_block(toks, k) {
            blocks.push(unguarded_block(rel, line));
        }
        if val == "proptest" && ident(toks, k + 1) == Some("as") {
            forms.push(fork_form(rel, line, FORM_RENAME));
        }
        if matches!(val, "with_fork" | "with_timeout") {
            forms.push(fork_form(rel, line, FORM_BUILDER));
        }
        if RUNNER_IDENTS.contains(&val) {
            forms.push(fork_form(rel, line, FORM_RUNNER));
        }
        if matches!(val, "fork" | "timeout")
            && k > 0
            && is_p(toks, k - 1, '.')
            && is_p(toks, k + 1, '=')
            && !is_p(toks, k + 2, '=')
        {
            forms.push(fork_form(rel, line, FORM_ASSIGN));
        }
        if CONFIG_SEED.contains(&val) && ident(toks, k + 1) == Some("as") {
            forms.push(fork_form(rel, line, FORM_CONFIG_NAME));
        }
        if val == "type" && !(k > 0 && is_sep(toks, k - 1)) {
            let e = p.stop[k + 1];
            if e > k + 2 && seeds[e] > seeds[k + 2] {
                forms.push(fork_form(rel, line, FORM_CONFIG_NAME));
            }
        }
        if config.contains(val) && is_p(toks, k + 1, '{') {
            literal_forms(rel, p, k + 1, &mut forms);
        }
    }
    field_forms(rel, p, config, &mut forms);
    (blocks, forms)
}

// ------------------------------------------------- A1: field forms (#10312)

/// The fields of proptest's `Config` that switch fork or timeout on.
const FORK_FIELDS: &[&str] = &["fork", "timeout"];

/// Words before a `{` that open a block (`else {`, `unsafe {`), never a
/// literal.
const BLOCK_HEADS: &[&str] = &["async", "const", "else", "loop", "move", "try", "unsafe"];

/// Words in the head of a `{` (at its own depth) that make it an item,
/// function or match body, which holds no field.
const BODY_WORDS: &[&str] = &[
    "extern",
    "fn",
    "impl",
    "macro_rules",
    "match",
    "mod",
    "struct",
    "trait",
    "union",
    "where",
];

/// What a `{` opens, for the fields directly inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Brace {
    /// A struct literal or pattern, or a macro body (unclassifiable, so read
    /// as a literal): a `fork` or `timeout` field in it is a form.
    Literal,
    /// A block, an item body or a declaration: its fields are not writes.
    Block,
    /// An `enum` body: a `{` directly in it declares a variant.
    Variants,
}

/// For every token the opener of the group directly around it, and for
/// every closer its opener (one pass).
fn group_tables(toks: &[Lexed]) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
    let mut inside = vec![None; toks.len()];
    let mut open_of = vec![None; toks.len()];
    let mut stack = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        inside[k] = stack.last().copied();
        match t.tok {
            Tok::Punct('(' | '[' | '{') => stack.push(k),
            Tok::Punct(')' | ']' | '}') => open_of[k] = stack.pop(),
            _ => {}
        }
    }
    (inside, open_of)
}

/// The path that names the type of the `{` at `o`:
/// `[$] Ident (:: Ident)* [::] [<..>]`, as (its first token, its last
/// ident). `None` when no path ends at `o` (after `)`, `=>`, `->`, `::`).
fn literal_path(toks: &[Lexed], o: usize) -> Option<(usize, &str)> {
    let mut j = o.checked_sub(1)?;
    if is_p(toks, j, '>') {
        let mut depth = 0usize;
        loop {
            let arrow = j > 0 && (is_p(toks, j - 1, '-') || is_p(toks, j - 1, '='));
            if is_p(toks, j, '>') && arrow {
                return None;
            }
            if is_p(toks, j, '>') {
                depth += 1;
            } else if is_p(toks, j, '<') {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    break;
                }
            } else if matches!(tok(toks, j), Some(Tok::Punct(';' | '{' | '}'))) {
                return None;
            }
            j = j.checked_sub(1)?;
        }
        j = j.checked_sub(1)?;
        if is_sep(toks, j) {
            j = j.checked_sub(1)?;
        }
    }
    let last = ident(toks, j)?;
    let mut s = j;
    while s >= 2 && is_sep(toks, s - 1) && ident(toks, s - 2).is_some() {
        s -= 2;
    }
    if s >= 1 && (is_sep(toks, s - 1) || is_p(toks, s - 1, '$')) {
        s -= 1;
    }
    Some((s, last))
}

/// Whether the `=` at `i` is a plain `=` (not `==`, `=>`, `!=`, `<=`, `>=`).
fn plain_eq(toks: &[Lexed], i: usize) -> bool {
    is_p(toks, i, '=')
        && !is_p(toks, i + 1, '=')
        && !is_p(toks, i + 1, '>')
        && (i == 0 || !['=', '!', '<', '>'].iter().any(|c| is_p(toks, i - 1, *c)))
}

/// What the `{` at `o` opens, read from its own head only: the tokens at its
/// depth back to the `;`, `{` or `}` before it, nested groups skipped whole.
/// Anything not shown to be a block is a literal (fail closed).
fn brace_head(
    toks: &[Lexed],
    inside: &[Option<usize>],
    open_of: &[Option<usize>],
    o: usize,
) -> Brace {
    if o > 0 && is_p(toks, o - 1, '!') {
        return Brace::Literal;
    }
    let Some((s, last)) = literal_path(toks, o) else {
        return Brace::Block;
    };
    if BLOCK_HEADS.contains(&last) || (s > 0 && is_p(toks, s - 1, '.')) {
        return Brace::Block;
    }
    let lo = inside[o];
    let (mut eq_seen, mut in_seen) = (false, false);
    let mut j = s;
    while let Some(i) = j.checked_sub(1) {
        if Some(i) == lo {
            break;
        }
        match tok(toks, i) {
            Some(Tok::Punct(';' | '{' | '}')) => break,
            Some(Tok::Punct(')' | ']')) => {
                j = open_of[i].unwrap_or(i);
                continue;
            }
            Some(Tok::Punct('=')) if plain_eq(toks, i) => eq_seen = true,
            Some(Tok::Ident(w)) => match w.as_str() {
                "enum" => return Brace::Variants,
                "if" | "while" => return Brace::Block,
                "let" if !eq_seen => return Brace::Literal,
                "in" => in_seen = true,
                "for" if in_seen => return Brace::Block,
                w if BODY_WORDS.contains(&w) => return Brace::Block,
                _ => {}
            },
            _ => {}
        }
        j = i;
    }
    Brace::Literal
}

/// What the `{` at `o` opens, with a variant of an enum body as a block.
fn brace_kind(
    toks: &[Lexed],
    inside: &[Option<usize>],
    open_of: &[Option<usize>],
    o: usize,
) -> Brace {
    match brace_head(toks, inside, open_of, o) {
        Brace::Literal => match inside[o] {
            Some(l)
                if is_p(toks, l, '{')
                    && brace_head(toks, inside, open_of, l) == Brace::Variants =>
            {
                Brace::Block
            }
            _ => Brace::Literal,
        },
        other => other,
    }
}

/// The first token of the place expression that ends with the field at `k`
/// (after its `.`): segments (an ident, a number or a `(..)`/`[..]` group,
/// with the ident before a group) joined by `.` or `::`. `memo` holds the
/// place start of every earlier field, so a chain is walked once.
fn place_start(
    toks: &[Lexed],
    open_of: &[Option<usize>],
    memo: &[Option<usize>],
    k: usize,
) -> usize {
    let mut s = k.saturating_sub(1);
    while let Some(e) = s.checked_sub(1) {
        if let Some(m) = memo[e] {
            return m;
        }
        let mut start = match tok(toks, e) {
            Some(Tok::Ident(w)) if w != "mut" => e,
            Some(Tok::Num(_)) => e,
            Some(Tok::Punct(')' | ']')) => {
                let g = open_of[e].unwrap_or(e);
                if g > 0 && ident(toks, g - 1).is_some_and(|w| w != "mut") {
                    g - 1
                } else {
                    g
                }
            }
            _ => break,
        };
        if start > 0 && is_p(toks, start - 1, '$') {
            start -= 1;
        }
        s = start;
        match start.checked_sub(1) {
            Some(p)
                if is_sep(toks, p)
                    || (is_p(toks, p, '.') && !(p > 0 && is_p(toks, p - 1, '.'))) =>
            {
                s = p;
            }
            _ => break,
        }
    }
    s
}

/// Whether the place starting at `s` is borrowed mutably: `&mut`,
/// `&raw mut` or `addr_of_mut!(`.
fn borrowed_mut(toks: &[Lexed], s: usize) -> bool {
    let back = |n: usize| s.checked_sub(n);
    let at = |n: usize, c: char| back(n).is_some_and(|i| is_p(toks, i, c));
    let word = |n: usize, w: &str| back(n).is_some_and(|i| ident(toks, i) == Some(w));
    (word(1, "mut") && (at(2, '&') || (word(2, "raw") && at(3, '&'))))
        || (at(1, '(') && at(2, '!') && word(3, "addr_of_mut"))
}

/// Whether the field at `k` (after its `.`) is the target of a compound
/// assignment (`+=`, `-=`, `*=`, `/=`, `%=`, `^=`, `&=`, `|=`, `<<=`, `>>=`).
fn compound_assigned(toks: &[Lexed], k: usize) -> bool {
    let one = ['+', '-', '*', '/', '%', '^', '&', '|']
        .iter()
        .any(|c| is_p(toks, k + 1, *c))
        && is_p(toks, k + 2, '=')
        && !is_p(toks, k + 3, '=');
    let two = ['<', '>']
        .iter()
        .any(|c| is_p(toks, k + 1, *c) && is_p(toks, k + 2, *c))
        && is_p(toks, k + 3, '=')
        && !is_p(toks, k + 4, '=');
    one || two
}

/// Whether the ident at `k` starts a field of the `{` at `o`: after the
/// `{` or a `,`, with an optional `ref` and `mut` before it.
fn field_start(toks: &[Lexed], o: usize, k: usize) -> bool {
    let mut j = k;
    for w in ["mut", "ref"] {
        if j > 0 && ident(toks, j - 1) == Some(w) {
            j -= 1;
        }
    }
    j > 0 && (j - 1 == o || is_p(toks, j - 1, ',') || rep_open(toks, j - 1))
}

/// The finding text of a field form: a metavariable or a `fork`/`timeout`.
fn field_form(meta: bool) -> &'static str {
    if meta {
        FORM_META_FIELD
    } else {
        FORM_FIELD_WRITE
    }
}

/// Whether the token at `i` opens a macro repetition, `$(`.
fn rep_open(toks: &[Lexed], i: usize) -> bool {
    is_p(toks, i, '(') && i > 0 && is_p(toks, i - 1, '$')
}

/// For every token the group whose field list holds it: the group directly
/// around it, through any macro repetitions `$( .. )` between them. One
/// forward pass (an opener comes before what it holds), so linear.
fn field_groups(toks: &[Lexed], inside: &[Option<usize>]) -> Vec<Option<usize>> {
    let mut out: Vec<Option<usize>> = Vec::with_capacity(toks.len());
    for &around in inside {
        let g = match around {
            Some(g) if rep_open(toks, g) => out[g],
            other => other,
        };
        out.push(g);
    }
    out
}

/// The #10312 forms: every `fork` or `timeout` ident in a field or
/// assignment position that is not a method call or a path. A field
/// `fork:` or shorthand `fork` of any literal or pattern (a `{` that is not
/// shown to be a block), except a `fork:` of a proptest Config literal,
/// which [`literal_forms`] reads; and a field access `.fork` that is the
/// target of a compound assignment or borrowed mutably. A plain `.fork =`
/// is [`FORM_ASSIGN`]. One pass, each `{` head and each place read once.
fn field_forms(rel: &str, p: &Prep<'_>, config: &BTreeSet<String>, out: &mut Vec<String>) {
    let toks = p.toks;
    let (inside, open_of) = group_tables(toks);
    let groups = field_groups(toks, &inside);
    let mut kinds: BTreeMap<usize, Brace> = BTreeMap::new();
    let mut memo = vec![None; toks.len()];
    for k in 0..toks.len() {
        let Some(val) = ident(toks, k) else { continue };
        // A metavariable (`$f`) may name any field, fork included, so it is
        // read like `fork` (fail closed); `$crate` is a path.
        let dollar = k > 0 && is_p(toks, k - 1, '$');
        let meta = dollar && val != "crate";
        if !(meta || (!dollar && FORK_FIELDS.contains(&val))) {
            continue;
        }
        // `f` is the field's first token: the `$` of a metavariable.
        let f = if meta { k - 1 } else { k };
        let line = toks[k].line;
        let after_dot = f > 0 && is_p(toks, f - 1, '.');
        if after_dot {
            if f > 1 && is_p(toks, f - 2, '.') {
                continue;
            }
            if is_p(toks, k + 1, '(') || is_sep(toks, k + 1) {
                continue;
            }
            let s = place_start(toks, &open_of, &memo, f);
            memo[f] = Some(s);
            // A plain `.fork =` is FORM_ASSIGN; a plain `.$f =` is read here.
            let assigned = meta && plain_eq(toks, k + 1);
            if assigned || compound_assigned(toks, k) || borrowed_mut(toks, s) {
                out.push(fork_form(rel, line, field_form(meta)));
            }
            continue;
        }
        let Some(o) = groups[f].filter(|o| is_p(toks, *o, '{')) else {
            continue;
        };
        let colon = is_p(toks, k + 1, ':') && !is_p(toks, k + 2, ':');
        let shorthand = is_p(toks, k + 1, ',') || is_p(toks, k + 1, '}');
        let rep_end = meta && is_p(toks, k + 1, ')') && inside[f] != Some(o);
        if !(colon || shorthand || rep_end) || !field_start(toks, o, f) {
            continue;
        }
        let kind = *kinds
            .entry(o)
            .or_insert_with(|| brace_kind(toks, &inside, &open_of, o));
        if kind != Brace::Literal {
            continue;
        }
        let read_by_literal_forms =
            !meta && colon && o > 0 && ident(toks, o - 1).is_some_and(|h| config.contains(h));
        if !read_by_literal_forms {
            out.push(fork_form(rel, line, field_form(meta)));
        }
    }
}

/// The forms inside the `Config { .. }` literal opened at `open`. Nested
/// groups are skipped whole, and the scan ends at the struct update, so a
/// token is read by at most one literal (linear over the file).
fn literal_forms(rel: &str, p: &Prep<'_>, open: usize, out: &mut Vec<String>) {
    let toks = p.toks;
    let end = p
        .close
        .get(open)
        .copied()
        .flatten()
        .unwrap_or(toks.len())
        .min(toks.len());
    let mut m = open + 1;
    while m < end {
        match tok(toks, m) {
            Some(Tok::Punct('(' | '[' | '{')) => {
                m = p.close.get(m).copied().flatten().unwrap_or(end).max(m);
            }
            Some(Tok::Ident(s))
                if (s == "fork" || s == "timeout")
                    && is_p(toks, m + 1, ':')
                    && !is_sep(toks, m + 1) =>
            {
                out.push(fork_form(rel, toks[m].line, FORM_FIELD));
            }
            Some(Tok::Punct('.')) if is_p(toks, m + 1, '.') => {
                if !default_base(toks, m + 2, end) {
                    out.push(fork_form(rel, toks[m].line, FORM_UPDATE));
                }
                return;
            }
            _ => {}
        }
        m += 1;
    }
}

/// Files of any type whose bytes name a proptest environment variable, with
/// the exact count and the reason. Counted by `py/count_starts.py`.
const ENV_ROWS: &[(&str, usize, &str)] = &[
    (
        "changelog.d/10176.fixed.md",
        2,
        "release note naming the two variables the guard refuses",
    ),
    (
        "scripts/ci/tests/test_census_rows_10286.py",
        1,
        "#10299 Python bound fixture: the literal each generated constant binds",
    ),
    (
        "tests/common/census_config_10301.json",
        4,
        "#10301 shared table: the env rows and lines a cargo config refusal names",
    ),
    (
        "tests/common/census_env_name_10299.json",
        23,
        "#10299 shared table: the literal the fixture constants and calls name",
    ),
    (
        "tests/common/census_env_name_10299.rs",
        1,
        "#10299 Rust bound fixture: the literal each generated constant binds",
    ),
    (
        "tests/common/proptest_guard.rs",
        4,
        "the run-time guard: its doc (twice) and the two variable-name constants",
    ),
];

/// The prefix of every proptest environment variable, built so this file
/// does not hold it as one literal.
fn env_needle() -> String {
    let mut s = FORK_VAR.to_string();
    s.truncate(FORK_VAR.find('_').map_or(0, |i| i + 1));
    s
}

fn count_bytes(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

// ---------------------------------------------------------------- tree

struct Tree {
    /// (relative path, bytes) of every regular file outside [`SKIPPED`].
    files: Vec<(String, Vec<u8>)>,
    links: Vec<String>,
    /// Directories (relative) holding a `Cargo.toml`, the root excluded.
    packages: Vec<String>,
    /// The directory the tree was read from; `None` for a tree built in
    /// memory. Include targets are looked up under it (#10300).
    root: Option<PathBuf>,
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk(dir: &Path, root: &Path, tree: &mut Tree) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "#10176: read dir {}: {e}; an unreadable dir is not clean",
            dir.display()
        )
    });
    let mut entries: Vec<_> = entries
        .map(|e| e.unwrap_or_else(|e| panic!("#10176: read dir {}: {e}", dir.display())))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .expect("walked path is under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if SKIPPED.iter().any(|(n, _)| rel == *n) {
            continue;
        }
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("#10176: stat {}: {e}", path.display()));
        if kind.is_symlink() {
            tree.links.push(rel);
        } else if kind.is_dir() {
            if path.join("Cargo.toml").exists() {
                tree.packages.push(rel.clone());
            }
            walk(&path, root, tree);
        } else {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("#10176: read {}: {e}", path.display()));
            tree.files.push((rel, bytes));
        }
    }
}

fn read_tree(root: &Path) -> Tree {
    let mut tree = Tree {
        files: Vec::new(),
        links: Vec::new(),
        packages: Vec::new(),
        root: Some(root.to_path_buf()),
    };
    walk(root, root, &mut tree);
    tree
}

fn in_package(rel: &str, packages: &[String]) -> bool {
    packages.iter().any(|p| {
        rel.strip_prefix(p.as_str())
            .is_some_and(|r| r.starts_with('/'))
    })
}

/// The lexed `.rs` files of the tree (a file that is not UTF-8 is a finding).
fn rust_files(tree: &Tree, errors: &mut Vec<String>) -> Vec<(String, Vec<Lexed>)> {
    let mut out = Vec::new();
    for (rel, bytes) in &tree.files {
        if !Path::new(rel)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => out.push((rel.clone(), lex(text))),
            Err(e) => errors.push(format!(
                "{rel}: not UTF-8 ({e}); the census cannot read it (#10176)"
            )),
        }
    }
    out
}

// ---------------------------------------------------------------- R3: token census

/// The seed of the watched names (#10176 round 3): the process module and
/// the start types and traits, libc, nix, and every proptest macro and
/// runner. The census counts every identifier token of these names and of
/// every name bound to one of them (see [`watched_closure`]), under any cfg,
/// in any macro body and in any path, and the count of each file is a row of
/// [`TOKEN_ROWS`]. A token count needs no model of the start form.
const WATCHED: &[&str] = &[
    "Command",
    "CommandCargoExt",
    "CommandExt",
    "TestRunner",
    "audited_command",
    "audited_tokio_command",
    "cargo_bin",
    "cargo_bin_cmd",
    "libc",
    "nix",
    "process",
    "prop",
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "prop_assume",
    "prop_compose",
    "prop_oneof",
    "property_test",
    "proptest",
    "proptest_helper",
    "rusty_fork",
    "rusty_fork_test",
    "wait_timeout",
];

/// The seed of the proptest names: a macro of one of these names, or of a
/// name bound to one, reaches the proptest runner.
const RUNNER_FAMILY: &[&str] = &[
    "TestRunner",
    "prop",
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "prop_assume",
    "prop_compose",
    "prop_oneof",
    "property_test",
    "proptest",
    "proptest_helper",
    "rusty_fork",
    "rusty_fork_test",
    "wait_timeout",
];

/// The proptest macros that build a strategy or assert inside a case and
/// never run cases themselves.
const NON_RUNNING: &[&str] = &[
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "prop_assume",
    "prop_compose",
    "prop_oneof",
];

/// The `cfg_attr` predicates under which an expect or allow of
/// `clippy::disallowed_methods` counts as in reach, written with no blanks.
/// Empty: every conditional silence is out of reach (#10176 R9).
const ACCEPTED_PREDICATES: &[&str] = &[];

/// The one file that may define `proptest_guarded`.
const GUARD_FILE: &str = "tests/common/proptest_guard.rs";

/// Whether the token at `k` is an identifier of the set.
fn ident_in(toks: &[Lexed], k: usize, set: &BTreeSet<String>) -> bool {
    ident(toks, k).is_some_and(|s| set.contains(s))
}

const SHAPE_IMPL: &str = "an impl whose header names a watched process, libc, nix or proptest name";
const SHAPE_METAVAR: &str = "a watched path followed by a macro metavariable";
const SHAPE_GLOB: &str = "a glob import of a watched path";
const SHAPE_PASTE: &str = "a pasted or concatenated identifier";
const SHAPE_ASM: &str = "inline assembly";
const SHAPE_EXTERN: &str = "an extern block";

/// The message of one shape kind of [`census_pins::shapes_of`].
fn shape_what(kind: &str) -> &'static str {
    match kind {
        "impl" => SHAPE_IMPL,
        "metavar" => SHAPE_METAVAR,
        "glob" => SHAPE_GLOB,
        "paste" => SHAPE_PASTE,
        "asm" => SHAPE_ASM,
        "extern" => SHAPE_EXTERN,
        _ => "a shape kind the census does not name",
    }
}

/// The finding for one shape of a file that has no [`SHAPE_ROWS`] row.
fn shape_finding(rel: &str, line: usize, what: &str) -> String {
    format!(
        "{rel}:{line}: {what}; a form the census does not model needs a SHAPE_ROWS row with its reason (#10176)"
    )
}

/// The C findings of one file: a macro that reaches the proptest runner
/// outside a guarded `proptest!` block, a second definition or rename of
/// the guard, and a guard module that is not the guard file.
fn guard_findings(rel: &str, toks: &[Lexed], pt: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for k in 0..toks.len() {
        let Some(val) = ident(toks, k) else { continue };
        let line = toks[k].line;
        if is_p(toks, k + 1, '!') && !is_p(toks, k + 2, '=') {
            let via = k > 1 && is_sep(toks, k - 1) && ident_in(toks, k - 2, pt);
            if (pt.contains(val) || via)
                && val != "proptest"
                && val != "macro_rules"
                && !NON_RUNNING.contains(&val)
            {
                out.push(format!(
                    "{rel}:{line}: {val}! reaches the proptest runner outside a guarded proptest! block (#10176)"
                ));
            }
        }
        if val == "proptest_guarded" && rel != GUARD_FILE && k > 0 {
            let before = ident(toks, k - 1);
            let defines =
                matches!(
                    before,
                    Some("fn" | "as" | "const" | "static" | "let" | "mut")
                ) || (k > 1 && is_p(toks, k - 1, '!') && ident(toks, k - 2) == Some("macro_rules"));
            if defines {
                out.push(format!(
                    "{rel}:{line}: a definition or rename of proptest_guarded outside {GUARD_FILE}; a guarded block must call the one guard (#10176)"
                ));
            }
        }
        if val == "mod" && ident(toks, k + 1) == Some("proptest_guard") && !guard_path(rel, toks, k)
        {
            out.push(format!(
                "{rel}:{line}: a proptest_guard module not loaded from {GUARD_FILE} by #[path] (#10176)"
            ));
        }
    }
    out
}

/// Whether the `mod proptest_guard` at `k` is `#[path = ".."]`, right
/// before it (and its `pub` or `pub(..)`), naming [`GUARD_FILE`] from `rel`,
/// and ends in `;`.
fn guard_path(rel: &str, toks: &[Lexed], k: usize) -> bool {
    if !is_p(toks, k + 2, ';') {
        return false;
    }
    let mut b = k;
    if b > 0 && ident(toks, b - 1) == Some("pub") {
        b -= 1;
    } else if b > 3
        && is_p(toks, b - 1, ')')
        && is_p(toks, b - 3, '(')
        && ident(toks, b - 4) == Some("pub")
    {
        b -= 4;
    }
    let Some(a) = b.checked_sub(6) else {
        return false;
    };
    let Some(Tok::Str(path)) = tok(toks, a + 4) else {
        return false;
    };
    is_p(toks, a, '#')
        && is_p(toks, a + 1, '[')
        && ident(toks, a + 2) == Some("path")
        && is_p(toks, a + 3, '=')
        && is_p(toks, a + 5, ']')
        && lexical_join(rel, path).as_deref() == Some(GUARD_FILE)
}

/// The tree path that `path` names from the directory of `rel`, with `.`
/// and `..` folded; `None` when it leaves the tree or is absolute.
fn lexical_join(rel: &str, path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = rel.split('/').collect();
    parts.pop();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

/// The tokens of a `cfg_attr` predicate written with no blanks.
fn predicate_text(toks: &[Lexed]) -> String {
    let mut s = String::new();
    for t in toks {
        match &t.tok {
            Tok::Ident(v) | Tok::Num(v) => {
                if s.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                    s.push(' ');
                }
                s.push_str(v);
            }
            Tok::Punct(c) => s.push(*c),
            Tok::PathSep => s.push_str("::"),
            Tok::Str(v) => {
                s.push('"');
                s.push_str(v);
                s.push('"');
            }
            Tok::Char(v) => s.push_str(v),
        }
    }
    s
}

/// Whether every `cfg_attr` predicate in the attribute body is accepted.
fn predicates_accepted(body: &[Lexed], accepted: &[&str]) -> bool {
    for k in 0..body.len() {
        if ident(body, k) != Some("cfg_attr") || !is_p(body, k + 1, '(') {
            continue;
        }
        let end = group_end(body, k + 1).min(body.len());
        let mut depth = 0usize;
        let mut comma = end;
        for m in k + 2..end {
            match tok(body, m) {
                Some(Tok::Punct('(' | '[' | '{')) => depth += 1,
                Some(Tok::Punct(')' | ']' | '}')) => depth = depth.saturating_sub(1),
                Some(Tok::Punct(',')) if depth == 0 => {
                    comma = m;
                    break;
                }
                _ => {}
            }
        }
        let text = predicate_text(&body[k + 2..comma]);
        if !accepted.contains(&text.as_str()) {
            return false;
        }
    }
    true
}

/// The finding for a token, shape or env-name table whose count differs.
fn table_line(rel: &str, table: &str, have: usize, want: usize) -> String {
    match table {
        "TOKEN_ROWS" => format!(
            "{rel}: {have} watched process, libc, nix or proptest tokens, TOKEN_ROWS has {want}; every reference under any cfg, in any macro or by any path needs its exact row (#10176)"
        ),
        "SHAPE_ROWS" => format!(
            "{rel}: {have} forms the census does not model, SHAPE_ROWS has {want}; each needs its exact row with its reason (#10176)"
        ),
        _ => format!(
            "{rel}: {have} environment names that are not one string literal or one named constant, {table} has {want}; a built name can switch proptest fork on (#10176)"
        ),
    }
}

/// Both directions of an R3 table, then each row without a reason of at
/// least 20 bytes and each row out of order.
fn table_findings(
    table: &str,
    have: &BTreeMap<String, usize>,
    rows: &[(&str, usize, &str)],
) -> Vec<String> {
    let want: BTreeMap<&str, usize> = rows.iter().map(|(p, n, _)| (*p, *n)).collect();
    let mut out = Vec::new();
    for (rel, n) in have {
        let w = want.get(rel.as_str()).copied().unwrap_or(0);
        if w != *n {
            out.push(table_line(rel, table, *n, w));
        }
    }
    for (rel, w) in &want {
        if !have.contains_key(*rel) {
            out.push(table_line(rel, table, 0, *w));
        }
    }
    for (rel, _, why) in rows {
        if why.trim().len() < 20 {
            out.push(format!(
                "{rel}: the {table} row has no reason of at least 20 bytes (#10176)"
            ));
        }
    }
    for w in rows.windows(2) {
        if w[0].0 >= w[1].0 {
            out.push(format!(
                "{}: {table} is not sorted or holds the file twice (#10176)",
                w[1].0
            ));
        }
    }
    out
}

/// #10311: the findings of a file rowed `R_SHAPE_EXTERN` whose extern blocks
/// declare anything but `acl_*` functions.
/// The blocks are found with the predicate of the extern arm of
/// [`census_pins::shapes_of`] (`extern {` or `extern "abi" {`). Each item of
/// a block is read at depth 0: `pub`, `pub(..)`, `unsafe` and `safe` are
/// skipped; `fn acl_*` is the one permitted item; an attribute is named
/// `#[name]`, a `static`, `type` or other `fn` by its name, and any other
/// item (a macro call among them) by its first token. Each block is read
/// once and the scan resumes after it, so the cost is linear.
fn extern_row_findings(rel: &str, toks: &[Lexed]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut k = 0;
    while k < toks.len() {
        let open = if ident(toks, k) != Some("extern") {
            None
        } else if is_p(toks, k + 1, '{') {
            Some(k + 1)
        } else if matches!(tok(toks, k + 1), Some(Tok::Str(_))) && is_p(toks, k + 2, '{') {
            Some(k + 2)
        } else {
            None
        };
        let Some(open) = open else {
            k += 1;
            continue;
        };
        let end = group_end(toks, open);
        extern_items(toks, open + 1, end, &mut names);
        k = end + 1;
    }
    names
        .into_iter()
        .map(|n| format!("{rel} is rowed R_SHAPE_EXTERN but declares {n} (#10311)"))
        .collect()
}

/// The index after the `;` that ends the item at `k` (groups skipped whole),
/// or `end`.
fn item_end(toks: &[Lexed], mut k: usize, end: usize) -> usize {
    while k < end {
        if is_p(toks, k, '(') || is_p(toks, k, '[') || is_p(toks, k, '{') {
            k = group_end(toks, k) + 1;
        } else if is_p(toks, k, ';') {
            return k + 1;
        } else {
            k += 1;
        }
    }
    end
}

/// The text of one token, for the name of an unexpected item.
fn tok_text(t: &Tok) -> String {
    match t {
        Tok::Ident(s) | Tok::Char(s) | Tok::Num(s) => s.clone(),
        Tok::Punct(c) => c.to_string(),
        Tok::PathSep => "::".to_string(),
        Tok::Str(s) => format!("{s:?}"),
    }
}

/// The names of the items of one extern block body, `toks[k..end]`, that are
/// not `acl_*` functions.
fn extern_items(toks: &[Lexed], mut k: usize, end: usize, names: &mut Vec<String>) {
    while k < end {
        match ident(toks, k) {
            Some("pub") if is_p(toks, k + 1, '(') => k = group_end(toks, k + 1) + 1,
            Some("pub" | "unsafe" | "safe") => k += 1,
            Some("fn") => {
                match ident(toks, k + 1) {
                    Some(n) if n.len() > "acl_".len() && n.starts_with("acl_") => {}
                    Some(n) => names.push(n.to_string()),
                    None => names.push("fn".to_string()),
                }
                k = item_end(toks, k + 1, end);
            }
            Some(kw @ ("static" | "type")) => {
                let at = if kw == "static" && ident(toks, k + 1) == Some("mut") {
                    k + 2
                } else {
                    k + 1
                };
                names.push(ident(toks, at).unwrap_or(kw).to_string());
                k = item_end(toks, at, end);
            }
            _ if is_p(toks, k, ';') => k += 1,
            _ if is_p(toks, k, '#') => {
                let br = if is_p(toks, k + 1, '!') { k + 2 } else { k + 1 };
                if is_p(toks, br, '[') {
                    names.push(format!("#[{}]", ident(toks, br + 1).unwrap_or("?")));
                    k = group_end(toks, br) + 1;
                } else {
                    names.push("#".to_string());
                    k += 1;
                }
            }
            _ => {
                names.push(toks.get(k).map_or_else(String::new, |t| tok_text(&t.tok)));
                k = item_end(toks, k, end);
            }
        }
    }
}

/// #10311: the extern reason of a `SHAPE_ROWS` row read as a claim about the
/// file. Under `R_SHAPE_EXTERN` every form is an extern block that declares
/// only `acl_*` functions; under any other reason no form is an extern block.
fn extern_reason_findings(
    rel: &str,
    toks: &[Lexed],
    found: &[(&'static str, usize)],
    reason: &str,
) -> Vec<String> {
    if reason == census_rows::R_SHAPE_EXTERN {
        let mut out: Vec<String> = found
            .iter()
            .filter(|(kind, _)| *kind != "extern")
            .map(|(kind, line)| {
                format!(
                    "{rel}:{line}: a {kind} form under an R_SHAPE_EXTERN row, whose reason covers only extern blocks (#10311)"
                )
            })
            .collect();
        out.extend(extern_row_findings(rel, toks));
        out
    } else {
        found
            .iter()
            .filter(|(kind, _)| *kind == "extern")
            .map(|(_, line)| {
                format!(
                    "{rel}:{line}: an extern block under a SHAPE_ROWS row whose reason is not R_SHAPE_EXTERN (#10311)"
                )
            })
            .collect()
    }
}

/// The proptest variable names that a `concat!` builds and that no one of
/// its literals holds alone.
fn concat_needles(toks: &[Lexed], needle: &str) -> usize {
    let mut n = 0;
    for k in 0..toks.len() {
        if ident(toks, k) != Some("concat") || !is_p(toks, k + 1, '!') {
            continue;
        }
        let end = group_end(toks, k + 2).min(toks.len());
        let parts: Vec<&str> = toks
            .get(k + 3..end)
            .unwrap_or(&[])
            .iter()
            .filter_map(|t| match &t.tok {
                Tok::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        let joined = parts.concat();
        let alone: usize = parts.iter().map(|p| p.matches(needle).count()).sum();
        n += joined.matches(needle).count().saturating_sub(alone);
    }
    n
}

/// Every census finding of the tree: B, A1 and the env rows.
fn census(tree: &Tree) -> Vec<String> {
    let mut out: Vec<String> = tree
        .links
        .iter()
        .map(|l| format!("{l}: a symbolic link; the census never follows links (#10176)"))
        .collect();
    let mut lexed = rust_files(tree, &mut out);
    census_include::join_includes(tree, &mut lexed, &mut out);
    let names = libc_start_names();
    let aliases: BTreeSet<String> = lexed.iter().flat_map(|(_, t)| aliases_in(t)).collect();
    let preps: Vec<Prep<'_>> = lexed.iter().map(|(_, t)| Prep::new(t)).collect();
    let consts = census_consts::const_names(&preps);
    let graph = census_pins::RenameGraph::of(&preps);
    let watched = graph.reach(WATCHED).names;
    let pt = graph.reach(RUNNER_FAMILY).names;
    let env_mod = graph.reach(census_pins::ENV_MOD_SEED).names;
    let env_fns = graph.reach(census_pins::ENV_FN_SEED).names;
    let config = graph.reach(CONFIG_SEED).names;
    let env_reach: BTreeSet<String> = env_mod.union(&env_fns).cloned().collect();
    let hot: BTreeSet<String> = watched
        .iter()
        .chain(&pt)
        .chain(&env_reach)
        .cloned()
        .chain(census_macros::FORK_NAMES.iter().map(|s| (*s).to_string()))
        .collect();
    let site_rows: BTreeMap<&str, &[&str]> = SITE_ROWS.iter().map(|(r, d)| (*r, *d)).collect();
    let mut site_have: BTreeSet<&str> = BTreeSet::new();
    let mut macros: BTreeMap<(String, &'static str), Vec<usize>> = BTreeMap::new();
    let shape_rowed: BTreeMap<&str, &str> = SHAPE_ROWS.iter().map(|r| (r.0, r.2)).collect();
    let needle = env_needle();
    let mut counts = BTreeMap::new();
    let mut outside = BTreeMap::new();
    let mut a1 = BTreeMap::new();
    let mut tokens = BTreeMap::new();
    let mut shapes = BTreeMap::new();
    let mut env_names = BTreeMap::new();
    let mut joined = BTreeMap::new();
    for ((rel, toks), prep) in lexed.iter().zip(&preps) {
        let n = (0..toks.len())
            .filter(|&k| ident_in(toks, k, &watched))
            .count();
        if n > 0 {
            tokens.insert(rel.clone(), n);
        }
        let found = census_pins::shapes_of(prep, &watched);
        if let Some(reason) = shape_rowed.get(rel.as_str()) {
            out.extend(extern_reason_findings(rel, toks, &found, reason));
            if !found.is_empty() {
                shapes.insert(rel.clone(), found.len());
            }
        } else {
            out.extend(
                found
                    .iter()
                    .map(|(kind, line)| shape_finding(rel, *line, shape_what(kind))),
            );
        }
        out.extend(guard_findings(rel, toks, &pt));
        let n = census_pins::env_calls(prep, &env_fns, &consts).len();
        if n > 0 {
            env_names.insert(rel.clone(), n);
        }
        let row = site_rows.get(rel.as_str()).copied();
        match census_pins::sites_of(prep, &watched, &env_reach, &env_fns, &consts) {
            Ok(sites) if !sites.is_empty() => {
                site_have.insert(rel.as_str());
                out.extend(census_pins::site_findings(rel, &sites, row));
            }
            Ok(_) => {}
            Err(e) => {
                site_have.insert(rel.as_str());
                out.push(format!("{rel}: {e}"));
            }
        }
        for (form, line) in census_macros::macro_forms(prep, &hot) {
            macros.entry((rel.clone(), form)).or_default().push(line);
        }
        let n = concat_needles(toks, &needle);
        if n > 0 {
            joined.insert(rel.clone(), n);
        }
        let sites = starts(toks, &aliases, &names);
        let pkg = in_package(rel, &tree.packages);
        if !sites.is_empty() {
            counts.insert(rel.clone(), sites.len());
            if pkg {
                outside.insert(rel.clone(), sites.len());
            }
        }
        out.extend(start_findings(rel, toks, &sites, pkg));
        let (blocks, forms) = proptest_findings(rel, prep, &config);
        out.extend(blocks);
        if !forms.is_empty() {
            a1.insert(rel.clone(), forms);
        }
    }
    out.extend(census_pins::site_table_findings(SITE_ROWS, &site_have));
    out.extend(census_macros::macro_findings(
        &macros,
        census_macros::MACRO_ROWS,
    ));
    for (rel, bytes) in &tree.files {
        if rel.rsplit('/').next() == Some("Cargo.toml") {
            out.extend(census_cargo::manifest_findings(rel, bytes));
        } else if census_config::is_config(rel) {
            out.extend(census_config::config_findings(rel, bytes));
        }
    }
    out.extend(compare_counts(
        "START_ROWS",
        &counts,
        START_ROWS.iter().map(|(p, n)| (*p, *n)),
    ));
    out.extend(compare_counts(
        "OUTSIDE_LAYER_ONE",
        &outside,
        OUTSIDE_LAYER_ONE
            .iter()
            .filter(|r| r.1 > 0)
            .map(|(p, n, _)| (*p, *n)),
    ));
    out.extend(table_findings("TOKEN_ROWS", &tokens, TOKEN_ROWS));
    out.extend(table_findings("SHAPE_ROWS", &shapes, SHAPE_ROWS));
    out.extend(compare_forms(&a1));
    out.extend(env_findings(tree, &joined));
    out.extend(table_findings("ENV_NAME_ROWS", &env_names, ENV_NAME_ROWS));
    out
}

/// Both directions of an exact per-file count table.
fn compare_counts<'a>(
    table: &str,
    have: &BTreeMap<String, usize>,
    want: impl Iterator<Item = (&'a str, usize)>,
) -> Vec<String> {
    let want: BTreeMap<&str, usize> = want.collect();
    let mut out = Vec::new();
    for (rel, n) in have {
        let w = want.get(rel.as_str()).copied().unwrap_or(0);
        if w != *n {
            out.push(format!(
                "{rel}: {n} process-start sites, {table} has {w}; a new or removed start needs its row (#10176)"
            ));
        }
    }
    for (rel, w) in &want {
        if !have.contains_key(*rel) {
            out.push(format!(
                "{rel}: 0 process-start sites, {table} has {w}; a new or removed start needs its row (#10176)"
            ));
        }
    }
    out
}

fn compare_forms(have: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, forms) in have {
        match A1_ROWS.iter().find(|r| r.0 == rel) {
            Some(r) if r.1 == forms.len() => {}
            Some(r) => out.push(format!(
                "{rel}: {} fork or timeout forms, A1_ROWS has {} (#10176)",
                forms.len(),
                r.1
            )),
            None => out.extend(forms.iter().cloned()),
        }
    }
    for (rel, n, _) in A1_ROWS {
        if !have.contains_key(*rel) {
            out.push(format!(
                "{rel}: 0 fork or timeout forms, A1_ROWS has {n} (#10176)"
            ));
        }
    }
    out
}

/// The [`ENV_ROWS`] findings: the byte count of the needle in every file plus
/// `joined`, the names a `concat!` of a `.rs` file builds from parts.
fn env_findings(tree: &Tree, joined: &BTreeMap<String, usize>) -> Vec<String> {
    let needle = env_needle();
    let have: BTreeMap<&str, usize> = tree
        .files
        .iter()
        .map(|(rel, b)| {
            let built = joined.get(rel).copied().unwrap_or(0);
            (rel.as_str(), count_bytes(b, needle.as_bytes()) + built)
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    let want: BTreeMap<&str, usize> = ENV_ROWS.iter().map(|(p, n, _)| (*p, *n)).collect();
    let mut out = Vec::new();
    for rel in have.keys().chain(want.keys()).collect::<BTreeSet<_>>() {
        let (h, w) = (
            have.get(rel).copied().unwrap_or(0),
            want.get(rel).copied().unwrap_or(0),
        );
        if h != w {
            out.push(format!(
                "{rel}: names a proptest environment variable {h} times, ENV_ROWS has {w}; a variable set in CI, .cargo config, a script or code can switch fork on (#10176)"
            ));
        }
    }
    out
}

#[test]
fn every_process_start_is_counted_and_covered_under_every_cfg_10176() {
    let tree = read_tree(&crate_root());
    let findings = census(&tree);
    assert!(
        findings.is_empty(),
        "#10176 census:\n{}",
        findings.join("\n")
    );
}

#[test]
fn every_row_has_a_reason_and_the_tables_are_sorted_10176() {
    let names: Vec<&str> = START_ROWS.iter().map(|r| r.0).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names, sorted, "START_ROWS is sorted and has no duplicate");
    for (p, n, why) in OUTSIDE_LAYER_ONE.iter().chain(A1_ROWS).chain(ENV_ROWS) {
        assert!(why.len() >= 20, "{p}: a reason of at least 20 bytes");
        let _ = n;
    }
    for (table, rows) in [
        ("TOKEN_ROWS", TOKEN_ROWS),
        ("SHAPE_ROWS", SHAPE_ROWS),
        ("ENV_NAME_ROWS", ENV_NAME_ROWS),
    ] {
        assert_eq!(
            table_findings(table, &BTreeMap::new(), rows).len(),
            rows.len(),
            "{table}: every row is reasoned and sorted (one stale line per row only)"
        );
        assert!(rows.iter().all(|r| r.1 > 0), "{table}: no row of count 0");
    }
    for (p, why) in SKIPPED {
        assert!(why.len() >= 10, "{p}: a skip reason");
    }
    for (name, _, why) in LIBC_FAMILIES {
        assert!(why.len() >= 10, "libc::{name}: a reason");
    }
    for row in LOCK_ROWS {
        assert!(row.why.len() >= 20, "{}: a reason", row.name);
    }
}

// ---------------------------------------------------------------- B mutants

/// The B findings of one fixture file (aliases from the fixture itself).
fn b_fixture(rel: &str, text: &str) -> Vec<String> {
    let toks = lex(text);
    let aliases = aliases_in(&toks);
    let sites = starts(&toks, &aliases, &libc_start_names());
    start_findings(rel, &toks, &sites, false)
}

#[test]
fn a_raw_start_under_any_cfg_without_an_expect_is_red_10176() {
    let rel = "src/governance/x.rs";
    let red: &[(&str, usize)] = &[
        (
            "#[cfg(target_os = \"macos\")]\nfn f() {\n    std::process::Command::new(\"chmod\");\n}\n",
            3,
        ),
        (
            "#[cfg(windows)]\nfn f() {\n    let _ = std::process::Command::new(\"icacls\");\n}\n",
            3,
        ),
        (
            "use std::process::Command as Run;\nfn f() {\n    Run::new(\"x\");\n}\n",
            3,
        ),
        (
            "type Run = std::process::Command;\nfn f() { Run::new(\"x\"); }\n",
            2,
        ),
        ("fn f() { tokio::process::Command::new(\"x\"); }\n", 1),
        ("fn f() { assert_cmd::Command::cargo_bin(\"x\"); }\n", 1),
        (
            "fn f() { ai_memory::spawn_audit::audited_command(\"x\"); }\n",
            1,
        ),
        (
            "fn f() { <std::process::Command as CommandExt>::exec(c); }\n",
            1,
        ),
        ("fn f() { unsafe { libc::fork() }; }\n", 1),
        ("fn f() { unsafe { libc::dlmopen(0, p, 0) }; }\n", 1),
        ("fn f() { unsafe { libc::execvP(a, b, c) }; }\n", 1),
        (
            "#[expect(clippy::disallowed_methods)]\nfn g() {}\nfn f() { std::process::Command::new(\"x\"); }\n",
            3,
        ),
        (
            "fn f() {\n    #[expect(clippy::disallowed_methods)]\n    let a = 1;\n    std::process::Command::new(\"x\");\n}\n",
            4,
        ),
        (
            "#[expect(clippy::needless_pass_by_value)]\nfn f() { std::process::Command::new(\"x\"); }\n",
            2,
        ),
    ];
    for (text, line) in red {
        assert_eq!(
            b_fixture(rel, text),
            vec![uncovered(rel, *line)],
            "fixture:\n{text}"
        );
    }
}

#[test]
fn a_start_under_an_expect_in_reach_is_green_10176() {
    let green: &[&str] = &[
        "#[cfg(target_os = \"macos\")]\n#[expect(clippy::disallowed_methods, reason = \"r\")]\nfn f() { std::process::Command::new(\"chmod\"); }\n",
        "fn f() {\n    #[expect(clippy::disallowed_methods, reason = \"r\")]\n    let c = std::process::Command::new(\"x\");\n}\n",
        "mod m {\n    #![allow(clippy::disallowed_methods)]\n    fn f() { std::process::Command::new(\"x\"); }\n}\n",
        "#![expect(clippy::disallowed_methods)]\nfn f() { std::process::Command::new(\"x\"); }\n",
        "#[expect(clippy::disallowed_methods)]\nimpl Drop for G { fn drop(&mut self) { std::process::Command::new(\"x\"); } }\n",
        "use std::process::Command;\nuse assert_cmd::cargo::CommandCargoExt;\nuse ai_memory::spawn_audit::audited_command;\n",
        "pub fn audited_command(p: &str) {}\n",
        "fn f() { let s = \"std::process::Command::new\"; } // Command::new\n",
    ];
    for text in green {
        assert_eq!(
            b_fixture("src/x.rs", text),
            Vec::<String>::new(),
            "fixture:\n{text}"
        );
    }
}

#[test]
fn a_use_that_hides_a_libc_start_and_a_nix_path_are_red_10176() {
    let rel = "src/x.rs";
    for text in [
        "use libc::fork;\n",
        "use libc::{fork, getpid};\n",
        "use libc::*;\n",
        "use libc as c;\n",
        "pub use libc::execvp;\n",
        "pub(crate) use libc::{self};\n",
    ] {
        let got = b_fixture(rel, text);
        assert_eq!(got, vec![libc_use(rel, 1)], "fixture: {text}");
    }
    assert_eq!(
        b_fixture(
            rel,
            "use libc::socklen_t;\nuse libc::__errno_location as errno_location;\n"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        b_fixture(rel, "fn f() { nix::unistd::fork(); }\n"),
        vec![nix_path(rel, 1)]
    );
}

#[test]
fn the_count_tables_are_exact_in_both_directions_10176() {
    let have: BTreeMap<String, usize> = [("src/a.rs".to_string(), 2)].into();
    assert_eq!(
        compare_counts("START_ROWS", &have, [("src/a.rs", 1), ("src/b.rs", 1)].into_iter()),
        vec![
            "src/a.rs: 2 process-start sites, START_ROWS has 1; a new or removed start needs its row (#10176)".to_string(),
            "src/b.rs: 0 process-start sites, START_ROWS has 1; a new or removed start needs its row (#10176)".to_string(),
        ]
    );
    assert_eq!(
        compare_counts("START_ROWS", &have, [("src/a.rs", 2)].into_iter()),
        Vec::<String>::new()
    );
}

#[test]
fn a_nested_package_file_and_a_link_are_seen_10176() {
    let packages = vec!["tools/x".to_string()];
    assert!(in_package("tools/x/src/main.rs", &packages));
    assert!(!in_package("tools/xy/src/main.rs", &packages));
    assert!(!in_package("tools/x", &packages));
    let tree = Tree {
        files: vec![],
        links: vec!["src/l.rs".to_string()],
        packages: vec![],
        root: None,
    };
    let got = census(&tree);
    assert_eq!(
        got.first().map(String::as_str),
        Some("src/l.rs: a symbolic link; the census never follows links (#10176)")
    );
}

#[test]
fn the_census_is_linear_on_large_input_10176() {
    let mut text = String::from("#![allow(dead_code)]\n");
    for i in 0..20_000 {
        writeln!(
            text,
            "#[expect(clippy::disallowed_methods)]\nfn f{i}() {{ std::process::Command::new(\"x\"); }}\nuse a::b{i};"
        )
        .expect("writing to a String cannot fail");
    }
    text.push_str("fn deep() ");
    text.push_str(&"{ ".repeat(20_000));
    text.push_str("std::process::Command::new(\"x\")");
    text.push_str(&" }".repeat(20_000));
    text.push_str("\nfn long() { x(");
    text.push_str(&"std::process::Command::new(\"y\"), ".repeat(20_000));
    text.push_str("); }\n");
    assert!(text.len() > 100_000);
    let t0 = std::time::Instant::now();
    let got = b_fixture("src/big.rs", &text);
    let _ = pt_findings("src/big.rs", &text);
    assert_eq!(
        got.len(),
        20_001,
        "the deep site and every long-statement site"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(20),
        "census took {:?}",
        t0.elapsed()
    );
}

/// The #10312 field-form scan is linear: 20,000 literal fields in one
/// argument list, a metavariable field under 20,000 nested repetitions, a
/// 20,000-segment `&mut` place and 20,000 reads of a shared chain give the
/// exact finding counts within the ceiling.
#[test]
fn the_field_form_scan_is_linear_on_a_large_file_10312() {
    const N: usize = 20_000;
    let mut text = String::from("fn lits() { x(");
    text.push_str(&"X { fork: 1 }, ".repeat(N));
    text.push_str("); }\nmacro_rules! m { () => { Cfg { ");
    text.push_str(&"$( ".repeat(N));
    text.push_str("$f: 1");
    text.push_str(&" )*".repeat(N));
    text.push_str(" } } }\nfn chain() { let r = &mut a");
    text.push_str(&".a".repeat(N));
    text.push_str(".fork; let t = ");
    text.push_str(&"a.b.fork + ".repeat(N));
    text.push_str("0; }\n");
    assert!(text.len() > 100_000);
    let t0 = std::time::Instant::now();
    let (_, forms) = pt_findings("src/big.rs", &text);
    let elapsed = t0.elapsed();
    let count = |what: &str| forms.iter().filter(|f| f.contains(what)).count();
    assert_eq!(
        count(FORM_FIELD_WRITE),
        N + 1,
        "the literal fields and the &mut place"
    );
    assert_eq!(count(FORM_META_FIELD), 1, "the metavariable field");
    assert_eq!(forms.len(), N + 2, "no other finding");
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "field forms took {elapsed:?}"
    );
}

// ---------------------------------------------------------------- A1 mutants

/// The A1 findings of one fixture file, with the config closure of that file.
fn pt_findings(rel: &str, text: &str) -> (Vec<String>, Vec<String>) {
    let toks = lex(text);
    let prep = Prep::new(&toks);
    let config = census_pins::closure(std::slice::from_ref(&prep), CONFIG_SEED);
    proptest_findings(rel, &prep, &config)
}

#[test]
fn every_unguarded_proptest_block_form_is_red_10176() {
    let rel = "tests/p.rs";
    for text in [
        "proptest! {\n    #[test]\n    fn t(x in 0..1u8) {}\n}\n",
        "proptest::proptest! {\n    #![proptest_config(Config::with_cases(8))]\n    #[test] fn t(x in 0..1u8) {}\n}\n",
        "proptest! {\n    #![proptest_config(not_the_guard(Config::default()))]\n}\n",
        "proptest!(|(x in 0..1u8)| { prop_assert!(x < 1); });\n",
        "proptest! [ ]\n",
    ] {
        let (blocks, _) = pt_findings(rel, text);
        assert_eq!(blocks, vec![unguarded_block(rel, 1)], "fixture:\n{text}");
    }
    for text in [
        "proptest! {\n    #![proptest_config(proptest_guarded(proptest::test_runner::Config::default()))]\n}\n",
        "proptest::proptest! {\n    #![proptest_config(crate::test_support::proptest_guard::proptest_guarded(Config::with_cases(64)))]\n}\n",
        "macro_rules! m { () => {} }\n",
    ] {
        let (blocks, forms) = pt_findings(rel, text);
        assert!(blocks.is_empty() && forms.is_empty(), "fixture:\n{text}");
    }
}

#[test]
fn every_fork_or_timeout_form_is_red_10176() {
    let rel = "tests/p.rs";
    let red: &[(&str, &str)] = &[
        (
            "let c = Config { fork: true, ..Config::default() };",
            FORM_FIELD,
        ),
        (
            "let c = ProptestConfig { timeout: 5, ..ProptestConfig::default() };",
            FORM_FIELD,
        ),
        ("let c = Config { cases: 8, ..base };", FORM_UPDATE),
        (
            "let c = Config { cases: 8, ..Config::with_cases(8) };",
            FORM_UPDATE,
        ),
        ("let c = Config::default().with_fork(true);", FORM_BUILDER),
        ("let c = Config::default().with_timeout(5);", FORM_BUILDER),
        ("c.fork = true;", FORM_ASSIGN),
        ("cfg.timeout = 10;", FORM_ASSIGN),
        ("let r = TestRunner::new(c);", FORM_RUNNER),
        ("rusty_fork::rusty_fork_id!();", FORM_RUNNER),
        ("use proptest as p;", FORM_RENAME),
        ("#[property_test]\nfn t() {}", FORM_RUNNER),
    ];
    for (text, what) in red {
        let (_, forms) = pt_findings(rel, text);
        assert_eq!(forms, vec![fork_form(rel, 1, what)], "fixture: {text}");
    }
    for text in [
        "let c = Config { cases: 8, max_shrink_iters: 4, ..proptest::test_runner::Config::default() };",
        "let c = Config { cases: 8, ..Config::default() };",
        "let ok = c.timeout == 0 && !c.fork();",
        "struct S { timeout: u32 }",
    ] {
        let (_, forms) = pt_findings(rel, text);
        assert!(forms.is_empty(), "fixture: {text}: {forms:?}");
    }
}

/// Every write to a `fork` or `timeout` field that #10312 found green: a
/// literal field under `Self`, a metavariable or any other type, field
/// shorthand, a pattern field, any compound assignment and a `&mut` borrow.
/// Each row is one exact finding, and the `timeout` twin of each row too.
/// The expected line is written out here, never built by the census.
#[test]
fn every_fork_or_timeout_field_form_is_red_10312() {
    let rel = "tests/p.rs";
    let want = "tests/p.rs:1: a field form of fork or timeout (a literal or pattern field outside a proptest Config literal, field shorthand, a compound assignment or a &mut borrow); a proptest config with fork or timeout on re-runs this test binary outside the sandbox (#10176)";
    let red: &[&str] = &[
        "macro_rules! m { ($t:expr) => { Cfg { fork: $t } } }",
        "macro_rules! m { ($t:ident) => { $t { fork: true } } }",
        "macro_rules! m { ($t:ty) => { type C = $t; let c = C { fork: true }; } }",
        "impl Default for ProptestConfig { fn default() -> Self { Self { fork: true, ..base() } } }",
        "impl ProptestConfig { fn f(fork: bool) -> Self { Self { fork } } }",
        "let c = ProptestConfig { fork, ..ProptestConfig::default() };",
        "let c = Cfg { cases: 1, fork };",
        "let Cfg { ref mut fork, .. } = c;",
        "if let Cfg { fork, .. } = c {}",
        "let d = Outer { inner: Inner { fork: true } };",
        "c.fork += 1;",
        "c.fork |= true;",
        "c.fork <<= 1;",
        "c.fork >>= 1;",
        "c.fork -= 1;",
        "let r = &mut c.fork;",
        "core::mem::replace(&mut c.fork, true);",
        "let r = &mut self.cfg.fork;",
        "let r = &mut (*p).fork;",
        "let r = &mut v[0].fork;",
        "let r = &raw mut c.fork;",
        "let r = core::ptr::addr_of_mut!(c.fork);",
    ];
    for row in red {
        for text in [row.to_string(), row.replace("fork", "timeout")] {
            let (_, forms) = pt_findings(rel, &text);
            assert_eq!(forms, vec![want.to_string()], "fixture: {text}");
        }
    }
    let green: &[&str] = &[
        "let c = Config { cases: 8, ..Config::default() };",
        "let ok = c.fork == 0 && !c.fork();",
        "let t = c.fork;",
        "let ok = c.fork <= 5 || c.fork >= 1 || c.fork != 2 || c.fork < 3;",
        "struct S { fork: u32 }",
        "pub struct S<T> where T: Copy { fork: T }",
        "enum E { A, V { fork: u32 } }",
        "fn f(fork: u32) -> u32 { fork }",
        "fn f() { let fork: u32 = 5; let g = |a, fork: u32| a; }",
        "let t = if x { fork } else { fork };",
        "while running { fork }",
        "for i in 0..fork { fork }",
        "loop { fork }",
        "let v = unsafe { fork };",
        "match x { fork => 1, _ => fork }",
        "use x::{fork, y};",
        "let f = Cfg::fork;",
        "let d = c.fork.clone();",
    ];
    for row in green {
        for text in [row.to_string(), row.replace("fork", "timeout")] {
            let (_, forms) = pt_findings(rel, &text);
            assert!(forms.is_empty(), "fixture: {text}: {forms:?}");
        }
    }
}

/// The sibling of #10312 through a macro: a metavariable in a field
/// position may name `fork` or `timeout` (`m!(fork)`), so it is one exact
/// finding of its own; a metavariable in a value, matcher or path position
/// is not. The expected line is written out here.
#[test]
fn every_metavariable_field_form_is_red_10312() {
    let rel = "tests/p.rs";
    let want = "tests/p.rs:1: a macro metavariable in field position (a literal or pattern field, an assignment, a compound assignment or a &mut borrow), which may name fork or timeout; a proptest config with fork or timeout on re-runs this test binary outside the sandbox (#10176)";
    let red: &[&str] = &[
        "macro_rules! m { ($f:ident) => { Cfg { $f: true } } }",
        "macro_rules! m { ($f:ident) => { Config { $f: true, ..Config::default() } } }",
        "macro_rules! m { ($f:ident) => { Cfg { cases: 1, $f } } }",
        "macro_rules! m { ($($f:ident),*) => { Cfg { $($f: true),* } } }",
        "macro_rules! m { ($($f:ident),*) => { Cfg { $($f),* } } }",
        "macro_rules! m { ($f:ident) => { c.$f = true; } }",
        "macro_rules! m { ($f:ident) => { c.$f += 1; } }",
        "macro_rules! m { ($f:ident) => { let r = &mut c.$f; } }",
        "macro_rules! m { ($c:expr, $f:ident) => { $c.$f = true; } }",
    ];
    for text in red {
        let (_, forms) = pt_findings(rel, text);
        assert_eq!(forms, vec![want.to_string()], "fixture: {text}");
    }
    let green: &[&str] = &[
        "macro_rules! m { ($t:expr) => { Cfg { cases: $t } } }",
        "macro_rules! m { ($t:expr) => { let x = $t; } }",
        "macro_rules! m { ($c:expr) => { let t = $c.cases; } }",
        "macro_rules! m { ($f:ident) => { let ok = c.$f == 1; } }",
        "macro_rules! m { ($f:ident) => { let t = c.$f; } }",
        "macro_rules! m { ($f:ident) => { c.$f(); } }",
        "macro_rules! m { () => { $crate::f(); } }",
        "macro_rules! m { ($t:ty) => { impl X for $t { fn f() {} } } }",
    ];
    for text in green {
        let (_, forms) = pt_findings(rel, text);
        assert!(forms.is_empty(), "fixture: {text}: {forms:?}");
    }
}

#[test]
fn a_proptest_variable_in_any_file_is_an_exact_row_10176() {
    let needle = env_needle();
    assert_eq!(needle.len(), 9, "the prefix of {FORK_VAR}");
    let tree = Tree {
        files: vec![
            (
                ".github/workflows/x.yml".to_string(),
                format!("env:\n  {needle}FORK: 'true'\n").into_bytes(),
            ),
            (
                ".cargo/config.toml".to_string(),
                format!("[env]\n{needle}TIMEOUT = \"5\"\n").into_bytes(),
            ),
        ],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let got = env_findings(&tree, &BTreeMap::new());
    let line = |rel: &str, h: usize, w: usize| {
        format!(
            "{rel}: names a proptest environment variable {h} times, ENV_ROWS has {w}; a variable set in CI, .cargo config, a script or code can switch fork on (#10176)"
        )
    };
    assert_eq!(
        got,
        vec![
            line(".cargo/config.toml", 1, 0),
            line(".github/workflows/x.yml", 1, 0),
            line("changelog.d/10176.fixed.md", 0, ENV_ROWS[0].1),
            line(
                "scripts/ci/tests/test_census_rows_10286.py",
                0,
                ENV_ROWS[1].1
            ),
            line("tests/common/census_config_10301.json", 0, ENV_ROWS[2].1),
            line("tests/common/census_env_name_10299.json", 0, ENV_ROWS[3].1),
            line("tests/common/census_env_name_10299.rs", 0, ENV_ROWS[4].1),
            line("tests/common/proptest_guard.rs", 0, ENV_ROWS[5].1),
        ]
    );
}

// ---------------------------------------------------------------- R3 mutants

/// The census findings of a one-file tree that name that file.
fn r3_fixture(rel: &str, text: &str) -> Vec<String> {
    let tree = Tree {
        files: vec![(rel.to_string(), text.as_bytes().to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{rel}:");
    census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head) && !R4_TAGS.iter().any(|t| l.ends_with(t)))
        .collect()
}

/// The tags of the round-four rules; the round-three table reads the rest,
/// and [`r4_fixture`] reads these.
const R4_TAGS: &[&str] = &["(#10286)", "(#10287)", "(#10289)"];

/// The round-four lines of the census of one file.
fn r4_fixture(rel: &str, text: &str) -> Vec<String> {
    let tree = Tree {
        files: vec![(rel.to_string(), text.as_bytes().to_vec())],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let head = format!("{rel}:");
    census(&tree)
        .into_iter()
        .filter(|l| l.starts_with(&head) && R4_TAGS.iter().any(|t| l.ends_with(t)))
        .collect()
}

/// Every form the round-2 recogniser did not model (R2, R3, R9, R10, R13) and
/// the forms invented in round 3 (I1 to I13): each is red with its exact
/// lines. The expected lines are written out here, never built by the census.
#[test]
fn every_round_three_form_is_red_10176() {
    let rel = "src/r3.rs";
    let tok = |n: usize| {
        format!(
            "{rel}: {n} watched process, libc, nix or proptest tokens, TOKEN_ROWS has 0; every reference under any cfg, in any macro or by any path needs its exact row (#10176)"
        )
    };
    let shape = |line: usize, what: &str| {
        format!(
            "{rel}:{line}: {what}; a form the census does not model needs a SHAPE_ROWS row with its reason (#10176)"
        )
    };
    let runner = |line: usize, name: &str| {
        format!(
            "{rel}:{line}: {name}! reaches the proptest runner outside a guarded proptest! block (#10176)"
        )
    };
    let env_name = |n: usize| {
        format!(
            "{rel}: {n} environment names that are not one string literal or one named constant, ENV_NAME_ROWS has 0; a built name can switch proptest fork on (#10176)"
        )
    };
    let env = |n: usize| {
        format!(
            "{rel}: names a proptest environment variable {n} times, ENV_ROWS has 0; a variable set in CI, .cargo config, a script or code can switch fork on (#10176)"
        )
    };
    let uncovered = |line: usize| {
        format!(
            "{rel}:{line}: process start with no #[expect(clippy::disallowed_methods)] on its item or statement; layer 1 does not see code under a cfg the clippy jobs do not compile (#10176)"
        )
    };
    let start = format!(
        "{rel}: 1 process-start sites, START_ROWS has 0; a new or removed start needs its row (#10176)"
    );
    let metavar = "a watched path followed by a macro metavariable";
    let impl_ = "an impl whose header names a watched process, libc, nix or proptest name";
    let glob = "a glob import of a watched path";
    let paste = "a pasted or concatenated identifier";
    let rows: Vec<(&str, &str, Vec<String>)> = vec![
        (
            "R2 a macro metavariable after std::process",
            "#[cfg(windows)]\nmacro_rules! spawn_it {\n    ($t:ident) => { std::process::$t::new(\"x\") };\n}\n",
            vec![shape(3, metavar), tok(2)],
        ),
        (
            "R3 an impl for std::process::Command",
            "#[cfg(target_os = \"macos\")]\nimpl Spawn for std::process::Command {\n    fn spawn_it() -> Self { Self::new(\"x\") }\n}\n",
            vec![shape(2, impl_), tok(2)],
        ),
        (
            "R9 an expect under cfg_attr(any())",
            "#[cfg_attr(any(), expect(clippy::disallowed_methods, reason = \"x\"))]\nfn f() { std::process::Command::new(\"x\"); }\n",
            vec![uncovered(2), start.clone(), tok(2)],
        ),
        (
            "I10 an allow under cfg_attr(not(all()))",
            "#[cfg_attr(not(all()), allow(clippy::disallowed_methods))]\nfn f() { std::process::Command::new(\"x\"); }\n",
            vec![uncovered(2), start.clone(), tok(2)],
        ),
        (
            "R10 proptest_helper! outside a guarded block",
            "fn t() {\n    proptest_helper!(@_WRAP (x));\n}\n",
            vec![runner(2, "proptest_helper"), tok(1)],
        ),
        (
            "R13 a proptest variable name built by concat!",
            "fn f() {\n    std::env::set_var(concat!(\"PROPTEST\", \"_FORK\"), \"true\");\n}\n",
            vec![env(1), env_name(1)],
        ),
        (
            "I1 an extern block",
            "extern \"C\" {\n    fn fork() -> i32;\n}\n",
            vec![shape(1, "an extern block")],
        ),
        (
            "I2 inline assembly",
            "fn f() {\n    unsafe { core::arch::asm!(\"syscall\") }\n}\n",
            vec![shape(2, "inline assembly")],
        ),
        (
            "I3 a pasted identifier",
            "paste::paste! {\n    fn [<sp awn>]() {}\n}\n",
            vec![shape(1, paste), shape(2, paste)],
        ),
        (
            "I4 std::process renamed by self as",
            "use std::process::{self as p};\nfn f() -> u32 {\n    p::id()\n}\n",
            vec![tok(3)],
        ),
        (
            "I5 a type alias of a process type",
            "type Run = std::process::Child;\nfn f(_: Run) {}\n",
            vec![tok(3)],
        ),
        (
            "I6 proptest_helper! through #[macro_use] extern crate",
            "#[macro_use]\nextern crate proptest;\nfn t() {\n    proptest_helper!(@_WRAP (x));\n}\n",
            vec![runner(4, "proptest_helper"), tok(2)],
        ),
        (
            "I7 a glob import of std::process",
            "use std::process::*;\n",
            vec![shape(1, glob), tok(1)],
        ),
        (
            "I8 an environment name passed as a variable",
            "fn f(k: &str) {\n    let _ = std::env::var(k);\n}\n",
            vec![env_name(1)],
        ),
        (
            "I9 a proptest variable name built in a const",
            "const N: &str = concat!(\"PROPTEST\", \"_TIMEOUT\");\n",
            vec![env(1)],
        ),
        (
            "I11 a macro that wraps a proptest macro",
            "macro_rules! cases {\n    () => { proptest::prop_compose!{} };\n}\nfn t() { cases!(); }\n",
            vec![runner(4, "cases"), tok(4)],
        ),
        (
            "I12 another function renamed to proptest_guarded",
            "use std::convert::identity as proptest_guarded;\n",
            vec![format!(
                "{rel}:1: a definition or rename of proptest_guarded outside tests/common/proptest_guard.rs; a guarded block must call the one guard (#10176)"
            )],
        ),
        (
            "I13 a proptest_guard module from another file",
            "#[path = \"evil.rs\"]\nmod proptest_guard;\n",
            vec![
                // #10300: the #[path] site is followed, and this tree has no evil.rs.
                format!(
                    "{rel}:1: #[path] \"evil.rs\" names src/evil.rs, which is not a regular file (#10300)"
                ),
                format!(
                    "{rel}:2: a proptest_guard module not loaded from tests/common/proptest_guard.rs by #[path] (#10176)"
                ),
            ],
        ),
    ];
    for (form, text, want) in rows {
        assert_eq!(r3_fixture(rel, text), want, "{form}:\n{text}");
    }
}

/// A rowed file with another count and a row whose file has no token are
/// each red with the exact line of the R3 tables.
#[test]
fn a_wrong_count_and_a_stale_row_of_the_token_tables_are_red_10176() {
    let tree = Tree {
        files: vec![(
            "tests/common/tls_serve.rs".to_string(),
            b"fn f() -> u32 {\n    std::process::id()\n}\n".to_vec(),
        )],
        links: vec![],
        packages: vec![],
        root: None,
    };
    let got: Vec<String> = census(&tree)
        .into_iter()
        .filter(|l| {
            (l.starts_with("tests/common/tls_serve.rs:") || l.starts_with("src/daemon_runtime.rs:"))
                && (l.contains("TOKEN_ROWS") || l.contains("SHAPE_ROWS"))
        })
        .collect();
    assert_eq!(
        got,
        vec![
            "tests/common/tls_serve.rs: 1 watched process, libc, nix or proptest tokens, TOKEN_ROWS has 6; every reference under any cfg, in any macro or by any path needs its exact row (#10176)".to_string(),
            "src/daemon_runtime.rs: 0 watched process, libc, nix or proptest tokens, TOKEN_ROWS has 178; every reference under any cfg, in any macro or by any path needs its exact row (#10176)".to_string(),
            "src/daemon_runtime.rs: 0 forms the census does not model, SHAPE_ROWS has 1; each needs its exact row with its reason (#10176)".to_string(),
            "tests/common/tls_serve.rs: 0 forms the census does not model, SHAPE_ROWS has 3; each needs its exact row with its reason (#10176)".to_string(),
        ]
    );
}

/// #10311: a file rowed `R_SHAPE_EXTERN` declares only `acl_*` functions in
/// its extern blocks; any other function, a static, a type, an attribute
/// (a `link_name` can bind an `acl_*` name to any symbol) or a macro item is
/// red with its exact finding. The rows are written out by hand.
#[test]
fn a_shape_extern_row_for_a_non_acl_extern_is_red_10311() {
    let red = |name: &str| format!("a.rs is rowed R_SHAPE_EXTERN but declares {name} (#10311)");
    let rows: [(&str, Vec<String>); 9] = [
        (
            "unsafe extern \"C\" {\n    fn acl_free(p: *mut u8) -> i32;\n    fn acl_get_fd_np(fd: i32, t: i32) -> *mut u8;\n}\n",
            vec![],
        ),
        (
            "extern {\n    pub fn acl_x(f: fn(i32) -> i32);\n}\n",
            vec![],
        ),
        (
            "unsafe extern \"C\" {\n    fn acl_free(p: *mut u8) -> i32;\n    fn fork() -> i32;\n}\n",
            vec![red("fork")],
        ),
        (
            "extern \"C\" {\n    fn posix_spawn() -> i32;\n}\n",
            vec![red("posix_spawn")],
        ),
        (
            "extern {\n    static mut environ: *const u8;\n}\n",
            vec![red("environ")],
        ),
        ("extern \"C\" {\n    type acl_t;\n}\n", vec![red("acl_t")]),
        (
            "extern \"C\" {\n    #[link_name = \"fork\"]\n    fn acl_free() -> i32;\n}\n",
            vec![red("#[link_name]")],
        ),
        ("extern \"C\" {\n    m! { fn fork(); }\n}\n", vec![red("m")]),
        (
            "extern \"C\" {\n    fn acl_a();\n}\nextern \"C\" {\n    fn execve();\n    safe fn acl_b();\n}\n",
            vec![red("execve")],
        ),
    ];
    for (src, want) in rows {
        assert_eq!(extern_row_findings("a.rs", &lex(src)), want, "{src}");
    }
}

/// The wall-clock ceiling of the extern-row scan on one 100K+ input (#10311).
const EXTERN_SCAN_CEILING: std::time::Duration = std::time::Duration::from_secs(5);

/// #10311: the extern-row scan is linear: 10 000 acl-only blocks are clean,
/// and 60 000 nested unclosed `extern {` openings are one finding, each over
/// 100K bytes and under [`EXTERN_SCAN_CEILING`].
#[test]
fn the_extern_row_scan_is_linear_on_large_input_10311() {
    let clean = "unsafe extern \"C\" {\n    fn acl_free(p: *mut u8) -> i32;\n}\n".repeat(10_000);
    let nested = "extern {\n".repeat(60_000);
    let cases = [
        (clean, Vec::<String>::new()),
        (
            nested,
            vec!["a.rs is rowed R_SHAPE_EXTERN but declares extern (#10311)".to_string()],
        ),
    ];
    for (src, want) in cases {
        assert!(src.len() > 100_000);
        let toks = lex(&src);
        let t0 = std::time::Instant::now();
        assert_eq!(extern_row_findings("a.rs", &toks), want);
        assert!(
            t0.elapsed() < EXTERN_SCAN_CEILING,
            "took {:?}",
            t0.elapsed()
        );
    }
}

/// #10311: the census reads the extern reason of a `SHAPE_ROWS` row as a
/// claim about the file. A rowed `R_SHAPE_EXTERN` file whose extern block
/// declares a non-`acl_*` function, an `R_SHAPE_EXTERN` row over a form that
/// is not an extern block, and an extern block under a row with another
/// reason are each red with the exact line. The files and lines are written
/// out by hand; the rows are the committed ones.
#[test]
fn the_census_truth_checks_the_extern_reason_of_a_shape_row_10311() {
    let ext = "src/governance/deferred_audit.rs";
    let imp = "tests/common/tls_serve.rs";
    let rows: [(&str, &str, Vec<String>); 4] = [
        (
            ext,
            "unsafe extern \"C\" {\n    fn acl_free() -> i32;\n}\nunsafe extern \"C\" {\n    fn acl_get_entry() -> i32;\n}\n",
            vec![],
        ),
        (
            ext,
            "unsafe extern \"C\" {\n    fn acl_free() -> i32;\n}\nunsafe extern \"C\" {\n    fn fork() -> i32;\n}\n",
            vec![format!(
                "{ext} is rowed R_SHAPE_EXTERN but declares fork (#10311)"
            )],
        ),
        (
            ext,
            "use proptest::prelude::*;\nunsafe extern \"C\" {\n    fn acl_free() -> i32;\n}\n",
            vec![format!(
                "{ext}:1: a glob form under an R_SHAPE_EXTERN row, whose reason covers only extern blocks (#10311)"
            )],
        ),
        (
            imp,
            "extern \"C\" {\n    fn acl_free() -> i32;\n}\n",
            vec![format!(
                "{imp}:1: an extern block under a SHAPE_ROWS row whose reason is not R_SHAPE_EXTERN (#10311)"
            )],
        ),
    ];
    for (rel, src, want) in rows {
        let tree = Tree {
            files: vec![(rel.to_string(), src.as_bytes().to_vec())],
            links: vec![],
            packages: vec![],
            root: None,
        };
        let got: Vec<String> = census(&tree)
            .into_iter()
            .filter(|l| l.ends_with("(#10311)"))
            .collect();
        assert_eq!(got, want, "{rel}:\n{src}");
    }
}

/// A row with a short reason, a row out of order and a file held twice are
/// each red with the exact line; a matching table is green.
#[test]
fn a_reasonless_or_unsorted_r3_row_is_red_10176() {
    let why = "a reason of more than twenty bytes";
    let have: BTreeMap<String, usize> = [("a.rs".to_string(), 1), ("b.rs".to_string(), 2)]
        .into_iter()
        .collect();
    assert_eq!(
        table_findings("TOKEN_ROWS", &have, &[("a.rs", 1, why), ("b.rs", 2, why)]),
        Vec::<String>::new()
    );
    assert_eq!(
        table_findings(
            "SHAPE_ROWS",
            &have,
            &[("a.rs", 1, "short"), ("b.rs", 2, why)]
        ),
        vec!["a.rs: the SHAPE_ROWS row has no reason of at least 20 bytes (#10176)".to_string()]
    );
    assert_eq!(
        table_findings(
            "ENV_NAME_ROWS",
            &have,
            &[("b.rs", 2, why), ("a.rs", 1, why)]
        ),
        vec!["a.rs: ENV_NAME_ROWS is not sorted or holds the file twice (#10176)".to_string()]
    );
    assert_eq!(
        table_findings(
            "TOKEN_ROWS",
            &have,
            &[("a.rs", 1, why), ("a.rs", 1, why), ("b.rs", 2, why)]
        ),
        vec!["a.rs: TOKEN_ROWS is not sorted or holds the file twice (#10176)".to_string()]
    );
}

/// Part D: a silence under `cfg_attr` is in reach only for a predicate of the
/// accepted set, which is empty in the census; an accepted predicate in a
/// test set is in reach, and a second predicate that is not accepted is not.
#[test]
fn a_cfg_attr_silence_is_in_reach_only_for_an_accepted_predicate_10176() {
    assert!(
        ACCEPTED_PREDICATES.is_empty(),
        "no cfg_attr silence is accepted"
    );
    let text =
        "#[cfg_attr(test, expect(clippy::disallowed_methods, reason = \"x\"))]\nfn f() { g(); }\n";
    let toks = lex(text);
    let at = toks
        .iter()
        .position(|t| is_ident_tok(t, "g"))
        .expect("the call is lexed");
    assert!(
        !coverage(&toks)[at],
        "cfg_attr(test, ..) is out of reach in the census"
    );
    assert!(
        coverage_with(&toks, &["test"])[at],
        "an accepted predicate is in reach"
    );
    assert!(
        !coverage_with(&toks, &["unix"])[at],
        "another accepted predicate does not cover cfg_attr(test, ..)"
    );
    let nested =
        "#[cfg_attr(test, cfg_attr(unix, expect(clippy::disallowed_methods)))]\nfn f() { g(); }\n";
    let toks = lex(nested);
    let at = toks
        .iter()
        .position(|t| is_ident_tok(t, "g"))
        .expect("the call is lexed");
    assert!(
        !coverage_with(&toks, &["test"])[at],
        "every nested predicate must be accepted"
    );
    assert!(coverage_with(&toks, &["test", "unix"])[at]);
    let plain = lex("#[expect(clippy::disallowed_methods)]\nfn f() { g(); }\n");
    let at = plain
        .iter()
        .position(|t| is_ident_tok(t, "g"))
        .expect("the call is lexed");
    assert!(
        coverage(&plain)[at],
        "an unconditional expect stays in reach"
    );
}

// ---------------------------------------------------------------- A2: Cargo.lock

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Can start a process or load code on a path this repository builds; the
    /// row names the guard.
    In,
    /// Has a start or load site that no build of this repository reaches.
    Out,
}

struct LockRow {
    name: &'static str,
    versions: &'static [&'static str],
    verdict: Verdict,
    why: &'static str,
}

const fn row(
    name: &'static str,
    versions: &'static [&'static str],
    verdict: Verdict,
    why: &'static str,
) -> LockRow {
    LockRow {
        name,
        versions,
        verdict,
        why,
    }
}

/// Every `Cargo.lock` crate whose code can start a process, re-run the test
/// binary or load code, with the versions read for this table. Read by hand
/// from the registry sources at these versions.
const LOCK_ROWS: &[LockRow] = &[
    row(
        "proptest",
        &["1.11.0"],
        Verdict::In,
        "trigger: fork and timeout features on; guard: A1 (every block guarded) and A3 (run-time refusal)",
    ),
    row(
        "rusty-fork",
        &["0.3.1"],
        Verdict::In,
        "re-runs the test binary for a forked proptest case; guard: A1 and A3",
    ),
    row(
        "wait-timeout",
        &["0.2.1"],
        Verdict::In,
        "waits on the rusty-fork child of a timed proptest case; guard: A1 and A3",
    ),
    row(
        "assert_cmd",
        &["2.2.1"],
        Verdict::In,
        "Command::cargo_bin starts a built binary; guard: clippy.toml entries and B",
    ),
    row(
        "tokio",
        &["1.53.3"],
        Verdict::In,
        "tokio::process::Command; guard: clippy.toml entry and B",
    ),
    row(
        "libc",
        &["0.2.191"],
        Verdict::In,
        "the fork, exec, spawn and loader families; guard: clippy.toml entries, C and B",
    ),
    row(
        "nix",
        &["0.31.3"],
        Verdict::In,
        "unistd::fork and execv wrappers, not used in this tree; guard: B refuses any nix path",
    ),
    row(
        "gemm-common",
        &["0.19.0"],
        Verdict::In,
        "runs the system program lscpu to size caches, a binary not built from this repo",
    ),
    row(
        "criterion",
        &["0.5.1"],
        Verdict::In,
        "runs the system program gnuplot when present; benches only, never a test binary",
    ),
    row(
        "criterion-plot",
        &["0.5.0"],
        Verdict::In,
        "builds the gnuplot command criterion runs; benches only",
    ),
    row(
        "cc",
        &["1.2.60"],
        Verdict::In,
        "runs the C compiler at build time only, never in a test process",
    ),
    row(
        "cmake",
        &["0.1.58"],
        Verdict::In,
        "runs cmake at build time only",
    ),
    row(
        "autocfg",
        &["1.5.0"],
        Verdict::In,
        "runs rustc at build time only",
    ),
    row(
        "pkg-config",
        &["0.3.33"],
        Verdict::In,
        "runs pkg-config at build time only",
    ),
    row(
        "rustc_version",
        &["0.4.1"],
        Verdict::In,
        "runs rustc --version at build time only",
    ),
    row(
        "version_check",
        &["0.9.5"],
        Verdict::In,
        "runs rustc --version at build time only",
    ),
    row(
        "jobserver",
        &["0.1.34"],
        Verdict::In,
        "configures a build-time child's job server; build scripts only",
    ),
    row(
        "openssl-src",
        &["300.6.0+3.6.2"],
        Verdict::In,
        "runs perl, make and the C compiler at build time only",
    ),
    row(
        "openssl-sys",
        &["0.9.113"],
        Verdict::In,
        "its build script runs the C compiler and pkg-config at build time only",
    ),
    row(
        "find-msvc-tools",
        &["0.1.9"],
        Verdict::In,
        "finds and runs MSVC tools at build time, Windows only",
    ),
    row(
        "aws-lc-sys",
        &["0.45.0"],
        Verdict::In,
        "its build script runs cmake and the C compiler at build time only",
    ),
    row(
        "sqlx-macros-core",
        &["0.8.6"],
        Verdict::In,
        "runs cargo metadata inside the sqlx macros at compile time only",
    ),
    row(
        "candle-core",
        &["0.11.1"],
        Verdict::Out,
        "starts nvcc only in the cuda code, behind a feature this repo leaves off",
    ),
    row(
        "android_system_properties",
        &["0.1.5"],
        Verdict::Out,
        "loads libc.so with dlopen on Android only, a target this repo does not build",
    ),
    row(
        "rustix",
        &["0.38.44", "1.1.6"],
        Verdict::Out,
        "its only fork is in the libc backend's apple setattrlistat emulation; Linux uses linux_raw",
    ),
    row(
        "kqueue",
        &["1.2.0"],
        Verdict::Out,
        "starts a process only in its own cfg(test) code",
    ),
    row(
        "gethostname",
        &["0.5.0"],
        Verdict::Out,
        "starts hostname only in its own cfg(test) code",
    ),
    row(
        "hf-hub",
        &["0.5.0"],
        Verdict::Out,
        "starts a process only in its own cfg(test) code",
    ),
    row(
        "sysctl",
        &["0.6.0"],
        Verdict::Out,
        "starts sysctl only in its own cfg(test) code",
    ),
    row(
        "zip",
        &["9.2.2"],
        Verdict::Out,
        "starts a process only in its own cfg(test) code",
    ),
    row(
        "portable-atomic",
        &["1.13.1"],
        Verdict::Out,
        "starts a process only in its own cfg(test) code",
    ),
    row(
        "redox_users",
        &["0.5.2"],
        Verdict::Out,
        "has a login_cmd builder this repo never calls; Redox only",
    ),
    row(
        "dotenvy",
        &["0.15.7"],
        Verdict::Out,
        "starts a process only in its own bin target, never built as a dependency",
    ),
];

/// Crates known to start processes, re-run a binary or load code. Each is
/// absent from `Cargo.lock` or has a row: a new dependency on one of them
/// turns this red until its row is written. Written by hand.
const PROCESS_NAMES: &[&str] = &[
    "duct",
    "subprocess",
    "xshell",
    "cmd_lib",
    "command-group",
    "process-wrap",
    "async-process",
    "portable-pty",
    "expectrl",
    "rexpect",
    "fork",
    "daemonize",
    "escargot",
    "trycmd",
    "snapbox",
    "libloading",
    "dlopen",
    "dlopen2",
    "open",
    "opener",
    "webbrowser",
    "self-replace",
    "self_update",
    "which",
    "shell-words",
    "rusty-fork",
    "wait-timeout",
    "nix",
    "assert_cmd",
];

/// (name, version) of every `[[package]]` of a `Cargo.lock` text.
fn lock_packages(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            name = None;
        } else if let Some(v) = line
            .strip_prefix("name = \"")
            .and_then(|r| r.strip_suffix('"'))
        {
            name = Some(v.to_string());
        } else if let Some(v) = line
            .strip_prefix("version = \"")
            .and_then(|r| r.strip_suffix('"'))
            && let Some(n) = name.take()
        {
            out.push((n, v.to_string()));
        }
    }
    out
}

fn lock_findings(text: &str) -> Vec<String> {
    let mut have: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, v) in lock_packages(text) {
        have.entry(n).or_default().push(v);
    }
    let mut out = Vec::new();
    for r in LOCK_ROWS {
        let mut got = have.get(r.name).cloned().unwrap_or_default();
        got.sort();
        let want: Vec<String> = r.versions.iter().map(ToString::to_string).collect();
        if got != want {
            out.push(format!(
                "Cargo.lock: {} is at {got:?}, LOCK_ROWS pins {want:?}; re-read that version for process starts and update its row (#10176)",
                r.name
            ));
        }
    }
    for n in PROCESS_NAMES {
        if have.contains_key(*n) && !LOCK_ROWS.iter().any(|r| r.name == *n) {
            out.push(format!(
                "Cargo.lock: {n} starts processes or loads code and has no LOCK_ROWS row (#10176)"
            ));
        }
    }
    out
}

#[test]
fn every_dependency_that_starts_a_process_is_a_reasoned_row_10176() {
    let text = std::fs::read_to_string(crate_root().join("Cargo.lock"))
        .unwrap_or_else(|e| panic!("#10176: read Cargo.lock: {e}"));
    assert!(
        lock_packages(&text).len() > 100,
        "the lock parser reads the lock"
    );
    let got = lock_findings(&text);
    assert!(got.is_empty(), "#10176 lock census:\n{}", got.join("\n"));
    assert!(LOCK_ROWS.iter().any(|r| r.verdict == Verdict::Out));
}

#[test]
fn a_lock_change_without_its_row_is_red_10176() {
    let text = std::fs::read_to_string(crate_root().join("Cargo.lock"))
        .unwrap_or_else(|e| panic!("#10176: read Cargo.lock: {e}"));
    let bumped = text.replacen(
        "name = \"wait-timeout\"\nversion = \"0.2.1\"",
        "name = \"wait-timeout\"\nversion = \"0.2.2\"",
        1,
    );
    assert_ne!(bumped, text, "the mutant applies");
    assert_eq!(
        lock_findings(&bumped),
        vec!["Cargo.lock: wait-timeout is at [\"0.2.2\"], LOCK_ROWS pins [\"0.2.1\"]; re-read that version for process starts and update its row (#10176)".to_string()]
    );
    let removed = text.replacen("name = \"wait-timeout\"", "name = \"wait-timeout-gone\"", 1);
    assert_eq!(
        lock_findings(&removed),
        vec!["Cargo.lock: wait-timeout is at [], LOCK_ROWS pins [\"0.2.1\"]; re-read that version for process starts and update its row (#10176)".to_string()]
    );
    let added = format!("{text}\n[[package]]\nname = \"duct\"\nversion = \"1.0.0\"\n");
    assert_eq!(
        lock_findings(&added),
        vec![
            "Cargo.lock: duct starts processes or loads code and has no LOCK_ROWS row (#10176)"
                .to_string()
        ]
    );
}

// ---------------------------------------------------------------- A3: run-time refusal

#[test]
fn the_run_time_refusal_is_exact_for_every_value_10176() {
    let bad = std::os::unix::ffi::OsStrExt::from_bytes(b"\xff\xfe");
    let bad: &OsStr = bad;
    let unproven = |name, shown: &str, off| {
        Some(EnvRefusal::Unproven {
            name,
            shown: shown.to_string(),
            off,
        })
    };
    let enables = |name, shown: &str| {
        Some(EnvRefusal::Enables {
            name,
            shown: shown.to_string(),
        })
    };
    let rows: Vec<(&'static str, Option<&OsStr>, Option<EnvRefusal>)> = vec![
        (FORK_VAR, None, None),
        (FORK_VAR, Some(OsStr::new("false")), None),
        (
            FORK_VAR,
            Some(OsStr::new("")),
            unproven(FORK_VAR, "\"\"", FORK_OFF),
        ),
        (
            FORK_VAR,
            Some(OsStr::new("0")),
            unproven(FORK_VAR, "\"0\"", FORK_OFF),
        ),
        (
            FORK_VAR,
            Some(OsStr::new("1")),
            unproven(FORK_VAR, "\"1\"", FORK_OFF),
        ),
        (
            FORK_VAR,
            Some(OsStr::new("TRUE")),
            unproven(FORK_VAR, "\"TRUE\"", FORK_OFF),
        ),
        (
            FORK_VAR,
            Some(OsStr::new(" false")),
            unproven(FORK_VAR, "\" false\"", FORK_OFF),
        ),
        (
            FORK_VAR,
            Some(OsStr::new("true")),
            enables(FORK_VAR, "\"true\""),
        ),
        (
            FORK_VAR,
            Some(bad),
            Some(EnvRefusal::Unreadable { name: FORK_VAR }),
        ),
        (TIMEOUT_VAR, None, None),
        (TIMEOUT_VAR, Some(OsStr::new("0")), None),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("")),
            unproven(TIMEOUT_VAR, "\"\"", TIMEOUT_OFF),
        ),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("false")),
            unproven(TIMEOUT_VAR, "\"false\"", TIMEOUT_OFF),
        ),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("-1")),
            unproven(TIMEOUT_VAR, "\"-1\"", TIMEOUT_OFF),
        ),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("00")),
            unproven(TIMEOUT_VAR, "\"00\"", TIMEOUT_OFF),
        ),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("1")),
            enables(TIMEOUT_VAR, "\"1\""),
        ),
        (
            TIMEOUT_VAR,
            Some(OsStr::new("5000")),
            enables(TIMEOUT_VAR, "\"5000\""),
        ),
        (
            TIMEOUT_VAR,
            Some(bad),
            Some(EnvRefusal::Unreadable { name: TIMEOUT_VAR }),
        ),
    ];
    for (name, value, want) in rows {
        assert_eq!(env_refusal(name, value), want, "{name}={value:?}");
    }
    assert_eq!(
        enables(FORK_VAR, "\"true\"").map(|r| r.to_string()),
        Some(format!(
            "{FORK_VAR}=\"true\" makes proptest run each case in a child process that re-runs this test binary outside the #10176 sandbox; unset it"
        ))
    );
    assert_eq!(
        unproven(TIMEOUT_VAR, "\"x\"", TIMEOUT_OFF).map(|r| r.to_string()),
        Some(format!(
            "{TIMEOUT_VAR}=\"x\" is not a value proven to leave proptest's fork and timeout off (unset, or exactly \"0\"); unset it (#10176)"
        ))
    );
    assert_eq!(
        EnvRefusal::Unreadable { name: FORK_VAR }.to_string(),
        format!("{FORK_VAR} holds bytes that are not UTF-8; unset it (#10176)")
    );
}

#[test]
fn a_long_value_is_cut_on_a_char_boundary_10176() {
    for len in [
        SHOWN_MAX_CHARS - 1,
        SHOWN_MAX_CHARS,
        SHOWN_MAX_CHARS + 1,
        100_000,
    ] {
        let value: String = "é".repeat(len);
        let got = env_refusal(FORK_VAR, Some(OsStr::new(&value)));
        let kept: String = "é".repeat(len.min(SHOWN_MAX_CHARS));
        let shown = if len > SHOWN_MAX_CHARS {
            format!("{kept:?}...")
        } else {
            format!("{kept:?}")
        };
        assert_eq!(
            got,
            Some(EnvRefusal::Unproven {
                name: FORK_VAR,
                shown,
                off: FORK_OFF,
            }),
            "len {len}"
        );
    }
}

fn panic_text(f: impl FnOnce()) -> String {
    // The closure owns its Config and nothing is observed after the unwind.
    let err =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).expect_err("the guard panics");
    err.downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(ToString::to_string))
        .unwrap_or_default()
}

#[test]
fn the_guard_refuses_a_config_with_fork_or_timeout_on_10176() {
    use proptest::test_runner::Config;
    // The two A1_ROWS forms of this file.
    let fork = Config {
        fork: true,
        ..Config::default()
    };
    let timed = Config {
        timeout: 1,
        ..Config::default()
    };
    assert!(
        panic_text(move || drop(proptest_guarded(fork))).starts_with(
            "#10176: the given proptest config has fork on; a forked case re-runs this test binary outside the sandbox"
        )
    );
    // A timeout switches fork() on as well; the fork check fires first.
    assert!(
        panic_text(move || drop(proptest_guarded(timed))).starts_with(
            "#10176: the given proptest config has fork on; a forked case re-runs this test binary outside the sandbox"
        )
    );
    let ok = proptest_guarded(Config::with_cases(3));
    assert_eq!((ok.cases, ok.fork(), ok.timeout()), (3, false, 0));
}

// ---------------------------------------------------------------- C: libc families

/// Every libc 0.2.191 `pub fn` that starts a process, replaces the process
/// image or loads code, and the near names that do not. Enumerated by regex
/// sweeps over the registry source (`pub fn <name>` with the hints fork, exec,
/// spawn, popen, system, dl, clone, daemon, syscall, proc, load), each name
/// then read by hand; never derived from `clippy.toml`.
const LIBC_FAMILIES: &[(&str, Verdict, &str)] = &[
    ("fork", Verdict::In, "POSIX: starts a process"),
    ("vfork", Verdict::In, "starts a process sharing memory"),
    (
        "clone",
        Verdict::In,
        "Linux, Android, Fuchsia: starts a process or thread",
    ),
    ("daemon", Verdict::In, "forks and detaches"),
    ("forkpty", Verdict::In, "forks onto a pseudo-terminal"),
    ("execl", Verdict::In, "exec family: replaces the image"),
    ("execle", Verdict::In, "exec family"),
    ("execlp", Verdict::In, "exec family"),
    ("execv", Verdict::In, "exec family"),
    ("execve", Verdict::In, "exec family"),
    ("execvp", Verdict::In, "exec family"),
    ("execvpe", Verdict::In, "exec family"),
    ("fexecve", Verdict::In, "exec by file descriptor"),
    (
        "execveat",
        Verdict::In,
        "Linux gnu, Hurd: exec relative to a directory",
    ),
    ("posix_spawn", Verdict::In, "starts a process"),
    (
        "posix_spawnp",
        Verdict::In,
        "starts a process found on PATH",
    ),
    ("system", Verdict::In, "runs a shell command"),
    ("popen", Verdict::In, "runs a shell command with a pipe"),
    (
        "syscall",
        Verdict::In,
        "raw entry: can reach fork, clone, execve",
    ),
    ("dlopen", Verdict::In, "loads code by name"),
    ("dlsym", Verdict::In, "looks up any of these by name"),
    ("dlvsym", Verdict::In, "versioned dlsym"),
    (
        "dlmopen",
        Verdict::In,
        "Linux gnu, Hurd: loads code into a namespace",
    ),
    (
        "execvP",
        Verdict::In,
        "Apple, FreeBSD-like: exec with a search path",
    ),
    ("exect", Verdict::In, "FreeBSD-like: exec with tracing"),
    ("rfork", Verdict::In, "FreeBSD: starts a process"),
    (
        "pdfork",
        Verdict::In,
        "FreeBSD: starts a process with a descriptor",
    ),
    ("kld_load", Verdict::In, "FreeBSD: loads a kernel module"),
    (
        "dlfork",
        Verdict::In,
        "Cygwin: fork that keeps loaded modules",
    ),
    ("execlpe", Verdict::In, "Windows: exec family"),
    ("wexecl", Verdict::In, "Windows: wide exec family"),
    ("wexecle", Verdict::In, "Windows: wide exec family"),
    ("wexeclp", Verdict::In, "Windows: wide exec family"),
    ("wexeclpe", Verdict::In, "Windows: wide exec family"),
    ("wexecv", Verdict::In, "Windows: wide exec family"),
    ("wexecve", Verdict::In, "Windows: wide exec family"),
    ("wexecvp", Verdict::In, "Windows: wide exec family"),
    ("wexecvpe", Verdict::In, "Windows: wide exec family"),
    ("load_image", Verdict::In, "Haiku: starts a program image"),
    ("load_add_on", Verdict::In, "Haiku: loads code"),
    (
        "rtpSpawn",
        Verdict::In,
        "VxWorks: starts a real-time process",
    ),
    (
        "sceKernelLoadExec",
        Verdict::In,
        "PSP: replaces the running program",
    ),
    ("sceKernelLoadModule", Verdict::In, "PSP: loads code"),
    (
        "sceKernelLoadModuleBufferUsbWlan",
        Verdict::In,
        "PSP: loads code",
    ),
    ("sceKernelLoadModuleByID", Verdict::In, "PSP: loads code"),
    ("sceKernelLoadModuleMs", Verdict::In, "PSP: loads code"),
    ("sceUtilityLoadAvModule", Verdict::In, "PSP: loads code"),
    ("sceUtilityLoadModule", Verdict::In, "PSP: loads code"),
    ("sceUtilityLoadNetModule", Verdict::In, "PSP: loads code"),
    ("sceUtilityLoadUsbModule", Verdict::In, "PSP: loads code"),
    (
        "__syscall_SYS_execve",
        Verdict::In,
        "wasm32 WALI: raw execve",
    ),
    ("__syscall_SYS_fork", Verdict::In, "wasm32 WALI: raw fork"),
    (
        "pthread_atfork",
        Verdict::Out,
        "registers fork handlers; starts nothing",
    ),
    (
        "spawn_thread",
        Verdict::Out,
        "Haiku: starts a thread in this process",
    ),
    ("clone_area", Verdict::Out, "Haiku: clones a memory area"),
    ("clonefile", Verdict::Out, "Apple: copies a file"),
    (
        "dladdr",
        Verdict::Out,
        "inspects loaded code; loads nothing",
    ),
    ("dlclose", Verdict::Out, "unloads code"),
    ("dlerror", Verdict::Out, "reads the loader error"),
    ("dl_iterate_phdr", Verdict::Out, "walks loaded objects"),
    (
        "posix_spawnattr_init",
        Verdict::Out,
        "configures a spawn; starts nothing (whole posix_spawnattr_ family)",
    ),
    (
        "posix_spawn_file_actions_init",
        Verdict::Out,
        "configures a spawn (whole posix_spawn_file_actions_ family)",
    ),
    ("unload_add_on", Verdict::Out, "Haiku: unloads code"),
    ("kld_isloaded", Verdict::Out, "FreeBSD: queries a module"),
    (
        "getexecname",
        Verdict::Out,
        "Solaris: reads this program's path",
    ),
    (
        "getexecpath",
        Verdict::Out,
        "OpenBSD: reads this program's path",
    ),
    (
        "_NSGetExecutablePath",
        Verdict::Out,
        "Apple: reads this program's path",
    ),
    ("regexec", Verdict::Out, "matches a regular expression"),
    ("fdopendir", Verdict::Out, "opens a directory"),
    ("setproctitle", Verdict::Out, "renames this process"),
];

/// The `libc::` names of the `disallowed-methods` entries of a
/// `clippy.toml` text.
fn clippy_libc(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.split("path = \"libc::").nth(1))
        .filter_map(|r| r.split('"').next())
        .map(ToString::to_string)
        .collect()
}

fn family_findings(clippy: &str) -> Vec<String> {
    let have = clippy_libc(clippy);
    let mut out = Vec::new();
    for (name, verdict, _) in LIBC_FAMILIES {
        let listed = have.contains(*name);
        match (verdict, listed) {
            (Verdict::In, false) => out.push(format!(
                "clippy.toml: libc::{name} starts a process or loads code in libc 0.2.191 and has no disallowed-methods entry (#10176)"
            )),
            (Verdict::Out, true) => out.push(format!(
                "clippy.toml: libc::{name} has an entry but LIBC_FAMILIES rules it out (#10176)"
            )),
            _ => {}
        }
    }
    for name in &have {
        if !LIBC_FAMILIES.iter().any(|(n, _, _)| n == name) {
            out.push(format!(
                "clippy.toml: libc::{name} has an entry but no LIBC_FAMILIES row (#10176)"
            ));
        }
    }
    out
}

/// The `disallowed-methods` entries that may carry `allow-invalid = true`,
/// written out by hand: each is a libc 0.2.191 function that does not exist
/// for x86_64-unknown-linux-gnu, the CI clippy target, so its entry would
/// otherwise warn there. The flag drops only the unresolved-path warning, so
/// it is an exact allowlist: an entry that resolves on Linux never carries it.
const ALLOW_INVALID: &[&str] = &[
    "libc::execvP",
    "libc::exect",
    "libc::rfork",
    "libc::pdfork",
    "libc::kld_load",
    "libc::dlfork",
    "libc::execlpe",
    "libc::wexecl",
    "libc::wexecle",
    "libc::wexeclp",
    "libc::wexeclpe",
    "libc::wexecv",
    "libc::wexecve",
    "libc::wexecvp",
    "libc::wexecvpe",
    "libc::load_image",
    "libc::load_add_on",
    "libc::rtpSpawn",
    "libc::sceKernelLoadExec",
    "libc::sceKernelLoadModule",
    "libc::sceKernelLoadModuleBufferUsbWlan",
    "libc::sceKernelLoadModuleByID",
    "libc::sceKernelLoadModuleMs",
    "libc::sceUtilityLoadAvModule",
    "libc::sceUtilityLoadModule",
    "libc::sceUtilityLoadNetModule",
    "libc::sceUtilityLoadUsbModule",
    "libc::__syscall_SYS_execve",
    "libc::__syscall_SYS_fork",
];

/// The exact form of the flag on an allowlisted entry.
const ALLOW_INVALID_FORM: &str = "allow-invalid = true, reason = ";

/// Findings for the `allow-invalid` flag in a `clippy.toml` text: any line
/// that names the flag in any spelling (case, `_` for `-`) must be a one-line
/// entry whose path is in [`ALLOW_INVALID`] and that holds
/// [`ALLOW_INVALID_FORM`]; every [`ALLOW_INVALID`] path must carry it.
fn allow_invalid_findings(clippy: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, line) in clippy.lines().enumerate() {
        let norm = line.to_ascii_lowercase().replace('_', "-");
        // A whole-line TOML comment cannot set a key.
        if line.trim_start().starts_with('#') || !norm.contains("allow-invalid") {
            continue;
        }
        let n = i + 1;
        let path = line
            .split("path = \"")
            .nth(1)
            .and_then(|r| r.split('"').next());
        match path {
            None => out.push(format!(
                "clippy.toml:{n}: allow-invalid outside a one-line disallowed-methods entry (#10176)"
            )),
            Some(p) if !ALLOW_INVALID.contains(&p) => out.push(format!(
                "clippy.toml:{n}: {p} carries allow-invalid but is not in ALLOW_INVALID; an entry that resolves on Linux glibc must warn when it stops resolving (#10176)"
            )),
            Some(p) if !line.contains(ALLOW_INVALID_FORM) => out.push(format!(
                "clippy.toml:{n}: {p} names allow-invalid but not as `{ALLOW_INVALID_FORM}` (#10176)"
            )),
            Some(p) => {
                seen.insert(p.to_string());
            }
        }
    }
    for p in ALLOW_INVALID {
        if !seen.contains(*p) {
            out.push(format!(
                "clippy.toml: {p} is in ALLOW_INVALID but its entry does not carry allow-invalid = true (#10176)"
            ));
        }
    }
    out
}

#[test]
fn every_libc_start_and_loader_family_has_a_clippy_entry_10176() {
    let text = std::fs::read_to_string(crate_root().join("clippy.toml"))
        .unwrap_or_else(|e| panic!("#10176: read clippy.toml: {e}"));
    let got = family_findings(&text);
    assert!(got.is_empty(), "#10176 libc families:\n{}", got.join("\n"));
    let flags = allow_invalid_findings(&text);
    assert!(
        flags.is_empty(),
        "#10176 allow-invalid:\n{}",
        flags.join("\n")
    );
}

#[test]
fn allow_invalid_is_an_exact_allowlist_10176() {
    let entry = |p: &str, flag: &str| format!("    {{ path = \"{p}\", {flag}reason = \"r\" }},\n");
    let mut all = String::new();
    for p in ALLOW_INVALID {
        all.push_str(&entry(p, "allow-invalid = true, "));
    }
    all.push_str(&entry("libc::fork", ""));
    assert_eq!(allow_invalid_findings(&all), Vec::<String>::new());
    assert_eq!(
        allow_invalid_findings(&format!(
            "# the target-only entries carry allow-invalid = true\n{all}"
        )),
        Vec::<String>::new()
    );
    let last = ALLOW_INVALID.len() + 1;
    let cases: [(String, Vec<String>); 5] = [
        (
            all.replace(
                &entry("libc::fork", ""),
                &entry("libc::fork", "allow-invalid = true, "),
            ),
            vec![format!(
                "clippy.toml:{last}: libc::fork carries allow-invalid but is not in ALLOW_INVALID; an entry that resolves on Linux glibc must warn when it stops resolving (#10176)"
            )],
        ),
        (
            all.replace(
                &entry("libc::fork", ""),
                &entry("libc::fork", "ALLOW_INVALID=true, "),
            ),
            vec![format!(
                "clippy.toml:{last}: libc::fork carries allow-invalid but is not in ALLOW_INVALID; an entry that resolves on Linux glibc must warn when it stops resolving (#10176)"
            )],
        ),
        (
            all.replace(
                &entry("libc::rfork", "allow-invalid = true, "),
                &entry("libc::rfork", ""),
            ),
            vec![
                "clippy.toml: libc::rfork is in ALLOW_INVALID but its entry does not carry allow-invalid = true (#10176)"
                    .to_string(),
            ],
        ),
        (
            all.replace(
                &entry("libc::rfork", "allow-invalid = true, "),
                &entry("libc::rfork", "allow-invalid = false, "),
            ),
            vec![
                "clippy.toml:3: libc::rfork names allow-invalid but not as `allow-invalid = true, reason = ` (#10176)"
                    .to_string(),
                "clippy.toml: libc::rfork is in ALLOW_INVALID but its entry does not carry allow-invalid = true (#10176)"
                    .to_string(),
            ],
        ),
        (
            format!("{all}    allow-invalid = true,\n"),
            vec![format!(
                "clippy.toml:{}: allow-invalid outside a one-line disallowed-methods entry (#10176)",
                last + 1
            )],
        ),
    ];
    for (text, want) in cases {
        assert_eq!(allow_invalid_findings(&text), want);
    }
}

#[test]
fn a_missing_or_unlisted_libc_entry_is_red_10176() {
    let text = std::fs::read_to_string(crate_root().join("clippy.toml"))
        .unwrap_or_else(|e| panic!("#10176: read clippy.toml: {e}"));
    let entry = |n: &str| format!("    {{ path = \"libc::{n}\", reason = \"r\" }},\n");
    let mut all = String::new();
    for (n, v, _) in LIBC_FAMILIES {
        if *v == Verdict::In {
            all.push_str(&entry(n));
        }
    }
    assert_eq!(family_findings(&all), Vec::<String>::new());
    let dropped = all.replace(&entry("dlmopen"), "");
    assert_eq!(
        family_findings(&dropped),
        vec!["clippy.toml: libc::dlmopen starts a process or loads code in libc 0.2.191 and has no disallowed-methods entry (#10176)".to_string()]
    );
    let extra = format!("{all}{}{}", entry("dlclose"), entry("getpid"));
    assert_eq!(
        family_findings(&extra),
        vec![
            "clippy.toml: libc::dlclose has an entry but LIBC_FAMILIES rules it out (#10176)"
                .to_string(),
            "clippy.toml: libc::getpid has an entry but no LIBC_FAMILIES row (#10176)".to_string(),
        ]
    );
    assert!(
        !clippy_libc(&text).is_empty(),
        "the real clippy.toml has libc entries"
    );
}
