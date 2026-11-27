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
//! What this census does not see: a variable set at run time from another
//! thread, or a name built at compile time (`concat!`), reaches proptest
//! without passing A1; the run-time refusal (A3) is the guard there. Code of a
//! dependency is not read; A2 is the reasoned list of those crates.

#[path = "common/proptest_guard.rs"]
mod proptest_guard;
#[path = "common/rust_lex.rs"]
mod rust_lex;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
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
/// outside a `use` or a `fn` definition.
const DIRECT: &[&str] = &[
    "audited_command",
    "audited_tokio_command",
    "CommandCargoExt",
];

/// Names whose renaming with `as` is a site (an alias hides later calls).
const ALIASED: &[&str] = &[
    "Command",
    "CommandExt",
    "libc",
    "audited_command",
    "audited_tokio_command",
    "CommandCargoExt",
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
    ("tests/cli_write_verb_pg_refuse_ceiling_2572.rs", 1),
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
    ("tests/spawn_gate_pins_10176.rs", 9),
    ("tests/sqlite_write_txn_immediate_gate_5084.rs", 1),
    ("tests/stop_signal_8193.rs", 1),
    ("tests/store_url_ambiguous_userinfo_6096.rs", 2),
    ("tests/store_url_fail_closed_2679.rs", 2),
    ("tests/symlink_follow_8950.rs", 1),
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
        if ident(toks, k) == Some("Command") && ident(toks, k + 1) == Some("as") {
            if let Some(name) = ident(toks, k + 2).filter(|n| *n != "_") {
                out.insert(name.to_string());
            }
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
        }
        if DIRECT.contains(&val) {
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
        }
    }
    out
}

/// Whether the attribute opened by the `#` at `k` (`#[..]` or `#![..]`)
/// expects or allows `clippy::disallowed_methods`; returns the index of its
/// `[` too.
fn silence_attr(toks: &[Lexed], k: usize) -> Option<(usize, bool)> {
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
    Some((open, level && lint))
}

/// Per token: whether a silence attribute is in reach (its statement or
/// item prefix, an enclosing item or block, the block's inner attributes,
/// or the file's inner attributes). One forward pass, linear in the tokens.
fn coverage(toks: &[Lexed]) -> Vec<bool> {
    let mut file_inner = false;
    let mut k = 0;
    while is_p(toks, k, '#') && is_p(toks, k + 1, '!') {
        let Some((open, sil)) = silence_attr(toks, k) else {
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
        if let Some((_, true)) = silence_attr(toks, k) {
            seg = true;
        }
        *slot = seg || block;
        match tok(toks, k) {
            Some(Tok::Punct('{')) => {
                let mut inner = false;
                let mut m = k + 1;
                while is_p(toks, m, '#') && is_p(toks, m + 1, '!') {
                    let Some((open, sil)) = silence_attr(toks, m) else {
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
const FORM_RUNNER: &str = "TestRunner, rusty_fork, wait_timeout or property_test, which run cases outside a guarded proptest! block";
const FORM_RENAME: &str = "proptest renamed with as, which hides its blocks from this scan";

/// Idents that run cases without a guarded block.
const RUNNER_IDENTS: &[&str] = &[
    "TestRunner",
    "rusty_fork",
    "rusty_fork_test",
    "wait_timeout",
    "property_test",
];

/// Files allowed to hold A1 forms, with the exact count and the reason.
const A1_ROWS: &[(&str, usize, &str)] = &[(
    "tests/process_start_census_10176.rs",
    2,
    "the A3 table proves proptest_guarded refuses a Config with fork on and one with a timeout",
)];

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

/// The A1 findings of a file that names proptest: unguarded blocks first
/// (never allowlisted), then the fork and timeout forms.
fn proptest_findings(rel: &str, toks: &[Lexed]) -> (Vec<String>, Vec<String>) {
    let (mut blocks, mut forms) = (Vec::new(), Vec::new());
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
        if matches!(val, "Config" | "ProptestConfig") && is_p(toks, k + 1, '{') {
            literal_forms(rel, toks, k + 1, &mut forms);
        }
    }
    (blocks, forms)
}

/// The forms inside the `Config { .. }` literal opened at `open`.
fn literal_forms(rel: &str, toks: &[Lexed], open: usize, out: &mut Vec<String>) {
    let end = group_end(toks, open).min(toks.len());
    let mut depth = 0usize;
    let mut m = open + 1;
    while m < end {
        match tok(toks, m) {
            Some(Tok::Punct('(' | '[' | '{')) => depth += 1,
            Some(Tok::Punct(')' | ']' | '}')) => depth = depth.saturating_sub(1),
            Some(Tok::Ident(s))
                if depth == 0
                    && (s == "fork" || s == "timeout")
                    && is_p(toks, m + 1, ':')
                    && !is_sep(toks, m + 1) =>
            {
                out.push(fork_form(rel, toks[m].line, FORM_FIELD));
            }
            Some(Tok::Punct('.')) if depth == 0 && is_p(toks, m + 1, '.') => {
                if !default_base(toks, m + 2, end) {
                    out.push(fork_form(rel, toks[m].line, FORM_UPDATE));
                }
                m += 1;
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
        if !rel.ends_with(".rs") {
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

/// Every census finding of the tree: B, A1 and the env rows.
fn census(tree: &Tree) -> Vec<String> {
    let mut out: Vec<String> = tree
        .links
        .iter()
        .map(|l| format!("{l}: a symbolic link; the census never follows links (#10176)"))
        .collect();
    let lexed = rust_files(tree, &mut out);
    let names = libc_start_names();
    let aliases: BTreeSet<String> = lexed.iter().flat_map(|(_, t)| aliases_in(t)).collect();
    let mut counts = BTreeMap::new();
    let mut outside = BTreeMap::new();
    let mut a1 = BTreeMap::new();
    for (rel, toks) in &lexed {
        let sites = starts(toks, &aliases, &names);
        let pkg = in_package(rel, &tree.packages);
        if !sites.is_empty() {
            counts.insert(rel.clone(), sites.len());
            if pkg {
                outside.insert(rel.clone(), sites.len());
            }
        }
        out.extend(start_findings(rel, toks, &sites, pkg));
        if toks.iter().any(|t| is_ident_tok(t, "proptest")) {
            let (blocks, forms) = proptest_findings(rel, toks);
            out.extend(blocks);
            if !forms.is_empty() {
                a1.insert(rel.clone(), forms);
            }
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
    out.extend(compare_forms(&a1));
    out.extend(env_findings(tree));
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

fn env_findings(tree: &Tree) -> Vec<String> {
    let needle = env_needle();
    let have: BTreeMap<&str, usize> = tree
        .files
        .iter()
        .map(|(rel, b)| (rel.as_str(), count_bytes(b, needle.as_bytes())))
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
    assert!(compare_counts("START_ROWS", &have, [("src/a.rs", 2)].into_iter()).is_empty());
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
        text.push_str(&format!(
            "#[expect(clippy::disallowed_methods)]\nfn f{i}() {{ std::process::Command::new(\"x\"); }}\nuse a::b{i};\n"
        ));
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
    let toks = lex(&text);
    let _ = proptest_findings("src/big.rs", &toks);
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

// ---------------------------------------------------------------- A1 mutants

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
        let (blocks, _) = proptest_findings(rel, &lex(text));
        assert_eq!(blocks, vec![unguarded_block(rel, 1)], "fixture:\n{text}");
    }
    for text in [
        "proptest! {\n    #![proptest_config(proptest_guarded(proptest::test_runner::Config::default()))]\n}\n",
        "proptest::proptest! {\n    #![proptest_config(crate::test_support::proptest_guard::proptest_guarded(Config::with_cases(64)))]\n}\n",
        "macro_rules! m { () => {} }\n",
    ] {
        let (blocks, forms) = proptest_findings(rel, &lex(text));
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
        let (_, forms) = proptest_findings(rel, &lex(text));
        assert_eq!(forms, vec![fork_form(rel, 1, what)], "fixture: {text}");
    }
    for text in [
        "let c = Config { cases: 8, max_shrink_iters: 4, ..proptest::test_runner::Config::default() };",
        "let c = Config { cases: 8, ..Config::default() };",
        "let ok = c.timeout == 0 && !c.fork();",
        "struct S { timeout: u32 }",
    ] {
        let (_, forms) = proptest_findings(rel, &lex(text));
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
    };
    let got = env_findings(&tree);
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
            line("tests/common/proptest_guard.rs", 0, ENV_ROWS[1].1),
        ]
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

#[test]
fn every_libc_start_and_loader_family_has_a_clippy_entry_10176() {
    let text = std::fs::read_to_string(crate_root().join("clippy.toml"))
        .unwrap_or_else(|e| panic!("#10176: read clippy.toml: {e}"));
    let got = family_findings(&text);
    assert!(got.is_empty(), "#10176 libc families:\n{}", got.join("\n"));
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
    assert!(family_findings(&all).is_empty());
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
