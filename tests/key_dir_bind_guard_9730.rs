//! Key-dir bind guard (#9730, #9803).
//!
//! What the checks do:
//! - Every tracked `.rs` file is lexed: comments are skipped; string, raw,
//!   byte and C string literals are decoded; delimiters are matched. Each token
//!   gets a site: the `fn`, `mod`, `trait`, `struct`, `enum`, `impl` and
//!   `macro_rules!` items around it and the `const`, `static` or `use`
//!   statement it is in, each with the `#[cfg(..)]` written on it, joined with
//!   `::` (`<file root>` when there is none). A statement, field, parameter or
//!   arm that carries a `#[cfg(..)]` adds `<cfg> stmt` until its `;`, its `,`
//!   or the end of its first block. The site starts with the module
//!   path the file is reached under from its crate root, found by following
//!   the `mod` declarations (and their `#[path]` and cfg); a file reached
//!   under more than one path is checked under each, up to
//!   `MAX_PREFIXES_PER_FILE`.
//! - A file named by `include!` or `#[path]` is scanned as Rust whatever its
//!   extension. Doc comments (`///`, `//!`, `/**`, `/*!`) are scanned as
//!   doctests: a fence with a Rust info (or none) is scanned as Rust, an info
//!   in `DOCTEST_SKIPPED_INFO` is skipped, and any other info is a finding.
//! - An identifier equal to the key-dir variable name, its constant, the bind
//!   helper, the sandbox module or its armed entry point, and a string literal
//!   that holds one of them as a name, is refused unless `ALLOWED_SITES` has a
//!   row with that exact file, site and kind of use (`Op`: read, write, child
//!   env or any other use, by the call its innermost parenthesis belongs to).
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
//! - A tracked file that is not `.rs` (and not compiled as Rust) is decoded
//!   (BOM, UTF-16, UTF-8, else Latin-1) and unescaped once; when it holds the
//!   variable name, its constant or the bind helper, `NON_RUST` must have a
//!   row with its exact path and mention count.
//! - The files of the `cargo_skip` set (any `.md`, `docs/`, `scripts/ci/tests/`)
//!   are not read here: a change to only such a file skips cargo, so a test
//!   that read them would not run on it (#9842). They are judged by
//!   `scripts/ci/tests/test_key_dir_name_mentions_9730.py` with the same
//!   decode, unescape, count and written-out rows, and the ledger gate
//!   runs it on every change. That test proves its domain covers the set and
//!   equals `PY_JUDGED_SUFFIX` and `PY_JUDGED_PREFIXES` below.
//! - The table sizes are pinned (`table_sizes_are_pinned_9730`) and the tree
//!   scan has a wall-clock ceiling (`TREE_WALL_CLOCK_CEILING`).
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

/// The module of the test key-dir sandbox.
fn sandbox_mod_token() -> String {
    ["test", "key", "dir"].join("_")
}

/// The armed-sandbox entry point of that module.
fn armed_token() -> String {
    ["armed", "sandbox"].join("_")
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
        .replace("@T@", &sandbox_mod_token())
        .replace("@A@", &armed_token())
}

/// The kind of use an allowed site names: the call its innermost enclosing
/// parenthesis belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// `var`, `var_os`, `vars`, `env!`, `option_env!`.
    Read,
    /// `set_var`, `remove_var`, and the `set` / `remove` of an env guard.
    Write,
    /// `env`, `envs`, `env_remove`, `env_clear` on a child `Command`.
    Child,
    /// Any other place: a definition, an argument of another call, a path.
    Use,
}

impl Op {
    /// Every kind of use, in table order.
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Child, Self::Use];

    /// The lower-case name a message uses.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Child => "child",
            Self::Use => "use",
        }
    }
}

/// One allowed site: a file, the exact site path inside it (with the cfg of
/// every enclosing item and the module path it is reached under) and the
/// one kind of use allowed there.
struct SiteRow {
    file: &'static str,
    site: &'static str,
    op: Op,
    reason: &'static str,
}

/// One allowed fragment: a file, a site and the exact words that hold a piece.
struct FragmentRow {
    file: &'static str,
    site: &'static str,
    text: &'static str,
    reason: &'static str,
}

/// One tracked non-Rust file that holds the names, and how many times.
struct NonRustRow {
    path: &'static str,
    mentions: usize,
    reason: &'static str,
}

/// A tracked file whose name ends with this is judged by the Python test
/// `scripts/ci/tests/test_key_dir_name_mentions_9730.py`, not here.
const PY_JUDGED_SUFFIX: &str = ".md";
/// A tracked file whose path starts with one of these is judged by the same
/// Python test. Together with the suffix this is the `cargo_skip` set: a change
/// to only such a file skips cargo, so a Rust test that read it would not run
/// on that change (#9842). The Python test proves the set is covered.
///
/// The second prefix writes its slashes as hex escapes on purpose: a plain
/// path literal naming that directory would count as a read of every file in
/// it for the cargo skip ledger, which is the defect this split removes. The
/// Python test decodes the escapes before it compares.
const PY_JUDGED_PREFIXES: [&str; 2] = ["docs/", "scripts\x2fci\x2ftests\x2f"];

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
/// A caller of the test key-dir sandbox module.
const SANDBOX_USER: &str = "a test or test-support site that reaches the key-dir sandbox module; the site is pinned so a new caller elsewhere, a product one above all, is refused";
/// The resolver hooks of the sandbox.
const SANDBOX_GATE: &str = "a statement of the production resolver compiled only under test or the test-support feature: it asserts the resolved dir is isolated or hands out the armed sandbox";
/// The declaration of the sandbox module.
const SANDBOX_DECL: &str =
    "the declaration of the sandbox module, compiled only under test or the test-support feature";
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
        file: "src/approvals.rs",
        site: "mod approvals::mod signed::#[cfg(test)] mod tests::fn gate_engages_when_sig_presented_even_if_not_required",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/approvals.rs",
        site: "mod approvals::mod signed::#[cfg(test)] mod tests::fn gate_fails_closed_when_namespace_term_requires_but_no_sigs",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/approvals.rs",
        site: "mod approvals::mod signed::#[cfg(test)] mod tests::fn gate_fails_closed_when_stored_flag_requires_but_no_sigs",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod cli::mod link::#[cfg(test)] mod tests::fn cli_link_signs_edge_when_keypair_present_parity_3036",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod cli::mod link::#[cfg(test)] mod tests::fn cli_link_signs_edge_when_keypair_present_parity_3036",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod cli::mod link::#[cfg(test)] mod tests::fn cli_link_warns_on_non_notfound_keypair_error_3051",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/link.rs",
        site: "mod cli::mod link::#[cfg(test)] mod tests::fn cli_link_warns_on_non_notfound_keypair_error_3051",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn @B@",
        op: Op::Write,
        reason: STORE_BIND,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn @B@",
        op: Op::Use,
        reason: STORE_BIND,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn env_var_guard_restores_previous_value_on_drop",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn env_var_guard_restores_previous_value_on_drop",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn store_sign_with_allow_claimed_stores_claimed_and_warns_3409",
        op: Op::Use,
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn store_sign_with_bound_key_is_agent_attested_3409",
        op: Op::Use,
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn store_sign_without_bound_key_refuses_3409",
        op: Op::Use,
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn test_store_sign_with_bound_key_stamps_agent_attested",
        op: Op::Use,
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/store.rs",
        site: "mod cli::mod store::#[cfg(test)] mod tests::fn test_store_sign_without_local_keypair_errors",
        op: Op::Use,
        reason: STORE_CALLER,
    },
    SiteRow {
        file: "src/cli/test_utils.rs",
        site: "mod cli::#[cfg(test)] mod test_utils::fn ensure_no_config_env",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/cli/verify.rs",
        site: "mod cli::mod verify::#[cfg(test)] mod tests::fn tampered_sig_edge_marked_failed",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/cli/verify.rs",
        site: "mod cli::mod verify::#[cfg(test)] mod tests::fn verify_edge_signed_with_unknown_agent_fails",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/config.rs",
        site: "mod config::#[cfg(test)] mod tests::fn load_capability_config_is_a_closed_allowlist_that_only_shrinks",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/config.rs",
        site: "mod config::#[cfg(test)] mod tests::fn load_capability_config_is_a_closed_allowlist_that_only_shrinks",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/daemon_runtime_shutdown_tests.rs",
        site: "mod daemon_runtime::#[cfg(test)] mod daemon_runtime_shutdown_tests::fn serve_bind_failure_drains_writers_before_returning_fatal_status",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/encryption/mod.rs",
        site: "mod encryption::#[cfg(test)] mod tests::fn secure_tmp_key_dir",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/enterprise_federation_posture.rs",
        site: "mod enterprise_federation_posture::#[cfg(test)] mod tests::fn audit_signing_disarmed_fails_check_19",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/federation/identity/issuer.rs",
        site: "mod federation::mod identity::mod issuer::#[cfg(test)] mod tests::fn load_missing_private_key_is_error",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/federation/identity/issuer.rs",
        site: "mod federation::mod identity::mod issuer::#[cfg(test)] mod tests::fn load_reads_signing_key_and_issues",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/federation/peer_posture.rs",
        site: "mod federation::mod peer_posture::#[cfg(test)] mod tests::#[cfg(unix)] fn enrollment_directory_cycles_are_unobservable_3582",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/federation/peer_posture.rs",
        site: "mod federation::mod peer_posture::#[cfg(test)] mod tests::fn recursive_public_enrollment_never_reads_private_material_3582",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/agent_action.rs",
        site: "mod governance::mod agent_action::#[cfg(test)] mod tests::#[cfg(unix)] fn issue_3647_unserializable_action_never_falls_back_to_plaintext",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/agent_action.rs",
        site: "mod governance::mod agent_action::#[cfg(test)] mod tests::fn issue_3647_forensic_actions_and_outcomes_never_persist_secrets",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/agent_action.rs",
        site: "mod governance::mod agent_action::#[cfg(test)] mod tests::fn issue_3647_refused_command_is_redacted_through_public_checks",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn issue_3647_database_signer_does_not_enable_forensic_files",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_keys_return_none_when_no_keypair_for_agent",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_keys_return_none_when_no_keypair_for_agent",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_signing_key_returns_none_when_dir_missing",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_signing_key_returns_none_when_dir_missing",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_verifying_key_returns_none_when_dir_missing",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod tests::fn load_daemon_verifying_key_returns_none_when_dir_missing",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::#[cfg(test)] mod unsigned_ledger_3354_tests::fn ledger_signing_status_is_consistent_with_the_installed_key_3354",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod governance::mod rules_store::#[cfg(test)] mod tests::fn resolve_operator_pubkey_reads_keygen_layout_from_key_dir",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod governance::mod rules_store::#[cfg(test)] mod tests::fn resolve_operator_pubkey_reads_keygen_layout_from_key_dir",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod governance::mod rules_store::#[cfg(test)] mod tests::fn resolve_operator_pubkey_reads_legacy_raw_layout_from_key_dir",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/governance/rules_store.rs",
        site: "mod governance::mod rules_store::#[cfg(test)] mod tests::fn resolve_operator_pubkey_reads_legacy_raw_layout_from_key_dir",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::fn historical_registry_miss_never_falls_back_to_current_keydir_3464",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::fn pull_attestation_forged_sig_refused_2715",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::fn pull_attestation_unsigned_lands_claimed_2715",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::fn pull_attestation_valid_sig_upgrades_and_applies_2715",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::impl Drop for KeyDirEnvGuard::fn drop",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::impl KeyDirEnvGuard::fn set",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/handlers/federation_receive.rs",
        site: "mod handlers::mod federation_receive::#[cfg(test)] mod tests::impl KeyDirEnvGuard::fn set",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::#[cfg(test)] mod tests::fn default_key_dir_ends_in_ai_memory_keys",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::#[cfg(test)] mod tests::fn default_key_dir_honours_env_override",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::#[cfg(test)] mod tests::fn default_key_dir_honours_env_override",
        op: Op::Use,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::const @C@",
        op: Op::Use,
        reason: DEFINE,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::fn default_key_dir::#[cfg(any(test, feature = \"test-support\"))] stmt",
        op: Op::Use,
        reason: SANDBOX_GATE,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::fn key_dir_env_override",
        op: Op::Read,
        reason: READER,
    },
    SiteRow {
        file: "src/identity/keypair.rs",
        site: "mod identity::mod keypair::fn resolved_default_key_dir_path::#[cfg(any(test, feature = \"test-support\"))] stmt",
        op: Op::Use,
        reason: SANDBOX_GATE,
    },
    SiteRow {
        file: "src/identity/mod.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@",
        op: Op::Use,
        reason: SANDBOX_DECL,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::#[cfg(test)] mod tests::fn key_dir_env_bind_restores_prior_on_panic_3584",
        op: Op::Read,
        reason: HELPER_TEST,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::fn @A@",
        op: Op::Use,
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::fn @B@_env",
        op: Op::Read,
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::fn @B@_env::#[cfg(not(test))] stmt",
        op: Op::Read,
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::fn set_key_dir_env",
        op: Op::Use,
        reason: HELPER,
    },
    SiteRow {
        file: "src/identity/test_key_dir.rs",
        site: "mod identity::#[cfg(any(test, feature = \"test-support\"))] mod @T@::impl Drop for KeyDirEnvBind::fn drop",
        op: Op::Use,
        reason: HELPER,
    },
    SiteRow {
        file: "src/main.rs",
        site: "#[cfg(test)] mod tests::fn boot_and_emit_3647",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/main.rs",
        site: "#[cfg(test)] mod tests::fn init_forensic_audit_with_temp_dir_does_not_panic",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_self_signed_link_verifies_and_populates_signed_fields",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_self_signed_link_verifies_and_populates_signed_fields",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_self_signed_link_verifies_and_populates_signed_fields",
        op: Op::Use,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_signed_link_without_local_pubkey_reports_stored_attest_and_unverified",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_signed_link_without_local_pubkey_reports_stored_attest_and_unverified",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_tampered_signature_returns_false_and_keeps_stored_level_3021",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_tampered_signature_returns_false_and_keeps_stored_level_3021",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn handle_verify_tampered_signature_returns_false_and_keeps_stored_level_3021",
        op: Op::Use,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn issue_811_load_active_keypair_for_mcp_falls_back_to_daemon_when_agent_specific_missing",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn issue_811_load_active_keypair_for_mcp_falls_back_when_agent_id_unresolvable",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn issue_811_load_active_keypair_for_mcp_picks_agent_specific_when_present",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/mcp/mod.rs",
        site: "mod mcp::#[cfg(test)] mod tests::fn issue_811_load_active_keypair_for_mcp_returns_none_when_neither_present",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod mcp::mod checkpoint::#[cfg(test)] mod handler_tests::fn epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007_3368",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod mcp::mod checkpoint::#[cfg(test)] mod handler_tests::fn epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007_3368",
        op: Op::Use,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod mcp::mod checkpoint::#[cfg(test)] mod handler_tests::fn epoch_advance_resolve_without_enrolled_sig_stays_unsigned_3007",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/mcp/tools/checkpoint.rs",
        site: "mod mcp::mod checkpoint::#[cfg(test)] mod handler_tests::fn epoch_advance_resolve_without_enrolled_sig_stays_unsigned_3007",
        op: Op::Use,
        reason: PROCESS,
    },
    SiteRow {
        file: "src/test_support.rs",
        site: "#[cfg(test)] mod test_support::#[cfg(test)] fn run_env_isolated_child_or_spawn_scrubbing",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn embedder_offline_empty_cache_reports_fallback_miss_not_coldfetch_3788",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn spawn_daemon",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/acceptance/acceptance_nhi_sqlite.rs",
        site: "fn spawn_mcp_full",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_default_permissive_lands_unsigned_store_claimed_1985",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_opt_out_zero_lands_unsigned_store_claimed_1751",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/agent_attestation_integrity.rs",
        site: "fn cli_require_attestation_rejects_unsigned_store",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/archive_on_gc_config_3385.rs",
        site: "fn cli_gc_honours_v2_archive_policy_3385",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/archive_restore_cid_identity_2385.rs",
        site: "fn open_db",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/as_agent_read_visibility_3499.rs",
        site: "impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/audit_cli_honors_db_3429.rs",
        site: "impl Sandbox::fn run",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/authority_boundary_3549.rs",
        site: "fn spawn_mcp",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/bind_api_key_token_file_3781.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/boot_posture_banner_2908.rs",
        site: "fn serve_boot_lines",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/capture_turn_identity_3393.rs",
        site: "impl Mcp::fn start",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_stdout_hygiene_behaviour_3436.rs",
        site: "fn run",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_store_sign_unbound_3409.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_verify_chain.rs",
        site: "fn signed_valid_chain_exits_0",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/cli_verify_chain.rs",
        site: "fn tampered_signature_exits_nonzero",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/key_dir_sandbox.rs",
        site: "mod key_dir_sandbox::fn pin",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/common/mcp_stdio_child.rs",
        site: "mod mcp_stdio_child::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/mod.rs",
        site: "#[cfg(feature = \"sal\")] mod common::fn ensure_no_config_env",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/common/mod.rs",
        site: "#[cfg(feature = \"sal-postgres\")] mod common::fn ensure_no_config_env",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/common/mod.rs",
        site: "mod common::fn ensure_no_config_env",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/common/tls_serve.rs",
        site: "#[cfg(feature = \"sal\")] mod common::mod tls_serve::fn try_spawn_serve_once",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/tls_serve.rs",
        site: "#[cfg(feature = \"sal-postgres\")] mod common::mod tls_serve::fn try_spawn_serve_once",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/common/tls_serve.rs",
        site: "mod common::mod tls_serve::fn try_spawn_serve_once",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/config_show_effective_3715.rs",
        site: "fn command_with_config",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/conformance_export_roundtrip_2030.rs",
        site: "fn build_fixture_envelope",
        op: Op::Use,
        reason: MULTI,
    },
    SiteRow {
        file: "tests/cov_fupb_fed_signing.rs",
        site: "fn clear_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_fupb_fed_signing.rs",
        site: "fn enrol_peer_key",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn clear_fed_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn enroll_peer",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_applies_action_transition_sqlite",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_replayed_action_transition_refused_1805",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_push_sig_present_no_enrolled_key_refuses_401",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_federation.rs",
        site: "fn sync_since_sig_present_no_enrolled_key_refuses_401",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn clear_fed_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn enroll_peer",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/cov_ga2_pg_federation.rs",
        site: "fn pg_sync_push_via_store_applies_action_transition",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/credential_to_sink_3711.rs",
        site: "fn run_bin",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/deployment_shape_posture_3700.rs",
        site: "fn command_with_config",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/deployment_shape_posture_3700_pg.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_cli.rs",
        site: "fn ai_memory",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_over_depth_4715.rs",
        site: "fn ai_memory",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_pg_floor_4333.rs",
        site: "fn doctor_json_env",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_posture_exit_code_3003.rs",
        site: "fn armed_failing_cmd",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/doctor_synchronous_posture_3553.rs",
        site: "fn bare_cmd",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/encryption_key_absent_3718_head.rs",
        site: "fn cmd",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/export_import_roundtrip_3405.rs",
        site: "fn ai_memory",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/export_import_roundtrip_3405.rs",
        site: "fn cli_children_use_the_sandboxed_key_dir_and_leave_home_clean_7232",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/fed_checkpoint_lane_3075_pg.rs",
        site: "fn reset_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_1566_embed_ship.rs",
        site: "fn signature_covers_shipped_vector_tamper_yields_401",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_1936_checkpoint_fed.rs",
        site: "fn reset_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_bulk_catchup_governed_egress_3148.rs",
        site: "fn refuse_rule_blocks_the_bulk_catchup_lane_and_emits_governance_check",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_checkpoint_ns_scope_2708.rs",
        site: "fn reset_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_nonce_replay_922.rs",
        site: "fn setup",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_peer_posture_3582.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/federation_signal_authorship_1843.rs",
        site: "fn clear_all_env",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_signal_authorship_1843.rs",
        site: "fn strict_mode_requires_enrolled_author_key_1843",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_push_catchup_sig_2297.rs",
        site: "fn push_signed_is_accepted_2297",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_push_catchup_sig_2297.rs",
        site: "fn push_unsigned_is_refused_2297",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_since_sig_1031.rs",
        site: "fn setup",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/federation_sync_since_sig_1031.rs",
        site: "fn sync_since_mtls_bypass_still_requires_signature_under_require_sig_1040",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/file_sink_warn_3650.rs",
        site: "fn isolated_command_3650",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_cross_process_4304.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_exit_drain_4319.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_outage_pg_4199.rs",
        site: "fn serve",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_tail_4199.rs",
        site: "fn purge_with_deadline",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/forensic_tail_4199.rs",
        site: "fn run_with_env",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/g3_postgres_verify_link_signature_roundtrip.rs",
        site: "fn ephemeral_keypair",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/g_phase_e_4_verify_exit_codes.rs",
        site: "fn reflection_chain_tampered_signature_exits_2_and_ok_false",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_egress_port_4414.rs",
        site: "fn issue_4414_port_rules_enforce_on_the_real_egress_sinks",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_seed_ceremony_3430.rs",
        site: "impl Drop for KeyDirGuard::fn drop",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_seed_ceremony_3430.rs",
        site: "impl KeyDirGuard::fn set",
        op: Op::Read,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/governance_seed_ceremony_3430.rs",
        site: "impl KeyDirGuard::fn set",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/h2_invalidate_link_signed.rs",
        site: "fn setup",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/identity_e2e.rs",
        site: "fn setup",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/identity_generate_not_preempted_3743.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/inbox_notify_cli_pg_refusal_3730.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/integration.rs",
        site: "fn cmd",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_guard_not_in_binary_3516.rs",
        site: "fn operator_cmd",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_guard_not_in_binary_3516.rs",
        site: "use",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "#[cfg(unix)] fn resolver_rejects_a_symlink_alias_into_temporary_home",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn ambient_override_probe",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn guarded_child_without_override_uses_the_shared_sandbox_instead_of_home",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn install_neutralises_ambient_key_dir_3584",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn resolver_panics_under_temporary_home_and_accepts_isolated_override",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "fn shared_helper_isolates_x25519_and_ed25519_writes",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/key_dir_isolation_3355.rs",
        site: "use",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/keys_escrow_recovery_3717.rs",
        site: "impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/keys_prune_3355.rs",
        site: "impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/logging_pipeline_3651.rs",
        site: "fn run_with_section",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_format_refusal_3803.rs",
        site: "impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_governance_pre_action_1685.rs",
        site: "fn spawn_mcp",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_governance_pre_write_hook_1583.rs",
        site: "fn spawn_mcp",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/mcp_signal_drain_4347.rs",
        site: "fn spawn_mcp",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/memory_verify.rs",
        site: "fn setup",
        op: Op::Write,
        reason: PROCESS,
    },
    SiteRow {
        file: "tests/migrate_no_create_3435.rs",
        site: "fn run",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/notify_inbox_no_overwrite_3639.rs",
        site: "fn ai_memory",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/portability_export_completeness_2571.rs",
        site: "fn archived_memory_import_seals_content_at_rest_when_encryption_enabled_2571_f2",
        op: Op::Use,
        reason: MULTI,
    },
    SiteRow {
        file: "tests/posture_control15_pg_resolution_3106.rs",
        site: "fn run_bin",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/retired_provider_aliases.rs",
        site: "fn product_command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/routine_run_authorization_3506.rs",
        site: "impl Mcp::fn start",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/secret_screen_g29.rs",
        site: "fn spawn_mcp",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/signed_events_fresh_store_signs_3354.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/signed_events_fresh_store_signs_3354_pg.rs",
        site: "fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/skill_promote_visibility_3551/mod.rs",
        site: "mod visibility_3551::impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/skill_scope_integrity_8832_8834.rs",
        site: "const ENV_@K@",
        op: Op::Use,
        reason: ALIAS,
    },
    SiteRow {
        file: "tests/store_parity_gaps.rs",
        site: "#[cfg(feature = \"sal-postgres\")] mod postgres_side::fn key_dir_guard",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/store_url_ambiguous_userinfo_6096.rs",
        site: "fn config_show_effective_redacts_a_case_variant_store_scheme_6102",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/store_url_ambiguous_userinfo_6096.rs",
        site: "fn run_bin",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/test_key_dir_isolated_temp_root_3859.rs",
        site: "use",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/tls_verbs_3709.rs",
        site: "fn command_with_config",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/toon_meta_budget_3802.rs",
        site: "impl Fixture::fn command",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/transit_encryption_3705.rs",
        site: "fn command_with_config",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/transit_floor_unverifiable_4434.rs",
        site: "fn run",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/url_allowlist_render_3667.rs",
        site: "fn run_bin",
        op: Op::Child,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "const HUB_ENV_NAMES",
        op: Op::Use,
        reason: NAMES,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "const SINK_ENV_NAMES",
        op: Op::Use,
        reason: NAMES,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "fn hub_env",
        op: Op::Use,
        reason: CHILD,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "fn sink_command",
        op: Op::Use,
        reason: SANDBOX_USER,
    },
    SiteRow {
        file: "tests/wake_hub_readonly_modes_9562.rs",
        site: "fn sink_env",
        op: Op::Use,
        reason: CHILD,
    },
];

/// Every literal or identifier that may hold a piece of the variable name.
const ALLOWED_FRAGMENTS: &[FragmentRow] = &[
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::#[cfg(test)] mod reanchor_ceremony_2004_cli_tests::fn re_anchor_absent_custody_is_explicit_skip_not_fail",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::#[cfg(test)] mod reanchor_ceremony_2004_cli_tests::fn re_anchor_unloadable_custody_fails_closed_nonzero",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::fn bring_up_remaining",
        text: "AI_MEMORY_RECORDER_@K@ _JUDGE_@K@ _STOPPER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::fn bring_up_remaining",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::fn run_re_anchor",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/cli/audit.rs",
        site: "mod cli::mod audit::fn run_restore_attest",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::const JUDGE_@C@",
        text: "AI_MEMORY_JUDGE_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::const RECORDER_@C@",
        text: "AI_MEMORY_RECORDER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::const STOPPER_@C@",
        text: "AI_MEMORY_STOPPER_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::const WITNESS_@C@",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "src/governance/audit.rs",
        site: "mod governance::mod audit::fn last_audit_watermark",
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
        file: "tests/boot_posture_banner_2908.rs",
        site: "fn serve_boot_lines",
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
        site: "fn asi_hard_cold_boot_fresh_db_boots_clean_2942",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
    FragmentRow {
        file: "tests/security_profile_dispatch_1961.rs",
        site: "fn asi_hard_engaged_pins_rollback_check_and_refuses_open_on_wiped_db",
        text: "AI_MEMORY_WITNESS_@K@",
        reason: SIBLING,
    },
];

/// Every tracked non-Rust file that names the variable, with its mention count,
/// except the files of the `cargo_skip` set: `PY_JUDGED_SUFFIX` and
/// `PY_JUDGED_PREFIXES` name them, and
/// `scripts/ci/tests/test_key_dir_name_mentions_9730.py` holds their rows.
const NON_RUST: &[NonRustRow] = &[
    NonRustRow {
        path: ".github/workflows/batman-mode-acceptance.yml",
        mentions: 6,
        reason: DEPLOY,
    },
    NonRustRow {
        path: "cookbook/production-deployment/01-secure-bootstrap.sh",
        mentions: 2,
        reason: TOOLING,
    },
    NonRustRow {
        path: "deploy/do-1461/provision/45_zero_touch.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "deploy/do-1461/provision/46_batman.sh",
        mentions: 5,
        reason: TOOLING,
    },
    NonRustRow {
        path: "deploy/docker-1461/docker-compose.yml",
        mentions: 2,
        reason: DEPLOY,
    },
    NonRustRow {
        path: "deploy/docker-1461/provision/lib.sh",
        mentions: 1,
        reason: TOOLING,
    },
    NonRustRow {
        path: "deploy/enterprise-federation-repro/repro.sh",
        mentions: 1,
        reason: TOOLING,
    },
    NonRustRow {
        path: "deploy/hive-1461/provision/45_zero_touch.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "entrypoint.plan-c.sh",
        mentions: 4,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/bench-mesh/entrypoint.sh",
        mentions: 7,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/bench-mesh/gen-mesh.py",
        mentions: 2,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/do-hive/cloud-init-memory.yaml.tpl",
        mentions: 1,
        reason: DEPLOY,
    },
    NonRustRow {
        path: "infra/do-hive/crypto/test-api-mtls.sh",
        mentions: 1,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/do-hive/crypto/test-attestation.sh",
        mentions: 4,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/do-hive/crypto/test-fed-write-sig-attestation.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "infra/federation-lab/run.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/bench/run-ops-producers.sh",
        mentions: 2,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/bench/wake_bench_env.sh",
        mentions: 4,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/check-bootstrap-cert-gate.sh",
        mentions: 5,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/check-docs-vs-ssot.sh",
        mentions: 1,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/check-test-env-lock.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/check-test-keydir-mode.py",
        mentions: 12,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/docker/Dockerfile.batman-active",
        mentions: 1,
        reason: BATMAN_DOCKERFILE,
    },
    NonRustRow {
        path: "scripts/docker/docker-compose.batman-active.yml",
        mentions: 5,
        reason: DEPLOY,
    },
    NonRustRow {
        path: "scripts/recapture-cert-3607-posture.py",
        mentions: 2,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/recapture-cert-55-posture.sh",
        mentions: 2,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/recapture-cert-9220-posture.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/recapture-cert-eba96b307-posture.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/recapture-cert-f32c-posture.sh",
        mentions: 3,
        reason: TOOLING,
    },
    NonRustRow {
        path: "scripts/test/test_cert_gate_evidence_7181.py",
        mentions: 3,
        reason: TOOLING,
    },
];

/// The doc-comment fence infos rustdoc does not compile as a doctest. A
/// fence whose info is a Rust tag (or empty) is scanned as Rust; any info
/// that is neither a Rust tag nor in this list is a finding.
pub const DOCTEST_SKIPPED_INFO: &[&str] = &[
    "text", "toml", "json", "jsonc", "sh", "bash", "console", "yaml", "yml", "sql", "cypher",
    "plain", "none",
];

/// The expanded tables the scanner reads.
#[derive(Default)]
pub struct Tables {
    pub sites: Vec<(String, String, Op)>,
    pub fragments: Vec<(String, String, String)>,
    pub non_rust: Vec<(String, usize)>,
}

/// The rows a run matched, by index into `Tables`.
#[derive(Default)]
pub struct Used {
    pub sites: BTreeSet<usize>,
    pub fragments: BTreeSet<usize>,
    pub non_rust: BTreeSet<usize>,
}

fn tree_tables() -> Tables {
    Tables {
        sites: ALLOWED_SITES
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site), r.op))
            .collect(),
        fragments: ALLOWED_FRAGMENTS
            .iter()
            .map(|r| (r.file.to_owned(), expand(r.site), expand(r.text)))
            .collect(),
        non_rust: NON_RUST
            .iter()
            .map(|r| (r.path.to_owned(), r.mentions))
            .collect(),
    }
}

/// The allowed sites of the synthetic file the allow and deny rows use:
/// each site is allowed for every kind of use, so a row tests the site
/// rule alone; the op rule has its own rows.
fn syn_tables() -> Tables {
    let sites = [
        "fn allowed_reader",
        "fn allowed_caller",
        "fn @B@",
        "const @C@",
    ];
    Tables {
        sites: sites
            .iter()
            .flat_map(|s| Op::ALL.map(|op| (SYN_FILE.to_owned(), expand(s), op)))
            .collect(),
        ..Tables::default()
    }
}

mod scan {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::path::Path;
    use std::process::Command;

    use super::{
        DOCTEST_SKIPPED_INFO, Op, PY_JUDGED_PREFIXES, PY_JUDGED_SUFFIX, Tables, Used, armed_token,
        call_token, const_token, frag_token, sandbox_mod_token, var_token,
    };

    /// Most distinct module paths one file may be reached under.
    pub const MAX_PREFIXES_PER_FILE: usize = 8;
    /// The site scope a Rust doctest is walked under.
    const DOCTEST_SCOPE: &str = "::doctest";
    /// The macro whose string target is compiled as Rust in place.
    const INCLUDE_MACRO: &str = "include";
    /// File names that own their directory for `mod` resolution.
    const MOD_RS_NAMES: [&str; 3] = ["mod.rs", "lib.rs", "main.rs"];
    /// The shortest code fence.
    const FENCE_MIN: usize = 3;
    /// Fence info words rustdoc compiles or checks as Rust.
    const RUST_FENCE_TAGS: [&str; 8] = [
        "rust",
        "ignore",
        "no_run",
        "should_panic",
        "compile_fail",
        "test_harness",
        "standalone_crate",
        "allow_fail",
    ];
    /// Fence info word prefixes rustdoc reads as Rust attributes.
    const RUST_FENCE_TAG_PREFIXES: [&str; 1] = ["edition"];
    /// Calls whose argument is written to the process environment.
    const WRITE_CALLS: [&str; 4] = ["set_var", "remove_var", "set", "remove"];
    /// Calls whose argument goes to a child process environment.
    const CHILD_CALLS: [&str; 4] = ["env", "envs", "env_remove", "env_clear"];
    /// Calls whose argument is read from the environment.
    const READ_CALLS: [&str; 5] = ["var", "var_os", "vars", "env!", "option_env!"];
    /// Byte order marks of the encodings a non-Rust file is decoded from.
    const UTF16LE_BOM: &[u8] = &[0xFF, 0xFE];
    const UTF16BE_BOM: &[u8] = &[0xFE, 0xFF];
    const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    /// Longest `\u{...}` escape body.
    const MAX_BRACED_HEX: usize = 6;
    /// Longest octal escape body.
    const MAX_OCTAL_DIGITS: usize = 3;
    /// Longest numeric HTML entity body.
    const MAX_ENTITY_DIGITS: usize = 7;

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
    /// The site part of a statement, expression, field or arm that carries a
    /// `#[cfg(..)]`; it follows the cfg labels, as an item name does.
    const STATEMENT_SCOPE: &str = "stmt";
    /// The file root marker followed by a scope separator.
    const FILE_ROOT_SCOPE: &str = "<file root>::";

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
        sandbox: String,
        armed: String,
        ident_fragments: Vec<String>,
    }

    impl Names {
        /// The names refused as a whole identifier.
        fn whole_idents(&self) -> [&String; 5] {
            [
                &self.var,
                &self.constant,
                &self.call,
                &self.sandbox,
                &self.armed,
            ]
        }

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
                sandbox: sandbox_mod_token(),
                armed: armed_token(),
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
        /// One line of a doc comment: the text after its marker.
        Doc,
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
                    let doc = match (self.peek(2), self.peek(3)) {
                        (Some('/'), Some('/')) => false,
                        (Some('/' | '!'), _) => true,
                        _ => false,
                    };
                    let mut text = String::new();
                    while let Some(ch) = self.peek(0).filter(|ch| *ch != '\n') {
                        self.bump()?;
                        text.push(ch);
                    }
                    if doc {
                        self.push(Kind::Doc, text.chars().skip(3).collect(), line);
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

        /// Skips a block comment; a `/**` or `/*!` doc comment gives one
        /// `Doc` token per line, with a leading `*` margin removed.
        fn block_comment(&mut self, line: usize) -> Result<(), Stop> {
            let doc = match (self.peek(2), self.peek(3)) {
                (Some('*'), Some('*' | '/')) => false,
                (Some('*' | '!'), _) => true,
                _ => false,
            };
            self.bump()?;
            self.bump()?;
            if doc {
                self.bump()?;
            }
            let mut depth = 1usize;
            let mut text = String::new();
            let mut at = self.line;
            loop {
                let here = self.line;
                match self.bump()? {
                    None => return Err(bad(line, "unterminated block comment")),
                    Some('/') if self.peek(0) == Some('*') => {
                        self.bump()?;
                        depth += 1;
                        text.push_str("/*");
                    }
                    Some('*') if self.peek(0) == Some('/') => {
                        self.bump()?;
                        depth -= 1;
                        if depth == 0 {
                            if doc {
                                self.push_doc_line(&text, at);
                            }
                            return Ok(());
                        }
                        text.push_str("*/");
                    }
                    Some('\n') => {
                        if doc {
                            self.push_doc_line(&text, at);
                        }
                        text.clear();
                        at = here + 1;
                    }
                    Some(ch) => text.push(ch),
                }
            }
        }

        fn push_doc_line(&mut self, text: &str, line: usize) {
            let trimmed = text.trim_start();
            let body = trimmed.strip_prefix('*').unwrap_or(text);
            self.push(Kind::Doc, body.to_owned(), line);
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
        inline_mod: Option<String>,
    }

    struct Pending {
        label: String,
        depth: usize,
        any_open: bool,
        inline_mod: Option<String>,
    }

    struct Delim {
        open: char,
        line: usize,
        frame: bool,
        callee: Option<String>,
    }

    enum Hit {
        Use {
            line: usize,
            name: String,
            string: bool,
            site: String,
            op: Op,
        },
        Fragment {
            line: usize,
            string: bool,
            site: String,
            text: String,
        },
        Unclassified {
            line: usize,
            what: String,
        },
    }

    /// A `mod NAME;` declaration: its label with cfg, the site it is in, its
    /// `#[path]` value and the inline modules around it.
    #[derive(Clone)]
    struct ModDecl {
        line: usize,
        name: String,
        label: String,
        site: String,
        path: Option<String>,
        inline: Vec<String>,
    }

    /// An `include!` of a string literal and the site of the call.
    #[derive(Clone)]
    struct IncludeAt {
        line: usize,
        target: String,
        site: String,
    }

    /// What one walk of a file found.
    #[derive(Default)]
    struct Walked {
        hits: Vec<Hit>,
        decls: Vec<ModDecl>,
        includes: Vec<IncludeAt>,
    }

    /// How a doc-comment fence is treated.
    enum Fence {
        Rust,
        Skipped,
        Unknown,
    }

    struct Walker<'a, 'm> {
        toks: &'a [Tok],
        names: &'a Names,
        meter: &'m mut Meter,
        prefix: String,
        doctest: bool,
        frames: Vec<Frame>,
        pending: Option<Pending>,
        delims: Vec<Delim>,
        attrs: Vec<String>,
        /// The delimiter depth of the cfg attributes in `attrs`.
        attrs_depth: usize,
        path_attr: Option<String>,
        out: Walked,
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
            Kind::Doc => format!("///{}", t.text),
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

    /// `inner` inside `prefix`: the prefix alone for the file root, and the
    /// file root marker dropped when a prefix replaces it.
    pub fn join_site(prefix: &str, inner: &str) -> String {
        if prefix.is_empty() {
            inner.to_owned()
        } else if inner == FILE_ROOT {
            prefix.to_owned()
        } else if let Some(rest) = inner.strip_prefix(FILE_ROOT_SCOPE) {
            format!("{prefix}::{rest}")
        } else {
            format!("{prefix}::{inner}")
        }
    }

    /// The scope a declaration at `site` opens under `prefix` (empty at the
    /// root of a root file).
    fn scope(prefix: &str, site: &str) -> String {
        if site == FILE_ROOT {
            prefix.to_owned()
        } else {
            join_site(prefix, site)
        }
    }

    /// A fence opener: its character and width.
    fn fence_of(text: &str) -> Option<(char, usize)> {
        let c = text.chars().next().filter(|c| *c == '`' || *c == '~')?;
        let width = text.chars().take_while(|x| *x == c).count();
        (width >= FENCE_MIN).then_some((c, width))
    }

    fn closes(text: &str, c: char, width: usize) -> bool {
        let run = text.chars().take_while(|x| *x == c).count();
        run >= width && text[run..].trim().is_empty()
    }

    fn fence_kind(info: &str) -> Fence {
        let parts: Vec<&str> = info
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        let rust = |p: &str| {
            RUST_FENCE_TAGS.contains(&p) || RUST_FENCE_TAG_PREFIXES.iter().any(|x| p.starts_with(x))
        };
        if parts.is_empty() || parts.iter().any(|p| rust(p)) {
            Fence::Rust
        } else if parts.iter().all(|p| DOCTEST_SKIPPED_INFO.contains(p)) {
            Fence::Skipped
        } else {
            Fence::Unknown
        }
    }

    /// A doctest line with rustdoc's hidden-line marker removed.
    fn hidden_stripped(line: &str) -> &str {
        let t = line.trim_start();
        if t == "#" {
            ""
        } else if let Some(rest) = t.strip_prefix("# ") {
            rest
        } else if t.starts_with("##") {
            &t[1..]
        } else {
            line
        }
    }

    impl<'a, 'm> Walker<'a, 'm> {
        fn new(
            toks: &'a [Tok],
            names: &'a Names,
            meter: &'m mut Meter,
            prefix: String,
            doctest: bool,
        ) -> Self {
            Self {
                toks,
                names,
                meter,
                prefix,
                doctest,
                frames: Vec::new(),
                pending: None,
                delims: Vec::new(),
                attrs: Vec::new(),
                attrs_depth: 0,
                path_attr: None,
                out: Walked::default(),
            }
        }

        fn walk(mut self) -> Result<Walked, Stop> {
            let toks = self.toks;
            let mut doc_start: Option<usize> = None;
            for (i, tok) in toks.iter().enumerate() {
                self.meter.tick()?;
                match tok.kind {
                    Kind::Doc => {
                        let start = *doc_start.get_or_insert(i);
                        if toks.get(i + 1).is_none_or(|t| t.kind != Kind::Doc) {
                            doc_start = None;
                            self.doc_block(&toks[start..=i])?;
                        }
                    }
                    Kind::Punct => self.punct(i)?,
                    Kind::Ident => {
                        self.keyword(i)?;
                        self.include(i);
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
            Ok(self.out)
        }

        /// The label of the statement the cfg attributes in `attrs` are on,
        /// when no item has taken them.
        fn statement_label(&self) -> Option<String> {
            (!self.attrs.is_empty()).then(|| {
                let mut label = String::new();
                for a in &self.attrs {
                    label.push_str(a);
                    label.push(' ');
                }
                label.push_str(STATEMENT_SCOPE);
                label
            })
        }

        fn site(&self) -> String {
            let statement = self.statement_label();
            let mut parts: Vec<&str> = self.frames.iter().map(|f| f.label.as_str()).collect();
            if let Some(p) = &self.pending {
                parts.push(&p.label);
            }
            if let Some(s) = &statement {
                parts.push(s);
            }
            let inner = if parts.is_empty() {
                FILE_ROOT.to_owned()
            } else {
                parts.join("::")
            };
            join_site(&self.prefix, &inner)
        }

        fn statement_at(&self, depth: usize) -> bool {
            self.frames
                .last()
                .is_some_and(|f| f.statement && f.depth == depth)
        }

        /// The cfg attributes before the item, each followed by one space.
        fn take_attrs(&mut self) -> String {
            std::mem::take(&mut self.attrs)
                .into_iter()
                .fold(String::new(), |mut acc, a| {
                    acc.push_str(&a);
                    acc.push(' ');
                    acc
                })
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
                        let label = format!("{}{kw} {}", self.take_attrs(), name.text);
                        let inline_mod = (kw == "mod").then(|| name.text.clone());
                        if inline_mod.is_some() && is_punct(toks.get(i + 2), ";") {
                            self.mod_decl(toks[i].line, &name.text, &label);
                        }
                        self.pending = Some(Pending {
                            label,
                            depth,
                            any_open: false,
                            inline_mod,
                        });
                    }
                }
                "macro_rules" => {
                    if let (true, Some(name)) = (is_punct(next, "!"), is_name(toks.get(i + 2))) {
                        self.pending = Some(Pending {
                            label: format!("{}macro_rules! {}", self.take_attrs(), name.text),
                            depth,
                            any_open: true,
                            inline_mod: None,
                        });
                    }
                }
                "impl" => {
                    let header = self.impl_header(i)?;
                    self.pending = Some(Pending {
                        label: format!("{}{header}", self.take_attrs()),
                        depth,
                        any_open: false,
                        inline_mod: None,
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
                        let label = format!("{}{kw} {}", self.take_attrs(), name.text);
                        self.frames.push(Frame {
                            label,
                            depth,
                            statement: true,
                            inline_mod: None,
                        });
                    }
                }
                "use" if !self.statement_at(depth) => {
                    let label = format!("{}use", self.take_attrs());
                    self.frames.push(Frame {
                        label,
                        depth,
                        statement: true,
                        inline_mod: None,
                    });
                }
                _ => {}
            }
            Ok(())
        }

        fn mod_decl(&mut self, line: usize, name: &str, label: &str) {
            let path = self.path_attr.take();
            if self.doctest {
                return;
            }
            let site = self.site();
            let inline = self
                .frames
                .iter()
                .filter_map(|f| f.inline_mod.clone())
                .collect();
            self.out.decls.push(ModDecl {
                line,
                name: name.to_owned(),
                label: label.to_owned(),
                site,
                path,
                inline,
            });
        }

        fn include(&mut self, i: usize) {
            let toks = self.toks;
            if toks[i].text != INCLUDE_MACRO
                || !is_punct(toks.get(i + 1), "!")
                || !is_punct(toks.get(i + 2), "(")
                || self.doctest
            {
                return;
            }
            let line = toks[i].line;
            match (toks.get(i + 3), is_punct(toks.get(i + 4), ")")) {
                (Some(t), true) if t.kind == Kind::Str => {
                    let site = self.site();
                    self.out.includes.push(IncludeAt {
                        line,
                        target: t.text.clone(),
                        site,
                    });
                }
                _ => self.out.hits.push(Hit::Unclassified {
                    line,
                    what: format!("`{INCLUDE_MACRO}!` target is not a string literal"),
                }),
            }
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

        /// An outer attribute: a `cfg` is kept for the next item's label and
        /// a `path` value for the next `mod` declaration.
        fn attribute(&mut self, i: usize) -> Result<(), Stop> {
            let toks = self.toks;
            if !is_punct(toks.get(i + 1), "[") {
                return Ok(());
            }
            let Some(head) = is_name(toks.get(i + 2)) else {
                return Ok(());
            };
            match head.text.as_str() {
                "cfg" => {
                    let line = toks[i].line;
                    let mut label = String::from("#[");
                    let mut nest = 0usize;
                    for t in &toks[i + 2..] {
                        self.meter.tick()?;
                        let punct = t.kind == Kind::Punct;
                        if punct {
                            match t.text.as_str() {
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
                        match t.text.as_str() {
                            "," if punct => label.push_str(", "),
                            "=" if punct => label.push_str(" = "),
                            _ => label.push_str(&display(t)),
                        }
                        if label.len() > MAX_HEADER_CHARS {
                            return Err(bad(
                                line,
                                format!("cfg attribute longer than {MAX_HEADER_CHARS} characters"),
                            ));
                        }
                    }
                    label.push(']');
                    self.attrs.push(label);
                    self.attrs_depth = self.delims.len();
                }
                "path" => {
                    if let (true, Some(t), true) = (
                        is_punct(toks.get(i + 3), "="),
                        toks.get(i + 4).filter(|t| t.kind == Kind::Str),
                        is_punct(toks.get(i + 5), "]"),
                    ) {
                        self.path_attr = Some(t.text.clone());
                    }
                }
                _ => {}
            }
            Ok(())
        }

        /// The callee of a `(` at `i`: the name before it, `name!` for a macro.
        fn callee(&self, i: usize) -> Option<String> {
            let prev = self.toks.get(i.checked_sub(1)?)?;
            match prev.kind {
                Kind::Ident | Kind::RawIdent => Some(prev.text.clone()),
                Kind::Punct if prev.text == "!" => {
                    let name = is_name(self.toks.get(i.checked_sub(2)?))?;
                    Some(format!("{}!", name.text))
                }
                _ => None,
            }
        }

        /// The kind of use at this point: the call of the innermost `(`.
        fn op_here(&self) -> Op {
            let Some(callee) = self
                .delims
                .last()
                .filter(|d| d.open == '(')
                .and_then(|d| d.callee.as_deref())
            else {
                return Op::Use;
            };
            if WRITE_CALLS.contains(&callee) {
                Op::Write
            } else if CHILD_CALLS.contains(&callee) {
                Op::Child
            } else if READ_CALLS.contains(&callee) {
                Op::Read
            } else {
                Op::Use
            }
        }

        fn clear_attrs(&mut self) {
            self.attrs.clear();
            self.path_attr = None;
        }

        fn punct(&mut self, i: usize) -> Result<(), Stop> {
            let tok = &self.toks[i];
            let Some(c) = tok
                .text
                .chars()
                .next()
                .filter(|_| tok.text.chars().count() == 1)
            else {
                return Ok(());
            };
            match c {
                '#' => self.attribute(i)?,
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
                            inline_mod: p.inline_mod,
                        });
                    }
                    // A block of a cfg'd statement keeps the cfg in its site
                    // until the block closes.
                    let statement = (c == '{' && !activate)
                        .then(|| self.statement_label())
                        .flatten();
                    let frame = activate || statement.is_some();
                    if let Some(label) = statement {
                        self.frames.push(Frame {
                            label,
                            depth,
                            statement: false,
                            inline_mod: None,
                        });
                    }
                    if c == '{' {
                        self.clear_attrs();
                    }
                    let callee = if c == '(' { self.callee(i) } else { None };
                    self.delims.push(Delim {
                        open: c,
                        line: tok.line,
                        frame,
                        callee,
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
                    if c == '}' {
                        self.clear_attrs();
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
                    self.clear_attrs();
                }
                ',' if self.delims.len() == self.attrs_depth => self.clear_attrs(),
                _ => {}
            }
            Ok(())
        }

        /// One run of doc-comment lines: each fenced block is scanned as Rust,
        /// skipped for a listed non-Rust info, or a finding.
        fn doc_block(&mut self, run: &[Tok]) -> Result<(), Stop> {
            let mut k = 0;
            while k < run.len() {
                self.meter.tick()?;
                let open = run[k].text.trim_start();
                let Some((c, width)) = fence_of(open) else {
                    k += 1;
                    continue;
                };
                let info = open[width..].trim();
                let mut end = k + 1;
                while end < run.len() && !closes(run[end].text.trim_start(), c, width) {
                    self.meter.tick()?;
                    end += 1;
                }
                match fence_kind(info) {
                    Fence::Rust => self.doctest_code(&run[k + 1..end])?,
                    Fence::Skipped => {}
                    Fence::Unknown => self.out.hits.push(Hit::Unclassified {
                        line: run[k].line,
                        what: format!("doctest fence info `{info}` is not in DOCTEST_SKIPPED_INFO"),
                    }),
                }
                k = end + 1;
            }
            Ok(())
        }

        /// Lexes and walks the code lines of one Rust doctest, keeping the
        /// line numbers of the file.
        fn doctest_code(&mut self, body: &[Tok]) -> Result<(), Stop> {
            let Some(last) = body.last().map(|t| t.line) else {
                return Ok(());
            };
            let mut text = String::new();
            let mut lines = Vec::with_capacity(body.len());
            for t in body {
                text.push_str(hidden_stripped(&t.text));
                text.push('\n');
                lines.push(t.line);
            }
            let at = |l: usize| {
                l.checked_sub(1)
                    .and_then(|k| lines.get(k))
                    .copied()
                    .unwrap_or(last)
            };
            let lexed = Lexer {
                chars: text.chars().collect(),
                pos: 0,
                line: 1,
                meter: &mut *self.meter,
                toks: Vec::new(),
            }
            .run();
            let mut toks = match lexed {
                Ok(toks) => toks,
                Err(Stop::Bad { line, what }) => {
                    self.out.hits.push(Hit::Unclassified {
                        line: at(line),
                        what: format!("doctest: {what}"),
                    });
                    return Ok(());
                }
                Err(Stop::Steps) => return Err(Stop::Steps),
            };
            for t in &mut toks {
                t.line = at(t.line);
            }
            let prefix = format!("{}{DOCTEST_SCOPE}", self.site());
            match Walker::new(&toks, self.names, &mut *self.meter, prefix, true).walk() {
                Ok(walked) => self.out.hits.extend(walked.hits),
                Err(Stop::Bad { line, what }) => self.out.hits.push(Hit::Unclassified {
                    line,
                    what: format!("doctest: {what}"),
                }),
                Err(Stop::Steps) => return Err(Stop::Steps),
            }
            Ok(())
        }

        fn use_hit(&mut self, tok: &Tok, name: &str, string: bool) {
            let site = self.site();
            let op = self.op_here();
            self.out.hits.push(Hit::Use {
                line: tok.line,
                name: name.to_owned(),
                string,
                site,
                op,
            });
        }

        fn fragment_hit(&mut self, tok: &Tok, string: bool, text: String) {
            let site = self.site();
            self.out.hits.push(Hit::Fragment {
                line: tok.line,
                string,
                site,
                text,
            });
        }

        fn ident(&mut self, tok: &Tok) {
            let names = self.names;
            if let Some(name) = names.whole_idents().into_iter().find(|n| **n == tok.text) {
                self.use_hit(tok, name, false);
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

    fn classify(text: &str, ceiling: u64) -> Result<Walked, Stop> {
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
        Walker::new(&toks, &names, &mut meter, String::new(), false).walk()
    }

    /// The walk of one Rust source, or the one message that says why the
    /// file cannot be classified.
    fn scan_source(file: &str, bytes: &[u8], ceiling: u64) -> Result<Walked, String> {
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(format!(
                "#9730 guard: {file} is {} bytes, over the {MAX_SOURCE_BYTES} byte cap; the guard cannot classify it",
                bytes.len()
            ));
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(format!(
                "#9730 guard: {file} is not UTF-8; the guard cannot classify it"
            ));
        };
        match classify(text, ceiling) {
            Ok(walked) => Ok(walked),
            Err(Stop::Bad { line, what }) => Err(format!(
                "#9730 guard: {file}:{line}: {what}; the guard cannot classify this file"
            )),
            Err(Stop::Steps) => Err(format!(
                "#9730 guard: {file}: step ceiling {ceiling} exceeded; the guard cannot classify it"
            )),
        }
    }

    /// The findings of the hits of `file` when it is reached under `prefix`.
    /// An unclassified form is reported once, with the first prefix.
    fn evaluate(
        file: &str,
        prefix: &str,
        hits: &[Hit],
        tables: &Tables,
        used: &mut Used,
        first: bool,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for hit in hits {
            match hit {
                Hit::Use {
                    line,
                    name,
                    string,
                    site,
                    op,
                } => {
                    let site = join_site(prefix, site);
                    let rows: Vec<usize> = tables
                        .sites
                        .iter()
                        .enumerate()
                        .filter(|(_, (f, s, _))| f == file && *s == site)
                        .map(|(i, _)| i)
                        .collect();
                    let kind = if *string { "string" } else { "identifier" };
                    if let Some(row) = rows.iter().find(|r| tables.sites[**r].2 == *op) {
                        used.sites.insert(*row);
                    } else if rows.is_empty() {
                        out.push(format!(
                            "#9730 guard: {file}:{line}: `{name}` {kind} at `{site}` is outside the allowed sites"
                        ));
                    } else {
                        let ops: BTreeSet<Op> = rows.iter().map(|r| tables.sites[*r].2).collect();
                        let ops: Vec<&str> = ops.into_iter().map(Op::label).collect();
                        out.push(format!(
                            "#9730 guard: {file}:{line}: `{name}` {kind} at `{site}` is a {}; the allowed rows there are {}",
                            op.label(),
                            ops.join(", ")
                        ));
                    }
                }
                Hit::Fragment {
                    line,
                    string,
                    site,
                    text,
                } => {
                    let site = join_site(prefix, site);
                    let row = tables
                        .fragments
                        .iter()
                        .position(|(f, s, t)| f == file && *s == site && t == text);
                    if let Some(row) = row {
                        used.fragments.insert(row);
                    } else {
                        let what = if *string {
                            "a string literal"
                        } else {
                            "an identifier"
                        };
                        out.push(format!(
                            "#9730 guard: {file}:{line}: {what} holds a fragment of the key-dir variable name at `{site}`; the guard cannot classify it"
                        ));
                    }
                }
                Hit::Unclassified { line, what } => {
                    if first {
                        out.push(format!(
                            "#9730 guard: {file}:{line}: {what}; the guard cannot classify it"
                        ));
                    }
                }
            }
        }
        out
    }

    /// The findings of one Rust source file reached under `prefix` (empty for
    /// a crate root). `mod` and `include!` targets are resolved by `check_tree`.
    pub fn check_file_at(
        file: &str,
        prefix: &str,
        bytes: &[u8],
        tables: &Tables,
        ceiling: u64,
        used: &mut Used,
    ) -> Vec<String> {
        match scan_source(file, bytes, ceiling) {
            Ok(walked) => evaluate(file, prefix, &walked.hits, tables, used, true),
            Err(message) => vec![message],
        }
    }

    /// The findings of one Rust source file as a crate root.
    pub fn check_file(
        file: &str,
        bytes: &[u8],
        tables: &Tables,
        ceiling: u64,
        used: &mut Used,
    ) -> Vec<String> {
        check_file_at(file, "", bytes, tables, ceiling, used)
    }

    fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
        char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|c| unit(*c)))
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    fn utf8_or_latin1(bytes: &[u8]) -> String {
        std::str::from_utf8(bytes).map_or_else(
            |_| bytes.iter().map(|b| char::from(*b)).collect(),
            str::to_owned,
        )
    }

    /// The text of a non-Rust file: UTF-16 by its byte order mark or, with
    /// none, by where its NUL bytes are; otherwise UTF-8, else Latin-1.
    fn decode_text(bytes: &[u8]) -> String {
        if let Some(rest) = bytes.strip_prefix(UTF16LE_BOM) {
            return utf16(rest, u16::from_le_bytes);
        }
        if let Some(rest) = bytes.strip_prefix(UTF16BE_BOM) {
            return utf16(rest, u16::from_be_bytes);
        }
        if let Some(rest) = bytes.strip_prefix(UTF8_BOM) {
            return utf8_or_latin1(rest);
        }
        let pairs = bytes.len() / 2;
        let nul_at = |parity: usize| {
            bytes
                .iter()
                .skip(parity)
                .step_by(2)
                .filter(|b| **b == 0)
                .count()
        };
        let (even, odd) = (nul_at(0), nul_at(1));
        if pairs > 0 && odd * 2 >= pairs && even * 4 < pairs {
            utf16(bytes, u16::from_le_bytes)
        } else if pairs > 0 && even * 2 >= pairs && odd * 4 < pairs {
            utf16(bytes, u16::from_be_bytes)
        } else {
            utf8_or_latin1(bytes)
        }
    }

    /// The value of up to `max` digits of `radix` at the start of `b`, and
    /// how many digits it took.
    fn digits(b: &[u8], radix: u32, max: usize) -> (u32, usize) {
        let mut value = 0u32;
        let mut n = 0;
        while n < max {
            let Some(d) = b.get(n).and_then(|c| char::from(*c).to_digit(radix)) else {
                break;
            };
            value = value.saturating_mul(radix).saturating_add(d);
            n += 1;
        }
        (value, n)
    }

    /// The character an escape at the start of `b` stands for, and its length
    /// in bytes: `\xHH`, `\u{H}`, `\uHHHH`, `\UHHHHHHHH`, octal, `\\`,
    /// `&#N;`, `&#xH;` and `%HH`.
    fn escape_at(b: &[u8]) -> Option<(char, usize)> {
        let exact = |from: usize, radix: u32, width: usize| {
            let (v, n) = digits(b.get(from..)?, radix, width);
            (n == width).then_some((char::from_u32(v)?, from + width))
        };
        match (b.first()?, b.get(1)) {
            (b'\\', Some(b'x')) => exact(2, 16, 2),
            (b'\\', Some(b'u')) if b.get(2) == Some(&b'{') => {
                let (v, n) = digits(b.get(3..)?, 16, MAX_BRACED_HEX);
                (n > 0 && b.get(3 + n) == Some(&b'}')).then_some((char::from_u32(v)?, 4 + n))
            }
            (b'\\', Some(b'u')) => exact(2, 16, 4),
            (b'\\', Some(b'U')) => exact(2, 16, 8),
            (b'\\', Some(b'\\')) => Some(('\\', 2)),
            (b'\\', Some(c)) if (b'0'..=b'7').contains(c) => {
                let (v, n) = digits(&b[1..], 8, MAX_OCTAL_DIGITS);
                Some((char::from_u32(v)?, 1 + n))
            }
            (b'&', Some(b'#')) => {
                let (radix, from) = match b.get(2) {
                    Some(b'x' | b'X') => (16, 3),
                    _ => (10, 2),
                };
                let (v, n) = digits(b.get(from..)?, radix, MAX_ENTITY_DIGITS);
                (n > 0 && b.get(from + n) == Some(&b';'))
                    .then_some((char::from_u32(v)?, from + n + 1))
            }
            (b'%', _) => exact(1, 16, 2),
            _ => None,
        }
    }

    /// `text` with every escape replaced by the character it stands for, once.
    fn unescape(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut k = 0;
        while let Some(rest) = text.get(k..).filter(|r| !r.is_empty()) {
            if let Some((ch, len)) = escape_at(rest.as_bytes()) {
                out.push(ch);
                k += len;
            } else if let Some(ch) = rest.chars().next() {
                out.push(ch);
                k += ch.len_utf8();
            }
        }
        out
    }

    /// The mentions of the three key-dir names in a non-Rust file, after
    /// decoding, counted left to right without overlap.
    pub fn mention_count(bytes: &[u8]) -> usize {
        let text = unescape(&decode_text(bytes));
        let names = [var_token(), const_token(), call_token()];
        let b = text.as_bytes();
        let mut count = 0;
        let mut k = 0;
        while k < b.len() {
            if let Some(name) = names.iter().find(|n| b[k..].starts_with(n.as_bytes())) {
                count += 1;
                k += name.len();
            } else {
                k += 1;
            }
        }
        count
    }

    /// The findings of one tracked file that is not compiled as Rust: its
    /// mention count must equal its `NON_RUST` row.
    pub fn check_other(file: &str, bytes: &[u8], tables: &Tables, used: &mut Used) -> Vec<String> {
        let count = mention_count(bytes);
        match tables.non_rust.iter().position(|(p, _)| p == file) {
            Some(row) => {
                used.non_rust.insert(row);
                let pinned = tables.non_rust[row].1;
                if count == pinned {
                    Vec::new()
                } else {
                    vec![format!(
                        "#9730 guard: {file} holds {count} key-dir name mention(s); its NON_RUST row says {pinned}"
                    )]
                }
            }
            None if count == 0 => Vec::new(),
            None => vec![format!(
                "#9730 guard: {file} holds {count} key-dir name mention(s) and has no NON_RUST row"
            )],
        }
    }

    /// One message per table row that no file matched.
    pub fn unused_rows(tables: &Tables, used: &Used) -> Vec<String> {
        let mut out = Vec::new();
        for (i, (file, site, op)) in tables.sites.iter().enumerate() {
            if !used.sites.contains(&i) {
                out.push(format!(
                    "#9730 guard: allowed site {file} `{site}` ({}) matches nothing; remove the row",
                    op.label()
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
        for (i, (path, _)) in tables.non_rust.iter().enumerate() {
            if !used.non_rust.contains(&i) {
                out.push(format!(
                    "#9730 guard: non-Rust row {path} matches no tracked non-Rust file; remove the row"
                ));
            }
        }
        out
    }

    /// True for a file the Python test judges (`PY_JUDGED_SUFFIX`,
    /// `PY_JUDGED_PREFIXES`); the tree scan leaves it out and reads nothing of it.
    pub(super) fn is_python_judged(name: &str) -> bool {
        name.ends_with(PY_JUDGED_SUFFIX)
            || PY_JUDGED_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
    }

    fn is_rust(name: &str) -> bool {
        // Any case of the extension is lexed as Rust.
        Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    }

    /// `rel` under the directory `dir`, with `.` and `..` resolved; `None`
    /// when it leaves the tree or is absolute.
    fn normalize(dir: &str, rel: &str) -> Option<String> {
        if rel.starts_with('/') {
            return None;
        }
        let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
        for part in rel.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                p => parts.push(p),
            }
        }
        Some(parts.join("/"))
    }

    fn parent_dir(file: &str) -> &str {
        file.rsplit_once('/').map_or("", |(d, _)| d)
    }

    /// The tracked files a `mod` declaration of `file` may name, in the
    /// order rustc tries them. `mod_rs` is true when `file` owns its
    /// directory (a crate root, `mod.rs`, or a file loaded by `#[path]`).
    fn decl_targets(file: &str, mod_rs: bool, decl: &ModDecl) -> Vec<String> {
        let dir = parent_dir(file);
        let mut base = if mod_rs {
            dir.to_owned()
        } else {
            let stem = Path::new(file)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            format!("{dir}/{stem}")
        };
        for inline in &decl.inline {
            base = format!("{base}/{inline}");
        }
        let rels = match &decl.path {
            Some(p) if decl.inline.is_empty() => return normalize(dir, p).into_iter().collect(),
            Some(p) => vec![p.clone()],
            None => vec![format!("{}.rs", decl.name), format!("{}/mod.rs", decl.name)],
        };
        rels.iter().filter_map(|r| normalize(&base, r)).collect()
    }

    fn owns_dir(file: &str) -> bool {
        Path::new(file)
            .file_name()
            .is_some_and(|n| MOD_RS_NAMES.iter().any(|m| n == *m))
    }

    /// Reads one tracked file, refusing anything but a regular file.
    fn read_tracked(root: &Path, name: &str) -> Result<Vec<u8>, String> {
        let path = root.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                return Err(format!(
                    "#9730 guard: {name} is not a regular file; the guard cannot classify it"
                ));
            }
            Err(e) => return Err(format!("#9730 guard: {name} cannot be read: {e}")),
        }
        std::fs::read(&path).map_err(|e| format!("#9730 guard: {name} cannot be read: {e}"))
    }

    /// One place a file is reached from: its prefix, whether it owns its
    /// directory, and the files on the way to it.
    struct Visit {
        file: String,
        prefix: String,
        mod_rs: bool,
        chain: Vec<String>,
    }

    /// The state of one tree walk.
    struct TreeWalk<'r> {
        root: &'r Path,
        tracked: BTreeSet<String>,
        scanned: BTreeMap<String, Walked>,
        failed: BTreeSet<String>,
        prefixes: BTreeMap<String, BTreeSet<String>>,
        over: BTreeMap<String, BTreeSet<String>>,
        out: Vec<String>,
        reported: BTreeSet<String>,
    }

    impl TreeWalk<'_> {
        fn report(&mut self, message: String) {
            if self.reported.insert(message.clone()) {
                self.out.push(message);
            }
        }

        /// Lexes `file` once; a non-Rust file reached as a module is lexed too.
        fn scan(&mut self, file: &str) -> bool {
            if self.scanned.contains_key(file) {
                return true;
            }
            if self.failed.contains(file) {
                return false;
            }
            let walked = read_tracked(self.root, file)
                .and_then(|bytes| scan_source(file, &bytes, step_ceiling(bytes.len())));
            match walked {
                Ok(w) => {
                    self.scanned.insert(file.to_owned(), w);
                    true
                }
                Err(message) => {
                    self.failed.insert(file.to_owned());
                    self.out.push(message);
                    false
                }
            }
        }

        /// The tracked `.rs` files no declaration or include could name.
        fn roots(&self) -> Vec<String> {
            let mut named = BTreeSet::new();
            for (file, walked) in &self.scanned {
                for decl in &walked.decls {
                    for mod_rs in [true, false] {
                        named.extend(decl_targets(file, mod_rs, decl));
                    }
                }
                for inc in &walked.includes {
                    named.extend(normalize(parent_dir(file), &inc.target));
                }
            }
            self.scanned
                .keys()
                .filter(|f| !named.contains(*f))
                .cloned()
                .collect()
        }

        fn visit_from(&mut self, start: String) {
            let mut queue = VecDeque::from([Visit {
                chain: vec![start.clone()],
                file: start,
                prefix: String::new(),
                mod_rs: true,
            }]);
            while let Some(v) = queue.pop_front() {
                let seen = self.prefixes.entry(v.file.clone()).or_default();
                if seen.contains(&v.prefix) {
                    continue;
                }
                if seen.len() >= MAX_PREFIXES_PER_FILE {
                    self.over.entry(v.file).or_default().insert(v.prefix);
                    continue;
                }
                seen.insert(v.prefix.clone());
                if !self.scan(&v.file) {
                    continue;
                }
                let (decls, includes) = match self.scanned.get(&v.file) {
                    Some(w) => (w.decls.clone(), w.includes.clone()),
                    None => continue,
                };
                for decl in decls {
                    let targets = decl_targets(&v.file, v.mod_rs, &decl);
                    let Some(target) = targets.into_iter().find(|t| self.tracked.contains(t))
                    else {
                        self.report(format!(
                            "#9730 guard: {}:{}: `mod {}` resolves to no tracked file; the guard cannot classify it",
                            v.file, decl.line, decl.name
                        ));
                        continue;
                    };
                    let prefix = join_site(&scope(&v.prefix, &decl.site), &decl.label);
                    let mod_rs = decl.path.is_some() || owns_dir(&target);
                    self.follow(&mut queue, &v, target, prefix, mod_rs, decl.line);
                }
                for inc in includes {
                    let target = normalize(parent_dir(&v.file), &inc.target)
                        .filter(|t| self.tracked.contains(t));
                    let Some(target) = target else {
                        self.report(format!(
                            "#9730 guard: {}:{}: `{INCLUDE_MACRO}!` target `{}` is not a tracked file; the guard cannot classify it",
                            v.file, inc.line, inc.target
                        ));
                        continue;
                    };
                    let prefix = scope(&v.prefix, &inc.site);
                    self.follow(&mut queue, &v, target, prefix, true, inc.line);
                }
            }
        }

        fn follow(
            &mut self,
            queue: &mut VecDeque<Visit>,
            from: &Visit,
            target: String,
            prefix: String,
            mod_rs: bool,
            line: usize,
        ) {
            if from.chain.contains(&target) {
                self.report(format!(
                    "#9730 guard: {}:{line}: {target} is already on its own module path; the guard cannot classify it",
                    from.file
                ));
                return;
            }
            let mut chain = from.chain.clone();
            chain.push(target.clone());
            queue.push_back(Visit {
                file: target,
                prefix,
                mod_rs,
                chain,
            });
        }
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
        let mut walk = TreeWalk {
            root,
            tracked: BTreeSet::new(),
            scanned: BTreeMap::new(),
            failed: BTreeSet::new(),
            prefixes: BTreeMap::new(),
            over: BTreeMap::new(),
            out: Vec::new(),
            reported: BTreeSet::new(),
        };
        for raw in listing.split(|b| *b == 0).filter(|n| !n.is_empty()) {
            match std::str::from_utf8(raw) {
                Ok(name) => {
                    walk.tracked.insert(name.to_owned());
                }
                Err(_) => walk.out.push(format!(
                    "#9730 guard: {} is not UTF-8; the guard cannot classify it",
                    String::from_utf8_lossy(raw)
                )),
            }
        }
        let rust: Vec<String> = walk
            .tracked
            .iter()
            .filter(|n| is_rust(n))
            .cloned()
            .collect();
        for name in &rust {
            walk.scan(name);
        }
        for start in walk.roots() {
            walk.visit_from(start);
        }
        let unreached: Vec<String> = walk
            .scanned
            .keys()
            .filter(|f| !walk.prefixes.contains_key(*f))
            .cloned()
            .collect();
        for start in unreached {
            walk.visit_from(start);
        }
        let mut used = Used::default();
        for (file, extra) in &walk.over {
            let n = walk.prefixes.get(file).map_or(0, BTreeSet::len) + extra.len();
            walk.out.push(format!(
                "#9730 guard: {file} is reached as a module from {n} places; the guard cannot classify it"
            ));
        }
        for (file, walked) in &walk.scanned {
            let Some(prefixes) = walk.prefixes.get(file) else {
                continue;
            };
            for (k, prefix) in prefixes.iter().enumerate() {
                walk.out.extend(evaluate(
                    file,
                    prefix,
                    &walked.hits,
                    tables,
                    &mut used,
                    k == 0,
                ));
            }
        }
        let others: Vec<String> = walk
            .tracked
            .iter()
            .filter(|n| {
                !is_rust(n)
                    && !is_python_judged(n)
                    && !walk.scanned.contains_key(*n)
                    && !walk.failed.contains(*n)
            })
            .cloned()
            .collect();
        for name in others {
            match read_tracked(root, &name) {
                Ok(bytes) => walk
                    .out
                    .extend(check_other(&name, &bytes, tables, &mut used)),
                Err(message) => walk.out.push(message),
            }
        }
        if rust.is_empty() {
            walk.out.push(
                "#9730 guard: git ls-files listed no .rs file; the guard cannot run".to_owned(),
            );
        }
        walk.out.extend(unused_rows(tables, &used));
        walk.out
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

/// The module path `src/cli/store.rs` is reached under from the crate root.
const STORE_PREFIX: &str = "mod cli::mod store";

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
    let before = scan::check_file_at(
        file,
        STORE_PREFIX,
        text.as_bytes(),
        &tables,
        scan::step_ceiling(text.len()),
        &mut Used::default(),
    );
    assert!(before.is_empty(), "{}", report(&before));
    let got = scan::check_file_at(
        file,
        STORE_PREFIX,
        mutated.as_bytes(),
        &tables,
        scan::step_ceiling(mutated.len()),
        &mut Used::default(),
    );
    let line = to + 1;
    assert_eq!(
        got,
        vec![expand(&format!(
            "#9730 guard: {file}:{line}: `@B@` identifier at `{STORE_PREFIX}::#[cfg(test)] mod tests::fn read_back_persisted_errors_when_row_is_missing_3025` is outside the allowed sites"
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
        sites: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned(), Op::Read)],
        fragments: vec![(SYN_FILE.to_owned(), "fn nowhere".to_owned(), prefix_token())],
        non_rust: vec![("docs/gone.md".to_owned(), 1)],
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
                "#9730 guard: allowed site {SYN_FILE} `fn nowhere` (read) matches nothing; remove the row"
            ),
            format!(
                "#9730 guard: allowed fragment {SYN_FILE} `fn nowhere` matches nothing; remove the row"
            ),
            "#9730 guard: non-Rust row docs/gone.md matches no tracked non-Rust file; remove the row"
                .to_owned(),
        ]
    );
}

#[test]
fn non_rust_files_need_a_row_by_path_9730() {
    let text = expand("set @V@ before the run, then unset @V@\n");
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
            "#9730 guard: docs/notes.md holds 2 key-dir name mention(s) and has no NON_RUST row"
                .to_owned()
        ]
    );
    let pinned = Tables {
        non_rust: vec![("docs/notes.md".to_owned(), 2)],
        ..Tables::default()
    };
    let mut used = Used::default();
    let got = scan::check_other("docs/notes.md", text.as_bytes(), &pinned, &mut used);
    assert!(got.is_empty(), "{}", report(&got));
    assert_eq!(scan::unused_rows(&pinned, &used), Vec::<String>::new());
    let other = scan::check_other(
        "docs/other.md",
        text.as_bytes(),
        &pinned,
        &mut Used::default(),
    );
    assert_eq!(
        other,
        vec![
            "#9730 guard: docs/other.md holds 2 key-dir name mention(s) and has no NON_RUST row"
                .to_owned()
        ]
    );
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
    for r in NON_RUST {
        if r.reason.trim().is_empty() || r.mentions == 0 {
            missing.push(r.path.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "rows without a reason: {}",
        report(&missing)
    );
}

/// Wall-clock ceiling for one scan of the whole tracked tree.
const TREE_WALL_CLOCK_CEILING: Duration = Duration::from_secs(300);
/// Rows of `ALLOWED_SITES`; a new row changes this pin in the same commit.
const ALLOWED_SITES_COUNT: usize = 205;
/// Rows of `ALLOWED_FRAGMENTS`.
const ALLOWED_FRAGMENTS_COUNT: usize = 17;
/// Rows of `NON_RUST`.
const NON_RUST_COUNT: usize = 30;
/// Rows of `known_green_rows`, the forms tracked at `KNOWN_GREEN_TRACKER`.
const KNOWN_GREEN_COUNT: usize = 10;
/// Entries of `DOCTEST_SKIPPED_INFO`.
const DOCTEST_SKIPPED_INFO_COUNT: usize = 13;

#[test]
fn tracked_tree_holds_no_key_dir_route_outside_the_allowed_sites_9730() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let start = Instant::now();
    let got = scan::check_tree(root, &tree_tables());
    let took = start.elapsed();
    assert!(got.is_empty(), "{}", report(&got));
    assert!(
        took <= TREE_WALL_CLOCK_CEILING,
        "tree scan took {took:?}, over the {TREE_WALL_CLOCK_CEILING:?} ceiling"
    );
}

#[test]
fn table_sizes_are_pinned_9730() {
    assert_eq!(
        [
            ALLOWED_SITES.len(),
            ALLOWED_FRAGMENTS.len(),
            NON_RUST.len(),
            known_green_rows().len(),
            DOCTEST_SKIPPED_INFO.len(),
        ],
        [
            ALLOWED_SITES_COUNT,
            ALLOWED_FRAGMENTS_COUNT,
            NON_RUST_COUNT,
            KNOWN_GREEN_COUNT,
            DOCTEST_SKIPPED_INFO_COUNT,
        ]
    );
}

/// The scratch root of the fixture trees the class rows build.
const FIXTURE_DIR: &str = "key_dir_bind_guard_9730";
/// The tracker of the forms the text scan cannot see.
const KNOWN_GREEN_TRACKER: u32 = 9786;

/// One tracked fixture tree and the exact findings the guard must report on it.
struct TreeCase {
    name: &'static str,
    files: Vec<(&'static str, Vec<u8>)>,
    sites: Vec<(&'static str, &'static str, Op)>,
    non_rust: Vec<(&'static str, usize)>,
    expected: Vec<String>,
}

fn tree_case(
    name: &'static str,
    files: &[(&'static str, &str)],
    sites: &[(&'static str, &'static str, Op)],
    non_rust: &[(&'static str, usize)],
    expected: &[&str],
) -> TreeCase {
    TreeCase {
        name,
        files: files
            .iter()
            .map(|(p, t)| (*p, expand(t).into_bytes()))
            .collect(),
        sites: sites.to_vec(),
        non_rust: non_rust.to_vec(),
        expected: expected.iter().map(|e| expand(e)).collect(),
    }
}

/// Writes `files` under a fresh directory and tracks them in a new git repository.
fn fixture_tree(name: &str, files: &[(&str, Vec<u8>)]) -> std::path::PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(FIXTURE_DIR)
        .join(name);
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove the old fixture tree");
    }
    for (rel, bytes) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a fixture path has a parent"))
            .expect("create the fixture directory");
        std::fs::write(&path, bytes).expect("write the fixture file");
    }
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed: {status}");
    };
    git(&["init", "-q"]);
    let mut add = vec!["add", "--"];
    add.extend(files.iter().map(|(rel, _)| *rel));
    git(&add);
    root
}

fn fixture_tables(sites: &[(&str, &str, Op)], non_rust: &[(&str, usize)]) -> Tables {
    Tables {
        sites: sites
            .iter()
            .map(|(f, s, op)| ((*f).to_owned(), expand(s), *op))
            .collect(),
        fragments: Vec::new(),
        non_rust: non_rust
            .iter()
            .map(|(p, n)| ((*p).to_owned(), *n))
            .collect(),
    }
}

fn run_tree_cases(cases: &[TreeCase]) -> Vec<String> {
    let mut failures = Vec::new();
    for c in cases {
        let root = fixture_tree(c.name, &c.files);
        let mut got = scan::check_tree(&root, &fixture_tables(&c.sites, &c.non_rust));
        got.sort();
        let mut expected = c.expected.clone();
        expected.sort();
        if got != expected {
            failures.push(format!("{}: expected {expected:?}, got {got:?}", c.name));
        }
    }
    failures
}

/// `name` with its first letter written in each escape form a config file decodes.
fn escaped_forms(name: &str) -> Vec<String> {
    let first = name.chars().next().expect("a name has a first letter");
    let rest = &name[first.len_utf8()..];
    let code = u32::from(first);
    vec![
        format!("a = \"\\x{code:02X}{rest}\""),
        format!("b = \"\\u{{{code:x}}}{rest}\""),
        format!("c = &#{code};{rest}"),
        format!("d = %{code:02X}{rest}"),
    ]
}

fn utf16le(text: &str, bom: bool) -> Vec<u8> {
    let mut out = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Class A: every tracked non-Rust file is pinned by its own path and its
/// mention count, after decoding; a file compiled as Rust is scanned as Rust.
fn non_rust_rows() -> Vec<TreeCase> {
    let lib = ("src/lib.rs", "");
    let mut rows = vec![
        tree_case(
            "a1-new-file-of-a-listed-kind",
            &[
                lib,
                ("cfg/old.cfg", "set @V@\n"),
                ("cfg/new.cfg", "uses @V@ here\n"),
            ],
            &[],
            &[("cfg/old.cfg", 1)],
            &["#9730 guard: cfg/new.cfg holds 1 key-dir name mention(s) and has no NON_RUST row"],
        ),
        tree_case(
            "a1b-new-mention-in-a-listed-file",
            &[lib, ("cfg/old.cfg", "set @V@\nand @C@ too\n")],
            &[],
            &[("cfg/old.cfg", 1)],
            &["#9730 guard: cfg/old.cfg holds 2 key-dir name mention(s); its NON_RUST row says 1"],
        ),
        tree_case(
            "a1c-stale-non-rust-row",
            &[lib, ("cfg/old.cfg", "set @V@\n")],
            &[],
            &[("cfg/old.cfg", 1), ("cfg/gone.cfg", 1)],
            &[
                "#9730 guard: non-Rust row cfg/gone.cfg matches no tracked non-Rust file; remove the row",
            ],
        ),
        tree_case(
            "a1d-skip-set-files-are-judged-in-python-not-read-here",
            &[
                lib,
                ("docs/notes.md", "set @V@\n"),
                ("CHANGELOG.md", "set @V@\n"),
                ("changelog.d/1.fixed.md", "set @V@\n"),
                ("sdk/python/README.md", "set @V@\n"),
                ("scripts/ci/tests/data/pins.json", "set @V@\n"),
                ("scripts/ci/tests/test_x.py", "set @V@\n"),
                ("docs/a2a.html", "set @V@\n"),
            ],
            &[],
            &[],
            &[],
        ),
        tree_case(
            "a1e-near-misses-of-the-skip-set-are-judged-here",
            &[
                lib,
                ("notes.MD", "set @V@\n"),
                ("doc/notes.txt", "set @V@\n"),
                ("scripts/ci/other.py", "set @V@\n"),
                ("xdocs/notes.txt", "set @V@\n"),
            ],
            &[],
            &[],
            &[
                "#9730 guard: doc/notes.txt holds 1 key-dir name mention(s) and has no NON_RUST row",
                "#9730 guard: notes.MD holds 1 key-dir name mention(s) and has no NON_RUST row",
                "#9730 guard: scripts/ci/other.py holds 1 key-dir name mention(s) and has no NON_RUST row",
                "#9730 guard: xdocs/notes.txt holds 1 key-dir name mention(s) and has no NON_RUST row",
            ],
        ),
        tree_case(
            "a4-include-of-a-txt-file",
            &[
                (
                    "src/lib.rs",
                    "fn main() {\n    include!(\"body.txt\");\n}\n",
                ),
                ("src/body.txt", "let _ = std::env::var(\"@V@\");\n"),
            ],
            &[],
            &[],
            &[
                "#9730 guard: src/body.txt:1: `@V@` string at `fn main` is outside the allowed sites",
            ],
        ),
        tree_case(
            "a4b-path-attr-to-an-md-file",
            &[
                ("src/lib.rs", "#[path = \"m.md\"]\nmod m;\n"),
                ("src/m.md", "fn f() { let _ = std::env::var(\"@V@\"); }\n"),
            ],
            &[],
            &[],
            &[
                "#9730 guard: src/m.md:1: `@V@` string at `mod m::fn f` is outside the allowed sites",
            ],
        ),
        tree_case(
            "a5-include-of-a-missing-file",
            &[("src/lib.rs", "include!(\"gone.txt\");\n")],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:1: `include!` target `gone.txt` is not a tracked file; the guard cannot classify it",
            ],
        ),
        tree_case(
            "a5b-include-of-a-computed-path",
            &[("src/lib.rs", "include!(concat!(\"bo\", \"dy.rs\"));\n")],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:1: `include!` target is not a string literal; the guard cannot classify it",
            ],
        ),
        tree_case(
            "a6-mod-with-no-file",
            &[("src/lib.rs", "mod gone;\n")],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:1: `mod gone` resolves to no tracked file; the guard cannot classify it",
            ],
        ),
    ];
    for (name, bom) in [
        ("a2-utf16-toml-with-a-bom", true),
        ("a2b-utf16-toml-without-a-bom", false),
    ] {
        let mut case = tree_case(
            name,
            &[lib],
            &[],
            &[],
            &["#9730 guard: cfg/a.toml holds 1 key-dir name mention(s) and has no NON_RUST row"],
        );
        case.files
            .push(("cfg/a.toml", utf16le(&expand("dir = \"@V@\"\n"), bom)));
        rows.push(case);
    }
    let mut escaped = tree_case(
        "a3-escaped-names-in-a-config-file",
        &[lib],
        &[],
        &[],
        &["#9730 guard: cfg/a.cfg holds 4 key-dir name mention(s) and has no NON_RUST row"],
    );
    escaped.files.push((
        "cfg/a.cfg",
        (escaped_forms(&var_token()).join("\n") + "\n").into_bytes(),
    ));
    rows.push(escaped);
    rows
}

/// Class B: an allowance names one item path (with its cfg) and one kind of use.
fn site_rows() -> Vec<TreeCase> {
    vec![
        tree_case(
            "b1-write-in-an-allowed-reader",
            &[(
                "src/lib.rs",
                "fn reader() {\n    let _ = std::env::var(\"@V@\");\n    unsafe { std::env::set_var(\"@V@\", \"x\") };\n}\n",
            )],
            &[("src/lib.rs", "fn reader", Op::Read)],
            &[],
            &[
                "#9730 guard: src/lib.rs:3: `@V@` string at `fn reader` is a write; the allowed rows there are read",
            ],
        ),
        tree_case(
            "b2-cfg-not-test-twin",
            &[(
                "src/lib.rs",
                "#[cfg(test)]\nmod tests {\n    fn t() { let _ = std::env::var(\"@V@\"); }\n}\n\n#[cfg(not(test))]\nmod tests {\n    fn t() { let _ = std::env::var(\"@V@\"); }\n}\n",
            )],
            &[("src/lib.rs", "#[cfg(test)] mod tests::fn t", Op::Read)],
            &[],
            &[
                "#9730 guard: src/lib.rs:8: `@V@` string at `#[cfg(not(test))] mod tests::fn t` is outside the allowed sites",
            ],
        ),
        tree_case(
            "b3-new-product-caller-of-the-sandbox",
            &[(
                "src/lib.rs",
                "fn main() {\n    crate::identity::@T@::install();\n}\n",
            )],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:2: `@T@` identifier at `fn main` is outside the allowed sites",
            ],
        ),
        tree_case(
            "b4-cfg-on-a-mod-declaration",
            &[
                ("src/lib.rs", "#[cfg(not(test))]\nmod child;\n"),
                (
                    "src/child.rs",
                    "fn f() { let _ = std::env::var(\"@V@\"); }\n",
                ),
            ],
            &[("src/child.rs", "#[cfg(test)] mod child::fn f", Op::Read)],
            &[],
            &[
                "#9730 guard: src/child.rs:1: `@V@` string at `#[cfg(not(test))] mod child::fn f` is outside the allowed sites",
                "#9730 guard: allowed site src/child.rs `#[cfg(test)] mod child::fn f` (read) matches nothing; remove the row",
            ],
        ),
        tree_case(
            "b5-uncfgd-caller-beside-an-allowed-cfgd-statement",
            &[(
                "src/lib.rs",
                "fn resolve() {\n    #[cfg(test)]\n    crate::@T@::assert_isolated();\n    crate::@T@::install();\n}\n",
            )],
            &[("src/lib.rs", "fn resolve::#[cfg(test)] stmt", Op::Use)],
            &[],
            &[
                "#9730 guard: src/lib.rs:4: `@T@` identifier at `fn resolve` is outside the allowed sites",
            ],
        ),
        tree_case(
            "b6-cfg-not-test-statement-twin",
            &[(
                "src/lib.rs",
                "fn resolve() {\n    #[cfg(test)]\n    if let Some(s) = crate::@T@::@A@() {\n        crate::@T@::install();\n    }\n    #[cfg(not(test))]\n    if let Some(s) = crate::@T@::@A@() {\n        crate::@T@::install();\n    }\n    let _ = (1, 2);\n}\n",
            )],
            &[("src/lib.rs", "fn resolve::#[cfg(test)] stmt", Op::Use)],
            &[],
            &[
                "#9730 guard: src/lib.rs:7: `@T@` identifier at `fn resolve::#[cfg(not(test))] stmt` is outside the allowed sites",
                "#9730 guard: src/lib.rs:7: `@A@` identifier at `fn resolve::#[cfg(not(test))] stmt` is outside the allowed sites",
                "#9730 guard: src/lib.rs:8: `@T@` identifier at `fn resolve::#[cfg(not(test))] stmt` is outside the allowed sites",
            ],
        ),
        tree_case(
            "b7-cfg-ends-with-its-statement-field-or-block",
            &[(
                "src/lib.rs",
                "struct S {\n    #[cfg(test)]\n    a: u8,\n    b: crate::@T@::Kind,\n}\nfn f() {\n    #[cfg(test)]\n    {\n        crate::@T@::install();\n    }\n    crate::@T@::install();\n}\n",
            )],
            &[
                ("src/lib.rs", "struct S", Op::Use),
                ("src/lib.rs", "fn f::#[cfg(test)] stmt", Op::Use),
            ],
            &[],
            &[
                "#9730 guard: src/lib.rs:11: `@T@` identifier at `fn f` is outside the allowed sites",
            ],
        ),
    ]
}

/// Class C: a direct spelling inside a doc-comment code block is scanned.
fn doctest_rows() -> Vec<TreeCase> {
    vec![
        tree_case(
            "c1-direct-spelling-in-a-doctest",
            &[(
                "src/lib.rs",
                "/// ```\n/// unsafe { std::env::set_var(\"@V@\", \"x\") };\n/// ```\nfn documented() {}\n",
            )],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:2: `@V@` string at `<file root>::doctest` is outside the allowed sites",
            ],
        ),
        tree_case(
            "c2-unlisted-fence-info",
            &[("src/lib.rs", "//! ```python\n//! print(1)\n//! ```\n")],
            &[],
            &[],
            &[
                "#9730 guard: src/lib.rs:1: doctest fence info `python` is not in DOCTEST_SKIPPED_INFO; the guard cannot classify it",
            ],
        ),
    ]
}

#[test]
fn non_rust_files_are_pinned_by_path_9730() {
    let failures = run_tree_cases(&non_rust_rows());
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn sites_are_pinned_by_cfg_and_op_9730() {
    let failures = run_tree_cases(&site_rows());
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn doctests_are_scanned_9730() {
    let failures = run_tree_cases(&doctest_rows());
    assert!(failures.is_empty(), "{}", report(&failures));
}

/// Forms a text scan cannot see (computed names). Each row asserts the form
/// is NOT detected today; the day one is detected this test goes red and the
/// row moves to the deny rows. Tracked at issue `KNOWN_GREEN_TRACKER`.
fn known_green_rows() -> Vec<(&'static str, String)> {
    let v = var_token();
    let witness = ["WITNESS", "KEY", "DIR", "ENV"].join("_");
    let chars: Vec<String> = v.chars().map(|c| format!("'{c}'")).collect();
    let bytes: Vec<String> = v.bytes().map(|b| b.to_string()).collect();
    let read = |arg: &str| format!("fn f() {{ let _ = std::env::var({arg}); }}");
    vec![
        (
            "concat-3",
            read(&format!(
                "concat!(\"{}\", \"{}\", \"{}\")",
                &v[..5],
                &v[5..13],
                &v[13..]
            )),
        ),
        (
            "concat-security",
            read(&format!(
                "concat!(\"{}\", \"{}\", \"{}\")",
                &v[..9],
                &v[9..13],
                &v[13..]
            )),
        ),
        (
            "join-4",
            read("[\"AI\", \"MEMORY\", \"KEY\", \"DIR\"].join(\"_\")"),
        ),
        (
            "format-3",
            read(&format!(
                "format!(\"{{}}_{{}}_{{}}\", \"{}\", \"{}\", \"{}\")",
                &v[..9],
                &v[10..13],
                &v[14..]
            )),
        ),
        (
            "chars",
            read(&format!("[{}].iter().collect::<String>()", chars.join(", "))),
        ),
        (
            "bytes",
            read(&format!(
                "String::from_utf8(vec![{}]).unwrap_or_default()",
                bytes.join(", ")
            )),
        ),
        (
            "witness-replace",
            read(&format!("crate::w::{witness}.replace(\"WITNESS_\", \"\")")),
        ),
        (
            "prose-split",
            read(&format!(
                "\"{v} is the name\".split(' ').next().unwrap_or_default()"
            )),
        ),
        (
            "suffix-scan",
            format!(
                "fn f() {{ let _ = std::env::vars().find(|(k, _)| k.ends_with(\"{}\") && k.contains(\"{}\")); }}",
                &v[13..],
                &v[3..13]
            ),
        ),
        (
            "doctest-computed-name",
            "/// ```\n/// unsafe { std::env::set_var([\"AI\", \"MEMORY\", \"KEY\", \"DIR\"].join(\"_\"), \"x\") };\n/// ```\nfn f() {}\n".to_owned(),
        ),
    ]
}

#[test]
fn known_green_forms_stay_undetected_9786() {
    let mut detected = Vec::new();
    for (name, source) in known_green_rows() {
        let got = run_case(&Case {
            name,
            source: source.into_bytes(),
            expected: Vec::new(),
        });
        if !got.is_empty() {
            detected.push(format!(
                "{name} (#{KNOWN_GREEN_TRACKER}) is detected now; move it to the deny rows: {got:?}"
            ));
        }
    }
    assert!(detected.is_empty(), "{}", report(&detected));
}
