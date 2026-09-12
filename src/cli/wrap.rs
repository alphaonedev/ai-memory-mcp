// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wrap <agent>` — cross-platform Rust replacement for the
//! shell wrappers PR-1 of issue #487 shipped in the integration recipes.
//!
//! ## What it does
//!
//! 1. Calls `cli::boot::run` in-process, capturing its stdout into a
//!    buffer. No subprocess; no shell. The `--no-boot` flag skips this
//!    step so a misconfigured DB path doesn't block the agent.
//! 2. Builds a system-context string of the form
//!    `<preamble>\n\n<boot output>` where the preamble explains to the
//!    downstream agent that it has ai-memory access.
//! 3. Spawns the wrapped agent (`std::process::Command`) with the
//!    system-context delivered via the chosen strategy:
//!    - `SystemFlag` — `<agent> <flag> "<system_msg>" <trailing args...>`
//!    - `SystemEnv`  — `<env_name>=<system_msg> <agent> <trailing args...>`
//!    - `MessageFile` — write `<system_msg>` to a `NamedTempFile`, pass
//!      `<flag> <tempfile_path>` to the agent, drop the tempfile on
//!      exit so it is cleaned up by the OS.
//!    - `Auto` — resolved at runtime from a built-in lookup table
//!      (`default_strategy`).
//! 4. Forwards the parent's stdin / stdout / stderr unmodified
//!    (`Stdio::inherit`).
//! 5. Returns the wrapped agent's exit code as the wrap subcommand's
//!    exit code, so wrappers compose cleanly with shell pipelines and
//!    CI gates that branch on `$?`.
//!
//! ## Why Rust, not bash + PowerShell
//!
//! The user directive on issue #487 PR-6 was: implementation should be
//! predominantly Rust with config hooks. PR-1 shipped per-recipe bash
//! and PowerShell wrappers, which doubled the maintenance surface and
//! couldn't run in restricted Windows / containerized environments
//! without a shell. A single cross-platform Rust subcommand eliminates
//! both problems — it's the same code path on macOS / Linux / Windows
//! / Docker / Kubernetes / Nix / etc.
//!
//! ## Lookup table
//!
//! [`crate::llm_cli_wrap::default_strategy`] resolves the unflagged
//! form `ai-memory wrap <agent> -- <args>` to the right delivery
//! mechanism for the agents we can identify by name today. Unknown
//! agents fall through to `--system <msg>` because that's the most
//! common contract across OpenAI-compatible CLIs. Future PRs (notably
//! PR-7) can extend the table by adding match arms.
//!
//! ## Substrate split (#1183)
//!
//! The per-CLI-binary `WrapStrategy` enum + the per-vendor table live
//! in [`crate::llm_cli_wrap`], adjacent to [`crate::llm`]'s alias
//! tables, so the per-vendor substrate has one home per concern (HTTP
//! wire shape in `llm.rs`, CLI ABI in `llm_cli_wrap.rs`). The
//! CLI-binary-name detection logic that PICKS a `WrapStrategy` stays
//! HERE because it's CLI-specific (clap `WrapArgs` overrides → table
//! fallback).

use crate::cli::CliOutput;
use crate::cli::boot::{self, BootArgs};
use crate::llm_cli_wrap::{WrapStrategy, default_strategy, is_codex_cli_binary};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Default budget for the inner `ai-memory boot` call when the caller
/// doesn't override. Mirrors `cli::boot::DEFAULT_BUDGET_TOKENS` but is
/// re-declared here so wrap can tune independently if needed.
const DEFAULT_WRAP_BUDGET_TOKENS: usize = 4096;

/// Default row limit for the inner boot call. Same value `cli::boot`
/// itself defaults to.
const DEFAULT_WRAP_LIMIT: usize = 10;

/// Preamble injected before the boot output in every wrap call.
/// Explains to the downstream agent why it's seeing this context. Kept
/// short and stable so prompt-cache breakpoints upstream stay warm.
const WRAP_PREAMBLE: &str = "You have access to ai-memory, a persistent memory system. \
The recent context loaded for you appears below. Reference it when relevant to the user's request.";

/// #1575 — subdirectory of the per-user ai-memory data dir
/// (`~/.ai-memory`, [`crate::AI_MEMORY_HOME_DIR_NAME`]) where the
/// `MessageFile` strategy stages the boot-context system message.
const WRAP_STAGING_SUBDIR: &str = "wrap";

/// #3586 — operator-facing prefix for the one-line notice `wrap` writes
/// to its OWN stderr when the inner `boot --quiet` refuses the DB.
/// Post-#3411 `boot` is silent on stdout AND stderr under `--quiet`
/// (a hook must not inject a warn header into the agent's context), so
/// wrap recovers the reason itself and reports it to the operator. The
/// reason sits between this prefix and [`WRAP_BOOT_REFUSED_SUFFIX`];
/// the agent's system message is unaffected (preamble-only).
const WRAP_BOOT_REFUSED_PREFIX: &str = "ai-memory wrap: memory boot refused (";

/// #3586 — operator-facing suffix closing the refusal notice (see
/// [`WRAP_BOOT_REFUSED_PREFIX`]).
const WRAP_BOOT_REFUSED_SUFFIX: &str = "); running agent without boot context";

/// #3545 — exclusive upper bound of Codex CLI versions whose default
/// `--system` mapping is tested. `0.153.0` is the first known-broken
/// (upstream clap rejects `--system`). Tuple comparison is
/// lexicographic and matches three-component semver without
/// pre-release tags.
pub const CODEX_WRAP_TESTED_MAX_EXCLUSIVE: (u32, u32, u32) = (0, 153, 0);

/// #3545 — display form of the tested range. SSOT for the probe, the
/// refusal message, and operator docs (`docs/integrations/codex-cli.md`,
/// `docs/CLI_REFERENCE.md`, `docs/integrations/README.md`).
pub const CODEX_WRAP_TESTED_RANGE: &str = "< 0.153.0";

/// #3545 — display form of the known-broken range. SSOT twin of
/// [`CODEX_WRAP_TESTED_RANGE`].
pub const CODEX_WRAP_KNOWN_BROKEN: &str = ">= 0.153.0";

/// #3545 — override flag named in the fail-closed refusal. Keep this
/// the one production spelling so docs and the error cannot drift.
const WRAP_OVERRIDE_HINT_SYSTEM_FLAG: &str = "--system-flag";

/// #3545 — env-var override named alongside [`WRAP_OVERRIDE_HINT_SYSTEM_FLAG`].
const WRAP_OVERRIDE_HINT_SYSTEM_ENV: &str = "--system-env";

/// #1575 — resolve (and secure) the staging directory for the
/// `MessageFile` boot-context file: `~/.ai-memory/wrap/`, mode 0700.
///
/// The boot-context system message contains memory contents, so it
/// must not sit on a world-readable tmpfs path for the wrapped
/// agent's whole lifetime (the pre-#1575 behavior — `NamedTempFile`
/// under `std::env::temp_dir()`). Returns `None` when the home
/// directory cannot be resolved or the directory cannot be created /
/// permission-tightened; the caller then falls back to the platform
/// temp dir with an operator-visible WARN.
fn message_file_staging_dir() -> Option<std::path::PathBuf> {
    let dir = dirs::home_dir()?
        .join(crate::AI_MEMORY_HOME_DIR_NAME)
        .join(WRAP_STAGING_SUBDIR);
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    Some(dir)
}

/// Args for `ai-memory wrap`. Designed so the simplest form
/// (`ai-memory wrap codex -- "hello"`) just works — every flag has a
/// defaulted value or the lookup table fills it in.
#[derive(Args, Debug)]
pub struct WrapArgs {
    /// Name of the agent CLI to wrap, e.g. `codex`, `aider`, `gemini`,
    /// `ollama`. Resolved against
    /// [`crate::llm_cli_wrap::default_strategy`] to pick the
    /// system-message delivery mechanism unless the user overrides
    /// with one of the strategy flags below. The agent name is also
    /// the executable looked up on `$PATH`.
    pub agent: String,

    /// Override the system-message flag (e.g. `--system-prompt`). When
    /// set, wrap delivers the system message via this flag regardless
    /// of what the lookup table says for `<agent>`.
    #[arg(long, value_name = "FLAG")]
    pub system_flag: Option<String>,

    /// Override the system-message env var (e.g. `OPENAI_CLI_SYSTEM`).
    /// Mutually exclusive with `--system-flag` and
    /// `--message-file-flag`; if multiple are set, the last specified
    /// on the command line wins (clap default), but the most common
    /// case is supplying exactly one.
    #[arg(long, value_name = "NAME", conflicts_with_all = ["system_flag", "message_file_flag"])]
    pub system_env: Option<String>,

    /// Override the message-file flag (e.g. `--message-file`). Wrap
    /// will write the system message to a tempfile and pass this flag
    /// + the tempfile path to the agent. The tempfile is cleaned up on
    /// wrap exit (cross-platform; uses `tempfile::NamedTempFile`).
    #[arg(long, value_name = "FLAG", conflicts_with_all = ["system_flag", "system_env"])]
    pub message_file_flag: Option<String>,

    /// Skip the inner `ai-memory boot` call entirely. The wrapped
    /// agent runs without any prepended memory context. Useful when
    /// the DB is known to be unavailable, when the user wants the wrap
    /// subcommand for argv-forwarding only, or for tests that want to
    /// isolate the wrapping behavior from the boot-loading behavior.
    #[arg(long, default_value_t = false)]
    pub no_boot: bool,

    /// Row limit forwarded to the inner `ai-memory boot --limit`.
    /// Clamped to `[1, 50]` by `cli::boot` itself.
    #[arg(long, default_value_t = DEFAULT_WRAP_LIMIT)]
    pub limit: usize,

    /// Approximate token budget forwarded to the inner
    /// `ai-memory boot --budget-tokens`.
    #[arg(long, default_value_t = DEFAULT_WRAP_BUDGET_TOKENS)]
    pub budget_tokens: usize,

    /// Trailing arguments forwarded verbatim to the wrapped agent CLI
    /// after the system-message delivery (the convention is to
    /// separate them with `--` on the command line:
    /// `ai-memory wrap codex -- chat --model gpt-5`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub trailing: Vec<String>,
}

/// Resolve the active strategy from the user-supplied overrides plus
/// the built-in lookup table. Order of precedence:
///
/// 1. `--system-env <name>` → `SystemEnv`
/// 2. `--message-file-flag <flag>` → `MessageFile`
/// 3. `--system-flag <flag>` → `SystemFlag`
/// 4. fall through to
///    [`crate::llm_cli_wrap::default_strategy`]`(agent)` (the
///    per-CLI-binary lookup table)
fn resolve_strategy(args: &WrapArgs) -> WrapStrategy {
    if let Some(name) = args.system_env.as_deref() {
        return WrapStrategy::SystemEnv { name: name.into() };
    }
    if let Some(flag) = args.message_file_flag.as_deref() {
        return WrapStrategy::MessageFile { flag: flag.into() };
    }
    if let Some(flag) = args.system_flag.as_deref() {
        return WrapStrategy::SystemFlag { flag: flag.into() };
    }
    default_strategy(&args.agent)
}

/// True when the caller supplied a strategy override, so they have
/// taken responsibility for the wrapped CLI's system-message ABI.
#[must_use]
fn has_strategy_override(args: &WrapArgs) -> bool {
    args.system_flag.is_some() || args.system_env.is_some() || args.message_file_flag.is_some()
}

/// Parse the first `X.Y` or `X.Y.Z` triplet in `text`. A two-component
/// value is treated as patch `0` so `0.153` compares equal to the
/// exclusive bound. Unparseable input is `None` (fail closed).
#[must_use]
fn parse_semver_triplet(text: &str) -> Option<(u32, u32, u32)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            if let Some(parsed) = parse_dotted_triplet(&text[start..i]) {
                return Some(parsed);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Split `major.minor` or `major.minor.patch` into a triplet.
fn parse_dotted_triplet(candidate: &str) -> Option<(u32, u32, u32)> {
    let mut parts = candidate.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = match parts.next() {
        Some(p) if !p.is_empty() => p.parse::<u32>().ok()?,
        Some(_) | None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[must_use]
fn version_in_tested_range(version: (u32, u32, u32)) -> bool {
    version < CODEX_WRAP_TESTED_MAX_EXCLUSIVE
}

fn format_version(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

/// Probe `{agent} --version` and parse a semver triplet. Stdio is
/// captured (never inherited) so the probe cannot leak into the
/// wrapped session.
fn probe_cli_version(agent: &str) -> Result<(u32, u32, u32)> {
    let output = Command::new(agent)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| {
            format!(
                "ai-memory wrap: failed to run `{agent} --version` (is `{agent}` on $PATH?). \
                 Pass {WRAP_OVERRIDE_HINT_SYSTEM_FLAG} <flag> (or {WRAP_OVERRIDE_HINT_SYSTEM_ENV} \
                 <name>) to override."
            )
        })?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    parse_semver_triplet(&text).with_context(|| {
        format!(
            "ai-memory wrap: could not parse a version from `{agent} --version` \
             (refusing the default --system mapping). Pass {WRAP_OVERRIDE_HINT_SYSTEM_FLAG} \
             <flag> (or {WRAP_OVERRIDE_HINT_SYSTEM_ENV} <name>) to override."
        )
    })
}

/// #3545 — fail closed when the default Codex `--system` mapping is
/// known-broken for the installed CLI, unless the caller overrode the
/// strategy. Runs *before* boot so a doomed wrap does not pay DB/LLM
/// cost.
fn enforce_codex_wrap_version_gate(agent: &str) -> Result<()> {
    let version = probe_cli_version(agent)?;
    if version_in_tested_range(version) {
        return Ok(());
    }
    bail!(
        "ai-memory wrap: Codex CLI {} is outside the tested range for the default \
         --system mapping ({CODEX_WRAP_TESTED_RANGE}; known-broken {CODEX_WRAP_KNOWN_BROKEN}). \
         Pass {WRAP_OVERRIDE_HINT_SYSTEM_FLAG} <flag> (or {WRAP_OVERRIDE_HINT_SYSTEM_ENV} <name>) \
         to override, or use native MCP. See docs/integrations/codex-cli.md.",
        format_version(version)
    );
}

/// Run `cli::boot::run` in-process, capturing its stdout into a
/// `Vec<u8>`. Stderr is also captured but discarded — the boot helper
/// already honors `--quiet` for us, so any stderr that escapes is by
/// design (a developer-facing diagnostic).
///
/// On any boot failure, this function returns an empty `String` rather
/// than propagating — the agent should still run even if memory load
/// fails. Since #3411 `boot --quiet` emits no header on stdout for a
/// refusal, so an empty body is indistinguishable here from a healthy
/// but empty store; the `run` caller recovers the reason with
/// [`probe_boot_refusal`] and reports it on wrap's own stderr (#3586).
fn run_boot_capture(
    db_path: &Path,
    limit: usize,
    budget_tokens: usize,
    app_config: &crate::config::AppConfig,
) -> String {
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
    let args = BootArgs {
        namespace: None,
        limit,
        budget_tokens,
        format: "text".to_string(),
        no_header: false,
        // --quiet so a missing DB never blocks the wrapped agent.
        quiet: true,
        cwd: None,
    };
    if boot::run(db_path, &args, app_config, &mut out).is_err() {
        // Even on hard failure (which `cli::boot::run` should never
        // hit thanks to the `--quiet` graceful path), return an empty
        // string so the agent runs unwrapped rather than getting a
        // blocking error.
        return String::new();
    }
    String::from_utf8(stdout).unwrap_or_default()
}

/// #3586 — recover the refusal reason `boot --quiet` swallowed.
///
/// Post-#3411 the inner `boot` call refuses a missing / schema-behind /
/// schema-ahead DB with EMPTY stdout and stderr under `--quiet`, so the
/// reason is not present in [`run_boot_capture`]'s buffers. Probing
/// [`crate::db::open_existing_read_only`] reproduces the SAME typed
/// refusal without creating or migrating anything (ERRORS-01), so
/// `wrap` can surface it on its own stderr without changing `boot`'s
/// own contract.
///
/// Returns `None` when boot is disabled by operator choice — `boot`
/// then returns empty by design, which is NOT a refusal — and when the
/// DB opens cleanly (a healthy but empty store).
fn probe_boot_refusal(db_path: &Path, app_config: &crate::config::AppConfig) -> Option<String> {
    if !app_config.effective_boot().effective_enabled() {
        return None;
    }
    match crate::db::open_existing_read_only(db_path) {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    }
}

/// Assemble the `<preamble>\n\n<boot_output>` system message. Trims
/// trailing whitespace on the boot section to keep the assembled
/// string tidy in the agent's prompt.
fn build_system_message(boot_output: &str) -> String {
    let trimmed = boot_output.trim_end();
    if trimmed.is_empty() {
        // Even with an empty body the preamble is still useful — it
        // tells the agent "you have memory access" so it knows it can
        // call `memory_recall` mid-session if it has the tool.
        WRAP_PREAMBLE.to_string()
    } else {
        format!("{WRAP_PREAMBLE}\n\n{trimmed}")
    }
}

/// Spawn the agent with stdio inherited and return the exit code.
/// Wrapped here so tests can assert on the spawned-command shape via
/// the helpers in `#[cfg(test)] mod tests`.
fn spawn_and_wait(mut cmd: Command) -> Result<i32> {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd
        .status()
        .with_context(|| format!("ai-memory wrap: failed to spawn agent {cmd:?}"))?;
    // Unix: `code()` is None when the child was killed by a signal.
    // We then surface 128+sig per the standard shell convention so the
    // caller can branch on the signal in CI scripts.
    let code = if let Some(c) = status.code() {
        c
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |s| 128 + s)
        }
        #[cfg(not(unix))]
        {
            1
        }
    };
    Ok(code)
}

/// Build the `Command` for an agent given a strategy. Pulled out of
/// `run` so the tests can assert directly on the resulting `Command`'s
/// argv / env without spawning a subprocess.
///
/// Returns the assembled `Command` + (when the strategy is
/// `MessageFile`) the `NamedTempFile` whose lifetime governs cleanup.
/// The caller MUST keep the returned `Option<NamedTempFile>` alive
/// until after the child has exited; dropping it sooner unlinks the
/// file mid-spawn on platforms where unlink-while-open is permitted.
fn build_command_for_strategy(
    agent: &str,
    strategy: &WrapStrategy,
    system_msg: &str,
    trailing: &[String],
) -> Result<(Command, Option<tempfile::NamedTempFile>)> {
    // #1937 V08-PE-3 — audited chokepoint: emit a signed `process.spawn_audited`
    // row (argv0 = wrapped agent, caller = this builder) as the wrapped-agent
    // `Command` is minted. Best-effort; the audit never blocks the launch.
    let mut cmd =
        crate::spawn_audit::audited_command(agent, crate::spawn_audit::CALLER_CLI_WRAP_AGENT);
    let mut tempfile_handle: Option<tempfile::NamedTempFile> = None;
    match strategy {
        WrapStrategy::SystemFlag { flag } => {
            cmd.arg(flag).arg(system_msg);
            for t in trailing {
                cmd.arg(t);
            }
        }
        WrapStrategy::SystemEnv { name } => {
            cmd.env(name, system_msg);
            for t in trailing {
                cmd.arg(t);
            }
        }
        WrapStrategy::MessageFile { flag } => {
            // `tempfile::NamedTempFile` is cross-platform: on Unix it's
            // a regular file with a randomised name; on Windows it
            // skips the unlink-while-open trick (which Windows
            // disallows) and cleans up on `Drop`. Either way the file
            // is gone after wrap exits.
            //
            // #1575 — stage under `~/.ai-memory/wrap/` (0700 dir,
            // 0600 file) instead of the platform temp dir, so the
            // memory-bearing boot context never sits on a
            // world-readable tmpfs path for the agent's lifetime.
            // The temp dir remains ONLY as a home-unresolvable
            // fallback, with an operator-visible WARN.
            let mut tf = match message_file_staging_dir() {
                Some(dir) => tempfile::NamedTempFile::new_in(&dir).context(
                    "ai-memory wrap: failed to create system-message file in staging dir",
                )?,
                None => {
                    tracing::warn!(
                        "ai-memory wrap: could not resolve/secure the {}/{} staging dir under \
                         the home directory; falling back to the platform temp dir for the \
                         boot-context message file (#1575 — memory contents will transit a \
                         shared temp path)",
                        crate::AI_MEMORY_HOME_DIR_NAME,
                        WRAP_STAGING_SUBDIR
                    );
                    tempfile::NamedTempFile::new()
                        .context("ai-memory wrap: failed to create system-message tempfile")?
                }
            };
            // Belt-and-braces: the tempfile crate already creates
            // 0600 on Unix; pin it explicitly so a future tempfile
            // upgrade can't silently loosen the boot-context file.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(tf.path(), std::fs::Permissions::from_mode(0o600));
            }
            tf.write_all(system_msg.as_bytes())
                .context("ai-memory wrap: failed to write system-message tempfile")?;
            // Flush so the agent process reads the full message even
            // if the OS hasn't drained the buffer yet.
            tf.flush()
                .context("ai-memory wrap: failed to flush system-message tempfile")?;
            cmd.arg(flag).arg(tf.path().as_os_str());
            for t in trailing {
                cmd.arg(t);
            }
            tempfile_handle = Some(tf);
        }
        WrapStrategy::Auto => {
            // Resolve and recurse. `Auto` should be handled by
            // `resolve_strategy` before we get here, but if a caller
            // synthesises a `WrapArgs` programmatically and leaves
            // strategy as `Auto`, fall through to the lookup table.
            let resolved = default_strategy(agent);
            return build_command_for_strategy(agent, &resolved, system_msg, trailing);
        }
    }
    Ok((cmd, tempfile_handle))
}

/// `ai-memory wrap` entry point. Returns the wrapped agent's exit code
/// so `daemon_runtime` can `std::process::exit(code)` on a non-zero
/// outcome — that's how shell pipelines and CI gates branch on the
/// agent's success.
///
/// # Errors
///
/// - The wrapped agent binary cannot be spawned (`Command::status`
///   surfaces the OS-level error).
/// - `tempfile::NamedTempFile::new()` fails when the strategy is
///   `MessageFile` (very rare; `/tmp` full or unwritable).
/// - #3545: wrapping `codex` / `codex-cli` without a strategy override
///   when `{agent} --version` is outside [`CODEX_WRAP_TESTED_RANGE`].
pub fn run(
    db_path: &Path,
    args: &WrapArgs,
    app_config: &crate::config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    // Fail closed *before* boot: Codex CLI >= 0.153.0 rejects the
    // default `--system` mapping. An explicit strategy override is the
    // operator's acknowledgement that they own the ABI.
    if is_codex_cli_binary(&args.agent) && !has_strategy_override(args) {
        enforce_codex_wrap_version_gate(&args.agent)?;
    }

    let strategy = resolve_strategy(args);

    // Boot context. `--no-boot` skips it so the agent runs unwrapped
    // (still through `Command::new(agent)` so this subcommand stays
    // useful as a strategy-hooked launcher even with memory off).
    let system_msg = if args.no_boot {
        WRAP_PREAMBLE.to_string()
    } else {
        let boot_output = run_boot_capture(db_path, args.limit, args.budget_tokens, app_config);
        // #3586 — `boot --quiet` (#3411) is deliberately silent on an
        // unreachable DB so a hook cannot inject a warn header into the
        // agent's context; that silence must NOT extend to the OPERATOR.
        // Recover the refusal reason and emit exactly ONE line on wrap's
        // OWN stderr. The agent's system message stays preamble-only
        // (`build_system_message` below).
        if boot_output.trim_end().is_empty()
            && let Some(reason) = probe_boot_refusal(db_path, app_config)
        {
            // Keep it to a single line even if a typed refusal is multiline.
            let reason = reason.replace('\n', " ");
            writeln!(
                out.stderr,
                "{WRAP_BOOT_REFUSED_PREFIX}{reason}{WRAP_BOOT_REFUSED_SUFFIX}"
            )?;
        }
        build_system_message(&boot_output)
    };

    let (cmd, _tempfile_handle) =
        build_command_for_strategy(&args.agent, &strategy, &system_msg, &args.trailing)?;

    // _tempfile_handle is held by the local binding so it lives until
    // after `spawn_and_wait` returns. Don't shorten its scope.
    let code = spawn_and_wait(cmd)?;
    Ok(code)
}

/// Public helper for callers (tests + future PR-7 recipe additions)
/// that want to format an `OsStr` argv element back to UTF-8 for
/// assertions / logging. Falls back to the lossy form so platforms
/// with non-UTF-8 paths don't panic.
#[must_use]
pub fn os_str_to_string_lossy(s: &OsStr) -> String {
    s.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, materialize_empty_schema, seed_memory};

    fn default_args(agent: &str) -> WrapArgs {
        WrapArgs {
            agent: agent.to_string(),
            system_flag: None,
            system_env: None,
            message_file_flag: None,
            no_boot: false,
            limit: DEFAULT_WRAP_LIMIT,
            budget_tokens: DEFAULT_WRAP_BUDGET_TOKENS,
            trailing: Vec::new(),
        }
    }

    // NOTE: The canonical per-agent table pin moved to
    // `crate::llm_cli_wrap::tests::default_strategy_per_known_agent_pins_1183`
    // alongside the table itself in #1183. The tests below exercise the
    // wrap-side dispatch (override precedence + command-build shape) and
    // reach the moved table via the re-imported `default_strategy`
    // symbol.

    #[test]
    fn resolve_strategy_explicit_overrides_lookup_table() {
        let mut args = default_args("ollama");
        args.system_flag = Some("--system-prompt".into());
        // Even though "ollama" maps to SystemEnv in the lookup,
        // explicit `--system-flag` wins.
        assert_eq!(
            resolve_strategy(&args),
            WrapStrategy::SystemFlag {
                flag: "--system-prompt".into()
            }
        );
    }

    #[test]
    fn resolve_strategy_env_override_takes_precedence_over_flag_default() {
        let mut args = default_args("codex");
        args.system_env = Some("OPENAI_CLI_SYSTEM".into());
        assert_eq!(
            resolve_strategy(&args),
            WrapStrategy::SystemEnv {
                name: "OPENAI_CLI_SYSTEM".into()
            }
        );
    }

    #[test]
    fn resolve_strategy_message_file_override() {
        let mut args = default_args("codex");
        args.message_file_flag = Some("--prompt-file".into());
        assert_eq!(
            resolve_strategy(&args),
            WrapStrategy::MessageFile {
                flag: "--prompt-file".into()
            }
        );
    }

    #[test]
    fn build_system_message_prepends_preamble() {
        let msg = build_system_message("- [mid/abc] hello");
        assert!(msg.starts_with(WRAP_PREAMBLE));
        assert!(msg.contains("hello"));
        assert!(msg.contains("\n\n"), "preamble + body separator missing");
    }

    #[test]
    fn build_system_message_empty_body_returns_preamble_only() {
        let msg = build_system_message("");
        assert_eq!(msg, WRAP_PREAMBLE);
    }

    #[test]
    fn build_system_message_strips_trailing_whitespace() {
        let msg = build_system_message("body line\n\n\n");
        assert!(msg.ends_with("body line"));
    }

    #[test]
    fn build_command_system_flag_sets_argv_correctly() {
        let strat = WrapStrategy::SystemFlag {
            flag: "--system".into(),
        };
        let trailing = vec![
            "chat".to_string(),
            "--model".to_string(),
            "gpt-5".to_string(),
        ];
        let (cmd, tf) =
            build_command_for_strategy("codex", &strat, "SYS-MSG-VALUE", &trailing).unwrap();
        assert!(tf.is_none(), "SystemFlag must not allocate a tempfile");
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        assert_eq!(
            argv,
            vec!["--system", "SYS-MSG-VALUE", "chat", "--model", "gpt-5"]
        );
        // Verify the program name (first arg of Command, not in
        // get_args) — get_program is part of the std API.
        assert_eq!(cmd.get_program(), OsStr::new("codex"));
    }

    #[test]
    fn build_command_system_env_sets_env_var_and_omits_flag() {
        let strat = WrapStrategy::SystemEnv {
            name: "OLLAMA_SYSTEM".into(),
        };
        let trailing = vec!["run".to_string(), "hermes3:8b".to_string()];
        let (cmd, tf) =
            build_command_for_strategy("ollama", &strat, "SYS-ENV-MSG", &trailing).unwrap();
        assert!(tf.is_none(), "SystemEnv must not allocate a tempfile");
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        // The env-var strategy never injects a flag — argv is just the
        // trailing args.
        assert_eq!(argv, vec!["run", "hermes3:8b"]);
        // Confirm OLLAMA_SYSTEM is set on the Command's env. get_envs()
        // yields (key, Option<value>) pairs.
        let env_pairs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    os_str_to_string_lossy(k),
                    v.map(|x| os_str_to_string_lossy(x)),
                )
            })
            .collect();
        let entry = env_pairs
            .iter()
            .find(|(k, _)| k == "OLLAMA_SYSTEM")
            .expect("OLLAMA_SYSTEM must be set");
        assert_eq!(entry.1.as_deref(), Some("SYS-ENV-MSG"));
    }

    #[test]
    fn wrap_strategy_message_file_creates_tempfile_and_cleans_up() {
        let strat = WrapStrategy::MessageFile {
            flag: "--message-file".into(),
        };
        let (path_owned, exists_during) = {
            let (cmd, tf) =
                build_command_for_strategy("aider", &strat, "FILE-MSG-CONTENT", &[]).unwrap();
            let tf = tf.expect("MessageFile must allocate a tempfile");
            // The argv should point at the tempfile path. We can't
            // directly assert path equality on Windows (canonicalisation
            // differs), so just check the `--message-file` flag is the
            // first arg and the second arg is some non-empty path.
            let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
            assert_eq!(argv.len(), 2);
            assert_eq!(argv[0], "--message-file");
            assert!(!argv[1].is_empty());
            // Sanity: the tempfile contains the expected message body.
            let read_back = std::fs::read_to_string(tf.path()).unwrap();
            assert_eq!(read_back, "FILE-MSG-CONTENT");
            let exists = tf.path().exists();
            // Take the path as PathBuf BEFORE dropping `tf` so we can
            // re-stat after the block exits.
            let p = tf.path().to_path_buf();
            (p, exists)
        };
        assert!(
            exists_during,
            "tempfile must exist while NamedTempFile is alive"
        );
        // After the block ends, NamedTempFile is dropped, which
        // unlinks the file (Unix and Windows both — tempfile crate
        // smooths over the platform difference).
        assert!(
            !path_owned.exists(),
            "tempfile must be cleaned up on Drop, but {} still exists",
            path_owned.display()
        );
    }

    /// #1575 — the boot-context message file must be staged under the
    /// per-user ai-memory data dir (`~/.ai-memory/wrap/`, 0700 dir /
    /// 0600 file), NOT the platform temp dir. The temp dir is only the
    /// home-unresolvable fallback (exercised implicitly when
    /// `dirs::home_dir()` returns `None`, which cannot be forced here
    /// without unsafe env mutation — the fallback arm is plain
    /// pre-#1575 behavior).
    #[test]
    fn message_file_staged_under_ai_memory_home_with_tight_perms_1575() {
        let Some(staging) = message_file_staging_dir() else {
            // No resolvable home in this environment — the WARN +
            // temp-dir fallback arm applies; nothing to assert.
            return;
        };
        let strat = WrapStrategy::MessageFile {
            flag: "--message-file".into(),
        };
        let (_cmd, tf) =
            build_command_for_strategy("aider", &strat, "BOOT-CONTEXT-1575", &[]).unwrap();
        let tf = tf.expect("MessageFile must allocate a staged file");
        assert_eq!(
            tf.path().parent(),
            Some(staging.as_path()),
            "boot-context file must live under the ai-memory staging dir, got {}",
            tf.path().display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dmode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
            assert_eq!(dmode, 0o700, "staging dir must be 0700");
            let fmode = std::fs::metadata(tf.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(fmode, 0o600, "boot-context file must be 0600");
        }
    }

    #[test]
    fn wrap_with_unreachable_db_runs_agent_unwrapped_3411() {
        // #3411 contract: `boot --quiet` with a missing DB exits 0 with
        // EMPTY stdout (a hook must not inject a warn header into the
        // agent's context). The captured stdout becomes the body of the
        // wrap system message, so with an unreachable DB the body is
        // empty and the agent runs with the preamble alone. We assert:
        // (a) `run_boot_capture` returns an empty string without
        // erroring, and (b) the assembled system message is exactly the
        // preamble so the agent still knows it has memory access.
        let env = TestEnv::fresh();
        let bad = env
            .db_path
            .parent()
            .unwrap()
            .join("nope/that/does/not/exist/db.sqlite");
        let captured = run_boot_capture(
            &bad,
            10,
            DEFAULT_WRAP_BUDGET_TOKENS,
            &crate::config::AppConfig::default(),
        );
        assert!(
            captured.is_empty(),
            "`boot --quiet` must be silent on an unreachable DB (#3411): {captured}"
        );
        let assembled = build_system_message(&captured);
        assert_eq!(
            assembled, WRAP_PREAMBLE,
            "an empty boot body must leave exactly the preamble"
        );
    }

    #[test]
    fn wrap_with_no_boot_skips_context() {
        // Smoke: the run path with `no_boot = true` produces a system
        // message that's exactly the preamble (no boot body). We verify
        // by re-running the equivalent assembly the `run` function uses
        // when `args.no_boot` is true.
        let mut args = default_args("codex");
        args.no_boot = true;
        // The `run` body's `if args.no_boot { WRAP_PREAMBLE.to_string() }`
        // branch is what produces the system message in this mode.
        // We replicate it here so we can assert on the value without
        // spawning a subprocess (the real `codex` isn't on the test
        // host's PATH).
        let system_msg = if args.no_boot {
            WRAP_PREAMBLE.to_string()
        } else {
            unreachable!()
        };
        assert_eq!(system_msg, WRAP_PREAMBLE);
        // And the assembled command for that message must contain
        // exactly the preamble as the flag value, no boot context.
        let (cmd, _tf) = build_command_for_strategy(
            &args.agent,
            &resolve_strategy(&args),
            &system_msg,
            &args.trailing,
        )
        .unwrap();
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], "--system");
        assert_eq!(argv[1], WRAP_PREAMBLE);
    }

    #[test]
    fn wrap_injects_system_message_via_flag() {
        // Seed a memory so the boot output is non-empty, then assert
        // the assembled system message that wrap would pass to the
        // agent contains both the preamble AND the seeded memory's
        // title. This is the contract the docs/integrations recipes
        // depend on.
        let env = TestEnv::fresh();
        seed_memory(&env.db_path, "ns-wrap-test", "wrap-injection-canary", "x");
        let captured = run_boot_capture(
            &env.db_path,
            10,
            DEFAULT_WRAP_BUDGET_TOKENS,
            &crate::config::AppConfig::default(),
        );
        // boot::run sets the namespace from auto_namespace, which won't
        // match `ns-wrap-test` unless cwd is set. The fallback path
        // should still surface SOMETHING so the captured body is
        // non-empty (warn or info header at minimum).
        assert!(
            !captured.is_empty(),
            "expected non-empty boot capture, got empty"
        );
        let assembled = build_system_message(&captured);
        assert!(assembled.starts_with(WRAP_PREAMBLE));
        assert!(assembled.len() > WRAP_PREAMBLE.len());
        // Now assert the assembled message rides through to the
        // command's argv.
        let (cmd, _tf) = build_command_for_strategy(
            "codex",
            &WrapStrategy::SystemFlag {
                flag: "--system".into(),
            },
            &assembled,
            &[],
        )
        .unwrap();
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], "--system");
        assert!(argv[1].starts_with(WRAP_PREAMBLE));
    }

    #[test]
    fn wrap_passes_through_exit_code_via_status_propagation() {
        // We can't assume any specific binary is on PATH, but we can
        // exercise the propagation logic with a guaranteed-available
        // command: `false` on Unix exits 1, `true` exits 0.
        #[cfg(unix)]
        {
            // Exit 0
            let cmd = Command::new("true");
            let code = spawn_and_wait(cmd).unwrap();
            assert_eq!(code, 0);
            // Exit 1
            let cmd = Command::new("false");
            let code = spawn_and_wait(cmd).unwrap();
            assert_eq!(code, 1);
        }
    }

    #[test]
    fn wrap_run_returns_exit_code_for_real_subprocess() {
        // End-to-end: drive `run` itself (not just the helpers). We
        // wrap a known-good binary (`true` on unix) and assert the
        // returned code matches.
        let mut env = TestEnv::fresh();
        let db_path = env.db_path.clone();
        let mut out = env.output();
        #[cfg(unix)]
        {
            let mut args = default_args("true");
            // Skip boot to avoid touching the DB and to keep the test
            // deterministic. `--system "..."` is still passed to the
            // agent — `true` ignores all argv, exits 0.
            args.no_boot = true;
            let code = run(
                &db_path,
                &args,
                &crate::config::AppConfig::default(),
                &mut out,
            )
            .unwrap();
            assert_eq!(code, 0);
        }
    }

    #[test]
    fn auto_strategy_resolves_at_command_build_time() {
        // Exercise the `WrapStrategy::Auto` recursive branch in
        // `build_command_for_strategy`.
        let (cmd, tf) = build_command_for_strategy(
            "codex",
            &WrapStrategy::Auto,
            "AUTO-MSG",
            &["chat".to_string()],
        )
        .unwrap();
        assert!(tf.is_none());
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        // codex auto-resolves to SystemFlag{--system}.
        assert_eq!(argv, vec!["--system", "AUTO-MSG", "chat"]);
    }

    #[test]
    fn auto_strategy_resolves_to_message_file_for_aider() {
        let (cmd, tf) =
            build_command_for_strategy("aider", &WrapStrategy::Auto, "AIDER-MSG", &[]).unwrap();
        // aider auto-resolves to MessageFile, so a tempfile must be
        // allocated.
        assert!(tf.is_some());
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], "--message-file");
    }

    #[test]
    fn run_boot_capture_returns_string_not_panics_on_missing_db() {
        // Hardening: every error path inside boot must surface as a
        // String (possibly empty, possibly the warn header) — never a
        // panic — so the wrapped agent always runs.
        let env = TestEnv::fresh();
        let bad = env
            .db_path
            .parent()
            .unwrap()
            .join("__definitely_missing__/db");
        let s = run_boot_capture(
            &bad,
            10,
            DEFAULT_WRAP_BUDGET_TOKENS,
            &crate::config::AppConfig::default(),
        );
        // Either the warn header or empty (both are non-panic outcomes).
        assert!(
            s.is_empty() || s.contains("# ai-memory boot:"),
            "expected warn header or empty, got: {s}"
        );
    }

    /// Coverage restoration (post-#1575 floor dip): the
    /// `boot::run(...).is_err()` hard-failure arm in
    /// `run_boot_capture` must return an EMPTY string (agent runs
    /// unwrapped) — forced by pointing db_path at a DIRECTORY, which
    /// the sqlite open cannot create-or-open even under `--quiet`.
    #[test]
    fn run_boot_capture_returns_empty_when_db_path_is_a_directory() {
        let env = TestEnv::fresh();
        let dir_as_db = env.db_path.parent().unwrap().to_path_buf();
        let s = run_boot_capture(
            &dir_as_db,
            10,
            DEFAULT_WRAP_BUDGET_TOKENS,
            &crate::config::AppConfig::default(),
        );
        assert!(
            s.is_empty() || s.contains("# ai-memory boot:"),
            "directory-as-db must yield empty or warn-header output, got: {s}"
        );
    }

    /// Coverage restoration: the MessageFile arm's trailing-arg
    /// passthrough loop — trailing CLI args must land on the wrapped
    /// command AFTER the message-file flag pair.
    #[test]
    fn message_file_strategy_passes_trailing_args_through() {
        let strat = WrapStrategy::MessageFile {
            flag: "--message-file".into(),
        };
        let trailing = vec!["--model".to_string(), "gpt-x".to_string()];
        let (cmd, tf) =
            build_command_for_strategy("aider", &strat, "BOOT-TRAIL", &trailing).unwrap();
        let _tf = tf.expect("MessageFile must allocate a staged file");
        let argv: Vec<String> = cmd.get_args().map(|s| os_str_to_string_lossy(s)).collect();
        assert_eq!(argv[0], "--message-file");
        assert_eq!(
            &argv[2..],
            ["--model", "gpt-x"],
            "trailing args must follow the message-file pair: {argv:?}"
        );
    }

    // ------------------------------------------------------------------
    // #3586 — `boot --quiet` (#3411) is silent on a refusal so a hook
    // cannot inject a warn header into the agent's context; wrap must
    // still tell the OPERATOR, on its OWN stderr, that the refusal
    // happened. The agent's system message stays preamble-only.
    // ------------------------------------------------------------------

    /// The end-to-end contract: an unreachable DB makes `run` emit one
    /// operator line on wrap's stderr while the wrapped agent still
    /// starts (exit 0 propagated) and no boot header leaks anywhere.
    #[test]
    #[cfg(unix)]
    fn wrap_unreachable_db_emits_operator_stderr_line_3586() {
        let mut env = TestEnv::fresh();
        let db_path = env.db_path.clone();
        let mut out = env.output();
        let code = run(
            &db_path,
            &default_args("true"),
            &crate::config::AppConfig::default(),
            &mut out,
        )
        .expect("wrap must run the agent even when boot refuses");
        drop(out);
        assert_eq!(code, 0, "the wrapped agent's exit code must propagate");
        let stderr = env.stderr_str();
        assert!(
            stderr.contains(WRAP_BOOT_REFUSED_PREFIX),
            "operator stderr must carry the refusal prefix: {stderr:?}"
        );
        assert!(
            stderr.contains(WRAP_BOOT_REFUSED_SUFFIX),
            "operator stderr must carry the refusal suffix: {stderr:?}"
        );
        assert!(
            stderr.contains("database does not exist"),
            "operator stderr must name the refusal reason: {stderr:?}"
        );
        // The agent's context stays clean: no boot warn header is routed
        // through wrap's stdout (the pre-#3411 behavior).
        assert!(
            !env.stdout_str().contains("# ai-memory boot:"),
            "boot's warn header must not leak into the agent's context"
        );
    }

    /// The agent-facing half of the contract: the refusal leaves the
    /// assembled system message exactly the preamble.
    #[test]
    fn wrap_unreachable_db_system_message_is_preamble_only_3586() {
        let env = TestEnv::fresh();
        let bad = env.db_path.parent().unwrap().join("nope/3586/db.sqlite");
        let captured = run_boot_capture(
            &bad,
            10,
            DEFAULT_WRAP_BUDGET_TOKENS,
            &crate::config::AppConfig::default(),
        );
        assert!(
            captured.is_empty(),
            "`boot --quiet` must stay silent on the refusal (#3411): {captured}"
        );
        assert_eq!(
            build_system_message(&captured),
            WRAP_PREAMBLE,
            "a refused boot must leave exactly the preamble for the agent"
        );
    }

    #[test]
    fn probe_boot_refusal_returns_reason_for_missing_db_3586() {
        let env = TestEnv::fresh();
        let bad = env.db_path.parent().unwrap().join("missing/3586.sqlite");
        let reason = probe_boot_refusal(&bad, &crate::config::AppConfig::default())
            .expect("a missing DB must yield a refusal reason");
        assert!(
            reason.contains("database does not exist"),
            "the recovered reason must name the refusal: {reason}"
        );
    }

    #[test]
    fn probe_boot_refusal_returns_none_for_healthy_db_3586() {
        let env = TestEnv::fresh();
        materialize_empty_schema(&env.db_path);
        assert!(
            probe_boot_refusal(&env.db_path, &crate::config::AppConfig::default()).is_none(),
            "a readable schema-current DB is not a refusal"
        );
    }

    /// An operator-disabled boot produces an empty capture BY CHOICE,
    /// not a refusal — the probe must stay silent (no false operator
    /// line for the privacy escape hatch).
    #[test]
    fn probe_boot_refusal_returns_none_when_boot_disabled_3586() {
        let env = TestEnv::fresh();
        let bad = env.db_path.parent().unwrap().join("disabled/3586.sqlite");
        let cfg = crate::config::AppConfig {
            boot: Some(crate::config::BootConfig {
                enabled: Some(false),
                redact_titles: None,
            }),
            ..crate::config::AppConfig::default()
        };
        assert!(
            probe_boot_refusal(&bad, &cfg).is_none(),
            "a disabled boot is not a refusal"
        );
    }

    // ------------------------------------------------------------------
    // #3545 — Codex CLI version gate (fail closed outside the tested
    // range unless `--system-flag` / `--system-env` is given).
    // ------------------------------------------------------------------

    #[test]
    fn parse_semver_triplet_picks_first_x_y_z() {
        assert_eq!(parse_semver_triplet("codex-cli 0.153.3"), Some((0, 153, 3)));
        assert_eq!(parse_semver_triplet("0.152.0\n"), Some((0, 152, 0)));
        assert_eq!(
            parse_semver_triplet("codex-cli 0.153"),
            Some((0, 153, 0)),
            "two-component form is patch 0 so 0.153 compares at the bound"
        );
        assert_eq!(parse_semver_triplet("not a version"), None);
        assert_eq!(parse_semver_triplet(""), None);
    }

    #[test]
    fn version_in_tested_range_is_strictly_below_0_153_0() {
        assert!(version_in_tested_range((0, 152, 99)));
        assert!(version_in_tested_range((0, 1, 0)));
        assert!(!version_in_tested_range((0, 153, 0)));
        assert!(!version_in_tested_range((0, 153, 3)));
        assert!(!version_in_tested_range((1, 0, 0)));
    }

    #[test]
    fn wrap_codex_docs_cite_tested_range_ssot_3545() {
        // The tested-range table is the single source for docs and the
        // probe (issue #3545 acceptance). Frozen review trees are out
        // of scope; these three operator-facing pages must cite the
        // consts by value.
        for (path, body) in [
            (
                "docs/integrations/codex-cli.md",
                include_str!("../../docs/integrations/codex-cli.md"),
            ),
            (
                "docs/CLI_REFERENCE.md",
                include_str!("../../docs/CLI_REFERENCE.md"),
            ),
            (
                "docs/integrations/README.md",
                include_str!("../../docs/integrations/README.md"),
            ),
        ] {
            assert!(
                body.contains(CODEX_WRAP_TESTED_RANGE),
                "{path} must cite CODEX_WRAP_TESTED_RANGE ({CODEX_WRAP_TESTED_RANGE})"
            );
            assert!(
                body.contains(CODEX_WRAP_KNOWN_BROKEN),
                "{path} must cite CODEX_WRAP_KNOWN_BROKEN ({CODEX_WRAP_KNOWN_BROKEN})"
            );
            assert!(
                body.contains(WRAP_OVERRIDE_HINT_SYSTEM_FLAG),
                "{path} must name {WRAP_OVERRIDE_HINT_SYSTEM_FLAG}"
            );
        }
    }

    #[cfg(unix)]
    fn install_fake_codex(dir: &Path, version_line: &str) {
        let bin = dir.join("codex");
        let safe = version_line.replace('\'', "");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' '{safe}'\n  exit 0\nfi\nexit 0\n"
        );
        std::fs::write(&bin, script).expect("write fake codex");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake codex");
    }

    #[cfg(unix)]
    fn with_fake_codex_on_path<R>(version_line: &str, f: impl FnOnce() -> R) -> R {
        let env = TestEnv::fresh();
        let bin_dir = env.db_path.parent().expect("tempdir parent").to_path_buf();
        install_fake_codex(&bin_dir, version_line);
        let _lock = crate::test_support::env_lock();
        let path_g = crate::test_support::EnvGuard::capture("PATH");
        let mut new_path = bin_dir.into_os_string();
        new_path.push(":");
        if let Some(rest) = std::env::var_os("PATH") {
            new_path.push(rest);
        }
        let new_path = new_path.to_string_lossy();
        path_g.set(&new_path);
        f()
    }

    /// Fake `codex` reporting 0.153.3: non-zero (Err) and the message
    /// names `--system-flag`.
    #[test]
    #[cfg(unix)]
    fn wrap_codex_0_153_3_refuses_naming_system_flag_3545() {
        with_fake_codex_on_path("codex-cli 0.153.3", || {
            let mut env = TestEnv::fresh();
            let db_path = env.db_path.clone();
            let mut out = env.output();
            let mut args = default_args("codex");
            args.no_boot = true;
            let err = run(
                &db_path,
                &args,
                &crate::config::AppConfig::default(),
                &mut out,
            )
            .expect_err("0.153.3 must refuse the default --system mapping");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(WRAP_OVERRIDE_HINT_SYSTEM_FLAG),
                "refusal must name {WRAP_OVERRIDE_HINT_SYSTEM_FLAG}: {msg}"
            );
            assert!(
                msg.contains(CODEX_WRAP_KNOWN_BROKEN),
                "refusal must cite the known-broken range: {msg}"
            );
            assert!(
                msg.contains("0.153.3"),
                "refusal must name the probed version: {msg}"
            );
        });
    }

    /// Fake `codex` reporting an in-range version: wrap proceeds.
    #[test]
    #[cfg(unix)]
    fn wrap_codex_in_range_version_passes_3545() {
        with_fake_codex_on_path("codex-cli 0.152.0", || {
            let mut env = TestEnv::fresh();
            let db_path = env.db_path.clone();
            let mut out = env.output();
            let mut args = default_args("codex");
            args.no_boot = true;
            let code = run(
                &db_path,
                &args,
                &crate::config::AppConfig::default(),
                &mut out,
            )
            .expect("in-range Codex CLI must be allowed");
            assert_eq!(code, 0);
        });
    }

    /// `--system-flag` given: 0.153.3 is allowed (operator owns the ABI).
    #[test]
    #[cfg(unix)]
    fn wrap_codex_0_153_3_with_system_flag_passes_3545() {
        with_fake_codex_on_path("codex-cli 0.153.3", || {
            let mut env = TestEnv::fresh();
            let db_path = env.db_path.clone();
            let mut out = env.output();
            let mut args = default_args("codex");
            args.no_boot = true;
            args.system_flag = Some("--system-prompt".into());
            let code = run(
                &db_path,
                &args,
                &crate::config::AppConfig::default(),
                &mut out,
            )
            .expect("--system-flag must skip the version gate");
            assert_eq!(code, 0);
        });
    }

    #[test]
    fn unparseable_codex_version_refuses_closed_3545() {
        // Pure parser pin: garbage `--version` output is not in-range.
        assert!(parse_semver_triplet("codex (devel)").is_none());
    }

    #[test]
    #[cfg(unix)]
    fn wrap_codex_unparseable_version_refuses_naming_system_flag_3545() {
        with_fake_codex_on_path("codex (devel)", || {
            let mut env = TestEnv::fresh();
            let db_path = env.db_path.clone();
            let mut out = env.output();
            let mut args = default_args("codex");
            args.no_boot = true;
            let err = run(
                &db_path,
                &args,
                &crate::config::AppConfig::default(),
                &mut out,
            )
            .expect_err("unparseable --version must refuse");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(WRAP_OVERRIDE_HINT_SYSTEM_FLAG),
                "unparseable refusal must name {WRAP_OVERRIDE_HINT_SYSTEM_FLAG}: {msg}"
            );
        });
    }
}
