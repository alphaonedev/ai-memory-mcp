// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-CLI-binary `WrapStrategy` table for the `ai-memory wrap <agent>`
//! subcommand.
//!
//! # Why this module exists (#1183, split out of #1174 PR4)
//!
//! The `ai-memory wrap` subcommand spawns *external CLI binaries* (the
//! `codex`, `aider`, `gemini`, `ollama`, … executables on `$PATH`) and
//! prepends a system-message envelope onto each invocation. Each
//! downstream CLI has its own ABI for accepting that envelope —
//! `--system "<msg>"` vs. `OLLAMA_SYSTEM=<msg>` vs. `--message-file
//! <path>` — and the table that maps "agent binary name" → "delivery
//! strategy" is the canonical knowledge of those ABIs.
//!
//! That table is **adjacent to** the LLM-backend alias tables in
//! [`crate::llm`] (the `default_base_url_for_alias` / vendor URL +
//! Bearer-key map used by the HTTP LLM client), but is *not* the same
//! concern:
//!
//! - [`crate::llm`] is the **HTTP LLM client** — `POST
//!   /v1/chat/completions`, Bearer auth, circuit breaker. The agent
//!   name here means "wire-shape selector" (`xai`, `openai`, …).
//! - This module is the **CLI process-spawning wrapper** —
//!   `std::process::Command::new(<binary>)`, `Stdio::inherit`,
//!   tempfile cleanup. The agent name here means "binary on `$PATH`"
//!   (`codex`, `aider`, …).
//!
//! Keeping the two tables in sibling modules at the crate root
//! preserves both concerns at one substrate level without conflating
//! them into the HTTP client module. The CLI-binary-name detection
//! logic that PICKS a `WrapStrategy` stays in [`crate::cli::wrap`]
//! (it's CLI-specific); only the per-vendor TABLE lives here.

/// Strategy for delivering the assembled system message to the wrapped
/// agent. Each variant maps to a distinct CLI ABI an agent might
/// expose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapStrategy {
    /// Pass the system message as the value of a CLI flag, e.g.
    /// `codex --system "<msg>" <args...>`.
    SystemFlag {
        /// The flag name including any leading dashes — e.g. `--system`,
        /// `--system-prompt`, `-s`.
        flag: String,
    },
    /// Set the system message as an environment variable for the child
    /// process. e.g. `OLLAMA_SYSTEM=<msg> ollama run hermes3:8b`.
    SystemEnv {
        /// The env var name, e.g. `OLLAMA_SYSTEM`.
        name: String,
    },
    /// Write the system message to a tempfile and pass the path via a
    /// CLI flag. e.g. `aider --message-file <path> <args...>`. Used by
    /// agents whose system-message length exceeds shell argv limits or
    /// whose CLI explicitly takes a file path.
    MessageFile {
        /// The flag that takes the file path, e.g. `--message-file`.
        flag: String,
    },
    /// Resolve the strategy at runtime from [`default_strategy`].
    /// This is the natural mode when the user hasn't passed any of the
    /// strategy override flags.
    Auto,
}

/// Built-in agent → strategy lookup. The list is small by design — we
/// only encode strategies for agents we've actually verified. Anything
/// not in the table falls through to `--system <msg>` because that's
/// the most common contract across OpenAI-compatible CLIs.
///
/// PR-7 may extend this map; the matrix is intentionally tabular so
/// adding a row is a one-line change.
///
/// **Substrate note (#1183).** This table sits next to
/// [`crate::llm`]'s alias tables (`default_base_url_for_alias`,
/// `alias_api_key_env_vars`) at the crate root so the "per-vendor
/// behavior" substrate has one home per concern: HTTP wire shape in
/// `llm.rs`, CLI ABI in `llm_cli_wrap.rs`. The agent-name strings here
/// are CLI **binary names** on `$PATH`, NOT the
/// `AI_MEMORY_LLM_BACKEND` wire-shape selector — overlap is
/// coincidental (e.g. `ollama` is both a CLI binary AND a backend
/// selector, but the two columns are independent).
#[must_use]
pub fn default_strategy(agent: &str) -> WrapStrategy {
    match agent {
        // OpenAI Codex CLI. The flag name varies between Codex variants
        // (`--system`, `--system-prompt`, `OPENAI_CLI_SYSTEM`) but
        // `--system` is the documented form on the upstream codex-cli
        // crate (PR-1 recipe + Codex CLI README). Users running a
        // variant that exposes a different flag can override with
        // `--system-flag <flag>`.
        "codex" | "codex-cli" => WrapStrategy::SystemFlag {
            flag: "--system".into(),
        },
        // Anthropic Claude Code CLI (#1238). The canonical flag for
        // appending a system prompt onto a `claude` invocation is
        // `--append-system-prompt "<msg>"` per the upstream
        // `@anthropic-ai/claude-code` CLI docs. The env-var equivalent
        // is `CLAUDE_SYSTEM_PROMPT` but the flag form is preferred —
        // it composes with `claude -p` (one-shot mode) without forcing
        // operators to leak the prompt into the child's env block.
        // Pre-#1238 this fell through to the generic `--system`
        // fallback, which `claude` either rejects or silently
        // ignores — the project's own primary use case sat in the
        // unverified fallback.
        "claude" | "claude-cli" => WrapStrategy::SystemFlag {
            flag: "--append-system-prompt".into(),
        },
        // Aider takes its system / instructions input from a file via
        // `--message-file`. Aider's CLI explicitly recommends this for
        // anything longer than a one-liner because it doesn't shell-quote
        // the arg-form for newlines reliably.
        "aider" => WrapStrategy::MessageFile {
            flag: "--message-file".into(),
        },
        // Google Gemini CLI. `--system` is the documented prepend form.
        "gemini" => WrapStrategy::SystemFlag {
            flag: "--system".into(),
        },
        // Ollama uses an env var because `ollama run <model>` doesn't
        // expose a `--system` flag at the CLI level — it expects the
        // system prompt either inside the prompt body or via the
        // `OLLAMA_SYSTEM` env var (also the form `ollama serve` reads).
        "ollama" => WrapStrategy::SystemEnv {
            name: "OLLAMA_SYSTEM".into(),
        },
        // Default: most OpenAI-compatible CLIs accept `--system <msg>`.
        // If that's wrong, users override with `--system-flag` /
        // `--system-env` / `--message-file-flag`.
        //
        // # Documented gaps (#1238)
        //
        // The following vendor CLI binaries are intentionally LEFT in
        // the generic fallback rather than pinned to a flag, because
        // upstream documentation does not surface a canonical
        // `--system`-equivalent flag the way the entries above do:
        //
        // - `gpt` — no canonical first-party OpenAI CLI binary uses
        //   that name; multiple community wrappers exist with
        //   incompatible flag shapes. Falls through to `--system`.
        // - `grok` — xAI ships no first-party CLI binary at v0.7.0
        //   (the Grok surface is API-only); falls through to
        //   `--system` for any community wrapper that defaults to it.
        // - `anthropic-cli` — there is no first-party CLI binary
        //   named `anthropic-cli` at v0.7.0 (Anthropic ships the
        //   Python SDK + the `claude` Claude Code CLI handled above);
        //   falls through to `--system` for any third-party tool.
        //
        // Operators running a vendor CLI in any of the three gaps
        // above pass `--system-flag <flag>` (or `--system-env <name>`
        // / `--message-file-flag <flag>`) explicitly. If a canonical
        // upstream form lands for any of these later, add a row
        // here + extend `default_strategy_per_known_agent_pins_1183`.
        _ => WrapStrategy::SystemFlag {
            flag: "--system".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte preservation pin for the per-agent CLI-ABI table
    /// after the #1183 move. If any of these assertions break, the
    /// `ai-memory wrap` runtime contract with downstream agent CLIs is
    /// broken too — the inputs to `Command::new(<agent>)` change shape
    /// and existing integrations rely on the exact `--system` /
    /// `OLLAMA_SYSTEM` / `--message-file` argv shape.
    #[test]
    fn default_strategy_per_known_agent_pins_1183() {
        assert_eq!(
            default_strategy("codex"),
            WrapStrategy::SystemFlag {
                flag: "--system".into()
            }
        );
        assert_eq!(
            default_strategy("codex-cli"),
            WrapStrategy::SystemFlag {
                flag: "--system".into()
            }
        );
        assert_eq!(
            default_strategy("aider"),
            WrapStrategy::MessageFile {
                flag: "--message-file".into()
            }
        );
        assert_eq!(
            default_strategy("gemini"),
            WrapStrategy::SystemFlag {
                flag: "--system".into()
            }
        );
        assert_eq!(
            default_strategy("ollama"),
            WrapStrategy::SystemEnv {
                name: "OLLAMA_SYSTEM".into()
            }
        );
        // #1238 — Claude Code CLI uses --append-system-prompt; the
        // pre-#1238 default fall-through to `--system` is wrong for
        // `claude` and `claude-cli` (the project's own primary
        // wrapped agent).
        assert_eq!(
            default_strategy("claude"),
            WrapStrategy::SystemFlag {
                flag: "--append-system-prompt".into()
            }
        );
        assert_eq!(
            default_strategy("claude-cli"),
            WrapStrategy::SystemFlag {
                flag: "--append-system-prompt".into()
            }
        );
        // #1238 — documented gaps. `gpt`, `grok`, `anthropic-cli`
        // have no canonical first-party CLI flag at v0.7.0 ship;
        // they intentionally fall through to the generic --system
        // default. If a canonical form lands for any of these
        // later, add a row in `default_strategy` AND extend this
        // assertion.
        for gap in ["gpt", "grok", "anthropic-cli"] {
            assert_eq!(
                default_strategy(gap),
                WrapStrategy::SystemFlag {
                    flag: "--system".into()
                },
                "documented #1238 gap `{gap}` must fall through to the generic --system \
                 default until a canonical upstream form is verifiable"
            );
        }
        // Unknown agent → fall through to --system.
        assert_eq!(
            default_strategy("some-future-cli"),
            WrapStrategy::SystemFlag {
                flag: "--system".into()
            }
        );
    }
}
