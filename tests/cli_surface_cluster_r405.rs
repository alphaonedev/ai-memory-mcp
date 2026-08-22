// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! R-405 CLI-surface cluster — clap-level regression pins.
//!
//! Every defect in this cluster lives in the ARG SURFACE, not in a handler:
//! a flag that is declared but never read, a subcommand-local flag silently
//! overwritten by a global env-backed one, a value the parser eats as a flag.
//! None of those are observable from a handler unit test that constructs the
//! args struct by hand — they only exist once clap has parsed a real argv.
//! So these tests drive [`ai_memory::daemon_runtime::Cli::try_parse_from`]
//! with the exact argv (and env) the operator types.
//!
//! Covered here:
//!   - #3017 `agents subkey-certs --principal` must NOT be fillable from the
//!     global env-backed `--agent-id` / `AI_MEMORY_AGENT_ID`.
//!   - #3019 `agents bind-key --pubkey <VALUE>` must accept a url-safe-no-pad
//!     base64 key whose first character is `-` or `_`.
//!   - #3013 `archive purge` must expose `--namespace` / `--confirm-global` /
//!     `--dry-run`.
//!   - #3012 `delete` must expose `--hard`.
//!   - #2815 `doctor --remote` must expose the transport-auth knobs.

use ai_memory::cli::agents::AgentsAction;
use ai_memory::cli::archive::ArchiveAction;
use ai_memory::daemon_runtime::{Cli, Command};
use clap::Parser;

/// `AI_MEMORY_AGENT_ID` is process-global and the root `--agent-id` reads it,
/// so every test in this binary that parses a `Cli` serialises on this lock.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII: pin `AI_MEMORY_AGENT_ID` to a known state for the test body and
/// restore the ambient value on drop. The caller MUST already hold
/// [`ENV_GUARD`] — that is what makes the env writes sound here.
struct AgentIdEnv(Option<String>);

impl AgentIdEnv {
    fn set(value: Option<&str>) -> Self {
        let prev = std::env::var("AI_MEMORY_AGENT_ID").ok();
        // SAFETY: `ENV_GUARD` is held by the caller, so no other test in this
        // binary reads or writes the environment concurrently.
        unsafe {
            match value {
                Some(v) => std::env::set_var("AI_MEMORY_AGENT_ID", v),
                None => std::env::remove_var("AI_MEMORY_AGENT_ID"),
            }
        }
        Self(prev)
    }
}

impl Drop for AgentIdEnv {
    fn drop(&mut self) {
        // SAFETY: as in `set` — the caller still holds `ENV_GUARD`.
        unsafe {
            match self.0.take() {
                Some(v) => std::env::set_var("AI_MEMORY_AGENT_ID", v),
                None => std::env::remove_var("AI_MEMORY_AGENT_ID"),
            }
        }
    }
}

fn parse(argv: &[&str]) -> Cli {
    Cli::try_parse_from(argv).expect("argv must parse")
}

// ---------------------------------------------------------------------------
// #3017 — subkey-certs identity must not be shadowed by the global env arg
// ---------------------------------------------------------------------------

#[test]
fn subkey_certs_principal_is_not_filled_from_agent_id_env_3017() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(Some("ai:cert-fed-proxy"));

    let cli = parse(&["ai-memory", "agents", "subkey-certs"]);
    // The global still resolves from the env — that surface is unchanged.
    assert_eq!(cli.agent_id.as_deref(), Some("ai:cert-fed-proxy"));

    let Command::Agents(agents) = cli.command else {
        panic!("expected the agents subcommand");
    };
    let Some(AgentsAction::SubkeyCerts { principal }) = agents.action else {
        panic!("expected the subkey-certs action");
    };
    // Pre-#3017 this was `Some("ai:cert-fed-proxy")`: clap propagates a
    // matched GLOBAL arg down into every subcommand's `ArgMatches`,
    // overwriting the same-named subcommand-local `--agent-id`. The certified
    // posture always exports `AI_MEMORY_AGENT_ID`, so the node-wide sub-key
    // cert inventory silently filtered to one principal and reported
    // `{"count":0}` over a populated table.
    assert_eq!(
        principal, None,
        "the node-wide sub-key cert inventory must NOT be silently \
         filtered by AI_MEMORY_AGENT_ID"
    );
}

#[test]
fn subkey_certs_principal_flag_still_filters_3017() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);
    let cli = parse(&[
        "ai-memory",
        "agents",
        "subkey-certs",
        "--principal",
        "ai:a5-agent",
    ]);
    let Command::Agents(agents) = cli.command else {
        panic!("expected the agents subcommand");
    };
    let Some(AgentsAction::SubkeyCerts { principal }) = agents.action else {
        panic!("expected the subkey-certs action");
    };
    assert_eq!(principal.as_deref(), Some("ai:a5-agent"));
}

// ---------------------------------------------------------------------------
// #3019 — a leading `-` / `_` in a url-safe-no-pad pubkey is a VALUE
// ---------------------------------------------------------------------------

#[test]
fn bind_key_accepts_leading_hyphen_pubkey_3019() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);
    // `identity export-pub` emits url-safe-no-pad base64; 2 of the 64
    // possible leading characters (`-`, `_`) made clap reject the whole
    // invocation with a usage error (exit 2) — ~1 enrollment in 40.
    for key in [
        "-e0dOKuoQ0mQF5oQxG2rL0lQx3aW7cV9nB1kJ8yT4sU",
        "_e0dOKuoQ0mQF5oQxG2rL0lQx3aW7cV9nB1kJ8yT4sU",
    ] {
        let cli = parse(&[
            "ai-memory",
            "agents",
            "bind-key",
            "--agent-id",
            "ai:a5-agent",
            "--pubkey",
            key,
        ]);
        let Command::Agents(agents) = cli.command else {
            panic!("expected the agents subcommand");
        };
        let Some(AgentsAction::BindKey { pubkey, .. }) = agents.action else {
            panic!("expected the bind-key action");
        };
        assert_eq!(pubkey, key, "the pubkey must survive parsing verbatim");
    }
}

// ---------------------------------------------------------------------------
// #3013 — `archive purge` exposes the forget-parity safety rail
// ---------------------------------------------------------------------------

#[test]
fn archive_purge_exposes_namespace_confirm_global_and_dry_run_3013() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);

    // Pre-#3013 the ENTIRE argument surface was `--older-than-days`, so this
    // argv was a usage error and the unguarded form below wiped every
    // namespace with no confirmation.
    let cli = parse(&[
        "ai-memory",
        "archive",
        "purge",
        "--namespace",
        "scratch",
        "--older-than-days",
        "30",
    ]);
    let Command::Archive(archive) = cli.command else {
        panic!("expected the archive subcommand");
    };
    let ArchiveAction::Purge {
        older_than_days,
        namespace,
        confirm_global,
        dry_run,
    } = archive.action
    else {
        panic!("expected the purge action");
    };
    assert_eq!(older_than_days, Some(30));
    assert_eq!(namespace.as_deref(), Some("scratch"));
    assert!(!confirm_global);
    assert!(!dry_run);
}

#[test]
fn archive_purge_dry_run_and_confirm_global_parse_3013() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);

    for (argv, want_confirm, want_dry) in [
        (
            vec!["ai-memory", "archive", "purge", "--dry-run"],
            false,
            true,
        ),
        (
            vec!["ai-memory", "archive", "purge", "--confirm-global"],
            true,
            false,
        ),
    ] {
        let cli = parse(&argv);
        let Command::Archive(archive) = cli.command else {
            panic!("expected the archive subcommand");
        };
        let ArchiveAction::Purge {
            confirm_global,
            dry_run,
            namespace,
            ..
        } = archive.action
        else {
            panic!("expected the purge action");
        };
        assert_eq!(confirm_global, want_confirm, "argv: {argv:?}");
        assert_eq!(dry_run, want_dry, "argv: {argv:?}");
        assert_eq!(namespace, None, "argv: {argv:?}");
    }
}

// ---------------------------------------------------------------------------
// #3012 — `delete` defaults to archive-first; `--hard` is the explicit opt-in
// ---------------------------------------------------------------------------

#[test]
fn delete_hard_is_an_explicit_opt_in_3012() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);

    for (argv, want_hard) in [
        (vec!["ai-memory", "delete", "abc123"], false),
        (vec!["ai-memory", "delete", "abc123", "--hard"], true),
    ] {
        let cli = parse(&argv);
        let Command::Delete(args) = cli.command else {
            panic!("expected the delete subcommand");
        };
        assert_eq!(args.id, "abc123");
        // The DEFAULT must be the recoverable archive-first path: pre-#3012
        // the targeted verb destroyed the last copy of the memory text while
        // the BULK `forget` stayed restorable.
        assert_eq!(args.hard, want_hard, "argv: {argv:?}");
    }
}

// ---------------------------------------------------------------------------
// #2815 — `doctor --remote` exposes the transport-auth knobs
// ---------------------------------------------------------------------------

#[test]
fn doctor_remote_exposes_transport_auth_flags_2815() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);

    // The certified enterprise posture: TLS + mandatory client-cert mTLS +
    // top-level api_key. Pre-#2815 this argv was a usage error, so a
    // certified Postgres deployment had NO working first-party doctor path.
    let cli = parse(&[
        "ai-memory",
        "doctor",
        "--remote",
        "https://memory.prod.example.com",
        "--ca-cert",
        "/etc/ai-memory/tls/ca.pem",
        "--client-cert",
        "/etc/ai-memory/tls/client.crt",
        "--client-key",
        "/etc/ai-memory/tls/client.key",
        "--api-key-file",
        "/etc/ai-memory/keys/api.key",
    ]);
    let Command::Doctor(args) = cli.command else {
        panic!("expected the doctor subcommand");
    };
    assert_eq!(
        args.remote.as_deref(),
        Some("https://memory.prod.example.com")
    );
    assert_eq!(
        args.ca_cert.as_deref(),
        Some(std::path::Path::new("/etc/ai-memory/tls/ca.pem"))
    );
    assert_eq!(
        args.client_cert.as_deref(),
        Some(std::path::Path::new("/etc/ai-memory/tls/client.crt"))
    );
    assert_eq!(
        args.client_key.as_deref(),
        Some(std::path::Path::new("/etc/ai-memory/tls/client.key"))
    );
    assert_eq!(
        args.api_key_file.as_deref(),
        Some(std::path::Path::new("/etc/ai-memory/keys/api.key"))
    );
    assert_eq!(args.api_key, None);
}

/// The mTLS pair is both-or-neither (`requires`), and the argv api-key
/// conflicts with the non-argv file form (#1927) so an operator cannot
/// silently ship a secret on argv while believing the file is in use.
#[test]
fn doctor_transport_flag_pairing_is_enforced_2815() {
    let _g = ENV_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _env = AgentIdEnv::set(None);

    for argv in [
        vec![
            "ai-memory",
            "doctor",
            "--remote",
            "https://d",
            "--client-cert",
            "/c.crt",
        ],
        vec![
            "ai-memory",
            "doctor",
            "--remote",
            "https://d",
            "--client-key",
            "/c.key",
        ],
        vec![
            "ai-memory",
            "doctor",
            "--remote",
            "https://d",
            "--api-key",
            "k",
            "--api-key-file",
            "/k.txt",
        ],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_err(),
            "must be refused at parse time: {argv:?}"
        );
    }
}
