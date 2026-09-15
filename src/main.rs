// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// v0.7.0 ARCH-12 (med/low review batch) — match the lib crate's
// `recursion_limit = "512"` so macro-heavy code (clap derive, schemars
// derive, etc.) that lands in `main.rs` does not surprise-hit a tighter
// cap than the same code compiled through the lib target. The 256 default
// historically sufficed when `main.rs` was a near-empty shim; keeping the
// two compile units in lockstep prevents drift surprises.
#![recursion_limit = "512"]

// W6 reduced `main.rs` to a thin shim: every CLI subcommand and the HTTP
// daemon body now live in `ai_memory::daemon_runtime`. The bin keeps its
// `#[tokio::main]` entry point + the bootstrap calls (color init, config
// load, env-var seeding, clap parse) and immediately delegates. Coverage
// for serve()/dispatch is now attributed to the lib crate.
use ai_memory::daemon_runtime::Cli;
use ai_memory::{audit, color, config, daemon_runtime, logging, permissions};
use anyhow::Result;
use clap::Parser;

#[cfg(test)]
use ai_memory::cli::helpers::{human_age, id_short};
#[cfg(test)]
use ai_memory::tls;

// COVERAGE NOTE (FUPC): the `#[tokio::main] async fn main()` body
// (lines ~30-97 below) is the real process entry point. It is
// UNREACHABLE from any in-process test — it performs `Cli::parse()`
// (reads the live process argv), installs process-wide singletons
// (color init, OnceLock-backed permissions/hmac/audit posture) and
// can call `std::process::exit(78)` on a bad hmac secret, which would
// abort the test harness. Its individual steps are covered indirectly:
//   - `config::AppConfig::load_for_boot` / `write_default_if_missing` — config tests
//     (+ `tests/boot_fail_closed_config_3166.rs` drives the real binary)
//   - `daemon_runtime::apply_startup_env` / `apply_anonymize_default` — daemon_runtime tests
//   - `config::set_active_permissions_mode` / `set_active_hooks_hmac_secret`
//     / `set_allow_loopback_webhooks` — config tests
//   - `subscriptions::validate_hmac_secret_hex` — subscriptions tests
//   - `permissions::set_active_permission_rules` — permissions tests
//   - `logging::init_file_logging` / `audit::init_from_config` — their
//     own module tests
//   - `init_forensic_audit` — see `tests::init_forensic_audit_*` below
//   - `daemon_runtime::run` — the serve_*/cli_*/cov_* integration suite
// The `std::process::exit(78)` arm (invalid hmac secret) is documented
// as uncoverable: exercising it would terminate the test process.
// #1889 — the entry point is a SYNCHRONOUS `fn main()`, not `#[tokio::main]`.
// `#[tokio::main]` expands to a `fn main()` that builds a multi-threaded runtime
// (spawning worker threads) and only THEN runs the async body — so any
// `std::env::set_var` in that body races with those workers (glibc UB; `unsafe`
// in edition 2024). Doing config-load + `Cli::parse` + ALL process-environment
// seeding (`apply_startup_env`) here, on the single main thread BEFORE
// `Runtime::block_on`, makes the "no other thread touches the environment"
// invariant actually true. The async daemon body then runs under a manually
// built runtime that mirrors the previous `#[tokio::main]` default
// (multi-thread + all drivers enabled).
fn main() -> Result<()> {
    color::init();

    // #3166 — parse argv FIRST. `Cli::parse()` reads only the process argv
    // (and exits on its own for `--version` / `--help` / a usage error), so it
    // has no dependency on the config. Doing it before the config load means
    // (a) a malformed `config.toml` can never make `ai-memory --version`
    // unusable, and (b) the boot-refusal below knows WHICH subcommand was
    // asked for. It also still runs up front so `apply_startup_env` can read
    // `--db-passphrase-file`.
    let cli = Cli::parse();

    // #3329 / TASK-01 — config-path advisories are emitted before tracing is
    // initialised, so an explicitly quiet boot seeds the one-way suppression
    // latch before config resolution. Path selection remains unchanged.
    if matches!(
        &cli.command,
        daemon_runtime::Command::Boot(args) if args.quiet
    ) {
        config::suppress_config_boot_warnings();
    }

    // #3166 — FAIL CLOSED on a config that exists but cannot be honoured.
    //
    // The pre-#3166 `AppConfig::load()` swallowed a TOML syntax error, a
    // secret-validation rejection, and every io error (EACCES/EIO were
    // indistinguishable from the documented ENOENT) and returned
    // `AppConfig::default()`. `effective_db` then resolved the RELATIVE
    // `ai-memory.db`, so a one-character typo in a config carrying
    // `db = "/var/lib/ai-memory/prod.db"` made the daemon open/create a fresh
    // empty database in `$PWD`, report healthy, and accept writes into that
    // orphan — corpus split-brain, the prime-directive violation. In the same
    // stroke `[storage].append_only`, `[governance].require_operator_pubkey`
    // and `[[permissions.rules]]` silently reverted to their defaults.
    //
    // A MISSING config file is still the documented "compiled defaults" case
    // (`AppConfig::load_for_boot` matches `ErrorKind::NotFound` explicitly),
    // and `AI_MEMORY_NO_CONFIG=1` still short-circuits to defaults, so CI and
    // the test suite are byte-identical.
    // #3715 carve-out 1 — the `config` verbs (`check` / `migrate` / `show`)
    // are the repair tools for a refused config: they read the file through
    // `toml::Value` themselves and never depend on the boot loader, so they
    // do not run it (running it would print the refusal they exist to
    // explain, ahead of their own report).
    let is_config_verb = matches!(&cli.command, daemon_runtime::Command::Config(_));
    // #3715 / the #2445 disposition — `backup` / `export` take the durable
    // text OUT and must not be locked behind a config key the daemon refuses:
    // they load with the KNOWN keys applied (so `db` is the configured one,
    // never the relative default) and the refusal text as a loud WARN.
    let is_egress_verb = matches!(
        &cli.command,
        daemon_runtime::Command::Backup(_)
            | daemon_runtime::Command::Export(_)
            | daemon_runtime::Command::ExportForensicBundle(_)
    );
    let app_config = match if is_config_verb {
        Ok(config::AppConfig::default())
    } else if is_egress_verb && !config::skip_config() {
        config::AppConfig::config_path().map_or_else(
            || Ok(config::AppConfig::default()),
            |p| {
                config::AppConfig::try_load_from_optional_for_egress(&p).map(|(cfg, warn)| {
                    if let Some(w) = warn {
                        eprintln!(
                            "ai-memory: WARN {w}\nai-memory: continuing for this EGRESS verb with \
                             the KNOWN keys applied (#3715 / #2445 disposition): your durable \
                             text is taken from the CONFIGURED `db`, but `serve` / `mcp` and \
                             every writing verb REFUSE this config until the key is fixed."
                        );
                    }
                    cfg
                })
            },
        )
    } else {
        config::AppConfig::load_for_boot()
    } {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("ai-memory: config is UNUSABLE — {e:#}");
            if config_tolerant_command(&cli.command) {
                eprintln!(
                    "ai-memory: continuing on COMPILED DEFAULTS for this read-only \
                     diagnostic / config-repair subcommand — every config-backed \
                     setting (including `db`) is being IGNORED, so treat its output \
                     as describing the defaults, not your configuration (#3166)."
                );
                config::AppConfig::default()
            } else {
                eprintln!(
                    "ai-memory: boot REFUSED (#3166) — nothing was started and no \
                     database was opened. Continuing on compiled defaults would open \
                     the relative `ai-memory.db` in the current directory instead of \
                     the configured `db` (corpus split-brain) and would revert \
                     [storage].append_only, [governance].require_operator_pubkey and \
                     [[permissions.rules]]. Fix the file, then re-run. \
                     `ai-memory doctor` and `ai-memory config` still run."
                );
                std::process::exit(config::EX_CONFIG);
            }
        }
    };
    config::AppConfig::write_default_if_missing();

    // #1889 — ALL env mutation (passphrase-file export + anonymize seeding)
    // happens HERE, synchronously, before any thread (tracing appender worker,
    // tokio runtime workers) exists. See `daemon_runtime::apply_startup_env`.
    daemon_runtime::apply_startup_env(&cli, &app_config)?;

    // Wave-1 S1 / Wave-2 B3 — singleton-sqlite fail-closed at-rest gate.
    // After `--db-passphrase-file` has been seeded. Passphrase without
    // sqlcipher refuses; ENCRYPT_AT_REST engages ChaCha and boots.
    // `doctor` still opens so it can surface a passphrase refusal as a
    // Storage Critical (plus a WARN on default-plaintext standalone).
    let is_doctor = matches!(&cli.command, daemon_runtime::Command::Doctor(_));
    if !is_doctor {
        ai_memory::storage::refuse_at_rest_requested_without_sqlcipher()?;
    }

    // #2386 (v1.0.0 #1961 posture) — resolve + enforce the security posture
    // HERE too, under the same #1889 pre-runtime contract: under `asi-hard`
    // the enforcement PINS every unset fail-closed knob via
    // `std::env::set_var`, which must never run once the tracing appender
    // worker (spawned by `init_file_logging` below) or a tokio runtime
    // worker exists. Fail-closed: a loosening override or a garbage posture
    // token aborts the boot right here, before anything else starts. The
    // async body logs the stashed pin report via the READ-ONLY
    // `security_profile::runtime_boot_report`.
    // #3714 — the deployment shape derives the posture: under a hardened
    // shape an unset `AI_MEMORY_SECURITY_PROFILE` is pinned to `asi-hard`
    // (same `set_var` pre-runtime contract as the KNOBS pins below) and a
    // `standard` override refuses; the at-rest floor is checked here too.
    // MUST precede `security_profile::enforce_at_boot_pre_runtime` so the
    // posture enforcement observes the pin. `doctor` still runs so it can
    // report a shape refusal.
    match ai_memory::config::shape::enforce_at_boot_pre_runtime(&app_config) {
        Ok(_) => {}
        // `doctor` reports a shape refusal in its "Deployment shape"
        // section instead of dying on it (the pin is simply not applied).
        Err(e) if is_doctor => eprintln!("ai-memory: WARN shape enforcement: {e:#}"),
        Err(e) => return Err(e),
    }

    // v1.0.0 #3700 — the deployment-shape DETECTOR (read-only): holds the
    // configured signals (peers, bindings, allowlist, forward URL, wake hub,
    // monitoring scopes) against the DECLARED shape. A hardened declared
    // shape with any pinned knob below its floor refuses here, naming EVERY
    // disabled knob; configuration that looks like a stricter shape than
    // declared is WARNED and recorded, never re-postured (promotion is an
    // operator act). `doctor` never refuses — it reports the detector.
    if !is_doctor {
        let argv = match &cli.command {
            daemon_runtime::Command::Serve(args) => Some((
                !args.quorum_peers.is_empty(),
                args.mtls_allowlist.as_deref(),
            )),
            daemon_runtime::Command::SyncDaemon(args) => Some((!args.peers.is_empty(), None)),
            _ => None,
        };
        // Daemon entry points announce an undeclared promotion on stderr;
        // one-shot verbs stay quiet (hooks capture stderr).
        let announce = argv.is_some();
        ai_memory::config::shape::detector::assess_pre_runtime(&app_config, argv, announce)?;
    }
    ai_memory::security_profile::enforce_at_boot_pre_runtime()?;

    // v1.0.0 #3124 — the unstamped-row mutation posture is a mandate-class
    // knob: an unrecognised token refuses boot (naming the knob, the token and
    // the grammar) instead of being guessed. `doctor` stays runnable so it can
    // report the bad value.
    if !is_doctor {
        ai_memory::identity::owner_stamp::validate_boot_token()?;
    }

    // v1.0.0 #3705 — "only encrypted data in transit": the selector token
    // (one grammar; falsy or unrecognised REFUSES, never proceeds in
    // cleartext), the removed downgrade paths (a set hatch refuses) and the
    // config-carried outbound URLs. Read-only. `doctor` never refuses — it
    // reports the transit posture of every surface instead.
    if !is_doctor {
        ai_memory::transit_encryption::enforce_process_floor()?;
        ai_memory::transit_encryption::enforce_config_urls(&app_config)?;
    }

    // #3582: evaluate the argv peer lists even with quorum_writes=0, before
    // workers or stores start. Doctor must remain able to diagnose refusal.
    match &cli.command {
        daemon_runtime::Command::Serve(args) => {
            ai_memory::federation::peer_posture::enforce_at_boot(
                !args.quorum_peers.is_empty(),
                args.mtls_allowlist.as_deref(),
            )?;
            // v1.0.0 #3705 — a plaintext peer URL is refused pre-runtime, even
            // with quorum_writes=0 (where FederationConfig::build never runs).
            for peer in &args.quorum_peers {
                ai_memory::tls::validate_peer_url_scheme(peer)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
        }
        daemon_runtime::Command::SyncDaemon(args) => {
            ai_memory::federation::peer_posture::enforce_at_boot(!args.peers.is_empty(), None)?;
            for peer in &args.peers {
                ai_memory::tls::validate_peer_url_scheme(peer)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
        }
        _ => {}
    }

    // v1.0.0 §5.3 (3x7 cutline ruling, 2026-08-01) — the opt-in
    // enterprise-federation certified-posture boot gate. Same #1889
    // pre-runtime contract as the call directly above (this function is
    // itself read-only, but is kept in the same synchronous phase for a
    // single boot-refusal call site). No-op (byte-identical legacy boot)
    // unless `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is truthy.
    // Runs AFTER the asi-hard enforcement above so it observes the
    // already-pinned asi-hard knobs. See
    // `src/enterprise_federation_posture.rs`.
    //
    // #3003 — `ai-memory doctor --posture <name>` is THE read-only diagnostic
    // for this very gate: it renders the per-control PASS/FAIL report the boot
    // refusal points the operator at, and it computes the contracted exit
    // codes itself (`cli::doctor::run_posture` → 0 PASS / 2 FAIL). It MUST NOT
    // be caught by the boot refusal — otherwise, with the gate armed+failing,
    // the diagnostic the remediation names exits 1 (a generic anyhow-bail CLI
    // error) instead of the contracted 2, and the operator is told to re-run
    // the command that just refused. Bypass the gate for that one subcommand
    // so the report always renders and the exit code is the contracted 2.
    let is_posture_doctor = matches!(
        &cli.command,
        daemon_runtime::Command::Doctor(a) if a.posture.is_some()
    );
    if !is_posture_doctor {
        ai_memory::enterprise_federation_posture::enforce_at_boot_pre_runtime(&app_config)?;
    }

    // v0.7.0 K3 — pin the process-wide governance gate posture before
    // any subcommand has a chance to call `db::enforce_governance`.
    // Idempotent (`OnceLock::set`); first writer wins.
    config::set_active_permissions_mode(app_config.effective_permissions_mode());

    // v0.7.0 K7 — pin the process-wide webhook HMAC override (if any)
    // before the daemon spawns any subscription-dispatch worker thread.
    // Idempotent; the dispatcher reads via
    // `crate::config::active_hooks_hmac_secret` and falls back to the
    // per-subscription secret when unset.
    //
    // v0.7.0 #1048 (Agent-5 #8) — validate that the operator-supplied
    // `hmac_secret` is valid hex BEFORE installing it. The runtime
    // `subscriptions::hmac_sha256_hex` falls back to using the raw
    // config bytes as HMAC key material when the hex decode fails —
    // wire-stable but the WEAK-key posture is not what the operator
    // configured. Surface the misconfiguration at boot so the
    // operator fixes it before traffic flows.
    let resolved_hmac_secret = app_config.effective_hooks_hmac_secret();
    if let Err(msg) =
        ai_memory::subscriptions::validate_hmac_secret_hex(resolved_hmac_secret.as_deref())
    {
        eprintln!("ai-memory: boot refused — #1048 invalid hmac_secret\n  {msg}");
        std::process::exit(config::EX_CONFIG); // sysexits.h EX_CONFIG (#3166)
    }
    config::set_active_hooks_hmac_secret(resolved_hmac_secret);

    // v0.7.0 H11 (#628 blocker) — pin the loopback-webhook opt-in. The
    // SSRF guard in `validate_url` rejects loopback URLs by default;
    // operators who need to point a webhook at a local listener (CI,
    // dev) set `[subscriptions] allow_loopback_webhooks = true`.
    config::set_allow_loopback_webhooks(app_config.effective_allow_loopback_webhooks());
    // v1.0.0 #3705 — the webhook dispatcher's extra root certificate
    // (`[subscriptions] ca_cert`): a configured file that cannot be read or
    // parsed refuses boot — an unreachable receiver is loud, never silent.
    if let Some(path) = app_config
        .subscriptions
        .as_ref()
        .and_then(|s| s.ca_cert.as_deref())
    {
        let pem = std::fs::read(path).map_err(|e| {
            anyhow::anyhow!(
                "[subscriptions] ca_cert {}: cannot read: {e} (#3705)",
                path.display()
            )
        })?;
        ai_memory::subscriptions::install_dispatch_root_certificate(&pem)?;
    }

    // v0.7.0 K9 — load `[[permissions.rules]]` into the process-wide
    // registry consulted by `Permissions::evaluate`. Empty by default
    // (pre-K9 behaviour: mode + hooks + governance gate decide
    // everything).
    permissions::set_active_permission_rules(app_config.effective_permission_rules());

    // v0.9.0 G6 (#1823) / PR-2 — arm the append-only revision spine in the
    // #1889 synchronous pre-runtime phase, BEFORE the tokio runtime is built
    // and BEFORE any CLI subcommand dispatches through `daemon_runtime::run`.
    // A CLI write (`ai-memory store` / `undo-edit` / `curator`, the real
    // offline-write attack surface) is armed the moment `main` resolves config,
    // not only the direct library callers of `run`. Resolves
    // `AI_MEMORY_APPEND_ONLY` env > `[storage].append_only` > compiled `false`;
    // the resolved default is `false`, so a default deployment is byte-identical.
    // Idempotent with the (`#[cfg(not(test))]`-gated) seed inside `run`. Pinned
    // by `tests/append_only_boot_seed.rs`.
    config::set_append_only(app_config.resolve_storage().append_only);

    // PR-5 (issue #487): bootstrap operational logging + security
    // audit trail. Both are default-OFF; init returns silently when
    // disabled. The `_log_guard` MUST stay in scope for the lifetime
    // of the process — when dropped it flushes the non-blocking
    // tracing writer to disk.
    let _log_guard =
        logging::init_file_logging(&app_config.effective_logging()).unwrap_or_else(|e| {
            eprintln!("ai-memory: file logging init failed (continuing without): {e}");
            None
        });
    if let Err(e) = audit::init_from_config(&app_config.effective_audit()) {
        eprintln!("ai-memory: audit init failed (continuing without): {e}");
    }

    // v0.7.0 #697 — bootstrap the Ed25519-signed forensic governance
    // log alongside the flat audit chain. Same resolved directory as
    // the flat audit log; daily-rotated `forensic-<YYYY-MM-DD>.jsonl`
    // files chained + signed by the daemon's Ed25519 key (when one is
    // enrolled). The sink is process-wide; failures here are logged
    // and swallowed so a missing key never blocks daemon startup.
    init_forensic_audit(&app_config);

    // v1.0.0 L4 (PR-3) — resolve the out-of-band audit pin HERE, in the same
    // SYNCHRONOUS pre-runtime phase as the posture enforcement above (the #1889
    // contract). The `--audit-pubkey` flag (highest precedence) or the
    // `AI_MEMORY_AUDIT_PUBKEY` env is decoded to an `Option<VerifyingKey>` ONCE
    // and threaded as an explicit parameter into `daemon_runtime::run` — never
    // re-published to the process environment via `set_var` (the #2905 env-leak
    // class). A malformed pin aborts the boot here rather than silently
    // verifying against nothing. Only the `verify-audit-trail` subcommand
    // carries the flag; every other command resolves the pin from the env alone
    // (or `None`), which is inert for them.
    let audit_pubkey_flag = match &cli.command {
        daemon_runtime::Command::VerifyAuditTrail(a) => a.audit_pubkey.as_deref(),
        _ => None,
    };
    let audit_pubkey = ai_memory::governance::audit::resolve_audit_pubkey(audit_pubkey_flag)?;

    // #1889 — build the async runtime AFTER all env seeding is done, then hand
    // off to the daemon body. Mirrors the `#[tokio::main]` default (multi-thread
    // scheduler, all drivers enabled). `_log_guard` stays in scope across the
    // whole `block_on` so the non-blocking tracing writer flushes on exit.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(daemon_runtime::run(cli, &app_config, audit_pubkey.as_ref()));
    if result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<daemon_runtime::FatalShutdownError>()
            .is_some()
    }) {
        // EX_TEMPFAIL. Exit before dropping the runtime: a synchronous writer
        // that missed its shutdown deadline may be uncancellable, while its
        // fsynced deferred-audit spool remains boot-recoverable.
        std::process::exit(75);
    }
    result
}

/// #3166 — the ONLY subcommands allowed to keep running on compiled defaults
/// when `config.toml` exists but cannot be honoured.
///
/// The set is deliberately tiny and justified per member:
///
/// * `doctor` — the verb an operator reaches for BECAUSE the config is
///   broken. Refusing it would hide the very fault it exists to surface; it
///   instead REPORTS the breakage in its own `Configuration` section
///   (`cli::doctor::section_config_health_3166`).
/// * `config` — the repair verb (`config migrate`), which reads and rewrites
///   the broken file directly and has its own parse-error exit codes.
/// * `completions` / `man` — pure argv-to-stdout generators. They open no
///   database and read no config-backed setting.
///
/// Everything else — including `boot`, which would otherwise serve an agent
/// its first-turn context out of the WRONG database — fails closed. Reading
/// the wrong corpus is a wrong ANSWER, which the data-integrity directive
/// ranks with corruption, not with degraded function.
fn config_tolerant_command(cmd: &daemon_runtime::Command) -> bool {
    matches!(
        cmd,
        daemon_runtime::Command::Doctor(_)
            | daemon_runtime::Command::Config(_)
            | daemon_runtime::Command::Completions(_)
            | daemon_runtime::Command::Man
            // #3715 carve-out 1 — the K11 `[[governance.policy]]` translator
            // is a config REPAIR tool (parses via `toml::Value`); a
            // fail-closed loader whose repair path sits behind the same
            // gate is a lockout, not a control.
            | daemon_runtime::Command::Governance(daemon_runtime::GovernanceCliArgs {
                action: daemon_runtime::GovernanceAction::MigrateToPermissions(_),
                ..
            })
    )
}

/// v0.7.0 #697 / v1.0.0 #3647 — best-effort init of the forensic log on the
/// directory parallel to the flat audit log. The sink comes up on every boot,
/// so its content-free integrity rows (the #1850 truncation watermark the
/// `verify-audit-trail` lanes read, the #3199 unverified-restore record) are
/// written by default, and so are the screened governance decision rows
/// (Conductor ruling on #3647). A missing key gives unsigned rows and withheld
/// commitments — never a fatal error.
fn init_forensic_audit(app_config: &config::AppConfig) {
    let audit_cfg = app_config.effective_audit();
    let agent_id = ai_memory::identity::resolve_agent_id(None, None)
        .unwrap_or_else(|_| "ai-memory".to_string());
    let signing_key =
        ai_memory::governance::audit::load_daemon_signing_key(&agent_id).unwrap_or(None);
    // The database audit signers must not depend on the forensic directory
    // resolving or being creatable (#3647).
    ai_memory::governance::audit::init_audit_signers(signing_key.as_ref());
    let log_path = ai_memory::audit::resolve_audit_path(&audit_cfg);
    let Some(dir) = log_path.parent() else {
        eprintln!("ai-memory: forensic init skipped (could not resolve audit dir)");
        return;
    };
    warn_if_plaintext_retention_requested(&audit_cfg);
    if let Err(e) = ai_memory::governance::audit::init(dir, signing_key) {
        eprintln!("ai-memory: forensic audit init failed (continuing unsigned): {e}");
    }
}

/// #3647 — `audit.redact_content = false` asks for plaintext retention, which
/// is unsupported. It is ignored with a diagnostic rather than silently: the
/// forensic decision rows stay written and stay screened (keyed commitments
/// only). Removing the operator's evidence is never the answer to a
/// disclosure concern (Conductor ruling on #3647). Returns whether the
/// diagnostic fired.
fn warn_if_plaintext_retention_requested(audit_cfg: &config::AuditConfig) -> bool {
    if audit_cfg.redact_content != Some(false) {
        return false;
    }
    eprintln!(
        "ai-memory: audit.redact_content=false (plaintext retention) is unsupported and \
         ignored: forensic governance decision rows record keyed commitments only (#3647)"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forensic_boot_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    const ISSUE_3647_BOOT_SECRET: &str = "ISSUE_3647_DEFAULT_BOOT_SECRET";

    /// Boot `init_forensic_audit` on a scratch audit directory, then emit one
    /// sentinel-bearing decision row and one watermark, and return every row
    /// the real JSONL holds (plus the raw text).
    fn boot_and_emit_3647(
        enabled: Option<bool>,
        redact_content: Option<bool>,
    ) -> (Vec<ai_memory::governance::audit::ForensicDecision>, String) {
        let _ = ai_memory::identity::test_key_dir::install();
        let tmp = tempfile::tempdir().expect("scratch audit directory");
        let app_config = config::AppConfig {
            audit: Some(config::AuditConfig {
                path: Some(tmp.path().join("audit.log").to_string_lossy().into_owned()),
                enabled,
                redact_content,
                ..Default::default()
            }),
            ..Default::default()
        };
        ai_memory::governance::audit::shutdown();
        init_forensic_audit(&app_config);
        assert!(
            ai_memory::governance::audit::is_enabled(),
            "the sink comes up on every boot (#1850 watermark lane)"
        );
        ai_memory::governance::audit::record_decision(
            "agent:3647",
            "refuse",
            "bash",
            "R3647",
            ai_memory::governance::audit::ForensicPayload::new()
                .commit("reason", ISSUE_3647_BOOT_SECRET),
        );
        ai_memory::governance::audit::record_audit_watermark(64, &"ab".repeat(32), Some("db3647"));
        ai_memory::governance::audit::shutdown();
        let mut body = String::new();
        for entry in std::fs::read_dir(tmp.path()).expect("directory") {
            let path = entry.expect("entry").path();
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("forensic-"))
            {
                body.push_str(&std::fs::read_to_string(path).expect("JSONL"));
            }
        }
        let rows = body
            .lines()
            .map(|line| serde_json::from_str(line).expect("row"))
            .collect();
        (rows, body)
    }

    /// Conductor ruling on #3647: every boot, whatever `audit.enabled` says,
    /// writes the screened decision row next to the integrity row.
    #[test]
    fn issue_3647_every_boot_writes_screened_decision_rows_and_integrity_rows() {
        let _guard = forensic_boot_lock();
        for enabled in [None, Some(false), Some(true)] {
            let (rows, body) = boot_and_emit_3647(enabled, None);
            assert_screened_decision_then_watermark(&rows, &body);
        }
    }

    /// `redact_content = false` is ignored with a diagnostic; the decision row
    /// is still written, and still screened.
    #[test]
    fn issue_3647_plaintext_request_is_ignored_and_rows_stay_screened() {
        let _guard = forensic_boot_lock();
        assert!(warn_if_plaintext_retention_requested(
            &config::AuditConfig {
                redact_content: Some(false),
                ..Default::default()
            }
        ));
        assert!(!warn_if_plaintext_retention_requested(
            &config::AuditConfig::default()
        ));
        let (rows, body) = boot_and_emit_3647(Some(true), Some(false));
        assert_screened_decision_then_watermark(&rows, &body);
    }

    fn assert_screened_decision_then_watermark(
        rows: &[ai_memory::governance::audit::ForensicDecision],
        body: &str,
    ) {
        assert!(!body.contains(ISSUE_3647_BOOT_SECRET));
        assert_eq!(rows.len(), 2, "decision + watermark: {rows:?}");
        assert_eq!(rows[0].actor, "agent:3647");
        assert_eq!(rows[0].decision, "refuse");
        assert_eq!(rows[0].rule_id, "R3647");
        // Keyed when a daemon key resolves, withheld when unsigned; never text.
        let reason = rows[0].payload["reason"].as_str().expect("reason");
        assert!(
            reason == ai_memory::governance::audit::FORENSIC_COMMITMENT_WITHHELD
                || reason.starts_with(ai_memory::governance::audit::FORENSIC_COMMITMENT_PREFIX),
            "reason must be a commitment: {reason}"
        );
        assert_eq!(
            rows[1].kind,
            ai_memory::governance::audit::AUDIT_WATERMARK_KIND
        );
        assert_eq!(rows[1].payload["head_sequence"], 64);
        assert_eq!(rows[1].payload["db_id"], "db3647");
    }

    #[test]
    fn id_short_truncates() {
        assert_eq!(id_short("abcdefghijklmnop"), "abcdefgh");
    }

    #[test]
    fn id_short_short_input() {
        assert_eq!(id_short("abc"), "abc");
    }

    #[test]
    fn id_short_empty() {
        assert_eq!(id_short(""), "");
    }

    #[test]
    fn human_age_just_now() {
        let now = chrono::Utc::now().to_rfc3339();
        assert_eq!(human_age(&now), "just now");
    }

    #[test]
    fn human_age_minutes() {
        let past = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("m ago"), "got: {age}");
    }

    #[test]
    fn human_age_hours() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("h ago"), "got: {age}");
    }

    #[test]
    fn human_age_days() {
        let past = (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
        let age = human_age(&past);
        assert!(age.contains("d ago"), "got: {age}");
    }

    #[test]
    fn human_age_invalid_returns_input() {
        assert_eq!(human_age("not-a-date"), "not-a-date");
    }

    #[test]
    fn auto_namespace_returns_nonempty() {
        let ns = ai_memory::cli::helpers::auto_namespace();
        assert!(!ns.is_empty());
    }

    // Issue #358: parser must accept inline trailing comments after a
    // fingerprint, in addition to the existing full-line `#` comment skip.
    #[tokio::test]
    async fn fingerprint_allowlist_tolerates_trailing_comments() {
        let fp_a = "a".repeat(64);
        let fp_b = "b".repeat(64);
        let fp_c = format!("{}:{}", "c".repeat(32), "c".repeat(32));
        let body = format!(
            "# authorised mTLS peers\n\
             {fp_a}  # node-1\n\
             \n\
             sha256:{fp_b}\t# node-2 with tab\n\
             {fp_c}\n"
        );
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), body).unwrap();
        let set = tls::load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 3, "expected 3 fingerprints, got {}", set.len());
        assert!(set.contains(&[0xaa; 32]));
        assert!(set.contains(&[0xbb; 32]));
        assert!(set.contains(&[0xcc; 32]));
    }

    /// FUPC — `init_forensic_audit` resolves the audit dir (here pinned
    /// to a temp path via `AI_MEMORY_AUDIT_DIR`), loads the (absent)
    /// daemon signing key, and brings the sink up. A missing key is a
    /// non-fatal unsigned-rows posture, never a panic. Exercises the
    /// happy path through `resolve_audit_path` → `dir.parent()` →
    /// `governance::audit::init`.
    #[test]
    fn init_forensic_audit_with_temp_dir_does_not_panic() {
        let _guard = forensic_boot_lock();
        let _ = ai_memory::identity::test_key_dir::install();
        // Scratch under the repo's gitignored .local-runs/ per the
        // project no-/tmp HARD RULE.
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local-runs")
            .join("main-init-forensic-audit");
        std::fs::create_dir_all(&root).ok();
        let tmp = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
        let prev = std::env::var("AI_MEMORY_AUDIT_DIR").ok();
        // SAFETY: single-threaded test process; env set/restore is local.
        unsafe { std::env::set_var("AI_MEMORY_AUDIT_DIR", tmp.path()) };

        let app_config = config::AppConfig::default();
        // Must not panic and must leave the process bootable (unsigned).
        init_forensic_audit(&app_config);

        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_AUDIT_DIR", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_AUDIT_DIR") },
        }
    }

    #[tokio::test]
    async fn fingerprint_allowlist_rejects_embedded_whitespace() {
        // Ultrareview #338 strictness preserved — whitespace before the
        // `#` is fine (gets trimmed), but whitespace inside the hex run
        // still errors so soft-wrap copy-paste artefacts are caught.
        let body = format!("{} {}\n", "a".repeat(32), "a".repeat(32));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), body).unwrap();
        let err = tls::load_fingerprint_allowlist(tmp.path())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unexpected character"),
            "expected strict char-set error, got: {err}"
        );
    }
}
