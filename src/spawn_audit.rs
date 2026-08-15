// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 V08-PE-3 (#1937) — MINIMAL signed spawn-audit chokepoint.
//!
//! # Ratified spec (the `4d3ea1c5` minimal shape, #1840 closing 2×5 vote)
//!
//! Emit exactly **one** signed `signed_events`-table row (see
//! [`crate::signed_events`]) per PRODUCTION `Command` spawn, carrying
//! **`argv0` + `caller`**, by
//! reusing the existing [`crate::signed_events::SignedEvent::with_daemon_signature`]
//! idiom. Explicitly **NO eBPF / NO dtrace** — the substrate attests its OWN
//! spawns, not the kernel's process tree. Claims-safe: v0.8/v0.9 advertise no
//! subprocess-chain-visibility, so no shipped claim depends on this.
//!
//! # Chokepoint design (the anti-regression core)
//!
//! Every production subprocess launch routes through ONE audited helper
//! ([`audited_command`] for `std::process::Command`, [`audited_tokio_command`]
//! for the async `tokio::process::Command`). The helper emits the signed
//! audit row (best-effort) and returns a ready-to-configure `Command`. A
//! CI gate (`tests/spawn_audit_gate_1937.rs`) asserts NO raw `Command::new`
//! escapes this module in production code — so a NEW un-audited spawn site
//! fails CI. This makes the audit coverage future-proof: you cannot add a
//! production spawn without either routing it through the chokepoint or
//! tripping the gate.
//!
//! # Wired production spawn sites (#1937 acceptance item 1)
//!
//! | Site | Program | Caller const |
//! |---|---|---|
//! | `cli::helpers::auto_namespace` | `git` | [`CALLER_CLI_NAMESPACE_GIT`] |
//! | `cli::doctor::nvidia_gpu_detected` | `nvidia-smi` | [`CALLER_CLI_DOCTOR_GPU`] |
//! | `cli::wrap::build_command_for_strategy` | wrapped agent | [`CALLER_CLI_WRAP_AGENT`] |
//! | `hooks::executor` exec path | hook command | [`CALLER_HOOK_EXEC`] |
//! | `hooks::executor` daemon path | hook command | [`CALLER_HOOK_DAEMON`] |
//!
//! # Keyless-context handling (#1937 design guidance, M-PANIC-IS-STOP)
//!
//! Audit is best-effort OBSERVABILITY — it MUST NOT block or fail a spawn.
//! The two soft-failure modes are handled gracefully, never by panic:
//!
//! - **No signing key** — [`crate::signed_events::SignedEvent::with_daemon_signature`]
//!   already falls back to `attest_level = "unsigned"` + `signature: None`
//!   when no daemon audit key is enrolled (the same posture as
//!   `reflection.decorrelation_refused` / `egress.inference_refused`).
//! - **No resolvable audit DB** — a spawn site (e.g. CLI `doctor` running
//!   before the boot seed, or a unit test that never booted) has no seeded
//!   audit DB path. [`emit_spawn_audit_best_effort`] then SKIPS with a trace
//!   line and the spawn proceeds unaudited. The boot path
//!   ([`crate::daemon_runtime::run`]) seeds the resolved DB path via
//!   [`seed_spawn_audit_db_path`] so every serve / mcp / CLI subcommand
//!   dispatch has a live audit target.
//!
//! # sqlite + postgres parity (#1937 acceptance item 4)
//!
//! The sqlite production emission opens a short-lived connection at the seeded
//! DB path (mirroring the shipped #1963 `refuse_inference_egress_audited`
//! precedent). The identical spawn-audit ROW shape persists + verifies on
//! postgres via [`crate::store::postgres::PostgresStore::emit_spawn_audit`];
//! both backends build the row from the SAME [`spawn_audit_payload_hash`]
//! pre-image and the SAME `with_daemon_signature` idiom, and both walk it
//! through their (K3-parity) `verify_audit_trail` twin.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Result;
use rusqlite::Connection;

use crate::signed_events::{
    SignedEvent, append_signed_event, event_types::PROCESS_SPAWN_AUDITED, payload_hash,
};

// ---------------------------------------------------------------------------
// Caller-identity SSOT (M-DOCUMENTED-MAGIC). Each spawn site passes its own
// stable `caller` slug so a downstream auditor can attribute a spawn row to
// the exact production site without decoding argv. One const per site keeps
// the strings out of the scattered call sites (pm-v3.1 no-literals discipline).
// ---------------------------------------------------------------------------

/// Caller slug for the `git remote get-url origin` spawn in
/// [`crate::cli::helpers::auto_namespace`].
pub const CALLER_CLI_NAMESPACE_GIT: &str = "cli::helpers::auto_namespace";

/// Caller slug for the `nvidia-smi -L` GPU-detection spawn in
/// `crate::cli::doctor::nvidia_gpu_detected`.
pub const CALLER_CLI_DOCTOR_GPU: &str = "cli::doctor::nvidia_gpu_detected";

/// Caller slug for the wrapped-agent spawn built in
/// `crate::cli::wrap::build_command_for_strategy`.
pub const CALLER_CLI_WRAP_AGENT: &str = "cli::wrap::build_command_for_strategy";

/// Caller slug for the per-fire hook-command exec spawn in
/// `crate::hooks::executor` (`ExecExecutor`).
pub const CALLER_HOOK_EXEC: &str = "hooks::executor::exec_fire";

/// Caller slug for the long-lived daemon-mode hook-command spawn in
/// `crate::hooks::executor` (`DaemonExecutor`).
pub const CALLER_HOOK_DAEMON: &str = "hooks::executor::daemon_connect";

/// Field separator for the canonical spawn-audit pre-image. A single ASCII
/// `|` mirrors the [`crate::egress::emit_inference_egress_refusal`] pre-image
/// grammar; `argv0` / `caller` never contain a raw `|`-delimited structural
/// ambiguity that matters because the auditor reads back the labelled fields,
/// not a positional parse.
const PREIMAGE_TAG: &str = "spawn-audit";

/// Process-wide audit DB path, seeded once at boot by
/// [`seed_spawn_audit_db_path`]. `None` until seeded (early boot / unit
/// tests) → [`emit_spawn_audit_best_effort`] skips with a trace line.
static SPAWN_AUDIT_DB_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Seed the process-wide audit DB path for the best-effort spawn-audit
/// emission. Called once from the top-level CLI dispatch
/// ([`crate::daemon_runtime::run`]) right after the effective DB path is
/// resolved, so every serve / mcp / CLI subcommand has a live audit target
/// before any production spawn fires. Idempotent — first writer wins
/// (mirrors `crate::quotas::set_quota_defaults`); a later call is a silent
/// no-op, which keeps re-entrant test harnesses from panicking.
pub fn seed_spawn_audit_db_path(path: &Path) {
    let _ = SPAWN_AUDIT_DB_PATH.set(path.to_path_buf());
}

/// The seeded audit DB path, or `None` when unseeded.
#[must_use]
fn audit_db_path() -> Option<&'static PathBuf> {
    SPAWN_AUDIT_DB_PATH.get()
}

/// Canonical, secret-free pre-image bytes for a spawn-audit row.
///
/// Carries ONLY `argv0` (the spawned program) + `caller` (the spawn-site
/// identity) — deliberately NOT the full argv, which can carry secrets
/// (#1937 spec). Shared by the sqlite emitter and the postgres twin so both
/// backends produce a byte-identical `payload_hash` (K3 parity).
#[must_use]
pub fn spawn_audit_preimage(argv0: &str, caller: &str) -> String {
    format!("{PREIMAGE_TAG}|argv0={argv0}|caller={caller}")
}

/// SHA-256 `payload_hash` over [`spawn_audit_preimage`]. The single hashing
/// site both backends call, so the postgres parity row and the sqlite
/// production row commit to identical bytes.
#[must_use]
pub fn spawn_audit_payload_hash(argv0: &str, caller: &str) -> Vec<u8> {
    payload_hash(spawn_audit_preimage(argv0, caller).as_bytes())
}

/// Lossy `argv0` for the audit pre-image + log lines. The spawned program is
/// an `OsStr`; a non-UTF-8 program path is rendered with the standard lossy
/// conversion (readability outweighs fidelity for an audit attribution — the
/// governance wire-check matcher, not this row, is the load-bearing binary
/// gate).
fn argv0_lossy(program: &OsStr) -> String {
    program.to_string_lossy().into_owned()
}

/// Build + append ONE signed `process.spawn_audited` row using an open
/// sqlite connection. Reuses the `with_daemon_signature` idiom (daemon-signed
/// when an audit key is enrolled, else `unsigned`); the sqlite append
/// chokepoint ([`append_signed_event`]) re-signs the daemon row over the full
/// identity tuple (#1925) exactly as for every other producer.
///
/// # Errors
///
/// Propagates the underlying [`append_signed_event`] error (typically a
/// sqlite failure). Callers treat the emission as best-effort and WARN on
/// error rather than failing the spawn (M-PANIC-IS-STOP: audit never blocks).
pub fn emit_spawn_audit(conn: &Connection, argv0: &str, caller: &str) -> Result<()> {
    let event = SignedEvent::with_daemon_signature(
        spawn_audit_payload_hash(argv0, caller),
        crate::identity::sentinels::DAEMON_PRINCIPAL.to_string(),
        PROCESS_SPAWN_AUDITED.to_string(),
        chrono::Utc::now().to_rfc3339(),
        None,
    );
    append_signed_event(conn, &event)
}

/// Best-effort audited emission for the spawn chokepoint, which holds a
/// program name (not an open connection). Resolves the seeded audit DB path,
/// opens a short-lived connection — mirroring
/// [`crate::egress::refuse_inference_egress_audited`] — appends the signed
/// row, and WARNs on any failure WITHOUT disturbing the spawn (the caller
/// spawns the child regardless).
///
/// Keyless-context handling (M-PANIC-IS-STOP): an unseeded DB path (early
/// boot / no-daemon unit test) SKIPS with a `debug` trace line — never a
/// panic, never a blocked spawn.
pub fn emit_spawn_audit_best_effort(argv0: &str, caller: &str) {
    let Some(db_path) = audit_db_path() else {
        tracing::debug!(
            target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
            argv0, caller,
            "spawn-audit skipped: no audit DB path seeded (pre-boot / no-daemon context)"
        );
        return;
    };
    match crate::db::open(db_path) {
        Ok(conn) => {
            // #1937 — the spawn-audit is best-effort observability on the spawn
            // HOT PATH; cap the WAL write-lock wait (default open path uses 5s,
            // `storage::connection`) so a contended audit write can never add
            // meaningful latency to — let alone block — the child spawn. On
            // BUSY it errors fast and the WARN arm below records the miss; the
            // spawn proceeds regardless (M-PANIC-IS-STOP: audit never gates a
            // spawn).
            let _ = conn.busy_timeout(std::time::Duration::from_millis(250));
            if let Err(e) = emit_spawn_audit(&conn, argv0, caller) {
                tracing::warn!(
                    target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                    argv0, caller,
                    "spawn-audit row NOT recorded (append failed): {e}"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                target: crate::signed_events::SIGNED_EVENTS_TRACE_TARGET,
                argv0, caller,
                "spawn-audit row NOT recorded (db open failed): {e}"
            );
        }
    }
}

/// THE production chokepoint for a `std::process::Command` spawn. Emits ONE
/// best-effort signed `process.spawn_audited` row for `program` + `caller`,
/// then returns a fresh `std::process::Command::new(program)` for the caller
/// to configure (args / env / stdio) and spawn. Every production
/// `std::process::Command` launch MUST route through here — the CI gate
/// forbids a raw `Command::new` in production code outside this module.
#[must_use]
pub fn audited_command<S: AsRef<OsStr>>(program: S, caller: &str) -> std::process::Command {
    emit_spawn_audit_best_effort(&argv0_lossy(program.as_ref()), caller);
    std::process::Command::new(program)
}

/// THE production chokepoint for a `tokio::process::Command` spawn (the async
/// hook executor path). Emits ONE best-effort signed `process.spawn_audited`
/// row, then returns a fresh `tokio::process::Command::new(program)`. The
/// returned command is built ONCE and re-`spawn()`-ed across the executor's
/// transient-errno retry ladder, so the audit row is emitted exactly once per
/// logical spawn (not per retry).
#[must_use]
pub fn audited_tokio_command<S: AsRef<OsStr>>(program: S, caller: &str) -> tokio::process::Command {
    // M4 / rust `M-BLOCKING-IN-ASYNC` / `async-spawn-blocking` (#2007): the
    // best-effort emit opens a sqlite connection via `crate::db::open` — the full
    // schema/migrate/rollback-check funnel, SYNCHRONOUS I/O. This chokepoint fires
    // on the async hook-executor path (`hooks::executor`), so an inline emit would
    // block a tokio worker per hook-fired spawn. Route the blocking open+append
    // onto the blocking pool (fire-and-forget — the spawn NEVER waits;
    // M-PANIC-IS-STOP: audit never gates a spawn). With no runtime present (a
    // non-async caller / unit test) fall back to a synchronous emit so the
    // seeded-path / no-key skip semantics are byte-identical either way.
    let argv0 = argv0_lossy(program.as_ref());
    let caller_owned = caller.to_string();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || emit_spawn_audit_best_effort(&argv0, &caller_owned));
        }
        Err(_) => emit_spawn_audit_best_effort(&argv0, &caller_owned),
    }
    tokio::process::Command::new(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_is_secret_free_and_labelled() {
        let pre = spawn_audit_preimage("git", CALLER_CLI_NAMESPACE_GIT);
        assert_eq!(
            pre,
            "spawn-audit|argv0=git|caller=cli::helpers::auto_namespace"
        );
        // argv0 + caller ONLY — the pre-image must never carry positional args.
        assert!(
            !pre.contains("--"),
            "pre-image must not carry full argv: {pre}"
        );
    }

    #[test]
    fn payload_hash_is_stable_and_field_sensitive() {
        let a = spawn_audit_payload_hash("git", CALLER_CLI_NAMESPACE_GIT);
        let a2 = spawn_audit_payload_hash("git", CALLER_CLI_NAMESPACE_GIT);
        let b = spawn_audit_payload_hash("nvidia-smi", CALLER_CLI_DOCTOR_GPU);
        assert_eq!(a, a2, "same inputs → same hash");
        assert_ne!(a, b, "distinct inputs → distinct hash");
        assert_eq!(a.len(), 32, "SHA-256 is 32 bytes");
    }

    #[test]
    fn caller_slugs_are_distinct() {
        let slugs = [
            CALLER_CLI_NAMESPACE_GIT,
            CALLER_CLI_DOCTOR_GPU,
            CALLER_CLI_WRAP_AGENT,
            CALLER_HOOK_EXEC,
            CALLER_HOOK_DAEMON,
        ];
        let mut sorted = slugs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), slugs.len(), "caller slugs must be unique");
    }

    #[test]
    fn best_effort_is_a_noop_without_a_seeded_db_path() {
        // No DB seeded in this unit-test context → the best-effort emitter
        // skips gracefully (never panics, M-PANIC-IS-STOP).
        emit_spawn_audit_best_effort("git", CALLER_CLI_NAMESPACE_GIT);
    }

    #[test]
    fn audited_command_returns_a_usable_command() {
        // The chokepoint returns a configurable Command even with no audit
        // target seeded; the spawn must never be blocked by the audit.
        let mut cmd = audited_command("true", CALLER_CLI_NAMESPACE_GIT);
        cmd.arg("--version");
        let program = cmd.get_program().to_string_lossy().into_owned();
        assert_eq!(program, "true");
    }

    #[tokio::test]
    async fn tokio_chokepoint_returns_usable_command_off_reactor() {
        // #2007 — inside a tokio runtime the audit emit is routed onto the
        // blocking pool (the `Handle::try_current().Ok` arm), so the chokepoint
        // returns a configurable Command WITHOUT running the synchronous
        // `db::open` funnel on the reactor thread. No seeded audit DB here, so
        // the off-reactor emit is itself a graceful no-op; the point is that the
        // call returns a usable Command and never panics/blocks.
        let mut cmd = audited_tokio_command("true", CALLER_HOOK_EXEC);
        cmd.arg("--version");
        let program = cmd.as_std().get_program().to_string_lossy().into_owned();
        assert_eq!(program, "true");
        // Yield so any spawned blocking task can run to completion (no assertion
        // on its result — it is best-effort observability).
        tokio::task::yield_now().await;
    }

    #[test]
    fn emit_writes_one_verifiable_row() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-audit-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("audit.db");
        {
            let conn = crate::db::open(&path).expect("init db");
            emit_spawn_audit(&conn, "git", CALLER_CLI_NAMESPACE_GIT).expect("emit");
        }
        let conn = crate::db::open(&path).expect("reopen");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                [PROCESS_SPAWN_AUDITED],
                |r| r.get(0),
            )
            .expect("count spawn rows");
        assert_eq!(count, 1, "exactly one process.spawn_audited row expected");
        // The row is a first-class member of the chain — verify_audit_trail
        // walks it and reports a clean, intact chain.
        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must be intact: {report:?}");
        assert_eq!(
            report.total_events, 1,
            "the spawn row is counted: {report:?}"
        );
    }
}
