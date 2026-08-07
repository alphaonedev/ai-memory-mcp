// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_forget` migration. See `cli::store` for the design pattern.
//!
//! ## Round-2 F11 — global-scope safety rail
//!
//! `forget --pattern <p>` and `forget --tier <t>` without `--namespace`
//! delete across every namespace in the database. That has been the
//! contract since v0.6.x, but it is a sharp edge: a typo in `--pattern`
//! can wipe the operator's working set with no confirmation.
//!
//! v0.7.0 adds a `--confirm-global` flag. When `--namespace` is omitted
//! AND (`--pattern` or `--tier` is set) the handler refuses to proceed
//! unless `--confirm-global` is also present. `forget --id` is fine
//! because the id is unambiguous; `forget --namespace` is fine because
//! the blast radius is bounded.

use crate::cli::CliOutput;
use crate::{db, models};
use anyhow::{Result, bail};
use clap::Args;
use models::Tier;
use std::path::Path;

#[derive(Args)]
pub struct ForgetArgs {
    #[arg(long, short)]
    pub namespace: Option<String>,
    #[arg(long, short)]
    pub pattern: Option<String>,
    #[arg(long, short)]
    pub tier: Option<String>,
    /// Round-2 F11 — required when `--namespace` is omitted and either
    /// `--pattern` or `--tier` is set, since those flags then delete
    /// across every namespace in the database. Without `--namespace`
    /// the handler refuses to run without this confirmation.
    #[arg(long, default_value_t = false)]
    pub confirm_global: bool,
    /// #1832 (TRACT-gap G18) — QUERY-ONLY: print the SIGNED ERASURE ATTESTATION
    /// (forget receipt) for an already-forgotten `<memory_id>` instead of
    /// forgetting anything. The receipt is the proof-of-erasure the substrate
    /// already recorded at forget time (identity + time, NEVER content). Its
    /// `signed` flag is `false` on an unsigned daemon. Not a covenant-enforcement
    /// guarantee — see `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §8.
    #[arg(long, value_name = "MEMORY_ID")]
    pub show_receipt: Option<String>,
    /// #1832 (TRACT-gap G18) — QUERY-ONLY: verify the forget receipt for an
    /// already-forgotten `<memory_id>` against the daemon audit key, recomputing
    /// the canonical signable bytes from the receipt itself. Prints
    /// `valid`/`invalid`/`unsigned`/`no key`. Does not forget anything.
    #[arg(long, value_name = "MEMORY_ID")]
    pub verify_receipt: Option<String>,
}

/// Round-2 F11 — return the safety-rail error string when the operator
/// invoked a global-scope `forget` without the `--confirm-global`
/// opt-in. Pulled out so the integration test in
/// `tests/round2_f11_forget_safety.rs` can assert on the exact
/// wording without coupling to handler-internal control flow.
#[must_use]
pub fn global_scope_forget_error_message() -> &'static str {
    "global-scope forget requires --confirm-global; restrict with --namespace=<ns> for safety"
}

/// Round-2 F11 — predicate used by both the CLI handler and the
/// integration test. Returns `true` when the args describe a
/// global-scope delete (no `--namespace`, but `--pattern` or `--tier`
/// set) and `--confirm-global` was NOT supplied.
#[must_use]
pub fn requires_global_confirmation(args: &ForgetArgs) -> bool {
    let no_namespace = args.namespace.is_none();
    let has_global_filter = args.pattern.is_some() || args.tier.is_some();
    no_namespace && has_global_filter && !args.confirm_global
}

/// `forget` handler. Deletes (and archives) memories matching at least
/// one of namespace/pattern/tier. CLI always passes `archive=true`.
pub fn cmd_forget(
    db_path: &Path,
    args: &ForgetArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // #1832 — QUERY-ONLY sub-modes: inspect / verify a past forget's receipt.
    // These never forget; they short-circuit before the delete path.
    if let Some(id) = args.show_receipt.as_deref() {
        return cmd_show_receipt(db_path, id, json_out, out);
    }
    if let Some(id) = args.verify_receipt.as_deref() {
        return cmd_verify_receipt(db_path, id, json_out, out);
    }

    // Round-2 F11 — refuse global-scope deletes without explicit
    // confirmation. The error is propagated via `bail!` (not stderr +
    // process::exit) so test code can assert on the message without
    // killing the test process.
    if requires_global_confirmation(args) {
        bail!(global_scope_forget_error_message());
    }

    let tier = args.tier.as_deref().and_then(Tier::from_str);
    // v1.0.0 #2572 — REFUSE this erasure on a Postgres store (see `refuse_pg_store`).
    // The query-only receipt sub-modes above short-circuit before this and carry
    // their own guard.
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "forget", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    // v1.0.0 #2446 — resolve the FULL matched id set BEFORE the delete
    // commits (same connection, synchronous), so the federated erasure
    // outbox can queue every erased id. Empty + free when undrainable.
    let outbox_ids = crate::federation::erasure_outbox::collect_forget_ids(
        &conn,
        args.namespace.as_deref(),
        args.pattern.as_deref(),
        tier.as_ref(),
        None,
    );
    match db::forget(
        &conn,
        args.namespace.as_deref(),
        args.pattern.as_deref(),
        tier.as_ref(),
        true, // always archive from CLI
    ) {
        Ok(n) => {
            // Best-effort + infallible: never converts a previously-local,
            // always-succeeding erasure into an error.
            crate::federation::erasure_outbox::enqueue_erasures(
                &conn,
                &outbox_ids,
                crate::federation::erasure_outbox::surfaces::CLI_FORGET,
            );
            if json_out {
                writeln!(out.stdout, "{}", serde_json::json!({"deleted": n}))?;
            } else {
                writeln!(out.stdout, "forgot {n} memories")?;
            }
        }
        Err(e) => {
            writeln!(out.stderr, "{}", crate::errors::msg::error_line(&e))?;
            std::process::exit(1);
        }
    }
    Ok(())
}

/// #1832 — base64 (url-safe, no pad) render of a receipt signature, matching
/// the witness/approval-key encoding used elsewhere in the CLI.
fn sig_b64(sig: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
}

/// #1832 — `forget --show-receipt <id>`: print the signed erasure attestation
/// for an already-forgotten memory id. Query-only.
fn cmd_show_receipt(
    db_path: &Path,
    memory_id: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE on a Postgres store (a phantom SQLite read returns
    // an empty conjured database; see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "forget --show-receipt", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let Some(receipt) = db::get_forget_tombstone(&conn, memory_id)? else {
        if json_out {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({"memory_id": memory_id, "receipt": null})
            )?;
        } else {
            writeln!(out.stdout, "no forget receipt for {memory_id}")?;
        }
        return Ok(());
    };
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "memory_id": receipt.memory_id,
                "namespace": receipt.namespace,
                "forgotten_at": receipt.forgotten_at,
                "agent_id": receipt.agent_id,
                "signed": receipt.signed,
                "signature": receipt.signature.as_deref().map(sig_b64),
            })
        )?;
    } else {
        writeln!(out.stdout, "forget receipt for {}", receipt.memory_id)?;
        writeln!(out.stdout, "  namespace:    {}", receipt.namespace)?;
        writeln!(out.stdout, "  forgotten_at: {}", receipt.forgotten_at)?;
        writeln!(
            out.stdout,
            "  agent_id:     {}",
            receipt.agent_id.as_deref().unwrap_or("(none)")
        )?;
        match receipt.signature.as_deref() {
            Some(sig) => writeln!(out.stdout, "  signature:    {} (signed)", sig_b64(sig))?,
            None => writeln!(
                out.stdout,
                "  signature:    (unsigned — daemon had no enrolled audit key)"
            )?,
        }
    }
    Ok(())
}

/// #1832 — `forget --verify-receipt <id>`: verify the forget receipt's
/// signature against the daemon audit key. Query-only. Reuses the same
/// verifying-key resolution ladder as `verify-audit-trail` (`src/cli/audit.rs`).
fn cmd_verify_receipt(
    db_path: &Path,
    memory_id: &str,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // v1.0.0 #2572 — REFUSE on a Postgres store (a phantom SQLite read returns
    // an empty conjured database; see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "forget --verify-receipt", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    let Some(receipt) = db::get_forget_tombstone(&conn, memory_id)? else {
        if json_out {
            writeln!(
                out.stdout,
                "{}",
                serde_json::json!({"memory_id": memory_id, "verdict": "no receipt"})
            )?;
        } else {
            writeln!(out.stdout, "no forget receipt for {memory_id}")?;
        }
        return Ok(());
    };

    // Resolve the daemon audit verifying key (same ladder as verify-audit-trail).
    let agent_id =
        crate::identity::resolve_agent_id(None, None).unwrap_or_else(|_| "ai-memory".to_string());
    let verifying_key =
        crate::governance::audit::load_daemon_verifying_key(&agent_id).unwrap_or(None);

    let verdict = match (&verifying_key, receipt.signed) {
        // No key on this host — cannot verify a signed receipt here.
        (None, true) => "no key",
        (Some(vk), _) => match db::verify_forget_receipt(&receipt, vk) {
            db::ForgetReceiptVerdict::Valid => "valid",
            db::ForgetReceiptVerdict::Invalid => "invalid",
            db::ForgetReceiptVerdict::Unsigned => "unsigned",
        },
        // Unsigned receipt, no key needed to say so.
        (None, false) => "unsigned",
    };

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "memory_id": receipt.memory_id,
                "namespace": receipt.namespace,
                "forgotten_at": receipt.forgotten_at,
                "signed": receipt.signed,
                "verdict": verdict,
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "forget receipt {}: {verdict}",
            receipt.memory_id
        )?;
    }
    // A tampered/invalid signature is a hard failure signal for scripting.
    // Propagated via `bail!` (the module's round-2 F11 discipline: not
    // stderr + process::exit, which skips destructors and cannot be
    // asserted in-process) — the CLI top-level renders the error and maps
    // it to exit code 1. The verdict line above has already been written,
    // so scripting consumers get both the structured verdict and the
    // non-zero exit.
    if verdict == "invalid" {
        bail!(
            "forget receipt {}: signature verification FAILED (invalid)",
            receipt.memory_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    fn args() -> ForgetArgs {
        ForgetArgs {
            namespace: None,
            pattern: None,
            tier: None,
            confirm_global: false,
            show_receipt: None,
            verify_receipt: None,
        }
    }

    #[test]
    fn test_forget_by_namespace() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "alpha", "a", "ca");
        let _ = seed_memory(&db, "beta", "b", "cb");
        let mut a = args();
        a.namespace = Some("alpha".to_string());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_u64().unwrap(), 1);
        // beta still present.
        let conn = db::open(&db).unwrap();
        let still = db::list(
            &conn,
            Some("beta"),
            None,
            10,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert_eq!(still.len(), 1);
    }

    #[test]
    fn test_forget_by_pattern() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "apple pie", "yum");
        let _ = seed_memory(&db, "ns", "banana split", "also yum");
        let mut a = args();
        a.pattern = Some("apple".to_string());
        // Round-2 F11 — `forget --pattern` without `--namespace` is a
        // global delete and now requires the operator opt-in.
        a.confirm_global = true;
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_u64().unwrap(), 1);
    }

    #[test]
    fn test_forget_by_tier() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id_long = seed_memory(&db, "ns", "long-row", "x");
        let _ = seed_memory(&db, "ns", "mid-row", "y");
        {
            let conn = db::open(&db).unwrap();
            db::update(
                &conn,
                &id_long,
                None,
                None,
                Some(&Tier::Long),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }
        let mut a = args();
        a.tier = Some(Tier::Long.as_str().to_string());
        // Round-2 F11 — `forget --tier` without `--namespace` requires
        // the global confirmation flag.
        a.confirm_global = true;
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["deleted"].as_u64().unwrap(), 1);
    }

    #[test]
    fn test_forget_combined_filters() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "alpha", "apple-1", "x");
        let _ = seed_memory(&db, "beta", "apple-2", "y");
        let _ = seed_memory(&db, "alpha", "banana", "z");
        let mut a = args();
        a.namespace = Some("alpha".to_string());
        a.pattern = Some("apple".to_string());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // Only the alpha+apple row should be removed.
        assert_eq!(v["deleted"].as_u64().unwrap(), 1);
        let conn = db::open(&db).unwrap();
        let beta_apples = db::list(
            &conn,
            Some("beta"),
            None,
            10,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert_eq!(beta_apples.len(), 1);
    }

    #[test]
    fn test_forget_no_filter_errors_or_no_op() {
        // db::forget bails when no filter is supplied. The handler turns
        // that into an stderr line + std::process::exit(1) — which we
        // can't observe in-process. Surface the bail by calling db::forget
        // directly so the test asserts the underlying contract.
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "x", "y");
        let conn = db::open(&db).unwrap();
        let res = db::forget(&conn, None, None, None, false);
        assert!(res.is_err(), "no-filter forget must error");
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("at least one of namespace, pattern, or tier")
        );
    }

    // ---- Round-2 F11 safety-rail unit tests ------------------------------

    #[test]
    fn requires_global_confirmation_pattern_no_namespace() {
        let mut a = args();
        a.pattern = Some("apple".into());
        assert!(requires_global_confirmation(&a));
    }

    #[test]
    fn requires_global_confirmation_tier_no_namespace() {
        let mut a = args();
        a.tier = Some(Tier::Long.as_str().into());
        assert!(requires_global_confirmation(&a));
    }

    #[test]
    fn does_not_require_confirmation_when_namespace_present() {
        let mut a = args();
        a.namespace = Some("ns".into());
        a.pattern = Some("apple".into());
        assert!(!requires_global_confirmation(&a));
    }

    #[test]
    fn does_not_require_confirmation_when_only_namespace_set() {
        let mut a = args();
        a.namespace = Some("ns".into());
        // No pattern, no tier — `forget --namespace=ns` is bounded.
        assert!(!requires_global_confirmation(&a));
    }

    #[test]
    fn does_not_require_confirmation_when_confirm_flag_set() {
        let mut a = args();
        a.pattern = Some("apple".into());
        a.confirm_global = true;
        assert!(!requires_global_confirmation(&a));
    }

    #[test]
    fn cmd_forget_refuses_global_pattern_without_confirm() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "apple pie", "yum");
        let mut a = args();
        a.pattern = Some("apple".into());
        let mut out = env.output();
        let res = cmd_forget(&db, &a, true, &mut out);
        assert!(res.is_err(), "expected refusal");
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("--confirm-global"), "got: {msg}");
    }

    #[test]
    fn cmd_forget_proceeds_with_confirm_global() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "apple pie", "yum");
        let _ = seed_memory(&db, "other", "apple cake", "yum");
        let mut a = args();
        a.pattern = Some("apple".into());
        a.confirm_global = true;
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // Both rows match — global delete succeeded under explicit
        // confirmation.
        assert_eq!(v["deleted"].as_u64().unwrap(), 2);
    }

    #[test]
    fn test_forget_text_output_count() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "a", "x");
        let _ = seed_memory(&db, "ns", "b", "y");
        let mut a = args();
        a.namespace = Some("ns".to_string());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, false, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("forgot 2 memories"), "got: {stdout}");
    }

    // ---- #1832 forget-receipt query sub-modes -----------------------------

    #[test]
    fn show_receipt_after_forget_returns_unsigned_receipt() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "gone", "bye");
        // Forget it (records the tombstone).
        {
            let mut a = args();
            a.namespace = Some("ns".to_string());
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        // Now inspect the receipt for the forgotten id.
        let mut a = args();
        a.show_receipt = Some(id.clone());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        // stdout carries both the forget line and the receipt line — the
        // receipt JSON is the last line.
        let last = env.stdout_str().trim().lines().last().unwrap().to_string();
        let v: serde_json::Value = serde_json::from_str(&last).unwrap();
        assert_eq!(v["memory_id"].as_str().unwrap(), id);
        assert_eq!(v["namespace"].as_str().unwrap(), "ns");
        // The test daemon has no enrolled audit key → unsigned receipt.
        assert_eq!(v["signed"].as_bool().unwrap(), false);
        assert!(v["signature"].is_null());
        assert!(v["forgotten_at"].as_str().is_some());
    }

    #[test]
    fn show_receipt_missing_id_reports_none() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut a = args();
        a.show_receipt = Some("never-forgotten".to_string());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["receipt"].is_null());
    }

    #[test]
    fn verify_receipt_unsigned_daemon_reports_unsigned() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "gone", "bye");
        {
            let mut a = args();
            a.namespace = Some("ns".to_string());
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let mut a = args();
        a.verify_receipt = Some(id.clone());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let last = env.stdout_str().trim().lines().last().unwrap().to_string();
        let v: serde_json::Value = serde_json::from_str(&last).unwrap();
        // No enrolled audit key + unsigned tombstone → "unsigned".
        assert_eq!(v["verdict"].as_str().unwrap(), "unsigned");
        assert_eq!(v["signed"].as_bool().unwrap(), false);
    }

    #[test]
    fn show_receipt_does_not_forget() {
        // The query sub-mode must never delete: a live row survives an
        // invocation that carries --show-receipt.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _ = seed_memory(&db, "ns", "keep", "me");
        let mut a = args();
        a.namespace = Some("ns".to_string()); // present but must be IGNORED
        a.show_receipt = Some("whatever".to_string());
        {
            let mut out = env.output();
            cmd_forget(&db, &a, true, &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let still = db::list(
            &conn,
            Some("ns"),
            None,
            10,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(still.len(), 1, "show-receipt must not forget anything");
    }
}
