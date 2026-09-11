// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_link` and `cmd_resolve` migrations. See `cli::store` for the
//! design pattern.

use crate::cli::CliOutput;
use crate::{color, db, validate};
use anyhow::Result;
use clap::Args;
use std::path::Path;

#[derive(Args)]
pub struct LinkArgs {
    pub source_id: String,
    pub target_id: String,
    #[arg(long, short, default_value = "related_to")]
    pub relation: String,
}

#[derive(Args)]
pub struct ResolveArgs {
    /// Resolve as an allowlisted hardened process principal.
    #[arg(long)]
    pub as_admin: bool,
    /// ID of the memory that wins (supersedes)
    pub winner_id: String,
    /// ID of the memory that loses (superseded)
    pub loser_id: String,
}

/// #3036 — resolve the active edge-signing keypair for the CLI `link`
/// surface, mirroring `mcp::mod::load_active_keypair_for_mcp_in` so a
/// CLI-created edge is signed identically to an MCP `memory_link` edge under
/// the certified all-sig-lanes posture (before #3036 every CLI edge landed
/// `attest_level=unsigned`, permanently unattestable). Resolution ladder:
/// the caller's `<agent_id>.priv` when it can sign, else the substrate
/// daemon keypair, else `None` (the key dir holds no signing key — the edge
/// is written UNSIGNED, byte-identical to the pre-#3036 behaviour). Read
/// errors degrade to the next rung rather than failing the link.
///
/// v1.0.0 #3051 (R-405) — a load error that is NOT "no such key" (mode-refused
/// `.priv`, truncated/corrupt key file, unreadable dir) is WARNED to stderr
/// before we degrade, matching the MCP twin `load_active_keypair_for_mcp_in`
/// (`src/mcp/mod.rs`). Swallowing it silently downgraded the edge to
/// `unsigned` with no operator-visible signal — indistinguishable from the
/// legitimate "no key configured" path, which is exactly the case an operator
/// running under the all-sig-lanes posture needs to be able to tell apart.
fn resolve_active_link_keypair(
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Option<crate::identity::keypair::AgentKeypair> {
    let dir = crate::identity::keypair::default_key_dir().ok()?;
    if !dir.exists() {
        return None;
    }
    if let Ok(agent_id) = crate::identity::resolve_agent_id(cli_agent_id, None) {
        match crate::identity::keypair::load(&agent_id, &dir) {
            Ok(kp) if kp.can_sign() => return Some(kp),
            Ok(_) => {}
            Err(e) => {
                warn_unless_not_found(out, &format!("keypair load failed for {agent_id}"), &e)
            }
        }
    }
    // Fallback: substrate-managed daemon keypair (created by the serve/mcp
    // boot path). Matches the MCP `active_keypair` fallback exactly.
    match crate::identity::keypair::load(crate::identity::keypair::DAEMON_KEYPAIR_LABEL, &dir) {
        Ok(kp) if kp.can_sign() => Some(kp),
        Ok(_) => None,
        Err(e) => {
            warn_unless_not_found(out, "daemon keypair load failed", &e);
            None
        }
    }
}

/// #3051 — emit `context: <error>` on stderr unless the error is an
/// ordinary "this key does not exist" (the expected, silent rung-miss).
/// The not-found discrimination is the SHARED
/// [`crate::identity::keypair::is_key_absent_error`] predicate the MCP twin
/// uses, so the two surfaces cannot drift apart.
fn warn_unless_not_found(out: &mut CliOutput<'_>, context: &str, err: &anyhow::Error) {
    if crate::identity::keypair::is_key_absent_error(err) {
        return;
    }
    let msg = format!("{err:#}");
    // Best-effort diagnostic: a broken stderr pipe must not fail the link
    // write itself, so the write result is deliberately discarded here.
    let _ = writeln!(out.stderr, "ai-memory: {context}: {msg}");
}

/// `link` handler.
pub fn cmd_link(
    db_path: &Path,
    args: &LinkArgs,
    json_out: bool,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    validate::validate_link(&args.source_id, &args.target_id, &args.relation)?;
    // v1.0.0 #2572 — REFUSE this write on a Postgres store (see `refuse_pg_store`).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "link", out)?;
    let db_path = db_path.as_path();
    let conn = db::open(db_path)?;
    // #3036 — sign the edge with the resolved keypair (MCP `memory_link`
    // precedent, `db::create_link_signed`) instead of the unsigned
    // `db::create_link`, so CLI edges carry the same `self_signed`
    // attestation MCP edges do. `None` keypair falls through to
    // `attest_level=unsigned` (byte-identical to the prior CLI behaviour).
    let keypair = resolve_active_link_keypair(cli_agent_id, out);
    let attest_level = db::create_link_signed(
        &conn,
        &args.source_id,
        &args.target_id,
        &args.relation,
        keypair.as_ref(),
    )?;
    // v1.0.0 #3403 — subscription/webhook fan-out for a CLI-originated
    // edge, through the shared funnel the MCP twin calls
    // (`crate::write_events`), with the same source-origin resolution.
    {
        let (event_namespace, event_agent_id) =
            crate::write_events::link_event_origin(&conn, &args.source_id);
        crate::write_events::link_created(
            &conn,
            db_path,
            &args.source_id,
            &event_namespace,
            event_agent_id.as_deref(),
            &crate::subscriptions::LinkCreatedEventDetails {
                target_id: args.target_id.clone(),
                relation: args.relation.clone(),
            },
        );
    }
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({"linked": true, (crate::models::field_names::ATTEST_LEVEL): attest_level})
        )?;
    } else {
        writeln!(
            out.stdout,
            "linked: {} --[{}]--> {} ({})",
            args.source_id, args.relation, args.target_id, attest_level
        )?;
    }
    Ok(())
}

/// Archive the older loser under hardened authority; preserve the winner bytes.
pub fn cmd_resolve(
    db_path: &Path,
    args: &ResolveArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    validate::validate_id(&args.winner_id)?;
    validate::validate_id(&args.loser_id)?;
    let principal =
        crate::identity::supersession::SupersessionPrincipal::from_process_environment()?;
    let request = crate::storage::supersession::SupersessionRequest {
        principal: principal.as_ref(),
        as_admin: args.as_admin,
    };
    let result = match crate::store_url::resolve_store_url(None)? {
        Some(url) if crate::store_url::is_postgres_url(&url) => {
            #[cfg(feature = "sal-postgres")]
            {
                crate::cli::doctor::run_pg_probe(|| async {
                    let store = crate::migrate::open_store(&url).await?;
                    Ok::<_, anyhow::Error>(
                        store
                            .resolve_supersession(&args.loser_id, &args.winner_id, request)
                            .await?,
                    )
                })??
            }
            #[cfg(not(feature = "sal-postgres"))]
            anyhow::bail!("PostgreSQL resolve requires the sal-postgres feature");
        }
        _ => {
            // Preserve the established fail-closed SQLite URL / --db agreement.
            let db_path = crate::cli::backup::resolve_sqlite_store(
                db_path,
                None,
                "resolve",
                crate::cli::backup::StoreDisagreement::Refuse,
                None,
                out,
            )?;
            let conn = db::open(&db_path)?;
            crate::storage::supersession::resolve(&conn, &args.loser_id, &args.winner_id, request)?
        }
    };
    if let Some(reason) = result.refusal {
        return Err(reason.into());
    }
    if json_out {
        writeln!(out.stdout, "{}", {
            let mut response = serde_json::json!({"resolved": true, "winner": args.winner_id, "loser": args.loser_id});
            result.add_response_fields(&mut response);
            response
        })?;
    } else {
        writeln!(
            out.stdout,
            "resolved: {} supersedes {}",
            color::long(&args.winner_id),
            color::dim(&args.loser_id)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    #[test]
    fn test_link_happy_path() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let args = LinkArgs {
            source_id: id1.clone(),
            target_id: id2.clone(),
            relation: "related_to".to_string(),
        };
        {
            let mut out = env.output();
            cmd_link(&db, &args, false, None, &mut out).unwrap();
        }
        assert!(
            env.stdout_str().contains("linked:"),
            "got: {}",
            env.stdout_str()
        );
        // Confirm row exists in DB.
        let conn = db::open(&db).unwrap();
        let links = db::get_links(&conn, &id1).unwrap();
        assert!(links.iter().any(|l| l.target_id == id2));
    }

    /// #3036 — a CLI-created edge must carry the SAME `self_signed`
    /// attestation an MCP `memory_link` edge does (both route through
    /// `db::create_link_signed` with the resolved keypair), NOT
    /// `attest_level=unsigned`. Provide a signing keypair on disk under a
    /// temp `AI_MEMORY_KEY_DIR` and drive `cmd_link` end-to-end.
    #[test]
    fn cli_link_signs_edge_when_keypair_present_parity_3036() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");

        let key_dir = tempfile::tempdir().unwrap();
        let kp = crate::identity::keypair::generate("ai:linker").unwrap();
        crate::identity::keypair::save(&kp, key_dir.path()).unwrap();

        // Serialize the process-global AI_MEMORY_KEY_DIR mutation.
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os("AI_MEMORY_KEY_DIR");
        // SAFETY: env mutation serialized on the key-dir lock.
        unsafe { std::env::set_var("AI_MEMORY_KEY_DIR", key_dir.path()) };

        let args = LinkArgs {
            source_id: id1.clone(),
            target_id: id2.clone(),
            relation: "related_to".to_string(),
        };
        {
            let mut out = env.output();
            // Explicit cli_agent_id so the resolved signer is `ai:linker`
            // regardless of any leaked AI_MEMORY_AGENT_ID.
            cmd_link(&db, &args, false, Some("ai:linker"), &mut out).unwrap();
        }

        // Restore BEFORE asserting so a failure never leaks the var.
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_KEY_DIR", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_KEY_DIR") },
        }

        let conn = db::open(&db).unwrap();
        let links = db::get_links(&conn, &id1).unwrap();
        let edge = links
            .iter()
            .find(|l| l.target_id == id2)
            .expect("edge exists");
        assert_eq!(
            edge.attest_level.as_deref(),
            Some(crate::models::AttestLevel::SelfSigned.as_str()),
            "CLI edge must be self_signed (#3036); got {:?}",
            edge.attest_level
        );
        // `get_links` deliberately projects `signature: None` (the raw blob
        // is the verifier's surface), so read it from the row directly to
        // prove the signature bytes actually landed.
        let sig: Option<Vec<u8>> = conn
            .query_row(
                "SELECT signature FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
                rusqlite::params![id1, id2],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            sig.is_some_and(|s| !s.is_empty()),
            "CLI edge must carry signature bytes (#3036)"
        );
    }

    /// #3051 (R-405) — a key-load failure that is NOT "no such key" must be
    /// WARNED on stderr before the CLI degrades to an unsigned edge, matching
    /// the MCP twin. Pre-fix the `_ => {}` arm swallowed it, so a
    /// mode-refused `.priv` (S4-LOW1) silently produced an unattestable edge
    /// that looked identical to the legitimate "no keypair configured" case.
    #[test]
    fn cli_link_warns_on_non_notfound_keypair_error_3051() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");

        let key_dir = tempfile::tempdir().unwrap();
        let kp = crate::identity::keypair::generate("ai:linker").unwrap();
        crate::identity::keypair::save(&kp, key_dir.path()).unwrap();
        // Widen the `.priv` mode so `keypair::load` refuses it (S4-LOW1).
        // That error message carries neither "No such file" nor "not found",
        // so it must reach stderr rather than being swallowed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let priv_path = key_dir.path().join("ai:linker.priv");
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        // Serialize the process-global AI_MEMORY_KEY_DIR mutation.
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = std::env::var_os("AI_MEMORY_KEY_DIR");
        // SAFETY: env mutation serialized on the key-dir lock.
        unsafe { std::env::set_var("AI_MEMORY_KEY_DIR", key_dir.path()) };

        let args = LinkArgs {
            source_id: id1.clone(),
            target_id: id2.clone(),
            relation: "related_to".to_string(),
        };
        {
            let mut out = env.output();
            cmd_link(&db, &args, false, Some("ai:linker"), &mut out).unwrap();
        }

        // Restore BEFORE asserting so a failure never leaks the var.
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_KEY_DIR", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_KEY_DIR") },
        }

        #[cfg(unix)]
        {
            let warned = env.stderr_str().to_string();
            assert!(
                warned.contains("keypair load failed for ai:linker")
                    && warned.contains("insecure mode"),
                "a mode-refused .priv must warn on stderr (#3051); got: {warned:?}"
            );
            // The edge still lands (degrade, never refuse) — just unsigned.
            let conn = db::open(&db).unwrap();
            let links = db::get_links(&conn, &id1).unwrap();
            let edge = links
                .iter()
                .find(|l| l.target_id == id2)
                .expect("edge exists");
            assert_eq!(
                edge.attest_level.as_deref(),
                Some(crate::models::AttestLevel::Unsigned.as_str())
            );
        }
    }

    #[test]
    fn test_link_invalid_relation_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let args = LinkArgs {
            source_id: id1,
            target_id: id2,
            relation: "totally-bogus-relation".to_string(),
        };
        let mut out = env.output();
        let res = cmd_link(&db, &args, false, None, &mut out);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("invalid relation"), "got: {msg}");
    }

    #[test]
    fn test_link_self_link_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id = seed_memory(&db, "ns", "a", "ca");
        let args = LinkArgs {
            source_id: id.clone(),
            target_id: id,
            relation: "related_to".to_string(),
        };
        let mut out = env.output();
        let res = cmd_link(&db, &args, false, None, &mut out);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("itself"), "got: {msg}");
    }

    #[test]
    fn test_link_json_output() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let args = LinkArgs {
            source_id: id1,
            target_id: id2,
            relation: "supersedes".to_string(),
        };
        {
            let mut out = env.output();
            cmd_link(&db, &args, true, None, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["linked"].as_bool().unwrap(), true);
    }

    // -----------------------------------------------------------------
    // GA-drive 2026-06-09 (per-module floor 96%) — error-branch
    // coverage for the remaining `?` propagation sites. Each fallible
    // call's closing `)?;` line carries the error-branch region; these
    // tests drive each Err path so the line counts as covered.
    // -----------------------------------------------------------------

    /// Writer that always fails — drives the `?` error branch on the
    /// `writeln!` sites (the broken-pipe propagation contract that
    /// `cli::io_writer` documents: handlers must return the I/O error,
    /// not panic).
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test writer: broken pipe",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_link_human_output_broken_pipe_propagates() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let args = LinkArgs {
            source_id: id1,
            target_id: id2,
            relation: "related_to".to_string(),
        };
        let mut failing = FailingWriter;
        let mut stderr: Vec<u8> = Vec::new();
        let mut out = CliOutput {
            stdout: &mut failing,
            stderr: &mut stderr,
        };
        let res = cmd_link(&db, &args, false, None, &mut out);
        assert!(res.is_err(), "broken pipe must propagate, not panic");
    }

    #[test]
    fn test_link_json_output_broken_pipe_propagates() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let id1 = seed_memory(&db, "ns", "a", "ca");
        let id2 = seed_memory(&db, "ns", "b", "cb");
        let args = LinkArgs {
            source_id: id1,
            target_id: id2,
            relation: "related_to".to_string(),
        };
        let mut failing = FailingWriter;
        let mut stderr: Vec<u8> = Vec::new();
        let mut out = CliOutput {
            stdout: &mut failing,
            stderr: &mut stderr,
        };
        let res = cmd_link(&db, &args, true, None, &mut out);
        assert!(res.is_err(), "broken pipe must propagate, not panic");
    }
}
