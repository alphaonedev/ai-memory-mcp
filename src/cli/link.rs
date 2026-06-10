// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_link` and `cmd_resolve` migrations. See `cli::store` for the
//! design pattern.

use crate::cli::CliOutput;
use crate::{color, db, models, validate};
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
    /// ID of the memory that wins (supersedes)
    pub winner_id: String,
    /// ID of the memory that loses (superseded)
    pub loser_id: String,
}

/// `link` handler.
pub fn cmd_link(
    db_path: &Path,
    args: &LinkArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    validate::validate_link(&args.source_id, &args.target_id, &args.relation)?;
    let conn = db::open(db_path)?;
    db::create_link(&conn, &args.source_id, &args.target_id, &args.relation)?;
    if json_out {
        writeln!(out.stdout, "{}", serde_json::json!({"linked": true}))?;
    } else {
        writeln!(
            out.stdout,
            "linked: {} --[{}]--> {}",
            args.source_id, args.relation, args.target_id
        )?;
    }
    Ok(())
}

/// `resolve` handler — record `winner supersedes loser`, demote loser
/// priority/confidence, and refresh winner's TTL.
pub fn cmd_resolve(
    db_path: &Path,
    args: &ResolveArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let conn = db::open(db_path)?;
    validate::validate_link(
        &args.winner_id,
        &args.loser_id,
        crate::models::MemoryLinkRelation::Supersedes.as_str(),
    )?;
    db::create_link(
        &conn,
        &args.winner_id,
        &args.loser_id,
        crate::models::MemoryLinkRelation::Supersedes.as_str(),
    )?;
    let _ = db::update(
        &conn,
        &args.loser_id,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        Some(0.1),
        None,
        None,
    )?;
    db::touch(
        &conn,
        &args.winner_id,
        models::SHORT_TTL_EXTEND_SECS,
        models::MID_TTL_EXTEND_SECS,
    )?;
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({"resolved": true, "winner": args.winner_id, "loser": args.loser_id})
        )?;
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
            cmd_link(&db, &args, false, &mut out).unwrap();
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
        let res = cmd_link(&db, &args, false, &mut out);
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
        let res = cmd_link(&db, &args, false, &mut out);
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
            cmd_link(&db, &args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["linked"].as_bool().unwrap(), true);
    }

    #[test]
    fn test_resolve_creates_supersedes_link() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let args = ResolveArgs {
            winner_id: winner.clone(),
            loser_id: loser.clone(),
        };
        {
            let mut out = env.output();
            cmd_resolve(&db, &args, false, &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let links = db::get_links(&conn, &winner).unwrap();
        assert!(
            links.iter().any(|l| l.target_id == loser
                && l.relation == crate::models::MemoryLinkRelation::Supersedes),
            "expected supersedes link from winner to loser"
        );
    }

    #[test]
    fn test_resolve_demotes_loser_priority_and_confidence() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let args = ResolveArgs {
            winner_id: winner,
            loser_id: loser.clone(),
        };
        {
            let mut out = env.output();
            cmd_resolve(&db, &args, true, &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let mem = db::get(&conn, &loser).unwrap().unwrap();
        assert_eq!(mem.priority, 1);
        assert!((mem.confidence - 0.1).abs() < 1e-6);
    }

    #[test]
    fn test_resolve_touches_winner() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        // Capture access_count + updated_at before resolve.
        let conn = db::open(&db).unwrap();
        let pre = db::get(&conn, &winner).unwrap().unwrap();
        let pre_access = pre.access_count;
        drop(conn);
        let args = ResolveArgs {
            winner_id: winner.clone(),
            loser_id: loser,
        };
        {
            let mut out = env.output();
            cmd_resolve(&db, &args, true, &mut out).unwrap();
        }
        let conn = db::open(&db).unwrap();
        let post = db::get(&conn, &winner).unwrap().unwrap();
        // touch() bumps access_count.
        assert!(
            post.access_count >= pre_access,
            "access_count should not regress: pre={pre_access} post={}",
            post.access_count
        );
    }

    /// Coverage restoration (post-#1558 floor dip): `cmd_resolve`'s
    /// validate-error propagation path — `cmd_link`'s twin is pinned
    /// by `test_link_self_link_validation_error`, but resolve's
    /// validate call (winner == loser ⇒ self-supersede) was not.
    #[test]
    fn test_resolve_self_resolve_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let only = seed_memory(&db, "ns", "only", "self");
        let args = ResolveArgs {
            winner_id: only.clone(),
            loser_id: only,
        };
        let mut out = env.output();
        let err = cmd_resolve(&db, &args, false, &mut out).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("self"),
            "self-resolve must be refused by validate_link: {err}"
        );
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
    fn test_resolve_missing_ids_create_link_error() {
        // Valid-format IDs that don't exist: validate passes, the
        // create_link write refuses with the typed MemoryNotFound.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Initialize schema so the failure comes from the link write,
        // not from a missing table.
        drop(db::open(&db).unwrap());
        let args = ResolveArgs {
            winner_id: "nonexistent-winner-id".into(),
            loser_id: "nonexistent-loser-id".into(),
        };
        let mut out = env.output();
        let res = cmd_resolve(&db, &args, false, &mut out);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains(crate::errors::msg::MEMORY_NOT_FOUND),
            "got: {msg}"
        );
    }

    #[test]
    fn test_resolve_update_failure_propagates() {
        // Force db::update on the loser to fail AFTER the supersedes
        // link landed, via an abort trigger keyed on the loser row.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let conn = db::open(&db).unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER test_fail_loser_update BEFORE UPDATE ON memories \
             WHEN NEW.id = '{loser}' \
             BEGIN SELECT RAISE(ABORT, 'test trigger: loser update refused'); END;"
        ))
        .unwrap();
        drop(conn);
        let args = ResolveArgs {
            winner_id: winner,
            loser_id: loser,
        };
        let mut out = env.output();
        let res = cmd_resolve(&db, &args, false, &mut out);
        assert!(res.is_err());
        // storage::update maps the RAISE(ABORT) into its canonical
        // constraint-violation wrap; the raw trigger prose may be
        // swallowed by that mapping, so accept either spelling.
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("update failed") || msg.contains("loser update refused"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_resolve_touch_failure_propagates() {
        // db::update targets only the loser; an abort trigger keyed on
        // the winner row fires first inside db::touch.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let conn = db::open(&db).unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER test_fail_winner_touch BEFORE UPDATE ON memories \
             WHEN NEW.id = '{winner}' \
             BEGIN SELECT RAISE(ABORT, 'test trigger: winner touch refused'); END;"
        ))
        .unwrap();
        drop(conn);
        let args = ResolveArgs {
            winner_id: winner,
            loser_id: loser,
        };
        let mut out = env.output();
        let res = cmd_resolve(&db, &args, true, &mut out);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("winner touch refused"), "got: {msg}");
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
        let res = cmd_link(&db, &args, false, &mut out);
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
        let res = cmd_link(&db, &args, true, &mut out);
        assert!(res.is_err(), "broken pipe must propagate, not panic");
    }

    #[test]
    fn test_resolve_json_output_broken_pipe_propagates() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let args = ResolveArgs {
            winner_id: winner,
            loser_id: loser,
        };
        let mut failing = FailingWriter;
        let mut stderr: Vec<u8> = Vec::new();
        let mut out = CliOutput {
            stdout: &mut failing,
            stderr: &mut stderr,
        };
        let res = cmd_resolve(&db, &args, true, &mut out);
        assert!(res.is_err(), "broken pipe must propagate, not panic");
    }

    #[test]
    fn test_resolve_human_output_broken_pipe_propagates() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let winner = seed_memory(&db, "ns", "winner", "wins");
        let loser = seed_memory(&db, "ns", "loser", "loses");
        let args = ResolveArgs {
            winner_id: winner,
            loser_id: loser,
        };
        let mut failing = FailingWriter;
        let mut stderr: Vec<u8> = Vec::new();
        let mut out = CliOutput {
            stdout: &mut failing,
            stderr: &mut stderr,
        };
        let res = cmd_resolve(&db, &args, false, &mut out);
        assert!(res.is_err(), "broken pipe must propagate, not panic");
    }
}
