// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory reown` — rewrite the `metadata.agent_id` ownership stamp
//! on the memories in a namespace (or every namespace), BEFORE an operator
//! enables `scope=private` visibility filtering or
//! `AI_MEMORY_UNSTAMPED_MUTATION=refuse`.
//!
//! # v0.8.0 §1709/#1720 Workstream-B unit B2 · v1.0.0 #3124 R4
//!
//! The A2-A6 owner-keyed `scope=private` visibility filter drops rows
//! owned by a different agent, and #3124's `refuse` posture refuses a
//! caller-scoped mutation of an UNSTAMPED row. An operator who turns either
//! on against legacy rows would lock themselves out of their own data.
//! `reown` is the admin migration that establishes durable ownership FIRST.
//!
//! ## Semantics
//!
//! - `--namespace <ns>` is an EXACT namespace match (not the subtree);
//!   `--all-namespaces` sweeps every namespace. Exactly one is required.
//! - Default: rewrite every row that already carries an `agent_id` (any
//!   current owner).
//! - `--only-unowned`: rewrite ONLY the unstamped rows (missing / null /
//!   `""` `agent_id` — the #3124 definition) and never an owned one. This is
//!   the remedy `ai-memory doctor` names for the unstamped-owner census.
//! - `--claim-unowned`: rewrite EVERY row in scope, owned rows INCLUDED
//!   (claim-all). It takes rows from their current owners — use
//!   `--only-unowned` to adopt only the legacy class.
//! - `--dry-run`: count the matched rows, write NOTHING. Run it first.
//!
//! Only `metadata.agent_id` is touched (`json_set` of the single key);
//! every other metadata key is preserved and the `agent_id_idx`
//! generated column re-projects the new owner. Each rewritten row gets
//! `version + 1` and a fresh `updated_at`, and one `memory.reowned`
//! signed-chain row naming the operator is appended in the same
//! transaction; the write is refused under record-stop. `--to` is
//! validated so a malformed owner can never be written.
//!
//! Operator-only: there is no MCP / HTTP surface; the audit actor is the
//! RESOLVED principal (`--agent-id` / `AI_MEMORY_AGENT_ID` / the synthesised
//! durable default) and an anonymous principal is refused, so every reown is
//! attributable. Both backends: a `postgres://` store (`--store-url`, or the
//! `AI_MEMORY_STORE_URL[_FILE]` channels, resolved like `curator` / `serve`)
//! routes through the SAL `MemoryStore::reown`; the local SQLite leg keeps the
//! #2572 funnel so a build without `sal` still refuses a Postgres store.

use anyhow::{Context, Result};
use std::path::Path;

use crate::cli::CliOutput;

/// Shared `.context` label for the report-write paths (pm-v3.1
/// literal de-dup — referenced at every `writeln!` site below).
const CTX_WRITE_REOWN_REPORT: &str = "write reown report";

/// Prefix every anonymous (ephemeral) principal carries.
const ANONYMOUS_PRINCIPAL_PREFIX: &str = "anonymous:";

/// Arguments for `ai-memory reown`.
#[derive(clap::Args, Debug)]
pub struct ReownArgs {
    /// The namespace whose memories are re-owned. EXACT match — the
    /// namespace subtree is NOT included, for predictable + safe admin
    /// migration. Required unless `--all-namespaces`.
    #[arg(
        long,
        value_name = "NAMESPACE",
        required_unless_present = "all_namespaces",
        conflicts_with = "all_namespaces"
    )]
    pub namespace: Option<String>,

    /// Sweep EVERY namespace instead of one (#3124).
    #[arg(long)]
    pub all_namespaces: bool,

    /// The new owner agent_id stamped onto `metadata.agent_id`.
    /// Validated against the wire agent_id shape; a malformed value is
    /// rejected before any write.
    #[arg(long, value_name = "AGENT_ID")]
    pub to: String,

    /// Count the matched rows and print the plan WITHOUT writing
    /// anything. Run this first.
    #[arg(long)]
    pub dry_run: bool,

    /// Re-own EVERY row in scope, owned rows INCLUDED (claim-all): rows are
    /// taken from their current owners. To adopt only the legacy rows that
    /// carry no owner, use `--only-unowned` instead.
    #[arg(long, conflicts_with = "only_unowned")]
    pub claim_unowned: bool,

    /// Re-own ONLY rows with no ownership stamp (missing / null / empty
    /// `metadata.agent_id`); a row that has an owner is never touched
    /// (#3124). The remedy `ai-memory doctor` names for unstamped rows.
    #[arg(long)]
    pub only_unowned: bool,

    /// Postgres store to re-own on (`postgres://…`). The
    /// `AI_MEMORY_STORE_URL_FILE` / `AI_MEMORY_STORE_URL` channels are
    /// honoured with the same precedence as `curator` / `serve`. Without a
    /// postgres store the local `--db` SQLite file is used.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,

    /// Emit the machine-readable JSON report
    /// (`{matched, rewritten, dry_run, select}`) instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

impl ReownArgs {
    /// The row selection the flags name.
    #[must_use]
    pub fn select(&self) -> crate::storage::ReownSelect {
        if self.only_unowned {
            crate::storage::ReownSelect::OnlyUnowned
        } else if self.claim_unowned {
            crate::storage::ReownSelect::All
        } else {
            crate::storage::ReownSelect::Owned
        }
    }

    /// `None` = `--all-namespaces`.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        if self.all_namespaces {
            None
        } else {
            self.namespace.as_deref()
        }
    }

    fn scope_label(&self) -> &str {
        self.namespace()
            .unwrap_or(crate::storage::REOWN_ALL_NAMESPACES_TOKEN)
    }
}

/// Resolve the operator principal the audit row is attributed to. An
/// anonymous (ephemeral, per-process) principal is refused: a re-ownership
/// that cannot be attributed to a durable operator is not auditable.
///
/// # Errors
///
/// The principal cannot be resolved, or resolves to an anonymous one.
pub fn resolve_operator(cli_agent_id: Option<&str>) -> Result<String> {
    let actor = crate::identity::resolve_agent_id(cli_agent_id, None)
        .context("reown: resolve the operator agent id")?;
    if actor.starts_with(ANONYMOUS_PRINCIPAL_PREFIX) {
        anyhow::bail!(
            "reown: refusing an anonymous operator principal ({actor}); pass --agent-id or set \
             AI_MEMORY_AGENT_ID so the memory.reowned audit row names a durable operator"
        );
    }
    Ok(actor)
}

fn render(
    args: &ReownArgs,
    report: &crate::storage::ReownReport,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if args.json {
        let json = serde_json::to_string_pretty(report).context("serialize reown report")?;
        writeln!(out.stdout, "{json}").context(CTX_WRITE_REOWN_REPORT)?;
    } else if report.dry_run {
        writeln!(
            out.stdout,
            "would reown {} row(s) in {} to {} (select: {})",
            report.matched,
            args.scope_label(),
            args.to,
            report.select.as_str(),
        )
        .context(CTX_WRITE_REOWN_REPORT)?;
    } else {
        writeln!(
            out.stdout,
            "reowned {} of {} row(s) in {} to {} (select: {})",
            report.rewritten,
            report.matched,
            args.scope_label(),
            args.to,
            report.select.as_str(),
        )
        .context(CTX_WRITE_REOWN_REPORT)?;
    }
    Ok(())
}

/// Run the reown migration against the LOCAL sqlite database. Returns
/// `Ok(0)` on success.
///
/// # Errors
///
/// Returns the underlying `rusqlite`, validation, serializer, or
/// formatter error if the DB open, the re-own sweep, or the report
/// render fails; refuses a Postgres store on a build that cannot route it.
pub fn run(
    db_path: &Path,
    args: &ReownArgs,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let actor = resolve_operator(cli_agent_id)?;
    // v1.0.0 #2572 — the SQLite leg still refuses a Postgres store (a build
    // without `sal` cannot route one, and a phantom write to a throwaway
    // SQLite file would report success while the data is lost). The pg leg
    // is routed by the dispatcher through [`run_store`] (#3124 R4).
    let db_path = crate::cli::backup::refuse_pg_store(db_path, "reown", out)?;
    let db_path = db_path.as_path();
    let conn =
        crate::db::open(db_path).with_context(|| crate::errors::msg::opening(db_path.display()))?;
    let report = crate::storage::reown(
        &conn,
        args.namespace(),
        &args.to,
        args.select(),
        args.dry_run,
        &actor,
    )
    .context("reown over memories")?;
    render(args, &report, out)?;
    Ok(0)
}

/// #3124 R4 — route `ai-memory reown` to its backend. A `postgres://` store
/// (the flag or the #1927 env channels, resolved exactly as `curator` /
/// `serve` resolve it) goes through the SAL [`run_store`]; the async store
/// build happens BEFORE the stdout lock is taken (the `quarantine`
/// precedent). A non-postgres `--store-url` is refused (it would silently
/// operate a different database than the one named). Everything else is the
/// local SQLite leg [`run`], which keeps the #2572 funnel.
///
/// # Errors
///
/// Store-url resolution, the store build, or the selected leg failed.
pub async fn dispatch(
    args: &ReownArgs,
    db_path: &Path,
    app_config: &crate::config::AppConfig,
    cli_agent_id: Option<&str>,
) -> Result<i32> {
    let resolved = crate::store_url::resolve_store_url(args.store_url.as_deref())?;
    if let Some(url) = resolved
        .as_deref()
        .filter(|u| crate::store_url::is_postgres_url(u))
    {
        #[cfg(feature = "sal")]
        {
            let store =
                crate::daemon_runtime::build_curator_store(Some(url), db_path, app_config).await?;
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let mut so = stdout.lock();
            let mut se = stderr.lock();
            let mut out = CliOutput::from_std(&mut so, &mut se);
            return run_store(store.as_ref(), args, cli_agent_id, &mut out).await;
        }
        #[cfg(not(feature = "sal"))]
        {
            let _ = app_config;
            anyhow::bail!(
                "reown on {} requires the 'sal' build feature; this binary was built \
                 without it",
                crate::logging::redact_url_password(url)
            );
        }
    }
    if let Some(flag) = args.store_url.as_deref()
        && !crate::store_url::is_postgres_url(flag)
    {
        anyhow::bail!(
            "reown --store-url accepts a postgres:// store only; use --db for a \
             SQLite file (got {})",
            crate::logging::redact_url_password(flag)
        );
    }
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut so = stdout.lock();
    let mut se = stderr.lock();
    let mut out = CliOutput::from_std(&mut so, &mut se);
    run(db_path, args, cli_agent_id, &mut out)
}

/// #3124 R4 — run the reown migration through the SAL (the postgres leg).
/// The operator lane is an ADMIN lane: `for_admin` because the admin posture
/// is structural — reaching this verb requires local CLI access to the store
/// credentials, the same gate `quarantine release` relies on.
///
/// # Errors
///
/// Operator resolution, the store sweep, or the report render failed.
#[cfg(feature = "sal")]
pub async fn run_store(
    store: &dyn crate::store::MemoryStore,
    args: &ReownArgs,
    cli_agent_id: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let actor = resolve_operator(cli_agent_id)?;
    let ctx = crate::store::CallerContext::for_admin(actor);
    let report = store
        .reown(
            &ctx,
            args.namespace(),
            &args.to,
            args.select(),
            args.dry_run,
        )
        .await
        .map_err(|e| anyhow::anyhow!("reown over memories: {e}"))?;
    render(args, &report, out)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("reown-cli-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join("test.db");
        drop(crate::db::open(&path).expect("init db"));
        (dir, path)
    }

    fn seed(path: &Path, title: &str, ns: &str, agent_id: &str) {
        let conn = crate::db::open(path).expect("open");
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("content {title}"),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({ "agent_id": agent_id }),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        crate::storage::insert(&conn, &mem).expect("insert");
    }

    #[test]
    fn cli_reown_rewrites_and_reports_counts() {
        let (_dir, path) = temp_db();
        seed(&path, "a", "claim-ns", "alice");
        seed(&path, "b", "claim-ns", "alice");
        seed(&path, "c", "other-ns", "alice");

        let args = ReownArgs {
            namespace: Some("claim-ns".to_string()),
            all_namespaces: false,
            to: "bob".to_string(),
            dry_run: false,
            claim_unowned: false,
            only_unowned: false,
            store_url: None,
            json: true,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, Some("ai:operator"), &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("\"matched\": 2"), "got: {s}");
        assert!(s.contains("\"rewritten\": 2"), "got: {s}");
        assert!(s.contains("\"dry_run\": false"), "got: {s}");
    }

    #[test]
    fn cli_reown_refuses_an_anonymous_operator_3124() {
        let err = resolve_operator(Some("anonymous:pid-1-abcd1234")).expect_err("refused");
        assert!(format!("{err}").contains("anonymous operator"), "{err}");
        assert_eq!(
            resolve_operator(Some("ai:operator")).expect("ok"),
            "ai:operator"
        );
    }

    #[test]
    fn cli_reown_flags_map_to_the_selection_3124() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            args: ReownArgs,
        }
        let parse = |argv: &[&str]| Wrap::try_parse_from(argv).map(|w| w.args);
        let a = parse(&["x", "--namespace", "n", "--to", "b"]).expect("default");
        assert_eq!(a.select(), crate::storage::ReownSelect::Owned);
        let a = parse(&["x", "--all-namespaces", "--to", "b", "--only-unowned"]).expect("only");
        assert_eq!(a.select(), crate::storage::ReownSelect::OnlyUnowned);
        assert!(a.namespace().is_none());
        let a = parse(&["x", "--namespace", "n", "--to", "b", "--claim-unowned"]).expect("all");
        assert_eq!(a.select(), crate::storage::ReownSelect::All);
        assert!(parse(&["x", "--to", "b"]).is_err(), "a scope is required");
        assert!(
            parse(&["x", "--namespace", "n", "--all-namespaces", "--to", "b"]).is_err(),
            "--namespace conflicts with --all-namespaces"
        );
        assert!(
            parse(&[
                "x",
                "--namespace",
                "n",
                "--to",
                "b",
                "--claim-unowned",
                "--only-unowned"
            ])
            .is_err(),
            "--claim-unowned conflicts with --only-unowned"
        );
    }

    #[test]
    fn cli_reown_dry_run_human_text() {
        let (_dir, path) = temp_db();
        seed(&path, "a", "claim-ns", "alice");
        let args = ReownArgs {
            namespace: Some("claim-ns".to_string()),
            all_namespaces: false,
            to: "bob".to_string(),
            dry_run: true,
            claim_unowned: false,
            only_unowned: false,
            store_url: None,
            json: false,
        };
        let mut buf_out = Vec::<u8>::new();
        let mut buf_err = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut buf_out, &mut buf_err);
        let code = run(&path, &args, Some("ai:operator"), &mut out).expect("run");
        assert_eq!(code, 0);
        let s = String::from_utf8(buf_out).expect("utf-8");
        assert!(s.contains("would reown 1 row(s)"), "got: {s}");
        assert!(s.contains("select: owned"), "got: {s}");
    }
}
