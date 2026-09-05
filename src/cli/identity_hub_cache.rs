// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Public wake-hub snapshot export; the hub itself never opens the store.

use crate::wake_hub::delegation_verifier::{AllowlistCache, AllowlistFile};
use anyhow::{Context as _, Result};
use std::path::{Path, PathBuf};

/// Export a complete allowlist; omission revokes a previously exported agent.
#[derive(Debug, clap::Args)]
pub struct HubCacheArgs {
    // v1.0.0 #3508 — deliberately NOT named `--agent-id`, and this rationale
    // is a plain comment so it never reaches the operator's `--help`. The
    // root `--agent-id` is `global = true` (env `AI_MEMORY_AGENT_ID`) and
    // names the CALLER, while this flag names the principals to admit.
    // Declaring the same long under a different argument id made clap refuse
    // to BUILD the command ("'--agent-id' in use by both 'agents' and
    // 'agent_id'"), which broke `ai-memory completions` and `ai-memory man`
    // in debug builds. Same hazard, same remedy as `agents subkey-certs
    // --principal` (#3017).
    /// Principals to retain. Repeat per agent; omit all to revoke everyone.
    #[arg(long = "include-agent", value_name = "AGENT_ID")]
    pub agents: Vec<String>,
    /// Public cache file consumed by wake-hub --allowlist. Atomically written 0600.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Store URL; standard store URL environment/file channels take precedence.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

/// Derive and audit a complete snapshot before atomically publishing it.
///
/// # Errors
/// Propagates source, audit and publication failures without using stale data.
pub fn run(db_path: &Path, args: &HubCacheArgs, out: &mut crate::cli::CliOutput<'_>) -> Result<()> {
    let previous = match std::fs::symlink_metadata(&args.out) {
        Ok(_) => Some(AllowlistCache::read_file(&args.out)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut agents = args.agents.clone();
    agents.sort();
    agents.dedup();
    let snapshot = derive(
        db_path,
        args.store_url.as_deref(),
        &agents,
        Some(previous.as_ref()),
    )?;
    crate::identity::hub_cache::publish(&args.out, &snapshot)?;
    writeln!(
        out.stdout,
        "{}",
        serde_json::to_string(&serde_json::json!({
            "allowlist": args.out,
            "agents": snapshot.agents.len(),
            "refreshed_at": snapshot.refreshed_at,
            "max_age_secs": crate::identity::hub_cache::MAX_CACHE_AGE_SECS,
        }))?
    )?;
    Ok(())
}

/// Read the selected durable backend; optionally audit a publication.
/// `Some(None)` audits an initial snapshot, `None` is a read-only mint check.
///
/// # Errors
/// Unknown URLs, unavailable backends and any store/audit failure are refusals.
pub fn derive(
    db_path: &Path,
    store_url: Option<&str>,
    agents: &[String],
    audit_previous: Option<Option<&AllowlistFile>>,
) -> Result<AllowlistFile> {
    let url = crate::store_url::resolve_store_url(store_url)?;
    if let Some(url) = url
        .as_deref()
        .filter(|url| crate::store_url::is_postgres_url(url))
    {
        #[cfg(feature = "sal-postgres")]
        {
            // CLI dispatch can already be inside Tokio. Own a scoped worker
            // runtime instead of blocking/re-entering that runtime (CONCURRENCY-20).
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?
                            .block_on(async {
                                let store =
                                    crate::store::postgres::PostgresStore::connect(url).await?;
                                let snapshot = store.derive_hub_cache(agents).await?;
                                if let Some(previous) = audit_previous {
                                    store.audit_hub_cache(previous, &snapshot).await?;
                                }
                                Ok(snapshot)
                            })
                    })
                    .join()
                    .map_err(|_| anyhow::anyhow!("hub cache backend worker panicked"))?
            });
        }
        #[cfg(not(feature = "sal-postgres"))]
        {
            let _ = url;
            anyhow::bail!("PostgreSQL hub identity requires the sal-postgres feature");
        }
    }
    let path = match url.as_deref() {
        None => db_path,
        Some(url) => Path::new(
            url.strip_prefix("sqlite://")
                .context("unsupported hub identity store URL")?,
        ),
    };
    let conn = crate::db::open(path)?;
    let snapshot = crate::identity::hub_cache::derive_sqlite(&conn, agents)?;
    if let Some(previous) = audit_previous {
        crate::identity::hub_cache::audit_sqlite(&conn, previous, &snapshot)?;
    }
    Ok(snapshot)
}
