// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator key hygiene against the selected SQLite or PostgreSQL registry.

use crate::identity::key_inventory::{self, Inventory};
use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct KeysArgs {
    /// Key directory to inspect (defaults to AI_MEMORY_KEY_DIR).
    #[arg(long, global = true)]
    pub key_dir: Option<PathBuf>,
    /// Registry store URL; also honors the configured store URL channels.
    #[arg(long, global = true)]
    pub store_url: Option<String>,
    #[command(subcommand)]
    pub action: KeysAction,
}

#[derive(Subcommand)]
pub enum KeysAction {
    /// Preview orphan key files; deletion requires --yes.
    Prune {
        /// List candidates without removing files.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,
        /// Remove only unregistered regular key files.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(db: &Path, args: KeysArgs, json: bool, out: &mut super::CliOutput<'_>) -> Result<()> {
    let KeysAction::Prune { yes, .. } = args.action;
    let dir = args
        .key_dir
        .map_or_else(crate::identity::keypair::default_key_dir, Ok)?;
    let result = inventory(db, args.store_url.as_deref(), &dir, yes)?;
    if json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({"dry_run": !yes, "inventory": result})
        )?;
    } else {
        for name in &result.orphan_files {
            writeln!(
                out.stdout,
                "{} {name}",
                if yes { "removed" } else { "orphan" }
            )?;
        }
        writeln!(
            out.stdout,
            "{} orphan files; {} protected; {} symlinks skipped",
            result.orphan_files.len(),
            result.protected_files.len(),
            result.skipped_symlinks.len()
        )?;
        if !yes {
            writeln!(
                out.stdout,
                "Dry run: no files removed. Review before repeating with --yes."
            )?;
        }
    }
    Ok(())
}

/// Both doctor and prune resolve and read the same registry. Unknown backends,
/// unavailable registries and malformed rows fail closed, never as an empty set.
pub(crate) fn inventory(
    db: &Path,
    url: Option<&str>,
    dir: &Path,
    delete: bool,
) -> Result<Inventory> {
    let url = crate::store_url::resolve_store_url(url)?;
    if let Some(url) = &url {
        if crate::store_url::is_postgres_url(url) {
            #[cfg(feature = "sal-postgres")]
            return postgres(url, dir, delete);
            #[cfg(not(feature = "sal-postgres"))]
            bail!("PostgreSQL key registry requires the sal-postgres feature");
        }
    }
    let db = match url.as_deref() {
        None => db,
        Some(url) => Path::new(
            url.strip_prefix("sqlite://")
                .context("unsupported key registry store URL")?,
        ),
    };
    sqlite(db, dir, delete)
}

fn sqlite(db: &Path, dir: &Path, delete: bool) -> Result<Inventory> {
    if !db.is_file() {
        bail!("key registry database does not exist; refusing key pruning");
    }
    let conn = if delete {
        crate::db::open_unmigrated(db)?
    } else {
        crate::db::open_read_only(db)?
    };
    // IMMEDIATE excludes concurrent registration until the filesystem operation
    // finishes. The read-only preview needs no writer reservation.
    conn.execute_batch(if delete { "BEGIN IMMEDIATE" } else { "BEGIN" })?;
    let metadata = {
        let mut statement = conn.prepare("SELECT metadata FROM memories WHERE namespace = ?1")?;
        statement
            .query_map([crate::models::AGENTS_NAMESPACE], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let ids = key_inventory::registered_ids(metadata)?;
    let result = key_inventory::inspect(dir, &ids, delete);
    conn.execute_batch("ROLLBACK")?;
    result
}

#[cfg(feature = "sal-postgres")]
fn postgres(url: &str, dir: &Path, delete: bool) -> Result<Inventory> {
    super::doctor::run_pg_probe(|| async {
        use sqlx::Connection as _;
        let operation = async {
            let mut conn = sqlx::PgConnection::connect(url).await?;
            let mut tx = conn.begin().await?;
            if delete {
                // Protect the entire _agents population against insertion,
                // deletion and rename while pruning. No migrations or writes.
                sqlx::query("LOCK TABLE memories IN SHARE MODE")
                    .execute(&mut *tx)
                    .await?;
            }
            let metadata: Vec<String> =
                sqlx::query_scalar("SELECT metadata::text FROM memories WHERE namespace = $1")
                    .bind(crate::models::AGENTS_NAMESPACE)
                    .fetch_all(&mut *tx)
                    .await?;
            let ids = key_inventory::registered_ids(metadata)?;
            let result = key_inventory::inspect(dir, &ids, delete);
            tx.rollback().await?;
            result
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), operation)
            .await
            .context("key registry inspection timed out")?
    })?
}
