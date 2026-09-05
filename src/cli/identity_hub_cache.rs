// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Public wake-hub snapshot export; the hub itself never opens the store.

use crate::wake_hub::delegation_verifier::{AllowlistCache, AllowlistEntry, AllowlistFile};
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
    /// v1.0.0 #3469 — also publish the reserved `wake-hub-producer` row,
    /// binding it to THIS host's enrolled `daemon` public key so a daemon with
    /// `[wake_hub].sink_socket` set can join the hub and push wakes.
    ///
    /// Off by default. It is the operator's single, explicit, revocable grant:
    /// omit it on the next refresh and the row disappears, which revokes the
    /// daemon's wake authority within the hub's one-second revalidation.
    /// Reads only the PUBLIC key, and its `bind_authority` states its real
    /// provenance (`daemon_key_dir`) rather than claiming a possession proof
    /// the daemon key never performed.
    #[arg(long)]
    pub daemon_producer: bool,
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
    // A reserved principal has no v97 key history, so the store loop would
    // SILENTLY OMIT it and publish a snapshot that looks successful and grants
    // nothing (#3469). Refuse loudly and name the switch that does work.
    if let Some(reserved) = agents
        .iter()
        .find(|agent| crate::validate::RESERVED_AGENT_IDS.contains(&agent.as_str()))
    {
        anyhow::bail!(
            "--include-agent {reserved} names a RESERVED internal principal, which has no \
             enrolled key history and would be silently omitted from the snapshot. The \
             only reserved principal this command can publish is \
             `{}`, and it is published with --daemon-producer.",
            crate::identity::sentinels::WAKE_HUB_PRODUCER
        );
    }
    let extra = if args.daemon_producer {
        let key_dir = crate::identity::keypair::default_key_dir()?;
        vec![crate::identity::hub_cache::daemon_producer_entry(
            &key_dir,
            &chrono::Utc::now().to_rfc3339(),
        )?]
    } else {
        Vec::new()
    };
    let snapshot = derive_with_extra(
        db_path,
        args.store_url.as_deref(),
        &agents,
        Some(previous.as_ref()),
        &extra,
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
            // v1.0.0 #3505 — how much namespace-topic authority this snapshot
            // grants, so an operator can SEE a widening (or a narrowing) in
            // the same line that reports the publish, without opening the
            // 0600 file. Totals only: the per-agent prefixes are inside the
            // file.
            "readable_prefixes": snapshot
                .agents
                .iter()
                .map(|entry| entry.readable_prefixes.len())
                .sum::<usize>(),
            "max_readable_prefixes_per_agent":
                crate::wake_hub::limits::MAX_READABLE_PREFIXES,
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
    derive_with_extra(db_path, store_url, agents, audit_previous, &[])
}

/// [`derive`], plus STORE-FREE rows appended before the snapshot is audited.
///
/// Its production caller is the `--daemon-producer` switch, whose row is
/// derived from this host's key directory rather than from the v97 ledger
/// (#3469). Appending BEFORE the audit is the point — such a row
/// then rides the same `identity.hub_allow` / `identity.hub_revoke` spine as
/// every store-derived row, so granting and revoking the daemon's wake
/// authority is as tamper-evident as granting and revoking an agent's.
///
/// # Errors
/// Unknown URLs, unavailable backends and any store/audit failure are refusals.
pub fn derive_with_extra(
    db_path: &Path,
    store_url: Option<&str>,
    agents: &[String],
    audit_previous: Option<Option<&AllowlistFile>>,
    extra: &[AllowlistEntry],
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
                                let mut snapshot = store.derive_hub_cache(agents).await?;
                                // Store-free rows join the snapshot BEFORE the
                                // audit, so they are as tamper-evident as the
                                // derived ones (#3469).
                                snapshot.agents.extend_from_slice(extra);
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
    let mut snapshot = crate::identity::hub_cache::derive_sqlite(&conn, agents)?;
    // Store-free rows join the snapshot BEFORE the audit (#3469).
    snapshot.agents.extend_from_slice(extra);
    if let Some(previous) = audit_previous {
        crate::identity::hub_cache::audit_sqlite(&conn, previous, &snapshot)?;
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DENIED: naming a reserved principal is refused outright.
    ///
    /// Before #3469 this path exited 0 and published a snapshot with the
    /// principal SILENTLY OMITTED — a reserved id has no v97 key history, so
    /// `derive_sqlite`'s `current_issuer` check fails and the loop `continue`s.
    /// An operator following the docs would have seen `"agents": 0`, a
    /// published file, and a hub that admitted nobody. A refusal that names the
    /// switch that does work is the fail-closed answer.
    #[test]
    fn a_reserved_principal_is_refused_rather_than_silently_omitted_3469() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = HubCacheArgs {
            agents: vec![crate::identity::sentinels::WAKE_HUB_PRODUCER.to_owned()],
            out: dir.path().join("allow.json"),
            store_url: None,
            daemon_producer: false,
        };
        let mut sink = Vec::new();
        let mut err_sink = Vec::new();
        let mut out = crate::cli::CliOutput {
            stdout: &mut sink,
            stderr: &mut err_sink,
        };
        let err = run(&dir.path().join("x.db"), &args, &mut out).expect_err("must refuse");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("RESERVED"), "{rendered}");
        assert!(rendered.contains("--daemon-producer"), "{rendered}");
        assert!(
            !dir.path().join("allow.json").exists(),
            "a refused publication must not leave a snapshot behind"
        );
    }
}
