// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10021 — the PostgreSQL leg of `backup` / `restore`.
//!
//! When the configured store is Postgres, `backup` writes a native dump
//! (`ai-memory-<ts>.pgdata`) and its operator-signed manifest
//! (`ai-memory-<ts>.pgmanifest.json`), both mode 0600, and `restore` loads one
//! into an EMPTY, freshly migrated Postgres store in one transaction. The
//! format, the verification and the load live on the store layer
//! ([`crate::store::native_backup`], `MemoryStore::native_backup` /
//! `native_restore`); this module resolves the files, the keys and the
//! confirmation, and nothing else.
//!
//! Every PostgreSQL backup is signed and every PostgreSQL restore verifies the
//! signature and every digest against the operator key resolved on this host
//! before the first write. `--skip-verify` and `--allow-unsigned-manifest`
//! are refused on this path under every posture.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{BACKUP_TS_FMT, BackupArgs, BackupPolicy, RestoreArgs, RestorePolicy};
use crate::cli::CliOutput;
use crate::store::native_backup as nb;

/// What a PostgreSQL backup holds besides memories, printed on every backup
/// and restated in docs/CLI_REFERENCE.md (C-8 of vote V1-10021).
pub const PG_BACKUP_CONTENT_NOTICE: &str = "NOTICE: this PostgreSQL backup holds every \
     table of the store verbatim, including API-key hashes, the key history and session \
     transcripts. It holds no private signing key and no plaintext API key. Keep it as \
     private as the database itself (#10021).";

/// `backup` on Postgres with no usable operator signing key.
pub const PG_BACKUP_NEEDS_SIGNING_KEY: &str = "backup: a PostgreSQL backup is always signed, \
     and no operator signing key is usable on this host. Nothing was written. Create the \
     operator key with `ai-memory rules keygen` (#10021)";

/// `restore` on Postgres with no operator public key to verify against.
pub const PG_RESTORE_NEEDS_ANCHOR: &str = "restore: a PostgreSQL restore verifies the \
     backup's signature against the operator public key, and none resolves on this host \
     (AI_MEMORY_OPERATOR_PUBKEY or the key directory). Nothing was written (#10021)";

/// `restore --skip-verify` / `--allow-unsigned-manifest` on Postgres.
pub const PG_RESTORE_REFUSES_UNVERIFIED: &str = "restore: --skip-verify and \
     --allow-unsigned-manifest are refused for a PostgreSQL restore; only a backup whose \
     signature and digests verify is loaded. Nothing was written (#10021)";

/// `restore --latest` with a PostgreSQL target.
pub const PG_RESTORE_NEEDS_SNAPSHOT: &str = "restore: a PostgreSQL restore from a \
     directory needs --snapshot <ai-memory-<ts>> naming one backup; --latest is not \
     supported on this path (#10021)";

/// The configured store URL when it names Postgres, after the same ambiguity
/// refusal the SQLite path applies.
///
/// # Errors
/// An argv/env store-URL disagreement, or an unreadable env channel.
pub(super) fn configured_pg_url(store_url_arg: Option<&str>, verb: &str) -> Result<Option<String>> {
    let url = super::unambiguous_store_url(store_url_arg, verb)?;
    Ok(url.filter(|u| crate::daemon_runtime::is_postgres_url(u)))
}

/// Build the future with `make` and run it to completion on a private
/// current-thread runtime in a scoped thread: deadlock-free whether or not
/// the caller is inside a runtime (the `cli::recall` bridge, #1182). The
/// future is built on the worker thread, so it need not be `Send`, and the
/// pool it opens lives and dies on that one runtime.
fn block_on<M, F>(make: M) -> Result<F::Output>
where
    M: FnOnce() -> F + Send,
    F: std::future::Future,
    F::Output: Send,
{
    let joined = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|rt| rt.block_on(make()))
            })
            .join()
    });
    match joined {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(anyhow::Error::new(e).context("starting the PostgreSQL runtime")),
        Err(_) => anyhow::bail!("the PostgreSQL backup worker panicked (#10021)"),
    }
}

async fn connect(url: &str) -> Result<crate::store::postgres::PostgresStore> {
    crate::store::postgres::PostgresStore::connect(url)
        .await
        .with_context(|| {
            format!(
                "{} {}",
                crate::store::postgres::CTX_CONNECT_POSTGRES_ADAPTER,
                crate::url_display::store_url_display(url)
            )
        })
}

/// The two file names of one PostgreSQL backup id.
fn pair_names(id: &str) -> (String, String) {
    (
        format!("{id}.{}", nb::PG_BACKUP_DATA_SUFFIX),
        format!("{id}.{}", nb::PG_BACKUP_MANIFEST_SUFFIX),
    )
}

/// Record a path this run created (a poisoned lock still records it).
fn note_created(created: &std::sync::Mutex<Vec<PathBuf>>, path: &Path) {
    created
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
}

/// Create one artifact file: `create_new`, mode 0600 (an existing entry,
/// a symlink included, is refused).
fn create_private(path: &Path) -> Result<std::fs::File> {
    nb::create_private_file(path)
        .with_context(|| format!("creating PostgreSQL backup file {}", path.display()))
}

/// Print one `--json` envelope line.
fn emit_json(out: &mut CliOutput<'_>, envelope: &serde_json::Value) -> Result<()> {
    writeln!(out.stdout, "{envelope}")?;
    Ok(())
}

/// Remove files this run created (best effort; the caller is already failing).
fn remove_created(paths: &[&Path]) {
    for p in paths {
        // Deliberate discard: the original error is what the caller reports.
        let _ = std::fs::remove_file(p);
    }
}

/// `backup` against a Postgres store.
///
/// # Errors
/// No usable signing key (nothing written), an unreachable store, or any dump
/// or write failure (the files this run created are removed).
pub(super) fn run_pg_backup(
    url: &str,
    args: &BackupArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
    policy: &BackupPolicy,
) -> Result<()> {
    // Decided before anything is created or connected.
    let Some(key) = super::backup_signing_key(policy, out)? else {
        anyhow::bail!(PG_BACKUP_NEEDS_SIGNING_KEY);
    };
    use crate::store::MemoryStore;
    let ts = chrono::Utc::now().format(BACKUP_TS_FMT).to_string();
    let (data_name, manifest_name) = pair_names(&format!("ai-memory-{ts}"));
    let data_path = args.to.join(&data_name);
    let manifest_path = args.to.join(&manifest_name);
    // Paths this run created, so a failure removes exactly those (never a
    // pre-existing entry that create_new refused).
    let created = std::sync::Mutex::new(Vec::<PathBuf>::new());
    let written = block_on(|| async {
        // Connect first: an unreachable store creates nothing on disk.
        let store = connect(url).await?;
        std::fs::create_dir_all(&args.to)
            .with_context(|| format!("creating backup dir {}", args.to.display()))?;
        // create_new + 0600: an existing entry (file, symlink) is refused.
        let manifest_file = create_private(&manifest_path)?;
        note_created(&created, &manifest_path);
        let data_file = create_private(&data_path)?;
        note_created(&created, &data_path);
        let body = store
            .native_backup(data_file)
            .await
            .map_err(anyhow::Error::new)?;
        Ok::<_, anyhow::Error>((body, manifest_file))
    })
    .and_then(|r| r)
    .and_then(|(body, mut manifest_file)| {
        let signed = nb::sign_pg_manifest(&body, key)?;
        let bytes = signed.to_json_bytes()?;
        manifest_file.write_all(&bytes)?;
        manifest_file.sync_all()?;
        (policy.sync_dir)(&args.to)?;
        Ok(body)
    });
    let body = match written {
        Ok(b) => b,
        Err(e) => {
            let paths = created
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let refs: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
            remove_created(&refs);
            return Err(e.context("PostgreSQL backup failed; no partial file was kept (#10021)"));
        }
    };
    let rows: u64 = body
        .tables
        .iter()
        .map(|t| t.rows)
        .fold(0, u64::saturating_add);
    let signer = super::manifest::fingerprint(&key.verifying_key());
    writeln!(out.stderr, "{PG_BACKUP_CONTENT_NOTICE}")?;
    if json_out {
        let envelope = serde_json::json!({
            "backend": nb::PG_BACKUP_BACKEND,
            "data": data_path.display().to_string(),
            "manifest": manifest_path.display().to_string(),
            "sha256": body.data_sha256,
            "bytes": body.data_len,
            "tables": body.tables.len(),
            "rows": rows,
            "sequences": body.sequences.len(),
            "schema_version": body.schema_version,
            "signed": true,
            "signer": signer,
            "durable": true,
            "rotation": serde_json::Value::Null,
            "contains": ["api_key_hashes", "key_history", "transcripts"],
        });
        emit_json(out, &envelope)?;
    } else {
        writeln!(out.stdout, "Data    : {}", data_path.display())?;
        writeln!(out.stdout, "Manifest: {}", manifest_path.display())?;
        writeln!(out.stdout, "SHA-256 : {}", body.data_sha256)?;
        writeln!(out.stdout, "Bytes   : {}", body.data_len)?;
        writeln!(out.stdout, "Tables  : {}", body.tables.len())?;
        writeln!(out.stdout, "Rows    : {rows}")?;
        writeln!(out.stdout, "Signed  : operator key {signer}")?;
        writeln!(out.stdout, "Durable : yes")?;
        writeln!(
            out.stdout,
            "Rotation: not applied to PostgreSQL backups (--keep counts SQLite snapshots)"
        )?;
    }
    Ok(())
}

/// The data and manifest paths a PostgreSQL `restore` reads.
fn select_pg_pair(args: &RestoreArgs) -> Result<(PathBuf, PathBuf)> {
    let strip = |name: &str| -> Option<String> {
        [nb::PG_BACKUP_MANIFEST_SUFFIX, nb::PG_BACKUP_DATA_SUFFIX]
            .iter()
            .find_map(|s| name.strip_suffix(&format!(".{s}")))
            .map(str::to_owned)
    };
    let (dir, id) = if args.from.is_dir() {
        if args.latest {
            anyhow::bail!(PG_RESTORE_NEEDS_SNAPSHOT);
        }
        let Some(name) = args.snapshot.as_deref() else {
            anyhow::bail!(PG_RESTORE_NEEDS_SNAPSHOT);
        };
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
        {
            anyhow::bail!("restore: --snapshot must be a plain backup name, not a path (#10021)");
        }
        (
            args.from.clone(),
            strip(name).unwrap_or_else(|| name.to_owned()),
        )
    } else {
        let name = args
            .from
            .file_name()
            .and_then(|n| n.to_str())
            .context("restore: --from names no file")?;
        let Some(id) = strip(name) else {
            anyhow::bail!(
                "restore: {} is not a PostgreSQL backup file (expected *.{} or *.{}) (#10021)",
                args.from.display(),
                nb::PG_BACKUP_DATA_SUFFIX,
                nb::PG_BACKUP_MANIFEST_SUFFIX
            );
        };
        let dir = args
            .from
            .parent()
            .map_or_else(PathBuf::new, Path::to_path_buf);
        (dir, id)
    };
    let (data_name, manifest_name) = pair_names(&id);
    Ok((dir.join(data_name), dir.join(manifest_name)))
}

/// `restore` against a Postgres store.
///
/// # Errors
/// Every refusal before the load (unverified flags, no anchor, a bad or
/// missing artifact, no confirmation) and every load refusal of
/// `native_restore` (non-empty target, schema mismatch, ...); none writes.
pub(super) fn run_pg_restore(
    url: &str,
    args: &RestoreArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
    policy: RestorePolicy,
) -> Result<()> {
    if args.skip_verify || args.allow_unsigned_manifest {
        anyhow::bail!(PG_RESTORE_REFUSES_UNVERIFIED);
    }
    let Some(anchor) = policy.anchor else {
        anyhow::bail!(PG_RESTORE_NEEDS_ANCHOR);
    };
    let (data_path, manifest_path) = select_pg_pair(args)?;
    let manifest_bytes = nb::read_manifest_capped(&manifest_path)
        .with_context(|| format!("manifest {}", manifest_path.display()))?;
    let data = std::fs::File::open(&data_path)
        .with_context(|| format!("opening {}", data_path.display()))?;
    // Signature and every digest, before any connection or write.
    let verified = nb::verify_pg_backup(&manifest_bytes, data, &anchor)
        .with_context(|| format!("backup {}", manifest_path.display()))?;
    if super::restore_requires_confirmation(args) {
        if json_out {
            anyhow::bail!(super::RESTORE_JSON_REQUIRES_YES);
        }
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            anyhow::bail!(super::RESTORE_NON_INTERACTIVE_REQUIRES_YES);
        }
        writeln!(
            out.stdout,
            "About to load {} ({} tables) into the PostgreSQL store {}. The store must be \
             empty (freshly migrated); a non-empty store is refused and left unchanged.",
            data_path.display(),
            verified.body().tables.len(),
            crate::url_display::store_url_display(url)
        )?;
        if !super::confirm_restore(out)? {
            anyhow::bail!("restore: not confirmed; nothing was written (#10021)");
        }
    }
    use crate::store::MemoryStore;
    let report = block_on(|| async move {
        let store = connect(url).await?;
        store
            .native_restore(verified)
            .await
            .map_err(anyhow::Error::new)
            .context("PostgreSQL restore refused; the store was not changed (#10021)")
    })??;
    if json_out {
        let envelope = serde_json::json!({
            "backend": nb::PG_BACKUP_BACKEND,
            "restored_from": data_path.display().to_string(),
            "manifest_verification": "signed",
            "tables": report.tables,
            "rows": report.rows,
            "sequences": report.sequences,
            "leases_clamped": report.leases_clamped,
            "age_edges_projected": report.age_edges_projected,
        });
        emit_json(out, &envelope)?;
    } else {
        writeln!(
            out.stdout,
            "Restored {} rows in {} tables and {} sequences from {} (signature and \
             digests verified; {} unexpired leases set to expire now).",
            report.rows,
            report.tables,
            report.sequences,
            data_path.display(),
            report.leases_clamped
        )?;
    }
    Ok(())
}
