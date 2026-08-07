// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_backup` and `cmd_restore` migrations. See `cli::store` for the
//! design pattern.

use crate::cli::CliOutput;
use crate::db;
use anyhow::{Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

/// `<stem>.manifest.json` — sidecar manifest name for a snapshot stem
/// (#1558 batch 6).
fn manifest_file_name(stem: &str) -> String {
    format!("{stem}.manifest.json")
}

/// Timestamp format used for snapshot filenames. RFC3339-compatible but
/// filesystem-safe: no colons, no slashes.
const BACKUP_TS_FMT: &str = "%Y-%m-%dT%H%M%SZ";

/// Verb name threaded into the #2444 store-guard diagnostics so the refusal
/// names the command the operator actually typed.
const VERB_BACKUP: &str = "backup";
/// See [`VERB_BACKUP`].
const VERB_RESTORE: &str = "restore";

/// Backend tag stamped into [`BackupManifest::backend`]. `backup` snapshots a
/// local SQLite file via `VACUUM INTO` and refuses every other store (#2444),
/// so this is the only value it ever writes; the field exists so a restore can
/// refuse a snapshot whose backend disagrees with the resolved target.
const BACKEND_SQLITE: &str = "sqlite";

/// SQLite WAL sidecar suffixes. A restore that moves `<db>` aside without
/// these leaves the PREVIOUS database's `-wal` / `-shm` sitting beside the
/// freshly-copied snapshot, where SQLite may replay stale frames INTO the
/// restored file (#2444 — silent corruption of the restored corpus).
const SQLITE_SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

/// Append a byte suffix to a path without going through `to_string_lossy`,
/// so a non-UTF-8 database path keeps its exact bytes.
fn sidecar_path(base: &Path, suffix: &str) -> PathBuf {
    let mut raw = base.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

#[derive(Args)]
pub struct BackupArgs {
    /// Directory where the snapshot and manifest are written. Created if
    /// missing.
    #[arg(long, default_value = "./backups")]
    pub to: PathBuf,
    /// Retention: after writing a new snapshot, delete the oldest
    /// snapshots so that at most this many remain. 0 disables rotation.
    #[arg(long, default_value_t = 48)]
    pub keep: usize,
    /// Store URL this deployment serves, in the same grammar `serve` /
    /// `curator` accept (`sqlite:///path` or `postgres://…`). Declaring it
    /// makes `backup` REFUSE a store it cannot capture instead of snapshotting
    /// an unrelated local file (#2444). Also read, without this flag, from
    /// `AI_MEMORY_STORE_URL_FILE` / `AI_MEMORY_STORE_URL`.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Path to a snapshot file OR a backup directory. When a directory is
    /// supplied, the most recent snapshot is used.
    #[arg(long)]
    pub from: PathBuf,
    /// Skip sha256 verification against the manifest. Not recommended.
    #[arg(long)]
    pub skip_verify: bool,
    /// Store URL this deployment serves — see `backup --store-url`. Restoring
    /// a SQLite snapshot onto a Postgres-backed deployment would report
    /// success while leaving the real corpus untouched, so it is REFUSED
    /// (#2444).
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    pub snapshot: String,
    pub sha256: String,
    pub bytes: u64,
    pub source_db: String,
    pub version: String,
    pub created_at: String,
    /// #2444 — which backend produced this snapshot ([`BACKEND_SQLITE`]).
    /// `#[serde(default)]` so a pre-#2444 manifest still deserialises; a
    /// `None` here means "written before the field existed", NOT "unknown
    /// backend", and is therefore accepted by restore.
    #[serde(default)]
    pub backend: Option<String>,
    /// #2444 — the applied migration-ladder version of the captured database,
    /// so a restore can refuse a snapshot from a NEWER binary whose extra
    /// columns this build would silently drop on the next write.
    #[serde(default)]
    pub schema_version: Option<i64>,
    /// #2444 — live `memories` row count at capture time. Recorded (not
    /// enforced) so an operator reading the manifest can see at a glance that
    /// a snapshot captured nothing.
    #[serde(default)]
    pub memory_count: Option<i64>,
}

/// #2444 — resolve the local SQLite file a `backup` / `restore` invocation is
/// allowed to act on, or REFUSE.
///
/// `ai-memory backup` is a SQLite-only control: it snapshots via SQLite's
/// `VACUUM INTO`. Before #2444 it took the `--db` path unconditionally, and
/// [`crate::db::open`] CREATES a missing file (running the full bootstrap +
/// migration ladder on it), so on a Postgres-backed deployment the command
/// manufactured an empty SQLite database, VACUUMed it into a timestamped
/// snapshot, wrote a VALID sha256 manifest, rotated `--keep`, and exited 0.
/// Every signal the operator had said the backup succeeded; the DR restore
/// returned nothing. This resolves the CONFIGURED store first and refuses
/// anything it cannot capture.
///
/// Resolution mirrors the daemon exactly — [`crate::daemon_runtime::resolve_store_url`]
/// (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` > the `--store-url`
/// argument, #1927) — so `backup` reads the store from the same channels
/// `serve` does rather than re-deriving its own notion of it.
/// v1.0.0 #2490 — what [`resolve_sqlite_store`] does when a `sqlite://`
/// store URL names a DIFFERENT file than `--db`.
///
/// The #2444 disposition (kept for `backup` / `restore` / `export`) is to
/// act on the CONFIGURED store and say so loudly, because the store URL is
/// authoritative for `serve`. That is right for a READ: the worst case is
/// snapshotting the wrong file, which costs time.
///
/// It is NOT right for a WRITE. `docs/postgres-age-guide.md` and
/// `docs/production-deployment.md` both instruct operators to `export
/// AI_MEMORY_STORE_URL` at shell/cron scope, so an ambient sqlite store URL
/// would silently redirect `ai-memory --db ./scratch.db import < bundle.json`
/// into the deployment's REAL database — turning a scratch import into a
/// production write behind a one-line `note:`. A write verb REFUSES the
/// disagreement instead (5-agent vote 4d3ea1c5, falsification-lens F5, the
/// single biggest risk identified in the review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreDisagreement {
    /// READ verbs: act on the configured store, note it on stderr (#2444).
    RedirectWithNote,
    /// WRITE verbs: refuse rather than write to a file the operator did not
    /// name on the command line.
    Refuse,
}

/// `backup` / `restore` entry point — the #2444 read-verb disposition.
fn resolve_sqlite_source(
    db_path: &Path,
    store_url_arg: Option<&str>,
    verb: &str,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    resolve_sqlite_store(
        db_path,
        store_url_arg,
        verb,
        StoreDisagreement::RedirectWithNote,
        None,
        out,
    )
}

/// v1.0.0 #2572 — HTTP-daemon remedy hint threaded into the Postgres refusal
/// for the class-(a) CLI write/read verbs (see [`refuse_pg_store`]).
pub(crate) const PG_CLI_ALTERNATIVE: &str = "the local SQLite CLI cannot reach a \
    Postgres store — a write would land in a throwaway SQLite file the Postgres \
    deployment never reads (reported as success while the data is silently LOST), \
    and a read would return an empty conjured database. Route this operation \
    through the HTTP daemon (`ai-memory serve`) or MCP-over-HTTP instead; see \
    docs/production-deployment.md";

/// v1.0.0 #2572 — the shared Postgres-refusal funnel for the class-(a) CLI
/// verbs (`store` / `link` / `update` / `promote` / `forget` / `delete` / `gc`
/// / `archive` / `consolidate` / `namespace` / `reown` / `share` / `offload` /
/// `reflect` / `atomise` / `reembed` / `mine` / `sync` / `calibrate confidence`).
///
/// Each of those verbs opens the local SQLite `--db` directly; on a
/// Postgres-served deployment (`AI_MEMORY_STORE_URL=postgres://…`, the #1927
/// non-argv channel, or `--store-url`) that write phantom-lands in a throwaway
/// SQLite file the served store never reads — reporting success while the data
/// is LOST (the exact #2490 class PR #2568 closed for the durability verbs).
/// This gate resolves the configured store BEFORE `db::open` and REFUSES a
/// Postgres URL (5-agent vote `4d3ea1c5`, UNANIMOUS REFUSE). The Route-through-
/// SAL capability is deferred to #2772.
///
/// Returns the resolved local SQLite path (byte-identical to `db_path` in every
/// `Ok` case) so the caller opens exactly what it would have, or the typed
/// Postgres / ambiguous-store refusal. `store_url_arg` is `None` because no
/// class-(a) verb carries a `--store-url` flag; the env channels
/// (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL`) are still consulted.
///
/// # Errors
///
/// Refuses on a Postgres store URL, an unrecognised scheme, an argv/env
/// store-URL disagreement, an empty `sqlite://` path, or a `sqlite://` path that
/// disagrees with `--db` (WRITE disposition — never a silent redirect).
pub(crate) fn refuse_pg_store(
    db_path: &Path,
    verb: &str,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    resolve_sqlite_store(
        db_path,
        None,
        verb,
        StoreDisagreement::Refuse,
        Some(PG_CLI_ALTERNATIVE),
        out,
    )
}

/// v1.0.0 #2490 — the shared store-resolution gate, reused verbatim by
/// `export` / `export --full` / `import` so the refusal SET cannot drift
/// between the durability verbs.
///
/// # Errors
///
/// Refuses (never falls back to `--db`) on: a Postgres store URL, an
/// unrecognised scheme, an argv/env store-URL disagreement, an empty
/// `sqlite://` path, and — under [`StoreDisagreement::Refuse`] — a
/// `sqlite://` path that disagrees with `--db`.
///
/// v1.0.0 #2572 — `pg_alternative` names the store-appropriate remedy in the
/// Postgres-refusal message. `None` (backup / restore / export / import) keeps
/// the #2444/#2490 pg-native-dump guidance verbatim; `Some(hint)` (the class-(a)
/// CLI write/read verbs) points the operator at the HTTP daemon instead, since a
/// local-SQLite write cannot reach a Postgres store.
pub(crate) fn resolve_sqlite_store(
    db_path: &Path,
    store_url_arg: Option<&str>,
    verb: &str,
    disagreement: StoreDisagreement,
    pg_alternative: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    use crate::daemon_runtime::{SQLITE_URL_SCHEME, is_postgres_url, resolve_store_url};
    use crate::logging::redact_url_password;

    // Ambiguity is REFUSED, never silently resolved. `resolve_store_url` gives
    // the env channels precedence over the argv flag (#1927), so an explicit
    // `--store-url` that DISAGREES with an exported AI_MEMORY_STORE_URL would
    // otherwise capture a store the operator did not name — on a durability
    // command "which store did I actually snapshot?" must never be a guess.
    if let Some(arg) = store_url_arg {
        if let Some(env_url) = resolve_store_url(None)? {
            if env_url.trim() != arg.trim() {
                anyhow::bail!(
                    "ambiguous store: --store-url names {} but the environment \
                     (AI_MEMORY_STORE_URL / AI_MEMORY_STORE_URL_FILE) names {}. \
                     Refusing to guess which store `{verb}` should act on — \
                     unset one of them (#2444).",
                    redact_url_password(arg),
                    redact_url_password(&env_url),
                );
            }
        }
    }

    let Some(url) = resolve_store_url(store_url_arg)? else {
        // No store URL on any channel: the configured store IS the local
        // sqlite `--db` path. Unchanged pre-#2444 behaviour.
        return Ok(db_path.to_path_buf());
    };

    if is_postgres_url(&url) {
        if let Some(alt) = pg_alternative {
            anyhow::bail!(
                "`ai-memory {verb}` operates on a local SQLite database only, but this \
                 deployment's configured store is Postgres ({}). Refusing — {alt} (#2572).",
                redact_url_password(&url)
            );
        }
        anyhow::bail!(
            "`ai-memory {verb}` acts on a local SQLite database only, but this \
             deployment's configured store is Postgres ({}). Refusing — a SQLite \
             artifact would NOT contain the corpus, and a restore from it would \
             silently return nothing. Use `pg_dump` (or `pg_basebackup` + WAL \
             archiving) instead; see docs/production-deployment.md (#2444, #2490).",
            redact_url_password(&url)
        );
    }

    if let Some(path) = url.strip_prefix(SQLITE_URL_SCHEME) {
        // `sqlite:///abs` → `/abs`; `sqlite://./rel` → `./rel`. Same
        // normalisation `migrate::open_store` applies, so the two agree on
        // which file a given URL names.
        let clean = path
            .strip_prefix('/')
            .map_or(path, |p| if p.starts_with('/') { p } else { path });
        if clean.is_empty() {
            anyhow::bail!(
                "store URL {SQLITE_URL_SCHEME} names no path — refusing to guess \
                 which database `{verb}` should act on (#2444)"
            );
        }
        let resolved = PathBuf::from(clean);
        if resolved != db_path {
            match disagreement {
                StoreDisagreement::RedirectWithNote => {
                    // The store URL is authoritative for `serve`
                    // (`build_store_handle` takes it over `--db`), so it is
                    // authoritative here too. Say so loudly rather than
                    // silently capturing a different file.
                    writeln!(
                        out.stderr,
                        "note: acting on the configured store {} (the --db path {} is not the store)",
                        resolved.display(),
                        db_path.display()
                    )?;
                }
                StoreDisagreement::Refuse => {
                    // #2490 — `{verb}` WRITES. Redirecting a write to a file
                    // the operator did not name is worse than refusing it.
                    anyhow::bail!(
                        "ambiguous target: the configured store is {} but --db names {}. \
                         Refusing — `ai-memory {verb}` WRITES, and an ambient \
                         AI_MEMORY_STORE_URL (the documented cron/shell posture) would \
                         otherwise redirect this write into a database you did not name \
                         on the command line. Point --db at the configured store, or \
                         unset the store URL for this invocation (#2490).",
                        resolved.display(),
                        db_path.display()
                    );
                }
            }
        }
        return Ok(resolved);
    }

    anyhow::bail!(
        "unrecognised store URL: {} (expected sqlite:///path or postgres://...). \
         Refusing to fall back to the local --db file, because that would produce \
         a snapshot of a database this deployment does not serve (#2444).",
        redact_url_password(&url)
    )
}

/// `backup` handler.
pub fn run_backup(
    db_path: &Path,
    args: &BackupArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use std::io::Read;
    // #2444 — resolve (and where necessary REFUSE) the configured store BEFORE
    // anything is created on disk. A backup that cannot capture the configured
    // store must ERROR, never produce an artifact.
    let source_db = resolve_sqlite_source(db_path, args.store_url.as_deref(), VERB_BACKUP, out)?;
    // #2444 — `db::open` CREATES the file when absent (src/storage/connection.rs)
    // and then runs the bootstrap schema + the whole migration ladder on it, so
    // the created file is NOT distinguishable from a real database by any
    // schema probe. The only honest discriminator is that it did not exist, so
    // check that before the open can bring it into being.
    if !source_db.exists() {
        anyhow::bail!(
            "no SQLite database at {} — refusing to create one and snapshot it. \
             A backup of a database that does not exist would produce an empty \
             artifact carrying a VALID checksum, and the DR restore from it \
             would silently return nothing (#2444).",
            source_db.display()
        );
    }
    std::fs::create_dir_all(&args.to)
        .with_context(|| format!("creating backup dir {}", args.to.display()))?;
    // SQLite VACUUM INTO is hot-backup-safe and produces a defragmented
    // file. Equivalent to `sqlite3 source '.backup dest'` in effect but
    // runs in-process via our existing connection.
    // v1.0.0 #2445 — EGRESS FALLBACK. `db::open` now REFUSES a database whose
    // schema is ahead of this binary, and that refusal must never cost the
    // operator their backup: snapshotting the durable text is the FIRST thing
    // a competent operator does in exactly this incident, and `VACUUM INTO`
    // copies bytes it does not have to understand. So on that ONE typed error
    // we re-open through the unmigrated funnel (no bootstrap DDL, no ladder,
    // no trigger install) and proceed. Every other open failure still
    // propagates. `open_read_only` cannot serve this path — `PRAGMA
    // query_only = ON` refuses `VACUUM INTO` (verified, not assumed).
    let conn = match db::open(&source_db) {
        Ok(conn) => conn,
        Err(e) if crate::storage::schema_guard::schema_ahead_of(&e).is_some() => {
            tracing::warn!(
                target: crate::storage::schema_guard::TRACE_TARGET,
                error = %e,
                "database schema is ahead of this binary — taking the snapshot anyway \
                 through the read-oriented funnel so the durable text is preserved"
            );
            db::open_unmigrated(&source_db)
                .context("opening source DB for backup (schema-ahead fallback)")?
        }
        Err(e) => return Err(e.context("opening source DB for backup")),
    };
    // #2444 — provenance recorded INTO the manifest so the artifact is
    // self-describing: which backend produced it, which migration ladder it is
    // on, and how many memories it actually contains.
    let memory_count: i64 = conn
        .query_row(
            crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
            [],
            |r| r.get(0),
        )
        .context("counting memories in the source DB")?;
    let schema_version: i64 = conn
        .query_row(
            crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL,
            [],
            |r| r.get(0),
        )
        .context("reading the source DB schema version")?;
    let ts = chrono::Utc::now().format(BACKUP_TS_FMT).to_string();
    let snapshot_name = format!("ai-memory-{ts}.db");
    let snapshot_path = args.to.join(&snapshot_name);
    if snapshot_path.exists() {
        anyhow::bail!(
            "refusing to overwrite existing snapshot {}",
            snapshot_path.display()
        );
    }
    conn.execute(
        "VACUUM INTO ?1",
        rusqlite::params![snapshot_path.to_string_lossy()],
    )
    .context("VACUUM INTO failed")?;
    drop(conn);

    let bytes = std::fs::metadata(&snapshot_path)?.len();
    let sha = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut f = std::fs::File::open(&snapshot_path)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        format!("{:x}", hasher.finalize())
    };

    let manifest = BackupManifest {
        snapshot: snapshot_name.clone(),
        sha256: sha.clone(),
        bytes,
        source_db: source_db.to_string_lossy().into_owned(),
        version: crate::PKG_VERSION.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        backend: Some(BACKEND_SQLITE.to_string()),
        schema_version: Some(schema_version),
        memory_count: Some(memory_count),
    };
    let manifest_path = args.to.join(format!("ai-memory-{ts}.manifest.json"));
    let manifest_text = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&manifest_path, manifest_text.as_bytes())?;

    // Rotation — newest-first listing, drop everything past `keep`.
    if args.keep > 0 {
        prune_old_snapshots(&args.to, args.keep)?;
    }

    // #2444 — an empty corpus is REPORTED, not refused. A row count cannot
    // tell a legitimately-fresh SQLite deployment apart from a wrong-store
    // capture (and on a Postgres host the local sqlite sidecar legitimately
    // holds 0 memories while carrying the only copy of the governance audit
    // spine), so refusing here would both miss the migrated-host case and
    // false-refuse real data. The store guard above is the structural control;
    // this is the honest signal. (3x3 adversarial vote, this session.)
    if memory_count == 0 {
        writeln!(
            out.stderr,
            "WARNING: this snapshot contains 0 memories (source {}). If this \
             deployment's corpus lives in Postgres, `ai-memory backup` did NOT \
             capture it — use pg_dump / pg_basebackup, and pass --store-url so \
             the command can refuse instead of guessing. See \
             docs/production-deployment.md (#2444).",
            source_db.display()
        )?;
    }

    if json_out {
        writeln!(out.stdout, "{}", serde_json::to_string(&manifest)?)?;
    } else {
        writeln!(out.stdout, "Snapshot: {}", snapshot_path.display())?;
        writeln!(out.stdout, "Manifest: {}", manifest_path.display())?;
        writeln!(out.stdout, "SHA-256 : {sha}")?;
        writeln!(out.stdout, "Bytes   : {bytes}")?;
        writeln!(out.stdout, "Memories: {memory_count}")?;
    }
    Ok(())
}

/// Enumerate existing `ai-memory-*.db` snapshot files newest-first and
/// delete everything past `keep`. Also deletes the matching manifest
/// for each removed snapshot.
fn prune_old_snapshots(dir: &Path, keep: usize) -> Result<()> {
    let mut snaps: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_owned();
            let is_snapshot = name.starts_with("ai-memory-")
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("db"));
            if is_snapshot {
                let mtime = entry.metadata().ok()?.modified().ok()?;
                Some((mtime, path))
            } else {
                None
            }
        })
        .collect();
    snaps.sort_by_key(|b| std::cmp::Reverse(b.0));
    for (_, path) in snaps.into_iter().skip(keep) {
        let _ = std::fs::remove_file(&path);
        // Matching manifest (same stem, .manifest.json extension pattern)
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            let manifest = dir.join(manifest_file_name(stem));
            let _ = std::fs::remove_file(manifest);
        }
    }
    Ok(())
}

/// `restore` handler.
pub fn run_restore(
    db_path: &Path,
    args: &RestoreArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use std::io::Read;
    // #2444 — a restore onto a Postgres-backed deployment would copy a SQLite
    // snapshot to a placeholder path, print "Restored", and exit 0 while the
    // real corpus was never touched. That is the false-assurance half of the
    // same defect, and it lands at the exact moment it cannot be fixed.
    let target_db = resolve_sqlite_source(db_path, args.store_url.as_deref(), VERB_RESTORE, out)?;
    let (snapshot_path, manifest_path) = if args.from.is_dir() {
        // Pick the newest snapshot in the directory.
        let mut snaps: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&args.from)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let name = path.file_name()?.to_str()?.to_owned();
                let is_snapshot = name.starts_with("ai-memory-")
                    && path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("db"));
                if is_snapshot {
                    let mtime = entry.metadata().ok()?.modified().ok()?;
                    Some((mtime, path))
                } else {
                    None
                }
            })
            .collect();
        snaps.sort_by_key(|b| std::cmp::Reverse(b.0));
        let snap = snaps
            .into_iter()
            .next()
            .map(|(_, p)| p)
            .ok_or_else(|| anyhow::anyhow!("no snapshots found in {}", args.from.display()))?;
        let stem = snap.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let manifest = args.from.join(manifest_file_name(stem));
        (snap, manifest)
    } else {
        // File path supplied directly.
        let snap = args.from.clone();
        let stem = snap.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parent = snap.parent().unwrap_or_else(|| Path::new("."));
        let manifest = parent.join(manifest_file_name(stem));
        (snap, manifest)
    };

    if !snapshot_path.exists() {
        anyhow::bail!("snapshot {} does not exist", snapshot_path.display());
    }

    // SHA-256 verification against manifest.
    if !args.skip_verify {
        if !manifest_path.exists() {
            anyhow::bail!(
                "manifest {} not found; pass --skip-verify to restore anyway",
                manifest_path.display()
            );
        }
        let manifest_text = std::fs::read_to_string(&manifest_path)?;
        let manifest: BackupManifest = serde_json::from_str(&manifest_text)
            .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
        // #2444 — cross-backend refusal. The manifest field is `Option` so a
        // pre-#2444 manifest (no `backend` key) still restores; a snapshot that
        // POSITIVELY declares a non-sqlite origin is refused rather than copied
        // onto a SQLite path.
        if let Some(backend) = manifest.backend.as_deref() {
            if backend != BACKEND_SQLITE {
                anyhow::bail!(
                    "snapshot {} declares backend `{backend}`, but `restore` writes a \
                     local SQLite database. Refusing a cross-backend restore (#2444).",
                    snapshot_path.display()
                );
            }
        }
        // #2444 — forward-schema refusal. Restoring a snapshot taken by a NEWER
        // binary onto this one opens cleanly (the ladder only ever migrates
        // FORWARD) and then writes rows that silently drop the newer columns.
        // Refuse: degrade loudly rather than corrupt quietly.
        if let Some(snap_version) = manifest.schema_version {
            let ours = crate::storage::migrations::current_schema_version();
            if snap_version > ours {
                anyhow::bail!(
                    "snapshot {} is on schema v{snap_version} but this binary \
                     understands v{ours}. Refusing — restoring it would open cleanly \
                     and then silently drop the newer columns on the next write. \
                     Restore with ai-memory >= the version that took the snapshot \
                     (#2444).",
                    snapshot_path.display()
                );
            }
        }
        let observed = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            let mut f = std::fs::File::open(&snapshot_path)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            format!("{:x}", hasher.finalize())
        };
        if observed != manifest.sha256 {
            anyhow::bail!(
                "sha256 mismatch — manifest says {}, snapshot is {}",
                manifest.sha256,
                observed
            );
        }
    }

    // #2444 — STRUCTURAL validation before the live database is touched. The
    // sha256 above proves only that the bytes match the manifest WE wrote over
    // whatever `VACUUM INTO` produced (and `--skip-verify` proves nothing at
    // all), so a truncated / foreign / non-SQLite file passes it. Probe the
    // snapshot read-only: if it is not an ai-memory database this query fails,
    // and we refuse BEFORE moving the operator's live corpus aside.
    {
        let probe = db::open_read_only(&snapshot_path).with_context(|| {
            format!(
                "snapshot {} is not a readable SQLite database — refusing to restore \
                 it over the live corpus (#2444)",
                snapshot_path.display()
            )
        })?;
        let _: i64 = probe
            .query_row(
                crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
                [],
                |r| r.get(0),
            )
            .with_context(|| {
                format!(
                    "snapshot {} has no `memories` table — it is not an ai-memory \
                     database. Refusing to restore it over the live corpus (#2444)",
                    snapshot_path.display()
                )
            })?;
        // v1.0.0 #2445 — MANIFEST-INDEPENDENT forward-schema refusal. The
        // #2444 check above reads `manifest.schema_version`, and the whole
        // manifest block is nested inside `if !args.skip_verify` — so
        // `restore --skip-verify` (the ONLY way to restore the manifest-less
        // pre-migration snapshot that `snapshot_before_migration` writes)
        // bypassed it entirely and could plant a database nothing on this host
        // can then open. The probe connection is already here and already
        // read-only, so re-deriving the truth from the FILE costs one query
        // and cannot be skipped.
        let stamp = crate::storage::probe_schema_stamp(&probe).with_context(|| {
            format!(
                "cannot read the schema version of snapshot {} — refusing to \
                 restore it over the live corpus (#2445)",
                snapshot_path.display()
            )
        })?;
        crate::storage::schema_guard::evaluate(
            stamp.version(),
            crate::storage::migrations::current_schema_version(),
            crate::storage::schema_guard::BACKEND_SQLITE,
            &snapshot_path.display().to_string(),
        )?;
    }

    // Move current DB aside as a safety net (only if it exists).
    //
    // #2444 — the `-wal` / `-shm` sidecars move WITH it. Renaming only the main
    // file left the PREVIOUS database's write-ahead log sitting next to the
    // freshly-copied snapshot, where SQLite would replay those stale frames INTO
    // the restored database (corruption of the restore), and left the moved-aside
    // safety copy without its own WAL (an incomplete safety net — the thing that
    // has to survive when a restore turns out to be the wrong call).
    let ts = chrono::Utc::now().format(BACKUP_TS_FMT).to_string();
    let aside = target_db.with_extension(format!("pre-restore-{ts}.db"));
    if target_db.exists() {
        std::fs::rename(&target_db, &aside)
            .with_context(|| format!("moving current DB aside to {}", aside.display()))?;
        if !json_out {
            writeln!(out.stdout, "Previous DB moved to {}", aside.display())?;
        }
    }
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        let live_sidecar = sidecar_path(&target_db, suffix);
        if live_sidecar.exists() {
            std::fs::rename(&live_sidecar, sidecar_path(&aside, suffix)).with_context(|| {
                format!(
                    "moving stale SQLite sidecar {} aside — leaving it beside the \
                     restored database risks replaying old WAL frames into it (#2444)",
                    live_sidecar.display()
                )
            })?;
        }
    }

    std::fs::copy(&snapshot_path, &target_db)
        .with_context(|| format!("copying snapshot to {}", target_db.display()))?;

    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "status": "restored",
                "from": snapshot_path.to_string_lossy(),
                "to": target_db.to_string_lossy(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "Restored {} → {}",
            snapshot_path.display(),
            target_db.display()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    /// v1.0.0 #2572 — the class-(a) guard returns the typed Postgres refusal
    /// (naming the HTTP-daemon remedy, DSN-redacted) on a `postgres://` store
    /// URL, and is byte-transparent (returns the `--db` path unchanged) when no
    /// store URL is configured.
    ///
    /// The Postgres URL is supplied through the ARG channel, exercising the
    /// exact `Refuse` disposition + `PG_CLI_ALTERNATIVE` hint that
    /// [`refuse_pg_store`] threads — WITHOUT ever setting a process-global
    /// `AI_MEMORY_STORE_URL`. Lib tests run in parallel in one process, and a
    /// transiently-set `postgres://` env could make a concurrent `sal` test
    /// attempt a real pg connection; the env channel is instead covered by the
    /// isolated-subprocess behavioral legs in
    /// `tests/cli_write_verb_pg_refuse_ceiling_2572.rs`. The ambient env is
    /// cleared under the shared `store_url_env_lock` (#2146) so the arg is
    /// authoritative; nothing is ever SET.
    #[test]
    fn refuse_pg_store_typed_refusal_on_postgres_url_2572() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation is serialized by `store_url_env_lock`; we only
        // CLEAR (never set) so a concurrent test can never observe a pg URL.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_ENV);
            std::env::remove_var(crate::store_url::STORE_URL_FILE_ENV);
        }

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();

        // 1) No store URL (arg None, env cleared) → transparent --db pass-through.
        {
            let mut out = env.output();
            let resolved =
                refuse_pg_store(&db, "store", &mut out).expect("no store URL → pass-through");
            assert_eq!(
                resolved, db,
                "with no store URL the guard must return the --db path unchanged (#2572)"
            );
        }

        // 2) postgres:// via the ARG channel → typed refusal, HTTP-daemon remedy,
        //    DSN password redacted.
        {
            let mut out = env.output();
            let err = resolve_sqlite_store(
                &db,
                Some("postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory"),
                "store",
                StoreDisagreement::Refuse,
                Some(PG_CLI_ALTERNATIVE),
                &mut out,
            )
            .expect_err("postgres:// must refuse (#2572)");
            let msg = err.to_string();
            assert!(msg.contains("#2572"), "refusal must cite #2572: {msg}");
            assert!(
                msg.contains("HTTP daemon"),
                "refusal must name the HTTP-daemon remedy, not pg_dump: {msg}"
            );
            assert!(
                !msg.contains("hunter2"),
                "refusal must redact the DSN password: {msg}"
            );
        }
    }

    #[test]
    fn test_backup_happy_path_creates_snapshot_and_manifest() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x1");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, false, &mut out).unwrap();
        }
        // At least one snapshot + manifest must exist.
        let mut snap_count = 0;
        let mut manifest_count = 0;
        for entry in std::fs::read_dir(&backup_dir).unwrap().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("ai-memory-") && s.ends_with(".db") {
                snap_count += 1;
            }
            if s.ends_with(".manifest.json") {
                manifest_count += 1;
            }
        }
        assert!(snap_count >= 1, "expected at least one snapshot");
        assert!(manifest_count >= 1, "expected at least one manifest");
        assert!(env.stdout_str().contains("Snapshot:"));
    }

    #[test]
    fn test_backup_json_emits_manifest_with_sha256() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x2");
        let args = BackupArgs {
            to: backup_dir,
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["sha256"].is_string());
        let sha = v["sha256"].as_str().unwrap();
        assert_eq!(sha.len(), 64); // hex sha256
    }

    #[test]
    fn test_restore_from_directory_picks_newest() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "before-backup", "stuff");
        let backup_dir = db.parent().unwrap().join("backups-x3");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, false, &mut out).unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: backup_dir,
            skip_verify: false,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("Restored"));
    }

    #[test]
    fn test_restore_from_explicit_file_path() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x4");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let snap_path = backup_dir.join(&manifest.snapshot);
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: snap_path,
            skip_verify: false,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["status"].as_str().unwrap(), "restored");
    }

    #[test]
    fn test_restore_with_skip_verify_succeeds_without_manifest() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x5");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let snap_path = backup_dir.join(&manifest.snapshot);
        // Delete manifest file so verification would fail; skip_verify = true should still pass.
        let manifest_path = backup_dir.join(format!(
            "{}.manifest.json",
            snap_path.file_stem().unwrap().to_string_lossy()
        ));
        std::fs::remove_file(&manifest_path).unwrap();
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: snap_path,
            skip_verify: true,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("Restored"));
    }

    #[test]
    fn test_restore_bad_sha256_errors() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x6");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let manifest_path = backup_dir.join(format!(
            "{}.manifest.json",
            std::path::Path::new(&manifest.snapshot)
                .file_stem()
                .unwrap()
                .to_string_lossy()
        ));
        // Corrupt sha in manifest.
        let mut bad = manifest;
        bad.sha256 = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        std::fs::write(&manifest_path, serde_json::to_string(&bad).unwrap()).unwrap();
        let snap_path = backup_dir.join(&bad.snapshot);
        let restore_args = RestoreArgs {
            from: snap_path,
            skip_verify: false,
            store_url: None,
        };
        let mut out = env.output();
        let res = run_restore(&db, &restore_args, false, &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn test_backup_retention_prunes_old_snapshots() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x7");
        // Take a few backups in succession; with `keep=1` only the newest must remain.
        for _ in 0..3 {
            // Sleep 1 second to avoid filename collision (BACKUP_TS_FMT is per-second).
            std::thread::sleep(std::time::Duration::from_secs(1));
            let args = BackupArgs {
                to: backup_dir.clone(),
                keep: 1,
                store_url: None,
            };
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
            drop(out);
            env.stdout.clear();
            env.stderr.clear();
        }
        let snaps: Vec<_> = std::fs::read_dir(&backup_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with("ai-memory-") && s.ends_with(".db")
            })
            .collect();
        assert_eq!(snaps.len(), 1, "retention should keep exactly 1 snapshot");
    }

    // ------------------------------------------------------------------
    // #2444 — fail-closed store guard + restore hardening.
    //
    // These complement `tests/backup_fail_closed_2444.rs`, which carries the
    // R-203 before/after evidence by driving the real binary through the env
    // channel. The unit tests below exercise the arms that are awkward to
    // reach through a subprocess (a forward-schema manifest, a corrupt
    // snapshot, WAL sidecar handling) and the `--store-url` ARGUMENT channel.
    // ------------------------------------------------------------------

    /// A postgres store declared on the flag is refused, and the message names
    /// the supported path. The credential in the DSN is redacted.
    #[test]
    fn backup_refuses_a_postgres_store_url_argument_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-pg"),
            keep: 48,
            store_url: Some("postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory".to_string()),
        };
        let mut out = env.output();
        let err = run_backup(&db, &args, false, &mut out)
            .expect_err("a postgres store must be refused")
            .to_string();
        assert!(err.contains("pg_dump"), "got: {err}");
        assert!(!err.contains("hunter2"), "DSN password leaked: {err}");
    }

    /// `restore` refuses the same store — the false-assurance half of #2444.
    #[test]
    fn restore_refuses_a_postgres_store_url_argument_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = RestoreArgs {
            from: db.parent().unwrap().join("backups-2444-pg-restore"),
            skip_verify: false,
            store_url: Some("postgresql://ai_memory:hunter2@127.0.0.1:5432/ai".to_string()),
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("restoring onto a postgres store must be refused")
            .to_string();
        assert!(err.contains("pg_dump"), "got: {err}");
        assert!(!err.contains("hunter2"), "DSN password leaked: {err}");
    }

    /// An unrecognised scheme must NOT fall back to the local `--db` file —
    /// that fallback is precisely how a snapshot of the wrong database gets a
    /// valid manifest.
    #[test]
    fn backup_refuses_an_unrecognised_store_url_scheme_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-scheme");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: Some("mysql://localhost/ai_memory".to_string()),
        };
        {
            let mut out = env.output();
            let err = run_backup(&db, &args, false, &mut out)
                .expect_err("an unrecognised scheme must be refused")
                .to_string();
            assert!(err.contains("unrecognised store URL"), "got: {err}");
        }
        assert_eq!(
            snapshot_count(&backup_dir),
            0,
            "a refused backup must leave no snapshot"
        );
    }

    /// `backup` must not CREATE the database it claims to capture. `db::open`
    /// would have created AND fully migrated it, so the resulting file is
    /// indistinguishable from a real one by any schema probe — the existence
    /// check has to happen first.
    #[test]
    fn backup_refuses_to_create_a_missing_source_database_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let missing = db.parent().unwrap().join("never-created-2444.db");
        let backup_dir = db.parent().unwrap().join("backups-2444-missing");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            let err = run_backup(&missing, &args, false, &mut out)
                .expect_err("a missing source DB must be refused")
                .to_string();
            assert!(err.contains("refusing to create"), "got: {err}");
        }
        assert!(!missing.exists(), "backup created the source database");
        assert_eq!(snapshot_count(&backup_dir), 0);
    }

    /// The manifest is self-describing: backend, applied schema version, and
    /// the row count actually captured.
    #[test]
    fn backup_manifest_records_backend_schema_and_memory_count_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-manifest"),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(manifest.backend.as_deref(), Some(BACKEND_SQLITE));
        assert_eq!(
            manifest.schema_version,
            Some(crate::storage::migrations::current_schema_version())
        );
        assert_eq!(manifest.memory_count, Some(1));
    }

    /// A zero-memory snapshot is WARNed, never refused: a row count cannot
    /// tell a legitimately fresh deployment from a wrong-store capture, and
    /// refusing would strand the sqlite governance sidecar on a pg host.
    #[test]
    fn backup_warns_but_succeeds_on_an_empty_corpus_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Bring the database into existence WITHOUT storing any memory.
        drop(db::open(&db).unwrap());
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-empty"),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, false, &mut out).expect("an empty corpus still backs up");
        }
        assert!(
            env.stderr_str().contains("0 memories"),
            "an empty snapshot must be reported; stderr was: {}",
            env.stderr_str()
        );
    }

    /// A manifest that POSITIVELY declares a non-sqlite origin is refused
    /// rather than copied onto a SQLite path.
    #[test]
    fn restore_refuses_a_cross_backend_manifest_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-xbackend");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        let mut tampered = manifest;
        tampered.backend = Some("postgres".to_string());
        let snap = backup_dir.join(&tampered.snapshot);
        std::fs::write(&manifest_path, serde_json::to_string(&tampered).unwrap()).unwrap();

        let args = RestoreArgs {
            from: snap,
            skip_verify: false,
            store_url: None,
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("a cross-backend snapshot must be refused")
            .to_string();
        assert!(err.contains("cross-backend"), "got: {err}");
    }

    /// A snapshot from a NEWER binary opens cleanly (the ladder only migrates
    /// forward) and then silently drops the newer columns on the next write.
    /// Refuse instead.
    #[test]
    fn restore_refuses_a_forward_schema_snapshot_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-forward");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        let mut tampered = manifest;
        tampered.schema_version = Some(crate::storage::migrations::current_schema_version() + 1);
        let snap = backup_dir.join(&tampered.snapshot);
        std::fs::write(&manifest_path, serde_json::to_string(&tampered).unwrap()).unwrap();

        let args = RestoreArgs {
            from: snap,
            skip_verify: false,
            store_url: None,
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("a forward-schema snapshot must be refused")
            .to_string();
        assert!(err.contains("understands v"), "got: {err}");
    }

    /// A pre-#2444 manifest carries none of the new keys; it must still
    /// restore (`#[serde(default)]`), because refusing every artifact an
    /// operator already holds would be its own data-loss event.
    #[test]
    fn restore_accepts_a_legacy_manifest_without_the_new_fields_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-legacy");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        // Re-serialise WITHOUT the #2444 keys, exactly as v0.9 would have.
        let legacy = serde_json::json!({
            "snapshot": manifest.snapshot,
            "sha256": manifest.sha256,
            "bytes": manifest.bytes,
            "source_db": manifest.source_db,
            "version": manifest.version,
            "created_at": manifest.created_at,
        });
        std::fs::write(&manifest_path, serde_json::to_string(&legacy).unwrap()).unwrap();

        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            skip_verify: false,
            store_url: None,
        };
        let mut out = env.output();
        run_restore(&db, &args, false, &mut out).expect("a legacy manifest must still restore");
    }

    /// The sha256 only proves the bytes match a manifest WE wrote over
    /// whatever was produced — and `--skip-verify` proves nothing at all. A
    /// foreign / truncated file must be refused BEFORE the live corpus is
    /// moved aside.
    #[test]
    fn restore_refuses_a_snapshot_that_is_not_an_ai_memory_database_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "survivor", "must not be clobbered");
        let backup_dir = db.parent().unwrap().join("backups-2444-garbage");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let bogus = backup_dir.join("ai-memory-2026-01-01T000000Z.db");
        std::fs::write(&bogus, b"this is not a sqlite database at all").unwrap();

        let live_before = std::fs::metadata(&db).unwrap().len();
        let args = RestoreArgs {
            from: bogus,
            skip_verify: true,
            store_url: None,
        };
        {
            let mut out = env.output();
            let err = run_restore(&db, &args, false, &mut out)
                .expect_err("a non-ai-memory snapshot must be refused")
                .to_string();
            assert!(
                err.contains("not an ai-memory database"),
                "refusal must say it will not clobber the live corpus; got: {err}"
            );
        }
        assert_eq!(
            std::fs::metadata(&db).unwrap().len(),
            live_before,
            "a refused restore must not touch the live database"
        );
    }

    /// Renaming `<db>` aside without its `-wal` / `-shm` left the PREVIOUS
    /// database's write-ahead log beside the freshly copied snapshot, where
    /// SQLite can replay stale frames INTO the restored corpus.
    #[test]
    fn restore_moves_the_wal_and_shm_sidecars_aside_2444() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-wal");
        let manifest = take_backup(&mut env, &db, &backup_dir);

        // Plant sidecars that must not survive next to the restored file.
        let live_wal = sidecar_path(&db, "-wal");
        let live_shm = sidecar_path(&db, "-shm");
        std::fs::write(&live_wal, b"stale wal frames").unwrap();
        std::fs::write(&live_shm, b"stale shm").unwrap();

        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            skip_verify: false,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_restore(&db, &args, false, &mut out).unwrap();
        }
        assert!(
            !live_wal.exists(),
            "a stale -wal beside the restored DB can be replayed into it"
        );
        assert!(!live_shm.exists(), "a stale -shm must not survive either");

        // And they moved WITH the safety copy, not into the void — the
        // pre-restore snapshot has to stay recoverable.
        let dir = db.parent().unwrap();
        let aside_sidecars = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.contains("pre-restore-") && (n.ends_with("-wal") || n.ends_with("-shm"))
            })
            .count();
        assert_eq!(aside_sidecars, 2, "both sidecars must be preserved aside");
    }

    // -- helpers -------------------------------------------------------

    fn snapshot_count(dir: &Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .flatten()
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.starts_with("ai-memory-") && n.ends_with(".db")
                })
                .count()
        })
    }

    fn manifest_path_for(dir: &Path, snapshot: &str) -> PathBuf {
        let stem = Path::new(snapshot).file_stem().unwrap().to_string_lossy();
        dir.join(manifest_file_name(&stem))
    }

    /// Take a real backup and return the parsed manifest, clearing the
    /// captured buffers so the caller's assertions see only their own output.
    fn take_backup(env: &mut TestEnv, db: &Path, backup_dir: &Path) -> BackupManifest {
        let args = BackupArgs {
            to: backup_dir.to_path_buf(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(db, &args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        env.stdout.clear();
        env.stderr.clear();
        manifest
    }
}
