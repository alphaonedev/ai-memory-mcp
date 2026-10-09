// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6383 / #6386 — per-binary Postgres database isolation.
//!
//! Every integration-test binary that talks to the shared CI Postgres tier
//! used to share ONE database, which is why the class-(a) binaries had to run
//! one after another. With `AI_MEMORY_TEST_PG_ISOLATE=1` each binary gets its
//! own database cloned from a never-connected template
//! (`CREATE DATABASE ... TEMPLATE`), so binaries can run side by side.
//!
//! Two layers, both default OFF:
//!
//! * **CI** (primary): `scripts/test/pg_isolated_binary.py` mints the clone and
//!   exports the minted `AI_MEMORY_TEST_POSTGRES_URL` before it launches
//!   `cargo test --test <bin>`, so the ~200 test files that read the variable
//!   directly need no edit. The URL it hands out already names an
//!   `ai_memory_t_*` database, and this helper then does nothing.
//! * **Local / library** (this file): [`isolated_url`] mints once per process
//!   when the flag is on and the URL is not already isolated, then publishes
//!   the minted URL to the process environment under the shared env lock so
//!   child processes inherit it.
//!
//! Fail closed: flag on but the clone cannot be made is a panic with the
//! reason, never a silent fall back to the shared database. Flag off is
//! byte-for-byte today's behaviour.
//!
//! A minted database is reclaimed by the sweep (process-exit `Drop` is not
//! reliable under libtest). The sweep drops only databases that match the exact
//! name shape, are older than [`STALE_AFTER`], AND have no live session, so a
//! concurrent run's long binary is never dropped.
//!
//! Names are `ai_memory_t_<10-digit unix seconds>_<8 hex>`: the exact shape
//! `pg_barrier::parse_scratch_name` recognises. The binary name goes to the log
//! line, not the identifier.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant};

use sqlx::Connection as _;
use sqlx::postgres::PgPoolOptions;

#[path = "pg_barrier.rs"]
mod pg_barrier;

pub use pg_barrier::with_database;

/// Opt-in switch; only the exact value `1` enables isolation.
pub const FLAG_VAR: &str = "AI_MEMORY_TEST_PG_ISOLATE";
/// Template database to clone (default: the database of the base URL).
pub const TEMPLATE_VAR: &str = "AI_MEMORY_TEST_PG_TEMPLATE";
/// The URL every test reads.
pub const URL_VAR: &str = "AI_MEMORY_TEST_POSTGRES_URL";
/// The Apache AGE sibling URL.
pub const AGE_URL_VAR: &str = "AI_MEMORY_TEST_AGE_URL";
/// Name prefix of a minted database (a `_` and the shape suffix follow).
pub const ISOLATED_PREFIX: &str = "ai_memory_t";
/// Age past which an idle minted database is an orphan.
pub const STALE_AFTER: Duration = pg_barrier::STALE_SCRATCH_AGE;

/// `CREATE DATABASE ... TEMPLATE` attempts (the template must have no session).
const MINT_ATTEMPTS: u32 = 3;
/// Pause between attempts, multiplied by the attempt number.
const RETRY_PAUSE: Duration = Duration::from_millis(500);
/// SQLSTATE `object_in_use`: the source database is being accessed by others.
const IN_USE_SQLSTATE: &str = "55006";
/// Bound on every connect so an unreachable host cannot hang a test binary.
const IO_BOUND: Duration = Duration::from_secs(60);
/// How long publishing to the environment waits for the shared env lock.
const ENV_LOCK_WAIT: Duration = Duration::from_secs(30);

/// What to do with the URL a test asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Hand the value back unchanged.
    Passthrough(Option<String>),
    /// Clone a database for this process, then rewrite the URL to it.
    Mint { base: String },
}

/// Decide, purely, from the flag value and the URL. Only the exact flag `1`
/// mints, and a URL that already names an isolated database is left alone.
#[must_use]
pub fn plan(flag: Option<&str>, url: Option<&str>) -> Plan {
    let Some(url) = url else {
        return Plan::Passthrough(None);
    };
    if flag == Some("1") && !is_isolated_url(url) {
        Plan::Mint {
            base: url.to_string(),
        }
    } else {
        Plan::Passthrough(Some(url.to_string()))
    }
}

/// True when the URL's database is a minted `ai_memory_t_*` one.
#[must_use]
pub fn is_isolated_url(url: &str) -> bool {
    super::lane_db::database_name(url).starts_with("ai_memory_t_")
}

/// A fresh minted-database name for `now_unix`.
#[must_use]
pub fn isolated_db_name(now_unix: u64) -> String {
    pg_barrier::scratch_db_name(ISOLATED_PREFIX, now_unix)
}

/// Creation time embedded in a minted name, `None` for any other shape.
#[must_use]
pub fn parse_isolated_name(name: &str) -> Option<u64> {
    pg_barrier::parse_scratch_name(ISOLATED_PREFIX, name)
}

static ISOLATED: OnceLock<Option<String>> = OnceLock::new();

/// The Postgres URL tests should use: the raw `AI_MEMORY_TEST_POSTGRES_URL`
/// when isolation is off (today's behaviour), else this process's own clone
/// (minted once and cached).
///
/// # Panics
///
/// With the reason when the flag is on and the clone cannot be created.
#[must_use]
pub fn isolated_url() -> Option<String> {
    // Flag off: read the environment live on every call, exactly as before.
    if std::env::var(FLAG_VAR).ok().as_deref() != Some("1") {
        return std::env::var(URL_VAR).ok();
    }
    ISOLATED.get_or_init(resolve).clone()
}

fn resolve() -> Option<String> {
    let flag = std::env::var(FLAG_VAR).ok();
    let url = std::env::var(URL_VAR).ok();
    match plan(flag.as_deref(), url.as_deref()) {
        Plan::Passthrough(found) => found,
        Plan::Mint { base } => {
            let template = std::env::var(TEMPLATE_VAR)
                .unwrap_or_else(|_| super::lane_db::database_name(&base).to_string());
            match mint_blocking(&base, &template) {
                Ok(minted) => {
                    let name = super::lane_db::database_name(&minted).to_string();
                    publish_env(&base, &name, &minted);
                    eprintln!("[pg_isolate] {} -> {name}", exe_stem());
                    Some(minted)
                }
                Err(why) => panic!(
                    "#6383: {FLAG_VAR}=1 but this binary's isolated database could not be \
                     created from template `{template}`: {why}"
                ),
            }
        }
    }
}

fn exe_stem() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown-binary".to_string())
}

/// Take the shared env lock, giving up after [`ENV_LOCK_WAIT`] so a caller that
/// already holds an `EnvVarGuard` cannot deadlock this thread.
fn lock_env_bounded() -> Option<MutexGuard<'static, ()>> {
    let deadline = Instant::now() + ENV_LOCK_WAIT;
    loop {
        match super::ENV_LOCK.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

/// True when both URLs name the same server and credentials (database and
/// query ignored).
fn same_server(a: &str, b: &str) -> bool {
    let head = |u: &str| with_database(u, "").split('?').next().map(str::to_string);
    head(a).is_some() && head(a) == head(b)
}

/// Point the process environment at the minted database so every raw env reader
/// and every spawned child sees it. On env-lock timeout the cached return value
/// of [`isolated_url`] is still isolated; only raw env readers are not.
fn publish_env(base: &str, name: &str, minted: &str) {
    let Some(_guard) = lock_env_bounded() else {
        eprintln!(
            "WARN: [pg_isolate] env lock busy for {}s; {URL_VAR} left unchanged, helper callers \
             still get the isolated URL",
            ENV_LOCK_WAIT.as_secs()
        );
        return;
    };
    // SAFETY: env mutation is serialised by `ENV_LOCK`, held in `_guard`.
    unsafe {
        std::env::set_var(URL_VAR, minted);
        if let Ok(age) = std::env::var(AGE_URL_VAR)
            && same_server(base, &age)
        {
            std::env::set_var(AGE_URL_VAR, with_database(&age, name));
        }
    }
}

/// Run `fut` to completion on its own thread and runtime, so it works from a
/// sync fn called inside or outside an async test.
fn run_blocking<T, F>(fut: F) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name("pg-isolate".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not build a runtime: {e}"))?;
            rt.block_on(fut)
        })
        .map_err(|e| format!("could not spawn a thread: {e}"))?;
    handle
        .join()
        .map_err(|_| "the pg-isolate thread panicked".to_string())?
}

fn is_template_in_use(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == IN_USE_SQLSTATE)
}

/// Mint one database from `template` on the server `base` points at and return
/// its URL (query string preserved).
///
/// # Errors
///
/// Connecting, the sweep listing, or every `CREATE DATABASE` attempt failed.
pub fn mint_blocking(base: &str, template: &str) -> Result<String, String> {
    let (base, template) = (base.to_string(), template.to_string());
    run_blocking(async move {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(IO_BOUND)
            .connect(&base)
            .await
            .map_err(|e| format!("could not connect the admin connection: {e}"))?;
        let minted = mint_with(&admin, &base, &template).await;
        admin.close().await;
        minted
    })
}

async fn mint_with(admin: &sqlx::PgPool, base: &str, template: &str) -> Result<String, String> {
    let now = pg_barrier::server_unix(admin)
        .await
        .map_err(|e| format!("could not read the server clock: {e}"))?;
    match sweep_idle_stale(admin, now).await {
        Ok(dropped) if !dropped.is_empty() => {
            eprintln!("[pg_isolate] swept {} orphan database(s)", dropped.len());
        }
        Ok(_) => {}
        Err(e) => eprintln!("WARN: [pg_isolate] orphan sweep failed (continuing): {e}"),
    }
    let name = isolated_db_name(now);
    let sql = format!(
        "CREATE DATABASE {} TEMPLATE {}",
        pg_barrier::quote_ident(&name),
        pg_barrier::quote_ident(template)
    );
    for attempt in 1..=MINT_ATTEMPTS {
        match sqlx::query(&sql).execute(admin).await {
            Ok(_) => return Ok(with_database(base, &name)),
            Err(e) if is_template_in_use(&e) && attempt < MINT_ATTEMPTS => {
                tokio::time::sleep(RETRY_PAUSE * attempt).await;
            }
            Err(e) => {
                return Err(format!(
                    "CREATE DATABASE {name} TEMPLATE {template} failed (attempt \
                     {attempt}/{MINT_ATTEMPTS}): {e}"
                ));
            }
        }
    }
    Err("no CREATE DATABASE attempt was made".to_string())
}

/// Drop every minted database that is stale AND idle (no live session). A
/// fresh one, one with a session, and any name that does not match the exact
/// shape are left alone. Returns the dropped names.
async fn sweep_idle_stale(admin: &sqlx::PgPool, now_unix: u64) -> Result<Vec<String>, sqlx::Error> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT d.datname::text FROM pg_database d WHERE starts_with(d.datname, $1) \
         AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
    )
    .bind(format!("{ISOLATED_PREFIX}_"))
    .fetch_all(admin)
    .await?;
    let mut dropped = Vec::new();
    for name in names {
        let Some(created) = parse_isolated_name(&name) else {
            continue;
        };
        if now_unix.saturating_sub(created) <= STALE_AFTER.as_secs() {
            continue;
        }
        let sql = format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            pg_barrier::quote_ident(&name)
        );
        match sqlx::query(&sql).execute(admin).await {
            Ok(_) => dropped.push(name),
            Err(e) => eprintln!("WARN: [pg_isolate] could not sweep {name}: {e}"),
        }
    }
    Ok(dropped)
}

/// Drop the minted database `name` through `admin_url`. Refuses any name that
/// is not an exact minted shape, so a typo can never drop a lane database.
///
/// # Errors
///
/// The name is not a minted one, or connecting or the `DROP` failed.
pub fn drop_database_blocking(admin_url: &str, name: &str) -> Result<(), String> {
    if parse_isolated_name(name).is_none() {
        return Err(format!("refusing to drop `{name}`: not a minted database name"));
    }
    let (url, name) = (admin_url.to_string(), name.to_string());
    run_blocking(async move {
        let connected = tokio::time::timeout(IO_BOUND, sqlx::PgConnection::connect(&url))
            .await
            .map_err(|_| "timed out connecting to drop the database".to_string())?;
        let mut conn = connected.map_err(|e| format!("could not connect to drop {name}: {e}"))?;
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            pg_barrier::quote_ident(&name)
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| format!("could not drop {name}: {e}"))?;
        Ok(())
    })
}

/// How many of `names` are installed as extensions in the database `url`
/// names.
///
/// # Errors
///
/// Connecting or the catalog query failed.
pub fn extension_count_blocking(url: &str, names: &[&str]) -> Result<i64, String> {
    let url = url.to_string();
    let names: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    run_blocking(async move {
        let connected = tokio::time::timeout(IO_BOUND, sqlx::PgConnection::connect(&url))
            .await
            .map_err(|_| "timed out connecting to count extensions".to_string())?;
        let mut conn = connected.map_err(|e| format!("could not connect: {e}"))?;
        sqlx::query_scalar("SELECT count(*) FROM pg_extension WHERE extname = ANY($1)")
            .bind(names)
            .fetch_one(&mut conn)
            .await
            .map_err(|e| format!("extension count failed: {e}"))
    })
}
