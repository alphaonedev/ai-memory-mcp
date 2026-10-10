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
//! **Opt-in.** Isolation is off unless the flag is exactly `1`, and
//! `CI_PG_ISOLATE_OFF=1` switches it off even then. `.github/workflows/ci.yml`
//! sets the flag on no leg; default-on waits for two green sharded carrier
//! runs and a 5-agent vote (4d3ea1c5).
//!
//! Two layers:
//!
//! * **CI** (primary): `scripts/test/pg_isolated_binary.py` mints the clone and
//!   exports the minted `AI_MEMORY_TEST_POSTGRES_URL` before it launches
//!   `cargo test --test <bin>`, so the test files that read the variable
//!   directly need no edit. The URL it hands out already names an
//!   `ai_memory_t_*` database, and this helper then does nothing.
//! * **Local / library** (this file): [`isolated_url`] mints once per process
//!   when the flag is on and the URL is not already isolated, holds a session
//!   on the clone for the life of the process, and publishes the minted URL to
//!   the process environment under the shared env lock so children inherit it.
//!
//! Fail closed: flag on but the clone cannot be made is a panic with the
//! reason, never a silent fall back to the shared database. In particular the
//! template must be named explicitly ([`TEMPLATE_VAR`]); the shared database
//! is never used as a clone source. Flag off is byte-for-byte today's
//! behaviour.
//!
//! Names are `ai_memory_t_<run id>_<10-digit unix seconds>_<8 hex>`. The run
//! id comes from [`RUN_ID_VAR`] (CI exports one per workflow run) or is
//! generated per process. Every sweep and drop here is scoped to ONE run id,
//! skips any clone with a live session, and never uses the FORCE option: a
//! database with a session cannot be dropped, so a race fails instead of
//! terminating another binary's work. Idle clones of other runs are reclaimed
//! by the CI teardown of that run or by the admin-only
//! `pg_isolated_binary.py sweep --older-than N`.

#![allow(dead_code)]

use std::future::Future;
use std::sync::mpsc;
use std::sync::{MutexGuard, OnceLock, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sqlx::Connection as _;
use sqlx::postgres::PgPoolOptions;

#[path = "pg_barrier.rs"]
mod pg_barrier;

pub use pg_barrier::with_database;

/// Opt-in switch; only the exact value `1` enables isolation.
pub const FLAG_VAR: &str = "AI_MEMORY_TEST_PG_ISOLATE";
/// Hard kill switch; the exact value `1` disables isolation even with the flag.
pub const KILL_VAR: &str = "CI_PG_ISOLATE_OFF";
/// Template database to clone. Required when minting; there is no fallback.
pub const TEMPLATE_VAR: &str = "AI_MEMORY_TEST_PG_TEMPLATE";
/// Run id embedded in every clone name (generated per process when unset).
pub const RUN_ID_VAR: &str = "AI_MEMORY_TEST_PG_RUN_ID";
/// The URL every test reads.
pub const URL_VAR: &str = "AI_MEMORY_TEST_POSTGRES_URL";
/// The Apache AGE sibling URL.
pub const AGE_URL_VAR: &str = "AI_MEMORY_TEST_AGE_URL";
/// Name prefix of a minted database (`_<run id>_` and the shape suffix follow).
pub const ISOLATED_PREFIX: &str = "ai_memory_t";
/// Longest run id; keeps every clone name inside the 63-byte identifier limit.
pub const RUN_ID_MAX_LEN: usize = 20;
/// Age past which an idle minted database of this run is an orphan.
pub const STALE_AFTER: Duration = pg_barrier::STALE_SCRATCH_AGE;

/// Longest Postgres identifier.
const IDENT_MAX: usize = 63;
/// `CREATE DATABASE ... TEMPLATE` attempts (the template must have no session).
const MINT_ATTEMPTS: u32 = 3;
/// Pause between mint attempts, multiplied by the attempt number.
const RETRY_PAUSE: Duration = Duration::from_millis(500);
/// `DROP DATABASE` attempts while a closing session drains.
const DROP_ATTEMPTS: u32 = 5;
/// Pause between drop attempts.
const DROP_PAUSE: Duration = Duration::from_millis(400);
/// SQLSTATE `object_in_use`: the database is being accessed by other users.
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

/// Decide, purely, from the flag, the kill switch and the URL. Only the exact
/// flag `1` mints, the exact kill switch `1` overrides it, and a URL that
/// already names an isolated database is left alone.
#[must_use]
pub fn plan(flag: Option<&str>, kill: Option<&str>, url: Option<&str>) -> Plan {
    let Some(url) = url else {
        return Plan::Passthrough(None);
    };
    if flag == Some("1") && kill != Some("1") && !is_isolated_url(url) {
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

/// True for a run id of the shape `[a-z0-9]{1,RUN_ID_MAX_LEN}`.
#[must_use]
pub fn is_valid_run_id(run: &str) -> bool {
    !run.is_empty()
        && run.len() <= RUN_ID_MAX_LEN
        && run
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The run id to mint under: `explicit` verbatim when valid, a fresh one when
/// absent.
///
/// # Errors
///
/// `explicit` is present but not a valid run id (fail closed, never rewritten).
pub fn run_id_from(explicit: Option<&str>) -> Result<String, String> {
    match explicit {
        Some(run) if is_valid_run_id(run) => Ok(run.to_string()),
        Some(run) => Err(format!(
            "{RUN_ID_VAR}={run:?} must match [a-z0-9]{{1,{RUN_ID_MAX_LEN}}}"
        )),
        None => {
            let id = uuid::Uuid::new_v4().simple().to_string();
            Ok(format!("p{}", &id[..11]))
        }
    }
}

/// The template to clone from. There is no default: cloning the live shared
/// database would copy whatever another binary left in it (review r1 M1).
///
/// # Errors
///
/// No template, an empty one, or a name that is not a plain identifier.
pub fn template_for_mint(template: Option<&str>) -> Result<String, String> {
    match template {
        None | Some("") => Err(format!(
            "{TEMPLATE_VAR} is unset; isolation needs an explicit template \
             (`pg_isolated_binary.py setup` creates one)"
        )),
        Some(t) if is_plain_ident(t) => Ok(t.to_string()),
        Some(t) => Err(format!("{TEMPLATE_VAR}={t:?} is not a plain identifier")),
    }
}

fn is_plain_ident(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= IDENT_MAX
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn run_prefix(run: &str) -> String {
    format!("{ISOLATED_PREFIX}_{run}")
}

/// A fresh minted-database name for run `run` at `now_unix`.
#[must_use]
pub fn isolated_db_name(run: &str, now_unix: u64) -> String {
    pg_barrier::scratch_db_name(&run_prefix(run), now_unix)
}

/// Creation time embedded in a clone name of run `run`; `None` for any other
/// shape, including another run's clone.
#[must_use]
pub fn parse_isolated_name(run: &str, name: &str) -> Option<u64> {
    if !is_valid_run_id(run) {
        return None;
    }
    pg_barrier::parse_scratch_name(&run_prefix(run), name)
}

/// The run id of any clone name, `None` when the name is not a clone.
fn run_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(ISOLATED_PREFIX)?.strip_prefix('_')?;
    let mut parts = rest.rsplitn(3, '_');
    let (_hex, _ts, run) = (parts.next()?, parts.next()?, parts.next()?);
    parse_isolated_name(run, name).map(|_| run)
}

static ISOLATED: OnceLock<Option<String>> = OnceLock::new();
static PROCESS_HOLD: OnceLock<Hold> = OnceLock::new();

/// The Postgres URL tests should use: the raw `AI_MEMORY_TEST_POSTGRES_URL`
/// when isolation is off (today's behaviour), else this process's own clone
/// (minted once and cached).
///
/// # Panics
///
/// With the reason when the flag is on and the clone cannot be created.
#[must_use]
pub fn isolated_url() -> Option<String> {
    // Flag off (or killed): read the environment live on every call, as before.
    if std::env::var(FLAG_VAR).ok().as_deref() != Some("1")
        || std::env::var(KILL_VAR).ok().as_deref() == Some("1")
    {
        return std::env::var(URL_VAR).ok();
    }
    ISOLATED.get_or_init(resolve).clone()
}

fn resolve() -> Option<String> {
    let flag = std::env::var(FLAG_VAR).ok();
    let kill = std::env::var(KILL_VAR).ok();
    let url = std::env::var(URL_VAR).ok();
    match plan(flag.as_deref(), kill.as_deref(), url.as_deref()) {
        Plan::Passthrough(found) => found,
        Plan::Mint { base } => match mint_for_process(&base) {
            Ok(minted) => Some(minted),
            Err(why) => panic!(
                "#6383: {FLAG_VAR}=1 but this binary's isolated database could not be \
                 created: {why}"
            ),
        },
    }
}

fn mint_for_process(base: &str) -> Result<String, String> {
    let template = template_for_mint(std::env::var(TEMPLATE_VAR).ok().as_deref())?;
    let run = run_id_from(std::env::var(RUN_ID_VAR).ok().as_deref())?;
    let minted = mint_blocking(base, &template, &run)?;
    let name = super::lane_db::database_name(&minted).to_string();
    match hold_blocking(&minted) {
        Ok(hold) => {
            // First and only initialisation: `resolve` runs once per process.
            let _ = PROCESS_HOLD.set(hold);
        }
        Err(why) => {
            if let Err(e) = drop_database_blocking(base, &run, &name) {
                eprintln!("WARN: [pg_isolate] could not drop {name} after a failed hold: {e}");
            }
            return Err(format!("could not hold a session on {name}: {why}"));
        }
    }
    publish_env(base, &name, &minted);
    eprintln!("[pg_isolate] {} -> {name}", exe_stem());
    Ok(minted)
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

fn is_in_use(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|c| c == IN_USE_SQLSTATE)
}

async fn connect(url: &str) -> Result<sqlx::PgConnection, String> {
    tokio::time::timeout(IO_BOUND, sqlx::PgConnection::connect(url))
        .await
        .map_err(|_| "timed out connecting".to_string())?
        .map_err(|e| format!("could not connect: {e}"))
}

/// Mint one database of run `run` from `template` on the server `base` points
/// at and return its URL (query string preserved). This run's idle stale
/// clones are swept first.
///
/// # Errors
///
/// A bad template or run id, connecting, or every `CREATE DATABASE` attempt
/// failed.
pub fn mint_blocking(base: &str, template: &str, run: &str) -> Result<String, String> {
    let template = template_for_mint(Some(template))?;
    if !is_valid_run_id(run) {
        return Err(format!("run id {run:?} is not valid"));
    }
    let (base, run) = (base.to_string(), run.to_string());
    run_blocking(async move {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(IO_BOUND)
            .connect(&base)
            .await
            .map_err(|e| format!("could not connect the admin connection: {e}"))?;
        let minted = mint_with(&admin, &base, &template, &run).await;
        admin.close().await;
        minted
    })
}

async fn mint_with(
    admin: &sqlx::PgPool,
    base: &str,
    template: &str,
    run: &str,
) -> Result<String, String> {
    let now = pg_barrier::server_unix(admin)
        .await
        .map_err(|e| format!("could not read the server clock: {e}"))?;
    match sweep_run_stale(admin, run, now).await {
        Ok(dropped) if !dropped.is_empty() => {
            eprintln!(
                "[pg_isolate] swept {} stale clone(s) of run {run}",
                dropped.len()
            );
        }
        Ok(_) => {}
        Err(e) => eprintln!("WARN: [pg_isolate] run-scoped sweep failed (continuing): {e}"),
    }
    let name = isolated_db_name(run, now);
    create_clone(admin, template, &name).await?;
    Ok(with_database(base, &name))
}

async fn create_clone(admin: &sqlx::PgPool, template: &str, name: &str) -> Result<(), String> {
    let sql = format!(
        "CREATE DATABASE {} TEMPLATE {}",
        pg_barrier::quote_ident(name),
        pg_barrier::quote_ident(template)
    );
    for attempt in 1..=MINT_ATTEMPTS {
        match sqlx::query(&sql).execute(admin).await {
            Ok(_) => return Ok(()),
            Err(e) if is_in_use(&e) && attempt < MINT_ATTEMPTS => {
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

/// Create the clone `name` (any run's exact clone shape) from `template`.
///
/// # Errors
///
/// A bad name or template, connecting, or the `CREATE DATABASE` failed.
pub fn clone_as_blocking(base: &str, template: &str, name: &str) -> Result<(), String> {
    let template = template_for_mint(Some(template))?;
    if run_of(name).is_none() {
        return Err(format!("refusing to create `{name}`: not a clone name"));
    }
    let (base, name) = (base.to_string(), name.to_string());
    run_blocking(async move {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(IO_BOUND)
            .connect(&base)
            .await
            .map_err(|e| format!("could not connect the admin connection: {e}"))?;
        let made = create_clone(&admin, &template, &name).await;
        admin.close().await;
        made
    })
}

/// Drop the idle clones of run `run` older than [`STALE_AFTER`]. A fresh one,
/// one with a session, another run's clone and any name that does not match
/// the exact shape are left alone. Returns the dropped names.
async fn sweep_run_stale(
    admin: &sqlx::PgPool,
    run: &str,
    now_unix: u64,
) -> Result<Vec<String>, sqlx::Error> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT d.datname::text FROM pg_database d WHERE starts_with(d.datname, $1) \
         AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname) \
         ORDER BY 1",
    )
    .bind(format!("{}_", run_prefix(run)))
    .fetch_all(admin)
    .await?;
    let mut dropped = Vec::new();
    for name in names {
        let Some(created) = parse_isolated_name(run, &name) else {
            continue;
        };
        if now_unix.saturating_sub(created) <= STALE_AFTER.as_secs() {
            continue;
        }
        let sql = format!("DROP DATABASE IF EXISTS {}", pg_barrier::quote_ident(&name));
        match sqlx::query(&sql).execute(admin).await {
            Ok(_) => dropped.push(name),
            Err(e) => eprintln!("WARN: [pg_isolate] could not sweep {name}: {e}"),
        }
    }
    Ok(dropped)
}

/// Run-scoped sweep through `base` (see [`STALE_AFTER`]). Returns the dropped
/// names.
///
/// # Errors
///
/// A bad run id, connecting, the clock read or the listing failed.
pub fn sweep_run_blocking(base: &str, run: &str) -> Result<Vec<String>, String> {
    if !is_valid_run_id(run) {
        return Err(format!("run id {run:?} is not valid"));
    }
    let (base, run) = (base.to_string(), run.to_string());
    run_blocking(async move {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(IO_BOUND)
            .connect(&base)
            .await
            .map_err(|e| format!("could not connect the admin connection: {e}"))?;
        let swept = async {
            let now = pg_barrier::server_unix(&admin)
                .await
                .map_err(|e| format!("could not read the server clock: {e}"))?;
            sweep_run_stale(&admin, &run, now)
                .await
                .map_err(|e| format!("sweep listing failed: {e}"))
        }
        .await;
        admin.close().await;
        swept
    })
}

/// Drop the clone `name` of run `run` through `admin_url`, without FORCE.
/// Refuses any name that is not this run's exact clone shape, so a typo can
/// never drop a lane database or another run's clone. A clone whose session
/// is still closing is retried briefly; one that stays held is an error.
///
/// # Errors
///
/// The name is not this run's clone, connecting failed, or the `DROP` failed
/// (including: the database still has a session).
pub fn drop_database_blocking(admin_url: &str, run: &str, name: &str) -> Result<(), String> {
    if parse_isolated_name(run, name).is_none() {
        return Err(format!(
            "refusing to drop `{name}`: not a clone of run `{run}`"
        ));
    }
    let (url, name) = (admin_url.to_string(), name.to_string());
    run_blocking(async move {
        let mut conn = connect(&url).await?;
        let sql = format!("DROP DATABASE IF EXISTS {}", pg_barrier::quote_ident(&name));
        let mut outcome = Err(format!("no DROP attempt was made for {name}"));
        for attempt in 1..=DROP_ATTEMPTS {
            match sqlx::query(&sql).execute(&mut conn).await {
                Ok(_) => {
                    outcome = Ok(());
                    break;
                }
                Err(e) if is_in_use(&e) && attempt < DROP_ATTEMPTS => {
                    tokio::time::sleep(DROP_PAUSE).await;
                }
                Err(e) => {
                    outcome = Err(format!("could not drop {name}: {e}"));
                    break;
                }
            }
        }
        if let Err(e) = conn.close().await {
            eprintln!("WARN: [pg_isolate] closing the drop connection failed: {e}");
        }
        outcome
    })
}

/// Whether the database `name` exists on the server `base` points at.
///
/// # Errors
///
/// Connecting or the catalog query failed.
pub fn database_exists_blocking(base: &str, name: &str) -> Result<bool, String> {
    let (url, name) = (base.to_string(), name.to_string());
    run_blocking(async move {
        let mut conn = connect(&url).await?;
        let found: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(&name)
                .fetch_one(&mut conn)
                .await
                .map_err(|e| format!("exists query failed: {e}"))?;
        if let Err(e) = conn.close().await {
            eprintln!("WARN: [pg_isolate] closing the catalog connection failed: {e}");
        }
        Ok(found)
    })
}

/// A live session on one database. While it exists the database cannot be
/// dropped (no drop here uses FORCE). Dropping it closes the session.
pub struct Hold {
    release: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        // Closing the channel wakes the worker, which closes its connection.
        drop(self.release.take());
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            eprintln!("WARN: [pg_isolate] the hold thread panicked");
        }
    }
}

/// Open a session on the database `url` names and keep it open until the
/// returned [`Hold`] is dropped.
///
/// # Errors
///
/// The thread or runtime could not start, or connecting failed.
pub fn hold_blocking(url: &str) -> Result<Hold, String> {
    let url = url.to_string();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let worker = std::thread::Builder::new()
        .name("pg-isolate-hold".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("could not build a runtime: {e}")));
                    return;
                }
            };
            let conn = match rt.block_on(connect(&url)) {
                Ok(conn) => conn,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            // Blocks until the Hold is dropped (sender gone) or a stray send.
            let _ = release_rx.recv();
            if let Err(e) = rt.block_on(conn.close()) {
                eprintln!("WARN: [pg_isolate] closing the hold failed: {e}");
            }
        })
        .map_err(|e| format!("could not spawn the hold thread: {e}"))?;
    let hold = Hold {
        release: Some(release_tx),
        worker: Some(worker),
    };
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(hold),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the hold thread exited before connecting".to_string()),
    }
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
        let mut conn = connect(&url).await?;
        let count = sqlx::query_scalar("SELECT count(*) FROM pg_extension WHERE extname = ANY($1)")
            .bind(names)
            .fetch_one(&mut conn)
            .await
            .map_err(|e| format!("extension count failed: {e}"))?;
        if let Err(e) = conn.close().await {
            eprintln!("WARN: [pg_isolate] closing the catalog connection failed: {e}");
        }
        Ok(count)
    })
}
