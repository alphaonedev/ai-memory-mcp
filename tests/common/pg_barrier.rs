// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared wall-clock budget for the live-Postgres lock-barrier suites (#4336).
//!
//! The interleaving suites park a writer behind a held lock and then poll
//! `pg_blocking_pids` until the writer is observed waiting. The writer cannot
//! reach its lock wait before it owns a connection, and a brand-new backend on
//! a freshly created database (cold catalog and plan caches, TLS handshake,
//! `after_connect` GUCs) can take far longer than a warm one under host load.
//! The production pool tolerates that for `acquire_timeout_secs` (30 s) and
//! then lets the statement wait `lock_timeout` (5 s). A barrier that gives up
//! sooner than the pool does fails on a perfectly healthy run: the first run
//! against a fresh database on a busy host panicked with `barrier not reached`
//! after exactly the old 20 s literal (#4336).
//!
//! So the barrier budget is DERIVED from those production constants instead of
//! being a free-standing literal. It is a ceiling only: every barrier returns
//! the moment its condition holds, and no assertion is weakened.
//!
//! Take it with the `#[path]` leaf idiom (no `mod common;` weight):
//!
//! ```ignore
//! #[path = "common/pg_barrier.rs"]
//! mod pg_barrier;
//! ```

#![allow(dead_code)]

use std::time::Duration;

use ai_memory::store::PoolConfig;
use ai_memory::store::postgres::DEFAULT_LOCK_TIMEOUT_SECS;

/// Budget for a lock barrier to be reached: twice the sum of the pool's
/// connection-acquire timeout and the per-statement lock timeout.
#[must_use]
pub fn barrier_budget() -> Duration {
    let acquire = Duration::from_secs(PoolConfig::default().acquire_timeout_secs);
    let lock = Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS);
    acquire.saturating_add(lock).saturating_mul(2)
}

/// Async deadline for a barrier poll loop.
#[must_use]
pub fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + barrier_budget()
}

// ---------------------------------------------------------------------------
// Cold-backend injection and scratch-database hygiene (#4336 / #4489)
// ---------------------------------------------------------------------------

/// Slack kept between the injected login delay and the pool's acquire timeout,
/// so the injected connect is slow but still one the pool accepts.
const INJECTION_MARGIN: Duration = Duration::from_secs(8);

/// Cold-login latency the injection cells apply: the pool acquire timeout minus
/// [`INJECTION_MARGIN`]. Derived (not a literal) so it tracks the production
/// pool constant; with the 30 s default it is 22 s, above the 20 s deadline the
/// barriers used before #4336.
#[must_use]
pub fn injected_login_delay() -> Duration {
    Duration::from_secs(PoolConfig::default().acquire_timeout_secs).saturating_sub(INJECTION_MARGIN)
}

/// Age past which a prefixed scratch database is an orphan of a killed run.
/// Far above any cell's runtime, so a concurrent live run is never swept.
pub const STALE_SCRATCH_AGE: Duration = Duration::from_secs(600);

/// Swap the database name in a postgres URL, preserving the query string (this
/// tier pins `sslmode=verify-full` and a CA path in it).
#[must_use]
pub fn with_database(url: &str, db: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let trimmed = base.trim_end_matches('/');
    let cut = trimmed.rfind('/').expect("postgres url has a path segment");
    let mut out = format!("{}/{db}", &trimmed[..cut]);
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// Digits in the creation-time field: Unix seconds, ten digits until the year 2286.
const SCRATCH_TS_DIGITS: usize = 10;
/// Lowercase hex characters in the random suffix.
const SCRATCH_ID_HEX: usize = 8;

/// A scratch database name: `<prefix>_<unix-seconds, 10 digits>_<8 lowercase hex>`.
/// The embedded creation time is what lets a later run recognise an orphan.
#[must_use]
pub fn scratch_db_name(prefix: &str, now_unix: u64) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!(
        "{prefix}_{now_unix:0width$}_{}",
        &id[..SCRATCH_ID_HEX],
        width = SCRATCH_TS_DIGITS
    )
}

/// Parse `name` against the EXACT whole-name scratch shape
/// `^<prefix>_[0-9]{10}_[0-9a-f]{8}$` and return its creation time. Anything
/// else (a lane or operator database, a `+` sign, uppercase or wrong-width
/// fields, quotes, semicolons, trailing text) is `None` and must never be
/// dropped (#4489 review B1).
#[must_use]
pub fn parse_scratch_name(prefix: &str, name: &str) -> Option<u64> {
    let rest = name.strip_prefix(prefix)?.strip_prefix('_')?;
    let (ts, id) = rest.split_once('_')?;
    let ts_ok = ts.len() == SCRATCH_TS_DIGITS && ts.bytes().all(|b| b.is_ascii_digit());
    let id_ok = id.len() == SCRATCH_ID_HEX
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ts_ok && id_ok {
        ts.parse::<u64>().ok()
    } else {
        None
    }
}

/// Quote an SQL identifier: wrap in double quotes and double any embedded
/// double quote. Defence in depth; names are shape-checked before this is used.
#[must_use]
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The SERVER clock in Unix seconds, so naming and the sweep age never depend on
/// the (possibly skewed) clock of the host running the test.
///
/// # Errors
///
/// The query failed.
pub async fn server_unix(admin: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    let secs: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
        .fetch_one(admin)
        .await?;
    Ok(u64::try_from(secs).unwrap_or(0))
}

/// Drop every `<prefix>_<ts>_<id>` database (EXACT shape, see
/// [`parse_scratch_name`]) whose timestamp is older than [`STALE_SCRATCH_AGE`]
/// relative to `now_unix`. A fresh one (a concurrent live run) and every name
/// that does not match the shape are left alone. Returns the dropped names. A
/// killed run leaves its scratch database, and its login-delay trigger, behind
/// (#4489). Each drop is ONE statement with a properly quoted identifier.
///
/// # Errors
///
/// The catalog listing failed. A single failed drop is reported on stderr and
/// skipped, never fatal.
pub async fn sweep_stale_scratch_dbs(
    admin: &sqlx::PgPool,
    prefix: &str,
    now_unix: u64,
) -> Result<Vec<String>, sqlx::Error> {
    let names: Vec<String> =
        sqlx::query_scalar("SELECT datname::text FROM pg_database WHERE starts_with(datname, $1)")
            .bind(format!("{prefix}_"))
            .fetch_all(admin)
            .await?;
    let mut dropped = Vec::new();
    for name in names {
        let Some(created) = parse_scratch_name(prefix, &name) else {
            continue;
        };
        if now_unix.saturating_sub(created) <= STALE_SCRATCH_AGE.as_secs() {
            continue;
        }
        match sqlx::query(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            quote_ident(&name)
        ))
        .execute(admin)
        .await
        {
            Ok(_) => dropped.push(name),
            Err(e) => eprintln!("WARN: could not sweep stale scratch database {name}: {e}"),
        }
    }
    Ok(dropped)
}

/// Bound on the guard's own connect and drop, so an unreachable host cannot hang
/// a panicking test for the OS TCP timeout.
const GUARD_IO_BOUND: Duration = Duration::from_secs(20);

/// A cluster-level scratch database that is dropped when the guard goes out of
/// scope, INCLUDING on a panic unwind (`Drop` runs, and the drop is driven on its
/// own thread and runtime so it works while the test runtime is unwinding).
/// `SIGKILL` cannot be caught, so a killed run still leaves its database behind;
/// the sweep in [`Self::create`] is the backstop for that case (#4489).
pub struct ScratchDb {
    admin_url: String,
    name: String,
}

impl ScratchDb {
    /// Sweep stale orphans of `prefix`, then create a fresh scratch database.
    /// Both the name and the sweep age use the server clock.
    ///
    /// # Errors
    ///
    /// Connecting to `admin_url`, the sweep listing, or `CREATE DATABASE` failed.
    pub async fn create(admin_url: &str, prefix: &str) -> Result<Self, sqlx::Error> {
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(admin_url)
            .await?;
        let now = server_unix(&admin).await?;
        sweep_stale_scratch_dbs(&admin, prefix, now).await?;
        let name = scratch_db_name(prefix, now);
        sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
            .execute(&admin)
            .await?;
        admin.close().await;
        Ok(Self {
            admin_url: admin_url.to_string(),
            name,
        })
    }

    /// The scratch database name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The connection URL of the scratch database (query string preserved).
    #[must_use]
    pub fn url(&self) -> String {
        with_database(&self.admin_url, &self.name)
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        let (url, name) = (self.admin_url.clone(), self.name.clone());
        // OWNERSHIP-25: nothing here may panic (a panic during an unwind aborts).
        // `Builder::spawn` returns an error instead of panicking when a thread
        // cannot be created; log it and leave the sweep to clean up.
        let log_name = name.clone();
        let spawned = std::thread::Builder::new()
            .name("scratch-db-drop".to_string())
            .spawn(move || drop_scratch_blocking(&url, &name));
        match spawned {
            Ok(handle) => {
                if handle.join().is_err() {
                    eprintln!("WARN: scratch database drop thread panicked for {log_name}");
                }
            }
            Err(e) => eprintln!(
                "WARN: could not spawn a thread to drop scratch database {log_name}: {e}; \
                 the next run's sweep will remove it"
            ),
        }
    }
}

/// Drop `name` on a private runtime. Every step is bounded and none can panic.
fn drop_scratch_blocking(url: &str, name: &str) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("WARN: could not build a runtime to drop scratch database {name}");
        return;
    };
    rt.block_on(async {
        use sqlx::Connection as _;
        let connected =
            tokio::time::timeout(GUARD_IO_BOUND, sqlx::PgConnection::connect(url)).await;
        let mut conn = match connected {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                eprintln!("WARN: could not connect to drop scratch database {name}: {e}");
                return;
            }
            Err(_) => {
                eprintln!("WARN: timed out connecting to drop scratch database {name}");
                return;
            }
        };
        let dropped = tokio::time::timeout(
            GUARD_IO_BOUND,
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote_ident(name)
            ))
            .execute(&mut conn),
        )
        .await;
        match dropped {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("WARN: could not drop scratch database {name}: {e}"),
            Err(_) => eprintln!("WARN: timed out dropping scratch database {name}"),
        }
    });
}

/// SQL installing a login event trigger that makes a new connection to the
/// current database sleep [`injected_login_delay`] whenever `when_sql` is true.
/// Needs a superuser role.
#[must_use]
pub fn login_delay_sql(trigger: &str, when_sql: &str) -> String {
    let secs = injected_login_delay().as_secs();
    format!(
        "CREATE FUNCTION {trigger}() RETURNS event_trigger LANGUAGE plpgsql AS \
         $$ BEGIN IF {when_sql} THEN PERFORM pg_sleep({secs}); END IF; END $$; \
         CREATE EVENT TRIGGER {trigger} ON login EXECUTE FUNCTION {trigger}();"
    )
}
