// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]

//! #7130 — the certified postgres+AGE install must survive a ROLLBACK of a
//! failed transaction that raced a burst of catalog invalidations.
//!
//! Defect class: Apache AGE 1.8.0 (apache/age#2580) runs its
//! `post_parse_analyze` hook on the ROLLBACK statement of an aborted
//! transaction. When a shared-invalidation catch-up has cleared AGE's
//! extension cache while the session idled in the failed transaction, the hook
//! reads `pg_extension` in the aborted state; the ROLLBACK then fails with
//! `ResourceOwnerEnlarge called after release started` and leaks fast-path
//! locks into that backend's PGPROC. Every later backend that inherits the
//! PGPROC fails at connect with XX000 `failed to re-find shared lock object`
//! until the server restarts — the shared-tier failure the Certified pg+AGE
//! cells reported. The fix lives in the server's AGE build (upstream
//! apache/age 06ce678: `is_age_extension_exists` returns early outside a
//! transaction state); this test pins that the certified install carries it.
//!
//! Isolation (#7324 review HIGH-1): on an unpatched AGE the race poisons the
//! server it runs on until that server restarts, so it NEVER runs against the
//! shared tier. The test creates a private, throwaway postmaster from the
//! certified install's binaries (`initdb` + `pg_ctl` under the project-local
//! `.local-runs/`, a free loopback port, `shared_preload_libraries = 'age'`,
//! `dynamic_library_path = '$libdir'`), races there, and destroys it. A nonce
//! GUC proves every race connection reached the private server. When the
//! shared tier URL is set, the test also checks that the private server runs
//! the same server build and AGE version as the tier, and after the race it
//! opens fresh connections to the tier and requires every one to succeed.
//!
//! Prerequisites: `AI_MEMORY_TEST_PG_BINDIR` (the certified install's bin
//! directory) and, for the parity and probe half, `AI_MEMORY_TEST_AGE_URL`
//! (fallback `AI_MEMORY_TEST_POSTGRES_URL`). Under CI (`CI` set) a missing
//! prerequisite FAILS the test (fail closed, #7324 MEDIUM-1); outside CI it
//! prints a skip line and returns. `AI_MEMORY_TEST_AGE_7130_LIBRARY_DIR`
//! prepends a directory to the private server's `dynamic_library_path` so a
//! developer can prove the cell red against a stock `age.so`; it is refused
//! under CI because the cell must certify the installed library.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{Connection, PgConnection};

/// Temp tables created and dropped by the invalidation burst: enough to
/// overflow the shared-invalidation queue for an idle peer backend.
const INVALIDATION_BURST: u32 = 1500;
/// How long the failed session idles after the burst so the catch-up signal
/// is processed before it sends ROLLBACK.
const SETTLE: Duration = Duration::from_secs(1);
/// Fresh connections opened and held on the private server after the
/// ROLLBACKs; each takes a distinct PGPROC, any of which a leak may have
/// poisoned.
const PROBE_CONNECTS: u32 = 20;
/// Fresh connections opened on the shared tier after the race; every one must
/// succeed (the #7324 review's isolation probe).
const SHARED_PROBE_CONNECTS: u32 = 40;
/// Rounds of the race; three make the red deterministic on an unpatched AGE.
const ROUNDS: u32 = 3;
/// Attempts to start the private postmaster, each on a freshly picked port
/// (another process may take a free port between the pick and the bind).
const START_ATTEMPTS: u32 = 3;
/// Seconds `pg_ctl` waits for the private postmaster to start or stop.
const PG_CTL_WAIT_SECS: &str = "60";
const LEAK_MSG: &str = "ResourceOwnerEnlarge called after release started";
const REFIND_MSG: &str = "failed to re-find shared lock object";

/// Superuser role `initdb` creates in the private cluster (trust auth,
/// loopback only, destroyed with the cluster).
const SCRATCH_ROLE: &str = "r7130";
/// Placeholder GUC carrying the private cluster's nonce: a server that
/// returns the nonce is the private one, the shared tier returns nothing.
const NONCE_GUC: &str = "r7130.cluster_nonce";
/// The only library the private server may preload.
const AGE_LIBRARY: &str = "age";
/// `dynamic_library_path` of a server that loads the installed `age.so`.
const LIBDIR_ONLY: &str = "$libdir";

const BINDIR_ENV: &str = "AI_MEMORY_TEST_PG_BINDIR";
const AGE_URL_ENV: &str = "AI_MEMORY_TEST_AGE_URL";
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const LIBRARY_DIR_ENV: &str = "AI_MEMORY_TEST_AGE_7130_LIBRARY_DIR";

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// True under a CI runner: GitHub Actions sets `CI=true`.
fn in_ci() -> bool {
    env_nonempty("CI").is_some_and(|v| v != "false" && v != "0")
}

/// What the cell needs to run.
struct Prereqs {
    bindir: PathBuf,
    shared_url: Option<String>,
    library_dir: Option<String>,
}

/// Resolve the prerequisites. Under CI a missing one panics (fail closed);
/// outside CI it prints a skip line and returns `None`.
fn prereqs() -> Option<Prereqs> {
    let bindir = env_nonempty(BINDIR_ENV).map(PathBuf::from);
    let shared_url = env_nonempty(AGE_URL_ENV).or_else(|| env_nonempty(PG_URL_ENV));
    let library_dir = env_nonempty(LIBRARY_DIR_ENV);
    let ci = in_ci();

    let mut missing = Vec::new();
    if bindir.is_none() {
        missing.push(format!("{BINDIR_ENV} unset"));
    }
    if ci && shared_url.is_none() {
        missing.push(format!("{AGE_URL_ENV} / {PG_URL_ENV} unset"));
    }
    assert!(
        !(ci && library_dir.is_some()),
        "#7130: {LIBRARY_DIR_ENV} is set under CI; the cert cell must certify the \
         installed age.so, not a substituted library"
    );
    if !missing.is_empty() {
        let why = missing.join("; ");
        assert!(
            !ci,
            "#7130: cert cell prerequisites missing under CI (fail closed): {why}"
        );
        eprintln!("skip: #7130 {why}");
        return None;
    }
    let bindir = bindir?;
    Some(Prereqs {
        bindir,
        shared_url,
        library_dir,
    })
}

/// The entries of a `shared_preload_libraries` value, unquoted and trimmed.
fn preload_entries(setting: &str) -> Vec<&str> {
    setting
        .split(',')
        .map(|e| e.trim().trim_matches('"').trim())
        .filter(|e| !e.is_empty())
        .collect()
}

/// True when one preload entry names the AGE library exactly: `age`,
/// `age.so` or a path whose last component is one of those. A substring
/// match would accept `pageinspect` (#7324 review LOW-1).
fn is_age_entry(entry: &str) -> bool {
    let base = entry.rsplit('/').next().unwrap_or(entry);
    base.strip_suffix(".so").unwrap_or(base) == AGE_LIBRARY
}

fn preloads_age(setting: &str) -> bool {
    preload_entries(setting).into_iter().any(is_age_entry)
}

/// A private postmaster under `.local-runs/`, stopped and removed on drop
/// (also when the test panics).
struct ScratchCluster {
    bindir: PathBuf,
    root: PathBuf,
    data: PathBuf,
    url: String,
    nonce: String,
}

impl ScratchCluster {
    fn start(bindir: &Path, library_dir: Option<&str>) -> Result<Self, String> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("clock before epoch: {e}"))?
            .as_nanos();
        let nonce = format!("{}-{stamp}", std::process::id());
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".local-runs")
            .join(format!("age-7130-{nonce}"));
        std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
        let mut cluster = Self {
            bindir: bindir.to_path_buf(),
            data: root.join("data"),
            root,
            url: String::new(),
            nonce,
        };
        cluster.initdb()?;
        cluster.configure(library_dir)?;
        let mut last = String::new();
        for _ in 0..START_ATTEMPTS {
            let port = free_port()?;
            match cluster.pg_ctl_start(port) {
                Ok(()) => {
                    cluster.url = format!(
                        "postgres://{SCRATCH_ROLE}@127.0.0.1:{port}/postgres?sslmode=disable"
                    );
                    return Ok(cluster);
                }
                Err(e) => last = e,
            }
        }
        Err(format!(
            "private postmaster did not start in {START_ATTEMPTS} attempts: {last}"
        ))
    }

    fn tool(&self, name: &str) -> Command {
        let mut cmd = Command::new(self.bindir.join(name));
        cmd.env("TMPDIR", &self.root);
        cmd
    }

    fn initdb(&self) -> Result<(), String> {
        let out = self
            .tool("initdb")
            .arg("-D")
            .arg(&self.data)
            .args(["-A", "trust", "-U", SCRATCH_ROLE, "-E", "UTF8", "--no-sync"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("spawn initdb from {}: {e}", self.bindir.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "initdb failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }

    fn configure(&self, library_dir: Option<&str>) -> Result<(), String> {
        let mut conf = String::from(
            "\n# #7130 private race cluster\n\
             listen_addresses = '127.0.0.1'\n\
             unix_socket_directories = ''\n\
             logging_collector = off\n\
             fsync = off\n\
             max_connections = 50\n",
        );
        let _ = writeln!(conf, "shared_preload_libraries = '{AGE_LIBRARY}'");
        let _ = writeln!(conf, "{NONCE_GUC} = '{}'", self.nonce);
        match library_dir {
            Some(dir) => {
                let _ = writeln!(conf, "dynamic_library_path = '{dir}:{LIBDIR_ONLY}'");
            }
            None => {
                let _ = writeln!(conf, "dynamic_library_path = '{LIBDIR_ONLY}'");
            }
        }
        let path = self.data.join("postgresql.conf");
        let mut base =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        base.push_str(&conf);
        std::fs::write(&path, base).map_err(|e| format!("write {}: {e}", path.display()))
    }

    fn log_path(&self) -> PathBuf {
        self.root.join("server.log")
    }

    fn pg_ctl_start(&self, port: u16) -> Result<(), String> {
        let out = self
            .tool("pg_ctl")
            .arg("-D")
            .arg(&self.data)
            .arg("-l")
            .arg(self.log_path())
            .args(["-w", "-t", PG_CTL_WAIT_SECS, "-o"])
            .arg(format!("-p {port}"))
            .arg("start")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("spawn pg_ctl: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let log = std::fs::read_to_string(self.log_path()).unwrap_or_default();
        let tail: String = log.lines().rev().take(5).collect::<Vec<_>>().join(" | ");
        Err(format!(
            "pg_ctl start on port {port} failed ({}): {tail}",
            out.status
        ))
    }

    /// Leak and re-find lines the private server logged (red diagnostics).
    fn log_counts(&self) -> (usize, usize) {
        let log = std::fs::read_to_string(self.log_path()).unwrap_or_default();
        (
            log.matches(LEAK_MSG).count(),
            log.matches(REFIND_MSG).count(),
        )
    }
}

impl Drop for ScratchCluster {
    fn drop(&mut self) {
        if self.data.join("postmaster.pid").exists() {
            let stopped = self
                .tool("pg_ctl")
                .arg("-D")
                .arg(&self.data)
                .args(["-m", "immediate", "-w", "-t", PG_CTL_WAIT_SECS, "stop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match stopped {
                Ok(s) if s.success() => {}
                Ok(s) => eprintln!("#7130: pg_ctl stop of the private cluster exited {s}"),
                Err(e) => eprintln!("#7130: pg_ctl stop of the private cluster failed: {e}"),
            }
        }
        if let Err(e) = std::fs::remove_dir_all(&self.root) {
            eprintln!("#7130: remove {}: {e}", self.root.display());
        }
    }
}

/// A loopback port nothing listens on right now.
fn free_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("bind probe: {e}"))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("probe local_addr: {e}"))
}

/// What a server reports about its build and configuration.
struct ServerFacts {
    preload: String,
    version_num: String,
    age_version: String,
    nonce: String,
}

async fn server_facts(url: &str) -> Result<ServerFacts, String> {
    let mut conn = PgConnection::connect(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (preload, version_num, age_version, nonce): (String, String, String, String) =
        sqlx::query_as(
            "SELECT current_setting('shared_preload_libraries'), \
                    current_setting('server_version_num'), \
                    COALESCE((SELECT default_version FROM pg_available_extensions \
                              WHERE name = $1), ''), \
                    COALESCE(current_setting($2, true), '')",
        )
        .bind(AGE_LIBRARY)
        .bind(NONCE_GUC)
        .fetch_one(&mut conn)
        .await
        .map_err(|e| format!("read server facts: {e}"))?;
    conn.close().await.map_err(|e| format!("close: {e}"))?;
    Ok(ServerFacts {
        preload,
        version_num,
        age_version,
        nonce,
    })
}

async fn dynamic_library_path(url: &str) -> Result<String, String> {
    let mut conn = PgConnection::connect(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let dlp: String = sqlx::query_scalar("SELECT current_setting('dynamic_library_path')")
        .fetch_one(&mut conn)
        .await
        .map_err(|e| format!("read dynamic_library_path: {e}"))?;
    conn.close().await.map_err(|e| format!("close: {e}"))?;
    Ok(dlp)
}

fn burst_sql() -> String {
    format!(
        "DO $b$ BEGIN FOR i IN 1..{INVALIDATION_BURST} LOOP \
         EXECUTE format('CREATE TEMP TABLE r7130_%s (x int)', i); \
         EXECUTE format('DROP TABLE r7130_%s', i); END LOOP; END $b$"
    )
}

async fn one_round(url: &str) -> Result<(), String> {
    let mut failed = PgConnection::connect(url)
        .await
        .map_err(|e| format!("connect session A: {e}"))?;
    sqlx::raw_sql("SELECT 1")
        .execute(&mut failed)
        .await
        .map_err(|e| format!("prime AGE extension cache: {e}"))?;
    sqlx::raw_sql("BEGIN")
        .execute(&mut failed)
        .await
        .map_err(|e| format!("begin: {e}"))?;
    if sqlx::raw_sql("SELECT 1/0")
        .execute(&mut failed)
        .await
        .is_ok()
    {
        return Err("SELECT 1/0 must fail to abort the transaction".to_string());
    }

    let mut burst = PgConnection::connect(url)
        .await
        .map_err(|e| format!("connect session B: {e}"))?;
    sqlx::raw_sql(&burst_sql())
        .execute(&mut burst)
        .await
        .map_err(|e| format!("invalidation burst: {e}"))?;
    burst
        .close()
        .await
        .map_err(|e| format!("close session B: {e}"))?;

    tokio::time::sleep(SETTLE).await;

    if let Err(e) = sqlx::raw_sql("ROLLBACK").execute(&mut failed).await {
        let msg = e.to_string();
        let class = if msg.contains(LEAK_MSG) {
            "lock leak"
        } else {
            "unexpected error"
        };
        return Err(format!(
            "ROLLBACK of an aborted transaction failed after an invalidation burst \
             ({class}); the install's AGE build lacks the apache/age#2580 fix: {msg}"
        ));
    }
    let alive: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut failed)
        .await
        .map_err(|e| format!("session A unusable after ROLLBACK: {e}"))?;
    if alive != 1 {
        return Err(format!("session A returned {alive} for SELECT 1"));
    }
    failed
        .close()
        .await
        .map_err(|e| format!("close session A: {e}"))
}

/// Open `count` fresh connections; return the first failure.
///
/// `Probe::Held` keeps every connection open until all are made, so each one
/// takes a distinct PGPROC and a poisoned slot cannot hide behind a reused
/// one; `Probe::Sequential` closes each before the next (light enough for
/// the shared tier, which other jobs are using).
async fn probe_connects(url: &str, count: u32, probe: Probe) -> Result<(), String> {
    let mut held = Vec::new();
    for i in 0..count {
        match PgConnection::connect(url).await {
            Ok(conn) if probe == Probe::Held => held.push(conn),
            Ok(conn) => conn
                .close()
                .await
                .map_err(|e| format!("close probe {i}: {e}"))?,
            Err(e) => {
                let msg = e.to_string();
                let class = if msg.contains(REFIND_MSG) {
                    "XX000 poisoned PGPROC"
                } else {
                    "unexpected error"
                };
                return Err(format!("probe connect {i} failed ({class}): {msg}"));
            }
        }
    }
    for (i, conn) in held.into_iter().enumerate() {
        conn.close()
            .await
            .map_err(|e| format!("close held probe {i}: {e}"))?;
    }
    Ok(())
}

/// How [`probe_connects`] uses its connections.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    Held,
    Sequential,
}

/// The race: `ROUNDS` rounds, then fresh connects on the private server.
async fn race(url: &str) -> Result<(), String> {
    for _ in 0..ROUNDS {
        one_round(url).await?;
    }
    probe_connects(url, PROBE_CONNECTS, Probe::Held).await
}

/// Check the private server is the certified install (and is not the shared
/// tier), run the race there, then require the shared tier to stay healthy.
async fn certify(prereqs: &Prereqs, cluster: &ScratchCluster) -> Result<(), String> {
    let private = server_facts(&cluster.url)
        .await
        .map_err(|e| format!("private server: {e}"))?;
    assert_eq!(
        private.nonce, cluster.nonce,
        "#7130: the race target must be the private cluster this test started"
    );
    assert_eq!(
        preload_entries(&private.preload),
        vec![AGE_LIBRARY],
        "#7130: the private server must preload exactly AGE"
    );
    assert!(
        !private.age_version.is_empty(),
        "#7130: the private server's install has no AGE extension"
    );
    let dlp = dynamic_library_path(&cluster.url)
        .await
        .map_err(|e| format!("private server: {e}"))?;
    if prereqs.library_dir.is_none() {
        assert_eq!(
            dlp, LIBDIR_ONLY,
            "#7130: the private server must load the installed age.so"
        );
    }

    if let Some(shared_url) = &prereqs.shared_url {
        let shared = server_facts(shared_url)
            .await
            .map_err(|e| format!("shared tier: {e}"))?;
        assert_ne!(
            shared.nonce, cluster.nonce,
            "#7130: the shared tier answered as the private cluster; the race would hit it"
        );
        assert!(
            preloads_age(&shared.preload),
            "#7130 pins the certified tier: AGE must be preloaded, got {:?}",
            shared.preload
        );
        assert_eq!(
            private.version_num, shared.version_num,
            "#7130: {BINDIR_ENV} must be the shared tier's server build"
        );
        assert_eq!(
            private.age_version, shared.age_version,
            "#7130: the private server's AGE version must match the shared tier's"
        );
    }

    let outcome = race(&cluster.url).await;

    if let Some(shared_url) = &prereqs.shared_url
        && let Err(e) = probe_connects(shared_url, SHARED_PROBE_CONNECTS, Probe::Sequential).await
    {
        panic!(
            "#7130: the shared tier lost a connection slot while the race ran on the \
             private cluster ({SHARED_PROBE_CONNECTS} probes): {e}"
        );
    }
    outcome
}

#[test]
#[ignore = "requires the certified PG install (AI_MEMORY_TEST_PG_BINDIR) and AI_MEMORY_TEST_AGE_URL"]
fn rollback_after_invalidation_burst_does_not_leak_locks_7130() {
    let Some(prereqs) = prereqs() else {
        return;
    };
    let cluster = ScratchCluster::start(&prereqs.bindir, prereqs.library_dir.as_deref())
        .unwrap_or_else(|e| panic!("#7130: private race cluster: {e}"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let outcome = runtime.block_on(certify(&prereqs, &cluster));
    drop(runtime);
    let (leaks, refinds) = cluster.log_counts();
    drop(cluster);
    if let Err(e) = outcome {
        panic!("#7130: {e} (private server log: leak={leaks} refind={refinds})");
    }
}

#[test]
fn preload_match_is_exact_not_substring_7130() {
    assert!(!preloads_age("pageinspect"));
    assert!(!preloads_age("storage_engine, pg_stat_statements"));
    assert!(!preloads_age("agent"));
    assert!(!preloads_age(""));
    assert!(!preloads_age("$libdir/agex"));
}

#[test]
fn preload_match_accepts_list_path_and_suffix_forms_7130() {
    assert!(preloads_age("age"));
    assert!(preloads_age("pg_stat_statements, age"));
    assert!(preloads_age("\"age\",vector"));
    assert!(preloads_age("$libdir/age"));
    assert!(preloads_age("/usr/lib/postgresql/18/lib/age.so"));
    assert_eq!(preload_entries(" age , "), vec!["age"]);
}
