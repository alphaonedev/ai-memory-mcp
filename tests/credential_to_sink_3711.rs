// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! The credential-to-sink family (#3711 #3667 #3675 #3684 #3687 #3710
//! #3724): a store DSN, a federation peer URL or a webhook target that
//! carries a credential in its userinfo, its query string or its path must
//! reach NO sink — stderr, the operator log, a `--json` report, a doctor
//! report, a `sync_state` key, a DLQ `last_error` — in any form but the
//! allowlist rendering (`url_display`: scheme / host / port [/ database]).
//!
//! Every cell plants ALL the credential shapes at once and asserts by
//! ABSENCE over the whole sink, so a shape nobody enumerated (the
//! userinfo-only masker's failure mode, #3674 ruling) cannot pass. A
//! closed loopback port stands in for every unreachable target: the
//! transport error it produces is the one whose `Display` names the full
//! request URL (#3710).

#![cfg(feature = "sal")]

use std::path::Path;
use std::sync::{Arc, Mutex};

use ai_memory::subscriptions::{NewSubscription, dispatch_event, dlq_reason, insert, list_dlq};

mod common;
use rusqlite::Connection;
use tempfile::TempDir;

const USER: &str = "svc-alice-3711";
const USERINFO_PW: &str = "userinfo-s3cr3t-3711";
const QUERY_PW: &str = "query-p4ssw0rd-3711";
const SSL_PW: &str = "ssl-p4ss-3711";
const SSL_KEY: &str = "/etc/pg/client-3711.key";
const PATH_TOKEN: &str = "T0kenInPath3711";
const QUERY_TOKEN: &str = "query-t0ken-3711";

/// Every credential shape a URL can carry. A sink is clean iff none of
/// these substrings appears anywhere in it.
const SECRETS: &[&str] = &[
    USER,
    USERINFO_PW,
    QUERY_PW,
    SSL_PW,
    SSL_KEY,
    PATH_TOKEN,
    QUERY_TOKEN,
];

fn assert_clean(sink: &str, what: &str) {
    for s in SECRETS {
        assert!(!sink.contains(s), "#3711: {s:?} reached {what}:\n{sink}");
    }
}

/// A DSN carrying a userinfo password AND a query-form password AND the
/// TLS client-key secrets, pointed at a closed loopback port.
fn credentialed_dsn() -> String {
    format!(
        "postgres://{USER}:{USERINFO_PW}@127.0.0.1:9/ai_memory?password={QUERY_PW}&sslpassword={SSL_PW}&sslkey={SSL_KEY}&sslmode=verify-full"
    )
}

/// A federation peer URL carrying a userinfo password, a path and a
/// query token, pointed at a closed loopback port.
fn credentialed_peer() -> String {
    format!("http://{USER}:{USERINFO_PW}@127.0.0.1:9/{PATH_TOKEN}?token={QUERY_TOKEN}")
}

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("credential-to-sink-3711");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// In-memory `tracing` writer (the `tests/agent_api_key_admin_route_3474.rs`
/// idiom): the assertion reads what the subscriber actually emitted.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .to_string()
    }
}

fn capture_subscriber(sink: &Capture) -> impl tracing::Subscriber + Send + Sync {
    let w = sink.clone();
    tracing_subscriber::fmt()
        .with_writer(move || w.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish()
}

fn run_bin(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (String, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".config")).expect("scratch home");
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).expect("scratch keys");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .args(args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "trace");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn ai-memory");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------
// #3711 — store DSN sites: migrate --json, schema-init --json, doctor,
// the mutually-exclusive --db/--store-url refusal.
// ---------------------------------------------------------------------

#[test]
fn migrate_json_and_stderr_render_the_dsn_from_the_allowlist_3711() {
    let dir = scratch("migrate");
    let src = dir.path().join("src.db");
    let _ = ai_memory::db::open(&src).expect("seed source");
    let from = format!("sqlite://{}", src.display());
    let dsn = credentialed_dsn();
    // Whether or not this binary carries `sal-postgres`, every path a
    // postgres `--to` takes (the feature refusal, the connect refusal, the
    // sslmode floor, the --json report) renders the DSN from the allowlist.
    let (out, err) = run_bin(
        dir.path(),
        &["migrate", "--from", &from, "--to", &dsn, "--json"],
        &[],
    );
    assert_clean(&out, "migrate --json stdout");
    assert_clean(&err, "migrate stderr");
    let combined = format!("{out}{err}");
    assert!(
        combined.contains("postgres://127.0.0.1:9/ai_memory") || combined.contains("127.0.0.1:9"),
        "the allowlist rendering (host:port/db) must still identify the store:\n{combined}"
    );
}

#[test]
fn schema_init_json_renders_the_dsn_from_the_allowlist_3711() {
    let dir = scratch("schema-init");
    let dsn = credentialed_dsn();
    let (out, err) = run_bin(
        dir.path(),
        &["schema-init", "--store-url", &dsn, "--json"],
        &[],
    );
    assert_clean(&out, "schema-init --json stdout");
    assert_clean(&err, "schema-init stderr");
}

#[test]
fn doctor_report_renders_the_dsn_from_the_allowlist_3711() {
    let dir = scratch("doctor");
    let db = dir.path().join("d.db");
    let dsn = credentialed_dsn();
    let db_s = db.display().to_string();
    let (out, err) = run_bin(
        dir.path(),
        &["--db", &db_s, "doctor"],
        &[("AI_MEMORY_STORE_URL", dsn.as_str())],
    );
    assert_clean(&out, "doctor stdout");
    assert_clean(&err, "doctor stderr");
}

#[test]
fn db_and_store_url_conflict_refusal_renders_the_dsn_from_the_allowlist_3711() {
    let dir = scratch("conflict");
    let db = dir.path().join("d.db");
    let dsn = credentialed_dsn();
    let db_s = db.display().to_string();
    let (out, err) = run_bin(
        dir.path(),
        &["--db", &db_s, "serve", "--store-url", &dsn, "--port", "0"],
        &[],
    );
    assert_clean(&out, "serve stdout");
    assert_clean(&err, "serve stderr");
}

// ---------------------------------------------------------------------
// #3675 / #3687 / #3710 — sync-daemon: the cycle's log, its error and
// the durable sync_state key.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sync_cycle_never_persists_or_logs_the_peer_credential_3675_3687_3710() {
    let dir = scratch("sync");
    let db = dir.path().join("sync.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    let peer = credentialed_peer();
    let rendered = ai_memory::url_display::url_origin_and_path(&peer);
    assert_eq!(rendered, format!("http://127.0.0.1:9/{PATH_TOKEN}"));
    // A pre-#3675 daemon keyed the cursor by the RAW URL; plant that row
    // so the cycle has something to heal.
    {
        let conn = Connection::open(&db).expect("open");
        ai_memory::db::sync_state_observe(
            &conn,
            "me-3711",
            peer.trim_end_matches('/'),
            "2026-09-01T00:00:00Z",
        )
        .expect("plant raw-keyed row");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("client");
    let sink = Capture::default();
    let err = {
        let _default = tracing::subscriber::set_default(capture_subscriber(&sink));
        ai_memory::daemon_runtime::sync_cycle_once(&client, &db, "me-3711", &peer, None, 10)
            .await
            .expect_err("closed port: the cycle fails")
    };
    let err_text = format!("{err:#}");
    // The path token is NOT a credential for a federation peer (it is the
    // peer's path, operator config) and is part of the rendered key; every
    // other shape must be absent from both the error and the log.
    for s in [USER, USERINFO_PW, QUERY_TOKEN] {
        assert!(
            !err_text.contains(s),
            "#3710: {s:?} reached the cycle error: {err_text}"
        );
        assert!(
            !sink.text().contains(s),
            "#3687: {s:?} reached the log:\n{}",
            sink.text()
        );
    }
    assert!(
        err_text.contains("network: "),
        "the transport failure is classified, not rendered: {err_text}"
    );
    // #3675 — the durable key is the rendering; the raw row is gone and its
    // cursor survived the move.
    let conn = Connection::open(&db).expect("open");
    let clock = ai_memory::db::sync_state_load(&conn, "me-3711").expect("load");
    assert!(
        clock.entries.contains_key(&rendered),
        "cursor keyed by the rendering: {:?}",
        clock.entries
    );
    assert_eq!(
        clock.entries.get(&rendered).map(String::as_str),
        Some("2026-09-01T00:00:00Z")
    );
    let stored: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT peer_id FROM sync_state")
            .expect("prepare");
        stmt.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    for key in &stored {
        for s in [USER, USERINFO_PW, QUERY_TOKEN] {
            assert!(
                !key.contains(s),
                "#3675: {s:?} persisted in sync_state.peer_id={key}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// #3684 / #3724 — webhook dispatch: the log names the target's origin
// only; the DLQ `last_error` is the closed vocabulary and never the
// receiver's text.
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn webhook_dlq_and_log_carry_no_path_token_and_no_receiver_text_3684_3724() {
    // #3705 — every http:// webhook target is refused, loopback included, so
    // the hostile receiver speaks TLS through the shared fixture and the
    // dispatcher trusts that leaf as its operator-installed root
    // (`[subscriptions] ca_cert`). Loopback is still the SSRF guard's call.
    ai_memory::config::set_allow_loopback_webhooks(true);
    let dir = scratch("webhook");
    let tls = common::tls::TestTls::generate(&dir.path().join("tls"));
    ai_memory::subscriptions::install_dispatch_root_certificate(tls.cert_pem.as_bytes())
        .expect("install the fixture leaf as the dispatcher root (#3705)");
    // A hostile receiver: 2xx with a chosen `status` and a chosen
    // `correlation_id` — both used to be persisted verbatim.
    let hostile_status = "<script>evil-3724</script>";
    let hostile_corr = "attacker-chosen-corr-3724";
    let app = axum::Router::new().fallback(move || async move {
        axum::Json(serde_json::json!({
            "status": hostile_status,
            "correlation_id": hostile_corr,
        }))
    });
    let (port, _receiver) = tls.serve_router(app).await;

    let db = dir.path().join("hooks.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    // The Slack/Discord shape: the credential IS the path.
    let hostile_url = format!(
        "{}/services/T1/B2/{PATH_TOKEN}?t={QUERY_TOKEN}",
        common::tls::TestTls::base_url(port)
    );
    let unreachable_url = format!("https://127.0.0.1:9/hooks/{PATH_TOKEN}?t={QUERY_TOKEN}");
    let (sub_hostile, sub_unreachable) = {
        let conn = Connection::open(&db).expect("open");
        let mk = |url: &str| {
            insert(
                &conn,
                &NewSubscription {
                    url,
                    events: "*",
                    secret: Some("test-sub-secret-3711"),
                    namespace_filter: None,
                    agent_filter: None,
                    created_by: None,
                    event_types: None,
                },
            )
            .expect("insert subscription")
        };
        (mk(&hostile_url), mk(&unreachable_url))
    };
    let sink = Capture::default();
    // The dispatcher delivers on its own worker threads, which a
    // thread-local `set_default` does not reach; this is the ONE test in
    // the binary that installs the process-global subscriber.
    tracing::subscriber::set_global_default(capture_subscriber(&sink))
        .expect("first and only global subscriber in this binary");
    {
        let conn = Connection::open(&db).expect("open");
        dispatch_event(&conn, "memory_store", "evt-3711", "ns-3711", None, &db);
        // A failed delivery may consume four ACK windows plus the retry
        // backoffs (~26.2 s, `subscriptions.rs`), and under the #3705 TLS
        // floor each attempt also pays a handshake; both deliveries run
        // concurrently. Poll for both DLQ rows past that worst case (40 s):
        // on a loaded host the 20 s bound this used to carry landed 1 row.
        let db_poll = db.clone();
        let rows = tokio::task::spawn_blocking(move || {
            for _ in 0..400 {
                let conn = Connection::open(&db_poll).expect("open");
                let all = list_dlq(&conn, None).expect("dlq");
                if all.len() >= 2 {
                    return all;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Vec::new()
        })
        .await
        .expect("join");
        assert_eq!(rows.len(), 2, "one DLQ row per failed delivery: {rows:?}");
        for row in &rows {
            assert_clean(&row.last_error, "subscription_dlq.last_error");
            assert!(
                !row.last_error.contains(hostile_status) && !row.last_error.contains(hostile_corr),
                "#3724: receiver text persisted: {}",
                row.last_error
            );
            if row.subscription_id == sub_hostile {
                assert_eq!(row.last_error, dlq_reason::ACK_STATUS_NOT_ACK);
            } else {
                assert_eq!(row.subscription_id, sub_unreachable);
                assert!(
                    row.last_error.starts_with("network: "),
                    "unreachable target classifies as a transport failure: {}",
                    row.last_error
                );
                assert!(
                    !row.last_error.contains("127.0.0.1"),
                    "#3710: URL in DLQ: {}",
                    row.last_error
                );
            }
        }
    }
    let logs = sink.text();
    assert_clean(&logs, "the operator log");
    // The operator STILL sees the receiver's chosen text (TIER 2) and the
    // target's origin — what the wire dropped, the log keeps.
    assert!(
        logs.contains(hostile_status),
        "operator log keeps the receiver's status:\n{logs}"
    );
    assert!(
        logs.contains(&ai_memory::url_display::url_origin(&hostile_url)),
        "operator log names the target origin:\n{logs}"
    );
}

// ---------------------------------------------------------------------
// #3711 — the sqlx→StoreError funnel: a refused connect never renders
// the DSN (live only under sal-postgres; a closed port needs no server).
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_connect_refusal_never_renders_the_dsn_3711() {
    let dsn = credentialed_dsn();
    let Err(err) = ai_memory::store::postgres::PostgresStore::connect(&dsn).await else {
        panic!("closed port refuses");
    };
    let text = format!("{err}");
    assert_clean(&text, "PostgresStore::connect error");
    let dbg = format!("{err:?}");
    assert_clean(&dbg, "PostgresStore::connect Debug");
}

// ---------------------------------------------------------------------
// #3711 — the userinfo-only maskers have NO production caller left. The
// two functions stay in `src/logging.rs` (their unit tests exercise them
// and an in-flight branch still edits them) but nothing under `src/`
// may render a URL through them again: a masker is a denylist, and the
// only sanctioned URL rendering is `url_display`. Mechanical, so the
// class cannot creep back one site at a time.
// ---------------------------------------------------------------------

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_production_site_renders_a_url_through_the_userinfo_maskers_3711() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut offenders = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .expect("under the crate")
            .to_path_buf();
        if rel == Path::new("src/logging.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read source");
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("redact_url_password(") || code.contains("redact_urls_in_message(") {
                offenders.push(format!("{}:{}: {}", rel.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "#3711: a URL is rendered through a userinfo-only masker; use \
         `url_display::{{url_origin, url_origin_and_path, store_url_display}}`:\n{}",
        offenders.join("\n")
    );
}
