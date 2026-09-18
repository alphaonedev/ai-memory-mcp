// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3744 — userinfo in a webhook URL must not hide the target from the
//! SSRF guard at REGISTRATION.
//!
//! `subscriptions::validate_url` took the host as the text before the last
//! `:` of the raw authority, so for `https://a:b@169.254.169.254/` the
//! "host" was the username `a`, the loopback / private-range checks ran
//! against that literal and PASSED, and `insert` stored a subscription
//! aimed at the cloud instance-metadata endpoint. Only the dispatch-time
//! DNS guard refused it — because `user:pw@host` does not resolve, not
//! because it saw the address: a defence that held by accident, under the
//! wrong reason (`dns_ssrf_rejected`), one refactor from not holding.
//!
//! Both guards now strip userinfo at the LAST `@` of the authority before
//! any host extraction (`subscriptions::authority_without_userinfo`); the
//! unit cells beside the guards pin the syntactic and the DNS line. These
//! cells pin the REGISTRATION surface the tenant reaches: `insert` refuses
//! each shape, names the real host, and never echoes the userinfo.
//! RED on `1ec64196b` (every `insert` below succeeded), GREEN on the fix.

#![cfg(feature = "sal")]

use ai_memory::subscriptions::{NewSubscription, insert, list};
use rusqlite::Connection;

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch under .local-runs");
    let db = dir.path().join("hooks.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    (dir, db)
}

fn register(conn: &Connection, url: &str) -> Result<String, String> {
    insert(
        conn,
        &NewSubscription {
            url,
            events: "*",
            secret: Some("test-sub-secret-3744"),
            namespace_filter: None,
            agent_filter: None,
            created_by: None,
            event_types: None,
        },
    )
    .map_err(|e| e.to_string())
}

#[test]
fn registration_refuses_a_userinfo_url_to_a_private_loopback_or_metadata_host_3744() {
    // The guard's default posture: loopback webhooks DISALLOWED.
    ai_memory::config::set_allow_loopback_webhooks(false);
    let (_dir, db) = fresh_db();
    let conn = Connection::open(&db).expect("open");
    for (url, host) in [
        ("https://a:b@10.0.0.1/hook", "10.0.0.1"),
        (
            "https://a:b@169.254.169.254/latest/meta-data",
            "169.254.169.254",
        ),
        ("https://a:b@127.0.0.1:9/hook", "127.0.0.1"),
        ("https://a:b@[fd00::1]/hook", "fd00::1"),
        ("https://example.com:pw@10.0.0.1/hook", "10.0.0.1"),
    ] {
        let err =
            register(&conn, url).expect_err(&format!("#3744: registration must refuse {url}"));
        assert!(
            err.contains(host),
            "#3744: the refusal names the real host {host} for {url}: {err}"
        );
        assert!(
            !err.contains("a:b") && !err.contains("example.com:pw"),
            "#3744: the refusal never echoes the userinfo for {url}: {err}"
        );
    }
    assert!(
        list(&conn, None).expect("list").is_empty(),
        "#3744: nothing was registered"
    );
}

#[test]
fn registration_still_accepts_a_public_host_with_userinfo_3744() {
    // Stripping, not refusing: a userinfo URL to a PUBLIC host is the
    // Slack/Discord shape with basic auth in front of it, and it registers
    // as before. (Whether userinfo itself should be refused as a credential
    // in the row is #3697's territory, not this guard's.)
    let (_dir, db) = fresh_db();
    let conn = Connection::open(&db).expect("open");
    register(&conn, "https://a:b@hooks.example.com/services/T/B/X")
        .expect("#3744: a public host behind userinfo still registers");
}

/// #3744 — the dispatch cell the issue asked for, on the ONE row shape that
/// can still carry the defect: a subscription registered BEFORE the fix
/// (the table holds it verbatim; the guard at `insert` never ran on this
/// URL). With loopback DISALLOWED the syntactic guard `send` runs first
/// must refuse it under the SSRF reason — `ssrf_rejected`, the class the
/// row belongs to — never `dns_ssrf_rejected` (the accidental refusal the
/// pre-fix guard produced by failing to RESOLVE the username), and the
/// loopback listener must see no connection at all. RED with f1fbfe312's
/// `authority_without_userinfo` reverted (the DLQ row reads
/// `dns_ssrf_rejected`), GREEN on the tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_userinfo_row_is_refused_at_dispatch_as_ssrf_not_dns_3744() {
    use ai_memory::subscriptions::{dispatch_event, dlq_reason, list_dlq, wait_dispatch_idle};

    ai_memory::config::set_allow_loopback_webhooks(false);
    let (_dir, db) = fresh_db();
    // A listener on loopback that must never be reached: a refusal that
    // happens in the guard costs no connect.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let legacy_url = format!("https://a:b@127.0.0.1:{port}/hook");
    let sub_id = {
        let conn = Connection::open(&db).expect("open");
        // The guard at `insert` refuses the legacy shape on this tip, so the
        // pre-fix row can only reach the table around it: register a public
        // target, then rewrite the stored URL the way a pre-fix `insert`
        // would have stored it.
        let id = register(&conn, "https://hooks.example.com/services/T/B/legacy")
            .expect("a public target registers");
        conn.execute(
            "UPDATE subscriptions SET url = ?1 WHERE id = ?2",
            rusqlite::params![legacy_url, id],
        )
        .expect("rewrite the stored URL to the pre-fix userinfo shape");
        id
    };
    {
        let conn = Connection::open(&db).expect("open");
        dispatch_event(&conn, "memory_store", "evt-3744", "ns-3744", None, &db);
        // #3764 — the dispatcher's own completion signal, not a wall-clock poll.
        wait_dispatch_idle().await;
    }
    let rows = {
        let conn = Connection::open(&db).expect("open");
        list_dlq(&conn, Some(sub_id.as_str())).expect("dlq")
    };
    assert_eq!(
        rows.len(),
        1,
        "#3744: one DLQ row for the refused delivery: {rows:?}"
    );
    assert_eq!(
        rows[0].last_error,
        dlq_reason::SSRF_REJECTED,
        "#3744: a legacy userinfo row to loopback is refused as an SSRF violation, \
         not as a resolver miss"
    );
    assert_ne!(rows[0].last_error, dlq_reason::DNS_SSRF_REJECTED);
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("#3744: the loopback listener must never be connected to: {other:?}"),
    }
}
