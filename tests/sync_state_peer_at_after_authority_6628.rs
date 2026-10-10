// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6628 / #6700 — a sync-daemon peer URL with a literal `@` left after the
//! url-crate PARSED authority has no durable `sync_state` key (3-agent vote
//! (6def5ab6), memory 67aec9a2, option A: refuse on the parsed authority).
//!
//! The old check was a fixed list of shapes plus a raw `://` scan, so a
//! numeric-prefixed password (`svc:123/<pw>@host`, parsed as port `123`), a
//! password-less token holding `/` and the #6700 parser-divergence shape
//! (no slashes after the scheme, `://` inside the secret) were rendered as a
//! key holding credential bytes and written to `sync_state.peer_id`.
//!
//! The cycle must refuse such a peer BEFORE any `sync_state` read or write
//! and before the #3675 rekey, delete a row a previous daemon keyed by the
//! raw credential URL, and name only the redacted key plus the `%40` remedy.
//! A `%40`-encoded `@` keeps a durable key and syncs as before.

use std::path::Path;

use rusqlite::Connection;
use tempfile::TempDir;

const MARKER: &str = "SECRETK6628";
const AGENT: &str = "me-6628";

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("sync-state-peer-at-6628");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("scratch dir")
}

fn stored_keys(db: &Path) -> Vec<String> {
    let conn = Connection::open(db).expect("open");
    let mut stmt = conn
        .prepare("SELECT peer_id FROM sync_state ORDER BY peer_id")
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("client")
}

/// Every refused shape the issues name. `127.0.0.1:9` (discard) is the
/// "real" host, so an accepted URL fails on the connection, never on DNS.
fn refused_peers() -> Vec<(&'static str, String)> {
    vec![
        (
            "numeric-password-slash",
            format!("https://svc:123/{MARKER}pw@127.0.0.1:9/mesh"),
        ),
        (
            "numeric-password-query",
            format!("https://svc:123?{MARKER}pw@127.0.0.1:9/mesh"),
        ),
        (
            "numeric-password-fragment",
            format!("https://svc:123#{MARKER}pw@127.0.0.1:9/mesh"),
        ),
        (
            "token-only-slash",
            format!("https://tok/{MARKER}@127.0.0.1:9/mesh"),
        ),
        (
            "token-only-query",
            format!("https://tok?{MARKER}@127.0.0.1:9/mesh"),
        ),
        (
            "parser-divergence-6700",
            format!("https:svc:/{MARKER}/x://y/z@127.0.0.1:9/mesh"),
        ),
        (
            "literal-at-in-path",
            format!("https://127.0.0.1:9/mesh/{MARKER}@b"),
        ),
    ]
}

/// The refusal: named by the redacted key only, with the `%40` remedy, and
/// the row a previous daemon keyed by the raw credential URL is deleted.
#[tokio::test(flavor = "multi_thread")]
async fn at_after_parsed_authority_is_refused_and_raw_row_deleted_6628() {
    for (tag, peer) in refused_peers() {
        let dir = scratch(tag);
        let db = dir.path().join("sync.db");
        let _ = ai_memory::db::open(&db).expect("seed db");
        {
            let conn = Connection::open(&db).expect("open");
            ai_memory::db::sync_state_observe(&conn, AGENT, &peer, "2026-09-01T00:00:00Z")
                .expect("plant raw-keyed row");
            ai_memory::db::sync_state_observe(
                &conn,
                AGENT,
                "https://other.example/mesh",
                "2026-09-02T00:00:00Z",
            )
            .expect("plant an unrelated peer row");
        }
        let err =
            ai_memory::daemon_runtime::sync_cycle_once(&client(), &db, AGENT, &peer, None, 10)
                .await
                .expect_err("a literal '@' after the parsed authority is refused");
        let text = format!("{err:#}");
        assert!(
            !text.contains(MARKER),
            "{tag}: the refusal carries credential bytes: {text}"
        );
        assert!(
            text.contains("#6628"),
            "{tag}: refused for another reason: {text}"
        );
        assert!(
            text.contains("%40"),
            "{tag}: the refusal does not name the %40 remedy: {text}"
        );
        assert!(
            text.contains("<redacted-authority>"),
            "{tag}: the refusal does not name the redacted key: {text}"
        );
        let keys = stored_keys(&db);
        assert!(
            keys.iter().all(|k| !k.contains(MARKER)),
            "{tag}: a sync_state key still holds credential bytes: {keys:?}"
        );
        assert!(
            keys.iter().all(|k| !k.contains("<redacted-authority>")),
            "{tag}: a cursor was keyed by the shared redacted rendering: {keys:?}"
        );
        assert_eq!(
            keys,
            vec!["https://other.example/mesh".to_string()],
            "{tag}: an unrelated peer row was touched"
        );
    }
}

/// The remedy the refusal names: a literal `@` written `%40` (in the path
/// and in the password) keeps a durable key. The cycle gets past the key
/// check, folds the raw-keyed row onto the rendered key (#3675), and fails
/// only on the connection to the discard port.
#[tokio::test(flavor = "multi_thread")]
async fn percent_encoded_at_is_accepted_and_keeps_its_cursor_6628() {
    let dir = scratch("percent-40");
    let db = dir.path().join("sync.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    let peer = format!("https://svc:{MARKER}%40x@127.0.0.1:9/mesh/a%40b");
    {
        let conn = Connection::open(&db).expect("open");
        ai_memory::db::sync_state_observe(&conn, AGENT, &peer, "2026-09-01T00:00:00Z")
            .expect("plant raw-keyed row");
    }
    let err = ai_memory::daemon_runtime::sync_cycle_once(&client(), &db, AGENT, &peer, None, 10)
        .await
        .expect_err("the discard port refuses the connection");
    let text = format!("{err:#}");
    assert!(
        !text.contains("#6628"),
        "a %40 URL was refused by the key check: {text}"
    );
    assert!(
        !text.contains(MARKER),
        "the error carries credential bytes: {text}"
    );
    assert_eq!(
        stored_keys(&db),
        vec!["https://127.0.0.1:9/mesh/a%40b".to_string()],
        "the %40 peer lost its cursor or kept the raw credential key"
    );
}
