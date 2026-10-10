// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6101 follow-up — the `sync_state` key of a sync-daemon peer is
//! `url_display::url_origin_and_path(peer_url)` (#3675). Since #6101 that
//! renderer returns the CONSTANT `scheme://<redacted-authority>` for every
//! peer URL with an ambiguous authority, and an unparseable URL renders a
//! constant too. Two such peers would then share ONE cursor row: the
//! #3675 heal (`rekey_peer`) folds both raw-keyed rows into it and each
//! peer pulls from the other's watermark, skipping rows it never received.
//!
//! The cycle must refuse such a peer BEFORE it reads `sync_state`: no row
//! is keyed by a non-unique rendering, no cursor is folded, the refusal
//! carries no credential byte, and (#6628) a raw-keyed row holding the
//! credential URL is deleted rather than kept at rest.

use std::path::Path;

use rusqlite::Connection;
use tempfile::TempDir;

const MARKER: &str = "SECRETK6101";

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("sync-state-peer-key-6101");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("scratch dir")
}

fn stored_keys(db: &Path) -> Vec<(String, String)> {
    let conn = Connection::open(db).expect("open");
    let mut stmt = conn
        .prepare("SELECT peer_id, COALESCE(last_seen_at, '') FROM sync_state ORDER BY peer_id")
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// Two peers whose keys would collide, each with a planted pre-#3675
/// raw-keyed cursor at a DIFFERENT watermark.
async fn assert_no_shared_key(tag: &str, peers: &[String; 2]) {
    let dir = scratch(tag);
    let db = dir.path().join("sync.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    let a_key = ai_memory::url_display::url_origin_and_path(&peers[0]);
    let b_key = ai_memory::url_display::url_origin_and_path(&peers[1]);
    assert_eq!(a_key, b_key, "{tag}: the fixture pair must collide");
    {
        let conn = Connection::open(&db).expect("open");
        for (peer, at) in peers
            .iter()
            .zip(["2026-09-01T00:00:00Z", "2026-09-20T00:00:00Z"])
        {
            ai_memory::db::sync_state_observe(&conn, "me-6101", peer, at)
                .expect("plant raw-keyed row");
        }
    }
    let before = stored_keys(&db);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("client");
    let mut errors = Vec::new();
    for peer in peers {
        let err =
            ai_memory::daemon_runtime::sync_cycle_once(&client, &db, "me-6101", peer, None, 10)
                .await
                .expect_err("a peer without a unique sync_state key is refused");
        errors.push(format!("{err:#}"));
    }
    let after = stored_keys(&db);
    assert_eq!(before.len(), 2, "{tag}: both raw-keyed rows were planted");
    assert!(
        after.iter().all(|(k, _)| *k != a_key),
        "{tag}: a cursor was keyed by the shared rendering {a_key:?}: {after:?}"
    );
    // #6628 (3-agent vote (6def5ab6), option A): a refused peer's raw-keyed
    // row holds the credential URL, so the refusal deletes it rather than
    // keeping it at rest; no cursor is folded into the shared rendering.
    assert!(
        after.iter().all(|(k, _)| !k.contains(MARKER)),
        "{tag}: a refused peer's raw credential key survived at rest: {after:?}"
    );
    assert!(
        after.is_empty(),
        "{tag}: sync_state gained a row for a refused peer: {after:?}"
    );
    for text in &errors {
        assert!(
            !text.contains(MARKER),
            "{tag}: the refusal carries credential bytes: {text}"
        );
        assert!(
            text.contains("#6101"),
            "{tag}: the cycle failed for another reason than the key refusal: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_peers_never_share_a_sync_state_key_6101() {
    assert_no_shared_key(
        "ambiguous",
        &[
            format!("https://svc:a@127.0.0.1:9/{MARKER}a@peer-a.example/mesh"),
            format!("https://svc:a@127.0.0.1:9/{MARKER}b@peer-b.example/mesh"),
        ],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unparseable_peers_never_share_a_sync_state_key_6101() {
    assert_no_shared_key(
        "unparseable",
        &[
            format!("https://svc:{MARKER}@127.0.0.1:99999/a"),
            format!("https://svc:{MARKER}@127.0.0.1:99999/b"),
        ],
    )
    .await;
}
