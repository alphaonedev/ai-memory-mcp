//! #9466 (E-1, E-4, E-5, E-7; 3-agent vote 71472661) — the sqlite
//! `DELETE /api/v1/links` branch decides on the endpoint rows AS READ:
//!
//! * a missing endpoint row is a refusal (`{"deleted": false}`, no DELETE),
//!   never an admission — including the missing-SOURCE arm, which before
//!   #9466 called `db::delete_link` with no owner check at all;
//! * a failed TARGET read is a read error (500, no DELETE), never folded
//!   into "no target row";
//! * the both-unstamped legacy admission needs an EMPTY source addressee.
//!
//! Orphan edges are seeded with `PRAGMA foreign_keys = OFF`: both
//! `memory_links` foreign keys are `ON DELETE CASCADE`, so with the keys on
//! no edge can outlive an endpoint; the orphan shape is what the gate must
//! still refuse when it does exist.

use super::*;

const VICTIM: &str = "ai:victim-9466";
const STRANGER: &str = "ai:stranger-9466";
const OTHER_ADDRESSEE: &str = "ai:addressee-9466";
const ABSENT_ID: &str = "99999999-9999-4999-8999-999999999466";
const NS: &str = "ns-9466";
const RELATION: &str = "related_to";

fn owned_by(agent: &str) -> serde_json::Value {
    json!({ "agent_id": agent })
}

/// Seed a `memory_links` row whose endpoints need not exist.
async fn seed_edge(state: &Db, source_id: &str, target_id: &str) {
    let lock = state.lock().await;
    lock.0.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    lock.0
        .execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![source_id, target_id, RELATION, Utc::now().to_rfc3339()],
        )
        .unwrap();
    lock.0.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
}

async fn edge_count(state: &Db, source_id: &str, target_id: &str) -> i64 {
    let lock = state.lock().await;
    lock.0
        .query_row(
            "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
            rusqlite::params![source_id, target_id],
            |r| r.get(0),
        )
        .unwrap()
}

/// Store the row's `tags` as a BLOB so `db::get` fails decoding it (a real
/// read error, not an absent row; an INTEGER would be coerced to TEXT by the
/// column affinity).
async fn corrupt_row(state: &Db, id: &str) {
    let lock = state.lock().await;
    let changed = lock
        .0
        .execute(
            "UPDATE memories SET tags = X'00' WHERE id = ?1",
            rusqlite::params![id],
        )
        .unwrap();
    assert_eq!(changed, 1, "the corrupted row must exist");
    assert!(
        db::get(&lock.0, id).is_err(),
        "the corrupted row must give a read error, not a row and not None"
    );
}

async fn http_delete(
    state: &Db,
    caller: &str,
    source_id: &str,
    target_id: &str,
) -> (StatusCode, serde_json::Value) {
    let app = Router::new()
        .route("/api/v1/links", axum::routing::delete(delete_link))
        .with_state(test_app_state(state.clone()));
    let body = json!({ "source_id": source_id, "target_id": target_id, "relation": RELATION });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/links")
                .method("DELETE")
                .header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON)
                .header("x-agent-id", caller)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// REPRO links.rs 1087: source row absent, target owned by the victim, an
/// ordinary stranger. Pre-#9466 the missing-source arm deleted the edge.
#[tokio::test]
async fn http_delete_link_missing_source_refuses_a_stranger_9466() {
    let state = test_state();
    let target =
        insert_test_memory_with_metadata(&state, NS, "victim-target", owned_by(VICTIM)).await;
    seed_edge(&state, ABSENT_ID, &target).await;
    let (status, v) = http_delete(&state, STRANGER, ABSENT_ID, &target).await;
    assert_eq!(
        (
            status,
            v.clone(),
            edge_count(&state, ABSENT_ID, &target).await
        ),
        (StatusCode::OK, json!({"deleted": false}), 1),
        "a stranger must not sever an orphan edge whose source row is absent: {v}"
    );
}

/// D-3: the caller owns the present endpoint, so the orphan edge is theirs
/// to sever (today's result kept).
#[tokio::test]
async fn http_delete_link_missing_source_target_owner_still_deletes_9466() {
    let state = test_state();
    let target = insert_test_memory_with_metadata(&state, NS, "own-target", owned_by(VICTIM)).await;
    seed_edge(&state, ABSENT_ID, &target).await;
    let (status, v) = http_delete(&state, VICTIM, ABSENT_ID, &target).await;
    assert_eq!(
        (status, v, edge_count(&state, ABSENT_ID, &target).await),
        (StatusCode::OK, json!({"deleted": true}), 0),
        "the owner of the surviving target must still sever the orphan edge"
    );
}

/// E-7: a wire caller cannot be the daemon: the reserved id is refused like
/// a stranger and the orphan edge is kept.
#[tokio::test]
async fn http_delete_link_missing_source_wire_daemon_claim_refused_9466() {
    let state = test_state();
    let target =
        insert_test_memory_with_metadata(&state, NS, "daemon-target", owned_by(VICTIM)).await;
    seed_edge(&state, ABSENT_ID, &target).await;
    let (status, v) = http_delete(
        &state,
        crate::identity::sentinels::DAEMON_PRINCIPAL,
        ABSENT_ID,
        &target,
    )
    .await;
    // `daemon` is a reserved id: a wire caller cannot claim it (it resolves
    // to the invalid-identity sentinel), so this caller is a stranger. The
    // daemon's own orphan removal is the store-level cell
    // `store::delete_link_owner_9466` (daemon row: Removed).
    assert_eq!(
        (status, v, edge_count(&state, ABSENT_ID, &target).await),
        (StatusCode::OK, json!({"deleted": false}), 1),
        "a wire caller naming the reserved daemon id is not the daemon"
    );
}

/// E-1: target row absent, unstamped source, a stranger. Pre-#9466 the
/// absent target counted as unstamped and the legacy admission deleted it.
#[tokio::test]
async fn http_delete_link_missing_target_refuses_a_stranger_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "unstamped-source", json!({})).await;
    seed_edge(&state, &source, ABSENT_ID).await;
    let (status, v) = http_delete(&state, STRANGER, &source, ABSENT_ID).await;
    assert_eq!(
        (
            status,
            v.clone(),
            edge_count(&state, &source, ABSENT_ID).await
        ),
        (StatusCode::OK, json!({"deleted": false}), 1),
        "an absent target row is not an unstamped one: {v}"
    );
}

/// E-7: both endpoint rows absent; a stranger is refused, and so is a wire
/// caller naming the reserved daemon id.
#[tokio::test]
async fn http_delete_link_both_missing_9466() {
    let state = test_state();
    let other_absent = "88888888-8888-4888-8888-888888889466";
    seed_edge(&state, ABSENT_ID, other_absent).await;
    let (status, v) = http_delete(&state, STRANGER, ABSENT_ID, other_absent).await;
    assert_eq!((status, v), (StatusCode::OK, json!({"deleted": false})));
    assert_eq!(edge_count(&state, ABSENT_ID, other_absent).await, 1);
    let (status, v) = http_delete(
        &state,
        crate::identity::sentinels::DAEMON_PRINCIPAL,
        ABSENT_ID,
        other_absent,
    )
    .await;
    // The reserved daemon id is not claimable over the wire (see above).
    assert_eq!(
        (status, v, edge_count(&state, ABSENT_ID, other_absent).await),
        (StatusCode::OK, json!({"deleted": false}), 1),
    );
}

/// links.rs 1095-1097: a failed TARGET read is a read error, never "no
/// target row": 500 with the generic text, and no DELETE runs.
#[tokio::test]
async fn http_delete_link_target_read_error_is_not_absence_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "unstamped-src", json!({})).await;
    let target = insert_test_memory_with_metadata(&state, NS, "corrupt-target", json!({})).await;
    seed_edge(&state, &source, &target).await;
    corrupt_row(&state, &target).await;
    let (status, v) = http_delete(&state, STRANGER, &source, &target).await;
    assert_eq!(
        (
            status,
            v.clone(),
            edge_count(&state, &source, &target).await
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR}),
            1
        ),
        "a failed target read must refuse with the read error and keep the edge: {v}"
    );
}

/// E-4: both rows present and unstamped, but the source is ADDRESSED to
/// another agent: no legacy admission for a stranger.
#[tokio::test]
async fn http_delete_link_addressed_unstamped_source_refuses_a_stranger_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(
        &state,
        NS,
        "addressed-src",
        json!({ "target_agent_id": OTHER_ADDRESSEE }),
    )
    .await;
    let target = insert_test_memory_with_metadata(&state, NS, "unstamped-tgt", json!({})).await;
    seed_edge(&state, &source, &target).await;
    let (status, _) = http_delete(&state, STRANGER, &source, &target).await;
    assert_eq!(
        (status, edge_count(&state, &source, &target).await),
        (StatusCode::FORBIDDEN, 1)
    );
}

/// E-3/E-4: both rows present, unstamped, no addressee: the legacy
/// admission stands under the default `warn` posture (today's result).
#[tokio::test]
async fn http_delete_link_both_unstamped_legacy_admits_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "legacy-src", json!({})).await;
    let target = insert_test_memory_with_metadata(&state, NS, "legacy-tgt", json!({})).await;
    seed_edge(&state, &source, &target).await;
    let (status, v) = http_delete(&state, STRANGER, &source, &target).await;
    assert_eq!((status, v), (StatusCode::OK, json!({"deleted": true})));
}

/// E-2 on the HTTP surface: a present target whose `metadata` column is not
/// JSON is an undecodable owner (refused), never the `{}` `db::get` folds it
/// to — which would read as unstamped and take the legacy admission.
#[tokio::test]
async fn http_delete_link_undecodable_target_owner_refuses_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "plain-src", json!({})).await;
    let target = insert_test_memory_with_metadata(&state, NS, "garbled-tgt", json!({})).await;
    seed_edge(&state, &source, &target).await;
    {
        let lock = state.lock().await;
        let changed = lock
            .0
            .execute(
                "UPDATE memories SET metadata = '{not json 9466' WHERE id = ?1",
                rusqlite::params![target],
            )
            .unwrap();
        assert_eq!(changed, 1, "the garbled row must exist");
    }
    let (status, _) = http_delete(&state, STRANGER, &source, &target).await;
    assert_eq!(
        (status, edge_count(&state, &source, &target).await),
        (StatusCode::FORBIDDEN, 1),
        "an undecodable owner is not an unstamped one"
    );
}

/// Ruling 2ed6d3a8 item 4: an EMPTY caller id never matches an EMPTY owner.
/// An empty `X-Agent-Id` resolves to a fresh `anonymous:req-…` id, and an
/// `agent_id: ""` row is unstamped (never `Stamped("")`), so over a
/// victim-owned target the empty caller is refused like any stranger.
#[tokio::test]
async fn http_delete_link_empty_caller_is_not_the_empty_owner_9466() {
    let state = test_state();
    let source =
        insert_test_memory_with_metadata(&state, NS, "empty-owner-src", json!({"agent_id": ""}))
            .await;
    let target =
        insert_test_memory_with_metadata(&state, NS, "victim-tgt-e", owned_by(VICTIM)).await;
    seed_edge(&state, &source, &target).await;
    let (status, _) = http_delete(&state, "", &source, &target).await;
    assert_eq!(
        (status, edge_count(&state, &source, &target).await),
        (StatusCode::FORBIDDEN, 1),
        "an empty caller id must not own an empty-owner row"
    );
}

/// #9483 site 2 (target arm), owner side: the owner of the surviving SOURCE
/// still severs an orphan edge whose target row is absent.
#[tokio::test]
async fn http_delete_link_missing_target_source_owner_still_deletes_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "own-source", owned_by(VICTIM)).await;
    seed_edge(&state, &source, ABSENT_ID).await;
    let (status, v) = http_delete(&state, VICTIM, &source, ABSENT_ID).await;
    assert_eq!(
        (status, v, edge_count(&state, &source, ABSENT_ID).await),
        (StatusCode::OK, json!({"deleted": true}), 0),
        "the owner of the surviving source must still sever the orphan edge"
    );
}

/// #9483 site 2, owner side of the read error: a failed TARGET read refuses
/// even the SOURCE owner (no decision from a row that was not read; 500 and
/// the edge kept).
#[tokio::test]
async fn http_delete_link_target_read_error_refuses_the_source_owner_too_9466() {
    let state = test_state();
    let source = insert_test_memory_with_metadata(&state, NS, "owned-src", owned_by(VICTIM)).await;
    let target = insert_test_memory_with_metadata(&state, NS, "corrupt-tgt-2", json!({})).await;
    seed_edge(&state, &source, &target).await;
    corrupt_row(&state, &target).await;
    let (status, v) = http_delete(&state, VICTIM, &source, &target).await;
    assert_eq!(
        (status, v, edge_count(&state, &source, &target).await),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR}),
            1
        ),
    );
}
