// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3961 — the postgres half of #1773: a same-id federation merge where the
//! remote wins the LWW tiebreak must archive the PRE-MERGE row under
//! `archive_reason = 'federation_merge'`, exactly as the sqlite
//! `overwrite_full_row_by_id` does (pinned there by
//! `tests/encryption_at_rest.rs::federation_merge_seals_content_and_snapshots_1773`).
//! Before #3961 `PostgresStore::merge_inbound` overwrote the row with no
//! snapshot while its own comment claimed one existed, so a stock postgres
//! node permanently discarded locally-authored content that a peer's newer
//! write replaced.
//!
//! The assertion keys on the archive REASON, so it cannot pass on an archive
//! row written for some other cause; the negative cell proves a merge that
//! overwrote nothing (no row by id) writes no snapshot.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::models::Memory;
use ai_memory::models::field_names::ARCHIVE_REASON_FEDERATION_MERGE;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

const LOCAL_CONTENT: &str = "locally authored content the peer overwrites";
const REMOTE_CONTENT: &str = "newer content pushed by a federation peer";

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn mem(id: &str, ns: &str, content: &str, updated_at: &str, author: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: format!("merge-snapshot-3961 {id}"),
        content: content.to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: updated_at.to_string(),
        metadata: serde_json::json!({ "agent_id": author }),
        ..Memory::default()
    }
}

/// Every `federation_merge` archive row for `id` in `ns`, as its archived content.
async fn merge_snapshots(store: &PostgresStore, ns: &str, id: &str) -> Vec<String> {
    store
        .list_archived(Some(ns), 1000, 0)
        .await
        .expect("list_archived")
        .into_iter()
        .filter(|row| row.get("id").and_then(|v| v.as_str()) == Some(id))
        .filter(|row| {
            row.get("archive_reason").and_then(|v| v.as_str())
                == Some(ARCHIVE_REASON_FEDERATION_MERGE)
        })
        .map(|row| {
            row.get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn pg_merge_inbound_snapshots_the_pre_merge_row_3961() {
    let Some(store) = connect().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let author = "ai:merge-snapshot-3961";
    let ns = format!("merge-snapshot-3961-{}", uuid::Uuid::new_v4());
    let id = uuid::Uuid::new_v4().to_string();
    let ctx = CallerContext::for_agent(author);

    store
        .store(
            &ctx,
            &mem(&id, &ns, LOCAL_CONTENT, "2026-01-01T00:00:00+00:00", author),
        )
        .await
        .expect("seed the local row");

    // SAME id, NEWER updated_at — the remote wins the LWW tiebreak.
    let inbound = mem(
        &id,
        &ns,
        REMOTE_CONTENT,
        "2026-06-01T00:00:00+00:00",
        author,
    );
    store
        .merge_inbound(&ctx, &inbound, false)
        .await
        .expect("merge_inbound");

    let live = store.get(&ctx, &id).await.expect("merged row");
    assert_eq!(live.content, REMOTE_CONTENT, "the remote won the merge");

    let snaps = merge_snapshots(&store, &ns, &id).await;
    assert_eq!(
        snaps,
        vec![LOCAL_CONTENT.to_string()],
        "#3961: a postgres federation merge must archive the pre-merge row under \
         archive_reason='{ARCHIVE_REASON_FEDERATION_MERGE}' (sqlite parity, #1773)"
    );

    // Idempotent: a repeated merge keeps ONE most-recent snapshot, as sqlite's
    // INSERT OR REPLACE does.
    store
        .merge_inbound(&ctx, &inbound, false)
        .await
        .expect("repeat merge_inbound");
    assert_eq!(
        merge_snapshots(&store, &ns, &id).await.len(),
        1,
        "a repeated merge replaces the snapshot, never accumulates"
    );
}

#[tokio::test]
async fn pg_merge_inbound_without_an_existing_row_writes_no_snapshot_3961() {
    let Some(store) = connect().await else {
        eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let author = "ai:merge-snapshot-3961";
    let ns = format!("merge-snapshot-3961-neg-{}", uuid::Uuid::new_v4());
    let id = uuid::Uuid::new_v4().to_string();
    let ctx = CallerContext::for_agent(author);

    let inbound = mem(
        &id,
        &ns,
        REMOTE_CONTENT,
        "2026-06-01T00:00:00+00:00",
        author,
    );
    store
        .merge_inbound(&ctx, &inbound, false)
        .await
        .expect("merge_inbound of a fresh row");

    assert!(
        merge_snapshots(&store, &ns, &id).await.is_empty(),
        "a merge that overwrote nothing must not write a federation_merge snapshot"
    );
}
