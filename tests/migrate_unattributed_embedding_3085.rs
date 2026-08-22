// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3085 — `migrate` must never mint an UNATTRIBUTED embedding stamp.
//!
//! The #3060 Phase-3 embedding copy bucketed a source row whose
//! `embedding_space` is SQL NULL under `space.unwrap_or_default()` — the EMPTY
//! STRING — and then wrote it verbatim. `''` is NON-NULL, so the destination
//! row fell outside BOTH the #2167 recall gate (`AND embedding_space =
//! <active_fp>`) and every NULL-space heal scan: permanently non-recallable
//! AND unhealable, while `migrate` reported `errors: []`.
//!
//! The fix is provenance-honest: a NULL-space source vector has NO provenance
//! to preserve, so it is NOT copied. The destination row lands unembedded and
//! its own backfill re-derives the vector from the DURABLE TEXT under the live
//! embedder, stamping the ACTIVE space — the self-healing pre-#3060 state. The
//! count is REPORTED (`embeddings_unattributed`) rather than silently absorbed.

#![cfg(feature = "sal")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn mem(id: &str, ns: &str, title: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("durable text for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: serde_json::json!({ "agent_id": "ai:3085-migrate" }),
        version: 1,
        ..Memory::default()
    }
}

/// Scratch dir under `.local-runs/` (project no-`/tmp` HARD RULE).
fn scratch(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3085-migrate-unattributed");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// A NULL-space source vector must NOT be copied as `''`; it must be skipped,
/// COUNTED, and leave the destination row unembedded (so the destination's own
/// backfill heals it), while an ATTRIBUTED vector is still copied verbatim.
#[tokio::test]
async fn migrate_skips_and_reports_null_space_vectors_3085() {
    let dir = scratch("null-space");
    let src_path = dir.path().join("src.db");
    let dst_path = dir.path().join("dst.db");
    let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
    let dst = SqliteStore::open(dst_path.to_str().unwrap()).expect("open dst");

    let ns = "ns3085";
    let ctx = CallerContext::for_admin("ai:3085-migrate");
    let attributed_id = uuid::Uuid::new_v4().to_string();
    let unattributed_id = uuid::Uuid::new_v4().to_string();
    src.store(&ctx, &mem(&attributed_id, ns, "attributed row"))
        .await
        .expect("store attributed");
    src.store(&ctx, &mem(&unattributed_id, ns, "unattributed row"))
        .await
        .expect("store unattributed");

    let fp = ai_memory::embeddings::embedding_space_fingerprint("test-space-3085");
    let vec: Vec<f32> = {
        let mut v = vec![0.0_f32; 8];
        v[0] = 1.0;
        v
    };
    src.update_embedding(&ctx, &attributed_id, Some(&vec), &fp)
        .await
        .expect("stamp attributed");
    src.update_embedding(&ctx, &unattributed_id, Some(&vec), &fp)
        .await
        .expect("stamp before NULLing");
    // Reproduce the LEGACY unverified-provenance state (`embedding IS NOT
    // NULL AND embedding_space IS NULL`). The write funnels cannot produce it
    // — that is the #3085 fail-closed half — so seed it directly, exactly as a
    // pre-v84 corpus carries it.
    {
        let conn = rusqlite::Connection::open(&src_path).expect("raw open src");
        let n = conn
            .execute(
                "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
                rusqlite::params![unattributed_id],
            )
            .expect("null the source stamp");
        assert_eq!(n, 1, "fixture must NULL exactly one source stamp");
    }

    let report = ai_memory::migrate::migrate(&src, &dst, 100, Some(ns.to_string()), false).await;

    assert!(
        report.errors.is_empty(),
        "migrate must complete cleanly: {:?}",
        report.errors
    );
    assert_eq!(report.memories_written, 2, "both memories migrate");
    assert_eq!(
        report.embeddings_copied, 1,
        "only the ATTRIBUTED vector is copied"
    );
    assert_eq!(
        report.embeddings_unattributed, 1,
        "#3085: the NULL-space vector must be COUNTED, not silently absorbed"
    );

    let copied = dst
        .get_embedding_with_space(&ctx, &attributed_id)
        .await
        .expect("read attributed");
    let (copied_vec, copied_space) = copied.expect("attributed vector copied");
    assert_eq!(copied_vec, vec, "the attributed vector is copied verbatim");
    assert_eq!(
        copied_space.as_deref(),
        Some(fp.as_str()),
        "its space fingerprint is preserved verbatim (never re-derived)"
    );

    let skipped = dst
        .get_embedding_with_space(&ctx, &unattributed_id)
        .await
        .expect("read unattributed");
    assert!(
        skipped.is_none(),
        "#3085: the NULL-space vector must NOT be copied. Pre-fix it landed with \
         embedding_space='' — non-NULL, so excluded from the #2167 recall gate AND from \
         every NULL-space heal scan (permanent silent recall loss). Leaving the row \
         unembedded lets the destination backfill re-derive it from the durable text."
    );

    // The DURABLE TEXT — the actual source of truth — is intact either way.
    let text = dst.get(&ctx, &unattributed_id).await.expect("get migrated");
    assert_eq!(text.content, format!("durable text for {}", "unattributed row"));
}

/// The dry-run plan must report the SAME copied/unattributed split the live
/// run produces — an operator sizing a migration must not be told a vector
/// will be copied that the live run will skip.
#[tokio::test]
async fn migrate_dry_run_reports_the_same_split_3085() {
    let dir = scratch("null-space-dry");
    let src_path = dir.path().join("src.db");
    let dst_path = dir.path().join("dst.db");
    let src = SqliteStore::open(src_path.to_str().unwrap()).expect("open src");
    let dst = SqliteStore::open(dst_path.to_str().unwrap()).expect("open dst");

    let ns = "ns3085dry";
    let ctx = CallerContext::for_admin("ai:3085-migrate");
    let id = uuid::Uuid::new_v4().to_string();
    src.store(&ctx, &mem(&id, ns, "unattributed only"))
        .await
        .expect("store");
    let fp = ai_memory::embeddings::embedding_space_fingerprint("test-space-3085");
    src.update_embedding(&ctx, &id, Some(&[1.0_f32, 0.0, 0.0, 0.0]), &fp)
        .await
        .expect("stamp");
    {
        let conn = rusqlite::Connection::open(&src_path).expect("raw open src");
        conn.execute(
            "UPDATE memories SET embedding_space = NULL WHERE id = ?1",
            rusqlite::params![id],
        )
        .expect("null the source stamp");
    }

    let report = ai_memory::migrate::migrate(&src, &dst, 100, Some(ns.to_string()), true).await;
    assert!(report.dry_run);
    assert_eq!(
        report.embeddings_copied, 0,
        "the dry-run plan must not promise to copy an unattributed vector"
    );
    assert_eq!(report.embeddings_unattributed, 1);
}

/// #3085 fail-closed half, sqlite lane: the `db::` embedding write funnels
/// REFUSE an empty space stamp for a real vector, so the corrupt state cannot
/// be re-minted by any future caller (this is what makes the migrate skip a
/// closure rather than a patch on one call site).
#[tokio::test]
async fn sqlite_write_funnels_refuse_an_empty_embedding_space_3085() {
    use ai_memory::storage as db;

    let dir = scratch("refuse-empty");
    let path = dir.path().join("guard.db");
    // Seed through the real store so every column invariant the schema
    // enforces is satisfied, then drive the `db::` funnels on a second
    // connection to the same file (WAL allows the concurrent reader/writer).
    let id = uuid::Uuid::new_v4().to_string();
    {
        let store = SqliteStore::open(path.to_str().unwrap()).expect("open store");
        store
            .store(
                &CallerContext::for_admin("ai:3085-guard"),
                &mem(&id, "ns3085guard", "guard row"),
            )
            .await
            .expect("seed row");
    }
    let mut conn = db::open(&path).expect("open raw");

    let vec = vec![1.0_f32, 0.0, 0.0, 0.0];
    assert!(
        db::set_embedding(&conn, &id, &vec, "").is_err(),
        "#3085: set_embedding must refuse an empty embedding_space"
    );
    assert!(
        db::set_embedding(&conn, &id, &vec, "  ").is_err(),
        "#3085: a whitespace-only stamp is the same unattributed state"
    );
    let entries = vec![(id.clone(), vec.clone())];
    assert!(
        db::set_embeddings_batch(&mut conn, &entries, "").is_err(),
        "#3085: set_embeddings_batch must refuse an empty embedding_space"
    );
    assert!(
        db::set_embeddings_batch_reembed(&mut conn, &entries, "").is_err(),
        "#3085: the reembed replace-writer must refuse it too"
    );
    assert!(
        db::get_embedding_with_space(&conn, &id)
            .expect("read back")
            .is_none(),
        "#3085: a refused write must leave the row unembedded, never partly stamped"
    );

    // A REAL fingerprint still writes.
    let fp = ai_memory::embeddings::embedding_space_fingerprint("test-space-3085");
    db::set_embedding(&conn, &id, &vec, &fp).expect("a real fingerprint must still write");
    let (got_vec, got_space) = db::get_embedding_with_space(&conn, &id)
        .expect("read back")
        .expect("stamped");
    assert_eq!(got_vec, vec);
    assert_eq!(got_space.as_deref(), Some(fp.as_str()));

    // The named validator is the SSOT both adapters route through.
    assert!(db::reject_unattributed_embedding_space("op", "").is_err());
    assert!(db::reject_unattributed_embedding_space("op", "\t \n").is_err());
    assert!(db::reject_unattributed_embedding_space("op", &fp).is_ok());
}
