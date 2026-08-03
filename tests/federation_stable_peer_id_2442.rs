// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2442 regression suite — the federation push-DLQ routing key MUST be
//! derived from peer IDENTITY, never from the `--quorum-peers` flag position.
//!
//! ## The defect these tests pin
//!
//! `FederationConfig::build` used to mint `PeerEndpoint { id: format!("peer-{i}") }`
//! from the `.enumerate()` index and discard the URL. That id is not a label:
//! it is the DURABLE routing key of `federation_push_dlq.peer_id` (enqueued in
//! `federation::sync`, resolved in `push_dlq::replay_once` by
//! `config.peers.iter().find(|p| p.id == row.peer_id)`) and of the `sync_state`
//! catch-up vector clock.
//!
//! Remove one peer and every higher index shifts DOWN by one. A row queued for
//! the old `peer-2` then resolves to a DIFFERENT HOST, is POSTed there, and is
//! stamped `replayed_at`. Both halves of the north star break at once:
//!
//! 1. an unintended peer receives content it was never authorised to hold, and
//! 2. the intended peer never receives the write and diverges permanently,
//!    with no counter and no error.
//!
//! ## R-203 — what fails at the parent commit `03bbd556`
//!
//! [`decommissioned_peer_dlq_row_is_never_delivered_to_a_survivor_2442`] is the
//! load-bearing test. It does NOT merely compare id strings — an id-only
//! assertion passes for the wrong reason, because it never enters the replay
//! path where the misrouting actually happens. It stands up three live mock
//! peers, queues one DLQ row for B and one for C, decommissions B, and drives a
//! real `replay_once` tick. At the parent, C receives B's payload (disclosure)
//! and never receives its own (silent loss). After the fix, C receives exactly
//! its own payload.
//!
//! The positive control is deliberate: a test that only asserts "nothing was
//! delivered" would keep passing if a later refactor made `replay_once` return
//! early for an unrelated reason. Asserting that the SURVIVING peer's own row
//! still lands proves the replay path really ran.

#![allow(clippy::doc_markdown)]

use std::time::Duration;

use ai_memory::federation::FederationConfig;
use ai_memory::federation::peer::is_legacy_positional_peer_id;

const PEER_A: &str = "https://peer-a.example:8443/base";
const PEER_B: &str = "https://peer-b.example:8443/base";
const PEER_C: &str = "https://peer-c.example:8443/base";

/// Build a `FederationConfig` from the real production entry point and return
/// the minted peer ids in flag order.
fn ids_for(urls: &[&str]) -> Vec<String> {
    let owned: Vec<String> = urls.iter().map(|u| (*u).to_string()).collect();
    let cfg = FederationConfig::build(
        1,
        &owned,
        Duration::from_millis(500),
        None,
        None,
        None,
        "ai:2442-test".to_string(),
        None,
    )
    .expect("build must succeed for distinct peer urls")
    .expect("federation is enabled when w>0 and peers are non-empty");
    cfg.peers.into_iter().map(|p| p.id).collect()
}

// ---------------------------------------------------------------------------
// Identity properties of the minted id
// ---------------------------------------------------------------------------

/// THE named #2442 scenario. Peer C is stable across B's decommissioning.
///
/// At the parent commit C is `peer-2` in the 3-peer list and `peer-1` in the
/// 2-peer list, so a DLQ row queued under `peer-2` would resolve to a
/// different host entirely.
#[test]
fn decommissioning_a_peer_does_not_rekey_survivors_2442() {
    let before = ids_for(&[PEER_A, PEER_B, PEER_C]);
    let after = ids_for(&[PEER_A, PEER_C]);

    assert_eq!(
        before[2], after[1],
        "peer C must keep its routing key when peer B is decommissioned; \
         positional ids gave C `peer-2` then `peer-1`, silently re-pointing \
         every queued row for the old `peer-2` at a different host (#2442)"
    );
    assert_eq!(before[0], after[0], "peer A must be unaffected");
    assert!(
        !after.contains(&before[1]),
        "the decommissioned peer's routing key must NOT be inherited by any \
         surviving peer — that inheritance is the misrouting defect itself"
    );
}

/// Reordering the flag list must not re-key anything.
#[test]
fn reordering_peers_does_not_rekey_2442() {
    let forward = ids_for(&[PEER_A, PEER_B, PEER_C]);
    let reversed = ids_for(&[PEER_C, PEER_B, PEER_A]);

    assert_eq!(forward[0], reversed[2], "A keeps its id under reordering");
    assert_eq!(forward[1], reversed[1], "B keeps its id under reordering");
    assert_eq!(forward[2], reversed[0], "C keeps its id under reordering");
}

/// Two distinct peers must never share a routing key — a shared key would
/// merge their DLQ rows and misroute in a different direction.
#[test]
fn distinct_peers_mint_distinct_ids_2442() {
    let ids = ids_for(&[PEER_A, PEER_B, PEER_C]);
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "peer ids must be pairwise distinct"
    );
}

/// The id must agree with the duplicate-URL check's normalisation: a trailing
/// slash and ASCII case are not identity. Both spellings are refused inside ONE
/// config by the `#341` duplicate guard, so the property is asserted across two
/// separate builds — which is also the real-world shape (an operator rewrites
/// the flag on upgrade and must not re-key the peer).
#[test]
fn trailing_slash_and_case_mint_the_same_id_2442() {
    let plain = ids_for(&[PEER_A]);
    let with_slash = ids_for(&[&format!("{PEER_A}/")]);
    let upper_host = ids_for(&["HTTPS://PEER-A.EXAMPLE:8443/BASE"]);

    assert_eq!(
        plain[0], with_slash[0],
        "a trailing slash must not change peer identity — the duplicate-URL \
         check already treats the two as the same peer, so minting two ids \
         would split one peer's DLQ rows across two routing keys"
    );
    assert_eq!(
        plain[0], upper_host[0],
        "ASCII case must not change peer identity, for the same reason"
    );
}

/// A duplicate that the `#341` check catches must still be a boot refusal —
/// the shared normalisation helper must not have weakened it.
#[test]
fn duplicate_urls_are_still_refused_at_build_2442() {
    let urls = vec![PEER_A.to_string(), format!("{PEER_A}/")];
    let Err(err) = FederationConfig::build(
        1,
        &urls,
        Duration::from_millis(500),
        None,
        None,
        None,
        "ai:2442-test".to_string(),
        None,
    ) else {
        panic!("duplicate peer URLs must be refused at build time");
    };
    assert!(
        err.to_string().contains("duplicate peer URL"),
        "expected the #341 duplicate refusal, got: {err}"
    );
}

/// The id stays short, fixed-width and label-safe. The `#304` concern that
/// reverted the `peer-{i}:{url}` form was that an UNBOUNDED URL landed in the
/// value; a fixed-width digest never does.
#[test]
fn peer_id_is_short_bounded_and_label_safe_2442() {
    let ids = ids_for(&[PEER_A, PEER_B, PEER_C]);
    let long_url = format!("https://{}.example/deeply/nested/path", "x".repeat(400));
    let long = ids_for(&[&long_url]);

    for id in ids.iter().chain(long.iter()) {
        assert_eq!(
            id.len(),
            39,
            "peer id must be FIXED width (`peer-h1` + 32 hex nibbles), got {id}"
        );
        assert!(
            id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "peer id must be plain ASCII so it is safe as a metric label and a \
             durable key, got {id}"
        );
    }
    assert_eq!(
        long[0].len(),
        ids[0].len(),
        "a 400-character URL must not produce a longer id than a short one — \
         that unbounded growth is exactly the #304 nit"
    );
}

/// A minted id must never be mistakable for a pre-#2442 positional key.
///
/// This is structural, not probabilistic: 32 hex nibbles are all-decimal-digits
/// often enough to matter, so the non-digit `h` in the prefix is what makes the
/// two keyspaces disjoint.
#[test]
fn minted_id_never_matches_the_legacy_positional_shape_2442() {
    for id in ids_for(&[PEER_A, PEER_B, PEER_C]) {
        assert!(
            id.starts_with("peer-h1"),
            "minted ids carry the versioned stable-identity prefix, got {id}"
        );
        assert!(
            !is_legacy_positional_peer_id(&id),
            "a minted id must never impersonate a legacy positional routing \
             key, got {id}"
        );
    }
    // ...and the detector must still recognise the real legacy shape.
    for legacy in ["peer-0", "peer-1", "peer-27", "peer-100"] {
        assert!(
            is_legacy_positional_peer_id(legacy),
            "{legacy} is a pre-#2442 positional routing key"
        );
    }
    for other in ["peer-", "peer-a", "peer-1a", "peer", "sender-0", ""] {
        assert!(
            !is_legacy_positional_peer_id(other),
            "{other} is not a positional routing key"
        );
    }
}

/// FROZEN WIRE FORMAT — deliberate tripwire, not a behavioural assertion.
///
/// Every other test here asserts a PROPERTY, precisely so the suite does not
/// mask a change to the derivation. This one test does the opposite on purpose,
/// and it is the only one that may pin a literal digest.
///
/// The reason: `normalize_peer_url` is shared with the duplicate-URL check, and
/// those two consumers have OPPOSING long-run requirements. The duplicate check
/// SHOULD normalise more over time (IDNA/punycode, default-port stripping,
/// percent-decoding) to close the `#341` double-count gap. The id must normalise
/// identically FOREVER, because every `federation_push_dlq.peer_id` and
/// `sync_state.peer_id` ever written depends on it. Without this test, the first
/// person to correctly harden the normalisation would ship a silent fleet-wide
/// identity rotation that orphans every persisted row, with no error and no
/// failing test.
///
/// If you are here because this test went red: you have changed the derivation.
/// That is a MIGRATION, not a refactor. Bump `PEER_ID_DERIVATION_DOMAIN` to
/// `v2` and `STABLE_PEER_ID_PREFIX` to `peer-h2` so both generations are
/// structurally distinguishable in a table that will contain them both, then
/// update this golden.
///
/// The expected value is computed independently of the Rust code by:
/// `printf 'ai-memory:peer-id:v1\0https://peer-a.example:8443/base' | sha256sum`
#[test]
fn frozen_wire_format_golden_2442() {
    let expected = "peer-h1".to_string()
        + &"99028c749b09846117900845984b8dfb4d4061bca764d097fa7b1019ebdc5e49"[..32];
    assert_eq!(
        ids_for(&[PEER_A])[0],
        expected,
        "the peer-id derivation is a FROZEN WIRE FORMAT — see this test's doc \
         comment before touching it (#2442)"
    );
}

// ---------------------------------------------------------------------------
// The load-bearing security tests — the DLQ replay path itself
// ---------------------------------------------------------------------------

#[cfg(feature = "sal")]
mod replay {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use ai_memory::federation::FederationConfig;
    use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink, replay_once};

    /// A mock peer that records the `probe` marker of every payload it is
    /// POSTed, so a test can assert WHICH row reached WHICH host — a bare hit
    /// counter cannot tell a correct delivery from a misdelivery.
    #[derive(Clone, Default)]
    struct PeerState {
        received_probes: Arc<Mutex<Vec<String>>>,
        hits: Arc<AtomicUsize>,
    }

    async fn push_handler(
        State(state): State<PeerState>,
        axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
    ) -> (StatusCode, axum::Json<serde_json::Value>) {
        state.hits.fetch_add(1, Ordering::Relaxed);
        let probe = body
            .get("probe")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<none>")
            .to_string();
        state.received_probes.lock().await.push(probe);
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
        )
    }

    async fn spawn_mock_peer(state: PeerState) -> String {
        let app = Router::new()
            .route("/api/v1/sync/push", post(push_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    fn fresh_db() -> (tempfile::TempDir, ai_memory::handlers::Db) {
        let tmp = tempfile::Builder::new()
            .prefix("v09-2442-dlq-")
            .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
            .expect("create local-runs tempdir");
        let db_path = tmp.path().join("dlq.db");
        let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
        let ttl = ai_memory::config::ResolvedTtl::default();
        let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path, ttl, true)));
        (tmp, handle)
    }

    fn config_for(urls: &[String], sink: Arc<dyn FederationDlqSink>) -> FederationConfig {
        let mut cfg = FederationConfig::build(
            1,
            urls,
            Duration::from_secs(2),
            None,
            None,
            None,
            "ai:2442-replay".to_string(),
            None,
        )
        .expect("build")
        .expect("federation enabled");
        cfg.dlq_sink = Some(sink);
        cfg
    }

    /// THE #2442 security test.
    ///
    /// Queue a DLQ row for peer B and one for peer C, decommission B, then run a
    /// real replay tick. The invariant is not "the ids differ" — it is that
    /// **no payload queued for B is ever delivered to C**.
    ///
    /// Observed at parent `03bbd556`: C's `received_probes` is `["for-B"]` —
    /// B's payload is POSTed to C and stamped replayed, while C's own row is
    /// skipped as unresolvable. Disclosure and silent loss, in one tick.
    #[tokio::test]
    async fn decommissioned_peer_dlq_row_is_never_delivered_to_a_survivor_2442() {
        let peer_a = PeerState::default();
        let peer_b = PeerState::default();
        let peer_c = PeerState::default();
        let url_a = spawn_mock_peer(peer_a.clone()).await;
        let url_b = spawn_mock_peer(peer_b.clone()).await;
        let url_c = spawn_mock_peer(peer_c.clone()).await;

        let (_tmp, db) = fresh_db();
        let sink: Arc<dyn FederationDlqSink> =
            Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());

        // Phase 1 — the pre-decommission mesh [A, B, C]. Capture the routing
        // keys the running daemon would have persisted.
        let three = vec![url_a.clone(), url_b.clone(), url_c.clone()];
        let cfg_three = config_for(&three, sink.clone());
        let id_b = cfg_three.peers[1].id.clone();
        let id_c = cfg_three.peers[2].id.clone();

        // Two undelivered writes land in the DLQ, one per peer, with
        // distinguishable payloads.
        sink.enqueue_push_failure(
            "mem-for-b",
            &id_b,
            &serde_json::json!({"probe": "for-B", "memories": []}),
            "deadline_exceeded",
        )
        .await
        .expect("enqueue B row");
        sink.enqueue_push_failure(
            "mem-for-c",
            &id_c,
            &serde_json::json!({"probe": "for-C", "memories": []}),
            "deadline_exceeded",
        )
        .await
        .expect("enqueue C row");

        // Phase 2 — the operator decommissions B. This is the ordinary action
        // that detonated the defect.
        let two = vec![url_a.clone(), url_c.clone()];
        let cfg_two = config_for(&two, sink.clone());

        replay_once(&cfg_two, sink.as_ref()).await;

        // --- The security assertion -------------------------------------
        let c_probes = peer_c.received_probes.lock().await.clone();
        assert!(
            !c_probes.iter().any(|p| p == "for-B"),
            "CROSS-TENANT DISCLOSURE: peer C received the payload queued for the \
             decommissioned peer B ({c_probes:?}). The DLQ routing key must be \
             derived from peer identity, not the --quorum-peers flag index (#2442)"
        );
        let a_probes = peer_a.received_probes.lock().await.clone();
        assert!(
            !a_probes.iter().any(|p| p == "for-B"),
            "peer A must not receive B's payload either, got {a_probes:?}"
        );
        assert_eq!(
            peer_b.hits.load(Ordering::Relaxed),
            0,
            "the decommissioned peer is not in the config and must receive nothing"
        );

        // --- The positive control ---------------------------------------
        // Without this, a refactor that made replay_once bail out early would
        // still satisfy every assertion above while proving nothing.
        assert_eq!(
            c_probes,
            vec!["for-C".to_string()],
            "peer C's OWN queued row must still be delivered exactly once — this \
             proves the replay path actually ran (positive control)"
        );

        // The surviving peer's row is retired; B's row is retained, not
        // silently marked delivered.
        let pending = sink.take_pending_dlq_rows(64).await.expect("take pending");
        assert!(
            pending.iter().all(|r| r.memory_id != "mem-for-c"),
            "C's row was delivered and must be cleared"
        );
        let b_row = pending
            .iter()
            .find(|r| r.memory_id == "mem-for-b")
            .expect("B's undelivered row must be RETAINED, never destroyed");
        assert!(
            b_row.last_error.contains("no longer in FederationConfig"),
            "B's row must be classified as an unresolvable peer, got {}",
            b_row.last_error
        );
    }

    /// Legacy-row disposition: a row written by a PRE-#2442 binary carries a
    /// positional key. It must be skipped and annotated — never auto-remapped
    /// onto `config.peers[N]`, which is the defect itself.
    ///
    /// Also pins the two properties the 3x3 vote made non-negotiable:
    /// the ORIGINAL enqueue reason survives the annotation (the row is the
    /// forensic record of an undelivered write), and the annotation is applied
    /// exactly once rather than re-appended on every tick.
    #[tokio::test]
    async fn legacy_positional_dlq_row_is_skipped_not_remapped_2442() {
        let peer_a = PeerState::default();
        let peer_b = PeerState::default();
        let url_a = spawn_mock_peer(peer_a.clone()).await;
        let url_b = spawn_mock_peer(peer_b.clone()).await;

        let (_tmp, db) = fresh_db();
        let sink: Arc<dyn FederationDlqSink> =
            Arc::new(SqliteDlqSink::new(db.clone()).await.unwrap());

        // A row exactly as a pre-#2442 binary would have written it.
        sink.enqueue_push_failure(
            "mem-legacy",
            "peer-1",
            &serde_json::json!({"probe": "legacy", "memories": []}),
            "http 503 Service Unavailable",
        )
        .await
        .expect("enqueue legacy row");

        let cfg = config_for(&[url_a.clone(), url_b.clone()], sink.clone());
        replay_once(&cfg, sink.as_ref()).await;

        assert_eq!(
            peer_a.hits.load(Ordering::Relaxed),
            0,
            "a legacy positional row must not be POSTed anywhere"
        );
        assert_eq!(
            peer_b.hits.load(Ordering::Relaxed),
            0,
            "`peer-1` must NOT be remapped onto config.peers[1] — that mapping is \
             only correct if the peer list never changed, and an upgrade is \
             exactly when it does (#2442)"
        );

        let pending = sink.take_pending_dlq_rows(64).await.expect("take");
        let row = pending
            .iter()
            .find(|r| r.memory_id == "mem-legacy")
            .expect("the legacy row must be RETAINED, never destroyed");
        assert!(
            row.last_error.contains("#2442 legacy positional peer_id"),
            "the row must be annotated so an operator can find it, got {}",
            row.last_error
        );
        assert!(
            row.last_error.contains("http 503 Service Unavailable"),
            "the ORIGINAL enqueue reason must survive — the DLQ row is the \
             forensic record of why the write was undelivered, and overwriting \
             it with a migration artifact destroys that record. Got: {}",
            row.last_error
        );

        // A second tick must not re-annotate: `last_error` would grow without
        // bound across the ~100 ticks before quarantine.
        let before = row.last_error.clone();
        replay_once(&cfg, sink.as_ref()).await;
        let pending = sink.take_pending_dlq_rows(64).await.expect("take again");
        let row = pending
            .iter()
            .find(|r| r.memory_id == "mem-legacy")
            .expect("still retained");
        assert_eq!(
            row.last_error, before,
            "the legacy annotation must be applied exactly once, not appended \
             on every replay tick"
        );
    }

    /// Postgres parity. The id derivation is backend-BLIND (a pure function of
    /// the URL, no SQL), and this fix adds no sink method and changes no
    /// schema — so the only thing worth proving on the postgres arm is that the
    /// shared `replay_once` skip behaves identically against the postgres sink.
    ///
    /// Uses a caller-supplied scratch database; leaves no residue beyond the
    /// rows it writes under a uuid-scoped memory id.
    #[cfg(feature = "sal-postgres")]
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL pointing at a live instance"]
    async fn pg_legacy_positional_dlq_row_is_skipped_not_remapped_2442() {
        use ai_memory::federation::push_dlq::PostgresDlqSink;
        use ai_memory::store::postgres::PostgresStore;

        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = match PostgresStore::connect(&url).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                eprintln!("test skipped: PostgresStore::connect failed: {e}");
                return;
            }
        };
        let sink: Arc<dyn FederationDlqSink> = Arc::new(PostgresDlqSink::new(store));

        let peer_a = PeerState::default();
        let peer_b = PeerState::default();
        let url_a = spawn_mock_peer(peer_a.clone()).await;
        let url_b = spawn_mock_peer(peer_b.clone()).await;

        let mem_id = format!("mem-2442-pg-{}", uuid::Uuid::new_v4());
        sink.enqueue_push_failure(
            &mem_id,
            "peer-1",
            &serde_json::json!({"probe": "legacy-pg", "memories": []}),
            "http 503 Service Unavailable",
        )
        .await
        .expect("pg enqueue legacy row");

        let cfg = config_for(&[url_a.clone(), url_b.clone()], sink.clone());
        replay_once(&cfg, sink.as_ref()).await;

        assert_eq!(
            peer_b.hits.load(Ordering::Relaxed),
            0,
            "postgres arm: `peer-1` must not be remapped onto config.peers[1]"
        );
        assert_eq!(
            peer_a.hits.load(Ordering::Relaxed),
            0,
            "postgres arm: a legacy row must not be POSTed anywhere"
        );

        let pending = sink.take_pending_dlq_rows(256).await.expect("pg take");
        let row = pending
            .iter()
            .find(|r| r.memory_id == mem_id)
            .expect("postgres arm: the legacy row must be retained");
        assert!(
            row.last_error.contains("#2442 legacy positional peer_id"),
            "postgres arm: annotated, got {}",
            row.last_error
        );
        assert!(
            row.last_error.contains("http 503 Service Unavailable"),
            "postgres arm: original enqueue reason preserved, got {}",
            row.last_error
        );
    }
}
