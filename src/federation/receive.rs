// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Post-partition catchup poller: spawn_catchup_loop, catchup_once,
//! urlencoding_encode.

#[cfg(feature = "sal")]
use std::sync::Arc;
use std::time::Duration;

use super::FederationConfig;
use super::pull_cursor::RefusalReason;

// ---------------------------------------------------------------------------
// #1558 batch 5 wave 2 — file-local catchup log helpers.
//
// The three catchup variants (`catchup_once_with_store`,
// `catchup_once_legacy`, `catchup_once_for_tests`) previously spelled
// each of these tracing templates inline, tripling every wording. The
// helpers below are the single spelling; message bytes are IDENTICAL
// to the prior inline macros (`tracing` level per helper unchanged).
// ---------------------------------------------------------------------------

// #3654 — each outcome helper ALSO records the outcome against the peer's
// pull freshness (`super::freshness`). A single failure stays at DEBUG here;
// the freshness registry escalates a sustained streak to a rate-limited WARN
// and logs the recovery, so the three variants cannot disagree about when a
// peer is "down".

fn log_catchup_http_skip(peer_id: &str, status: reqwest::StatusCode) {
    tracing::debug!("catchup: peer {peer_id} returned HTTP {status} — skipping this tick");
    super::freshness::record(
        peer_id,
        super::freshness::Direction::Pull,
        super::freshness::Observation::Failure(super::freshness::FailureClass::from_http_status(
            status.as_u16(),
        )),
    );
}

/// #3710 — takes the `reqwest::Error` itself and logs its CLASS: the
/// error's Display names the full request URL (`for url (…)`), and a peer
/// URL may carry a credential.
fn log_catchup_unreachable(peer_id: &str, e: &reqwest::Error) {
    let class = crate::url_display::TransportFailure::classify(e);
    tracing::debug!("catchup: peer {peer_id} unreachable: {class}");
    super::freshness::record(
        peer_id,
        super::freshness::Direction::Pull,
        super::freshness::Observation::Failure(super::freshness::FailureClass::Unreachable),
    );
}

fn log_catchup_unparseable_body(peer_id: &str, e: impl std::fmt::Display) {
    tracing::warn!("catchup: peer {peer_id} returned unparseable body: {e}");
    super::freshness::record(
        peer_id,
        super::freshness::Direction::Pull,
        super::freshness::Observation::Failure(super::freshness::FailureClass::BadResponse),
    );
}

/// #3654 — a 2xx whose envelope has no `memories` array. Pre-#3654 this was
/// a silent `continue`; it is a malformed response and now counts as one.
fn log_catchup_missing_memories(peer_id: &str) {
    tracing::debug!("catchup: peer {peer_id} returned a sync envelope with no memories array");
    super::freshness::record(
        peer_id,
        super::freshness::Direction::Pull,
        super::freshness::Observation::Failure(super::freshness::FailureClass::BadResponse),
    );
}

fn log_catchup_pull_ok(peer_id: &str, rows: usize) {
    // #3654 — structured fields so the success line is queryable without
    // parsing prose; the message bytes are unchanged (pinned by
    // `tests/federation_catchup_api_key.rs`).
    tracing::info!(
        peer_id = %peer_id,
        rows,
        "catchup: pull: {peer_id} ok ({rows} row(s) returned)"
    );
    super::freshness::record(
        peer_id,
        super::freshness::Direction::Pull,
        super::freshness::Observation::Success,
    );
}

/// #3654 — ONE classifier for the catch-up answer, shared by all three
/// pullers (the SAL `serve` loop, the sqlite-only `serve` loop and the
/// `catchup_once_for_tests` probe). A transport failure, a non-2xx, an
/// unparseable body and a 2xx envelope with no `memories` array each record
/// exactly one pull failure on the peer's freshness row; only a well-formed
/// envelope returns. The probe used to carry its own copy that read a
/// missing array as an EMPTY window and stamped a success, so the pin that
/// drives it could not see the arm the two production loops already had —
/// three copies of one classification is how that happens.
async fn fetch_catchup_envelope(
    peer_id: &str,
    req: reqwest::RequestBuilder,
) -> Option<(serde_json::Value, Vec<serde_json::Value>)> {
    let resp = match req.send().await {
        Ok(r) => accept_catchup_response(peer_id, r)?,
        Err(e) => {
            log_catchup_unreachable(peer_id, &e);
            return None;
        }
    };
    let body: serde_json::Value = match read_capped_sync_json(resp).await {
        Ok(v) => v,
        Err(e) => {
            log_catchup_unparseable_body(peer_id, e);
            return None;
        }
    };
    let memories = match body.get("memories").and_then(|v| v.as_array()) {
        Some(arr) => arr.clone(),
        None => {
            log_catchup_missing_memories(peer_id);
            return None;
        }
    };
    Some((body, memories))
}

/// #3654 — take a catch-up response: record the peer's clock offset from its
/// `Date` header (any response, success or not, carries the peer's clock),
/// then keep it only when it is a 2xx. The single spelling for the three
/// catch-up variants.
fn accept_catchup_response(peer_id: &str, resp: reqwest::Response) -> Option<reqwest::Response> {
    super::freshness::record_response_clock(peer_id, resp.headers());
    if resp.status().is_success() {
        Some(resp)
    } else {
        log_catchup_http_skip(peer_id, resp.status());
        None
    }
}

fn log_catchup_unparseable_memory(peer_id: &str, e: impl std::fmt::Display) {
    tracing::warn!("catchup: unparseable memory from peer {peer_id}: {e}");
}

fn log_catchup_ns_probe_failed(peer_id: &str, memory_id: &str, e: impl std::fmt::Display) {
    tracing::warn!(
        target: crate::handlers::federation_receive::ATTESTATION_TRACE_TARGET,
        memory_id = %memory_id,
        "catchup: namespace-scope pre-resolve failed for {memory_id} from peer {peer_id}: {e}; \
         refusing the write (#3195 fail-closed, halt watermark — transient probe error)"
    );
}

/// #3195 — apply a stored-namespace probe result.
/// `Ok` proceeds. `Err` is transient: skip the row AND hold the cursor below
/// it (#8743 `deferred`) so the next tick re-pulls.
fn catchup_take_ns_probe<T, E: std::fmt::Display>(
    result: Result<T, E>,
    peer_id: &str,
    memory_id: &str,
    tracker: &mut super::pull_cursor::PullCursorTracker,
    row_ts: &str,
) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            log_catchup_ns_probe_failed(peer_id, memory_id, e);
            tracker.deferred(row_ts, memory_id);
            None
        }
    }
}

/// #8788 / #8789 — record a delivered row the receiver refuses (logged,
/// counted, listed in the window outcome); the cursor may pass it.
fn catchup_refuse(
    tracker: &mut super::pull_cursor::PullCursorTracker,
    raw: &serde_json::Value,
    peer_id: &str,
    row_ts: &str,
    reason: RefusalReason,
) {
    let id = raw
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>");
    tracker.refused(peer_id, id, Some(row_ts), reason);
}

/// #8743 — the page size the peer applied to this window: its advertised
/// `limit`, never above the default the catch-up request relies on.
fn catchup_page_limit(body: &serde_json::Value) -> usize {
    body.get("limit")
        .and_then(serde_json::Value::as_u64)
        .and_then(|l| usize::try_from(l).ok())
        .map_or(super::pull_cursor::SYNC_SINCE_DEFAULT_LIMIT, |l| {
            l.min(super::pull_cursor::SYNC_SINCE_DEFAULT_LIMIT)
        })
}

/// #8743 — admit one delivered row by its raw `updated_at`. `Some(ts)` when
/// it may proceed to the apply gates; `None` when the tracker deferred or
/// rejected it (already counted and logged).
fn catchup_admit_row(
    tracker: &mut super::pull_cursor::PullCursorTracker,
    raw: &serde_json::Value,
    peer_id: &str,
) -> Option<String> {
    let ts = raw
        .get(crate::models::field_names::UPDATED_AT)
        .and_then(serde_json::Value::as_str);
    let id = raw
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>");
    match tracker.admit(ts, peer_id, id) {
        super::pull_cursor::RowAdmission::Admit => ts.map(str::to_string),
        super::pull_cursor::RowAdmission::FutureSkew
        | super::pull_cursor::RowAdmission::Rejected => None,
    }
}

/// #8743 — the one log line for a finished catch-up window: the canonical
/// `ok` line (and a freshness success) when complete, else a WARN with the
/// counts. The peer answered either way, so freshness records a success.
fn log_catchup_window(peer_id: &str, outcome: &super::pull_cursor::PullOutcome) {
    if outcome.is_complete() {
        log_catchup_pull_ok(peer_id, outcome.returned);
    } else {
        super::pull_cursor::log_pull_outcome("catchup", peer_id, outcome);
        super::freshness::record(
            peer_id,
            super::freshness::Direction::Pull,
            super::freshness::Observation::Success,
        );
    }
}

/// #3195 — sqlite stored-namespace probe for the catch-up Layer-1 gate.
/// `Ok(None)` means the read was elided OR there is provably no live row.
/// `Err` is UNRESOLVABLE: the caller MUST skip AND halt the watermark.
fn catchup_probe_existing_ns_sqlite(
    conn: &rusqlite::Connection,
    memory_id: &str,
    needs: bool,
) -> anyhow::Result<Option<String>> {
    if !needs {
        return Ok(None);
    }
    crate::db::namespace_by_id(conn, memory_id)
}

fn log_catchup_sync_state_observe_failed(peer_id: &str, e: impl std::fmt::Display) {
    tracing::warn!("catchup: sync_state_observe failed for {peer_id}: {e}");
}

/// #3655 — the durable contact stamp could not be written. The pull itself
/// succeeded; only the offline evidence of it is missing, so WARN and go on.
fn log_catchup_contact_stamp_failed(peer_id: &str, e: impl std::fmt::Display) {
    tracing::warn!("catchup: sync_peer_record_contact failed for {peer_id}: {e}");
}

/// Gate 1 / #2480 / #3195 — may this catchup-pulled memory be applied from `peer_id`?
///
/// Admin `CallerContext` bypasses SAL *visibility* so the peer snapshot can
/// round-trip; it must **not** bypass `AI_MEMORY_FED_PEER_ATTESTATION` namespace
/// scope. Accept-scope reuses the same operator-authored `allowed_namespaces`
/// as push (bidirectional decision: one list, both directions).
///
/// Shared choke with `/sync/push` `memories[]` so dispositions cannot fork.
/// Pre-#3195 this helper hardcoded `existing_namespace: None`, so the
/// Layer-1 stored-namespace probe the push lane runs fail-closed
/// (`federation_receive.rs` `#2447`) was structurally absent on PULL —
/// a `public/*`-scoped peer could relocate/clobber an out-of-scope
/// `secure/ops` row by serving its id under an in-scope claimed
/// namespace. Callers MUST pass the stored namespace when
/// [`inbound_write_needs_existing_namespace`] is true, and `None` only
/// when that predicate elides the read (zero-config / no declared
/// scope — ZERO extra reads).
///
/// An absent allowlist fails closed when namespace scope is required; only
/// the explicit Standard require-scope opt-out permits that case (#3582).
#[must_use]
fn catchup_memory_namespace_authorized(
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    require_push_ns_scope: bool,
    peer_id: &str,
    mem: &crate::models::Memory,
    existing_namespace: Option<&str>,
) -> bool {
    crate::federation::receive_auth::inbound_write_namespace_authorized(
        crate::federation::receive_auth::LANE_MEMORIES,
        &mem.id,
        &mem.namespace,
        existing_namespace,
        attest_cfg,
        Some(peer_id),
        require_push_ns_scope,
    )
}

/// #2290 — sign an outbound `/sync/since` catch-up GET so an ENROLLED peer
/// accepts the pull under the default `AI_MEMORY_FED_REQUIRE_SIG=1` posture.
///
/// The inbound `/sync/since` receiver (`verify_get_signature_or_reject`)
/// refuses an enrolled peer's request that omits `X-Memory-Sig` with
/// `401 x_memory_sig_missing`, but pre-#2290 NO outbound catch-up client
/// signed the GET — so the MOST-secure (fully enrolled, default-strict)
/// mesh got the WORST catch-up (structurally 401'd every tick). This mirrors
/// the `/sync/push` client signing EXACTLY (`X-Memory-Sig` + `X-Memory-Nonce`
/// over the shared canonical GET bytes). When no daemon signing key is on
/// disk the request stays unsigned (byte-identical to the pre-#2290 wire),
/// preserving the permissive / unenrolled `AI_MEMORY_FED_REQUIRE_SIG=0`
/// posture. `url` is parsed exactly as `reqwest` will send it, so the signed
/// path+query match the receiver's `OriginalUri` byte-for-byte.
fn sign_catchup_get(
    req: reqwest::RequestBuilder,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    url: &str,
) -> reqwest::RequestBuilder {
    match crate::federation::signing::sign_get_url(signing_key, url) {
        Some((sig, nonce)) => req
            .header(crate::federation::signing::SIGNATURE_HEADER, sig)
            .header(crate::federation::signing::NONCE_HEADER, nonce),
        None => req,
    }
}

/// #1928 (CWE-770) — hard ceiling on a federation catchup/sync response body.
/// reqwest's `.json()` buffers the ENTIRE body into RAM before parsing with no
/// length bound, so a hostile-but-enrolled peer answering `/sync/since` with a
/// multi-gigabyte body could drive the daemon to OOM (the federation client
/// sets only a wall-clock timeout, NOT a byte bound). We cap here exactly as
/// the LLM client does at `src/llm.rs`: a `Content-Length` pre-check rejects an
/// honest oversize body before a byte is read, and a streaming accumulator
/// aborts a lying peer mid-transfer.
const MAX_SYNC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// #1928 — buffer a federation catchup response, aborting as soon as the
/// accumulated body would exceed [`MAX_SYNC_RESPONSE_BYTES`], then parse JSON.
/// Replaces the unbounded `resp.json().await` at every `/sync/since` pull.
async fn read_capped_sync_json(resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
    read_capped_sync_json_inner(resp, MAX_SYNC_RESPONSE_BYTES).await
}

/// Cap-parameterised core of [`read_capped_sync_json`], split out so a unit
/// test can exercise the rejection against a tiny `cap` without streaming a
/// real 64 MiB body.
async fn read_capped_sync_json_inner(
    mut resp: reqwest::Response,
    cap: usize,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::anyhow;
    if let Some(len) = resp.content_length() {
        if len > cap as u64 {
            return Err(anyhow!(
                "federation sync response too large: Content-Length {len} exceeds cap of {cap} bytes"
            ));
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow!("reading federation sync response chunk: {e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(anyhow!(
                "federation sync response exceeded cap of {cap} bytes while streaming"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| anyhow!("parsing federation sync response: {e}"))
}

/// v0.6.0.1 (#320) — post-partition catchup poller.
///
/// Previously a node rejoining the mesh after SIGSTOP / network blip / restart
/// would only receive NEW writes that arrived AFTER resume; anything the
/// other peers wrote during the outage stayed on those peers. r14 scenario-14
/// observed this as node-3 seeing 2/20 writes post-SIGCONT.
///
/// This loop periodically calls `GET /api/v1/sync/since?peer=<local>` against
/// each configured peer, applying returned memories via `insert_if_newer`.
/// The `since` value is the receiver-side vector clock entry for that peer,
/// so we never re-pull already-applied rows. First catchup after a restart
/// runs with `since=None`, pulling a capped snapshot (limit=500).
///
/// Interval is operator-tunable via `--catchup-interval-secs`. 0 disables.
/// The loop is a best-effort background task: errors are logged but never
/// propagated. In the happy path a partitioned node converges within one
/// interval after resume.
///
/// This is deliberately NOT a substitute for the synchronous quorum-write
/// path — it's a safety net for the tail. Normal writes still fan out via
/// `broadcast_store_quorum`; catchup only fires for rows that DIDN'T land
/// during the original write deadline.
pub fn spawn_catchup_loop(
    config: FederationConfig,
    db: crate::handlers::Db,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    // Pre-existing no-sal build break (caught by the #625 port subagent
    // 2026-05-11): the historical bootstrap path forwarded through
    // `spawn_catchup_loop_with_store`, which is `#[cfg(feature = "sal")]`
    // only. With `sal` off the call site is unresolved. Inline the
    // tokio::spawn loop here so the sqlite-only build compiles. Under
    // `sal` we still route through the store-aware variant so
    // postgres-backed daemons keep the M3 routing fix.
    #[cfg(feature = "sal")]
    {
        spawn_catchup_loop_with_store(config, db, None, interval)
    }
    #[cfg(not(feature = "sal"))]
    {
        // #3654 — publish the cadence so a stalled worker is alertable; the
        // guard lives in the task, so the series dies with the loop.
        let cadence = super::freshness::publish_catchup_interval(interval);
        tokio::spawn(async move {
            let _cadence = cadence;
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                let _ = catchup_once(&config, &db).await;
                tokio::time::sleep(interval).await;
            }
        })
    }
}

/// v0.7.0 M3 — same as [`spawn_catchup_loop`] but accepts an optional
/// SAL-trait store handle. When `store` is `Some`, applied memories are
/// written through `store.apply_remote_memory` (which routes through the
/// active backend — postgres on `--store-url postgres://` deployments,
/// sqlite otherwise). When `None`, the legacy `db::insert_if_newer` path
/// over the shared rusqlite connection is preserved verbatim.
///
/// The split exists so the bootstrap can keep the historical
/// `spawn_catchup_loop` signature (used by tests) intact while
/// postgres-backed daemons get the routing fix.
#[cfg(feature = "sal")]
pub fn spawn_catchup_loop_with_store(
    config: FederationConfig,
    db: crate::handlers::Db,
    store: Option<Arc<dyn crate::store::MemoryStore>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    // #3654 — publish the cadence so a stalled worker is alertable; the
    // guard lives in the task, so the series dies with the loop.
    let cadence = super::freshness::publish_catchup_interval(interval);
    tokio::spawn(async move {
        let _cadence = cadence;
        // Small upfront delay so the first catchup doesn't fire before the
        // HTTP server has bound — avoids spurious "connection refused" on
        // node-1 during rolling start of a fresh cluster.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let _ = catchup_once_with_store(&config, &db, store.as_ref()).await;
            tokio::time::sleep(interval).await;
        }
    })
}

/// Legacy two-arg wrapper preserved so existing tests + non-SAL builds
/// keep dispatching through the sqlite path. Postgres-backed daemons
/// should invoke [`catchup_once_with_store`] directly via
/// [`spawn_catchup_loop_with_store`].
#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn catchup_once(
    config: &FederationConfig,
    db: &crate::handlers::Db,
) -> Vec<(String, super::pull_cursor::PullOutcome)> {
    #[cfg(feature = "sal")]
    {
        catchup_once_with_store(config, db, None).await
    }
    #[cfg(not(feature = "sal"))]
    {
        catchup_once_legacy(config, db).await
    }
}

/// #8743 — integration-test driver: one catch-up pass over every configured
/// peer through the production loop (SAL `None` / legacy sqlite path),
/// returning each peer's [`super::pull_cursor::PullOutcome`].
#[doc(hidden)]
pub async fn catchup_pass_for_tests(
    config: &FederationConfig,
    db: &crate::handlers::Db,
) -> Vec<(String, super::pull_cursor::PullOutcome)> {
    catchup_once(config, db).await
}

/// #8743 — integration-test driver: one catch-up pass through the SAL store
/// branch (`apply_remote_memory`, sqlite or postgres).
#[cfg(feature = "sal")]
#[doc(hidden)]
pub async fn catchup_pass_with_store_for_tests(
    config: &FederationConfig,
    db: &crate::handlers::Db,
    store: &Arc<dyn crate::store::MemoryStore>,
) -> Vec<(String, super::pull_cursor::PullOutcome)> {
    catchup_once_with_store(config, db, Some(store)).await
}

#[cfg(feature = "sal")]
pub(super) async fn catchup_once_with_store(
    config: &FederationConfig,
    db: &crate::handlers::Db,
    store: Option<&Arc<dyn crate::store::MemoryStore>>,
) -> Vec<(String, super::pull_cursor::PullOutcome)> {
    let local_id = config.sender_agent_id.clone();
    let mut outcomes = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        // Rebuild the peer's base URL from sync_push_url to get the
        // /api/v1/sync/since endpoint without recomputing peer config.
        let base = peer
            .sync_push_url
            .trim_end_matches(crate::handlers::routes::SYNC_PUSH)
            .to_string();

        // Load our local vector-clock entry for this peer so we only pull
        // the delta. First-time-ever runs with no prior clock pull a full
        // snapshot (capped below by ?limit=500 on the peer side).
        let since_opt: Option<String> = {
            let lock = db.lock().await;
            match crate::db::sync_state_load(&lock.0, &local_id) {
                Ok(clock) => clock.entries.get(&peer.id).cloned(),
                Err(_) => None,
            }
        };

        let url = sync_since_url(&base, &local_id, since_opt.as_deref());

        // v0.7.0 #239 — attach `x-peer-id` to the outbound /sync/since
        // GET so the peer's per-peer namespace allowlist can scope
        // the returned rows. Without this, a v0.7.0 peer that's
        // configured an allowlist will default-deny our catchup and
        // hand back an empty page.
        //
        // #935 (v0.7.0 Track D, 2026-05-20): attach `x-api-key` when
        // the daemon was configured with `[api] api_key` so peers
        // running with api-key auth accept the catchup GET. The
        // pre-#935 catchup loop omitted this header even though
        // `sync_cycle_once` and `broadcast_store_quorum` both forward
        // it, so alice's catchup-pull from bob 401'd on every tick
        // while the broadcast path worked. The header is attached
        // ONLY when `config.api_key` is `Some` so mTLS-only
        // deployments keep the v0.6.x backwards-compatible header
        // set (the inbound `/sync/since` auth bypass for mTLS
        // listeners absorbs the missing header). Also attach
        // `x-agent-id` for parity with `sync_cycle_once` so the
        // receive-side identity gate (#238/#239) sees a consistent
        // wire identity on every sync path.
        let mut req = config
            .client
            .get(&url)
            .header(crate::HEADER_AGENT_ID, local_id.as_str())
            .header(
                crate::federation::peer_attestation::PEER_ID_HEADER,
                local_id.as_str(),
            );
        if let Some(ref key) = config.api_key {
            req = req.header(crate::HEADER_API_KEY, key);
        }
        // #2290 — sign the catch-up GET so enrolled peers accept it under
        // the default AI_MEMORY_FED_REQUIRE_SIG=1 posture (see fn docs).
        req = sign_catchup_get(req, config.signing_key.as_deref(), &url);
        // #3654 — one classifier for all three pullers; every malformed answer
        // records exactly one pull failure before this `continue`.
        let Some((body, memories)) = fetch_catchup_envelope(&peer.id, req).await else {
            continue;
        };
        // #2441 (CB-11) — the peer applies its per-peer namespace allowlist +
        // `scope=private` visibility filter IN MEMORY, AFTER the SQL `LIMIT`, so a
        // window composed entirely of out-of-scope rows returns `count:0` behind
        // an HTTP 200. `next_since` is the peer's honest examined-watermark;
        // consuming it lets an all-filtered (or empty) window still advance the
        // cursor instead of re-requesting the identical window forever — the
        // #2441 stall, which #2663 fixed on `sync_cycle_once` but never on this
        // `serve` puller. `PullCursorTracker::resolve` honours it only when it
        // is behind this node's clock and below every un-applied row (#8743).
        let next_since: Option<String> = body
            .get("next_since")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // #3655 — durable CONTACT stamp, apart from the data watermark below:
        // an empty window is still an answered pull. Carries this loop's
        // cadence so `doctor` applies the same reachability window (#3654).
        {
            let lock = db.lock().await;
            let cadence = super::freshness::catchup_interval().map(|d| d.as_secs());
            if let Err(e) =
                crate::db::sync_peer_record_contact(&lock.0, &local_id, &peer.id, cadence)
            {
                log_catchup_contact_stamp_failed(&peer.id, e);
            }
        }
        // #2441 — NO `if memories.is_empty() { continue }` early-out: an empty
        // window must still fall through to consume `next_since` below so an
        // all-out-of-scope window converges. The apply loops no-op on empty.

        // #1687 / #2714 / #3233 / #8743 — every delivered row is recorded in
        // the tracker, which resolves the cursor from this node's clock and the
        // rows durably applied, held strictly below any delivered row that was
        // not applied (see `pull_cursor`).
        let mut tracker = super::pull_cursor::PullCursorTracker::new(
            since_opt.clone(),
            catchup_page_limit(&body),
        );
        // #2480 — load peer-attestation once per peer tick (not per row).
        let attest_cfg = crate::federation::peer_attestation::PeerAttestationConfig::from_env();
        let require_push_ns_scope =
            crate::federation::receive_auth::require_push_namespace_scope_enabled();
        // #3195 — elide the stored-namespace probe unless Layer 1 is
        // armed for this peer (same predicate the push lane uses).
        // Zero-config stays at ZERO extra reads.
        let ns_scope_needs_existing =
            crate::federation::receive_auth::inbound_write_needs_existing_namespace(
                Some(peer.id.as_str()),
                &attest_cfg,
            );

        // v0.7.0 M3 — when a SAL store handle is supplied (postgres-
        // backed daemons) we dispatch each row through
        // `store.apply_remote_memory`, which routes the write to the
        // active backend instead of always landing in the local sqlite
        // file. Default-None preserves the legacy behavior (sqlite via
        // `db::insert_if_newer`) for daemons that don't yet have a SAL
        // handle plumbed through (e.g. v0.6.x configurations).
        if let Some(store) = store {
            // #910 — federation catchup is operator-level (peer sync);
            // it MUST round-trip every row regardless of metadata.scope
            // so the receiving daemon has the full snapshot. Use the
            // admin builder to bypass the SAL visibility filter.
            let ctx = crate::store::CallerContext::for_admin(
                crate::identity::sentinels::FEDERATION_CATCHUP,
            );
            for raw in &memories {
                // #8743 — judge the row's timestamp against this node's clock
                // before anything else; a deferred or rejected row is counted.
                let Some(row_ts) = catchup_admit_row(&mut tracker, raw, &peer.id) else {
                    continue;
                };
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        catchup_refuse(
                            &mut tracker,
                            raw,
                            &peer.id,
                            &row_ts,
                            RefusalReason::UnparseableBody,
                        );
                        continue;
                    }
                };
                if let Err(e) = crate::validate::validate_memory(&mem) {
                    super::pull_cursor::log_invalid_memory(&peer.id, &mem.id, &e);
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::InvalidMemory,
                    );
                    continue;
                }
                // #3195 — SAL stored-namespace probe. Admin ctx is already
                // in scope (visibility bypass, NOT a namespace-scope
                // bypass); `namespace_by_id` is the SCALAR projection so
                // an unopenable at-rest envelope cannot brick the row
                // (#2488 decrypt trap). Probe error is TRANSIENT → skip
                // AND halt so the row is re-pulled. A scope REFUSAL
                // below is PERMANENT → skip without halt.
                let existing_ns = if ns_scope_needs_existing {
                    match catchup_take_ns_probe(
                        store.namespace_by_id(&ctx, &mem.id).await,
                        &peer.id,
                        &mem.id,
                        &mut tracker,
                        &row_ts,
                    ) {
                        Some(ns) => ns,
                        None => continue,
                    }
                } else {
                    None
                };
                if !catchup_memory_namespace_authorized(
                    &attest_cfg,
                    require_push_ns_scope,
                    peer.id.as_str(),
                    &mem,
                    existing_ns.as_deref(),
                ) {
                    // #8788 (supersedes the #3233 halt) — a delivered row we
                    // refuse to apply is recorded (WARN + counter + outcome)
                    // and settled, so one refused row never halts every later
                    // row. Distinct from #2441 (empty window: never delivered).
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::NamespaceScope,
                    );
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write CONTENT attestation, the pull
                // sibling of the `/sync/push` gate. Verify a presented
                // `metadata.write_signature` against the author's enrolled key:
                // forged → refuse (skip), valid → agent_attested, absent →
                // claimed.
                // #8788 — a *delivered* attest refusal is recorded and settled
                // (WARN + counter + outcome), never a silent skip and never a
                // halt of every later row.
                crate::handlers::federation_receive::sanitize_inbound_pull_memory(&mut mem);
                let author_bound_key = if let Some(author) =
                    crate::identity::attest::presented_attestation_author_needing_bound_key(
                        &mem, None,
                    ) {
                    crate::handlers::federation_receive::historical_author_key_or_warn(
                        store
                            .agent_pubkey_for_attestation_at(author, &mem.created_at)
                            .await,
                        author,
                    )
                } else {
                    None
                };
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(
                    &mut mem,
                    author_bound_key.as_ref(),
                ) {
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::Attestation,
                    );
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark ONLY for rows that
                // durably applied, halting at the first failure, so sync_state
                // never moves past an un-persisted row (which would silently
                // drop it from every future delta). Idempotent upserts make
                // re-fetching post-failure rows next cycle harmless.
                // #3631 — pre-apply inbox probe; see `applied_wake`.
                let inbox_wake_pre =
                    crate::federation::applied_wake::probe_store(&**store, &ctx, &mem).await;
                match store.apply_remote_memory(&ctx, &mem).await {
                    Ok(applied_id) => {
                        tracker.applied(&row_ts, &mem.id);
                        // #3631 — wake the local recipient of a delivered
                        // inbox message (the catch-up half of the hop).
                        crate::federation::applied_wake::fire_store(
                            &**store,
                            &ctx,
                            inbox_wake_pre,
                            &mem,
                            &applied_id,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracker.deferred(&row_ts, &mem.id);
                        tracing::warn!(
                            "catchup: apply_remote_memory failed for peer {}: {e}",
                            peer.id
                        );
                    }
                }
            }
            // #2714 + #2441 — advance to the peer's examined-watermark on a clean
            // window; hold at the last durable success when an apply halted.
            if let Some(ts) = tracker.resolve(next_since.as_deref(), memories.len(), &peer.id) {
                let lock = db.lock().await;
                if let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts) {
                    log_catchup_sync_state_observe_failed(&peer.id, e);
                }
            }
        } else {
            let lock = db.lock().await;
            for raw in &memories {
                // #8743 — judge the row's timestamp against this node's clock
                // before anything else; a deferred or rejected row is counted.
                let Some(row_ts) = catchup_admit_row(&mut tracker, raw, &peer.id) else {
                    continue;
                };
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        catchup_refuse(
                            &mut tracker,
                            raw,
                            &peer.id,
                            &row_ts,
                            RefusalReason::UnparseableBody,
                        );
                        continue;
                    }
                };
                if let Err(e) = crate::validate::validate_memory(&mem) {
                    super::pull_cursor::log_invalid_memory(&peer.id, &mem.id, &e);
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::InvalidMemory,
                    );
                    continue;
                }
                // #3195 — sqlite stored-namespace probe (legacy
                // `db::insert_if_newer` branch). Same halt-vs-skip
                // disposition as the SAL twin.
                let existing_ns = match catchup_take_ns_probe(
                    catchup_probe_existing_ns_sqlite(&lock.0, &mem.id, ns_scope_needs_existing),
                    &peer.id,
                    &mem.id,
                    &mut tracker,
                    &row_ts,
                ) {
                    Some(ns) => ns,
                    None => continue,
                };
                if !catchup_memory_namespace_authorized(
                    &attest_cfg,
                    require_push_ns_scope,
                    peer.id.as_str(),
                    &mem,
                    existing_ns.as_deref(),
                ) {
                    // #8788 — delivered ns refusal is recorded (see SAL).
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::NamespaceScope,
                    );
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write content attestation (see the
                // SAL branch). #8788 — a delivered attest refusal is recorded.
                crate::handlers::federation_receive::sanitize_inbound_pull_memory(&mut mem);
                let author_bound_key =
                    crate::identity::attest::presented_attestation_author_needing_bound_key(
                        &mem, None,
                    )
                    .and_then(|author| {
                        crate::handlers::federation_receive::historical_author_key_or_warn(
                            crate::db::agent_pubkey_for_attestation_at(
                                &lock.0,
                                author,
                                &mem.created_at,
                            ),
                            author,
                        )
                    });
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(
                    &mut mem,
                    author_bound_key.as_ref(),
                ) {
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::Attestation,
                    );
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark only on a successful
                // insert and halt at the first failure (see the SAL branch).
                // #3631 — pre-apply inbox probe; see `applied_wake`.
                let inbox_wake_pre = crate::federation::applied_wake::probe_sqlite(&lock.0, &mem);
                match crate::db::insert_if_newer(&lock.0, &mem) {
                    Ok(applied_id) => {
                        tracker.applied(&row_ts, &mem.id);
                        // #3631 — wake the local recipient of a delivered
                        // inbox message (the catch-up half of the hop).
                        crate::federation::applied_wake::fire_sqlite(
                            &lock.0,
                            inbox_wake_pre,
                            &mem,
                            &applied_id,
                        );
                    }
                    Err(_) => tracker.deferred(&row_ts, &mem.id),
                }
            }
            // #2714 + #2441 — halt-gated, validated cursor advance.
            if let Some(ts) = tracker.resolve(next_since.as_deref(), memories.len(), &peer.id)
                && let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts)
            {
                log_catchup_sync_state_observe_failed(&peer.id, e);
            }
        }

        // #935 / #8743 — the canonical "pull: <peer-id> ok" line (pinned by
        // `tests/federation_catchup_api_key.rs`) is logged only for a window
        // that left no delivered row behind; any other window WARNs its counts.
        let outcome = tracker.outcome();
        log_catchup_window(&peer.id, &outcome);
        if outcome.applied > 0 {
            tracing::info!(
                "catchup: applied {} memories from peer {} (since={})",
                outcome.applied,
                peer.id,
                since_opt.as_deref().unwrap_or("<full-snapshot>"),
            );
        }
        outcomes.push((peer.id.clone(), outcome));
    }
    outcomes
}

/// v0.7.0 M3 — non-SAL fallback. Default sqlite-only path is preserved
/// verbatim for builds without `--features sal`. The signature parallels
/// the SAL variant minus the `store` parameter so callers compiled
/// against the legacy posture continue to dispatch through the local
/// rusqlite connection.
#[cfg(not(feature = "sal"))]
async fn catchup_once_legacy(
    config: &FederationConfig,
    db: &crate::handlers::Db,
) -> Vec<(String, super::pull_cursor::PullOutcome)> {
    let local_id = config.sender_agent_id.clone();
    let mut outcomes = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        let base = peer
            .sync_push_url
            .trim_end_matches(crate::handlers::routes::SYNC_PUSH)
            .to_string();

        let since_opt: Option<String> = {
            let lock = db.lock().await;
            match crate::db::sync_state_load(&lock.0, &local_id) {
                Ok(clock) => clock.entries.get(&peer.id).cloned(),
                Err(_) => None,
            }
        };

        let url = sync_since_url(&base, &local_id, since_opt.as_deref());

        // v0.7.0 #239 — attach `x-peer-id` so the peer's per-peer
        // namespace allowlist can scope the returned rows (sqlite
        // catchup path, parity with the SAL-routed loop above).
        //
        // #935 (v0.7.0 Track D, 2026-05-20): attach `x-api-key` +
        // `x-agent-id` for parity with the SAL branch and
        // `sync_cycle_once`. See the matching block in
        // `catchup_once_with_store` for the full RCA.
        let mut req = config
            .client
            .get(&url)
            .header(crate::HEADER_AGENT_ID, local_id.as_str())
            .header(
                crate::federation::peer_attestation::PEER_ID_HEADER,
                local_id.as_str(),
            );
        if let Some(ref key) = config.api_key {
            req = req.header(crate::HEADER_API_KEY, key);
        }
        // #2290 — sign the catch-up GET so enrolled peers accept it under
        // the default AI_MEMORY_FED_REQUIRE_SIG=1 posture (see fn docs).
        req = sign_catchup_get(req, config.signing_key.as_deref(), &url);
        // #3654 — one classifier for all three pullers; every malformed answer
        // records exactly one pull failure before this `continue`.
        let Some((body, memories)) = fetch_catchup_envelope(&peer.id, req).await else {
            continue;
        };

        // #2441 (CB-11) — consume the peer's examined-watermark so an
        // all-out-of-scope (count:0) window still advances (see the SAL branch).
        let next_since: Option<String> = body
            .get("next_since")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // #3655 — durable CONTACT stamp, apart from the data watermark (see
        // the SAL twin above): an empty window is still an answered pull.
        {
            let lock = db.lock().await;
            let cadence = super::freshness::catchup_interval().map(|d| d.as_secs());
            if let Err(e) =
                crate::db::sync_peer_record_contact(&lock.0, &local_id, &peer.id, cadence)
            {
                log_catchup_contact_stamp_failed(&peer.id, e);
            }
        }
        // #2441 — no `if memories.is_empty() { continue }`: an empty window still
        // consumes `next_since`. The apply loop no-ops on empty.

        // #1687 / #2714 / #3233 / #8743 — every delivered row is recorded in
        // the tracker, which resolves the cursor from this node's clock and the
        // rows durably applied, held strictly below any delivered row that was
        // not applied (see `pull_cursor`).
        let mut tracker = super::pull_cursor::PullCursorTracker::new(
            since_opt.clone(),
            catchup_page_limit(&body),
        );
        // #2480 — load peer-attestation once per peer tick (not per row).
        let attest_cfg = crate::federation::peer_attestation::PeerAttestationConfig::from_env();
        let require_push_ns_scope =
            crate::federation::receive_auth::require_push_namespace_scope_enabled();
        let ns_scope_needs_existing =
            crate::federation::receive_auth::inbound_write_needs_existing_namespace(
                Some(peer.id.as_str()),
                &attest_cfg,
            );
        {
            let lock = db.lock().await;
            for raw in &memories {
                // #8743 — judge the row's timestamp against this node's clock
                // before anything else; a deferred or rejected row is counted.
                let Some(row_ts) = catchup_admit_row(&mut tracker, raw, &peer.id) else {
                    continue;
                };
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        catchup_refuse(
                            &mut tracker,
                            raw,
                            &peer.id,
                            &row_ts,
                            RefusalReason::UnparseableBody,
                        );
                        continue;
                    }
                };
                if let Err(e) = crate::validate::validate_memory(&mem) {
                    super::pull_cursor::log_invalid_memory(&peer.id, &mem.id, &e);
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::InvalidMemory,
                    );
                    continue;
                }
                // #3195 — no-sal catchup_once_legacy twin of the sqlite
                // probe in `catchup_once_with_store`. Without this, the
                // default (no-sal) CI clippy leg ships an ungated PULL.
                let existing_ns = match catchup_take_ns_probe(
                    catchup_probe_existing_ns_sqlite(&lock.0, &mem.id, ns_scope_needs_existing),
                    &peer.id,
                    &mem.id,
                    &mut tracker,
                    &row_ts,
                ) {
                    Some(ns) => ns,
                    None => continue,
                };
                if !catchup_memory_namespace_authorized(
                    &attest_cfg,
                    require_push_ns_scope,
                    peer.id.as_str(),
                    &mem,
                    existing_ns.as_deref(),
                ) {
                    // #8788 — delivered ns refusal is recorded (see SAL).
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::NamespaceScope,
                    );
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write content attestation (see the
                // SAL branch). #8788 — a delivered attest refusal is recorded.
                crate::handlers::federation_receive::sanitize_inbound_pull_memory(&mut mem);
                let author_bound_key =
                    crate::identity::attest::presented_attestation_author_needing_bound_key(
                        &mem, None,
                    )
                    .and_then(|author| {
                        crate::handlers::federation_receive::historical_author_key_or_warn(
                            crate::db::agent_pubkey_for_attestation_at(
                                &lock.0,
                                author,
                                &mem.created_at,
                            ),
                            author,
                        )
                    });
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(
                    &mut mem,
                    author_bound_key.as_ref(),
                ) {
                    catchup_refuse(
                        &mut tracker,
                        raw,
                        &peer.id,
                        &row_ts,
                        RefusalReason::Attestation,
                    );
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark only on a successful
                // insert and halt at the first failure (see the SAL branch).
                // #3631 — pre-apply inbox probe; see `applied_wake`.
                let inbox_wake_pre = crate::federation::applied_wake::probe_sqlite(&lock.0, &mem);
                match crate::db::insert_if_newer(&lock.0, &mem) {
                    Ok(applied_id) => {
                        tracker.applied(&row_ts, &mem.id);
                        // #3631 — wake the local recipient of a delivered
                        // inbox message (the catch-up half of the hop).
                        crate::federation::applied_wake::fire_sqlite(
                            &lock.0,
                            inbox_wake_pre,
                            &mem,
                            &applied_id,
                        );
                    }
                    Err(_) => tracker.deferred(&row_ts, &mem.id),
                }
            }
            // #2714 + #2441 — halt-gated, validated cursor advance.
            if let Some(ts) = tracker.resolve(next_since.as_deref(), memories.len(), &peer.id)
                && let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts)
            {
                log_catchup_sync_state_observe_failed(&peer.id, e);
            }
        }

        // #935 / #8743 — the canonical "pull: <peer-id> ok" line (pinned by
        // `tests/federation_catchup_api_key.rs`) is logged only for a window
        // that left no delivered row behind; any other window WARNs its counts.
        let outcome = tracker.outcome();
        log_catchup_window(&peer.id, &outcome);
        if outcome.applied > 0 {
            tracing::info!(
                "catchup: applied {} memories from peer {} (since={})",
                outcome.applied,
                peer.id,
                since_opt.as_deref().unwrap_or("<full-snapshot>"),
            );
        }
        outcomes.push((peer.id.clone(), outcome));
    }
    outcomes
}

/// v0.7.0 Track D #935 — minimal test-driver helper for the
/// catchup GET path. Used by `tests/federation_catchup_api_key.rs`
/// to assert the outbound request headers without bringing the
/// full sqlite `Db` / `MemoryStore` plumbing into the test scope.
///
/// The helper fires ONE GET against the configured peer's
/// `/api/v1/sync/since` endpoint using the exact same header set
/// `catchup_once_with_store` does (including the #935 `x-api-key`
/// forward when `config.api_key.is_some()`), then logs the
/// canonical `catchup: pull: <peer-id> ok` line on success so
/// regression coverage can pin the wire-level wording.
///
/// This is a no-side-effect probe: no memories are applied, no
/// sync-state is advanced. Production code MUST continue to call
/// `spawn_catchup_loop_with_store` (SAL) or `spawn_catchup_loop`
/// (sqlite-only) — this helper is `#[cfg(any(test, ...))]`-gated
/// for the integration test only.
#[doc(hidden)]
pub async fn catchup_once_for_tests(config: &FederationConfig) {
    let local_id = config.sender_agent_id.clone();
    for peer in &config.peers {
        let base = peer
            .sync_push_url
            .trim_end_matches(crate::handlers::routes::SYNC_PUSH)
            .to_string();
        let url = sync_since_url(&base, &local_id, None);

        let mut req = config
            .client
            .get(&url)
            .header(crate::HEADER_AGENT_ID, local_id.as_str())
            .header(
                crate::federation::peer_attestation::PEER_ID_HEADER,
                local_id.as_str(),
            );
        if let Some(ref key) = config.api_key {
            req = req.header(crate::HEADER_API_KEY, key);
        }
        // #2290 — sign the catch-up GET so enrolled peers accept it under
        // the default AI_MEMORY_FED_REQUIRE_SIG=1 posture (see fn docs).
        req = sign_catchup_get(req, config.signing_key.as_deref(), &url);
        // #3654 — one classifier for all three pullers; every malformed answer
        // records exactly one pull failure before this `continue`.
        let Some((_body, memories)) = fetch_catchup_envelope(&peer.id, req).await else {
            continue;
        };
        log_catchup_pull_ok(&peer.id, memories.len());
    }
}

/// Build the outbound `/api/v1/sync/since` catch-up URL for `base`
/// (the peer base URL with the push suffix already trimmed): optional
/// `since` vector-clock cursor + the local peer id. ONE builder so the
/// three catch-up paths (store-backed, legacy, test harness) cannot
/// drift on the query shape (#1558 batch 4).
fn sync_since_url(base: &str, local_id: &str, since: Option<&str>) -> String {
    match since {
        Some(s) => format!(
            "{base}{}?since={}&peer={local_id}",
            crate::handlers::routes::SYNC_SINCE,
            urlencoding_encode(s)
        ),
        None => format!(
            "{base}{}?peer={local_id}",
            crate::handlers::routes::SYNC_SINCE
        ),
    }
}

// Minimal RFC 3986 percent-encoder for the `since` timestamp. Only covers
// what RFC 3339 + our namespace/id charsets can produce. We intentionally
// avoid pulling in a url-encoding crate for a 12-character string.
pub(super) fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 6);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod issue_2480_tests {
    //! #2480 — catchup PULL must refuse out-of-scope namespaces under enrolled
    //! allowlist (admin visibility bypass is not a namespace-scope bypass).
    use super::{catchup_memory_namespace_authorized, catchup_take_ns_probe};
    use crate::federation::peer_attestation::{PeerAttestationConfig, PeerScope};
    use crate::models::Memory;

    fn mem(ns: &str) -> Memory {
        Memory {
            id: "m-2480".to_string(),
            namespace: ns.to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            created_at: "2026-08-03T00:00:00Z".to_string(),
            ..Memory::default()
        }
    }

    #[test]
    fn no_allowlist_catchup_requires_explicit_scope_opt_out_3582() {
        let cfg = PeerAttestationConfig::default();
        assert!(
            !catchup_memory_namespace_authorized(&cfg, true, "peer-1", &mem("secure/ops"), None),
            "required scope must refuse catchup without an allowlist"
        );
        assert!(
            catchup_memory_namespace_authorized(&cfg, false, "peer-1", &mem("secure/ops"), None),
            "explicit Standard rollout opt-out retains legacy catchup"
        );
    }

    #[test]
    fn enrolled_scoped_peer_refuses_out_of_scope_pull_2480() {
        let mut cfg = PeerAttestationConfig::default();
        cfg.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec![],
                allowed_namespaces: vec!["public/*".to_string()],
            },
        );
        assert!(
            catchup_memory_namespace_authorized(&cfg, true, "peer-1", &mem("public/ok"), None),
            "in-scope pull accepted"
        );
        assert!(
            !catchup_memory_namespace_authorized(&cfg, true, "peer-1", &mem("secure/ops"), None),
            "#2480: out-of-scope catchup row must be refused"
        );
    }

    #[test]
    fn stored_namespace_out_of_scope_refuses_claimed_in_scope_3195() {
        // #3195 — the merge-clobber variant: claimed namespace is in
        // scope (`public/x`) but the LIVE row is `secure/ops`. The
        // push lane refuses this; catch-up must too.
        let mut cfg = PeerAttestationConfig::default();
        cfg.peers.insert(
            "peer-1".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec![],
                allowed_namespaces: vec!["public/*".to_string()],
            },
        );
        let claimed_in_scope = mem("public/x");
        assert!(
            catchup_memory_namespace_authorized(&cfg, true, "peer-1", &claimed_in_scope, None),
            "claimed-only (no stored row) in-scope still accepted"
        );
        assert!(
            !catchup_memory_namespace_authorized(
                &cfg,
                true,
                "peer-1",
                &claimed_in_scope,
                Some("secure/ops")
            ),
            "#3195: stored out-of-scope namespace must refuse even when claimed is in-scope"
        );
    }

    #[test]
    fn probe_error_halts_watermark_3195() {
        // Probe Err is transient → skip AND hold so the row is re-pulled.
        // A scope refusal is a different path (recorded, #8788); this pins the
        // helper both SAL and sqlite catch-up branches now share.
        const ROW_TS: &str = "2026-06-15T00:00:01Z";
        let mut tracker = super::super::pull_cursor::PullCursorTracker::new(None, 500);
        let probe_err: Result<Option<String>, &str> = Err("io timeout");
        assert!(
            catchup_take_ns_probe(probe_err, "peer-1", "mem-1", &mut tracker, ROW_TS).is_none(),
            "probe Err must skip the row"
        );
        assert_eq!(
            tracker.outcome().deferred,
            1,
            "probe Err must hold the cursor"
        );
        let probe_ok: Result<Option<String>, &str> = Ok(Some("secure/ops".to_string()));
        assert_eq!(
            catchup_take_ns_probe(probe_ok, "peer-1", "mem-1", &mut tracker, ROW_TS),
            Some(Some("secure/ops".to_string()))
        );
        assert_eq!(
            tracker.outcome().deferred,
            1,
            "Ok probe must not hold the cursor"
        );
        assert_eq!(tracker.resolve(Some(ROW_TS), 1, "peer-1"), None);
    }
}

#[cfg(test)]
mod issue_1687_2714_2441_tests {
    //! #1687 / #2714 (CB-10) row-loss guard + #2441 / #2715 (CB-11) stall fix
    //! + #3233 skip-halts, now resolved by the #8743 `PullCursorTracker`
    //! against a pinned clock.
    use super::super::pull_cursor::PullCursorTracker;

    const NOW: &str = "2026-06-15T00:01:00+00:00";
    const T1: &str = "2026-06-15T00:00:01Z";
    const T2: &str = "2026-06-15T00:00:02Z";
    const T3: &str = "2026-06-15T00:00:03Z";
    const PAGE: usize = 500;
    const PEER: &str = "peer-x";

    fn tracker(current: Option<&str>) -> PullCursorTracker {
        let now = chrono::DateTime::parse_from_rfc3339(NOW)
            .expect("NOW parses")
            .with_timezone(&chrono::Utc);
        PullCursorTracker::new_at(current.map(str::to_string), PAGE, now)
    }

    #[test]
    fn advances_to_newest_applied_row_1687() {
        let mut t = tracker(None);
        t.applied(T1, "t1-1687");
        t.applied(T2, "t2-1687");
        assert_eq!(t.resolve(None, 2, PEER).as_deref(), Some(T2));
    }

    #[test]
    fn does_not_advance_past_a_failed_row_1687() {
        let mut t = tracker(None);
        t.applied(T1, "t1-1687");
        t.deferred(T2, "t2-1687");
        t.applied(T3, "t3-1687");
        assert_eq!(
            t.resolve(None, 3, PEER).as_deref(),
            Some(T1),
            "the cursor must stop below the un-applied row"
        );
    }

    #[test]
    fn catchup_does_not_leap_skipped_ns_3233() {
        let mut t = tracker(Some(T1));
        t.deferred(T2, "t2-1687");
        assert_eq!(
            t.resolve(Some(T3), 1, PEER),
            None,
            "an all-skipped delivered window holds the cursor so the row re-pulls"
        );
    }

    #[test]
    fn halted_never_advances_to_next_since_2714() {
        let mut t = tracker(None);
        t.applied(T1, "t1-1687");
        t.deferred(T2, "t2-1687");
        assert_eq!(t.resolve(Some(T3), 2, PEER).as_deref(), Some(T1));
    }

    #[test]
    fn clean_window_consumes_next_since_2441() {
        let mut t = tracker(Some(T1));
        t.applied(T2, "t2-1687");
        assert_eq!(t.resolve(Some(T3), 1, PEER).as_deref(), Some(T3));
    }

    #[test]
    fn empty_filtered_window_still_advances_via_next_since_2441() {
        let mut t = tracker(Some(T1));
        assert_eq!(t.resolve(Some(T3), 0, PEER).as_deref(), Some(T3));
    }

    #[test]
    fn poisoned_far_future_next_since_falls_back_to_applied_2718() {
        let mut t = tracker(Some(T1));
        t.applied(T2, "t2-1687");
        assert_eq!(
            t.resolve(Some("2999-01-01T00:00:00Z"), 1, PEER).as_deref(),
            Some(T2)
        );
    }

    #[test]
    fn legacy_peer_without_next_since_uses_applied_2441() {
        let mut t = tracker(Some(T1));
        t.applied(T2, "t2-1687");
        assert_eq!(t.resolve(None, 1, PEER).as_deref(), Some(T2));
        let mut empty = tracker(Some(T1));
        assert_eq!(empty.resolve(None, 0, PEER), None);
    }
}

#[cfg(test)]
mod issue_1928_tests {
    //! #1928 (CWE-770) — ADVERSARIAL: a hostile-but-enrolled federation peer
    //! answers a `/sync/since` pull with a body far larger than any legitimate
    //! delta, driving the daemon toward OOM. The catchup path used the
    //! unbounded `resp.json().await`; the cap now rejects it.
    use super::{MAX_SYNC_RESPONSE_BYTES, read_capped_sync_json_inner};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// v1.0.0 #3140 — a bounded client for the hostile-peer probes.
    ///
    /// `reqwest::Client::new()` has NO request timeout. A HOSTILE peer that
    /// accepts the connection and then stalls would park the test forever —
    /// the very posture these tests exist to prove we survive.
    fn bounded_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("bounded test client builds")
    }

    /// Spawn a one-shot TCP "peer" that returns `body` under a crafted
    /// `Content-Length: content_length_hdr` and returns its address.
    async fn hostile_peer(content_length_hdr: u64, body: &'static [u8]) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut scratch = [0u8; 2048];
                let _ = sock.read(&mut scratch).await; // drain request line/headers
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length_hdr}\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn oversize_sync_body_rejected_before_buffering() {
        // Advertise 100 MiB — the exact multi-gigabyte-class OOM vector.
        let advertised = 100 * 1024 * 1024u64;
        let addr = hostile_peer(advertised, b"{").await;
        let client = bounded_test_client();
        let resp = client
            .get(format!("http://{addr}/sync/since"))
            .send()
            .await
            .expect("connect to hostile peer");
        // Cap far below the advertised length → rejected on the Content-Length
        // pre-check, before a single body byte is buffered.
        let out = read_capped_sync_json_inner(resp, 4096).await;
        assert!(
            out.is_err(),
            "oversize federation sync body (Content-Length {advertised}) must be rejected (#1928)"
        );
    }

    #[tokio::test]
    async fn legitimate_small_sync_body_still_parses() {
        let body = br#"{"memories":[]}"#;
        let addr = hostile_peer(body.len() as u64, body).await;
        let client = bounded_test_client();
        let resp = client
            .get(format!("http://{addr}/sync/since"))
            .send()
            .await
            .expect("connect to peer");
        let out = read_capped_sync_json_inner(resp, MAX_SYNC_RESPONSE_BYTES)
            .await
            .expect("a legitimate under-cap body parses");
        assert!(out.get("memories").is_some());
    }
}

/// #3521 — catch-up helper pins (per-module coverage floor).
///
/// Three small helpers on the catch-up path had no direct test: the
/// stored-namespace probe's "we DO need the row" arm, the transient
/// `sync_state_observe` WARN, and the `/sync/since` URL builder. The URL
/// builder is the one that matters most for integrity: the three catch-up
/// paths share it precisely so a cursor can never be dropped on one path
/// and kept on another (a dropped `since` silently re-pulls, or worse,
/// re-anchors, the whole peer corpus).
#[cfg(test)]
mod cov_catchup_helpers_3521 {
    use super::{
        catchup_probe_existing_ns_sqlite, log_catchup_sync_state_observe_failed, sync_since_url,
    };

    /// With `needs = true` the probe actually READS: a row the substrate
    /// does not hold is `Ok(None)` (no live row), never an `Err` — an
    /// `Err` here would halt the watermark, so the distinction is load
    /// bearing.
    #[test]
    fn ns_probe_reads_when_needed_and_reports_no_live_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("catchup-probe-3521.db");
        let conn = crate::db::open(&db).expect("db::open");
        let got = catchup_probe_existing_ns_sqlite(&conn, "no-such-memory", true)
            .expect("a missing row is not a probe failure");
        assert!(got.is_none(), "no live row must be Ok(None), got {got:?}");
    }

    /// The transient-observe WARN must not panic on any peer id / error
    /// pair — it runs inside the catch-up loop's hot path.
    #[test]
    fn sync_state_observe_warning_is_infallible() {
        log_catchup_sync_state_observe_failed("peer-3521", "connection reset");
    }

    /// The `since` cursor is carried EXACTLY once, percent-encoded, and
    /// the local peer id is always present. Dropping either would turn a
    /// bounded delta pull into a full-corpus re-pull.
    #[test]
    fn sync_since_url_carries_the_cursor_and_the_local_peer_id() {
        let with_cursor =
            sync_since_url("https://peer.test", "local-1", Some("2026-01-01T00:00:00Z"));
        assert!(
            with_cursor.contains("since=2026-01-01T00%3A00%3A00Z"),
            "the cursor must be percent-encoded; got {with_cursor}"
        );
        assert!(
            with_cursor.contains("peer=local-1"),
            "the local peer id must be present; got {with_cursor}"
        );

        let without_cursor = sync_since_url("https://peer.test", "local-1", None);
        assert!(
            !without_cursor.contains("since="),
            "no cursor must mean no since= parameter; got {without_cursor}"
        );
        assert!(
            without_cursor.contains("peer=local-1"),
            "the local peer id must be present without a cursor; got {without_cursor}"
        );
    }
}
