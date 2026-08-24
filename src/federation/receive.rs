// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Post-partition catchup poller: spawn_catchup_loop, catchup_once,
//! urlencoding_encode.

#[cfg(feature = "sal")]
use std::sync::Arc;
use std::time::Duration;

use super::FederationConfig;

// ---------------------------------------------------------------------------
// #1558 batch 5 wave 2 — file-local catchup log helpers.
//
// The three catchup variants (`catchup_once_with_store`,
// `catchup_once_legacy`, `catchup_once_for_tests`) previously spelled
// each of these tracing templates inline, tripling every wording. The
// helpers below are the single spelling; message bytes are IDENTICAL
// to the prior inline macros (`tracing` level per helper unchanged).
// ---------------------------------------------------------------------------

fn log_catchup_http_skip(peer_id: &str, status: impl std::fmt::Display) {
    tracing::debug!("catchup: peer {peer_id} returned HTTP {status} — skipping this tick");
}

fn log_catchup_unreachable(peer_id: &str, e: impl std::fmt::Display) {
    tracing::debug!("catchup: peer {peer_id} unreachable: {e}");
}

fn log_catchup_unparseable_body(peer_id: &str, e: impl std::fmt::Display) {
    tracing::warn!("catchup: peer {peer_id} returned unparseable body: {e}");
}

fn log_catchup_pull_ok(peer_id: &str, rows: usize) {
    tracing::info!("catchup: pull: {peer_id} ok ({rows} row(s) returned)");
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
/// `Ok` proceeds. `Err` is transient: skip the row AND halt the watermark
/// so the next tick re-pulls. Scope *refusal* is a different path
/// (`continue` without setting `catchup_halted`).
fn catchup_take_ns_probe<T, E: std::fmt::Display>(
    result: Result<T, E>,
    peer_id: &str,
    memory_id: &str,
    catchup_halted: &mut bool,
) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            log_catchup_ns_probe_failed(peer_id, memory_id, e);
            *catchup_halted = true;
            None
        }
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
/// Zero-config (`!has_allowlist`) short-circuits inside the helper to true.
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

/// #1687 — advance the per-peer catchup watermark for a row that just applied
/// successfully, but never while `halted` (set once any earlier row in the
/// batch failed to apply). Guarantees `sync_state` is never moved past an
/// un-persisted row — which would silently drop it from every future delta.
#[inline]
fn advance_catchup_watermark(latest_ts: &mut Option<String>, halted: bool, row_ts: &str) {
    if !halted && latest_ts.as_deref().is_none_or(|cur| row_ts > cur) {
        *latest_ts = Some(row_ts.to_string());
    }
}

/// #2714 (CB-10) + #2441/#2715 (CB-11) — resolve the per-peer catch-up cursor to
/// advance `sync_state` to after applying one `/sync/since` window on the `serve`
/// catch-up puller, unifying two data-integrity invariants that MUST hold
/// together (consuming `next_since` to fix the stall is exactly what would
/// otherwise open the row-loss surface, so the two fixes are one decision):
///
///  - **Never advance past an un-applied row (#1687/#2714).** When a
///    transient/non-durable apply halted this window (`halted == true`), advance
///    ONLY to `latest_ts` — the last DURABLE success (`advance_catchup_watermark`
///    froze it at the pre-failure high-water). A `SQLITE_BUSY` (and siblings) on
///    one row therefore leaves the cursor behind that row so it is re-pulled next
///    cycle; the cursor is NEVER leapt forward to the peer's examined-watermark
///    past a row this replica has not persisted.
///
///  - **Converge an all-out-of-scope window (#2441).** When the window applied
///    cleanly (`halted == false`), consume the peer's honest examined-watermark
///    `next_since` so a window the peer filtered to `count:0` (its per-peer
///    allowlist + `scope=private` filter run IN MEMORY, AFTER the SQL `LIMIT`)
///    still advances instead of re-requesting the identical window forever. The
///    peer-controlled candidate is VALIDATED first — the same #2718
///    cursor-poisoning guard `sync_cycle_once` uses (RFC3339, not far-future,
///    strictly ahead of the current cursor) — because it is written into the
///    monotonic (refuse-to-regress) `sync_state` upsert; on rejection, or for a
///    legacy peer that publishes no `next_since`, fall back to `latest_ts`.
fn resolve_catchup_advance(
    halted: bool,
    latest_ts: Option<&str>,
    next_since: Option<&str>,
    current_since: Option<&str>,
    peer_id: &str,
) -> Option<String> {
    if halted {
        // #2714 — hold at the last durable success; do NOT honour next_since.
        return latest_ts.map(str::to_string);
    }
    match next_since {
        Some(candidate) => {
            match crate::daemon_runtime::validate_pull_cursor(candidate, current_since) {
                Ok(()) => Some(candidate.to_string()),
                Err(reason) => {
                    tracing::warn!(
                        target: crate::federation::SCOPE_TRACE_TARGET,
                        peer = %peer_id,
                        candidate = %candidate,
                        reason,
                        "catchup: refusing peer-advertised next_since cursor; leaving \
                         sync_state watermark at the last durable success (#2718 cursor-poisoning guard)"
                    );
                    latest_ts.map(str::to_string)
                }
            }
        }
        None => latest_ts.map(str::to_string),
    }
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
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                catchup_once(&config, &db).await;
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
    tokio::spawn(async move {
        // Small upfront delay so the first catchup doesn't fire before the
        // HTTP server has bound — avoids spurious "connection refused" on
        // node-1 during rolling start of a fresh cluster.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            catchup_once_with_store(&config, &db, store.as_ref()).await;
            tokio::time::sleep(interval).await;
        }
    })
}

/// Legacy two-arg wrapper preserved so existing tests + non-SAL builds
/// keep dispatching through the sqlite path. Postgres-backed daemons
/// should invoke [`catchup_once_with_store`] directly via
/// [`spawn_catchup_loop_with_store`].
#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn catchup_once(config: &FederationConfig, db: &crate::handlers::Db) {
    #[cfg(feature = "sal")]
    {
        catchup_once_with_store(config, db, None).await;
    }
    #[cfg(not(feature = "sal"))]
    {
        catchup_once_legacy(config, db).await;
    }
}

#[cfg(feature = "sal")]
pub(super) async fn catchup_once_with_store(
    config: &FederationConfig,
    db: &crate::handlers::Db,
    store: Option<&Arc<dyn crate::store::MemoryStore>>,
) {
    let local_id = config.sender_agent_id.clone();
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
        let resp = match req.send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log_catchup_http_skip(&peer.id, r.status());
                continue;
            }
            Err(e) => {
                log_catchup_unreachable(&peer.id, e);
                continue;
            }
        };

        let body: serde_json::Value = match read_capped_sync_json(resp).await {
            Ok(v) => v,
            Err(e) => {
                log_catchup_unparseable_body(&peer.id, e);
                continue;
            }
        };

        let memories = match body.get("memories").and_then(|v| v.as_array()) {
            Some(arr) => arr.clone(),
            None => continue,
        };
        // #2441 (CB-11) — the peer applies its per-peer namespace allowlist +
        // `scope=private` visibility filter IN MEMORY, AFTER the SQL `LIMIT`, so a
        // window composed entirely of out-of-scope rows returns `count:0` behind
        // an HTTP 200. `next_since` is the peer's honest examined-watermark;
        // consuming it lets an all-filtered (or empty) window still advance the
        // cursor instead of re-requesting the identical window forever — the
        // #2441 stall, which #2663 fixed on `sync_cycle_once` but never on this
        // `serve` puller. See `resolve_catchup_advance` for the halt-gated,
        // validated advance (the legacy `latest_ts` remains the fallback).
        let next_since: Option<String> = body
            .get("next_since")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // #935 (v0.7.0 Track D, 2026-05-20): emit an info-level
        // success line on every accepted pull so operators tailing
        // `docker logs alice | grep catchup` can confirm the
        // catchup loop is healthy without enabling `RUST_LOG=trace`.
        // The "pull: <peer-id> ok" tag pins the canonical wording
        // pinned by the regression test in
        // `tests/federation_catchup_api_key.rs`.
        log_catchup_pull_ok(&peer.id, memories.len());
        // #2441 — NO `if memories.is_empty() { continue }` early-out: an empty
        // window must still fall through to consume `next_since` below so an
        // all-out-of-scope window converges. The apply loops no-op on empty.

        let mut applied = 0usize;
        let mut latest_ts: Option<String> = None;
        // #1687 — once an apply fails, stop advancing the catchup watermark so
        // sync_state never moves past an un-persisted row.
        let mut catchup_halted = false;
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
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        continue;
                    }
                };
                if crate::validate::validate_memory(&mem).is_err() {
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
                        &mut catchup_halted,
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
                    // #3233 — a delivered row we refused to apply must halt
                    // the watermark. Consuming `next_since` would leap past
                    // it; an allowlist/key-enrollment change can make a later
                    // re-pull succeed. Distinct from #2441 (empty window:
                    // the peer never delivered the row).
                    catchup_halted = true;
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write CONTENT attestation, the pull
                // sibling of the `/sync/push` gate. Verify a presented
                // `metadata.write_signature` against the author's enrolled key:
                // forged → refuse (skip), valid → agent_attested, absent →
                // claimed.
                // #3233 — skip of a *delivered* attest refusal also halts:
                // missing-author-key is recoverable after enrollment, and
                // leaping `next_since` is silent inbound data loss.
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(&mut mem) {
                    catchup_halted = true;
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark ONLY for rows that
                // durably applied, halting at the first failure, so sync_state
                // never moves past an un-persisted row (which would silently
                // drop it from every future delta). Idempotent upserts make
                // re-fetching post-failure rows next cycle harmless.
                match store.apply_remote_memory(&ctx, &mem).await {
                    Ok(_) => {
                        applied += 1;
                        advance_catchup_watermark(&mut latest_ts, catchup_halted, &mem.updated_at);
                    }
                    Err(e) => {
                        catchup_halted = true;
                        tracing::warn!(
                            "catchup: apply_remote_memory failed for peer {}: {e}",
                            peer.id
                        );
                    }
                }
            }
            // #2714 + #2441 — advance to the peer's examined-watermark on a clean
            // window; hold at the last durable success when an apply halted.
            if let Some(ts) = resolve_catchup_advance(
                catchup_halted,
                latest_ts.as_deref(),
                next_since.as_deref(),
                since_opt.as_deref(),
                &peer.id,
            ) {
                let lock = db.lock().await;
                if let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts) {
                    log_catchup_sync_state_observe_failed(&peer.id, e);
                }
            }
        } else {
            let lock = db.lock().await;
            for raw in &memories {
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        continue;
                    }
                };
                if crate::validate::validate_memory(&mem).is_err() {
                    continue;
                }
                // #3195 — sqlite stored-namespace probe (legacy
                // `db::insert_if_newer` branch). Same halt-vs-skip
                // disposition as the SAL twin.
                let existing_ns = match catchup_take_ns_probe(
                    catchup_probe_existing_ns_sqlite(&lock.0, &mem.id, ns_scope_needs_existing),
                    &peer.id,
                    &mem.id,
                    &mut catchup_halted,
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
                    // #3233 — delivered ns-skip halts the watermark (see SAL).
                    catchup_halted = true;
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write content attestation (see the
                // SAL branch). #3233 — delivered attest-skip also halts.
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(&mut mem) {
                    catchup_halted = true;
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark only on a successful
                // insert and halt at the first failure (see the SAL branch).
                match crate::db::insert_if_newer(&lock.0, &mem) {
                    Ok(_) => {
                        applied += 1;
                        advance_catchup_watermark(&mut latest_ts, catchup_halted, &mem.updated_at);
                    }
                    Err(_) => catchup_halted = true,
                }
            }
            // #2714 + #2441 — halt-gated, validated cursor advance.
            if let Some(ts) = resolve_catchup_advance(
                catchup_halted,
                latest_ts.as_deref(),
                next_since.as_deref(),
                since_opt.as_deref(),
                &peer.id,
            ) && let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts)
            {
                log_catchup_sync_state_observe_failed(&peer.id, e);
            }
        }

        if applied > 0 {
            tracing::info!(
                "catchup: applied {applied} memories from peer {} (since={})",
                peer.id,
                since_opt.as_deref().unwrap_or("<full-snapshot>"),
            );
        }
    }
}

/// v0.7.0 M3 — non-SAL fallback. Default sqlite-only path is preserved
/// verbatim for builds without `--features sal`. The signature parallels
/// the SAL variant minus the `store` parameter so callers compiled
/// against the legacy posture continue to dispatch through the local
/// rusqlite connection.
#[cfg(not(feature = "sal"))]
async fn catchup_once_legacy(config: &FederationConfig, db: &crate::handlers::Db) {
    let local_id = config.sender_agent_id.clone();
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
        let resp = match req.send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log_catchup_http_skip(&peer.id, r.status());
                continue;
            }
            Err(e) => {
                log_catchup_unreachable(&peer.id, e);
                continue;
            }
        };

        let body: serde_json::Value = match read_capped_sync_json(resp).await {
            Ok(v) => v,
            Err(e) => {
                log_catchup_unparseable_body(&peer.id, e);
                continue;
            }
        };

        let memories = match body.get("memories").and_then(|v| v.as_array()) {
            Some(arr) => arr.clone(),
            None => continue,
        };

        // #2441 (CB-11) — consume the peer's examined-watermark so an
        // all-out-of-scope (count:0) window still advances (see the SAL branch).
        let next_since: Option<String> = body
            .get("next_since")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // #935 — emit the canonical "pull: <peer> ok" success line
        // pinned by `tests/federation_catchup_api_key.rs`.
        log_catchup_pull_ok(&peer.id, memories.len());
        // #2441 — no `if memories.is_empty() { continue }`: an empty window still
        // consumes `next_since`. The apply loop no-ops on empty.

        let mut applied = 0usize;
        let mut latest_ts: Option<String> = None;
        // #1687 — once an apply fails, stop advancing the catchup watermark so
        // sync_state never moves past an un-persisted row.
        let mut catchup_halted = false;
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
                let mut mem: crate::models::Memory = match serde_json::from_value(raw.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        log_catchup_unparseable_memory(&peer.id, e);
                        continue;
                    }
                };
                if crate::validate::validate_memory(&mem).is_err() {
                    continue;
                }
                // #3195 — no-sal catchup_once_legacy twin of the sqlite
                // probe in `catchup_once_with_store`. Without this, the
                // default (no-sal) CI clippy leg ships an ungated PULL.
                let existing_ns = match catchup_take_ns_probe(
                    catchup_probe_existing_ns_sqlite(&lock.0, &mem.id, ns_scope_needs_existing),
                    &peer.id,
                    &mem.id,
                    &mut catchup_halted,
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
                    // #3233 — delivered ns-skip halts the watermark (see SAL).
                    catchup_halted = true;
                    continue;
                }
                // #2715 (CB-11 / B-4) — per-write content attestation (see the
                // SAL branch). #3233 — delivered attest-skip also halts.
                if !crate::handlers::federation_receive::attest_inbound_pull_memory(&mut mem) {
                    catchup_halted = true;
                    continue;
                }
                // #1687/#2714 — advance the catchup watermark only on a successful
                // insert and halt at the first failure (see the SAL branch).
                match crate::db::insert_if_newer(&lock.0, &mem) {
                    Ok(_) => {
                        applied += 1;
                        advance_catchup_watermark(&mut latest_ts, catchup_halted, &mem.updated_at);
                    }
                    Err(_) => catchup_halted = true,
                }
            }
            // #2714 + #2441 — halt-gated, validated cursor advance.
            if let Some(ts) = resolve_catchup_advance(
                catchup_halted,
                latest_ts.as_deref(),
                next_since.as_deref(),
                since_opt.as_deref(),
                &peer.id,
            ) && let Err(e) = crate::db::sync_state_observe(&lock.0, &local_id, &peer.id, &ts)
            {
                log_catchup_sync_state_observe_failed(&peer.id, e);
            }
        }

        if applied > 0 {
            tracing::info!(
                "catchup: applied {applied} memories from peer {} (since={})",
                peer.id,
                since_opt.as_deref().unwrap_or("<full-snapshot>"),
            );
        }
    }
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
        let resp = match req.send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log_catchup_http_skip(&peer.id, r.status());
                continue;
            }
            Err(e) => {
                log_catchup_unreachable(&peer.id, e);
                continue;
            }
        };

        let body: serde_json::Value = match read_capped_sync_json(resp).await {
            Ok(v) => v,
            Err(e) => {
                log_catchup_unparseable_body(&peer.id, e);
                continue;
            }
        };
        let memories = body
            .get("memories")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
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
    fn zero_config_accepts_any_namespace_2480() {
        let cfg = PeerAttestationConfig::default();
        assert!(
            catchup_memory_namespace_authorized(&cfg, true, "peer-1", &mem("secure/ops"), None),
            "zero-config must stay byte-identical faith pull"
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
        // Probe Err is transient → skip AND halt so the row is re-pulled.
        // A scope refusal is a different path (no halt); this pins the
        // helper both SAL and sqlite catch-up branches now share.
        let mut halted = false;
        let probe_err: Result<Option<String>, &str> = Err("io timeout");
        assert!(
            catchup_take_ns_probe(probe_err, "peer-1", "mem-1", &mut halted).is_none(),
            "probe Err must skip the row"
        );
        assert!(halted, "probe Err must halt the watermark");
        halted = false;
        let probe_ok: Result<Option<String>, &str> = Ok(Some("secure/ops".to_string()));
        assert_eq!(
            catchup_take_ns_probe(probe_ok, "peer-1", "mem-1", &mut halted),
            Some(Some("secure/ops".to_string()))
        );
        assert!(!halted, "Ok probe must not halt");
    }
}

#[cfg(test)]
mod issue_1687_tests {
    use super::advance_catchup_watermark;

    #[test]
    fn advances_on_success_monotonically_when_not_halted() {
        let mut ts = None;
        advance_catchup_watermark(&mut ts, false, "2026-06-15T00:00:01Z");
        assert_eq!(ts.as_deref(), Some("2026-06-15T00:00:01Z"));
        advance_catchup_watermark(&mut ts, false, "2026-06-15T00:00:02Z");
        assert_eq!(ts.as_deref(), Some("2026-06-15T00:00:02Z"));
        // an older ts never moves the watermark backward
        advance_catchup_watermark(&mut ts, false, "2026-06-15T00:00:01Z");
        assert_eq!(ts.as_deref(), Some("2026-06-15T00:00:02Z"));
    }

    #[test]
    fn does_not_advance_past_a_failed_row_once_halted() {
        // row1 ok -> t1; row2 FAILED (caller sets halted); row3 ok but later ts
        // -> watermark MUST stay at t1 so row2 is re-fetched next delta (#1687).
        let mut ts = None;
        advance_catchup_watermark(&mut ts, false, "t1");
        advance_catchup_watermark(&mut ts, true, "t3");
        assert_eq!(
            ts.as_deref(),
            Some("t1"),
            "watermark must stop at the last pre-failure success"
        );
    }
}

#[cfg(test)]
mod issue_2714_2441_tests {
    //! #2714 (CB-10) row-loss guard + #2441/#2715 (CB-11) stall fix for the
    //! `serve` catch-up puller's cursor-advance resolution. Uses fixed-instant
    //! RFC3339 timestamps so `validate_pull_cursor` (RFC3339 + not-far-future +
    //! strictly-ahead) accepts them deterministically.
    use super::resolve_catchup_advance;

    const T1: &str = "2026-06-15T00:00:01Z";
    const T2: &str = "2026-06-15T00:00:02Z";
    const T3: &str = "2026-06-15T00:00:03Z";

    #[test]
    #[test]
    fn catchup_does_not_leap_skipped_ns() {
        // #3233 — a receiver-side skip of a *delivered* row (ns-scope or
        // attest) is the same cursor disposition as an apply halt: do NOT
        // consume the peer's examined-watermark `next_since` (T3) past the
        // skipped high-water. Empty/all-peer-filtered windows still
        // advance via `next_since` (#2441) because nothing was delivered.
        let skipped = true;
        let advance = resolve_catchup_advance(skipped, Some(T1), Some(T3), Some(T1), "peer-x");
        assert_eq!(
            advance.as_deref(),
            Some(T1),
            "row-loss guard: a skipped delivered row must not leap to next_since"
        );
        let skipped_no_apply = resolve_catchup_advance(skipped, None, Some(T3), Some(T1), "peer-x");
        assert_eq!(
            skipped_no_apply, None,
            "all-skipped delivered window holds the cursor so the rows re-pull"
        );
    }

    #[test]
    fn halted_never_advances_to_next_since_2714() {
        // A transient apply FAILED this window (halted). The peer's
        // examined-watermark `next_since` (T3) is FAR past the last durable
        // success (T1). The cursor MUST hold at T1 so the un-applied row is
        // re-pulled — never leap to T3 (which would drop it forever, #2714).
        let advance = resolve_catchup_advance(true, Some(T1), Some(T3), Some(T1), "peer-x");
        assert_eq!(
            advance.as_deref(),
            Some(T1),
            "row-loss guard: a halted window must advance only to the last durable success"
        );
    }

    #[test]
    fn halted_with_no_success_holds_cursor_2714() {
        // The very first row failed transiently: no durable success this window.
        // The cursor MUST NOT advance at all (None) so the window is re-pulled.
        let advance = resolve_catchup_advance(true, None, Some(T3), Some(T1), "peer-x");
        assert_eq!(
            advance, None,
            "row-loss guard: no durable success => no advance, whole window re-pulled"
        );
    }

    #[test]
    fn clean_window_consumes_next_since_2441() {
        // A clean window (not halted) advances to the peer's honest
        // examined-watermark so an all-filtered (count:0) window converges.
        let advance = resolve_catchup_advance(false, Some(T2), Some(T3), Some(T1), "peer-x");
        assert_eq!(
            advance.as_deref(),
            Some(T3),
            "stall fix: a clean window advances to the validated next_since"
        );
    }

    #[test]
    fn empty_filtered_window_still_advances_via_next_since_2441() {
        // The #2441 stall: an ALL-out-of-scope window returns count:0, so no row
        // applied (latest_ts None) and NOT halted. Pre-fix the cursor never
        // advanced and the identical window re-pulled forever. `next_since` now
        // advances it past the filtered rows.
        let advance = resolve_catchup_advance(false, None, Some(T3), Some(T1), "peer-x");
        assert_eq!(
            advance.as_deref(),
            Some(T3),
            "stall fix: an empty/all-filtered window must still advance via next_since"
        );
    }

    #[test]
    fn poisoned_far_future_next_since_falls_back_to_latest_ts_2718() {
        // A peer-advertised far-future cursor must be REFUSED (cursor-poisoning
        // guard); advance only to the honest last durable success instead.
        let poison = "2999-01-01T00:00:00Z";
        let advance = resolve_catchup_advance(false, Some(T2), Some(poison), Some(T1), "peer-x");
        assert_eq!(
            advance.as_deref(),
            Some(T2),
            "cursor-poisoning guard: a far-future next_since falls back to latest_ts"
        );
    }

    #[test]
    fn legacy_peer_without_next_since_uses_latest_ts_2441() {
        // A legacy peer that does not publish `next_since` falls back to the
        // applied-rows high-water (byte-identical to the pre-#2441 behaviour for
        // a non-empty window).
        let advance = resolve_catchup_advance(false, Some(T2), None, Some(T1), "peer-x");
        assert_eq!(advance.as_deref(), Some(T2));
        // ...and a legacy peer with an EMPTY window still stalls (unavoidable
        // without the field) — no advance.
        let advance_empty = resolve_catchup_advance(false, None, None, Some(T1), "peer-x");
        assert_eq!(advance_empty, None);
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
