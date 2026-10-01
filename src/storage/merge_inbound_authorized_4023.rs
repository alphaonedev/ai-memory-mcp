// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4023 — the sqlite federation merge with the in-transaction peer-scope
//! re-check, split out of `storage/mod.rs` (qual_10 headroom for the
//! #4029-#4033 / #4348 siblings that assemble on the same file).
//!
//! `merge_inbound` (the unchecked wrapper) stays in `storage/mod.rs`; it calls
//! [`merge_inbound_authorized`] with a literal `None` authorizer, which the
//! `tests/merge_inbound_unchecked_ceiling_4023.rs` ceiling pins to exactly
//! that one site. Re-exported from `storage/mod.rs`, so callers are unchanged.

use super::*;

/// #4023 — a federation peer-scope verdict re-evaluated against the STORED
/// namespace of the row a same-`id` merge is about to overwrite, read INSIDE
/// the merge's write transaction. `true` authorizes the merge.
pub type StoredNamespaceAuthorizer<'a> = &'a (dyn Fn(&str) -> bool + Send + Sync);

/// #4023 — the refusal detail when [`merge_inbound_authorized`]'s in-transaction
/// re-check finds the colliding row in a namespace the peer is not scoped for.
/// One builder shared by both backends so the log line cannot drift.
#[must_use]
pub fn inbound_stored_namespace_refused(id: &str, stored_namespace: &str) -> String {
    format!(
        "federation merge refused for {id}: the stored row is in namespace \
         {stored_namespace:?}, outside the pushing peer's scope (#4023 in-transaction re-check)"
    )
}

/// #4023 — the TYPED refusal [`merge_inbound_authorized`] returns (inside the
/// `anyhow::Error`) so an adapter can map it to
/// `StoreError::PermissionDenied` exactly as the postgres adapter does
/// (5-agent vote (4d3ea1c5), memory 179cf088 — error parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundStoredNamespaceRefused {
    /// The inbound row's id (the refusal `target`).
    pub id: String,
    /// The namespace of the locked row the peer is not scoped for.
    pub stored_namespace: String,
}

impl std::fmt::Display for InboundStoredNamespaceRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&inbound_stored_namespace_refused(
            &self.id,
            &self.stored_namespace,
        ))
    }
}

impl std::error::Error for InboundStoredNamespaceRefused {}

/// [`merge_inbound`] with the #4023 in-transaction peer-scope re-check.
///
/// The receive funnel authorizes a colliding row's STORED namespace on a
/// pre-read, but `merge_memory` LWWs `namespace`, so a concurrent writer that
/// moved the row between that pre-read and this write would otherwise have the
/// narrow peer's merge land on a row it was never authorized for. When
/// `authorize_stored` is `Some`, the namespace of the row read under this
/// function's `BEGIN IMMEDIATE` lock is re-authorized and a refusal rolls the
/// merge back (nothing written). The no-row fall-through needs no re-check:
/// its `(title, namespace)` upsert targets the CLAIMED namespace (already
/// authorized), and a same-`id` row appearing concurrently fails the insert
/// on the primary key rather than being overwritten.
///
/// # Errors
///
/// Everything [`merge_inbound`] returns, plus a refusal (built by
/// [`inbound_stored_namespace_refused`]) when the locked row's namespace is
/// not authorized.
pub fn merge_inbound_authorized(
    conn: &Connection,
    inbound: &Memory,
    receiver_verified: bool,
    authorize_stored: Option<StoredNamespaceAuthorizer<'_>>,
) -> Result<String> {
    // Wave-2 B2 — record-stop fence on the same-id overwrite path.
    // `insert_if_newer` (no-row fall-through) already gated; the existing-row
    // branch used to bypass via `overwrite_full_row_by_id`. Federation-receive
    // (`handlers/federation_receive.rs`) calls this free-fn directly, so the
    // SAL `SqliteStore::merge_inbound` gate is not sufficient (ERRORS-09).
    crate::storage::record_stop::gate_storage_conn(conn)?;
    // Take the write lock up front so the read-merge-write is atomic
    // against a concurrent peer push (BEGIN IMMEDIATE — same idiom as
    // `consolidate` / `size_gc`).
    let write_txn = connection::WriteTxn::begin(conn)?;
    let tx_result = (|| -> Result<Option<String>> {
        // Boids item 3 R2.2 (#3905) — `get_any`, not `get`: `get` hides
        // system-only rows, so a contaminated local row fell through to the
        // insert lane instead of reaching `merge_memory` (whose R2.1
        // predicate keeps the local taint). The postgres twin already reads
        // the raw row by id (`SQL_SELECT_MEMORY_ROW_BY_ID`).
        match get_any(conn, &inbound.id)? {
            Some(existing) => {
                // #4023 — re-authorize the row actually being overwritten,
                // under the write lock (the caller's pre-read may be stale).
                if let Some(authorize) = authorize_stored
                    && !authorize(&existing.namespace)
                {
                    return Err(anyhow::Error::new(InboundStoredNamespaceRefused {
                        id: inbound.id.clone(),
                        stored_namespace: existing.namespace.clone(),
                    }));
                }
                // #2123 — backend parity with `PostgresStore::merge_inbound`:
                // the same-`id` field-merge path persists via
                // `overwrite_full_row_by_id`, which (deliberately) bypasses
                // the `insert` / `insert_if_newer` chokepoints — so pre-#2123
                // this funnel consulted NEITHER the pre-write governance hook
                // NOR the covenant clause-1 inbound why_trace gate NOR the
                // secret screen, while the postgres twin runs all three.
                // Screen first (ALWAYS redact, NEVER refuse — a refused
                // inbound row would diverge replicas, env #95), then consult
                // governance (refusal rolls the merge back, postgres parity),
                // then the never-refuse inbound why_trace gate (advisory
                // WARN + forensic record only — CRDT convergence is the
                // load-bearing property of the merge primitive).
                let screened = crate::secret_screen::redact_memory_for_receive(inbound);
                let inbound = screened.as_ref().unwrap_or(inbound);
                consult_governance_pre_write(inbound)?;
                consult_why_trace_gate_inbound(inbound);
                // #1719 item 3a — NEVER trust a peer's self-asserted
                // attestation for the merge tiebreak: neutralize the
                // inbound's `metadata.attest_level` to `claimed` so a
                // forged remote cannot win the attested-identity LWW
                // tiebreak by self-asserting `agent_attested`. Only the
                // receiver's own stored local level can win on attestation.
                let sanitized = crate::models::sanitize_inbound_attestation(inbound);
                // #1755 item 3b — cap a relayed row's post-dated
                // `updated_at` (the primary LWW key) to a freshness ceiling
                // so an enrolled relay cannot win the merge by stamping a
                // far-future timestamp. now + the attestation skew window.
                let prepared = crate::models::clamp_inbound_updated_at(
                    sanitized,
                    &chrono::Utc::now().to_rfc3339(),
                    crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS,
                );
                // #224 field-wise merge — the SAME pure reconciler the
                // postgres adapter calls in Rust (no per-backend drift).
                let merged = crate::models::merge_memory(&existing, &prepared);
                // #2863 — re-assert the receiver-VERIFIED `agent_attested` level
                // ATOMICALLY (inside this BEGIN IMMEDIATE tx, before the
                // content-sealing `overwrite_full_row_by_id`). `sanitize` above
                // demoted the inbound level to `claimed` for the LWW tiebreak
                // (correct — a peer must not self-assert), but that must not
                // DEMOTE a level THIS node verified over the persisted bytes:
                // when the merged row's full SignableWrite surface + signature is
                // byte-identical to the verified inbound, restore `agent_attested`.
                // No-op when `receiver_verified` is false (every non-receive
                // caller) — byte-identical legacy merge.
                let merged = crate::models::reassert_verified_attestation(
                    merged,
                    inbound,
                    receiver_verified,
                );
                overwrite_full_row_by_id(conn, &merged)?;
                Ok(Some(merged.id))
            }
            // No row by this id — defer to the (title, namespace) dedup
            // path OUTSIDE this transaction (signalled by `None`).
            None => Ok(None),
        }
    })();

    match tx_result {
        Ok(Some(id)) => {
            write_txn.commit()?;
            Ok(id)
        }
        Ok(None) => {
            // Nothing was written in the merge transaction; close it
            // cleanly and fall through to the unchanged LWW path
            // (handles fresh insert + (title, namespace) dedup-upsert).
            write_txn.commit()?;
            insert_if_newer(conn, inbound)
        }
        Err(e) => {
            write_txn.rollback();
            Err(e)
        }
    }
}
