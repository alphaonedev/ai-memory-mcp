// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — attested-checkpoint sqlite free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the future MCP stdio `memory_checkpoint_*` tool handlers (which hold a
//! bare `Connection`, not a SAL store) share one implementation — exactly
//! the split [`crate::signals`] uses for the signed-signal surface. The
//! postgres adapter keeps its own sqlx-native path in
//! `crate::store::postgres`.
//!
//! Backs the v61 `checkpoints` table (conditional coordination gates whose
//! resolution is Ed25519-attested). The `signature` / `resolver_pubkey`
//! columns are persisted verbatim as byte vectors — a checkpoint resolved
//! with empty `signature` / `resolver_pubkey` is simply unattested; the
//! attested-resolution signing logic lands in a subsequent unit.

use crate::identity::keypair::AgentKeypair;
use crate::identity::sign::{SignableCheckpointResolution, sign_checkpoint_resolution};
use crate::identity::verify::verify_checkpoint_resolution;
use crate::models::{Checkpoint, CheckpointState, ConditionType};
use rusqlite::{Connection, OptionalExtension, params};

/// Build the [`SignableCheckpointResolution`] view of a [`Checkpoint`] — the
/// immutable-once-resolved fields the resolution signature commits to,
/// borrowing from `cp`. Shared by [`sign_resolution_into`] (outbound) and
/// [`verify`] (inbound) so both commit to byte-identical canonical bytes —
/// the same shared-view discipline [`crate::signals::signable`] uses for the
/// signed-signal surface.
///
/// FED-RQ-01 (#1936) — also consumed by the federation receive funnel to
/// re-derive the canonical bytes an inbound resolution's attestation must
/// verify against the resolver's ENROLLED key, so `pub(crate)`.
pub(crate) fn resolution_signable(cp: &Checkpoint) -> SignableCheckpointResolution<'_> {
    SignableCheckpointResolution {
        checkpoint_id: &cp.id,
        namespace: &cp.namespace,
        state: cp.state.as_str(),
        resolved_by: cp.resolved_by.as_deref().unwrap_or(""),
        resolution: cp.resolution.as_deref(),
        resolved_at: cp.resolved_at.unwrap_or(0),
    }
}

/// Sign `cp`'s resolution in place with `keypair`'s private key.
///
/// Builds the [`SignableCheckpointResolution`] view, signs the canonical CBOR
/// via [`sign_checkpoint_resolution`], then sets `cp.signature` to the 64-byte
/// signature and `cp.resolver_pubkey` to the signer's 32 public-key bytes.
/// Mirrors [`crate::signals::sign_into`] for the signed-signal surface.
///
/// # Errors
/// Returns the [`sign_checkpoint_resolution`] error when `keypair` is
/// public-only (`can_sign() == false`) or the CBOR encode fails.
pub fn sign_resolution_into(cp: &mut Checkpoint, keypair: &AgentKeypair) -> anyhow::Result<()> {
    let sig = sign_checkpoint_resolution(keypair, &resolution_signable(cp))?;
    cp.signature = sig;
    cp.resolver_pubkey = keypair.public.to_bytes().to_vec();
    Ok(())
}

/// Verify a checkpoint's Ed25519 attested-resolution signature against its
/// embedded `resolver_pubkey`.
///
/// Returns `false` for an unattested checkpoint (empty `signature` OR empty
/// `resolver_pubkey`) and for any signature that does not validate against the
/// re-derived canonical resolution bytes. Never panics. Mirrors
/// [`crate::signals::verify`].
#[must_use]
pub fn verify(cp: &Checkpoint) -> bool {
    if cp.signature.is_empty() || cp.resolver_pubkey.is_empty() {
        return false;
    }
    verify_checkpoint_resolution(&resolution_signable(cp), &cp.signature, &cp.resolver_pubkey)
}

/// SELECT column list for the `checkpoints` table, in the canonical order
/// [`row_to_checkpoint`] expects. One definition shared by every checkpoint
/// read.
pub const CHECKPOINT_SELECT_SQL: &str = "SELECT id, namespace, title, condition_type, condition, \
     state, created_by, resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
     created_at, deadline_at, resolved_at, metadata FROM checkpoints";

/// Shared SQL fragment for the `state` equality narrowing — one definition
/// referenced by both the sqlite free-fns here and the postgres adapter so
/// the filter clause never drifts (and the literal lives at one site).
pub const SQL_AND_STATE_EQ: &str = " AND state = ";

/// Shared SQL fragment for the newest-first ordering + LIMIT placeholder
/// position — referenced by both the sqlite free-fns here and the postgres
/// adapter. Callers append the placeholder (`?`) / bind the limit.
pub const SQL_ORDER_BY_CREATED_DESC_LIMIT: &str = " ORDER BY created_at DESC LIMIT ";

/// Map a `rusqlite` row (the [`CHECKPOINT_SELECT_SQL`] column order) to a
/// [`Checkpoint`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_checkpoint(r: &rusqlite::Row<'_>) -> rusqlite::Result<Checkpoint> {
    Ok(Checkpoint {
        id: r.get(0)?,
        namespace: r.get(1)?,
        title: r.get(2)?,
        condition_type: ConditionType::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
        condition: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(serde_json::Value::Null),
        state: CheckpointState::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        created_by: r.get(6)?,
        resolved_by: r.get(7)?,
        resolution: r.get(8)?,
        resolution_note: r.get(9)?,
        // The `signature` / `resolver_pubkey` columns are nullable BLOB —
        // read as `Option<Vec<u8>>` and collapse NULL to an empty vec so a
        // pre-resolution (unattested) row round-trips without a column-type
        // error. INSERT always writes a non-NULL (possibly empty) vec.
        signature: r.get::<_, Option<Vec<u8>>>(10)?.unwrap_or_default(),
        resolver_pubkey: r.get::<_, Option<Vec<u8>>>(11)?.unwrap_or_default(),
        created_at: r.get(12)?,
        deadline_at: r.get(13)?,
        resolved_at: r.get(14)?,
        metadata: serde_json::from_str(&r.get::<_, String>(15)?).unwrap_or(serde_json::Value::Null),
    })
}

/// Insert a checkpoint. Returns the checkpoint id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn insert(conn: &Connection, cp: &Checkpoint) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO checkpoints \
            (id, namespace, title, condition_type, condition, state, created_by, \
             resolved_by, resolution, resolution_note, signature, resolver_pubkey, \
             created_at, deadline_at, resolved_at, metadata) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            cp.id,
            cp.namespace,
            cp.title,
            cp.condition_type.as_str(),
            cp.condition.to_string(),
            cp.state.as_str(),
            cp.created_by,
            cp.resolved_by,
            cp.resolution,
            cp.resolution_note,
            cp.signature,
            cp.resolver_pubkey,
            cp.created_at,
            cp.deadline_at,
            cp.resolved_at,
            cp.metadata.to_string(),
        ],
    )?;
    Ok(cp.id.clone())
}

/// Fetch a checkpoint by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Checkpoint>> {
    conn.query_row(
        &format!("{CHECKPOINT_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_checkpoint,
    )
    .optional()
}

/// `WHERE id = ?1` scalar SELECT of a checkpoint's `namespace` only — the
/// checkpoints-table twin of [`crate::storage::namespace_by_id`].
const SQL_SELECT_CHECKPOINT_NAMESPACE_BY_ID: &str =
    "SELECT namespace FROM checkpoints WHERE id = ?1";

/// Resolve the STORED `namespace` of the checkpoint row with `id`, or `None`
/// when no such row exists locally.
///
/// #2708 (CB-3, CWE-284/#2447-class) — the federation checkpoint-resolution
/// receive lane authorizes a peer's per-peer `allowed_namespaces` scope, but
/// the [`apply_inbound_resolution`] CAS keys on `(id, state)` ONLY: on the
/// pending→resolved arm it resolves the LOCAL row by id and writes NOTHING to
/// its `namespace`. So the confinement subject on that arm is the STORED
/// namespace, NOT the attacker-chosen wire `namespace` — a peer scoped to
/// `public/*` must not resolve a `secure/ops` freeze anchor by presenting a
/// `public/ok` wire namespace. This scalar is the by-id namespace probe the
/// receive funnel feeds as `existing_namespace`, mirroring how the memories
/// lane consumes [`crate::storage::namespace_by_id`] (#2447) — a SCALAR
/// projection, never a full-row [`get`], so a probe never depends on mapping
/// the checkpoint's condition JSON / attestation bytes.
///
/// # Errors
/// Propagates the `rusqlite` query error (the caller MUST fail closed — an
/// unresolvable probe cannot be reported as "provably no local row").
pub fn namespace_by_id(conn: &Connection, id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(SQL_SELECT_CHECKPOINT_NAMESPACE_BY_ID, params![id], |row| {
        row.get::<_, String>(0)
    })
    .optional()
}

/// List a namespace's checkpoints, newest-first, capped at `limit`. When
/// `state` is `Some`, narrows to that lifecycle state; when `None`, returns
/// every checkpoint in the namespace.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn list(
    conn: &Connection,
    namespace: &str,
    state: Option<CheckpointState>,
    limit: usize,
) -> rusqlite::Result<Vec<Checkpoint>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{CHECKPOINT_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(st) = state {
        sql.push_str(SQL_AND_STATE_EQ);
        sql.push('?');
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(SQL_ORDER_BY_CREATED_DESC_LIMIT);
    sql.push('?');
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_checkpoint,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Query a namespace's checkpoints narrowed by an optional `condition_type`
/// AND an optional `state`, newest-first, capped at `limit`.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn query(
    conn: &Connection,
    namespace: &str,
    condition_type: Option<ConditionType>,
    state: Option<CheckpointState>,
    limit: usize,
) -> rusqlite::Result<Vec<Checkpoint>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{CHECKPOINT_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(ct) = condition_type {
        sql.push_str(" AND condition_type = ?");
        binds.push(Box::new(ct.as_str().to_string()));
    }
    if let Some(st) = state {
        sql.push_str(SQL_AND_STATE_EQ);
        sql.push('?');
        binds.push(Box::new(st.as_str().to_string()));
    }
    sql.push_str(SQL_ORDER_BY_CREATED_DESC_LIMIT);
    sql.push('?');
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_checkpoint,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Resolve a checkpoint: set `state` + `resolved_by` + `resolution` +
/// `resolution_note` + `resolved_at`. Returns the resolved row, or `None`
/// if the id does not exist.
///
/// When `keypair` is `Some(kp)` AND `kp.can_sign()`, the resolved row's
/// canonical RESOLUTION (the separation-of-duties attestation: who resolved
/// this checkpoint, to what, when) is Ed25519-signed and the 64-byte signature
/// + 32-byte resolver public key are persisted into the `signature` /
/// `resolver_pubkey` columns in the same write — mirroring how
/// [`crate::signals::signal_send`] signs a signal row before insert. A `None`
/// (or public-only) keypair leaves `signature` / `resolver_pubkey` empty
/// (unattested), so [`verify`] returns `false` for that row.
///
/// # Errors
/// Propagates the `rusqlite` update/query error. A signing failure (CBOR
/// encode) surfaces as a `rusqlite` SQL error path is NOT taken — signing is
/// only attempted for a `can_sign()` keypair over a fixed-shape input, which
/// is infallible in practice; an encode error is mapped to a SQL misuse error
/// so the resolve fails closed rather than persisting an unsigned row that the
/// caller believed was signed.
pub fn resolve(
    conn: &Connection,
    id: &str,
    state: CheckpointState,
    resolved_by: &str,
    resolution: Option<&str>,
    resolution_note: Option<&str>,
    resolved_at: i64,
    keypair: Option<&AgentKeypair>,
) -> rusqlite::Result<Option<Checkpoint>> {
    let n = conn.execute(
        "UPDATE checkpoints SET state = ?1, resolved_by = ?2, resolution = ?3, \
            resolution_note = ?4, resolved_at = ?5 WHERE id = ?6",
        params![
            state.as_str(),
            resolved_by,
            resolution,
            resolution_note,
            resolved_at,
            id,
        ],
    )?;
    if n == 0 {
        return Ok(None);
    }
    let Some(mut row) = get(conn, id)? else {
        return Ok(None);
    };
    // Sign the resolution + persist the attestation columns when a signing
    // keypair is supplied — done after the resolution-field UPDATE so the
    // signable view reads the final resolved state/resolved_by/resolution/
    // resolved_at.
    if let Some(kp) = keypair {
        if kp.can_sign() {
            sign_resolution_into(&mut row, kp).map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                    "checkpoint resolution sign failed: {e:#}"
                ))))
            })?;
            conn.execute(
                "UPDATE checkpoints SET signature = ?1, resolver_pubkey = ?2 WHERE id = ?3",
                params![row.signature, row.resolver_pubkey, id],
            )?;
        }
    }
    Ok(Some(row))
}

/// Outcome of applying an inbound federated checkpoint RESOLUTION via
/// [`apply_inbound_resolution`] — the FED-RQ-01 (#1936) receive-side CRDT apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundResolutionOutcome {
    /// The resolution was newly applied — either the resolved checkpoint was
    /// inserted verbatim (no local row existed) or a locally-PENDING checkpoint
    /// transitioned to carry the inbound resolution + attestation.
    Applied,
    /// Idempotent replay — the checkpoint is already resolved locally with the
    /// byte-identical resolution tuple. No write performed.
    Noop,
    /// The checkpoint is already resolved locally with a DIFFERENT resolution.
    /// Under the substrate's first-resolution-wins rule the LOCAL resolution is
    /// kept and the inbound one refused. No write performed.
    Conflict,
}

/// Whether two checkpoints carry the identical resolution tuple — the
/// idempotency key for [`apply_inbound_resolution`]: same terminal `state`,
/// same `resolved_by`, same `resolution` verdict. A byte-identical replay is a
/// no-op; any divergence is a first-resolution-wins conflict. (`resolution_note`
/// is advisory prose and deliberately excluded from the conflict key, matching
/// the fields the [`resolution_signable`] attestation binds.)
fn resolutions_match(local: &Checkpoint, incoming: &Checkpoint) -> bool {
    local.state == incoming.state
        && local.resolved_by == incoming.resolved_by
        && local.resolution == incoming.resolution
}

/// First-resolution-wins disposition for an inbound resolution that lost the
/// race (or arrived after) a resolution already committed locally: a
/// byte-identical tuple is an idempotent replay, anything else is a conflict
/// with the LOCAL resolution kept. Never a write.
fn classify_against_local(local: &Checkpoint, incoming: &Checkpoint) -> InboundResolutionOutcome {
    if resolutions_match(local, incoming) {
        InboundResolutionOutcome::Noop
    } else {
        InboundResolutionOutcome::Conflict
    }
}

/// Whether a `rusqlite` error is a constraint violation — the shape a losing
/// concurrent INSERT of the same checkpoint id takes (`checkpoints.id` is the
/// PRIMARY KEY). Used by [`apply_inbound_resolution`] to turn a lost
/// insert race into the documented first-resolution-wins disposition instead
/// of a hard error.
fn is_constraint_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// COMPARE-AND-SWAP write used by [`apply_inbound_resolution`]: stamps the
/// inbound resolution + attestation onto a checkpoint ONLY while that
/// checkpoint is still locally `pending` (`?9` binds
/// [`CheckpointState::Pending`]). The `AND state = ?9` guard is what makes
/// first-resolution-wins hold under concurrency — without it the read that
/// decided "local is pending" and the write that acts on that decision are a
/// TOCTOU window in which a concurrently-committed local resolution is
/// silently overwritten (#2396).
const APPLY_INBOUND_RESOLUTION_CAS_SQL: &str = "UPDATE checkpoints SET state = ?1, resolved_by = ?2, resolution = ?3, \
        resolution_note = ?4, resolved_at = ?5, signature = ?6, resolver_pubkey = ?7 \
     WHERE id = ?8 AND state = ?9";

/// Apply an inbound FEDERATED checkpoint resolution under the checkpoint
/// substrate's **first-resolution-wins** rule (FED-RQ-01, #1936).
///
/// `incoming` MUST be a resolved (non-[`CheckpointState::Pending`]) checkpoint
/// — the federation receive funnel filters out unresolved rows before calling
/// this (an unresolved checkpoint carries no attestation). Disposition:
///
/// - **No local row** → the resolution is the first to land: INSERT `incoming`
///   verbatim (subject + resolution arrive together). → [`InboundResolutionOutcome::Applied`].
/// - **Local row is `Pending`** → first resolution: UPDATE the resolution +
///   attestation fields verbatim. → `Applied`.
/// - **Local row already resolved, identical tuple** ([`resolutions_match`]) →
///   idempotent replay. → [`InboundResolutionOutcome::Noop`].
/// - **Local row already resolved, DIFFERENT tuple** → first-resolution-wins:
///   keep the local resolution, refuse the inbound. → [`InboundResolutionOutcome::Conflict`].
///
/// # Concurrency (#2396)
/// The pending→resolved transition is a **compare-and-swap**
/// ([`APPLY_INBOUND_RESOLUTION_CAS_SQL`] carries `AND state = 'pending'`), and
/// the "no local row" arm treats a losing INSERT (PRIMARY-KEY violation) as the
/// same first-resolution-wins disposition. A concurrent local resolve or a
/// second inbound resolution therefore can NEVER overwrite an
/// already-committed resolution: the loser is reported as
/// [`InboundResolutionOutcome::Conflict`] (or `Noop` when byte-identical) and
/// the receive loop counts it in `checkpoints_conflicted`. Before the CAS this
/// was a get-then-UPDATE TOCTOU that let a late writer flip a resolved
/// authority-lane verdict after the fact.
///
/// The receiver **NEVER re-signs**: the resolver's Ed25519 attestation
/// (`signature` / `resolver_pubkey`) travels on `incoming` and is persisted
/// verbatim (the v0.8.0 local-substrate rule — a node stamps only its OWN
/// writes). Authorization (verifying that attestation against the resolver's
/// locally-ENROLLED key) is the caller's responsibility; this function is the
/// idempotent CRDT apply once the verdict is `Accept`.
///
/// # Errors
/// Propagates the `rusqlite` read/write error.
pub fn apply_inbound_resolution(
    conn: &Connection,
    incoming: &Checkpoint,
) -> rusqlite::Result<InboundResolutionOutcome> {
    // Step 1 — CAS the locally-PENDING row. `n == 1` means THIS call won the
    // pending→resolved transition; the guard makes a concurrent second writer
    // see `n == 0` instead of clobbering the winner's resolution.
    let updated = conn.execute(
        APPLY_INBOUND_RESOLUTION_CAS_SQL,
        params![
            incoming.state.as_str(),
            incoming.resolved_by,
            incoming.resolution,
            incoming.resolution_note,
            incoming.resolved_at,
            incoming.signature,
            incoming.resolver_pubkey,
            incoming.id,
            CheckpointState::Pending.as_str(),
        ],
    )?;
    if updated > 0 {
        return Ok(InboundResolutionOutcome::Applied);
    }

    // Step 2 — the CAS did not fire: either no local row exists yet, or the
    // checkpoint is already resolved (possibly by a writer that raced us).
    let Some(local) = get(conn, &incoming.id)? else {
        return match insert(conn, incoming) {
            Ok(_) => Ok(InboundResolutionOutcome::Applied),
            // Lost the INSERT race — the winner's row landed between our read
            // and our write. Fall back to the first-resolution-wins
            // disposition against whatever is now committed; never overwrite.
            Err(e) if is_constraint_violation(&e) => match get(conn, &incoming.id)? {
                Some(local) => Ok(classify_against_local(&local, incoming)),
                None => Err(e),
            },
            Err(e) => Err(e),
        };
    };
    Ok(classify_against_local(&local, incoming))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Checkpoint {
        Checkpoint {
            id: id.to_string(),
            namespace: "_cp".to_string(),
            title: "needs approval".to_string(),
            condition_type: ConditionType::Approval,
            condition: serde_json::json!({}),
            state: CheckpointState::Pending,
            created_by: "agent-creator".to_string(),
            resolved_by: None,
            resolution: None,
            resolution_note: None,
            signature: vec![],
            resolver_pubkey: vec![],
            created_at: 1_700_000_000,
            deadline_at: None,
            resolved_at: None,
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn insert_then_get_roundtrips() {
        let conn = fresh();
        let id = insert(&conn, &sample("c1")).unwrap();
        assert_eq!(id, "c1");
        let got = get(&conn, "c1").unwrap().expect("present");
        assert_eq!(got.namespace, "_cp");
        assert_eq!(got.title, "needs approval");
        assert_eq!(got.condition_type, ConditionType::Approval);
        assert_eq!(got.state, CheckpointState::Pending);
        assert_eq!(got.created_by, "agent-creator");
        assert_eq!(got.condition, serde_json::json!({}));
        assert_eq!(got.metadata, serde_json::json!({}));
        assert!(got.signature.is_empty());
        assert!(got.resolver_pubkey.is_empty());
        assert!(got.resolved_by.is_none());
        assert!(got.resolved_at.is_none());
        assert!(get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn list_filters_by_namespace_and_state() {
        let conn = fresh();
        insert(&conn, &sample("p1")).unwrap();
        let mut p2 = sample("p2");
        p2.created_at = 1_700_000_100;
        insert(&conn, &p2).unwrap();
        // A resolved checkpoint in the same namespace.
        let mut done = sample("done");
        done.state = CheckpointState::Resolved;
        done.created_at = 1_700_000_050;
        insert(&conn, &done).unwrap();
        // A checkpoint in a different namespace must not surface.
        let mut other = sample("other-ns");
        other.namespace = "_cp_elsewhere".to_string();
        insert(&conn, &other).unwrap();

        // No state filter — every checkpoint in the namespace, newest-first.
        let all = list(&conn, "_cp", None, 50).unwrap();
        let ids: Vec<&str> = all.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["p2", "done", "p1"], "newest-first ordering");
        assert!(!ids.contains(&"other-ns"), "other-namespace hidden");

        // State filter narrows to pending only.
        let pending = list(&conn, "_cp", Some(CheckpointState::Pending), 50).unwrap();
        let pids: Vec<&str> = pending.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(pids, vec!["p2", "p1"]);
    }

    #[test]
    fn query_filters_by_condition_type() {
        let conn = fresh();
        insert(&conn, &sample("approval")).unwrap();
        let mut deadline = sample("deadline");
        deadline.condition_type = ConditionType::Deadline;
        deadline.created_at = 1_700_000_100;
        insert(&conn, &deadline).unwrap();

        let approvals = query(&conn, "_cp", Some(ConditionType::Approval), None, 50).unwrap();
        let ids: Vec<&str> = approvals.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["approval"]);

        // condition_type + state together.
        let none = query(
            &conn,
            "_cp",
            Some(ConditionType::Deadline),
            Some(CheckpointState::Resolved),
            50,
        )
        .unwrap();
        assert!(none.is_empty(), "no resolved deadline checkpoint exists");
    }

    #[test]
    fn resolve_flips_state_and_stamps_resolver() {
        let conn = fresh();
        insert(&conn, &sample("r1")).unwrap();
        let resolved = resolve(
            &conn,
            "r1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            Some("looks good"),
            1_700_000_500,
            None,
        )
        .unwrap()
        .expect("resolve returns the updated row");
        assert_eq!(resolved.state, CheckpointState::Resolved);
        assert_eq!(resolved.resolved_by.as_deref(), Some("agent-approver"));
        assert_eq!(resolved.resolution.as_deref(), Some("approved"));
        assert_eq!(resolved.resolution_note.as_deref(), Some("looks good"));
        assert_eq!(resolved.resolved_at, Some(1_700_000_500));

        // The persisted row reflects the resolution.
        let got = get(&conn, "r1").unwrap().expect("present");
        assert_eq!(got.state, CheckpointState::Resolved);
        assert_eq!(got.resolved_at, Some(1_700_000_500));
    }

    #[test]
    fn resolve_missing_returns_none() {
        let conn = fresh();
        let missing = resolve(
            &conn,
            "does-not-exist",
            CheckpointState::Resolved,
            "agent-approver",
            None,
            None,
            1_700_000_500,
            None,
        )
        .unwrap();
        assert!(
            missing.is_none(),
            "resolving a missing checkpoint yields None"
        );
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-1 (#1709) — attested-resolution sign + verify
    // -----------------------------------------------------------------

    #[test]
    fn resolve_signed_then_verifies() {
        let conn = fresh();
        insert(&conn, &sample("s1")).unwrap();
        let kp = crate::identity::keypair::generate("agent-approver").expect("generate");
        let resolved = resolve(
            &conn,
            "s1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            Some("looks good"),
            1_700_000_500,
            Some(&kp),
        )
        .unwrap()
        .expect("resolve returns the updated row");
        // The returned row carries the attestation and verifies.
        assert_eq!(
            resolved.signature.len(),
            64,
            "Ed25519 signature is 64 bytes"
        );
        assert_eq!(resolved.resolver_pubkey.len(), 32, "pubkey is 32 bytes");
        assert!(verify(&resolved), "signed resolution must verify");

        // The persisted row (re-read) also carries + verifies the attestation.
        let got = get(&conn, "s1").unwrap().expect("present");
        assert_eq!(got.signature, resolved.signature);
        assert_eq!(got.resolver_pubkey, resolved.resolver_pubkey);
        assert!(verify(&got), "persisted signed resolution must verify");
    }

    #[test]
    fn verify_false_after_resolution_tamper() {
        let conn = fresh();
        insert(&conn, &sample("t1")).unwrap();
        let kp = crate::identity::keypair::generate("agent-approver").expect("generate");
        let mut resolved = resolve(
            &conn,
            "t1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            None,
            1_700_000_500,
            Some(&kp),
        )
        .unwrap()
        .expect("resolve returns the updated row");
        assert!(verify(&resolved), "baseline signed resolution verifies");
        // Tamper with the resolution verdict after signing.
        resolved.resolution = Some("rejected".to_string());
        assert!(
            !verify(&resolved),
            "a mutated resolution must not verify under the original signature"
        );
    }

    #[test]
    fn verify_false_for_unsigned_resolution() {
        let conn = fresh();
        insert(&conn, &sample("u1")).unwrap();
        // No keypair → unsigned path: signature/resolver_pubkey stay empty.
        let resolved = resolve(
            &conn,
            "u1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            None,
            1_700_000_500,
            None,
        )
        .unwrap()
        .expect("resolve returns the updated row");
        assert!(resolved.signature.is_empty());
        assert!(resolved.resolver_pubkey.is_empty());
        assert!(!verify(&resolved), "an unsigned resolution must not verify");
    }

    // -----------------------------------------------------------------
    // FED-RQ-01 (#1936) — inbound federated resolution apply (CRDT,
    // first-resolution-wins). See `federation::receive_auth` for the
    // authority-lane signature verification that precedes this apply.
    // -----------------------------------------------------------------

    /// A fully-resolved, attested checkpoint as it would arrive on the wire.
    fn resolved_remote(id: &str, verdict: &str) -> Checkpoint {
        let kp = crate::identity::keypair::generate("agent-resolver").expect("generate");
        let mut cp = sample(id);
        cp.state = CheckpointState::Resolved;
        cp.resolved_by = Some("agent-resolver".to_string());
        cp.resolution = Some(verdict.to_string());
        cp.resolved_at = Some(1_700_000_900);
        sign_resolution_into(&mut cp, &kp).expect("sign");
        cp
    }

    #[test]
    fn apply_inbound_resolution_inserts_when_absent() {
        let conn = fresh();
        let remote = resolved_remote("fed-absent", "approved");
        assert_eq!(
            apply_inbound_resolution(&conn, &remote).unwrap(),
            InboundResolutionOutcome::Applied
        );
        // Persisted verbatim — attestation preserved (receiver did NOT re-sign).
        let got = get(&conn, "fed-absent").unwrap().expect("present");
        assert_eq!(got.state, CheckpointState::Resolved);
        assert_eq!(got.resolution.as_deref(), Some("approved"));
        assert_eq!(got.signature, remote.signature);
        assert_eq!(got.resolver_pubkey, remote.resolver_pubkey);
        assert!(
            verify(&got),
            "verbatim-persisted attestation still verifies"
        );
    }

    #[test]
    fn apply_inbound_resolution_resolves_local_pending() {
        let conn = fresh();
        // A locally-created PENDING checkpoint with the SAME id.
        insert(&conn, &sample("fed-pending")).unwrap();
        let remote = resolved_remote("fed-pending", "approved");
        assert_eq!(
            apply_inbound_resolution(&conn, &remote).unwrap(),
            InboundResolutionOutcome::Applied
        );
        let got = get(&conn, "fed-pending").unwrap().expect("present");
        assert_eq!(got.state, CheckpointState::Resolved);
        assert_eq!(got.resolved_by.as_deref(), Some("agent-resolver"));
        assert_eq!(got.signature, remote.signature);
        assert!(verify(&got));
    }

    #[test]
    fn apply_inbound_resolution_idempotent_replay_is_noop() {
        let conn = fresh();
        let remote = resolved_remote("fed-replay", "approved");
        assert_eq!(
            apply_inbound_resolution(&conn, &remote).unwrap(),
            InboundResolutionOutcome::Applied
        );
        // Byte-identical replay → Noop, no second write.
        assert_eq!(
            apply_inbound_resolution(&conn, &remote).unwrap(),
            InboundResolutionOutcome::Noop
        );
    }

    #[test]
    fn apply_inbound_resolution_divergent_is_conflict_first_wins() {
        let conn = fresh();
        let first = resolved_remote("fed-conflict", "approved");
        assert_eq!(
            apply_inbound_resolution(&conn, &first).unwrap(),
            InboundResolutionOutcome::Applied
        );
        // A DIFFERENT resolution for the same id → Conflict; local kept.
        let mut second = resolved_remote("fed-conflict", "rejected");
        second.state = CheckpointState::Rejected;
        assert_eq!(
            apply_inbound_resolution(&conn, &second).unwrap(),
            InboundResolutionOutcome::Conflict
        );
        let got = get(&conn, "fed-conflict").unwrap().expect("present");
        assert_eq!(
            got.state,
            CheckpointState::Resolved,
            "first resolution wins"
        );
        assert_eq!(got.resolution.as_deref(), Some("approved"));
    }

    #[test]
    fn resolve_with_public_only_keypair_stays_unsigned() {
        let conn = fresh();
        insert(&conn, &sample("p1")).unwrap();
        let kp = crate::identity::keypair::generate("agent-approver").unwrap();
        let pub_only = crate::identity::keypair::AgentKeypair {
            agent_id: "agent-approver".to_string(),
            public: kp.public,
            private: None,
        };
        let resolved = resolve(
            &conn,
            "p1",
            CheckpointState::Resolved,
            "agent-approver",
            Some("approved"),
            None,
            1_700_000_500,
            Some(&pub_only),
        )
        .unwrap()
        .expect("resolve returns the updated row");
        // can_sign() == false → unattested, exactly like the None path.
        assert!(resolved.signature.is_empty());
        assert!(resolved.resolver_pubkey.is_empty());
        assert!(!verify(&resolved));
    }
}
