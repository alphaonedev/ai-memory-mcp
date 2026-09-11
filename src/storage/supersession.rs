// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 deterministic store supersession. Authority, both row reads, fresh
//! insertion, production archive and pointers share one write transaction.

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use crate::identity::supersession::{
    SupersessionDecision, SupersessionPrincipal, SupersessionRefusal, authorize_supersession,
};
use crate::models::{Memory, field_names};

const SQL_SELECT_ARCHIVED_MEMORY_ROW_BY_ID: &str = "SELECT * FROM archived_memories WHERE id = ?1";

/// Evidence supplied by the actual transport edge, never deserialized from JSON.
#[derive(Clone, Copy)]
pub struct SupersessionRequest<'a> {
    pub principal: Option<&'a SupersessionPrincipal>,
    pub as_admin: bool,
}

/// Returned only after the complete write commits. A refusal never names OLD.
#[derive(Debug)]
pub struct SupersessionResult {
    pub id: String,
    pub superseded: Option<String>,
    pub refusal: Option<SupersessionRefusal>,
}

impl SupersessionResult {
    /// Attach the same optional fields to all transport envelopes.
    pub fn add_response_fields(&self, response: &mut serde_json::Value) {
        if let Some(old) = &self.superseded {
            response[field_names::SUPERSEDED] = serde_json::json!(old);
        }
        if self.refusal.is_some() {
            response["supersede_skipped"] = serde_json::json!("unauthenticated_principal");
        }
    }

    /// Emit success only after commit; refused attempts leave OLD live.
    pub(crate) fn audit(&self, request: SupersessionRequest<'_>, memory: &Memory) {
        if self.superseded.is_none() && self.refusal.is_none() {
            return;
        }
        let reason = self.refusal.map(|r| format!("{r:?}"));
        audit_decision(
            request,
            &self.id,
            &memory.namespace,
            self.superseded.as_deref(),
            reason.as_deref(),
        );
    }
}

/// Audit a final operation error without exposing backend diagnostics or an
/// unreadable predecessor. Resolve has no trusted namespace if its row read
/// failed, so it supplies an empty namespace rather than performing another read.
/// Called outside the transaction/retry boundary; never emits an Allow.
pub(crate) fn audit_failure(request: SupersessionRequest<'_>, new_id: &str, namespace: &str) {
    audit_decision(request, new_id, namespace, None, Some("operation_failed"));
}

fn audit_decision(
    request: SupersessionRequest<'_>,
    new_id: &str,
    namespace: &str,
    superseded: Option<&str>,
    reason: Option<&str>,
) {
    let actor = request.principal.map_or(
        crate::identity::sentinels::ANONYMOUS_INVALID,
        SupersessionPrincipal::agent_id,
    );
    let denied = reason.is_some();
    crate::governance::audit::record_decision(
        actor,
        if denied { "Deny" } else { "Allow" },
        "supersession",
        "3587",
        serde_json::json!({
            "new_id": new_id,
            (field_names::SUPERSEDED): superseded,
            "reason": reason,
        }),
    );
    crate::audit::emit(
        crate::audit::EventBuilder::new(
            crate::audit::AuditAction::Update,
            crate::audit::AuditActor {
                agent_id: actor.to_owned(),
                scope: None,
                synthesis_source: request.principal.map_or_else(
                    || crate::audit::synthesis_sources::DEFAULT_FALLBACK.to_owned(),
                    |p| format!("{:?}", p.source()),
                ),
            },
            crate::audit::AuditTarget {
                memory_id: new_id.to_owned(),
                namespace: namespace.to_owned(),
                title: None,
                tier: None,
                scope: None,
            },
        )
        .outcome(if denied {
            crate::audit::AuditOutcome::Deny
        } else {
            crate::audit::AuditOutcome::Allow
        }),
    );
}

/// Bulk cannot decide ordered supersession safely; clients use single creates.
pub const KEYED_BULK_UNSUPPORTED: &str = "KEYED_BULK_UNSUPPORTED";

/// Typed refusal shared by both bulk backends.
#[derive(Debug)]
pub struct KeyedBulkUnsupported;

impl std::fmt::Display for KeyedBulkUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ruling_key is unsupported in bulk; use single-memory store")
    }
}

impl std::error::Error for KeyedBulkUnsupported {}

/// Validate a keyed store before any merge/synthesis mutation.
///
/// # Errors
/// A present key must be a nonempty string.
pub fn ruling_key(metadata: &serde_json::Value) -> Result<Option<&str>> {
    metadata
        .get(field_names::RULING_KEY)
        .map(|value| {
            value
                .as_str()
                .filter(|key| !key.is_empty())
                .ok_or_else(|| anyhow::anyhow!("ruling_key must be a nonempty string"))
        })
        .transpose()
}

// SQLite's julianday loses sub-millisecond precision. Compare RFC3339 instants
// without floating point (PERF-25), retaining only one id/time pair while scanning
// this key. Load the full selected row under the caller's write transaction.
// Invalid persisted time fails closed instead of silently excluding a candidate.
fn newest_predecessor(conn: &Connection, namespace: &str, key: &str) -> Result<Option<Memory>> {
    let mut statement = conn.prepare(
        "SELECT id, created_at FROM memories WHERE namespace = ?1 \
         AND json_type(metadata, '$.ruling_key') = 'text' \
         AND json_extract(metadata, '$.ruling_key') = ?2",
    )?;
    let rows = statement.query_map(params![namespace, key], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut newest = None;
    for row in rows {
        let (id, created_at) = row?;
        let instant = chrono::DateTime::parse_from_rfc3339(&created_at)
            .context("invalid supersession predecessor timestamp")?;
        let candidate = (instant, id);
        if newest.as_ref().is_none_or(|current| &candidate > current) {
            newest = Some(candidate);
        }
    }
    newest
        .map(|(_, id)| {
            conn.query_row(
                super::SQL_SELECT_MEMORY_ROW_BY_ID,
                [id],
                super::row_to_memory,
            )
            .map_err(Into::into)
        })
        .transpose()
}

/// Store a fresh keyed row and archive its authorized predecessor atomically.
///
/// # Errors
/// Propagates record-stop, conflict, authority evidence mismatch, SQL and vector
/// failures. Every failure rolls back the entire write (ERRORS-02).
pub fn store(
    conn: &Connection,
    memory: &Memory,
    request: SupersessionRequest<'_>,
    embedding: Option<(&[f32], &str)>,
) -> Result<SupersessionResult> {
    store_transaction(conn, memory, request, embedding)
        .inspect_err(|_| audit_failure(request, &memory.id, &memory.namespace))
}

// The transaction guard unwinds here before the outer final-error audit.
fn store_transaction(
    conn: &Connection,
    memory: &Memory,
    request: SupersessionRequest<'_>,
    embedding: Option<(&[f32], &str)>,
) -> Result<SupersessionResult> {
    super::record_stop::gate_storage_conn(conn)?;
    let key = ruling_key(&memory.metadata)?
        .ok_or_else(|| anyhow::anyhow!("supersession store requires ruling_key"))?;
    let tx = super::connection::WriteTxn::begin(conn)?;
    let old = newest_predecessor(conn, &memory.namespace, key)?;
    let id = super::insert_no_overwrite(conn, memory)?;
    ensure!(id == memory.id, "fresh supersession insert changed id");
    let mut result = SupersessionResult {
        id,
        superseded: None,
        refusal: None,
    };
    if let Some(old) = old {
        let new = conn.query_row(
            super::SQL_SELECT_MEMORY_ROW_BY_ID,
            [&result.id],
            super::row_to_memory,
        )?;
        match authorize_supersession(
            request.principal,
            request.as_admin,
            &crate::identity::admin_agent_ids(),
            &old,
            &new,
        ) {
            SupersessionDecision::Authorized(authorized) => {
                archive_as_superseded(conn, &authorized)?;
                result.superseded = Some(old.id);
            }
            SupersessionDecision::Refused(reason) => result.refusal = Some(reason),
            SupersessionDecision::AlreadySuperseded => {}
        }
    }
    if let Some((vector, space)) = embedding {
        super::set_embedding(conn, &result.id, vector, space)?;
    }
    tx.commit()?;
    result.audit(request, memory);
    Ok(result)
}

/// Resolve two existing rows through the same production archive primitive.
///
/// # Errors
/// Missing rows, record-stop, database and archive failures propagate. Refusals
/// are audited and returned without mutating either row.
pub fn resolve(
    conn: &Connection,
    old_id: &str,
    new_id: &str,
    request: SupersessionRequest<'_>,
) -> Result<SupersessionResult> {
    resolve_transaction(conn, old_id, new_id, request)
        .inspect_err(|_| audit_failure(request, new_id, ""))
}

// The transaction guard unwinds here before the outer final-error audit.
fn resolve_transaction(
    conn: &Connection,
    old_id: &str,
    new_id: &str,
    request: SupersessionRequest<'_>,
) -> Result<SupersessionResult> {
    super::record_stop::gate_storage_conn(conn)?;
    let tx = super::connection::WriteTxn::begin(conn)?;
    let new = conn
        .query_row(
            super::SQL_SELECT_MEMORY_ROW_BY_ID,
            [new_id],
            super::row_to_memory,
        )
        .optional()?
        .ok_or_else(|| anyhow::anyhow!(crate::errors::msg::MEMORY_NOT_FOUND))?;
    let old = conn
        .query_row(
            super::SQL_SELECT_MEMORY_ROW_BY_ID,
            [old_id],
            super::row_to_memory,
        )
        .optional()?;
    let old_is_archived = old.is_none();
    let old = match old {
        Some(old) => old,
        None => conn
            .query_row(
                SQL_SELECT_ARCHIVED_MEMORY_ROW_BY_ID,
                [old_id],
                super::row_to_memory,
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!(crate::errors::msg::MEMORY_NOT_FOUND))?,
    };
    let mut result = SupersessionResult {
        id: new.id.clone(),
        superseded: None,
        refusal: None,
    };
    match authorize_supersession(
        request.principal,
        request.as_admin,
        &crate::identity::admin_agent_ids(),
        &old,
        &new,
    ) {
        SupersessionDecision::Authorized(_) if old_is_archived => {
            result.refusal = Some(SupersessionRefusal::ArchivedPredecessor);
        }
        SupersessionDecision::Authorized(authorized) => {
            archive_as_superseded(conn, &authorized)?;
            result.superseded = Some(old.id);
        }
        SupersessionDecision::Refused(reason) => result.refusal = Some(reason),
        SupersessionDecision::AlreadySuperseded => {}
    }
    tx.commit()?;
    result.audit(request, &new);
    Ok(result)
}

/// Consume authority while both row snapshots remain pinned by BEGIN IMMEDIATE.
fn archive_as_superseded(
    conn: &Connection,
    authorized: &crate::identity::supersession::AuthorizedSupersession<'_>,
) -> Result<()> {
    super::record_stop::gate_storage_conn(conn)?;
    ensure!(
        !conn.is_autocommit(),
        "supersession requires a write transaction"
    );
    let old = authorized.old();
    let new = authorized.new_memory();
    ensure!(
        old.id != new.id,
        "supersession cannot archive the replacement id"
    );
    ensure!(
        super::archive_memory_no_tx(conn, &old.id, Some(field_names::ARCHIVE_REASON_SUPERSEDED))?,
        "supersession archive lost predecessor"
    );
    ensure!(conn.execute(
        "UPDATE archived_memories SET metadata = json_set(metadata, '$.superseded_by', ?1) WHERE id = ?2",
        params![new.id, old.id],
    )? == 1, "supersession archive pointer row missing");
    ensure!(conn.execute(
        "UPDATE memories SET metadata = json_set(metadata, '$.superseded_id', ?1) WHERE id = ?2",
        params![old.id, new.id],
    )? == 1, "supersession replacement pointer row missing");
    Ok(())
}
