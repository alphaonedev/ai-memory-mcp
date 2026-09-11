// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U1 `[autonomy] supersede_on_contradiction = "propose"` — the PENDING
//! supersession proposal on SQLite (5-agent vote 4d3ea1c5, decision memory
//! `57956a65`).
//!
//! The curator queues a `supersede` pending row for a conserved same-author
//! contradiction. Nothing is archived until the old row's HARDENED owner
//! approves it on a local surface, and the approved replay runs through the
//! same resolve transaction as `ai-memory resolve`. Three rules keep the
//! approval plane from becoming a way to hide someone else's memory:
//!
//! * only a row the curator queued is a proposal (`requested_by`);
//! * every approve surface calls [`gate_before_approve`] with its hardened
//!   channel principal BEFORE `approve_with_approver_type`, so a refusal never
//!   leaves an approved-but-unexecuted row;
//! * the principal-less `execute_pending_action` refuses the type outright
//!   (federation and any caller without a hardened principal).

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use crate::identity::sentinels::AI_CURATOR;
use crate::identity::supersession::{
    PENDING_ACTION_SUPERSEDE, SupersessionProposal, SupersessionRefusal,
};
use crate::models::PendingAction;

use super::supersession::{SupersessionRequest, precheck_proposal, resolve_proposal};

/// Audit event for a refused approved replay (the row stays unexecuted).
pub(crate) const EVENT_REFUSED_SUPERSESSION: &str = "pending_action.refused_supersession";
/// Audit event for the principal-less executor refusing the type.
pub(crate) const EVENT_REFUSED_PRINCIPAL_REQUIRED: &str =
    "pending_action.refused_principal_required";

/// True when `pa` is a curator supersession proposal row.
#[must_use]
pub fn is_supersession(pa: &PendingAction) -> bool {
    pa.action_type == PENDING_ACTION_SUPERSEDE
}

/// Queue one proposal unless an identical one is still pending. Returns the
/// new pending id, or `None` for the idempotent duplicate.
///
/// # Errors
/// Record-stop and SQL failures propagate.
pub fn queue_proposal(conn: &Connection, proposal: &SupersessionProposal) -> Result<Option<String>> {
    super::record_stop::gate_storage_conn(conn)?;
    let duplicate: Option<String> = conn
        .query_row(
            "SELECT id FROM pending_actions WHERE action_type = ?1 AND status = 'pending' \
             AND memory_id = ?2 AND json_extract(payload, '$.new_id') = ?3 LIMIT 1",
            params![PENDING_ACTION_SUPERSEDE, proposal.old_id(), proposal.new_id()],
            |row| row.get(0),
        )
        .optional()?;
    if duplicate.is_some() {
        return Ok(None);
    }
    let namespace = super::namespace_by_id(conn, proposal.old_id())?
        .ok_or_else(|| anyhow::anyhow!(crate::errors::msg::MEMORY_NOT_FOUND))?;
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
        params![
            id,
            PENDING_ACTION_SUPERSEDE,
            proposal.old_id(),
            namespace,
            serde_json::to_string(&proposal.to_payload())?,
            AI_CURATOR,
            chrono::Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(Some(id))
}

/// Outcome of [`gate_before_approve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalGate {
    /// Not a supersession row: the surface keeps its ordinary path.
    NotSupersession,
    /// Authorized; the surface may approve and then call [`execute_with`].
    Proceed,
    /// Refused (already audited); the surface must NOT approve.
    Refused(SupersessionRefusal),
}

/// Shared structural checks (both backends): curator-queued row, parseable
/// payload, and a hardened principal that IS the approver the surface records.
pub(crate) fn proposal_of(
    pa: &PendingAction,
    approver_id: Option<&str>,
    request: SupersessionRequest<'_>,
) -> Result<SupersessionProposal, SupersessionRefusal> {
    if pa.requested_by != AI_CURATOR {
        return Err(SupersessionRefusal::StaleProposal);
    }
    let Some(principal) = request.principal else {
        return Err(SupersessionRefusal::UnauthenticatedPrincipal);
    };
    if approver_id.is_some_and(|approver| approver != principal.agent_id()) {
        return Err(SupersessionRefusal::UnauthenticatedPrincipal);
    }
    SupersessionProposal::from_payload(&pa.payload)
}

/// Read-only authority check every approve surface runs BEFORE approving.
///
/// # Errors
/// Pending-row lookup and row-read failures propagate.
pub fn gate_before_approve(
    conn: &Connection,
    pending_id: &str,
    approver_id: &str,
    request: SupersessionRequest<'_>,
) -> Result<ProposalGate> {
    let Some(pa) = super::get_pending_action(conn, pending_id)? else {
        return Ok(ProposalGate::NotSupersession);
    };
    if !is_supersession(&pa) {
        return Ok(ProposalGate::NotSupersession);
    }
    let refusal = match proposal_of(&pa, Some(approver_id), request) {
        Ok(proposal) => precheck_proposal(conn, &proposal, request)?,
        Err(reason) => Some(reason),
    };
    Ok(match refusal {
        None => ProposalGate::Proceed,
        Some(reason) => {
            super::supersession::audit_refusal(request, &pa, reason);
            ProposalGate::Refused(reason)
        }
    })
}

/// Execute an APPROVED pending row. A supersession replays through
/// [`resolve_proposal`] under `request`; every other type keeps the
/// principal-less [`super::execute_pending_action`].
///
/// # Errors
/// As [`super::execute_pending_action`]; a refused supersession returns the
/// typed [`SupersessionRefusal`] and leaves both rows untouched.
pub fn execute_with(
    conn: &Connection,
    pending_id: &str,
    request: SupersessionRequest<'_>,
) -> Result<Option<String>> {
    let pa = super::get_pending_action(conn, pending_id)?;
    match pa {
        Some(pa) if is_supersession(&pa) => execute_approved(conn, &pa, request),
        _ => super::execute_pending_action(conn, pending_id),
    }
}

fn execute_approved(
    conn: &Connection,
    pa: &PendingAction,
    request: SupersessionRequest<'_>,
) -> Result<Option<String>> {
    super::record_stop::gate_storage_conn(conn)?;
    if pa.status != "approved" {
        return Err(anyhow::Error::new(
            super::StorageError::PendingActionStateInvalid {
                pending_id: pa.id.clone(),
                status: pa.status.clone(),
            },
        ));
    }
    if let Err(e) = super::verify_payload_agent_id(pa) {
        super::emit_pending_action_event(
            conn,
            pa,
            super::EVENT_PENDING_ACTION_REFUSED_AGENT_ID_MISMATCH,
            None,
        );
        return Err(e);
    }
    let proposal = match proposal_of(pa, pa.decided_by.as_deref(), request) {
        Ok(proposal) => proposal,
        Err(reason) => {
            super::supersession::audit_refusal(request, pa, reason);
            super::emit_pending_action_event(conn, pa, EVENT_REFUSED_SUPERSESSION, None);
            return Err(anyhow::Error::new(reason));
        }
    };
    let result = resolve_proposal(conn, &proposal, request)?;
    if let Some(reason) = result.refusal {
        super::emit_pending_action_event(conn, pa, EVENT_REFUSED_SUPERSESSION, None);
        return Err(anyhow::Error::new(reason));
    }
    super::emit_pending_action_event(
        conn,
        pa,
        super::EVENT_PENDING_ACTION_APPROVED,
        pa.decided_by.as_deref(),
    );
    Ok(Some(result.id))
}
