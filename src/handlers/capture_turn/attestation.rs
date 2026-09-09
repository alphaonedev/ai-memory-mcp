// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3406 — HTTP admission for an already-verified legacy host envelope.
//! This is not a SignableWrite: only session, turn, role and content are
//! signed. Durable turn dedup provides idempotency; the timestamp-based
//! attested-write ledger cannot protect this envelope's unsigned timestamp.

use super::{AppState, MemoryCaptureTurnRequest};
use crate::identity::attest::{WriteSurface, require_agent_attestation_for};
use crate::models::{AttestLevel, CaptureTurnWrite};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub(super) fn refusal(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "code": crate::errors::error_codes::ATTESTATION_FAILED,
            "error": message,
        })),
    )
        .into_response()
}

/// Called only after `prepare_capture_turn` has checked the signature,
/// paired fields, and the host-key allowlist. No host assertion alone can
/// authorize use of another agent's identity, including in permissive mode.
pub(super) async fn admit(
    app: &AppState,
    req: &MemoryCaptureTurnRequest,
    write: &CaptureTurnWrite,
    caller: &str,
) -> Result<AttestLevel, Response> {
    let Some(presented) = req.host_pubkey_b64.as_deref() else {
        if require_agent_attestation_for(WriteSurface::HttpDirect) {
            return Err(refusal(
                StatusCode::FORBIDDEN,
                "HTTP capture requires a host signature bound to the caller; unsigned direct writes are refused.",
            ));
        }
        audit_unsigned_opt_out(write, caller);
        return Ok(AttestLevel::SelfSigned);
    };

    #[cfg(feature = "sal")]
    let bound = app.store.agent_pubkey(caller).await.map_err(|_| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "Cannot resolve the caller's bound host key; capture refused.",
        )
    })?;
    #[cfg(not(feature = "sal"))]
    let bound = {
        let lock = app.db.lock().await;
        crate::db::agent_pubkey(&lock.0, caller).map_err(|_| {
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "Cannot resolve the caller's bound host key; capture refused.",
            )
        })?
    };

    let matches = bound.as_deref().is_some_and(|bound| {
        let decode = crate::identity::keypair::decode_public_base64;
        match (decode(presented), decode(bound)) {
            (Ok(presented), Ok(bound)) => presented == bound,
            _ => false,
        }
    });
    if !matches {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "The verified host key is not bound to the resolved caller; capture refused.",
        ));
    }
    Ok(AttestLevel::SignedByPeer)
}

fn audit_unsigned_opt_out(write: &CaptureTurnWrite, caller: &str) {
    use crate::audit::{AuditAction, AuditActor, AuditTarget, EventBuilder};
    crate::audit::emit(EventBuilder::new(
        AuditAction::Store,
        AuditActor {
            agent_id: caller.to_string(),
            scope: None,
            synthesis_source: crate::audit::synthesis_sources::HTTP_HEADER.to_string(),
        },
        AuditTarget {
            memory_id: write.memory.id.clone(),
            namespace: write.memory.namespace.clone(),
            title: Some("capture_turn: unsigned HTTP attestation opt-out".to_string()),
            tier: Some(write.memory.tier.as_str().to_string()),
            scope: None,
        },
    ));
}
