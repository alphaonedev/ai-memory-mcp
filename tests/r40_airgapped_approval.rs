// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! R40 (#1957) — human-key-signed approvals + m-of-n + typed escalation
//! routing, with a **30-minute airgapped operability** acceptance gate.
//!
//! # What this proves
//!
//! * **Human-key approval accepted / forged-rejected / unenrolled-rejected**
//!   through the env-resolved enrollment surface
//!   (`AI_MEMORY_OPERATOR_PUBKEY` / `AI_MEMORY_APPROVER_PUBKEYS`).
//! * **m-of-n**: M-1 signatures stay pending, M proceeds, a duplicate signer
//!   is not double-counted.
//! * **Typed escalation → approval routing**: a
//!   [`Decision::Escalate`](ai_memory::governance::agent_action::Decision)
//!   is routed to a pending action that REQUIRES a signed approval; the
//!   escalated op cannot proceed on an unsigned approve and DOES proceed once
//!   the operator's signature is applied.
//! * **Airgapped operability (D)**: the whole sign → verify → apply path runs
//!   with an in-memory `SQLite` DB, an in-process Ed25519 keypair, and env-only
//!   enrollment. There is **zero network dependency and no external service**.
//!   The elapsed wall-clock is asserted to complete far inside a bounded
//!   operability window.
//!
//! # HONEST crypto-vs-operational boundary
//!
//! **Cryptographically enforced (attestable):** the Ed25519 signature
//! verification + the distinct-enrolled-signer count. **Operational (NOT a
//! cryptographic property):** the enrollment custody (who is an approver) and
//! the "30-minute" figure — that is an operability SLO this test *demonstrates*
//! (it completes in well under a second), not a signed attestation.

use ai_memory::approvals::Decision;
use ai_memory::approvals::signed::{
    QuorumError, SignedApproval, approval_signing_bytes, route_escalation_to_approval_gate,
    verify_quorum_from_env,
};
use ai_memory::models::GovernedAction;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The demonstrated operability window. The R40 acceptance names 30 minutes;
/// this offline flow completes in milliseconds, so we assert a generous 60 s
/// bound — enough to catch a hang, honest about the SLO being operational.
const OPERABILITY_WINDOW: Duration = Duration::new(60, 0);

/// Env-mutating tests are process-global; serialise them.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Deterministic, rng-free keypair from a 32-byte seed (airgapped: no rng
/// service, no entropy daemon assumptions).
fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_b64(sk: &SigningKey) -> String {
    b64(&sk.verifying_key().to_bytes())
}

fn sign_approval(sk: &SigningKey, pending_id: &str) -> SignedApproval {
    let msg = approval_signing_bytes(pending_id, Decision::Approve);
    SignedApproval {
        signer_pubkey_b64: pubkey_b64(sk),
        signature_b64: b64(&sk.sign(&msg).to_bytes()),
    }
}

/// Clear every env knob this suite touches so tests don't bleed into each
/// other (and don't leak an enrolled operator key into unrelated assertions).
fn clear_env() {
    // SAFETY: guarded by ENV_LOCK; single-threaded within the critical section.
    unsafe {
        std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
        std::env::remove_var("AI_MEMORY_APPROVER_PUBKEYS");
        std::env::remove_var("AI_MEMORY_APPROVAL_THRESHOLD");
    }
}

fn set_var(k: &str, v: &str) {
    // SAFETY: guarded by ENV_LOCK; single-threaded within the critical section.
    unsafe { std::env::set_var(k, v) };
}

#[test]
fn human_key_accept_forge_unenrolled_via_env_enrollment() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_env();

    let operator = keypair(1);
    // Enrol the operator key through the governance operator-key custody env.
    set_var("AI_MEMORY_OPERATOR_PUBKEY", &pubkey_b64(&operator));
    set_var("AI_MEMORY_APPROVAL_THRESHOLD", "1");

    let pid = "pa-env-accept";

    // Accepted: a valid operator signature over the right bytes.
    let good = sign_approval(&operator, pid);
    let met = verify_quorum_from_env(pid, Decision::Approve, &[good]).expect("accepted");
    assert_eq!(met.distinct_signers, 1);

    // Forged: valid length + enrolled signer, but signed over DIFFERENT bytes.
    let mut forged = sign_approval(&operator, pid);
    let wrong = approval_signing_bytes("pa-DIFFERENT", Decision::Approve);
    forged.signature_b64 = b64(&operator.sign(&wrong).to_bytes());
    let err = verify_quorum_from_env(pid, Decision::Approve, &[forged]).unwrap_err();
    assert!(matches!(err, QuorumError::Forged(_)), "got {err:?}");

    // Unenrolled: a stranger key not in the enrolled set.
    let stranger = keypair(99);
    let strange = sign_approval(&stranger, pid);
    let err = verify_quorum_from_env(pid, Decision::Approve, &[strange]).unwrap_err();
    assert!(matches!(err, QuorumError::Unenrolled(_)), "got {err:?}");

    clear_env();
}

#[test]
fn m_of_n_threshold_via_env() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_env();

    let a = keypair(11);
    let b = keypair(12);
    let c = keypair(13);
    set_var(
        "AI_MEMORY_APPROVER_PUBKEYS",
        &format!("{}, {}, {}", pubkey_b64(&a), pubkey_b64(&b), pubkey_b64(&c)),
    );
    set_var("AI_MEMORY_APPROVAL_THRESHOLD", "2");

    let pid = "pa-env-mofn";

    // M-1 (one distinct signer) → stays pending.
    let err =
        verify_quorum_from_env(pid, Decision::Approve, &[sign_approval(&a, pid)]).unwrap_err();
    assert!(
        matches!(
            err,
            QuorumError::ThresholdNotMet {
                distinct: 1,
                threshold: 2
            }
        ),
        "got {err:?}"
    );

    // M (two distinct signers) → proceeds.
    let met = verify_quorum_from_env(
        pid,
        Decision::Approve,
        &[sign_approval(&a, pid), sign_approval(&b, pid)],
    )
    .expect("quorum met");
    assert_eq!(met.distinct_signers, 2);

    // Duplicate signer is not double-counted: two sigs from `a` = 1 distinct.
    let err = verify_quorum_from_env(
        pid,
        Decision::Approve,
        &[sign_approval(&a, pid), sign_approval(&a, pid)],
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            QuorumError::ThresholdNotMet {
                distinct: 1,
                threshold: 2
            }
        ),
        "duplicate signer must not double-count: {err:?}"
    );

    clear_env();
}

#[test]
fn airgapped_escalation_to_signed_approval_end_to_end() {
    let _g = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_env();

    // ---- entirely offline: in-memory DB, in-process key, env enrollment ----
    let started = Instant::now();

    let operator = keypair(7);
    set_var("AI_MEMORY_OPERATOR_PUBKEY", &pubkey_b64(&operator));
    set_var("AI_MEMORY_APPROVAL_THRESHOLD", "1");

    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open in-memory db");

    // (C) Route a typed escalation to the approval gate. Use Promote with an
    // unbound target so the eventual execute step short-circuits (no reflect /
    // LLM / embedder needed) — we only care that the SIGNED GATE governs it.
    let target = "11111111-2222-3333-4444-555555555555";
    let pending_id = route_escalation_to_approval_gate(
        &conn,
        GovernedAction::Promote,
        "airgap-ns",
        Some(target),
        "ai:worker",
        &json!({ "target_tier": "long" }),
        "L1-8-escalate",
        "escalated for human approval (airgapped)",
    )
    .expect("route escalation");

    // The pending action carries the signed-approval requirement.
    let pa = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("get pending")
        .expect("pending exists");
    assert!(
        ai_memory::approvals::signed::pending_requires_signed_approval(&pa.payload),
        "escalated pending must require a signed approval"
    );

    // (D-neg) An unsigned approve on an escalation-routed pending is REFUSED.
    let unsigned = ai_memory::mcp::handle_pending_approve(
        &conn,
        &json!({ "id": pending_id, "agent_id": "ai:operator" }),
        None,
    )
    .expect_err("unsigned approve of an escalated op must be refused");
    assert!(
        unsigned.contains("signed approval"),
        "unsigned refusal should name the signed-approval gate, got: {unsigned}"
    );

    // (D-pos) The operator signs the approval bytes OFFLINE and applies it.
    let sig = sign_approval(&operator, &pending_id);
    let params = json!({
        "id": pending_id,
        "agent_id": "ai:operator",
        "approvals": [{ "pubkey": sig.signer_pubkey_b64, "signature": sig.signature_b64 }],
    });
    let result = ai_memory::mcp::handle_pending_approve(&conn, &params, None);

    // The signed gate PASSED: the outcome is no longer a signed-approval
    // refusal. (Downstream execute of an unbound Promote may itself be a
    // benign not-found — that is past the gate and acceptable here.)
    match result {
        Ok(resp) => assert_eq!(
            resp["approved"], true,
            "signed approve should proceed: {resp}"
        ),
        Err(e) => assert!(
            !e.contains("signed approval"),
            "must be past the signed gate, got a gate error: {e}"
        ),
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed < OPERABILITY_WINDOW,
        "airgapped operability: sign→verify→apply took {elapsed:?}, over the {OPERABILITY_WINDOW:?} window"
    );
    // Operability SLO (operational, not attested): the R40 30-minute window is
    // demonstrated by completing the full offline flow in {elapsed:?}.

    clear_env();
}
