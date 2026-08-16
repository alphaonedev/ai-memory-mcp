// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2994 — the coordination write plane (actions / signals / checkpoints /
//! routines) bypasses the memory-lane storage funnel, so it needs its own
//! caller-origin credential screen. This exercises the shared enforcement
//! primitives (`secret_screen::screen_{text,json}_field_for_caller`) that the
//! four MCP create handlers + `handlers::coordination::send_signal` are wired
//! to call, under the certified `SECRET_SCREEN_MODE=refuse` posture.
//!
//! It lives in its OWN integration-test binary (not a lib unit test) because
//! `set_screen_mode` seeds a process-wide `OnceLock` (first-writer-wins): a
//! `Refuse` seed inside the shared lib-test binary would leak into unrelated
//! tests that store credential-shaped fixtures (`federation::receive_auth`,
//! `identity::cid`, `handlers::admin`, …) and false-refuse them. A dedicated
//! binary is its own process, so the seed is contained — the subprocess-
//! isolation discipline the posture-test env-leak class (#2905) established.

use ai_memory::secret_screen::{
    SecretScreenMode, screen_json_field_for_caller, screen_text_field_for_caller, set_screen_mode,
};
use serde_json::json;

/// An `AKIA…` AWS access-key id (the exact anchored shape the screen fires on).
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn seed_refuse() {
    // Idempotent first-writer-wins; every test in this binary seeds the same
    // value so ordering does not matter.
    set_screen_mode(SecretScreenMode::Refuse);
    assert_eq!(
        ai_memory::secret_screen::screen_mode(),
        SecretScreenMode::Refuse,
        "this binary must run under the refuse posture"
    );
}

#[test]
fn refuse_mode_refuses_a_credential_in_a_text_field() {
    seed_refuse();
    let mut title = format!("deploy with aws_access_key_id = {AWS_KEY}");
    let err = screen_text_field_for_caller(&mut title)
        .expect_err("a credential in a coordination text field must be refused under refuse mode");
    assert!(
        err.to_string().contains("credential"),
        "refusal names credential material: {err}"
    );
    // The field is NOT mutated on a refusal — the caller write is rejected whole.
    assert!(title.contains(AWS_KEY), "refuse does not mutate the field");
}

#[test]
fn refuse_mode_passes_a_benign_text_field() {
    seed_refuse();
    let mut title = "ship the v1.0.0 release".to_string();
    screen_text_field_for_caller(&mut title).expect("benign text passes");
    assert_eq!(
        title, "ship the v1.0.0 release",
        "benign text is byte-identical"
    );
}

#[test]
fn refuse_mode_refuses_a_credential_in_a_json_body_leaf() {
    seed_refuse();
    let mut body = json!({
        "step": "provision",
        "creds": { "aws_access_key_id": AWS_KEY },
    });
    let err = screen_json_field_for_caller(&mut body)
        .expect_err("a credential in a coordination JSON body leaf must be refused");
    assert!(
        err.to_string().contains("credential"),
        "refusal names it: {err}"
    );
}

#[test]
fn refuse_mode_passes_a_benign_json_body_and_preserves_carveout_keys() {
    seed_refuse();
    // `agent_id` is a crypto/system carve-out key — its (non-credential) value
    // is never screened, so a legitimate id survives even under refuse mode.
    let mut body = json!({
        "task": "reflect",
        "agent_id": "ai:worker-1",
        "count": 3,
    });
    screen_json_field_for_caller(&mut body).expect("benign body passes");
    assert_eq!(body["agent_id"].as_str(), Some("ai:worker-1"));
    assert_eq!(body["count"].as_i64(), Some(3));
}
