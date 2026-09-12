// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3616: legacy freeze attestations refuse execution until explicitly re-frozen.

#![cfg(test)]

use crate::models::{Routine, RoutineState};
use ciborium::Value::{Bytes, Integer, Map, Text};
use ed25519_dalek::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn issue_3616_legacy_freeze_refuses_run_with_refreeze_remedy() -> anyhow::Result<()> {
    let conn = crate::storage::open(std::path::Path::new(":memory:"))?;
    let kp = crate::identity::keypair::generate("ai:routine3616")?;
    let mut routine = Routine {
        id: "routine3616".into(),
        namespace: "routine3616".into(),
        name: "upgrade".into(),
        template: json!({"actions": [{"kind": "work", "title": "must be attested"}]}),
        parameters: json!([]),
        state: RoutineState::Frozen,
        created_by: "ai:routine3616".into(),
        created_at: 1,
        frozen_at: Some(2),
        signature: vec![],
        signer_pubkey: kp.public.to_bytes().to_vec(),
        metadata: json!({}),
    };
    // Pin the pre-3616 canonical map independently of the production encoder.
    let legacy = Map(vec![
        (Text("name".into()), Text(routine.name.clone())),
        (Text("frozen_at".into()), Integer(2.into())),
        (Text("namespace".into()), Text(routine.namespace.clone())),
        (Text("routine_id".into()), Text(routine.id.clone())),
        (
            Text("template_sha256".into()),
            Bytes(Sha256::digest(routine.template.to_string().as_bytes()).to_vec()),
        ),
        (
            Text("parameters_sha256".into()),
            Bytes(Sha256::digest(routine.parameters.to_string().as_bytes()).to_vec()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&legacy, &mut bytes)?;
    let signature = kp
        .private
        .as_ref()
        .expect("generated signing key")
        .sign(&bytes);
    kp.public.verify_strict(&bytes, &signature)?;
    routine.signature = signature.to_bytes().to_vec();
    assert!(!crate::routines::verify(&routine));
    crate::routines::routine_insert(&conn, &routine)?;
    let params = json!({"routine_id": routine.id, "arguments": {}});
    let failed = super::handle_routine_run(&conn, &params).map_err(anyhow::Error::msg)?;
    assert_eq!(
        failed["run"]["state"], "failed",
        "legacy attestation must refuse execution"
    );
    let error = failed["error"].as_str().expect("operator-visible refusal");
    assert!(error.contains("re-freeze"), "missing remedy: {error}");
    assert!(
        error.contains("memory_routine_freeze"),
        "missing tool: {error}"
    );
    assert_eq!(
        failed["run"]["error"], error,
        "persist the remedy for status readers"
    );
    assert_eq!(failed["run"]["created_action_ids"], json!([]));
    let status = super::handle_routine_status(&conn, &json!({"run_id": failed["run"]["id"]}))
        .map_err(anyhow::Error::msg)?;
    assert_eq!(status["run"]["state"], "failed");
    assert_eq!(status["run"]["error"], error);
    let actions: i64 = conn.query_row("SELECT count(*) FROM actions", [], |r| r.get(0))?;
    assert_eq!(actions, 0, "refusal must not materialize actions");

    // The documented remedy must work for an already-frozen persisted row.
    super::handle_routine_freeze(&conn, &json!({"id": routine.id}), Some(&kp))
        .map_err(anyhow::Error::msg)?;
    let repaired = crate::routines::routine_get(&conn, &routine.id)?.expect("persisted routine");
    assert!(crate::routines::verify(&repaired));
    assert_eq!(repaired.frozen_at, routine.frozen_at);
    let allowed = super::handle_routine_run(&conn, &params).map_err(anyhow::Error::msg)?;
    assert_eq!(allowed["run"]["state"], "completed");
    let actions: i64 = conn.query_row("SELECT count(*) FROM actions", [], |r| r.get(0))?;
    assert_eq!(actions, 1, "re-freezing restores execution");
    Ok(())
}
