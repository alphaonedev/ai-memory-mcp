// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Public SQLite CLI and MCP registration surfaces cannot replace an identity.
//! HTTP/SAL PostgreSQL twins are exercised in `issue_1539_bind_pubkey_route`.

use ai_memory::cli::agents::{AgentsAction, AgentsArgs};
use ai_memory::identity::keypair::{AgentKeypair, generate};
use ai_memory::identity::pubkey_bind::sign_bind_challenge;
use serde_json::json;

fn offline_proof(
    conn: &rusqlite::Connection,
    path: &std::path::Path,
    agent: &str,
    key: &AgentKeypair,
) {
    let challenge =
        ai_memory::db::issue_pubkey_bind_challenge(conn, agent, &key.public_base64(), "test-3464")
            .expect("challenge");
    let signature = sign_bind_challenge(key.private.as_ref().expect("private key"), &challenge);
    std::fs::write(path, serde_json::to_vec(&json!({
        "nonce": challenge.nonce_b64, "expires_at": challenge.expires_at, "signature_b64": signature,
    })).expect("proof JSON")).expect("proof file");
}

#[test]
fn cli_wrong_agent_and_closed_history_refuse_candidate_proof_3464() {
    let dir = tempfile::tempdir().expect("scratch");
    let path = dir.path().join("identity.db");
    let conn = ai_memory::db::open(&path).expect("database");
    let victim = "ai:surface-victim";
    let other = "ai:surface-other";
    for agent in [victim, other] {
        ai_memory::db::register_agent(&conn, agent, "ai:generic", &[]).expect("register");
    }
    let key = generate(victim).expect("key");
    let attacker = generate("ai:surface-admin").expect("attacker key");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, victim, &key).expect("bootstrap");
    let wrong = dir.path().join("wrong.json");
    offline_proof(&conn, &wrong, other, &key);
    let run = |proof_file, candidate: &AgentKeypair| {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        ai_memory::cli::agents::run_agents(
            &path,
            AgentsArgs {
                action: Some(AgentsAction::BindKey {
                    agent_id: victim.to_string(),
                    pubkey: candidate.public_base64(),
                    proof_file: Some(proof_file),
                }),
            },
            true,
            &mut output,
        )
    };
    assert!(
        run(wrong, &key).is_err(),
        "wrong-agent proof cannot reassert victim"
    );
    ai_memory::db::revoke_agent_pubkey(&conn, victim).expect("revoke");
    for (name, candidate) in [("owner.json", &key), ("attacker.json", &attacker)] {
        let proof = dir.path().join(name);
        offline_proof(&conn, &proof, victim, candidate);
        assert!(
            run(proof, candidate).is_err(),
            "candidate proof cannot reopen revoked identity"
        );
    }
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, victim).expect("flat key"),
        None
    );
    let history = ai_memory::db::agent_pubkey_versions(&conn, victim).expect("history");
    assert_eq!(history.len(), 1);
    assert!(history[0].superseded_at.is_some());
}

#[test]
fn mcp_registration_cannot_inject_candidate_or_reopen_history_3464() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("database");
    let victim = "ai:mcp-victim";
    let key = generate(victim).expect("key");
    let attacker = generate("ai:mcp-admin").expect("attacker");
    ai_memory::db::register_agent(&conn, victim, "ai:generic", &[]).expect("register");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, victim, &key).expect("bootstrap");
    for closed in [false, true] {
        if closed {
            ai_memory::db::revoke_agent_pubkey(&conn, victim).expect("revoke");
        }
        let request = json!({
            "agent_id": victim, "agent_type": "ai:generic",
            "agent_pubkey": attacker.public_base64(),
            "metadata": {"agent_pubkey": attacker.public_base64()},
            "pubkey_b64": attacker.public_base64(), "proof_b64": "candidate-proof-is-not-lineage",
        });
        ai_memory::mcp::handle_agent_register(&conn, &request).expect("registration refresh");
        let expected = if closed {
            None
        } else {
            Some(key.public_base64())
        };
        assert_eq!(
            ai_memory::db::agent_pubkey(&conn, victim).expect("current"),
            expected
        );
        let history = ai_memory::db::agent_pubkey_versions(&conn, victim).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].pubkey_b64, key.public_base64());
        assert_eq!(history[0].superseded_at.is_some(), closed);
    }
}
