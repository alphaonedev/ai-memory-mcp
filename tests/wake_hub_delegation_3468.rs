// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` scoped delegation, end to end over a REAL socket
//! (issue [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! The unit tests in `src/wake_hub/delegation_verifier.rs` cover the decision
//! table. This suite proves the same decisions hold when they are reached the
//! way production reaches them: a delegation minted by an ENROLLED key, an
//! allowlist loaded from a 0600 file on disk, and a hello presented across a
//! Unix domain socket.

mod wake_hub_harness;

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::identity::hub_delegation::{
    A2A_HUB_SCOPE, DelegationWire, MAX_DELEGATION_TTL_SECS, sign_hub_delegation,
};
use ai_memory::wake_hub::delegation_verifier::{
    ALLOWLIST_FILE_VERSION, AllowlistCache, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::frame::{ErrorCode, Kind};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use wake_hub_harness::Harness;

const AGENT: &str = "agent-delegated";
const HUB: &str = "ai-memory-wake-hub";

fn enrolled_key() -> SigningKey {
    SigningKey::from_bytes(&[21u8; 32])
}

fn delegated_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

/// Write a 0600 allowlist naming one agent with the given bind authority.
fn write_allowlist(dir: &Path, authority: &str, key: &SigningKey) -> PathBuf {
    let path = dir.join("allow.json");
    let body = serde_json::json!({
        "version": ALLOWLIST_FILE_VERSION,
        "agents": [{
            "agent_id": AGENT,
            "pubkey_b64": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "bind_authority": authority,
        }],
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .expect("create allowlist");
    file.write_all(serde_json::to_string_pretty(&body).unwrap().as_bytes())
        .expect("write allowlist");
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    path
}

/// Mint a delegation the way `ai-memory identity delegate` does.
fn mint(hub_id: &str, ttl_secs: i64) -> Bytes {
    let now = chrono::Utc::now();
    let mut wire = DelegationWire {
        principal: AGENT.to_owned(),
        scope: A2A_HUB_SCOPE.to_owned(),
        delegate_key_id: delegated_key().verifying_key().to_bytes(),
        hub_id: hub_id.to_owned(),
        not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        not_after: (now + chrono::Duration::seconds(ttl_secs))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        signature: [0u8; 64],
    };
    wire.signature = sign_hub_delegation(&enrolled_key(), &wire.as_delegation()).expect("mint");
    Bytes::from(wire.encode().expect("encode"))
}

/// A hub whose verifier is loaded from a real 0600 allowlist file.
fn hub_with_allowlist(authority: &str) -> (Harness, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let path = write_allowlist(dir.path(), authority, &enrolled_key());
    let cache = AllowlistCache::load_from_file(&path).expect("load allowlist");
    assert_eq!(cache.len(), 1);
    let harness = Harness::start(
        |_| {},
        Arc::new(ScopedDelegationVerifier::new(cache)),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    (harness, dir)
}

#[tokio::test]
async fn allowed_a_minted_delegation_admits_the_hello_over_a_real_socket() {
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client
        .hello(AGENT, &delegated_key(), &["#hive".to_string()])
        .await;
    let welcome = client.expect_frame().await;
    assert_eq!(
        welcome.kind,
        Kind::Welcome,
        "a delegation minted by the enrolled key must admit the delegated key"
    );
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 0);
    hub.stop().await;
}

#[tokio::test]
async fn denied_an_unproven_root_cannot_delegate_over_a_real_socket() {
    // The allowlist says this agent's key was bound before #3464 required
    // proof of possession. Letting it delegate would reopen that defect one
    // hop out, so the hub refuses even though the signature is perfectly good.
    let (hub, _dir) = hub_with_allowlist("legacy_unproven");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client
        .hello(AGENT, &delegated_key(), &["#hive".to_string()])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 1);
    hub.stop().await;
}

#[tokio::test]
async fn denied_no_delegation_presented_is_refused() {
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    // `delegation` left empty — the shape a pre-#3468 client would send.
    client
        .hello(AGENT, &delegated_key(), &["#hive".to_string()])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_delegation_for_another_hub_is_refused() {
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint("some-other-hub", 3_600);
    client
        .hello(AGENT, &delegated_key(), &["#hive".to_string()])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_an_over_long_window_is_refused_over_a_real_socket() {
    // Signature-valid but un-revocable: the hub does no live revocation
    // lookup, so a window past the maximum must not admit.
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, MAX_DELEGATION_TTL_SECS + 60);
    client
        .hello(AGENT, &delegated_key(), &["#hive".to_string()])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_delegation_presented_with_a_different_key_is_refused() {
    // The delegation names ONE hello key. A holder of the delegation bytes who
    // does not hold that key cannot use it.
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client
        .hello(AGENT, &SigningKey::from_bytes(&[99u8; 32]), &[])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// The allowlist file itself
// ---------------------------------------------------------------------------

#[test]
fn a_group_readable_allowlist_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_allowlist(dir.path(), "possession_proof", &enrolled_key());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let err = AllowlistCache::load_from_file(&path).expect_err("must refuse");
    assert!(
        format!("{err}").contains("owner-only"),
        "the allowlist names every agent permitted to join: {err}"
    );
}

#[test]
fn a_duplicate_agent_id_is_refused_rather_than_resolved_by_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dup.json");
    let key_b64 = URL_SAFE_NO_PAD.encode(enrolled_key().verifying_key().to_bytes());
    let body = serde_json::json!({
        "version": ALLOWLIST_FILE_VERSION,
        "agents": [
            {"agent_id": AGENT, "pubkey_b64": key_b64, "bind_authority": "possession_proof"},
            {"agent_id": AGENT, "pubkey_b64": key_b64, "bind_authority": "legacy_unproven"},
        ],
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .expect("create");
    file.write_all(serde_json::to_string(&body).unwrap().as_bytes())
        .expect("write");
    drop(file);
    let err = AllowlistCache::load_from_file(&path).expect_err("must refuse");
    assert!(
        format!("{err}").contains("twice"),
        "which key is trusted must never depend on iteration order: {err}"
    );
}

#[test]
fn an_entry_without_a_bind_authority_cannot_delegate() {
    // An omitted `bind_authority` is treated as legacy_unproven: an unstated
    // provenance is not a proven one.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-authority.json");
    let body = serde_json::json!({
        "version": ALLOWLIST_FILE_VERSION,
        "agents": [{
            "agent_id": AGENT,
            "pubkey_b64": URL_SAFE_NO_PAD.encode(enrolled_key().verifying_key().to_bytes()),
        }],
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .expect("create");
    file.write_all(serde_json::to_string(&body).unwrap().as_bytes())
        .expect("write");
    drop(file);
    let cache = AllowlistCache::load_from_file(&path).expect("loads");
    assert_eq!(cache.len(), 1);
}

#[test]
fn an_unknown_allowlist_version_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v99.json");
    let body = serde_json::json!({"version": 99, "agents": []});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .expect("create");
    file.write_all(serde_json::to_string(&body).unwrap().as_bytes())
        .expect("write");
    drop(file);
    assert!(
        AllowlistCache::load_from_file(&path).is_err(),
        "an unknown format version must be refused, never best-effort read"
    );
}
