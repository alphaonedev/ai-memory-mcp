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
    ALLOWLIST_FILE_VERSION, AllowlistCache, ReloadingAllowlist, ScopedDelegationVerifier,
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

/// The binding stamp every pre-#3540 fixture used: comfortably older than
/// anything the tests mint, so the binding-order check never bit.
const OLD_BOUND_AT: &str = "2026-09-01T00:00:00Z";

/// Write a 0600 allowlist naming one agent with the given bind authority.
fn write_allowlist(dir: &Path, authority: &str, key: &SigningKey) -> PathBuf {
    write_allowlist_bound_at(dir, authority, key, OLD_BOUND_AT)
}

/// [`write_allowlist`], with the entry's `bound_at` under the caller's control
/// so v1.0.0 #3540 can exercise the binding-order check with the SUB-SECOND
/// stamp a real `agents bind-key` / `identity hub-cache` row carries.
fn write_allowlist_bound_at(
    dir: &Path,
    authority: &str,
    key: &SigningKey,
    bound_at: &str,
) -> PathBuf {
    let path = dir.join("allow.json");
    let body = serde_json::json!({
        "version": ALLOWLIST_FILE_VERSION,
        "refreshed_at": chrono::Utc::now().to_rfc3339(),
        "agents": [{
            "agent_id": AGENT,
            "pubkey_b64": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "bind_authority": authority,
            "bound_at": bound_at,
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
    mint_at(hub_id, ttl_secs, chrono::Utc::now())
}

/// The whole-second instant `secs_ago` seconds back — the exact value a
/// second-floored `not_before` denotes, so a #3540 test can construct a
/// `bound_at` that provably lands in the SAME second (or a later one).
fn floored_secs_ago(secs_ago: i64) -> chrono::DateTime<chrono::Utc> {
    let base = chrono::Utc::now() - chrono::Duration::seconds(secs_ago);
    let rendered = base.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    chrono::DateTime::parse_from_rfc3339(&rendered)
        .expect("a second-floored stamp round-trips")
        .with_timezone(&chrono::Utc)
}

/// [`mint`], from an instant the caller pins, so #3540 can place `not_before`
/// in an exactly-known second relative to the binding it is judged against.
///
/// `not_before` stays WHOLE SECONDS — that is the format's own precision
/// (v1.0.0 #3511), and it is exactly what makes the binding-order comparison
/// second-granular.
fn mint_at(hub_id: &str, ttl_secs: i64, now: chrono::DateTime<chrono::Utc>) -> Bytes {
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
    hub_with_allowlist_bound_at(authority, OLD_BOUND_AT)
}

/// [`hub_with_allowlist`], with the entry's binding stamp under test control.
fn hub_with_allowlist_bound_at(authority: &str, bound_at: &str) -> (Harness, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let path = write_allowlist_bound_at(dir.path(), authority, &enrolled_key(), bound_at);
    let cache = AllowlistCache::load_from_file(&path).expect("load allowlist");
    assert_eq!(cache.len(), 1);
    let harness = Harness::start(
        |_| {},
        Arc::new(ScopedDelegationVerifier::new(
            ReloadingAllowlist::new(path).unwrap(),
        )),
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
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
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
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
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
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
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
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
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
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
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
        "refreshed_at": chrono::Utc::now().to_rfc3339(),
        "agents": [
            {"agent_id": AGENT, "pubkey_b64": key_b64, "bind_authority": "possession_proof", "bound_at": "2026-09-01T00:00:00Z"},
            {"agent_id": AGENT, "pubkey_b64": key_b64, "bind_authority": "legacy_unproven", "bound_at": "2026-09-01T00:00:00Z"},
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
        "refreshed_at": chrono::Utc::now().to_rfc3339(),
        "agents": [{
            "agent_id": AGENT,
            "pubkey_b64": URL_SAFE_NO_PAD.encode(enrolled_key().verifying_key().to_bytes()),
            "bound_at": "2026-09-01T00:00:00Z",
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

#[test]
fn allowlist_requires_exact_mode_and_never_follows_symlinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_allowlist(dir.path(), "possession_proof", &enrolled_key());
    for mode in [0o400, 0o700, 0o660, 0o1600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            AllowlistCache::load_from_file(&path).is_err(),
            "mode {mode:o}"
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(AllowlistCache::load_from_file(&link).is_err());
    assert!(AllowlistCache::load_from_file(&path).is_ok());
}

#[tokio::test]
async fn allowed_guardian_recovery_root_can_delegate() {
    let (hub, _dir) = hub_with_allowlist("guardian_recovery");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client.hello(AGENT, &delegated_key(), &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    hub.stop().await;
}

#[tokio::test]
async fn revoked_delegated_key_refuses_new_hellos_and_closes_idle_sessions() {
    let (hub, dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client.hello(AGENT, &delegated_key(), &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    let path = dir.path().join("allow.json");
    let mut cache = AllowlistCache::read_file(&path).unwrap();
    cache.agents[0]
        .revoked_keys
        .push(URL_SAFE_NO_PAD.encode(delegated_key().verifying_key().to_bytes()));
    ai_memory::identity::hub_cache::publish(&path, &cache).unwrap();
    let mut replay = hub.connect().await;
    replay.delegation = mint(HUB, 3_600);
    replay.hello(AGENT, &delegated_key(), &[]).await;
    replay.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn expired_cache_closes_an_idle_session_and_refuses_new_hellos() {
    let (hub, dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client.hello(AGENT, &delegated_key(), &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    let path = dir.path().join("allow.json");
    let mut cache = AllowlistCache::read_file(&path).unwrap();
    cache.refreshed_at = Some((chrono::Utc::now() - chrono::Duration::seconds(61)).to_rfc3339());
    ai_memory::identity::hub_cache::publish(&path, &cache).unwrap();
    client.expect_closed().await;
    let mut replay = hub.connect().await;
    replay.delegation = mint(HUB, 3_600);
    replay.hello(AGENT, &delegated_key(), &[]).await;
    replay.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    hub.stop().await;
}

#[tokio::test]
async fn subscription_cannot_expand_the_authenticated_namespace_read_scope() {
    let (hub, _dir) = hub_with_allowlist("possession_proof");
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client.hello(AGENT, &delegated_key(), &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    client
        .subscribe(&["#_inbox/another-agent".to_owned()])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    let mut client = hub.connect().await;
    client.delegation = mint(HUB, 3_600);
    client.hello(AGENT, &delegated_key(), &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    // #3532 — the own-inbox subscribe the verifier DOES admit is now
    // acknowledged in its own right, so acceptance is proved directly instead
    // of inferred from a ping that round-trips after it.
    client.subscribe_acked(&[format!("#_inbox/{AGENT}")]).await;
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// v1.0.0 #3540 — the binding-order check, over a REAL socket
// ---------------------------------------------------------------------------

/// ALLOWED: the SHIPPED ceremony — generate, register, bind-key, delegate, all
/// back to back — mints the delegation in the SAME wall-clock second as the
/// binding. The snapshot's `bound_at` carries sub-second precision; the
/// delegation's `not_before` is second-floored by the format. Before #3540 the
/// sub-second remainder alone refused every such hello (`delegation_invalid`),
/// which is what the #3473 acceptance run measured: 135 denials for 16 agents.
#[tokio::test]
async fn allowed_a_delegation_minted_in_the_binding_second_is_admitted_3540() {
    // Pin the second so the same-second case is exercised on EVERY run, not
    // only when the wall clock happens to cooperate: the delegation names
    // `issued`, and the binding lands half a second later INSIDE that second.
    let issued = floored_secs_ago(2);
    let bound_at = (issued + chrono::Duration::milliseconds(500)).to_rfc3339();
    let (hub, _dir) = hub_with_allowlist_bound_at("possession_proof", &bound_at);
    let mut client = hub.connect().await;
    client.delegation = mint_at(HUB, 3_600, issued);
    client
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    let welcome = client.expect_frame().await;
    assert_eq!(
        welcome.kind,
        Kind::Welcome,
        "bind-then-delegate inside one second is the documented ceremony; hub said {:?}",
        ai_memory::wake_hub::frame::decode_error(&welcome.payload)
    );
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 0);
    hub.stop().await;
}

/// DENIED, the twin: a delegation minted in an EARLIER second than the binding
/// is STILL refused. This is the property the check exists for — a bundle
/// harvested under a superseded root must not ride a newer binding — and the
/// #3540 precision fix must not widen past the second the delegation names.
#[tokio::test]
async fn denied_a_delegation_minted_before_the_binding_is_still_refused_3540() {
    let binding_second = floored_secs_ago(2);
    let bound_at = (binding_second + chrono::Duration::milliseconds(500)).to_rfc3339();
    let (hub, _dir) = hub_with_allowlist_bound_at("possession_proof", &bound_at);
    let mut client = hub.connect().await;
    // Five seconds BEFORE the binding: a different, strictly earlier second.
    client.delegation = mint_at(HUB, 3_600, binding_second - chrono::Duration::seconds(5));
    client
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    assert!(hub.metrics.snapshot(0).denied_hello >= 1);
    hub.stop().await;
}
