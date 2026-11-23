// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9996 / #10037 — shared helpers for suites that pull `/sync/since`.
//!
//! The pull path serves a row only to an AUTHENTICATED peer whose outbound
//! scope (`AI_MEMORY_FED_PEER_OUTBOUND_SCOPE`) names it: the id bound to the mTLS
//! client certificate, else an `X-Peer-Id` whose request signature verified
//! against an enrolled key. A bare header authenticates nobody and gets the
//! empty `outbound_scope_deny` page. Suites that pin the attestation,
//! visibility or watermark behaviour BEHIND that gate use this module to
//! become a signed, scoped peer, so their own assertions stay as they were.
//!
//! Include with `#[path = "common/signed_pull.rs"] mod signed_pull;` (a leaf
//! module: it does not pull in `common/mod.rs`). Every function that changes
//! the environment must be called while the suite's env lock is held.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]

use ai_memory::federation::outbound_scope::OUTBOUND_SCOPE_ENV;
use ai_memory::federation::signing::{NONCE_HEADER, SIGNATURE_HEADER, sign_body_with_nonce_header};
use ai_memory::identity::keypair as kp_mod;

/// The key directory the daemon-key loader reads.
pub const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";
/// The `/sync/since` route path (the path the signature binds).
pub const SYNC_SINCE_PATH: &str = "/api/v1/sync/since";
/// The pulling peer's push-lane URL: the key of its outbound-scope entry.
pub const PULL_PEER_URL: &str = "https://pull-peer.sync-since-9996.invalid:9077";

/// Enrolled pulling peers: each id's public key sits in a private (0700)
/// key directory that `AI_MEMORY_KEY_DIR` points at, and the private halves
/// stay here to sign the pulls.
pub struct EnrolledPullers {
    key_dir: tempfile::TempDir,
    keys: Vec<kp_mod::AgentKeypair>,
}

impl EnrolledPullers {
    /// Enrol every id in `peer_ids` and point `AI_MEMORY_KEY_DIR` at the
    /// key directory. Call with the suite's env lock held.
    #[must_use]
    pub fn enrol(peer_ids: &[&str]) -> Self {
        let key_dir = tempfile::TempDir::new().expect("signed_pull: key tempdir");
        // The key-dir guard (#3198) refuses a group-writable directory.
        std::fs::set_permissions(
            key_dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("signed_pull: chmod 0700 the key dir");
        let mut keys = Vec::with_capacity(peer_ids.len());
        for id in peer_ids {
            let kp = kp_mod::generate(id).expect("signed_pull: generate keypair");
            let public_only = kp_mod::AgentKeypair {
                agent_id: kp.agent_id.clone(),
                public: kp.public,
                private: None,
            };
            kp_mod::save_public_only(&public_only, key_dir.path())
                .expect("signed_pull: enrol the public key");
            keys.push(kp);
        }
        // SAFETY: env mutation under the caller's env lock.
        unsafe { std::env::set_var(KEY_DIR_ENV, key_dir.path()) };
        Self { key_dir, keys }
    }

    /// The key directory (for suites that enrol more keys themselves).
    #[must_use]
    pub fn key_dir(&self) -> &std::path::Path {
        self.key_dir.path()
    }

    /// Add the `X-Memory-Sig` and `X-Memory-Nonce` headers that sign a
    /// `GET <path>?<query>` as `peer_id`. The id must be enrolled here.
    #[must_use]
    pub fn sign_get(
        &self,
        builder: axum::http::request::Builder,
        peer_id: &str,
        path: &str,
        query: &str,
    ) -> axum::http::request::Builder {
        let key = self
            .keys
            .iter()
            .find(|k| k.agent_id == peer_id)
            .and_then(|k| k.private.as_ref())
            .unwrap_or_else(|| panic!("signed_pull: {peer_id} is not enrolled"));
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"GET\n");
        canonical.extend_from_slice(path.as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(query.as_bytes());
        let nonce = uuid::Uuid::new_v4().to_string();
        builder
            .header(
                SIGNATURE_HEADER,
                sign_body_with_nonce_header(key, &canonical, &nonce),
            )
            .header(NONCE_HEADER, nonce)
    }
}

/// The outbound-scope config that lets `peer_ids` receive every namespace
/// (`["**"]`, the explicit all-namespaces scope) under one push-lane entry.
#[must_use]
pub fn outbound_scope_all(peer_ids: &[&str]) -> String {
    serde_json::json!({
        PULL_PEER_URL: {
            "allowed_namespaces": ["**"],
            "peer_ids": peer_ids,
        }
    })
    .to_string()
}

/// Set the all-namespaces outbound scope for `peer_ids`. Call with the
/// suite's env lock held.
pub fn set_outbound_scope_all(peer_ids: &[&str]) {
    // SAFETY: env mutation under the caller's env lock.
    unsafe { std::env::set_var(OUTBOUND_SCOPE_ENV, outbound_scope_all(peer_ids)) };
}

/// Remove the outbound scope and the key directory pin.
pub fn clear() {
    // SAFETY: env mutation under the caller's env lock.
    unsafe {
        std::env::remove_var(OUTBOUND_SCOPE_ENV);
        std::env::remove_var(KEY_DIR_ENV);
    }
}
