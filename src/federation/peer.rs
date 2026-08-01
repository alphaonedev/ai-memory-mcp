// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Peer construction and `FederationConfig::build`.

use std::time::Duration;

use crate::replication::QuorumPolicy;

use super::{FederationConfig, PeerEndpoint};

/// #1579 B5 — keep idle per-peer connections pooled for 5 minutes.
///
/// reqwest's default `pool_idle_timeout` is 90s. Federation traffic is
/// bursty: quorum pushes arrive on the operator's write cadence and
/// the DLQ replay / catchup workers tick on 30–60s intervals, so the
/// 90s default regularly evicted the warm connection between bursts
/// and the next push paid a fresh mTLS handshake (~4.3×RTT — 0.39s
/// cross-region vs ~0.09s reused, measured on do-1461, P3 leg 1/leg 2).
/// 5 minutes comfortably spans the worker cadences without holding
/// sockets forever on a reconfigured mesh.
const FED_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// #1579 B5 — OS-level TCP keepalive probes on pooled federation
/// connections, every 60s.
///
/// Deliberately conservative: PR #314 attempted `tcp_keepalive(1s)` +
/// `pool_idle_timeout(5s)` and ship-gate run 21 showed that
/// combination caused 40+ minute hangs from connection-pool churn +
/// per-socket probe traffic (see the revert note in
/// [`FederationConfig::build`]). 60s generates negligible probe load
/// while still detecting half-open connections (NAT/conntrack drops on
/// cross-region paths) well inside the 5-minute pool window, so a
/// dead pooled socket is reaped instead of donating a connect error to
/// the next quorum push.
const FED_CLIENT_TCP_KEEPALIVE: Duration = Duration::from_secs(60);

/// `tracing` target for federation peer-construction events. Hoisted to a
/// named const so the bare `"federation"` string lives at one site (the
/// pm-v3.1 no-hardcoded-literal discipline), referenced by name everywhere.
const FED_LOG_TARGET: &str = "federation";

impl FederationConfig {
    /// Build a `FederationConfig` from the serve-time CLI flags. Returns
    /// `None` when federation is disabled (`quorum_writes == 0` or the
    /// peer list is empty).
    ///
    /// `api_key` carries the local daemon's configured `[api] api_key`
    /// (issue #702, v0.7.0 fold-A2A1.4). When `Some`, every outbound
    /// federation POST attaches an `x-api-key` header so peers that
    /// themselves run with api-key auth accept the request. `None`
    /// preserves the backwards-compatible header set used by mTLS-only
    /// deployments — outbound POSTs stay unauthenticated at the
    /// application layer and rely on the TLS layer for trust.
    ///
    /// # Errors
    ///
    /// Returns an error if the reqwest client cannot be constructed
    /// with the supplied certificate material.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        quorum_writes: usize,
        peer_urls: &[String],
        timeout: Duration,
        client_cert_path: Option<&std::path::Path>,
        client_key_path: Option<&std::path::Path>,
        ca_cert_path: Option<&std::path::Path>,
        sender_agent_id: String,
        api_key: Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        if quorum_writes == 0 || peer_urls.is_empty() {
            return Ok(None);
        }
        // Ultrareview #341: reject duplicate peer URLs at build time.
        // If the same peer URL appears twice under different indices,
        // both would count as distinct ack sources and the quorum
        // guarantee is violated. Normalize (trim trailing slash,
        // lowercase scheme+host) before comparing.
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        for raw in peer_urls {
            // #2477 — refuse a peer that would carry PLAINTEXT memory
            // content off-host BEFORE anything else uses the URL. Pre-fix
            // this loop validated only for duplicates and the raw string
            // went straight into `sync_push_url`, so `http://peer:9077`
            // replicated content in the clear — trivially bypassing the
            // four-condition ceremony #2448 built for the strictly weaker
            // accept-any-server-cert case.
            //
            // Refusal is WHOLE-BOOT, never per-peer skip-and-continue:
            // `n = 1 + peer_urls.len()` below feeds `QuorumPolicy::new`, so
            // silently dropping a peer would change the quorum guarantee
            // without saying so — and `PeerEndpoint.id` is a positional
            // index (#2442), so a shrunken list also re-keys every DLQ row
            // above the gap.
            crate::tls::validate_peer_url_scheme(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
            let normalized = raw.trim_end_matches('/').to_ascii_lowercase();
            if !seen_urls.insert(normalized.clone()) {
                return Err(anyhow::anyhow!(
                    "duplicate peer URL in --quorum-peers: {raw} (normalized: {normalized}) \
                     — duplicates would let a single peer contribute to quorum more than once"
                ));
            }
        }
        let n = 1 + peer_urls.len(); // local node + remotes
        let policy = QuorumPolicy::new(n, quorum_writes, timeout, Duration::from_secs(30))
            .map_err(|e| anyhow::anyhow!("invalid quorum policy: {e}"))?;
        let peers: Vec<PeerEndpoint> = peer_urls
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                // `id` is used as a Prometheus metric label; keep it
                // low-cardinality. The full URL is logged separately.
                // (#304 nit — prior form `peer-{i}:{url}` blew up the
                // label space as deployment size grew.)
                let trimmed = raw.trim_end_matches('/');
                tracing::debug!(
                    target: FED_LOG_TARGET,
                    peer_index = i,
                    url = trimmed,
                    "registered peer"
                );
                PeerEndpoint {
                    id: format!("peer-{i}"),
                    sync_push_url: format!("{trimmed}/api/v1/sync/push"),
                }
            })
            .collect();

        // Federation client tuning.
        //
        // An earlier PR #314 attempted tight `tcp_keepalive(1s)` +
        // `pool_idle_timeout(5s)` on this builder to close the Phase
        // 4 partition_minority convergence gap. Ship-gate run 21
        // showed that combination caused Phase 4 to hang for 40+
        // minutes — suspected cause was connection-pool churn on the
        // chaos-client's local 3-process mesh exhausting ephemeral
        // ports under continuous close+reopen cycles with the tight
        // keepalive generating probe traffic on every idle socket.
        //
        // Reverted to the conservative-default client here. Partition-
        // recovery under chaos is moved out of the required ship-gate
        // and into an opt-in campaign shape. Real partition resilience
        // is a v0.6.0.1+ investigation with instrumented cycle data
        // (cycles_by_fault now landed in ship-gate, giving us per-cycle
        // visibility the next time we attempt this).
        //
        // #1579 B5 (2026-06-10) — persistent outbound connections. This
        // single client is shared by every outbound federation surface
        // (quorum push, bulk catchup, DLQ replay, /sync/since pull), so
        // tuning it is the one-stop connection-lifecycle fix. The two
        // knobs below are an order of magnitude more conservative than
        // the reverted #314 attempt (300s/60s vs 5s/1s) — they EXTEND
        // pooling rather than churn it. Measured basis: fresh mTLS ≈
        // 4.3×RTT (1.0s cold cross-globe), reused ≈ 1×RTT (P3 leg 1);
        // DLQ replay serialized at ~0.3s/row/peer on fresh handshakes.
        let mut client_builder = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(2))
            .pool_idle_timeout(FED_CLIENT_POOL_IDLE_TIMEOUT)
            .tcp_keepalive(FED_CLIENT_TCP_KEEPALIVE)
            // #2032 L3 — refuse redirects. Peers are mTLS/pin-authenticated;
            // reqwest's default `Policy::limited(10)` would re-resolve DNS
            // for a 3xx `Location` host and reconnect WITHOUT re-running the
            // server-cert pin / CA gate, so a compromised peer answering a
            // redirect could steer the outbound to an unvalidated host. A
            // 3xx from a federation peer is anomalous and must fail, not
            // silently follow (mirrors the webhook client's stance).
            .redirect(reqwest::redirect::Policy::none());
        // #1678 — outbound server-cert pinning. When the operator sets
        // `AI_MEMORY_FED_PEER_FINGERPRINTS`, install a preconfigured rustls
        // config carrying the per-SNI-host pin verifier (fail-CLOSED for any
        // unpinned host) plus the mTLS client identity. This REPLACES the
        // use_rustls_tls + --quorum-ca-cert + identity path: under pinning the
        // fingerprint is the trust anchor (CA roots are not consulted) and an
        // unpinned peer is refused rather than silently CA-validated. With
        // pinning OFF the `else` arm below is byte-identical to the pre-#1678
        // client.
        if let Some(pins) = crate::tls::peer_fingerprint_map_from_env()? {
            tracing::info!(
                target: FED_LOG_TARGET,
                pinned_hosts = pins.len(),
                "outbound federation TLS: server-cert PINNING active, fail-closed for \
                 unpinned peers (#1678)"
            );
            let pinning_config = crate::tls::build_rustls_pinning_client_config(
                pins,
                client_cert_path,
                client_key_path,
            )?;
            client_builder = client_builder.use_preconfigured_tls(pinning_config);
        } else {
            client_builder = client_builder.use_rustls_tls();
            // --quorum-ca-cert: trust a caller-supplied root CA for outbound
            // federation POSTs. Required whenever peers present a cert NOT
            // rooted in webpki-roots (Mozilla CA bundle) — e.g. a self-
            // signed / ephemeral CA generated for an isolated test fleet.
            // Without this, reqwest's rustls-tls feature (webpki-roots
            // only) rejects the peer cert and every quorum write times
            // out as quorum_not_met. See alphaonedev/ai-memory-mcp#333.
            if let Some(ca_path) = ca_cert_path {
                let ca_pem = std::fs::read(ca_path)
                    .map_err(|e| anyhow::anyhow!("read --quorum-ca-cert: {e}"))?;
                // v0.7.0 #1070 follow-up — `reqwest::Certificate::from_pem`
                // post-#1070 (rustls-only backend, no native-tls fallback)
                // accepts a file with no PEM markers as an empty cert chain
                // without erroring. That breaks the strict-validation
                // contract `config_build_rejects_invalid_ca_cert_pem` pins.
                // Pre-flight the file content for a `-----BEGIN ` marker so
                // a non-PEM operator-supplied path produces the same
                // explicit error message the legacy native-tls parser
                // emitted.
                let has_pem_marker = ca_pem.windows(11).any(|w| w == b"-----BEGIN ");
                if !has_pem_marker {
                    anyhow::bail!(
                        "parse --quorum-ca-cert: input at {} contains no PEM `-----BEGIN ` marker",
                        ca_path.display()
                    );
                }
                let ca = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| anyhow::anyhow!("parse --quorum-ca-cert: {e}"))?;
                client_builder = client_builder.add_root_certificate(ca);
            }
            if let (Some(cert), Some(key)) = (client_cert_path, client_key_path) {
                let cert_pem =
                    std::fs::read(cert).map_err(|e| anyhow::anyhow!("read --client-cert: {e}"))?;
                let key_pem =
                    std::fs::read(key).map_err(|e| anyhow::anyhow!("read --client-key: {e}"))?;
                let mut pem = cert_pem;
                pem.extend_from_slice(b"\n");
                pem.extend_from_slice(&key_pem);
                let identity = reqwest::Identity::from_pem(&pem)
                    .map_err(|e| anyhow::anyhow!("build mTLS identity: {e}"))?;
                client_builder = client_builder.identity(identity);
            }
        }
        let client = client_builder
            .build()
            .map_err(|e| anyhow::anyhow!("build federation client: {e}"))?;

        // v0.7.0 #791 — load the daemon's Ed25519 signing key (no-op
        // stub here; the full #697 audit/identity module loads from
        // disk). NON-FATAL: peers running `AI_MEMORY_FED_REQUIRE_SIG=0`
        // accept unsigned posts even when the signing key is missing.
        let signing_key = resolve_daemon_signing_key(
            crate::governance::audit::load_daemon_signing_key(&sender_agent_id),
            &sender_agent_id,
        );
        Ok(Some(Self {
            policy,
            peers,
            client,
            sender_agent_id,
            api_key,
            signing_key,
            // v0.7.0 Track D #933 — federation push DLQ sink is
            // populated by the daemon bootstrap AFTER the SAL store
            // handle resolves (see `daemon_runtime.rs`). The build()
            // path here returns `None` so an `ai-memory serve`
            // invocation that never bootstraps a store (none today;
            // belt-and-braces) doesn't trip a half-wired DLQ.
            #[cfg(feature = "sal")]
            dlq_sink: None,
        }))
    }

    /// Count of peers in the mesh (excludes the local node). Useful for
    /// metrics labels.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Resolve the optional daemon signing key from a
/// [`crate::governance::audit::load_daemon_signing_key`] result.
///
/// On success the key (if any) is wrapped in an `Arc`. On error the daemon
/// degrades to UNSIGNED — it logs the key-directory resolution failure and
/// returns `None` rather than failing the whole `build`, because peers
/// running `AI_MEMORY_FED_REQUIRE_SIG=0` still accept unsigned posts.
///
/// Extracted from [`FederationConfig::build`] so the error branch is
/// unit-testable: forcing `load_daemon_signing_key` to actually error
/// requires an unresolvable host config dir, which is not deterministic in
/// tests (the `dirs` crate falls back to `getpwuid` when `HOME` is unset).
fn resolve_daemon_signing_key(
    loaded: anyhow::Result<Option<ed25519_dalek::SigningKey>>,
    sender_agent_id: &str,
) -> Option<std::sync::Arc<ed25519_dalek::SigningKey>> {
    match loaded {
        Ok(maybe_key) => maybe_key.map(std::sync::Arc::new),
        Err(e) => {
            tracing::warn!(
                target: FED_LOG_TARGET,
                sender_agent_id = %sender_agent_id,
                error = %e,
                "could not resolve the daemon key directory; federation \
                 posts will be sent UNSIGNED — peers with require_sig \
                 enabled will silently reject them (partition risk). \
                 Fix the key directory permissions/path."
            );
            None
        }
    }
}

#[cfg(test)]
mod resolve_signing_key_tests {
    use super::resolve_daemon_signing_key;

    #[test]
    fn key_dir_error_degrades_to_unsigned() {
        // #1533 — the build() key-load error branch must warn and continue
        // UNSIGNED, never propagate. Driving the resolver with a synthetic
        // Err covers the branch deterministically (the live error needs an
        // unresolvable host config dir, which tests cannot force).
        let got = resolve_daemon_signing_key(
            Err(anyhow::anyhow!("synthetic key-dir resolution failure")),
            "ai:unsigned-builder",
        );
        assert!(got.is_none(), "key-dir error must degrade to unsigned");
    }

    #[test]
    fn absent_key_resolves_to_none() {
        let got = resolve_daemon_signing_key(Ok(None), "ai:no-key");
        assert!(got.is_none(), "no enrolled key resolves to None");
    }

    #[test]
    fn present_key_is_wrapped_in_arc() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let expected = key.to_bytes();
        let got = resolve_daemon_signing_key(Ok(Some(key)), "ai:signed");
        let got = got.expect("present key must resolve to Some");
        assert_eq!(got.to_bytes(), expected, "the loaded key is preserved");
    }
}

#[cfg(test)]
mod build_pinning_tests {
    use super::FederationConfig;
    use std::time::Duration;

    /// #1678 — exercise the outbound-pinning branch of `build()`: with
    /// `AI_MEMORY_FED_PEER_FINGERPRINTS` set to a valid host→fp file, the
    /// shared quorum client is constructed via `use_preconfigured_tls` with
    /// the fail-closed pin verifier (no mTLS identity here → with_no_client_auth).
    /// Serialised on the shared env lock so it never races the `tls` unset
    /// test that reads the same var.
    #[test]
    fn build_takes_pinning_branch_when_env_set() {
        let _g = crate::tls::fed_pin_env_lock();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), format!("peer.example {}\n", "a".repeat(64))).unwrap();
        // SAFETY: serialised via fed_pin_env_lock(); removed before asserts so
        // a failed assertion never leaks the var to a later test.
        unsafe {
            std::env::set_var(
                crate::tls::FED_PEER_FINGERPRINTS_ENV,
                tmp.path().as_os_str(),
            );
        }
        let built = FederationConfig::build(
            1,
            &["https://peer.example:9077".to_string()],
            Duration::from_secs(5),
            None, // client_cert_path → with_no_client_auth in the pinning config
            None, // client_key_path
            None, // ca_cert_path (ignored under pinning)
            "ai:pinning-build-test".to_string(),
            None, // api_key
        );
        unsafe {
            std::env::remove_var(crate::tls::FED_PEER_FINGERPRINTS_ENV);
        }
        let cfg = built.expect("pinning build must succeed");
        assert!(cfg.is_some(), "quorum_writes=1 with a peer must yield Some");
    }
}
