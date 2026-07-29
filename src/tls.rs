// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! TLS / mTLS configuration and verifiers for the HTTP daemon.
//!
//! Wave 4 (v0.6.3) — extracted verbatim from `src/main.rs`. Three layers:
//!
//! 1. **Layer 1** — server-side TLS via `axum-server` + rustls.
//!    `load_rustls_config` parses a PEM cert + PEM key (PKCS#8 / RSA / SEC1)
//!    and surfaces operator-friendly errors instead of letting rustls' wrapped
//!    IO errors bubble up. TLS misconfiguration is the #1 new-deploy footgun.
//!
//! 2. **Layer 2** — mTLS with SHA-256 client-cert fingerprint allowlist.
//!    `load_mtls_rustls_config` builds a rustls `ServerConfig` that:
//!      - presents the local cert/key (same as Layer 1),
//!      - demands a client certificate on every connection,
//!      - accepts the client cert only if its SHA-256 fingerprint appears on
//!        the operator-configured allowlist. Any other cert — including ones
//!        signed by trusted CAs — is rejected. This is the fastest path to
//!        "only authorised peers can even connect" without depending on a
//!        PKI/CA ecosystem. Fingerprint pinning is a well-understood primitive
//!        (HTTP Public Key Pinning, SSH host keys).
//!
//!    The allowlist parser tolerates:
//!      - blank lines and `#` full-line comments,
//!      - trailing inline comments (issue #358),
//!      - optional `:` separators in the hex,
//!      - an optional leading `sha256:` marker (forward-compat).
//!    It rejects embedded whitespace inside the hex run (issue #338) so
//!    soft-wrap copy-paste artefacts surface a clear "unexpected character"
//!    error rather than a misleading length error further down.
//!
//! 3. **Layer 2b (client side)** — outbound peer SERVER-cert verification.
//!    [`select_sync_tls_mode`] is the single decision point: server-cert
//!    PINNING (`AI_MEMORY_FED_PEER_FINGERPRINTS`, fail-closed for unpinned
//!    hosts) wins; otherwise the secure default is normal CA validation
//!    (`SyncTlsMode::CaValidated`, #1794). The accept-ANY disposition is
//!    reachable ONLY when the operator BOTH passes
//!    `--insecure-skip-server-verify` (itself gated on an mTLS client cert)
//!    AND explicitly sets `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` to a falsy
//!    token (#2448) — otherwise the mode selector REFUSES, so federation
//!    never pushes plaintext memory content to an unauthenticated server by
//!    default or by a single flag.
//!
//! Every public symbol below is move-extracted byte-for-byte from `main.rs`
//! at the W3 commit, with `pub` added for cross-module visibility. Behaviour
//! must remain bit-for-bit identical at the call sites.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

/// Env var naming a host→SHA-256 server-cert pin file for OUTBOUND
/// federation TLS (#1678). When set, the outbound federation client(s)
/// pin each peer's SERVER certificate by fingerprint per SNI host — the
/// outbound mirror of the inbound `--mtls-allowlist` client-cert pinning.
/// Federation file-path knobs in this crate are env-only (cf.
/// `AI_MEMORY_FED_CRED_PATH` / `AI_MEMORY_FED_INVENTORY_PATH`); there is
/// no clap flag. Unset / empty ⇒ pinning OFF (current behaviour, byte-
/// identical path). See `load_peer_fingerprint_map`.
pub const FED_PEER_FINGERPRINTS_ENV: &str = "AI_MEMORY_FED_PEER_FINGERPRINTS";

/// Error-prefix label for the peer-fingerprint pin-file parser. Hoisted to
/// a const so the no-hardcoded-literal gate sees one named site, not the
/// same string scattered across the parser's bail arms.
const PEER_FP_LABEL: &str = "peer fingerprint file";

/// **[#2448, v1.0.0]** Env var gating the outbound federation accept-ANY
/// server-cert disposition. Defaults **ON** (fail-closed): with it enabled,
/// [`select_sync_tls_mode`] REFUSES to resolve
/// [`SyncTlsMode::AcceptAny`], so `--insecure-skip-server-verify` no longer
/// suffices on its own to disable peer server-cert verification.
///
/// Federation replicates PLAINTEXT memory content and is NOT end-to-end
/// encrypted (`src/encryption/mod.rs`, #1968), so an unauthenticated server
/// on that wire is a direct content-disclosure surface for a DNS/BGP-position
/// adversary. The compensating control the accept-any posture historically
/// leaned on — the peer fingerprint-pinning OUR client cert via
/// `--mtls-allowlist` — protects the PEER from an impostor client; it does
/// not protect US from an impostor SERVER, and that is the direction that
/// governs content confidentiality.
///
/// Setting an explicit falsy token (`0`/`false`/`no`/`off`) is the
/// staged-rollout escape hatch (the `AI_MEMORY_FED_REQUIRE_WRITE_SIG` #94 /
/// `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` #125 shape). It is strictly
/// ADDITIVE to the pre-existing requirements, never a cheaper path: accept-any
/// still ALSO requires `--insecure-skip-server-verify` plus BOTH
/// `--client-cert` and `--client-key`. Under the `asi-hard` posture the knob
/// is PINNED to `1` by `security_profile::KNOBS`, so the escape hatch itself
/// is no-disable there (a falsy override refuses boot).
pub const FED_REQUIRE_SERVER_VERIFY_ENV: &str = "AI_MEMORY_FED_REQUIRE_SERVER_VERIFY";

/// Whether outbound peer server-cert verification is REQUIRED (#2448).
///
/// Uses the house default-ON federation-knob grammar: disabled only by an
/// explicit falsy token (`0`/`false`/`no`/`off`, trimmed); every other value —
/// including unset, the empty string, or an unknown word — keeps it enabled.
/// Mirrors `federation::receive_auth::env_flag_default_on`, re-implemented
/// here because that module is `--features sal`-gated while `tls` is in the
/// default build.
#[must_use]
pub fn server_verify_required() -> bool {
    std::env::var(FED_REQUIRE_SERVER_VERIFY_ENV)
        .ok()
        .is_none_or(|v| !matches!(v.trim(), "0" | "false" | "no" | "off"))
}

/// v0.7.0 H3 — pin the rustls protocol-version floor to TLS 1.2 with TLS 1.3
/// preferred. Listed in descending preference order; rustls negotiates the
/// highest protocol both peers support. TLS 1.0 / 1.1 are deliberately
/// omitted: they have known weaknesses (BEAST, POODLE, no AEAD) and are
/// disabled in every modern client (Chrome ≥ 84, Firefox ≥ 78, Safari ≥ 13).
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// v0.7.0 H4 — emit a `tracing::warn!` when the on-disk TLS key file is
/// world- or group-readable. On Unix, "loose" means
/// `mode & 0o077 != 0` — any bit in the group/world triad is set.
///
/// We intentionally do **not** refuse to load. Operators may have
/// deliberately set up a shared-group keymat layout (e.g. nginx-style
/// `ssl-cert` group), and refusing here would regress those flows.
/// Warning is the right surface: loud in `journalctl`, scrapable by
/// the SIEM, but never blocks startup.
///
/// On non-Unix targets the check is a no-op (Windows ACLs are richer
/// than `st_mode` bits and would warrant a separate audit).
fn warn_if_key_perms_loose(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    target: "ai_memory::tls",
                    path = %path.display(),
                    mode = format!("{mode:#o}"),
                    "TLS private key file is group- or world-accessible \
                     (mode {mode:#o}); recommended permissions are 0600. \
                     Loading anyway — operator may have intentional shared-group setup."
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows uses ACLs, not POSIX modes. A separate audit would be
        // needed to surface "Everyone has Read" — out of v0.7.0 scope.
        let _ = path;
    }
}

/// Load a PEM cert + PEM key (PKCS#8 or RSA) into an `axum-server`
/// rustls config. Returns an error with a specific message for the
/// operator rather than letting rustls' wrapped IO error bubble up —
/// TLS misconfigurations are the #1 new-deploy footgun.
///
/// **v0.7.0 H3** — protocol versions are pinned to TLS 1.3 (preferred)
/// + TLS 1.2 (floor). See [`SUPPORTED_PROTOCOL_VERSIONS`].
///
/// **v0.7.0 H4** — private key file permissions are checked before
/// loading; loose permissions surface as a WARN but do not refuse.
pub async fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    warn_if_key_perms_loose(key_path);
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("failed to read TLS cert from {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("failed to read TLS key from {}", key_path.display()))?;

    // v0.7.0 H3 — `RustlsConfig::from_pem` doesn't expose protocol-
    // version pinning. We build a `rustls::ServerConfig` directly with
    // `with_protocol_versions(&[TLS13, TLS12])`, then wrap it for
    // axum_server. Same parser surface, but with the version floor
    // bolted on.
    let certs = rustls_pki_pem_iter_certs(&cert_pem)?;
    let key = rustls_pki_pem_parse_private_key(&key_pem)?;
    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(SUPPORTED_PROTOCOL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context(
                "failed to build rustls ServerConfig — ensure PEM-encoded (cert may be fullchain; \
         key must be PKCS#8 or RSA)",
            )?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

// ---------------------------------------------------------------------------
// Layer 2 — mTLS with SHA-256 fingerprint allowlist.
// ---------------------------------------------------------------------------

/// Load a rustls server config with client-cert-fingerprint verification.
pub async fn load_mtls_rustls_config(
    cert_path: &Path,
    key_path: &Path,
    allowlist_path: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    let allowlist = load_fingerprint_allowlist(allowlist_path).await?;
    if allowlist.is_empty() {
        anyhow::bail!(
            "mTLS allowlist at {} is empty — refuse to start rather than silently accept all peers",
            allowlist_path.display()
        );
    }

    warn_if_key_perms_loose(key_path);
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("failed to read TLS cert from {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("failed to read TLS key from {}", key_path.display()))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pki_pem_iter_certs(&cert_pem)?;
    let key = rustls_pki_pem_parse_private_key(&key_pem)?;

    let verifier = Arc::new(FingerprintAllowlistVerifier { allowlist });
    // v0.7.0 H3 — same protocol-version pinning as the non-mTLS server
    // config above. TLS 1.3 preferred, TLS 1.2 floor.
    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(SUPPORTED_PROTOCOL_VERSIONS)
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("failed to build rustls ServerConfig for mTLS")?;

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

/// v0.7.0 #1581 — production acceptor for the TLS / mTLS `serve` path:
/// the rustls acceptor wrapped around [`axum_server::accept::NoDelayAcceptor`]
/// so `TCP_NODELAY` is set on every accepted socket BEFORE the handshake.
///
/// # Why (the #1579 P3 fleet finding)
///
/// `serve()` used to bind via `axum_server::bind_rustls`, whose inner
/// `DefaultAcceptor` is a no-op — Nagle's algorithm stayed enabled on every
/// accepted socket. After a TLS 1.3 handshake the server flushes the
/// NewSessionTicket records as a small TCP segment ahead of the first
/// response; with Nagle on, the response segment is then held until the
/// ticket segment is ACKed, and the client kernel's delayed-ACK timer
/// (40 ms minimum on Linux) is what finally supplies that ACK. Net effect:
/// the FIRST request of every fresh mTLS connection paid a fixed ~40 ms
/// stall that no later request on the same connection repeats — measured
/// fleet-wide on all 9 intra-region do-1461 peer pairs (first-request TTFB
/// ~52–57 ms vs ~5–8 ms reused, RTT 2–3 ms) and reproduced on loopback
/// (~41 ms gap between `time_appconnect` and `time_starttransfer` vs
/// ~2 ms for a reused connection).
///
/// Setting `TCP_NODELAY` disables Nagle so the response goes out the
/// moment it's written. The client side of federation sync was never
/// affected: reqwest defaults `tcp_nodelay(true)`, as does curl ≥ 7.50.
///
/// # Security
///
/// This is a pure socket-option change ahead of the handshake. The
/// verifier chain — [`FingerprintAllowlistVerifier`], `client_auth_mandatory`,
/// the protocol-version floor — is byte-identical to what
/// `axum_server::bind_rustls` constructs. Equivalence is pinned by
/// `tests/mtls_nodelay_acceptor.rs` (allowlisted cert accepted, unknown
/// cert rejected, absent cert rejected, on BOTH acceptor shapes).
pub fn serve_rustls_acceptor(
    config: &axum_server::tls_rustls::RustlsConfig,
) -> axum_server::tls_rustls::RustlsAcceptor<axum_server::accept::NoDelayAcceptor> {
    axum_server::tls_rustls::RustlsAcceptor::new(config.clone())
        .acceptor(axum_server::accept::NoDelayAcceptor::new())
}

// ---------------------------------------------------------------------------
// #2045 L6 — mTLS client-cert ↔ X-Peer-Id cross-check.
//
// The inbound federation `/sync/*` path trusted a verbatim `X-Peer-Id`
// header: any holder of ANY allowlisted client cert could assert any peer
// identity (the deferred fix flagged in `transport.rs`). This section binds
// the presenting client cert to the peer identity it is allowed to assert.
//
// TRUST MODEL. mTLS here is fingerprint-pinning of (typically self-signed)
// peer certs (`FingerprintAllowlistVerifier`), so a certificate's own
// Subject / SAN fields are attacker-chosen and MUST NOT be trusted as the
// peer identity — an enrolled peer could mint a cert whose SAN names a
// victim. The trustworthy anchor is the operator-declared fingerprint, so
// identity is bound through an operator-authored `<sha256-hex> <peer-id>`
// map file — the same operator-declares-the-pin model as the outbound
// `load_peer_fingerprint_map` (#1678) — rather than parsing a self-asserted
// cert SAN.
// ---------------------------------------------------------------------------

/// Env var naming an operator-authored file that binds each pinned mTLS
/// client-cert SHA-256 fingerprint to the ONE `x-peer-id` that cert is
/// allowed to assert on the inbound federation `/sync/*` path (#2045 L6).
/// Unset / empty ⇒ no bindings ⇒ every cert is "legacy" and the cross-check
/// degrades to a WARN (never bricks). See [`load_cert_peer_binding_map`].
pub const FED_CERT_PEER_BINDING_MAP_ENV: &str = "AI_MEMORY_FED_CERT_PEER_BINDING_MAP";

/// Env var selecting the enforcement posture of the mTLS cert↔`X-Peer-Id`
/// cross-check (#2045 L6): `off` | `warn` | `enforce`. Independent of
/// `AI_MEMORY_FED_REQUIRE_SIG` — it is the compensating control for the
/// `FED_REQUIRE_SIG=0` window. Default `warn` (one release, then `enforce`).
pub const FED_CERT_PEER_BINDING_ENV: &str = "AI_MEMORY_FED_CERT_PEER_BINDING";

/// Error-prefix label for the cert-peer-binding map parser (one named site
/// for the no-hardcoded-literal gate).
const CERT_PEER_BINDING_LABEL: &str = "cert peer-binding map";

/// Enforcement posture for the mTLS cert↔`X-Peer-Id` cross-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertPeerBindingMode {
    /// Cross-check disabled — verbatim `X-Peer-Id` (pre-#2045 behaviour).
    Off,
    /// A mismatch is logged at WARN but the request proceeds (default).
    Warn,
    /// A mismatch is rejected with `401 peer_id_cert_mismatch`.
    Enforce,
}

impl CertPeerBindingMode {
    /// Parse the posture token (case-insensitive). Unrecognised ⇒ `Warn`
    /// (the secure-but-non-bricking default), matching the enum-resolve
    /// fall-through shape of the other `off|warn|enforce` knobs.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "enforce" => Self::Enforce,
            _ => Self::Warn,
        }
    }
}

/// Resolve the cross-check posture from `AI_MEMORY_FED_CERT_PEER_BINDING`
/// (default `warn`). Read per request — the env is cheap and re-reading
/// lets an operator flip posture without a restart (mirrors the other
/// direct-read federation knobs).
#[must_use]
pub fn cert_peer_binding_mode() -> CertPeerBindingMode {
    std::env::var(FED_CERT_PEER_BINDING_ENV)
        .ok()
        .map_or(CertPeerBindingMode::Warn, |v| {
            CertPeerBindingMode::parse(&v)
        })
}

/// Parse an operator-authored cert-peer-binding map: one
/// `<sha256-hex> <peer-id>` per line. `#` comments, blank lines and inline
/// trailing `# …` comments are tolerated (mirrors the allowlist parser);
/// the fingerprint field accepts the same grammar as the allowlist
/// (`sha256:` marker + optional `:` separators). Several fingerprints may
/// bind the same peer-id (cert rotation); a single fingerprint binding two
/// DIFFERENT peer-ids is a fail-closed parse error (an ambiguous binding
/// would silently weaken the check).
pub fn load_cert_peer_binding_map(path: &Path) -> Result<HashMap<[u8; 32], String>> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read {CERT_PEER_BINDING_LABEL} from {}",
            path.display()
        )
    })?;
    let mut map: HashMap<[u8; 32], String> = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (fp_token, peer_id) = two_whitespace_fields(
            line,
            CERT_PEER_BINDING_LABEL,
            "`<sha256-hex> <peer-id>`",
            lineno,
        )?;
        let fp = parse_fingerprint_token(fp_token, CERT_PEER_BINDING_LABEL, lineno)?;
        // Reuse the wire agent-id shape check so a binding cannot smuggle
        // CRLF / control bytes into the peer-id (same discipline as
        // `extract_peer_id`).
        if crate::validate::validate_agent_id(peer_id).is_err() {
            anyhow::bail!(
                "{CERT_PEER_BINDING_LABEL} line {lineno}: `{peer_id}` is not a valid peer-id \
                 (agent-id shape)"
            );
        }
        if let Some(existing) = map.get(&fp) {
            if existing != peer_id {
                anyhow::bail!(
                    "{CERT_PEER_BINDING_LABEL} line {lineno}: fingerprint already bound to \
                     `{existing}`, cannot re-bind to `{peer_id}`"
                );
            }
        } else {
            map.insert(fp, peer_id.to_string());
        }
    }
    Ok(map)
}

/// Resolve the cert-peer-binding map from
/// `AI_MEMORY_FED_CERT_PEER_BINDING_MAP`. `Ok(None)` ⇒ env unset / empty ⇒
/// no bindings (the byte-identical pre-#2045 path; the peer-binding
/// acceptor is not installed).
pub fn cert_peer_binding_map_from_env() -> Result<Option<HashMap<[u8; 32], String>>> {
    let Some(raw) = std::env::var_os(FED_CERT_PEER_BINDING_MAP_ENV) else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(load_cert_peer_binding_map(&path)?))
}

/// Per-request extension injected by [`PeerBindingAcceptor`] on the inbound
/// mTLS `/sync/*` path (#2045 L6). Carries the operator-bound peer identity
/// resolved from the presenting client cert's SHA-256 fingerprint:
///   - `Some(peer_id)` — the fingerprint is bound to exactly this id;
///   - `None` — the fingerprint has NO binding ("legacy" cert): the
///     cross-check degrades to WARN and never bricks.
///
/// Absence of the extension entirely means the request did not arrive over
/// the peer-binding mTLS acceptor (plain HTTP / no binding map configured),
/// so the cross-check is skipped.
#[derive(Debug, Clone)]
pub struct ClientCertPeerId(pub Option<String>);

/// Compute the SHA-256(DER) fingerprint of the leaf client cert on a
/// completed TLS connection and resolve its operator-bound peer-id from
/// `bindings`. `None` when the peer presented no client cert (non-mTLS) or
/// the fingerprint carries no binding.
fn resolve_bound_peer_id(
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
    bindings: &HashMap<[u8; 32], String>,
) -> Option<String> {
    use sha2::{Digest, Sha256};
    let leaf = peer_certs?.first()?;
    let fp: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    bindings.get(&fp).cloned()
}

/// Per-connection `tower` service wrapper that inserts a [`ClientCertPeerId`]
/// extension into every request handled on the connection (#2045 L6). One
/// clone of a small `Option<String>` per request.
#[derive(Clone)]
pub struct CertExtensionService<S> {
    inner: S,
    cert_peer_id: ClientCertPeerId,
}

impl<S> CertExtensionService<S> {
    /// The [`ClientCertPeerId`] this wrapper injects into every request it
    /// serves — the operator-bound peer identity [`PeerBindingAcceptor`]
    /// resolved from the presenting client cert. Read accessor so the
    /// acceptor's post-handshake resolution is assertable end-to-end.
    #[must_use]
    pub fn client_cert_peer_id(&self) -> &ClientCertPeerId {
        &self.cert_peer_id
    }
}

impl<S, B> tower_service::Service<axum::http::Request<B>> for CertExtensionService<S>
where
    S: tower_service::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.cert_peer_id.clone());
        self.inner.call(req)
    }
}

/// mTLS acceptor that, after the rustls handshake completes, resolves the
/// presenting client cert's operator-bound peer identity and injects it as
/// a [`ClientCertPeerId`] request extension (#2045 L6). Wraps the same
/// `NoDelayAcceptor`-fronted rustls acceptor as [`serve_rustls_acceptor`]
/// so the `TCP_NODELAY` fix (#1581) and the verifier chain are preserved
/// verbatim — this ONLY adds the post-handshake extension injection.
#[derive(Clone)]
pub struct PeerBindingAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor<axum_server::accept::NoDelayAcceptor>,
    bindings: Arc<HashMap<[u8; 32], String>>,
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for PeerBindingAcceptor
where
    S: Send + 'static,
{
    type Stream = <axum_server::tls_rustls::RustlsAcceptor<
        axum_server::accept::NoDelayAcceptor,
    > as axum_server::accept::Accept<tokio::net::TcpStream, S>>::Stream;
    type Service = CertExtensionService<S>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let inner = axum_server::accept::Accept::accept(&self.inner, stream, service);
        let bindings = self.bindings.clone();
        Box::pin(async move {
            let (tls_stream, service) = inner.await?;
            // `get_ref().1` is the rustls `ServerConnection`; its
            // `peer_certificates()` is the client cert the verifier already
            // fingerprint-pinned. Resolved by inference — no tokio-rustls
            // type is named.
            let bound =
                resolve_bound_peer_id(tls_stream.get_ref().1.peer_certificates(), &bindings);
            let service = CertExtensionService {
                inner: service,
                cert_peer_id: ClientCertPeerId(bound),
            };
            Ok((tls_stream, service))
        })
    }
}

/// Build a [`PeerBindingAcceptor`] over the production mTLS config — the
/// [`serve_rustls_acceptor`] sibling used when an operator has configured a
/// cert-peer-binding map (#2045 L6). Verifier chain + `TCP_NODELAY` are
/// identical to [`serve_rustls_acceptor`].
#[must_use]
pub fn serve_rustls_acceptor_with_peer_binding(
    config: &axum_server::tls_rustls::RustlsConfig,
    bindings: HashMap<[u8; 32], String>,
) -> PeerBindingAcceptor {
    PeerBindingAcceptor {
        inner: serve_rustls_acceptor(config),
        bindings: Arc::new(bindings),
    }
}

/// Parse the allowlist file: one SHA-256 fingerprint per line, case-insensitive
/// hex with optional `:` separators. Empty lines and `#` comments are skipped.
pub async fn load_fingerprint_allowlist(path: &Path) -> Result<HashSet<[u8; 32]>> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read mTLS allowlist from {}", path.display()))?;
    let mut set = HashSet::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Issue #358: tolerate inline trailing comments — anything after `#`
        // on a non-comment line is dropped before the strict hex/colon
        // validation below. Safe because `#` is not a valid hex/colon char,
        // so it cannot appear in a legitimate SHA-256 fingerprint.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bytes = parse_fingerprint_token(line, "mTLS allowlist", lineno + 1)?;
        set.insert(bytes);
    }
    Ok(set)
}

/// Parse one SHA-256 fingerprint token into 32 raw bytes. Shared by the
/// inbound mTLS client-cert allowlist parser and the outbound peer
/// server-cert pin-map parser (#1678) so the strict-hex grammar lives in
/// exactly one place. `label` is the caller's error-message prefix (e.g.
/// `"mTLS allowlist"`) so each surface keeps its own wording.
///
/// Grammar: optional leading `sha256:` marker, then 64 case-insensitive
/// hex chars with optional `:` separators. Ultrareview #338: any non-hex,
/// non-colon character — including embedded whitespace/tabs — is rejected
/// rather than silently stripped, so copy-paste artefacts fail loudly.
fn parse_fingerprint_token(token: &str, label: &str, lineno: usize) -> Result<[u8; 32]> {
    let hex_part = token.strip_prefix("sha256:").unwrap_or(token);
    if let Some(bad) = hex_part
        .chars()
        .find(|c| !c.is_ascii_hexdigit() && *c != ':')
    {
        anyhow::bail!(
            "{label} line {lineno}: unexpected character {bad:?} — \
             entries must be 64 hex chars with optional `:` separators"
        );
    }
    let hex_clean: String = hex_part.chars().filter(|c| *c != ':').collect();
    if hex_clean.len() != 64 {
        anyhow::bail!(
            "{label} line {lineno}: expected 64 hex chars (optionally with `:` separators), got {}",
            hex_clean.len()
        );
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_clean[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("{label} line {lineno}: invalid hex"))?;
    }
    Ok(bytes)
}

/// Split a comment-stripped, non-empty pin-file line into EXACTLY two
/// whitespace-delimited fields, or bail with `label` / `grammar` / `lineno`
/// context. Shared by the two `<a> <b>` pin-file parsers
/// ([`load_peer_fingerprint_map`] #1678, [`load_cert_peer_binding_map`]
/// #2045) so the "exactly two fields" grammar lives in one place.
fn two_whitespace_fields<'a>(
    line: &'a str,
    label: &str,
    grammar: &str,
    lineno: usize,
) -> Result<(&'a str, &'a str)> {
    let mut parts = line.split_whitespace();
    let first = parts
        .next()
        .expect("non-empty line has at least one whitespace-delimited field");
    let Some(second) = parts.next() else {
        anyhow::bail!("{label} line {lineno}: expected {grammar}, got only `{first}`");
    };
    if parts.next().is_some() {
        anyhow::bail!("{label} line {lineno}: expected exactly two fields {grammar}");
    }
    Ok((first, second))
}

/// Normalise an operator-written host token into the canonical key used by
/// `FingerprintPinServerVerifier`'s map. An IP literal is round-tripped
/// through `std::net::IpAddr` (canonical form); a DNS name is lowercased.
/// MUST match `server_name_host_key` on the lookup side — the round-trip
/// is pinned by `peer_pin_host_key_round_trips`.
fn normalize_host_key(raw: &str) -> String {
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        raw.to_ascii_lowercase()
    }
}

/// Canonical host key for a rustls `ServerName`, matching `normalize_host_key`
/// on the load side. Returns `None` for the `#[non_exhaustive]` variants we
/// don't recognise so they route to the unpinned-host disposition rather
/// than silently matching.
fn server_name_host_key(server_name: &rustls::pki_types::ServerName<'_>) -> Option<String> {
    match server_name {
        rustls::pki_types::ServerName::DnsName(d) => Some(d.as_ref().to_ascii_lowercase()),
        rustls::pki_types::ServerName::IpAddress(ip) => {
            Some(std::net::IpAddr::from(*ip).to_string())
        }
        _ => None,
    }
}

/// Parse a peer server-cert pin file: one `<host> <sha256-hex>` per line.
/// `#` comments and blank lines are skipped; inline trailing `# …` comments
/// are dropped (mirrors the allowlist parser). A host may appear on several
/// lines to pin multiple acceptable fingerprints (rotation). Fail-closed:
/// an empty result errors, because the pinning verifier rejects every
/// unpinned host and an empty map would silently break ALL federation.
pub fn load_peer_fingerprint_map(path: &Path) -> Result<HashMap<String, HashSet<[u8; 32]>>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {PEER_FP_LABEL} from {}", path.display()))?;
    let mut map: HashMap<String, HashSet<[u8; 32]>> = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (host, fp_token) =
            two_whitespace_fields(line, PEER_FP_LABEL, "`<host> <sha256-hex>`", lineno)?;
        let fp = parse_fingerprint_token(fp_token, PEER_FP_LABEL, lineno)?;
        map.entry(normalize_host_key(host)).or_default().insert(fp);
    }
    if map.is_empty() {
        anyhow::bail!(
            "{PEER_FP_LABEL} {} contained no entries — peer-fingerprint pinning is \
             fail-closed and would reject every peer; add `<host> <sha256-hex>` lines \
             or unset {FED_PEER_FINGERPRINTS_ENV}",
            path.display()
        );
    }
    Ok(map)
}

/// Resolve the outbound peer server-cert pin map from
/// `AI_MEMORY_FED_PEER_FINGERPRINTS`. `Ok(None)` ⇒ pinning OFF (env unset
/// or empty), so callers leave the pre-#1678 client path byte-identical.
pub fn peer_fingerprint_map_from_env() -> Result<Option<HashMap<String, HashSet<[u8; 32]>>>> {
    let Some(raw) = std::env::var_os(FED_PEER_FINGERPRINTS_ENV) else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(load_peer_fingerprint_map(&path)?))
}

/// Disposition for a peer host with NO pin entry (mixed-mode rollout).
#[derive(Debug, Clone, Copy)]
pub enum UnpinnedHostPolicy {
    /// Reject the connection (fail-closed). Used on the production quorum
    /// client (`federation/peer.rs`), whose pre-pin behaviour was CA
    /// validation: once an operator opts in to pinning, every peer MUST be
    /// pinned — an unknown host is refused rather than silently downgraded.
    Reject,
    /// Accept any server cert (no downgrade). Used on the `ai-memory sync`
    /// CLI path whose pre-pin behaviour was ALREADY accept-any
    /// (`DangerousAnyServerVerifier`); pinning only STRENGTHENS pinned hosts
    /// there, so unpinned hosts keep the prior (no-worse) disposition.
    AcceptAny,
}

/// Outbound mirror of [`FingerprintAllowlistVerifier`]: pins a federation
/// peer's SERVER cert by SHA-256(DER), keyed per SNI host. Pin-only for a
/// pinned host (ignores the CA chain — the pin IS the trust anchor, same
/// SSH `known_hosts` model as the inbound verifier). A host with no pin
/// entry is dispositioned by `unpinned`.
///
/// # Security — the pin is layered ON TOP of handshake-signature verification
///
/// `verify_tls12_signature` / `verify_tls13_signature` MUST delegate to the
/// real `rustls::crypto::verify_tls1{2,3}_signature` (copied verbatim from
/// [`DangerousAnyServerVerifier`]) and are NEVER stubbed. The fingerprint
/// match alone is insufficient: a MITM could replay a captured pinned cert
/// it does not hold the private key for, so the pin is an ADDITIONAL
/// identity gate, never a replacement for proving cert ownership in the
/// handshake. (#1678 — 5-agent vote 4d3ea1c5.)
#[derive(Debug)]
pub struct FingerprintPinServerVerifier {
    pins: HashMap<String, HashSet<[u8; 32]>>,
    unpinned: UnpinnedHostPolicy,
}

impl FingerprintPinServerVerifier {
    #[must_use]
    pub fn new(pins: HashMap<String, HashSet<[u8; 32]>>, unpinned: UnpinnedHostPolicy) -> Self {
        Self { pins, unpinned }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintPinServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let host = server_name_host_key(server_name);
        if let Some(set) = host.as_deref().and_then(|h| self.pins.get(h)) {
            use sha2::{Digest, Sha256};
            let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            return if allowlist_contains_ct(set, &fp) {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(format!(
                    "peer server cert fingerprint {} not pinned for host {}",
                    hex_short(&fp),
                    host.as_deref().unwrap_or("<unknown>")
                )))
            };
        }
        match self.unpinned {
            UnpinnedHostPolicy::AcceptAny => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            UnpinnedHostPolicy::Reject => Err(rustls::Error::General(format!(
                "peer server cert host {} is not pinned (peer-fingerprint pinning is \
                 enabled and fail-closed); add its SHA-256 to {FED_PEER_FINGERPRINTS_ENV}",
                host.as_deref().unwrap_or("<unknown>")
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls `ClientConfig` that PINS peer server certs (#1678) for
/// the production quorum client. Unpinned hosts are fail-closed
/// ([`UnpinnedHostPolicy::Reject`]). Client-auth identity is attached when
/// `cert`/`key` are supplied (mTLS is preserved); otherwise no client auth.
/// CA roots (`--quorum-ca-cert`) are intentionally NOT consulted: under
/// pinning the fingerprint replaces CA trust for pinned hosts, and unpinned
/// hosts are refused regardless of CA.
pub fn build_rustls_pinning_client_config(
    pins: HashMap<String, HashSet<[u8; 32]>>,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
) -> Result<rustls::ClientConfig> {
    // Defensive: the daemon serve path may not have installed a process
    // default provider before this build site. Idempotent — ignore the Err
    // when one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let verifier = Arc::new(FingerprintPinServerVerifier::new(
        pins,
        UnpinnedHostPolicy::Reject,
    ));
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            warn_if_key_perms_loose(key_path);
            let cert_pem = std::fs::read(cert_path).with_context(|| {
                format!("failed to read client cert from {}", cert_path.display())
            })?;
            let key_pem = std::fs::read(key_path).with_context(|| {
                format!("failed to read client key from {}", key_path.display())
            })?;
            let certs = rustls_pki_pem_iter_certs(&cert_pem)?;
            let key = rustls_pki_pem_parse_private_key(&key_pem)?;
            builder
                .with_client_auth_cert(certs, key)
                .context("failed to build pinning rustls ClientConfig with client cert")?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(config)
}

pub fn rustls_pki_pem_iter_certs(
    pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject as _;
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_reader_iter(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse TLS cert PEM")?;
    if certs.is_empty() {
        anyhow::bail!("TLS cert PEM contained no certificates");
    }
    Ok(certs)
}

pub fn rustls_pki_pem_parse_private_key(
    pem: &[u8],
) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject as _;
    let mut cursor = std::io::Cursor::new(pem);
    let key = rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut cursor)
        .context("failed to parse TLS key PEM — expected PKCS#8, RSA, or SEC1")?;
    Ok(key)
}

/// Custom `ClientCertVerifier` that accepts only client certs whose SHA-256
/// DER fingerprint is on the allowlist. Ignores CA chain — fingerprint
/// pinning is the trust anchor here, same model as SSH `known_hosts`.
#[derive(Debug)]
pub struct FingerprintAllowlistVerifier {
    pub allowlist: HashSet<[u8; 32]>,
}

impl rustls::server::danger::ClientCertVerifier for FingerprintAllowlistVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if allowlist_contains_ct(&self.allowlist, &fp) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "client cert fingerprint {} not in mTLS allowlist",
                hex_short(&fp)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn hex_short(fp: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(12);
    for b in &fp[..6] {
        let _ = write!(s, "{b:02x}");
    }
    s.push('…');
    s
}

/// v0.7.0 M1 — constant-time allowlist membership check.
///
/// `HashSet::contains` is O(1) but the SipHash probe + early-exit
/// comparison both leak timing signal: the response time of a verify
/// handshake correlates with whether the offered fingerprint hash-
/// collides with any allowlist entry (and, on collision, how many
/// bytes match). A remote attacker who can observe TLS handshake
/// timing can in principle enumerate the allowlist that way.
///
/// We walk every entry in the allowlist on every call and XOR-fold
/// each byte through `subtle::ConstantTimeEq`. The result is the
/// OR-reduction of "this entry matched" across every entry — same
/// per-call cost regardless of whether a match exists or where in
/// the iteration order it sits. `subtle` is the RustCrypto-default
/// constant-time primitive (used by ring, ed25519-dalek, etc.).
///
/// Cost is O(N · 32) bytes per handshake. With a 1000-entry
/// allowlist that's 32 KB of memory comparison — well below the
/// dozens of milliseconds of cryptographic handshake work that
/// precedes it. The timing-attack threat dominates the perf cost.
fn allowlist_contains_ct(allowlist: &HashSet<[u8; 32]>, fp: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq as _;
    let mut found: subtle::Choice = subtle::Choice::from(0);
    for entry in allowlist {
        // `ct_eq` returns a `Choice` (0 or 1) without branching on
        // the comparison outcome — the inner XOR-fold runs the full
        // 32 bytes every call.
        found |= entry.ct_eq(fp);
    }
    bool::from(found)
}

/// #1794 (5-agent vote 4d3ea1c5) — the outbound TLS verification mode the CLI
/// `ai-memory sync` path selects for a peer connection. Precedence mirrors the
/// production quorum client (`federation/peer.rs`): server-cert PINNING
/// (`AI_MEMORY_FED_PEER_FINGERPRINTS`) wins; then the explicit
/// `--insecure-skip-server-verify` accept-any opt-out; otherwise the secure
/// default — normal CA validation (reqwest's bundled webpki roots, plus any
/// `--ca-cert` the operator adds for a self-signed peer). **[#2448]** the
/// accept-any arm additionally requires an explicit falsy
/// [`FED_REQUIRE_SERVER_VERIFY_ENV`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTlsMode {
    /// `AI_MEMORY_FED_PEER_FINGERPRINTS` set → per-host server-cert pinning,
    /// fail-closed for unpinned hosts.
    Pinning,
    /// Accept ANY server cert. Reachable only when the operator supplies ALL
    /// of: `--insecure-skip-server-verify`, BOTH `--client-cert` and
    /// `--client-key` (the pre-existing mTLS gate), AND an explicit falsy
    /// [`FED_REQUIRE_SERVER_VERIFY_ENV`] (#2448). Four conditions, not one.
    AcceptAny,
    /// Secure default → CA-validate the peer server cert (bundled webpki roots
    /// + optional `--ca-cert`).
    CaValidated,
}

/// #1794 — resolve the CLI sync TLS verification mode. Pinning >
/// insecure-opt-out > CA-validate (the secure default). `--ca-cert` does NOT
/// change the mode (still `CaValidated`); it only adds an extra trusted root.
/// Pure + total so the decision is unit-testable independently of the opaque
/// rustls/reqwest config it drives.
///
/// **[#2448]** `server_verify_required` (from [`server_verify_required`], i.e.
/// [`FED_REQUIRE_SERVER_VERIFY_ENV`], default **ON**) is the fail-closed gate
/// on the accept-ANY arm. The refusal lives HERE rather than at the call site
/// so it is structural: no present or future caller can resolve
/// [`SyncTlsMode::AcceptAny`] without explicitly threading a `false` through,
/// and federation therefore cannot push plaintext memory content to an
/// unauthenticated server on a single flag. Pinning still wins outright — a
/// pinned host is verified by fingerprint, so `--insecure-skip-server-verify`
/// alongside an active pin map is a no-op, not a refusal.
///
/// # Errors
/// Returns an error when `insecure_skip_server_verify` is set, pinning is
/// inactive, and server verification is required — naming the two SECURE
/// remedies first (`--ca-cert`, `AI_MEMORY_FED_PEER_FINGERPRINTS`) and the
/// staged-rollout escape hatch last.
pub fn select_sync_tls_mode(
    insecure_skip_server_verify: bool,
    pinning_active: bool,
    server_verify_required: bool,
) -> Result<SyncTlsMode> {
    if pinning_active {
        return Ok(SyncTlsMode::Pinning);
    }
    if insecure_skip_server_verify {
        if server_verify_required {
            anyhow::bail!(
                "--insecure-skip-server-verify is refused: it disables peer SERVER-certificate \
                 verification while federation replicates PLAINTEXT memory content, so a \
                 DNS/BGP-position adversary can read everything this node pushes. Pinning our \
                 client cert on the peer side does NOT protect this direction. Fix it with \
                 `--ca-cert <peer-ca.pem>` for a self-signed / private-CA peer, or set \
                 {FED_PEER_FINGERPRINTS_ENV} to pin the peer's server cert by SHA-256 \
                 (strongest). Only if you must keep the insecure posture for a staged-rollout \
                 window, set {FED_REQUIRE_SERVER_VERIFY_ENV}=0 (refused under the asi-hard \
                 security posture). (#2448)"
            );
        }
        return Ok(SyncTlsMode::AcceptAny);
    }
    Ok(SyncTlsMode::CaValidated)
}

/// `ServerCertVerifier` that accepts ANY peer certificate — it performs no
/// server-identity check whatsoever.
///
/// # Threat model (#224 → #1678 → #1794 → #2448)
///
/// The historical compensating argument was that the PEER fingerprint-pins
/// OUR client cert via `--mtls-allowlist`, so a spoofed server that lacks our
/// client key is filtered at the peer's `ClientCertVerifier`. **That argument
/// is directionally incomplete and no longer load-bearing** (#2448): it
/// protects the PEER from an impostor CLIENT; it does not protect US from an
/// impostor SERVER. Since federation replicates PLAINTEXT memory content
/// (NOT end-to-end encrypted — `src/encryption/mod.rs`, #1968), an adversary
/// in DNS or BGP position who presents any certificate would complete the
/// handshake and receive everything this node pushes. Confidentiality, not
/// integrity, is what breaks: inbound content is separately authenticated by
/// `AI_MEMORY_FED_REQUIRE_SIG` (#29) / `_WRITE_SIG` (#94) / nonce (#30) /
/// peer enrollment (#43).
///
/// # Current status — production-unreachable by default
///
/// - Outbound peer server-cert PINNING (`AI_MEMORY_FED_PEER_FINGERPRINTS`,
///   #1678) shipped at v0.8.0 and is the strongest control.
/// - The CLI sync path CA-validates by default (#1794).
/// - #2448 removed the last production constructor that installed this
///   verifier by default, and gated the remaining accept-any disposition
///   behind [`FED_REQUIRE_SERVER_VERIFY_ENV`] (default ON ⇒ refused).
///
/// In-tree, this type now survives for TEST harnesses that must speak to a
/// self-signed fixture server (`tests/mtls_nodelay_acceptor.rs`). **Do not
/// wire it into any production path**; the MCP / CLI / HTTP-app clients use
/// the default rustls verifier with platform roots. Removing the `Dangerous`
/// prefix from the type name would obscure the trade-off and is rejected.
/// Operator guidance lives in `docs/federation.md` §"Outbound peer
/// server-cert pinning".
#[derive(Debug)]
pub struct DangerousAnyServerVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousAnyServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Shared serialization lock for any test that mutates the process-wide
/// `AI_MEMORY_FED_PEER_FINGERPRINTS` env var. `env::set_var`/`remove_var`
/// are process-global, so the `tls` unset-path test and the
/// `federation::peer` build-pinning coverage test (different modules, same
/// test binary) MUST take this lock or they race (the #5d4e3ca3 parallel-
/// global-state flake class). Poison-tolerant: a panicking test still yields
/// the guard so the next test isn't blocked.
#[cfg(test)]
pub(crate) fn fed_pin_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Unit tests — pure-function and verifier coverage. Integration tests
// (anything requiring on-disk PEM fixtures end-to-end) live in
// `tests/tls_integration.rs` so the bin's compile time stays small.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::danger::ClientCertVerifier;

    /// Convenience: write `body` to a temp file and return the temp file
    /// (kept so the caller can `tmp.path()`).
    fn write_tmp(body: &str) -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), body).unwrap();
        tmp
    }

    // -----------------------------------------------------------------------
    // Allowlist parser
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_allowlist_empty_file_errors() {
        // An empty allowlist file produces an empty set. The "refuse to
        // start" check lives in `load_mtls_rustls_config`, not the parser
        // — so the parser succeeds with zero entries.
        let tmp = write_tmp("");
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert!(set.is_empty());
    }

    #[tokio::test]
    async fn test_allowlist_only_comments_errors() {
        // Comment-only file should likewise produce an empty set; the
        // empty-allowlist guard is enforced one layer up.
        let tmp = write_tmp("# header\n# more\n  # indented\n");
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert!(set.is_empty());
    }

    #[tokio::test]
    async fn test_allowlist_single_valid_fp() {
        let fp = "a".repeat(64);
        let tmp = write_tmp(&format!("{fp}\n"));
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xaa; 32]));
    }

    #[tokio::test]
    async fn test_allowlist_with_colons() {
        let fp = format!("{}:{}", "b".repeat(32), "b".repeat(32));
        let tmp = write_tmp(&format!("{fp}\n"));
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xbb; 32]));
    }

    #[tokio::test]
    async fn test_allowlist_sha256_prefix() {
        let fp = format!("sha256:{}", "c".repeat(64));
        let tmp = write_tmp(&format!("{fp}\n"));
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xcc; 32]));
    }

    /// Issue #358 — trailing inline comment after a fingerprint must parse.
    #[tokio::test]
    async fn test_allowlist_inline_comment() {
        let fp = "d".repeat(64);
        let body = format!("{fp}  # node-1 mTLS\n");
        let tmp = write_tmp(&body);
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xdd; 32]));
    }

    #[tokio::test]
    async fn test_allowlist_too_short_errors() {
        let tmp = write_tmp(&"a".repeat(63));
        let err = load_fingerprint_allowlist(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("expected 64 hex chars"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_allowlist_too_long_errors() {
        let tmp = write_tmp(&"a".repeat(65));
        let err = load_fingerprint_allowlist(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("expected 64 hex chars"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_allowlist_invalid_hex_errors() {
        // 64 chars, but `z` is non-hex → must hit the strict char check.
        let mut s = "a".repeat(63);
        s.push('z');
        let tmp = write_tmp(&s);
        let err = load_fingerprint_allowlist(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("unexpected character"),
            "got: {err}"
        );
    }

    /// Issue #338 — embedded whitespace inside the hex run must error
    /// with "unexpected character", not silently get stripped.
    #[tokio::test]
    async fn test_allowlist_embedded_whitespace_errors() {
        let body = format!("{} {}\n", "a".repeat(32), "a".repeat(32));
        let tmp = write_tmp(&body);
        let err = load_fingerprint_allowlist(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("unexpected character"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_allowlist_tab_in_hex_errors() {
        let body = format!("{}\t{}\n", "a".repeat(32), "a".repeat(32));
        let tmp = write_tmp(&body);
        let err = load_fingerprint_allowlist(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("unexpected character"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_allowlist_blank_lines_skipped() {
        let fp = "a".repeat(64);
        let body = format!("\n\n  \n{fp}\n\n   \n");
        let tmp = write_tmp(&body);
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 1);
    }

    #[tokio::test]
    async fn test_allowlist_multiple_entries() {
        let fp_a = "a".repeat(64);
        let fp_b = "b".repeat(64);
        let fp_c = format!("{}:{}", "c".repeat(32), "c".repeat(32));
        let body = format!(
            "# header\n\
             {fp_a}\n\
             sha256:{fp_b}\n\
             {fp_c}\n"
        );
        let tmp = write_tmp(&body);
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&[0xaa; 32]));
        assert!(set.contains(&[0xbb; 32]));
        assert!(set.contains(&[0xcc; 32]));
    }

    #[tokio::test]
    async fn test_allowlist_duplicate_entries_dedup() {
        let fp = "e".repeat(64);
        let body = format!("{fp}\n{fp}\n{fp}\n");
        let tmp = write_tmp(&body);
        let set = load_fingerprint_allowlist(tmp.path()).await.unwrap();
        // HashSet collapses dupes — exactly one fingerprint registered.
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xee; 32]));
    }

    // -----------------------------------------------------------------------
    // PEM parsers
    // -----------------------------------------------------------------------

    #[test]
    fn test_pem_iter_certs_empty_errors() {
        let err = rustls_pki_pem_iter_certs(b"").unwrap_err();
        // No certs at all → either parse-error or "contained no certificates".
        // The empty input is not a parse failure, it's just zero certs.
        assert!(
            err.to_string().contains("no certificates")
                || err.to_string().contains("failed to parse"),
            "got: {err}"
        );
    }

    #[test]
    fn test_pem_iter_certs_garbage_errors() {
        let err = rustls_pki_pem_iter_certs(b"not a pem file\n").unwrap_err();
        assert!(
            err.to_string().contains("no certificates")
                || err.to_string().contains("failed to parse"),
            "got: {err}"
        );
    }

    #[test]
    fn test_pem_iter_certs_single_cert() {
        let pem = std::fs::read("tests/fixtures/tls/valid_cert.pem")
            .expect("regenerate fixtures via tests/fixtures/tls/regenerate.sh");
        let certs = rustls_pki_pem_iter_certs(&pem).unwrap();
        assert_eq!(
            certs.len(),
            1,
            "expected exactly one cert in valid_cert.pem"
        );
    }

    #[test]
    fn test_pem_iter_certs_chain() {
        let pem = std::fs::read("tests/fixtures/tls/cert_chain.pem")
            .expect("regenerate fixtures via tests/fixtures/tls/regenerate.sh");
        let certs = rustls_pki_pem_iter_certs(&pem).unwrap();
        assert!(
            certs.len() >= 2,
            "expected leaf + intermediate, got {}",
            certs.len()
        );
    }

    #[test]
    fn test_pem_parse_pkcs8_key() {
        let pem = std::fs::read("tests/fixtures/tls/valid_key_pkcs8.pem")
            .expect("regenerate fixtures via tests/fixtures/tls/regenerate.sh");
        let key = rustls_pki_pem_parse_private_key(&pem).unwrap();
        // PKCS#8 envelopes RSA / ECDSA / Ed25519. The discriminant tells us
        // rustls picked the right branch — any PrivateKeyDer variant is fine.
        let _ = key;
    }

    #[test]
    fn test_pem_parse_rsa_key() {
        let pem = std::fs::read("tests/fixtures/tls/valid_key_rsa.pem")
            .expect("regenerate fixtures via tests/fixtures/tls/regenerate.sh");
        let key = rustls_pki_pem_parse_private_key(&pem).unwrap();
        let _ = key;
    }

    #[test]
    fn test_pem_parse_sec1_key() {
        let pem = std::fs::read("tests/fixtures/tls/valid_key_sec1.pem")
            .expect("regenerate fixtures via tests/fixtures/tls/regenerate.sh");
        let key = rustls_pki_pem_parse_private_key(&pem).unwrap();
        let _ = key;
    }

    #[test]
    fn test_pem_parse_garbage_errors() {
        let err = rustls_pki_pem_parse_private_key(b"not a pem file\n").unwrap_err();
        assert!(err.to_string().contains("failed to parse TLS key PEM"));
    }

    // -----------------------------------------------------------------------
    // hex_short
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_short_format() {
        // 6 bytes prefix → 12 hex chars + ellipsis.
        let mut fp = [0u8; 32];
        fp[0] = 0xde;
        fp[1] = 0xad;
        fp[2] = 0xbe;
        fp[3] = 0xef;
        fp[4] = 0x12;
        fp[5] = 0x34;
        // Bytes 6..32 must NOT appear in the output.
        for (i, slot) in fp.iter_mut().enumerate().skip(6) {
            *slot = (i as u8).wrapping_mul(7);
        }
        assert_eq!(hex_short(&fp), "deadbeef1234…");
    }

    #[test]
    fn test_hex_short_truncates_to_6_bytes() {
        let fp = [0xff; 32];
        let s = hex_short(&fp);
        // Strip the trailing ellipsis (`…` is 3 bytes in UTF-8).
        let hex_only = s.trim_end_matches('…');
        assert_eq!(hex_only.len(), 12, "expected 6 bytes = 12 hex chars");
        assert_eq!(hex_only, "ffffffffffff");
    }

    // -----------------------------------------------------------------------
    // FingerprintAllowlistVerifier
    // -----------------------------------------------------------------------

    #[test]
    fn test_verifier_accepts_allowlisted_fp() {
        use sha2::{Digest, Sha256};
        // Synthesize a "cert" — the verifier doesn't validate ASN.1 here,
        // only hashes the DER bytes. Any byte slice works; we just need
        // the fingerprint and the cert bytes to match.
        let fake_cert = b"fake certificate DER bytes for fingerprint test";
        let fp: [u8; 32] = Sha256::digest(fake_cert).into();
        let mut allowlist = HashSet::new();
        allowlist.insert(fp);
        let verifier = FingerprintAllowlistVerifier { allowlist };
        let cert = rustls::pki_types::CertificateDer::from(fake_cert.to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let result = verifier.verify_client_cert(&cert, &[], now);
        assert!(result.is_ok(), "expected accept, got: {result:?}");
    }

    #[test]
    fn test_verifier_rejects_unknown_fp() {
        let allowlist = HashSet::new();
        let verifier = FingerprintAllowlistVerifier { allowlist };
        let cert = rustls::pki_types::CertificateDer::from(b"unknown".to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let err = verifier.verify_client_cert(&cert, &[], now).unwrap_err();
        assert!(
            err.to_string().contains("not in mTLS allowlist"),
            "got: {err}"
        );
    }

    #[test]
    fn test_verifier_error_includes_truncated_fp() {
        let allowlist = HashSet::new();
        let verifier = FingerprintAllowlistVerifier { allowlist };
        let cert_bytes = b"some cert that won't be in the allowlist";
        let cert = rustls::pki_types::CertificateDer::from(cert_bytes.to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let err = verifier.verify_client_cert(&cert, &[], now).unwrap_err();
        let msg = err.to_string();
        // Compute the expected truncated fp prefix and assert it's present.
        use sha2::{Digest, Sha256};
        let fp: [u8; 32] = Sha256::digest(cert_bytes).into();
        let short = hex_short(&fp);
        assert!(msg.contains(&short), "expected fp {short} in: {msg}");
        // And the trailing `…` must be there — the fp must be truncated,
        // not full-length.
        assert!(msg.contains('…'), "expected truncation marker in: {msg}");
    }

    #[test]
    fn test_verifier_offer_client_auth_returns_true() {
        let verifier = FingerprintAllowlistVerifier {
            allowlist: HashSet::new(),
        };
        assert!(verifier.offer_client_auth());
    }

    #[test]
    fn test_verifier_client_auth_mandatory_returns_true() {
        let verifier = FingerprintAllowlistVerifier {
            allowlist: HashSet::new(),
        };
        assert!(verifier.client_auth_mandatory());
        // Also exercise root_hint_subjects — it's a one-line getter that
        // would otherwise sit at zero coverage.
        assert_eq!(verifier.root_hint_subjects().len(), 0);
    }

    /// Build a bogus `DigitallySignedStruct` from the on-the-wire byte
    /// format: 2-byte big-endian scheme + 2-byte big-endian signature
    /// length + N signature bytes. `DigitallySignedStruct::new` is
    /// crate-private in rustls 0.23, but the wire decoder is reachable
    /// through `rustls::internal::msgs::codec::{Codec, Reader}`.
    fn bogus_dss() -> rustls::DigitallySignedStruct {
        use rustls::internal::msgs::codec::{Codec, Reader};
        // ED25519 = 0x0807. Sig length = 0x0040 (64). Then 64 zero bytes.
        let mut wire = Vec::with_capacity(4 + 64);
        wire.extend_from_slice(&[0x08, 0x07]);
        wire.extend_from_slice(&[0x00, 0x40]);
        wire.extend_from_slice(&[0u8; 64]);
        let mut reader = Reader::init(&wire);
        rustls::DigitallySignedStruct::read(&mut reader)
            .expect("hand-rolled wire bytes must round-trip the Codec")
    }

    /// Exercise the rustls `verify_tls{12,13}_signature` + `supported_verify_schemes`
    /// trait methods on `FingerprintAllowlistVerifier`. We feed them a
    /// deliberately invalid signature so the underlying ring-backed
    /// verifier returns Err — that's fine, the test only asserts the
    /// method runs to completion (covers the body) without panicking.
    #[test]
    fn test_verifier_signature_methods_run() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = FingerprintAllowlistVerifier {
            allowlist: HashSet::new(),
        };
        // supported_verify_schemes is pure — must return non-empty.
        let schemes = verifier.supported_verify_schemes();
        assert!(
            !schemes.is_empty(),
            "ring provider must expose at least one signature scheme"
        );

        // verify_tls{12,13}_signature: feed bogus inputs and expect Err.
        let cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let dss = bogus_dss();
        let _ = verifier.verify_tls12_signature(b"bogus message", &cert, &dss);
        let _ = verifier.verify_tls13_signature(b"bogus message", &cert, &dss);
    }

    // -----------------------------------------------------------------------
    // DangerousAnyServerVerifier — the sync-daemon's client-side verifier.
    // verify_server_cert always Ok; the signature methods delegate to the
    // ring provider exactly like the server-side verifier above.
    // -----------------------------------------------------------------------

    #[test]
    fn test_dangerous_any_server_verifier_accepts_any_cert() {
        use rustls::client::danger::ServerCertVerifier;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = DangerousAnyServerVerifier;
        let cert = rustls::pki_types::CertificateDer::from(b"any bytes here".to_vec());
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let now = rustls::pki_types::UnixTime::now();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(
            result.is_ok(),
            "DangerousAnyServerVerifier accepts any cert (compensating mTLS control)"
        );
    }

    #[test]
    fn test_dangerous_any_server_verifier_signature_methods_run() {
        use rustls::client::danger::ServerCertVerifier;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = DangerousAnyServerVerifier;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());

        let cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let dss = bogus_dss();
        let _ = verifier.verify_tls12_signature(b"bogus message", &cert, &dss);
        let _ = verifier.verify_tls13_signature(b"bogus message", &cert, &dss);
    }

    // -----------------------------------------------------------------------
    // FingerprintPinServerVerifier (#1678) — outbound server-cert pinning.
    // Mirror of the inbound FingerprintAllowlistVerifier tests above.
    // -----------------------------------------------------------------------

    fn server_name(host: &str) -> rustls::pki_types::ServerName<'static> {
        rustls::pki_types::ServerName::try_from(host.to_string()).unwrap()
    }

    /// Build a single-host pin map: `host` → SHA-256(`cert_bytes`).
    fn pin_map(host: &str, cert_bytes: &[u8]) -> HashMap<String, HashSet<[u8; 32]>> {
        use sha2::{Digest, Sha256};
        let fp: [u8; 32] = Sha256::digest(cert_bytes).into();
        let mut set = HashSet::new();
        set.insert(fp);
        let mut map = HashMap::new();
        map.insert(normalize_host_key(host), set);
        map
    }

    #[test]
    fn pin_verifier_accepts_matching_fingerprint() {
        use rustls::client::danger::ServerCertVerifier;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_bytes = b"pinned peer server cert DER";
        let verifier = FingerprintPinServerVerifier::new(
            pin_map("peer.example", cert_bytes),
            UnpinnedHostPolicy::Reject,
        );
        let cert = rustls::pki_types::CertificateDer::from(cert_bytes.to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let res = verifier.verify_server_cert(&cert, &[], &server_name("peer.example"), &[], now);
        assert!(res.is_ok(), "matching pinned fp must be accepted: {res:?}");
    }

    #[test]
    fn pin_verifier_rejects_wrong_fingerprint_for_pinned_host() {
        use rustls::client::danger::ServerCertVerifier;
        let verifier = FingerprintPinServerVerifier::new(
            pin_map("peer.example", b"the pinned cert"),
            UnpinnedHostPolicy::AcceptAny,
        );
        // Different cert bytes for the SAME pinned host → must reject even
        // though the fallthrough is AcceptAny (a pinned host is fail-closed).
        let cert = rustls::pki_types::CertificateDer::from(b"an IMPOSTER cert".to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let err = verifier
            .verify_server_cert(&cert, &[], &server_name("peer.example"), &[], now)
            .unwrap_err();
        assert!(
            err.to_string().contains("not pinned for host"),
            "got: {err}"
        );
    }

    #[test]
    fn pin_verifier_reject_policy_refuses_unpinned_host() {
        use rustls::client::danger::ServerCertVerifier;
        let verifier = FingerprintPinServerVerifier::new(
            pin_map("peer.example", b"pinned cert"),
            UnpinnedHostPolicy::Reject,
        );
        let cert = rustls::pki_types::CertificateDer::from(b"whatever".to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let err = verifier
            .verify_server_cert(&cert, &[], &server_name("other.example"), &[], now)
            .unwrap_err();
        assert!(err.to_string().contains("is not pinned"), "got: {err}");
    }

    #[test]
    fn pin_verifier_acceptany_policy_passes_unpinned_host() {
        use rustls::client::danger::ServerCertVerifier;
        let verifier = FingerprintPinServerVerifier::new(
            pin_map("peer.example", b"pinned cert"),
            UnpinnedHostPolicy::AcceptAny,
        );
        let cert = rustls::pki_types::CertificateDer::from(b"unpinned-host cert".to_vec());
        let now = rustls::pki_types::UnixTime::now();
        let res = verifier.verify_server_cert(&cert, &[], &server_name("other.example"), &[], now);
        assert!(
            res.is_ok(),
            "AcceptAny fallthrough must pass unpinned host: {res:?}"
        );
    }

    /// CRITICAL (#1678 5-agent vote 4d3ea1c5): the pin verifier MUST do REAL
    /// handshake-signature verification, never a stub. A stubbed
    /// `verify_tls13_signature` returning Ok would accept a replayed pinned
    /// cert the attacker never held the key for. Feed a bogus signature and
    /// assert the method returns Err — proving it delegates to the real
    /// ring-backed `rustls::crypto::verify_tls13_signature`.
    #[test]
    fn pin_verifier_signature_methods_are_not_stubbed() {
        use rustls::client::danger::ServerCertVerifier;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier =
            FingerprintPinServerVerifier::new(HashMap::new(), UnpinnedHostPolicy::Reject);
        assert!(!verifier.supported_verify_schemes().is_empty());
        let cert = rustls::pki_types::CertificateDer::from(vec![0u8; 32]);
        let dss = bogus_dss();
        assert!(
            verifier
                .verify_tls12_signature(b"bogus", &cert, &dss)
                .is_err(),
            "verify_tls12_signature must REJECT a bogus signature (real crypto, not a stub)"
        );
        assert!(
            verifier
                .verify_tls13_signature(b"bogus", &cert, &dss)
                .is_err(),
            "verify_tls13_signature must REJECT a bogus signature (real crypto, not a stub)"
        );
    }

    /// The v2 TOP_RISK: URL host → rustls `ServerName` must round-trip to the
    /// same canonical key that `normalize_host_key` produces at load time,
    /// for both DNS names (case-folded) and IP literals.
    #[test]
    fn peer_pin_host_key_round_trips() {
        // DNS, mixed case → both sides lowercase.
        assert_eq!(normalize_host_key("Peer.Example.COM"), "peer.example.com");
        assert_eq!(
            server_name_host_key(&server_name("Peer.Example.COM")).as_deref(),
            Some("peer.example.com")
        );
        // IPv4 literal → identical canonical string on both sides.
        assert_eq!(normalize_host_key("192.168.1.5"), "192.168.1.5");
        assert_eq!(
            server_name_host_key(&server_name("192.168.1.5")).as_deref(),
            Some("192.168.1.5")
        );
    }

    #[test]
    fn peer_fingerprint_map_parses_host_and_fp() {
        let fp_a = "a".repeat(64);
        let fp_b = format!("{}:{}", "b".repeat(32), "b".repeat(32));
        let body = format!(
            "# comment line\n\
             peer-one.example {fp_a}\n\
             \n\
             PEER-TWO.example sha256:{fp_b}   # inline note\n\
             peer-one.example {}\n", // second fp for host one (rotation)
            "c".repeat(64)
        );
        let tmp = write_tmp(&body);
        let map = load_peer_fingerprint_map(tmp.path()).unwrap();
        assert_eq!(map.len(), 2, "two distinct hosts");
        assert_eq!(
            map["peer-one.example"].len(),
            2,
            "host one has two pinned fps"
        );
        assert!(
            map.contains_key("peer-two.example"),
            "host key is lowercased"
        );
    }

    #[test]
    fn peer_fingerprint_map_empty_file_is_fail_closed_error() {
        let tmp = write_tmp("# only comments\n\n   \n");
        let err = load_peer_fingerprint_map(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("contained no entries"),
            "got: {err}"
        );
    }

    #[test]
    fn peer_fingerprint_map_rejects_missing_fingerprint_field() {
        let tmp = write_tmp("peer-one.example\n");
        let err = load_peer_fingerprint_map(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("expected"), "got: {err}");
    }

    #[test]
    fn peer_fingerprint_map_rejects_extra_field() {
        let body = format!("peer.example {} extra-junk\n", "a".repeat(64));
        let tmp = write_tmp(&body);
        let err = load_peer_fingerprint_map(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("exactly two fields"), "got: {err}");
    }

    #[test]
    fn peer_fingerprint_env_unset_returns_none() {
        let _g = super::fed_pin_env_lock();
        // SAFETY: serialised via fed_pin_env_lock(); the only other writer of
        // this var (the federation::peer build-pinning test) takes the same
        // lock, so no concurrent reader observes the transient state.
        unsafe {
            std::env::remove_var(FED_PEER_FINGERPRINTS_ENV);
        }
        assert!(peer_fingerprint_map_from_env().unwrap().is_none());
    }

    #[test]
    fn select_sync_tls_mode_precedence_1794() {
        // Pinning wins over the insecure opt-out — a pinned host is verified
        // by fingerprint, so #2448's require-flag never refuses it.
        assert_eq!(
            select_sync_tls_mode(true, true, true).unwrap(),
            SyncTlsMode::Pinning
        );
        assert_eq!(
            select_sync_tls_mode(false, true, true).unwrap(),
            SyncTlsMode::Pinning
        );
        // Explicit insecure opt-out when pinning is off — only reachable once
        // the operator ALSO clears the #2448 require-flag.
        assert_eq!(
            select_sync_tls_mode(true, false, false).unwrap(),
            SyncTlsMode::AcceptAny
        );
        // Secure default — CA validation.
        assert_eq!(
            select_sync_tls_mode(false, false, true).unwrap(),
            SyncTlsMode::CaValidated
        );
        assert_eq!(
            select_sync_tls_mode(false, false, false).unwrap(),
            SyncTlsMode::CaValidated
        );
    }

    /// #2448 — the accept-ANY arm is fail-closed at the mode selector, so no
    /// caller can resolve it while server verification is required. The
    /// refusal must name the SECURE remedies before the escape hatch.
    #[test]
    fn select_sync_tls_mode_refuses_accept_any_when_verify_required_2448() {
        let err = select_sync_tls_mode(true, false, true)
            .expect_err("insecure opt-out must be refused while verification is required");
        let msg = err.to_string();
        assert!(msg.contains("--insecure-skip-server-verify"), "{msg}");
        // Secure remedies first…
        assert!(msg.contains("--ca-cert"), "{msg}");
        assert!(msg.contains(FED_PEER_FINGERPRINTS_ENV), "{msg}");
        // …escape hatch named last, so an operator reading the refusal is
        // steered to fix the posture rather than to disable the control.
        assert!(msg.contains(FED_REQUIRE_SERVER_VERIFY_ENV), "{msg}");
        assert!(
            msg.find("--ca-cert").unwrap() < msg.find(FED_REQUIRE_SERVER_VERIFY_ENV).unwrap(),
            "the secure remedy must precede the escape hatch: {msg}"
        );
    }

    /// #2448 — the require-flag follows the house default-ON federation-knob
    /// grammar: only an explicit falsy token disables it.
    #[test]
    fn server_verify_required_default_on_grammar_2448() {
        let _guard = fed_pin_env_lock();
        // SAFETY: the process-wide env mutation is serialized by the shared
        // federation-TLS test lock taken above.
        unsafe { std::env::remove_var(FED_REQUIRE_SERVER_VERIFY_ENV) };
        assert!(server_verify_required(), "unset ⇒ required (fail-closed)");
        for falsy in ["0", "false", "no", "off", " off "] {
            unsafe { std::env::set_var(FED_REQUIRE_SERVER_VERIFY_ENV, falsy) };
            assert!(!server_verify_required(), "{falsy:?} ⇒ permissive");
        }
        for truthy in ["1", "true", "yes", "on", "", "banana"] {
            unsafe { std::env::set_var(FED_REQUIRE_SERVER_VERIFY_ENV, truthy) };
            assert!(server_verify_required(), "{truthy:?} ⇒ required");
        }
        unsafe { std::env::remove_var(FED_REQUIRE_SERVER_VERIFY_ENV) };
    }

    #[test]
    fn build_pinning_client_config_with_client_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");
        let cfg = build_rustls_pinning_client_config(
            pin_map("peer.example", b"x"),
            Some(cert.as_path()),
            Some(key.as_path()),
        )
        .expect("pinning client config with client cert (mTLS identity) must build");
        drop(cfg);
    }

    #[test]
    fn build_pinning_client_config_without_client_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = build_rustls_pinning_client_config(pin_map("peer.example", b"x"), None, None)
            .expect("pinning client config with no client auth must build");
        drop(cfg);
    }

    // -----------------------------------------------------------------------
    // H3 — TLS version pinning. Both server configs MUST negotiate only
    // TLS 1.2 or TLS 1.3; legacy versions are off the table.
    // -----------------------------------------------------------------------

    #[test]
    fn test_supported_protocol_versions_pinned_to_tls12_and_tls13() {
        // The exported constant must list exactly TLS 1.3 (preferred) and
        // TLS 1.2 (floor) in that order. If a future rustls upgrade adds
        // a fourth `SupportedProtocolVersion` we want this test to fail
        // so the H3 review surfaces the change.
        assert_eq!(
            SUPPORTED_PROTOCOL_VERSIONS.len(),
            2,
            "expected exactly 2 pinned versions (TLS 1.3 + TLS 1.2)"
        );
        // rustls's `SupportedProtocolVersion::version` exposes the
        // wire-level `ProtocolVersion` enum. TLS 1.3 = 0x0304,
        // TLS 1.2 = 0x0303 (per RFC 8446 §4.1.2 / RFC 5246 §A.1).
        let v0 = SUPPORTED_PROTOCOL_VERSIONS[0].version;
        let v1 = SUPPORTED_PROTOCOL_VERSIONS[1].version;
        assert_eq!(v0, rustls::ProtocolVersion::TLSv1_3, "TLS 1.3 preferred");
        assert_eq!(v1, rustls::ProtocolVersion::TLSv1_2, "TLS 1.2 floor");
    }

    #[tokio::test]
    async fn test_load_rustls_config_pins_tls13_and_tls12() {
        // End-to-end: build a real ServerConfig via the production
        // helper and assert it accepts ONLY TLS 1.2 + TLS 1.3.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");

        // `rustls::ServerConfig`'s `versions` field is private in 0.23+,
        // so we assert version pinning at the input layer (the
        // `SUPPORTED_PROTOCOL_VERSIONS` constant the production builder
        // consumes) and rely on the test above
        // (`test_supported_protocol_versions_pinned_to_tls12_and_tls13`)
        // for the strict version-list assertion. Here we just confirm
        // the production async path consumes that constant successfully.
        let _config = load_rustls_config(&cert, &key)
            .await
            .expect("load_rustls_config must succeed with valid fixtures");

        // And exercise the mTLS path's protocol pinning by building a
        // FingerprintAllowlistVerifier + ServerConfig with the same
        // version-list input the production builder uses. A successful
        // build is sufficient — rustls refuses to construct a
        // ServerConfig if the version list is empty or malformed.
        let cert_pem = std::fs::read(&cert).unwrap();
        let key_pem = std::fs::read(&key).unwrap();
        let certs = rustls_pki_pem_iter_certs(&cert_pem).unwrap();
        let signing_key = rustls_pki_pem_parse_private_key(&key_pem).unwrap();
        let _server_config =
            rustls::ServerConfig::builder_with_protocol_versions(SUPPORTED_PROTOCOL_VERSIONS)
                .with_no_client_auth()
                .with_single_cert(certs, signing_key)
                .expect("ServerConfig with pinned versions must build");
    }

    // -----------------------------------------------------------------------
    // H4 — loose-permission warning. The check is best-effort + WARN-only
    // by design; we exercise the path on Unix where it has observable
    // semantics, and confirm it's a no-op when permissions are tight.
    // -----------------------------------------------------------------------

    /// Shared `MakeWriter` shim for the H4 WARN-capture tests. Uses an
    /// `Arc<Mutex<Vec<u8>>>` so the test can inspect every byte the
    /// subscriber emitted after the WARN call. Defined outside the
    /// per-test fn so the `MakeWriter` impl is namespace-stable.
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct WarnBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(unix)]
    impl std::io::Write for WarnBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WarnBuf {
        type Writer = WarnBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_key_perms_loose_emits_warn_on_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        use tracing::Level;

        let sink = WarnBuf::default();
        let buf = sink.0.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_writer(sink)
            .without_time()
            .finish();

        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), b"dummy keymat").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        tracing::subscriber::with_default(subscriber, || {
            warn_if_key_perms_loose(key.path());
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("group- or world-accessible"),
            "expected WARN about loose perms, got: {captured:?}"
        );
        assert!(
            captured.contains("0600"),
            "expected guidance pointer to 0600 in WARN, got: {captured:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_key_perms_loose_silent_on_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        use tracing::Level;

        let sink = WarnBuf::default();
        let buf = sink.0.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_writer(sink)
            .without_time()
            .finish();

        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), b"dummy keymat").unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600)).unwrap();

        tracing::subscriber::with_default(subscriber, || {
            warn_if_key_perms_loose(key.path());
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            !captured.contains("group- or world-accessible"),
            "0600 perms must NOT trigger the WARN; got: {captured:?}"
        );
    }

    // -----------------------------------------------------------------------
    // M1 — constant-time allowlist membership. We can't assert timing
    // directly in a unit test (jitter / scheduler noise), but we can
    // assert the correctness of the function on a populated allowlist
    // and on a near-miss (single-byte difference) to confirm the
    // XOR-fold runs the full 32 bytes before reporting.
    // -----------------------------------------------------------------------

    #[test]
    fn test_allowlist_contains_ct_matches_real_entry() {
        let mut allowlist = HashSet::new();
        allowlist.insert([0xaa; 32]);
        allowlist.insert([0xbb; 32]);
        allowlist.insert([0xcc; 32]);
        assert!(allowlist_contains_ct(&allowlist, &[0xbb; 32]));
    }

    #[test]
    fn test_allowlist_contains_ct_rejects_one_byte_off() {
        let mut allowlist = HashSet::new();
        allowlist.insert([0xaa; 32]);
        let mut near = [0xaa; 32];
        near[31] = 0xab; // single-byte flip
        assert!(!allowlist_contains_ct(&allowlist, &near));
    }

    #[test]
    fn test_allowlist_contains_ct_empty_allowlist_rejects() {
        let allowlist = HashSet::new();
        assert!(!allowlist_contains_ct(&allowlist, &[0u8; 32]));
    }

    // -----------------------------------------------------------------------
    // C-5 (#699): close the `load_mtls_rustls_config` gap.
    //
    // The mTLS server config path was completely uncovered at lib-tier
    // (38 lines / 38 misses → tls.rs sat at 92.94%). These tests drive
    // the happy path against the real PEM fixtures, the empty-allowlist
    // refusal, and the read-error branches for the cert + key paths.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_load_mtls_rustls_config_happy_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");
        // Build a single-entry allowlist on disk; the parser converts hex
        // into a [u8; 32] which goes into the verifier. Hex content is
        // irrelevant to the builder — it just needs to be non-empty so
        // the empty-allowlist refusal does not trip.
        let allowlist = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(allowlist.path(), format!("{}\n", "a".repeat(64))).unwrap();

        let config = load_mtls_rustls_config(&cert, &key, allowlist.path())
            .await
            .expect("mTLS server config build with valid cert+key+allowlist");
        // Returned RustlsConfig is opaque; success of the ?-cascade is
        // the contract.
        drop(config);
    }

    #[tokio::test]
    async fn test_load_mtls_rustls_config_empty_allowlist_refuses() {
        // Line 148-152: the operator-friendly refusal when an allowlist
        // file parses but contains zero fingerprints. We deliberately
        // never reach the cert/key reads.
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");
        let allowlist = tempfile::NamedTempFile::new().unwrap();
        // Comment-only allowlist — parses successfully, but the set is empty.
        std::fs::write(allowlist.path(), "# nothing here\n").unwrap();

        let err = load_mtls_rustls_config(&cert, &key, allowlist.path())
            .await
            .expect_err("empty allowlist must refuse to start");
        let msg = err.to_string();
        assert!(
            msg.contains("empty") && msg.contains("refuse"),
            "expected refuse-to-start error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_load_mtls_rustls_config_missing_cert_errors() {
        // Line 156-158: cert-read failure path inside the mTLS builder.
        let cert = std::path::PathBuf::from("/does/not/exist/mtls-cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");
        let allowlist = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(allowlist.path(), format!("{}\n", "b".repeat(64))).unwrap();

        let err = load_mtls_rustls_config(&cert, &key, allowlist.path())
            .await
            .expect_err("missing cert must error");
        assert!(
            err.to_string().contains("failed to read TLS cert"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_load_mtls_rustls_config_missing_key_errors() {
        // Line 159-161: key-read failure path inside the mTLS builder.
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from("/does/not/exist/mtls-key.pem");
        let allowlist = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(allowlist.path(), format!("{}\n", "c".repeat(64))).unwrap();

        let err = load_mtls_rustls_config(&cert, &key, allowlist.path())
            .await
            .expect_err("missing key must error");
        assert!(
            err.to_string().contains("failed to read TLS key"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_load_mtls_rustls_config_missing_allowlist_errors() {
        // The first read inside load_mtls_rustls_config — the allowlist
        // file itself — must surface a clean error envelope when the
        // file does not exist.
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls/valid_key_pkcs8.pem");
        let allowlist = std::path::PathBuf::from("/does/not/exist/allowlist.txt");

        let err = load_mtls_rustls_config(&cert, &key, &allowlist)
            .await
            .expect_err("missing allowlist must error");
        assert!(
            err.to_string().contains("failed to read mTLS allowlist"),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // #2045 L6 — cert-peer-binding acceptor glue.
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_bound_peer_id_matches_and_degrades() {
        use sha2::{Digest, Sha256};
        let leaf = rustls::pki_types::CertificateDer::from(vec![1u8, 2, 3, 4]);
        let fp: [u8; 32] = Sha256::digest([1u8, 2, 3, 4]).into();
        let mut map: HashMap<[u8; 32], String> = HashMap::new();
        map.insert(fp, "peer-x".to_string());
        // Presenting leaf's fingerprint is bound → its operator peer-id.
        assert_eq!(
            resolve_bound_peer_id(Some(std::slice::from_ref(&leaf)), &map).as_deref(),
            Some("peer-x")
        );
        // No client cert at all (non-mTLS) → None.
        assert_eq!(resolve_bound_peer_id(None, &map), None);
        assert_eq!(resolve_bound_peer_id(Some(&[]), &map), None);
        // Cert present but its fingerprint carries no binding (legacy) → None.
        let other = rustls::pki_types::CertificateDer::from(vec![9u8, 9, 9]);
        assert_eq!(
            resolve_bound_peer_id(Some(std::slice::from_ref(&other)), &map),
            None
        );
    }

    #[tokio::test]
    async fn cert_extension_service_injects_extension() {
        use tower::ServiceExt as _;
        // Inner service echoes back whatever ClientCertPeerId the wrapper
        // inserted into the request extensions.
        let inner = tower::service_fn(|req: axum::http::Request<()>| async move {
            let got = req.extensions().get::<ClientCertPeerId>().cloned();
            Ok::<_, std::convert::Infallible>(got)
        });
        let svc = CertExtensionService {
            inner,
            cert_peer_id: ClientCertPeerId(Some("peer-x".to_string())),
        };
        let echoed = svc
            .oneshot(axum::http::Request::new(()))
            .await
            .expect("inner service infallible");
        assert_eq!(
            echoed.expect("extension must be present").0.as_deref(),
            Some("peer-x"),
            "CertExtensionService::call must inject the ClientCertPeerId extension"
        );
    }

    #[test]
    fn two_whitespace_fields_enforces_exactly_two() {
        assert_eq!(
            two_whitespace_fields("a  b", "L", "`<a> <b>`", 1).unwrap(),
            ("a", "b")
        );
        assert!(
            two_whitespace_fields("a", "L", "`<a> <b>`", 1)
                .unwrap_err()
                .to_string()
                .contains("got only")
        );
        assert!(
            two_whitespace_fields("a b c", "L", "`<a> <b>`", 1)
                .unwrap_err()
                .to_string()
                .contains("exactly two")
        );
    }
}
