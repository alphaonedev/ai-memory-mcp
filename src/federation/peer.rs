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

/// #2442 — prefix of the stable, identity-derived [`PeerEndpoint::id`].
///
/// Two characters are load-bearing, neither is decoration:
///
/// * `h` ("hash") makes a minted id STRUCTURALLY unable to collide with the
///   pre-#2442 positional shape `peer-<digits>`. Hex nibbles are
///   all-decimal-digits a non-trivial fraction of the time, so without the
///   `h` a freshly minted id could impersonate a legacy DLQ routing key and
///   be misread by [`is_legacy_positional_peer_id`]. `h` is a constant, never
///   attacker-influenced, so no URL can be crafted to mint a legacy-looking
///   id.
/// * `1` is the DERIVATION VERSION, and it exists because the id is a durable
///   key. See [`PEER_ID_DERIVATION_DOMAIN`] — if the derivation ever changes,
///   the version must go to `2` so the shape is greppable and the two
///   generations are structurally distinguishable in a `federation_push_dlq`
///   table that will contain both.
const STABLE_PEER_ID_PREFIX: &str = "peer-h1";

/// #2442 — domain-separation + version tag hashed IN FRONT of the normalised
/// URL, so the peer id is not a bare `SHA-256(url)` that could alias any other
/// URL digest in the system, and so the derivation carries its own version.
///
/// This is the tripwire for the one failure mode that would otherwise be
/// silent and fleet-wide. [`normalize_peer_url`] is deliberately shared with
/// the duplicate-URL boot check, and those two consumers have OPPOSING
/// long-run requirements: the duplicate check should normalise MORE over time
/// (IDNA/punycode, default-port stripping, percent-decoding — all real
/// hardening for the `#341` double-count guarantee), whereas the id must
/// normalise IDENTICALLY FOREVER or every persisted DLQ row and `sync_state`
/// entry is orphaned. Whoever correctly hardens the normalisation MUST bump
/// this domain string and [`STABLE_PEER_ID_PREFIX`] to `v2`/`peer-h2` and
/// ship it as a migration. The frozen-digest golden test in
/// `tests/federation_stable_peer_id_2442.rs` exists precisely to go RED and
/// force that decision rather than let it happen by accident.
const PEER_ID_DERIVATION_DOMAIN: &[u8] = b"ai-memory:peer-id:v1\0";

/// #2442 — hex nibbles of the SHA-256 digest retained in a peer id.
///
/// **32 nibbles = 128 bits.** The sizing argument is a SECOND-PREIMAGE
/// argument, not a birthday argument, and that distinction is why this is
/// not the 12 nibbles a pure fleet-size calculation would suggest:
///
/// * The naive argument says 48 bits is plenty. v1.0.0 certifies 500–1000
///   agent clusters, i.e. TENS of federation peers; the birthday collision
///   probability at n peers is ≈ n²/2 ÷ 2⁴⁸, which at n = 100 is ≈ 1.8×10⁻¹¹
///   and even at a pathological n = 10 000 is ≈ 1.8×10⁻⁷.
/// * That argument is WRONG here, because the hash input is
///   OPERATOR-SUPPLIED and an adversary who can get one URL into
///   `--quorum-peers` picks it freely (only the trailing slash and ASCII case
///   are canonicalised — path, port, query and userinfo all survive). The
///   profitable target is a peer that has been REMOVED from the config but
///   whose rows are still sitting in `federation_push_dlq`: grind a URL whose
///   id equals the departed peer's, and `push_dlq::replay_once` hands you
///   another tenant's queued payloads. That is a second-preimage search
///   against one fixed digest — ≈ 2⁴⁸ SHA-256 evaluations, hours of commodity
///   GPU time — and the boot-time collision guard below CANNOT see it,
///   because the victim is not in the config to be compared against.
/// * At 128 bits that search is ≈ 2¹²⁸ and infeasible for any adversary. A
///   *free* collision (both URLs attacker-chosen) is still the 64-bit
///   birthday bound, but a free collision buys nothing: hijacking requires
///   colliding with a SPECIFIC existing peer's URL.
/// * The id must nevertheless stay SHORT and FIXED-WIDTH — it is a durable
///   routing key in `federation_push_dlq.peer_id` and `sync_state.peer_id`,
///   and a structured log field. `peer-h` + 32 = 38 ASCII characters,
///   bounded and constant. Note the `#304` label-space concern that the
///   pre-#2442 comment cited does NOT apply: `PeerEndpoint.id` reaches zero
///   Prometheus labels at v1.0.0 (see the corrected comment in `build`), so
///   widening the digest costs no cardinality.
const STABLE_PEER_ID_HASH_NIBBLES: usize = 32;

/// #2442 — canonical form of a peer URL for IDENTITY purposes.
///
/// This is the single source of truth shared by two callers that MUST agree:
/// the duplicate-URL boot refusal (Ultrareview #341) and [`stable_peer_id`].
/// If they disagreed, two spellings the duplicate check considers identical
/// could mint two different ids — splitting one peer's DLQ rows across two
/// routing keys — or, worse, two spellings it considers distinct could mint
/// one id and MERGE two peers' rows.
///
/// Deliberately NOT used to build `sync_push_url`: lowercasing is safe for
/// scheme+host comparison but would corrupt a case-sensitive path.
#[must_use]
fn normalize_peer_url(raw: &str) -> String {
    raw.trim_end_matches('/').to_ascii_lowercase()
}

/// #2442 — mint the stable, position-independent [`PeerEndpoint::id`].
///
/// ## Why this exists
///
/// The pre-#2442 id was `format!("peer-{i}")` — the `.enumerate()` index of
/// the `--quorum-peers` flag. That id is not a label; it is the DURABLE
/// routing key of the federation push DLQ (`federation_push_dlq.peer_id`,
/// enqueued in `sync.rs`, resolved in `push_dlq::replay_once` by
/// `config.peers.iter().find(|p| p.id == row.peer_id)`) AND the key of the
/// persisted catch-up vector clock (`sync_state`, see `receive.rs`).
///
/// Decommissioning one peer shifted every higher index down by one, so a row
/// queued for the old `peer-3` resolved to a DIFFERENT HOST, was POSTed
/// there, and was then stamped `replayed_at`. That is cross-tenant content
/// disclosure and silent write loss from an ordinary operator action.
///
/// ## Contract
///
/// The output is a pure, total function of the peer's NORMALISED URL and of
/// nothing else. It is therefore stable under adding, removing, or reordering
/// peers — the property the DLQ needs. Because DLQ rows and `sync_state`
/// entries minted under this id outlive the process, the derivation is a
/// FROZEN WIRE FORMAT: `STABLE_PEER_ID_PREFIX` + the first
/// `STABLE_PEER_ID_HASH_NIBBLES` lowercase hex nibbles of
/// `SHA-256(normalize_peer_url(raw))`. Changing the hash, the truncation
/// length, or [`normalize_peer_url`] re-keys every persisted row and MUST be
/// treated as a migration, not a refactor.
///
/// SHA-256 (not blake3, not a non-cryptographic hash) because the input is
/// operator-supplied: second-preimage resistance is the property that stops a
/// crafted peer URL from being ground to collide with an existing peer's id
/// and hijack its queued rows. A non-cryptographic hash (fnv/xxhash) would be
/// collidable in milliseconds by anyone who can propose a peer URL, which
/// disqualifies it for a routing key regardless of its speed.
#[must_use]
fn stable_peer_id(raw: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(PEER_ID_DERIVATION_DOMAIN);
    hasher.update(normalize_peer_url(raw).as_bytes());
    let mut id = String::with_capacity(STABLE_PEER_ID_PREFIX.len() + STABLE_PEER_ID_HASH_NIBBLES);
    id.push_str(STABLE_PEER_ID_PREFIX);
    id.push_str(&hex::encode(hasher.finalize())[..STABLE_PEER_ID_HASH_NIBBLES]);
    id
}

/// #2442 — first peer id minted twice, if any. Pure and total so the
/// fail-closed branch in [`FederationConfig::build`] is unit-testable without
/// standing up a reqwest client (same reason `resolve_daemon_signing_key` was
/// extracted below).
///
/// Returns `Some((first_url, duplicate_url, shared_id))`.
#[must_use]
fn first_peer_id_collision<'a>(ids: &[(&'a str, &'a str)]) -> Option<(&'a str, &'a str, &'a str)> {
    let mut seen: std::collections::HashMap<&str, &str> =
        std::collections::HashMap::with_capacity(ids.len());
    for (id, url) in ids {
        if let Some(previous) = seen.insert(id, url) {
            return Some((previous, url, id));
        }
    }
    None
}

/// #2442 — true when `peer_id` carries the pre-#2442 POSITIONAL shape
/// `peer-<decimal digits>`.
///
/// Used by the DLQ replay worker to tell "this row was written by a binary
/// that keyed on the flag index" apart from "the operator removed this peer".
/// Both leave the row unresolvable, but only the first is an upgrade artifact
/// with a mechanical remediation, and conflating them sends operators hunting
/// for a decommission that never happened.
///
/// Cannot false-positive on a minted id: every minted id starts with
/// `peer-h` and `h` is not a decimal digit.
#[must_use]
pub fn is_legacy_positional_peer_id(peer_id: &str) -> bool {
    peer_id
        .strip_prefix("peer-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

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
        //
        // #2442 — the normalisation is now the shared [`normalize_peer_url`]
        // helper rather than an inline expression, because `stable_peer_id`
        // derives the durable DLQ routing key from the SAME canonical form.
        // Two spellings this check calls identical MUST mint one id, and two
        // it calls distinct MUST mint two. One function, no drift.
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
            // without saying so — a caller that asked for W-of-N would
            // silently get W-of-(N-1).
            //
            // (Pre-#2442 there was a second reason: `PeerEndpoint.id` was
            // the positional `peer-{i}`, so a shrunken list ALSO re-keyed
            // every queued DLQ row above the gap. #2442 made the id a pure
            // function of peer identity, so that half no longer applies —
            // the quorum-denominator argument is now the whole of it.)
            //
            // The guard runs BEFORE `normalize_peer_url` is used for the
            // duplicate check, so a plaintext duplicate reports the scheme
            // refusal rather than the duplicate one. That ordering is
            // deliberate: refuse the insecure thing first.
            crate::tls::validate_peer_url_scheme(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
            let normalized = normalize_peer_url(raw);
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
                // #2442 — the id is NOT the enumerate index any more, and the
                // comment that used to sit here was doubly wrong, so it is
                // corrected rather than kept:
                //
                //  * It said "`id` is used as a Prometheus metric label; keep
                //    it low-cardinality (#304 nit — prior form
                //    `peer-{i}:{url}` blew up the label space)". VERIFIED
                //    FALSE at v1.0.0: `PeerEndpoint.id` reaches ZERO metric
                //    labels. Every `with_label_values` call in the federation
                //    lane takes a closed-set token — `cause` in
                //    `push_dlq.rs`, `outcome`/`reason` in `sync.rs` — and
                //    `federation_partial_quorum_total` is a bare IntCounter.
                //    The id is a structured LOG field and, far more
                //    importantly, a DURABLE KEY.
                //  * Treating it as "just a label" is what let it be
                //    positional. It is the routing key of the push DLQ
                //    (`federation_push_dlq.peer_id`) and of the `sync_state`
                //    catch-up vector clock, so a positional key silently
                //    re-pointed queued writes at a DIFFERENT HOST whenever a
                //    peer was decommissioned — cross-tenant disclosure plus
                //    silent write loss.
                //
                // It is now `stable_peer_id(raw)`: a function of peer IDENTITY
                // (the normalised URL) and of nothing else, so adding,
                // removing, or reordering peers never re-keys a survivor. The
                // legitimate half of the #304 concern still holds and is still
                // honoured — the id is short and FIXED-WIDTH (39 ASCII chars),
                // never an unbounded URL.
                let trimmed = raw.trim_end_matches('/');
                let id = stable_peer_id(raw);
                // #2442 — promoted debug -> info. The id is now opaque, so
                // this is the ONLY place an operator can resolve a DLQ row's
                // `peer_id` (or a Prometheus label) back to a host. It fires
                // once per peer at boot — tens of lines on the fleet sizes
                // v1.0.0 certifies, not a hot path.
                tracing::info!(
                    target: FED_LOG_TARGET,
                    peer_index = i,
                    peer_id = %id,
                    url = trimmed,
                    "registered peer (#2442: peer_id is derived from the URL, not the \
                     flag position; this line is the id -> url map for DLQ triage)"
                );
                PeerEndpoint {
                    id,
                    sync_push_url: format!("{trimmed}/api/v1/sync/push"),
                }
            })
            .collect();

        // #2442 — fail CLOSED on an actually-observed peer-id collision.
        //
        // The 48-bit truncation makes this astronomically unlikely at the
        // fleet sizes v1.0.0 certifies (see `STABLE_PEER_ID_HASH_NIBBLES`),
        // but "unlikely" is not a data-integrity guarantee: two peers sharing
        // a routing key would merge their DLQ rows and misroute content
        // exactly the way the positional id did. Refusing to boot is the
        // DEGRADE-not-CORRUPT answer, and it mirrors the duplicate-URL
        // refusal above — the precedent for a boot-time refusal on this loop.
        //
        // This guard ALSO backstops any future drift between the duplicate-URL
        // check and `stable_peer_id`: the only dangerous direction is "the
        // duplicate check calls two URLs distinct but they mint one id", and
        // that lands here.
        //
        // Scope, stated honestly: this compares peers WITHIN THE LIVE CONFIG.
        // It cannot see a peer that has been REMOVED but whose rows are still
        // in `federation_push_dlq`, so it is not the defence against a ground
        // second-preimage — 128 bits of digest is (see
        // `STABLE_PEER_ID_HASH_NIBBLES`). This guard is the accident case.
        let id_url_pairs: Vec<(&str, &str)> = peers
            .iter()
            .zip(peer_urls.iter())
            .map(|(peer, raw)| (peer.id.as_str(), raw.as_str()))
            .collect();
        if let Some((first, duplicate, id)) = first_peer_id_collision(&id_url_pairs) {
            return Err(anyhow::anyhow!(
                "federation peer-id collision in --quorum-peers: {first} and {duplicate} both \
                 derive the stable peer id {id} — refusing to start, because a shared routing \
                 key would merge the two peers' federation_push_dlq rows and deliver queued \
                 writes to the wrong host (#2442). Change one peer's URL spelling."
            ));
        }

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

    /// #2442 — the fail-closed collision branch in `build` is unreachable in
    /// practice (128 bits of SHA-256), which is exactly why the check is
    /// extracted as a pure function: an unreachable guard that cannot be
    /// exercised is a guard nobody can trust. Same reasoning as the
    /// `resolve_daemon_signing_key` extraction above.
    #[test]
    fn first_peer_id_collision_detects_a_shared_routing_key() {
        assert_eq!(
            super::first_peer_id_collision(&[
                ("peer-h1aaa", "https://a.example"),
                ("peer-h1bbb", "https://b.example"),
                ("peer-h1aaa", "https://c.example"),
            ]),
            Some(("https://a.example", "https://c.example", "peer-h1aaa")),
            "a shared id must be reported with BOTH urls so the boot refusal \
             can name what to change"
        );
    }

    #[test]
    fn first_peer_id_collision_is_none_for_distinct_ids() {
        assert_eq!(
            super::first_peer_id_collision(&[
                ("peer-h1aaa", "https://a.example"),
                ("peer-h1bbb", "https://b.example"),
            ]),
            None
        );
        assert_eq!(super::first_peer_id_collision(&[]), None);
    }

    /// #2442 — the id derivation and the `#341` duplicate-URL check MUST share
    /// one normalisation. If they drift, a URL the duplicate check calls
    /// identical could mint two routing keys (splitting one peer's DLQ rows)
    /// or two it calls distinct could mint one (merging two peers').
    #[test]
    fn normalisation_is_shared_between_the_dup_check_and_the_id() {
        for (a, b) in [
            ("https://p.example/base", "https://p.example/base/"),
            ("https://p.example/base", "HTTPS://P.EXAMPLE/BASE"),
            ("https://p.example", "https://p.example///"),
        ] {
            assert_eq!(
                super::normalize_peer_url(a),
                super::normalize_peer_url(b),
                "{a} and {b} must canonicalise identically"
            );
            assert_eq!(
                super::stable_peer_id(a),
                super::stable_peer_id(b),
                "{a} and {b} must mint one routing key"
            );
        }
        assert_ne!(
            super::stable_peer_id("https://p.example:8443"),
            super::stable_peer_id("https://p.example:9443"),
            "a port change is a DIFFERENT peer and must mint a different key"
        );
    }
}
