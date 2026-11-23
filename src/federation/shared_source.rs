// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10059 — the one shared source of the federation peer list and of the
//! outbound scope under the enterprise-federation posture (3-agent vote
//! (71472661) V2-10059, option A).
//!
//! Before this module the peer list existed only as the `serve --quorum-peers`
//! argument, so a fresh `doctor --posture enterprise-federation` process could
//! not see it and check #23 could never pass. Under the posture both the
//! daemon and a fresh doctor now read the same two keys of the existing
//! federation env family through ONE parse function,
//! [`BoundFederationSource::from_values`]:
//!
//! * [`PEERS_ENV`] (`AI_MEMORY_FED_QUORUM_PEERS`): the comma-separated https
//!   peer URLs, split by [`canonical_peer_list`], the same splitter applied to
//!   the `--quorum-peers` value when the two are compared;
//! * `AI_MEMORY_FED_PEER_OUTBOUND_SCOPE`: the per-peer outbound scope
//!   (unchanged contract, `super::outbound_scope`).
//!
//! The daemon is bound to the source: [`resolve_with`] returns
//! [`ServePeerSet::Bound`] only when the `--quorum-peers` value names exactly
//! the source's peers, and `serve` builds its federation config from the bound
//! value. A [`BoundFederationSource`] has private fields and no other
//! constructor, so a posture daemon cannot federate with a peer set the doctor
//! did not judge. Outside the posture nothing changes: the flag alone is used
//! ([`ServePeerSet::Unbound`]), and a fresh doctor fails check #23 with
//! [`SharedSourceError::PostureAbsent`].
//!
//! The source proves the BOOT configuration: an edit after boot applies only
//! after a restart. The daemon logs [`BoundFederationSource::digest_line`] at
//! boot and the doctor prints the same digest, so an edit is detectable. The
//! digest input is peer ids (a hash of the normalised URL) and scope patterns,
//! never a URL or a credential.

use super::outbound_scope::{self as scope, OutboundScopeConfigError, PeerOutboundScope};
use crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;

/// The shared peer list key: comma-separated https peer URLs, the same value
/// `serve --quorum-peers` takes.
pub const PEERS_ENV: &str = "AI_MEMORY_FED_QUORUM_PEERS";

/// Largest accepted [`PEERS_ENV`] value, in bytes.
pub const MAX_PEERS_ENV_BYTES: usize = 64 * 1024;

/// Most peers [`PEERS_ENV`] may name.
pub const MAX_PEERS: usize = 256;

/// Domain separator of the source digest (version 1 of its input layout).
const DIGEST_DOMAIN: &[u8] = b"ai-memory/federation-shared-source/v1\n";

/// Digest input tag of a denied (unscoped) peer.
const DIGEST_TAG_DENY: u8 = 0;

/// Digest input tag of a peer with namespace patterns.
const DIGEST_TAG_NAMESPACES: u8 = 1;

/// The fix every peer-list refusal names.
const PEERS_FIX: &str = "set it to the comma-separated https peer URLs (the exact \
                         --quorum-peers value) and restart";

/// Split peer list items on `,`, trim each part and drop empty parts. The one
/// splitter for both the [`PEERS_ENV`] value and the `--quorum-peers` value
/// when the two are compared.
#[must_use]
pub fn canonical_peer_list(items: &[String]) -> Vec<String> {
    items
        .iter()
        .flat_map(|item| item.split(','))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// Why the shared source does not bind (serve refuses, doctor FAILs check 23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedSourceError {
    /// The posture signal is not armed; the source binds only under it.
    PostureAbsent,
    /// [`PEERS_ENV`] is not set.
    Absent,
    /// [`PEERS_ENV`] is not valid UTF-8.
    NotUnicode,
    /// [`PEERS_ENV`] is over [`MAX_PEERS_ENV_BYTES`] or [`MAX_PEERS`].
    TooLarge,
    /// [`PEERS_ENV`] names no peer.
    Empty,
    /// A peer entry is not a usable https URL, or is listed twice. The reason
    /// names the peer by origin only.
    Malformed(String),
    /// The outbound scope value is refused.
    Scope(OutboundScopeConfigError),
    /// An outbound scope key (a stable peer id) names no peer of the list.
    UnknownScopeKey(String),
    /// `--quorum-peers` names a different peer set from the source.
    Divergent {
        /// Peers the flag names.
        flag: usize,
        /// Peers the source names.
        source: usize,
    },
}

impl fmt::Display for SharedSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostureAbsent => write!(
                f,
                "{ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE} is not armed: the federation peer \
                 list and outbound scope bind to {PEERS_ENV} only under the enterprise-federation \
                 posture; arm it, set {PEERS_ENV} and restart"
            ),
            Self::Absent => write!(
                f,
                "{PEERS_ENV} is not set: under the enterprise-federation posture the peer list is \
                 read from it; {PEERS_FIX}"
            ),
            Self::NotUnicode => write!(f, "{PEERS_ENV} is not valid UTF-8; {PEERS_FIX}"),
            Self::TooLarge => write!(
                f,
                "{PEERS_ENV} is over {MAX_PEERS_ENV_BYTES} bytes or {MAX_PEERS} peers; {PEERS_FIX}"
            ),
            Self::Empty => write!(f, "{PEERS_ENV} names no peer; {PEERS_FIX}"),
            Self::Malformed(reason) => write!(f, "{PEERS_ENV}: {reason}; {PEERS_FIX}"),
            Self::Scope(e) => write!(f, "{e}"),
            Self::UnknownScopeKey(id) => write!(
                f,
                "{}: key {id} names no peer of {PEERS_ENV}; list the peer there or remove the \
                 key, then restart",
                scope::OUTBOUND_SCOPE_ENV
            ),
            Self::Divergent { flag, source } => write!(
                f,
                "--quorum-peers names {flag} peer(s) that differ from the {source} peer(s) of \
                 {PEERS_ENV}: under the enterprise-federation posture the daemon federates only \
                 with that key's peers; set --quorum-peers to exactly the {PEERS_ENV} value and \
                 restart"
            ),
        }
    }
}

impl std::error::Error for SharedSourceError {}

/// The peer list and outbound scope a posture daemon federates with, as the
/// shared source names them. Private fields; the only constructor is
/// [`Self::from_values`] (and its env reader [`Self::load`]), so holding one
/// means the source parsed, every scope key names a listed peer, and the
/// digest is of exactly this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundFederationSource {
    peers: Vec<String>,
    scopes: BTreeMap<String, PeerOutboundScope>,
    digest: String,
}

impl BoundFederationSource {
    /// THE parse function of the shared source, called by `serve`,
    /// `sync-daemon` and a fresh doctor: `peers_raw` is the [`PEERS_ENV`]
    /// value and `scope_raw` the outbound scope value (`None` = unset).
    ///
    /// # Errors
    ///
    /// The [`SharedSourceError`] for an absent, non-UTF-8, oversized, empty
    /// or malformed peer list, a refused scope value, or a scope key that
    /// names no listed peer.
    pub fn from_values(
        peers_raw: Option<OsString>,
        scope_raw: Option<OsString>,
    ) -> Result<Self, SharedSourceError> {
        let raw = peers_raw
            .ok_or(SharedSourceError::Absent)?
            .into_string()
            .map_err(|_| SharedSourceError::NotUnicode)?;
        if raw.len() > MAX_PEERS_ENV_BYTES {
            return Err(SharedSourceError::TooLarge);
        }
        let peers = canonical_peer_list(std::slice::from_ref(&raw));
        if peers.is_empty() {
            return Err(SharedSourceError::Empty);
        }
        if peers.len() > MAX_PEERS {
            return Err(SharedSourceError::TooLarge);
        }
        let mut ids = BTreeSet::new();
        for peer in &peers {
            crate::tls::validate_peer_url_scheme(peer).map_err(SharedSourceError::Malformed)?;
            if !ids.insert(super::peer::stable_peer_id(peer)) {
                return Err(SharedSourceError::Malformed(format!(
                    "peer {} is listed twice",
                    crate::url_display::url_origin_and_path(peer)
                )));
            }
        }
        let scopes = match scope_raw {
            None => BTreeMap::new(),
            Some(value) => {
                let text = value
                    .into_string()
                    .map_err(|_| SharedSourceError::Scope(OutboundScopeConfigError::NotUnicode))?;
                scope::parse(&text).map_err(SharedSourceError::Scope)?
            }
        };
        if let Some(key) = scopes.keys().find(|key| !ids.contains(*key)) {
            return Err(SharedSourceError::UnknownScopeKey(key.clone()));
        }
        let digest = digest_of(&ids, &scopes);
        Ok(Self {
            peers,
            scopes,
            digest,
        })
    }

    /// [`Self::from_values`] over this process's environment.
    ///
    /// # Errors
    ///
    /// As [`Self::from_values`].
    pub fn load() -> Result<Self, SharedSourceError> {
        Self::from_values(
            std::env::var_os(PEERS_ENV),
            std::env::var_os(scope::OUTBOUND_SCOPE_ENV),
        )
    }

    /// The peer URLs, in source order, as given (a URL may carry a
    /// credential: never print one; use `url_display`).
    #[must_use]
    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// The outbound scope of each listed peer that has one, keyed by stable
    /// peer id; a listed peer without a key is denied.
    #[must_use]
    pub fn scopes(&self) -> &BTreeMap<String, PeerOutboundScope> {
        &self.scopes
    }

    /// The digest as printed by the daemon at boot and by the doctor:
    /// `sha256:<64 hex>`.
    #[must_use]
    pub fn digest_line(&self) -> String {
        format!("sha256:{}", self.digest)
    }
}

/// SHA-256 over the domain, then per peer id in sorted order: the id, a tag
/// and each pattern length-prefixed (so no two sources share an input).
fn digest_of(ids: &BTreeSet<String>, scopes: &BTreeMap<String, PeerOutboundScope>) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    for id in ids {
        hasher.update((id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
        match scopes.get(id) {
            Some(PeerOutboundScope::Namespaces(patterns)) => {
                hasher.update([DIGEST_TAG_NAMESPACES]);
                hasher.update((patterns.len() as u64).to_le_bytes());
                for pattern in patterns {
                    hasher.update((pattern.len() as u64).to_le_bytes());
                    hasher.update(pattern.as_bytes());
                }
            }
            Some(PeerOutboundScope::Deny) | None => hasher.update([DIGEST_TAG_DENY]),
        }
    }
    hex::encode(hasher.finalize())
}

/// The peer set a daemon starts federation with.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum ServePeerSet {
    /// Outside the posture: the flag value, unchanged, and the outbound
    /// scope from its env key as before #10059.
    Unbound(Vec<String>),
    /// Under the posture: the shared source, which the flag matches.
    Bound(BoundFederationSource),
}

impl ServePeerSet {
    /// The peer URLs federation is built from.
    #[must_use]
    pub fn peers(&self) -> &[String] {
        match self {
            Self::Unbound(peers) => peers,
            Self::Bound(source) => source.peers(),
        }
    }
}

/// Bind the daemon's peer list: outside the posture (`posture` false) the
/// flag value unchanged; under it the shared source, which the flag must name
/// exactly (as sets of stable peer ids).
///
/// # Errors
///
/// Under the posture, the source's [`SharedSourceError`], or
/// [`SharedSourceError::Divergent`] when the flag differs from it.
pub fn resolve_with(
    posture: bool,
    flag: &[String],
    peers_raw: Option<OsString>,
    scope_raw: Option<OsString>,
) -> Result<ServePeerSet, SharedSourceError> {
    if !posture {
        return Ok(ServePeerSet::Unbound(flag.to_vec()));
    }
    let source = BoundFederationSource::from_values(peers_raw, scope_raw)?;
    let mut flag_ids: Vec<String> = canonical_peer_list(flag)
        .iter()
        .map(|url| super::peer::stable_peer_id(url))
        .collect();
    flag_ids.sort_unstable();
    let mut source_ids: Vec<String> = source
        .peers()
        .iter()
        .map(|url| super::peer::stable_peer_id(url))
        .collect();
    source_ids.sort_unstable();
    if flag_ids != source_ids {
        return Err(SharedSourceError::Divergent {
            flag: flag_ids.len(),
            source: source_ids.len(),
        });
    }
    Ok(ServePeerSet::Bound(source))
}

/// [`resolve_with`] over this process's posture signal and environment; the
/// entry `serve` and `sync-daemon` call before federation starts.
///
/// # Errors
///
/// As [`resolve_with`].
pub fn resolve_peers(flag: &[String]) -> Result<ServePeerSet, SharedSourceError> {
    resolve_with(
        crate::enterprise_federation_posture::enterprise_federation_posture_required(),
        flag,
        std::env::var_os(PEERS_ENV),
        std::env::var_os(scope::OUTBOUND_SCOPE_ENV),
    )
}

/// The shared source as a fresh doctor reads it: the posture signal first
/// (the same one `serve` binds on), then [`BoundFederationSource::load`].
///
/// # Errors
///
/// [`SharedSourceError::PostureAbsent`] when the posture is not armed, else
/// as [`BoundFederationSource::from_values`].
pub fn load_for_doctor() -> Result<BoundFederationSource, SharedSourceError> {
    if !crate::enterprise_federation_posture::enterprise_federation_posture_required() {
        return Err(SharedSourceError::PostureAbsent);
    }
    BoundFederationSource::load()
}

/// `serve` boot: apply the bound peer set's outbound scope to the built
/// federation config and record its boot rows. [`ServePeerSet::Unbound`] keeps
/// the pre-#10059 path ([`scope::install_for_serve`]); [`ServePeerSet::Bound`]
/// applies the scope the shared source parsed, so the daemon serves exactly
/// what a fresh doctor judges.
///
/// # Errors
///
/// A scope key that names no configured peer, or the unbound path's error.
pub fn install_for_serve(
    config: Option<super::FederationConfig>,
    set: &ServePeerSet,
) -> anyhow::Result<Option<super::FederationConfig>> {
    let ServePeerSet::Bound(source) = set else {
        return scope::install_for_serve(config);
    };
    let Some(mut cfg) = config else {
        return Ok(None);
    };
    scope::apply(&mut cfg, source.scopes().clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    scope::record_boot_scopes(
        cfg.peers
            .iter()
            .map(|p| (p.id.as_str(), p.sync_push_url.as_str(), &p.outbound_scope)),
    );
    Ok(Some(cfg))
}

/// `sync-daemon` boot: the scope of each peer URL, in order. Unbound keeps
/// [`scope::sync_daemon_scopes`]; bound resolves the source's own scope map.
///
/// # Errors
///
/// A scope key that names no URL.
pub fn sync_daemon_scopes(
    set: &ServePeerSet,
) -> anyhow::Result<Vec<std::sync::Arc<PeerOutboundScope>>> {
    let ServePeerSet::Bound(source) = set else {
        return scope::sync_daemon_scopes(set.peers());
    };
    let urls = source.peers();
    let scopes =
        scope::resolve_for_urls(urls, source.scopes()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let ids: Vec<String> = urls
        .iter()
        .map(|u| super::peer::stable_peer_id(u))
        .collect();
    scope::record_boot_scopes(
        ids.iter()
            .zip(urls)
            .zip(&scopes)
            .map(|((id, url), s)| (id.as_str(), url.as_str(), s)),
    );
    Ok(scopes.into_iter().map(std::sync::Arc::new).collect())
}

/// The boot line `serve` and `sync-daemon` print when bound: the peer count
/// and the digest a fresh doctor prints for the same source.
#[must_use]
pub fn boot_line(source: &BoundFederationSource) -> String {
    format!(
        "ai-memory: INFO federation shared source bound: {} peer(s), digest {} (#10059)",
        source.peers().len(),
        source.digest_line()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_A: &str = "https://user:pw@peer-a.example.org:9077/fed";
    const PEER_B: &str = "https://peer-b.example.org:9077";
    const FIX: &str = "set it to the comma-separated https peer URLs (the exact --quorum-peers \
                       value) and restart";

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn scope_for(url: &str, patterns: &str) -> String {
        format!(r#"{{"{url}": {{"allowed_namespaces": [{patterns}]}}}}"#)
    }

    fn not_unicode() -> Option<OsString> {
        use std::os::unix::ffi::OsStringExt as _;
        Some(OsString::from_vec(vec![0x66, 0xff, 0x6f]))
    }

    #[test]
    fn canonical_list_splits_trims_and_drops_empty_10059() {
        let cases: [(&[&str], &[&str]); 5] = [
            (&[], &[]),
            (&[""], &[]),
            (&[" , ,"], &[]),
            (&[" a , b,,c "], &["a", "b", "c"]),
            (&["a", "b,c"], &["a", "b", "c"]),
        ];
        for (input, want) in cases {
            assert_eq!(canonical_peer_list(&list(input)), list(want), "{input:?}");
        }
    }

    /// C-5: every degenerate source refuses with its exact text.
    #[test]
    fn degenerate_sources_refuse_with_exact_text_10059() {
        let shown_b = crate::url_display::url_origin_and_path(PEER_B);
        let dup = format!("{PEER_B},{PEER_B}/");
        let too_big = "a".repeat(MAX_PEERS_ENV_BYTES + 1);
        let too_many = vec![PEER_B; MAX_PEERS + 1].join(",");
        let bad_scope = scope::parse("not json").unwrap_err();
        let unknown_id = super::super::peer::stable_peer_id(PEER_A);
        let cases: Vec<(Option<OsString>, Option<OsString>, String)> = vec![
            (
                None,
                None,
                format!(
                    "AI_MEMORY_FED_QUORUM_PEERS is not set: under the enterprise-federation \
                     posture the peer list is read from it; {FIX}"
                ),
            ),
            (
                not_unicode(),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS is not valid UTF-8; {FIX}"),
            ),
            (
                os(&too_big),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS is over 65536 bytes or 256 peers; {FIX}"),
            ),
            (
                os(&too_many),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS is over 65536 bytes or 256 peers; {FIX}"),
            ),
            (
                os(""),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS names no peer; {FIX}"),
            ),
            (
                os(" , "),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS names no peer; {FIX}"),
            ),
            (
                os(&dup),
                None,
                format!("AI_MEMORY_FED_QUORUM_PEERS: peer {shown_b} is listed twice; {FIX}"),
            ),
            (os(PEER_B), os("not json"), bad_scope.to_string()),
            (
                os(PEER_B),
                not_unicode(),
                OutboundScopeConfigError::NotUnicode.to_string(),
            ),
            (
                os(PEER_B),
                os(&scope_for(PEER_A, r#""ops""#)),
                format!(
                    "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE: key {unknown_id} names no peer of \
                     AI_MEMORY_FED_QUORUM_PEERS; list the peer there or remove the key, then \
                     restart"
                ),
            ),
        ];
        for (peers, scope_raw, want) in cases {
            let err = BoundFederationSource::from_values(peers.clone(), scope_raw).unwrap_err();
            assert_eq!(err.to_string(), want, "{peers:?}");
            assert!(!err.to_string().contains("pw"), "no credential: {err}");
        }
        // A plaintext or scheme-less peer: the scheme validator's own reason.
        for bad in ["http://peer-b.example.org:9077", "peer-b.example.org:9077"] {
            let reason = crate::tls::validate_peer_url_scheme(bad).unwrap_err();
            assert_eq!(
                BoundFederationSource::from_values(os(bad), None).unwrap_err(),
                SharedSourceError::Malformed(reason),
                "{bad}"
            );
        }
    }

    /// C-6: the digest is stable under order and URL spelling, changes with
    /// any scope edit, and its printed form holds no URL or credential.
    #[test]
    fn digest_tracks_the_source_and_holds_no_secret_10059() {
        let scopes = format!(
            r#"{{"{PEER_A}": {{"allowed_namespaces": ["team/*"]}}, "{PEER_B}": {{"allowed_namespaces": ["ops"]}}}}"#
        );
        let ab = BoundFederationSource::from_values(os(&format!("{PEER_A},{PEER_B}")), os(&scopes))
            .unwrap();
        let ba = BoundFederationSource::from_values(
            os(&format!(" {}/ , {PEER_A}", PEER_B.to_ascii_uppercase())),
            os(&scopes),
        )
        .unwrap();
        assert_eq!(ab.digest_line(), ba.digest_line());
        let line = ab.digest_line();
        assert_eq!(line.len(), "sha256:".len() + 64, "{line}");
        assert!(line.starts_with("sha256:"));
        for secret in ["pw", "user", "peer-a", "example"] {
            assert!(!line.contains(secret), "{line}");
        }
        let edited = scopes.replace("\"ops\"", "\"ops/*\"");
        let changed =
            BoundFederationSource::from_values(os(&format!("{PEER_A},{PEER_B}")), os(&edited))
                .unwrap();
        assert_ne!(changed.digest_line(), line);
        let deny_b =
            BoundFederationSource::from_values(os(&format!("{PEER_A},{PEER_B}")), None).unwrap();
        assert_ne!(deny_b.digest_line(), line);
        // Pattern boundaries are part of the input: ["a,b"] is not ["a","b"].
        let one =
            BoundFederationSource::from_values(os(PEER_B), os(&scope_for(PEER_B, r#""a,b""#)))
                .unwrap();
        let two =
            BoundFederationSource::from_values(os(PEER_B), os(&scope_for(PEER_B, r#""a","b""#)))
                .unwrap();
        assert_ne!(one.digest_line(), two.digest_line());
    }

    /// C-2, C-8, C-9: posture off keeps the flag; posture on binds the source
    /// and refuses a flag that differs from it.
    #[test]
    fn resolve_binds_under_the_posture_only_10059() {
        let scopes = scope_for(PEER_B, r#""ops""#);
        // C-8: outside the posture the flag is used unchanged, source or not.
        for (peers_raw, flag) in [
            (None, list(&[PEER_B])),
            (os(PEER_A), list(&[PEER_B, " "])),
            (None, list(&[])),
        ] {
            assert_eq!(
                resolve_with(false, &flag, peers_raw, os(&scopes)).unwrap(),
                ServePeerSet::Unbound(flag.clone())
            );
        }
        // C-9: a matching flag binds (order and spelling free).
        let bound = resolve_with(
            true,
            &list(&[&format!("{PEER_B}/")]),
            os(PEER_B),
            os(&scopes),
        )
        .unwrap();
        let ServePeerSet::Bound(source) = &bound else {
            panic!("bound expected: {bound:?}");
        };
        assert_eq!(source.peers(), list(&[PEER_B]).as_slice());
        assert_eq!(bound.peers(), list(&[PEER_B]).as_slice());
        // C-2: a flag that differs from the source, or peers with no source.
        let divergent = |flag: usize, source: usize| {
            format!(
                "--quorum-peers names {flag} peer(s) that differ from the {source} peer(s) of \
                 AI_MEMORY_FED_QUORUM_PEERS: under the enterprise-federation posture the daemon \
                 federates only with that key's peers; set --quorum-peers to exactly the \
                 AI_MEMORY_FED_QUORUM_PEERS value and restart"
            )
        };
        let cases: [(Vec<String>, Option<OsString>, String); 4] = [
            (list(&[PEER_A]), os(PEER_B), divergent(1, 1)),
            (list(&[PEER_A, PEER_B]), os(PEER_B), divergent(2, 1)),
            (list(&[]), os(PEER_B), divergent(0, 1)),
            (list(&[PEER_B]), None, SharedSourceError::Absent.to_string()),
        ];
        for (flag, peers_raw, want) in cases {
            let err = resolve_with(true, &flag, peers_raw, os(&scopes)).unwrap_err();
            assert_eq!(err.to_string(), want, "{flag:?}");
        }
    }

    #[test]
    fn posture_absent_text_names_the_signal_and_the_key_10059() {
        assert_eq!(
            SharedSourceError::PostureAbsent.to_string(),
            "AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE is not armed: the federation peer \
             list and outbound scope bind to AI_MEMORY_FED_QUORUM_PEERS only under the \
             enterprise-federation posture; arm it, set AI_MEMORY_FED_QUORUM_PEERS and restart"
        );
    }

    /// C-3: a fresh doctor reads the posture signal first.
    #[test]
    fn doctor_load_needs_the_posture_signal_10059() {
        if crate::config::run_env_isolated_child_or_spawn(
            "federation::shared_source::tests::doctor_load_needs_the_posture_signal_10059",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        // SAFETY: env-isolated child holding the env lock; no other thread
        // reads these variables.
        unsafe {
            std::env::set_var(PEERS_ENV, PEER_B);
            std::env::remove_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE);
        }
        assert_eq!(load_for_doctor(), Err(SharedSourceError::PostureAbsent));
        // SAFETY: as above.
        unsafe {
            std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1");
        }
        assert_eq!(
            load_for_doctor().map(|s| s.peers().to_vec()),
            Ok(list(&[PEER_B]))
        );
    }
}
