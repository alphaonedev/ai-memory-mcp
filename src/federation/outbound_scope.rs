//! #9996 — sender-side outbound namespace scope for federation push.
//!
//! The sender decides what a peer may receive. Every `/sync/push` body is
//! cut per peer by that peer's [`PeerOutboundScope`] before it reaches the
//! transport, and the transport only accepts a [`ScopedOutbound`], a value
//! whose only constructor is [`admit`]. A peer with no configured scope is
//! [`PeerOutboundScope::Deny`] and receives nothing (deny by default).
//!
//! ## Config contract (`AI_MEMORY_FED_PEER_OUTBOUND_SCOPE`)
//!
//! A JSON object that mirrors the inbound `AI_MEMORY_FED_PEER_ATTESTATION`
//! `PeerScope` shape, keyed by the peer URL as given in `--quorum-peers`:
//!
//! ```json
//! {"https://peer-b:9077": {"allowed_namespaces": ["team/a/**", "shared"]}}
//! ```
//!
//! Patterns use the receive side's own matcher
//! ([`super::peer_attestation::namespace_allowed_test_glob`]), so both sides
//! agree by construction. The all-namespaces pattern is the literal
//! [`ALL_NAMESPACES_PATTERN`] (`**`); it must be written by the operator and
//! doctor reports it as a failing posture row under
//! `--posture enterprise-federation`.
//!
//! ## Item rules
//!
//! - Items that carry a namespace (`memories`, `checkpoints`, `pendings`,
//!   `signals`, `namespace_meta`) are kept only when that namespace is in
//!   scope; an item without a string namespace is dropped (fail closed).
//! - `embeddings` ride only beside a kept memory (matched on `memory_id`).
//! - `namespace_meta_clears` entries are namespaces and are filtered as such.
//! - Id-only items (`deletions`, `archives`, `restores`, `links`, ...)
//!   carry no namespace of their own. The lane that builds the body records
//!   the namespace of every id in [`OUTBOUND_NAMESPACES_KEY`] (an
//!   [`ItemNamespaces`] map, a link naming both endpoints). An id-only item
//!   is kept only when every id it names is annotated with a namespace in
//!   scope, or the peer's scope is all-namespaces. An id whose namespace is
//!   not known sends nothing to a narrowed peer (fail closed).
//! - The annotation is sender-local: it is kept in the queued payload (so a
//!   DLQ replay re-admits the same way) and never reaches the wire
//!   ([`ScopedOutbound::body`] strips it).
//! - A body with no item left is refused ([`OutboundRefusal::NothingInScope`])
//!   and sends no request.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;
use serde_json::{Map, Value};

use super::peer_attestation::namespace_allowed_test_glob;

/// Env key holding the per-peer outbound scope JSON (V1 config contract).
pub const OUTBOUND_SCOPE_ENV: &str = "AI_MEMORY_FED_PEER_OUTBOUND_SCOPE";
/// The one pattern that means every namespace.
pub const ALL_NAMESPACES_PATTERN: &str = "**";
/// Ceiling on patterns per peer.
pub const MAX_OUTBOUND_PATTERNS: usize = 256;
/// Ceiling on bytes per pattern.
pub const MAX_OUTBOUND_PATTERN_LEN: usize = 512;
/// Ceiling on the raw env value in bytes.
pub const MAX_OUTBOUND_SCOPE_ENV_BYTES: usize = 1 << 20;

/// Refusal reason: the peer has no outbound scope.
pub const REASON_NO_OUTBOUND_SCOPE: &str = "outbound scope: peer has no outbound namespace scope";
/// Refusal reason: nothing in the body is in the peer's scope.
pub const REASON_NOTHING_IN_SCOPE: &str =
    "outbound scope: no item of this push is in the peer's scope";
/// Refusal reason: the body is not a JSON object.
pub const REASON_MALFORMED_BODY: &str = "outbound scope: push body is not a JSON object";

/// Sender-local body key holding the `{id: namespace}` map of the id-only
/// items. Never sent to a peer.
pub const OUTBOUND_NAMESPACES_KEY: &str = "_outbound_scope_namespaces";

/// Trace target for outbound scope decisions.
pub const OUTBOUND_SCOPE_TRACE_TARGET: &str = "federation::outbound_scope";

/// Ceiling on distinct `(peer_id, namespace)` series of the C-6 filtered
/// counter; past it the namespace is counted as [`FILTERED_OVERFLOW_LABEL`].
pub const MAX_FILTERED_SERIES: usize = 1024;
/// Namespace label of filtered items once [`MAX_FILTERED_SERIES`] is reached.
pub const FILTERED_OVERFLOW_LABEL: &str = "_overflow";
/// Namespace label of a filtered item that carries no namespace.
pub const FILTERED_UNRESOLVED_LABEL: &str = "_unresolved";
/// Ceiling on the bytes of a namespace used as a counter label; a longer
/// one is cut at a char boundary.
pub const MAX_FILTERED_LABEL_BYTES: usize = 128;

const KEY_MEMORIES: &str = "memories";
const KEY_NAMESPACE_META_CLEARS: &str = "namespace_meta_clears";
const KEY_DRY_RUN: &str = "dry_run";
const KEY_MEMORY_ID: &str = "memory_id";
const KEY_ID: &str = "id";
const KEY_SOURCE_ID: &str = "source_id";
const KEY_TARGET_ID: &str = "target_id";
/// Sender envelope metadata: who sent, when, under which policy. It holds
/// no memory bytes, so every admitted peer receives it unchanged.
const ENVELOPE_KEYS: [&str; 6] = [
    crate::models::field_names::SENDER_AGENT_ID,
    KEY_DRY_RUN,
    crate::federation::push_lanes::SyncPushMetadataField::SenderClock.wire_field(),
    "sender_wall_clock",
    crate::models::field_names::SENDER_POLICY_SEQ,
    crate::models::field_names::SENDER_POLICY_DIGEST_HEX,
];
/// Item kinds that carry their own `namespace` field.
/// The id field of an `action_transitions` item.
const KEY_ACTION_ID: &str = "action_id";

const NAMESPACED_ITEM_KEYS: [&str; 5] = [
    KEY_MEMORIES,
    crate::federation::receive_auth::LANE_CHECKPOINTS,
    "pendings",
    "signals",
    crate::federation::receive_auth::LANE_NAMESPACE_META,
];

/// Posture label for a scope that admits every namespace (`**`).
const POSTURE_ALL_NAMESPACES: &str = "all_namespaces";

/// A peer's outbound namespace scope. Unset is [`Self::Deny`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PeerOutboundScope {
    /// No scope configured: the peer receives nothing.
    #[default]
    Deny,
    /// The peer may receive the namespaces these patterns match.
    Namespaces(Vec<String>),
}

impl PeerOutboundScope {
    /// The explicit all-namespaces scope (`["**"]`).
    #[must_use]
    pub fn all_explicit() -> Self {
        Self::Namespaces(vec![ALL_NAMESPACES_PATTERN.to_string()])
    }

    /// True when `namespace` may be sent to this peer.
    #[must_use]
    pub fn allows(&self, namespace: &str) -> bool {
        match self {
            Self::Deny => false,
            Self::Namespaces(patterns) => patterns
                .iter()
                .any(|p| namespace_allowed_test_glob(p, namespace)),
        }
    }

    /// True when the scope contains the explicit all-namespaces pattern.
    #[must_use]
    pub fn is_all(&self) -> bool {
        match self {
            Self::Deny => false,
            Self::Namespaces(patterns) => patterns.iter().any(|p| p == ALL_NAMESPACES_PATTERN),
        }
    }
}

/// Why a body was not admitted for a peer. Every variant is permanent:
/// nothing is queued for retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundRefusal {
    /// The peer has no outbound scope.
    NoOutboundScope,
    /// No item of the body is in the peer's scope.
    NothingInScope,
    /// The body is not a JSON object.
    MalformedBody,
}

impl OutboundRefusal {
    /// The exact reason text.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoOutboundScope => REASON_NO_OUTBOUND_SCOPE,
            Self::NothingInScope => REASON_NOTHING_IN_SCOPE,
            Self::MalformedBody => REASON_MALFORMED_BODY,
        }
    }
}

/// The namespace of every id an id-only item names, recorded by the lane
/// that builds the body (vote V2-9996 C-1). An id with no entry sends
/// nothing to a narrowed peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemNamespaces(BTreeMap<String, String>);

impl ItemNamespaces {
    /// An empty map: every id-only item goes only to an all-namespaces peer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The map with one entry, `id` in `namespace`.
    #[must_use]
    pub fn of(id: &str, namespace: &str) -> Self {
        let mut out = Self::new();
        out.insert(id, namespace);
        out
    }

    /// Record `id` in `namespace`. An empty namespace records nothing (the
    /// id stays unresolved and fails closed).
    pub fn insert(&mut self, id: &str, namespace: &str) {
        if !namespace.is_empty() {
            self.0.insert(id.to_string(), namespace.to_string());
        }
    }

    /// The namespace recorded for `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&str> {
        self.0.get(id).map(String::as_str)
    }

    /// The entries of `ids` only (a chunk of a bulk push carries the
    /// namespaces of its own ids, never the whole batch's map).
    #[must_use]
    pub fn subset<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> Self {
        let mut out = Self::new();
        for id in ids {
            if let Some(ns) = self.get(id) {
                out.insert(id, ns);
            }
        }
        out
    }

    /// True when nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Write the map into `body` under [`OUTBOUND_NAMESPACES_KEY`]. A
    /// non-object body or an empty map is left unchanged.
    pub fn annotate(&self, body: &mut Value) {
        if self.0.is_empty() {
            return;
        }
        if let Some(obj) = body.as_object_mut() {
            let map: Map<String, Value> = self
                .0
                .iter()
                .map(|(id, ns)| (id.clone(), Value::String(ns.clone())))
                .collect();
            obj.insert(OUTBOUND_NAMESPACES_KEY.to_string(), Value::Object(map));
        }
    }

    /// Read the map back from a body (a queued payload). Entries whose value
    /// is not a non-empty string are skipped, so they stay unresolved.
    #[must_use]
    pub fn from_body(body: &Value) -> Self {
        let mut out = Self::new();
        if let Some(Value::Object(map)) = body.get(OUTBOUND_NAMESPACES_KEY) {
            for (id, ns) in map {
                if let Some(ns) = ns.as_str() {
                    out.insert(id, ns);
                }
            }
        }
        out
    }
}

/// A push body cut to one peer's scope. The only constructor is [`admit`],
/// so the transport cannot be handed an unchecked body.
#[derive(Clone, Debug)]
pub struct ScopedOutbound {
    /// What goes on the wire: no [`OUTBOUND_NAMESPACES_KEY`].
    body: Value,
    /// What a queue row keeps: the wire body plus the annotation, so a
    /// replay re-admits with the same namespaces.
    stored: Value,
}

impl ScopedOutbound {
    /// The admitted wire body (no sender-local annotation).
    #[must_use]
    pub fn body(&self) -> &Value {
        &self.body
    }

    /// The admitted body with the namespace annotation, for a queue row.
    #[must_use]
    pub fn stored(&self) -> &Value {
        &self.stored
    }
}

/// The item's namespace, or `None` when it has no non-empty string one
/// (such an item is dropped: fail closed).
fn item_namespace(item: &Value) -> Option<&str> {
    item.get(crate::models::field_names::NAMESPACE)?
        .as_str()
        .filter(|ns| !ns.is_empty())
}

/// The ids an id-only item names: the string itself, both endpoints of a
/// link, or an object's `id`. Anything else names no id.
fn item_ids(item: &Value) -> Vec<&str> {
    if let Some(id) = item.as_str() {
        return vec![id];
    }
    let src = item.get(KEY_SOURCE_ID).and_then(Value::as_str);
    let dst = item.get(KEY_TARGET_ID).and_then(Value::as_str);
    if let (Some(src), Some(dst)) = (src, dst) {
        return vec![src, dst];
    }
    item.get(KEY_ID)
        .or_else(|| item.get(KEY_ACTION_ID))
        .and_then(Value::as_str)
        .map_or_else(Vec::new, |id| vec![id])
}

/// An id-only item is in scope when the peer takes every namespace, or every
/// id it names is annotated with a namespace the scope allows.
fn id_only_allowed(scope: &PeerOutboundScope, item: &Value, namespaces: &ItemNamespaces) -> bool {
    if scope.is_all() {
        return true;
    }
    let ids = item_ids(item);
    !ids.is_empty()
        && ids
            .iter()
            .all(|id| namespaces.get(id).is_some_and(|ns| scope.allows(ns)))
}

/// Cut `body` to the items `scope` allows. The namespaces of id-only items
/// come from the body's own [`OUTBOUND_NAMESPACES_KEY`] annotation.
///
/// # Errors
///
/// [`OutboundRefusal`] when the peer is deny-scoped, the body is not an
/// object, or the body offers items and none survives the cut (an
/// envelope-only body offers none and is sent as is).
pub fn admit(scope: &PeerOutboundScope, body: &Value) -> Result<ScopedOutbound, OutboundRefusal> {
    admit_counted(scope, body, &mut FilteredTally::default())
}

/// The namespaces of the items one admission left out, with their counts
/// (vote V2-9996 C-6). An id-only item whose id carries no namespace is
/// counted under [`FILTERED_UNRESOLVED_LABEL`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FilteredTally(BTreeMap<String, u64>);

impl FilteredTally {
    /// Count one left-out item in `namespace`.
    pub(crate) fn add(&mut self, namespace: &str) {
        let n = self.0.entry(namespace.to_string()).or_insert(0);
        *n = n.saturating_add(1);
    }

    /// The `(namespace, count)` pairs, namespace order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// True when nothing was left out.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The tally label of a left-out id-only item: its annotated namespace, or
/// [`FILTERED_UNRESOLVED_LABEL`] for each id with none.
fn tally_id_only(tally: &mut FilteredTally, item: &Value, namespaces: &ItemNamespaces) {
    let ids = item_ids(item);
    if ids.is_empty() {
        tally.add(FILTERED_UNRESOLVED_LABEL);
    }
    for id in ids {
        tally.add(namespaces.get(id).unwrap_or(FILTERED_UNRESOLVED_LABEL));
    }
}

/// [`admit`], also recording in `tally` the namespace of every item left out.
/// A deny-scoped peer is evaluated like a scope that admits nothing, so its
/// left-out items are counted before the refusal.
///
/// # Errors
///
/// As [`admit`].
pub fn admit_counted(
    scope: &PeerOutboundScope,
    body: &Value,
    tally: &mut FilteredTally,
) -> Result<ScopedOutbound, OutboundRefusal> {
    let Some(obj) = body.as_object() else {
        return Err(if matches!(scope, PeerOutboundScope::Deny) {
            OutboundRefusal::NoOutboundScope
        } else {
            OutboundRefusal::MalformedBody
        });
    };
    let namespaces = ItemNamespaces::from_body(body);
    let mut kept_memory_ids: HashSet<String> = HashSet::new();
    if let Some(Value::Array(mems)) = obj.get(KEY_MEMORIES) {
        for m in mems {
            if item_namespace(m).is_some_and(|ns| scope.allows(ns))
                && let Some(id) = m.get(KEY_ID).and_then(Value::as_str)
            {
                kept_memory_ids.insert(id.to_string());
            }
        }
    }
    let mut out = Map::new();
    let mut kept_namespaces = ItemNamespaces::new();
    let mut items = 0usize;
    // Items the caller offered: an envelope-only body (nothing offered)
    // carries no namespace, so it is sent as is to a non-deny peer.
    let mut offered = 0usize;
    for (key, value) in obj {
        let k = key.as_str();
        if k == OUTBOUND_NAMESPACES_KEY {
            continue;
        }
        if ENVELOPE_KEYS.contains(&k) {
            out.insert(key.clone(), value.clone());
            continue;
        }
        let Value::Array(values) = value else {
            // A non-array item key is kept only for an all-namespaces peer.
            offered = offered.saturating_add(1);
            if scope.is_all() {
                items = items.saturating_add(1);
                out.insert(key.clone(), value.clone());
            }
            continue;
        };
        let kept: Vec<Value> = if NAMESPACED_ITEM_KEYS.contains(&k) {
            let mut kept = Vec::with_capacity(values.len());
            for it in values {
                match item_namespace(it) {
                    Some(ns) if scope.allows(ns) => kept.push(it.clone()),
                    Some(ns) => tally.add(ns),
                    None => tally.add(FILTERED_UNRESOLVED_LABEL),
                }
            }
            kept
        } else if k == crate::models::field_names::EMBEDDINGS {
            values
                .iter()
                .filter(|e| {
                    e.get(KEY_MEMORY_ID)
                        .and_then(Value::as_str)
                        .is_some_and(|id| kept_memory_ids.contains(id))
                })
                .cloned()
                .collect()
        } else if k == KEY_NAMESPACE_META_CLEARS {
            let mut kept = Vec::with_capacity(values.len());
            for ns in values {
                match ns.as_str().filter(|ns| !ns.is_empty()) {
                    Some(n) if scope.allows(n) => kept.push(ns.clone()),
                    Some(n) => tally.add(n),
                    None => tally.add(FILTERED_UNRESOLVED_LABEL),
                }
            }
            kept
        } else {
            let mut kept: Vec<Value> = Vec::with_capacity(values.len());
            for it in values {
                if id_only_allowed(scope, it, &namespaces) {
                    kept.push(it.clone());
                } else {
                    tally_id_only(tally, it, &namespaces);
                }
            }
            for it in &kept {
                for id in item_ids(it) {
                    if let Some(ns) = namespaces.get(id) {
                        kept_namespaces.insert(id, ns);
                    }
                }
            }
            kept
        };
        if k != crate::models::field_names::EMBEDDINGS {
            items = items.saturating_add(kept.len());
            offered = offered.saturating_add(values.len());
        }
        out.insert(key.clone(), Value::Array(kept));
    }
    if matches!(scope, PeerOutboundScope::Deny) {
        return Err(OutboundRefusal::NoOutboundScope);
    }
    if items == 0 && offered > 0 {
        return Err(OutboundRefusal::NothingInScope);
    }
    let body = Value::Object(out);
    let mut stored = body.clone();
    kept_namespaces.annotate(&mut stored);
    Ok(ScopedOutbound { body, stored })
}

/// Config entry shape, the inbound `PeerScope` minus the sender list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundScopeEntry {
    allowed_namespaces: Vec<String>,
}

/// Why the outbound scope config was refused (boot fails closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundScopeConfigError {
    /// The env value is not valid UTF-8.
    NotUnicode,
    /// The env value is over [`MAX_OUTBOUND_SCOPE_ENV_BYTES`].
    TooLarge,
    /// The JSON does not parse into the contract shape.
    Malformed(String),
    /// A peer has more than [`MAX_OUTBOUND_PATTERNS`] patterns.
    TooManyPatterns(String),
    /// A pattern is empty or longer than [`MAX_OUTBOUND_PATTERN_LEN`].
    BadPattern(String),
    /// A key names no configured `--quorum-peers` peer.
    UnknownPeer(String),
    /// Two keys normalise to the same peer (case or a trailing `/`), so
    /// which scope applies would depend on key order.
    DuplicatePeer(String),
}

impl std::fmt::Display for OutboundScopeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUnicode => write!(f, "{OUTBOUND_SCOPE_ENV} is not valid UTF-8"),
            Self::TooLarge => write!(
                f,
                "{OUTBOUND_SCOPE_ENV} is over {MAX_OUTBOUND_SCOPE_ENV_BYTES} bytes"
            ),
            Self::Malformed(e) => write!(f, "{OUTBOUND_SCOPE_ENV} is malformed: {e}"),
            Self::TooManyPatterns(p) => write!(
                f,
                "{OUTBOUND_SCOPE_ENV}: peer {p} has more than {MAX_OUTBOUND_PATTERNS} patterns"
            ),
            Self::BadPattern(p) => write!(
                f,
                "{OUTBOUND_SCOPE_ENV}: peer {p} has an empty pattern or one over \
                 {MAX_OUTBOUND_PATTERN_LEN} bytes"
            ),
            Self::UnknownPeer(p) => write!(
                f,
                "{OUTBOUND_SCOPE_ENV}: key {p} names no configured quorum peer"
            ),
            Self::DuplicatePeer(p) => write!(
                f,
                "{OUTBOUND_SCOPE_ENV}: peer {p} is named by more than one key"
            ),
        }
    }
}

impl std::error::Error for OutboundScopeConfigError {}

/// Where the value failed to parse, without any of its text: serde names
/// the offending value (`invalid type: string "..."`), and a peer key is a
/// URL that may carry credentials.
fn malformed_position(e: &serde_json::Error) -> String {
    let kind = match e.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "shape",
        serde_json::error::Category::Eof => "truncated",
    };
    format!("{kind} error at line {} column {}", e.line(), e.column())
}

/// Parse the env value into a map of stable peer id to scope.
///
/// # Errors
///
/// [`OutboundScopeConfigError`] for any value outside the contract.
pub fn parse(raw: &str) -> Result<BTreeMap<String, PeerOutboundScope>, OutboundScopeConfigError> {
    if raw.len() > MAX_OUTBOUND_SCOPE_ENV_BYTES {
        return Err(OutboundScopeConfigError::TooLarge);
    }
    let entries: BTreeMap<String, OutboundScopeEntry> = serde_json::from_str(raw)
        .map_err(|e| OutboundScopeConfigError::Malformed(malformed_position(&e)))?;
    let mut out = BTreeMap::new();
    for (url, entry) in entries {
        let shown = crate::url_display::url_origin_and_path(&url);
        if entry.allowed_namespaces.len() > MAX_OUTBOUND_PATTERNS {
            return Err(OutboundScopeConfigError::TooManyPatterns(shown));
        }
        if entry
            .allowed_namespaces
            .iter()
            .any(|p| p.is_empty() || p.len() > MAX_OUTBOUND_PATTERN_LEN)
        {
            return Err(OutboundScopeConfigError::BadPattern(shown));
        }
        let scope = if entry.allowed_namespaces.is_empty() {
            PeerOutboundScope::Deny
        } else {
            PeerOutboundScope::Namespaces(entry.allowed_namespaces)
        };
        if out
            .insert(super::peer::stable_peer_id(&url), scope)
            .is_some()
        {
            return Err(OutboundScopeConfigError::DuplicatePeer(shown));
        }
    }
    Ok(out)
}

/// Read [`OUTBOUND_SCOPE_ENV`]; unset is an empty map (every peer denied).
///
/// # Errors
///
/// [`OutboundScopeConfigError`] for a value outside the contract.
pub fn from_env() -> Result<BTreeMap<String, PeerOutboundScope>, OutboundScopeConfigError> {
    match std::env::var(OUTBOUND_SCOPE_ENV) {
        Ok(raw) => parse(&raw),
        Err(std::env::VarError::NotPresent) => Ok(BTreeMap::new()),
        Err(std::env::VarError::NotUnicode(_)) => Err(OutboundScopeConfigError::NotUnicode),
    }
}

/// Apply a parsed scope map to the configured peers. Every key must name a
/// peer; a peer with no key stays [`PeerOutboundScope::Deny`].
///
/// # Errors
///
/// [`OutboundScopeConfigError::UnknownPeer`] for a key that names no peer.
pub fn apply(
    config: &mut super::FederationConfig,
    mut scopes: BTreeMap<String, PeerOutboundScope>,
) -> Result<(), OutboundScopeConfigError> {
    for peer in &mut config.peers {
        peer.outbound_scope = scopes.remove(&peer.id).unwrap_or_default();
    }
    if let Some((id, _)) = scopes.into_iter().next() {
        return Err(OutboundScopeConfigError::UnknownPeer(id));
    }
    Ok(())
}

/// Daemon boot wrapper: apply [`from_env`] to a built federation config.
///
/// # Errors
///
/// The config error, so boot refuses instead of sending unscoped.
pub fn apply_env(
    config: Option<super::FederationConfig>,
) -> Result<Option<super::FederationConfig>, OutboundScopeConfigError> {
    let Some(mut cfg) = config else {
        return Ok(None);
    };
    apply(&mut cfg, from_env()?)?;
    Ok(Some(cfg))
}

/// The scope of each `sync-daemon --peers` URL, in order, from a parsed map.
/// A URL with no key is [`PeerOutboundScope::Deny`].
///
/// # Errors
///
/// [`OutboundScopeConfigError::UnknownPeer`] for a key that names no URL.
pub fn resolve_for_urls(
    urls: &[String],
    scopes: &BTreeMap<String, PeerOutboundScope>,
) -> Result<Vec<PeerOutboundScope>, OutboundScopeConfigError> {
    let ids: Vec<String> = urls
        .iter()
        .map(|u| super::peer::stable_peer_id(u))
        .collect();
    let known: HashSet<&str> = ids.iter().map(String::as_str).collect();
    if let Some(id) = scopes.keys().find(|k| !known.contains(k.as_str())) {
        return Err(OutboundScopeConfigError::UnknownPeer(id.clone()));
    }
    Ok(ids
        .iter()
        .map(|id| scopes.get(id).cloned().unwrap_or_default())
        .collect())
}

/// `serve` boot: apply [`from_env`] to the built federation config and
/// record one row (and one WARN when unscoped) per peer (C-5).
///
/// # Errors
///
/// A malformed value or a key naming no peer, so boot refuses rather than
/// sending unscoped.
pub fn install_for_serve(
    config: Option<super::FederationConfig>,
) -> anyhow::Result<Option<super::FederationConfig>> {
    let config = apply_env(config).map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(cfg) = config.as_ref() {
        record_boot_scopes(
            cfg.peers
                .iter()
                .map(|p| (p.id.as_str(), p.sync_push_url.as_str(), &p.outbound_scope)),
        );
    }
    Ok(config)
}

/// `sync-daemon` boot: the scope of each `--peers` URL, in order, from
/// [`from_env`], with one row (and one WARN when unscoped) per peer (C-5).
///
/// # Errors
///
/// A malformed value or a key naming no URL, so the daemon refuses to start.
pub fn sync_daemon_scopes(
    urls: &[String],
) -> anyhow::Result<Vec<std::sync::Arc<PeerOutboundScope>>> {
    let map = from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    let scopes = resolve_for_urls(urls, &map).map_err(|e| anyhow::anyhow!("{e}"))?;
    let ids: Vec<String> = urls
        .iter()
        .map(|u| super::peer::stable_peer_id(u))
        .collect();
    record_boot_scopes(
        ids.iter()
            .zip(urls)
            .zip(&scopes)
            .map(|((id, url), scope)| (id.as_str(), url.as_str(), scope)),
    );
    Ok(scopes.into_iter().map(std::sync::Arc::new).collect())
}

/// The per-peer cut of one lane's body: who receives what, who is refused.
pub(super) struct DispatchPlan {
    admitted: Vec<(super::PeerEndpoint, ScopedOutbound)>,
}

impl DispatchPlan {
    /// Admit `body` for every configured peer. A refused peer gets no
    /// request and no queue row; the refusal is traced and counted.
    pub(super) fn new(config: &super::FederationConfig, body: &Value, lane: &str) -> Self {
        let mut admitted = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            match admit_recorded(&peer.id, &peer.outbound_scope, body) {
                Ok(scoped) => admitted.push((peer.clone(), scoped)),
                Err(refusal) => note_refusal(&peer.id, lane, &refusal),
            }
        }
        Self { admitted }
    }

    /// The same admitted peers, each with `body` cut to its scope. Used for
    /// the per-id queue rows of a multi-id push: a peer whose scope refuses
    /// the narrower body drops out (it was traced on the first admission).
    pub(super) fn rescoped(&self, body: &Value) -> Self {
        let admitted = self
            .admitted
            .iter()
            .filter_map(|(peer, _)| {
                admit(&peer.outbound_scope, body)
                    .ok()
                    .map(|scoped| (peer.clone(), scoped))
            })
            .collect();
        Self { admitted }
    }

    /// The admitted peers with their cut bodies.
    pub(super) fn admitted(&self) -> impl Iterator<Item = (&super::PeerEndpoint, &ScopedOutbound)> {
        self.admitted.iter().map(|(p, s)| (p, s))
    }

    /// #9996 (vote V2-9996 C-4) — the write's quorum denominator is the
    /// local commit plus the admitted peers; the minimum stays `W`. A set
    /// below `W` makes the lane answer `QuorumFailureReason::OutboundScope`
    /// (never a narrowed `W`, never quorum-met).
    pub(super) fn record_quorum_scope(
        &self,
        tracker: &mut crate::replication::AckTracker,
        lane: &str,
    ) {
        if let Some((w, replicas)) = tracker.record_scope_replicas(self.admitted.len()) {
            tracing::warn!(
                target: OUTBOUND_SCOPE_TRACE_TARGET,
                lane = %lane,
                quorum_minimum = w,
                replicas_in_scope = replicas,
                "federation: lane {lane} cannot reach quorum W={w}: only {replicas} \
                 replica(s) are in outbound scope for this push",
            );
        }
    }
}

/// [`note_refusal`] for a crate caller outside `federation` (the sync daemon).
pub(crate) fn note_refusal_public(peer_id: &str, lane: &str, refusal: &OutboundRefusal) {
    note_refusal(peer_id, lane, refusal);
}

/// [`admit`] for one send to `peer_id`, recording the C-6 filtered counts.
///
/// # Errors
///
/// As [`admit`].
pub(crate) fn admit_recorded(
    peer_id: &str,
    scope: &PeerOutboundScope,
    body: &Value,
) -> Result<ScopedOutbound, OutboundRefusal> {
    let mut tally = FilteredTally::default();
    let res = admit_counted(scope, body, &mut tally);
    record_filtered(peer_id, &tally);
    res
}

/// Trace one refusal. No body byte is logged.
pub(super) fn note_refusal(peer_id: &str, lane: &str, refusal: &OutboundRefusal) {
    tracing::debug!(
        target: OUTBOUND_SCOPE_TRACE_TARGET,
        peer_id = %peer_id,
        lane = %lane,
        reason = refusal.reason(),
        "federation: outbound push to peer {peer_id} on lane {lane} not sent: {}",
        refusal.reason()
    );
    crate::metrics::registry()
        .federation_outbound_scope_refused
        .inc();
}

/// The `(peer_id, namespace)` series the C-6 counter has minted, with their
/// counts, so stats and doctor read one bounded map.
static FILTERED_SERIES: std::sync::Mutex<BTreeMap<(String, String), u64>> =
    std::sync::Mutex::new(BTreeMap::new());

/// `namespace` cut to [`MAX_FILTERED_LABEL_BYTES`] at a char boundary.
fn label_of(namespace: &str) -> &str {
    if namespace.len() <= MAX_FILTERED_LABEL_BYTES {
        return namespace;
    }
    let mut end = MAX_FILTERED_LABEL_BYTES;
    while !namespace.is_char_boundary(end) {
        end -= 1;
    }
    &namespace[..end]
}

/// Count one admission's left-out items per `(peer_id, namespace)` (vote
/// V2-9996 C-6). A new series past [`MAX_FILTERED_SERIES`] is counted under
/// [`FILTERED_OVERFLOW_LABEL`] instead.
pub(crate) fn record_filtered(peer_id: &str, tally: &FilteredTally) {
    if tally.is_empty() {
        return;
    }
    let mut series = FILTERED_SERIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (namespace, n) in tally.iter() {
        let mut key = (
            label_of(peer_id).to_string(),
            label_of(namespace).to_string(),
        );
        if !series.contains_key(&key) && series.len() >= MAX_FILTERED_SERIES {
            // Both labels collapse: a new peer label past the cap would
            // otherwise still mint a new Prometheus series.
            key = (
                FILTERED_OVERFLOW_LABEL.to_string(),
                FILTERED_OVERFLOW_LABEL.to_string(),
            );
        }
        let total = series.entry(key.clone()).or_insert(0);
        *total = total.saturating_add(n);
        crate::metrics::registry()
            .federation_outbound_scope_filtered
            .with_label_values(&[key.0.as_str(), key.1.as_str()])
            .inc_by(n);
    }
}

/// One filtered series as stats and doctor show it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilteredSeries {
    /// Stable (hashed) peer id; never the URL.
    pub peer_id: String,
    /// Namespace label (cut, overflow or unresolved as documented).
    pub namespace: String,
    /// Items left out for that peer and namespace.
    pub count: u64,
}

/// Snapshot of the C-6 series, `(peer_id, namespace)` order.
#[must_use]
pub fn filtered_series() -> Vec<FilteredSeries> {
    FILTERED_SERIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|((peer_id, namespace), count)| FilteredSeries {
            peer_id: peer_id.clone(),
            namespace: namespace.clone(),
            count: *count,
        })
        .collect()
}

/// A configured peer's outbound scope class (vote V2-9996 C-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopePosture {
    /// No scope: the peer receives nothing. Doctor fails this row under
    /// every posture.
    Unscoped,
    /// The explicit all-namespaces scope. Doctor warns; the
    /// enterprise-federation posture fails it.
    AllNamespaces,
    /// Named namespaces only.
    Narrowed,
}

impl ScopePosture {
    /// The class of `scope`.
    #[must_use]
    pub fn of(scope: &PeerOutboundScope) -> Self {
        match scope {
            PeerOutboundScope::Deny => Self::Unscoped,
            s if s.is_all() => Self::AllNamespaces,
            PeerOutboundScope::Namespaces(_) => Self::Narrowed,
        }
    }

    /// The doctor / wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unscoped => "unscoped",
            Self::AllNamespaces => POSTURE_ALL_NAMESPACES,
            Self::Narrowed => "narrowed",
        }
    }
}

/// One configured peer's scope row, content-free (stable peer id only).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerScopeRow {
    /// Stable (hashed) peer id.
    pub peer_id: String,
    /// The peer's scope class.
    pub posture: ScopePosture,
}

/// The scope rows the running daemon recorded at boot. `None` in a process
/// that configured no peers (for example a local doctor).
static BOOT_SCOPE_ROWS: std::sync::RwLock<Option<Vec<PeerScopeRow>>> = std::sync::RwLock::new(None);

/// WARN text for a peer with no outbound scope at boot (C-5).
pub const WARN_UNSCOPED_PEER: &str = "has no outbound namespace scope and receives nothing";

/// Boot (C-5): one WARN per configured peer with no outbound scope, naming
/// it (origin and path, never credentials) and its stable id; the rows are
/// kept for stats and doctor. `peers` is `(stable peer id, peer url, scope)`.
pub fn record_boot_scopes<'a>(
    peers: impl IntoIterator<Item = (&'a str, &'a str, &'a PeerOutboundScope)>,
) -> Vec<PeerScopeRow> {
    let mut rows = Vec::new();
    for (peer_id, url, scope) in peers {
        let peer_id = peer_id.to_string();
        let posture = ScopePosture::of(scope);
        if posture == ScopePosture::Unscoped {
            let shown = crate::url_display::url_origin_and_path(url);
            let shown = shown.as_str();
            tracing::warn!(
                target: OUTBOUND_SCOPE_TRACE_TARGET,
                peer = %shown,
                peer_id = %peer_id,
                "federation: peer {shown} ({peer_id}) {WARN_UNSCOPED_PEER}; set \
                 {OUTBOUND_SCOPE_ENV} to name the namespaces it may receive",
            );
        }
        rows.push(PeerScopeRow { peer_id, posture });
    }
    *BOOT_SCOPE_ROWS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(rows.clone());
    rows
}

/// Doctor fact key prefix of a peer's scope row (`outbound_scope.<peer_id>`).
pub const DOCTOR_FACT_SCOPE_PREFIX: &str = "outbound_scope.";
/// Doctor fact key prefix of a filtered series
/// (`outbound_scope_filtered.<peer_id>.<namespace>`).
pub const DOCTOR_FACT_FILTERED_PREFIX: &str = "outbound_scope_filtered.";

/// How loud a doctor row about the outbound scope is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeAlarm {
    /// Every peer is narrowed (or no peer is configured).
    Clear,
    /// A peer has the explicit all-namespaces scope.
    AllNamespaces,
    /// A peer has no scope: a failing row under every posture (C-5).
    Unscoped,
}

/// The doctor facts for `rows` and `filtered`: one per peer and one per
/// filtered series, plus the alarm level of the worst peer.
#[must_use]
pub fn doctor_facts(
    rows: &[PeerScopeRow],
    filtered: &[FilteredSeries],
) -> (Vec<(String, String)>, ScopeAlarm) {
    let mut facts = Vec::with_capacity(rows.len() + filtered.len());
    let mut alarm = ScopeAlarm::Clear;
    for row in rows {
        facts.push((
            format!("{DOCTOR_FACT_SCOPE_PREFIX}{}", row.peer_id),
            row.posture.as_str().to_string(),
        ));
        alarm = alarm.max(match row.posture {
            ScopePosture::Unscoped => ScopeAlarm::Unscoped,
            ScopePosture::AllNamespaces => ScopeAlarm::AllNamespaces,
            ScopePosture::Narrowed => ScopeAlarm::Clear,
        });
    }
    for s in filtered {
        facts.push((
            format!("{DOCTOR_FACT_FILTERED_PREFIX}{}.{}", s.peer_id, s.namespace),
            s.count.to_string(),
        ));
    }
    (facts, alarm)
}

/// Doctor note for a non-clear [`ScopeAlarm`].
#[must_use]
pub fn doctor_note(alarm: ScopeAlarm) -> Option<String> {
    match alarm {
        ScopeAlarm::Clear => None,
        ScopeAlarm::AllNamespaces => Some(format!(
            "#9996: a peer has the explicit all-namespaces outbound scope \
             ({ALL_NAMESPACES_PATTERN}); name the namespaces it may receive in {OUTBOUND_SCOPE_ENV}."
        )),
        ScopeAlarm::Unscoped => Some(format!(
            "#9996: a configured peer has no outbound namespace scope and receives nothing; \
             set {OUTBOUND_SCOPE_ENV} for it, or remove the peer."
        )),
    }
}

/// The rows [`record_boot_scopes`] kept, if any.
#[must_use]
pub fn boot_scope_rows() -> Option<Vec<PeerScopeRow>> {
    BOOT_SCOPE_ROWS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(test)]
#[path = "outbound_scope_tests.rs"]
mod tests;
