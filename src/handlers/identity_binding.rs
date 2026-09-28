// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2044 (v1.0.0, #2032-A) — HTTP-surface per-agent-key principal binding.
//!
//! Closes the two highest findings of the #2032 adversarial assessment, which
//! share ONE root cause: on the HTTP surface the `X-Agent-Id` header is a
//! SELF-ASSERTED principal while the `api_key` is only a SHARED transport
//! credential. So any api-key-bearing caller could
//!
//!   * **H1 (IDOR/BOLA)** set `X-Agent-Id: <victim>` and read/mutate another
//!     agent's `scope=private` rows on `GET/PUT/DELETE/promote /memories/{id}`;
//!   * **M1 (admin spoof)** set `X-Agent-Id: <admin>` and pass the
//!     [`crate::handlers::admin_role::require_admin`] allowlist gate.
//!
//! The fix is **per-agent-key principal binding**: a request asserting
//! `X-Agent-Id: X` must prove control of agent `X`'s enrolled per-agent api-key
//! (a server-held secret in the `agent_api_keys` table, `sha256(token) →
//! agent_id`) before the header identity is honored on the IDOR-sensitive
//! read/mutate and admin paths. The principal is keyed to a server-held secret,
//! NEVER a header (the #1570/#1582 lesson). Per the #1950 read-path freeze this
//! introduces NO new signed request envelope — it reuses the presented
//! per-agent key.
//!
//! The [`crate::handlers::api_key_auth`] middleware BINDS the presented per-agent
//! key's `agent_id` onto the `X-Agent-Id` header; the IDOR/admin gates re-derive
//! the caller's [`AuthLevel`] self-containedly from the enrolled map + presented
//! `X-API-Key` ([`resolve_auth_level`]) and consume it. Posture is the tri-state
//! [`crate::config::HttpIdentityMode`] (`off`/`advisory`/`enforce`, default
//! `advisory`).

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::HttpIdentityMode;

/// The provenance of the caller's resolved `agent_id` on the HTTP surface.
///
/// Re-derived per request by [`resolve_auth_level`] and consumed by the
/// IDOR/admin gates (via [`enforce_sensitive_identity`]). Ordering is significant:
/// `Claimed < KeyAuthenticated < SignatureAttested` by assurance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// Self-asserted `X-Agent-Id` only — proven possession of the SHARED
    /// transport credential (or a keyless bind), NOT of this principal. The
    /// spoofable level the #2044 fix distrusts on sensitive paths.
    Claimed,
    /// The presented `X-API-Key` is an enrolled PER-AGENT key whose
    /// `sha256(token)` resolved to this `agent_id` (`agent_api_keys` table).
    /// Cryptographic-secret possession of this principal.
    KeyAuthenticated,
    /// Reserved — a per-request Ed25519 `SignableWrite` attestation. NOT
    /// produced by this train (#1950 froze the read/mutate request envelope);
    /// the additive `ai-memory/recall-attestation/v1` lands post-v1.0.
    SignatureAttested,
}

impl AuthLevel {
    /// Lowercase wire tag for audit surfaces.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::KeyAuthenticated => "key_authenticated",
            Self::SignatureAttested => "signature_attested",
        }
    }

    /// `true` when the level proves cryptographic-secret possession of the
    /// principal (i.e. NOT merely `Claimed`). This is the bar the `enforce`
    /// posture requires on IDOR-sensitive read/mutate + admin paths.
    #[must_use]
    pub fn is_key_bound(self) -> bool {
        matches!(self, Self::KeyAuthenticated | Self::SignatureAttested)
    }
}

/// Lowercase hex `sha256` of an api-key token — the stored `agent_api_keys`
/// lookup key. The raw token is NEVER persisted (only its digest), so a DB read
/// cannot recover the bearer secret.
#[must_use]
pub fn api_key_sha256_hex(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        // `write!` into a `String` is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// v1.0.0 #3418 — the LIVE enrolled per-agent api-key registry.
///
/// # The defect this closes
///
/// The enrolled map used to be an `Arc<HashMap<..>>` captured ONCE at boot and
/// cloned into `AppState` + `ApiKeyState`. Everything downstream was correct;
/// the map itself was a photograph. Three consequences, and the third is a
/// security defect rather than an ergonomic one:
///
/// * a swarm/hive that mints agents dynamically could never bind them without
///   restarting the data-tier daemon per enrollment, so the only workable
///   posture for a live fleet was `advisory` — self-asserted identity, which is
///   exactly what the enforce mode exists to refuse;
/// * enrollment on the certified postgres tier appeared unreachable;
/// * **a REVOKED key stayed valid until the next restart.** Revocation that
///   does not revoke is the worst failure mode a credential control has: the
///   operator has been told the key is dead and it is not.
///
/// # The control
///
/// One swappable snapshot behind an `RwLock`. Readers take the lock only long
/// enough to bump an `Arc` refcount and release it, so the hot auth path stays
/// allocation-free and lock-free in the contended sense, and NO guard is ever
/// held across an `.await` (CONCURRENCY-20). Writers install a whole new map;
/// there is no partial state a reader can observe, so a refresh can never leave
/// the registry half-updated — a reader sees either the old map or the new one.
///
/// `generation` increments on every INSTALLED change, so boot, doctor and the
/// refresh loop can report "the posture actually moved" rather than "we asked".
///
/// # Loads are ordered against mutations (v1.0.0 #4066)
///
/// Whole-map replacement alone does not order a store READ against the
/// publication of its result. A refresh that read the key set BEFORE a revoke
/// committed could publish that set AFTER the revoke narrowed the map, and so
/// re-arm a credential the revoke response had just called dead. Two rules
/// close that, both enforced under the ONE write lock that publishes the map:
///
/// * every MUTATION ([`Self::mutate`], [`Self::mutate_if_current`],
///   [`Self::install`]) bumps a mutation `epoch` in the same critical section
///   that publishes its map, so a transform is an atomic read-modify-write
///   rather than a clone that a concurrent writer can overwrite;
/// * every LOAD captures a [`LoadTicket`] (the epoch) BEFORE its store read
///   starts ([`refresh_agent_keys`]) and publishes through
///   [`Self::install_loaded`], which compares the ticket against the epoch
///   under that same lock and DISCARDS a read that a mutation has overtaken.
///
/// A discarded load is a degrade (the registry keeps the mutation's map, which
/// already reflects the durable write) — never a resurrection.
#[derive(Debug)]
pub struct EnrolledAgentKeys {
    inner: std::sync::RwLock<Published>,
    generation: std::sync::atomic::AtomicU64,
    pub(crate) monitoring: super::monitoring::MonitoringConfig,
    pub(crate) monitoring_tls: bool,
}

/// The published registry state: the map plus the mutation epoch it was
/// published at. Kept behind ONE lock so the epoch comparison and the
/// publication are a single critical section (#4066).
#[derive(Debug)]
struct Published {
    map: std::sync::Arc<std::collections::HashMap<String, String>>,
    epoch: u64,
}

/// Proof of WHEN a registry load began: the mutation epoch observed before the
/// store read started (v1.0.0 #4066).
///
/// Opaque by design — only [`EnrolledAgentKeys::begin_load`] mints one — so a
/// caller cannot fabricate a "fresh" ticket for a read that is actually stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a load ticket only protects a load that publishes through it"]
pub struct LoadTicket {
    epoch: u64,
}

/// What [`EnrolledAgentKeys::install_loaded`] did with a loaded map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadInstall {
    /// The loaded map differed and is now published.
    Installed,
    /// The loaded map equals the published one; nothing changed.
    Unchanged,
    /// A mutation was published after the load's ticket was taken, so the
    /// read may predate a durable revoke. It was DISCARDED (#4066).
    Superseded,
}

impl EnrolledAgentKeys {
    /// Seed the registry from an already-loaded map (generation 0).
    #[must_use]
    pub fn from_map(map: std::collections::HashMap<String, String>) -> Self {
        Self {
            inner: std::sync::RwLock::new(Published {
                map: std::sync::Arc::new(map),
                epoch: 0,
            }),
            generation: std::sync::atomic::AtomicU64::new(0),
            monitoring: super::monitoring::MonitoringConfig::default(),
            monitoring_tls: false,
        }
    }

    /// Assign health-only scopes and actual listener TLS posture before sharing.
    /// Scope assignments remain fixed while enrolled keys refresh/revoke live.
    #[must_use]
    pub fn with_monitoring(
        mut self,
        scopes: super::monitoring::MonitoringConfig,
        tls: bool,
    ) -> Self {
        self.monitoring = scopes;
        self.monitoring_tls = tls;
        self
    }

    /// An EMPTY registry — the inert posture (see [`enforce_for_request`]).
    #[must_use]
    pub fn empty() -> Self {
        Self::from_map(std::collections::HashMap::new())
    }

    /// Cheap read: bump the `Arc` refcount and drop the lock immediately.
    ///
    /// A poisoned lock recovers via `into_inner` rather than panicking — this
    /// sits on the request auth path, and taking the whole surface down because
    /// some unrelated writer panicked would convert a bug into an outage
    /// (CONCURRENCY-18).
    #[must_use]
    pub fn snapshot(&self) -> std::sync::Arc<std::collections::HashMap<String, String>> {
        match self.inner.read() {
            Ok(g) => std::sync::Arc::clone(&g.map),
            Err(poisoned) => std::sync::Arc::clone(&poisoned.into_inner().map),
        }
    }

    /// The publication lock, recovering from poison (CONCURRENCY-18: the auth
    /// path must not turn an unrelated panic into an outage).
    fn write_published(&self) -> std::sync::RwLockWriteGuard<'_, Published> {
        match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Publish `map` under an already-held write guard and bump the epoch.
    /// Returns whether the contents changed. The epoch moves even when they
    /// did not: a mutation is ordered against in-flight loads by the fact that
    /// it HAPPENED, not by whether this process's view moved (#4066).
    fn publish_mutation(
        &self,
        mut guard: std::sync::RwLockWriteGuard<'_, Published>,
        map: std::collections::HashMap<String, String>,
    ) -> bool {
        guard.epoch = guard.epoch.wrapping_add(1);
        if *guard.map == map {
            return false;
        }
        guard.map = std::sync::Arc::new(map);
        drop(guard);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        true
    }

    /// AUTHORITATIVE replacement: publish `map` as a mutation. Every load whose
    /// ticket predates this call is superseded. Returns `true` when the
    /// contents actually CHANGED, so callers can log a real transition.
    pub fn install(&self, map: std::collections::HashMap<String, String>) -> bool {
        let guard = self.write_published();
        self.publish_mutation(guard, map)
    }

    /// Atomic read-modify-write of the published map (#4066).
    ///
    /// `transform` runs on a copy of the CURRENT map while the publication lock
    /// is held, so two concurrent transforms serialise instead of each cloning
    /// the same snapshot and the later install silently undoing the earlier
    /// one. Keep `transform` short and non-blocking: it runs under the lock the
    /// request auth path reads through.
    pub fn mutate(
        &self,
        transform: impl FnOnce(&mut std::collections::HashMap<String, String>),
    ) -> bool {
        let guard = self.write_published();
        let mut next = (*guard.map).clone();
        transform(&mut next);
        self.publish_mutation(guard, next)
    }

    /// [`Self::mutate`], but only when no mutation has been published since
    /// `ticket` was taken. Returns `None` (nothing applied) when one has.
    ///
    /// This is the WIDENING form: a bind takes its ticket BEFORE its durable
    /// write, and applies its insert here afterwards. If a revoke's transform
    /// landed in between, the insert could re-arm a key the revoke already
    /// removed, so it is refused and the caller falls back to an
    /// authoritative load instead.
    pub fn mutate_if_current(
        &self,
        ticket: LoadTicket,
        transform: impl FnOnce(&mut std::collections::HashMap<String, String>),
    ) -> Option<bool> {
        let guard = self.write_published();
        if guard.epoch != ticket.epoch {
            return None;
        }
        let mut next = (*guard.map).clone();
        transform(&mut next);
        Some(self.publish_mutation(guard, next))
    }

    /// Take a [`LoadTicket`]. MUST be called before the store read it guards
    /// starts; [`refresh_agent_keys`] enforces that ordering structurally.
    pub fn begin_load(&self) -> LoadTicket {
        let epoch = match self.inner.read() {
            Ok(g) => g.epoch,
            Err(poisoned) => poisoned.into_inner().epoch,
        };
        LoadTicket { epoch }
    }

    /// Publish a LOADED map, unless a mutation overtook the read (#4066).
    ///
    /// The ticket is compared under the same write lock that publishes, so no
    /// mutation can slip between the check and the install. A load does not
    /// bump the epoch: it reports the store, it does not change it.
    pub fn install_loaded(
        &self,
        ticket: LoadTicket,
        map: std::collections::HashMap<String, String>,
    ) -> LoadInstall {
        let mut guard = self.write_published();
        if guard.epoch != ticket.epoch {
            return LoadInstall::Superseded;
        }
        if *guard.map == map {
            return LoadInstall::Unchanged;
        }
        guard.map = std::sync::Arc::new(map);
        drop(guard);
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        LoadInstall::Installed
    }

    /// Number of currently enrolled keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// `true` when no per-agent key is enrolled — the fully-inert posture.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshot().is_empty()
    }

    /// How many times an actual change has been installed since boot.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Env var resolving how often the daemon re-reads `agent_api_keys`.
///
/// Named here rather than in `config.rs` because the VALUE is identity-binding
/// policy: it is the upper bound on how long a REVOKED key keeps working.
pub const ENV_AGENT_KEY_REFRESH_SECS: &str = "AI_MEMORY_AGENT_KEY_REFRESH_SECS";

/// Compiled default refresh cadence, in seconds.
///
/// 15s is chosen as the revocation window an operator can reason about: short
/// enough that "I revoked that key" is true within a quarter-minute, long
/// enough that a 1000-daemon fleet polling one postgres tier costs one trivial
/// indexed read per daemon per 15s. The read is `SELECT token_sha256, agent_id`
/// over a table sized by ENROLLED AGENTS, not by memories.
pub const DEFAULT_AGENT_KEY_REFRESH_SECS: u64 = 15;

/// Resolve the refresh cadence from [`ENV_AGENT_KEY_REFRESH_SECS`].
///
/// `0` DISABLES the loop and pins the pre-#3418 restart-required behaviour —
/// an operator may legitimately want that on a single-operator box. It is
/// returned as `None` so the caller can say so at boot rather than silently
/// running with a photograph.
///
/// An unparseable or negative value falls back to the default with a WARN: an
/// unrecognised token must NEVER silently widen a security window (the #131 /
/// FBL-14 rule), and "the operator meant to tighten this and got the default"
/// is recoverable, while "the operator meant to tighten this and got infinity"
/// is not.
#[must_use]
pub fn resolve_agent_key_refresh_interval() -> Option<std::time::Duration> {
    let raw = match std::env::var(ENV_AGENT_KEY_REFRESH_SECS) {
        Ok(v) => v,
        Err(_) => {
            return Some(std::time::Duration::from_secs(
                DEFAULT_AGENT_KEY_REFRESH_SECS,
            ));
        }
    };
    match raw.trim().parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(std::time::Duration::from_secs(secs)),
        Err(_) => {
            tracing::warn!(
                target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                "{ENV_AGENT_KEY_REFRESH_SECS}={raw:?} is not a whole number of seconds \
                 — falling back to the {DEFAULT_AGENT_KEY_REFRESH_SECS}s default rather \
                 than widening the per-agent-key revocation window"
            );
            Some(std::time::Duration::from_secs(
                DEFAULT_AGENT_KEY_REFRESH_SECS,
            ))
        }
    }
}

/// The boot line describing the live-refresh posture, so an operator can read
/// their revocation window off the log instead of inferring it.
#[must_use]
pub fn refresh_posture_note(interval: Option<std::time::Duration>) -> String {
    match interval {
        Some(d) => format!(
            "per-agent api-key registry refreshes every {}s (#3418): enrollment and \
             REVOCATION take effect within that window with no daemon restart",
            d.as_secs()
        ),
        None => format!(
            "per-agent api-key live refresh is DISABLED ({ENV_AGENT_KEY_REFRESH_SECS}=0): \
             the enrolled set is a boot snapshot, so an enrollment will not be honoured \
             and a REVOKED key will keep authenticating until this daemon restarts"
        ),
    }
}

/// What one pass of the live-refresh loop DID — the observable outcome of
/// [`apply_agent_key_refresh`].
///
/// Returned (rather than only logged) so the refresh contract is testable
/// without standing up a daemon: "a failed read keeps the last known set" is a
/// security property, and a property that only exists inside a `tokio::spawn`
/// body is a property no regression test can pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKeyRefresh {
    /// The store returned a DIFFERENT set; it is now installed. Carries the
    /// new enrolled count.
    Installed(usize),
    /// The store returned the same set; nothing was installed. Carries the
    /// unchanged enrolled count.
    Unchanged(usize),
    /// The read FAILED. The previous snapshot is retained; carries the count
    /// that is still armed.
    KeptLastKnown(usize),
    /// The read SUCCEEDED but a mutation (a revoke or bind) was published
    /// after it began, so its result may predate that durable write and was
    /// DISCARDED (#4066). The registry keeps the mutation's map; carries the
    /// count that is still armed. The next refresh reads again.
    Superseded(usize),
}

/// The ONE place a refresh result becomes registry state.
///
/// Both the sqlite and the postgres refresh paths funnel through here, so the
/// degrade rule is stated once rather than per backend:
///
/// **A failed read KEEPS the last known snapshot.** Installing an empty map on
/// a transient store error would silently disarm the identity gate — an empty
/// registry makes [`enforce_for_request`] inert in EVERY mode (the #1985
/// unsatisfiable-default rule), so a blip on the data tier would quietly
/// downgrade an `enforce` deployment to self-asserted identity. Staleness is a
/// bounded, observable degrade; disarming is a silent one. Degrade, never
/// corrupt.
///
/// **A read overtaken by a mutation is DISCARDED (#4066).** `ticket` must have
/// been taken before the read began; if a revoke or bind was published since,
/// the rows may predate it and installing them could re-arm a revoked key.
pub fn apply_agent_key_refresh<E: std::fmt::Display>(
    registry: &EnrolledAgentKeys,
    ticket: LoadTicket,
    loaded: Result<Vec<(String, String)>, E>,
) -> AgentKeyRefresh {
    match loaded {
        Ok(rows) => {
            let map: std::collections::HashMap<String, String> = rows.into_iter().collect();
            let count = map.len();
            match registry.install_loaded(ticket, map) {
                LoadInstall::Installed => {
                    tracing::info!(
                        target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                        "#3418: per-agent api-key registry refreshed — {count} enrolled \
                         (generation {})",
                        registry.generation()
                    );
                    AgentKeyRefresh::Installed(count)
                }
                LoadInstall::Unchanged => AgentKeyRefresh::Unchanged(count),
                LoadInstall::Superseded => {
                    let kept = registry.len();
                    tracing::debug!(
                        target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                        "#4066: per-agent api-key refresh discarded — a revoke/bind was \
                         published after this read began; keeping the newer map \
                         ({kept} keys)"
                    );
                    AgentKeyRefresh::Superseded(kept)
                }
            }
        }
        Err(e) => {
            let kept = registry.len();
            tracing::warn!(
                target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                "#3418: per-agent api-key refresh failed ({e}); KEEPING the last known \
                 enrolled set ({kept} keys) rather than disarming the identity gate"
            );
            AgentKeyRefresh::KeptLastKnown(kept)
        }
    }
}

/// Run ONE ordered registry refresh: take the [`LoadTicket`], THEN start the
/// store read, then publish through [`apply_agent_key_refresh`] (#4066).
///
/// `load` is a closure returning the read future rather than the future
/// itself, so the read cannot have begun before the ticket exists — the
/// ordering the staleness check depends on is structural, not a convention.
/// Every refresh path (the background loop on both backends and the admin
/// handlers) goes through here.
pub async fn refresh_agent_keys<E, F, Fut>(registry: &EnrolledAgentKeys, load: F) -> AgentKeyRefresh
where
    E: std::fmt::Display,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<(String, String)>, E>>,
{
    let ticket = registry.begin_load();
    let loaded = load().await;
    apply_agent_key_refresh(registry, ticket, loaded)
}

impl Default for EnrolledAgentKeys {
    fn default() -> Self {
        Self::empty()
    }
}

/// #2044 — re-derive the caller's [`AuthLevel`] SELF-CONTAINEDLY from the
/// presented `X-API-Key` header and the boot-seeded enrolled per-agent-key map.
///
/// Returns [`AuthLevel::KeyAuthenticated`] iff the presented api-key is an
/// enrolled per-agent key whose bound `agent_id` EQUALS `caller` (the header the
/// [`crate::handlers::api_key_auth`] middleware already bound to the key-derived
/// principal). Otherwise [`AuthLevel::Claimed`] — a shared-transport-key or
/// keyless caller whose `X-Agent-Id` is self-asserted. This is the level the
/// IDOR/admin gates consume; deriving it here (rather than trusting a header or
/// a caller-controlled field) keeps the principal keyed to a server-held secret.
#[must_use]
pub fn resolve_auth_level(
    enrolled: &EnrolledAgentKeys,
    headers: &axum::http::HeaderMap,
    caller: &str,
) -> AuthLevel {
    // #3418 — ONE snapshot for this decision. Taking it once (rather than
    // consulting the registry twice) means a concurrent refresh cannot make
    // the emptiness check and the lookup disagree.
    let enrolled = enrolled.snapshot();
    if enrolled.is_empty() {
        return AuthLevel::Claimed;
    }
    let token = headers
        .get(crate::HEADER_API_KEY)
        .and_then(|v| v.to_str().ok());
    let Some(token) = token else {
        return AuthLevel::Claimed;
    };
    let hash = api_key_sha256_hex(token);
    match enrolled.get(&hash) {
        Some(agent_id) if agent_id == caller => AuthLevel::KeyAuthenticated,
        _ => AuthLevel::Claimed,
    }
}

/// #2044 — convenience wrapper: re-derive the caller's [`AuthLevel`] from the
/// request + enrolled map ([`resolve_auth_level`]) and apply the posture gate
/// ([`enforce_sensitive_identity`]) in one call. Returns `Some(403)` to refuse.
/// This is the single line every IDOR-sensitive read/mutate handler and
/// [`crate::handlers::admin_role::require_admin`] invokes.
///
/// **Fully inert when no per-agent keys are enrolled** (in EVERY mode): the
/// feature is off until an operator opts in by enrolling keys. This is what
/// keeps `advisory` (the v1.0.0 default) zero-WARN for a single-operator
/// deployment AND stops `enforce` from bricking every named caller when nobody
/// could possibly be key-attested (the #1985 unsatisfiable-default trap).
/// Enforcement (advisory WARN / enforce 403) only engages once at least one
/// per-agent key exists.
#[must_use]
pub fn enforce_for_request(
    enrolled: &EnrolledAgentKeys,
    mode: HttpIdentityMode,
    headers: &axum::http::HeaderMap,
    caller: &str,
    endpoint: &str,
) -> Option<Response> {
    if enrolled.is_empty() {
        return None;
    }
    let level = resolve_auth_level(enrolled, headers, caller);
    enforce_sensitive_identity(mode, level, caller, endpoint)
}

/// #3155 (v1.0.0, security) — boot-time verdict on whether an `enforce`
/// identity gate is actually ARMED.
///
/// [`enforce_for_request`] returns `None` on an EMPTY enrolled map in every
/// mode, and that is deliberate (the #1985 unsatisfiable-default trap: an
/// `enforce` posture that bricked every named caller when nobody COULD be
/// key-attested would be worse than useless). The defect #3155 closes is that
/// an operator who DELIBERATELY selected `enforce` got no signal whatsoever
/// that the control was disarmed — no boot WARN, no readiness flag — so a
/// deployment could believe it was refusing spoofed `X-Agent-Id` headers while
/// serving every one of them `200`.
///
/// Returns `Some(reason)` only for the one silently-disarmed combination
/// (`enforce` + zero enrolled per-agent keys). The caller decides severity by
/// posture: WARN under the default (this changes NO request-path behaviour and
/// must not silently tighten a documented contract), REFUSE under `asi-hard`,
/// whose contract is that no security control may be disabled. Pure, so the
/// wiring and its tests share one decision.
#[must_use]
pub fn inert_enforce_boot_reason(mode: HttpIdentityMode, enrolled_count: usize) -> Option<String> {
    if mode != HttpIdentityMode::Enforce || enrolled_count > 0 {
        return None;
    }
    Some(format!(
        "{}=enforce is set but ZERO per-agent api-keys are enrolled, so the identity gate \
         is INERT: every IDOR-sensitive read/mutate and every admin request is served on a \
         self-asserted X-Agent-Id header exactly as it would be with the gate off. \
         Enforcement engages only once at least one per-agent key exists (#1985 — an \
         enforce posture that refused every caller when nobody could be key-attested would \
         brick the deployment). Enrol keys with `ai-memory agents bind-api-key <agent-id>`, \
         or set {}=advisory to match the posture you actually have (#3155).",
        crate::config::ENV_HTTP_ATTESTED_IDENTITY,
        crate::config::ENV_HTTP_ATTESTED_IDENTITY,
    ))
}

/// #2044 (v1.0.0, #2032-A / H1 IDOR) — the one-line IDOR gate for the
/// object-level read/mutate handlers (`GET/PUT/DELETE/promote /memories/{id}`).
/// Resolves the caller from the (middleware-bound) `X-Agent-Id` header and
/// applies [`enforce_for_request`]. Under `enforce`, a `Claimed` (shared-key)
/// caller acting as a NAMED principal is refused BEFORE the ownership /
/// visibility check — closing the cross-tenant IDOR where a shared-key holder
/// sets `X-Agent-Id: <victim>` to read/edit the victim's `scope=private` rows.
#[must_use]
pub fn enforce_idor_identity(
    enrolled: &EnrolledAgentKeys,
    mode: HttpIdentityMode,
    headers: &axum::http::HeaderMap,
    endpoint: &str,
) -> Option<Response> {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());
    enforce_for_request(enrolled, mode, headers, &caller, endpoint)
}

/// #2044 — the shared IDOR/admin identity gate.
///
/// Consumed at the top of every IDOR-sensitive read/mutate handler and by
/// [`crate::handlers::admin_role::require_admin`]. Given the resolved posture,
/// the caller's re-derived [`AuthLevel`] (see [`resolve_auth_level`]), and the
/// `caller` id the handler is about to act as, returns:
///
///   * `None` — proceed (identity is acceptable for this posture);
///   * `Some(403)` — refuse (`enforce` posture, the caller is only `Claimed`
///     for an identity that is not the trivially-safe anonymous request id).
///
/// Under `advisory` (the v1.0.0 default) a `Claimed` sensitive caller is
/// ALLOWED but WARNed — inert + silent for a single-operator deployment because
/// `resolve_auth_level` returns `Claimed` and the anonymous/`==caller`
/// short-circuits fire. Under `off` the gate is a no-op.
#[must_use]
pub fn enforce_sensitive_identity(
    mode: HttpIdentityMode,
    level: AuthLevel,
    caller: &str,
    endpoint: &str,
) -> Option<Response> {
    if mode == HttpIdentityMode::Off {
        return None;
    }
    // A key-bound caller (a per-agent key whose bound agent_id == the header the
    // middleware already bound) is always acceptable — it proved possession of
    // this principal's server-held secret.
    if level.is_key_bound() {
        return None;
    }
    // An anonymous caller is not an assertion of another agent's identity — it
    // only ever sees non-private rows and owns nothing durable, so it is never an
    // IDOR/admin lever. Carve out EVERY HTTP anonymous form so the gate is
    // consistent regardless of which resolver produced the caller string
    // (`enforce_idor_identity` → `anonymous:req-…` on absent/invalid header;
    // `http_caller_ctx` → `anonymous:invalid` on a resolve error) — #2095 MINOR
    // sentinel-divergence alignment. Mirrors the create-path anonymous carve-out.
    if caller.starts_with(crate::identity::sentinels::ANONYMOUS_REQ_PREFIX)
        || caller == crate::identity::sentinels::ANONYMOUS_INVALID
    {
        return None;
    }
    match mode {
        HttpIdentityMode::Off => None,
        HttpIdentityMode::Advisory => {
            tracing::warn!(
                target: crate::handlers::AUTHZ_TRACE_TARGET,
                endpoint,
                caller,
                "#2044 advisory: request acts as named principal {caller:?} on \
                 {endpoint} without a per-agent-key attestation (X-Agent-Id is \
                 self-asserted). Enroll a per-agent api-key + set \
                 AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce to refuse this."
            );
            None
        }
        HttpIdentityMode::Enforce => {
            tracing::warn!(
                target: crate::handlers::AUTHZ_TRACE_TARGET,
                endpoint,
                caller,
                "#2044 enforce: refused unattested named principal {caller:?} on {endpoint}"
            );
            Some(
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "attested_identity_required",
                        "message": "X-Agent-Id is self-asserted; present the agent's \
                                    enrolled per-agent api-key (X-API-Key) to act as \
                                    this principal",
                        "endpoint": endpoint,
                    })),
                )
                    .into_response(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_stable_and_hex() {
        let h = api_key_sha256_hex("hunter2");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls.
        assert_eq!(h, api_key_sha256_hex("hunter2"));
        assert_ne!(h, api_key_sha256_hex("hunter3"));
    }

    #[test]
    fn auth_level_ordering_and_key_bound() {
        assert!(AuthLevel::Claimed < AuthLevel::KeyAuthenticated);
        assert!(AuthLevel::KeyAuthenticated < AuthLevel::SignatureAttested);
        assert!(!AuthLevel::Claimed.is_key_bound());
        assert!(AuthLevel::KeyAuthenticated.is_key_bound());
        assert!(AuthLevel::SignatureAttested.is_key_bound());
    }

    #[test]
    fn off_mode_is_noop() {
        assert!(
            enforce_sensitive_identity(HttpIdentityMode::Off, AuthLevel::Claimed, "alice", "ep")
                .is_none()
        );
    }

    #[test]
    fn advisory_allows_claimed_named_principal() {
        // H1/M1 advisory posture: WARN but allow (default; inert for single-op).
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Advisory,
                AuthLevel::Claimed,
                "alice",
                "ep"
            )
            .is_none()
        );
    }

    #[test]
    fn enforce_refuses_claimed_named_principal() {
        // M1 regression: an unattested named principal is refused under enforce.
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Enforce,
                AuthLevel::Claimed,
                "alice",
                "ep"
            )
            .is_some()
        );
    }

    #[test]
    fn enforce_allows_key_bound_caller() {
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Enforce,
                AuthLevel::KeyAuthenticated,
                "alice",
                "ep"
            )
            .is_none()
        );
    }

    #[test]
    fn enforce_allows_anonymous_request_id() {
        let anon = format!(
            "{}deadbeef",
            crate::identity::sentinels::ANONYMOUS_REQ_PREFIX
        );
        assert!(
            enforce_sensitive_identity(HttpIdentityMode::Enforce, AuthLevel::Claimed, &anon, "ep")
                .is_none()
        );
    }

    #[test]
    fn resolve_auth_level_empty_map_is_claimed() {
        // #3418 — the registry, not a bare map; empty is still the inert posture.
        let map = EnrolledAgentKeys::empty();
        let headers = axum::http::HeaderMap::new();
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::Claimed
        );
    }

    #[test]
    fn resolve_auth_level_matches_enrolled_key() {
        let mut seed = std::collections::HashMap::new();
        seed.insert(api_key_sha256_hex("alice-token"), "alice".to_string());
        let map = EnrolledAgentKeys::from_map(seed);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            crate::HEADER_API_KEY,
            axum::http::HeaderValue::from_static("alice-token"),
        );
        // Key bound to alice, acting as alice → KeyAuthenticated.
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::KeyAuthenticated
        );
        // Same key, acting as bob → Claimed (cannot borrow alice's attestation).
        assert_eq!(
            resolve_auth_level(&map, &headers, "bob"),
            AuthLevel::Claimed
        );
    }

    #[test]
    fn resolve_auth_level_shared_key_is_claimed() {
        let mut seed = std::collections::HashMap::new();
        seed.insert(api_key_sha256_hex("alice-token"), "alice".to_string());
        let map = EnrolledAgentKeys::from_map(seed);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            crate::HEADER_API_KEY,
            axum::http::HeaderValue::from_static("shared-global-key"),
        );
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::Claimed
        );
    }
}
