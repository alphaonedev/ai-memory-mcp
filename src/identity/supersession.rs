// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U1/U1b: authority shared by the SQLite and PostgreSQL archive callers.
//!
//! A resolved caller string, `CallerContext`, `clientInfo`, priority or metadata
//! attestation label cannot construct a principal. Constructors read the actual
//! process/header channel or verify a signature against the persisted key binding.
//! The HTTP channel is trusted under the issue's explicit X-Agent-Id ruling;
//! transport authentication and header/body agreement remain the edge's job.
//!
//! This is a policy prerequisite, not a write funnel. Callers must read/recheck
//! both rows under their write transaction, handle every refusal with a Deny
//! audit, and keep the token inside that transaction. Attested-write replay
//! admission, record-stop and ordinary archive gates remain mandatory.

use anyhow::Result;
use axum::http::HeaderMap;
use chrono::DateTime;

use crate::models::{Memory, field_names};

/// Evidence channel retained for audit; never accepted as constructor input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalSource {
    /// Operator-configured `AI_MEMORY_AGENT_ID`, without identity fallbacks.
    ProcessEnvironment,
    /// The request's single, validated X-Agent-Id header.
    HttpHeader,
    /// A v1 signature verified against the store's current bound key.
    VerifiedV1,
    /// A v2 write verified through the live cert/revocation gate.
    VerifiedV2,
}

/// An unforgeable-by-wire principal (ERRORS-09). No `Deserialize` or raw-id ctor.
#[derive(Debug)]
pub struct SupersessionPrincipal {
    agent_id: String,
    source: PrincipalSource,
    verified_write: Option<VerifiedWrite>,
}

/// Bind signer evidence to the verified write, not just to an agent string.
/// Own the small identity fields and hash content instead of cloning a `Memory`.
#[derive(Debug)]
struct VerifiedWrite {
    id: String,
    namespace: String,
    title: String,
    kind: String,
    created_at: String,
    content_hash: [u8; 32],
}

impl VerifiedWrite {
    fn new(memory: &Memory) -> Self {
        Self {
            id: memory.id.clone(),
            namespace: memory.namespace.clone(),
            title: memory.title.clone(),
            kind: memory.memory_kind.as_str().to_owned(),
            created_at: memory.created_at.clone(),
            content_hash: super::attest::content_sha256(&memory.content),
        }
    }

    fn matches(&self, memory: &Memory) -> bool {
        self.id == memory.id
            && self.namespace == memory.namespace
            && self.title == memory.title
            && self.kind == memory.memory_kind.as_str()
            && DateTime::parse_from_rfc3339(&self.created_at)
                .ok()
                .zip(DateTime::parse_from_rfc3339(&memory.created_at).ok())
                .is_some_and(|(verified, stored)| verified == stored)
            && self.content_hash == super::attest::content_sha256(&memory.content)
    }
}

fn validate_principal(agent_id: &str) -> Result<()> {
    crate::validate::validate_agent_id_shape(agent_id)?;
    anyhow::ensure!(
        !agent_id.is_empty()
            && agent_id != super::sentinels::ANONYMOUS_INVALID
            && !agent_id.starts_with(super::sentinels::ANONYMOUS_REQ_PREFIX),
        "supersession requires a non-anonymous principal"
    );
    Ok(())
}

impl SupersessionPrincipal {
    /// Read only the operator-configured identity; absence is not authentication.
    ///
    /// # Errors
    /// A present malformed identity fails closed, as on MCP visibility reads.
    pub fn from_process_environment() -> Result<Option<Self>> {
        super::resolve_mcp_read_visibility_caller()?
            .map(|agent_id| {
                validate_principal(&agent_id)?;
                Ok(Self {
                    agent_id,
                    source: PrincipalSource::ProcessEnvironment,
                    verified_write: None,
                })
            })
            .transpose()
    }

    /// Extract the header channel only; never fall back to body/metadata ids.
    ///
    /// # Errors
    /// Duplicate, non-text, anonymous or malformed headers are refused.
    pub fn from_http_headers(headers: &HeaderMap) -> Result<Option<Self>> {
        let mut values = headers.get_all("x-agent-id").iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        anyhow::ensure!(values.next().is_none(), "ambiguous X-Agent-Id headers");
        let agent_id = value.to_str()?;
        validate_principal(agent_id)?;
        Ok(Some(Self {
            agent_id: agent_id.to_owned(),
            source: PrincipalSource::HttpHeader,
            verified_write: None,
        }))
    }

    /// Verify v1 against the SQLite binding, never a caller-supplied public key.
    ///
    /// # Errors
    /// Propagates key lookup, identity validation and signature verification errors.
    pub fn verify_v1_sync(
        conn: &rusqlite::Connection,
        memory: &Memory,
        agent_id: &str,
        signature: &[u8],
    ) -> Result<Self> {
        validate_principal(agent_id)?;
        let bound = crate::db::agent_pubkey(conn, agent_id)?;
        Self::verify_v1_bound(memory, agent_id, bound.as_deref(), signature)
    }

    /// SAL twin: the same verifier and evidence binding with an async key lookup.
    ///
    /// # Errors
    /// Propagates store, identity validation and signature verification errors.
    #[cfg(feature = "sal")]
    pub async fn verify_v1_async(
        store: &dyn crate::store::MemoryStore,
        memory: &Memory,
        agent_id: &str,
        signature: &[u8],
    ) -> Result<Self> {
        validate_principal(agent_id)?;
        let bound = store.agent_pubkey(agent_id).await?;
        Self::verify_v1_bound(memory, agent_id, bound.as_deref(), signature)
    }

    fn verify_v1_bound(
        memory: &Memory,
        agent_id: &str,
        bound: Option<&str>,
        signature: &[u8],
    ) -> Result<Self> {
        let level = super::attest::resolve_write_attest_level(
            memory,
            agent_id,
            bound,
            Some(signature),
            true,
        )?;
        anyhow::ensure!(
            level == super::verify::AttestLevel::AgentAttested,
            "supersession requires verified agent attestation"
        );
        Ok(Self::verified(
            memory,
            agent_id,
            PrincipalSource::VerifiedV1,
        ))
    }

    /// Reuse the complete live v2 gate, including revocation and signed time.
    ///
    /// # Errors
    /// Propagates identity, key lookup, freshness, cert, signature and revocation errors.
    pub fn verify_v2_sync(
        conn: &rusqlite::Connection,
        memory: &mut Memory,
        agent_id: &str,
        presented: &super::attest_v2::PresentedWriteV2,
    ) -> Result<Self> {
        validate_principal(agent_id)?;
        super::attest_v2::stamp_v2_sync(conn, memory, agent_id, presented)?;
        anyhow::ensure!(
            matches!(
                super::attest::admit_attested_write_sync(
                    conn,
                    agent_id,
                    &memory.created_at,
                    presented.write_signature()
                )
                .map_err(anyhow::Error::msg)?,
                super::attest::AttestedWriteAdmission::Fresh
            ),
            super::attest::ATTESTED_WRITE_REPLAY_REFUSAL
        );
        Ok(Self::verified(
            memory,
            agent_id,
            PrincipalSource::VerifiedV2,
        ))
    }

    /// Verify v2 on the live SAL backend and admit its signature exactly once.
    ///
    /// # Errors
    /// Verification, revocation, replay and backend errors fail closed.
    #[cfg(feature = "sal")]
    pub async fn verify_v2_async(
        store: &dyn crate::store::MemoryStore,
        memory: &mut Memory,
        agent_id: &str,
        presented: &super::attest_v2::PresentedWriteV2,
    ) -> Result<Self> {
        validate_principal(agent_id)?;
        super::attest_v2::stamp_v2_async(store, memory, agent_id, presented).await?;
        anyhow::ensure!(
            matches!(
                super::attest::admit_attested_write_async(
                    store,
                    agent_id,
                    &memory.created_at,
                    presented.write_signature()
                )
                .await
                .map_err(anyhow::Error::msg)?,
                super::attest::AttestedWriteAdmission::Fresh
            ),
            super::attest::ATTESTED_WRITE_REPLAY_REFUSAL
        );
        Ok(Self::verified(
            memory,
            agent_id,
            PrincipalSource::VerifiedV2,
        ))
    }

    fn verified(memory: &Memory, agent_id: &str, source: PrincipalSource) -> Self {
        Self {
            agent_id: agent_id.to_owned(),
            source,
            verified_write: Some(VerifiedWrite::new(memory)),
        }
    }

    /// Authenticated actor, without a `CallerContext::as_agent` override.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Evidence provenance for the decision audit.
    #[must_use]
    pub fn source(&self) -> PrincipalSource {
        self.source
    }
}

/// Refusals carry no owner/id values, so they do not disclose a predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupersessionRefusal {
    /// No hardened evidence, even if metadata claims an owner or attestation.
    UnauthenticatedPrincipal,
    /// Explicit admin mode requires the operator allowlist.
    AdminNotAllowed,
    /// Empty/malformed legacy owner, including for admin attempts.
    UnownedPredecessor,
    /// A hardened non-admin principal does not own the predecessor.
    OwnerMismatch,
    /// Evidence was minted for another write or its signed fields changed.
    VerifiedWriteMismatch,
    /// Never archive an actual insert id that aliases the old row.
    SameId,
    /// Namespace equality is exact, never prefix matching.
    NamespaceMismatch,
    /// A timestamp is malformed or the new instant is not strictly later.
    NotStrictlyNewer,
    /// An archived row without a supersession pointer cannot be resolved again.
    ArchivedPredecessor,
}

impl std::fmt::Display for SupersessionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "supersession refused: {self:?}")
    }
}

impl std::error::Error for SupersessionRefusal {}

/// A checked pair; private fields and borrowed rows prevent unchecked creation
/// and mutation of the snapshots while the authorization is being consumed.
#[derive(Debug)]
pub struct AuthorizedSupersession<'a> {
    old: &'a Memory,
    new: &'a Memory,
    principal: &'a SupersessionPrincipal,
    as_admin: bool,
}

impl AuthorizedSupersession<'_> {
    /// The predecessor to archive through the production archive core.
    #[must_use]
    pub fn old(&self) -> &Memory {
        self.old
    }
    /// The independently stored replacement to stamp after archive succeeds.
    #[must_use]
    pub fn new_memory(&self) -> &Memory {
        self.new
    }
    /// The principal for the ordinary archive gate and decision audit.
    #[must_use]
    pub fn principal(&self) -> &SupersessionPrincipal {
        self.principal
    }
    /// True only after explicit admin mode passes the supplied operator allowlist.
    #[must_use]
    pub fn as_admin(&self) -> bool {
        self.as_admin
    }
}

/// A no-op cannot accidentally be treated as an authorized archive (ERRORS-09).
#[derive(Debug)]
pub enum SupersessionDecision<'a> {
    /// Both rows passed the common authority/time/namespace checks.
    Authorized(AuthorizedSupersession<'a>),
    /// The caller must retain the predecessor and audit a Deny.
    Refused(SupersessionRefusal),
    /// Authorized caller replayed a predecessor already carrying a pointer.
    AlreadySuperseded,
}

/// Check common store/resolve authority on transaction-pinned row snapshots.
/// Store callers additionally require [`same_ruling_key`] under the same lock.
/// The allowlist MUST be operator configuration, never request JSON.
#[must_use]
pub fn authorize_supersession<'a>(
    principal: Option<&'a SupersessionPrincipal>,
    as_admin: bool,
    admin_agent_ids: &[String],
    old: &'a Memory,
    new: &'a Memory,
) -> SupersessionDecision<'a> {
    use SupersessionDecision::{AlreadySuperseded, Authorized, Refused};
    use SupersessionRefusal as Refusal;
    let Some(principal) = principal else {
        return Refused(Refusal::UnauthenticatedPrincipal);
    };
    if as_admin && !super::is_admin_agent_in(principal.agent_id(), admin_agent_ids) {
        return Refused(Refusal::AdminNotAllowed);
    }
    let owner = old
        .metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str);
    let Some(owner) = owner.filter(|owner| validate_principal(owner).is_ok()) else {
        return Refused(Refusal::UnownedPredecessor);
    };
    if !as_admin && owner != principal.agent_id() {
        return Refused(Refusal::OwnerMismatch);
    }
    if principal
        .verified_write
        .as_ref()
        .is_some_and(|write| !write.matches(new))
    {
        return Refused(Refusal::VerifiedWriteMismatch);
    }
    if old.id == new.id {
        return Refused(Refusal::SameId);
    }
    if old.namespace != new.namespace {
        return Refused(Refusal::NamespaceMismatch);
    }
    if old.metadata.get(field_names::SUPERSEDED_BY).is_some() {
        return AlreadySuperseded;
    }
    let times = DateTime::parse_from_rfc3339(&old.created_at)
        .ok()
        .zip(DateTime::parse_from_rfc3339(&new.created_at).ok());
    if !times.is_some_and(|(old_time, new_time)| new_time > old_time) {
        return Refused(Refusal::NotStrictlyNewer);
    }
    Authorized(AuthorizedSupersession {
        old,
        new,
        principal,
        as_admin,
    })
}

/// An update cannot introduce, erase, change or mistype a ruling key.
/// Omission preserves the existing value; an identical explicit string is allowed.
///
/// # Errors
/// Returns a typed refusal before a provenance-preservation merge can hide it.
pub fn validate_ruling_key_update(
    existing: &serde_json::Value,
    incoming: &serde_json::Value,
) -> Result<()> {
    if let Some(value) = incoming.get(field_names::RULING_KEY) {
        anyhow::ensure!(
            value.as_str().is_some_and(|key| !key.is_empty())
                && existing.get(field_names::RULING_KEY) == Some(value),
            RulingKeyImmutable
        );
    }
    Ok(())
}

/// Wire-independent typed write-once refusal.
#[derive(Debug)]
pub struct RulingKeyImmutable;

impl std::fmt::Display for RulingKeyImmutable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ruling_key is immutable after creation")
    }
}

impl std::error::Error for RulingKeyImmutable {}

/// Exact keyed-store match. Missing, null, non-string and empty keys never match.
#[must_use]
pub fn same_ruling_key(old: &Memory, new: &Memory) -> bool {
    old.namespace == new.namespace
        && old
            .metadata
            .get(field_names::RULING_KEY)
            .and_then(serde_json::Value::as_str)
            .filter(|key| !key.is_empty())
            .zip(
                new.metadata
                    .get(field_names::RULING_KEY)
                    .and_then(serde_json::Value::as_str),
            )
            .is_some_and(|(old_key, new_key)| old_key == new_key)
}

#[cfg(test)]
mod tests;
