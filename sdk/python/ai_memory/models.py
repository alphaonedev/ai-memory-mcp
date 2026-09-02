# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pydantic models mirroring Rust structs in ``src/models.rs``.

Design notes
------------
* Every model uses ``model_config = ConfigDict(populate_by_name=True,
  extra="allow")`` so:
  * Callers can pass snake_case keys (the wire form) or Pythonic field names.
  * Forward-compatible fields added server-side (e.g. Task 1.10+ payloads)
    don't break deserialization — we keep them on the object verbatim.
* ``metadata`` is typed as ``dict[str, Any]`` because the Rust side is
  ``serde_json::Value`` — servers stamp arbitrary keys (``agent_id``,
  ``scope``, ``governance``, ``imported_from_agent_id``, …) into it.
* Timestamps are RFC3339 strings on the wire; we keep them as ``str`` to
  avoid clobbering fractional seconds / timezone offsets produced by Rust's
  ``chrono``. Callers that want ``datetime`` can call
  ``datetime.fromisoformat(...)`` after Python 3.11 (3.10 needs
  ``dateutil`` for ``Z`` offsets).
* ``Optional[T]`` is used for every field the Rust struct declares as
  ``Option<T>``; all other fields are required. ``CreateMemory`` mirrors
  the server-side defaults so SDK callers can omit tier/namespace/etc.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    """Shared config: populate by alias or field name, keep unknown keys."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class Tier(str, Enum):
    """Memory tier — mirrors ``enum Tier`` in ``src/models.rs``."""

    SHORT = "short"
    MID = "mid"
    LONG = "long"


class GovernanceLevel(str, Enum):
    """``enum GovernanceLevel`` — who may perform a governed action."""

    ANY = "any"
    REGISTERED = "registered"
    OWNER = "owner"
    APPROVE = "approve"


class ApproverType(_Base):
    """``enum ApproverType`` — serialized externally tagged.

    The Rust enum serializes three shapes:

    * ``"human"`` — bare string
    * ``{"agent": "<id>"}`` — single-key object
    * ``{"consensus": <n>}`` — single-key object

    We model it as a struct with two optional fields + a ``kind`` tag so
    callers can introspect. Use :meth:`to_wire` to emit the externally
    tagged JSON form.
    """

    kind: str = Field(description="human | agent | consensus")
    agent_id: str | None = None
    consensus: int | None = None

    @classmethod
    def human(cls) -> ApproverType:
        return cls(kind="human")

    @classmethod
    def agent(cls, agent_id: str) -> ApproverType:
        return cls(kind="agent", agent_id=agent_id)

    @classmethod
    def consensus_of(cls, n: int) -> ApproverType:
        return cls(kind="consensus", consensus=n)

    def to_wire(self) -> Any:
        if self.kind == "human":
            return "human"
        if self.kind == "agent":
            return {"agent": self.agent_id}
        if self.kind == "consensus":
            return {"consensus": self.consensus}
        raise ValueError(f"unknown ApproverType kind: {self.kind!r}")


class GovernancePolicy(_Base):
    """``struct GovernancePolicy`` — per-namespace action gating."""

    write: GovernanceLevel = GovernanceLevel.ANY
    promote: GovernanceLevel = GovernanceLevel.ANY
    delete: GovernanceLevel = GovernanceLevel.OWNER
    approver: ApproverType = Field(default_factory=ApproverType.human)
    # #1720 C — per-namespace required write scope (refuse-only). When set,
    # a Store whose effective ``metadata.scope`` (absent ⇒ ``"private"``)
    # does not equal this is refused at the governance gate. One of
    # ``"private" | "team" | "unit" | "org" | "collective"``; ``None`` ⇒
    # no scope requirement. Rides in ``metadata.governance``.
    required_scope: str | None = None


class Memory(_Base):
    """A Memory row. Mirrors ``ai_memory::models::Memory``, which carries

    **30 fields** at v1.0.0 (``Memory::FIELD_COUNT``, SSOT
    ``src/models/memory.rs``) — and all 30 are now typed here (#2834). The
    first 15 are the v0.6.x core; the 15 declared after ``metadata`` are the
    v0.7.0+ additions (``reflection_depth``, ``memory_kind``, ``entity_id``,
    ``persona_version``, ``citations``, ``source_uri``, ``source_span``,
    ``confidence_source``, ``confidence_signals``, ``confidence_decayed_at``,
    ``version``, ``lifecycle_state``, ``cid``, ``valid_from``,
    ``valid_until``).

    This is a **typing-completeness** change, not a data-loss fix: those 15
    already survived a round trip because ``_Base`` sets ``extra="allow"``, so
    an unknown key was kept on the object verbatim — it was untyped, never
    lost. Declaring them gives callers typed, attribute-style access for the
    full row. (``kind_provenance`` is a schema-v79 DB column but is NOT a field
    on the Rust ``struct Memory``, so it is deliberately not declared here.)

    Every added field is ``Optional[T] = None`` so a response from an OLDER
    daemon that omits it still parses. ``metadata`` is a free-form ``dict``
    since the server stores ``serde_json::Value``.
    """

    id: str
    tier: Tier
    namespace: str
    title: str
    content: str
    tags: list[str] = Field(default_factory=list)
    priority: int = 5
    confidence: float = 1.0
    source: str = "api"
    access_count: int = 0
    created_at: str
    updated_at: str
    last_accessed_at: str | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # v0.7.0+ typed columns (#2834 typing completeness). All optional-with-
    # default so an older daemon's response that omits any of them still
    # parses. Wire keys match the Rust serde field names verbatim (snake_case).
    reflection_depth: int | None = None
    # ``memory_kind`` / ``confidence_source`` / ``lifecycle_state`` are
    # snake_case enum strings on the wire (e.g. "observation",
    # "caller_provided", "open"); kept as ``str`` so a future variant the SDK
    # predates still parses.
    memory_kind: str | None = None
    entity_id: str | None = None
    persona_version: int | None = None
    # ``citations`` is a JSON array of Citation envelopes
    # ({uri, accessed_at, hash?, span?}); ``source_span`` is a JSON
    # {start, end} object; ``confidence_signals`` is a JSON object.
    citations: list[Any] | None = None
    source_uri: str | None = None
    source_span: dict[str, Any] | None = None
    confidence_source: str | None = None
    confidence_signals: dict[str, Any] | None = None
    confidence_decayed_at: str | None = None
    version: int | None = None
    lifecycle_state: str | None = None
    cid: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None


class MemoryLink(_Base):
    """``struct MemoryLink`` — typed directional relationship."""

    source_id: str
    target_id: str
    relation: str = "related_to"
    created_at: str


class CreateMemory(_Base):
    """Request body for ``POST /api/v1/memories``.

    Mirrors ``struct CreateMemory`` including server-side defaults. The
    server will stamp ``metadata.agent_id`` from the body, the
    ``X-Agent-Id`` header, or a per-request anonymous id — callers only
    need to set it when they want a specific NHI claim.

    #2455 — ``signature`` / ``created_at`` / ``kind`` were MISSING here,
    which made a successful store impossible against a stock daemon:
    ``POST /api/v1/memories`` is ``WriteSurface::HttpDirect`` and fails
    CLOSED by default, so an unsigned write is ``403 ATTESTATION_FAILED``.
    Use :func:`ai_memory.attestation.attestation_fields` (or pass
    ``signing_key=`` to :meth:`AiMemoryClient.store`) to populate them.
    """

    title: str
    content: str
    tier: Tier = Tier.MID
    namespace: str = "global"
    tags: list[str] = Field(default_factory=list)
    priority: int = 5
    confidence: float = 1.0
    source: str = "api"
    expires_at: str | None = None
    ttl_secs: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    scope: str | None = None
    # #1385 — Batman-taxonomy memory-kind selector. Absent/unknown values are
    # treated as omission by the server, which then stores ``observation``.
    # It is INSIDE the signed envelope, so a signed write must send the same
    # kind it signed.
    kind: str | None = None
    # #626 Layer-3 — detached Ed25519 attestation over the ``SignableWrite``
    # envelope, STANDARD base64. When set, ``created_at`` is REQUIRED (the
    # signer cannot predict the server clock).
    signature: str | None = None
    # RFC3339 timestamp the caller signed. Validated against the server's
    # +/-300s attestation freshness window, then adopted verbatim.
    created_at: str | None = None


class UpdateMemory(_Base):
    """Request body for ``PUT /api/v1/memories/{id}`` — all fields optional.

    **Optimistic concurrency is a HEADER, not a body field.** The server
    reads the expected row version from ``If-Match`` (bare integer or a
    quoted ETag-style value) — see ``src/handlers/memories.rs:245-260``;
    ``struct UpdateMemory`` in ``src/models/memory.rs:1602`` has no
    ``version`` field at all. A ``version`` key placed in this body would be
    silently swallowed by ``extra="allow"`` and ignored by the server,
    giving the caller a false sense of lost-update protection while the
    write remained last-write-wins. Pass ``expected_version=`` to
    :meth:`AiMemoryClient.update` instead; a stale version yields ``409``.
    """

    title: str | None = None
    content: str | None = None
    tier: Tier | None = None
    namespace: str | None = None
    tags: list[str] | None = None
    priority: int | None = None
    confidence: float | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] | None = None


class RecallRequest(_Base):
    """Body of ``POST /api/v1/recall`` (and query params of the GET form)."""

    context: str
    namespace: str | None = None
    limit: int | None = 10
    tags: str | None = None
    since: str | None = None
    until: str | None = None
    as_agent: str | None = None
    budget_tokens: int | None = None


class RecallResponse(_Base):
    """Typed wrapper around the recall response payload.

    The server currently returns ``{"count": N, "memories": [Memory, ...]}``.
    We keep both fields optional on the wrapper so a future version can add
    rerank scores / explanations without breaking deserialization.
    """

    count: int = 0
    memories: list[Memory] = Field(default_factory=list)


class AgentRegistration(_Base):
    """``struct AgentRegistration`` — one row from ``GET /api/v1/agents``."""

    agent_id: str
    agent_type: str
    capabilities: list[str] = Field(default_factory=list)
    registered_at: str
    last_seen_at: str


class PendingAction(_Base):
    """``struct PendingAction`` — governance-queued action."""

    id: str
    action_type: str
    memory_id: str | None = None
    namespace: str
    payload: dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    requested_at: str
    status: str
    decided_by: str | None = None
    decided_at: str | None = None
    approvals: list[dict[str, Any]] = Field(default_factory=list)


class Stats(_Base):
    """``struct Stats`` — output of ``GET /api/v1/stats``."""

    total_memories: int
    by_tier: list[dict[str, Any]] = Field(default_factory=list)
    by_namespace: list[dict[str, Any]] = Field(default_factory=list)
    expiring_soon: int = 0
    links_count: int = 0
    db_size_bytes: int = 0
    live: int = 0
    expired_pending_gc: int = 0
    storage_backend: str | None = None


# ---------------------------------------------------------------------------
# Subscriptions / webhooks / inbox / cluster
#
# These endpoints may not be merged on every server — the models are kept
# loose (extra=allow) so the SDK can target in-flight server branches
# without breaking when fields shift. Requests use snake_case to match the
# existing Rust serde conventions.
# ---------------------------------------------------------------------------


class SubscriptionRequest(_Base):
    """Body for ``POST /api/v1/subscriptions``.

    Subscribers receive webhook deliveries signed with ``secret`` via
    HMAC-SHA256 (see :mod:`ai_memory.webhooks`).
    """

    url: str
    events: list[str] = Field(default_factory=list)
    namespace: str | None = None
    secret: str | None = None
    filter: dict[str, Any] | None = None


class Subscription(_Base):
    """``GET /api/v1/subscriptions`` row."""

    id: str
    url: str
    events: list[str] = Field(default_factory=list)
    namespace: str | None = None
    created_at: str | None = None


class NotifyRequest(_Base):
    """Body for ``POST /api/v1/notify`` — agent-to-agent message."""

    target_agent_id: str
    title: str
    #: Message body. The daemon's ``NotifyBody`` takes ``payload`` OR ``content``
    #: (both ``Option<String>``); exactly one is required. Strings only — a
    #: structured object is rejected (422) by the daemon.
    payload: str | None = None
    content: str | None = None
    priority: int | None = None
    tier: str | None = None
    agent_id: str | None = None
    why_trace: str | None = None


class InboxMessage(_Base):
    """Row from ``GET /api/v1/inbox``."""

    id: str
    from_: str = Field(alias="from")
    to: str
    subject: str
    body: str
    received_at: str
    read: bool = False


class BulkCreateResponse(_Base):
    """Response envelope for ``POST /api/v1/memories/bulk``.

    ``created + updated + deduped + rejected + len(pending) == sent`` is the
    reconciliation identity a bulk loader should assert on every batch
    (ai-memory#2551).

    ``created`` counts rows the call INSERTED and ``updated`` counts rows it
    upserted onto an existing ``(title, namespace)``; both are persisted.
    ``deduped`` counts rows whose content was superseded by a LATER row in the
    SAME batch — that row is NOT what you sent, and ``deduped_rows`` carries
    the affected input indices.

    ``warnings`` reports post-commit REPLICATION problems only: those rows are
    durable locally, which is why they are not in ``errors``.

    The daemon-declared ``ids`` field was removed: the handler has never
    emitted it, so it was permanently empty and misdescribed the wire.
    """

    sent: int = 0
    created: int = 0
    updated: int = 0
    deduped: int = 0
    rejected: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)
    deduped_rows: list[dict[str, Any]] = Field(default_factory=list)
    pending: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
