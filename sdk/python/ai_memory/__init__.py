# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ai-memory — Python SDK for the ai-memory HTTP API.

The SDK exposes a synchronous :class:`AiMemoryClient` and an asynchronous
:class:`AsyncAiMemoryClient` over the daemon's ``/api/v1/`` REST surface
(port 9077 by default). Models mirror the Rust structs in ``src/models.rs``
and use Pydantic v2 with ``populate_by_name=True`` so callers may construct
objects using either snake_case aliases (wire form) or Pythonic names.

Example
-------
>>> from ai_memory import AiMemoryClient, Tier
>>> from ai_memory.attestation import AgentSigningKey
>>> key = AgentSigningKey.generate()  # doctest: +SKIP
>>> with AiMemoryClient(base_url="http://localhost:9077") as c:  # doctest: +SKIP
...     c.bind_agent_pubkey("svc", key.public_key_b64())  # once, admin-gated
...     created = c.store(
...         title="hello", content="world", tier=Tier.MID,
...         agent_id="svc", signing_key=key,
...     )
...     hits = c.recall(context="hello")

Signing is not optional decoration: ``POST /api/v1/memories`` is
``WriteSurface::HttpDirect`` and fails CLOSED by default, so an unsigned
store returns ``403 ATTESTATION_FAILED`` unless the operator has set
``AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0``. See :mod:`ai_memory.attestation`.
"""

from ai_memory._common import SDK_VERSION
from ai_memory.async_client import AsyncAiMemoryClient
from ai_memory.client import AiMemoryClient
from ai_memory.errors import (
    AiMemoryError,
    AuthError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TransportError,
    ValidationError,
)
from ai_memory.models import (
    AgentRegistration,
    ApproverType,
    BulkCreateResponse,
    CreateMemory,
    GovernanceLevel,
    GovernancePolicy,
    InboxMessage,
    Memory,
    MemoryLink,
    NotifyRequest,
    PendingAction,
    RecallRequest,
    RecallResponse,
    Stats,
    Subscription,
    SubscriptionRequest,
    Tier,
    UpdateMemory,
)
from ai_memory.profile import (
    ProfileNotLoaded,
    require_profile,
    require_profile_async,
    resolve_required_families,
)
from ai_memory.webhooks import sign_webhook_body, verify_webhook_signature

# #2455 — single-sourced from the installed package metadata (pyproject.toml
# `version`). Previously this was a hand-maintained literal that had drifted
# to "0.8.0" while pyproject said "1.0.0" and the User-Agent said
# "0.6.0-alpha.0" — three different answers to "what version is this?".
__version__ = SDK_VERSION

__all__ = [
    "AgentRegistration",
    "AiMemoryClient",
    "AiMemoryError",
    "ApproverType",
    "AsyncAiMemoryClient",
    "AuthError",
    "BulkCreateResponse",
    "ConflictError",
    "CreateMemory",
    "ForbiddenError",
    "GovernanceLevel",
    "GovernancePolicy",
    "InboxMessage",
    "Memory",
    "MemoryLink",
    "NotFoundError",
    "NotifyRequest",
    "PendingAction",
    "ProfileNotLoaded",
    "RateLimitError",
    "RecallRequest",
    "RecallResponse",
    "ServerError",
    "Stats",
    "Subscription",
    "SubscriptionRequest",
    "Tier",
    "TransportError",
    "UpdateMemory",
    "ValidationError",
    "__version__",
    "require_profile",
    "require_profile_async",
    "resolve_required_families",
    "sign_webhook_body",
    "verify_webhook_signature",
]
