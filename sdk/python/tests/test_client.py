# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for :class:`AiMemoryClient`.

The suite is split in two:

* **Offline tests** (always run) — exercise the pure-Python parts: model
  serialization, webhook HMAC, error mapping.
* **Daemon tests** (opt-in) — run only when ``AI_MEMORY_TEST_DAEMON=1`` is
  set and a daemon is reachable at ``http://localhost:9077``. Every daemon
  test writes and deletes its own namespace to avoid polluting shared state.
"""

from __future__ import annotations

import json
import os
import uuid

import httpx
import pytest

from ai_memory import (
    AiMemoryClient,
    AiMemoryError,
    CreateMemory,
    NotFoundError,
    Tier,
    ValidationError,
)
from ai_memory.errors import raise_for_status
from ai_memory.models import Memory

TEST_BASE_URL = os.environ.get("AI_MEMORY_TEST_BASE_URL", "http://localhost:9077")
DAEMON_ENABLED = os.environ.get("AI_MEMORY_TEST_DAEMON") == "1"


def _daemon_reachable() -> bool:
    if not DAEMON_ENABLED:
        return False
    try:
        response = httpx.get(f"{TEST_BASE_URL}/api/v1/health", timeout=2.0)
    except httpx.HTTPError:
        return False
    return response.status_code == 200


skip_without_daemon = pytest.mark.skipif(
    not _daemon_reachable(),
    reason="AI_MEMORY_TEST_DAEMON!=1 or daemon not reachable at localhost:9077",
)


# ---------------------------------------------------------------------------
# Offline: model + error + webhook tests
# ---------------------------------------------------------------------------


def test_tier_enum_values() -> None:
    assert Tier.SHORT.value == "short"
    assert Tier.MID.value == "mid"
    assert Tier.LONG.value == "long"


def test_create_memory_defaults_match_server() -> None:
    body = CreateMemory(title="t", content="c")
    dumped = body.model_dump(by_alias=True)
    assert dumped["tier"] == "mid"
    assert dumped["namespace"] == "global"
    assert dumped["priority"] == 5
    assert dumped["confidence"] == 1.0
    assert dumped["source"] == "api"


def test_memory_round_trips_metadata() -> None:
    payload = {
        "id": "abc",
        "tier": "long",
        "namespace": "global",
        "title": "t",
        "content": "c",
        "tags": ["x"],
        "priority": 7,
        "confidence": 0.8,
        "source": "api",
        "access_count": 3,
        "created_at": "2026-04-19T00:00:00Z",
        "updated_at": "2026-04-19T00:00:00Z",
        "metadata": {"agent_id": "alice", "scope": "team"},
    }
    m = Memory.model_validate(payload)
    assert m.metadata["agent_id"] == "alice"
    assert m.tier is Tier.LONG


def test_memory_back_compat_without_v070_fields() -> None:
    """An OLDER daemon's response omits the v0.7.0+ columns entirely; the
    model must still parse and default the missing typed fields to ``None``."""
    payload = {
        "id": "abc",
        "tier": "mid",
        "namespace": "global",
        "title": "t",
        "content": "c",
        "created_at": "2026-04-19T00:00:00Z",
        "updated_at": "2026-04-19T00:00:00Z",
    }
    m = Memory.model_validate(payload)
    # #2834 — the added fields are optional-with-default so a legacy response
    # round-trips cleanly.
    assert m.version is None
    assert m.lifecycle_state is None
    assert m.memory_kind is None
    assert m.cid is None
    assert m.citations is None
    assert m.valid_from is None
    assert m.valid_until is None


def test_memory_types_all_30_fields() -> None:
    """#2834 — all 30 server-side ``Memory`` fields are typed and round-trip.

    Typing completeness only: the v0.7.0+ fields already survived via
    ``extra="allow"`` before they were declared; this asserts they now read
    back through the typed attributes."""
    payload = {
        "id": "abc",
        "tier": "long",
        "namespace": "global",
        "title": "t",
        "content": "c",
        "tags": ["x"],
        "priority": 7,
        "confidence": 0.8,
        "source": "api",
        "access_count": 3,
        "created_at": "2026-04-19T00:00:00Z",
        "updated_at": "2026-04-19T00:00:00Z",
        "last_accessed_at": "2026-04-19T01:00:00Z",
        "expires_at": "2026-04-26T00:00:00Z",
        "metadata": {"agent_id": "alice"},
        "reflection_depth": 2,
        "memory_kind": "reflection",
        "entity_id": "ent-1",
        "persona_version": 4,
        "citations": [{"uri": "doc:1", "accessed_at": "2026-04-19T00:00:00Z"}],
        "source_uri": "doc:1",
        "source_span": {"start": 0, "end": 10},
        "confidence_source": "auto_derived",
        "confidence_signals": {"source_age_days": 1.5},
        "confidence_decayed_at": "2026-04-20T00:00:00Z",
        "version": 3,
        "lifecycle_state": "open",
        "cid": "b3:deadbeef",
        "valid_from": "2026-04-01T00:00:00Z",
        "valid_until": "2026-05-01T00:00:00Z",
    }
    m = Memory.model_validate(payload)
    assert m.reflection_depth == 2
    assert m.memory_kind == "reflection"
    assert m.entity_id == "ent-1"
    assert m.persona_version == 4
    assert m.citations == [{"uri": "doc:1", "accessed_at": "2026-04-19T00:00:00Z"}]
    assert m.source_uri == "doc:1"
    assert m.source_span == {"start": 0, "end": 10}
    assert m.confidence_source == "auto_derived"
    assert m.confidence_signals == {"source_age_days": 1.5}
    assert m.confidence_decayed_at == "2026-04-20T00:00:00Z"
    assert m.version == 3
    assert m.lifecycle_state == "open"
    assert m.cid == "b3:deadbeef"
    assert m.valid_from == "2026-04-01T00:00:00Z"
    assert m.valid_until == "2026-05-01T00:00:00Z"
    # All 30 server-side fields are declared on the model.
    assert len(Memory.model_fields) == 30


def test_raise_for_status_maps_404() -> None:
    with pytest.raises(NotFoundError) as info:
        raise_for_status(404, {"error": "not found"})
    assert info.value.status_code == 404


def test_raise_for_status_maps_400_to_validation() -> None:
    with pytest.raises(ValidationError):
        raise_for_status(400, {"error": "title cannot be empty"})


def test_raise_for_status_passes_on_2xx() -> None:
    raise_for_status(200, {"ok": True})  # does not raise


# ---------------------------------------------------------------------------
# C-20 (3x7 claims register, 2026-08-01) — the daemon registers ``delete`` on
# the COLLECTION path ``/api/v1/subscriptions`` only; the id rides the query
# string (``UnsubscribeQuery`` in ``src/handlers/subscriptions.rs``). Both the
# sync and async SDK clients used to send ``DELETE /api/v1/subscriptions/{id}``,
# which matches no route — so webhook teardown appeared to fail safe while the
# decommissioned endpoint kept receiving signed deliveries indefinitely.
#
# Offline: an ``httpx.MockTransport`` captures the URL the SDK builds, so no
# daemon is required.
# ---------------------------------------------------------------------------


def _capture_transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"deleted": True})

    return httpx.MockTransport(handler)


def test_unsubscribe_targets_collection_path_with_id_query() -> None:
    seen: list[httpx.Request] = []
    client = AiMemoryClient(base_url=TEST_BASE_URL)
    client._client = httpx.Client(  # noqa: SLF001 - offline URL-shape probe
        base_url=TEST_BASE_URL, transport=_capture_transport(seen)
    )

    assert client.unsubscribe("sub-abc-123") == {"deleted": True}

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "DELETE"
    # The registered route is the bare collection path.
    assert request.url.path == "/api/v1/subscriptions"
    # The id is a query parameter, not a path segment.
    assert request.url.params.get("id") == "sub-abc-123"
    # Guard the exact regression: no `/api/v1/subscriptions/<id>` form.
    assert "/api/v1/subscriptions/" not in str(request.url)


def test_removed_v1_methods_are_gone() -> None:
    """``grant`` / ``revoke`` / ``cluster`` hit routes the daemon never had.

    ``rg '"/api/v1/cluster"|/grant"|/revoke"' src/handlers/routes.rs`` returns
    nothing, so every call 404'd. They were deleted at v1.0.0 rather than
    documented — a shipped method against a nonexistent route is a claim, not
    a feature.
    """
    from ai_memory import AsyncAiMemoryClient

    for cls in (AiMemoryClient, AsyncAiMemoryClient):
        for name in ("grant", "revoke", "cluster"):
            assert not hasattr(cls, name), f"{cls.__name__}.{name} must not exist"


def _wire_memory(memory_id: str = "mem-3331") -> dict[str, object]:
    return {
        "id": memory_id, "tier": "mid", "namespace": "global",
        "title": "wire fixture", "content": "zebra", "tags": [],
        "priority": 5, "confidence": 1.0, "source": "api", "access_count": 0,
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z", "metadata": {},
    }


def _wire_handler(seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/api/v1/search":
            return httpx.Response(200, json={"count": 1, "query": "zebra", "results": [_wire_memory()]})
        if path == "/api/v1/memories/mem-3331":
            return httpx.Response(200, json={"memory": _wire_memory(), "links": []})
        if path == "/api/v1/notify":
            return httpx.Response(201, json={"id": "n1", "target_agent_id": "ai:target", "namespace": "global", "storage_backend": "postgres"})
        if path == "/api/v1/stats":
            return httpx.Response(200, json={"total_memories": 1, "by_tier": [], "by_namespace": [], "expiring_soon": 0, "links_count": 0, "db_size_bytes": 10, "live": 1, "expired_pending_gc": 0, "storage_backend": "postgres"})
        if path == "/api/v1/forget":
            return httpx.Response(200, json={"deleted": 1})
        raise AssertionError(path)
    return handler


def test_v1_wire_contract_sync() -> None:
    seen: list[httpx.Request] = []
    client = AiMemoryClient(base_url=TEST_BASE_URL)
    client._client = httpx.Client(base_url=TEST_BASE_URL, transport=httpx.MockTransport(_wire_handler(seen)))
    assert client.search("zebra")[0].id == "mem-3331"
    assert client.get("mem-3331").title == "wire fixture"
    client.notify({"target_agent_id": "ai:target", "title": "hello", "payload": {"x": 1}})
    assert client.stats().total_memories == 1
    assert client.forget(namespace="global") == {"deleted": 1}
    notify = next(r for r in seen if r.url.path.endswith("notify"))
    forget = next(r for r in seen if r.url.path.endswith("forget"))
    assert json.loads(notify.read()) == {
        "target_agent_id": "ai:target", "title": "hello", "payload": {"x": 1}
    }
    assert forget.url.query == b""
    assert json.loads(forget.read()) == {"namespace": "global"}


@pytest.mark.asyncio
async def test_v1_wire_contract_async() -> None:
    from ai_memory import AsyncAiMemoryClient
    seen: list[httpx.Request] = []
    client = AsyncAiMemoryClient(base_url=TEST_BASE_URL)
    client._client = httpx.AsyncClient(base_url=TEST_BASE_URL, transport=httpx.MockTransport(_wire_handler(seen)))
    assert (await client.search("zebra"))[0].id == "mem-3331"
    assert (await client.get("mem-3331")).title == "wire fixture"
    await client.notify({"target_agent_id": "ai:target", "title": "hello", "payload": {"x": 1}})
    assert (await client.stats()).total_memories == 1
    assert await client.forget(namespace="global") == {"deleted": 1}
    forget = next(r for r in seen if r.url.path.endswith("forget"))
    assert forget.url.query == b""
    assert json.loads(forget.read()) == {"namespace": "global"}
    await client.aclose()


# The webhook-HMAC tests moved to tests/test_webhooks.py (#2455). The version
# that lived here computed its "expected" signature with the SAME construction
# the implementation used, then asserted the implementation agreed with itself
# — it passed while the SDK could not verify a single genuine delivery. The
# replacement asserts against a fixture emitted by the RUST signer.


# ---------------------------------------------------------------------------
# Daemon-backed integration tests (opt-in)
# ---------------------------------------------------------------------------


@skip_without_daemon
def test_health_ok() -> None:
    with AiMemoryClient(base_url=TEST_BASE_URL) as c:
        out = c.health()
        assert out.get("status") == "ok"


@skip_without_daemon
def test_store_and_get_roundtrip() -> None:
    ns = f"sdk-test-{uuid.uuid4().hex[:8]}"
    with AiMemoryClient(base_url=TEST_BASE_URL) as c:
        created = c.store(title="hello", content="world", namespace=ns)
        memory_id = created["id"]
        try:
            fetched = c.get(memory_id)
            assert fetched.namespace == ns
            assert fetched.title == "hello"
        finally:
            c.forget(namespace=ns)


@skip_without_daemon
def test_recall_returns_wrapper() -> None:
    ns = f"sdk-test-{uuid.uuid4().hex[:8]}"
    with AiMemoryClient(base_url=TEST_BASE_URL) as c:
        c.store(title="recall subject", content="body text", namespace=ns)
        try:
            resp = c.recall(context="recall subject", namespace=ns)
            assert resp.count >= 0
            assert isinstance(resp.memories, list)
        finally:
            c.forget(namespace=ns)


@skip_without_daemon
def test_not_found_raises() -> None:
    with AiMemoryClient(base_url=TEST_BASE_URL) as c:
        with pytest.raises(AiMemoryError):
            c.get("does-not-exist-" + uuid.uuid4().hex)
