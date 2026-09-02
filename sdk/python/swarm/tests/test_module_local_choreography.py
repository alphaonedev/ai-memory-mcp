# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3441 — choreographies must stay inside one module (data tier).

Two fake modules, each an ``httpx.MockTransport`` with its OWN inbox and memory
store and NO federation between them — exactly the shape of the 2-module run
where ``producer_consumer`` and ``consensus_quorum`` failed because agent 0 sat
on f2 and agent 1 on f1. Offline: no daemon, no OpenRouter.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from ai_memory import AsyncAiMemoryClient
from ai_memory.attestation import AgentSigningKey
from swarm.agent import SwarmAgent
from swarm.choreography import (consensus_quorum, cross_module_handoff, federation_expected,
                                module_of, modules, producer_consumer, run_all)
from swarm.config import SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.toolset import AgentIdentity
from swarm.tests.test_agent_loop_mock import _FakeModel
from swarm.openrouter import Decision


class _Module:
    """One INDEPENDENT data tier: its own inboxes, memories, and request log."""

    def __init__(self, base_url: str, *, leaks_to: _Module | None = None) -> None:
        self.base_url = base_url
        self.inboxes: dict[str, list[dict[str, str]]] = {}
        self.requests: list[httpx.Request] = []
        self.rows = 0
        self.written: dict[tuple[object, object, object], str] = {}
        #: Ids this tier actually minted; anything else is "memory not found".
        self.minted: set[str] = set()
        #: Only set by the leak test: simulates a boundary that is NOT airtight.
        self.leaks_to = leaks_to

    def deliver(self, target: str, title: str) -> None:
        self.inboxes.setdefault(target, []).append({"title": title, "payload": "x"})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method
        agent = request.headers.get("X-Agent-Id", "")
        if path == "/api/v1/notify":
            body = json.loads(request.content)
            self.deliver(body["target_agent_id"], body["title"])
            if self.leaks_to is not None:
                self.leaks_to.deliver(body["target_agent_id"], body["title"])
            return httpx.Response(200, json={"delivered": True})
        if path == "/api/v1/inbox":
            target = request.url.params.get("agent_id") or agent
            return httpx.Response(200, json={"messages": self.inboxes.get(target, [])})
        if path == "/api/v1/memories" and method == "POST":
            body = json.loads(request.content)
            # Replay-guard: the SAME signed envelope dedups to the same row,
            # never a second durable write (what `replay_guard` asserts).
            key = (body.get("title"), body.get("signature"), body.get("created_at"))
            if body.get("signature") and key in self.written:
                return httpx.Response(200, json={"id": self.written[key], "version": 1})
            self.rows += 1
            memory_id = f"{self.base_url}-mem-{self.rows}"
            self.minted.add(memory_id)
            if body.get("signature"):
                self.written[key] = memory_id
            return httpx.Response(201, json={"id": memory_id, "version": 1})
        if path == "/api/v1/consolidate":
            # A tier can only fold ids IT stored: a vote written to the other
            # module is "memory not found" here, exactly as the daemon reports.
            unknown = [i for i in json.loads(request.content).get("ids", [])
                       if i not in self.minted]
            if unknown:
                return httpx.Response(404, json={"error": f"memory not found: {unknown[0]}"})
            return httpx.Response(201, json={"id": f"{self.base_url}-con"})
        if path.startswith("/api/v1/memories/") and method == "GET" \
                and not path.endswith("/lineage"):
            return httpx.Response(200, json={"memory": {
                "id": path.rsplit("/", 1)[-1], "tier": "mid", "namespace": "swarm-000",
                "title": "t", "content": "c", "tags": [], "priority": 5, "confidence": 1.0,
                "source": "api", "access_count": 0, "created_at": "2026-09-01T00:00:00Z",
                "updated_at": "2026-09-01T00:00:00Z", "metadata": {}}, "links": []})
        if path == "/api/v1/recall":
            return httpx.Response(200, json={"count": 0, "memories": []})
        if path == "/api/v1/search":
            return httpx.Response(200, json={"results": [], "count": 0, "query": ""})
        return httpx.Response(200, json={"ok": True})


def _agent_on(module: _Module, ordinal: int) -> SwarmAgent:
    """One agent bound to ``module`` — its client speaks ONLY to that tier."""
    agent_id = f"ai:swarm-{ordinal:03d}"
    namespace = f"swarm-{ordinal:03d}"
    config = SwarmConfig(base_urls=[module.base_url], n_agents=1, max_steps=1)
    client = AsyncAiMemoryClient(base_url=module.base_url, agent_id=agent_id)
    client._client = httpx.AsyncClient(  # noqa: SLF001 - offline transport injection
        base_url=module.base_url, transport=httpx.MockTransport(module.handle),
        headers={"X-Agent-Id": agent_id})
    identity = AgentIdentity(
        agent_id=agent_id, signing_key=AgentSigningKey.generate(),
        namespace=namespace, allowed_namespaces={namespace, "swarm-shared"})
    return SwarmAgent(identity=identity, client=client,
                      model=_FakeModel(Decision(None, [], {})),  # type: ignore[arg-type]
                      config=config, coverage=CoverageTracker())


def _two_module_swarm(*, leaky: bool = False) -> tuple[SimpleNamespace, _Module, _Module]:
    """Agents round-robined across two modules, exactly as the launcher does."""
    second = _Module("http://mod-b")
    first = _Module("http://mod-a", leaks_to=second if leaky else None)
    agents = [_agent_on(first if ordinal % 2 == 0 else second, ordinal)
              for ordinal in range(6)]
    swarm = SimpleNamespace(agents=agents, coverage=CoverageTracker(),
                            shared_namespace="swarm-shared")
    return swarm, first, second


async def _aclose(swarm: SimpleNamespace) -> None:
    for agent in swarm.agents:
        await agent.aclose()


def test_modules_groups_agents_by_client_base_url() -> None:
    swarm, first, second = _two_module_swarm()
    grouped = modules(swarm)
    assert sorted(grouped) == ["http://mod-a", "http://mod-b"]
    assert [module_of(agent) for agent in grouped["http://mod-a"]] == ["http://mod-a"] * 3
    # Round-robin really does split agent 0 from agent 1 (the #3441 failure).
    assert module_of(swarm.agents[0]) != module_of(swarm.agents[1])


@pytest.mark.asyncio
async def test_producer_consumer_is_module_local() -> None:
    swarm, first, second = _two_module_swarm()
    try:
        agents = modules(swarm)["http://mod-a"]
        result = await producer_consumer(swarm, agents, "http://mod-a")
    finally:
        await _aclose(swarm)
    assert result.ok, result.detail
    assert result.name == "producer_consumer@http://mod-a"
    assert "b_saw=True" in result.detail and "c_isolated=True" in result.detail
    # Every call stayed on one tier; the other module was never touched.
    assert second.requests == []


@pytest.mark.asyncio
async def test_producer_consumer_across_modules_would_fail() -> None:
    """The behaviour this issue is about, kept as the negative control."""
    swarm, _first, _second = _two_module_swarm()
    try:
        # agents[0] and agents[1] are on DIFFERENT modules (the old default).
        result = await producer_consumer(swarm, swarm.agents[:3])
    finally:
        await _aclose(swarm)
    assert not result.ok
    assert "b_saw=False" in result.detail


@pytest.mark.asyncio
async def test_consensus_quorum_across_modules_cannot_read_its_own_votes() -> None:
    """The observed failure: votes=256 consolidated=False ("memory not found")."""
    swarm, _first, _second = _two_module_swarm()
    try:
        result = await consensus_quorum(swarm, swarm.agents)
    finally:
        await _aclose(swarm)
    assert not result.ok
    assert "consolidated=False" in result.detail


@pytest.mark.asyncio
async def test_consensus_quorum_votes_and_consolidates_on_one_module() -> None:
    swarm, first, second = _two_module_swarm()
    try:
        result = await consensus_quorum(swarm, modules(swarm)["http://mod-b"], "http://mod-b")
    finally:
        await _aclose(swarm)
    assert result.ok, result.detail
    assert result.name == "consensus_quorum@http://mod-b"
    assert "votes=3" in result.detail
    # The consolidator only ever saw ids minted by its own module.
    assert first.requests == []


@pytest.mark.asyncio
async def test_run_all_runs_every_scenario_once_per_module() -> None:
    swarm, _first, _second = _two_module_swarm()
    try:
        results = await run_all(swarm)
    finally:
        await _aclose(swarm)
    names = [result.name for result in results]
    for scenario in ("producer_consumer", "consensus_quorum", "governance_approval",
                     "full_surface_sweep"):
        assert f"{scenario}@http://mod-a" in names
        assert f"{scenario}@http://mod-b" in names
        # No un-tagged (cross-module) variant is run any more.
        assert scenario not in names
    assert "cross_module_handoff" in names
    assert "replay_guard" in names
    failed = [(r.name, r.detail) for r in results if not r.ok]
    assert failed == [], failed


@pytest.mark.asyncio
async def test_single_module_run_is_unchanged() -> None:
    only = _Module("http://mod-a")
    agents = [_agent_on(only, ordinal) for ordinal in range(3)]
    swarm = SimpleNamespace(agents=agents, coverage=CoverageTracker(),
                            shared_namespace="swarm-shared")
    try:
        results = await run_all(swarm)
    finally:
        await _aclose(swarm)
    names = [result.name for result in results]
    assert names == ["producer_consumer", "consensus_quorum", "governance_approval",
                     "full_surface_sweep", "replay_guard"]
    assert all(result.ok for result in results), [r.detail for r in results if not r.ok]


@pytest.mark.asyncio
async def test_cross_module_handoff_reports_not_federated_rather_than_fail() -> None:
    swarm, _first, _second = _two_module_swarm()
    try:
        result = await cross_module_handoff(swarm, modules(swarm), federated=False)
    finally:
        await _aclose(swarm)
    assert result.ok
    assert result.detail.startswith("cross-module: not federated (expected)")


@pytest.mark.asyncio
async def test_cross_module_handoff_fails_when_an_unfederated_boundary_leaks() -> None:
    """Not a rubber stamp: a message that DOES cross is a data-isolation failure."""
    swarm, _first, _second = _two_module_swarm(leaky=True)
    try:
        result = await cross_module_handoff(swarm, modules(swarm), federated=False)
    finally:
        await _aclose(swarm)
    assert not result.ok
    assert "CROSSED an unfederated boundary" in result.detail


@pytest.mark.asyncio
async def test_cross_module_handoff_asserts_delivery_once_federated() -> None:
    # SWARM_FEDERATED=1 flips the probe into a real delivery assertion.
    swarm, _first, _second = _two_module_swarm()
    try:
        unfederated = await cross_module_handoff(swarm, modules(swarm), federated=True)
    finally:
        await _aclose(swarm)
    assert not unfederated.ok
    assert "b_saw=False" in unfederated.detail

    federated_swarm, _a, _b = _two_module_swarm(leaky=True)
    try:
        delivered = await cross_module_handoff(federated_swarm, modules(federated_swarm),
                                               federated=True)
    finally:
        await _aclose(federated_swarm)
    assert delivered.ok
    assert "b_saw=True" in delivered.detail


def test_federation_flag_is_opt_in_and_explicit() -> None:
    assert federation_expected({}) is False
    assert federation_expected({"SWARM_FEDERATED": "0"}) is False
    assert federation_expected({"SWARM_FEDERATED": ""}) is False
    assert federation_expected({"SWARM_FEDERATED": "1"}) is True
    assert federation_expected({"SWARM_FEDERATED": "true"}) is True


@pytest.mark.asyncio
async def test_cross_module_handoff_is_not_applicable_on_one_module() -> None:
    only = _Module("http://mod-a")
    agents = [_agent_on(only, ordinal) for ordinal in range(2)]
    swarm = SimpleNamespace(agents=agents, coverage=CoverageTracker(),
                            shared_namespace="swarm-shared")
    try:
        result = await cross_module_handoff(swarm, modules(swarm), federated=False)
    finally:
        await _aclose(swarm)
    assert result.ok and result.detail == "single module: not applicable"
