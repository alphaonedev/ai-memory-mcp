# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline coverage for preflight, lifecycle sweep, and JSONL journals."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from swarm.__main__ import _write_journals
from swarm.agent import StepRecord
from swarm.choreography import full_surface_sweep, run_all
from swarm.coverage import CoverageTracker
from swarm.orchestrator import Swarm
from swarm.tests.test_agent_loop_mock import _FakeModel, _agent
from swarm.openrouter import Decision


@pytest.mark.asyncio
async def test_preflight_dispatches_health_and_capabilities_once_per_agent() -> None:
    seen: list[httpx.Request] = []
    agents = [_agent(_FakeModel(Decision(None, [], {})), seen) for _ in range(2)]
    swarm = SimpleNamespace(agents=agents, coverage=CoverageTracker())
    try:
        await Swarm.preflight(swarm)
    finally:
        for agent in agents:
            await agent.aclose()
    paths = [request.url.path for request in seen]
    assert paths.count("/api/v1/health") == 2
    assert paths.count("/api/v1/capabilities") == 2
    assert paths.count("/api/v1/stats") == 2
    assert swarm.coverage.tools["health"].successes == 2
    assert swarm.coverage.tools["capabilities"].successes == 2


@pytest.mark.asyncio
async def test_full_surface_sweep_dispatches_order_and_confines_forget() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen)
    counter = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal counter
        seen.append(request)
        if request.url.path == "/api/v1/memories" and request.method == "POST":
            counter += 1
            return httpx.Response(201, json={"id": f"mem-{counter}", "version": 3})
        return httpx.Response(200, json={"ok": True})

    await agent.client._client.aclose()  # noqa: SLF001
    agent.client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://mock", transport=httpx.MockTransport(handler)
    )
    swarm = SimpleNamespace(agents=[agent], coverage=CoverageTracker())
    try:
        result = await full_surface_sweep(swarm)
    finally:
        await agent.aclose()
    assert result.ok, result.detail
    expected = [
        ("POST", "/api/v1/memories"), ("POST", "/api/v1/memories"),
        ("POST", "/api/v1/links"), ("GET", "/api/v1/links/mem-2"),
        ("GET", "/api/v1/memories/mem-2/lineage"),
        ("PUT", "/api/v1/memories/mem-1"),
        ("POST", "/api/v1/memories/mem-1/promote"),
        ("POST", "/api/v1/memory_reflect"),
        ("DELETE", "/api/v1/memories/mem-2"), ("POST", "/api/v1/forget"),
    ]
    assert [(request.method, request.url.path) for request in seen] == expected
    assert seen[5].headers["if-match"] == "3"
    reflect = json.loads(seen[7].content)
    assert reflect["source_ids"] == ["mem-1", "mem-2"]
    forgotten = json.loads(seen[9].content)
    assert forgotten["namespace"] == "swarm-000"
    assert forgotten["pattern"].startswith("full-surface-")


@pytest.mark.asyncio
async def test_run_all_includes_full_surface_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(_swarm: object):
        return SimpleNamespace(name="fake", ok=True, detail="ok")

    import swarm.choreography as choreography
    for name in ("producer_consumer", "consensus_quorum", "governance_approval",
                 "full_surface_sweep"):
        monkeypatch.setattr(choreography, name, fake)
    results = await run_all(SimpleNamespace(agents=[]))
    assert len(results) == 4


def test_write_journals_serializes_each_agent(tmp_path: Path) -> None:
    identity = SimpleNamespace(agent_id="ai:test-agent")
    agent = SimpleNamespace(identity=identity, journal=[StepRecord(1, "seen", ["store"], ["ok"])])
    _write_journals(SimpleNamespace(agents=[agent]), str(tmp_path))
    path = tmp_path / "ai:test-agent.jsonl"
    assert json.loads(path.read_text()) == {
        "decided_tools": ["store"], "outcomes": ["ok"],
        "perceived": "seen", "step": 1,
    }
