# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline coverage for preflight, lifecycle sweep, and JSONL journals."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from swarm.__main__ import _write_journals, _write_usage
from swarm.agent import StepRecord
from swarm.choreography import ScenarioResult, full_surface_sweep, nhi_assessment, run_all
from swarm.coverage import CoverageTracker
from swarm.orchestrator import Swarm
from swarm.tests.test_agent_loop_mock import _FakeModel, _agent
from swarm.openrouter import AccountSnapshot, Decision


def _mem(memory_id: str) -> dict[str, object]:
    return {"id": memory_id, "tier": "mid", "namespace": "swarm-000", "title": "t", "content": "c", "tags": [],
            "priority": 5, "confidence": 1.0, "source": "api", "access_count": 0,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z", "metadata": {}}


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
        if request.method == "GET" and request.url.path.startswith("/api/v1/memories/mem-") \
                and not request.url.path.endswith("/lineage"):
            return httpx.Response(200, json={"memory": _mem(request.url.path.rsplit("/", 1)[-1]), "links": []})
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
        ("GET", "/api/v1/memories/mem-1"),
        ("GET", "/api/v1/memories/mem-2/lineage"),
        ("PUT", "/api/v1/memories/mem-1"),
        ("POST", "/api/v1/memories/mem-1/promote"),
        ("POST", "/api/v1/memory_reflect"),
        ("DELETE", "/api/v1/memories/mem-2"), ("POST", "/api/v1/forget"),
    ]
    assert [(request.method, request.url.path) for request in seen] == expected
    assert seen[6].headers["if-match"] == "3"
    reflect = json.loads(seen[8].content)
    assert reflect["source_ids"] == ["mem-1", "mem-2"]
    forgotten = json.loads(seen[10].content)
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
        "perceived": "seen", "step": 1, "started_at": "",
        "finished_at": "", "latency_ms": 0.0,
    }


@pytest.mark.asyncio
async def test_nhi_assessment_is_plain_completion_and_attested_store() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen)
    calls: list[dict[str, object]] = []

    async def complete(**kwargs: object) -> str:
        calls.append(kwargs)
        return "Evidence is complete. Verdict: PASS"

    agent.model.complete = complete  # type: ignore[attr-defined,method-assign]
    swarm = SimpleNamespace(
        agents=[agent], coverage=CoverageTracker(), shared_namespace="swarm-shared"
    )
    try:
        result, report = await nhi_assessment(
            swarm, [ScenarioResult("probe", True, "proved")]
        )
    finally:
        await agent.aclose()
    assert result.ok, result.detail
    assert report == "Evidence is complete. Verdict: PASS"
    assert len(calls) == 1
    assert set(calls[0]) == {"messages"}
    request = [r for r in seen if r.url.path == "/api/v1/memories" and r.method == "POST"][-1]
    body = json.loads(request.content)
    assert body["content"] == report
    assert body["namespace"] == "swarm-shared"
    assert body["scope"] == "collective"
    assert body["signature"]


def test_write_journals_writes_assessment_artifact(tmp_path: Path) -> None:
    swarm = SimpleNamespace(agents=[])
    _write_journals(swarm, str(tmp_path), assessment="Verdict: PASS")
    assert (tmp_path / "nhi-assessment.md").read_text() == "Verdict: PASS\n"


def test_write_usage_serializes_account_delta_and_agent_totals(tmp_path: Path) -> None:
    coverage = CoverageTracker()
    coverage.record_model_usage(
        "ai:a", {"prompt_tokens": 10, "completion_tokens": 2,
                  "total_tokens": 12, "cost": 0.003}
    )
    before = AccountSnapshot(1.0, 0.1, 0.5, 0.9)
    after = AccountSnapshot(1.003, 0.103, 0.503, 0.903)
    path = _write_usage(coverage, before, after, path=str(tmp_path / "usage.json"))
    payload = json.loads(path.read_text())
    assert payload["schema_version"] == 1
    assert payload["account_usd"]["delta"]["usage"] == pytest.approx(0.003)
    assert payload["completions"]["by_agent"]["ai:a"]["requests"] == 1
    assert payload["completions"]["total"]["total_tokens"] == 12
