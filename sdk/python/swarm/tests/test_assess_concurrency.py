# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3346 — per-agent rubric assessments run with a bounded concurrency.

Offline: the model is a fake with a fixed latency, the daemon an
``httpx.MockTransport``. Proves the phase is no longer serialised, that the
bound is respected, that per-agent usage stays exact under concurrency, and
that the results are identical (and identically ordered) to the sequential run.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import httpx
import pytest

from ai_memory import AsyncAiMemoryClient
from ai_memory.attestation import AgentSigningKey
from swarm.agent import SwarmAgent, StepRecord
from swarm.choreography import PARTIAL_ASSESSMENTS, collect_assessments
from swarm.config import DEFAULT_ASSESS_CONCURRENCY, ConfigError, SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.openrouter import OpenRouterError
from swarm.toolset import AgentIdentity


class _LatentModel:
    """A model whose completion takes ``latency`` seconds and bills per call."""

    def __init__(self, latency: float = 0.1, *, fail_for: set[str] | None = None) -> None:
        self.latency = latency
        self.fail_for = fail_for or set()
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0

    async def complete_with_usage(self, *, messages, temperature: float = 0.1):
        self.calls += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.latency)
            agent_id = json.loads(messages[1]["content"])["agent_id"]
            if agent_id in self.fail_for:
                raise OpenRouterError("induced upstream failure")
            ordinal = int(agent_id.rsplit("-", 1)[-1])
            rubric = {
                "recall_usefulness": 1 + ordinal % 5,
                "latency_acceptable": True,
                "failures_encountered": [],
                "isolation_respected": True,
                "would_rely_on_it": True,
                "free_text": f"agent {ordinal} reporting",
            }
            # Distinct token counts per agent: misattribution is then visible.
            usage = {"prompt_tokens": 10 + ordinal, "completion_tokens": 1,
                     "total_tokens": 11 + ordinal, "cost": 0.001}
            return json.dumps(rubric), usage
        finally:
            self.in_flight -= 1

    async def aclose(self) -> None:
        return None


def _mock_daemon() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/memories" and request.method == "POST":
            return httpx.Response(201, json={"id": "mem-1", "version": 1})
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


def _swarm(model: _LatentModel, n_agents: int, *, concurrency: int) -> SimpleNamespace:
    config = SwarmConfig(base_urls=["http://mock"], n_agents=n_agents, max_steps=1,
                         assess_concurrency=concurrency)
    agents = []
    for ordinal in range(n_agents):
        agent_id = f"ai:swarm-{ordinal}"
        client = AsyncAiMemoryClient(base_url="http://mock", agent_id=agent_id)
        client._client = httpx.AsyncClient(  # noqa: SLF001 - offline transport injection
            base_url="http://mock", transport=_mock_daemon())
        identity = AgentIdentity(agent_id=agent_id, signing_key=AgentSigningKey.generate(),
                                 namespace=f"swarm-{ordinal:03d}",
                                 allowed_namespaces={f"swarm-{ordinal:03d}", "swarm-shared"})
        agent = SwarmAgent(identity=identity, client=client,
                           model=model,  # type: ignore[arg-type]
                           config=config, coverage=CoverageTracker())
        agent.journal.append(StepRecord(1, "recall[ok]", ["store"], ["store -> ok"]))
        agents.append(agent)
    return SimpleNamespace(agents=agents, coverage=CoverageTracker(), config=config,
                           shared_namespace="swarm-shared")


async def _aclose(swarm: SimpleNamespace) -> None:
    for agent in swarm.agents:
        await agent.aclose()


@pytest.mark.asyncio
async def test_bounded_concurrency_collapses_the_assessment_tail() -> None:
    model = _LatentModel(latency=0.1)
    swarm = _swarm(model, 64, concurrency=16)
    started = time.perf_counter()
    try:
        assessments = await collect_assessments(swarm)
    finally:
        await _aclose(swarm)
    elapsed = time.perf_counter() - started
    # Sequential would be 64 x 100ms = 6.4 s; the issue's bar is < 2 s at 16.
    assert elapsed < 2.0, elapsed
    assert len(assessments) == 64
    assert model.max_in_flight <= 16
    # ... and the bound is actually USED (never a 64-wide blast, never serial).
    assert model.max_in_flight > 1
    assert swarm.coverage.phase_secs["assessments"] == pytest.approx(elapsed, abs=0.5)


@pytest.mark.asyncio
async def test_results_are_identical_and_ordered_like_the_sequential_run() -> None:
    sequential_swarm = _swarm(_LatentModel(latency=0.0), 12, concurrency=1)
    try:
        sequential = await collect_assessments(sequential_swarm)
    finally:
        await _aclose(sequential_swarm)
    concurrent_swarm = _swarm(_LatentModel(latency=0.01), 12, concurrency=8)
    try:
        concurrent = await collect_assessments(concurrent_swarm)
    finally:
        await _aclose(concurrent_swarm)
    assert [a.agent_id for a in concurrent] == [f"ai:swarm-{i}" for i in range(12)]
    assert [a.__dict__ for a in concurrent] == [a.__dict__ for a in sequential]


@pytest.mark.asyncio
async def test_per_agent_usage_accounting_survives_concurrency() -> None:
    """The `last_usage` race: whichever response landed last would bill everyone."""
    model = _LatentModel(latency=0.02)
    swarm = _swarm(model, 16, concurrency=8)
    try:
        await collect_assessments(swarm)
    finally:
        await _aclose(swarm)
    usage = swarm.coverage.model_usage
    assert len(usage) == 16
    for ordinal in range(16):
        totals = usage[f"ai:swarm-{ordinal}"]
        assert totals["requests"] == 1
        assert totals["prompt_tokens"] == 10 + ordinal
        assert totals["total_tokens"] == 11 + ordinal


@pytest.mark.asyncio
async def test_one_failing_agent_fails_closed_without_losing_the_fleet() -> None:
    model = _LatentModel(latency=0.0, fail_for={"ai:swarm-3"})
    swarm = _swarm(model, 6, concurrency=4)
    try:
        assessments = await collect_assessments(swarm)
    finally:
        await _aclose(swarm)
    assert len(assessments) == 6
    failed = [a for a in assessments if a.assessment_invalid]
    assert [a.agent_id for a in failed] == ["ai:swarm-3"]
    assert "OpenRouterError" in (failed[0].error or "")
    # Every agent still attested its rubric (including the failed one).
    assert swarm.coverage.tools["store"].successes == 6


@pytest.mark.asyncio
async def test_each_rubric_is_streamed_as_it_lands(tmp_path) -> None:
    model = _LatentModel(latency=0.01)
    swarm = _swarm(model, 8, concurrency=4)
    try:
        assessments = await collect_assessments(swarm, journal_dir=tmp_path)
    finally:
        await _aclose(swarm)
    streamed = [json.loads(line) for line in
                (tmp_path / PARTIAL_ASSESSMENTS).read_text(encoding="utf-8").splitlines()]
    # A killed run keeps every rubric it had already paid for, in any order.
    assert len(streamed) == len(assessments) == 8
    assert {item["agent_id"] for item in streamed} == {a.agent_id for a in assessments}
    assert {item["free_text"] for item in streamed} == {a.free_text for a in assessments}


def test_concurrency_is_configurable_and_fails_closed_on_nonsense() -> None:
    assert SwarmConfig.from_env({}).assess_concurrency == DEFAULT_ASSESS_CONCURRENCY == 8
    assert SwarmConfig.from_env({"SWARM_ASSESS_CONCURRENCY": "32"}).assess_concurrency == 32
    with pytest.raises(ConfigError, match="SWARM_ASSESS_CONCURRENCY"):
        SwarmConfig.from_env({"SWARM_ASSESS_CONCURRENCY": "many"})
    with pytest.raises(ConfigError, match="assess_concurrency must be >= 1"):
        SwarmConfig(base_urls=["http://mock"], assess_concurrency=0)


@pytest.mark.asyncio
async def test_complete_with_usage_returns_this_calls_usage() -> None:
    """The real client: usage travels with the response, not on the client."""
    from swarm.openrouter import OpenRouterClient

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        tag = payload["messages"][0]["content"]
        return httpx.Response(200, json={
            "choices": [{"message": {"content": f"reply-{tag}"}}],
            "usage": {"prompt_tokens": int(tag), "completion_tokens": 1,
                      "total_tokens": int(tag) + 1, "cost": 0.5},
        })

    client = OpenRouterClient(api_key="test", model_slug="test-model", base_url="http://mock")
    await client._client.aclose()  # noqa: SLF001
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://mock", transport=httpx.MockTransport(handler))
    try:
        results = await asyncio.gather(*(
            client.complete_with_usage(messages=[{"role": "system", "content": str(n)}])
            for n in (7, 11, 13)))
    finally:
        await client.aclose()
    assert [content for content, _usage in results] == ["reply-7", "reply-11", "reply-13"]
    assert [usage["prompt_tokens"] for _content, usage in results] == [7, 11, 13]
