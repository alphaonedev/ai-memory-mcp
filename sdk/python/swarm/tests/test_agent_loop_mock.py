# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Mocked dry-run of one agent loop — no daemon, no OpenRouter, no network.

Proves the perceive->decide->act->record loop:

* dispatches the reads at perceive and the model-chosen tool at act,
* records every outcome into the coverage tracker,
* CONFINES a write to the agent's own namespace (data-integrity guardrail),
* drives the driver-local ``signal_send`` route, and
* FAILS CLOSED (records, never fabricates success) when a tool errors.

The daemon is an ``httpx.MockTransport`` and the model is a hand-built
``Decision`` — the same offline technique the SDK's own ``test_client`` uses.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ai_memory import AsyncAiMemoryClient
from ai_memory.attestation import AgentSigningKey
from swarm.agent import SwarmAgent
from swarm.config import SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.openrouter import Decision, ToolCall
from swarm.toolset import AgentIdentity, dispatch


class _FakeModel:
    """Stands in for ``OpenRouterClient``; returns a scripted decision."""

    def __init__(self, decision: Decision) -> None:
        self._decision = decision
        self.calls = 0

    async def decide(self, **_kwargs: Any) -> Decision:
        self.calls += 1
        return self._decision

    async def aclose(self) -> None:
        return None


def _mock_daemon(
    seen: list[httpx.Request], *, fail_paths: set[str] | None = None
) -> httpx.MockTransport:
    fail = fail_paths or set()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path in fail:
            return httpx.Response(500, json={"error": "induced failure"})
        if path == "/api/v1/recall":
            return httpx.Response(200, json={"count": 0, "memories": []})
        if path == "/api/v1/search" and request.method == "GET":
            return httpx.Response(200, json={"results": [], "count": 0, "query": ""})
        if path == "/api/v1/memories" and request.method == "GET":
            return httpx.Response(200, json={"memories": []})
        if path == "/api/v1/inbox":
            return httpx.Response(200, json={"messages": []})
        if path == "/api/v1/memories" and request.method == "POST":
            body = json.loads(request.content)
            return httpx.Response(201, json={"id": "mem-1", "namespace": body.get("namespace")})
        if path == "/api/v1/signals":
            return httpx.Response(201, json={"id": "sig-1"})
        if path == "/api/v1/consolidate":
            return httpx.Response(201, json={"id": "con-1"})
        if path == "/api/v1/memory_reflect":
            return httpx.Response(200, json={"reflections": []})
        if path == "/api/v1/notify":
            return httpx.Response(200, json={"delivered": True})
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


def _agent(
    model: _FakeModel, seen: list[httpx.Request], *, fail_paths: set[str] | None = None
) -> SwarmAgent:
    config = SwarmConfig(base_urls=["http://mock"], n_agents=1, max_steps=2)
    client = AsyncAiMemoryClient(base_url="http://mock", agent_id="swarm-agent-000")
    client._client = httpx.AsyncClient(  # noqa: SLF001 - offline transport injection
        base_url="http://mock", transport=_mock_daemon(seen, fail_paths=fail_paths)
    )
    identity = AgentIdentity(
        agent_id="swarm-agent-000",
        signing_key=AgentSigningKey.generate(),
        namespace="swarm-000",
        allowed_namespaces={"swarm-000", "swarm-shared"},
    )
    return SwarmAgent(
        identity=identity, client=client, model=model,  # type: ignore[arg-type]
        config=config, coverage=CoverageTracker(),
    )


@pytest.mark.asyncio
async def test_one_loop_step_dispatches_and_records() -> None:
    decision = Decision(
        content=None,
        tool_calls=[ToolCall(id="c1", name="store",
                             arguments={"title": "t", "content": "hello world"})],
        raw={},
    )
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(decision), seen)
    try:
        record = await agent.run_once()
    finally:
        await agent.aclose()

    # perceive ran the three reads; act ran the store.
    assert record.decided_tools == ["store"]
    cov = agent.coverage.tools
    for read in ("recall", "search", "inbox"):
        assert cov[read].successes == 1, f"{read} not recorded"
    assert cov["store"].successes == 1
    assert cov["store"].covered

    # The attested store went out signed (signature present in the body).
    posts = [r for r in seen if r.url.path == "/api/v1/memories" and r.method == "POST"]
    assert len(posts) == 1
    body = json.loads(posts[0].content)
    assert body["signature"], "store must be attested (signed)"
    assert body["namespace"] == "swarm-000"


@pytest.mark.asyncio
async def test_write_namespace_is_confined() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen)
    try:
        # Model asks to write into a namespace this agent was NOT granted.
        outcome = await dispatch(
            agent.client, agent.identity, "store",
            {"title": "t", "content": "c", "namespace": "victim-namespace"},
        )
    finally:
        await agent.aclose()
    assert outcome.ok
    body = json.loads([r for r in seen if r.url.path == "/api/v1/memories"][0].content)
    # Confined back to the agent's own namespace — no cross-agent write.
    assert body["namespace"] == "swarm-000"


@pytest.mark.asyncio
async def test_signal_send_hits_driver_local_route() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen)
    try:
        outcome = await dispatch(
            agent.client, agent.identity, "signal_send",
            {"subject": "hi", "to_agent": "swarm-agent-001", "signal_type": "request"},
        )
    finally:
        await agent.aclose()
    assert outcome.ok
    assert any(r.url.path == "/api/v1/signals" and r.method == "POST" for r in seen)


@pytest.mark.asyncio
async def test_tool_error_fails_closed() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen, fail_paths={"/api/v1/consolidate"})
    try:
        outcome = await dispatch(
            agent.client, agent.identity, "consolidate", {"ids": ["a", "b"], "title": "x"},
        )
    finally:
        await agent.aclose()
    # Fail-closed: not ok, flagged, and NOT counted as coverage.
    assert not outcome.ok
    assert outcome.fail_closed
    tracker = agent.coverage
    tracker.record(outcome)
    assert not tracker.tools["consolidate"].covered


@pytest.mark.asyncio
async def test_missing_required_arg_fails_closed_without_request() -> None:
    seen: list[httpx.Request] = []
    agent = _agent(_FakeModel(Decision(None, [], {})), seen)
    try:
        # store with no title/content: dispatcher refuses before any HTTP call.
        outcome = await dispatch(agent.client, agent.identity, "store", {})
    finally:
        await agent.aclose()
    assert not outcome.ok
    assert outcome.fail_closed
    assert not any(r.url.path == "/api/v1/memories" for r in seen)
