# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline Part-2 NHI audit tests (MockTransport + fake model)."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from swarm.audit import (CallLog, build_nhi_report, parse_assessment, redact,
                         render_nhi_report, set_call_log, write_audit_artifacts)
from swarm.config import DEFAULT_MISSION, SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.openrouter import Decision, ToolCall
from swarm.tests.test_agent_loop_mock import _FakeModel, _agent


def test_default_mission_and_phase_prompts() -> None:
    config = SwarmConfig.from_env({})
    assert config.mission == DEFAULT_MISSION
    agent = _agent(_FakeModel(Decision(None, [], {})), [])
    agent.config = SwarmConfig(base_urls=["http://mock"], max_steps=6)
    assert "Gather facts" in agent.phase_goal(1)
    assert "Build lineage" in agent.phase_goal(3)
    assert "mission-summary-" in agent.phase_goal(agent.config.max_steps)


@pytest.mark.asyncio
async def test_journal_timing_and_full_tool_summary() -> None:
    long_content = "x" * 500
    model = _FakeModel(Decision(None, [ToolCall("1", "store", {
        "title": "long", "content": long_content})], {}))
    agent = _agent(model, [])
    await agent.client._client.aclose()  # noqa: SLF001
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/memories" and request.method == "POST":
            return httpx.Response(201, json={"id": "m1", "echo": long_content})
        if request.url.path == "/api/v1/recall":
            return httpx.Response(200, json={"memories": []})
        if request.url.path == "/api/v1/search":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(200, json={"messages": []})
    agent.client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://mock", transport=httpx.MockTransport(handler))
    try:
        record = await agent.run_once()
    finally:
        await agent.aclose()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT.*Z", record.started_at)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT.*Z", record.finished_at)
    assert record.latency_ms >= 0
    assert len(record.outcomes[0]) > 160


@pytest.mark.asyncio
async def test_call_log_redacts_and_reconciles(tmp_path) -> None:
    log = CallLog(tmp_path)
    set_call_log(log)
    tracker = CoverageTracker()
    agent = _agent(_FakeModel(Decision(None, [], {})), [])
    try:
        from swarm.toolset import dispatch
        outcome = await dispatch(agent.client, agent.identity, "search",
                                 {"q": "fact", "api_key": "do-not-log"})
        tracker.record(outcome)
    finally:
        await agent.aclose()
        set_call_log(None)
    assert log.entries[0]["args"]["api_key"] == "[REDACTED]"
    assert log.reconcile(tracker)["ok"]
    assert json.loads((tmp_path / "calls.jsonl").read_text())["tool"] == "search"


def test_rubric_strict_parse_and_report_artifacts(tmp_path) -> None:
    raw = json.dumps({
        "recall_usefulness": 4, "latency_acceptable": True,
        "failures_encountered": [["recall", "one timeout"]],
        "isolation_respected": True, "would_rely_on_it": False,
        "free_text": "Useful lineage, but recall was uneven.",
    })
    valid = parse_assessment("ai:one", raw)
    invalid = parse_assessment("ai:two", "not json")
    assert not valid.assessment_invalid
    assert invalid.assessment_invalid
    report = build_nhi_report(n_agents=2, completed=1,
                              assessments=[valid, invalid], auditor_verdict="FAIL")
    rendered = render_nhi_report(report)
    assert "mission completion rate: 50.0%" in rendered
    assert "quote [ai:one]" in rendered
    write_audit_artifacts(tmp_path, [valid, invalid], report)
    assert json.loads((tmp_path / "assessments.json").read_text())[1]["assessment_invalid"]
    assert json.loads((tmp_path / "nhi-audit.json").read_text())["auditor_verdict"] == "FAIL"


def test_recursive_secret_redaction() -> None:
    assert redact({"nested": {"Authorization": "Bearer x"}, "safe": "yes"}) == {
        "nested": {"Authorization": "[REDACTED]"}, "safe": "yes"}


def test_model_override_requires_recorded_reason() -> None:
    import pytest as _pytest
    from swarm.config import ConfigError
    with _pytest.raises(ConfigError, match="SWARM_MODEL_OVERRIDE_REASON"):
        SwarmConfig.from_env({"SWARM_MODEL_SLUG": "x-ai/grok-4.6"})
    cfg = SwarmConfig.from_env({"SWARM_MODEL_SLUG": "x-ai/grok-4.6",
                                "SWARM_MODEL_OVERRIDE_REASON": "experiential audit (operator 2026-09-01)"})
    assert cfg.model_slug == "x-ai/grok-4.6"
    report = build_nhi_report(n_agents=1, completed=1, assessments=[], auditor_verdict="PASS",
                              model=cfg.model_slug, model_override_reason=cfg.model_override_reason)
    assert "override: experiential audit" in render_nhi_report(report)
    assert report["model"] == "x-ai/grok-4.6"


def test_auditor_verdict_prefers_explicit_marker() -> None:
    from swarm.__main__ import _auditor_verdict
    assert _auditor_verdict("... **Verdict: FAIL**\n\nRationale: PASS would over-claim.") == "FAIL"
    assert _auditor_verdict("VERDICT: PASS — rationale mentions FAIL cases") == "PASS"
    assert _auditor_verdict("end with PASS or FAIL. Verdict: **PASS**") == "PASS"
    assert _auditor_verdict("no marker here") == "UNKNOWN"
