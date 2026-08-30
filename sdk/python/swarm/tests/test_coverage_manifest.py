# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for the coverage manifest + tracker (no daemon)."""

from __future__ import annotations

import pytest

from swarm.config import ConfigError, SwarmConfig
from swarm.coverage import CoverageError, CoverageTracker, manifest
from swarm.toolset import TOOL_SPECS, ToolOutcome, selectable_schemas


def test_manifest_covers_every_tool_spec() -> None:
    names = {row["name"] for row in manifest()}
    assert names == {s.name for s in TOOL_SPECS}
    # The three driver-local routes the SDK client does not wrap are present.
    assert {"signal_send", "consolidate", "reflect"} <= names


def test_manifest_records_source_and_method() -> None:
    by_name = {row["name"]: row for row in manifest()}
    assert by_name["signal_send"]["source"] == "driver-local"
    assert by_name["signal_send"]["http_method"] == "POST"
    assert by_name["signal_send"]["path"] == "/api/v1/signals"
    assert by_name["store"]["source"] == "sdk"


def test_openai_schemas_are_wellformed() -> None:
    schemas = selectable_schemas()
    assert schemas, "at least one selectable tool"
    for schema in schemas:
        assert schema["type"] == "function"
        fn = schema["function"]
        assert isinstance(fn["name"], str) and fn["name"]
        assert fn["parameters"]["type"] == "object"
        # non-selectable admin/health tools stay out of the model's menu
    selectable = {s["function"]["name"] for s in schemas}
    assert "health" not in selectable
    assert "store" in selectable


def test_tracker_starts_fully_uncovered() -> None:
    tracker = CoverageTracker()
    assert len(tracker.tools) == len(TOOL_SPECS)
    assert not tracker.is_full()
    assert set(tracker.uncovered()) == {s.name for s in TOOL_SPECS}


def test_success_marks_covered() -> None:
    tracker = CoverageTracker()
    tracker.record(ToolOutcome("store", ok=True, fail_closed=False, summary="{'id': 'x'}"))
    assert tracker.tools["store"].covered
    assert "store" not in tracker.uncovered()


def test_unexpected_failure_is_not_coverage() -> None:
    tracker = CoverageTracker()
    tracker.record(ToolOutcome("forget", ok=False, fail_closed=True, summary="boom"))
    # Fail-closed is only coverage if the operator DOCUMENTED it as expected.
    assert not tracker.tools["forget"].covered


def test_documented_fail_closed_counts_as_covered() -> None:
    tracker = CoverageTracker()
    tracker.mark_documented_fail_closed("forget")
    tracker.record(ToolOutcome("forget", ok=False, fail_closed=True, summary="501 skills-off"))
    assert tracker.tools["forget"].covered


def test_assert_full_raises_with_gap_names() -> None:
    tracker = CoverageTracker()
    tracker.record(ToolOutcome("store", ok=True, fail_closed=False, summary="ok"))
    with pytest.raises(CoverageError) as info:
        tracker.assert_full()
    assert "recall" in str(info.value)


def test_full_coverage_passes() -> None:
    tracker = CoverageTracker()
    for spec in TOOL_SPECS:
        tracker.record(ToolOutcome(spec.name, ok=True, fail_closed=False, summary="ok"))
    assert tracker.is_full()
    tracker.assert_full()  # does not raise
    assert "PASS" in tracker.matrix()


def test_reconcile_reports_daemon_only_gap() -> None:
    tracker = CoverageTracker()
    live = {"tools": [{"name": "memory_store"}, {"name": "memory_brand_new_tool"}]}
    report = tracker.reconcile_tools_list(live)
    assert "memory_brand_new_tool" in report.daemon_only
    # store IS wrapped (via its memory_store alias), so it is not a gap.
    assert "memory_store" not in report.daemon_only


def test_config_from_env_defaults_and_parsing() -> None:
    cfg = SwarmConfig.from_env({})
    assert cfg.base_urls == ["http://localhost:9077"]
    assert cfg.n_agents == 4
    cfg2 = SwarmConfig.from_env(
        {"SWARM_BASE_URLS": "http://a:9077, http://b:9077/", "SWARM_N": "8"}
    )
    assert cfg2.base_urls == ["http://a:9077", "http://b:9077"]
    assert cfg2.n_agents == 8
    assert cfg2.namespace_for(2) == "swarm-002"
    assert cfg2.base_url_for(1) == "http://b:9077"


def test_config_rejects_bad_int_and_requires_live_key() -> None:
    with pytest.raises(ConfigError):
        SwarmConfig.from_env({"SWARM_N": "not-a-number"})
    offline = SwarmConfig.from_env({})
    with pytest.raises(ConfigError):
        offline.require_live()
