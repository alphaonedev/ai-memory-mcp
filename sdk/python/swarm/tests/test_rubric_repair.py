# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3440 — bounded rubric repair and call-log mission evidence.

Offline only: no OpenRouter, no daemon. The last two tests replay the real
256-agent journal (``m2-swarm-256x10-20260901T231850Z``) when it is present on
this machine, and SKIP everywhere else — the synthetic cases above them cover
the same shapes deterministically.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from swarm.audit import (FREE_TEXT_LIMIT, build_nhi_report, mission_evidence,
                         parse_assessment, render_nhi_report)

#: The journal this issue was raised from. Overridable for a different run.
_JOURNAL = Path(os.environ.get(
    "SWARM_JOURNAL_FIXTURE",
    "/home/fate_two/v07/v09-dev/.local-runs/journals/m2-swarm-256x10-20260901T231850Z"))


def _rubric(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "recall_usefulness": 4,
        "latency_acceptable": True,
        "failures_encountered": [["recall", "one timeout"]],
        "isolation_respected": True,
        "would_rely_on_it": True,
        "free_text": "Recall was useful; lineage held.",
    }
    base.update(overrides)
    return base


def test_clean_rubric_is_not_marked_repaired() -> None:
    parsed = parse_assessment("ai:one", json.dumps(_rubric()))
    assert not parsed.assessment_invalid
    assert not parsed.repaired
    assert parsed.repairs == ()
    # The excerpt is kept ONLY as evidence for a repaired/invalid reply.
    assert parsed.raw_excerpt == ""


def test_code_fence_and_leading_prose_are_stripped() -> None:
    fenced = "Here is my assessment:\n```json\n" + json.dumps(_rubric()) + "\n```\nHope that helps."
    parsed = parse_assessment("ai:one", fenced)
    assert not parsed.assessment_invalid
    assert parsed.repairs == ("code_fence_stripped",)
    assert parsed.recall_usefulness == 4

    prose = "Sure — my rubric: " + json.dumps(_rubric()) + " (let me know if you need more)"
    extracted = parse_assessment("ai:one", prose)
    assert not extracted.assessment_invalid
    assert extracted.repairs == ("json_extracted",)
    # The raw reply is retained verbatim so the strictness stays auditable.
    assert extracted.raw_excerpt.startswith("Sure — my rubric:")


def test_over_long_free_text_is_truncated_not_discarded() -> None:
    long_text = "x" * 900
    parsed = parse_assessment("ai:one", json.dumps(_rubric(free_text=long_text)))
    # #3440: 95/256 agents lost five structured judgements to a long paragraph.
    assert not parsed.assessment_invalid
    assert parsed.repairs == ("free_text_truncated",)
    assert len(parsed.free_text) == FREE_TEXT_LIMIT
    assert parsed.free_text == long_text[:FREE_TEXT_LIMIT]
    assert parsed.recall_usefulness == 4 and parsed.would_rely_on_it is True


def test_extra_fields_are_dropped_and_counted() -> None:
    parsed = parse_assessment("ai:one", json.dumps(_rubric(confidence=0.9, notes="hi")))
    assert not parsed.assessment_invalid
    assert parsed.repairs == ("extra_fields_dropped",)


def test_repairs_compose_and_are_all_reported() -> None:
    raw = "```\n" + json.dumps(_rubric(free_text="y" * 700, extra=1)) + "\n```"
    parsed = parse_assessment("ai:one", raw)
    assert not parsed.assessment_invalid
    assert set(parsed.repairs) == {"code_fence_stripped", "extra_fields_dropped",
                                   "free_text_truncated"}


@pytest.mark.parametrize("raw", [
    "",
    "I could not complete the assessment.",
    json.dumps(_rubric(recall_usefulness=7)),
    json.dumps(_rubric(recall_usefulness="4")),
    json.dumps(_rubric(latency_acceptable="yes")),
    json.dumps(_rubric(failures_encountered=["recall"])),
    json.dumps(_rubric(free_text=None)),
    json.dumps({k: v for k, v in _rubric().items() if k != "isolation_respected"}),
])
def test_strictness_is_preserved_for_substantive_defects(raw: str) -> None:
    """Repair fixes PACKAGING only — a judgement the NHI did not state stays invalid."""
    parsed = parse_assessment("ai:one", raw)
    assert parsed.assessment_invalid
    assert parsed.error
    assert parsed.recall_usefulness is None and parsed.free_text == ""


def test_report_separates_raw_from_repaired() -> None:
    clean = parse_assessment("ai:one", json.dumps(_rubric()))
    repaired = parse_assessment("ai:two", json.dumps(_rubric(free_text="z" * 800)))
    invalid = parse_assessment("ai:three", "no rubric here")
    report = build_nhi_report(n_agents=3, completed=0,
                              assessments=[clean, repaired, invalid],
                              auditor_verdict="FAIL")
    assert report["assessments_valid"] == 2
    assert report["assessments_valid_raw"] == 1
    assert report["assessments_repaired"] == 1
    assert report["assessments_invalid"] == 1
    assert report["assessment_repairs"] == {"free_text_truncated": 1}
    assert "raw 1 + repaired 1" in render_nhi_report(report)


# -- call-log mission evidence (#3440 ask 2) --------------------------------

def _store(agent: str, title: str, *, ok: bool = True, memory_id: str = "",
           **args: object) -> dict[str, object]:
    return {"agent_id": agent, "tool": "store", "ok": ok,
            "args": {"title": title, **args},
            "summary": f"{{'id': '{memory_id}'}}" if memory_id else "{}"}


_A = "ai:agent-a"
_ID1 = "11111111-1111-4111-8111-111111111111"
_ID2 = "22222222-2222-4222-8222-222222222222"


def test_mission_evidence_sees_a_summary_the_strict_flag_misses() -> None:
    """The observed failure: a titled summary written WITHOUT the shared namespace."""
    entries = [
        _store(_A, "Fact 1", content="a", memory_id=_ID1),
        _store(_A, "Fact 2", content="b", memory_id=_ID2),
        _store(_A, f"mission-summary-{_A}", content=f"builds on {_ID1} and {_ID2}",
               scope="collective", tier="long"),
    ]
    found = mission_evidence(entries, shared_namespace="m2-shared")[_A]
    assert found["summary_stored"] is True
    assert found["summary_count"] == 1
    # ... and the audit still says the mission requirement was NOT met.
    assert found["summary_in_shared_namespace"] is False
    assert found["facts_stored"] == 2


def test_mission_evidence_accepts_an_untitled_consolidating_summary() -> None:
    entries = [
        _store(_A, "Fact 1", content="a", memory_id=_ID1),
        _store(_A, "Fact 2", content="b", memory_id=_ID2),
        _store(_A, "Run wrap-up", content=f"folds {_ID1} + {_ID2}", tier="long",
               namespace="m2-shared", scope="collective"),
    ]
    found = mission_evidence(entries, shared_namespace="m2-shared")[_A]
    assert found["summary_stored"] and found["summary_in_shared_namespace"]
    assert found["facts_stored"] == 2


def test_mission_evidence_never_counts_harness_or_failed_writes() -> None:
    entries = [
        # Harness-written rows dispatched through the agent's own identity.
        _store(_A, "consensus-vote-abc-0", content="the sky is blue", scope="collective"),
        _store(_A, f"nhi-audit-{_A}-abc", content=f"cites {_ID1} {_ID2}", scope="collective"),
        _store(_A, "AI-NHI swarm assessment abc", content="verdict", scope="collective"),
        # A refused write is not evidence of anything having been stored.
        _store(_A, f"mission-summary-{_A}", ok=False, content="x", scope="collective"),
        {"agent_id": _A, "tool": "consolidate", "ok": False,
         "args": {"ids": [_ID1], "title": "x"}, "summary": "boom"},
    ]
    assert mission_evidence(entries, shared_namespace="m2-shared") == {
        _A: {"summary_stored": False, "summary_count": 0,
             "summary_in_shared_namespace": False, "lineage_proved": False,
             "facts_stored": 0}}


def test_mission_evidence_lineage_from_consolidate_or_derives_from() -> None:
    consolidate = [{"agent_id": _A, "tool": "consolidate", "ok": True,
                    "args": {"ids": [_ID1, _ID2], "title": "phase-1"}, "summary": "{}"}]
    link = [{"agent_id": _A, "tool": "link", "ok": True,
             "args": {"source_id": _ID2, "target_id": _ID1, "relation": "derives_from"},
             "summary": "{}"}]
    unrelated = [{"agent_id": _A, "tool": "link", "ok": True,
                  "args": {"source_id": _ID2, "target_id": _ID1, "relation": "relates_to"},
                  "summary": "{}"}]
    assert mission_evidence(consolidate)[_A]["lineage_proved"] is True
    assert mission_evidence(link)[_A]["lineage_proved"] is True
    assert mission_evidence(unrelated)[_A]["lineage_proved"] is False


def test_origin_stamp_excludes_untitled_harness_dispatches() -> None:
    """What the title filter cannot catch: an untitled scripted derives_from link."""
    sweep_link = {"agent_id": _A, "tool": "link", "ok": True, "origin": "harness",
                  "args": {"source_id": _ID2, "target_id": _ID1,
                           "relation": "derives_from"}, "summary": "{}"}
    assert mission_evidence([sweep_link])[_A]["lineage_proved"] is False
    agent_link = {**sweep_link, "origin": "agent"}
    assert mission_evidence([agent_link])[_A]["lineage_proved"] is True


@pytest.mark.asyncio
async def test_harness_dispatches_stamps_the_call_log(tmp_path) -> None:
    from swarm.audit import CallLog, harness_dispatches, record_dispatch, set_call_log

    outcome = SimpleNamespace(ok=True, fail_closed=False, summary="{}")
    log = CallLog(tmp_path)
    set_call_log(log)
    try:
        record_dispatch(_A, "store", {"title": "Fact 1"}, outcome)
        with harness_dispatches():
            record_dispatch(_A, "store", {"title": "consensus-vote-1"}, outcome)
        record_dispatch(_A, "store", {"title": "Fact 2"}, outcome)
    finally:
        set_call_log(None)
    assert [entry["origin"] for entry in log.entries] == ["agent", "harness", "agent"]
    written = [json.loads(line) for line in
               (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [entry["origin"] for entry in written] == ["agent", "harness", "agent"]


# -- replay of the real 256-agent journal ------------------------------------

@pytest.mark.skipif(not (_JOURNAL / "assessments.json").exists(),
                    reason=f"journal fixture not present: {_JOURNAL}")
def test_journal_invalid_rubrics_are_now_repairable() -> None:
    stored = json.loads((_JOURNAL / "assessments.json").read_text(encoding="utf-8"))
    invalid = [a for a in stored if a["assessment_invalid"]]
    length_refusals = [a for a in invalid
                       if a["error"] == "free_text must be a string of at most 600 characters"]
    # The run as it happened: 156/256 invalid, 95 of them for free-text length.
    assert (len(stored), len(invalid), len(length_refusals)) == (256, 156, 95)

    # A rubric of exactly that shape (complete, over-long prose) now survives.
    over_long = parse_assessment("ai:one", json.dumps(_rubric(free_text="q" * 1200)))
    assert not over_long.assessment_invalid and over_long.repaired

    # Every rubric that WAS valid still parses valid, unchanged and un-repaired.
    for item in stored:
        if item["assessment_invalid"]:
            continue
        fields = {k: item[k] for k in
                  ("recall_usefulness", "latency_acceptable", "failures_encountered",
                   "isolation_respected", "would_rely_on_it", "free_text")}
        again = parse_assessment(item["agent_id"], json.dumps(fields))
        assert not again.assessment_invalid and not again.repaired
        assert again.recall_usefulness == item["recall_usefulness"]


@pytest.mark.skipif(not (_JOURNAL / "calls.jsonl").exists(),
                    reason=f"journal fixture not present: {_JOURNAL}")
def test_journal_call_log_explains_the_zero_percent_completion() -> None:
    entries = [json.loads(line) for line in
               (_JOURNAL / "calls.jsonl").read_text(encoding="utf-8").splitlines() if line]
    report = json.loads((_JOURNAL / "nhi-audit.json").read_text(encoding="utf-8"))
    found = mission_evidence(entries, shared_namespace="m2-shared")

    summaries = sum(item["summary_stored"] for item in found.values())
    in_shared = sum(item["summary_in_shared_namespace"] for item in found.values())
    lineage = sum(item["lineage_proved"] for item in found.values())
    facts = sum(item["facts_stored"] for item in found.values())

    # The run reported 0 summaries; the call log shows 61 agents stored one.
    assert report["mission_partial"]["summary_stored"] == 0
    assert summaries == 61
    # ... and none reached the shared namespace, which is WHY completion is 0%.
    assert in_shared == 0
    assert report["mission_completion_rate"] == 0.0
    # Lineage matches the strict counter, plus exactly one legacy artifact: this
    # journal predates the `origin` stamp, and `full_surface_sweep` dispatches an
    # UNTITLED derives_from link as agents[0], which no title filter can exclude.
    # New runs carry origin=harness on that link (see the test below).
    assert report["mission_partial"]["lineage_proved"] == 120
    assert lineage == 121
    assert sum(1 for entry in entries if "origin" in entry) == 0
    # The summaries the strict accounting mis-filed as plain facts are exactly
    # the difference (595 + 61).
    assert facts == 595
    assert facts + summaries == report["mission_partial"]["facts_stored_total"] == 656


def test_mission_progress_carries_both_views_into_the_report() -> None:
    """End-to-end wiring: strict flags AND call-log evidence reach the report."""
    from swarm.__main__ import _mission_partial
    from swarm.audit import CallLog
    from swarm.orchestrator import Swarm

    agent = SimpleNamespace(
        identity=SimpleNamespace(agent_id=_A),
        mission_summary_id=None, mission_summary_count=0,
        mission_lineage_proved=False, mission_memory_ids=[_ID1, _ID2],
        mission_summary_cites_sources=False)
    log = CallLog(None)
    log.entries = [
        _store(_A, "Fact 1", content="a", memory_id=_ID1),
        _store(_A, "Fact 2", content="b", memory_id=_ID2),
        _store(_A, f"mission-summary-{_A}", content=f"{_ID1} + {_ID2}",
               scope="collective", tier="long"),
    ]
    swarm = SimpleNamespace(agents=[agent], call_log=log, shared_namespace="m2-shared")
    progress = Swarm.mission_progress(swarm)[_A]
    # Strict: nothing completed (the summary never reached the shared namespace).
    assert progress["summary_stored"] is False
    # Evidence: the summary exists, and the report says where it went wrong.
    assert progress["summary_stored_evidence"] is True
    assert progress["summary_in_shared_namespace"] is False
    assert progress["facts_stored_evidence"] == 2

    report = build_nhi_report(n_agents=1, completed=0, assessments=[],
                              auditor_verdict="FAIL")
    report["mission_partial"] = _mission_partial({_A: progress})
    rendered = render_nhi_report(report)
    assert "mission partial: summaries 0" in rendered
    assert "mission evidence (call log): summaries 1 · in shared ns 0" in rendered
