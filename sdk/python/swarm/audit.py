# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Part-2 NHI audit artifacts: exhaustive calls, rubrics, and reports."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    """Return an RFC3339 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


_SECRET = re.compile(r"(api[-_]?key|authorization|token|secret|password|signature|private)", re.I)


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact credential-shaped fields before durable logging."""
    if _SECRET.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class CallLog:
    """Append-only JSONL log for every dispatcher outcome."""

    def __init__(self, journal_dir: str | Path | None) -> None:
        self.path = Path(journal_dir) / "calls.jsonl" if journal_dir else None
        self.entries: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    def append(self, *, agent_id: str, tool: str, args: dict[str, Any], outcome: Any,
               module: str | None = None) -> None:
        entry = {
            "agent_id": agent_id,
            "module": module,  # daemon base URL the call went to (multi-module runs)
            "tool": tool,
            "args": redact(args),
            "ok": bool(outcome.ok),
            "fail_closed": bool(outcome.fail_closed),
            "summary": outcome.summary,
            "ts": utc_now(),
        }
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True, default=str) + "\n")

    def reconcile(self, coverage: Any) -> dict[str, Any]:
        """Assert coverage invocation counts equal logged dispatch counts."""
        logged = Counter(entry["tool"] for entry in self.entries)
        covered = {name: item.invocations for name, item in coverage.tools.items() if item.invocations}
        names = set(logged) | set(covered)
        diff = {
            name: {"calls": logged.get(name, 0), "coverage": covered.get(name, 0)}
            for name in sorted(names)
            if logged.get(name, 0) != covered.get(name, 0)
        }
        result = {"ok": not diff, "logged": sum(logged.values()),
                  "coverage": sum(covered.values()), "diff": diff}
        # Never raise: a mismatch is EVIDENCE for the auditor and a non-zero
        # exit for the run, not an abort that would lose the artifacts.
        print("call-log reconcile: " + json.dumps(result, sort_keys=True))
        return result


_active_call_log: CallLog | None = None


def set_call_log(log: CallLog | None) -> None:
    global _active_call_log
    _active_call_log = log


def record_dispatch(agent_id: str, tool: str, args: dict[str, Any], outcome: Any,
                    module: str | None = None) -> None:
    if _active_call_log is not None:
        _active_call_log.append(agent_id=agent_id, tool=tool, args=args, outcome=outcome, module=module)


@dataclass(frozen=True)
class AgentAssessment:
    agent_id: str
    recall_usefulness: int | None
    latency_acceptable: bool | None
    failures_encountered: list[list[str]]
    isolation_respected: bool | None
    would_rely_on_it: bool | None
    free_text: str
    assessment_invalid: bool = False
    error: str | None = None


def parse_assessment(agent_id: str, raw: str) -> AgentAssessment:
    """Strictly parse the fixed per-agent rubric; malformed input is invalid."""
    try:
        value = json.loads(raw)
        required = {"recall_usefulness", "latency_acceptable", "failures_encountered",
                    "isolation_respected", "would_rely_on_it", "free_text"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("rubric must contain exactly the six required fields")
        score = value["recall_usefulness"]
        failures = value["failures_encountered"]
        if type(score) is not int or not 1 <= score <= 5:
            raise ValueError("recall_usefulness must be an integer from 1 to 5")
        for field in ("latency_acceptable", "isolation_respected", "would_rely_on_it"):
            if type(value[field]) is not bool:
                raise ValueError(f"{field} must be boolean")
        if (not isinstance(failures, list) or
                any(not isinstance(x, list) or len(x) != 2 or
                    any(not isinstance(y, str) for y in x) for x in failures)):
            raise ValueError("failures_encountered must be [[tool, what], ...]")
        if not isinstance(value["free_text"], str) or len(value["free_text"]) > 600:
            raise ValueError("free_text must be a string of at most 600 characters")
        return AgentAssessment(agent_id=agent_id, **value)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return AgentAssessment(agent_id, None, None, [], None, None, "",
                               assessment_invalid=True, error=str(exc))


def build_nhi_report(*, n_agents: int, completed: int,
                     assessments: list[AgentAssessment], auditor_verdict: str,
                     negative_evidence: list[dict[str, Any]] | None = None,
                     model: str | None = None, model_override_reason: str | None = None,
                     ) -> dict[str, Any]:
    valid = [a for a in assessments if not a.assessment_invalid]
    failures = Counter(f"{tool}: {what}" for a in valid for tool, what in a.failures_encountered)
    return {
        "model": model,
        "model_override_reason": model_override_reason,
        "generated_at": utc_now(),
        "n_agents": n_agents,
        "mission_completed": completed,
        "mission_completion_rate": completed / n_agents if n_agents else 0.0,
        "assessments_valid": len(valid),
        "assessments_invalid": len(assessments) - len(valid),
        "recall_usefulness_mean": (
            sum(a.recall_usefulness or 0 for a in valid) / len(valid) if valid else None
        ),
        "latency_acceptable_count": sum(a.latency_acceptable is True for a in valid),
        "isolation_respected_count": sum(a.isolation_respected is True for a in valid),
        "would_rely_on_it_count": sum(a.would_rely_on_it is True for a in valid),
        "top_failures": [text for text, _count in failures.most_common(3)],
        "quotes": [{"agent_id": a.agent_id, "free_text": a.free_text} for a in valid],
        "auditor_verdict": auditor_verdict,
        "negative_evidence": negative_evidence or [],
    }


def render_nhi_report(report: dict[str, Any]) -> str:
    lines = ["NHI AUDIT", "=" * 60,
             f"model: {report.get('model')}" + (f"  (override: {report['model_override_reason']})" if report.get('model_override_reason') else ""),
             f"agents: {report['n_agents']}",
             f"mission completion rate: {report['mission_completion_rate']:.1%}",
             f"valid/invalid rubrics: {report['assessments_valid']}/{report['assessments_invalid']}",
             f"recall usefulness mean: {report['recall_usefulness_mean']}",
             f"latency acceptable: {report['latency_acceptable_count']}",
             f"isolation respected: {report['isolation_respected_count']}",
             f"would rely on it: {report['would_rely_on_it_count']}",
             "top failures: " + ("; ".join(report["top_failures"]) or "none")]
    if report.get("mission_partial"):
        mp = report["mission_partial"]
        lines.append(f"mission partial: summaries {mp['summary_stored']} · lineage {mp['lineage_proved']} · facts {mp['facts_stored_total']}")
    lines.extend(f"quote [{q['agent_id']}]: {q['free_text']}" for q in report["quotes"])
    lines.append("auditor verdict: " + report["auditor_verdict"])
    return "\n".join(lines)


def write_audit_artifacts(directory: str | Path, assessments: list[AgentAssessment],
                          report: dict[str, Any]) -> None:
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "assessments.json").write_text(
        json.dumps([asdict(a) for a in assessments], indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (destination / "nhi-audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


__all__ = ["AgentAssessment", "CallLog", "build_nhi_report", "parse_assessment",
           "record_dispatch", "redact", "render_nhi_report", "set_call_log", "utc_now",
           "write_audit_artifacts"]
