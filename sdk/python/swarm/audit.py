# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Part-2 NHI audit artifacts: exhaustive calls, rubrics, and reports."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
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
            # "agent" (the GLM loop chose it) or "harness" (a scripted
            # choreography/probe dispatched it AS the agent). Mission evidence
            # counts only agent-originated work (#3440).
            "origin": _call_origin,
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
#: Origin stamped on every logged dispatch; see :func:`harness_dispatches`.
_call_origin = "agent"


@contextmanager
def harness_dispatches() -> Iterator[None]:
    """Stamp every dispatch inside the block as HARNESS-originated (#3440).

    The scripted choreographies, the authorization probes, and the rubric
    attestations all dispatch AS an agent, so their writes are indistinguishable
    from mission work in the call log — a consensus vote or an untitled
    ``derives_from`` sweep link would otherwise be counted as an agent's own
    lineage. They run strictly AFTER ``Swarm.run()`` has returned, on the one
    orchestrating task, so a module-global marker is unambiguous here.
    """
    global _call_origin
    previous = _call_origin
    _call_origin = "harness"
    try:
        yield
    finally:
        _call_origin = previous


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
    #: True when the reply needed one of the bounded repairs below to parse.
    #: A repaired rubric is USABLE but never silently so: the repair kinds are
    #: recorded per agent and counted separately in the report.
    repaired: bool = False
    repairs: tuple[str, ...] = ()
    #: Verbatim head of the model reply, kept ONLY for repaired/invalid rubrics
    #: so an auditor can see exactly what the strictness reacted to.
    raw_excerpt: str = ""


#: The rubric fields :data:`swarm.choreography._RUBRIC_PROMPT` demands.
_RUBRIC_FIELDS = frozenset({
    "recall_usefulness", "latency_acceptable", "failures_encountered",
    "isolation_respected", "would_rely_on_it", "free_text",
})
#: Hard cap on the rubric's free-text field. Over-long text is TRUNCATED (the
#: prose is commentary, never durable memory data), not thrown away with the
#: five structured judgements that came with it.
FREE_TEXT_LIMIT = 600
#: Excerpt of a repaired/invalid reply retained as evidence.
_RAW_EXCERPT_CHARS = 600
_FENCE_RE = re.compile(r"```[A-Za-z0-9_+-]*\s*(?P<body>.*?)\s*```", re.S)


def _first_json_object(text: str) -> str | None:
    """Return the first balanced ``{...}`` span, ignoring braces inside strings."""
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return None


def _json_candidates(raw: str) -> list[tuple[str, str]]:
    """The verbatim reply first, then bounded repairs, as ``(text, repair)``."""
    candidates: list[tuple[str, str]] = [(raw, "")]
    candidates.extend((match.group("body"), "code_fence_stripped")
                      for match in _FENCE_RE.finditer(raw))
    embedded = _first_json_object(raw)
    if embedded is not None and embedded != raw.strip():
        candidates.append((embedded, "json_extracted"))
    return candidates


def _validate_rubric(value: dict[str, Any], repairs: list[str]) -> dict[str, Any]:
    """Validate the six rubric fields; raise ``ValueError`` on anything unfixable."""
    extra = set(value) - _RUBRIC_FIELDS
    if extra:
        value = {name: item for name, item in value.items() if name in _RUBRIC_FIELDS}
        repairs.append("extra_fields_dropped")
    missing = _RUBRIC_FIELDS - set(value)
    if missing:
        raise ValueError("rubric is missing required fields: " + ", ".join(sorted(missing)))
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
    free_text = value["free_text"]
    if not isinstance(free_text, str):
        raise ValueError("free_text must be a string")
    if len(free_text) > FREE_TEXT_LIMIT:
        value = {**value, "free_text": free_text[:FREE_TEXT_LIMIT]}
        repairs.append("free_text_truncated")
    return value


def parse_assessment(agent_id: str, raw: str) -> AgentAssessment:
    """Parse the fixed per-agent rubric, repairing only PRESENTATION defects.

    Strictness is unchanged for the five structured judgements: a wrong type, an
    out-of-range score, a missing field, or a reply with no JSON object at all is
    still ``assessment_invalid`` — the run never invents an opinion an NHI did
    not state. What IS repaired is packaging the model got wrong around an
    otherwise complete rubric (#3440):

    * a reply wrapped in a ``` code fence, or JSON preceded/followed by prose,
    * unknown extra keys alongside the six required ones,
    * a ``free_text`` longer than :data:`FREE_TEXT_LIMIT` (truncated).

    Every repair is named in :attr:`AgentAssessment.repairs` and counted
    separately by :func:`build_nhi_report`, so a repaired rubric can never be
    mistaken for one the model returned clean.
    """
    text = raw or ""
    repairs: list[str] = []
    value: dict[str, Any] | None = None
    for candidate, repair in _json_candidates(text):
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            value = parsed
            if repair:
                repairs.append(repair)
            break
    if value is None:
        return AgentAssessment(agent_id, None, None, [], None, None, "",
                               assessment_invalid=True,
                               error="no JSON rubric object in the model reply",
                               raw_excerpt=text[:_RAW_EXCERPT_CHARS])
    try:
        fields = _validate_rubric(value, repairs)
    except (ValueError, TypeError) as exc:
        return AgentAssessment(agent_id, None, None, [], None, None, "",
                               assessment_invalid=True, error=str(exc),
                               repairs=tuple(repairs),
                               raw_excerpt=text[:_RAW_EXCERPT_CHARS])
    return AgentAssessment(agent_id=agent_id, **fields, repaired=bool(repairs),
                           repairs=tuple(repairs),
                           raw_excerpt=text[:_RAW_EXCERPT_CHARS] if repairs else "")


#: Titles the HARNESS writes through an agent's own dispatch (choreographies,
#: authorization probes, rubric attestations). They are the harness's evidence,
#: never the agent's mission work, so they are excluded from mission evidence.
HARNESS_TITLE_PREFIXES = (
    "consensus-vote-", "consensus-", "nhi-audit-", "approval-decision-",
    "isolation-canary-", "replay-probe-", "full-surface-", "AI-NHI swarm assessment",
)
_MEMORY_ID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
#: A summary must fold at least this many of the agent's OWN earlier memory ids
#: to count as summary-shaped without carrying the mission title. One citation
#: is a fact referencing an observation; several is a consolidation.
_SUMMARY_MIN_CITATIONS = 2


def _is_harness_title(title: str) -> bool:
    return title.startswith(HARNESS_TITLE_PREFIXES)


def mission_evidence(entries: list[dict[str, Any]], *,
                     shared_namespace: str | None = None) -> dict[str, dict[str, Any]]:
    """Derive per-agent mission progress from the CALL LOG, not from a fixed tag.

    #3440: the in-agent ``summary_stored`` flag only fired when the model both
    titled the summary exactly and named the shared namespace, so a run where
    256 agents wrote summaries into their own namespace reported 0 summaries and
    an unexplainable 0% completion. Evidence here is read back from what was
    actually dispatched, and each signal is reported separately rather than
    collapsed into one pass/fail:

    * ``summary_stored`` — an ``ok`` store titled ``mission-summary-<agent_id>``
      (the mission's own contract) OR a durable store (tier ``long``, or
      collective/team scope, or the shared namespace) whose content cites at
      least :data:`_SUMMARY_MIN_CITATIONS` memory ids the SAME agent stored
      earlier in the run — i.e. a consolidation with derived-from lineage.
    * ``summary_in_shared_namespace`` — of those, whether any actually landed in
      the shared namespace (the part of the mission the agents missed).
    * ``lineage_proved`` — an ``ok`` ``consolidate`` or ``derives_from`` link.
    * ``facts_stored`` — every other ``ok`` agent store.

    Harness-written rows are excluded by their logged ``origin`` (see
    :func:`harness_dispatches`), falling back to
    :data:`HARNESS_TITLE_PREFIXES` for journals written before that field
    existed, so a choreography's consensus vote can never be counted as an
    agent's mission work.
    """
    evidence: dict[str, dict[str, Any]] = {}

    def _for(agent_id: str) -> dict[str, Any]:
        return evidence.setdefault(agent_id, {
            "summary_stored": False, "summary_count": 0,
            "summary_in_shared_namespace": False, "lineage_proved": False,
            "facts_stored": 0, "_ids": [],
        })

    for entry in entries:
        agent_id = str(entry.get("agent_id") or "")
        if not agent_id:
            continue
        item = _for(agent_id)  # every agent in the log gets a row, even an empty one
        # `origin` (#3440) is authoritative when present; journals written before
        # it existed fall back to excluding the harness's own titles, which
        # cannot catch an untitled scripted link — see the tests.
        origin = entry.get("origin")
        args = entry.get("args") if isinstance(entry.get("args"), dict) else {}
        title = str(args.get("title") or "")
        harness = origin != "agent" if origin is not None else _is_harness_title(title)
        if not entry.get("ok") or harness:
            continue
        tool = entry.get("tool")
        if tool in ("consolidate", "link"):
            if tool == "consolidate" or args.get("relation") == "derives_from":
                item["lineage_proved"] = True
            continue
        if tool != "store":
            continue
        content = str(args.get("content") or "")
        cited = {value for value in _MEMORY_ID_RE.findall(content) if value in item["_ids"]}
        durable = (args.get("tier") == "long" or args.get("scope") in ("collective", "team")
                   or (shared_namespace is not None and args.get("namespace") == shared_namespace))
        is_summary = (title == f"mission-summary-{agent_id}"
                      or (durable and len(cited) >= _SUMMARY_MIN_CITATIONS))
        if is_summary:
            item["summary_stored"] = True
            item["summary_count"] += 1
            if shared_namespace is not None and args.get("namespace") == shared_namespace:
                item["summary_in_shared_namespace"] = True
        else:
            item["facts_stored"] += 1
        found = _MEMORY_ID_RE.search(str(entry.get("summary") or ""))
        if found:
            item["_ids"].append(found.group(0))
    for item in evidence.values():
        del item["_ids"]
    return evidence


def build_nhi_report(*, n_agents: int, completed: int,
                     assessments: list[AgentAssessment], auditor_verdict: str,
                     negative_evidence: list[dict[str, Any]] | None = None,
                     model: str | None = None, model_override_reason: str | None = None,
                     ) -> dict[str, Any]:
    valid = [a for a in assessments if not a.assessment_invalid]
    repaired = [a for a in valid if a.repaired]
    repair_kinds = Counter(kind for a in assessments for kind in a.repairs)
    failures = Counter(f"{tool}: {what}" for a in valid for tool, what in a.failures_encountered)
    return {
        "model": model,
        "model_override_reason": model_override_reason,
        "generated_at": utc_now(),
        "n_agents": n_agents,
        "mission_completed": completed,
        "mission_completion_rate": completed / n_agents if n_agents else 0.0,
        "assessments_valid": len(valid),
        # Raw = parsed with ZERO repairs; repaired = usable only after a bounded
        # presentation repair. Both are reported so the strictness stays visible.
        "assessments_valid_raw": len(valid) - len(repaired),
        "assessments_repaired": len(repaired),
        "assessment_repairs": dict(sorted(repair_kinds.items())),
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
             f"valid/invalid rubrics: {report['assessments_valid']}/{report['assessments_invalid']}"
             + f"  (raw {report.get('assessments_valid_raw', report['assessments_valid'])}"
               f" + repaired {report.get('assessments_repaired', 0)})",
             f"recall usefulness mean: {report['recall_usefulness_mean']}",
             f"latency acceptable: {report['latency_acceptable_count']}",
             f"isolation respected: {report['isolation_respected_count']}",
             f"would rely on it: {report['would_rely_on_it_count']}",
             "top failures: " + ("; ".join(report["top_failures"]) or "none")]
    if report.get("mission_partial"):
        mp = report["mission_partial"]
        lines.append(f"mission partial: summaries {mp['summary_stored']} · lineage {mp['lineage_proved']} · facts {mp['facts_stored_total']}")
        if "summary_stored_evidence" in mp:
            lines.append(
                f"mission evidence (call log): summaries {mp['summary_stored_evidence']}"
                f" · in shared ns {mp['summary_in_shared_namespace']}"
                f" · lineage {mp['lineage_proved_evidence']}"
                f" · facts {mp['facts_stored_evidence']}")
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


__all__ = ["FREE_TEXT_LIMIT", "HARNESS_TITLE_PREFIXES", "AgentAssessment", "CallLog",
           "build_nhi_report", "harness_dispatches", "mission_evidence", "parse_assessment",
           "record_dispatch", "redact", "render_nhi_report", "set_call_log", "utc_now",
           "write_audit_artifacts"]
