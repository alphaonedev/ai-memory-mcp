# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tool-coverage accounting for the acceptance swarm.

The swarm's job is to PROVE that every ai-memory tool the driver can reach was
exercised at least once against a live daemon. This module:

* builds a manifest from :data:`swarm.toolset.TOOL_SPECS` (the SSOT),
* cross-checks that manifest against the daemon's live
  ``GET /api/v1/tools/list`` and ``GET /api/v1/capabilities`` so a tool the
  daemon exposes but the driver forgot to wrap is surfaced as a GAP,
* tallies every dispatched :class:`swarm.toolset.ToolOutcome`, and
* renders a coverage matrix + a pass/fail verdict.

A tool counts as COVERED when it was invoked >= 1 time and either succeeded or
produced a DOCUMENTED fail-closed outcome (an intentional refusal the operator
recorded as expected for this backend, e.g. skills on postgres). A tool that
was never invoked, or only ever crashed unexpectedly, is a coverage FAILURE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from typing import Any

from swarm.toolset import TOOL_SPECS, ToolOutcome, ToolSpec


@dataclass
class ToolCoverage:
    """Running tally for one tool."""

    spec: ToolSpec
    invocations: int = 0
    successes: int = 0
    fail_closed: int = 0
    unexpected_failures: int = 0
    last_summary: str = ""
    failure_summaries: deque[str] = field(default_factory=lambda: deque(maxlen=5))

    @property
    def covered(self) -> bool:
        """Covered = at least one success, OR only documented fail-closed."""
        if self.successes > 0:
            return True
        return self.invocations > 0 and self.unexpected_failures == 0 and self.fail_closed > 0


@dataclass
class CoverageTracker:
    """Aggregates outcomes across the whole swarm run.

    A single tracker is shared by every agent; ``record`` is called after each
    dispatched tool. It holds no daemon handle and does no I/O — safe to share
    across asyncio tasks (single-threaded event loop, no re-entrancy).
    """

    tools: dict[str, ToolCoverage] = field(default_factory=dict)
    documented_fail_closed: set[str] = field(default_factory=set)
    model_usage: dict[str, dict[str, float | int]] = field(default_factory=dict)
    model_latencies_ms: list[float] = field(default_factory=list)
    #: Wall-clock seconds per named run phase (e.g. "assessments"), so a long
    #: tail after the mission is visible in the artifacts, not just in a log.
    phase_secs: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tools:
            self.tools = {s.name: ToolCoverage(spec=s) for s in TOOL_SPECS}

    def record(self, outcome: ToolOutcome) -> None:
        """Fold one dispatched tool outcome into the tally."""
        cov = self.tools.get(outcome.name)
        if cov is None:  # a tool not in the manifest was somehow dispatched
            spec = _synthetic_spec(outcome.name)
            cov = ToolCoverage(spec=spec)
            self.tools[outcome.name] = cov
        cov.invocations += 1
        cov.last_summary = outcome.summary
        if outcome.ok:
            cov.successes += 1
        elif outcome.name in self.documented_fail_closed:
            cov.fail_closed += 1
        else:
            cov.unexpected_failures += 1
        if not outcome.ok:
            cov.failure_summaries.append(outcome.summary)

    def mark_documented_fail_closed(self, *names: str) -> None:
        """Record that a fail-closed outcome for ``names`` is EXPECTED.

        Use for backend-specific gaps the operator accepts — e.g. the skills
        plane returning 501 on a postgres daemon. Without this, a fail-closed
        outcome counts as an unexpected failure (coverage gap), which is the
        safe default.
        """
        self.documented_fail_closed.update(names)

    def record_phase(self, name: str, seconds: float) -> None:
        """Record (accumulate) the wall-clock a named run phase took."""
        self.phase_secs[name] = round(self.phase_secs.get(name, 0.0) + float(seconds), 3)

    def record_model_usage(
        self, agent_id: str, raw_usage: Any, latency_ms: float | None = None
    ) -> None:
        """Aggregate one OpenRouter completion's token, USD and latency accounting."""
        usage = raw_usage if isinstance(raw_usage, dict) else {}
        if latency_ms is not None:
            self.model_latencies_ms.append(float(latency_ms))
        totals = self.model_usage.setdefault(
            agent_id,
            {
                "requests": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
            },
        )
        totals["requests"] += 1
        for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(name, 0)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals[name] += int(value)
        cost = usage.get("cost", 0.0)
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            totals["cost_usd"] += float(cost)

    def model_latency_summary(self) -> dict[str, float | int | None]:
        """mean/p95 decide latency over the run (None when nothing was timed)."""
        xs = sorted(self.model_latencies_ms)
        if not xs:
            return {"n": 0, "mean_ms": None, "p95_ms": None}
        p95 = xs[max(0, min(len(xs) - 1, round(0.95 * len(xs)) - 1))]
        return {"n": len(xs), "mean_ms": round(sum(xs) / len(xs), 1), "p95_ms": round(p95, 1)}

    def model_usage_totals(self) -> dict[str, float | int]:
        """Sum the per-agent completion counters for the usage artifact."""
        total: dict[str, float | int] = {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
        }
        for usage in self.model_usage.values():
            for name, value in usage.items():
                total[name] += value
        return total

    # -- verdict -----------------------------------------------------------
    def uncovered(self) -> list[str]:
        """Names of manifest tools not yet covered, in manifest order."""
        return [name for name, cov in self.tools.items() if not cov.covered]

    def is_full(self) -> bool:
        return not self.uncovered()

    def assert_full(self) -> None:
        """Raise :class:`CoverageError` unless every manifest tool is covered."""
        gaps = self.uncovered()
        if gaps:
            raise CoverageError(f"{len(gaps)} tool(s) not covered: {', '.join(gaps)}")

    # -- reconciliation with the live daemon -------------------------------
    def reconcile_tools_list(self, tools_list: Any) -> ReconcileReport:
        """Compare the manifest with ``GET /api/v1/tools/list``.

        Returns a report of tools the daemon advertises that the driver does
        NOT wrap (``daemon_only``) and tools the driver wraps that the daemon
        does not advertise (``driver_only``). ``daemon_only`` is the important
        one: it is the surface the swarm cannot yet prove.
        """
        advertised = _extract_tool_names(tools_list)
        # tools/list uses MCP names (memory_*); the driver's HTTP names differ,
        # so reconciliation is advisory — reported, not asserted.
        driver = set(self.tools)
        return ReconcileReport(
            advertised=advertised,
            driver=driver,
            daemon_only=sorted(advertised - _mcp_aliases(driver)),
            driver_only=sorted(driver),
        )

    # -- rendering ---------------------------------------------------------
    def matrix(self) -> str:
        """A human-readable coverage matrix."""
        width = max((len(n) for n in self.tools), default=4)
        lines = [
            "ai-memory swarm — tool coverage matrix",
            "=" * 60,
            f"{'TOOL':<{width}}  {'KIND':<6} {'SRC':<12} {'INV':>4} {'OK':>3} {'FC':>3}  COVERED",
            "-" * 60,
        ]
        for name, cov in self.tools.items():
            mark = "yes" if cov.covered else "NO"
            lines.append(
                f"{name:<{width}}  {cov.spec.kind:<6} {cov.spec.source:<12} "
                f"{cov.invocations:>4} {cov.successes:>3} {cov.fail_closed:>3}  {mark}"
            )
        covered = sum(1 for c in self.tools.values() if c.covered)
        lines += [
            "-" * 60,
            f"covered {covered}/{len(self.tools)} tools; "
            f"verdict: {'PASS' if self.is_full() else 'FAIL'}",
        ]
        if not self.is_full():
            lines.append("uncovered: " + ", ".join(self.uncovered()))
        failures = [(name, summary) for name, cov in self.tools.items()
                    for summary in cov.failure_summaries]
        if failures:
            lines += ["", "FAILURES", "-" * 60]
            lines.extend(f"{name}: {summary}" for name, summary in failures)
        return "\n".join(lines)


@dataclass(frozen=True)
class ReconcileReport:
    """Advisory diff between the driver manifest and the daemon's tool list."""

    advertised: set[str]
    driver: set[str]
    daemon_only: list[str]
    driver_only: list[str]


class CoverageError(AssertionError):
    """Raised when the swarm did not cover the full manifest."""


def manifest() -> list[dict[str, str]]:
    """The tool manifest as plain dicts (for logging / JSON dumps)."""
    return [
        {
            "name": s.name,
            "kind": s.kind,
            "http_method": s.http_method,
            "path": s.path,
            "source": s.source,
        }
        for s in TOOL_SPECS
    ]


def _extract_tool_names(tools_list: Any) -> set[str]:
    if isinstance(tools_list, dict):
        tools = tools_list.get("tools", [])
    else:
        tools = tools_list or []
    names: set[str] = set()
    for t in tools:
        if isinstance(t, dict) and t.get("name"):
            names.add(str(t["name"]))
        elif isinstance(t, str):
            names.add(t)
    return names


def _mcp_aliases(driver_names: set[str]) -> set[str]:
    """Best-effort ``memory_*`` aliases for the driver's HTTP tool names.

    Reconciliation against MCP-named ``tools/list`` is advisory, so this only
    needs to catch the obvious 1:1 renames.
    """
    alias = set()
    for name in driver_names:
        alias.add(name)
        alias.add(f"memory_{name}")
    return alias


def _synthetic_spec(name: str) -> ToolSpec:
    async def _noop(_c: Any, _i: Any, _a: Any) -> Any:  # pragma: no cover - never dispatched
        return None

    return ToolSpec(name, "read", "GET", "?", "unknown", "(not in manifest)", {}, _noop)


__all__ = [
    "CoverageError",
    "CoverageTracker",
    "ReconcileReport",
    "ToolCoverage",
    "manifest",
]
