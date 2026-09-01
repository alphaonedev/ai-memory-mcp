# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""``python -m swarm`` — run the acceptance swarm from the environment.

Reads :class:`swarm.config.SwarmConfig` from the environment, runs the live
GLM-driven population plus the scripted choreographies, prints the coverage
matrix, and exits non-zero if the manifest was not fully covered.

Requires ``OPENROUTER_API_KEY`` and a reachable daemon (see ``README.md``).
This entry point does no work at import time, so ``python -m py_compile`` and
``import swarm`` stay side-effect-free.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from swarm.audit import build_nhi_report, render_nhi_report, write_audit_artifacts
from swarm.choreography import (collect_assessments, negative_authorization_evidence,
                                nhi_assessment, run_all)
from swarm.config import ConfigError, SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.openrouter import AccountSnapshot, OpenRouterClient
from swarm.orchestrator import Swarm


def _write_journals(
    swarm: Swarm, journal_dir: str | None = None, *, assessment: str | None = None
) -> None:
    """Write per-agent JSONL records and, when present, the NHI assessment."""
    raw_dir = journal_dir if journal_dir is not None else os.environ.get("SWARM_JOURNAL_DIR")
    if not raw_dir:
        return
    destination = Path(raw_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for agent in swarm.agents:
        path = destination / f"{agent.identity.agent_id}.jsonl"
        with path.open("w", encoding="utf-8") as stream:
            for record in agent.journal:
                stream.write(json.dumps(asdict(record), sort_keys=True) + "\n")
    if assessment is not None:
        (destination / "nhi-assessment.md").write_text(assessment + "\n", encoding="utf-8")


def _write_usage(
    coverage: CoverageTracker,
    before: AccountSnapshot | None,
    after: AccountSnapshot | None,
    model: str = "z-ai/glm-5.3-flash",
    path: str | None = None,
) -> Path:
    """Write machine-readable per-agent and account-level OpenRouter usage."""
    destination = Path(path or os.environ.get("SWARM_USAGE_PATH", "usage.json"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    before_data = asdict(before) if before else None
    after_data = asdict(after) if after else None
    delta = (
        {name: after_data[name] - before_data[name] for name in before_data}
        if before_data and after_data else None
    )
    payload = {
        "schema_version": 1,
        "model": model,
        "model_override_reason": os.environ.get("SWARM_MODEL_OVERRIDE_REASON") or None,
        "account_usd": {"before": before_data, "after": after_data, "delta": delta},
        "decide_latency_ms": coverage.model_latency_summary(),
        "completions": {
            "by_agent": coverage.model_usage,
            "total": coverage.model_usage_totals(),
        },
    }
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return destination



async def _snapshot(model: OpenRouterClient) -> AccountSnapshot | None:
    """Account usage snapshot, FAIL-SOFT: a usage-endpoint error never fails a run."""
    try:
        return await model.account_snapshot()
    except Exception as exc:  # noqa: BLE001 - accounting must not abort acceptance
        print(f"[usage] account snapshot unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None


def _usage_block(
    coverage: CoverageTracker,
    before: AccountSnapshot | None,
    after: AccountSnapshot | None,
    path: Path,
) -> str:
    """Human-readable AI MODEL USAGE summary printed at the end of a run."""
    t = coverage.model_usage_totals()
    delta = (after.usage - before.usage) if (before and after) else None
    lat = coverage.model_latency_summary()
    lines = ["", "AI MODEL USAGE (OpenRouter)", "-" * 60,
             f"completions {t['requests']}  prompt {t['prompt_tokens']}  completion {t['completion_tokens']}  total {t['total_tokens']} tokens",
             f"generation cost ${t['cost_usd']:.4f}  account delta {'$%.4f' % delta if delta is not None else 'n/a'} (includes daemon embed/LLM calls)",
             f"decide latency ms mean {lat['mean_ms']}  p95 {lat['p95_ms']}  n {lat['n']}",
             f"usage.json -> {path}"]
    return "\n".join(lines)

def _auditor_verdict(assessment: str | None) -> str:
    """The auditor's FINAL verdict: the last PASS/FAIL token in the report.

    Reports routinely contain both words ("end with PASS or FAIL"), so a naive
    substring test would read every FAIL report as PASS.
    """
    if not assessment:
        return "UNKNOWN"
    text = assessment.upper()
    tail = text[text.rfind("VERDICT"):] if "VERDICT" in text else text
    last_pass, last_fail = tail.rfind("PASS"), tail.rfind("FAIL")
    if last_pass < 0 and last_fail < 0:
        return "UNKNOWN"
    return "PASS" if last_pass > last_fail else "FAIL"


async def _main() -> int:
    config = SwarmConfig.from_env()
    config.require_live()
    assert config.openrouter_api_key is not None
    coverage = CoverageTracker()
    # Skills plane is sqlite-only; a postgres-backed acceptance run documents
    # its fail-closed 501s here (harmless on sqlite where they never fire).
    model = OpenRouterClient(
        api_key=config.openrouter_api_key,
        model_slug=config.model_slug,
        base_url=config.openrouter_base_url,
        timeout=config.request_timeout_secs,
    )
    swarm = Swarm(config, coverage=coverage)
    swarm.build_agents(model=model)
    try:
        usage_before = await _snapshot(model)
        try:
            await swarm.provision()
            await swarm.run()
            negative_evidence = await negative_authorization_evidence(swarm)
            results = await run_all(swarm)
            assessments = await collect_assessments(swarm)
            reconcile_result = swarm.call_log.reconcile(coverage)
            assessment_result, assessment = await nhi_assessment(
                swarm, results, reconcile_result=reconcile_result,
                negative_evidence=negative_evidence)
            results.append(assessment_result)
            final_reconcile = swarm.call_log.reconcile(coverage)
            _write_journals(swarm, assessment=assessment)
            for result in results:
                marker = "PASS" if result.ok else "FAIL"
                print(f"[choreography] {result.name}: {marker} ({result.detail})")
            completion = swarm.mission_completion()
            verdict = _auditor_verdict(assessment)
            report = build_nhi_report(
                n_agents=len(swarm.agents), completed=sum(completion.values()),
                assessments=assessments, auditor_verdict=verdict,
                negative_evidence=negative_evidence,
                model=config.model_slug, model_override_reason=config.model_override_reason)
            report["call_log_reconcile"] = final_reconcile
            report["mission_progress"] = swarm.mission_progress()
            prog = report["mission_progress"].values()
            report["mission_partial"] = {
                "summary_stored": sum(p["summary_stored"] for p in prog),
                "lineage_proved": sum(p["lineage_proved"] for p in prog),
                "facts_stored_total": sum(p["facts_stored"] for p in prog),
            }
            print("\n" + render_nhi_report(report))
            journal_dir = os.environ.get("SWARM_JOURNAL_DIR")
            if journal_dir:
                write_audit_artifacts(journal_dir, assessments, report)
        finally:
            usage_after = await _snapshot(model)
            usage_path = _write_usage(
                coverage, usage_before, usage_after, model=config.model_slug
            )
            print(_usage_block(coverage, usage_before, usage_after, usage_path))
    finally:
        await swarm.aclose()

    print()
    print(coverage.matrix())
    negative_ok = all(item.get("refused") is True for item in negative_evidence)
    reconciled = bool(final_reconcile.get("ok"))
    return 0 if (coverage.is_full() and all(result.ok for result in results)
                 and negative_ok and reconciled) else 1


def main() -> None:
    try:
        code = asyncio.run(_main())
    except ConfigError as exc:
        # Fail closed on misconfiguration with a clean, actionable message.
        print(f"swarm: refusing to launch — {exc}", file=sys.stderr)
        code = 2
    raise SystemExit(code)


if __name__ == "__main__":
    main()
