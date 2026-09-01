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

from swarm.choreography import run_all
from swarm.config import ConfigError, SwarmConfig
from swarm.coverage import CoverageTracker
from swarm.openrouter import OpenRouterClient
from swarm.orchestrator import Swarm


def _write_journals(swarm: Swarm, journal_dir: str | None = None) -> None:
    """Write the current run's per-agent step records as JSON Lines."""
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
        await swarm.provision()
        await swarm.run()
        _write_journals(swarm)
        for result in await run_all(swarm):
            marker = "PASS" if result.ok else "FAIL"
            print(f"[choreography] {result.name}: {marker} ({result.detail})")
    finally:
        await swarm.aclose()

    print()
    print(coverage.matrix())
    return 0 if coverage.is_full() else 1


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
