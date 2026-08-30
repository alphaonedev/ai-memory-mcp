# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""GLM-5.3-Flash acceptance swarm — TEST-ONLY driver for ai-memory.

Not shipped in the ``ai-memory-mcp`` wheel. Stands up N lightweight
GLM-5.3-Flash agents (via OpenRouter) that drive a compiled ai-memory daemon
over its HTTP tool surface to verify the feature/tool surface end to end:
attested writes, cross-agent isolation, coordination signals, consolidation,
reflection, and replay-guard — with a coverage matrix proving every drivable
tool was exercised.

Install the extra deps with ``pip install -e ".[swarm]"`` from ``sdk/python``.
See ``swarm/README.md`` for the full run recipe (needs ``OPENROUTER_API_KEY``
and a running daemon).
"""

from __future__ import annotations

from swarm.agent import SwarmAgent
from swarm.choreography import ScenarioResult, run_all
from swarm.config import MODEL_ID, ConfigError, SwarmConfig
from swarm.coverage import CoverageError, CoverageTracker, manifest
from swarm.orchestrator import Swarm, run_swarm

__all__ = [
    "MODEL_ID",
    "ConfigError",
    "CoverageError",
    "CoverageTracker",
    "ScenarioResult",
    "Swarm",
    "SwarmAgent",
    "SwarmConfig",
    "manifest",
    "run_all",
    "run_swarm",
]
