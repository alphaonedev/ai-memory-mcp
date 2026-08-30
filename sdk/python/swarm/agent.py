# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""``SwarmAgent`` — one GLM-5.3-Flash-driven ai-memory agent.

Each agent owns:

* an :class:`ai_memory.AsyncAiMemoryClient` bound to one daemon URL, with its
  ``X-Agent-Id`` header set to the agent's id, and
* its OWN :class:`ai_memory.attestation.AgentSigningKey`, so every store it
  writes is attested under its own identity (never a shared key).

It runs a bounded agentic loop:

    perceive  -> recall + search + inbox (reads gather situational context)
    decide    -> ONE glm-5.3-flash chat call; the tool schema IS the
                 ai-memory tool surface, so the model picks the next action
    act       -> dispatch the chosen tool(s) against the daemon
    record    -> fold every outcome into the shared coverage tracker

The loop is bounded (``max_steps``) with bounded exponential backoff, and
FAILS CLOSED: a decide error or a tool error is recorded and stops the step —
the agent never fabricates a tool call or silently pretends success.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ai_memory import AsyncAiMemoryClient
from ai_memory.attestation import AgentSigningKey

from swarm.openrouter import Decision, OpenRouterClient, OpenRouterError
from swarm.toolset import AgentIdentity, dispatch, selectable_schemas

if TYPE_CHECKING:  # pragma: no cover - typing only
    from swarm.config import SwarmConfig
    from swarm.coverage import CoverageTracker

_SYSTEM_PROMPT = (
    "You are one autonomous AI agent in a swarm exercising an ai-memory daemon. "
    "You have a private memory namespace. Each turn, choose exactly one tool "
    "call that makes progress on your goal: build up useful memories, link and "
    "consolidate related ones, reflect, and coordinate with peers via signals "
    "and notifications. Prefer variety across turns so the whole tool surface "
    "gets exercised. Never invent memory ids you have not seen in a read result."
)


@dataclass
class StepRecord:
    """One loop step's trace, for the run journal."""

    step: int
    perceived: str
    decided_tools: list[str]
    outcomes: list[str]


@dataclass
class SwarmAgent:
    """A single GLM-driven agent. Construct via :meth:`create`."""

    identity: AgentIdentity
    client: AsyncAiMemoryClient
    model: OpenRouterClient
    config: SwarmConfig
    coverage: CoverageTracker
    goal: str = "accumulate and organize useful team knowledge"
    journal: list[StepRecord] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        ordinal: int,
        base_url: str,
        namespace: str,
        allowed_namespaces: set[str],
        signing_key: AgentSigningKey,
        model: OpenRouterClient,
        config: SwarmConfig,
        coverage: CoverageTracker,
        goal: str = "accumulate and organize useful team knowledge",
    ) -> SwarmAgent:
        """Build an agent and its daemon client (no network I/O yet)."""
        agent_id = f"{config.namespace_prefix}-agent-{ordinal:03d}"
        client = AsyncAiMemoryClient(
            base_url=base_url,
            agent_id=agent_id,
            timeout=config.request_timeout_secs,
        )
        identity = AgentIdentity(
            agent_id=agent_id,
            signing_key=signing_key,
            namespace=namespace,
            allowed_namespaces=set(allowed_namespaces) | {namespace},
        )
        return cls(identity=identity, client=client, model=model,
                   config=config, coverage=coverage, goal=goal)

    async def aclose(self) -> None:
        await self.client.aclose()

    # -- perceive ----------------------------------------------------------
    async def perceive(self) -> str:
        """Gather situational context via reads (recall + search + inbox).

        Every read is recorded for coverage. Reads fail closed individually:
        one failing read degrades the observation (fewer signals) but does not
        abort the step.
        """
        parts: list[str] = []
        for tool, args in (
            ("recall", {"context": self.goal, "limit": 5}),
            ("search", {"q": self.goal.split()[0], "limit": 5}),
            ("inbox", {"unread_only": True, "limit": 5}),
        ):
            outcome = await dispatch(self.client, self.identity, tool, args)
            self.coverage.record(outcome)
            status = "ok" if outcome.ok else "fail-closed"
            parts.append(f"{tool}[{status}]: {outcome.summary}")
        return "\n".join(parts)

    # -- decide ------------------------------------------------------------
    async def decide(self, perceived: str) -> Decision:
        """One glm-5.3-flash call. Raises OpenRouterError on failure."""
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Your agent_id: {self.identity.agent_id}\n"
                    f"Your namespace: {self.identity.namespace}\n"
                    f"Your goal: {self.goal}\n\n"
                    f"Recent observations:\n{perceived}\n\n"
                    "Choose one tool call for your next action."
                ),
            },
        ]
        return await self.model.decide(messages=messages, tools=selectable_schemas())

    # -- act ---------------------------------------------------------------
    async def act(self, decision: Decision) -> list[str]:
        """Dispatch the model's chosen tool call(s); record each outcome."""
        summaries: list[str] = []
        for call in decision.tool_calls:
            outcome = await dispatch(self.client, self.identity, call.name, call.arguments)
            self.coverage.record(outcome)
            summaries.append(f"{call.name} -> {'ok' if outcome.ok else 'FAIL-CLOSED'}")
        return summaries

    # -- loop --------------------------------------------------------------
    async def run(self) -> None:
        """Run the bounded perceive->decide->act->record loop."""
        backoff = self.config.backoff_base_secs
        for step in range(1, self.config.max_steps + 1):
            perceived = await self.perceive()
            try:
                decision = await self.decide(perceived)
            except OpenRouterError as exc:
                # Fail closed: record the decide failure and back off, then
                # continue to the next bounded step rather than spinning.
                self.journal.append(StepRecord(step, perceived, [], [f"decide-error: {exc}"]))
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self.config.backoff_max_secs)
                continue
            tool_names = [c.name for c in decision.tool_calls]
            if not tool_names:
                # The model declined to act this step; that is a valid no-op.
                self.journal.append(StepRecord(step, perceived, [], ["no-tool"]))
                continue
            outcomes = await self.act(decision)
            self.journal.append(StepRecord(step, perceived, tool_names, outcomes))
            backoff = self.config.backoff_base_secs  # reset after a productive step

    async def run_once(self) -> StepRecord:
        """Run exactly one loop step and return its record (used by tests)."""
        perceived = await self.perceive()
        decision = await self.decide(perceived)
        tool_names = [c.name for c in decision.tool_calls]
        outcomes = await self.act(decision) if tool_names else ["no-tool"]
        record = StepRecord(1, perceived, tool_names, outcomes)
        self.journal.append(record)
        return record


__all__ = ["StepRecord", "SwarmAgent"]
