# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""``Swarm`` — spawns and supervises N GLM-driven agents.

The orchestrator turns a :class:`swarm.config.SwarmConfig` into a live
population:

1. For each agent it loads (or generates + persists) an Ed25519 seed under
   ``key_dir``, so re-runs reuse the same identity.
2. It provisions each agent on the daemon: ``register_agent`` then
   ``bind_agent_pubkey`` (admin-gated) so the agent's attested stores verify.
3. It assigns each agent a private namespace plus any shared/consensus
   namespaces the run needs.
4. It launches agents as asyncio tasks with STAGGERED starts — never a
   synchronized blast — so a large fleet does not thundering-herd the daemon.

Backends are just a list of base URLs: one URL is Config-1 (single daemon);
several are a swarm or federated mesh (Config-2..5). Agents are round-robin
assigned across them.

Nothing here runs the model unless :meth:`run` is called with live agents;
:meth:`provision` and key handling are exercised by the offline tests with a
mocked client + model.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from ai_memory.attestation import AgentSigningKey

from swarm.agent import SwarmAgent
from swarm.audit import CallLog, set_call_log
from swarm.coverage import CoverageTracker
from swarm.openrouter import OpenRouterClient

if TYPE_CHECKING:  # pragma: no cover - typing only
    from swarm.config import SwarmConfig


class Swarm:
    """A managed population of GLM-driven agents over one or more daemons."""

    def __init__(
        self,
        config: SwarmConfig,
        *,
        coverage: CoverageTracker | None = None,
        shared_namespace: str | None = None,
    ) -> None:
        self.config = config
        self.coverage = coverage or CoverageTracker()
        #: A namespace every agent may write to, for consensus/quorum scenarios.
        self.shared_namespace = shared_namespace or f"{config.namespace_prefix}-shared"
        self.agents: list[SwarmAgent] = []
        self._model: OpenRouterClient | None = None
        self.call_log = CallLog(os.environ.get("SWARM_JOURNAL_DIR"))
        set_call_log(self.call_log)

    # -- key handling ------------------------------------------------------
    def _load_or_create_key(self, agent_id: str) -> AgentSigningKey:
        """Load ``<key_dir>/<agent_id>.priv`` (32 raw bytes) or mint + persist it.

        The on-disk format matches the daemon's own key store, so a key the
        operator pre-provisioned with ``ai-memory identity generate`` is
        loaded verbatim.
        """
        key_dir = Path(self.config.key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        path = key_dir / f"{agent_id}.priv"
        if path.exists():
            return AgentSigningKey.from_file(path)
        key = AgentSigningKey.generate()
        # 0600 — the seed is a private credential.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.seed_bytes())
        return key

    # -- construction ------------------------------------------------------
    def build_agents(self, *, model: OpenRouterClient) -> list[SwarmAgent]:
        """Construct the agent objects (no network I/O)."""
        self._model = model
        self.agents = []
        for ordinal in range(self.config.n_agents):
            namespace = self.config.namespace_for(ordinal)
            stable = uuid.uuid5(
                uuid.NAMESPACE_URL, f"{self.config.namespace_prefix}:agent:{ordinal:03d}"
            )
            agent_id = f"ai:{self.config.namespace_prefix}-glm-{stable}"
            key = self._load_or_create_key(agent_id)
            self.agents.append(
                SwarmAgent.create(
                    ordinal=ordinal,
                    base_url=self.config.base_url_for(ordinal),
                    namespace=namespace,
                    allowed_namespaces={self.shared_namespace},
                    signing_key=key,
                    model=model,
                    config=self.config,
                    coverage=self.coverage,
                )
            )
        admin_ids = {
            value.strip()
            for value in os.environ.get("AI_MEMORY_ADMIN_AGENT_IDS", "").split(",")
            if value.strip()
        }
        if not any(agent.identity.agent_id in admin_ids for agent in self.agents):
            self.coverage.mark_documented_fail_closed(
                "stats", "namespaces", "agents", "forget"
            )
        return self.agents

    # -- provisioning ------------------------------------------------------
    async def preflight(self) -> None:
        """Dispatch health and capabilities exactly once for every agent."""
        from swarm.toolset import dispatch

        # health/capabilities are non-selectable (never model-chosen); the three
        # admin-gated reads are dispatched once too so a run is a coverage PROOF
        # (admin agents succeed; non-admin agents record a documented 403).
        for agent in self.agents:
            for tool in ("health", "capabilities", "stats", "namespaces", "agents"):
                outcome = await dispatch(agent.client, agent.identity, tool, {})
                self.coverage.record(outcome)

    async def provision(self) -> None:
        """Register each agent and bind its attestation pubkey on the daemon.

        Runs sequentially with the same stagger as launch, so provisioning a
        large fleet is also paced. Registration + pubkey bind for the read/
        write tools is recorded as coverage of ``agents``-plane surface.
        """
        # Administrative enrollment uses one explicit request principal. On
        # DO this identity is admitted only when the request also presents the
        # loadgen mTLS certificate and per-node API key; header trust is off.
        from ai_memory import AsyncAiMemoryClient

        admins: dict[str, AsyncAiMemoryClient] = {}
        try:
            for ordinal, agent in enumerate(self.agents):
                base_url = self.config.base_url_for(ordinal)
                admin = admins.get(base_url)
                if admin is None:
                    admin = AsyncAiMemoryClient(
                        base_url=base_url,
                        agent_id=self.config.admin_agent_id,
                        timeout=self.config.request_timeout_secs,
                        **self.config.daemon_client_kwargs(),
                    )
                    admins[base_url] = admin
                await admin.register_agent(
                    agent.identity.agent_id, agent_type="ai:glm-swarm"
                )
                await admin.bind_agent_pubkey(
                    agent.identity.agent_id,
                    agent.identity.signing_key.public_key_b64(),
                )
                await asyncio.sleep(self.config.stagger_secs)
            await self.preflight()
        finally:
            await asyncio.gather(*(admin.aclose() for admin in admins.values()))

    # -- run ---------------------------------------------------------------
    async def run(self) -> CoverageTracker:
        """Launch all agents with staggered starts; await completion.

        Returns the shared coverage tracker so the caller can print the
        matrix and assert full coverage.
        """
        tasks: list[asyncio.Task[None]] = []
        for agent in self.agents:
            tasks.append(asyncio.create_task(agent.run()))
            await asyncio.sleep(self.config.stagger_secs)  # staggered, not synchronized
        # Gather; a single agent's unexpected crash must not abort the fleet —
        # its failure is captured, the rest of the population still reports.
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.coverage

    async def aclose(self) -> None:
        """Close every agent's daemon client and the shared model client."""
        for agent in self.agents:
            await agent.aclose()
        if self._model is not None:
            await self._model.aclose()
        set_call_log(None)

    def mission_completion(self) -> dict[str, bool]:
        """Verify the concrete summary plus lineage/consolidation requirement."""
        return {agent.identity.agent_id:
                bool(agent.mission_summary_id and agent.mission_summary_count == 1
                     and agent.mission_lineage_proved and agent.mission_summary_cites_sources)
                for agent in self.agents}


async def run_swarm(config: SwarmConfig) -> CoverageTracker:
    """Convenience entry point for a full LIVE run.

    Fails closed if the config lacks an OpenRouter key (see
    :meth:`SwarmConfig.require_live`).
    """
    config.require_live()
    assert config.openrouter_api_key is not None  # narrowed by require_live
    model = OpenRouterClient(
        api_key=config.openrouter_api_key,
        model_slug=config.model_slug,
        base_url=config.openrouter_base_url,
        timeout=config.request_timeout_secs,
    )
    swarm = Swarm(config)
    swarm.build_agents(model=model)
    try:
        await swarm.provision()
        return await swarm.run()
    finally:
        await swarm.aclose()


__all__ = ["Swarm", "run_swarm"]
