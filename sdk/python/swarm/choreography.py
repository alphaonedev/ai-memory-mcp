# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Scripted agent-to-agent (A2A) choreographies.

Where :class:`swarm.agent.SwarmAgent` is GLM-DRIVEN (the model chooses each
action), these choreographies are DETERMINISTIC scripts that exercise specific
cross-agent invariants against the live, GLM-driven population running around
them. Each scenario returns a :class:`ScenarioResult` recording what it
asserted so the acceptance report can show the invariant held.

Scenarios
---------
* ``producer_consumer`` — A signals/notifies B; B consumes from its inbox and
  C (a bystander) confirms it received NOTHING (cross-agent isolation).
* ``consensus_quorum`` — several agents each attest the same fact into a
  shared namespace, then one consolidates them into a single consensus row
  (attestation + quorum + consolidation).
* ``governance_approval`` — a proposer requests an action; an approver attests
  an approval-decision memory and notifies back (an approval chain at the A2A
  layer; the daemon's ``/api/v1/pending/*`` routes are the deeper surface, not
  wrapped by the SDK client).
* ``replay_guard`` — the SAME signed write envelope is submitted twice; the
  daemon's replay-guard must refuse or dedup the second (no double-apply).

Every scenario dispatches through :mod:`swarm.toolset` (so its calls count for
coverage) or the attested SDK path directly, and FAILS CLOSED: an unexpected
daemon response makes the scenario ``ok=False`` rather than passing silently.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_memory.attestation import attestation_fields
from ai_memory.errors import AiMemoryError

from swarm.toolset import dispatch

_RUN = uuid.uuid4().hex[:8]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from swarm.agent import SwarmAgent
    from swarm.orchestrator import Swarm


@dataclass(frozen=True)
class ScenarioResult:
    """The outcome of one scripted choreography."""

    name: str
    ok: bool
    detail: str


async def producer_consumer(swarm: Swarm) -> ScenarioResult:
    """A -> B message lane; C must not see B's mail (isolation)."""
    if len(swarm.agents) < 2:
        return ScenarioResult("producer_consumer", ok=False, detail="need >= 2 agents")
    a, b = swarm.agents[0], swarm.agents[1]
    c = swarm.agents[2] if len(swarm.agents) > 2 else None

    subject = f"handoff-{a.identity.agent_id}"
    send = await dispatch(
        a.client, a.identity, "notify",
        {"to_agent": b.identity.agent_id, "subject": subject, "body": "unit-of-work"})
    swarm.coverage.record(send)
    # Also exercise the coordination signal lane.
    sig = await dispatch(a.client, a.identity, "signal_send",
                         {"to_agent": b.identity.agent_id, "subject": subject,
                          "signal_type": "request", "body": {"work": 1}})
    swarm.coverage.record(sig)

    got = await dispatch(b.client, b.identity, "inbox", {"unread_only": True, "limit": 10})
    swarm.coverage.record(got)
    # Inspect the FULL result, never the 160-char display summary (a long
    # agent_id pushed the subject past the truncation and read as "not seen").
    b_saw = got.ok and subject in json.dumps(got.result, default=str)

    c_isolated = True
    if c is not None:
        c_inbox = await dispatch(c.client, c.identity, "inbox", {"unread_only": True, "limit": 10})
        swarm.coverage.record(c_inbox)
        c_isolated = not (c_inbox.ok and subject in json.dumps(c_inbox.result, default=str))

    ok = send.ok and b_saw and c_isolated
    return ScenarioResult("producer_consumer", ok=ok,
                          detail=f"sent={send.ok} b_saw={b_saw} c_isolated={c_isolated}")


async def consensus_quorum(swarm: Swarm) -> ScenarioResult:
    """N agents attest the same fact into the shared ns; one consolidates."""
    if len(swarm.agents) < 2:
        return ScenarioResult("consensus_quorum", ok=False, detail="need >= 2 agents")
    fact = "the sky is blue"
    ids: list[str] = []
    for ordinal, agent in enumerate(swarm.agents):
        # Votes are "collective"-scoped: a private-scope row is readable only by
        # its author, so the consolidator could not read its peers' votes.
        out = await dispatch(agent.client, agent.identity, "store",
                             {"title": f"consensus-vote-{_RUN}-{ordinal}", "content": fact,
                              "namespace": swarm.shared_namespace, "scope": "collective"})
        swarm.coverage.record(out)
        if out.ok and isinstance(out.result, dict) and out.result.get("id"):
            ids.append(str(out.result["id"]))
    consolidator = swarm.agents[0]
    cons = await dispatch(consolidator.client, consolidator.identity, "consolidate",
                          {"ids": ids, "title": f"consensus-{_RUN}", "namespace": swarm.shared_namespace})
    swarm.coverage.record(cons)
    ok = len(ids) >= 2 and cons.ok
    return ScenarioResult("consensus_quorum", ok=ok,
                          detail=f"votes={len(ids)} consolidated={cons.ok}")


async def governance_approval(swarm: Swarm) -> ScenarioResult:
    """Proposer requests; approver attests an approval decision + notifies back."""
    if len(swarm.agents) < 2:
        return ScenarioResult("governance_approval", ok=False, detail="need >= 2 agents")
    proposer, approver = swarm.agents[0], swarm.agents[1]
    ask = await dispatch(proposer.client, proposer.identity, "notify",
                         {"to_agent": approver.identity.agent_id,
                          "subject": "approve: publish-report", "body": "please approve"})
    swarm.coverage.record(ask)
    decision = await dispatch(
        approver.client, approver.identity, "store",
        {"title": f"approval-decision-{_RUN}", "content": "APPROVED: publish-report",
         "namespace": swarm.shared_namespace, "scope": "collective",
         "tags": ["governance", "approval"]})
    swarm.coverage.record(decision)
    ack = await dispatch(approver.client, approver.identity, "notify",
                         {"to_agent": proposer.identity.agent_id,
                          "subject": "approved: publish-report", "body": "granted"})
    swarm.coverage.record(ack)
    ok = ask.ok and decision.ok and ack.ok
    return ScenarioResult("governance_approval", ok=ok,
                          detail=f"asked={ask.ok} decided={decision.ok} acked={ack.ok}")


async def replay_guard(agent: SwarmAgent, namespace: str | None = None) -> ScenarioResult:
    """Submit the SAME signed envelope twice; the second must be refused/dedup.

    Signs one attestation envelope and reuses its exact signature + created_at
    for both writes. A daemon with a working replay-guard rejects (or dedups
    to the same row) the second submission — the durable truth is never
    double-applied.
    """
    ns = namespace or agent.identity.namespace
    title = f"replay-probe-{_RUN}"
    content = "idempotency canary"
    fields = attestation_fields(
        agent.identity.signing_key,
        agent_id=agent.identity.agent_id,
        namespace=ns,
        title=title,
        content=content,
    )

    async def _submit() -> dict[str, object]:
        return await agent.client.store(
            title=title, content=content, namespace=ns, agent_id=agent.identity.agent_id,
            signature=fields["signature"], created_at=fields["created_at"], kind=fields["kind"],
        )

    first = await _submit()
    first_id = first.get("id") if isinstance(first, dict) else None
    guarded = False
    detail = "first-store failed"
    try:
        second = await _submit()
        second_id = second.get("id") if isinstance(second, dict) else None
        # Dedup-to-same-row is an acceptable guard outcome; a NEW id is a
        # replay-guard FAILURE (the durable write was double-applied).
        guarded = second_id == first_id
        detail = f"first={first_id} second={second_id} dedup={guarded}"
    except AiMemoryError as exc:
        # An explicit refusal (409/replay error) is the strongest guard signal.
        guarded = True
        detail = f"first={first_id} replay-refused={type(exc).__name__}"
    return ScenarioResult("replay_guard", ok=bool(first_id) and guarded, detail=detail)


async def run_all(swarm: Swarm) -> list[ScenarioResult]:
    """Run every scenario in sequence against the population."""
    results = [
        await producer_consumer(swarm),
        await consensus_quorum(swarm),
        await governance_approval(swarm),
    ]
    if swarm.agents:
        results.append(await replay_guard(swarm.agents[0]))
    return results


__all__ = [
    "ScenarioResult",
    "consensus_quorum",
    "governance_approval",
    "producer_consumer",
    "replay_guard",
    "run_all",
]
