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
* ``nhi_assessment`` — a final no-tools model call audits the run evidence and
  persists the report through the same attested store dispatch as every agent.

Every scenario dispatches through :mod:`swarm.toolset` (so its calls count for
coverage) or the attested SDK path directly, and FAILS CLOSED: an unexpected
daemon response makes the scenario ``ok=False`` rather than passing silently.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_memory.attestation import attestation_fields
from ai_memory.errors import AiMemoryError

from swarm.openrouter import OpenRouterError
from swarm.audit import AgentAssessment, parse_assessment
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


def module_of(agent: SwarmAgent) -> str:
    """The daemon (module) base URL this agent's client is bound to."""
    return str(getattr(getattr(agent.client, "_client", None), "base_url", "") or "")


def modules(swarm: Swarm) -> dict[str, list[SwarmAgent]]:
    """Group the population by module, preserving spawn order inside each.

    With ``SWARM_MODULES>1`` the launcher round-robins agents across several
    INDEPENDENT data tiers (separate PG+AGE+pgvector stacks). Agent 0 and agent
    1 then live on different tiers, so an A2A choreography built from
    ``agents[0]`` and ``agents[1]`` asserts a cross-tier invariant that cannot
    hold until node-to-node federation is wired (#3441).
    """
    grouped: dict[str, list[SwarmAgent]] = {}
    for agent in swarm.agents:
        grouped.setdefault(module_of(agent), []).append(agent)
    return grouped


def _slug(module: str | None) -> str:
    """Short, title-safe module tag; empty for a single-module run."""
    if not module:
        return ""
    return module.split("://", 1)[-1].strip("/").replace("/", "-") + "-"


def _named(name: str, module: str | None) -> str:
    """Scenario name, tagged with its module when the run is multi-module."""
    return name if module is None else f"{name}@{module}"


def _participants(swarm: Swarm, agents: list[SwarmAgent] | None) -> list[SwarmAgent]:
    return swarm.agents if agents is None else agents


async def producer_consumer(swarm: Swarm, agents: list[SwarmAgent] | None = None,
                            module: str | None = None) -> ScenarioResult:
    """A -> B message lane; C must not see B's mail (isolation).

    ``agents`` defaults to the whole population; a multi-module run passes ONE
    module's agents so the lane stays inside a single data tier.
    """
    name = _named("producer_consumer", module)
    population = _participants(swarm, agents)
    if len(population) < 2:
        return ScenarioResult(name, ok=False, detail="need >= 2 agents")
    a, b = population[0], population[1]
    c = population[2] if len(population) > 2 else None

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
    return ScenarioResult(name, ok=ok,
                          detail=f"sent={send.ok} b_saw={b_saw} c_isolated={c_isolated}")


async def consensus_quorum(swarm: Swarm, agents: list[SwarmAgent] | None = None,
                           module: str | None = None) -> ScenarioResult:
    """N agents attest the same fact into the shared ns; one consolidates.

    The consolidator must be able to READ every vote, so all voters and the
    consolidator have to sit on the same module (#3441): a vote stored on one
    tier is "memory not found" to a consolidator on another.
    """
    name = _named("consensus_quorum", module)
    population = _participants(swarm, agents)
    if len(population) < 2:
        return ScenarioResult(name, ok=False, detail="need >= 2 agents")
    fact = "the sky is blue"
    ids: list[str] = []
    for ordinal, agent in enumerate(population):
        # Votes are "collective"-scoped: a private-scope row is readable only by
        # its author, so the consolidator could not read its peers' votes.
        out = await dispatch(agent.client, agent.identity, "store",
                             {"title": f"consensus-vote-{_RUN}-{_slug(module)}{ordinal}",
                              "content": fact,
                              "namespace": swarm.shared_namespace, "scope": "collective"})
        swarm.coverage.record(out)
        if out.ok and isinstance(out.result, dict) and out.result.get("id"):
            ids.append(str(out.result["id"]))
    consolidator = population[0]
    # The daemon caps one consolidation at 100 sources ("cannot consolidate
    # more than 100 memories at once", measured at 128 agents). Fold the votes
    # in batches of <= 100, then fold the batch results into ONE consensus row.
    batch_size = 100
    level: list[str] = ids
    cons = None
    while True:
        next_level: list[str] = []
        for start in range(0, len(level), batch_size):
            chunk = level[start:start + batch_size]
            cons = await dispatch(consolidator.client, consolidator.identity, "consolidate",
                                  {"ids": chunk,
                                   "title": f"consensus-{_RUN}-{_slug(module)}{start // batch_size}-{len(level)}",
                                   "namespace": swarm.shared_namespace})
            swarm.coverage.record(cons)
            if not cons.ok:
                break
            cid = cons.result.get("id") if isinstance(cons.result, dict) else None
            if cid:
                next_level.append(str(cid))
        if cons is None or not cons.ok or len(level) <= batch_size or len(next_level) < 2:
            break
        level = next_level
    ok = len(ids) >= 2 and cons is not None and cons.ok
    return ScenarioResult(name, ok=ok,
                          detail=f"votes={len(ids)} consolidated={cons is not None and cons.ok}")


async def governance_approval(swarm: Swarm, agents: list[SwarmAgent] | None = None,
                              module: str | None = None) -> ScenarioResult:
    """Proposer requests; approver attests an approval decision + notifies back."""
    name = _named("governance_approval", module)
    population = _participants(swarm, agents)
    if len(population) < 2:
        return ScenarioResult(name, ok=False, detail="need >= 2 agents")
    proposer, approver = population[0], population[1]
    ask = await dispatch(proposer.client, proposer.identity, "notify",
                         {"to_agent": approver.identity.agent_id,
                          "subject": "approve: publish-report", "body": "please approve"})
    swarm.coverage.record(ask)
    decision = await dispatch(
        approver.client, approver.identity, "store",
        {"title": f"approval-decision-{_RUN}-{_slug(module)}", "content": "APPROVED: publish-report",
         "namespace": swarm.shared_namespace, "scope": "collective",
         "tags": ["governance", "approval"]})
    swarm.coverage.record(decision)
    ack = await dispatch(approver.client, approver.identity, "notify",
                         {"to_agent": proposer.identity.agent_id,
                          "subject": "approved: publish-report", "body": "granted"})
    swarm.coverage.record(ack)
    ok = ask.ok and decision.ok and ack.ok
    return ScenarioResult(name, ok=ok,
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


async def full_surface_sweep(swarm: Swarm, agents: list[SwarmAgent] | None = None,
                             module: str | None = None) -> ScenarioResult:
    """Exercise the complete memory lifecycle through the dispatcher."""
    name = _named("full_surface_sweep", module)
    population = _participants(swarm, agents)
    if not population:
        return ScenarioResult(name, ok=False, detail="need >= 1 agent")
    agent = population[0]
    pattern = f"full-surface-{_RUN}-{_slug(module)}"
    completed: list[str] = []

    async def call(tool: str, args: dict[str, object]):
        outcome = await dispatch(agent.client, agent.identity, tool, args)
        swarm.coverage.record(outcome)
        if outcome.ok:
            completed.append(tool)
        return outcome

    first = await call("store", {"title": f"{pattern}-source", "content": "source"})
    second = await call("store", {"title": f"{pattern}-target", "content": "target"})
    if not first.ok or not second.ok or not isinstance(first.result, dict) or not isinstance(second.result, dict):
        return ScenarioResult(name, False, f"stopped after {','.join(completed)}")
    source_id, target_id = first.result.get("id"), second.result.get("id")
    if not source_id or not target_id:
        return ScenarioResult(name, False, "store response missing id")

    # Lineage edges point CHILD -> PARENT: the daemon's temporal lineage guard
    # (#3041) refuses an edge whose target is NEWER than its source, so the
    # second (newer) row derives_from the first (older) row.
    steps = (
        ("link", {"source_id": target_id, "target_id": source_id, "relation": "derives_from"}),
        ("get_links", {"memory_id": target_id}),
        ("get_memory", {"memory_id": source_id}),
        ("lineage", {"memory_id": target_id, "direction": "ancestors"}),
        ("update", {"memory_id": source_id, "content": "source updated",
                    "expected_version": int(first.result.get("version") or 1)}),
        ("promote", {"memory_id": source_id}),
        ("reflect", {"source_ids": [source_id, target_id],
                     "title": f"{pattern}-reflection", "content": "reflection"}),
        ("delete", {"memory_id": target_id}),
        ("forget", {"pattern": pattern}),
    )
    for tool, args in steps:
        outcome = await call(tool, args)
        if not outcome.ok:
            # A DOCUMENTED fail-closed refusal (e.g. admin-gated `forget` when
            # this agent is not an admin) is the expected posture, not a sweep
            # failure: the tracker already counts it as covered.
            if tool in swarm.coverage.documented_fail_closed and outcome.fail_closed:
                completed.append(f"{tool}(fail-closed:documented)")
                continue
            return ScenarioResult(name, False,
                                  f"{tool} failed after {','.join(completed)}: {outcome.summary}")
    return ScenarioResult(name, True, " -> ".join(completed))


#: ~150k tokens at 4 chars/token — safely inside every model we run (GLM 200k, Grok 500k).
_AUDIT_EVIDENCE_CHARS = 600_000


def _budget(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[evidence truncated: {len(text) - limit} chars omitted; full artifacts on disk]"


async def nhi_assessment(
    swarm: Swarm, scenarios: list[ScenarioResult], *, reconcile_result: dict[str, object] | None = None,
    negative_evidence: list[dict[str, object]] | None = None,
) -> tuple[ScenarioResult, str | None]:
    """Ask one NHI to audit the completed run, then attest its report.

    The assessment completion receives evidence only and has no tools.  Its
    resulting report is stored by the first agent through ``dispatch`` so the
    normal namespace confinement and per-agent Ed25519 attestation apply.
    """
    if not swarm.agents:
        return ScenarioResult("nhi_assessment", False, "need >= 1 agent"), None
    agent = swarm.agents[0]

    def _clip(text: object, n: int) -> str:
        t = str(text)
        return t if len(t) <= n else t[:n] + f"...[+{len(t) - n} chars]"

    # The auditor's context is finite (Grok 4.6: 500k tokens; run #1 overflowed
    # it with full call summaries). Journals and call log are CLIPPED per field;
    # the complete artifacts stay on disk (calls.jsonl, <agent>.jsonl) for humans.
    entries = getattr(getattr(swarm, "call_log", None), "entries", [])
    evidence = {
        "coverage_matrix": swarm.coverage.matrix(),
        "scenarios": [result.__dict__ for result in scenarios],
        "agent_journals": {
            item.identity.agent_id: [
                {**record.__dict__, "perceived": _clip(record.perceived, 600),
                 "outcomes": [_clip(o, 300) for o in record.outcomes]}
                for record in item.journal
            ]
            for item in swarm.agents
        },
        "call_log_size": len(entries),
        "call_log_clipped": [
            {k: (_clip(v, 200) if k in ("summary", "args") else v) for k, v in entry.items()}
            for entry in entries[-400:]
        ],
        "call_log_reconcile": reconcile_result,
        "negative_evidence": negative_evidence or [],
    }
    extra_path = os.environ.get("SWARM_EXTRA_EVIDENCE")
    if extra_path:
        try:
            # Intentionally verbatim: the auditor must see the original battery artifact.
            from pathlib import Path
            evidence["extra_evidence_verbatim"] = Path(extra_path).read_text(encoding="utf-8")[:60000]
        except OSError as exc:
            evidence["extra_evidence_error"] = f"{type(exc).__name__}: {exc}"
    messages = [
        {
            "role": "system",
            "content": (
                "You are the independent AI-NHI auditor for an ai-memory acceptance run. "
                "Assess only the supplied evidence. Identify failures, coverage gaps, and "
                "data-integrity concerns; do not claim anything that the evidence does not "
                "prove. End with an explicit PASS or FAIL verdict and concise rationale."
            ),
        },
        {
            "role": "user",
            "content": "Audit this completed swarm run:\n"
            + _budget(json.dumps(evidence, default=str), _AUDIT_EVIDENCE_CHARS),
        },
    ]
    try:
        report = await agent.model.complete(messages=messages)
        swarm.coverage.record_model_usage(agent.identity.agent_id, getattr(agent.model, "last_usage", None))
    except OpenRouterError as exc:
        # The caller renders this as a failed choreography. No fabricated
        # assessment is stored when OpenRouter fails or returns empty content.
        return ScenarioResult(
            "nhi_assessment", False, f"assessment failed closed: {type(exc).__name__}: {exc}"
        ), None

    stored = await dispatch(
        agent.client,
        agent.identity,
        "store",
        {
            "title": f"AI-NHI swarm assessment {_RUN}",
            "content": report,
            "namespace": swarm.shared_namespace,
            "scope": "collective",
            "tags": ["ai-nhi", "assessment", "audit"],
        },
    )
    swarm.coverage.record(stored)
    memory_id = stored.result.get("id") if stored.ok and isinstance(stored.result, dict) else None
    ok = stored.ok and bool(memory_id)
    detail = f"assessment_memory={memory_id}" if ok else f"assessment store failed: {stored.summary}"
    return ScenarioResult("nhi_assessment", ok, detail), report


async def negative_authorization_evidence(swarm: Swarm) -> list[dict[str, object]]:
    """Exercise expected isolation/refusal paths, all through logged dispatches."""
    if len(swarm.agents) < 2:
        return [{"probe": "authorization", "ok": False, "detail": "need >= 2 agents"}]
    owner, attacker = swarm.agents[0], swarm.agents[1]
    title = f"isolation-canary-{_RUN}"
    created = await dispatch(owner.client, owner.identity, "store",
                             {"title": title, "content": "owner only"})
    swarm.coverage.record(created)
    memory_id = created.result.get("id") if created.ok and isinstance(created.result, dict) else None
    probes: list[tuple[str, object]] = []
    if memory_id:
        probes.extend([
            ("cross_namespace_read", await dispatch(attacker.client, attacker.identity, "get_memory",
                                                     {"memory_id": memory_id})),
            ("unauthorized_update", await dispatch(attacker.client, attacker.identity, "update",
                                                    {"memory_id": memory_id, "content": "tamper"})),
            ("unauthorized_delete", await dispatch(attacker.client, attacker.identity, "delete",
                                                    {"memory_id": memory_id})),
        ])
    duplicate = await dispatch(owner.client, owner.identity, "store",
                               {"title": title, "content": "duplicate"})
    probes.append(("duplicate_title_conflict", duplicate))
    evidence = []
    for name, outcome in probes:
        swarm.coverage.record(outcome)
        refused = (not outcome.ok) and "unknown tool" not in outcome.summary
        evidence.append({"probe": name, "expected_refusal": True,
                         "refused": refused, "summary": outcome.summary})
    return evidence


_RUBRIC_PROMPT = """Return ONLY one JSON object with exactly these fields:
{"recall_usefulness":1-5,"latency_acceptable":true|false,
"failures_encountered":[["tool","what"]],"isolation_respected":true|false,
"would_rely_on_it":true|false,"free_text":"at most 600 characters"}
Assess your just-completed mission from the supplied journal. Do not use tools."""


async def collect_assessments(swarm: Swarm) -> list[AgentAssessment]:
    """Run one strict no-tools rubric completion per agent and attest it."""
    assessments: list[AgentAssessment] = []
    for agent in swarm.agents:
        messages = [{"role": "system", "content": _RUBRIC_PROMPT},
                    {"role": "user", "content": _budget(json.dumps(
                        {"agent_id": agent.identity.agent_id,
                         "journal": [record.__dict__ for record in agent.journal]}, default=str), 200_000)}]
        try:
            raw = await agent.model.complete(messages=messages)
            swarm.coverage.record_model_usage(agent.identity.agent_id, getattr(agent.model, "last_usage", None))
            assessment = parse_assessment(agent.identity.agent_id, raw)
        except OpenRouterError as exc:
            assessment = parse_assessment(agent.identity.agent_id, "")
            assessment = AgentAssessment(**{**assessment.__dict__,
                                            "error": f"{type(exc).__name__}: {exc}"})
        assessments.append(assessment)
        stored = await dispatch(agent.client, agent.identity, "store", {
            "title": f"nhi-audit-{agent.identity.agent_id}-{_RUN}",
            "content": json.dumps(assessment.__dict__, sort_keys=True),
            "namespace": swarm.shared_namespace, "scope": "collective",
            "tags": ["nhi-audit"],
        })
        swarm.coverage.record(stored)
    return assessments


#: Set to ``1`` once node-to-node federation is configured between the modules.
#: Until then a cross-module handoff is EXPECTED not to arrive, and the audit
#: says so explicitly instead of reporting a FAIL it cannot act on (#3441).
FEDERATED_ENV = "SWARM_FEDERATED"


def federation_expected(environ: dict[str, str] | None = None) -> bool:
    """Whether the operator asserts f1<->f2 federation is wired for this run."""
    env = os.environ if environ is None else environ
    return (env.get(FEDERATED_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


async def cross_module_handoff(swarm: Swarm, groups: dict[str, list[SwarmAgent]],
                               *, federated: bool | None = None) -> ScenarioResult:
    """A on module 1 notifies B on module 2 — the federation boundary probe.

    This is an ASSERTION in both directions, never a rubber stamp:

    * federation not configured (default): the notify must NOT reach the peer
      module. It landing there would mean two supposedly independent data tiers
      are leaking into each other — reported as a FAIL.
    * ``SWARM_FEDERATED=1``: the operator asserts the tiers are federated, so
      the message MUST arrive; not arriving is a FAIL.
    """
    name = "cross_module_handoff"
    ordered = sorted(groups)
    if len(ordered) < 2:
        return ScenarioResult(name, ok=True, detail="single module: not applicable")
    expect_federated = federation_expected() if federated is None else federated
    a = groups[ordered[0]][0]
    b = next((agent for agent in groups[ordered[1]] if agent is not a), None)
    if b is None:
        return ScenarioResult(name, ok=False, detail="need an agent on each module")

    subject = f"cross-module-{_RUN}-{a.identity.agent_id}"
    send = await dispatch(a.client, a.identity, "notify",
                          {"to_agent": b.identity.agent_id, "subject": subject,
                           "body": "cross-module handoff probe"})
    swarm.coverage.record(send)
    got = await dispatch(b.client, b.identity, "inbox", {"unread_only": True, "limit": 10})
    swarm.coverage.record(got)
    crossed = got.ok and subject in json.dumps(got.result, default=str)
    where = f"{ordered[0]} -> {ordered[1]}"
    if expect_federated:
        return ScenarioResult(name, ok=bool(send.ok and crossed),
                              detail=f"federated: {where} sent={send.ok} b_saw={crossed}")
    if crossed:
        return ScenarioResult(
            name, ok=False,
            detail=f"cross-module: {where} message CROSSED an unfederated boundary")
    return ScenarioResult(name, ok=True,
                          detail=f"cross-module: not federated (expected) [{where}]")


async def run_all(swarm: Swarm) -> list[ScenarioResult]:
    """Run every scenario in sequence against the population.

    A single-module run is unchanged. With several modules every A2A scenario
    runs ONCE PER MODULE over that module's own agents (#3441) — a producer and
    consumer split across two unfederated tiers can never see each other's
    inbox, and a consolidator can never read a vote stored on the other tier —
    and the boundary itself is probed by :func:`cross_module_handoff`.
    """
    groups = modules(swarm)
    if len(groups) <= 1:
        results = [
            await producer_consumer(swarm),
            await consensus_quorum(swarm),
            await governance_approval(swarm),
            await full_surface_sweep(swarm),
        ]
    else:
        results = []
        for module in sorted(groups):
            agents = groups[module]
            results.append(await producer_consumer(swarm, agents, module))
            results.append(await consensus_quorum(swarm, agents, module))
            results.append(await governance_approval(swarm, agents, module))
            results.append(await full_surface_sweep(swarm, agents, module))
        results.append(await cross_module_handoff(swarm, groups))
    if swarm.agents:
        results.append(await replay_guard(swarm.agents[0]))
    return results


__all__ = [
    "FEDERATED_ENV",
    "ScenarioResult",
    "consensus_quorum",
    "cross_module_handoff",
    "federation_expected",
    "module_of",
    "modules",
    "governance_approval",
    "nhi_assessment",
    "negative_authorization_evidence",
    "collect_assessments",
    "full_surface_sweep",
    "producer_consumer",
    "replay_guard",
    "run_all",
]
