# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The ai-memory tool surface, as the swarm drives it.

This module is the single source of truth for *what the swarm can do to a
daemon*. Each :class:`ToolSpec` couples three things that must never drift:

* the OpenAI-function schema the GLM-5.3-Flash model sees at decide time,
* the async handler that actually dispatches the call against an
  :class:`ai_memory.AsyncAiMemoryClient` (or a driver-local raw route), and
* the manifest metadata (HTTP method, path, kind, source) that
  :mod:`swarm.coverage` asserts against.

Driver-local tools
------------------
Three tools have live HTTP routes but no SDK method, so the driver issues the
raw request through the client's underlying ``httpx.AsyncClient``:

* ``signal_send``  -> ``POST /api/v1/signals``        (coordination fan-out)
* ``consolidate``  -> ``POST /api/v1/consolidate``    (merge N sources -> 1)
* ``reflect``      -> ``POST /api/v1/memory_reflect`` (substrate reflection)

Data-integrity guardrails (North Star)
-------------------------------------
Every write is namespace-CONFINED: a model-chosen namespace outside the
agent's granted set is forced back to the agent's primary namespace, so a
hallucinated namespace can never let one agent corrupt or delete another
agent's memories. ``forget`` (bulk delete) is confined to the agent's PRIVATE
namespace only — never a shared consensus namespace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Coroutine

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ai_memory import AsyncAiMemoryClient
    from ai_memory.attestation import AgentSigningKey

Handler = Callable[
    ["AsyncAiMemoryClient", "AgentIdentity", dict[str, Any]], Coroutine[Any, Any, Any]
]

#: Tool kinds, used by the coverage matrix and by the agent to know which
#: tools are safe reads vs. state-mutating writes.
KIND_READ = "read"
KIND_WRITE = "write"
KIND_ADMIN = "admin"


@dataclass
class AgentIdentity:
    """Everything the dispatcher needs to act AS one swarm agent.

    Attributes:
        agent_id: The agent's stable id (also its ``X-Agent-Id`` header, set
            on the client at construction).
        signing_key: The agent's own Ed25519 key; signs every attested store.
        namespace: The agent's PRIVATE namespace (isolation boundary).
        allowed_namespaces: Namespaces this agent may write to — its private
            namespace plus any shared/consensus namespaces the orchestrator
            granted. A write to anything else is confined to ``namespace``.
    """

    agent_id: str
    signing_key: AgentSigningKey
    namespace: str
    allowed_namespaces: set[str] = field(default_factory=set)

    def confine(self, requested: str | None) -> str:
        """Return a namespace the agent is allowed to write to.

        A ``None`` or out-of-scope request collapses to the private
        namespace — the fail-closed default that keeps writes inside the
        agent's own isolation boundary.
        """
        if requested and (requested in self.allowed_namespaces or requested == self.namespace):
            return requested
        return self.namespace


@dataclass(frozen=True)
class ToolOutcome:
    """The recorded result of one dispatched tool call."""

    name: str
    ok: bool
    fail_closed: bool
    summary: str
    result: Any = None


@dataclass(frozen=True)
class ToolSpec:
    """One drivable ai-memory tool."""

    name: str
    kind: str
    http_method: str
    path: str
    source: str  # "sdk" or "driver-local"
    description: str
    parameters: dict[str, Any]
    handler: Handler
    agent_selectable: bool = True

    def openai_schema(self) -> dict[str, Any]:
        """The OpenAI-function tool schema the model sees."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ---------------------------------------------------------------------------
# Driver-local raw-route helpers (routes the SDK client does not wrap).
# ---------------------------------------------------------------------------


def _raw(client: AsyncAiMemoryClient) -> Any:
    """The client's underlying ``httpx.AsyncClient`` for driver-local routes.

    Mirrors the SDK's own offline tests, which reach ``_client`` directly to
    probe URL shapes. Kept in one place so the private-attribute access is
    auditable.
    """
    return client._client  # noqa: SLF001 - intentional: SDK lacks these routes


async def _post_raw(client: AsyncAiMemoryClient, path: str, body: dict[str, Any]) -> Any:
    resp = await _raw(client).post(path, json=body)
    resp.raise_for_status()
    return resp.json()


async def _get_raw(client: AsyncAiMemoryClient, path: str) -> Any:
    resp = await _raw(client).get(path)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Handlers. Each takes (client, identity, args) and returns the raw result.
# They raise on failure; dispatch() converts that into a fail-closed outcome.
# ---------------------------------------------------------------------------


async def _h_store(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    title = _require(args, "title")
    content = _require(args, "content")
    ns = ident.confine(args.get("namespace"))
    return await client.store(
        title=title,
        content=content,
        namespace=ns,
        tier=args.get("tier"),
        tags=args.get("tags"),
        priority=args.get("priority"),
        agent_id=ident.agent_id,
        signing_key=ident.signing_key,
    )


async def _h_update(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    memory_id = _require(args, "memory_id")
    patch = {k: args[k] for k in ("content", "priority", "tags", "confidence") if k in args}
    return await client.update(memory_id, patch, expected_version=args.get("expected_version"))


async def _h_delete(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.delete(_require(args, "memory_id"))


async def _h_promote(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.promote(_require(args, "memory_id"))


async def _h_forget(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    # Confined to the agent's PRIVATE namespace: bulk delete never reaches a
    # shared consensus namespace, so one agent cannot wipe collective state.
    return await client.forget(
        namespace=ident.namespace, pattern=args.get("pattern"), tier=args.get("tier")
    )


async def _h_link(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.link(
        _require(args, "source_id"),
        _require(args, "target_id"),
        args.get("relation", "related_to"),
    )


async def _h_recall(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.recall(
        _require(args, "context"), namespace=ident.namespace, limit=args.get("limit")
    )


async def _h_search(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.search(
        _require(args, "q"), namespace=ident.namespace, limit=args.get("limit")
    )


async def _h_list(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.list(
        namespace=ident.namespace, tier=args.get("tier"), limit=args.get("limit")
    )


async def _h_get(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.get(_require(args, "memory_id"))


async def _h_get_links(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.get_links(_require(args, "memory_id"))


async def _h_lineage(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.lineage(
        _require(args, "memory_id"), direction=args.get("direction", "ancestors")
    )


async def _h_inbox(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.inbox(
        agent_id=ident.agent_id, unread_only=args.get("unread_only"), limit=args.get("limit")
    )


async def _h_notify(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.notify(
        {
            "to_agent": _require(args, "to_agent"),
            "from_agent": ident.agent_id,
            "subject": args.get("subject", ""),
            "body": args.get("body", ""),
        }
    )


async def _h_stats(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.stats()


async def _h_namespaces(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.namespaces()


async def _h_agents(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.agents()


async def _h_health(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await client.health()


async def _h_capabilities(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    return await _get_raw(client, "/api/v1/capabilities")


# -- driver-local writes ----------------------------------------------------


async def _h_signal_send(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    """``POST /api/v1/signals`` — coordination fan-out.

    ``from_agent`` is NOT a body field: the daemon takes it from the
    authenticated caller (the client's ``X-Agent-Id`` header), mirroring the
    create-memory provenance posture.
    """
    body = {
        "namespace": ident.confine(args.get("namespace")),
        "subject": _require(args, "subject"),
        "to_agent": args.get("to_agent"),
        "body": args.get("body", {}),
        "signal_type": args.get("signal_type"),
        "correlation_id": args.get("correlation_id"),
        "in_reply_to": args.get("in_reply_to"),
    }
    return await _post_raw(
        client, "/api/v1/signals", {k: v for k, v in body.items() if v is not None}
    )


async def _h_consolidate(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    """``POST /api/v1/consolidate`` — merge N source memories into one."""
    ids = _require(args, "ids")
    body = {
        "ids": ids,
        "title": args.get("title", "consolidated"),
        "namespace": ident.confine(args.get("namespace")),
        "agent_id": ident.agent_id,
    }
    if args.get("summary"):
        body["summary"] = args["summary"]
    else:
        body["use_llm"] = True
    return await _post_raw(client, "/api/v1/consolidate", body)


async def _h_reflect(
    client: AsyncAiMemoryClient, ident: AgentIdentity, args: dict[str, Any]
) -> Any:
    """``POST /api/v1/memory_reflect`` — substrate reflection over a set."""
    body = {
        "agent_id": ident.agent_id,
        "namespace": ident.confine(args.get("namespace")),
        "limit": args.get("limit", 10),
    }
    return await _post_raw(client, "/api/v1/memory_reflect", body)


# ---------------------------------------------------------------------------
# The registry.
# ---------------------------------------------------------------------------

_S: dict[str, Any] = {"type": "string"}
_I: dict[str, Any] = {"type": "integer"}


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required or [],
        "additionalProperties": False,
    }


TOOL_SPECS: list[ToolSpec] = [
    # -- reads (perceive + act) --------------------------------------------
    ToolSpec("recall", KIND_READ, "POST", "/api/v1/recall", "sdk",
             "Hybrid FTS+semantic recall of memories relevant to a context string.",
             _schema({"context": _S, "limit": _I}, ["context"]), _h_recall),
    ToolSpec("search", KIND_READ, "GET", "/api/v1/search", "sdk",
             "Keyword FTS search over memories.",
             _schema({"q": _S, "limit": _I}, ["q"]), _h_search),
    ToolSpec("list_memories", KIND_READ, "GET", "/api/v1/memories", "sdk",
             "List memories in the agent's namespace, optionally by tier.",
             _schema({"tier": _S, "limit": _I}), _h_list),
    ToolSpec("get_memory", KIND_READ, "GET", "/api/v1/memories/{id}", "sdk",
             "Fetch one memory by id.",
             _schema({"memory_id": _S}, ["memory_id"]), _h_get),
    ToolSpec("get_links", KIND_READ, "GET", "/api/v1/links/{id}", "sdk",
             "List links of a memory.",
             _schema({"memory_id": _S}, ["memory_id"]), _h_get_links),
    ToolSpec("lineage", KIND_READ, "GET", "/api/v1/memories/{id}/lineage", "sdk",
             "Walk the derivation lineage-DAG of a memory.",
             _schema({"memory_id": _S, "direction": _S}, ["memory_id"]), _h_lineage),
    ToolSpec("inbox", KIND_READ, "GET", "/api/v1/inbox", "sdk",
             "Read this agent's received agent-to-agent messages.",
             _schema({"unread_only": {"type": "boolean"}, "limit": _I}), _h_inbox),
    ToolSpec("stats", KIND_READ, "GET", "/api/v1/stats", "sdk",
             "Daemon-wide memory statistics.", _schema({}), _h_stats),
    ToolSpec("namespaces", KIND_READ, "GET", "/api/v1/namespaces", "sdk",
             "List namespaces known to the daemon.", _schema({}), _h_namespaces),
    ToolSpec("agents", KIND_READ, "GET", "/api/v1/agents", "sdk",
             "List registered agents.", _schema({}), _h_agents),
    ToolSpec("health", KIND_READ, "GET", "/api/v1/health", "sdk",
             "Daemon liveness probe.", _schema({}), _h_health, agent_selectable=False),
    ToolSpec("capabilities", KIND_READ, "GET", "/api/v1/capabilities", "driver-local",
             "Report the daemon's live capability surface.", _schema({}), _h_capabilities,
             agent_selectable=False),
    # -- writes (act) -------------------------------------------------------
    ToolSpec("store", KIND_WRITE, "POST", "/api/v1/memories", "sdk",
             "Store a new attested memory in the agent's namespace.",
             _schema({"title": _S, "content": _S, "tier": _S, "priority": _I,
                      "tags": {"type": "array", "items": _S}}, ["title", "content"]), _h_store),
    ToolSpec("update", KIND_WRITE, "PUT", "/api/v1/memories/{id}", "sdk",
             "Update an existing memory (optionally version-guarded).",
             _schema({"memory_id": _S, "content": _S, "priority": _I,
                      "expected_version": _I}, ["memory_id"]), _h_update),
    ToolSpec("delete", KIND_WRITE, "DELETE", "/api/v1/memories/{id}", "sdk",
             "Delete (tombstone) a memory by id.",
             _schema({"memory_id": _S}, ["memory_id"]), _h_delete),
    ToolSpec("promote", KIND_WRITE, "POST", "/api/v1/memories/{id}/promote", "sdk",
             "Promote a memory's tier toward long-term.",
             _schema({"memory_id": _S}, ["memory_id"]), _h_promote),
    ToolSpec("forget", KIND_WRITE, "POST", "/api/v1/forget", "sdk",
             "Bulk-forget memories in the agent's private namespace by pattern/tier.",
             _schema({"pattern": _S, "tier": _S}), _h_forget),
    ToolSpec("link", KIND_WRITE, "POST", "/api/v1/links", "sdk",
             "Create a typed link between two memories.",
             _schema({"source_id": _S, "target_id": _S, "relation": _S},
                     ["source_id", "target_id"]), _h_link),
    ToolSpec("notify", KIND_WRITE, "POST", "/api/v1/notify", "sdk",
             "Send an agent-to-agent message.",
             _schema({"to_agent": _S, "subject": _S, "body": _S}, ["to_agent"]), _h_notify),
    ToolSpec("signal_send", KIND_WRITE, "POST", "/api/v1/signals", "driver-local",
             "Send a coordination signal (point-to-point or namespace broadcast).",
             _schema({"subject": _S, "to_agent": _S, "signal_type": _S,
                      "correlation_id": _S, "in_reply_to": _S,
                      "body": {"type": "object"}}, ["subject"]), _h_signal_send),
    ToolSpec("consolidate", KIND_WRITE, "POST", "/api/v1/consolidate", "driver-local",
             "Consolidate several source memories into one summary memory.",
             _schema({"ids": {"type": "array", "items": _S}, "title": _S, "summary": _S},
                     ["ids"]), _h_consolidate),
    ToolSpec("reflect", KIND_WRITE, "POST", "/api/v1/memory_reflect", "driver-local",
             "Reflect over the agent's memory substrate, minting reflection memories.",
             _schema({"limit": _I}), _h_reflect),
]

SPECS_BY_NAME: dict[str, ToolSpec] = {s.name: s for s in TOOL_SPECS}


def selectable_schemas() -> list[dict[str, Any]]:
    """OpenAI tool schemas for the tools the GLM model may choose."""
    return [s.openai_schema() for s in TOOL_SPECS if s.agent_selectable]


def _require(args: dict[str, Any], key: str) -> Any:
    if key not in args or args[key] is None:
        raise ValueError(f"missing required argument {key!r}")
    return args[key]


async def dispatch(
    client: AsyncAiMemoryClient,
    identity: AgentIdentity,
    tool_name: str,
    args: dict[str, Any],
) -> ToolOutcome:
    """Dispatch one tool call and return a recorded outcome.

    FAIL-CLOSED: any exception becomes ``ok=False, fail_closed=True`` with the
    error captured in ``summary``. The caller NEVER treats a failed tool as a
    success — this is how the swarm degrades (fewer results) rather than
    silently corrupting or fabricating state.
    """
    spec = SPECS_BY_NAME.get(tool_name)
    if spec is None:
        return ToolOutcome(tool_name, ok=False, fail_closed=True,
                           summary=f"unknown tool {tool_name!r}")
    try:
        result = await spec.handler(client, identity, args)
    except Exception as exc:  # noqa: BLE001 - fail-closed boundary, re-surfaced in outcome
        return ToolOutcome(tool_name, ok=False, fail_closed=True,
                           summary=f"{type(exc).__name__}: {exc}")
    return ToolOutcome(tool_name, ok=True, fail_closed=False,
                       summary=_summarize(result), result=result)


def _summarize(result: Any) -> str:
    text = repr(result)
    return text if len(text) <= 160 else text[:157] + "..."


__all__ = [
    "AgentIdentity",
    "KIND_ADMIN",
    "KIND_READ",
    "KIND_WRITE",
    "SPECS_BY_NAME",
    "TOOL_SPECS",
    "ToolOutcome",
    "ToolSpec",
    "dispatch",
    "selectable_schemas",
]
