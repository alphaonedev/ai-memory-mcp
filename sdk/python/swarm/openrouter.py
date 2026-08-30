# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Minimal async OpenRouter chat client for the acceptance swarm.

Exactly one capability: issue ONE ``glm-5.3-flash`` chat-completion call whose
tool schema IS the ai-memory tool surface, and hand back the model's chosen
tool call(s). This is the "decide" step of the agent loop.

Kept deliberately thin — stdlib + ``httpx`` (already an SDK dependency), no
OpenAI/LangChain SDK — because the swarm is test infrastructure, not shipped
product. The wire shape is the OpenAI-compatible ``/chat/completions`` schema
OpenRouter exposes.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import Any

import httpx


@dataclass(frozen=True)
class ToolCall:
    """One tool the model chose to invoke.

    Attributes:
        id: OpenRouter's opaque call id (echoed back in the tool result turn).
        name: The ai-memory tool name (matches a manifest entry).
        arguments: Parsed JSON arguments object (``{}`` when the model sent
            an empty or unparseable argument string — the dispatcher then
            relies on its own defaults / fails closed on required fields).
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Decision:
    """The model's decision for one loop step."""

    content: str | None
    tool_calls: list[ToolCall]
    raw: dict[str, Any]


class OpenRouterError(RuntimeError):
    """A non-2xx or malformed response from OpenRouter."""


class OpenRouterClient:
    """Async client bound to one OpenRouter endpoint + model slug."""

    def __init__(
        self,
        *,
        api_key: str,
        model_slug: str,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout: float = 30.0,
    ) -> None:
        self._model = model_slug
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                # OpenRouter attribution headers (optional, but polite).
                "HTTP-Referer": "https://github.com/alphaonedev/ai-memory-mcp",
                "X-Title": "ai-memory acceptance swarm",
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> OpenRouterClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def decide(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float = 0.2,
    ) -> Decision:
        """One chat-completion call; return the parsed decision.

        Raises:
            OpenRouterError: on a non-2xx response or a body missing the
                expected ``choices[0].message`` shape. The caller treats this
                as a fail-closed decide error (it never fabricates a tool
                call to keep going).
        """
        payload = {
            "model": self._model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": temperature,
        }
        try:
            resp = await self._client.post("/chat/completions", json=payload)
        except httpx.HTTPError as exc:
            raise OpenRouterError(f"OpenRouter transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise OpenRouterError(
                f"OpenRouter returned {resp.status_code}: {resp.text[:500]}"
            )
        try:
            body = resp.json()
            message = body["choices"][0]["message"]
        except (ValueError, KeyError, IndexError) as exc:
            raise OpenRouterError(f"malformed OpenRouter response: {exc}") from exc
        return Decision(
            content=message.get("content"),
            tool_calls=_parse_tool_calls(message.get("tool_calls") or []),
            raw=body,
        )


def _parse_tool_calls(raw_calls: list[dict[str, Any]]) -> list[ToolCall]:
    import json

    parsed: list[ToolCall] = []
    for call in raw_calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        if not name:
            continue
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
        except (ValueError, TypeError):
            args = {}
        if not isinstance(args, dict):
            args = {}
        parsed.append(ToolCall(id=call.get("id", ""), name=name, arguments=args))
    return parsed
