# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Minimal async OpenRouter chat client for the acceptance swarm.

Two deliberately small capabilities: issue a tool-selecting completion for an
agent's "decide" step, or a plain (no-tools) completion for the end-of-run
AI-NHI assessment.

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


@dataclass(frozen=True)
class AccountSnapshot:
    """OpenRouter's cumulative USD counters for the authenticated key."""

    usage: float
    usage_daily: float
    usage_weekly: float
    usage_monthly: float


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
            # OpenRouter returns per-generation `cost` only when asked (#3338).
            "usage": {"include": True},
        }
        body, message = await self._chat(payload)
        return Decision(
            content=message.get("content"),
            tool_calls=_parse_tool_calls(message.get("tool_calls") or []),
            raw=body,
        )

    async def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        temperature: float = 0.1,
    ) -> str:
        """Return one plain chat completion, with no tool surface attached.

        This is intentionally separate from :meth:`decide`: an assessment
        must describe the evidence it was given, never take another action.
        Empty or non-text content is malformed and therefore fails closed.
        """
        _body, message = await self._chat({
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "usage": {"include": True},
        })
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise OpenRouterError("malformed OpenRouter response: missing assessment content")
        return content.strip()

    async def _chat(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Post and validate the common OpenAI-compatible response envelope."""
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
            if not isinstance(body, dict) or not isinstance(message, dict):
                raise TypeError("response body/message is not an object")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise OpenRouterError(f"malformed OpenRouter response: {exc}") from exc
        return body, message

    async def account_snapshot(self) -> AccountSnapshot:
        """Read the authenticated key's cumulative USD usage counters."""
        try:
            resp = await self._client.get("/auth/key")
        except httpx.HTTPError as exc:
            raise OpenRouterError(f"OpenRouter usage transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise OpenRouterError(
                f"OpenRouter usage returned {resp.status_code}: {resp.text[:500]}"
            )
        try:
            data = resp.json()["data"]
            return AccountSnapshot(
                **{
                    name: float(data[name])
                    for name in (
                        "usage", "usage_daily", "usage_weekly", "usage_monthly"
                    )
                }
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise OpenRouterError(
                f"malformed OpenRouter usage response: {exc}"
            ) from exc


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
