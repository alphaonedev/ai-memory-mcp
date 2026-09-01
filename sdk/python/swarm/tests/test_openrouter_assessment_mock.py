# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The NHI assessment uses a plain OpenRouter chat completion."""

from __future__ import annotations

import json

import httpx
import pytest

from swarm.openrouter import OpenRouterClient, OpenRouterError


@pytest.mark.asyncio
async def test_complete_sends_no_tools() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": " PASS "}}]})

    client = OpenRouterClient(api_key="test", model_slug="test-model", base_url="http://mock")
    await client._client.aclose()  # noqa: SLF001
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://mock", transport=httpx.MockTransport(handler)
    )
    try:
        content = await client.complete(messages=[{"role": "user", "content": "audit"}])
    finally:
        await client.aclose()
    assert content == "PASS"
    payload = json.loads(seen[0].content)
    assert payload["model"] == "test-model"
    assert "tools" not in payload
    assert "tool_choice" not in payload


@pytest.mark.asyncio
async def test_complete_rejects_empty_content() -> None:
    client = OpenRouterClient(api_key="test", model_slug="test-model", base_url="http://mock")
    await client._client.aclose()  # noqa: SLF001
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://mock",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})
        ),
    )
    try:
        with pytest.raises(OpenRouterError, match="assessment content"):
            await client.complete(messages=[])
    finally:
        await client.aclose()
