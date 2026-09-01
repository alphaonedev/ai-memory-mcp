# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for OpenRouter account-level usage snapshots."""

from __future__ import annotations

import httpx
import pytest

from swarm.openrouter import OpenRouterClient, OpenRouterError


@pytest.mark.asyncio
async def test_account_snapshot_reads_authenticated_key_counters() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {
            "usage": 1.25, "usage_daily": 0.25,
            "usage_weekly": 0.75, "usage_monthly": 1.0,
        }})

    client = OpenRouterClient(api_key="secret", model_slug="test")
    await client._client.aclose()  # noqa: SLF001
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="https://openrouter.ai/api/v1", transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer secret"},
    )
    try:
        snapshot = await client.account_snapshot()
    finally:
        await client.aclose()
    assert snapshot.usage == 1.25
    assert seen[0].url.path == "/api/v1/auth/key"
    assert seen[0].headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
async def test_account_snapshot_rejects_malformed_response() -> None:
    client = OpenRouterClient(api_key="secret", model_slug="test")
    await client._client.aclose()  # noqa: SLF001
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="https://openrouter.ai/api/v1",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )
    try:
        with pytest.raises(OpenRouterError, match="malformed OpenRouter usage response"):
            await client.account_snapshot()
    finally:
        await client.aclose()
