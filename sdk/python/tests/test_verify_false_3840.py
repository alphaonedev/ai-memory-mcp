# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""``verify=False`` is REFUSED by the one constructor funnel (#3840).

The client docstring and the README both said "never pass ``verify=False``"
while ``build_httpx_kwargs`` forwarded it to ``httpx`` untouched, so
``AiMemoryClient(base_url="https://...", verify=False)`` connected with
certificate verification OFF: an encrypted pipe to whoever answers, the same
man-in-the-middle exposure the #3828 ``http://`` refusal closes, one layer up.

Both clients construct through ``build_httpx_kwargs``, so the refusal lives
there once (the #3828 precedent) and these pins cover the funnel AND both
constructors. ``None`` (platform trust store), ``True`` and a CA-bundle path
stay admitted.
"""

from __future__ import annotations

import certifi
import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient
from ai_memory._common import build_httpx_kwargs

BASE_URL = "https://localhost:9077"


def _kwargs(verify: object) -> dict:
    return build_httpx_kwargs(
        base_url=BASE_URL,
        api_key=None,
        agent_id=None,
        timeout=1.0,
        verify=verify,  # type: ignore[arg-type]
        cert=None,
        extra_headers=None,
    )


def test_funnel_refuses_verify_false_naming_parameter_and_fix() -> None:
    with pytest.raises(ValueError) as excinfo:
        _kwargs(False)
    message = str(excinfo.value)
    assert "verify=False" in message
    assert "local-ca.pem" in message


@pytest.mark.parametrize("verify", [0, 0.0])
def test_funnel_refuses_falsy_non_bool_verify(verify: object) -> None:
    # httpx treats any falsy ``verify`` as "do not verify"; a ``0`` must not
    # slip past a refusal spelled ``verify is False``.
    with pytest.raises(ValueError):
        _kwargs(verify)


@pytest.mark.parametrize("verify", [None, True, certifi.where()])
def test_funnel_admits_none_true_and_ca_path(verify: object) -> None:
    kwargs = _kwargs(verify)
    if verify is None:
        assert "verify" not in kwargs
    else:
        assert kwargs["verify"] == verify


def test_sync_constructor_refuses_verify_false() -> None:
    with pytest.raises(ValueError, match="verify=False"):
        AiMemoryClient(base_url=BASE_URL, verify=False)


def test_async_constructor_refuses_verify_false() -> None:
    with pytest.raises(ValueError, match="verify=False"):
        AsyncAiMemoryClient(base_url=BASE_URL, verify=False)


def test_sync_constructor_admits_ca_path() -> None:
    with AiMemoryClient(base_url=BASE_URL, verify=certifi.where()) as client:
        assert isinstance(client._client, httpx.Client)  # noqa: SLF001 - construction probe


async def test_async_constructor_admits_ca_path() -> None:
    async with AsyncAiMemoryClient(base_url=BASE_URL, verify=certifi.where()) as client:
        assert isinstance(client._client, httpx.AsyncClient)  # noqa: SLF001 - construction probe
