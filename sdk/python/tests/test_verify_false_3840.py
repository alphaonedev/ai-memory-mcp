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

import pathlib
import ssl

import certifi
import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient
from ai_memory._common import build_httpx_kwargs


class _EmptyStr(str):
    """A str subclass whose ``strip`` lies; the guard must not trust it."""

    def strip(self, chars: str | None = None) -> str:  # noqa: ARG002
        return "x"


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _no_hostname_check_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    return context

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


@pytest.mark.parametrize(
    "verify",
    ["", " ", "\t\n", _EmptyStr(""), b"", [], {}, 1, object()],
    ids=["empty", "space", "whitespace", "str-subclass-empty", "bytes", "list", "dict", "int", "object"],
)
def test_funnel_refuses_blank_or_undocumented_verify_values(verify: object) -> None:
    # httpx 0.27.x reads ``verify=""`` as "do not verify"; any value the SDK
    # does not document is refused rather than forwarded (fail closed, #3840).
    with pytest.raises(ValueError):
        _kwargs(verify)


@pytest.mark.parametrize("make", [_unverified_context, _no_hostname_check_context])
def test_funnel_refuses_non_verifying_ssl_context(make: object) -> None:
    with pytest.raises(ValueError):
        _kwargs(make())  # type: ignore[operator]


def test_funnel_admits_verifying_ssl_context_and_pathlike() -> None:
    context = ssl.create_default_context()
    assert _kwargs(context)["verify"] is context
    ca = pathlib.Path(certifi.where())
    assert _kwargs(ca)["verify"] == ca


@pytest.mark.parametrize("verify", ["", _unverified_context()], ids=["empty", "context"])
def test_both_constructors_refuse_bypass_forms(verify: object) -> None:
    with pytest.raises(ValueError):
        AiMemoryClient(base_url=BASE_URL, verify=verify)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AsyncAiMemoryClient(base_url=BASE_URL, verify=verify)  # type: ignore[arg-type]
