# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the sync and async clients.

The two clients have near-identical surfaces; everything that does not need
an ``await`` lives here. In particular:

* Auth header injection (``X-API-Key`` and/or ``X-Agent-Id``)
* mTLS ``httpx`` config builder
* Response -> error mapping (delegates to :mod:`ai_memory.errors`)
* JSON body prep that strips ``None`` values (so omitted optional request
  fields don't clobber server defaults)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from ai_memory._version import __version__ as _SDK_VERSION
from ai_memory.errors import TransportError, raise_for_status
from ai_memory.models import CreateMemory

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ai_memory.attestation import AgentSigningKey

DEFAULT_BASE_URL = "http://localhost:9077"
DEFAULT_TIMEOUT = 30.0

#: The daemon's own default `memory_kind` when the field is absent. Kept here
#: because a SIGNED write must sign the kind the server will actually store —
#: leaving `kind` unset while signing a different value silently 403s.
DEFAULT_MEMORY_KIND = "observation"

#: SDK version. Re-exported from :mod:`ai_memory._version`, the ONE literal
#: that `pyproject.toml`, `__init__.__version__`, this User-Agent, and the
#: README all derive from (#2455 — they had drifted to three different
#: answers: 1.0.0 / 0.8.0 / 0.6.0-alpha.0).
SDK_VERSION = _SDK_VERSION


def encode_path_segment(value: str) -> str:
    """Percent-encode one caller-controlled HTTP path segment.

    ``agent_id`` deliberately permits SPIFFE URIs and therefore slashes.
    Interpolating it directly would turn one route parameter into several
    path components. ``safe=''`` is load-bearing because ``quote`` otherwise
    preserves ``/`` by default.
    """
    return quote(value, safe="")


def build_httpx_kwargs(
    *,
    base_url: str,
    api_key: str | None,
    agent_id: str | None,
    timeout: float,
    verify: bool | str | None,
    cert: str | tuple[str, str] | None,
    extra_headers: dict[str, str] | None,
) -> dict[str, Any]:
    """Build the ``httpx.Client`` / ``httpx.AsyncClient`` kwargs.

    mTLS is wired through the stock httpx params:

    * ``verify`` — path to the server CA bundle or ``True`` / ``False``.
    * ``cert`` — client certificate; accepts a single path or ``(cert, key)``.

    ``api_key`` is sent as ``X-API-Key`` (the server also accepts
    ``?api_key=`` query params, but a header keeps it out of access logs).
    ``agent_id`` is sent as ``X-Agent-Id`` — the HTTP daemon's default
    agent resolution precedence is body → header → per-request anonymous.
    """
    headers: dict[str, str] = {
        "User-Agent": f"ai-memory-python/{SDK_VERSION}",
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-Key"] = api_key
    if agent_id:
        headers["X-Agent-Id"] = agent_id
    if extra_headers:
        headers.update(extra_headers)

    kwargs: dict[str, Any] = {
        "base_url": base_url.rstrip("/"),
        "headers": headers,
        "timeout": timeout,
    }
    if verify is not None:
        kwargs["verify"] = verify
    if cert is not None:
        kwargs["cert"] = cert
    return kwargs


def prep_json(body: Any) -> Any:
    """Serialize Pydantic models and drop ``None`` at the top level.

    The server uses ``#[serde(default)]`` on most optional fields, so
    sending an explicit ``null`` would *not* be equivalent to omitting the
    key — some handlers would clobber an existing value. We drop keys whose
    value is ``None`` to preserve server-side defaults.
    """
    if isinstance(body, BaseModel):
        # by_alias=True so request models that use Field(alias=...) round-trip
        # (e.g. InboxMessage's ``from_`` → ``from``).
        return {k: v for k, v in body.model_dump(by_alias=True).items() if v is not None}
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if v is not None}
    return body


def handle_response(response: httpx.Response) -> Any:
    """Raise on error, otherwise decode JSON (or return text for text/plain).

    ``/api/v1/metrics`` is Prometheus text; every other endpoint is JSON.
    """
    content_type = response.headers.get("content-type", "")
    if response.status_code >= 400:
        payload: Any
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            payload = response.text or None
        raise_for_status(response.status_code, payload)
    if "application/json" in content_type:
        return response.json()
    return response.text


def build_create_body(
    *,
    title: str,
    content: str,
    signing_key: AgentSigningKey | None = None,
    fields: dict[str, Any],
) -> CreateMemory:
    """Assemble a :class:`CreateMemory`, signing it when a key is supplied.

    #2455 — ``POST /api/v1/memories`` is ``WriteSurface::HttpDirect`` and
    fails CLOSED by default, so an unsigned store is ``403
    ATTESTATION_FAILED``. Passing ``signing_key`` makes the SDK usable
    against a stock daemon; omitting it preserves the previous behaviour for
    deployments that explicitly set ``AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0``.

    Signing requires ``agent_id`` because it is inside the signed envelope and
    the SDK must sign the SAME id the server attributes the write to. The
    envelope also pins ``kind`` and ``namespace``, so both are resolved to the
    exact values that go on the wire before signing — never afterwards.

    **Namespace caveat:** when the caller omits ``namespace`` this resolves to
    the COMPILED default (``"global"``). A daemon configured with
    ``[storage].default_namespace`` would store the row elsewhere, and since
    the namespace is inside the envelope the signature would not verify. The
    client cannot see a server-side override, so signed writes against such a
    deployment MUST pass ``namespace`` explicitly.

    Args:
        fields: Optional ``CreateMemory`` fields; ``None`` values are dropped
            so server-side defaults apply.

    Raises:
        ValueError: when ``signing_key`` is given without an ``agent_id``, or
            when a caller-supplied ``signature`` would collide with one this
            function would mint.
    """
    supplied = {k: v for k, v in fields.items() if v is not None}

    if signing_key is not None:
        if supplied.get("signature"):
            raise ValueError(
                "pass either signing_key or an explicit signature, not both"
            )
        agent_id = supplied.get("agent_id")
        if not agent_id:
            raise ValueError(
                "signing_key requires an explicit agent_id: the signature commits "
                "to the agent_id, so the SDK cannot sign a write whose identity "
                "the server would resolve from the X-Agent-Id header or an "
                "anonymous fallback."
            )
        # Import here so `cryptography` stays an optional dependency for
        # callers who never sign.
        from ai_memory.attestation import attestation_fields

        namespace = supplied.get("namespace", CreateMemory.model_fields["namespace"].default)
        kind = supplied.get("kind") or DEFAULT_MEMORY_KIND
        supplied.update(
            attestation_fields(
                signing_key,
                agent_id=agent_id,
                namespace=namespace,
                title=title,
                content=content,
                kind=kind,
                created_at=supplied.get("created_at"),
            )
        )
        supplied["namespace"] = namespace

    return CreateMemory(title=title, content=content, **supplied)


def if_match_headers(expected_version: int | str | None) -> dict[str, str] | None:
    """Build the ``If-Match`` header for an optimistic-concurrency update.

    The daemon reads the expected row version from ``If-Match`` (bare integer
    or quoted ETag-style), NOT from the request body — see
    ``src/handlers/memories.rs:245-260``. A stale version yields ``409``.
    """
    if expected_version is None:
        return None
    return {"If-Match": str(expected_version)}


def wrap_transport_error(exc: Exception) -> TransportError:
    """Convert an httpx transport error to our hierarchy."""
    return TransportError(f"transport error: {exc}", payload=None)
