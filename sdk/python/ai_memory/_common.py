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
import os
import ssl
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from ai_memory._version import __version__ as _SDK_VERSION
from ai_memory.errors import TransportError, raise_for_status
from ai_memory.models import CreateMemory

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ai_memory.attestation import AgentSigningKey

# v1.0.0 #3782 — ``https`` even on loopback. Since #3705/#3709 every daemon
# listener serves TLS and ``tls_bind_guard`` refuses to bind a plaintext one,
# so an ``http://`` default could never reach a daemon. A zero-config daemon
# serves a certificate from the local CA it writes to
# ``<key_dir>/tls/local-ca.pem`` on first boot; pass that path as ``verify=``.
DEFAULT_BASE_URL = "https://localhost:9077"
DEFAULT_TIMEOUT = 30.0
# v1.0.0 #3288 — rows per export page when the caller names no limit; the
# daemon's default page ceiling (``AI_MEMORY_MAX_PAGE_SIZE``).
DEFAULT_EXPORT_PAGE_ROWS = 1000
# The daemon's typed refusal of an export ``limit`` above its page ceiling.
EXPORT_LIMIT_OUT_OF_RANGE = "EXPORT_LIMIT_OUT_OF_RANGE"


def export_ceiling_from_error(exc: Exception) -> int | None:
    """The page ceiling a daemon named when it refused an export ``limit``
    (HTTP 400 ``EXPORT_LIMIT_OUT_OF_RANGE``), or ``None`` for any other error."""
    payload = getattr(exc, "payload", None)
    if not isinstance(payload, dict) or payload.get("code") != EXPORT_LIMIT_OUT_OF_RANGE:
        return None
    ceiling = payload.get("max")
    return ceiling if isinstance(ceiling, int) and ceiling > 0 else None

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


_UNVERIFIED_MESSAGE = (
    "verify=False is refused: it would turn the daemon's TLS listener "
    "into an unauthenticated one (an encrypted pipe to whoever answers). "
    "This covers any falsy or blank verify value and an SSL context that "
    "does not verify certificates. "
    "Pass the CA bundle path instead — verify=<key_dir>/tls/local-ca.pem "
    "for a zero-config daemon — or omit verify= to use the platform "
    "trust store (#3840)."
)


def _context_verifies(context: ssl.SSLContext) -> bool:
    """Whether ``context`` requires a certificate AND checks the hostname.

    Read through the ``ssl.SSLContext`` base-class descriptors: a subclass can
    override ``verify_mode``/``check_hostname`` as Python properties and report
    a secure state over a context OpenSSL runs unverified (#6248).
    """
    return bool(
        ssl.SSLContext.verify_mode.__get__(context) == ssl.CERT_REQUIRED  # type: ignore[attr-defined]
        and ssl.SSLContext.check_hostname.__get__(context)  # type: ignore[attr-defined]
    )


def _checked_verify(verify: object) -> bool | ssl.SSLContext | None:
    """Return the ONLY value ``build_httpx_kwargs`` may forward, or raise (#3840).

    Forwarded to httpx: ``None`` (platform trust store, kwarg omitted), ``True``,
    a caller ``ssl.SSLContext`` that is ``CERT_REQUIRED`` with ``check_hostname``
    on (read via the base-class descriptors), or a context this SDK builds
    itself from the exact ``str`` of a non-blank CA path (``str`` or
    ``os.PathLike``). Never the caller's own str/path object: httpx 0.27 decides
    on its truthiness and 0.28 mishandles ``os.PathLike`` (#6248, #6245).
    Refused, fail closed: ``False`` and every other falsy or blank value, a
    non-verifying context, and any type this SDK does not document.
    """
    if verify is None or verify is True:
        return verify
    if isinstance(verify, ssl.SSLContext):
        if _context_verifies(verify):
            return verify
        raise ValueError(_UNVERIFIED_MESSAGE)
    if isinstance(verify, (str, os.PathLike)):
        raw = os.fspath(verify)
        # `str.__str__` yields an exact `str`: no overridden `strip`/`__bool__`.
        path = str.__str__(raw) if isinstance(raw, str) else ""
        if path.strip():
            if os.path.isdir(path):
                return ssl.create_default_context(capath=path)
            return ssl.create_default_context(cafile=path)
    raise ValueError(_UNVERIFIED_MESSAGE)


def _request_hooks(context: ssl.SSLContext, *, is_async: bool) -> list[Any]:
    """An httpx ``request`` hook that re-checks a caller-held context (#6249).

    The caller keeps a reference to the context they passed in and may weaken it
    after construction; the check therefore runs on every request.
    """

    def _recheck() -> None:
        if not _context_verifies(context):
            raise ValueError(_UNVERIFIED_MESSAGE)

    if is_async:

        async def _arequest(_request: httpx.Request) -> None:
            _recheck()

        return [_arequest]

    def _request(_request: httpx.Request) -> None:
        _recheck()

    return [_request]


def build_httpx_kwargs(
    *,
    base_url: str,
    api_key: str | None,
    agent_id: str | None,
    timeout: float,
    verify: bool | str | None,
    cert: str | tuple[str, str] | None,
    extra_headers: dict[str, str] | None,
    is_async: bool = False,
) -> dict[str, Any]:
    """Build the ``httpx.Client`` / ``httpx.AsyncClient`` kwargs.

    mTLS is wired through the stock httpx params:

    * ``verify`` — path to the server CA bundle or ``True``. For a
      zero-config daemon this is ``<key_dir>/tls/local-ca.pem`` (#3782).
      ``False`` (or any other falsy non-path value) is REFUSED — see Raises.
    * ``cert`` — client certificate; accepts a single path or ``(cert, key)``.

    ``api_key`` is sent as ``X-API-Key`` (the server also accepts
    ``?api_key=`` query params, but a header keeps it out of access logs).
    ``agent_id`` is sent as ``X-Agent-Id`` — the HTTP daemon's default
    agent resolution precedence is body → header → per-request anonymous.

    Raises:
        ValueError: on ``verify=False`` (#3840). Under the transit-encryption
            standard (#3824) an unverified TLS channel is an encrypted pipe to
            whoever answers — the man-in-the-middle exposure the #3828
            ``http://`` refusal closes, one layer up. Accepted forms are exactly
            ``None``, ``True``, a non-blank CA path (``str`` or ``os.PathLike``)
            and an ``ssl.SSLContext`` that is ``CERT_REQUIRED`` with
            ``check_hostname`` on. Every other value is refused. Only a checked
            value reaches httpx: a CA path becomes a context this SDK builds
            from the exact path string (#6248, #6245), and a caller-supplied
            context is re-checked before every request (#6249; the client does
            not own it, so a later weakening is refused, not honoured). Both
            clients construct through this one funnel, so the refusal lives
            here once.
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
    # #3840 — `False` was documented as "never pass" and forwarded untouched.
    # httpx reads ANY falsy `verify` as "do not verify" (httpx 0.27.x does so
    # for `""` too), and a caller-supplied `ssl.SSLContext` is used as given.
    # Only the value `_checked_verify` returns is forwarded (#6248), and a
    # caller-held context is re-checked on every request (#6249).
    checked = _checked_verify(verify)
    if checked is not None:
        kwargs["verify"] = checked
    if isinstance(checked, ssl.SSLContext) and checked is verify:
        kwargs["event_hooks"] = {"request": _request_hooks(checked, is_async=is_async)}
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
