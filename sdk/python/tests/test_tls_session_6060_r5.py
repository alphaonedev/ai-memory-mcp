# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Post-handshake TLS session enforcement, round 5 of #6060.

ADR-003 condition 3: an unverified TLS session is refused before any request
byte (and the ``X-API-Key`` header) is written, on EVERY connection shape the
client can take: direct, an ``http://`` CONNECT proxy, an ``https://`` CONNECT
proxy (TLS in TLS) and SOCKS5, sync and async.

3-agent vote (6def5ab6), Q1 option A (#6349, #6376): every
``*.start_tls.complete`` session on the caller's context is fully verified; a
session on another context is admitted only on ``connection.start_tls`` as a
per-request "pending" proxy leg that must be followed by a verified origin
session before any non-CONNECT request is sent.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
from collections.abc import Iterator
from typing import Any, Callable

import httpcore
import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _common
from ai_memory._common import build_httpx_kwargs

from ._tlslab import Lab, RecordingServer, TunnelProxy

_CLIENTS = [AiMemoryClient, AsyncAiMemoryClient]
_API_KEY = "k-6060-r5"
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return Lab(tmp_path_factory.mktemp("lab6060r5"))


@pytest.fixture
def origin(lab: Lab) -> Iterator[RecordingServer]:
    server = RecordingServer(lab.server_context("origin"))
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def anonymous_origin() -> Iterator[RecordingServer]:
    """A TLS 1.2 origin with anonymous (auth-null) suites and no certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("aNULL:@SECLEVEL=0")
    server = RecordingServer(context)
    try:
        yield server
    finally:
        server.close()


def _clear_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


@pytest.fixture(params=["http", "https", "socks5"])
def proxy(
    request: pytest.FixtureRequest, lab: Lab, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TunnelProxy]:
    """A forward proxy the client picks up from the environment (httpx trust_env)."""
    kind = request.param
    if kind == "socks5":
        pytest.importorskip("socksio", reason="httpx needs socksio for a SOCKS proxy")
    tunnel = TunnelProxy(kind, lab.server_context("proxy") if kind == "https" else None)
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("ALL_PROXY" if kind == "socks5" else "HTTPS_PROXY", tunnel.url)
    # The proxy leg of an https:// proxy is httpx's own context (certifi plus
    # SSL_CERT_FILE), never the caller's: trust the lab CA there.
    monkeypatch.setenv("SSL_CERT_FILE", str(lab.ca_path))
    try:
        yield tunnel
    finally:
        tunnel.close()


Hook = Callable[[ssl.SSLContext], None]


def _fetch(
    client_cls: type,
    url: str,
    verify: Any,
    paths: tuple[str, ...] = ("/x",),
    hook: Hook | None = None,
) -> list[int]:
    """GET each path on one client; ``hook`` runs after the SDK's request check."""
    context = verify if isinstance(verify, ssl.SSLContext) else None

    def weaken(_request: httpx.Request) -> None:
        if hook is not None and context is not None:
            hook(context)

    async def aweaken(_request: httpx.Request) -> None:
        weaken(_request)

    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=url, verify=verify, api_key=_API_KEY, timeout=5) as client:
            client._client.event_hooks["request"].append(weaken)  # noqa: SLF001
            return [client._client.get(path).status_code for path in paths]  # noqa: SLF001

    async def run() -> list[int]:
        async with AsyncAiMemoryClient(
            base_url=url, verify=verify, api_key=_API_KEY, timeout=5
        ) as client:
            client._client.event_hooks["request"].append(aweaken)  # noqa: SLF001
            return [(await client._client.get(path)).status_code for path in paths]  # noqa: SLF001

    return asyncio.run(run())


def _fool_predicate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-handshake predicate admits anything: the session check must hold alone."""
    monkeypatch.setattr("ai_memory._common._context_verifies", lambda _context: True)


def _cert_none_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _anonymous_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_ciphers("HIGH:aNULL:@SECLEVEL=0")
    return context


# ---- #6349: the tunnelled origin session is checked before the request -----


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_tunnelled_unverified_origin_is_refused_before_any_byte_6349(
    proxy: TunnelProxy, origin: RecordingServer, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _fool_predicate(monkeypatch)
    with pytest.raises(ValueError, match="verify=False"):
        _fetch(client_cls, origin.url, _cert_none_context())
    assert len(proxy.tunnels) == 1  # the origin was reached through the proxy
    assert origin.hits == []
    assert origin.api_keys == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_tunnelled_anonymous_origin_is_refused_before_any_byte_6349(
    proxy: TunnelProxy,
    anonymous_origin: RecordingServer,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    _fool_predicate(monkeypatch)
    with pytest.raises(ValueError, match="verify=False"):
        _fetch(client_cls, anonymous_origin.url, _anonymous_context())
    assert anonymous_origin.hits == []
    assert anonymous_origin.api_keys == []


# ---- #6376: a verified context works through every proxy shape -------------


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_verified_context_connects_through_every_proxy_6376(
    proxy: TunnelProxy, origin: RecordingServer, lab: Lab, client_cls: type
) -> None:
    assert _fetch(client_cls, origin.url, lab.client_context(), ("/a", "/b")) == [200, 200]
    assert origin.hits == ["/a", "/b"]
    assert origin.api_keys == [_API_KEY, _API_KEY]
    assert len(proxy.tunnels) == 1  # the verified tunnel is pooled and reused


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_verified_context_connects_directly_6376(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    assert _fetch(client_cls, origin.url, lab.client_context(), ("/a", "/b")) == [200, 200]
    assert origin.hits == ["/a", "/b"]


# ---- synthetic event sequences: branches a real server cannot reach --------


class _Session:
    """A stand-in for ``ssl.SSLObject`` after a handshake."""

    def __init__(self, context: object, *, host: str = "localhost", bits: int = 256) -> None:
        self.context = context
        self._peer = {
            "subject": ((("commonName", host),),),
            "subjectAltName": (("DNS", host),),
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "notAfter": "Jan  1 00:00:00 2099 GMT",
        }
        self._bits = bits

    def getpeercert(self, binary_form: bool = False) -> object:  # noqa: FBT001, FBT002
        return self._peer

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", self._bits)


class _Stream:
    def __init__(self, session: object) -> None:
        self.session = session
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        return self.session if name == "ssl_object" else None

    def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


_ORIGIN = "https://localhost:9077"


def _connect(
    target: bytes = b"localhost:9077", headers: list[tuple[bytes, bytes]] | None = None
) -> httpcore.Request:
    url = httpcore.URL(scheme=b"https", host=b"proxy.lab", port=3128, target=target)
    return httpcore.Request(
        b"CONNECT", url, headers=headers or [(b"Host", target), (b"Accept", b"*/*")]
    )


def _get_request() -> httpcore.Request:
    return httpcore.Request(b"GET", _ORIGIN + "/x", headers=[(b"X-API-Key", _API_KEY.encode())])


def _gated_trace(context: ssl.SSLContext, request: httpx.Request, *, is_async: bool) -> Any:
    """The trace the SDK's gated transport hands its inner transport (#6537)."""
    captured: list[Any] = []

    def capture(sent: httpx.Request) -> httpx.Response:
        captured.append(sent.extensions["trace"])
        return httpx.Response(200)

    if is_async:

        async def acapture(sent: httpx.Request) -> httpx.Response:
            return capture(sent)

        transport: Any = _common._AsyncGatedTransport(  # noqa: SLF001
            httpx.MockTransport(acapture), context
        )
        asyncio.run(transport.handle_async_request(request))
    else:
        _common._GatedTransport(httpx.MockTransport(capture), context).handle_request(  # noqa: SLF001
            request
        )
    return captured[0]


class _Driver:
    """Runs a fresh request through the SDK's gated transport and drives its trace."""

    def __init__(self, context: ssl.SSLContext, *, is_async: bool) -> None:
        kwargs = build_httpx_kwargs(
            base_url=_ORIGIN,
            api_key=_API_KEY,
            agent_id=None,
            timeout=1.0,
            verify=context,
            cert=None,
            extra_headers=None,
            is_async=is_async,
        )
        self.is_async = is_async
        self.context = context
        self.hooks = kwargs["event_hooks"]

    def new_request(self) -> Callable[[str, dict[str, Any]], None]:
        request = httpx.Request("GET", _ORIGIN + "/x")
        trace = _gated_trace(self.context, request, is_async=self.is_async)

        def fire(event: str, info: dict[str, Any]) -> None:
            if self.is_async:
                asyncio.run(trace(event, info))
            else:
                trace(event, info)

        return fire


@pytest.fixture(params=[False, True], ids=["sync", "async"])
def driver(request: pytest.FixtureRequest) -> tuple[_Driver, ssl.SSLContext]:
    context = ssl.create_default_context()
    return _Driver(context, is_async=request.param), context


@pytest.mark.parametrize("event", ["proxy.start_tls.complete", "socks.start_tls.complete"])
def test_tunnelled_session_on_another_context_is_refused_and_closed_6349(
    driver: tuple[_Driver, ssl.SSLContext], event: str
) -> None:
    drive, _ = driver
    stream = _Stream(_Session(ssl.create_default_context()))
    with pytest.raises(ValueError, match="verify=False"):
        drive.new_request()(event, {"return_value": stream})
    assert stream.closed


@pytest.mark.parametrize(
    "event",
    ["connection.start_tls.complete", "proxy.start_tls.complete", "socks.start_tls.complete"],
)
def test_missing_session_is_refused_on_every_tls_event_6349(
    driver: tuple[_Driver, ssl.SSLContext], event: str
) -> None:
    drive, _ = driver
    stream = _Stream(None)
    with pytest.raises(ValueError, match="verify=False"):
        drive.new_request()(event, {"return_value": stream})
    assert stream.closed


def test_proxy_leg_then_verified_tunnel_is_admitted_6376(
    driver: tuple[_Driver, ssl.SSLContext],
) -> None:
    drive, context = driver
    fire = drive.new_request()
    leg = _Stream(_Session(ssl.create_default_context(), host="proxy.lab"))
    fire("connection.start_tls.complete", {"return_value": leg})
    fire("http11.send_request_headers.started", {"request": _connect()})
    fire("proxy.start_tls.complete", {"return_value": _Stream(_Session(context))})
    fire("http11.send_request_headers.started", {"request": _get_request()})
    assert not leg.closed


@pytest.mark.parametrize(
    "event",
    [
        "http11.send_request_headers.started",
        "http2.send_connection_init.started",
        "http2.send_request_headers.started",
    ],
)
def test_foreign_session_without_a_verified_tunnel_never_sends_the_request_6349(
    driver: tuple[_Driver, ssl.SSLContext], event: str
) -> None:
    # A direct connection whose handshake ran on another context looks like a
    # proxy leg until the request goes out: it is refused there, and closed.
    drive, _ = driver
    fire = drive.new_request()
    leg = _Stream(_Session(ssl.create_default_context()))
    fire("connection.start_tls.complete", {"return_value": leg})
    with pytest.raises(ValueError, match="verify=False"):
        fire(event, {"request": _get_request()})
    assert leg.closed


@pytest.mark.parametrize(
    "connect",
    [
        _connect(target=b"elsewhere.lab:9077"),
        _connect(headers=[(b"Host", b"localhost:9077"), (b"X-API-Key", _API_KEY.encode())]),
        _connect(headers=[(b"Host", b"localhost:9077"), (b"x-agent-id", b"ai:x")]),
    ],
    ids=["other-target", "api-key", "agent-id"],
)
def test_only_the_tunnel_connect_crosses_a_pending_proxy_leg_6349(
    driver: tuple[_Driver, ssl.SSLContext], connect: httpcore.Request
) -> None:
    drive, _ = driver
    fire = drive.new_request()
    leg = _Stream(_Session(ssl.create_default_context()))
    fire("connection.start_tls.complete", {"return_value": leg})
    with pytest.raises(ValueError, match="verify=False"):
        fire("http11.send_request_headers.started", {"request": connect})
    assert leg.closed


def test_pending_state_is_per_request_6349(driver: tuple[_Driver, ssl.SSLContext]) -> None:
    # Request B's verified tunnel must not clear request A's pending proxy leg.
    drive, context = driver
    fire_a, fire_b = drive.new_request(), drive.new_request()
    leg = _Stream(_Session(ssl.create_default_context()))
    fire_a("connection.start_tls.complete", {"return_value": leg})
    fire_b("proxy.start_tls.complete", {"return_value": _Stream(_Session(context))})
    with pytest.raises(ValueError, match="verify=False"):
        fire_a("http11.send_request_headers.started", {"request": _get_request()})
    assert leg.closed


# ---- #6350: the session must authenticate the host the request goes to ----


@pytest.fixture
def wrong_name_origin(lab: Lab) -> Iterator[RecordingServer]:
    """An origin whose CA-valid certificate names another host."""
    server = RecordingServer(
        lab.server_context("wrong-name", dns=("wrong.lab",), ips=(), common_name="wrong.lab")
    )
    try:
        yield server
    finally:
        server.close()


def _no_hostname_check(context: ssl.SSLContext) -> None:
    """Weaken the caller's context AFTER the SDK's per-request check ran."""
    context.check_hostname = False


def _refused_then_reconnects(client_cls: type, url: str, context: ssl.SSLContext) -> object:
    """First request: hostname check off after the SDK check, must be refused.

    Second request on the SAME client with the check restored: must handshake
    again (and fail on the name), never reuse the refused connection.
    Returns what the second request produced: a status code or exception type.
    """
    weakened = [True]

    def weaken(_request: httpx.Request) -> None:
        if weakened[0]:
            _no_hostname_check(context)

    async def aweaken(_request: httpx.Request) -> None:
        weaken(_request)

    def restore() -> None:
        weakened[0] = False
        context.check_hostname = True

    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=url, verify=context, api_key=_API_KEY, timeout=5) as client:
            client._client.event_hooks["request"].append(weaken)  # noqa: SLF001
            with pytest.raises(ValueError, match="verify=False"):
                client._client.get("/first")  # noqa: SLF001
            restore()
            try:
                return client._client.get("/second").status_code  # noqa: SLF001
            except httpx.ConnectError as exc:
                return type(exc)

    async def run() -> object:
        async with AsyncAiMemoryClient(
            base_url=url, verify=context, api_key=_API_KEY, timeout=5
        ) as client:
            client._client.event_hooks["request"].append(aweaken)  # noqa: SLF001
            with pytest.raises(ValueError, match="verify=False"):
                await client._client.get("/first")  # noqa: SLF001
            restore()
            try:
                return (await client._client.get("/second")).status_code  # noqa: SLF001
            except httpx.ConnectError as exc:
                return type(exc)

    return asyncio.run(run())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_wrong_name_session_is_refused_and_evicted_6350(
    wrong_name_origin: RecordingServer,
    lab: Lab,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    _clear_proxy_env(monkeypatch)
    second = _refused_then_reconnects(client_cls, wrong_name_origin.url, lab.client_context())
    assert second is httpx.ConnectError  # a fresh handshake, not the pooled session
    assert wrong_name_origin.hits == []
    assert wrong_name_origin.api_keys == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_wrong_name_tunnelled_session_is_refused_6350(
    proxy: TunnelProxy, wrong_name_origin: RecordingServer, lab: Lab, client_cls: type
) -> None:
    with pytest.raises(ValueError, match="verify=False"):
        _fetch(client_cls, wrong_name_origin.url, lab.client_context(), hook=_no_hostname_check)
    assert wrong_name_origin.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_dns_only_certificate_does_not_cover_an_ip_host_6350(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    server = RecordingServer(lab.server_context("dns-only", dns=("localhost",), ips=()))
    try:
        url = f"https://127.0.0.1:{server.port}"
        with pytest.raises(ValueError, match="verify=False"):
            _fetch(client_cls, url, lab.client_context(), hook=_no_hostname_check)
        assert server.hits == []
    finally:
        server.close()


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_ip_san_covers_an_ip_host_6350(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    assert _fetch(client_cls, f"https://127.0.0.1:{origin.port}", lab.client_context()) == [200]


def _peer(dns: tuple[str, ...] = (), ips: tuple[str, ...] = (), cn: str | None = None) -> Any:
    peer: dict[str, Any] = {}
    sans = tuple(("DNS", name) for name in dns) + tuple(("IP Address", ip) for ip in ips)
    if sans:
        peer["subjectAltName"] = sans
    if cn is not None:
        peer["subject"] = ((("commonName", cn),),)
    return peer


@pytest.mark.parametrize(
    ("peer", "host", "matches"),
    [
        (_peer(dns=("api.lab.example",)), "API.lab.example.", True),
        (_peer(dns=("*.lab.example",)), "api.lab.example", True),
        (_peer(dns=("*.lab.example",)), "lab.example", False),
        (_peer(dns=("*.lab.example",)), "a.b.lab.example", False),
        (_peer(dns=("*.example",)), "lab.example", False),
        (_peer(dns=("a*.lab.example",)), "api.lab.example", False),
        (_peer(dns=("api.*.example",)), "api.lab.example", False),
        (_peer(dns=("localhost",)), "127.0.0.1", False),
        (_peer(ips=("127.0.0.1",)), "127.0.0.1", True),
        (_peer(ips=("::1",)), "0:0::1", True),
        (_peer(ips=("127.0.0.1",)), "localhost", False),
        (_peer(dns=("127.0.0.1",)), "127.0.0.1", False),
        (_peer(cn="api.lab.example"), "api.lab.example", True),
        (_peer(dns=("other.example",), cn="api.lab.example"), "api.lab.example", False),
        (_peer(cn="127.0.0.1"), "127.0.0.1", False),
        (_peer(), "api.lab.example", False),
    ],
)
def test_peer_name_matching_6350(peer: Any, host: str, matches: bool) -> None:
    from ai_memory._common import _peer_matches_host

    context = ssl.create_default_context()
    assert _peer_matches_host(peer, host, context) is matches


def test_common_name_fallback_follows_the_context_6350() -> None:
    from ai_memory._common import _peer_matches_host

    context = ssl.create_default_context()
    context.hostname_checks_common_name = False
    assert not _peer_matches_host(_peer(cn="api.lab.example"), "api.lab.example", context)


# ---- #6375: verify_flags that relax chain validation are refused -----------

# OpenSSL X509_V_FLAG_* bits that relax validation (by value: Python names
# only some of them in ssl.VerifyFlags).
_RELAXING_FLAGS = {
    "CB_ISSUER_CHECK": 0x1,
    "USE_CHECK_TIME": 0x2,
    "IGNORE_CRITICAL": 0x10,
    "ALLOW_PROXY_CERTS": 0x40,
    "NO_CHECK_TIME": 0x200000,
    "UNKNOWN_HIGH_BIT": 0x40000000,
}
# Bits that only strengthen validation (or are Python 3.13+ defaults).
_STRENGTHENING_FLAGS = {
    "CRL_CHECK_LEAF": 0x4,
    "CRL_CHECK_CHAIN": 0xC,
    "X509_STRICT": 0x20,
    "POLICY_CHECK": 0x80,
    "EXPLICIT_POLICY": 0x100,
    "INHIBIT_ANY": 0x200,
    "INHIBIT_MAP": 0x400,
    "EXTENDED_CRL_SUPPORT": 0x1000,
    "USE_DELTAS": 0x2000,
    "CHECK_SS_SIGNATURE": 0x4000,
    "TRUSTED_FIRST": 0x8000,
    "SUITEB_128_LOS": 0x30000,
    "PARTIAL_CHAIN": 0x80000,
    "NO_ALT_CHAINS": 0x100000,
}


def _with_flags(context: ssl.SSLContext, bits: int) -> ssl.SSLContext:
    context.verify_flags = ssl.VerifyFlags(int(context.verify_flags) | bits)
    return context


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("bits", _RELAXING_FLAGS.values(), ids=_RELAXING_FLAGS.keys())
def test_relaxing_verify_flags_are_refused_at_construction_6375(
    client_cls: type, bits: int
) -> None:
    context = _with_flags(ssl.create_default_context(), bits)
    with pytest.raises(ValueError, match="verify=False"):
        client_cls(base_url=_ORIGIN, verify=context)


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("bits", _STRENGTHENING_FLAGS.values(), ids=_STRENGTHENING_FLAGS.keys())
def test_strengthening_verify_flags_are_admitted_6375(client_cls: type, bits: int) -> None:
    client = client_cls(base_url=_ORIGIN, verify=_with_flags(ssl.create_default_context(), bits))
    if client_cls is AiMemoryClient:
        client.close()
    else:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_relaxing_flag_set_after_construction_is_refused_per_request_6375(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    context = lab.client_context()

    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=origin.url, verify=context, timeout=5) as client:
            _with_flags(context, _RELAXING_FLAGS["NO_CHECK_TIME"])
            with pytest.raises(ValueError, match="verify=False is refused"):
                client._client.get("/x")  # noqa: SLF001
    else:

        async def run() -> None:
            async with AsyncAiMemoryClient(
                base_url=origin.url, verify=context, timeout=5
            ) as client:
                _with_flags(context, _RELAXING_FLAGS["NO_CHECK_TIME"])
                with pytest.raises(ValueError, match="verify=False is refused"):
                    await client._client.get("/x")  # noqa: SLF001

        asyncio.run(run())
    assert origin.hits == []


_DAY = datetime.timedelta(days=1)


def _no_time_check(context: ssl.SSLContext) -> None:
    """Turn validity-date checking off AFTER the SDK's per-request check ran."""
    _with_flags(context, _RELAXING_FLAGS["NO_CHECK_TIME"])


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("window", ["expired", "not-yet-valid"])
def test_out_of_date_leaf_is_refused_after_the_handshake_6375(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type, window: str
) -> None:
    # The flag is set AFTER the SDK's per-request check, before the handshake:
    # only the post-handshake leaf validity check stands between the request
    # and a server whose certificate is out of date.
    _clear_proxy_env(monkeypatch)
    now = datetime.datetime.now(datetime.timezone.utc)
    if window == "expired":
        dates = {"not_before": now - 3 * _DAY, "not_after": now - _DAY}
    else:
        dates = {"not_before": now + _DAY, "not_after": now + 3 * _DAY}
    server = RecordingServer(lab.server_context(f"leaf-{window}", **dates))
    try:
        with pytest.raises(ValueError, match="verify=False"):
            _fetch(
                client_cls,
                server.url,
                lab.client_context(),
                hook=_no_time_check,
            )
        assert server.hits == []
    finally:
        server.close()


# ---- #6305: suites without server authentication refused at construction --

_UNAUTHENTICATED_SUITES = {
    "auth-null": "aNULL:@SECLEVEL=0",
    "null-encryption": "eNULL:@SECLEVEL=0",
    "auth-psk": "PSK:@SECLEVEL=0",
    "auth-srp": "SRP:@SECLEVEL=0",
    "openssl-DEFAULT": "DEFAULT",
}


def _with_ciphers(spec: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    try:
        context.set_ciphers(spec)
    except ssl.SSLError:
        pytest.skip(f"this OpenSSL has no {spec!r} suites")
    return context


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    "spec", _UNAUTHENTICATED_SUITES.values(), ids=_UNAUTHENTICATED_SUITES.keys()
)
def test_unauthenticated_suites_are_refused_at_construction_6305(
    client_cls: type, spec: str
) -> None:
    context = _with_ciphers(spec)
    if not any(
        suite.get("auth") in {"auth-null", "auth-psk", "auth-srp"} or suite.get("symmetric") is None
        for suite in context.get_ciphers()
    ):
        pytest.skip(f"{spec!r} has no unauthenticated suite on this OpenSSL")
    with pytest.raises(ValueError, match="verify=False") as refused:
        client_cls(base_url=_ORIGIN, verify=context)
    assert ":!PSK:!SRP:!aNULL:!eNULL" in str(refused.value)  # names the remedy


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_remedy_cipher_string_is_admitted_6305(client_cls: type) -> None:
    context = _with_ciphers("DEFAULT:!PSK:!SRP:!aNULL:!eNULL")
    client = client_cls(base_url=_ORIGIN, verify=context)
    if client_cls is AiMemoryClient:
        client.close()
    else:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_unauthenticated_suites_set_after_construction_are_refused_per_request_6305(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    context = lab.client_context()
    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=origin.url, verify=context, timeout=5) as client:
            context.set_ciphers("HIGH:aNULL:@SECLEVEL=0")
            with pytest.raises(ValueError, match="verify=False is refused"):
                client._client.get("/x")  # noqa: SLF001
    else:

        async def run() -> None:
            async with AsyncAiMemoryClient(
                base_url=origin.url, verify=context, timeout=5
            ) as client:
                context.set_ciphers("HIGH:aNULL:@SECLEVEL=0")
                with pytest.raises(ValueError, match="verify=False is refused"):
                    await client._client.get("/x")  # noqa: SLF001

        asyncio.run(run())
    assert origin.hits == []


class _NoCipherSession(_Session):
    def cipher(self) -> Any:
        return None


@pytest.mark.parametrize("session_kind", ["zero-secret-bits", "no-cipher"])
def test_session_without_secret_bits_is_refused_6305(
    driver: tuple[_Driver, ssl.SSLContext], session_kind: str
) -> None:
    drive, context = driver
    session = (
        _Session(context, bits=0)
        if session_kind == "zero-secret-bits"
        else _NoCipherSession(context)
    )
    stream = _Stream(session)
    with pytest.raises(ValueError, match="verify=False"):
        drive.new_request()("connection.start_tls.complete", {"return_value": stream})
    assert stream.closed


# ---- #6377: a CA directory is read once, at construction, and not shared ---

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")


def _subject_hash(cert_path: pathlib.Path) -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to hash a CA directory")
    return subprocess.run(  # noqa: S603 - fixed argv
        [openssl, "x509", "-hash", "-noout", "-in", str(cert_path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _add_anchor(directory: pathlib.Path, cert_path: pathlib.Path) -> pathlib.Path:
    entry = directory / f"{_subject_hash(cert_path)}.0"
    shutil.copy(cert_path, entry)
    entry.chmod(0o644)
    return entry


def _ca_dir(tmp_path: pathlib.Path, name: str = "ca", mode: int = 0o755) -> pathlib.Path:
    directory = tmp_path / name
    directory.mkdir()
    directory.chmod(mode)
    return directory


def _get_once(client_cls: type, url: str, verify: Any) -> object:
    """One GET on a fresh client: the status code, or the connect error type."""
    try:
        return _fetch(client_cls, url, verify)[0]
    except httpx.ConnectError as exc:
        return type(exc)


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_anchor_added_after_construction_is_not_trusted_6377(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    _clear_proxy_env(monkeypatch)
    directory = _ca_dir(tmp_path)
    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=origin.url, verify=str(directory), timeout=5) as client:
            _add_anchor(directory, lab.ca_path)
            with pytest.raises(httpx.ConnectError):
                client._client.get("/x")  # noqa: SLF001
    else:

        async def run() -> None:
            async with AsyncAiMemoryClient(
                base_url=origin.url, verify=str(directory), timeout=5
            ) as client:
                _add_anchor(directory, lab.ca_path)
                with pytest.raises(httpx.ConnectError):
                    await client._client.get("/x")  # noqa: SLF001

        asyncio.run(run())
    assert origin.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_anchor_present_at_construction_is_trusted_6377(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    _clear_proxy_env(monkeypatch)
    directory = _ca_dir(tmp_path)
    _add_anchor(directory, lab.ca_path)
    assert _get_once(client_cls, origin.url, str(directory)) == 200


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777, 0o1777], ids=oct)
def test_shared_writable_ca_directory_is_refused_6377(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type, mode: int
) -> None:
    directory = _ca_dir(tmp_path)
    _add_anchor(directory, lab.ca_path)
    directory.chmod(mode)
    with pytest.raises(ValueError, match="writable") as refused:
        client_cls(base_url=_ORIGIN, verify=str(directory))
    assert str(directory) in str(refused.value)
    assert oct(mode)[2:] in str(refused.value)  # names the mode, not the contents


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("mode", [0o664, 0o646], ids=oct)
def test_shared_writable_ca_file_is_refused_6377(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type, mode: int
) -> None:
    bundle = tmp_path / "bundle.pem"
    shutil.copy(lab.ca_path, bundle)
    bundle.chmod(mode)
    with pytest.raises(ValueError, match="writable"):
        client_cls(base_url=_ORIGIN, verify=str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_shared_writable_anchor_behind_a_symlink_is_refused_6377(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type
) -> None:
    shared = _ca_dir(tmp_path, "shared", 0o755)
    target = shared / "lab-ca.pem"
    shutil.copy(lab.ca_path, target)
    target.chmod(0o666)
    directory = _ca_dir(tmp_path)
    (directory / f"{_subject_hash(lab.ca_path)}.0").symlink_to(target)
    with pytest.raises(ValueError, match="writable"):
        client_cls(base_url=_ORIGIN, verify=str(directory))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_anchor_in_a_shared_writable_directory_is_refused_6377(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type
) -> None:
    # The file is 0644 but its directory lets others replace it.
    shared = _ca_dir(tmp_path, "shared", 0o755)
    target = shared / "lab-ca.pem"
    shutil.copy(lab.ca_path, target)
    target.chmod(0o644)
    shared.chmod(0o777)
    directory = _ca_dir(tmp_path)
    (directory / f"{_subject_hash(lab.ca_path)}.0").symlink_to(target)
    with pytest.raises(ValueError, match="writable"):
        client_cls(base_url=_ORIGIN, verify=str(directory))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_fifo_entry_in_a_ca_directory_is_refused_without_blocking_6377(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type
) -> None:
    directory = _ca_dir(tmp_path)
    os.mkfifo(directory / f"{_subject_hash(lab.ca_path)}.0", 0o644)
    with pytest.raises(ValueError, match="regular file"):
        client_cls(base_url=_ORIGIN, verify=str(directory))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_ca_directory_read_is_the_one_whose_mode_was_checked_6377(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    # verify= names a symlink to a checked 0755 directory. The link is moved to
    # a sticky shared directory holding the anchor after the mode check and
    # before the directory is listed: the SDK must list the directory it
    # resolved and checked, never what the name points at later.
    _clear_proxy_env(monkeypatch)
    checked = _ca_dir(tmp_path, "checked", 0o755)
    swapped = _ca_dir(tmp_path, "swapped", 0o755)
    _add_anchor(swapped, lab.ca_path)
    swapped.chmod(0o1777)
    link = tmp_path / "ca-link"
    link.symlink_to(checked)
    listdir = os.listdir

    def retarget_then_list(target: Any = ".") -> list[str]:
        if link.resolve() == checked.resolve():
            link.unlink()
            link.symlink_to(swapped)
        return listdir(target)

    monkeypatch.setattr(os, "listdir", retarget_then_list)
    assert _get_once(client_cls, origin.url, str(link)) is httpx.ConnectError
    assert origin.hits == []


# ---- #6360: the response backstop refuses on its own -----------------------


def _backstop(context: ssl.SSLContext, *, is_async: bool) -> Callable[[object], None]:
    """The SDK's response hook for ``context``, driven synchronously."""
    hook = _Driver(context, is_async=is_async).hooks["response"][0]

    def check(session: object) -> None:
        request = httpx.Request("GET", _ORIGIN + "/x")
        response = httpx.Response(
            200, request=request, extensions={"network_stream": _Stream(session)}
        )
        if is_async:
            asyncio.run(hook(response))
        else:
            hook(response)

    return check


@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize(
    "session",
    [
        pytest.param(lambda _context: None, id="no-session"),
        pytest.param(lambda _context: _Session(ssl.create_default_context()), id="other-context"),
        pytest.param(lambda context: _Session(context, host="elsewhere.lab"), id="wrong-name"),
        pytest.param(lambda context: _Session(context, bits=0), id="no-secret-bits"),
    ],
)
def test_backstop_refuses_an_unverified_response_session_6360(
    is_async: bool, session: Callable[[ssl.SSLContext], object]
) -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="verify=False"):
        _backstop(context, is_async=is_async)(session(context))


@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
def test_backstop_refuses_an_empty_peer_certificate_6360(is_async: bool) -> None:
    context = ssl.create_default_context()
    session = _Session(context)
    session._peer = {}  # noqa: SLF001
    with pytest.raises(ValueError, match="verify=False"):
        _backstop(context, is_async=is_async)(session)


@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
def test_backstop_admits_a_verified_response_session_6360(is_async: bool) -> None:
    context = ssl.create_default_context()
    _backstop(context, is_async=is_async)(_Session(context))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_backstop_refuses_when_the_session_trace_never_ran_6360(
    wrong_name_origin: RecordingServer,
    lab: Lab,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    # No trace is installed, so only the response hook stands between the
    # weakened context and a response from a server named for another host.
    _clear_proxy_env(monkeypatch)
    monkeypatch.setattr("ai_memory._common._with_trace", lambda _request, _trace: None)
    with pytest.raises(ValueError, match="verify=False"):
        _fetch(client_cls, wrong_name_origin.url, lab.client_context(), hook=_no_hostname_check)


# ---- #6361: a refused session's stream is closed, once, before the raise ---


class _CountingStream(_Stream):
    """Counts close calls; optionally fails them the way a dead socket does."""

    def __init__(self, session: object, *, fail: bool = False) -> None:
        super().__init__(session)
        self.closes = 0
        self.fail = fail
        self.closed_while_raising = False

    def close(self) -> None:
        self.closes += 1
        # Closed by a handler or finally that runs after the refusal was raised?
        self.closed_while_raising |= sys.exc_info()[0] is not None
        if self.fail:
            raise OSError("already closed")

    async def aclose(self) -> None:
        self.close()


@pytest.mark.parametrize("fail", [False, True], ids=["clean-close", "close-raises"])
@pytest.mark.parametrize(
    ("event", "session"),
    [
        pytest.param(
            "connection.start_tls.complete",
            lambda context: _Session(context, host="elsewhere.lab"),
            id="direct-wrong-name",
        ),
        pytest.param("connection.start_tls.complete", lambda _context: None, id="direct-none"),
        pytest.param(
            "proxy.start_tls.complete",
            lambda _context: _Session(ssl.create_default_context()),
            id="tunnel-foreign",
        ),
        pytest.param(
            "socks.start_tls.complete",
            lambda context: _Session(context, bits=0),
            id="socks-no-bits",
        ),
    ],
)
def test_refused_session_stream_is_closed_once_before_the_raise_6361(
    driver: tuple[_Driver, ssl.SSLContext],
    event: str,
    session: Callable[[ssl.SSLContext], object],
    fail: bool,
) -> None:
    drive, context = driver
    stream = _CountingStream(session(context), fail=fail)
    with pytest.raises(ValueError, match="verify=False"):
        drive.new_request()(event, {"return_value": stream})
    assert stream.closes == 1
    assert not stream.closed_while_raising


def test_pending_proxy_leg_stream_is_closed_when_the_request_is_refused_6361(
    driver: tuple[_Driver, ssl.SSLContext],
) -> None:
    drive, _ = driver
    fire = drive.new_request()
    leg = _CountingStream(_Session(ssl.create_default_context()))
    fire("connection.start_tls.complete", {"return_value": leg})
    assert leg.closes == 0  # a proxy leg is pending, not yet refused
    with pytest.raises(ValueError, match="verify=False"):
        fire("http11.send_request_headers.started", {"request": _get_request()})
    assert leg.closes == 1


@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
def test_verified_session_stream_is_left_open_6361(is_async: bool) -> None:
    context = ssl.create_default_context()
    stream = _CountingStream(_Session(context))
    _Driver(context, is_async=is_async).new_request()(
        "connection.start_tls.complete", {"return_value": stream}
    )
    assert stream.closes == 0


# ---- #6362: a trace already on the request is chained after the SDK's ------


def _chained(
    context: ssl.SSLContext, *, is_async: bool, inherited_async: bool
) -> tuple[Callable[[str, dict[str, Any]], None], list[str]]:
    """Run the SDK gated transport on a request that already carries a trace."""
    seen: list[str] = []

    def inherited(event: str, _info: dict[str, Any]) -> None:
        seen.append(event)

    async def ainherited(event: str, info: dict[str, Any]) -> None:
        inherited(event, info)

    request = httpx.Request(
        "GET", _ORIGIN + "/x", extensions={"trace": ainherited if inherited_async else inherited}
    )
    trace = _gated_trace(context, request, is_async=is_async)

    def fire(event: str, info: dict[str, Any]) -> None:
        if is_async:
            asyncio.run(trace(event, info))
        else:
            trace(event, info)

    return fire, seen


_CHAIN_SHAPES = [
    pytest.param(False, False, id="sync"),
    pytest.param(True, True, id="async-inherits-async"),
    pytest.param(True, False, id="async-inherits-sync"),
]


@pytest.mark.parametrize(("is_async", "inherited_async"), _CHAIN_SHAPES)
def test_inherited_trace_still_receives_every_event_6362(
    is_async: bool, inherited_async: bool
) -> None:
    context = ssl.create_default_context()
    fire, seen = _chained(context, is_async=is_async, inherited_async=inherited_async)
    fire("connection.connect_tcp.complete", {"return_value": object()})
    fire("connection.start_tls.complete", {"return_value": _Stream(_Session(context))})
    fire("http11.send_request_headers.started", {"request": _get_request()})
    assert seen == [
        "connection.connect_tcp.complete",
        "connection.start_tls.complete",
        "http11.send_request_headers.started",
    ]


@pytest.mark.parametrize(("is_async", "inherited_async"), _CHAIN_SHAPES)
def test_sdk_check_runs_before_the_inherited_trace_6362(
    is_async: bool, inherited_async: bool
) -> None:
    context = ssl.create_default_context()
    fire, seen = _chained(context, is_async=is_async, inherited_async=inherited_async)
    stream = _Stream(_Session(ssl.create_default_context(), host="elsewhere.lab"))
    with pytest.raises(ValueError, match="verify=False"):
        fire("proxy.start_tls.complete", {"return_value": stream})
    assert seen == []  # refused before the inherited trace saw the session
    assert stream.closed


# ---- #6363: every handshake attribute is pinned at class level -------------

_PINNED_HANDSHAKE_ATTRIBUTES = frozenset(
    {
        "wrap_socket",
        "wrap_bio",
        "verify_mode",
        "check_hostname",
        "sslsocket_class",
        "sslobject_class",
        "verify_flags",
        "hostname_checks_common_name",
        "get_ciphers",
    }
)


def _stock_descriptor(name: str) -> Any:
    for klass in ssl.SSLContext.__mro__:
        if name in klass.__dict__:
            return klass.__dict__[name]
    raise AssertionError(name)


def _equivalent_replacement(name: str) -> object:
    """A class attribute that behaves exactly like the stock one for ``name``."""
    stock = _stock_descriptor(name)
    if isinstance(stock, type):
        return type(stock.__name__, (stock,), {})
    if hasattr(stock, "__set__"):
        return property(stock.__get__, stock.__set__)

    def forward(self: ssl.SSLContext, *args: Any, **kwargs: Any) -> Any:
        return stock.__get__(self, ssl.SSLContext)(*args, **kwargs)

    return forward


def test_handshake_attribute_list_is_complete_6363() -> None:
    from ai_memory import _common

    assert frozenset(_common._HANDSHAKE_ATTRIBUTES) == _PINNED_HANDSHAKE_ATTRIBUTES  # noqa: SLF001


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("name", sorted(_PINNED_HANDSHAKE_ATTRIBUTES))
def test_class_level_replacement_of_any_handshake_attribute_is_refused_6363(
    monkeypatch: pytest.MonkeyPatch, client_cls: type, name: str
) -> None:
    context = ssl.create_default_context()
    monkeypatch.setattr(ssl.SSLContext, name, _equivalent_replacement(name), raising=False)
    with pytest.raises(ValueError, match="verify=False is refused"):
        client_cls(base_url=_ORIGIN, verify=context)


# ---- #6378: the per-request re-check refuses on its own ---------------------


def _weakened_then_get(client_cls: type, url: str, context: ssl.SSLContext, weaken: Hook) -> None:
    """Build a client on ``context``, weaken the context, then send one GET."""
    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=url, verify=context, api_key=_API_KEY, timeout=5) as client:
            weaken(context)
            client._client.get("/x")  # noqa: SLF001
        return

    async def run() -> None:
        async with AsyncAiMemoryClient(
            base_url=url, verify=context, api_key=_API_KEY, timeout=5
        ) as client:
            weaken(context)
            await client._client.get("/x")  # noqa: SLF001

    asyncio.run(run())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_hostname_check_turned_off_after_construction_is_refused_by_the_recheck_6378(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    # The server's certificate names the request host, so the session check
    # admits the session: only the per-request re-check sees the change.
    _clear_proxy_env(monkeypatch)
    with pytest.raises(ValueError, match="verify=False is refused"):
        _weakened_then_get(client_cls, origin.url, lab.client_context(), _no_hostname_check)
    assert origin.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_class_level_patch_after_construction_is_refused_by_the_recheck_6378(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)

    def patch_class(_context: ssl.SSLContext) -> None:
        monkeypatch.setattr(ssl.SSLContext, "wrap_bio", _equivalent_replacement("wrap_bio"))

    with pytest.raises(ValueError, match="verify=False is refused"):
        _weakened_then_get(client_cls, origin.url, lab.client_context(), patch_class)
    assert origin.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_unweakened_context_reaches_the_right_name_origin_6378(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    _weakened_then_get(client_cls, origin.url, lab.client_context(), lambda _context: None)
    assert len(origin.hits) == 1


# ---- #6537: a later caller hook cannot remove the session check ------------


def _late_trace_fetch(
    client_cls: type, url: str, context: ssl.SSLContext, action: str, seen: list[str]
) -> int:
    """GET once with a caller hook, appended after the SDK's, that weakens the
    context and then replaces (``replace``) or deletes (``remove``) the
    httpcore trace on the request. A replacing trace records its events in
    ``seen``. Returns the status code.
    """

    def record(event: str, _info: dict[str, Any]) -> None:
        seen.append(event)

    async def arecord(event: str, info: dict[str, Any]) -> None:
        record(event, info)

    def late(request: httpx.Request, trace: Any) -> None:
        if action == "weaken-replace" or action == "weaken-remove":
            _no_hostname_check(context)
        if action.endswith("remove"):
            request.extensions.pop("trace", None)
        else:
            request.extensions["trace"] = trace

    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=url, verify=context, api_key=_API_KEY, timeout=5) as client:
            client._client.event_hooks["request"].append(  # noqa: SLF001
                lambda request: late(request, record)
            )
            return client._client.get("/x").status_code  # noqa: SLF001

    async def run() -> int:
        async with AsyncAiMemoryClient(
            base_url=url, verify=context, api_key=_API_KEY, timeout=5
        ) as client:

            async def alate(request: httpx.Request) -> None:
                late(request, arecord)

            client._client.event_hooks["request"].append(alate)  # noqa: SLF001
            return (await client._client.get("/x")).status_code  # noqa: SLF001

    return asyncio.run(run())


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("action", ["weaken-replace", "weaken-remove"])
def test_later_hook_cannot_remove_the_session_check_6537(
    wrong_name_origin: RecordingServer,
    lab: Lab,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    action: str,
) -> None:
    # The hook runs after the SDK's re-check, so only the session check can
    # refuse the wrong-name server, and it must do so before any byte.
    _clear_proxy_env(monkeypatch)
    with pytest.raises(ValueError, match="verify=False"):
        _late_trace_fetch(client_cls, wrong_name_origin.url, lab.client_context(), action, [])
    assert wrong_name_origin.hits == []
    assert wrong_name_origin.api_keys == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("action", ["weaken-replace", "weaken-remove"])
def test_later_hook_cannot_remove_the_tunnelled_session_check_6537(
    proxy: TunnelProxy,
    wrong_name_origin: RecordingServer,
    lab: Lab,
    client_cls: type,
    action: str,
) -> None:
    with pytest.raises(ValueError, match="verify=False"):
        _late_trace_fetch(client_cls, wrong_name_origin.url, lab.client_context(), action, [])
    assert len(proxy.tunnels) == 1
    assert wrong_name_origin.hits == []
    assert wrong_name_origin.api_keys == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_trace_set_by_a_later_hook_still_receives_events_6537(
    origin: RecordingServer, lab: Lab, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    _clear_proxy_env(monkeypatch)
    seen: list[str] = []
    assert _late_trace_fetch(client_cls, origin.url, lab.client_context(), "replace", seen) == 200
    assert "connection.start_tls.complete" in seen
    assert "http11.send_request_headers.started" in seen
    assert origin.hits == ["/x"]


# ---- #6559: a symlink on the CA path may not sit in a shared-writable dir ---


def _linked_ca(lab: Lab, tmp_path: pathlib.Path, kind: str, mode: int) -> str:
    """A ``verify=`` path whose ``kind`` symlink lives in a directory of ``mode``.

    The CA file and CA directory themselves are safe (0644 in 0755); only the
    directory holding the link lets others replace it.
    """
    safe = _ca_dir(tmp_path, "safe", 0o755)
    bundle = safe / "lab-ca.pem"
    shutil.copy(lab.ca_path, bundle)
    bundle.chmod(0o644)
    hashed = _ca_dir(tmp_path, "hashed", 0o755)
    _add_anchor(hashed, lab.ca_path)
    swap = _ca_dir(tmp_path, "swap", 0o755)
    if kind == "file":
        (swap / "ca.pem").symlink_to(bundle)
        verify = swap / "ca.pem"
    elif kind == "directory":
        (swap / "ca").symlink_to(hashed)
        verify = swap / "ca"
    elif kind == "component":
        (swap / "certs").symlink_to(safe)
        verify = swap / "certs" / "lab-ca.pem"
    else:  # an entry of a safe CA directory points through a link in `swap`
        (swap / "anchor.pem").symlink_to(bundle)
        verify = _ca_dir(tmp_path, "entries", 0o755)
        (verify / f"{_subject_hash(lab.ca_path)}.0").symlink_to(swap / "anchor.pem")
    swap.chmod(mode)
    return str(verify)


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("mode", [0o777, 0o775], ids=oct)
@pytest.mark.parametrize("kind", ["file", "directory", "component", "entry"])
def test_symlink_in_a_shared_writable_directory_is_refused_6559(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type, mode: int, kind: str
) -> None:
    verify = _linked_ca(lab, tmp_path, kind, mode)
    with pytest.raises(ValueError, match="symlink") as refused:
        client_cls(base_url=_ORIGIN, verify=verify)
    assert "writable" in str(refused.value)


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("kind", ["file", "directory", "component", "entry"])
def test_own_symlink_in_a_sticky_directory_is_accepted_6559(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    kind: str,
) -> None:
    _clear_proxy_env(monkeypatch)
    verify = _linked_ca(lab, tmp_path, kind, 0o1777)
    assert _get_once(client_cls, origin.url, verify) == 200


# ---- #6538: env trust (SSL_CERT_FILE / SSL_CERT_DIR) is held to #6377 ------

_ENV_VERIFY = pytest.mark.parametrize("verify", [None, True], ids=["None", "True"])


def _env_trust(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    _clear_proxy_env(monkeypatch)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


@_ENV_VERIFY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_env_anchor_added_after_construction_is_not_trusted_6538(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    verify: object,
) -> None:
    directory = _ca_dir(tmp_path)
    _env_trust(monkeypatch, SSL_CERT_DIR=str(directory))
    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=origin.url, verify=verify, timeout=5) as client:  # type: ignore[arg-type]
            _add_anchor(directory, lab.ca_path)
            with pytest.raises(httpx.ConnectError):
                client._client.get("/x")  # noqa: SLF001
    else:

        async def run() -> None:
            async with AsyncAiMemoryClient(
                base_url=origin.url,
                verify=verify,  # type: ignore[arg-type]
                timeout=5,
            ) as client:
                _add_anchor(directory, lab.ca_path)
                with pytest.raises(httpx.ConnectError):
                    await client._client.get("/x")  # noqa: SLF001

        asyncio.run(run())
    assert origin.hits == []


@_ENV_VERIFY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_env_anchor_present_at_construction_is_trusted_6538(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    verify: object,
    variable: str,
) -> None:
    directory = _ca_dir(tmp_path)
    entry = _add_anchor(directory, lab.ca_path)
    _env_trust(monkeypatch, **{variable: str(entry if variable == "SSL_CERT_FILE" else directory)})
    assert _get_once(client_cls, origin.url, verify) == 200


@_POSIX_ONLY
@_ENV_VERIFY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_shared_writable_env_ca_directory_is_refused_6538(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    verify: object,
) -> None:
    directory = _ca_dir(tmp_path)
    _add_anchor(directory, lab.ca_path)
    directory.chmod(0o777)
    _env_trust(monkeypatch, SSL_CERT_DIR=str(directory))
    with pytest.raises(ValueError, match="writable"):
        client_cls(base_url=_ORIGIN, verify=verify)


@_POSIX_ONLY
@_ENV_VERIFY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_shared_writable_env_ca_file_is_refused_6538(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    verify: object,
) -> None:
    bundle = tmp_path / "bundle.pem"
    shutil.copy(lab.ca_path, bundle)
    bundle.chmod(0o666)
    _env_trust(monkeypatch, SSL_CERT_FILE=str(bundle))
    with pytest.raises(ValueError, match="writable"):
        client_cls(base_url=_ORIGIN, verify=verify)


@_ENV_VERIFY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    ("variable", "target"),
    [
        ("SSL_CERT_FILE", "missing"),
        ("SSL_CERT_DIR", "missing"),
        ("SSL_CERT_FILE", "directory"),
        ("SSL_CERT_DIR", "file"),
    ],
)
def test_unusable_env_trust_path_is_refused_6538(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    verify: object,
    variable: str,
    target: str,
) -> None:
    directory = _ca_dir(tmp_path)
    entry = _add_anchor(directory, lab.ca_path)
    path = {"missing": tmp_path / "absent", "directory": directory, "file": entry}[target]
    _env_trust(monkeypatch, **{variable: str(path)})
    with pytest.raises(ValueError, match=variable):
        client_cls(base_url=_ORIGIN, verify=verify)


@pytest.mark.parametrize("client_cls", [httpx.Client, httpx.AsyncClient], ids=["sync", "async"])
def test_unwrappable_transport_refuses_construction_6537(client_cls: type) -> None:
    context = ssl.create_default_context()
    kwargs = build_httpx_kwargs(
        base_url=_ORIGIN,
        api_key=_API_KEY,
        agent_id=None,
        timeout=1.0,
        verify=context,
        cert=None,
        extra_headers=None,
        is_async=client_cls is httpx.AsyncClient,
    )
    client = client_cls(**kwargs)
    inner = client._transport  # noqa: SLF001
    client._mounts[httpx.URL("https://other.invalid")] = object()  # type: ignore[index]  # noqa: SLF001
    with pytest.raises(ValueError, match="#6537"):
        _common.gate_transports(client, kwargs, context)
    assert client._transport is inner  # noqa: SLF001 - never left half-wrapped


def test_lab_temp_root_is_project_local_6309(lab: Lab) -> None:
    assert ".local-runs" in pathlib.Path(lab.ca_path).resolve().parts


# ---- #6690: one path check for verify= and the env trust variables ---------


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("source", ["verify", "SSL_CERT_FILE"])
def test_trailing_slash_on_a_ca_file_is_refused_6690(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    source: str,
) -> None:
    """``ca.pem/`` names no file to the kernel (ENOTDIR); both inputs refuse it."""
    directory = _ca_dir(tmp_path)
    entry = _add_anchor(directory, lab.ca_path)
    spelled = str(entry) + os.sep
    if source == "verify":
        _env_trust(monkeypatch)
        with pytest.raises(ValueError, match="not an existing regular file"):
            client_cls(base_url=_ORIGIN, verify=spelled)
    else:
        _env_trust(monkeypatch, SSL_CERT_FILE=spelled)
        with pytest.raises(ValueError, match="SSL_CERT_FILE"):
            client_cls(base_url=_ORIGIN, verify=None)


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("source", ["verify", "SSL_CERT_DIR"])
def test_trailing_slash_on_a_ca_directory_is_accepted_6690(
    origin: RecordingServer,
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    source: str,
) -> None:
    directory = _ca_dir(tmp_path)
    _add_anchor(directory, lab.ca_path)
    spelled = str(directory) + os.sep
    if source == "verify":
        _env_trust(monkeypatch)
        assert _get_once(client_cls, origin.url, spelled) == 200
    else:
        _env_trust(monkeypatch, SSL_CERT_DIR=spelled)
        assert _get_once(client_cls, origin.url, None) == 200


def test_env_and_verify_share_one_path_check_6690(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The env variables are checked by the same funnel as ``verify=<path>``."""
    seen: list[tuple[str, object]] = []
    real = _common._context_from_path

    def spy(path: str, *args: Any, **kwargs: Any) -> ssl.SSLContext:
        seen.append((path, kwargs.get("kind")))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(_common, "_context_from_path", spy)
    _env_trust(monkeypatch, SSL_CERT_FILE=str(tmp_path / "absent.pem"))
    with pytest.raises(ValueError, match="SSL_CERT_FILE"):
        AiMemoryClient(base_url=_ORIGIN, verify=None)
    assert seen == [(str(tmp_path / "absent.pem"), "file")]
