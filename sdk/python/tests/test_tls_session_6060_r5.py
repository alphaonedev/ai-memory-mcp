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
from collections.abc import Iterator
from typing import Any, Callable

import httpcore
import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient
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


class _Driver:
    """Installs the SDK's request hook on a fresh request and drives its trace."""

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
        self.hooks = kwargs["event_hooks"]

    def new_request(self) -> Callable[[str, dict[str, Any]], None]:
        request = httpx.Request("GET", _ORIGIN + "/x")
        hook = self.hooks["request"][0]
        if self.is_async:
            asyncio.run(hook(request))
        else:
            hook(request)
        trace = request.extensions["trace"]

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
                hook=lambda context: _with_flags(context, _RELAXING_FLAGS["NO_CHECK_TIME"]),
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


def test_lab_temp_root_is_project_local_6309(lab: Lab) -> None:
    assert ".local-runs" in pathlib.Path(lab.ca_path).resolve().parts
