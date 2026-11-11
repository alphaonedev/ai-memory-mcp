# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The SDK never performs an HTTPS handshake with verification off.

Class invariant (#6249 #6267 #6306, spec #3840 / #8195): for every accepted
``verify=`` form, for the whole client lifetime, on the sync and the async
client, the TLS handshake runs with certificate verification AND hostname
checking on. The check holds on the exact context object the handshake uses,
at use time, and no caller (or concurrent thread) can weaken that context:

* #6249 - a caller-held ``ssl.SSLContext`` weakened AFTER construction used
  to reach the handshake, because the SDK handed httpx the caller's object.
* #6267 - a ``truststore.SSLContext`` with verification off was admitted.
* #6306 - a concurrent ``verify_mode`` flip raced the handshake.

Every test talks to a real local HTTPS server (``_tlslab_6249``): a refused
handshake is proved by the TLS error, an accepted one by the health body.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import ssl
import threading
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient
from ai_memory.errors import TransportError
from tests._tlslab_6249 import LAB_HEALTH_BODY, Lab, LabServer, build_lab

#: OpenSSL's reason code for a chain or hostname the client did not accept.
VERIFY_FAILED = "CERTIFICATE_VERIFY_FAILED"
#: Upper bound on verify_mode flips in the race tests (the loop stops early
#: once the requests finish).
RACE_MAX_FLIPS = 200_000
#: Worker threads / requests per worker in the sync race.
RACE_WORKERS = 4
RACE_REQUESTS_PER_WORKER = 12
#: Concurrent requests in the async race.
RACE_ASYNC_REQUESTS = 48
#: The SDK's CA bundle read cap, and the wall-clock ceiling for refusing a
#: bundle one byte over it.
MAX_CA_BUNDLE_BYTES = 16 * 1024 * 1024
OVERSIZE_REFUSAL_CEILING_S = 2.0
#: Per-request timeout for every lab call (seconds).
LAB_TIMEOUT_S = 5.0

#: Exact construction-time refusal messages (the public contract).
MSG_FALSE = (
    "verify=False is refused: the ai-memory SDK never turns off TLS certificate "
    "verification; pass None, True, a CA bundle path or a verifying ssl.SSLContext"
)
MSG_MODE = (
    "verify=<{kind}> is refused: its verify_mode is {mode}, not CERT_REQUIRED; the "
    "ai-memory SDK never turns off TLS certificate verification"
)
MSG_HOST = (
    "verify=<{kind}> is refused: its check_hostname is off; the ai-memory SDK never "
    "turns off TLS hostname checking"
)
MSG_NO_CA = (
    "verify=<{kind}> is refused: it holds no CA certificate the SDK can copy (a "
    "capath directory is loaded lazily and cannot be copied); pass the CA bundle path "
    "as verify= instead"
)
MSG_CRL = (
    "verify=<{kind}> is refused: it asks for CRL checking, which the SDK cannot copy; "
    "pass the CA bundle path as verify= instead"
)
MSG_UNCLASSIFIABLE = (
    "verify=<{kind}> is refused: pass None, True, a CA bundle path (str or "
    "os.PathLike[str]) or an ssl.SSLContext with CERT_REQUIRED and check_hostname"
)
MSG_FROZEN = "the ai-memory SDK TLS context is frozen; {name} cannot be changed after construction"
MSG_USE_TIME = (
    "ai-memory SDK refused the TLS handshake: certificate verification or hostname "
    "checking is off on the handshake context"
)

CLIENT_KINDS = ("sync", "async")


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return build_lab(tmp_path_factory.mktemp("tlslab-6249"))


@pytest.fixture(scope="module")
def good_server(lab: Lab) -> Iterator[LabServer]:
    with LabServer(lab.good) as server:
        yield server


@pytest.fixture(scope="module")
def rogue_server(lab: Lab) -> Iterator[LabServer]:
    with LabServer(lab.rogue) as server:
        yield server


@pytest.fixture(scope="module")
def wrong_host_server(lab: Lab) -> Iterator[LabServer]:
    with LabServer(lab.wrong_host) as server:
        yield server


def _trusting_context(lab: Lab) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(lab.trusted_ca))


def _make(kind: str, url: str, **kwargs: Any) -> AiMemoryClient | AsyncAiMemoryClient:
    if kind == "sync":
        return AiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, **kwargs)
    return AsyncAiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, **kwargs)


#: One event loop for every async client of this module: an AsyncClient's
#: pooled connections are bound to the loop that opened them.
_LOOP: list[asyncio.AbstractEventLoop] = []


def _run(coro: Any) -> Any:
    if not _LOOP:
        _LOOP.append(asyncio.new_event_loop())
    return _LOOP[0].run_until_complete(coro)


@pytest.fixture(scope="module", autouse=True)
def _close_loop() -> Iterator[None]:
    yield
    while _LOOP:
        _LOOP.pop().close()


def _health(client: AiMemoryClient | AsyncAiMemoryClient) -> Any:
    if isinstance(client, AiMemoryClient):
        return client.health()

    async def run() -> Any:
        return await client.health()

    return _run(run())


def _close(client: AiMemoryClient | AsyncAiMemoryClient) -> None:
    if isinstance(client, AiMemoryClient):
        client.close()
    else:
        _run(client.aclose())


def _assert_refused(
    client: AiMemoryClient | AsyncAiMemoryClient, reason: str = VERIFY_FAILED
) -> None:
    with pytest.raises(TransportError) as info:
        _health(client)
    assert isinstance(info.value.__cause__, httpx.ConnectError)
    assert reason in str(info.value), str(info.value)


def _weaken(ctx: Any) -> None:
    """The #6249 caller move: turn verification off on a held context."""
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE


def _kind_name(obj: object) -> str:
    return type(obj).__name__


class _LyingContext(ssl.SSLContext):
    """A subclass whose Python properties claim a verifying context."""

    @property  # type: ignore[override]
    def verify_mode(self) -> ssl.VerifyMode:
        return ssl.CERT_REQUIRED

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode) -> None:
        ssl.SSLContext.verify_mode.__set__(self, value)  # type: ignore[attr-defined]

    @property  # type: ignore[override]
    def check_hostname(self) -> bool:
        return True

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        ssl.SSLContext.check_hostname.__set__(self, value)  # type: ignore[attr-defined]


class _PlainSubclass(ssl.SSLContext):
    """An honest subclass (its overrides must never reach the handshake)."""

    wrapped = 0

    def wrap_socket(self, *args: Any, **kwargs: Any) -> ssl.SSLSocket:
        type(self).wrapped += 1
        return super().wrap_socket(*args, **kwargs)


class _Pathish:
    def __init__(self, path: str) -> None:
        self._path = path

    def __fspath__(self) -> str:
        return self._path


def _cert_none_context(lab: Lab) -> ssl.SSLContext:
    ctx = _trusting_context(lab)
    _weaken(ctx)
    return ctx


def _optional_context(lab: Lab) -> ssl.SSLContext:
    ctx = _trusting_context(lab)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def _no_hostname_context(lab: Lab) -> ssl.SSLContext:
    ctx = _trusting_context(lab)
    ctx.check_hostname = False
    return ctx


def _lying_context(lab: Lab) -> ssl.SSLContext:
    ctx = _LyingContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(lab.trusted_ca))
    ssl.SSLContext.check_hostname.__set__(ctx, False)  # type: ignore[attr-defined]
    ssl.SSLContext.verify_mode.__set__(ctx, ssl.CERT_NONE)  # type: ignore[attr-defined]
    return ctx


def _crl_context(lab: Lab) -> ssl.SSLContext:
    ctx = _trusting_context(lab)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


def _empty_context(lab: Lab) -> ssl.SSLContext:
    del lab
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


#: (case id, builder, expected message builder) - every weakened or
#: unclassifiable form is refused at construction with the exact message.
REFUSED_AT_CONSTRUCTION: list[tuple[str, Callable[[Lab], Any], Callable[[Any], str]]] = [
    ("false", lambda lab: False, lambda v: MSG_FALSE),
    (
        "ctx_cert_none",
        _cert_none_context,
        lambda v: MSG_MODE.format(kind=_kind_name(v), mode="CERT_NONE"),
    ),
    (
        "ctx_cert_optional",
        _optional_context,
        lambda v: MSG_MODE.format(kind=_kind_name(v), mode="CERT_OPTIONAL"),
    ),
    ("ctx_no_hostname", _no_hostname_context, lambda v: MSG_HOST.format(kind=_kind_name(v))),
    (
        "subclass_lying_properties",
        _lying_context,
        lambda v: MSG_MODE.format(kind=_kind_name(v), mode="CERT_NONE"),
    ),
    ("ctx_crl_check", _crl_context, lambda v: MSG_CRL.format(kind=_kind_name(v))),
    ("ctx_without_ca", _empty_context, lambda v: MSG_NO_CA.format(kind=_kind_name(v))),
    ("int_zero", lambda lab: 0, lambda v: MSG_UNCLASSIFIABLE.format(kind="int")),
    ("int_one", lambda lab: 1, lambda v: MSG_UNCLASSIFIABLE.format(kind="int")),
    (
        "bytes_path",
        lambda lab: bytes(lab.trusted_ca),
        lambda v: MSG_UNCLASSIFIABLE.format(kind="bytes"),
    ),
    ("empty_str", lambda lab: "", lambda v: MSG_UNCLASSIFIABLE.format(kind="str")),
    ("object", lambda lab: object(), lambda v: MSG_UNCLASSIFIABLE.format(kind="object")),
    ("dict", lambda lab: {"cafile": "x"}, lambda v: MSG_UNCLASSIFIABLE.format(kind="dict")),
    (
        "fspath_returns_bytes",
        lambda lab: _Pathish(b"/etc/ssl/cert.pem"),  # type: ignore[arg-type]
        lambda v: MSG_UNCLASSIFIABLE.format(kind="_Pathish"),
    ),
]


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize(
    ("case", "builder", "message"),
    REFUSED_AT_CONSTRUCTION,
    ids=[row[0] for row in REFUSED_AT_CONSTRUCTION],
)
def test_weakened_or_unclassifiable_verify_refused_at_construction(
    lab: Lab, kind: str, case: str, builder: Callable[[Lab], Any], message: Callable[[Any], str]
) -> None:
    verify = builder(lab)
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=verify)
    assert str(info.value) == message(verify), case


#: Accepted forms; each must verify the good server and refuse the rogue one.
ACCEPTED_FORMS: list[tuple[str, Callable[[Lab], Any]]] = [
    ("ca_str", lambda lab: str(lab.trusted_ca)),
    ("ca_pathlib", lambda lab: lab.trusted_ca),
    ("ca_pathlike", lambda lab: _Pathish(str(lab.trusted_ca))),
    ("ca_dir", lambda lab: _hashed_ca_dir(lab)),
    ("stdlib_ctx", _trusting_context),
    ("subclass_ctx", lambda lab: _subclass_context(lab)),
]


def _subclass_context(lab: Lab) -> ssl.SSLContext:
    ctx = _PlainSubclass(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(lab.trusted_ca))
    return ctx


def _hashed_ca_dir(lab: Lab) -> str:
    """A capath directory: the CA under its OpenSSL subject-hash name."""
    directory = lab.root / "capath"
    directory.mkdir(exist_ok=True)
    # OpenSSL's subject hash is exposed by neither cryptography nor ssl.
    name_hash = _openssl_subject_hash(lab.trusted_ca)
    (directory / f"{name_hash}.0").write_bytes(lab.trusted_ca.read_bytes())
    return str(directory)


def _openssl_subject_hash(pem: pathlib.Path) -> str:
    import subprocess

    out = subprocess.run(
        ["openssl", "x509", "-noout", "-subject_hash", "-in", str(pem)],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize(("case", "builder"), ACCEPTED_FORMS, ids=[r[0] for r in ACCEPTED_FORMS])
def test_accepted_forms_verify_chain_and_hostname(
    lab: Lab,
    good_server: LabServer,
    rogue_server: LabServer,
    wrong_host_server: LabServer,
    kind: str,
    case: str,
    builder: Callable[[Lab], Any],
) -> None:
    verify = builder(lab)
    good = _make(kind, good_server.url, verify=verify)
    rogue = _make(kind, rogue_server.url, verify=verify)
    wrong = _make(kind, wrong_host_server.url, verify=verify)
    try:
        assert _health(good) == LAB_HEALTH_BODY, case
        _assert_refused(rogue)
        _assert_refused(wrong)
    finally:
        for client in (good, rogue, wrong):
            _close(client)


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("subclass", [False, True], ids=["stdlib", "subclass"])
def test_6249_context_weakened_after_construction_never_reaches_handshake(
    lab: Lab, good_server: LabServer, rogue_server: LabServer, kind: str, subclass: bool
) -> None:
    ctx = _subclass_context(lab) if subclass else _trusting_context(lab)
    good = _make(kind, good_server.url, verify=ctx)
    rogue = _make(kind, rogue_server.url, verify=ctx)
    try:
        _weaken(ctx)
        # Trusting the attacker's CA on the caller's object must not reach
        # the SDK either: its CA material was copied at construction.
        ctx.load_verify_locations(cafile=str(lab.rogue_ca))
        _assert_refused(rogue)
        assert _health(good) == LAB_HEALTH_BODY
    finally:
        _close(good)
        _close(rogue)
    if subclass:
        assert _PlainSubclass.wrapped == 0, "the caller's subclass ran the handshake"


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_6249_relative_ca_path_resolved_at_construction(
    lab: Lab, good_server: LabServer, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(lab.root)
    client = _make(kind, good_server.url, verify=lab.trusted_ca.name)
    try:
        monkeypatch.chdir(lab.root.parent)
        assert _health(client) == LAB_HEALTH_BODY
    finally:
        _close(client)


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_ca_path_that_is_not_a_regular_file_or_directory_is_refused(lab: Lab, kind: str) -> None:
    fifo = lab.root / f"ca-{kind}.fifo"
    if not fifo.exists():
        os.mkfifo(fifo)
    caught: list[BaseException] = []

    def construct() -> None:
        try:
            _close(_make(kind, "https://127.0.0.1:1", verify=str(fifo)))
        except BaseException as exc:  # noqa: BLE001 - recorded and asserted below
            caught.append(exc)

    worker = threading.Thread(target=construct, daemon=True)
    worker.start()
    worker.join(timeout=LAB_TIMEOUT_S)
    blocked = worker.is_alive()
    if blocked:
        # Release a reader stuck in open(): a writer that closes at once
        # hands it EOF.
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        worker.join(timeout=LAB_TIMEOUT_S)
    assert not blocked, "construction blocked reading a FIFO as a CA bundle"
    assert len(caught) == 1 and isinstance(caught[0], ValueError), caught
    assert str(caught[0]) == (
        f"verify={str(fifo)!r} is refused: the CA path is not a regular file or a directory"
    )


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_missing_or_garbage_ca_path_is_refused(lab: Lab, kind: str) -> None:
    missing = lab.root / "missing.pem"
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=str(missing))
    assert str(info.value) == (
        f"verify={str(missing)!r} is refused: the CA path cannot be read (No such file or directory)"
    )
    garbage = lab.root / "garbage.pem"
    garbage.write_text("not a certificate\n", encoding="utf-8")
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=str(garbage))
    assert str(info.value).startswith(
        f"verify={str(garbage)!r} is refused: the CA bundle could not be loaded ("
    )


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("verify", [None, True], ids=["none", "true"])
def test_default_trust_refuses_the_rogue_server(
    rogue_server: LabServer, kind: str, verify: bool | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    client = _make(kind, rogue_server.url, verify=verify)
    try:
        _assert_refused(client)
    finally:
        _close(client)


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_default_trust_honours_ssl_cert_file_like_httpx(
    lab: Lab, good_server: LabServer, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(lab.trusted_ca))
    client = _make(kind, good_server.url)
    try:
        assert _health(client) == LAB_HEALTH_BODY
    finally:
        _close(client)


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_mtls_client_certificate_rides_the_owned_context(lab: Lab, kind: str) -> None:
    with LabServer(lab.good, client_ca=lab.trusted_ca) as server:
        with_cert = _make(
            kind,
            server.url,
            verify=str(lab.trusted_ca),
            cert=(str(lab.client[0]), str(lab.client[1])),
        )
        try:
            assert _health(with_cert) == LAB_HEALTH_BODY
        finally:
            _close(with_cert)


def _handshake_context(client: AiMemoryClient | AsyncAiMemoryClient) -> Any:
    """The context httpcore hands to wrap_socket / wrap_bio."""
    return client._client._transport._pool._ssl_context


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("verify_form", ["none", "path", "ctx"])
def test_owned_context_is_private_and_frozen(lab: Lab, kind: str, verify_form: str) -> None:
    from ai_memory._tls import OwnedTLSContext

    caller = _trusting_context(lab)
    verify: Any = {"none": None, "path": str(lab.trusted_ca), "ctx": caller}[verify_form]
    client = _make(kind, "https://127.0.0.1:1", verify=verify)
    try:
        owned = _handshake_context(client)
        assert owned is not caller
        assert isinstance(owned, OwnedTLSContext)
        assert owned.verify_mode == ssl.CERT_REQUIRED
        assert owned.check_hostname is True
        assert owned.minimum_version >= ssl.TLSVersion.TLSv1_2
        for name, value in (
            ("check_hostname", False),
            ("verify_mode", ssl.CERT_NONE),
            ("verify_flags", ssl.VERIFY_DEFAULT),
            ("minimum_version", ssl.TLSVersion.TLSv1),
            ("options", 0),
            ("sni_callback", lambda *a: None),
            ("sslsocket_class", ssl.SSLSocket),
            ("sslobject_class", ssl.SSLObject),
            ("keylog_filename", str(lab.root / "keys.log")),
        ):
            with pytest.raises(AttributeError) as info:
                setattr(owned, name, value)
            assert str(info.value) == MSG_FROZEN.format(name=name)
        for method, args in (
            ("load_verify_locations", (str(lab.rogue_ca),)),
            ("load_default_certs", ()),
            ("set_default_verify_paths", ()),
            ("load_cert_chain", (str(lab.client[0]), str(lab.client[1]))),
            ("set_ciphers", ("aNULL",)),
            ("set_servername_callback", (None,)),
        ):
            with pytest.raises(AttributeError) as info:
                getattr(owned, method)(*args)
            assert str(info.value) == MSG_FROZEN.format(name=method)
        with pytest.raises(AttributeError) as info:
            del owned.check_hostname
        assert str(info.value) == MSG_FROZEN.format(name="check_hostname")
        assert owned.verify_mode == ssl.CERT_REQUIRED
        assert owned.check_hostname is True
    finally:
        _close(client)


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_use_time_check_refuses_a_context_weakened_below_python(
    lab: Lab, rogue_server: LabServer, kind: str
) -> None:
    """Even a C-level write past the frozen setters is caught at the handshake."""
    client = _make(kind, rogue_server.url, verify=str(lab.trusted_ca))
    try:
        owned = _handshake_context(client)
        base: Any = ssl.SSLContext.__base__
        base.check_hostname.__set__(owned, False)
        base.verify_mode.__set__(owned, ssl.CERT_NONE)
        _assert_refused(client, reason=MSG_USE_TIME)
    finally:
        _close(client)


def _flip_until(ctx: ssl.SSLContext, stop: threading.Event) -> int:
    flips = 0
    while not stop.is_set() and flips < RACE_MAX_FLIPS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        flips += 1
    return flips


def test_6306_concurrent_verify_mode_flip_never_completes_a_handshake_sync(
    lab: Lab, rogue_server: LabServer
) -> None:
    # Construction sees a verifying context; the race starts afterwards.
    ctx = _trusting_context(lab)
    client = AiMemoryClient(base_url=rogue_server.url, timeout=LAB_TIMEOUT_S, verify=ctx)
    stop = threading.Event()
    flips: list[int] = []
    flipper = threading.Thread(target=lambda: flips.append(_flip_until(ctx, stop)))
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(RACE_REQUESTS_PER_WORKER):
            try:
                client.health()
                result = "HANDSHAKE-COMPLETED"
            except TransportError as exc:
                result = VERIFY_FAILED if VERIFY_FAILED in str(exc) else f"other: {exc}"
            with lock:
                outcomes.append(result)

    workers = [threading.Thread(target=worker) for _ in range(RACE_WORKERS)]
    flipper.start()
    try:
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=60)
    finally:
        stop.set()
        flipper.join(timeout=60)
        client.close()
    assert flips and flips[0] > 0
    assert len(outcomes) == RACE_WORKERS * RACE_REQUESTS_PER_WORKER
    assert set(outcomes) == {VERIFY_FAILED}, outcomes


def test_6306_concurrent_verify_mode_flip_never_completes_a_handshake_async(
    lab: Lab, rogue_server: LabServer
) -> None:
    # Construction sees a verifying context; the race starts afterwards.
    ctx = _trusting_context(lab)
    racing = AsyncAiMemoryClient(base_url=rogue_server.url, timeout=LAB_TIMEOUT_S, verify=ctx)

    async def run() -> list[str]:
        async with racing as client:

            async def one() -> str:
                try:
                    await client.health()
                except TransportError as exc:
                    return VERIFY_FAILED if VERIFY_FAILED in str(exc) else f"other: {exc}"
                return "HANDSHAKE-COMPLETED"

            return list(await asyncio.gather(*(one() for _ in range(RACE_ASYNC_REQUESTS))))

    stop = threading.Event()
    flips: list[int] = []
    flipper = threading.Thread(target=lambda: flips.append(_flip_until(ctx, stop)))
    flipper.start()
    try:
        outcomes = asyncio.run(run())
    finally:
        stop.set()
        flipper.join(timeout=60)
    assert flips and flips[0] > 0
    assert len(outcomes) == RACE_ASYNC_REQUESTS
    assert set(outcomes) == {VERIFY_FAILED}, outcomes


# -- truststore (#6267) -------------------------------------------------------


def _truststore() -> Any:
    return pytest.importorskip("truststore")


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("weakening", ["cert_none", "cert_optional", "no_hostname"])
def test_6267_truststore_context_with_verification_off_is_refused(
    kind: str, weakening: str
) -> None:
    truststore = _truststore()
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if weakening == "cert_none":
        _weaken(ctx)
        expected = MSG_MODE.format(kind="SSLContext", mode="CERT_NONE")
    elif weakening == "cert_optional":
        ctx.verify_mode = ssl.CERT_OPTIONAL
        expected = MSG_MODE.format(kind="SSLContext", mode="CERT_OPTIONAL")
    else:
        ctx.check_hostname = False
        expected = MSG_HOST.format(kind="SSLContext")
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=ctx)
    assert str(info.value) == expected


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_6267_truststore_context_weakened_after_construction_never_reaches_handshake(
    lab: Lab, good_server: LabServer, rogue_server: LabServer, kind: str
) -> None:
    truststore = _truststore()
    from ai_memory._tls import OwnedTLSContext

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(lab.trusted_ca))
    good = _make(kind, good_server.url, verify=ctx)
    rogue = _make(kind, rogue_server.url, verify=ctx)
    try:
        owned = _handshake_context(good)
        assert owned is not ctx
        assert isinstance(owned, OwnedTLSContext)
        assert isinstance(owned, truststore.SSLContext)
        _weaken(ctx)
        _assert_refused(rogue)
        assert _health(good) == LAB_HEALTH_BODY
        with pytest.raises(AttributeError) as info:
            owned.verify_mode = ssl.CERT_NONE
        assert str(info.value) == MSG_FROZEN.format(name="verify_mode")
    finally:
        _close(good)
        _close(rogue)


def test_build_httpx_kwargs_never_forwards_the_caller_context_or_cert(lab: Lab) -> None:
    from ai_memory._common import build_httpx_kwargs
    from ai_memory._tls import OwnedTLSContext

    caller = _trusting_context(lab)
    kwargs = build_httpx_kwargs(
        base_url="https://127.0.0.1:1",
        api_key=None,
        agent_id=None,
        timeout=1.0,
        verify=caller,
        cert=(str(lab.client[0]), str(lab.client[1])),
        extra_headers=None,
    )
    assert isinstance(kwargs["verify"], OwnedTLSContext)
    assert kwargs["verify"] is not caller
    assert "cert" not in kwargs


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_oversized_ca_bundle_is_refused_within_a_bound(lab: Lab, kind: str) -> None:
    import time

    big = lab.root / "oversized.pem"
    with big.open("wb") as handle:
        handle.write(lab.trusted_ca.read_bytes())
        handle.write(b"#" * (MAX_CA_BUNDLE_BYTES + 1))
    started = time.monotonic()
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=str(big))
    elapsed = time.monotonic() - started
    assert str(info.value) == (
        f"verify={str(big)!r} is refused: the CA bundle is larger than {MAX_CA_BUNDLE_BYTES} bytes"
    )
    assert elapsed < OVERSIZE_REFUSAL_CEILING_S, elapsed


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize(
    ("cert", "expected"),
    [
        (
            b"client.crt",
            "cert=<bytes> is refused: pass a certificate path or (certificate, key[, password])",
        ),
        (
            ("a", "b", "c", "d"),
            "cert=<tuple> is refused: pass a certificate path or (certificate, key[, password])",
        ),
    ],
    ids=["bytes", "four_tuple"],
)
def test_unclassifiable_client_cert_is_refused(
    lab: Lab, kind: str, cert: Any, expected: str
) -> None:
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=str(lab.trusted_ca), cert=cert)
    assert str(info.value) == expected


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_missing_client_cert_is_refused(lab: Lab, kind: str) -> None:
    missing = str(lab.root / "no-client.crt")
    with pytest.raises(ValueError) as info:
        _make(kind, "https://127.0.0.1:1", verify=str(lab.trusted_ca), cert=missing)
    assert str(info.value) == (
        "cert= is refused: the client certificate could not be loaded (No such file or directory)"
    )


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_6267_truststore_platform_trust_only_still_refuses_the_rogue_server(
    rogue_server: LabServer, kind: str
) -> None:
    truststore = _truststore()
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client = _make(kind, rogue_server.url, verify=ctx)
    try:
        _assert_refused(client)
    finally:
        _close(client)
