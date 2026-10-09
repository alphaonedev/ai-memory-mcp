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

import datetime
import http.server
import ipaddress
import pathlib
import socketserver
import ssl
import threading
from collections.abc import Iterator

import certifi
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


def _effective(context: ssl.SSLContext) -> tuple[ssl.VerifyMode, bool]:
    """The OpenSSL-level state, read through the base-class descriptors so a
    subclass's overridden properties cannot misreport it."""
    return (
        ssl.SSLContext.verify_mode.__get__(context),
        ssl.SSLContext.check_hostname.__get__(context),
    )


def _client_context(client: AiMemoryClient | AsyncAiMemoryClient) -> ssl.SSLContext:
    pool = client._client._transport._pool  # noqa: SLF001 - effective TLS posture probe
    return pool._ssl_context  # type: ignore[no-any-return]  # noqa: SLF001


class _FalsyStr(str):
    """``__bool__`` lies: httpx 0.27 reads ``if self.verify:`` and skips verification."""

    def __bool__(self) -> bool:
        return False


class _ZeroLenStr(str):
    """``__len__`` lies: truthiness falls back to it when ``__bool__`` is absent."""

    def __len__(self) -> int:
        return 0


class _FalsyPathLike:
    def __init__(self, path: str) -> None:
        self._path = path

    def __fspath__(self) -> str:
        return self._path

    def __bool__(self) -> bool:
        return False


class _FalsyPath(type(pathlib.Path())):  # type: ignore[misc]
    def __bool__(self) -> bool:
        return False


class _LyingContext(ssl.SSLContext):
    """Python-level ``verify_mode``/``check_hostname`` report a secure state
    over a context whose OpenSSL state is CERT_NONE / no hostname check."""

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


def _lying_context() -> ssl.SSLContext:
    context = _LyingContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl.SSLContext.check_hostname.__set__(context, False)  # type: ignore[attr-defined]
    ssl.SSLContext.verify_mode.__set__(context, ssl.CERT_NONE)  # type: ignore[attr-defined]
    return context


_CA = certifi.where()
_CLIENTS = [AiMemoryClient, AsyncAiMemoryClient]


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    "make",
    [
        lambda: _FalsyStr(_CA),
        lambda: _ZeroLenStr(_CA),
        lambda: _FalsyPathLike(_CA),
        lambda: _FalsyPath(_CA),
    ],
    ids=["str-lying-bool", "str-lying-len", "pathlike-lying-bool", "path-subclass-lying-bool"],
)
def test_lying_path_objects_never_yield_an_unverified_client_6248(client_cls: type, make: object) -> None:
    # #6248 — httpx 0.27 decides with `if self.verify:`; the guard must forward
    # an exact checked value, not the caller's object. The client either
    # refuses or is built on a CERT_REQUIRED + check_hostname context.
    try:
        client = client_cls(base_url=BASE_URL, verify=make())  # type: ignore[operator]
    except ValueError:
        return
    assert _effective(_client_context(client)) == (ssl.CERT_REQUIRED, True)


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_lying_ssl_context_subclass_is_refused_6248(client_cls: type) -> None:
    # The properties say CERT_REQUIRED; OpenSSL says CERT_NONE. Refuse on the
    # base-class state (both httpx 0.27.2 and 0.28.1 use the context as given).
    with pytest.raises(ValueError):
        client_cls(base_url=BASE_URL, verify=_lying_context())


def test_funnel_forwards_nothing_the_caller_can_re_decide_6248() -> None:
    for make in (lambda: _FalsyStr(_CA), lambda: _FalsyPathLike(_CA), lambda: _FalsyPath(_CA)):
        forwarded = _kwargs(make())["verify"]  # type: ignore[operator]
        assert forwarded is True or type(forwarded) is ssl.SSLContext


# ---- request-level proofs against a self-signed local TLS listener --------


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, str]]:
    """A loopback HTTPS server with a self-signed cert; yields (base_url, cert_path)."""
    directory = tmp_path_factory.mktemp("tls6245")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 5  # a peer that aborts the handshake must not wedge a handler thread

        def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return

    class Server(http.server.ThreadingHTTPServer):
        def server_bind(self) -> None:
            # HTTPServer.server_bind resolves the FQDN, which stalls ~35s on hosts without DNS.
            socketserver.TCPServer.server_bind(self)
            self.server_name = "localhost"
            self.server_port = self.server_address[1]

    server = Server(("127.0.0.1", 0), Handler)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert_path), str(key_path))
    # Handshake lazily in the per-connection handler thread, not in accept():
    # a client that refuses the certificate must not stall the accept loop.
    server.socket = server_ctx.wrap_socket(
        server.socket, server_side=True, do_handshake_on_connect=False
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_address[1]}", str(cert_path)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("as_path", [True, False], ids=["pathlib.Path", "str"])
def test_ca_path_gives_a_working_verified_client_6245(tls_server: tuple[str, str], as_path: bool) -> None:
    # #6245 — a `pathlib.Path` CA crashed every request on httpx 0.28
    # (`set_alpn_protocols`). The server's own cert as the CA must verify.
    base_url, cert_path = tls_server
    verify = pathlib.Path(cert_path) if as_path else cert_path
    with AiMemoryClient(base_url=base_url, verify=verify) as client:
        assert client._client.get("/ok").status_code == 200  # noqa: SLF001


@pytest.mark.parametrize("as_path", [True, False], ids=["pathlib.Path", "str"])
async def test_async_ca_path_gives_a_working_verified_client_6245(
    tls_server: tuple[str, str], as_path: bool
) -> None:
    base_url, cert_path = tls_server
    verify = pathlib.Path(cert_path) if as_path else cert_path
    async with AsyncAiMemoryClient(base_url=base_url, verify=verify) as client:
        assert (await client._client.get("/ok")).status_code == 200  # noqa: SLF001


def test_wrong_ca_still_fails_verification_6245(tls_server: tuple[str, str]) -> None:
    # Harness control: the same listener is NOT trusted via the public bundle.
    base_url, _ = tls_server
    with AiMemoryClient(base_url=base_url, verify=pathlib.Path(certifi.where())) as client:
        with pytest.raises(httpx.ConnectError):
            client._client.get("/ok")  # noqa: SLF001


def _weaken(context: ssl.SSLContext) -> None:
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE


def test_context_weakened_after_construction_is_refused_per_request_6249(
    tls_server: tuple[str, str],
) -> None:
    # #6249 — the construction-time check must not be the only check: a caller
    # who weakens the context they passed in must not reach the server.
    base_url, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    with AiMemoryClient(base_url=base_url, verify=context) as client:
        assert client._client.get("/ok").status_code == 200  # noqa: SLF001
        _weaken(context)
        with pytest.raises(ValueError, match="verify=False"):
            client._client.get("/ok")  # noqa: SLF001


async def test_async_context_weakened_after_construction_is_refused_per_request_6249(
    tls_server: tuple[str, str],
) -> None:
    base_url, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    async with AsyncAiMemoryClient(base_url=base_url, verify=context) as client:
        assert (await client._client.get("/ok")).status_code == 200  # noqa: SLF001
        _weaken(context)
        with pytest.raises(ValueError, match="verify=False"):
            await client._client.get("/ok")  # noqa: SLF001


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


@pytest.mark.parametrize("verify", [None, True])
def test_funnel_admits_none_and_true(verify: object) -> None:
    kwargs = _kwargs(verify)
    if verify is None:
        assert "verify" not in kwargs
    else:
        assert kwargs["verify"] is True


def test_funnel_forwards_a_context_the_sdk_built_from_the_ca_path() -> None:
    # #3840 / #6248 — the SDK forwards ONLY what it checked: a CA path becomes
    # a verifying context built from the exact path string, never the
    # caller's object (httpx would re-read its truthiness or type).
    forwarded = _kwargs(certifi.where())["verify"]
    assert isinstance(forwarded, ssl.SSLContext)
    assert _effective(forwarded) == (ssl.CERT_REQUIRED, True)


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
    forwarded = _kwargs(pathlib.Path(certifi.where()))["verify"]
    assert isinstance(forwarded, ssl.SSLContext)
    assert _effective(forwarded) == (ssl.CERT_REQUIRED, True)


def test_funnel_refuses_cert_optional_context() -> None:
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_OPTIONAL
    with pytest.raises(ValueError):
        _kwargs(context)


@pytest.mark.parametrize("verify", ["", _unverified_context()], ids=["empty", "context"])
def test_both_constructors_refuse_bypass_forms(verify: object) -> None:
    with pytest.raises(ValueError):
        AiMemoryClient(base_url=BASE_URL, verify=verify)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AsyncAiMemoryClient(base_url=BASE_URL, verify=verify)  # type: ignore[arg-type]
