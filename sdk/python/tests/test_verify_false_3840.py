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
constructors. ``None`` (httpx default trust), ``True`` and a CA-bundle path
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


# ---- round 4: exact-type context allowlist (#6267 #6268), capath (#6269),
# ---- annotation (#6270). 5-agent vote (4d3ea1c5): exact `ssl.SSLContext` only.


def _insecure_stdlib_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class _InnerDelegatingContext(ssl.SSLContext):
    """Shape of ``truststore.SSLContext``: the OUTER object keeps the stock
    CERT_REQUIRED + check_hostname state, while the properties and the wrap
    methods delegate to an INNER context that verifies nothing (#6267)."""

    _inner: ssl.SSLContext

    @classmethod
    def build(cls) -> _InnerDelegatingContext:
        outer = cls(ssl.PROTOCOL_TLS_CLIENT)
        outer._inner = _insecure_stdlib_context()
        return outer

    @property  # type: ignore[override]
    def verify_mode(self) -> ssl.VerifyMode:
        return self._inner.verify_mode

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode) -> None:
        pass

    @property  # type: ignore[override]
    def check_hostname(self) -> bool:
        return self._inner.check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        pass

    def wrap_socket(self, sock, *args, **kwargs):  # type: ignore[no-untyped-def,override]
        return self._inner.wrap_socket(sock, *args, **kwargs)

    def wrap_bio(self, incoming, outgoing, *args, **kwargs):  # type: ignore[no-untyped-def,override]
        return self._inner.wrap_bio(incoming, outgoing, *args, **kwargs)


class _WrapOverrideContext(ssl.SSLContext):
    """Base descriptors report a secure state; the handshake runs elsewhere (#6268)."""

    def wrap_socket(self, sock, *args, **kwargs):  # type: ignore[no-untyped-def,override]
        return _insecure_stdlib_context().wrap_socket(sock, *args, **kwargs)

    def wrap_bio(self, incoming, outgoing, *args, **kwargs):  # type: ignore[no-untyped-def,override]
        return _insecure_stdlib_context().wrap_bio(incoming, outgoing, *args, **kwargs)


class _GetattributeContext(ssl.SSLContext):
    """Redirects ``ctx.wrap_socket`` through ``__getattribute__`` (#6268)."""

    def __getattribute__(self, name: str) -> object:
        if name in ("wrap_socket", "wrap_bio"):
            return getattr(_insecure_stdlib_context(), name)
        return super().__getattribute__(name)


class _BenignSubclass(ssl.SSLContext):
    """A subclass that overrides nothing: still refused (exact-type allowlist)."""


def _instance_patched_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    insecure = _insecure_stdlib_context()
    context.wrap_socket = insecure.wrap_socket  # type: ignore[method-assign]
    context.wrap_bio = insecure.wrap_bio  # type: ignore[method-assign]
    return context


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    "make",
    [
        _InnerDelegatingContext.build,
        lambda: _WrapOverrideContext(ssl.PROTOCOL_TLS_CLIENT),
        lambda: _GetattributeContext(ssl.PROTOCOL_TLS_CLIENT),
        lambda: _BenignSubclass(ssl.PROTOCOL_TLS_CLIENT),
        _instance_patched_context,
    ],
    ids=["inner-delegating", "wrap-override", "getattribute", "benign-subclass", "instance-patched"],
)
def test_only_an_exact_ssl_context_is_admitted_6267_6268(client_cls: type, make: object) -> None:
    with pytest.raises(ValueError) as excinfo:
        client_cls(base_url=BASE_URL, verify=make())  # type: ignore[operator]
    message = str(excinfo.value)
    # The refusal names the accepted forms and the way out.
    assert "ssl.SSLContext" in message
    assert "create_default_context" in message


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("trusting", [True, False], ids=["default", "verification-off"])
def test_truststore_context_is_refused_6267(client_cls: type, trusting: bool) -> None:
    truststore = pytest.importorskip("truststore")
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not trusting:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="ssl.SSLContext"):
        client_cls(base_url=BASE_URL, verify=context)


def test_exact_context_with_unrelated_attribute_is_admitted_6268() -> None:
    context = ssl.create_default_context()
    context.my_label = "corp-ca"  # type: ignore[attr-defined]
    assert _kwargs(context)["verify"] is context


def test_instance_patched_after_construction_is_refused_per_request_6268(
    tls_server: tuple[str, str],
) -> None:
    base_url, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    with AiMemoryClient(base_url=base_url, verify=context) as client:
        assert client._client.get("/ok").status_code == 200  # noqa: SLF001
        insecure = _insecure_stdlib_context()
        context.wrap_socket = insecure.wrap_socket  # type: ignore[method-assign]
        context.wrap_bio = insecure.wrap_bio  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="verify=False"):
            client._client.get("/ok")  # noqa: SLF001


async def test_async_instance_patched_after_construction_is_refused_per_request_6268(
    tls_server: tuple[str, str],
) -> None:
    base_url, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    async with AsyncAiMemoryClient(base_url=base_url, verify=context) as client:
        assert (await client._client.get("/ok")).status_code == 200  # noqa: SLF001
        insecure = _insecure_stdlib_context()
        context.wrap_socket = insecure.wrap_socket  # type: ignore[method-assign]
        context.wrap_bio = insecure.wrap_bio  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="verify=False"):
            await client._client.get("/ok")  # noqa: SLF001


def test_class_level_wrap_patch_is_refused_per_request_6268(
    tls_server: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    base_url, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    with AiMemoryClient(base_url=base_url, verify=context) as client:
        assert client._client.get("/ok").status_code == 200  # noqa: SLF001
        stock = ssl.SSLContext.wrap_socket
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda self, *a, **kw: stock(self, *a, **kw))
        with pytest.raises(ValueError, match="verify=False"):
            client._client.get("/ok")  # noqa: SLF001


# ---- #6269: a CA directory is resolved when checked, not at handshake ----


def _hashed_ca_dir(directory: pathlib.Path, cert_path: str) -> pathlib.Path:
    """A CA directory (`<subject-hash>.0`) trusting ``cert_path``."""
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to hash a CA directory")
    digest = subprocess.run(  # noqa: S603 - fixed argv
        [openssl, "x509", "-hash", "-noout", "-in", cert_path],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    directory.mkdir(parents=True)
    shutil.copy(cert_path, directory / f"{digest}.0")
    return directory


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_relative_ca_directory_does_not_drift_with_cwd_6269(
    tls_server: tuple[str, str],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    import asyncio

    base_url, cert_path = tls_server
    empty = tmp_path / "empty"
    (empty / "ca").mkdir(parents=True)
    trusting = tmp_path / "trusting"
    _hashed_ca_dir(trusting / "ca", cert_path)
    monkeypatch.chdir(empty)
    client = client_cls(base_url=base_url, verify="ca")
    monkeypatch.chdir(trusting)  # the same relative name now resolves to a trusting dir
    if client_cls is AiMemoryClient:
        with pytest.raises(httpx.ConnectError):
            client._client.get("/ok")  # noqa: SLF001
        client.close()
    else:
        with pytest.raises(httpx.ConnectError):
            asyncio.run(client._client.get("/ok"))  # noqa: SLF001


@pytest.mark.parametrize("as_path", [True, False], ids=["pathlib.Path", "str"])
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_nonexistent_ca_path_is_a_value_error_6269(
    tmp_path: pathlib.Path, client_cls: type, as_path: bool
) -> None:
    missing = tmp_path / "no-such-ca.pem"
    with pytest.raises(ValueError, match="verify="):
        client_cls(base_url=BASE_URL, verify=missing if as_path else str(missing))


def test_symlinked_ca_file_is_resolved_and_verifies_6269(
    tls_server: tuple[str, str], tmp_path: pathlib.Path
) -> None:
    base_url, cert_path = tls_server
    link = tmp_path / "link.pem"
    link.symlink_to(cert_path)
    with AiMemoryClient(base_url=base_url, verify=str(link)) as client:
        assert client._client.get("/ok").status_code == 200  # noqa: SLF001


# ---- #6270: the annotation matches the documented forms ------------------


def test_verify_annotation_lists_every_documented_form_6270() -> None:
    import os
    import typing

    from ai_memory import client as sync_module
    from ai_memory import async_client as async_module

    from ai_memory._common import build_httpx_kwargs as funnel

    for callable_ in (sync_module.AiMemoryClient.__init__, async_module.AsyncAiMemoryClient.__init__, funnel):
        hint = typing.get_type_hints(callable_)["verify"]
        members = {typing.get_origin(arg) or arg for arg in typing.get_args(hint)}
        assert {bool, str, os.PathLike, ssl.SSLContext, type(None)} <= members, callable_


def test_documented_verify_forms_pass_mypy_strict_6270(tmp_path: pathlib.Path) -> None:
    import subprocess
    import sys

    pytest.importorskip("mypy")
    sdk_root = pathlib.Path(__file__).resolve().parent.parent
    result = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-m",
            "mypy",
            "--strict",
            "--follow-imports=silent",
            f"--cache-dir={tmp_path / 'mypy-cache'}",
            "tests/typing_samples/verify_forms.py",
        ],
        cwd=sdk_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ---- #6273: the README lists exactly the forms the funnel implements -------


def test_readme_lists_the_accepted_and_refused_verify_forms_6273() -> None:
    readme = (pathlib.Path(__file__).resolve().parent.parent / "README.md").read_text()
    marker = "Accepted and refused `verify=` forms"
    assert marker in readme, "README needs a section titled: " + marker
    section = readme.split(marker, 1)[1].split("\n## ", 1)[0]
    accepted, _, refused = section.partition("Refused")
    for token in ("None", "True", "os.PathLike", "ssl.create_default_context", "exactly `ssl.SSLContext`"):
        assert token.lower() in accepted.lower(), f"accepted list lacks {token!r}"
    for token in (
        "False",
        "CERT_NONE",
        "CERT_OPTIONAL",
        "check_hostname",
        "subclass",
        "truststore",
        "wrap_socket",
        "does not exist",
    ):
        assert token in refused, f"refused list lacks {token!r}"
    flat = " ".join(section.split())
    assert "resolved" in flat and "working directory" in flat


# ---- round 4b: post-handshake enforcement (#6305 #6306 #6268), FIFO (#6307),
# ---- project-local temp (#6309), trust-store wording (#6310).
# ---- 5-agent vote (4d3ea1c5), round 2: both the predicate and the trace.


class _CountingServer:
    """A loopback HTTPS server that counts the requests it actually receives."""

    def __init__(self, context: ssl.SSLContext) -> None:
        self.hits: list[str] = []
        hits = self.hits

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 5

            def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
                hits.append(self.path)
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
                socketserver.TCPServer.server_bind(self)
                self.server_name = "localhost"
                self.server_port = self.server_address[1]

            def handle_error(self, request: object, client_address: object) -> None:
                return  # a refused handshake is the expected outcome here

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.socket = context.wrap_socket(
            self.server.socket, server_side=True, do_handshake_on_connect=False
        )
        self.url = f"https://localhost:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def counting_server(tls_server: tuple[str, str]) -> Iterator[_CountingServer]:
    """A certificate-presenting server (the cert of ``tls_server``) counting requests."""
    _, cert_path = tls_server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, str(pathlib.Path(cert_path).with_name("key.pem")))
    server = _CountingServer(context)
    try:
        yield server
    finally:
        server.close()


@pytest.fixture
def anonymous_server() -> Iterator[_CountingServer]:
    """A TLS 1.2 server with anonymous (auth-null) suites and NO certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("aNULL:@SECLEVEL=0")
    server = _CountingServer(context)
    try:
        yield server
    finally:
        server.close()


def _anonymous_cipher_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_ciphers("HIGH:aNULL:@SECLEVEL=0")
    return context


def _fooled_predicate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the pre-handshake predicate admit anything: the enforcement must hold alone."""
    monkeypatch.setattr("ai_memory._common._context_verifies", lambda _context: True)


def _get(client_cls: type, url: str, verify: object) -> None:
    import asyncio

    if client_cls is AiMemoryClient:
        with AiMemoryClient(base_url=url, verify=verify, timeout=5) as client:  # type: ignore[arg-type]
            client._client.get("/x")  # noqa: SLF001
        return

    async def run() -> None:
        async with AsyncAiMemoryClient(base_url=url, verify=verify, timeout=5) as client:  # type: ignore[arg-type]
            await client._client.get("/x")  # noqa: SLF001

    asyncio.run(run())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_anonymous_cipher_context_never_reaches_an_uncertified_server_6305(
    anonymous_server: _CountingServer, client_cls: type
) -> None:
    # A stock, unmodified, CERT_REQUIRED context with auth-null suites at
    # SECLEVEL=0 handshakes with a server that presents no certificate.
    with pytest.raises(ValueError, match="verify=False"):
        _get(client_cls, anonymous_server.url, _anonymous_cipher_context())
    assert anonymous_server.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    "make",
    [_insecure_stdlib_context, _instance_patched_context],
    ids=["cert-none-context", "handshake-handed-off"],
)
def test_unverified_session_is_aborted_even_if_the_predicate_is_fooled_6268(
    counting_server: _CountingServer,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    make: object,
) -> None:
    # The negotiated session, not the context object, is what is trusted: no
    # validated peer certificate, or a session of another context, is refused
    # before a request byte is sent.
    _fooled_predicate(monkeypatch)
    with pytest.raises(ValueError, match="verify=False"):
        _get(client_cls, counting_server.url, make())  # type: ignore[operator]
    assert counting_server.hits == []


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_context_flipped_between_check_and_handshake_is_aborted_6306(
    counting_server: _CountingServer, tls_server: tuple[str, str], client_cls: type
) -> None:
    # Deterministic race: a hook that runs AFTER the SDK's request check and
    # BEFORE the handshake weakens the caller's context.
    import asyncio

    _, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)

    def weaken(_request: httpx.Request) -> None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    async def aweaken(_request: httpx.Request) -> None:
        weaken(_request)

    if client_cls is AiMemoryClient:
        client = AiMemoryClient(base_url=counting_server.url, verify=context, timeout=5)
        client._client.event_hooks["request"].append(weaken)  # noqa: SLF001
        with pytest.raises(ValueError, match="verify=False"):
            client._client.get("/x")  # noqa: SLF001
        client.close()
    else:
        async def run() -> None:
            client = AsyncAiMemoryClient(base_url=counting_server.url, verify=context, timeout=5)
            client._client.event_hooks["request"].append(aweaken)  # noqa: SLF001
            with pytest.raises(ValueError, match="verify=False"):
                await client._client.get("/x")  # noqa: SLF001
            await client.aclose()

        asyncio.run(run())
    assert counting_server.hits == []


def test_verified_session_still_connects_and_reuses_the_connection_6305(
    counting_server: _CountingServer, tls_server: tuple[str, str]
) -> None:
    _, cert_path = tls_server
    context = ssl.create_default_context(cafile=cert_path)
    with AiMemoryClient(base_url=counting_server.url, verify=context, timeout=5) as client:
        assert client._client.get("/a").status_code == 200  # noqa: SLF001
        assert client._client.get("/b").status_code == 200  # noqa: SLF001
    assert counting_server.hits == ["/a", "/b"]


def test_negotiated_session_check_is_fail_closed_6305() -> None:
    from ai_memory._common import _assert_negotiated_session

    context = ssl.create_default_context()
    other = ssl.create_default_context()

    class FakeSession:
        def __init__(self, ctx: object, peer: object) -> None:
            self.context = ctx
            self._peer = peer

        def getpeercert(self, binary_form: bool = False) -> object:  # noqa: FBT001, FBT002
            return self._peer

    good = FakeSession(context, {"subject": ((("commonName", "x"),),)})
    _assert_negotiated_session(good, context, "x")  # does not raise
    for session in {
        "no session at all": None,
        "other context": FakeSession(other, {"subject": ((("commonName", "x"),),)}),
        "no validated peer certificate": FakeSession(context, {}),
        "peer certificate unavailable": FakeSession(context, None),
    }.values():
        with pytest.raises(ValueError, match="verify=False"):
            _assert_negotiated_session(session, context, "x")  # type: ignore[arg-type]


# ---- #6307: a FIFO as verify= must be refused, not opened ----------------


def test_fifo_as_verify_is_refused_without_hanging_6307(tmp_path: pathlib.Path) -> None:
    import os

    fifo = tmp_path / "ca.fifo"
    os.mkfifo(fifo)
    outcome: list[BaseException | None] = []

    def build() -> None:
        try:
            AiMemoryClient(base_url=BASE_URL, verify=str(fifo))
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            outcome.append(exc)

    worker = threading.Thread(target=build, daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():  # unblock the leaked opener before failing
        release = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        os.close(release)
        worker.join(2)
        pytest.fail("client construction blocked opening a FIFO")
    assert isinstance(outcome[0], ValueError)


# ---- #6269 addendum: "." and Path("") are cwd-relative too ----------------


@pytest.mark.parametrize("spelling", [".", ""], ids=["dot", "empty-Path"])
def test_dot_and_empty_path_do_not_drift_with_cwd_6269(
    tls_server: tuple[str, str],
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    base_url, cert_path = tls_server
    empty = tmp_path / "empty"
    empty.mkdir()
    trusting = _hashed_ca_dir(tmp_path / "trusting", cert_path)
    monkeypatch.chdir(empty)
    client = AiMemoryClient(base_url=base_url, verify=pathlib.Path(spelling))
    monkeypatch.chdir(trusting)
    with pytest.raises(httpx.ConnectError):
        client._client.get("/ok")  # noqa: SLF001
    client.close()


# ---- #6309: no test file under the system temp dir --------------------------


def test_pytest_temp_root_is_project_local_6309(tmp_path_factory: pytest.TempPathFactory) -> None:
    # Repo rule: no agent-created file under the system temp dir. The EC key
    # written by the `tls_server` fixture lives under this root.
    base = tmp_path_factory.getbasetemp().resolve()
    project_runs = (pathlib.Path(__file__).resolve().parents[3] / ".local-runs").resolve()
    assert project_runs in base.parents, base


# ---- #6310: verify=None is httpx's certifi/SSL_CERT_* store, not the OS store


def test_verify_none_is_not_described_as_the_os_trust_store_6310() -> None:
    import inspect

    from ai_memory import _common
    from ai_memory import async_client as async_module
    from ai_memory import client as sync_module

    sdk_root = pathlib.Path(__file__).resolve().parent.parent
    texts = {
        "README": (sdk_root / "README.md").read_text(),
        "_common": inspect.getsource(_common),
        "client": inspect.getsource(sync_module),
        "async_client": inspect.getsource(async_module),
        "test module": pathlib.Path(__file__).read_text().split("# ---- round 4", 1)[0],
    }
    for label, text in texts.items():
        flat = " ".join(text.lower().split())
        assert "platform trust store" not in flat, label
        assert "platform/os trust store" not in flat, label
        assert "os trust store" not in flat.replace("into the os trust store", ""), label
    readme = " ".join(texts["README"].split())
    assert "certifi" in readme and "SSL_CERT_FILE" in readme and "SSL_CERT_DIR" in readme
