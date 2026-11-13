"""Child process for ``test_tls_getset_identity_8195_r7``: the REAL clients against a TLS 1.1 origin (code r6 F1).

usage: ``OPENSSL_CONF=<lowsec.cnf> python _client_gate_child_8195.py <sdk> <scratch> <mode>``

A loopback origin accepts TLS 1.1 only and counts the request bytes it receives after the handshake. The
client context verifies the lab CA and its real floor is lowered to TLS 1.1; the SDK's construction and
per-request context predicates are switched off so the post-handshake session gate is the only defence
(the construction predicate has its own rows). Modes: ``sync-ctl`` and ``async-ctl`` (no replacement),
``objlie`` (pre-import ``sslobject_class`` subclass reporting TLSv1.2), ``biolie`` (pre-import ``wrap_bio``
wrapper whose session reports TLSv1.2), ``biofake`` (``wrap_bio`` returns a pure-Python stand-in), ``socklie``
(pre-import ``sslsocket_class`` subclass, sync client). Prints ``handshake=<ver>``, ``request_bytes=<n>`` and
``outcome=<COMPLETED|REFUSED-ValueError|OTHER-<name>>``. No request body, no credential.
"""
from __future__ import annotations

import asyncio
import pathlib
import socket
import ssl
import sys
import threading

import _ssl

SDK, SCRATCH, MODE = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, SDK)
sys.path.insert(0, SDK + "/tests")
import _tlslab  # type: ignore[import-not-found]  # noqa: E402

REAL_MIN = _ssl._SSLContext.__dict__["minimum_version"]
_V11 = getattr(ssl.TLSVersion, "TLSv1_1")  # the deliberately weak version this row must see refused
SERVER_ERRORS: list = []


class _LyingObject(ssl.SSLObject):
    def version(self):  # type: ignore[no-untyped-def]
        return "TLSv1.2"


class _LyingSocket(ssl.SSLSocket):
    def version(self):  # type: ignore[no-untyped-def]
        return "TLSv1.2"


class _Stand:
    """A pure-Python stand-in for the session object (no C object behind it)."""

    def __init__(self, real):  # type: ignore[no-untyped-def]
        self._real = real

    def __getattr__(self, name):  # type: ignore[no-untyped-def]
        return getattr(self._real, name)

    def version(self):  # type: ignore[no-untyped-def]
        return "TLSv1.2"


if MODE == "objlie":
    ssl.SSLContext.sslobject_class = _LyingObject  # type: ignore[assignment]
elif MODE == "socklie":
    ssl.SSLContext.sslsocket_class = _LyingSocket  # type: ignore[assignment]
elif MODE in ("biolie", "biofake"):
    _orig_wrap_bio = ssl.SSLContext.wrap_bio

    def _wrap_bio(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        real = _orig_wrap_bio(self, *args, **kwargs)
        if MODE == "biofake":
            return _Stand(real)
        real.version = lambda: "TLSv1.2"
        return real

    ssl.SSLContext.wrap_bio = _wrap_bio  # type: ignore[method-assign]

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _common  # noqa: E402

lab = _tlslab.Lab(pathlib.Path(SCRATCH))
server = lab.server_context("localhost")
server.minimum_version = _V11
server.maximum_version = _V11
server.set_ciphers("DEFAULT:@SECLEVEL=0")
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(4)
port = listener.getsockname()[1]
seen = {"version": "none", "bytes": 0}


def serve() -> None:
    try:
        conn, _ = listener.accept()
        wrapped = server.wrap_socket(conn, server_side=True)
        seen["version"] = str(ssl.SSLSocket.version(wrapped))
        wrapped.settimeout(3)
        try:
            seen["bytes"] = len(wrapped.recv(4096))
        except OSError as exc:
            SERVER_ERRORS.append(type(exc).__name__)
        wrapped.close()
    except OSError as exc:
        SERVER_ERRORS.append(type(exc).__name__)


thread = threading.Thread(target=serve, daemon=True)
thread.start()

context = lab.client_context()
REAL_MIN.__set__(context, _V11)
context.set_ciphers("DEFAULT:@SECLEVEL=0")
_common._context_verifies = lambda candidate: True  # type: ignore[assignment]
url = f"https://localhost:{port}"


async def run_async() -> object:
    async with AsyncAiMemoryClient(base_url=url, verify=context, timeout=5) as client:
        return await client.health()


def run_sync() -> object:
    with AiMemoryClient(base_url=url, verify=context, timeout=5) as client:
        return client.health()


try:
    if MODE in ("sync-ctl", "socklie"):
        run_sync()
    else:
        asyncio.run(run_async())
    outcome = "COMPLETED"
except ValueError:
    outcome = "REFUSED-ValueError"
except Exception as exc:  # noqa: BLE001 - the row reports the class only
    outcome = "OTHER-" + type(exc).__name__
thread.join(timeout=5)
print("handshake=" + seen["version"])
print("request_bytes=" + str(seen["bytes"]))
print("outcome=" + outcome)
print("server_errors=" + str(SERVER_ERRORS))
