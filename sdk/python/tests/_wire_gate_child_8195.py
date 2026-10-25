"""Child process for ``test_tls_getset_identity_8195_r7``: the post-handshake gate on a real wire (sec r6 S1-wire).

usage: ``OPENSSL_CONF=<lowsec.cnf> python _wire_gate_child_8195.py <sdk> <scratch> <mode>``

``plain`` and ``socklie``: a loopback server accepts TLS 1.1 only, the client context verifies the lab CA
and its real floor is lowered to TLS 1.1; ``socklie`` adds a pre-import ``sslsocket_class`` subclass whose
``version()`` reports ``TLSv1.2``. ``peerlie``: the client context is ``CERT_NONE`` (so the real peer
certificate is empty) and the subclass returns a valid-looking ``getpeercert()``. ``cipherlie``: both sides
negotiate an eNULL suite (no secret bits) and the subclass reports a 256-bit ``cipher()``. The SDK's own
``_assert_negotiated_session`` then runs on the client socket. Prints ``handshake=<OK|FAILED>`` and
``GATE=<REFUSED-ValueError|PASSED>``. ``ctxlie``: the handshake ran on one context, the gate is asked about
another, and the subclass reports the gate's context from ``context``. No request body, no credential.
"""
from __future__ import annotations

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


class _LyingSocket(ssl.SSLSocket):
    def version(self):  # type: ignore[no-untyped-def]
        return "TLSv1.2" if MODE == "socklie" else super().version()

    def getpeercert(self, binary_form=False):  # type: ignore[no-untyped-def]
        if MODE in ("peerlie", "leaflie"):
            return {
                "subjectAltName": (("DNS", "localhost"),),
                "notBefore": "Jan  1 00:00:00 2020 GMT",
                "notAfter": "Jan  1 00:00:00 2099 GMT",
            }
        return super().getpeercert(binary_form)

    def cipher(self):  # type: ignore[no-untyped-def]
        if MODE == "cipherlie":
            return ("ECDHE-ECDSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        return super().cipher()

    @property
    def context(self):  # type: ignore[no-untyped-def]
        return GATE_CONTEXT if MODE == "ctxlie" else self._context

    @context.setter
    def context(self, value):  # type: ignore[no-untyped-def]
        self._context = value


GATE_CONTEXT = None


if MODE != "plain":
    ssl.SSLContext.sslsocket_class = _LyingSocket  # type: ignore[assignment]

from ai_memory import _common  # noqa: E402

scratch = pathlib.Path(SCRATCH)
lab = _tlslab.Lab(scratch)
cert_path, key_path = lab.leaf("localhost")

server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if MODE in ("plain", "socklie"):
    server.minimum_version = _V11
    server.maximum_version = _V11
    server.set_ciphers("DEFAULT:@SECLEVEL=0")
elif MODE == "cipherlie":
    server.maximum_version = ssl.TLSVersion.TLSv1_2
    server.set_ciphers("eNULL:@SECLEVEL=0")
server.load_cert_chain(str(cert_path), str(key_path))
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]


def serve() -> None:
    try:
        conn, _ = listener.accept()
        wrapped = server.wrap_socket(conn, server_side=True)
        try:
            wrapped.recv(16)
        except OSError as exc:
            SERVER_ERRORS.append(type(exc).__name__)
        wrapped.close()
    except OSError as exc:
        SERVER_ERRORS.append(type(exc).__name__)


thread = threading.Thread(target=serve, daemon=True)
thread.start()

context = ssl.create_default_context(cafile=str(lab.ca_path))
if MODE in ("plain", "socklie"):
    REAL_MIN.__set__(context, _V11)
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
elif MODE in ("peerlie", "leaflie"):
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
elif MODE == "cipherlie":
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("eNULL:@SECLEVEL=0")
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
try:
    session = context.wrap_socket(raw, server_hostname="localhost")
except ssl.SSLError:
    print("handshake=FAILED")
    raise SystemExit(0)
print("handshake=OK real=" + str(ssl.SSLSocket.version(session)))
try:
    if MODE == "ctxlie":
        GATE_CONTEXT = ssl.create_default_context(cafile=str(lab.ca_path))
        _common._assert_negotiated_session(session, GATE_CONTEXT, "localhost")
    elif MODE == "leaflie":
        _common._assert_leaf_current(session)
    else:
        _common._assert_negotiated_session(session, context, "localhost")
    print("GATE=PASSED")
except ValueError:
    print("GATE=REFUSED-ValueError")
finally:
    session.close()
    thread.join(timeout=3)
print("server_errors=" + str(SERVER_ERRORS))
