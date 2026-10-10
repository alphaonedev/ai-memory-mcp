# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Loopback TLS lab for the ``verify=`` enforcement suites (#6060 round 5).

* :class:`Lab` - a throwaway CA and leaf certificates (right name, wrong name,
  expired, CN-only) written under a pytest temp directory.
* :class:`RecordingServer` - an HTTPS origin that records every request it
  actually receives and whether it carried ``X-API-Key``.
* :class:`TunnelProxy` - an HTTP CONNECT proxy (plain or TLS) or a SOCKS5
  proxy that records each tunnel it opens.

Everything binds ``127.0.0.1`` and is addressed as ``localhost``; nothing here
reaches the network.
"""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import pathlib
import select
import socket
import socketserver
import ssl
import struct
import threading
from collections.abc import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_NOW = datetime.datetime.now(datetime.timezone.utc)
_HEAD_LIMIT = 65536
_PIPE_CHUNK = 65536
_IO_TIMEOUT = 5.0


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


class Lab:
    """A CA and the leaf certificates it signs."""

    def __init__(self, directory: pathlib.Path) -> None:
        self.directory = directory
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ai-memory r5 lab CA")])
        self.ca = (
            x509.CertificateBuilder()
            .subject_name(self._name)
            .issuer_name(self._name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=30))
            .not_valid_after(_NOW + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self.ca_path = directory / "lab-ca.pem"
        self.ca_path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))

    def leaf(
        self,
        label: str,
        *,
        dns: Sequence[str] = ("localhost",),
        ips: Sequence[str] = ("127.0.0.1",),
        common_name: str = "localhost",
        not_before: datetime.datetime | None = None,
        not_after: datetime.datetime | None = None,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        """Issue a leaf; returns ``(cert_path, key_path)``. No SAN when both lists are empty."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self._name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or _NOW - datetime.timedelta(days=1))
            .not_valid_after(not_after or _NOW + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
        )
        names: list[x509.GeneralName] = [x509.DNSName(name) for name in dns]
        names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        cert = builder.sign(self._key, hashes.SHA256())
        cert_path = self.directory / f"{label}.pem"
        key_path = self.directory / f"{label}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(_pem_key(key))
        return cert_path, key_path

    def server_context(self, label: str, **leaf: object) -> ssl.SSLContext:
        cert_path, key_path = self.leaf(label, **leaf)  # type: ignore[arg-type]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        return context

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca_path))


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:
        # HTTPServer.server_bind resolves the FQDN, which stalls on hosts without DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def handle_error(self, request: object, client_address: object) -> None:
        return  # a refused handshake is an expected outcome in these suites


class RecordingServer:
    """An HTTPS origin recording the requests it actually receives."""

    def __init__(self, context: ssl.SSLContext) -> None:
        self.hits: list[str] = []
        self.api_keys: list[str] = []
        hits, api_keys = self.hits, self.api_keys

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = _IO_TIMEOUT
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
                hits.append(self.path)
                key = self.headers.get("X-API-Key")
                if key is not None:
                    api_keys.append(key)
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        self.server = _QuietServer(("127.0.0.1", 0), Handler)
        self.server.socket = context.wrap_socket(
            self.server.socket, server_side=True, do_handshake_on_connect=False
        )
        self.port = self.server.server_address[1]
        self.url = f"https://localhost:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _read_head(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > _HEAD_LIMIT:
            break
    return data


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("short read")
        data += chunk
    return data


def _pipe(left: socket.socket, right: socket.socket) -> None:
    """Relay bytes both ways on one thread (an SSL socket is not shared across threads)."""
    sockets = [left, right]
    for sock in sockets:
        sock.setblocking(False)
    try:
        while True:
            ready: list[socket.socket] = [
                s for s in sockets if isinstance(s, ssl.SSLSocket) and s.pending()
            ]
            if not ready:
                ready, _, _ = select.select(sockets, [], [], _IO_TIMEOUT)
                if not ready:
                    return
            for src in ready:
                dst = right if src is left else left
                try:
                    chunk = src.recv(_PIPE_CHUNK)
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                if not chunk:
                    return
                dst.setblocking(True)
                dst.sendall(chunk)
                dst.setblocking(False)
    except OSError:
        return


class TunnelProxy:
    """A forward proxy: ``kind`` is ``"http"`` (CONNECT), ``"https"`` (CONNECT over TLS) or ``"socks5"``."""

    def __init__(self, kind: str, tls: ssl.SSLContext | None = None) -> None:
        self.kind = kind
        self.tunnels: list[str] = []
        self.heads: list[bytes] = []
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                conn: socket.socket = self.request
                conn.settimeout(_IO_TIMEOUT)
                try:
                    target = proxy._open(conn)
                except (OSError, ValueError):
                    return
                if target is None:
                    return
                with target:
                    _pipe(conn, target)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request: object, client_address: object) -> None:
                return

        self.server = Server(("127.0.0.1", 0), Handler)
        if kind == "https":
            if tls is None:
                raise ValueError("an https proxy needs a server context")
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        scheme = "socks5" if kind == "socks5" else kind
        self.url = f"{scheme}://localhost:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _open(self, conn: socket.socket) -> socket.socket | None:
        if self.kind == "socks5":
            return self._open_socks(conn)
        head = _read_head(conn)
        self.heads.append(head)
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        method, _, rest = line.partition(" ")
        authority = rest.split(" ", 1)[0]
        if method != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return None
        host, _, port = authority.rpartition(":")
        upstream = socket.create_connection(("127.0.0.1", int(port)), timeout=_IO_TIMEOUT)
        self.tunnels.append(f"{host}:{port}")
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        return upstream

    def _open_socks(self, conn: socket.socket) -> socket.socket | None:
        version, count = _recv_exact(conn, 2)
        _recv_exact(conn, count)
        if version != 5:
            return None
        conn.sendall(b"\x05\x00")
        _, command, _, atyp = _recv_exact(conn, 4)
        if atyp == 3:
            host = _recv_exact(conn, _recv_exact(conn, 1)[0]).decode("idna")
        elif atyp == 1:
            host = socket.inet_ntoa(_recv_exact(conn, 4))
        else:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
        (port,) = struct.unpack("!H", _recv_exact(conn, 2))
        if command != 1:
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return None
        upstream = socket.create_connection(("127.0.0.1", port), timeout=_IO_TIMEOUT)
        self.tunnels.append(f"{host}:{port}")
        conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port))
        return upstream

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
