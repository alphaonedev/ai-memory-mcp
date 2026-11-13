# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Local TLS lab for the SDK TLS-verification tests (#6249 #6267 #6306).

Mints a throwaway PKI with ``cryptography`` (already a dev dependency) and
runs a tiny HTTPS server on 127.0.0.1 that answers every GET with a JSON
health body. Nothing here touches the network beyond the loopback socket.

PKI:
    trusted_ca   the CA the client is told to trust
    rogue_ca     a CA the client never trusts (the attacker's)
    good leaf    signed by trusted_ca, SAN 127.0.0.1 / localhost
    rogue leaf   signed by rogue_ca,   SAN 127.0.0.1 / localhost
    wrong leaf   signed by trusted_ca, SAN wrong.example only (hostname check)
    client leaf  signed by trusted_ca, for the mTLS leg
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

#: Lifetime of every lab certificate. Short, the lab is rebuilt per session.
LAB_CERT_DAYS = 2
#: Seconds a lab server socket waits on a stalled peer before giving up.
LAB_SOCKET_TIMEOUT_S = 5.0
#: The health body every lab server returns.
LAB_HEALTH_BODY = {"status": "ok", "lab": "tls-6249"}


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclass(frozen=True)
class _Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey


def _ca(common_name: str) -> _Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=LAB_CERT_DAYS))
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _Issued(cert, key)


def _leaf(
    issuer: _Issued, common_name: str, sans: list[x509.GeneralName], *, client: bool
) -> _Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    usage = ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=LAB_CERT_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()),
            critical=False,
        )
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return _Issued(builder.sign(issuer.key, hashes.SHA256()), key)


def _write_pair(directory: Path, stem: str, issued: _Issued) -> tuple[Path, Path]:
    cert_path = directory / f"{stem}.crt"
    key_path = directory / f"{stem}.key"
    cert_path.write_bytes(issued.cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        issued.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@dataclass(frozen=True)
class Lab:
    """Paths of every lab PEM file."""

    root: Path
    trusted_ca: Path
    rogue_ca: Path
    good: tuple[Path, Path]
    rogue: tuple[Path, Path]
    wrong_host: tuple[Path, Path]
    client: tuple[Path, Path]


def build_lab(root: Path) -> Lab:
    """Mint the lab PKI under ``root`` and return the file paths."""
    root.mkdir(parents=True, exist_ok=True)
    trusted = _ca("ai-memory tls lab trusted CA")
    rogue = _ca("ai-memory tls lab rogue CA")
    loopback: list[x509.GeneralName] = [
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.DNSName("localhost"),
    ]
    trusted_ca, _ = _write_pair(root, "trusted-ca", trusted)
    rogue_ca, _ = _write_pair(root, "rogue-ca", rogue)
    return Lab(
        root=root,
        trusted_ca=trusted_ca,
        rogue_ca=rogue_ca,
        good=_write_pair(root, "good", _leaf(trusted, "good", loopback, client=False)),
        rogue=_write_pair(root, "rogue", _leaf(rogue, "rogue", loopback, client=False)),
        wrong_host=_write_pair(
            root,
            "wrong-host",
            _leaf(trusted, "wrong", [x509.DNSName("wrong.example")], client=False),
        ),
        client=_write_pair(root, "client", _leaf(trusted, "lab-client", [], client=True)),
    )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = json.dumps(LAB_HEALTH_BODY).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


class _TLSServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self._ssl_context = ssl_context
        self._count_lock = threading.Lock()
        #: Server-side handshakes that completed (a refused client adds none).
        self.handshakes = 0
        super().__init__(("127.0.0.1", 0), _Handler)

    def get_request(self) -> tuple[Any, Any]:
        sock, addr = self.socket.accept()
        sock.settimeout(LAB_SOCKET_TIMEOUT_S)
        return sock, addr

    def finish_request(self, request: Any, client_address: Any) -> None:
        # The handshake runs on the worker thread so one refused client
        # never stalls the accept loop.
        try:
            tls = self._ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        with self._count_lock:
            self.handshakes += 1
        try:
            super().finish_request(tls, client_address)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle_error(self, request: Any, client_address: Any) -> None:
        return


@final
class LabServer:
    """An HTTPS server on 127.0.0.1 presenting one lab leaf."""

    def __init__(self, leaf: tuple[Path, Path], *, client_ca: Path | None = None) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(leaf[0]), str(leaf[1]))
        if client_ca is not None:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=str(client_ca))
        self._server = _TLSServer(ctx)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def handshakes(self) -> int:
        """Completed server-side handshakes so far."""
        return self._server.handshakes

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"https://{host}:{port}"

    def __enter__(self) -> LabServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=LAB_SOCKET_TIMEOUT_S)
