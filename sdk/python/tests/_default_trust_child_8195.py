"""Child process of ``test_default_trust_8195_r3`` (not collected by pytest).

Simulates a host whose OpenSSL policy permits TLS 1.1 (the parent points OPENSSL_CONF at
``DEFAULT:@SECLEVEL=0``), serves a TLS 1.1-only lab origin, points ``certifi.where`` at the
lab CA and prints one JSON object per ``verify`` form: the outcome, the protocol versions the
server saw and whether the ``X-API-Key`` header reached it. Usage::

    python -I _default_trust_child_8195.py <sdk/python> <scratch dir>
"""
from __future__ import annotations

import json
import os
import pathlib
import socket
import ssl
import sys
import tempfile
import threading

PLACEHOLDER_KEY = "placeholder-not-a-credential-8195"
FORMS = ("none", "true", "ca-path", "default-context")


def _serve(sctx: ssl.SSLContext, lsock: socket.socket, seen: dict) -> None:
    lsock.settimeout(8)
    for _ in range(8):
        try:
            conn, _addr = lsock.accept()
        except OSError:
            return
        try:
            tls = sctx.wrap_socket(conn, server_side=True)
            seen["versions"].append(tls.version())
            tls.settimeout(2)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            if b"x-api-key" in data.lower():
                seen["api_key"] = True
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
            tls.close()
        except (OSError, ssl.SSLError):
            conn.close()


def main(sdk: str, scratch: str) -> int:
    sys.path.insert(0, sdk)
    sys.path.insert(0, os.path.join(sdk, "tests"))
    import _tlslab
    import certifi

    import ai_memory

    os.umask(0o022)
    lab = _tlslab.Lab(pathlib.Path(tempfile.mkdtemp(dir=scratch)))
    certifi.where = lambda: str(lab.ca_path)  # the httpx default trust now names the lab CA
    cert, key = lab.leaf("srv")
    try:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        sctx.minimum_version = ssl.TLSVersion.TLSv1_1
        sctx.maximum_version = ssl.TLSVersion.TLSv1_1
        sctx.load_cert_chain(str(cert), str(key))
    except (ValueError, ssl.SSLError):
        print(json.dumps({"form": "setup", "outcome": "CANNOT-BUILD-TLS11-SERVER"}))
        return 0
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    port = lsock.getsockname()[1]
    seen: dict = {"versions": [], "api_key": False}
    threading.Thread(target=_serve, args=(sctx, lsock, seen), daemon=True).start()
    verifies = {
        "none": None,
        "true": True,
        "ca-path": str(lab.ca_path),
        "default-context": lab.client_context(),
    }
    for form in FORMS:
        seen["api_key"] = False
        before = len(seen["versions"])
        try:
            client = ai_memory.AiMemoryClient(
                f"https://localhost:{port}", verify=verifies[form], api_key=PLACEHOLDER_KEY
            )
        except ValueError:
            print(json.dumps({"form": form, "outcome": "REFUSED-AT-CONSTRUCTION", "versions": [], "api_key": False}))
            continue
        try:
            client.health()
            outcome = "SENT-OK"
        except ValueError:
            outcome = "REFUSED-SESSION-GATE"
        except Exception as err:  # noqa: BLE001 - classify the outcome for the parent
            outcome = f"ERR-{type(err).__name__}"
        client.close()
        print(json.dumps({"form": form, "outcome": outcome, "versions": seen["versions"][before:], "api_key": seen["api_key"]}))
    lsock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
