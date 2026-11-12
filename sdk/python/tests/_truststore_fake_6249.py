# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""truststore-shaped fakes for the #6267 shape tests (no truststore needed).

CI installs no truststore (#6688), so the rows that pin the SDK's truststore
contract run against these fakes. Each fake reproduces one released shape:

* 0.10.5+ - an inner ``_ctx``, a re-entrant ``_ctx_lock`` taken by
  ``wrap_socket`` / ``wrap_bio``, and verifying socket / SSL-object classes
  with their own ``do_handshake`` (where truststore checks the platform store
  on macOS and Windows);
* 0.10.4 - the same, with a non-reentrant ``threading.Lock`` (the SDK taking
  it around truststore's own ``wrap_socket`` would block forever);
* 0.10.0 .. 0.10.3 - no ``_ctx_lock`` at all.

The fake verifies with OpenSSL on its inner context, as truststore does on
Linux, so a fake that the SDK accepts can complete a real lab handshake.
"""

from __future__ import annotations

import contextlib
import ssl
import threading
import types
from collections.abc import Callable
from typing import Any

#: The module name the SDK looks up in ``sys.modules``.
TRUSTSTORE_MODULE = "truststore"


class _VerifyingSocket(ssl.SSLSocket):
    """truststore's TruststoreSSLSocket: verification inside do_handshake."""

    def do_handshake(self, block: bool = False) -> None:
        super().do_handshake(block)


class _VerifyingObject(ssl.SSLObject):
    """truststore's TruststoreSSLObject: verification inside do_handshake."""

    def do_handshake(self) -> None:
        super().do_handshake()


def fake_truststore(
    version: str,
    lock_factory: Callable[[], Any] | None,
    *,
    verifying_classes: bool = True,
) -> types.ModuleType:
    """A ``truststore`` module whose ``SSLContext`` has the given shape."""

    class SSLContext(ssl.SSLContext):
        def __init__(self, protocol: int = ssl.PROTOCOL_TLS_CLIENT) -> None:
            inner = ssl.SSLContext(protocol)
            if verifying_classes:
                inner.sslsocket_class = _VerifyingSocket
                inner.sslobject_class = _VerifyingObject
            self._ctx = inner
            if lock_factory is not None:
                self._ctx_lock = lock_factory()

        def _lock(self) -> Any:
            return self.__dict__.get("_ctx_lock") or contextlib.nullcontext()

        def load_verify_locations(self, *args: Any, **kwargs: Any) -> None:
            self._ctx.load_verify_locations(*args, **kwargs)

        def load_cert_chain(self, *args: Any, **kwargs: Any) -> None:
            self._ctx.load_cert_chain(*args, **kwargs)

        def set_alpn_protocols(self, protocols: Any) -> None:
            self._ctx.set_alpn_protocols(protocols)

        def wrap_socket(self, sock: Any, *args: Any, **kwargs: Any) -> Any:
            with self._lock():
                return self._ctx.wrap_socket(sock, *args, **kwargs)

        def wrap_bio(self, *args: Any, **kwargs: Any) -> Any:
            with self._lock():
                return self._ctx.wrap_bio(*args, **kwargs)

    module = types.ModuleType(TRUSTSTORE_MODULE)
    module.__version__ = version  # type: ignore[attr-defined]
    module.SSLContext = SSLContext  # type: ignore[attr-defined]
    return module


#: (version, lock factory) of each released shape.
SHAPE_CURRENT = ("0.10.5", threading.RLock)
SHAPE_PLAIN_LOCK = ("0.10.4", threading.Lock)
SHAPE_NO_LOCK = ("0.10.3", None)
