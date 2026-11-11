# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The SDK-owned TLS context (#6249 #6267 #6306, spec #3840 / #8195).

Invariant: the SDK never performs an HTTPS handshake with certificate
verification or hostname checking off, for any ``verify=`` input, for the
whole client lifetime, on the sync and the async client.

How it holds:

* :func:`build_owned_context` turns every accepted ``verify=`` form into a
  NEW context the SDK builds itself. CA material is copied out of the
  caller's input; the caller's object never reaches httpx, so mutating it
  after construction (#6249) or concurrently (#6306) cannot reach the
  handshake.
* Weakened inputs (``False``, ``CERT_NONE`` / ``CERT_OPTIONAL``,
  ``check_hostname`` off, CRL flags that cannot be copied) and every form
  the SDK cannot classify are refused with :class:`ValueError`. State is
  read through the C-level ``_ssl._SSLContext`` descriptors, so a subclass
  whose Python properties lie is judged by what OpenSSL will do; a
  ``truststore.SSLContext`` is judged by its inner context, under its own
  lock (#6267).
* The owned context is frozen once built: attribute writes, deletes and
  the trust / identity mutators raise :class:`AttributeError`.
* ``wrap_socket`` / ``wrap_bio`` re-check the exact context at use time and
  raise :class:`InsecureHandshakeRefused` (an :class:`ssl.SSLError`, so
  httpx reports a ``ConnectError``) before any handshake on a context whose
  verification is off. The SSL object is created with handshake deferred
  and the context is checked again after creation, so the state the SSL
  object inherited is the state that was checked. For truststore the check
  and the creation run under the context's own lock.
"""

from __future__ import annotations

import os
import ssl
import stat
import sys
import threading
from typing import Any, Final

#: The C base of ``ssl.SSLContext``. Its descriptors read and write the real
#: OpenSSL state, whatever a subclass's Python properties claim.
_C_BASE: Final[Any] = ssl.SSLContext.__base__

#: Largest CA bundle the SDK reads (a full public-root bundle is ~300 KiB).
MAX_CA_BUNDLE_BYTES: Final = 16 * 1024 * 1024

#: CRL checking cannot be copied (the CRLs are not readable back out of a
#: context), so a caller context that asks for it is refused, never silently
#: downgraded.
_CRL_FLAGS: Final = ssl.VerifyFlags.VERIFY_CRL_CHECK_LEAF | ssl.VerifyFlags.VERIFY_CRL_CHECK_CHAIN

MSG_FALSE: Final = (
    "verify=False is refused: the ai-memory SDK never turns off TLS certificate "
    "verification; pass None, True, a CA bundle path or a verifying ssl.SSLContext"
)
MSG_MODE: Final = (
    "verify=<{kind}> is refused: its verify_mode is {mode}, not CERT_REQUIRED; the "
    "ai-memory SDK never turns off TLS certificate verification"
)
MSG_HOST: Final = (
    "verify=<{kind}> is refused: its check_hostname is off; the ai-memory SDK never "
    "turns off TLS hostname checking"
)
MSG_CRL: Final = (
    "verify=<{kind}> is refused: it asks for CRL checking, which the SDK cannot copy; "
    "pass the CA bundle path as verify= instead"
)
MSG_NO_CA: Final = (
    "verify=<{kind}> is refused: it holds no CA certificate the SDK can copy (a "
    "capath directory is loaded lazily and cannot be copied); pass the CA bundle path "
    "as verify= instead"
)
MSG_UNCLASSIFIABLE: Final = (
    "verify=<{kind}> is refused: pass None, True, a CA bundle path (str or "
    "os.PathLike[str]) or an ssl.SSLContext with CERT_REQUIRED and check_hostname"
)
MSG_NOT_FILE: Final = "{label} is refused: the CA path is not a regular file or a directory"
MSG_UNREADABLE: Final = "{label} is refused: the CA path cannot be read ({reason})"
MSG_TOO_BIG: Final = "{label} is refused: the CA bundle is larger than {limit} bytes"
MSG_BAD_BUNDLE: Final = "{label} is refused: the CA bundle could not be loaded ({reason})"
MSG_BAD_CERT: Final = "cert= is refused: the client certificate could not be loaded ({reason})"
MSG_FROZEN: Final = (
    "the ai-memory SDK TLS context is frozen; {name} cannot be changed after construction"
)
MSG_USE_TIME: Final = (
    "ai-memory SDK refused the TLS handshake: certificate verification or hostname "
    "checking is off on the handshake context"
)

#: Methods that change trust, identity or negotiation; refused once frozen.
#: ``set_alpn_protocols`` stays open: httpcore sets ALPN on every connect.
_FROZEN_METHODS: Final = (
    "load_verify_locations",
    "load_cert_chain",
    "load_default_certs",
    "set_default_verify_paths",
    "set_ciphers",
    "set_servername_callback",
    "set_psk_client_callback",
    "set_psk_server_callback",
    "load_dh_params",
    "set_ecdh_curve",
    "set_npn_protocols",
)


class InsecureHandshakeRefused(ssl.SSLError):
    """Raised at use time when the handshake context is not verifying."""


def _mode_of(ctx: Any) -> ssl.VerifyMode:
    return ssl.VerifyMode(_C_BASE.verify_mode.__get__(ctx))


def _hostname_of(ctx: Any) -> bool:
    return bool(_C_BASE.check_hostname.__get__(ctx))


def _verifying(ctx: Any) -> bool:
    return _mode_of(ctx) == ssl.CERT_REQUIRED and _hostname_of(ctx)


class OwnedTLSContext:
    """Mixin for the SDK-owned contexts: frozen after build, checked at use."""

    def _sdk_freeze(self) -> None:
        super().__setattr__("_sdk_frozen", True)

    def _sdk_is_frozen(self) -> bool:
        return bool(self.__dict__.get("_sdk_frozen", False))

    def __setattr__(self, name: str, value: Any) -> None:
        if self._sdk_is_frozen():
            raise AttributeError(MSG_FROZEN.format(name=name))
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if self._sdk_is_frozen():
            raise AttributeError(MSG_FROZEN.format(name=name))
        super().__delattr__(name)

    # The verifying state the handshake will inherit; overridden for truststore.
    def _sdk_handshake_ctx(self) -> Any:
        return self

    def _sdk_lock(self) -> Any:
        return _NO_LOCK

    def _sdk_require_verifying(self) -> None:
        if not _verifying(self._sdk_handshake_ctx()):
            raise InsecureHandshakeRefused(MSG_USE_TIME)

    def wrap_socket(self, sock: Any, *args: Any, **kwargs: Any) -> Any:
        connect_handshake = _pop_handshake_flag(args, kwargs)
        with self._sdk_lock():
            self._sdk_require_verifying()
            tls = super().wrap_socket(sock, *args, **kwargs)  # type: ignore[misc]
            try:
                self._sdk_require_verifying()
                if connect_handshake and _is_connected(tls):
                    tls.do_handshake()
            except BaseException:
                tls.close()
                raise
        return tls

    def wrap_bio(self, *args: Any, **kwargs: Any) -> Any:
        with self._sdk_lock():
            self._sdk_require_verifying()
            obj = super().wrap_bio(*args, **kwargs)  # type: ignore[misc]
            self._sdk_require_verifying()
        return obj


def _frozen_method(name: str) -> Any:
    def method(self: OwnedTLSContext, *args: Any, **kwargs: Any) -> Any:
        if self._sdk_is_frozen():
            raise AttributeError(MSG_FROZEN.format(name=name))
        return getattr(super(OwnedTLSContext, self), name)(*args, **kwargs)

    method.__name__ = name
    return method


for _name in _FROZEN_METHODS:
    setattr(OwnedTLSContext, _name, _frozen_method(_name))


class _NoLock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


_NO_LOCK: Final = _NoLock()


def _pop_handshake_flag(args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
    """Force ``do_handshake_on_connect=False``; return what the caller wanted."""
    if len(args) >= 2:
        # Positional (server_side, do_handshake_on_connect, ...) is not used by
        # httpx / httpcore; refuse it rather than guess.
        raise TypeError("wrap_socket: pass do_handshake_on_connect by keyword")
    wanted = bool(kwargs.pop("do_handshake_on_connect", True))
    kwargs["do_handshake_on_connect"] = False
    return wanted


def _is_connected(tls: Any) -> bool:
    try:
        tls.getpeername()
    except OSError:
        return False
    return True


class _OwnedStdlibContext(OwnedTLSContext, ssl.SSLContext):
    """The SDK's own stdlib context."""


_TRUSTSTORE_OWNED: dict[type, type] = {}
_TRUSTSTORE_LOCK = threading.Lock()


def _truststore_type() -> type | None:
    module = sys.modules.get("truststore")
    return getattr(module, "SSLContext", None) if module is not None else None


def _owned_truststore_class(base: type) -> type:
    with _TRUSTSTORE_LOCK:
        owned = _TRUSTSTORE_OWNED.get(base)
        if owned is None:

            def handshake_ctx(self: Any) -> Any:
                return self.__dict__["_ctx"]

            def lock(self: Any) -> Any:
                return self.__dict__["_ctx_lock"]

            owned = type(
                "_OwnedTruststoreContext",
                (OwnedTLSContext, base),
                {"_sdk_handshake_ctx": handshake_ctx, "_sdk_lock": lock},
            )
            _TRUSTSTORE_OWNED[base] = owned
        return owned


_TEMPLATE: list[ssl.SSLContext] = []


def _template() -> ssl.SSLContext:
    """``create_default_context()``'s flags for this Python (built once)."""
    if not _TEMPLATE:
        _TEMPLATE.append(ssl.create_default_context())
    return _TEMPLATE[0]


def _new_stdlib_owned(minimum: ssl.TLSVersion | None) -> _OwnedStdlibContext:
    tmpl = _template()
    owned = _OwnedStdlibContext(ssl.PROTOCOL_TLS_CLIENT)
    owned.verify_flags = tmpl.verify_flags
    owned.options = tmpl.options
    owned.minimum_version = _max_version(tmpl.minimum_version, minimum)
    return owned


def _max_version(a: ssl.TLSVersion, b: ssl.TLSVersion | None) -> ssl.TLSVersion:
    if b is None or b in (ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.MAXIMUM_SUPPORTED):
        return a
    if a in (ssl.TLSVersion.MINIMUM_SUPPORTED,):
        return b
    return max(a, b)


def _kind(value: object) -> str:
    return type(value).__name__


def _read_bundle(label: str, path: str) -> str:
    """Read a regular file as PEM text, without blocking on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise ValueError(MSG_UNREADABLE.format(label=label, reason=exc.strerror)) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(MSG_NOT_FILE.format(label=label))
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_CA_BUNDLE_BYTES:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_CA_BUNDLE_BYTES:
            raise ValueError(MSG_TOO_BIG.format(label=label, limit=MAX_CA_BUNDLE_BYTES))
    except OSError as exc:
        raise ValueError(MSG_UNREADABLE.format(label=label, reason=exc.strerror)) from None
    finally:
        os.close(fd)
    # PEM is ASCII; comment bytes outside it carry no certificate.
    return b"".join(chunks).decode("ascii", errors="ignore")


def _load_path(owned: Any, label: str, raw: str) -> None:
    path = os.path.abspath(raw)
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise ValueError(MSG_UNREADABLE.format(label=label, reason=exc.strerror)) from None
    try:
        if stat.S_ISDIR(mode):
            owned.load_verify_locations(capath=path)
            return
        if not stat.S_ISREG(mode):
            raise ValueError(MSG_NOT_FILE.format(label=label))
        owned.load_verify_locations(cadata=_read_bundle(label, path))
    except ssl.SSLError as exc:
        raise ValueError(MSG_BAD_BUNDLE.format(label=label, reason=exc.reason or exc)) from None


def _load_default_trust(owned: Any) -> None:
    """httpx's default trust: SSL_CERT_FILE, then SSL_CERT_DIR, then certifi."""
    cert_file = os.environ.get("SSL_CERT_FILE")
    if cert_file:
        _load_path(owned, f"SSL_CERT_FILE={cert_file!r}", cert_file)
        return
    cert_dir = os.environ.get("SSL_CERT_DIR")
    if cert_dir:
        _load_path(owned, f"SSL_CERT_DIR={cert_dir!r}", cert_dir)
        return
    import certifi  # httpx's own dependency

    where = certifi.where()
    _load_path(owned, f"certifi bundle {where!r}", where)


def _snapshot(ctx: Any, kind: str, *, allow_empty_ca: bool) -> tuple[bytes, ssl.TLSVersion]:
    """Judge a caller context by its real OpenSSL state; return its CA DER."""
    mode = _mode_of(ctx)
    if mode != ssl.CERT_REQUIRED:
        raise ValueError(MSG_MODE.format(kind=kind, mode=mode.name))
    if not _hostname_of(ctx):
        raise ValueError(MSG_HOST.format(kind=kind))
    if ssl.VerifyFlags(_C_BASE.verify_flags.__get__(ctx)) & _CRL_FLAGS:
        raise ValueError(MSG_CRL.format(kind=kind))
    certs = _C_BASE.get_ca_certs(ctx, True)
    if not certs and not allow_empty_ca:
        raise ValueError(MSG_NO_CA.format(kind=kind))
    minimum = ssl.TLSVersion(_C_BASE.minimum_version.__get__(ctx))
    return b"".join(certs), minimum


def _from_stdlib_context(ctx: ssl.SSLContext) -> OwnedTLSContext:
    cadata, minimum = _snapshot(ctx, _kind(ctx), allow_empty_ca=False)
    owned = _new_stdlib_owned(minimum)
    owned.load_verify_locations(cadata=cadata)
    return owned


def _from_truststore_context(ctx: Any, base: type) -> OwnedTLSContext:
    inner = ctx.__dict__.get("_ctx")
    lock = ctx.__dict__.get("_ctx_lock")
    if not isinstance(inner, ssl.SSLContext) or lock is None:
        raise ValueError(MSG_UNCLASSIFIABLE.format(kind=_kind(ctx)))
    with lock:
        # truststore verifies against the platform store as well, so an
        # empty copied CA set still verifies.
        cadata, minimum = _snapshot(inner, _kind(ctx), allow_empty_ca=True)
    owned: Any = _owned_truststore_class(base)(ssl.PROTOCOL_TLS_CLIENT)
    inner_owned = owned.__dict__["_ctx"]
    _C_BASE.minimum_version.__set__(
        inner_owned,
        _max_version(_template().minimum_version, minimum),
    )
    if cadata:
        owned.load_verify_locations(cadata=cadata)
    return owned  # type: ignore[no-any-return]


def _path_of(verify: object) -> str | None:
    if isinstance(verify, str):
        return verify or None
    if isinstance(verify, os.PathLike):
        try:
            raw = os.fspath(verify)
        except TypeError:
            return None
        return raw if isinstance(raw, str) and raw else None
    return None


def _classify(verify: object) -> OwnedTLSContext:
    if verify is False:
        raise ValueError(MSG_FALSE)
    if verify is None or verify is True:
        owned = _new_stdlib_owned(None)
        _load_default_trust(owned)
        return owned
    if isinstance(verify, ssl.SSLContext):
        ts = _truststore_type()
        if ts is not None and isinstance(verify, ts):
            return _from_truststore_context(verify, ts)
        return _from_stdlib_context(verify)
    if isinstance(verify, (str, os.PathLike)):
        raw = _path_of(verify)
        if raw is not None:
            owned = _new_stdlib_owned(None)
            _load_path(owned, f"verify={raw!r}", raw)
            return owned
    raise ValueError(MSG_UNCLASSIFIABLE.format(kind=_kind(verify)))


def build_owned_context(verify: object, cert: object = None) -> OwnedTLSContext:
    """The frozen, SDK-owned context for one client; see the module docstring."""
    owned: Any = _classify(verify)
    if cert is not None:
        if isinstance(cert, str):
            files: tuple[Any, ...] = (cert,)
        elif isinstance(cert, tuple) and 1 <= len(cert) <= 3:
            files = cert
        else:
            raise ValueError(
                f"cert=<{_kind(cert)}> is refused: pass a certificate path or "
                "(certificate, key[, password])"
            )
        try:
            owned.load_cert_chain(*files)
        except (OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", None) or exc.strerror or exc
            raise ValueError(MSG_BAD_CERT.format(reason=reason)) from None
    if not _verifying(owned._sdk_handshake_ctx()):
        # Unreachable by construction; fail closed if a future edit breaks it.
        raise ValueError(MSG_USE_TIME)
    owned._sdk_freeze()
    return owned  # type: ignore[no-any-return]
