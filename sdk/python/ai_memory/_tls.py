# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The SDK-owned TLS context (#6249 #6267 #6306, spec #3840 / #8195).

Invariant: the SDK never performs an HTTPS handshake with certificate
verification or hostname checking off, for any ``verify=`` input, for the
whole client lifetime, on the sync and the async client; and the context it
connects with never verifies more weakly than a context the caller passed.

How it holds:

* :func:`build_owned_context` turns every accepted ``verify=`` form into a
  NEW context the SDK builds itself. CA material is copied out of the
  caller's input; the caller's object never reaches httpx, so mutating it
  after construction (#6249) or concurrently (#6306) cannot reach the
  handshake.
* The owned context starts from the SDK floor (``create_default_context()``
  flags, minimum TLS 1.2). Every verification-relevant setting of a caller
  ``ssl.SSLContext`` is one row of :data:`VERIFICATION_SETTINGS`: a row is
  either carried onto the owned context by a never-weaker merge (verify
  flags, options and hostname flags ORed in, the higher minimum and the
  lower maximum version, the higher security level, the intersection of the
  cipher lists) and read back, or the construction is refused with a named
  :class:`ValueError` (verification or hostname checking off, CRL checking,
  flag bits the SDK cannot classify, an empty version range, a cipher list
  or servername callback it cannot carry). A setting whose getter is missing
  or raises is refused, never skipped.
* State is read through the C-level ``_ssl._SSLContext`` descriptors, so a
  subclass whose Python properties lie is judged by what OpenSSL will do; a
  ``truststore.SSLContext`` is judged by its inner context, under its own
  lock (#6267). An attribute of the running Python that is in neither
  :data:`VERIFICATION_SETTINGS` nor :data:`NOT_VERIFICATION_RELEVANT` and
  differs from a fresh default context is refused by name.
* Residual settings with no getter, which the SDK can neither read nor
  carry: the ECDH curve (``set_ecdh_curve``) and the ALPN / NPN protocol
  lists (httpcore sets ALPN itself on every connect). Neither changes how
  the server certificate is verified. Never carried, each named with its
  reason in :data:`NOT_VERIFICATION_RELEVANT`: ``keylog_filename``,
  ``post_handshake_auth``, ``num_tickets``, the PSK callbacks and the
  client identity (``cert=``).
* The owned context is frozen once built: attribute writes, deletes and
  the trust / identity mutators raise :class:`AttributeError`.
* ``wrap_socket`` / ``wrap_bio`` re-check the exact context at use time and
  raise :class:`InsecureHandshakeRefused` (an :class:`ssl.SSLError`, so
  httpx reports a ``ConnectError``) before any handshake on a context whose
  verification is off. The SSL object is created with handshake deferred
  and the context is checked again after creation. On the stdlib path the
  SSL object inherits the checked OpenSSL state. On the truststore path the
  check and the creation run under truststore's own ``_ctx_lock``; on
  macOS and Windows truststore turns OpenSSL verification off on its inner
  context while it creates the SSL object and verifies the chain against
  the platform store inside its own ``do_handshake``, under the same lock.
  The SDK therefore requires that truststore shape (a re-entrant
  ``_ctx_lock`` and the verifying socket and SSL-object classes, truststore
  >= 0.10.5) and refuses any other shape at construction by name.
"""

from __future__ import annotations

import inspect
import os
import ssl
import stat
import sys
import threading
import types
from collections.abc import Mapping
from typing import Any, Final, NamedTuple

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
MSG_UNREADABLE_SETTING: Final = (
    "verify=<{kind}> is refused: its {setting} cannot be read from the OpenSSL context "
    "({error}); the ai-memory SDK refuses a verification setting it cannot check"
)
MSG_FLAG_UNKNOWN: Final = (
    "verify=<{kind}> is refused: its {setting} sets bits {bits:#x}, which the ai-memory "
    "SDK cannot classify; clear them or pass the CA bundle path as verify= instead"
)
MSG_VERSION_RANGE: Final = (
    "verify=<{kind}> is refused: its TLS version range is empty once the ai-memory SDK "
    "floor applies (minimum {minimum}, maximum {maximum})"
)
MSG_CIPHERS: Final = (
    "verify=<{kind}> is refused: its cipher list cannot be carried onto the ai-memory "
    "SDK context ({detail})"
)
MSG_NOT_DEFAULT: Final = (
    "verify=<{kind}> is refused: its {setting} is not the default and the ai-memory "
    "SDK cannot carry it"
)
MSG_UNKNOWN_SETTING: Final = (
    "verify=<{kind}> is refused: its {setting} differs from a default context and the "
    "ai-memory SDK does not classify it; see VERIFICATION_SETTINGS in ai_memory._tls"
)
MSG_NOT_CARRIED: Final = (
    "verify=<{kind}> is refused: its {setting} could not be carried onto the ai-memory SDK context"
)
MSG_TRUSTSTORE_SHAPE: Final = (
    "verify=<{kind}> is refused: truststore {version} does not provide {missing}; the "
    "ai-memory SDK supports truststore >= {floor}"
)
MSG_CERT_FORM: Final = (
    "cert=<{kind}> is refused: pass a certificate path or (certificate, key[, password])"
)
MSG_CERT_ELEMENT: Final = "cert=<tuple> is refused: its {position} is <{kind}>, not {expected}"

#: Cipher-list refusal details (the ``{detail}`` of :data:`MSG_CIPHERS`).
CIPHERS_NONE_SHARED: Final = "none of its TLS 1.2 ciphers is in the SDK cipher list"
CIPHERS_NOT_SUBSET: Final = "the SDK context would offer a cipher the caller context does not"
CIPHERS_REJECTED: Final = "OpenSSL rejected the merged cipher list"
#: ``get_ciphers()`` protocol of a TLS 1.3 suite (fixed by OpenSSL, not by
#: ``set_ciphers``).
TLS13_PROTOCOL: Final = "TLSv1.3"

#: ``cert=`` tuple positions: (name, what it must be) for MSG_CERT_ELEMENT.
CERT_EXPECT_PATH: Final = "a path (str or os.PathLike[str])"
CERT_EXPECT_KEY: Final = "a path (str or os.PathLike[str]) or None"
CERT_EXPECT_PASSWORD: Final = "a password (str, bytes, bytearray, a callable or None)"
_CERT_POSITIONS: Final = (
    ("certificate", CERT_EXPECT_PATH),
    ("key", CERT_EXPECT_KEY),
    ("password", CERT_EXPECT_PASSWORD),
)
_PASSWORD_TYPES: Final = (str, bytes, bytearray)

#: The SDK floor: no caller value lowers it (merge is never weaker, X-2).
SDK_MINIMUM_TLS_VERSION: Final = ssl.TLSVersion.TLSv1_2
#: The oldest truststore whose shape the owned context relies on.
TRUSTSTORE_MIN_VERSION: Final = "0.10.5"
#: truststore shape gaps (the ``{missing}`` of :data:`MSG_TRUSTSTORE_SHAPE`).
TRUSTSTORE_NO_INNER: Final = "an inner ssl.SSLContext (_ctx)"
TRUSTSTORE_NO_LOCK: Final = "a context lock (_ctx_lock)"
TRUSTSTORE_LOCK_NOT_REENTRANT: Final = "a re-entrant context lock (_ctx_lock is not an RLock)"
TRUSTSTORE_NO_SOCKET_CLASS: Final = "a verifying sslsocket_class (its own do_handshake)"
TRUSTSTORE_NO_OBJECT_CLASS: Final = "a verifying sslobject_class (its own do_handshake)"
#: Lock types that a thread may acquire again while it holds them.
_REENTRANT_LOCKS: Final = tuple(
    t for t in (type(threading.RLock()), getattr(threading, "_PyRLock", None)) if t is not None
)


class FlagRule(NamedTuple):
    """How one integer flag setting merges: never weaker than the caller."""

    #: Stricter bits ORed onto the owned context.
    carry: int
    #: Looser bits never carried; the owned context keeps the SDK value.
    drop: int
    #: Bits refused with the row's own message.
    refuse: int


def _bits(*names: str, module: Any = ssl) -> int:
    value = 0
    for name in names:
        value |= int(getattr(module, name, 0))
    return value


#: OpenSSL X509_CHECK_FLAG_* host-check bits (``_host_flags``; ssl names none).
HOSTFLAG_ALWAYS_CHECK_SUBJECT: Final = 0x1
HOSTFLAG_NO_WILDCARDS: Final = 0x2
HOSTFLAG_NO_PARTIAL_WILDCARDS: Final = 0x4
HOSTFLAG_MULTI_LABEL_WILDCARDS: Final = 0x8
HOSTFLAG_SINGLE_LABEL_SUBDOMAINS: Final = 0x10
HOSTFLAG_NEVER_CHECK_SUBJECT: Final = 0x20

#: The flag rows of :data:`VERIFICATION_SETTINGS`.
FLAG_RULES: Final[Mapping[str, FlagRule]] = types.MappingProxyType(
    {
        "verify_flags": FlagRule(
            carry=_bits("VERIFY_X509_STRICT", "VERIFY_X509_TRUSTED_FIRST"),
            drop=_bits("VERIFY_ALLOW_PROXY_CERTS", "VERIFY_X509_PARTIAL_CHAIN"),
            refuse=int(_CRL_FLAGS),
        ),
        "options": FlagRule(
            carry=_bits(
                "OP_NO_SSLv2",
                "OP_NO_SSLv3",
                "OP_NO_TLSv1",
                "OP_NO_TLSv1_1",
                "OP_NO_TLSv1_2",
                "OP_NO_TLSv1_3",
                "OP_NO_COMPRESSION",
                "OP_NO_RENEGOTIATION",
                "OP_NO_TICKET",
            ),
            # Interoperability and server-side switches; none weakens how the
            # server certificate is checked, and none is carried.
            drop=_bits(
                "OP_ALL",
                "OP_LEGACY_SERVER_CONNECT",
                "OP_IGNORE_UNEXPECTED_EOF",
                "OP_ENABLE_MIDDLEBOX_COMPAT",
                "OP_CIPHER_SERVER_PREFERENCE",
                "OP_SINGLE_DH_USE",
                "OP_SINGLE_ECDH_USE",
                "OP_ENABLE_KTLS",
            ),
            refuse=0,
        ),
        "_host_flags": FlagRule(
            carry=HOSTFLAG_NO_WILDCARDS
            | HOSTFLAG_NO_PARTIAL_WILDCARDS
            | HOSTFLAG_NEVER_CHECK_SUBJECT,
            drop=HOSTFLAG_ALWAYS_CHECK_SUBJECT
            | HOSTFLAG_MULTI_LABEL_WILDCARDS
            | HOSTFLAG_SINGLE_LABEL_SUBDOMAINS,
            refuse=0,
        ),
    }
)


class Setting(NamedTuple):
    """One row of :data:`VERIFICATION_SETTINGS`."""

    #: Attribute (or pseudo-attribute) name on the OpenSSL context.
    name: str
    #: Merge rule, one key of ``_RULES``.
    rule: str
    #: The row's refusal message.
    message: str
    #: Mutator methods whose effect this row reads.
    mutators: tuple[str, ...] = ()


#: THE table of verification-relevant SSLContext state (X-1). Every row is
#: read through the C-base descriptors and either carried (never weaker) or
#: refused by its message. A new attribute of a future Python lands here or in
#: NOT_VERIFICATION_RELEVANT; the tripwire test fails until it does.
VERIFICATION_SETTINGS: Final[tuple[Setting, ...]] = (
    Setting("verify_mode", "require", MSG_MODE),
    Setting("check_hostname", "require", MSG_HOST),
    Setting("verify_flags", "flags", MSG_CRL),
    Setting("options", "flags", MSG_FLAG_UNKNOWN),
    Setting("_host_flags", "flags", MSG_FLAG_UNKNOWN),
    # A Python property over _host_flags (NEVER_CHECK_SUBJECT); carried there.
    Setting("hostname_checks_common_name", "derived", MSG_FLAG_UNKNOWN),
    Setting("minimum_version", "minimum", MSG_VERSION_RANGE),
    Setting("maximum_version", "maximum", MSG_VERSION_RANGE),
    Setting("security_level", "level", MSG_CIPHERS),
    Setting("ciphers", "ciphers", MSG_CIPHERS, ("set_ciphers",)),
    Setting("sni_callback", "default", MSG_NOT_DEFAULT, ("set_servername_callback",)),
    Setting(
        "ca_certs",
        "ca",
        MSG_NO_CA,
        (
            "load_verify_locations",
            "load_default_certs",
            "set_default_verify_paths",
            "_load_windows_store_certs",
        ),
    ),
)

#: SSLContext attributes and mutators that do not change how the server
#: certificate is verified, each with its one-line reason. None is carried.
NOT_VERIFICATION_RELEVANT: Final[Mapping[str, str]] = types.MappingProxyType(
    {
        "protocol": "the owned context is always PROTOCOL_TLS_CLIENT",
        "num_tickets": "session tickets a server issues; a client context never sends any",
        "post_handshake_auth": "offers the client certificate after the handshake; "
        "identity, not server verification",
        "keylog_filename": "writes session secrets to a file; never carried (it only weakens)",
        "_msg_callback": "a debug observer of handshake messages; never carried",
        "load_cert_chain": "the client identity, passed as cert=; not server verification",
        "load_dh_params": "server-side key-exchange parameters",
        "set_ecdh_curve": "the key-exchange curve; no getter, a named residual",
        "set_alpn_protocols": "protocol negotiation; httpcore sets ALPN on every connect",
        "_set_alpn_protocols": "the C half of set_alpn_protocols",
        "set_npn_protocols": "deprecated protocol negotiation; no getter, a named residual",
        "set_psk_client_callback": "a pre-shared key skips certificate verification; never carried",
        "set_psk_server_callback": "server-side pre-shared keys; never carried",
    }
)

#: Prefixes of the mutator methods the tripwire enumerates.
MUTATOR_PREFIXES: Final = ("set_", "load_", "_set_", "_load_")

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
_FRESH: list[ssl.SSLContext] = []


def _template() -> ssl.SSLContext:
    """``create_default_context()``'s flags for this Python (built once)."""
    if not _TEMPLATE:
        _TEMPLATE.append(ssl.create_default_context())
    return _TEMPLATE[0]


def _fresh_default() -> ssl.SSLContext:
    """A context nobody configured: what "default" means for X-4 / X-5."""
    if not _FRESH:
        _FRESH.append(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    return _FRESH[0]


def _unreadable(kind: str, setting: str, exc: BaseException) -> ValueError:
    return ValueError(
        MSG_UNREADABLE_SETTING.format(kind=kind, setting=setting, error=type(exc).__name__)
    )


def _read(ctx: Any, name: str, kind: str) -> Any:
    """Read one setting through the C-base descriptor; refuse if it cannot."""
    try:
        return getattr(_C_BASE, name).__get__(ctx)
    except Exception as exc:  # noqa: BLE001 - a missing or raising getter is a refusal (X-3)
        raise _unreadable(kind, name, exc) from None


def _call(ctx: Any, name: str, kind: str, *args: Any) -> Any:
    """Call one C-base reader method; refuse if it is missing or raises."""
    try:
        return getattr(_C_BASE, name)(ctx, *args)
    except Exception as exc:  # noqa: BLE001 - any failure here is a refusal (fail closed)
        raise _unreadable(kind, name, exc) from None


def _write(target: Any, name: str, value: Any, kind: str) -> None:
    """Write one setting through the C-base descriptor and read it back."""
    try:
        getattr(_C_BASE, name).__set__(target, value)
    except Exception:  # noqa: BLE001 - any failure here is a refusal (fail closed)
        raise ValueError(MSG_NOT_CARRIED.format(kind=kind, setting=name)) from None
    if _read(target, name, kind) != value:
        raise ValueError(MSG_NOT_CARRIED.format(kind=kind, setting=name))


def _apply_floor(target: Any) -> None:
    """The SDK floor on a context the SDK created: template flags, TLS 1.2."""
    tmpl = _template()
    kind = "SDK template"
    _write(target, "verify_flags", _read(tmpl, "verify_flags", kind), kind)
    _write(target, "options", _read(tmpl, "options", kind), kind)
    floor = _higher_minimum(_read(tmpl, "minimum_version", kind), SDK_MINIMUM_TLS_VERSION)
    _write(target, "minimum_version", floor, kind)


def _new_stdlib_owned() -> _OwnedStdlibContext:
    owned = _OwnedStdlibContext(ssl.PROTOCOL_TLS_CLIENT)
    _apply_floor(owned)
    return owned


#: Rank of the open ends of a TLS version range (a TLSVersion is its wire
#: number, 0x0300 .. 0x0304; the sentinels are negative).
_RANK_BOTTOM: Final = 0
_RANK_TOP: Final = 1 << 16


def _rank(version: Any) -> int:
    value = ssl.TLSVersion(version)
    if value is ssl.TLSVersion.MINIMUM_SUPPORTED:
        return _RANK_BOTTOM
    if value is ssl.TLSVersion.MAXIMUM_SUPPORTED:
        return _RANK_TOP
    return int(value)


def _higher_minimum(*versions: Any) -> ssl.TLSVersion:
    return ssl.TLSVersion(max(versions, key=_rank))


def _lower_maximum(*versions: Any) -> ssl.TLSVersion:
    return ssl.TLSVersion(min(versions, key=_rank))


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


class _Carry:
    """One construction: caller context -> owned (target) context."""

    def __init__(self, source: Any, target: Any, kind: str, *, allow_empty_ca: bool) -> None:
        self.source = source
        self.target = target
        self.kind = kind
        self.allow_empty_ca = allow_empty_ca
        self.cadata = b""

    def refuse(self, row: Setting, **fields: Any) -> ValueError:
        return ValueError(row.message.format(kind=self.kind, setting=row.name, **fields))

    def require(self, row: Setting) -> None:
        value = _read(self.source, row.name, self.kind)
        if row.name == "verify_mode":
            mode = ssl.VerifyMode(value)
            if mode != ssl.CERT_REQUIRED:
                raise self.refuse(row, mode=mode.name)
        elif not value:
            raise self.refuse(row)

    def flags(self, row: Setting) -> None:
        rule = FLAG_RULES[row.name]
        caller = int(_read(self.source, row.name, self.kind))
        owned = int(_read(self.target, row.name, self.kind))
        extra = caller & ~owned
        if extra & rule.refuse:
            raise self.refuse(row, bits=extra & rule.refuse)
        unknown = extra & ~(rule.carry | rule.drop | rule.refuse)
        if unknown:
            raise ValueError(
                MSG_FLAG_UNKNOWN.format(kind=self.kind, setting=row.name, bits=unknown)
            )
        carried = extra & rule.carry
        if carried:
            _write(
                self.target,
                row.name,
                type(_read(self.target, row.name, self.kind))(owned | carried),
                self.kind,
            )

    def derived(self, row: Setting) -> None:
        # hostname_checks_common_name is ssl.SSLContext's property over the C
        # _host_flags (carried by its own row); read it through ssl.SSLContext
        # so a subclass cannot lie about it, and check it arrived.
        getter = getattr(ssl.SSLContext, row.name, None)
        try:
            caller = bool(getter.__get__(self.source))  # type: ignore[union-attr]
            owned = bool(getter.__get__(self.target))  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - any failure here is a refusal (fail closed)
            raise _unreadable(self.kind, row.name, exc) from None
        if owned and not caller:
            raise ValueError(MSG_NOT_CARRIED.format(kind=self.kind, setting=row.name))

    def minimum(self, row: Setting) -> None:
        caller = _read(self.source, row.name, self.kind)
        owned = _read(self.target, row.name, self.kind)
        merged = _higher_minimum(owned, caller, SDK_MINIMUM_TLS_VERSION)
        if merged != owned:
            _write(self.target, row.name, merged, self.kind)

    def maximum(self, row: Setting) -> None:
        caller = _read(self.source, row.name, self.kind)
        owned = _read(self.target, row.name, self.kind)
        merged = _lower_maximum(owned, caller)
        minimum = ssl.TLSVersion(_read(self.target, "minimum_version", self.kind))
        if _rank(merged) < _rank(minimum):
            raise self.refuse(row, minimum=minimum.name, maximum=merged.name)
        if merged != owned:
            _write(self.target, row.name, merged, self.kind)

    def level(self, row: Setting) -> None:
        # Read both sides now so an unreadable level is refused by name; the
        # level is carried with the cipher list (OpenSSL sets it there).
        _read(self.source, row.name, self.kind)
        _read(self.target, row.name, self.kind)

    def ciphers(self, row: Setting) -> None:
        caller_list = _call(self.source, "get_ciphers", self.kind)
        owned_list = _call(self.target, "get_ciphers", self.kind)
        caller_names = {c["name"] for c in caller_list}
        caller_level = int(_read(self.source, "security_level", self.kind))
        owned_level = int(_read(self.target, "security_level", self.kind))
        level = max(caller_level, owned_level)
        owned12 = [c["name"] for c in owned_list if c.get("protocol") != TLS13_PROTOCOL]
        keep12 = [name for name in owned12 if name in caller_names]
        if keep12 != owned12 or level != owned_level:
            if not keep12:
                raise self.refuse(row, detail=CIPHERS_NONE_SHARED)
            spec = f"@SECLEVEL={level}:" + ":".join(keep12)
            try:
                _C_BASE.set_ciphers(self.target, spec)
            except Exception:  # noqa: BLE001 - any failure here is a refusal (fail closed)
                raise self.refuse(row, detail=CIPHERS_REJECTED) from None
        after = {c["name"] for c in _call(self.target, "get_ciphers", self.kind)}
        if not after <= caller_names:
            raise self.refuse(row, detail=CIPHERS_NOT_SUBSET)
        if int(_read(self.target, "security_level", self.kind)) < caller_level:
            raise ValueError(MSG_NOT_CARRIED.format(kind=self.kind, setting="security_level"))

    def default(self, row: Setting) -> None:
        value = _read(self.source, row.name, self.kind)
        if value != _read(_fresh_default(), row.name, self.kind):
            raise self.refuse(row)

    def ca(self, row: Setting) -> None:
        certs = _call(self.source, "get_ca_certs", self.kind, True)
        if not certs and not self.allow_empty_ca:
            raise self.refuse(row)
        self.cadata = b"".join(certs)

    def backstop(self) -> None:
        """X-5: an unclassified attribute that is not default is refused."""
        known = {row.name for row in VERIFICATION_SETTINGS} | set(NOT_VERIFICATION_RELEVANT)
        fresh = _fresh_default()
        for name, descriptor in _settings_descriptors().items():
            if name in known:
                continue
            try:
                value = descriptor.__get__(self.source)
                default = descriptor.__get__(fresh)
            except Exception as exc:  # noqa: BLE001 - any failure here is a refusal (fail closed)
                raise _unreadable(self.kind, name, exc) from None
            if value != default:
                raise ValueError(MSG_UNKNOWN_SETTING.format(kind=self.kind, setting=name))

    def run(self) -> bytes:
        for row in VERIFICATION_SETTINGS:
            getattr(self, row.rule)(row)
        self.backstop()
        return self.cadata


#: The real classes the tripwire and the backstop enumerate.
_SETTINGS_CLASSES: Final = (ssl.SSLContext.__base__, ssl.SSLContext)


def _settings_descriptors() -> dict[str, Any]:
    found: dict[str, Any] = {}
    for cls in _SETTINGS_CLASSES:
        for name, value in vars(cls).items():
            if not name.startswith("__") and inspect.isdatadescriptor(value):
                found.setdefault(name, value)
    return found


def settings_surface() -> tuple[frozenset[str], frozenset[str]]:
    """Every data descriptor and every set_* / load_* mutator of the running
    Python's ``ssl.SSLContext`` and ``_ssl._SSLContext`` (the X-6 tripwire)."""
    mutators: set[str] = set()
    for cls in _SETTINGS_CLASSES:
        for name, value in vars(cls).items():
            if name.startswith(MUTATOR_PREFIXES) and callable(value):
                mutators.add(name)
    return frozenset(_settings_descriptors()), frozenset(mutators)


def _carry_settings(source: Any, target: Any, kind: str, *, allow_empty_ca: bool) -> bytes:
    """Carry or refuse every row of VERIFICATION_SETTINGS; return the CA DER."""
    return _Carry(source, target, kind, allow_empty_ca=allow_empty_ca).run()


def _from_stdlib_context(ctx: ssl.SSLContext) -> OwnedTLSContext:
    owned = _new_stdlib_owned()
    cadata = _carry_settings(ctx, owned, _kind(ctx), allow_empty_ca=False)
    owned.load_verify_locations(cadata=cadata)
    return owned


def _truststore_version() -> str:
    module = sys.modules.get("truststore")
    return str(getattr(module, "__version__", "unknown"))


def _truststore_shape_gap(ctx: Any) -> str | None:
    """What the 0.10.5+ truststore contract is missing on ``ctx`` (or None)."""
    inner = ctx.__dict__.get("_ctx")
    if not isinstance(inner, ssl.SSLContext):
        return TRUSTSTORE_NO_INNER
    lock = ctx.__dict__.get("_ctx_lock")
    if lock is None:
        return TRUSTSTORE_NO_LOCK
    if not isinstance(lock, _REENTRANT_LOCKS):
        return TRUSTSTORE_LOCK_NOT_REENTRANT
    for attr, parent, gap in (
        ("sslsocket_class", ssl.SSLSocket, TRUSTSTORE_NO_SOCKET_CLASS),
        ("sslobject_class", ssl.SSLObject, TRUSTSTORE_NO_OBJECT_CLASS),
    ):
        cls = inner.__dict__.get(attr)
        if not (
            isinstance(cls, type)
            and issubclass(cls, parent)
            and cls is not parent
            and "do_handshake" in vars(cls)
        ):
            return gap
    return None


def _require_truststore_shape(ctx: Any, kind: str) -> None:
    gap = _truststore_shape_gap(ctx)
    if gap is not None:
        raise ValueError(
            MSG_TRUSTSTORE_SHAPE.format(
                kind=kind,
                version=_truststore_version(),
                missing=gap,
                floor=TRUSTSTORE_MIN_VERSION,
            )
        )


def _from_truststore_context(ctx: Any, base: type) -> OwnedTLSContext:
    kind = _kind(ctx)
    _require_truststore_shape(ctx, kind)
    owned: Any = _owned_truststore_class(base)(ssl.PROTOCOL_TLS_CLIENT)
    _require_truststore_shape(owned, kind)
    inner_owned = owned.__dict__["_ctx"]
    _apply_floor(inner_owned)
    with ctx.__dict__["_ctx_lock"]:
        # truststore verifies against the platform store as well, so an
        # empty copied CA set still verifies.
        cadata = _carry_settings(ctx.__dict__["_ctx"], inner_owned, kind, allow_empty_ca=True)
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
        owned = _new_stdlib_owned()
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
            owned = _new_stdlib_owned()
            _load_path(owned, f"verify={raw!r}", raw)
            return owned
    raise ValueError(MSG_UNCLASSIFIABLE.format(kind=_kind(verify)))


def _cert_files(cert: object) -> tuple[Any, ...]:
    """Validate ``cert=`` by type only; a message never echoes its content."""
    if isinstance(cert, str):
        if not cert:
            raise ValueError(MSG_CERT_FORM.format(kind=_kind(cert)))
        return (cert,)
    if not isinstance(cert, tuple) or not 1 <= len(cert) <= 3:
        raise ValueError(MSG_CERT_FORM.format(kind=_kind(cert)))
    files: list[Any] = []
    for index, element in enumerate(cert):
        position, expected = _CERT_POSITIONS[index]
        if index == 2:
            ok = element is None or callable(element) or isinstance(element, _PASSWORD_TYPES)
            files.append(element)
        elif index == 1 and element is None:
            ok = True
            files.append(None)
        else:
            path = _path_of(element)
            ok = path is not None
            files.append(path)
        if not ok:
            raise ValueError(
                MSG_CERT_ELEMENT.format(position=position, kind=_kind(element), expected=expected)
            )
    return tuple(files)


def build_owned_context(verify: object, cert: object = None) -> OwnedTLSContext:
    """The frozen, SDK-owned context for one client; see the module docstring."""
    owned: Any = _classify(verify)
    if cert is not None:
        files = _cert_files(cert)
        try:
            owned.load_cert_chain(*files)
        except (OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", None) or exc.strerror or exc
            raise ValueError(MSG_BAD_CERT.format(reason=reason)) from None
        except (TypeError, ValueError) as exc:
            # A password callable of the wrong shape; name the type only.
            raise ValueError(MSG_BAD_CERT.format(reason=type(exc).__name__)) from None
    if not _verifying(owned._sdk_handshake_ctx()):
        # Unreachable by construction; fail closed if a future edit breaks it.
        raise ValueError(MSG_USE_TIME)
    owned._sdk_freeze()
    return owned  # type: ignore[no-any-return]
