# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the sync and async clients.

The two clients have near-identical surfaces; everything that does not need
an ``await`` lives here. In particular:

* Auth header injection (``X-API-Key`` and/or ``X-Agent-Id``)
* mTLS ``httpx`` config builder
* Response -> error mapping (delegates to :mod:`ai_memory.errors`)
* JSON body prep that strips ``None`` values (so omitted optional request
  fields don't clobber server defaults)
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import time
from types import TracebackType
from typing import TYPE_CHECKING, Any, Union
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from ai_memory._version import __version__ as _SDK_VERSION
from ai_memory.errors import TransportError, raise_for_status
from ai_memory.models import CreateMemory

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ai_memory.attestation import AgentSigningKey

# v1.0.0 #3782 — ``https`` even on loopback. Since #3705/#3709 every daemon
# listener serves TLS and ``tls_bind_guard`` refuses to bind a plaintext one,
# so an ``http://`` default could never reach a daemon. A zero-config daemon
# serves a certificate from the local CA it writes to
# ``<key_dir>/tls/local-ca.pem`` on first boot; pass that path as ``verify=``.
DEFAULT_BASE_URL = "https://localhost:9077"
DEFAULT_TIMEOUT = 30.0
# v1.0.0 #3288 — rows per export page when the caller names no limit; the
# daemon's default page ceiling (``AI_MEMORY_MAX_PAGE_SIZE``).
DEFAULT_EXPORT_PAGE_ROWS = 1000
# The daemon's typed refusal of an export ``limit`` above its page ceiling.
EXPORT_LIMIT_OUT_OF_RANGE = "EXPORT_LIMIT_OUT_OF_RANGE"


def export_ceiling_from_error(exc: Exception) -> int | None:
    """The page ceiling a daemon named when it refused an export ``limit``
    (HTTP 400 ``EXPORT_LIMIT_OUT_OF_RANGE``), or ``None`` for any other error."""
    payload = getattr(exc, "payload", None)
    if not isinstance(payload, dict) or payload.get("code") != EXPORT_LIMIT_OUT_OF_RANGE:
        return None
    ceiling = payload.get("max")
    return ceiling if isinstance(ceiling, int) and ceiling > 0 else None

#: The daemon's own default `memory_kind` when the field is absent. Kept here
#: because a SIGNED write must sign the kind the server will actually store —
#: leaving `kind` unset while signing a different value silently 403s.
DEFAULT_MEMORY_KIND = "observation"

#: SDK version. Re-exported from :mod:`ai_memory._version`, the ONE literal
#: that `pyproject.toml`, `__init__.__version__`, this User-Agent, and the
#: README all derive from (#2455 — they had drifted to three different
#: answers: 1.0.0 / 0.8.0 / 0.6.0-alpha.0).
SDK_VERSION = _SDK_VERSION


def encode_path_segment(value: str) -> str:
    """Percent-encode one caller-controlled HTTP path segment.

    ``agent_id`` deliberately permits SPIFFE URIs and therefore slashes.
    Interpolating it directly would turn one route parameter into several
    path components. ``safe=''`` is load-bearing because ``quote`` otherwise
    preserves ``/`` by default.
    """
    return quote(value, safe="")


_UNVERIFIED_MESSAGE = (
    "verify=False is refused: it would turn the daemon's TLS listener "
    "into an unauthenticated one (an encrypted pipe to whoever answers). "
    "This covers any falsy or blank verify value and an SSL context that "
    "does not verify certificates or is not provably the stock one. "
    "Accepted verify= forms: None (httpx default trust: certifi, or SSL_CERT_FILE / SSL_CERT_DIR), True, the path of a "
    "CA bundle file or CA directory (str or os.PathLike), or exactly an "
    "ssl.SSLContext (not a subclass, such as truststore.SSLContext) that is "
    "CERT_REQUIRED with check_hostname on, has no verify_flags that relax "
    "chain validation, offers no cipher suite without server authentication "
    "(remove them with set_ciphers('<your list>:!PSK:!SRP:!aNULL:!eNULL')) "
    "and has no patched wrap_socket or "
    "wrap_bio. Build one with ssl.create_default_context(cafile=<CA path>) "
    "or pass verify=<CA path>, e.g. <key_dir>/tls/local-ca.pem for a "
    "zero-config daemon (#3840, #6267, #6268)."
)

#: ``ssl.SSLContext`` attributes that decide what a handshake verifies,
#: captured at import. A context is admitted only while every one of them is
#: still the stock object, so a later class-level patch is caught too (#6268).
_HANDSHAKE_ATTRIBUTES = (
    "wrap_socket",
    "wrap_bio",
    "verify_mode",
    "check_hostname",
    "sslsocket_class",
    "sslobject_class",
    "verify_flags",
    "hostname_checks_common_name",
    "get_ciphers",
)
_STOCK_HANDSHAKE = {name: ssl.SSLContext.__dict__.get(name) for name in _HANDSHAKE_ATTRIBUTES}

#: OpenSSL ``X509_V_FLAG_*`` bits a caller context may carry (#6375): each
#: one leaves chain validation at least as strict as the default. Every other
#: bit is refused, among them USE_CHECK_TIME (0x2), IGNORE_CRITICAL (0x10),
#: ALLOW_PROXY_CERTS (0x40), NO_CHECK_TIME (0x200000) and any bit OpenSSL adds
#: later. PARTIAL_CHAIN is admitted: Python 3.13+ ``create_default_context``
#: sets it, and it only lets a CA the caller loaded as trusted anchor a chain.
_ALLOWED_VERIFY_FLAGS = (
    0x4  # CRL_CHECK (VERIFY_CRL_CHECK_LEAF)
    | 0x8  # CRL_CHECK_ALL (with CRL_CHECK: VERIFY_CRL_CHECK_CHAIN)
    | 0x20  # X509_STRICT
    | 0x80  # POLICY_CHECK
    | 0x100  # EXPLICIT_POLICY
    | 0x200  # INHIBIT_ANY
    | 0x400  # INHIBIT_MAP
    | 0x1000  # EXTENDED_CRL_SUPPORT
    | 0x2000  # USE_DELTAS
    | 0x4000  # CHECK_SS_SIGNATURE
    | 0x8000  # TRUSTED_FIRST
    | 0x30000  # SUITEB_128_LOS_ONLY | SUITEB_192_LOS
    | 0x80000  # PARTIAL_CHAIN
    | 0x100000  # NO_ALT_CHAINS
)


def _context_verifies(context: object) -> bool:
    """Whether ``context`` is the stock ``ssl.SSLContext`` and verifies.

    Admitted only when ALL hold (5-agent vote 4d3ea1c5, form B):

    * ``type(context) is ssl.SSLContext``: a subclass, including
      ``truststore.SSLContext``, keeps its real state on an inner object, so
      the outer object reporting ``CERT_REQUIRED`` proves nothing (#6267);
    * ``verify_mode``/``check_hostname`` read through the base-class
      descriptors are ``CERT_REQUIRED`` and on (#6248);
    * the instance dict shadows no ``ssl.SSLContext`` attribute, so no
      ``context.wrap_socket = ...`` style patch reroutes the handshake (#6268);
    * the handshake-deciding class attributes are still the objects captured
      at import (#6268);
    * ``verify_flags`` (base descriptor) carries only bits in
      :data:`_ALLOWED_VERIFY_FLAGS` (#6375);
    * every cipher suite it offers authenticates the server and encrypts
      (:func:`_suites_authenticate_server`, #6305).
    """
    if type(context) is not ssl.SSLContext:
        return False
    if any(hasattr(ssl.SSLContext, key) for key in vars(context)):
        return False
    if any(ssl.SSLContext.__dict__.get(name) is not stock for name, stock in _STOCK_HANDSHAKE.items()):
        return False
    flags = int(ssl.SSLContext.verify_flags.__get__(context))  # type: ignore[attr-defined]
    if flags & ~_ALLOWED_VERIFY_FLAGS:
        return False
    if not _suites_authenticate_server(context):
        return False
    return bool(
        ssl.SSLContext.verify_mode.__get__(context) == ssl.CERT_REQUIRED  # type: ignore[attr-defined]
        and ssl.SSLContext.check_hostname.__get__(context)  # type: ignore[attr-defined]
    )


#: ``get_ciphers()`` ``auth`` values of suites that authenticate no server
#: certificate: anonymous, pre-shared key and SRP (#6305). TLS 1.3 suites
#: report ``auth-any``; their authentication is the certificate exchange.
_UNAUTHENTICATED_SUITE_AUTH = frozenset({"auth-null", "auth-psk", "auth-srp"})


def _suites_authenticate_server(context: ssl.SSLContext) -> bool:
    """Whether every suite ``context`` offers authenticates the server and encrypts (#6305).

    An entry without an ``auth`` value, with an unauthenticated one, or with
    no ``symmetric`` cipher (eNULL) refuses the whole context, and so does an
    empty list.
    """
    suites = ssl.SSLContext.get_ciphers(context)
    if not suites:
        return False
    for suite in suites:
        if not isinstance(suite, dict):
            return False
        auth = suite.get("auth")
        if not isinstance(auth, str) or auth in _UNAUTHENTICATED_SUITE_AUTH:
            return False
        if not isinstance(suite.get("symmetric"), str):
            return False
    return True


#: OpenSSL ``capath`` entry names: ``<subject hash>.<n>`` for a certificate,
#: ``<subject hash>.r<n>`` for a CRL. Only these are trust input in a hashed
#: CA directory, exactly as OpenSSL's own directory lookup reads it (#6377).
_HASHED_CA_ENTRY = re.compile(r"[0-9a-f]{8}\.r?[0-9]+")

#: Write bits that let someone other than the owner change trust input.
_SHARED_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH


def _shared_writable(mode: int) -> bool:
    """Whether ``mode`` lets the group or others write (POSIX only, #6377)."""
    return os.name != "nt" and bool(mode & _SHARED_WRITE_BITS)


def _refuse_shared_writable(what: str, path: str, mode: int) -> None:
    """Raise when a trust input ``path`` is group- or world-writable (#6377)."""
    if _shared_writable(mode):
        raise ValueError(
            f"verify= {what} {path!r} is group- or world-writable (mode "
            f"{stat.S_IMODE(mode):o}): anyone with that write access could change "
            "which servers this client trusts. Remove the write bits "
            "(chmod go-w) or pass a CA path only its owner can change (#6377)."
        )


#: Path separators a CA path may end with; a trailing one names a directory.
_PATH_SEPARATORS = tuple(sep for sep in (os.sep, os.altsep) if sep)

#: Symlinks followed while resolving one CA path, as Linux's MAXSYMLINKS.
_MAX_SYMLINK_HOPS = 40


def _checked_realpath(path: str) -> str:
    """``os.path.realpath(path)``, refusing a symlink others could re-point (#6559).

    Every component is resolved in order. A symlink met on the way (the path
    itself, a directory component, or a link its target leads through) is
    refused when the directory holding it lets the group or others write and
    is not sticky with the link owned by this user or root: anyone with that
    write access could replace the link and change which CA is read. This is
    the #6377 rule for a CA file's directory, applied to every link. A
    missing component ends the walk with the remainder appended, as
    ``realpath`` does; the caller then refuses the path.
    """
    if os.name == "nt":
        return os.path.realpath(path)
    parts = [part for part in os.path.join(os.getcwd(), path).split(os.sep) if part]
    resolved = os.sep
    hops = 0
    while parts:
        name = parts.pop(0)
        if name == ".":
            continue
        if name == "..":
            resolved = os.path.dirname(resolved)
            continue
        candidate = os.path.join(resolved, name)
        try:
            info = os.lstat(candidate)
        except OSError:
            return os.path.join(candidate, *parts)
        if not stat.S_ISLNK(info.st_mode):
            resolved = candidate
            continue
        hops += 1
        if hops > _MAX_SYMLINK_HOPS:
            raise ValueError(f"verify= CA path {path!r} has too many symlinks (#6559).")
        held = os.stat(resolved).st_mode
        sticky_and_owned = bool(held & stat.S_ISVTX) and info.st_uid in (0, os.geteuid())
        if _shared_writable(held) and not sticky_and_owned:
            raise ValueError(
                f"verify= CA path {path!r} passes through the symlink {candidate!r}, "
                f"whose directory is group- or world-writable (mode {stat.S_IMODE(held):o}): "
                "anyone with that write access could re-point it and change which "
                "servers this client trusts. Pass the real path, or keep the link in "
                "a directory only its owner can change (#6559)."
            )
        try:
            target = os.readlink(candidate)
        except OSError as exc:
            raise ValueError(
                f"verify= CA path {path!r}: symlink {candidate!r} cannot be read: "
                f"{exc.strerror} (#6559)."
            ) from None
        if os.path.isabs(target):
            resolved = os.sep
        parts = [part for part in target.split(os.sep) if part] + parts
    return resolved


def _pinned_base_context() -> ssl.SSLContext:
    """``ssl.create_default_context()`` with NO trust anchors loaded (#6377).

    The same steps the standard library takes for ``Purpose.SERVER_AUTH``
    (``PROTOCOL_TLS_CLIENT``, ``CERT_REQUIRED``, ``check_hostname``, the
    3.13+ strict and partial-chain flags, ``SSLKEYLOGFILE``), minus its
    fallback to the system store: an empty CA directory must mean no anchor
    at all, and ``create_default_context`` loads the system store whenever it
    is given no CA input.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    if sys.version_info >= (3, 13):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
    keylog = os.environ.get("SSLKEYLOGFILE")
    if keylog and not sys.flags.ignore_environment:
        context.keylog_filename = keylog
    return context


def _load_trust_file(context: ssl.SSLContext, shown: str, entry: str) -> None:
    """Load one CA file into ``context`` NOW, after checking who can change it.

    ``entry`` is resolved through symlinks (each held to #6559), opened without blocking (a FIFO
    would otherwise hang), and must be a regular file that neither it nor its
    directory lets the group or others rewrite; a sticky directory is
    admitted when the file belongs to this user or root, since nobody else
    can then replace it. The file is loaded by path and re-checked to be the
    same inode afterwards, so a swap during the load is refused (#6377).
    """
    real = _checked_realpath(entry)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(real, flags)
    except OSError as exc:
        raise ValueError(
            f"verify= CA file {shown!r} cannot be opened: {exc.strerror} (#6377)."
        ) from None
    try:
        opened = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(opened.st_mode):
        raise ValueError(
            f"verify= CA entry {shown!r} is not a regular file; a hashed CA "
            "directory may hold only certificate and CRL files (#6307, #6377)."
        )
    _refuse_shared_writable("CA file", real, opened.st_mode)
    parent = os.path.dirname(real)
    held = os.stat(parent)
    sticky_and_owned = bool(held.st_mode & stat.S_ISVTX) and opened.st_uid in (0, os.geteuid())
    if not sticky_and_owned:
        _refuse_shared_writable("CA file directory", parent, held.st_mode)
    try:
        context.load_verify_locations(cafile=real)
    except (ssl.SSLError, OSError) as exc:
        raise ValueError(
            f"verify= CA file {shown!r} holds no usable certificate: {exc} (#6377)."
        ) from None
    after = os.stat(real)
    if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
        raise ValueError(f"verify= CA file {shown!r} changed while it was being read (#6377).")


def _context_from_path(path: str, *, kind: str | None = None) -> ssl.SSLContext:
    """A verifying context for the CA file or directory ``path`` (#6269, #6377).

    The path is resolved NOW, as ``os.path.realpath`` does, refusing a symlink
    on the way that sits in a directory others can write (#6559). A path that is neither
    an existing regular file nor an existing directory (missing, FIFO, socket,
    device) is a ``ValueError`` rather than a late ``FileNotFoundError`` or a
    hang (#6307).

    Trust is read ONCE, here. For a directory every hashed entry
    (``<hash>.<n>``, ``<hash>.r<n>``) is loaded eagerly, so a certificate
    added to the directory after construction is never trusted (OpenSSL's own
    ``capath`` lookup reads the directory again on every handshake). A
    directory, file, symlink target or target directory that the group or
    others can write is refused (POSIX; #6377). An empty directory gives a
    context with no anchor at all, which fails every handshake (#6269).

    ``kind`` (``"file"`` or ``"directory"``) additionally requires that kind;
    the env trust variables pass it, so ``SSL_CERT_FILE`` and ``verify=`` share
    this one check (#6538, #6690). A path ending in a separator names a
    directory, as it does for the kernel: ``ca.pem/`` is refused (#6690).
    """
    resolved = _checked_realpath(path)
    try:
        mode = os.stat(resolved).st_mode
    except OSError:
        mode = 0
    if path.endswith(_PATH_SEPARATORS) and not stat.S_ISDIR(mode):
        # A trailing separator names a directory: the kernel refuses
        # ``ca.pem/`` (ENOTDIR) even though the walk above drops the empty
        # last part (#6690).
        mode = 0
    wanted = {"file": stat.S_ISREG, "directory": stat.S_ISDIR}.get(kind or "")
    if wanted is not None and not wanted(mode):
        raise ValueError(
            f"CA path {path!r} is not an existing "
            f"{'regular file' if kind == 'file' else kind} (#6538, #6690)."
        )
    if stat.S_ISDIR(mode):
        _refuse_shared_writable("CA directory", path, mode)
        context = _pinned_base_context()
        try:
            names = sorted(os.listdir(resolved))
        except OSError as exc:
            raise ValueError(
                f"verify= CA directory {path!r} cannot be listed: {exc.strerror} (#6377)."
            ) from None
        for name in names:
            if _HASHED_CA_ENTRY.fullmatch(name):
                _load_trust_file(context, os.path.join(path, name), os.path.join(resolved, name))
        return context
    if stat.S_ISREG(mode):
        context = _pinned_base_context()
        _load_trust_file(context, path, resolved)
        return context
    raise ValueError(
        "verify= names a CA path that is not an existing regular file or "
        f"directory: {path!r}. Pass the CA bundle file or hashed CA directory "
        "(#6269, #6307)."
    )


#: httpx's env trust, in its own precedence order: the variable, and whether
#: it must name a directory (else a regular file).
_ENV_TRUST = (("SSL_CERT_FILE", False), ("SSL_CERT_DIR", True))


def _context_from_env() -> ssl.SSLContext | None:
    """The env trust httpx would use for ``verify=None``/``True``, read NOW (#6538).

    httpx takes ``SSL_CERT_FILE`` when it is non-empty, else ``SSL_CERT_DIR``,
    else certifi (``None`` here). The named path is loaded through
    :func:`_context_from_path`, so the #6377 rules hold for it: read once at
    construction, never re-read per handshake, and refused when the group or
    others can change it. A path that is missing or of the wrong kind is
    refused, fail closed, where httpx 0.27 would silently fall back to
    certifi.
    """
    for variable, wants_directory in _ENV_TRUST:
        value = os.environ.get(variable, "")
        if not value:
            continue
        try:
            return _context_from_path(value, kind="directory" if wants_directory else "file")
        except ValueError as exc:
            raise ValueError(
                f"{variable}={value!r}: {exc} httpx would read trust from it; point "
                f"{variable} at a CA {'hashed directory' if wants_directory else 'bundle file'} "
                "or unset it (#6538)."
            ) from None
    return None


def _checked_verify(verify: object) -> bool | ssl.SSLContext | None:
    """Return the ONLY value ``build_httpx_kwargs`` may forward, or raise (#3840).

    Forwarded to httpx: ``None`` (httpx default trust, kwarg omitted) and
    ``True`` when no ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` is set, else the
    context :func:`_context_from_env` builds from that variable (#6538),
    a caller context that passes :func:`_context_verifies` (exactly
    ``ssl.SSLContext``), or a context this SDK builds itself from the resolved
    absolute path of an existing CA file or directory (``str`` or
    ``os.PathLike``). Never the caller's own str/path object: httpx 0.27
    decides on its truthiness and 0.28 mishandles ``os.PathLike`` (#6248,
    #6245). Refused, fail closed: ``False`` and every other falsy or blank
    value, a non-stock or non-verifying context, a CA path that does not
    exist, and any type this SDK does not document.
    """
    if verify is None or verify is True:
        from_env = _context_from_env()
        return verify if from_env is None else from_env
    if isinstance(verify, ssl.SSLContext):
        if _context_verifies(verify):
            return verify
        raise ValueError(_UNVERIFIED_MESSAGE)
    if isinstance(verify, (str, os.PathLike)):
        raw = os.fspath(verify)
        # `str.__str__` yields an exact `str`: no overridden `strip`/`__bool__`.
        path = str.__str__(raw) if isinstance(raw, str) else ""
        if path.strip():
            return _context_from_path(path)
    raise ValueError(_UNVERIFIED_MESSAGE)


_SESSION_MESSAGE = (
    "verify=False equivalent refused: the TLS session negotiated for this "
    "connection is not a verified session of the context passed as verify= "
    "(no validated server certificate, or the handshake ran on another "
    "context). Use ssl.create_default_context(cafile=<CA path>) or "
    "verify=<CA path> (#6305, #6306, #6268)."
)


def _assert_negotiated_session(session: object, context: ssl.SSLContext, host: str) -> None:
    """Raise ``ValueError`` unless ``session`` is a verified session of ``context`` for ``host``.

    ``session`` is the connection's ``ssl_object`` after the handshake. It must
    exist, belong to the caller's own context object (a handshake handed to
    another context is refused) and carry a VALIDATED peer certificate:
    ``getpeercert()`` is empty when the chain was not verified (``CERT_NONE``,
    ``CERT_OPTIONAL`` without a certificate, anonymous suites). The certificate
    must also name ``host``, the host the request is addressed to, whatever
    the context's ``check_hostname`` was at handshake time (#6350), and the
    negotiated suite must carry secret bits (no eNULL, #6305). Unlike the
    pre-handshake predicate this inspects what actually happened on the wire,
    so it also closes the check/use race (#6306) and auth-null suites (#6305).
    """
    if session is None or getattr(session, "context", None) is not context:
        raise ValueError(_SESSION_MESSAGE)
    getpeercert = getattr(session, "getpeercert", None)
    peer = None if getpeercert is None else getpeercert()
    if not isinstance(peer, dict) or not peer:
        raise ValueError(_SESSION_MESSAGE)
    if not _peer_matches_host(peer, host, context):
        raise ValueError(_SESSION_MESSAGE)
    cipher = getattr(session, "cipher", None)
    negotiated = None if cipher is None else cipher()
    if (
        not isinstance(negotiated, tuple)
        or len(negotiated) != 3
        or not isinstance(negotiated[2], int)
        or negotiated[2] <= 0
    ):
        raise ValueError(_SESSION_MESSAGE)


def _ip_or_none(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _dns_name_matches(pattern: object, host: str) -> bool:
    """RFC 6125 name match: a wildcard only as the whole left-most label."""
    if not isinstance(pattern, str):
        return False
    labels = pattern.rstrip(".").lower().split(".")
    if "*" not in pattern:
        return labels == host.split(".")
    if labels[0] != "*" or len(labels) < 3 or any("*" in label for label in labels[1:]):
        return False
    host_labels = host.split(".")
    return len(host_labels) == len(labels) and bool(host_labels[0]) and host_labels[1:] == labels[1:]


def _peer_matches_host(peer: dict[str, Any], host: str, context: ssl.SSLContext) -> bool:
    """Whether the validated peer certificate ``peer`` names ``host`` (#6350).

    ``ssl.match_hostname`` is gone since Python 3.12, so this mirrors what
    OpenSSL's host check does: an IP host matches only an iPAddress SAN; a DNS
    host matches a dNSName SAN; the subject commonName is a fallback only when
    the certificate has no dNSName SAN, the host is not an IP address and the
    context's ``hostname_checks_common_name`` (read through the base
    descriptor) allows it.
    """
    host = host.rstrip(".").lower()
    if not host:
        return False
    sans = peer.get("subjectAltName", ())
    if not isinstance(sans, tuple):
        return False
    entries = [entry for entry in sans if isinstance(entry, tuple) and len(entry) == 2]
    address = _ip_or_none(host)
    if address is not None:
        return any(
            kind == "IP Address" and _ip_or_none(value) == address for kind, value in entries
        )
    dns = [value for kind, value in entries if kind == "DNS"]
    if dns:
        return any(_dns_name_matches(value, host) for value in dns)
    common_name = ssl.SSLContext.__dict__.get("hostname_checks_common_name")
    if not isinstance(common_name, property) or common_name.fget is None:
        return False
    if common_name.fget(context) is not True:
        return False
    subject = peer.get("subject", ())
    if not isinstance(subject, tuple):
        return False
    return any(
        isinstance(attribute, tuple)
        and len(attribute) == 2
        and attribute[0] == "commonName"
        and _ip_or_none(attribute[1]) is None
        and _dns_name_matches(attribute[1], host)
        for rdn in subject
        if isinstance(rdn, tuple)
        for attribute in rdn
    )


def _assert_leaf_current(session: object) -> None:
    """Raise ``ValueError`` unless the peer leaf is inside its validity period now (#6375).

    A belt to the ``verify_flags`` check: a flag that skips the time check can
    be set after the per-request check and before the handshake. Only the leaf
    is visible here. This runs on new sessions only (in the trace), never on a
    pooled connection, whose leaf was current when it was verified.
    """
    getpeercert = getattr(session, "getpeercert", None)
    peer = None if getpeercert is None else getpeercert()
    if not isinstance(peer, dict):
        raise ValueError(_SESSION_MESSAGE)
    not_before, not_after = peer.get("notBefore"), peer.get("notAfter")
    if not isinstance(not_before, str) or not isinstance(not_after, str):
        raise ValueError(_SESSION_MESSAGE)
    try:
        start, end = ssl.cert_time_to_seconds(not_before), ssl.cert_time_to_seconds(not_after)
    except ValueError:
        raise ValueError(_SESSION_MESSAGE) from None
    if not start <= time.time() <= end:
        raise ValueError(_SESSION_MESSAGE)


def _request_host(url: httpx.URL) -> str:
    return url.raw_host.decode("ascii", "replace")


def _with_trace(request: httpx.Request, trace: Any) -> None:
    """Install ``trace`` on ``request``, chaining any trace the caller set."""
    inherited = request.extensions.get("trace")

    if inherited is None:
        request.extensions["trace"] = trace
        return

    if inspect.iscoroutinefunction(trace):

        async def chained_async(event: str, info: dict[str, Any]) -> None:
            await trace(event, info)
            result = inherited(event, info)
            if inspect.isawaitable(result):
                await result

        request.extensions["trace"] = chained_async
        return

    def chained(event: str, info: dict[str, Any]) -> None:
        trace(event, info)
        inherited(event, info)

    request.extensions["trace"] = chained


_TLS_DONE = "start_tls.complete"
_DIRECT_TLS = "connection"
# The events that precede the first byte a request writes on a connection:
# HTTP/1.1 request headers, the HTTP/2 connection preface, HTTP/2 headers.
_FIRST_WRITE_EVENTS = frozenset(
    {
        "http11.send_request_headers.started",
        "http2.send_connection_init.started",
        "http2.send_request_headers.started",
    }
)
_TUNNEL_CONNECT_EVENT = "http11.send_request_headers.started"
# httpcore's tunnel CONNECT carries Host and Accept plus the proxy's own
# headers; anything else (the SDK's X-API-Key / X-Agent-Id, caller extras)
# means the request is not the bare tunnel CONNECT.
_TUNNEL_CONNECT_HEADERS = frozenset({b"host", b"accept", b"proxy-authorization"})


def _session_of(stream: object) -> object:
    extra = getattr(stream, "get_extra_info", None)
    return None if extra is None else extra("ssl_object")


class _SessionGate:
    """Post-handshake session check for ONE request (3-agent vote 6def5ab6).

    httpcore reports every TLS handshake of a request as
    ``<leg>.start_tls.complete``: ``connection`` for the TCP connection (the
    origin when direct, the proxy when the proxy is ``https://``), ``proxy`` for
    the origin session inside an HTTP CONNECT tunnel and ``socks`` for the
    origin session over SOCKS. A session on the caller's context must be a
    verified session on every leg. A session on another context is admitted
    only on the ``connection`` leg, as a PENDING proxy leg: the bare tunnel
    CONNECT may cross it, and a verified tunnelled origin session clears it;
    any other first write while it is pending is refused. The state is per
    request so one request's tunnel never vouches for another's proxy leg.
    """

    def __init__(self, context: ssl.SSLContext, request: httpx.Request) -> None:
        self._context = context
        url = request.url
        self._host = _request_host(url)
        self._tunnel_target = b"%b:%d" % (url.raw_host, url.port or 443)
        self._pending: list[object] = []

    def refused(self, event: str, info: dict[str, Any]) -> list[object] | None:
        """Return the streams to close before refusing, or ``None`` to proceed."""
        leg, _, name = event.partition(".")
        if name == _TLS_DONE:
            stream = info.get("return_value")
            session = _session_of(stream)
            if (
                leg == _DIRECT_TLS
                and session is not None
                and getattr(session, "context", None) is not self._context
            ):
                self._pending.append(stream)
                return None
            try:
                _assert_negotiated_session(session, self._context, self._host)
                _assert_leaf_current(session)
            except ValueError:
                return [*self._pending, stream]
            if leg != _DIRECT_TLS:
                self._pending.clear()
            return None
        if event in _FIRST_WRITE_EVENTS and self._pending:
            if event == _TUNNEL_CONNECT_EVENT and self._is_tunnel_connect(info.get("request")):
                return None
            return list(self._pending)
        return None

    def _is_tunnel_connect(self, request: object) -> bool:
        if getattr(request, "method", None) != b"CONNECT":
            return False
        if getattr(getattr(request, "url", None), "target", None) != self._tunnel_target:
            return False
        headers = getattr(request, "headers", None)
        if not isinstance(headers, list):
            return False
        return all(
            isinstance(name, bytes) and name.lower() in _TUNNEL_CONNECT_HEADERS
            for name, _value in headers
        )


def _close_quietly(stream: object) -> None:
    close = getattr(stream, "close", None)
    if close is None:
        return
    try:
        close()
    except OSError:
        pass  # the refusal below is raised either way


async def _aclose_quietly(stream: object) -> None:
    aclose = getattr(stream, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except OSError:
        pass  # the refusal below is raised either way


def _session_trace(context: ssl.SSLContext, request: httpx.Request) -> Any:
    """The per-request httpcore trace that runs :class:`_SessionGate` (sync)."""
    gate = _SessionGate(context, request)

    def _trace(event: str, info: dict[str, Any]) -> None:
        streams = gate.refused(event, info)
        if streams is None:
            return
        for stream in streams:
            _close_quietly(stream)
        raise ValueError(_SESSION_MESSAGE)

    return _trace


def _async_session_trace(context: ssl.SSLContext, request: httpx.Request) -> Any:
    """The per-request httpcore trace that runs :class:`_SessionGate` (async)."""
    gate = _SessionGate(context, request)

    async def _atrace(event: str, info: dict[str, Any]) -> None:
        streams = gate.refused(event, info)
        if streams is None:
            return
        for stream in streams:
            await _aclose_quietly(stream)
        raise ValueError(_SESSION_MESSAGE)

    return _atrace


class _GatedTransport(httpx.BaseTransport):
    """Installs the session trace AFTER every request event hook ran (#6537).

    httpx calls a transport's ``handle_request`` once all request hooks have
    run, so a caller hook can no longer replace or remove the trace: a trace
    it set is chained after the SDK's. The request's own ``extensions`` dict
    is restored afterwards, so a resent or redirected request never stacks
    one hop's check on the next.
    """

    def __init__(self, inner: httpx.BaseTransport, context: ssl.SSLContext) -> None:
        self._inner = inner
        self._context = context

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        original = request.extensions
        request.extensions = dict(original)
        _with_trace(request, _session_trace(self._context, request))
        try:
            return self._inner.handle_request(request)
        finally:
            request.extensions = original

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> _GatedTransport:
        self._inner.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        self._inner.__exit__(exc_type, exc_value, traceback)


class _AsyncGatedTransport(httpx.AsyncBaseTransport):
    """The async :class:`_GatedTransport` (#6537)."""

    def __init__(self, inner: httpx.AsyncBaseTransport, context: ssl.SSLContext) -> None:
        self._inner = inner
        self._context = context

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        original = request.extensions
        request.extensions = dict(original)
        _with_trace(request, _async_session_trace(self._context, request))
        try:
            return await self._inner.handle_async_request(request)
        finally:
            request.extensions = original

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> _AsyncGatedTransport:
        await self._inner.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self._inner.__aexit__(exc_type, exc_value, traceback)


_GATE_UNSUPPORTED = (
    "verify=<ssl.SSLContext> needs the TLS session check on every transport, "
    "and this httpx client does not expose them; pass verify= a CA file or "
    "directory path instead (#6537)."
)


def gate_transports(
    client: httpx.Client | httpx.AsyncClient,
    kwargs: dict[str, Any],
    verify: object,
) -> None:
    """Put the post-handshake session check on every transport of ``client`` (#6537).

    Applies when ``kwargs`` (from :func:`build_httpx_kwargs`) forwards the
    caller's own context. The default transport and every mounted proxy
    transport are wrapped, so the check runs inside the transport, after all
    request event hooks. Fails closed: if the client does not expose its
    transports the client is closed and construction is refused.
    """
    context = kwargs.get("verify")
    if not (isinstance(context, ssl.SSLContext) and context is verify):
        return
    is_async = isinstance(client, httpx.AsyncClient)
    base: type = httpx.AsyncBaseTransport if is_async else httpx.BaseTransport
    gated: Any = _AsyncGatedTransport if is_async else _GatedTransport
    transport = getattr(client, "_transport", None)
    mounts = getattr(client, "_mounts", None)
    wrapped: dict[Any, Any] = {}
    supported = isinstance(transport, base) and isinstance(mounts, dict)
    if supported and isinstance(mounts, dict):
        for pattern, mounted in mounts.items():
            if isinstance(mounted, base):
                wrapped[pattern] = gated(mounted, context)
            elif mounted is not None:
                supported = False
                break
    if not supported or not isinstance(mounts, dict):
        # A just-built client has opened no connection; its sync transports
        # are closed anyway so nothing outlives the refusal.
        if not is_async:
            owned = [transport, *(mounts.values() if isinstance(mounts, dict) else ())]
            for candidate in owned:
                if isinstance(candidate, httpx.BaseTransport):
                    candidate.close()
        raise ValueError(_GATE_UNSUPPORTED)
    client._transport = gated(transport, context)  # noqa: SLF001
    mounts.update(wrapped)


def _request_hooks(context: ssl.SSLContext, *, is_async: bool) -> dict[str, list[Any]]:
    """httpx event hooks that enforce a caller-held context (#6249, #6305, #6306, #6349).

    * ``request``: re-check the context before every request (early, clear
      error). The post-handshake session check (:class:`_SessionGate`) is not
      installed here: a caller hook appended later could replace the trace
      (#6537). :func:`gate_transports` installs it inside every transport,
      after all request hooks; it inspects every TLS session of the request,
      direct, tunnelled or over SOCKS, right after its handshake and before
      the request's first byte is written on that connection, and an
      unverified session is closed and refused.
    * ``response``: a backstop that inspects the connection the response came
      over, which also covers a pooled connection and a trace event that never
      fired. It runs after the request was written, so it refuses the result
      but cannot un-send the request.

    The caller keeps a reference to the context and may weaken it after
    construction or between the check and the handshake; the session check
    does not depend on the context's state at any earlier moment.
    """

    def _recheck() -> None:
        if not _context_verifies(context):
            raise ValueError(_UNVERIFIED_MESSAGE)

    if is_async:

        async def _arequest(_request: httpx.Request) -> None:
            _recheck()

        async def _aresponse(response: httpx.Response) -> None:
            _assert_negotiated_session(
                _session_of(response.extensions.get("network_stream")),
                context,
                _request_host(response.request.url),
            )

        return {"request": [_arequest], "response": [_aresponse]}

    def _request(_request: httpx.Request) -> None:
        _recheck()

    def _response(response: httpx.Response) -> None:
        _assert_negotiated_session(
            _session_of(response.extensions.get("network_stream")),
            context,
            _request_host(response.request.url),
        )

    return {"request": [_request], "response": [_response]}


def build_httpx_kwargs(
    *,
    base_url: str,
    api_key: str | None,
    agent_id: str | None,
    timeout: float,
    verify: Union[bool, str, os.PathLike[str], ssl.SSLContext, None],
    cert: str | tuple[str, str] | None,
    extra_headers: dict[str, str] | None,
    is_async: bool = False,
) -> dict[str, Any]:
    """Build the ``httpx.Client`` / ``httpx.AsyncClient`` kwargs.

    mTLS is wired through the stock httpx params:

    * ``verify`` — path to the server CA bundle or ``True``. For a
      zero-config daemon this is ``<key_dir>/tls/local-ca.pem`` (#3782).
      ``False`` (or any other falsy non-path value) is REFUSED — see Raises.
    * ``cert`` — client certificate; accepts a single path or ``(cert, key)``.

    ``api_key`` is sent as ``X-API-Key`` (the server also accepts
    ``?api_key=`` query params, but a header keeps it out of access logs).
    ``agent_id`` is sent as ``X-Agent-Id`` — the HTTP daemon's default
    agent resolution precedence is body → header → per-request anonymous.

    Raises:
        ValueError: on ``verify=False`` (#3840). Under the transit-encryption
            standard (#3824) an unverified TLS channel is an encrypted pipe to
            whoever answers — the man-in-the-middle exposure the #3828
            ``http://`` refusal closes, one layer up. Accepted forms are exactly
            ``None``, ``True``, the path of an existing CA file or directory (``str``
            or ``os.PathLike``, resolved with ``os.path.realpath`` and read
            once at construction, never group- or world-writable, #6377) and
            exactly ``ssl.SSLContext`` (never a subclass) that is
            ``CERT_REQUIRED`` with ``check_hostname`` on, no relaxing verify
            flag, no suite without server authentication and no replaced
            handshake attribute. Every other value is refused. Only a checked
            value reaches httpx: a CA path becomes a context this SDK builds
            from the exact path string (#6248, #6245), and a caller-supplied
            context is re-checked before every request (#6249, #6375, #6305;
            the client does not own it, so turning verification off after
            construction is refused) and every TLS session is checked after
            its handshake (#6349, #6350). Both
            clients construct through this one funnel, so the refusal lives
            here once.
    """
    headers: dict[str, str] = {
        "User-Agent": f"ai-memory-python/{SDK_VERSION}",
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-Key"] = api_key
    if agent_id:
        headers["X-Agent-Id"] = agent_id
    if extra_headers:
        headers.update(extra_headers)

    kwargs: dict[str, Any] = {
        "base_url": base_url.rstrip("/"),
        "headers": headers,
        "timeout": timeout,
    }
    # #3840 — `False` was documented as "never pass" and forwarded untouched.
    # httpx reads ANY falsy `verify` as "do not verify" (httpx 0.27.x does so
    # for `""` too), and a caller-supplied `ssl.SSLContext` is used as given.
    # Only the value `_checked_verify` returns is forwarded (#6248), and a
    # caller-held context is re-checked on every request (#6249).
    checked = _checked_verify(verify)
    if checked is not None:
        kwargs["verify"] = checked
    if isinstance(checked, ssl.SSLContext) and checked is verify:
        kwargs["event_hooks"] = _request_hooks(checked, is_async=is_async)
    if cert is not None:
        kwargs["cert"] = cert
    return kwargs


def prep_json(body: Any) -> Any:
    """Serialize Pydantic models and drop ``None`` at the top level.

    The server uses ``#[serde(default)]`` on most optional fields, so
    sending an explicit ``null`` would *not* be equivalent to omitting the
    key — some handlers would clobber an existing value. We drop keys whose
    value is ``None`` to preserve server-side defaults.
    """
    if isinstance(body, BaseModel):
        # by_alias=True so request models that use Field(alias=...) round-trip
        # (e.g. InboxMessage's ``from_`` → ``from``).
        return {k: v for k, v in body.model_dump(by_alias=True).items() if v is not None}
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if v is not None}
    return body


def handle_response(response: httpx.Response) -> Any:
    """Raise on error, otherwise decode JSON (or return text for text/plain).

    ``/api/v1/metrics`` is Prometheus text; every other endpoint is JSON.
    """
    content_type = response.headers.get("content-type", "")
    if response.status_code >= 400:
        payload: Any
        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError):
            payload = response.text or None
        raise_for_status(response.status_code, payload)
    if "application/json" in content_type:
        return response.json()
    return response.text


def build_create_body(
    *,
    title: str,
    content: str,
    signing_key: AgentSigningKey | None = None,
    fields: dict[str, Any],
) -> CreateMemory:
    """Assemble a :class:`CreateMemory`, signing it when a key is supplied.

    #2455 — ``POST /api/v1/memories`` is ``WriteSurface::HttpDirect`` and
    fails CLOSED by default, so an unsigned store is ``403
    ATTESTATION_FAILED``. Passing ``signing_key`` makes the SDK usable
    against a stock daemon; omitting it preserves the previous behaviour for
    deployments that explicitly set ``AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0``.

    Signing requires ``agent_id`` because it is inside the signed envelope and
    the SDK must sign the SAME id the server attributes the write to. The
    envelope also pins ``kind`` and ``namespace``, so both are resolved to the
    exact values that go on the wire before signing — never afterwards.

    **Namespace caveat:** when the caller omits ``namespace`` this resolves to
    the COMPILED default (``"global"``). A daemon configured with
    ``[storage].default_namespace`` would store the row elsewhere, and since
    the namespace is inside the envelope the signature would not verify. The
    client cannot see a server-side override, so signed writes against such a
    deployment MUST pass ``namespace`` explicitly.

    Args:
        fields: Optional ``CreateMemory`` fields; ``None`` values are dropped
            so server-side defaults apply.

    Raises:
        ValueError: when ``signing_key`` is given without an ``agent_id``, or
            when a caller-supplied ``signature`` would collide with one this
            function would mint.
    """
    supplied = {k: v for k, v in fields.items() if v is not None}

    if signing_key is not None:
        if supplied.get("signature"):
            raise ValueError(
                "pass either signing_key or an explicit signature, not both"
            )
        agent_id = supplied.get("agent_id")
        if not agent_id:
            raise ValueError(
                "signing_key requires an explicit agent_id: the signature commits "
                "to the agent_id, so the SDK cannot sign a write whose identity "
                "the server would resolve from the X-Agent-Id header or an "
                "anonymous fallback."
            )
        # Import here so `cryptography` stays an optional dependency for
        # callers who never sign.
        from ai_memory.attestation import attestation_fields

        namespace = supplied.get("namespace", CreateMemory.model_fields["namespace"].default)
        kind = supplied.get("kind") or DEFAULT_MEMORY_KIND
        supplied.update(
            attestation_fields(
                signing_key,
                agent_id=agent_id,
                namespace=namespace,
                title=title,
                content=content,
                kind=kind,
                created_at=supplied.get("created_at"),
            )
        )
        supplied["namespace"] = namespace

    return CreateMemory(title=title, content=content, **supplied)


def if_match_headers(expected_version: int | str | None) -> dict[str, str] | None:
    """Build the ``If-Match`` header for an optimistic-concurrency update.

    The daemon reads the expected row version from ``If-Match`` (bare integer
    or quoted ETag-style), NOT from the request body — see
    ``src/handlers/memories.rs:245-260``. A stale version yields ``409``.
    """
    if expected_version is None:
        return None
    return {"If-Match": str(expected_version)}


def wrap_transport_error(exc: Exception) -> TransportError:
    """Convert an httpx transport error to our hierarchy."""
    return TransportError(f"transport error: {exc}", payload=None)
