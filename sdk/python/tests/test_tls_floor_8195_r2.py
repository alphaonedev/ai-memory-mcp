# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""TLS 1.2 floor, cipher classes and the mutants round 1 left uncaught (#8195, round 2).

Closes security r1 F1-F7 and code r1 F1-F6 on PR #8251:

* the SDK-built context sets ``minimum_version = TLSv1_2`` (named constant) and
  the validator refuses a caller context whose range reaches below it or ends
  below it, on the sync and the async path, before and after construction
  (sec r1 F4, code r1 F2);
* the negotiated protocol must be TLS 1.2 or newer, which also covers a
  caller context that leaves the range to the library default;
* a plain ``ssl.create_default_context()`` is ADMITTED on every OpenSSL build:
  only anonymous (aNULL), NULL-encryption (eNULL) and low-strength suites are
  refused, never "any suite that is not ECDHE" (code r1 F1);
* one test per mutant of the reviewers' tables that survived round 1: the
  auth-null and eNULL refusals at construction, the CA parse refusal and its
  content-free error, the three owner-file identity fields, the CA-directory
  ACL refusal, and the typed error where a raw ``OSError`` escaped (sec r1
  F5-F7, code r1 F5-F6).

No test here starts a server that speaks a protocol below TLS 1.2; the wire
version is checked through the session gate with a stand-in session.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import ssl
import subprocess
import sys
import types
from collections.abc import Iterator
from typing import Any

import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _common, _ownedfile

from ._tlslab import Lab, RecordingServer

_CLIENTS = [AiMemoryClient, AsyncAiMemoryClient]
_ORIGIN = "https://localhost:9077"
_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
_TLS = ssl.TLSVersion

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return Lab(tmp_path_factory.mktemp("lab8195r2"))


@pytest.fixture
def origin(lab: Lab) -> Iterator[RecordingServer]:
    server = RecordingServer(lab.server_context("origin"))
    try:
        yield server
    finally:
        server.close()


def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


def _construct(client_cls: type, verify: object) -> None:
    """Build and close one client: raises exactly what construction raises."""
    client = client_cls(base_url=_ORIGIN, verify=verify)
    if client_cls is AiMemoryClient:
        client.close()
    else:
        asyncio.run(client.aclose())


def _ranged(low: ssl.TLSVersion | None, high: ssl.TLSVersion | None) -> ssl.SSLContext:
    """A verifying default context with the protocol range set (skip if unsupported)."""
    context = ssl.create_default_context()
    try:
        if low is not None:
            context.minimum_version = low
        if high is not None:
            context.maximum_version = high
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL cannot express that protocol range")
    return context


# ---- sec r1 F4 / code r1 F2: the TLS 1.2 floor ---------------------------

_REFUSED_RANGES = {
    "floor-TLSv1": (_TLS.TLSv1, None),
    "floor-TLSv1_1": (_TLS.TLSv1_1, None),
    "floor-SSLv3": (_TLS.SSLv3, None),
    "ceiling-TLSv1": (_TLS.MINIMUM_SUPPORTED, _TLS.TLSv1),
    "ceiling-TLSv1_1": (_TLS.MINIMUM_SUPPORTED, _TLS.TLSv1_1),
}
_ADMITTED_RANGES = {
    "library-default": (None, None),
    "floor-minimum-supported": (_TLS.MINIMUM_SUPPORTED, None),
    "floor-TLSv1_2": (_TLS.TLSv1_2, None),
    "floor-TLSv1_3": (_TLS.TLSv1_3, None),
    "ceiling-TLSv1_2": (_TLS.MINIMUM_SUPPORTED, _TLS.TLSv1_2),
    "ceiling-TLSv1_3": (_TLS.MINIMUM_SUPPORTED, _TLS.TLSv1_3),
    "ceiling-maximum-supported": (_TLS.MINIMUM_SUPPORTED, _TLS.MAXIMUM_SUPPORTED),
    "pinned-TLSv1_2": (_TLS.TLSv1_2, _TLS.TLSv1_2),
}


def test_minimum_tls_version_is_the_named_constant_8195() -> None:
    assert _common.MINIMUM_TLS_VERSION == _TLS.TLSv1_2


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("bounds", _REFUSED_RANGES.values(), ids=_REFUSED_RANGES.keys())
def test_context_reaching_below_tls_1_2_is_refused_at_construction_8195(
    client_cls: type, bounds: tuple[ssl.TLSVersion | None, ssl.TLSVersion | None]
) -> None:
    context = _ranged(*bounds)
    with pytest.raises(ValueError, match="verify=False") as refused:
        _construct(client_cls, context)
    assert "TLSv1_2" in str(refused.value)  # names the remedy
    assert "localhost" not in str(refused.value)  # content-free


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("bounds", _ADMITTED_RANGES.values(), ids=_ADMITTED_RANGES.keys())
def test_context_at_or_above_tls_1_2_is_admitted_8195(
    client_cls: type, bounds: tuple[ssl.TLSVersion | None, ssl.TLSVersion | None]
) -> None:
    _construct(client_cls, _ranged(*bounds))


@pytest.mark.parametrize("bounds", _REFUSED_RANGES.values(), ids=_REFUSED_RANGES.keys())
def test_predicate_refuses_a_range_below_tls_1_2_8195(
    bounds: tuple[ssl.TLSVersion | None, ssl.TLSVersion | None],
) -> None:
    assert _common._context_verifies(_ranged(*bounds)) is False  # noqa: SLF001


@pytest.mark.parametrize("bounds", _ADMITTED_RANGES.values(), ids=_ADMITTED_RANGES.keys())
def test_predicate_admits_a_range_from_tls_1_2_8195(
    bounds: tuple[ssl.TLSVersion | None, ssl.TLSVersion | None],
) -> None:
    assert _common._context_verifies(_ranged(*bounds)) is True  # noqa: SLF001


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("lowered", ["floor", "ceiling"])
def test_range_lowered_after_construction_is_refused_per_request_8195(
    origin: RecordingServer,
    lab: Lab,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    lowered: str,
) -> None:
    _no_proxy(monkeypatch)
    context = lab.client_context()

    def lower() -> None:
        if lowered == "floor":
            context.minimum_version = _TLS.TLSv1
        else:
            context.minimum_version = _TLS.MINIMUM_SUPPORTED
            context.maximum_version = _TLS.TLSv1_1

    def get() -> object:
        if client_cls is AiMemoryClient:
            with AiMemoryClient(base_url=origin.url, verify=context, timeout=5) as client:
                lower()
                return client._client.get("/x").status_code  # noqa: SLF001

        async def run() -> object:
            async with AsyncAiMemoryClient(base_url=origin.url, verify=context, timeout=5) as client:
                lower()
                return (await client._client.get("/x")).status_code  # noqa: SLF001

        return asyncio.run(run())

    with pytest.raises(ValueError, match="verify=False is refused"):
        get()
    assert origin.hits == []


def test_builder_context_sets_the_floor_even_when_the_library_default_is_lower_8195(
    lab: Lab, tmp_path: pathlib.Path
) -> None:
    """A library configured with ``MinProtocol = TLSv1`` still yields a TLS 1.2 floor.

    The stock default would report ``TLSv1`` here, so only the builder's own
    assignment can produce ``TLSv1_2``.
    """
    conf = tmp_path / "openssl-minprotocol.cnf"
    conf.write_text(
        "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n"
        "[ssl_sect]\nsystem_default = system_default_sect\n"
        "[system_default_sect]\nMinProtocol = TLSv1\n"
    )
    program = (
        "import ssl\n"
        "from ai_memory import _common\n"
        "stock = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).minimum_version\n"
        "built = _common._pinned_base_context().minimum_version\n"
        "from_path = _common._context_from_path(%r)\n"
        "print(int(stock), int(built), int(from_path.minimum_version))\n" % str(lab.ca_path)
    )
    env = dict(os.environ, OPENSSL_CONF=str(conf))
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", program], env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr[-400:]
    stock, built, from_path = (int(x) for x in result.stdout.split())
    floor = int(_TLS.TLSv1_2)
    if stock >= floor:
        pytest.skip("this Python already defaults to TLS 1.2; the in-process test below covers the builder")
    assert built == floor
    assert from_path == floor


def test_builder_assigns_the_floor_over_a_lower_starting_state_8195(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The builder's own assignment sets TLS 1.2, whatever state a new context starts in.

    A context class that starts at ``MINIMUM_SUPPORTED`` stands in for a distro
    Python whose default is below TLS 1.2; only an explicit assignment in the
    builder can move it, on any Python and OpenSSL.
    """
    real = ssl.SSLContext

    class _LowStart(real):  # type: ignore[misc, valid-type]
        def __new__(cls, *args: Any, **kwargs: Any) -> Any:
            instance = super().__new__(cls, *args, **kwargs)
            instance.minimum_version = _TLS.MINIMUM_SUPPORTED
            return instance

    shim = types.SimpleNamespace(**{name: getattr(ssl, name) for name in dir(ssl)})
    shim.SSLContext = _LowStart
    monkeypatch.setattr(_common, "ssl", shim)
    built = _common._pinned_base_context()  # noqa: SLF001
    assert built.minimum_version == _TLS.TLSv1_2


def test_sdk_built_context_reports_the_floor_8195(lab: Lab) -> None:
    built = _common._context_from_path(str(lab.ca_path))  # noqa: SLF001
    assert built.minimum_version >= _TLS.TLSv1_2


class _WireSession:
    """A stand-in ``ssl.SSLObject`` carrying a chosen negotiated protocol."""

    def __init__(self, context: object, proto: object, *, bits: int = 128) -> None:
        self.context = context
        self._proto = proto
        self._bits = bits

    def getpeercert(self, binary_form: bool = False) -> object:  # noqa: FBT001, FBT002
        return {"subject": ((("commonName", "x"),),)}

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", self._bits)

    def version(self) -> object:
        return self._proto


class _NoVersionSession(_WireSession):
    version = None  # type: ignore[assignment]


@pytest.mark.parametrize("proto", ["TLSv1.2", "TLSv1.3"])
def test_session_negotiating_tls_1_2_or_newer_is_admitted_8195(proto: str) -> None:
    context = ssl.create_default_context()
    _common._assert_negotiated_session(_WireSession(context, proto), context, "x")  # noqa: SLF001


@pytest.mark.parametrize("proto", ["TLSv1", "TLSv1.1", "SSLv3", "", None, 771])
def test_session_negotiating_below_tls_1_2_is_refused_8195(proto: object) -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="verify=False"):
        _common._assert_negotiated_session(_WireSession(context, proto), context, "x")  # noqa: SLF001


def test_session_without_a_version_is_refused_8195() -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="verify=False"):
        _common._assert_negotiated_session(_NoVersionSession(context, "TLSv1.3"), context, "x")  # noqa: SLF001


# ---- code r1 F1: refuse anonymous and null suites, not every non-ECDHE suite


def _suite(
    auth: object = "auth-rsa", symmetric: object = "aes-256-gcm", bits: object = 256
) -> dict[str, object]:
    return {"auth": auth, "symmetric": symmetric, "strength_bits": bits}


def _offering(monkeypatch: pytest.MonkeyPatch, suites: list[Any]) -> ssl.SSLContext:
    """A verifying context whose ``get_ciphers`` lists ``suites`` (deterministic, any OpenSSL)."""
    def get_ciphers(_self: ssl.SSLContext) -> list[Any]:
        return suites

    # ``get_ciphers`` is one of the pinned handshake attributes: re-pin the
    # stand-in so only the suite list under test differs from stock.
    monkeypatch.setattr(ssl.SSLContext, "get_ciphers", get_ciphers)
    monkeypatch.setitem(_common._STOCK_HANDSHAKE, "get_ciphers", get_ciphers)  # noqa: SLF001
    return ssl.create_default_context()


_ADMITTED_SUITES = {
    "rsa-aes256": [_suite()],
    "tls13-auth-any": [_suite("auth-any", "aes-128-gcm", 128)],
    "psk-listed-with-rsa": [_suite(), _suite("auth-psk", "aes-128-gcm", 128)],
    "srp-listed-with-rsa": [_suite(), _suite("auth-srp", "aes-256-cbc", 256)],
    "exactly-112-bits": [_suite(bits=112)],
}
_REFUSED_SUITES = {
    "anonymous": [_suite(), _suite("auth-null")],
    "null-encryption": [_suite(), _suite(symmetric=None)],
    "no-symmetric-key": [_suite(), {"auth": "auth-rsa", "strength_bits": 256}],
    "export-grade-56-bits": [_suite(), _suite(bits=56)],
    "just-below-112-bits": [_suite(bits=111)],
    "no-strength-key": [_suite(), {"auth": "auth-rsa", "symmetric": "aes-256-gcm"}],
    "strength-is-bool": [_suite(bits=True)],
    "strength-is-text": [_suite(bits="256")],
    "no-auth-key": [_suite(), {"symmetric": "aes-256-gcm", "strength_bits": 256}],
    "entry-is-not-a-dict": [_suite(), "TLS_AES_128_GCM_SHA256"],
    "no-suites": [],
}


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("suites", _ADMITTED_SUITES.values(), ids=_ADMITTED_SUITES.keys())
def test_context_without_anonymous_or_null_suites_is_admitted_8195(
    monkeypatch: pytest.MonkeyPatch, client_cls: type, suites: list[Any]
) -> None:
    _construct(client_cls, _offering(monkeypatch, suites))


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("suites", _REFUSED_SUITES.values(), ids=_REFUSED_SUITES.keys())
def test_context_with_an_anonymous_null_or_weak_suite_is_refused_at_construction_8195(
    monkeypatch: pytest.MonkeyPatch, client_cls: type, suites: list[Any]
) -> None:
    context = _offering(monkeypatch, suites)
    with pytest.raises(ValueError, match="verify=False"):
        _construct(client_cls, context)


def test_refusal_names_a_remedy_that_does_not_mention_psk_or_srp_8195(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _offering(monkeypatch, [_suite("auth-null")])
    with pytest.raises(ValueError, match="verify=False") as refused:
        _construct(AiMemoryClient, context)
    text = str(refused.value)
    assert ":!aNULL:!eNULL" in text
    assert "!PSK" not in text
    assert "!SRP" not in text


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_plain_default_context_is_admitted_on_every_openssl_8195(client_cls: type) -> None:
    """The documented happy path: ``verify=ssl.create_default_context()`` (code r1 F1)."""
    _construct(client_cls, ssl.create_default_context())


# ---- sec r1 F5-F7 / code r1 F5: CA file parse refusal, content-free ---------

_CA_SENTINEL = "SENTINEL-NOT-A-CERTIFICATE-8195"


def _junk_ca(directory: pathlib.Path, body: str) -> pathlib.Path:
    path = directory / "junk-ca.pem"
    path.write_text(body)
    path.chmod(0o644)
    return path


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    "body",
    [
        f"-----BEGIN CERTIFICATE-----\n{_CA_SENTINEL}\n-----END CERTIFICATE-----\n",
        f"{_CA_SENTINEL}\n",
    ],
    ids=["pem-armour-bad-body", "not-pem-at-all"],
)
def test_ca_file_without_a_usable_certificate_is_refused_and_echoes_nothing_8195(
    tmp_path: pathlib.Path, client_cls: type, body: str
) -> None:
    directory = tmp_path / "ca"
    directory.mkdir(mode=0o755)
    ca_file = _junk_ca(directory, body)
    with pytest.raises(ValueError, match="holds no usable certificate") as refused:
        _construct(client_cls, str(ca_file))
    text = f"{refused.value} {refused.value.__cause__} {refused.value.__context__}"
    assert _CA_SENTINEL not in text


# ---- sec r1 F7 / code r1 F5: the CA-directory ACL refusal is reached --------


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_ca_directory_acl_refusal_is_enforced_before_the_directory_is_read_8195(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    """Linux reaches ``_refuse_foreign_acl_on_directory`` only through a stub (code r1 M25)."""
    directory = tmp_path / "ca"
    directory.mkdir(mode=0o755)
    seen: list[tuple[str, str]] = []
    listed: list[str] = []

    real_refuse = _common._refuse_foreign_acl_on_directory  # noqa: SLF001

    def refuse(what: str, path: str, resolved: str, info: os.stat_result) -> None:
        # The path walk calls this for every ancestor too ("CA path"); only the
        # directory the caller named is refused by the stub.
        if what != "CA directory":
            real_refuse(what, path, resolved, info)
            return
        seen.append((what, path))
        raise ValueError("verify= CA directory carries an extended ACL (stub)")

    real_listdir = os.listdir

    def listdir(path: Any) -> list[str]:
        listed.append(str(path))
        return real_listdir(path)

    monkeypatch.setattr(_common, "_refuse_foreign_acl_on_directory", refuse)
    monkeypatch.setattr(_common.os, "listdir", listdir)
    with pytest.raises(ValueError, match="extended ACL"):
        _construct(client_cls, str(directory))
    assert seen == [("CA directory", str(directory))]
    assert listed == []


# ---- sec r1 F5-F7 / code r1 F5-F6: owner-file identity fields and typed error

_OWNER_ONLY_MODE = 0o600


class _Refused(Exception):
    """The caller's refusal type (WakeError / KeyFileError in production)."""


def _credential(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "credential"
    path.write_bytes(b"checked-credential")
    path.chmod(_OWNER_ONLY_MODE)
    return path


def _open_after_lstat(path: pathlib.Path) -> int:
    return _ownedfile._open_checked_after_lstat(  # noqa: SLF001
        path, error=_Refused, mode_advice="advice", flags=os.O_RDONLY
    )


def _refusal_of(path: pathlib.Path) -> _Refused:
    """The refusal ``_open_after_lstat`` raises; a descriptor it returns is closed and fails the test."""
    try:
        fd = _open_after_lstat(path)
    except _Refused as refused:
        return refused
    os.close(fd)
    raise AssertionError("the open was admitted")


@_POSIX_ONLY
def test_unchanged_identity_opens_8195(tmp_path: pathlib.Path) -> None:
    fd = _open_after_lstat(_credential(tmp_path))
    os.close(fd)


@_POSIX_ONLY
@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_uid", "st_mode"])
def test_each_identity_field_alone_binds_the_open_to_the_check_8195(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    """Only ONE of device, inode, owner, mode differs; the owner/ACL checks are muted.

    Each field is then the sole defence, so dropping any of them from
    ``_IDENTITY_FIELDS`` lets the swapped file through (round 1 mutants
    st_dev, st_uid, st_mode; code r1 F5).
    """
    path = _credential(tmp_path)
    real_fstat = os.fstat

    def swapped(fd: int) -> object:
        real = real_fstat(fd)
        seen = {name: getattr(real, name) for name in _ownedfile._IDENTITY_FIELDS}  # noqa: SLF001
        seen[field] = seen[field] + 1
        return types.SimpleNamespace(**seen)

    monkeypatch.setattr(_ownedfile, "check_owned_stat", lambda *a, **k: None)
    monkeypatch.setattr(_ownedfile, "check_owned_acl", lambda *a, **k: None)
    monkeypatch.setattr(_ownedfile.os, "fstat", swapped)
    assert "changed between its check and its open" in str(_refusal_of(path))


@_POSIX_ONLY
def test_identity_fields_are_exactly_device_inode_owner_mode_8195() -> None:
    assert _ownedfile._IDENTITY_FIELDS == ("st_dev", "st_ino", "st_uid", "st_mode")  # noqa: SLF001


@_POSIX_ONLY
def test_file_vanishing_between_check_and_open_gives_the_typed_error_8195(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _credential(tmp_path)

    def gone(_path: Any, _flags: int, *_rest: Any) -> int:
        raise FileNotFoundError(2, "No such file or directory", str(_path))

    monkeypatch.setattr(_ownedfile.os, "open", gone)
    refused = _refusal_of(path)
    assert "could not be opened after its check" in str(refused)
    assert not isinstance(refused, OSError)
    assert "No such file" in str(refused)


# ---- code r2 F2: a bound that is not an ``ssl.TLSVersion`` is refused ----
# These tests pin the refusal as a whole. The ``_STOCK_HANDSHAKE`` identity check refuses a descriptor
# replaced after ``ai_memory`` is imported before the type check in ``_tls_range_is_modern`` runs. A
# descriptor replaced BEFORE the import is captured as stock, so there the type check is the only
# refusal; ``test_tls_prepatch_8195_r5.py`` pins that case in a fresh interpreter (mutant M66, code r4 F3).

_ORIG_BOUND = {"minimum_version": ssl.SSLContext.minimum_version, "maximum_version": ssl.SSLContext.maximum_version}

# Numerically legal bounds (771 is TLSv1_2) that are not a TLSVersion: the stock-descriptor identity check refuses them.
_NOT_A_TLS_VERSION = {"int-1.2": 771, "int-1.3": 772, "string": "TLSv1.2", "none": None}


def _stub_bound(monkeypatch: pytest.MonkeyPatch, attr: str, value: object) -> None:
    """Make ``SSLContext.<attr>`` report ``value`` (the property is Python-level)."""
    monkeypatch.setattr(ssl.SSLContext, attr, property(lambda _self: value, _ORIG_BOUND[attr].fset))


@pytest.mark.parametrize("attr", ["minimum_version", "maximum_version"])
@pytest.mark.parametrize("value", _NOT_A_TLS_VERSION.values(), ids=_NOT_A_TLS_VERSION.keys())
def test_predicate_refuses_a_bound_that_is_not_a_tls_version_8195(
    monkeypatch: pytest.MonkeyPatch, attr: str, value: object
) -> None:
    context = ssl.create_default_context()
    _stub_bound(monkeypatch, attr, value)
    assert _common._context_verifies(context) is False  # noqa: SLF001


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("attr", ["minimum_version", "maximum_version"])
@pytest.mark.parametrize("value", _NOT_A_TLS_VERSION.values(), ids=_NOT_A_TLS_VERSION.keys())
def test_bound_that_is_not_a_tls_version_is_refused_at_construction_8195(
    monkeypatch: pytest.MonkeyPatch, client_cls: type, attr: str, value: object
) -> None:
    context = ssl.create_default_context()
    _stub_bound(monkeypatch, attr, value)
    with pytest.raises(ValueError, match="verify=False"):
        _construct(client_cls, context)

