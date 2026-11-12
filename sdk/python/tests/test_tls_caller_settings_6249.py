# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A caller ``ssl.SSLContext`` is never verified more weakly than configured.

Class invariant (#6249 #6267, PR 9157 round 1, decision carry-or-refuse): the
SDK-owned context the handshake uses is never weaker, in any
verification-relevant setting, than the context the caller passed. Each
stricter caller setting is present on the owned context (and a real lab
handshake still verifies), or construction fails with the exact named
:class:`ValueError`; a looser caller setting never lowers the SDK floor.

Every row runs on the stdlib path and on the truststore path, on the sync and
the async client. The truststore path runs twice: against a truststore-shaped
fake (so the rows run in CI, where truststore is not installed) and against
the real truststore where it is installed. The fakes also pin the truststore
shape contract (>= 0.10.5) under a wall-clock ceiling, and the S-L1 rows weaken
the C-level state between the use-time pre-check and SSL object creation.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import types
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _tls
from ai_memory.errors import TransportError
from tests._tlslab_6249 import LAB_HEALTH_BODY, Lab, LabServer, build_lab
from tests._truststore_fake_6249 import (
    SHAPE_CURRENT,
    SHAPE_NO_LOCK,
    SHAPE_PLAIN_LOCK,
    TRUSTSTORE_MODULE,
    fake_truststore,
)

ssl = _tls.ssl
#: OP_NO_TLSv1_2 is deprecated in the stdlib; carrying it is still required.
pytestmark = pytest.mark.filterwarnings("ignore:ssl.OP_NO_SSL:DeprecationWarning")
CLIENT_KINDS = ("sync", "async")
#: Paths a caller context can take: stdlib, the truststore-shaped fake (runs
#: everywhere) and the real truststore (skipped where it is not installed).
CALLER_PATHS = ("stdlib", "truststore_fake", "truststore_real")
#: Per-request timeout for every lab call (seconds).
LAB_TIMEOUT_S = 5.0
#: Wall-clock ceiling for one construction plus one request on a truststore
#: shape row; past it the row fails as a hang instead of hanging the suite.
SHAPE_CEILING_S = 10.0
#: Kind name every caller context of this module reports.
CALLER_KIND = "SSLContext"
#: An ECDSA TLS 1.2 suite the lab's P-256 leaf can serve.
CALLER_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256"
#: The OpenSSL cipher string a foreign TLS 1.2 suite is picked from. The SDK
#: (create_default_context) list depends on how Python and OpenSSL were built
#: (Ubuntu's Python keeps AES128-SHA, other builds drop it), so the suite that
#: is not in it is chosen on the running interpreter: see _foreign_cipher().
FOREIGN_CIPHER_POOL = "ALL"
#: OpenSSL security levels: one above the SDK template, one below it.
STRICTER_SECLEVEL = 3
LOOSER_SECLEVEL = 1
#: X509_V_FLAG_* bits the SDK cannot classify (policy checks, ignore critical).
POLICY_CHECK_FLAG = 0x80
IGNORE_CRITICAL_FLAG = 0x10
#: An SSL_OP_* bit outside the SDK's carry and drop lists.
UNKNOWN_OPTION = 0x1000
#: OpenSSL X509_CHECK_FLAG_NEVER_CHECK_SUBJECT.
HOSTFLAG_NEVER_CHECK_SUBJECT = 0x20
#: The SDK floor the module pins (a looser caller never lowers it).
SDK_FLOOR = ssl.TLSVersion.TLSv1_2
TLS13 = ssl.TLSVersion.TLSv1_3
#: The truststore version floor of the shape contract.
TRUSTSTORE_FLOOR = "0.10.5"
#: An address nothing listens on; construction refusals never connect.
UNUSED_URL = "https://127.0.0.1:1"

#: Exact construction-time refusal messages (the public contract).
MSG_CRL = (
    "verify=<{kind}> is refused: it asks for CRL checking, which the SDK cannot copy; "
    "pass the CA bundle path as verify= instead"
)
MSG_UNREADABLE_SETTING = (
    "verify=<{kind}> is refused: its {setting} cannot be read from the OpenSSL context "
    "({error}); the ai-memory SDK refuses a verification setting it cannot check"
)
MSG_FLAG_UNKNOWN = (
    "verify=<{kind}> is refused: its {setting} sets bits {bits:#x}, which the ai-memory "
    "SDK cannot classify; clear them or pass the CA bundle path as verify= instead"
)
MSG_VERSION_RANGE = (
    "verify=<{kind}> is refused: its TLS version range is empty once the ai-memory SDK "
    "floor applies (minimum {minimum}, maximum {maximum})"
)
MSG_CIPHERS = (
    "verify=<{kind}> is refused: its cipher list cannot be carried onto the ai-memory "
    "SDK context ({detail})"
)
MSG_NOT_DEFAULT = (
    "verify=<{kind}> is refused: its {setting} is not the default and the ai-memory "
    "SDK cannot carry it"
)
MSG_UNKNOWN_SETTING = (
    "verify=<{kind}> is refused: its {setting} differs from a default context and the "
    "ai-memory SDK does not classify it; see VERIFICATION_SETTINGS in ai_memory._tls"
)
MSG_TRUSTSTORE_SHAPE = (
    "verify=<{kind}> is refused: truststore {version} does not provide {missing}; the "
    "ai-memory SDK supports truststore >= {floor}"
)
MSG_USE_TIME = (
    "ai-memory SDK refused the TLS handshake: certificate verification or hostname "
    "checking is off on the handshake context"
)
CIPHERS_NONE_SHARED = "none of its TLS 1.2 ciphers is in the SDK cipher list"
TRUSTSTORE_NO_LOCK = "a context lock (_ctx_lock)"
TRUSTSTORE_LOCK_NOT_REENTRANT = "a re-entrant context lock (_ctx_lock is not an RLock)"
TRUSTSTORE_NO_SOCKET_CLASS = "a verifying sslsocket_class (its own do_handshake)"

#: One fake per shape for the whole module (the SDK caches one owned class per
#: truststore class).
FAKE_CURRENT = fake_truststore(*SHAPE_CURRENT)


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return build_lab(tmp_path_factory.mktemp("tlslab-6249-settings"))


@pytest.fixture(scope="module")
def good_server(lab: Lab) -> Iterator[LabServer]:
    with LabServer(lab.good) as server:
        yield server


#: One event loop for every async client of this module: an AsyncClient's
#: pooled connections are bound to the loop that opened them.
_LOOP: list[asyncio.AbstractEventLoop] = []


def _run(coro: Any) -> Any:
    if not _LOOP:
        _LOOP.append(asyncio.new_event_loop())
    return _LOOP[0].run_until_complete(coro)


@pytest.fixture(scope="module", autouse=True)
def _close_loop() -> Iterator[None]:
    yield
    while _LOOP:
        _LOOP.pop().close()


def _make(kind: str, url: str, **kwargs: Any) -> AiMemoryClient | AsyncAiMemoryClient:
    if kind == "sync":
        return AiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, **kwargs)
    return AsyncAiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, **kwargs)


def _health(client: AiMemoryClient | AsyncAiMemoryClient) -> Any:
    if isinstance(client, AiMemoryClient):
        return client.health()

    async def run() -> Any:
        return await client.health()

    return _run(run())


def _close(client: AiMemoryClient | AsyncAiMemoryClient) -> None:
    if isinstance(client, AiMemoryClient):
        client.close()
    else:
        _run(client.aclose())


def _owned(client: AiMemoryClient | AsyncAiMemoryClient) -> Any:
    """The OpenSSL context the handshake inherits (the inner one for truststore)."""
    return client._client._transport._pool._ssl_context._sdk_handshake_ctx()


@pytest.fixture
def caller_path(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    path: str = request.param
    if path == "truststore_fake":
        monkeypatch.setitem(sys.modules, TRUSTSTORE_MODULE, FAKE_CURRENT)
    elif path == "truststore_real":
        real = pytest.importorskip(TRUSTSTORE_MODULE)
        monkeypatch.setitem(sys.modules, TRUSTSTORE_MODULE, real)
    return path


def _caller(
    path: str, lab: Lab, *, protocol: int = ssl.PROTOCOL_TLS_CLIENT
) -> tuple[Any, ssl.SSLContext]:
    """(the verify= object, the OpenSSL context its settings live on)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if path == "stdlib":
            ctx = ssl.SSLContext(protocol)
            inner = ctx
        else:
            ctx = sys.modules[TRUSTSTORE_MODULE].SSLContext(protocol)
            inner = ctx.__dict__["_ctx"]
    inner.verify_mode = ssl.CERT_REQUIRED
    inner.check_hostname = True
    ctx.load_verify_locations(cafile=str(lab.trusted_ca))
    return ctx, inner


def _names12(ctx: ssl.SSLContext) -> list[str]:
    return [c["name"] for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"]


def _template() -> ssl.SSLContext:
    return ssl.create_default_context()


# -- configure the caller context ---------------------------------------------


def _set_strict(c: ssl.SSLContext) -> None:
    c.verify_flags |= ssl.VERIFY_X509_STRICT


def _set_no_tls12(c: ssl.SSLContext) -> None:
    c.options |= ssl.OP_NO_TLSv1_2


def _set_cipher(c: ssl.SSLContext) -> None:
    c.set_ciphers(CALLER_CIPHER)


def _set_tls13_only(c: ssl.SSLContext) -> None:
    c.minimum_version = TLS13
    c.maximum_version = TLS13


def _set_min_tls13(c: ssl.SSLContext) -> None:
    c.minimum_version = TLS13


def _set_max_tls12(c: ssl.SSLContext) -> None:
    c.maximum_version = ssl.TLSVersion.TLSv1_2


def _set_seclevel3(c: ssl.SSLContext) -> None:
    c.set_ciphers(f"DEFAULT:@SECLEVEL={STRICTER_SECLEVEL}")


def _set_no_common_name(c: ssl.SSLContext) -> None:
    c.hostname_checks_common_name = False


def _set_nothing(c: ssl.SSLContext) -> None:
    del c


def _set_looser_minimum(c: ssl.SSLContext) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        c.minimum_version = ssl.TLSVersion.TLSv1


def _set_looser_flags(c: ssl.SSLContext) -> None:
    c.verify_flags = ssl.VERIFY_DEFAULT | ssl.VERIFY_ALLOW_PROXY_CERTS


def _set_looser_options(c: ssl.SSLContext) -> None:
    c.options &= ~ssl.OP_NO_COMPRESSION


def _set_looser_seclevel(c: ssl.SSLContext) -> None:
    c.set_ciphers(f"DEFAULT:@SECLEVEL={LOOSER_SECLEVEL}")


def _set_post_handshake_auth(c: ssl.SSLContext) -> None:
    c.post_handshake_auth = True


def _set_empty_range(c: ssl.SSLContext) -> None:
    c.minimum_version = TLS13
    c.maximum_version = ssl.TLSVersion.TLSv1_2


def _set_max_tls11(c: ssl.SSLContext) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        c.maximum_version = ssl.TLSVersion.TLSv1_1


def _set_unknown_option(c: ssl.SSLContext) -> None:
    c.options |= UNKNOWN_OPTION


def _set_policy_check(c: ssl.SSLContext) -> None:
    c.verify_flags |= POLICY_CHECK_FLAG


def _set_ignore_critical(c: ssl.SSLContext) -> None:
    c.verify_flags |= IGNORE_CRITICAL_FLAG


def _set_crl(c: ssl.SSLContext) -> None:
    c.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF


def _foreign_cipher() -> str:
    """A TLS 1.2 suite a default-level caller can set that the SDK list lacks."""
    pool = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pool.set_ciphers(FOREIGN_CIPHER_POOL)
    sdk_names = set(_names12(_template()))
    for name in sorted(set(_names12(pool)) - sdk_names):
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            probe.set_ciphers(name)
        except ssl.SSLError:
            continue
        if _names12(probe) == [name]:
            return name
    raise AssertionError(
        f"{ssl.OPENSSL_VERSION} offers no TLS 1.2 suite outside the SDK cipher list"
    )


def _set_foreign_cipher(c: ssl.SSLContext) -> None:
    c.set_ciphers(_foreign_cipher())


# -- check the owned context --------------------------------------------------


def _check_strict(o: Any) -> None:
    assert o.verify_flags & ssl.VERIFY_X509_STRICT, hex(o.verify_flags)


def _check_no_tls12(o: Any) -> None:
    assert o.options & ssl.OP_NO_TLSv1_2, hex(o.options)


def _check_cipher(o: Any) -> None:
    assert _names12(o) == [CALLER_CIPHER]


def _check_tls13_only(o: Any) -> None:
    assert (o.minimum_version, o.maximum_version) == (TLS13, TLS13)


def _check_min_tls13(o: Any) -> None:
    assert o.minimum_version == TLS13


def _check_max_tls12(o: Any) -> None:
    assert o.maximum_version == ssl.TLSVersion.TLSv1_2


def _check_seclevel3(o: Any) -> None:
    assert o.security_level == STRICTER_SECLEVEL


def _check_no_common_name(o: Any) -> None:
    assert o.hostname_checks_common_name is False
    base: Any = ssl.SSLContext.__base__
    assert base._host_flags.__get__(o) & HOSTFLAG_NEVER_CHECK_SUBJECT


def _check_template(o: Any) -> None:
    """The SDK floor: create_default_context()'s flags and a TLS 1.2 minimum."""
    tmpl = _template()
    assert o.verify_flags == tmpl.verify_flags, (hex(o.verify_flags), hex(tmpl.verify_flags))
    assert o.options == tmpl.options, (hex(o.options), hex(tmpl.options))
    assert o.minimum_version == SDK_FLOOR
    assert o.security_level == tmpl.security_level
    assert _names12(o) == _names12(tmpl)


def _check_floor_minimum(o: Any) -> None:
    assert o.minimum_version == SDK_FLOOR


def _check_floor_flags(o: Any) -> None:
    assert o.verify_flags == _template().verify_flags
    assert not o.verify_flags & ssl.VERIFY_ALLOW_PROXY_CERTS


def _check_floor_options(o: Any) -> None:
    assert o.options & ssl.OP_NO_COMPRESSION


def _check_floor_seclevel(o: Any) -> None:
    assert o.security_level == _template().security_level


def _check_no_post_handshake_auth(o: Any) -> None:
    assert o.post_handshake_auth is False


Configure = Callable[[ssl.SSLContext], None]
Check = Callable[[Any], None]

#: Stricter caller settings carried onto the owned context, and looser ones
#: that leave the SDK floor in place (X-2). Each row also completes a real
#: verifying handshake with the good lab server.
CARRIED: list[tuple[str, Configure, Check]] = [
    ("strict", _set_strict, _check_strict),
    ("op_no_tls12", _set_no_tls12, _check_no_tls12),
    ("set_ciphers", _set_cipher, _check_cipher),
    ("min_max_tls13", _set_tls13_only, _check_tls13_only),
    ("min_tls13", _set_min_tls13, _check_min_tls13),
    ("max_tls12", _set_max_tls12, _check_max_tls12),
    ("seclevel3", _set_seclevel3, _check_seclevel3),
    ("no_common_name", _set_no_common_name, _check_no_common_name),
    ("default_is_template", _set_nothing, _check_template),
    ("floor_minimum_tls1", _set_looser_minimum, _check_floor_minimum),
    ("floor_verify_flags", _set_looser_flags, _check_floor_flags),
    ("floor_options", _set_looser_options, _check_floor_options),
    ("floor_seclevel1", _set_looser_seclevel, _check_floor_seclevel),
    ("post_handshake_auth_not_carried", _set_post_handshake_auth, _check_no_post_handshake_auth),
]


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", CALLER_PATHS, indirect=True)
@pytest.mark.parametrize(("case", "configure", "check"), CARRIED, ids=[r[0] for r in CARRIED])
def test_6249_caller_setting_is_carried_never_weaker(
    lab: Lab,
    good_server: LabServer,
    caller_path: str,
    kind: str,
    case: str,
    configure: Configure,
    check: Check,
) -> None:
    verify, settings = _caller(caller_path, lab)
    configure(settings)
    client = _make(kind, good_server.url, verify=verify)
    try:
        check(_owned(client))
        assert _health(client) == LAB_HEALTH_BODY, case
    finally:
        _close(client)


def _flag_message(setting: str, bits: int) -> str:
    return MSG_FLAG_UNKNOWN.format(kind=CALLER_KIND, setting=setting, bits=bits)


#: Caller settings the SDK cannot carry: refused by exact message.
REFUSED: list[tuple[str, Configure, str]] = [
    (
        "empty_range",
        _set_empty_range,
        MSG_VERSION_RANGE.format(kind=CALLER_KIND, minimum="TLSv1_3", maximum="TLSv1_2"),
    ),
    (
        "max_below_floor",
        _set_max_tls11,
        MSG_VERSION_RANGE.format(kind=CALLER_KIND, minimum="TLSv1_2", maximum="TLSv1_1"),
    ),
    ("unknown_option", _set_unknown_option, _flag_message("options", UNKNOWN_OPTION)),
    ("policy_check", _set_policy_check, _flag_message("verify_flags", POLICY_CHECK_FLAG)),
    (
        "ignore_critical",
        _set_ignore_critical,
        _flag_message("verify_flags", IGNORE_CRITICAL_FLAG),
    ),
    ("crl_leaf", _set_crl, MSG_CRL.format(kind=CALLER_KIND)),
    (
        "foreign_cipher",
        _set_foreign_cipher,
        MSG_CIPHERS.format(kind=CALLER_KIND, detail=CIPHERS_NONE_SHARED),
    ),
]


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", CALLER_PATHS, indirect=True)
@pytest.mark.parametrize(("case", "configure", "message"), REFUSED, ids=[r[0] for r in REFUSED])
def test_6249_caller_setting_that_cannot_be_carried_is_refused(
    lab: Lab, caller_path: str, kind: str, case: str, configure: Configure, message: str
) -> None:
    verify, settings = _caller(caller_path, lab)
    configure(settings)
    with pytest.raises(ValueError) as info:
        _make(kind, UNUSED_URL, verify=verify)
    assert str(info.value) == message, case


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", CALLER_PATHS, indirect=True)
def test_6249_servername_callback_without_a_getter_is_refused_unless_default(
    lab: Lab, caller_path: str, kind: str
) -> None:
    """X-4: a callback the SDK cannot copy is refused (TLS_CLIENT forbids it,
    so the caller here is a generic PROTOCOL_TLS context made verifying)."""
    verify, settings = _caller(caller_path, lab, protocol=ssl.PROTOCOL_TLS)
    settings.sni_callback = lambda *args: None
    with pytest.raises(ValueError) as info:
        _make(kind, UNUSED_URL, verify=verify)
    assert str(info.value) == MSG_NOT_DEFAULT.format(kind=CALLER_KIND, setting="sni_callback")


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", CALLER_PATHS, indirect=True)
def test_6249_keylog_file_is_never_carried(
    lab: Lab, good_server: LabServer, caller_path: str, kind: str, tmp_path: Path
) -> None:
    verify, settings = _caller(caller_path, lab)
    keylog = tmp_path / "keylog.txt"
    settings.keylog_filename = str(keylog)
    client = _make(kind, good_server.url, verify=verify)
    try:
        assert _owned(client).keylog_filename is None
        assert _health(client) == LAB_HEALTH_BODY
    finally:
        _close(client)
    # Setting keylog_filename writes OpenSSL's comment header at once; a
    # carried keylog would add one secret line per handshake. Count only, so
    # a failure never prints key material.
    lines = keylog.read_text().splitlines() if keylog.exists() else []
    secret_lines = sum(1 for line in lines if line and not line.startswith("#"))
    assert secret_lines == 0, f"{secret_lines} key-log lines written"


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("verify_form", ["env", "path", "ctx"])
def test_6249_owned_verify_flags_equal_the_template_for_every_verify_form(
    lab: Lab, good_server: LabServer, kind: str, verify_form: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C-F2: the owned flags are create_default_context()'s, never VERIFY_DEFAULT."""
    verify: Any
    if verify_form == "env":
        monkeypatch.setenv("SSL_CERT_FILE", str(lab.trusted_ca))
        verify = True
    elif verify_form == "path":
        verify = str(lab.trusted_ca)
    else:
        verify = _caller("stdlib", lab)[0]
    client = _make(kind, good_server.url, verify=verify)
    try:
        _check_template(_owned(client))
        assert _health(client) == LAB_HEALTH_BODY
    finally:
        _close(client)


def test_6249_sdk_floor_is_pinned() -> None:
    """X-2: the floor no caller value lowers."""
    assert _tls.SDK_MINIMUM_TLS_VERSION is ssl.TLSVersion.TLSv1_2
    assert _tls.TRUSTSTORE_MIN_VERSION == TRUSTSTORE_FLOOR


# -- X-3: rows are read through the C-base descriptors -------------------------


class _RaisingGetter:
    """A C-base descriptor stand-in whose getter raises."""

    def __get__(self, obj: object, owner: object = None) -> Any:
        raise RuntimeError("getter failed")

    def __set__(self, obj: object, value: object) -> None:
        raise RuntimeError("setter failed")


def _c_base_copy(**overrides: Any) -> types.SimpleNamespace:
    """The C base's attributes as a namespace, with ``overrides`` applied
    (an override of None removes the attribute)."""
    real = ssl.SSLContext.__base__
    copy = {name: getattr(real, name) for name in dir(real) if not name.startswith("__")}
    copy.update(overrides)
    return types.SimpleNamespace(**{k: v for k, v in copy.items() if v is not None})


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", ["stdlib", "truststore_fake"], indirect=True)
@pytest.mark.parametrize(
    ("case", "replacement", "error"),
    [("raising", _RaisingGetter(), "RuntimeError"), ("missing", None, "AttributeError")],
)
def test_6249_unreadable_setting_is_refused_by_name(
    lab: Lab,
    caller_path: str,
    kind: str,
    case: str,
    replacement: Any,
    error: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verify, _ = _caller(caller_path, lab)
    monkeypatch.setattr(_tls, "_C_BASE", _c_base_copy(security_level=replacement))
    with pytest.raises(ValueError) as info:
        _make(kind, UNUSED_URL, verify=verify)
    assert str(info.value) == MSG_UNREADABLE_SETTING.format(
        kind=CALLER_KIND, setting="security_level", error=error
    ), case


# -- X-5: the runtime backstop -------------------------------------------------


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", ["stdlib", "truststore_fake"], indirect=True)
def test_6249_unclassified_attribute_that_is_not_default_is_refused(
    lab: Lab, caller_path: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A future attribute the table does not name is refused unless default."""
    unclassified = dict(_tls.NOT_VERIFICATION_RELEVANT)
    del unclassified["post_handshake_auth"]
    monkeypatch.setattr(_tls, "NOT_VERIFICATION_RELEVANT", types.MappingProxyType(unclassified))
    verify, settings = _caller(caller_path, lab)
    settings.post_handshake_auth = True
    with pytest.raises(ValueError) as info:
        _make(kind, UNUSED_URL, verify=verify)
    assert str(info.value) == MSG_UNKNOWN_SETTING.format(
        kind=CALLER_KIND, setting="post_handshake_auth"
    )


# -- S-M1: the truststore shape contract ---------------------------------------


def _bounded(attempt: Callable[[], Any]) -> Any:
    """Run ``attempt`` in a daemon thread; fail (never hang) past the ceiling."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = attempt()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test thread
            box["error"] = exc

    worker = threading.Thread(target=run, name="tls-shape-6249", daemon=True)
    worker.start()
    worker.join(SHAPE_CEILING_S)
    if worker.is_alive():
        pytest.fail(f"truststore shape row hung past {SHAPE_CEILING_S}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _construct_and_request(kind: str, url: str, verify: Any) -> Any:
    """One client, one request, closed; its own loop (runs off the main thread)."""
    if kind == "sync":
        client = AiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, verify=verify)
        try:
            return client.health()
        finally:
            client.close()

    async def run() -> Any:
        async with AsyncAiMemoryClient(base_url=url, timeout=LAB_TIMEOUT_S, verify=verify) as ac:
            return await ac.health()

    return asyncio.run(run())


SHAPE_REFUSALS: list[tuple[str, tuple[str, Any], bool, str]] = [
    ("plain_lock_0_10_4", SHAPE_PLAIN_LOCK, True, TRUSTSTORE_LOCK_NOT_REENTRANT),
    ("no_lock_0_10_3", SHAPE_NO_LOCK, True, TRUSTSTORE_NO_LOCK),
    ("no_verifying_classes", SHAPE_CURRENT, False, TRUSTSTORE_NO_SOCKET_CLASS),
]


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize(
    ("case", "shape", "verifying_classes", "missing"),
    SHAPE_REFUSALS,
    ids=[r[0] for r in SHAPE_REFUSALS],
)
def test_6267_truststore_without_the_0_10_5_shape_is_refused_within_a_bound(
    lab: Lab,
    good_server: LabServer,
    kind: str,
    case: str,
    shape: tuple[str, Any],
    verifying_classes: bool,
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    version, lock_factory = shape
    module = fake_truststore(version, lock_factory, verifying_classes=verifying_classes)
    monkeypatch.setitem(sys.modules, TRUSTSTORE_MODULE, module)
    verify, _ = _caller("truststore_fake", lab)
    with pytest.raises(ValueError) as info:
        _bounded(lambda: _construct_and_request(kind, good_server.url, verify))
    assert str(info.value) == MSG_TRUSTSTORE_SHAPE.format(
        kind=CALLER_KIND, version=version, missing=missing, floor=TRUSTSTORE_FLOOR
    ), case


@pytest.mark.parametrize("kind", CLIENT_KINDS)
def test_6267_truststore_with_the_0_10_5_shape_verifies_within_a_bound(
    lab: Lab, good_server: LabServer, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, TRUSTSTORE_MODULE, FAKE_CURRENT)
    verify, _ = _caller("truststore_fake", lab)
    body = _bounded(lambda: _construct_and_request(kind, good_server.url, verify))
    assert body == LAB_HEALTH_BODY
    with LabServer(lab.rogue) as rogue:
        with pytest.raises(TransportError) as info:
            _bounded(lambda: _construct_and_request(kind, rogue.url, verify))
        assert isinstance(info.value.__cause__, httpx.ConnectError)
        assert "CERTIFICATE_VERIFY_FAILED" in str(info.value)


# -- S-L1: weakened between the pre-check and SSL object creation --------------


def _c_weaken(ctx: Any) -> None:
    base: Any = ssl.SSLContext.__base__
    base.check_hostname.__set__(ctx, False)
    base.verify_mode.__set__(ctx, ssl.CERT_NONE)


def _weaken_inside(monkeypatch: pytest.MonkeyPatch, method: str, target: Any) -> list[int]:
    """Patch ``ssl.SSLContext.<method>`` so it weakens ``target`` just before the
    SSL object is created, i.e. after the SDK's pre-check has passed."""
    original = getattr(ssl.SSLContext, method)
    fired: list[int] = []

    def weakening(self: Any, *args: Any, **kwargs: Any) -> Any:
        if self is target:
            fired.append(1)
            _c_weaken(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, method, weakening)
    return fired


#: The sync client creates its SSL object with wrap_socket, the async one
#: (anyio) with wrap_bio.
WRAP_METHOD = {"sync": "wrap_socket", "async": "wrap_bio"}


@pytest.mark.parametrize("kind", CLIENT_KINDS)
@pytest.mark.parametrize("caller_path", CALLER_PATHS, indirect=True)
def test_6306_state_weakened_after_the_pre_check_never_completes_a_handshake(
    lab: Lab, caller_path: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if caller_path == "stdlib":
        verify: Any = str(lab.trusted_ca)
    else:
        verify = _caller(caller_path, lab)[0]
    with LabServer(lab.rogue) as rogue:
        client = _make(kind, rogue.url, verify=verify)
        try:
            fired = _weaken_inside(monkeypatch, WRAP_METHOD[kind], _owned(client))
            with pytest.raises(TransportError) as info:
                _health(client)
            assert isinstance(info.value.__cause__, httpx.ConnectError)
            assert MSG_USE_TIME in str(info.value), str(info.value)
            assert fired, "the weakening patch never ran"
        finally:
            monkeypatch.undo()
            _close(client)
        assert rogue.handshakes == 0
