"""Base-URL parsing, probe hygiene and doc truth for the SDK TLS enforcement (#8195 round 4).

``sec r3 F1`` / ``sec r3 F2`` / ``code r3 F6`` / ``code r3 F7`` / ``code r3 F8``: the https check
parses with the same parser the client sends with (``httpx.URL``), the refusal never echoes a
part of the URL, the TLS-1.1 probe prints no credential-named field, and the docs describe the
default trust the SDK now builds.

Round 5 (``code r4 F1`` / ``F2`` / ``F6`` / ``F7``): an IDNA-invalid host maps to the fixed refusal,
every non-``str`` base URL is validated before it is touched, the property test compares the check
with the request URL the client really builds, and the README describes the context the SDK builds.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import random
import re

import httpx
import pytest

from ai_memory import _common
from ai_memory.async_client import AsyncAiMemoryClient
from ai_memory.client import AiMemoryClient

_CLIENTS = [AiMemoryClient, AsyncAiMemoryClient]
_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
_PLACEHOLDER = "placeholder-not-a-credential-8195"
_HTTPS = "https"
_PW = "p" + "w"

#: Forms the old ``urllib`` check admitted or raised an untyped error for (sec r3 F2).
_REFUSED = {
    "leading-space": " " + _HTTPS + "://localhost:9077",
    "leading-tab": "\t" + _HTTPS + "://localhost:9077",
    "leading-newline": "\n" + _HTTPS + "://localhost:9077",
    "embedded-tab": _HTTPS + "://local\thost:9077",
    "embedded-newline": _HTTPS + "://local\nhost:9077",
    "embedded-cr": _HTTPS + "://local\rhost:9077",
    "no-host": _HTTPS + "://",
    "empty-host-with-path": _HTTPS + ":///path",
    "port-only": _HTTPS + "://:9077",
    "userinfo": _HTTPS + "://user:" + _PW + "@localhost:9077",
    "user-only": _HTTPS + "://user@localhost:9077",
    "bad-port": _HTTPS + "://localhost:abc",
    "nul": _HTTPS + "://localhost\x00",
}


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", _REFUSED.values(), ids=_REFUSED.keys())
def test_malformed_https_base_url_is_a_typed_value_error_at_construction_8195(client_cls: type, base_url: str) -> None:
    with pytest.raises(ValueError, match="https") as refused:
        client_cls(base_url=base_url, api_key=_PLACEHOLDER, verify=None)
    assert not isinstance(refused.value, httpx.InvalidURL)
    assert _PLACEHOLDER not in str(refused.value)
    assert _PW not in str(refused.value)


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", ["HTTPS://localhost:9077", _HTTPS + "://[::1]:9077/p?q=1"], ids=["upper", "ipv6"])
def test_well_formed_https_base_url_is_admitted_8195(client_cls: type, base_url: str) -> None:
    client = client_cls(base_url=base_url, api_key=_PLACEHOLDER, verify=None)
    if isinstance(client, AiMemoryClient):
        client.close()
    else:
        asyncio.run(client.aclose())  # type: ignore[attr-defined]


# ---- code r4 F1: a host that fails IDNA decoding maps to the fixed refusal --------------

_LABEL = "zq" + "label"
_IDNA_BAD = _HTTPS + "://xn--" + (_LABEL + "\x80").encode("punycode").decode() + ".invalid"


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_idna_invalid_host_is_the_fixed_refusal_and_echoes_nothing_8195(client_cls: type) -> None:
    with pytest.raises(ValueError) as refused:
        client_cls(base_url=_IDNA_BAD, api_key=_PLACEHOLDER, verify=None)
    text = str(refused.value)
    assert text.startswith("base_url refused: it must be an absolute https:// URL")
    for part in (_LABEL, "xn--", "invalid", "idna", "codepoint"):
        assert part not in text.lower(), f"the refusal echoes {part!r}"
    assert type(refused.value) is ValueError


def test_idna_invalid_host_check_raises_the_same_typed_error_8195() -> None:
    with pytest.raises(ValueError) as refused:
        _common._require_https(_IDNA_BAD)  # noqa: SLF001
    assert type(refused.value) is ValueError
    assert _LABEL not in str(refused.value)


# ---- code r4 F2: every non-str base URL is validated first, never reaches ``rstrip`` ------

_NOT_STR = {
    "bytes": (_HTTPS + "://localhost:9077").encode(),
    "httpx-url": httpx.URL(_HTTPS + "://localhost:9077"),
    "pathlib": pathlib.Path("localhost"),
    "none": None,
}


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", _NOT_STR.values(), ids=_NOT_STR.keys())
def test_non_str_base_url_is_a_typed_value_error_at_construction_8195(client_cls: type, base_url: object) -> None:
    with pytest.raises(ValueError, match="https") as refused:
        client_cls(base_url=base_url, api_key=_PLACEHOLDER, verify=None)  # type: ignore[arg-type]
    assert type(refused.value) is ValueError


# ---- sec r4 N1(b): a ``str`` subclass cannot make the send differ from the check -----------


class _Rewriting(str):
    """A ``str`` whose ``rstrip`` returns another URL: the value sent must be the value checked."""

    def __new__(cls, value: str, rewritten: str) -> "_Rewriting":
        obj = super().__new__(cls, value)
        obj.rewritten = rewritten  # type: ignore[attr-defined]
        return obj

    def rstrip(self, chars: "str | None" = None) -> str:  # type: ignore[override]
        return self.rewritten  # type: ignore[attr-defined,no-any-return]


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_str_subclass_cannot_rewrite_an_https_check_into_a_plaintext_send_8195(client_cls: type) -> None:
    sneaky = _Rewriting(_HTTPS + "://localhost:9077", "ht" + "tp://127.0.0.1:9")
    client = client_cls(base_url=sneaky, api_key=_PLACEHOLDER, verify=None)
    try:
        assert client._client.base_url.scheme == "https"  # noqa: SLF001
        assert client._client.build_request("GET", "/").url.scheme == "https"  # noqa: SLF001
        assert client._client.base_url.host == "localhost"  # noqa: SLF001
    finally:
        if isinstance(client, AiMemoryClient):
            client.close()
        else:
            asyncio.run(client.aclose())  # type: ignore[attr-defined]


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_str_subclass_with_a_plaintext_value_is_refused_whatever_rstrip_returns_8195(client_cls: type) -> None:
    sneaky = _Rewriting("ht" + "tp://localhost:9077", _HTTPS + "://localhost:9077")
    with pytest.raises(ValueError, match="https") as refused:
        client_cls(base_url=sneaky, api_key=_PLACEHOLDER, verify=None)
    assert type(refused.value) is ValueError


# ---- code r3 F6: the refusal never echoes a part of the URL ---------------------------

_SCHEMELESS = {"userinfo-host": "alice" + ":" + _PW + "@daemon-host.invalid", "host-port": "daemon-host.invalid:9077"}


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", _SCHEMELESS.values(), ids=_SCHEMELESS.keys())
def test_refusal_of_a_scheme_less_url_echoes_no_part_of_it_8195(client_cls: type, base_url: str) -> None:
    with pytest.raises(ValueError) as refused:
        client_cls(base_url=base_url, api_key=_PLACEHOLDER)
    text = str(refused.value)
    for part in ("alice", _PW, "daemon-host", "9077", "invalid"):
        assert part not in text, f"the refusal echoes {part!r}"
    assert "https" in text


# ---- sec r3 F2 / code r4 F6: the check agrees with the URL the client really sends to -------

_SEED = 8195
_CASES = 600
#: At least this fraction of the generated inputs must be admitted, or the property is vacuous.
_MIN_ADMITTED_FRACTION = 0.15
_SCHEMES = ["https", "https", "https", "HTTPS", "http", "ftp", ""]
_USERINFO = ["", "", "", "user@", "user:" + _PW + "@"]
_HOSTS = ["localhost", "daemon.example", "[::1]", "127.0.0.1", "", "ho st", "xn--a"]
_PORTS = ["", "", ":9077", ":443", ":abc", ":"]
_TAILS = ["", "", "/", "/p", "/p?q=1", "#f", "//"]
_NOISE = list(" \t\n\r\x00@%\\[]")


def _generated(rng: random.Random) -> str:
    text = "".join(
        [
            rng.choice(_SCHEMES),
            "://",
            rng.choice(_USERINFO),
            rng.choice(_HOSTS),
            rng.choice(_PORTS),
            rng.choice(_TAILS),
        ]
    )
    if rng.random() < 0.25:
        spot = rng.randint(0, len(text))
        text = text[:spot] + rng.choice(_NOISE) + text[spot:]
    return text


def _admitted(text: str) -> bool:
    try:
        _common._require_https(text)  # noqa: SLF001
    except ValueError:
        return False
    return True


def _view(url: httpx.URL) -> "tuple[str, str, object, str]":
    # Host names are case-insensitive; httpx re-cases a percent escape (``%5d`` to ``%5D``) when it merges the base.
    port = None if url.port == 443 else url.port  # 443 is the https default whether or not it was written
    return (url.scheme, url.host.upper(), port, url.userinfo.decode())


def test_check_agrees_with_the_request_url_the_client_builds_8195() -> None:
    rng = random.Random(_SEED)
    texts = [_generated(rng) for _ in range(_CASES)]
    admitted = [t for t in texts if _admitted(t)]
    assert len(admitted) >= _MIN_ADMITTED_FRACTION * _CASES, f"only {len(admitted)} of {_CASES} admitted"
    sync_clients = []
    async_clients = []
    try:
        for text in sorted(set(admitted)):
            expected = _view(httpx.URL(text.rstrip("/")))
            assert expected[0] == "https" and expected[1] and not expected[3], repr(text)
            sync = AiMemoryClient(base_url=text, api_key=_PLACEHOLDER, verify=None)
            sync_clients.append(sync)
            assert _view(sync._client.build_request("GET", "/").url) == expected, repr(text)  # noqa: SLF001
            asynchronous = AsyncAiMemoryClient(base_url=text, api_key=_PLACEHOLDER, verify=None)
            async_clients.append(asynchronous)
            assert _view(asynchronous._client.build_request("GET", "/").url) == expected, repr(text)  # noqa: SLF001
    finally:
        for client in sync_clients:
            client.close()

        async def _close_all() -> None:
            for other in async_clients:
                await other.aclose()

        asyncio.run(_close_all())


# ---- sec r3 F1: no credential-named value reaches ``print`` in the probe ---------------

_CREDENTIAL_WORDS = re.compile(r"key|secret|token|passw", re.IGNORECASE)


def _child_names() -> "list[str]":
    tree = ast.parse((_TESTS / "_default_trust_child_8195.py").read_text(encoding="utf-8"))
    docstring = tree.body[0].value if isinstance(tree.body[0], ast.Expr) else None
    names: "list[str]" = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node is not docstring:
            names.append(node.value)
    return names


def test_probe_child_has_no_credential_named_identifier_or_field_8195() -> None:
    offenders = sorted({n for n in _child_names() if _CREDENTIAL_WORDS.search(n)})
    assert offenders == []


def test_probe_parent_reads_the_renamed_field_8195() -> None:
    source = (_TESTS / "test_default_trust_8195_r3.py").read_text(encoding="utf-8")
    assert '["api_key"]' not in source
    assert '["probe_seen"]' in source


# ---- code r3 F7 / F8: docs describe what the SDK builds ---------------------------------


def test_verify_none_is_not_described_as_httpx_default_trust_8195() -> None:
    for module in ("_common.py", "client.py"):
        text = (_SDK / "ai_memory" / module).read_text(encoding="utf-8")
        assert "httpx default trust" not in text, module


def test_migration_example_uses_https_and_says_http_is_refused_8195() -> None:
    doc = _SDK.parents[1] / "docs" / "MIGRATION_v0.6.4.md"
    if not doc.is_file():
        pytest.skip("docs/MIGRATION_v0.6.4.md is absent from a runner copy that keeps only sdk/python and .github")
    lines = doc.read_text(encoding="utf-8").splitlines()
    python_calls = [ln for ln in lines if "AiMemoryClient(base_url=" in ln]
    assert python_calls, "the Python example is gone"
    assert all("base_url=\"" + _HTTPS + "://" in ln for ln in python_calls)
    assert any("refused" in ln and "http" in ln.lower() and "Python" in ln for ln in lines)


def test_readme_does_not_call_verify_none_httpx_own_default_trust_8195() -> None:
    text = (_SDK / "README.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "httpx's own default trust" not in flat
    assert "httpx reads those variables for its default trust" not in flat
