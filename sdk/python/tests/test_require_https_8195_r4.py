"""Base-URL parsing, probe hygiene and doc truth for the SDK TLS enforcement (#8195 round 4).

``sec r3 F1`` / ``sec r3 F2`` / ``code r3 F6`` / ``code r3 F7`` / ``code r3 F8``: the https check
parses with the same parser the client sends with (``httpx.URL``), the refusal never echoes a
part of the URL, the TLS-1.1 probe prints no credential-named field, and the docs describe the
default trust the SDK now builds.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import random
import re
import time

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


# ---- sec r3 F2: one parser for the check and the send (bounded property test) ----------

_ALPHABET = list("abcHTPS:/@.[]?#% \t\n\r\x00-1239") + ["https", "://", "http", "user", "localhost"]
_SEED = 8195
_CASES = 3000
_BUDGET_SECONDS = 2.0


def test_check_and_send_parsers_agree_on_generated_inputs_8195() -> None:
    rng = random.Random(_SEED)
    started = time.monotonic()
    for _ in range(_CASES):
        text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 9)))
        try:
            _common._require_https(text)  # noqa: SLF001
        except ValueError:
            continue
        url = httpx.URL(text)  # a check that admitted it must leave the sender able to parse it
        assert url.scheme == "https", repr(text)
        assert url.host, repr(text)
        assert not url.userinfo, repr(text)
    assert time.monotonic() - started <= _BUDGET_SECONDS


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
