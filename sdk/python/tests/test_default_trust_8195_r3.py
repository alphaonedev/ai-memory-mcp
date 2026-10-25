"""The default trust path holds the TLS 1.2 floor, and a non-https base URL is refused (#8195 r3).

sec r2 F1: ``verify=None`` and ``verify=True`` handed httpx's own default context to the
transport, with no TLS 1.2 minimum, no request hooks and no session gate. On a host whose
OpenSSL policy permits TLS 1.1 the request, and the API key, went out over TLS 1.1.
sec r2 F2: an ``http://`` base URL was accepted and the key went out in plaintext.
"""
from __future__ import annotations

import json
import os
import pathlib
import ssl
import subprocess
import sys

import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _common

_CLIENTS = [AiMemoryClient, AsyncAiMemoryClient]
_SDK = pathlib.Path(__file__).resolve().parents[1]
_CHILD = pathlib.Path(__file__).with_name("_default_trust_child_8195.py")
_PLACEHOLDER_KEY = "placeholder-not-a-credential-8195"
_LOW_SECURITY_CONF = (
    "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n"
    "[ssl_sect]\nsystem_default = system_default_sect\n"
    "[system_default_sect]\nCipherString = DEFAULT:@SECLEVEL=0\n"
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


def _build(client_cls: type, verify: object) -> object:
    return client_cls(base_url="https://localhost:9077", verify=verify, api_key=_PLACEHOLDER_KEY)


def _close(client: object) -> None:
    if isinstance(client, AiMemoryClient):
        client.close()
    else:
        import asyncio

        asyncio.run(client.aclose())  # type: ignore[attr-defined]


# ---- sec r2 F1 -----------------------------------------------------------------------


@pytest.mark.parametrize("verify", [None, True], ids=["none", "true"])
def test_default_trust_kwargs_carry_a_floored_context_with_hooks_8195(verify: object) -> None:
    kwargs = _common.build_httpx_kwargs(
        base_url="https://localhost:9077",
        api_key=None,
        agent_id=None,
        timeout=1.0,
        verify=verify,  # type: ignore[arg-type]
        cert=None,
        extra_headers=None,
    )
    context = kwargs.get("verify")
    assert isinstance(context, ssl.SSLContext)
    assert ssl.SSLContext.minimum_version.__get__(context) >= ssl.TLSVersion.TLSv1_2  # type: ignore[attr-defined]
    assert kwargs.get("event_hooks"), "the per-request re-check is installed for the default context"
    assert _common._context_verifies(context) is True  # noqa: SLF001


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("verify", [None, True], ids=["none", "true"])
def test_default_trust_transport_is_session_gated_8195(client_cls: type, verify: object) -> None:
    client = _build(client_cls, verify)
    try:
        transport = client._client._transport  # type: ignore[attr-defined]  # noqa: SLF001
        gated = _common._AsyncGatedTransport if client_cls is AsyncAiMemoryClient else _common._GatedTransport  # noqa: SLF001
        assert isinstance(transport, gated)
    finally:
        _close(client)


@pytest.mark.parametrize("verify", [None, True], ids=["none", "true"])
def test_default_trust_is_a_modern_context_even_if_the_library_default_is_lower_8195(
    monkeypatch: pytest.MonkeyPatch, verify: object
) -> None:
    """The floor is the builder's own assignment, not an inherited library default."""
    seen: list[ssl.TLSVersion] = []
    original = _common._pinned_base_context  # noqa: SLF001

    def spy() -> ssl.SSLContext:
        context = original()
        seen.append(ssl.SSLContext.minimum_version.__get__(context))  # type: ignore[attr-defined]
        return context

    monkeypatch.setattr(_common, "_pinned_base_context", spy)
    _common.build_httpx_kwargs(
        base_url="https://localhost:9077",
        api_key=None,
        agent_id=None,
        timeout=1.0,
        verify=verify,  # type: ignore[arg-type]
        cert=None,
        extra_headers=None,
    )
    assert seen, "the default context is built through the shared builder"
    assert all(version >= ssl.TLSVersion.TLSv1_2 for version in seen)


def test_default_trust_sends_nothing_over_tls_1_1_8195(tmp_path: pathlib.Path) -> None:
    """Reproduces sec r2 probe default_verify_probe.py: a TLS 1.1-only origin under SECLEVEL 0."""
    conf = tmp_path / "lowsec-openssl.cnf"
    conf.write_text(_LOW_SECURITY_CONF, encoding="utf-8")
    env = dict(os.environ, OPENSSL_CONF=str(conf), TMPDIR=str(tmp_path))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, "-I", "-W", "ignore", str(_CHILD), str(_SDK), str(tmp_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-400:]
    rows = {row["form"]: row for row in map(json.loads, done.stdout.splitlines())}
    if "setup" in rows:
        pytest.skip("this OpenSSL cannot serve TLS 1.1 even at SECLEVEL 0")
    for form in ("none", "true", "ca-path", "default-context"):
        assert form in rows, done.stdout
        assert rows[form]["api_key"] is False, f"{form}: the key reached a TLS 1.1 origin"
        assert rows[form]["outcome"] != "SENT-OK", f"{form}: the request went out over {rows[form]['versions']}"


# ---- sec r2 F2 -----------------------------------------------------------------------

_NOT_HTTPS = {
    "http": "http://localhost:9077",
    "http-upper": "HTTP://localhost:9077",
    "http-loopback-ip": "http://127.0.0.1:9077",
    "ftp": "ftp://localhost:9077",
    "no-scheme": "localhost:9077",
    "empty": "",
}


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", _NOT_HTTPS.values(), ids=_NOT_HTTPS.keys())
def test_non_https_base_url_is_refused_at_construction_8195(client_cls: type, base_url: str) -> None:
    with pytest.raises(ValueError, match="https") as refused:
        client_cls(base_url=base_url, api_key=_PLACEHOLDER_KEY, verify=None)
    assert _PLACEHOLDER_KEY not in str(refused.value)


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_refusal_names_the_scheme_and_never_the_key_or_host_8195(client_cls: type) -> None:
    with pytest.raises(ValueError) as refused:
        client_cls(base_url="http://user:secretpass@example.invalid:9077", api_key=_PLACEHOLDER_KEY)
    text = str(refused.value)
    assert "'http'" in text
    assert _PLACEHOLDER_KEY not in text
    assert "secretpass" not in text
    assert "example.invalid" not in text


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("base_url", ["https://localhost:9077", "HTTPS://localhost:9077/"], ids=["lower", "upper"])
def test_https_base_url_is_still_admitted_8195(client_cls: type, base_url: str) -> None:
    client = client_cls(base_url=base_url, api_key=_PLACEHOLDER_KEY)
    _close(client)
