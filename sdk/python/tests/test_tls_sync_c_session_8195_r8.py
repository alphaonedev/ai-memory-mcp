"""Round 8, code r7 F-A: the sync client admits the bare C ``_ssl._SSLSocket`` httpcore hands over (#8195).

httpcore's sync stream returns ``self._sock._sslobj`` as ``ssl_object``: the C object itself, which has no
``_sslobj`` attribute. The gate must read its facts from that object. These rows use no test seam: the
session is a real handshake on a loopback origin, for TLS 1.2 and TLS 1.3, on both clients.
"""
from __future__ import annotations

import asyncio
import ssl

import pytest

from ai_memory import AiMemoryClient, AsyncAiMemoryClient, _common

from ._tlslab import Lab, RecordingServer

_VERSIONS = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]


@pytest.fixture
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return Lab(tmp_path_factory.mktemp("lab8195r8"))


def _origin(lab: Lab, version: ssl.TLSVersion) -> RecordingServer:
    server = lab.server_context("localhost")
    server.minimum_version = version
    server.maximum_version = version
    return RecordingServer(server)


@pytest.mark.parametrize("version", _VERSIONS, ids=lambda v: v.name)
def test_sync_client_completes_over_a_verified_session_8195(
    lab: Lab, version: ssl.TLSVersion
) -> None:
    origin = _origin(lab, version)
    try:
        with AiMemoryClient(base_url=origin.url, verify=lab.client_context(), timeout=5) as client:
            response = client._client.get("/a")  # noqa: SLF001
        assert response.status_code == 200
        assert origin.hits == ["/a"]
    finally:
        origin.close()


@pytest.mark.parametrize("version", _VERSIONS, ids=lambda v: v.name)
def test_async_client_completes_over_a_verified_session_8195(
    lab: Lab, version: ssl.TLSVersion
) -> None:
    origin = _origin(lab, version)

    async def go() -> int:
        async with AsyncAiMemoryClient(
            base_url=origin.url, verify=lab.client_context(), timeout=5
        ) as client:
            return (await client._client.get("/a")).status_code  # noqa: SLF001

    try:
        assert asyncio.run(go()) == 200
        assert origin.hits == ["/a"]
    finally:
        origin.close()


def test_c_session_object_is_its_own_c_object_8195() -> None:
    raw = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO())._sslobj  # noqa: SLF001
    assert type(raw) is _common._C_SSLOBJ  # noqa: SLF001
    assert _common._c_sslobj(raw) is raw  # noqa: SLF001
    assert _common._c_sslobj(object()) is None  # noqa: SLF001


def test_stand_in_seam_never_reads_the_real_c_session_8195(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Code r7 F-B: the test seam must defer to the production reader for a real C session."""
    from . import _fake_session_8195

    _fake_session_8195.install(monkeypatch)
    raw = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO())._sslobj  # noqa: SLF001
    assert not isinstance(_common._session_facts(raw), _fake_session_8195._Facts)  # noqa: SLF001
