from __future__ import annotations

import ssl
from pathlib import Path
from unittest.mock import patch

from ai_memory import AsyncAiMemoryClient
from swarm.config import SwarmConfig
from swarm.tls import client_kwargs
from tests._tlslab_6249 import build_lab


def test_config_parses_mtls_and_api_key() -> None:
    config = SwarmConfig.from_env(
        {
            "SWARM_CLIENT_CERT": "/bundle/client.crt",
            "SWARM_CLIENT_KEY": "/bundle/client.key",
            "SWARM_CA_CERT": "/bundle/ca.crt",
            "SWARM_API_KEY": "secret",
        }
    )
    assert config.daemon_client_kwargs() == {
        "cert": ("/bundle/client.crt", "/bundle/client.key"),
        "verify": "/bundle/ca.crt",
        "api_key": "secret",
    }


def test_cert_kwargs_reach_httpx_async_client(tmp_path: Path) -> None:
    """The swarm's mTLS env reaches httpx as ONE SDK-owned context (#6249).

    ``verify`` is the frozen context the SDK built from the CA path, with
    the client certificate loaded into it; ``cert`` is never forwarded.
    """
    from ai_memory._tls import OwnedTLSContext

    lab = build_lab(tmp_path / "lab")
    kwargs = client_kwargs(
        {
            "SWARM_CLIENT_CERT": str(lab.client[0]),
            "SWARM_CLIENT_KEY": str(lab.client[1]),
            "SWARM_CA_CERT": str(lab.trusted_ca),
        }
    )
    with patch("ai_memory.async_client.httpx.AsyncClient") as constructor:
        AsyncAiMemoryClient(base_url="https://daemon.invalid", **kwargs)
    passed = constructor.call_args.kwargs
    assert "cert" not in passed
    assert isinstance(passed["verify"], OwnedTLSContext)
    assert passed["verify"].verify_mode == ssl.CERT_REQUIRED
    assert passed["verify"].check_hostname is True
