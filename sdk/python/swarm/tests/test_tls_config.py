from __future__ import annotations

import ssl
from unittest.mock import patch

import certifi
from ai_memory import AsyncAiMemoryClient

from swarm.config import SwarmConfig
from swarm.tls import client_kwargs


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


def test_cert_kwargs_reach_httpx_async_client() -> None:
    # #6248: the SDK forwards a context it builds from the CA path, never the
    # path object itself, so the CA must be a real bundle.
    kwargs = client_kwargs(
        {
            "SWARM_CLIENT_CERT": "client.crt",
            "SWARM_CLIENT_KEY": "client.key",
            "SWARM_CA_CERT": certifi.where(),
        }
    )
    with patch("ai_memory.async_client.httpx.AsyncClient") as constructor:
        AsyncAiMemoryClient(base_url="https://daemon.invalid", **kwargs)
    assert constructor.call_args.kwargs["cert"] == ("client.crt", "client.key")
    assert isinstance(constructor.call_args.kwargs["verify"], ssl.SSLContext)
