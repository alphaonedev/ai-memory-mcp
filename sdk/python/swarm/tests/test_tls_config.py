from __future__ import annotations

import datetime
import pathlib
import ssl
from unittest.mock import patch

from ai_memory import AsyncAiMemoryClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


def _write_ca(path: pathlib.Path, common_name: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_cert_kwargs_reach_httpx_async_client(tmp_path: pathlib.Path) -> None:
    # #6248 / #6272: the SDK forwards a context it builds from the CA path, so
    # the forwarded context must trust EXACTLY SWARM_CA_CERT. A bare
    # isinstance check passed when tls.py ignored the env var and fell back to
    # the platform store or certifi.
    ca = tmp_path / "swarm-ca.pem"
    _write_ca(ca, "swarm-test-ca-6272")
    kwargs = client_kwargs(
        {
            "SWARM_CLIENT_CERT": "client.crt",
            "SWARM_CLIENT_KEY": "client.key",
            "SWARM_CA_CERT": str(ca),
        }
    )
    with patch("ai_memory.async_client.httpx.AsyncClient") as constructor:
        AsyncAiMemoryClient(base_url="https://daemon.invalid", **kwargs)
    assert constructor.call_args.kwargs["cert"] == ("client.crt", "client.key")
    context = constructor.call_args.kwargs["verify"]
    assert isinstance(context, ssl.SSLContext)
    trusted = context.get_ca_certs()
    assert len(trusted) == 1
    assert dict(item[0] for item in trusted[0]["subject"])["commonName"] == "swarm-test-ca-6272"
