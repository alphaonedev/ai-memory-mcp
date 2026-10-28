"""Round 7, code r6 F1: the REAL clients refuse a TLS 1.1 session whatever the session class reports (#8195).

The async client's session is an ``ssl.SSLObject`` made by ``SSLContext.wrap_bio`` of ``sslobject_class``;
both are replaceable before ``ai_memory`` is imported. Each row runs in a fresh interpreter against a
loopback origin that accepts TLS 1.1 only and counts the request bytes it receives; the construction and
per-request context predicates are switched off in the child so the post-handshake gate is the only defence.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
_LOWSEC = (
    "openssl_conf = default_conf\n[default_conf]\nssl_conf = ssl_sect\n[ssl_sect]\n"
    "system_default = sys_default_sect\n[sys_default_sect]\n"
    "CipherString = DEFAULT:@SECLEVEL=0\nMinProtocol = TLSv1\n"
)


@pytest.mark.parametrize("mode", ["sync-ctl", "async-ctl", "socklie", "objlie", "biolie", "biofake"])
def test_real_client_sends_nothing_over_a_tls_1_1_session_8195(
    mode: str, tmp_path: pathlib.Path
) -> None:
    conf = tmp_path / "lowsec.cnf"
    conf.write_text(_LOWSEC)
    scratch = tmp_path / "lab"
    scratch.mkdir()
    env = dict(os.environ, PYTHONPATH=str(_SDK), OPENSSL_CONF=str(conf))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, str(_TESTS / "_client_gate_child_8195.py"), str(_SDK), str(scratch), mode],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )
    lines = done.stdout.splitlines()
    if "handshake=none" in lines:
        pytest.skip("this OpenSSL build cannot negotiate TLS 1.1 at security level 0")
    assert "handshake=TLSv1.1" in lines, f"child rc {done.returncode}: {done.stderr[-300:]} {lines}"
    assert "request_bytes=0" in lines
    assert "outcome=REFUSED-ValueError" in lines
