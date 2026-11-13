"""Round 7: the C bound descriptor is matched by identity, and the negotiated session is read through C (#8195).

``sec r6 S1``: a Python class named ``getset_descriptor`` was accepted as the genuine C getset.
``sec r6 S1-wire``: ``version()`` read through a replaceable Python socket class let a TLS 1.1 session
through the post-handshake gate. Each form runs in a fresh interpreter so the import order is real.
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


def _run(args: "list[str]", **extra: str) -> "tuple[list[str], int, str]":
    env = dict(os.environ, PYTHONPATH=str(_SDK), **extra)
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, *args], capture_output=True, text=True, env=env, timeout=180, check=False
    )
    return done.stdout.splitlines(), done.returncode, done.stderr[-300:]


@pytest.mark.parametrize("attr", ["minimum_version", "maximum_version"])
def test_forged_getset_descriptor_class_is_refused_8195(attr: str) -> None:
    lines, rc, err = _run([str(_TESTS / "_prepatch_getset_child_8195.py"), attr])
    outcome = [ln for ln in lines if ln.startswith("outcome=")]
    assert len(outcome) == 1, f"child rc {rc}: {err}"
    assert "forgery is genuine getset type: False" in lines
    assert outcome[0] == "outcome=REFUSED-ValueError"


@pytest.mark.parametrize("mode", ["plain", "socklie", "peerlie", "cipherlie", "ctxlie", "leaflie"])
def test_tls_1_1_wire_session_is_refused_even_with_a_lying_socket_class_8195(
    mode: str, tmp_path: pathlib.Path
) -> None:
    conf = tmp_path / "lowsec.cnf"
    conf.write_text(_LOWSEC)
    scratch = tmp_path / "lab"
    scratch.mkdir()
    lines, rc, err = _run(
        [str(_TESTS / "_wire_gate_child_8195.py"), str(_SDK), str(scratch), mode],
        OPENSSL_CONF=str(conf),
    )
    if "handshake=FAILED" in lines and mode in ("plain", "cipherlie"):
        pytest.skip("this OpenSSL build cannot negotiate the weak session at security level 0")
    gate = [ln for ln in lines if ln.startswith("GATE=")]
    assert len(gate) == 1, f"child rc {rc}: {err} {lines}"
    assert gate[0] == "GATE=REFUSED-ValueError"


def test_getset_type_is_the_builtin_identity_and_resolves_the_real_bounds_8195() -> None:
    import _ssl

    from ai_memory import _common

    real = _ssl._SSLContext.__dict__["minimum_version"]  # noqa: SLF001
    assert _common._GETSET is type(real)  # noqa: SLF001
    assert _common._C_MIN_VERSION is real  # noqa: SLF001
    forged = type("getset_descriptor", (), {})()
    assert type(forged).__name__ == "getset_descriptor"
    assert type(forged) is not _common._GETSET  # noqa: SLF001


class _StandInSession:
    """A Python object that carries a ``_sslobj`` which is not the C type."""

    _sslobj = object()


def test_session_without_a_c_sslobj_is_refused_8195() -> None:
    import ssl

    from ai_memory import _common

    assert _common._c_sslobj(_StandInSession()) is None  # noqa: SLF001
    assert _common._c_sslobj(None) is None  # noqa: SLF001
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="verify=False"):
        _common._assert_negotiated_session(_StandInSession(), context, "x")  # noqa: SLF001


def test_c_sslobj_is_read_past_a_getattribute_override_8195() -> None:
    import ssl

    from ai_memory import _common

    class _Liar(ssl.SSLObject):
        def __getattribute__(self, name: str) -> object:
            if name == "_sslobj":
                return _StandInSession()
            return super().__getattribute__(name)

    context = ssl.create_default_context()
    context.sslobject_class = _Liar  # type: ignore[assignment]
    session = context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="x")
    assert type(session) is _Liar
    assert type(_common._c_sslobj(session)) is _common._C_SSLOBJ  # noqa: SLF001
