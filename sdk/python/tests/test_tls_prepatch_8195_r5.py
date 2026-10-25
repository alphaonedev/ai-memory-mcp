"""A TLS bound replaced BEFORE ``ai_memory`` is imported is still refused (#8195 round 5, ``code r4 F3``).

``_STOCK_HANDSHAKE`` is captured at import, so a ``minimum_version`` / ``maximum_version`` descriptor
replaced before that import passes the stock-identity leg of ``_context_verifies``. The
``isinstance(..., ssl.TLSVersion)`` check in ``_tls_range_is_modern`` is then the only refusal: it
turns an ``int`` 771 (numerically TLS 1.2), a ``str`` or ``None`` bound into the typed ``ValueError``
instead of an admitted context or an untyped ``TypeError``. This file kills mutant M66; it reruns
the child in a fresh interpreter so the import order is real.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
_CHILD = _TESTS / "_prepatch_child_8195.py"


def _outcome(attr: str, kind: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(_SDK))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, str(_CHILD), attr, kind], capture_output=True, text=True, env=env, timeout=120, check=False
    )
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith("outcome=")]
    assert len(lines) == 1, f"child rc {done.returncode}: {done.stderr[-300:]}"
    return lines[0]


@pytest.mark.parametrize("kind", ["int-771", "str", "none"])
@pytest.mark.parametrize("attr", ["minimum_version", "maximum_version"])
def test_bound_replaced_before_import_is_refused_with_the_typed_error_8195(attr: str, kind: str) -> None:
    assert _outcome(attr, kind) == "outcome=REFUSED-ValueError"
