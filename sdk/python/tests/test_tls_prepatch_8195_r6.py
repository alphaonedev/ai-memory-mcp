"""A verification attribute replaced BEFORE ``ai_memory`` is imported is still refused (#8195 round 6, ``code r5 F2``).

``_STOCK_HANDSHAKE`` is captured at import, so a ``verify_mode``, ``check_hostname`` or ``verify_flags``
property replaced before that import counts as stock. A context whose C object is ``CERT_NONE``, has the
hostname check off, or carries ``NO_CHECK_TIME`` while the replaced property reports the strong value was
ADMITTED at construction. Each form runs in a fresh interpreter so the import order is real.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
_CHILD = _TESTS / "_prepatch_verify_child_8195.py"


@pytest.mark.parametrize("attr", ["verify_mode", "verify_mode_optional", "check_hostname", "verify_flags"])
def test_verification_attribute_replaced_before_import_is_refused_8195(attr: str) -> None:
    env = dict(os.environ, PYTHONPATH=str(_SDK))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, str(_CHILD), attr], capture_output=True, text=True, env=env, timeout=120, check=False
    )
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith("outcome=")]
    assert len(lines) == 1, f"child rc {done.returncode}: {done.stderr[-300:]}"
    assert lines[0] == "outcome=REFUSED-ValueError"
