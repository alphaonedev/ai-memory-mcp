"""#7062: a read boundary inside a secret form must not leak either side of it.

``run_redacted`` redacted the pending text before holding the tail back, so a
form split across two reads lost its leading half to the emitted prefix and the
trailing part (up to 11 characters, less than one ``_WINDOW``) was written
verbatim. Every split offset across a hex key and across a PEM body line is
pinned. Run from sdk/python: python -m pytest -q <this file>
"""

import base64
import importlib.util
import io
import pathlib
import sys

import pytest

KEY = bytes(range(40, 72))
PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    + base64.encodebytes(bytes(range(100, 221)))
    + b"-----END PRIVATE KEY-----\n"
)
HARNESS = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "sdk-python-live.py"
HEX = KEY.hex()
PEM_LINE = PEM.splitlines()[1].decode()


def _h():
    spec = importlib.util.spec_from_file_location("harness_stream_7062", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _split_run(h, form, cut, secret):
    code = (
        "import sys, time\n"
        f"sys.stdout.write('a' * 70000 + {form[:cut]!r}); sys.stdout.flush(); time.sleep(0.1)\n"
        f"sys.stdout.write({form[cut:]!r} + ' tail' * 10); sys.stdout.flush()\n"
    )
    sink, old = io.StringIO(), sys.stdout
    sys.stdout = sink
    try:
        h.run_redacted([sys.executable, "-c", code], cwd=".", env=None, secrets=[secret])
    finally:
        sys.stdout = old
    return sink.getvalue()


def _no_fragment_of(form, out, length=4):
    """No run of ``length`` or more consecutive characters of ``form`` survives in ``out``."""
    return not any(form[i : i + length] in out for i in range(len(form) - length + 1))


@pytest.mark.parametrize("cut", range(1, len(HEX)))
def test_7062_hex_key_split_at_every_offset_leaks_nothing(cut):
    out = _split_run(_h(), HEX, cut, KEY)
    assert _no_fragment_of(HEX, out), f"a fragment of the key survived a read boundary at {cut}"


@pytest.mark.parametrize("cut", range(1, len(PEM_LINE)))
def test_7062_pem_body_line_split_at_every_offset_leaks_nothing(cut):
    out = _split_run(_h(), PEM_LINE, cut, PEM)
    assert _no_fragment_of(PEM_LINE, out), (
        f"a fragment of the PEM line survived a read boundary at {cut}"
    )
