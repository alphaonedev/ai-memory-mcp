"""Kill tests for surviving #6964 redaction mutants R33 R34 R35 R41 (round-8 security review).

Run from sdk/python with the repo layout around it: python -m pytest -q <this file>
"""

import base64
import importlib.util
import io
import pathlib
import sys

KEY = bytes(range(40, 72))  # 32 bytes: base64 ends in one '='
PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    + base64.encodebytes(bytes(range(100, 221)))
    + b"-----END PRIVATE KEY-----\n"
)
HARNESS = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "sdk-python-live.py"


def _h():
    spec = importlib.util.spec_from_file_location("harness_pins", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(h, code, secrets):
    sink = io.StringIO()
    old, sys.stdout = sys.stdout, sink
    try:
        h.run_redacted([sys.executable, "-c", code], cwd=".", env=None, secrets=secrets)
    finally:
        sys.stdout = old
    return sink.getvalue()


def test_unpadded_base64_is_redacted():  # R33
    h = _h()
    form = base64.b64encode(KEY).decode().rstrip("=")
    assert form != base64.b64encode(KEY).decode()
    out = _run(h, f"print('x {form} y')", [KEY])
    assert form not in out


def test_a_single_pem_body_line_is_redacted():  # R34
    h = _h()
    line = PEM.splitlines()[1].decode()
    out = _run(h, f"print('x {line} y')", [PEM])
    assert line not in out


def test_a_key_split_across_two_writes_is_redacted():  # R35
    h = _h()
    hx = KEY.hex()
    code = (
        "import sys, time\n"
        f"sys.stdout.write('a' * 70000 + {hx[:30]!r}); sys.stdout.flush(); time.sleep(0.3)\n"
        f"sys.stdout.write({hx[30:]!r} + ' tail' * 10); sys.stdout.flush()\n"
    )
    out = _run(h, code, [KEY])
    assert hx not in out


def test_a_key_at_the_very_end_of_the_output_is_redacted():  # R41
    h = _h()
    hx = KEY.hex()
    out = _run(h, f"import sys; sys.stdout.write({hx!r})", [KEY])
    assert hx not in out
