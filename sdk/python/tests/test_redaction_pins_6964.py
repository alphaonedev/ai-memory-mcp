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


def test_a_key_at_the_very_end_of_the_output_is_redacted():
    # Not an R41 killer (#7065): every output here is already redacted before the final flush.
    h = _h()
    hx = KEY.hex()
    out = _run(h, f"import sys; sys.stdout.write({hx!r})", [KEY])
    assert hx not in out


def test_the_final_decoder_flush_is_redacted():  # R41 (#7065)
    """The final decode can add U+FFFD; a form that ends in it matches only after that flush."""
    h = _h()
    secret = b"0123456789A\xef\xbf\xbd"  # 14 bytes, valid UTF-8, ends in U+FFFD
    out = _run(
        h, "import sys; sys.stdout.buffer.write(b'0123456789A\\xef'); sys.stdout.flush()", [secret]
    )
    assert secret.decode("utf-8") not in out
    assert "\ufffd" not in out


def test_the_upper_case_hex_form_of_a_key_is_redacted():  # W4 (#7066)
    h = _h()
    upper = KEY.hex().upper()
    assert upper != KEY.hex()
    out = h.redact("err: " + upper + "\n", h.secret_forms(KEY))
    assert not any(upper[i : i + 6] in out for i in range(len(upper) - 5))
    assert upper in h.secret_forms(KEY)


SHORT = b"Zk3!pQ9x"  # 8 bytes: long enough to be a secret, too short for a 12-character window
STACK_KEYS = (b"signing-key-bytes-0123456789", b"tls-key-bytes-abcdefghijklmnop")


def test_a_secret_shorter_than_a_window_is_redacted_as_an_exact_form():  # R38
    h = _h()
    out = _run(h, f"print('x {SHORT.decode()} y')", [SHORT])
    assert SHORT.decode() not in out


def test_unpadded_base64_of_a_short_secret_is_redacted():  # R33 (window cannot cover it)
    h = _h()
    padded = base64.b64encode(SHORT).decode()
    form = padded.rstrip("=")
    assert form != padded and len(form) < 12
    out = _run(h, f"print('x {form} y')", [SHORT])
    assert form not in out


def test_a_short_secret_split_across_two_writes_is_redacted():  # R35 (window cannot cover it)
    h = _h()
    s = SHORT.decode()
    code = (
        "import sys, time\n"
        f"sys.stdout.write('a' * 70000 + {s[:4]!r}); sys.stdout.flush(); time.sleep(0.3)\n"
        f"sys.stdout.write({s[4:]!r} + ' tail' * 10); sys.stdout.flush()\n"
    )
    out = _run(h, code, [SHORT])
    assert s not in out
    assert s[:4] not in out and s[4:] not in out


def test_the_run_secrets_are_the_signing_key_the_daemon_key_and_the_tls_key(tmp_path):  # R36 R37
    h = _h()
    signing = tmp_path / "agent.priv"
    daemon = tmp_path / "daemon.priv"
    tls = tmp_path / "tls.key"
    signing.write_bytes(STACK_KEYS[0])
    daemon.write_bytes(b"daemon-key-bytes-QRSTUVWXYZ012")
    tls.write_bytes(STACK_KEYS[1])

    class Fake:
        signing_key = signing
        daemon_key = daemon

    assert sorted(h.run_secrets(Fake(), tls)) == sorted([*STACK_KEYS, daemon.read_bytes()])
