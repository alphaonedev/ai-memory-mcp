"""#7056: renderings of a key that the form list did not enumerate, including the one the
harness's own UTF-8 ``errors="replace"`` decoder produces from raw key bytes.

Run from sdk/python: python -m pytest -q <this file>
"""

import base64
import importlib.util
import io
import json
import pathlib
import sys
import urllib.parse

import pytest

HARNESS = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "sdk-python-live.py"
KEY = bytes(range(130, 162))  # 32 bytes, all >= 0x80: invalid UTF-8
# An EC private-key DER shape: the 32-byte scalar sits behind 04 20.
SCALAR = bytes((i * 7 + 3) % 256 for i in range(32))
DER = (
    b"\x30\x41\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x04\x20"
    + SCALAR
    + b"\xa1\x44"
)
PEM = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(DER) + b"-----END PRIVATE KEY-----\n"

RENDERINGS = {
    "utf8-replace": lambda b: b.decode("utf-8", "replace"),
    "utf8-backslashreplace": lambda b: b.decode("utf-8", "backslashreplace"),
    "hex-space": lambda b: b.hex(" "),
    "hex-hyphen": lambda b: b.hex("-"),
    "hex-little-endian": lambda b: b[::-1].hex(),
    "decimal-big": lambda b: str(int.from_bytes(b, "big")),
    "decimal-little": lambda b: str(int.from_bytes(b, "little")),
    "base32-lower": lambda b: base64.b32encode(b).decode().lower(),
    "base85": lambda b: base64.b85encode(b).decode(),
    "ascii85": lambda b: base64.a85encode(b).decode(),
    "json-latin1": lambda b: json.dumps(b.decode("latin-1"))[1:-1],
    "url-quoted": lambda b: urllib.parse.quote(b),
    "uniform-backslash-x": lambda b: "".join(f"\\x{c:02x}" for c in b),
    "base64-shift-1": lambda b: base64.b64encode(b[1:]).decode(),
    "base64-shift-2": lambda b: base64.b64encode(b[2:]).decode(),
}


def _h():
    spec = importlib.util.spec_from_file_location("harness_enc_7056", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _longest_run(form, out):
    best = 0
    for i in range(len(form)):
        n = best + 1
        while i + n <= len(form) and form[i : i + n] in out:
            best = n
            n += 1
    return best


@pytest.mark.parametrize("name", sorted(RENDERINGS))
def test_7056_every_rendering_of_a_key_is_redacted(name):
    h = _h()
    form = RENDERINGS[name](KEY)
    out = h.redact("err: " + form + " :end", h.secret_forms(KEY))
    assert _longest_run(form, out) < 12, (
        f"{name}: a run of {_longest_run(form, out)} characters survived"
    )


@pytest.mark.parametrize(
    "name", ["decimal-big", "decimal-little", "utf8-replace", "hex-space", "base64-shift-1"]
)
def test_7056_the_ec_scalar_inside_a_pem_is_redacted(name):
    h = _h()
    form = RENDERINGS[name](SCALAR)
    out = h.redact("err: " + form + " :end", h.secret_forms(PEM))
    assert _longest_run(form, out) < 12, (
        f"{name}: a run of {_longest_run(form, out)} characters survived"
    )


def test_7056_raw_key_bytes_on_the_childs_stdout_leave_no_replace_decoded_run():
    h = _h()
    code = f"import sys; sys.stdout.buffer.write(b'x ' + {KEY!r} + b' y'); sys.stdout.flush()"
    sink, old = io.StringIO(), sys.stdout
    sys.stdout = sink
    try:
        h.run_redacted([sys.executable, "-c", code], cwd=".", env=None, secrets=[KEY])
    finally:
        sys.stdout = old
    form = KEY.decode("utf-8", "replace")
    assert _longest_run(form, sink.getvalue()) < 12


def test_7056_the_daemon_key_is_a_run_secret(tmp_path):
    h = _h()
    files = {
        "signing": b"signing-key-bytes-0123456789",
        "tls": b"tls-key-bytes-abcdefghijklmnop",
        "daemon": b"daemon-key-bytes-QRSTUVWXYZ012",
    }
    paths = {}
    for name, data in files.items():
        paths[name] = tmp_path / f"{name}.key"
        paths[name].write_bytes(data)

    class Fake:
        signing_key = paths["signing"]
        daemon_key = paths["daemon"]

    assert sorted(h.run_secrets(Fake(), paths["tls"])) == sorted(files.values())
