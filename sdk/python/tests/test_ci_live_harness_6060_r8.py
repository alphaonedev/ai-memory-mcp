# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The sdk-python-live harness never prints the run's key material, round 8 of #6060.

* #6964: the harness let pytest write straight to the job log, so a failing
  live test whose assertion embedded the per-run signing key printed it
  (``repr`` form) into a world-readable CI log. The harness now filters
  pytest's output and replaces every raw, ``repr``, hex and base64 form of the
  signing key, and every line of the TLS private key, with ``<redacted>``.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

from .test_ci_live_tests_6746 import _harness

_KEY = bytes(range(40, 60)) + bytes(
    [0xFE, 0x01, 0x7F, 0xC3, 0x28, 0x22, 0x27, 0x5C, 0x09, 0x00, 0xA0, 0x7E]
)
_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQmFzZTY0Qm9keUxpbmVP\n"
    b"bmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVPbmVP\n"
    b"-----END PRIVATE KEY-----\n"
)


def _forms_of_key() -> list[str]:
    return [
        repr(_KEY),
        repr(_KEY)[2:-1],
        _KEY.hex(),
        base64.b64encode(_KEY).decode(),
        base64.urlsafe_b64encode(_KEY).decode(),
        _KEY.decode("latin-1"),
    ]


_MULTILINE = b"first-line-of-secret\nsecond-line-of-secret"


def test_secret_forms_cover_raw_repr_hex_and_base64_6964() -> None:
    forms = _harness().secret_forms(_KEY)
    for needed in _forms_of_key():
        assert needed in forms


def test_redact_replaces_every_form_and_keeps_the_rest_6964() -> None:
    h = _harness()
    forms = h.secret_forms(_KEY)
    line = "AssertionError: " + " | ".join(_forms_of_key()) + " | test_client.py:42"
    cleaned = h.redact(line, forms)
    for form in _forms_of_key():
        assert form not in cleaned
    assert cleaned.count("<redacted>") == len(set(_forms_of_key()))
    assert "AssertionError" in cleaned and "test_client.py:42" in cleaned


def test_short_secrets_are_not_turned_into_a_wildcard_6964() -> None:
    assert _harness().secret_forms(b"ab") == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX harness")
def test_a_failing_child_that_echoes_the_key_is_filtered_and_fails_6964(
    capsys: pytest.CaptureFixture[str],
) -> None:
    h = _harness()
    script = (
        "import sys\n"
        f"k = {_KEY!r}\n"
        "print(repr(k))\n"
        "print(k.hex())\n"
        "print('E   AssertionError: ' + repr(k), file=sys.stderr)\n"
        "print('plain progress line')\n"
        "sys.exit(3)\n"
    )
    code = h.run_redacted([sys.executable, "-c", script], cwd=".", env=None, secrets=[_KEY])
    seen = capsys.readouterr()
    text = seen.out + seen.err
    assert code == 3
    assert "plain progress line" in text
    assert "<redacted>" in text
    for form in _forms_of_key():
        assert form not in text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX harness")
def test_every_line_of_a_private_key_pem_is_filtered_6964(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    h = _harness()
    pem = tmp_path / "key.pem"
    pem.write_bytes(_PEM)
    script = f"import sys; sys.stdout.write(open({str(pem)!r}).read())\n"
    secrets = h.secret_forms(_PEM)
    assert secrets, "a PEM must yield forms"
    code = h.run_redacted([sys.executable, "-c", script], cwd=".", env=None, secrets=[_PEM])
    text = capsys.readouterr().out
    assert code == 0
    for body in _PEM.decode().splitlines():
        if not body.startswith("-----"):
            assert body not in text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX harness")
def test_a_secret_spanning_lines_is_filtered_across_the_chunks_6964(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A raw form that holds a newline is matched in the stream, not per line."""
    h = _harness()
    script = f"import sys; sys.stdout.write('head ' + {_MULTILINE.decode()!r} + ' tail\\n')\n"
    code = h.run_redacted([sys.executable, "-c", script], cwd=".", env=None, secrets=[_MULTILINE])
    text = capsys.readouterr().out
    assert code == 0
    assert "first-line-of-secret" not in text
    assert "second-line-of-secret" not in text
    assert "head " in text and " tail" in text
