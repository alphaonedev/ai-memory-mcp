# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The live harness filters every key form, the junit report and the child environment, round 9 of #6060.

* #6964 (security review F1): the CI-log filter replaced a list of exact encodings;
  upper-case hex, the decimal byte list, colon hex, base32, a half or truncated
  form and the decoded DER body all passed. ``redact`` now also removes every
  12-character fragment of any form.
* #7048: the ``--junitxml`` report pytest writes was never filtered.
* #7049: the pytest, daemon and hub children inherited every secret of the parent
  environment; they now get an explicit allow-list.
* #6813: every ``actions/checkout`` step of clients-ci.yml sets
  ``persist-credentials: false``.

The 12-character window count follows the security reviewer's probe
(``test_redaction_gaps_r8.py``); values are never printed, only booleans and counts.
"""

from __future__ import annotations

import base64
import io
import os
import sys
from pathlib import Path

import pytest

from .test_ci_live_tests_6746 import _harness

_KEY = bytes(range(7, 39))
_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    + base64.encodebytes(bytes(range(100, 221)))
    + b"-----END PRIVATE KEY-----\n"
)
_WORKFLOW = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "clients-ci.yml"


def _filtered(text: str) -> str:
    h = _harness()
    forms = [f for s in (_KEY, _PEM) for f in h.secret_forms(s)]
    forms.sort(key=len, reverse=True)
    return str(h.redact(text, forms))


@pytest.mark.parametrize(
    ("label", "form"),
    [
        ("upper-hex", _KEY.hex().upper()),
        ("int-list", str(list(_KEY))),
        ("colon-hex", _KEY.hex(":")),
        ("base32", base64.b32encode(_KEY).decode()),
        ("half-hex", _KEY[:16].hex()),
        ("pem-line-truncated", _PEM.splitlines()[1][:40].decode()),
        ("der-hex", base64.b64decode(b"".join(_PEM.splitlines()[1:-1])).hex()),
    ],
)
def test_ci_log_filter_removes_every_key_form_6964(label: str, form: str) -> None:
    out = _filtered(f"E   assert {form} == b''")
    assert form not in out, f"{label}: key form survives the CI-log filter"


def test_junit_report_is_filtered_7048(tmp_path: Path) -> None:
    h = _harness()
    keyfile, pemfile = tmp_path / "k.bin", tmp_path / "key.pem"
    keyfile.write_bytes(_KEY)
    pemfile.write_bytes(_PEM)
    (tmp_path / "test_leak.py").write_text(
        "import pathlib\n"
        f"def test_leak():\n    k = pathlib.Path({str(keyfile)!r}).read_bytes()\n"
        f"    pem = pathlib.Path({str(pemfile)!r}).read_bytes()\n"
        "    print(k.hex())\n    print(pem.decode())\n    assert pem == b''\n"
    )
    report = tmp_path / "junit.xml"
    sink, old = io.StringIO(), sys.stdout
    sys.stdout = sink
    try:
        code = h.run_redacted(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={report}",
                "test_leak.py",
            ],
            cwd=str(tmp_path),
            env=dict(os.environ, CI="true"),
            secrets=[_KEY, _PEM],
        )
    finally:
        sys.stdout = old
    assert code != 0
    body = [ln for ln in _PEM.decode().splitlines() if ln and not ln.startswith("-----")]
    windows = {ln[i : i + 12] for ln in body for i in range(len(ln) - 11)}
    junit, log = report.read_text(), sink.getvalue()
    assert sum(w in junit for w in windows) == 0, "the junit report carries PEM-body windows"
    assert sum(w in log for w in windows) == 0, "the CI log carries PEM-body windows"
    assert _KEY.hex() not in junit
    if sys.platform != "win32":
        assert (report.stat().st_mode & 0o777) == 0o600
