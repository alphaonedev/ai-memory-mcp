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
import re
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


def test_children_do_not_inherit_the_parent_secrets_7049(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    h = _harness()
    canaries = (
        "AI_MEMORY_CANARY_DB_URL",
        "PGPASSWORD",
        "GITHUB_TOKEN",
        "ANTHROPIC_API_KEY",
        "SSH_AUTH_SOCK",
    )
    for name in canaries:
        monkeypatch.setenv(name, "canary-not-for-children")
    monkeypatch.setenv("PATH", os.environ.get("PATH", "/usr/bin"))
    stack = h.Stack(Path("/nonexistent/ai-memory"), tmp_path, 1)
    for env in (stack.env(), h.child_env(SSL_CERT_FILE="x")):
        leaked = [n for n in canaries if n in env]
        assert leaked == [], f"children inherit {leaked}"
        assert "PATH" in env
    assert h.child_env(A_NAME="v")["A_NAME"] == "v"
    assert set(h.CHILD_ENV_ALLOW) >= {"PATH"}
    assert not {n for n in h.CHILD_ENV_ALLOW if re.search(r"TOKEN|SECRET|PASSWORD|KEY|CRED", n)}


def test_pytest_child_env_is_the_allow_list_7049(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run_stack hands pytest ``child_env``, not a copy of ``os.environ``."""
    h = _harness()
    monkeypatch.setenv("GITHUB_TOKEN", "canary-not-for-children")
    seen: dict[str, object] = {}

    class _Stack:
        run = tmp_path
        home = tmp_path / "home"
        signing_key = tmp_path / "agent.priv"
        daemon_key = tmp_path / "daemon.priv"
        socket = tmp_path / "s"
        bundle = tmp_path / "b"
        refresh_error = None

        def enroll(self) -> None: ...
        def start_daemon(self, *_a: object) -> None: ...
        def start_hub(self) -> None: ...
        def wait_daemon(self, *_a: object) -> None: ...
        def close(self) -> None: ...

    stack = _Stack()
    stack.signing_key.write_bytes(_KEY)
    stack.daemon_key.write_bytes(_KEY)
    key = tmp_path / "key.pem"
    key.write_bytes(_PEM)
    monkeypatch.setattr(h, "mint_tls", lambda _d: (tmp_path / "ca.pem", tmp_path / "cert.pem", key))

    def _fake_run(argv: object, *, cwd: object, env: dict[str, str], secrets: object) -> int:
        seen["env"] = env
        return 0

    monkeypatch.setattr(h, "run_redacted", _fake_run)
    h.run_stack(stack, tmp_path, 1)
    env = seen["env"]
    assert isinstance(env, dict)
    assert "GITHUB_TOKEN" not in env
    assert env["AI_MEMORY_TEST_DAEMON"] == "1"


def test_every_checkout_step_does_not_persist_the_token_6813() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    steps = list(
        re.finditer(r"^( *)- uses: actions/checkout@[^\n]*\n((?:\1 {2,}[^\n]*\n)*)", text, re.M)
    )
    assert len(steps) == text.count("actions/checkout@") >= 6
    for step in steps:
        assert re.search(r"^\s+persist-credentials: false$", step.group(2), re.M), step.group(0)
