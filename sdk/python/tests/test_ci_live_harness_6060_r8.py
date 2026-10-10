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
import os
import signal
import subprocess
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


# ---- #6935 / #6961: the r7 harness test's own teardown and lookups ---------------


def test_run_close_survives_eperm_from_a_zombie_only_group_6935(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """macOS answers ``killpg`` on a group holding only zombies with EPERM; close() must absorb it."""
    from . import test_ci_live_harness_6060_r7 as r7

    run = r7.Run(tmp_path)
    run.proc = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    run.proc.wait()

    def eperm(pgid: int, sig: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "killpg", eperm)
    run.close()


def test_run_close_is_idempotent_and_never_signals_a_reaped_group_6935(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After ``wait()`` the pid may be reused, so a second close() must not ``killpg`` it again."""
    from . import test_ci_live_harness_6060_r7 as r7

    run = r7.Run(tmp_path)
    run.proc = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    run.proc.wait()
    signalled: list[int] = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: signalled.append(pgid))
    run.close()
    run.close()
    assert len(signalled) <= 1, signalled


def test_leader_pgid_retries_a_transient_lookup_error_6961(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``os.getpgid`` of a just-started child can say ESRCH once under load: retry, then answer."""
    from . import test_ci_live_harness_6060_r7 as r7

    run = r7.Run(tmp_path)
    run.proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    real = os.getpgid
    attempts = {"n": 0}

    def flaky(pid: int) -> int:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ProcessLookupError(3, "No such process")
        return real(pid)

    monkeypatch.setattr(os, "getpgid", flaky)
    try:
        assert r7.leader_pgid(run) == run.proc.pid
        assert attempts["n"] == 3
    finally:
        run.proc.kill()
        run.proc.wait()


def test_leader_pgid_reports_the_output_of_a_harness_that_exited_6961(tmp_path: Path) -> None:
    from . import test_ci_live_harness_6060_r7 as r7

    run = r7.Run(tmp_path)
    run.proc = subprocess.Popen(
        [sys.executable, "-c", "print('harness died early')"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    run.proc.wait()
    with pytest.raises(pytest.fail.Exception, match="harness died early"):
        r7.leader_pgid(run)


# ---- #6960: a stop signal inside Stack.spawn leaves no untracked child ------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_stop_signal_inside_spawn_does_not_orphan_the_child_6960(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = _harness()
    previous = {sig: signal.signal(sig, h._stop) for sig in h.STOP_SIGNALS}
    stack = h.Stack(Path(sys.executable), tmp_path / "run", 0)
    (tmp_path / "run").mkdir()
    real = subprocess.Popen
    started: list[subprocess.Popen[bytes]] = []

    def popen(argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        child = real([sys.executable, "-c", "import time; time.sleep(300)"], **kwargs)  # type: ignore[call-overload]
        started.append(child)
        os.kill(os.getpid(), signal.SIGTERM)  # the stop signal lands right after the fork
        return child

    monkeypatch.setattr(h.subprocess, "Popen", popen)
    try:
        with pytest.raises(h.Stopped):
            stack.spawn("daemon", "-c", "pass")
        monkeypatch.setattr(h.subprocess, "Popen", real)
        stack.close()
        assert started, "the stub never started the child"
        assert started[0].poll() is not None, "the child outlived close(): it was never tracked"
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for child in started:
            if child.poll() is None:
                child.kill()
                child.wait()
