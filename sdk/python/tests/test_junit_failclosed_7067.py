"""#7067 (mutant J3): scrub_file removes a report it could not rewrite.

Run from sdk/python: python -m pytest -q <this file>
"""

import importlib.util
import pathlib
import sys

import pytest

HARNESS = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "sdk-python-live.py"
KEY = bytes(range(40, 72))


def _h():
    spec = importlib.util.spec_from_file_location("harness_failclosed_7067", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_7067_a_report_that_cannot_be_rewritten_is_removed(tmp_path, monkeypatch):
    h = _h()
    path = tmp_path / "junit.xml"
    path.write_text(f"<testsuite>{KEY.hex()}</testsuite>", encoding="utf-8")

    def refuse(*_a, **_k):
        raise PermissionError("chmod refused")

    monkeypatch.setattr(h.os, "chmod", refuse)
    with pytest.raises(OSError):
        h.scrub_file(path, [KEY])
    assert not path.exists(), "a report that could not be filtered must not be left on disk"


class _Stop(BaseException):
    """What the stop-signal handler raises: not an Exception, not an OSError."""


def test_7048_a_stop_inside_the_scrub_removes_the_report(tmp_path, monkeypatch):
    h = _h()
    path = tmp_path / "junit.xml"
    path.write_text(f"<testsuite>{KEY.hex()}</testsuite>", encoding="utf-8")

    def stop(*_a, **_k):
        raise _Stop

    monkeypatch.setattr(h.ET, "parse", stop)
    with pytest.raises(_Stop):
        h.scrub_file(path, [KEY])
    assert not path.exists(), "a stop during the scrub must not leave the unfiltered report"


def test_7048_a_stop_while_waiting_for_the_child_removes_the_report(tmp_path, monkeypatch):
    h = _h()
    report = tmp_path / "junit.xml"
    code = f"import pathlib; pathlib.Path({str(report)!r}).write_text({KEY.hex()!r})"
    real_wait = h.subprocess.Popen.wait

    def stop(self, *a, **k):
        real_wait(self, *a, **k)
        raise _Stop

    monkeypatch.setattr(h.subprocess.Popen, "wait", stop)
    with pytest.raises(_Stop):
        h.run_redacted(
            [sys.executable, "-c", code, f"--junitxml={report}"],
            cwd=str(tmp_path),
            env=None,
            secrets=[KEY],
        )
    assert not report.exists(), "a stop before the scrub must not leave the unfiltered report"
