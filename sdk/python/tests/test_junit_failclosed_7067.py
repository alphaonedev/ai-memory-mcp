"""#7067 (mutant J3): scrub_file removes a report it could not rewrite.

Run from sdk/python: python -m pytest -q <this file>
"""

import importlib.util
import pathlib

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
