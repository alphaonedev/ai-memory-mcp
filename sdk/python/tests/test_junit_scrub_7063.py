"""#7063 #7064: the scrubbed junit report stays well-formed XML, hides every escaped
rendering of a secret, and an unparseable report is removed (#7067).

Run from sdk/python: python -m pytest -q <this file>
"""

import importlib.util
import os
import pathlib
import sys
import xml.etree.ElementTree as ET

import pytest

HARNESS = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "sdk-python-live.py"
KEY = bytes(b for i in range(16) for b in (0x01 + i, ord("&")))  # 32 bytes, '&' on every 2nd byte
QUOTED = b'k"1<2>3\'4&5-secret-material-xyz'


def _h():
    spec = importlib.util.spec_from_file_location("harness_junit_7063", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _entities(text, how):
    """``text`` with every character written as a numeric character reference."""
    return "".join(f"&#{ord(c)};" if how == "dec" else f"&#x{ord(c):x};" for c in text)


def _report(tmp_path, message, body):
    path = tmp_path / "junit.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="s" tests="1">'
        f'<testcase classname="tests.test_x" name="test_y"><failure message="{message}">{body}</failure>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def _readable(path):
    """Everything an XML consumer reads out of the report."""
    root = ET.parse(str(path)).getroot()
    return "".join(e.text or "" for e in root.iter()) + "".join(v for e in root.iter() for v in e.attrib.values())


def test_7063_scrubbed_junit_is_still_parseable_by_the_harness(tmp_path):
    h = _h()
    path = _report(tmp_path, "m", repr(QUOTED).replace("&", "&amp;").replace("<", "&lt;"))
    h.scrub_file(path, [QUOTED])
    assert list(h.junit_outcomes(path).values()) == ["failed"]


@pytest.mark.parametrize("secret", [KEY, QUOTED])
def test_7064_xml_escaped_renderings_of_a_secret_are_redacted(tmp_path, secret):
    h = _h()
    inner = repr(secret)[2:-1]
    escaped = inner.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    path = _report(tmp_path, escaped, escaped)
    h.scrub_file(path, [secret])
    seen = _readable(path)
    assert inner not in seen
    assert not any(inner[i : i + 6] in seen for i in range(len(inner) - 5))


@pytest.mark.parametrize("how", ["dec", "hex"])
def test_7064_numeric_entity_renderings_of_a_secret_are_redacted(tmp_path, how):
    h = _h()
    hx = KEY.hex()
    path = _report(tmp_path, _entities(hx, how), _entities(hx, how))
    h.scrub_file(path, [KEY])
    seen = _readable(path)
    assert not any(hx[i : i + 6] in seen for i in range(len(hx) - 5))


def test_7064_ordinary_text_survives_the_scrub(tmp_path):
    h = _h()
    path = _report(tmp_path, "assert 1 == 2", "plain progress &lt;line&gt;")
    h.scrub_file(path, [KEY])
    assert "plain progress <line>" in _readable(path)
    assert path.stat().st_mode & 0o777 == 0o600


def test_7067_a_report_that_cannot_be_parsed_is_removed(tmp_path):
    h = _h()
    path = tmp_path / "junit.xml"
    path.write_text("<testsuite><unclosed>" + KEY.hex(), encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - ParseError or OSError, both are a refusal
        h.scrub_file(path, [KEY])
    assert not path.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX harness")
def test_7063_end_to_end_the_scrubbed_report_is_parseable_and_clean(tmp_path):
    h = _h()
    keyfile = tmp_path / "k.bin"
    keyfile.write_bytes(KEY)
    (tmp_path / "test_leak.py").write_text(
        "import pathlib\n"
        f"def test_leak():\n    k = pathlib.Path({str(keyfile)!r}).read_bytes()\n    assert k == b''\n"
    )
    report = tmp_path / "junit.xml"
    import io

    sink, old = io.StringIO(), sys.stdout
    sys.stdout = sink
    try:
        h.run_redacted(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={report}", "test_leak.py"],
            cwd=str(tmp_path),
            env=dict(os.environ, CI="true"),
            secrets=[KEY],
        )
    finally:
        sys.stdout = old
    assert list(h.junit_outcomes(report).values()) == ["failed"]
    assert repr(KEY)[2:-1] not in _readable(report)
