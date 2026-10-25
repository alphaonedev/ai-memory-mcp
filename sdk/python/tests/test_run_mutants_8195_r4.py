"""Mutant table integrity and the scheme gate on the PR's own fixtures (#8195 round 4).

``code r3 F1`` (``check-sdk-tls-scheme`` sees no plaintext daemon URL in the tests), ``F3``/``F4``
(the M66 rationale and the false test comment), ``F5`` (every row names its killers).
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

from . import run_mutants_8195 as runner
from ._mutants_8195 import MUTANTS, Mutant

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
#: The gate's pattern (scripts/check-sdk-tls-scheme.sh FORBIDDEN_RE), assembled so this file passes it.
_GATE_RE = re.compile("http" + r"://(localhost|127\.0\.0\.1)")
_SUFFIXES = (".ts", ".js", ".py", ".md", ".json", ".toml", ".sh")
_SKIP_PARTS = ("node_modules", "dist", "__pycache__", ".venv", ".local-runs", "egg-info")


def test_no_sdk_file_carries_a_plaintext_daemon_url_8195() -> None:
    hits = []
    for path in sorted(_SDK.parent.rglob("*")):
        if not path.is_file() or path.suffix not in _SUFFIXES:
            continue
        if any(part in path.parts for part in _SKIP_PARTS) or any(p.endswith("egg-info") for p in path.parts):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if _GATE_RE.search(line):
                hits.append(f"{path.relative_to(_SDK.parent)}:{number}")
    assert hits == []


def test_every_row_names_its_killers_explicitly_8195() -> None:
    bare = [m.label + " " + m.name for m in MUTANTS if not m.killers]
    assert bare == []


def test_every_named_killer_is_an_existing_test_file_8195() -> None:
    missing = []
    for mutant in MUTANTS:
        for killer in mutant.killers:
            if not (_SDK / killer.partition("::")[0]).is_file():
                missing.append(killer)
    assert missing == []


def test_runner_refuses_a_row_without_killers_8195(tmp_path: pathlib.Path) -> None:
    sdk = tmp_path / "repo" / "sdk" / "python"
    (sdk / "pkg").mkdir(parents=True)
    (sdk / "tests").mkdir()
    (sdk / "pkg" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (sdk / "tests" / "test_k.py").write_text("def test_ok() -> None:\n    assert True\n", encoding="utf-8")
    row = Mutant("T", "synthetic", "pkg/mod.py", "VALUE = 1", "VALUE = 2")
    result = runner.run_row(1, row, sdk, sys.executable, tmp_path / "s", 120, ("tests/test_k.py",))
    assert result.verdict == "NO-KILLERS"
    assert result.verdict not in runner.GOOD_VERDICTS


def test_no_op_row_with_an_unrelated_failing_test_is_not_red_8195(tmp_path: pathlib.Path) -> None:
    sdk = tmp_path / "repo" / "sdk" / "python"
    (sdk / "pkg").mkdir(parents=True)
    (sdk / "tests").mkdir()
    (sdk / "pkg" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (sdk / "tests" / "test_k.py").write_text("def test_ok() -> None:\n    assert True\n", encoding="utf-8")
    row = Mutant("T", "synthetic", "pkg/mod.py", "VALUE = 1", "VALUE = 1  # no-op", killers=("tests/test_k.py",))
    result = runner.run_row(1, row, sdk, sys.executable, tmp_path / "s", 120, ("tests/test_k.py",))
    assert result.verdict == "SURVIVES"


def _m66() -> Mutant:
    rows = [m for m in MUTANTS if "non-TLSVersion" in m.name]
    assert len(rows) == 1
    return rows[0]


def test_m66_rationale_names_the_identity_check_not_a_caller_that_catches_type_error_8195() -> None:
    row = _m66()
    assert row.equivalent is True
    assert "_STOCK_HANDSHAKE" in row.name
    assert "TypeError" not in row.name
    assert "caller refuses" not in row.name


def test_floor_tests_do_not_claim_that_only_a_type_check_refuses_the_bounds_8195() -> None:
    text = (_TESTS / "test_tls_floor_8195_r2.py").read_text(encoding="utf-8")
    assert "only a type check refuses them" not in text


@pytest.mark.parametrize("label", ["S02/C02"])
def test_the_two_equivalent_rows_are_the_only_ones_marked_equivalent_8195(label: str) -> None:
    flagged = sorted(m.label for m in MUTANTS if m.equivalent)
    assert label in flagged
    assert len(flagged) == 2
