"""Self-tests of the mutant runner (#8195 r3, code r2 F1).

The runner must start from a green unmutated baseline, keep the repository layout in
its copy, and call a row RED only when one of its NAMED killers fails. These tests run
the runner against a tiny synthetic SDK tree, so they prove the runner and not the TLS
code.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from . import run_mutants_8195 as runner
from ._mutants_8195 import Mutant

_WORKFLOW = ".github/workflows/clients-ci.yml"
_KILLERS = ("tests/test_k.py", "tests/test_o.py")


def _tree(base: Path, *, baseline_green: bool = True) -> Path:
    """A synthetic ``<base>/sdk/python`` with two modules and two test files."""
    sdk = base / "sdk" / "python"
    (sdk / "pkg").mkdir(parents=True)
    (sdk / "tests").mkdir()
    (sdk / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (sdk / "pkg" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (sdk / "pkg" / "other.py").write_text("OTHER = 1\n", encoding="utf-8")
    (sdk / "tests" / "test_k.py").write_text(
        "from pkg.mod import VALUE\n\n\ndef test_value() -> None:\n    assert VALUE == 1\n", encoding="utf-8"
    )
    expected = "1" if baseline_green else "2"
    (sdk / "tests" / "test_o.py").write_text(
        f"from pkg.other import OTHER\n\n\ndef test_other() -> None:\n    assert OTHER == {expected}\n",
        encoding="utf-8",
    )
    (base / ".github" / "workflows").mkdir(parents=True)
    (base / _WORKFLOW).write_text("name: x\n", encoding="utf-8")
    return sdk


def _row(path: str, old: str, new: str, killers: tuple[str, ...] = (), *, equivalent: bool = False) -> Mutant:
    return Mutant("T", "synthetic", path, old, new, equivalent, killers)


def _run(sdk: Path, scratch: Path, mutant: Mutant) -> runner.RowResult:
    return runner.run_row(1, mutant, sdk, sys.executable, scratch, 120, _KILLERS)


def test_row_whose_named_killers_stay_green_is_reported_survives_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo")
    result = _run(sdk, tmp_path / "s", _row("pkg/mod.py", "VALUE = 1", "VALUE = 1  # no-op", ("tests/test_k.py",)))
    assert result.verdict == "SURVIVES"


def test_row_is_red_and_names_the_failing_killer_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo")
    result = _run(sdk, tmp_path / "s", _row("pkg/mod.py", "VALUE = 1", "VALUE = 2", ("tests/test_k.py",)))
    assert result.verdict == "RED"
    assert "tests/test_k.py::test_value" in result.line


def test_failure_outside_the_named_killers_is_a_runner_defect_not_red_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo")
    row = _row("pkg/other.py", "OTHER = 1", "OTHER = 2", ("tests/test_k.py",))
    result = _run(sdk, tmp_path / "s", row)
    assert result.verdict == "UNATTRIBUTED"
    assert result.verdict not in runner.GOOD_VERDICTS


def test_every_failing_test_id_is_reported_not_only_the_first_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo")
    (sdk / "pkg" / "mod.py").write_text("VALUE = 1\nOTHER = 1\n", encoding="utf-8")
    (sdk / "tests" / "test_o.py").write_text(
        "from pkg.mod import VALUE, OTHER\n\n\ndef test_a() -> None:\n    assert VALUE == 1\n\n\n"
        "def test_b() -> None:\n    assert OTHER == 1\n",
        encoding="utf-8",
    )
    result = _run(sdk, tmp_path / "s", _row("pkg/mod.py", "VALUE = 1\nOTHER = 1", "VALUE = 2\nOTHER = 2"))
    assert result.verdict == "RED"
    assert "test_o.py::test_a" in result.line
    assert "test_o.py::test_b" in result.line


def test_red_baseline_aborts_the_run_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo", baseline_green=False)
    with pytest.raises(runner.BaselineRed) as red:
        runner.run_baseline(sdk, sys.executable, tmp_path / "s", 120, _KILLERS)
    assert "tests/test_o.py::test_other" in str(red.value)


def test_main_exits_with_the_typed_baseline_code_and_runs_no_row_8195(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sdk = _tree(tmp_path / "repo", baseline_green=False)
    monkeypatch.setattr(runner, "MUTANTS", (_row("pkg/mod.py", "VALUE = 1", "VALUE = 2"),))
    monkeypatch.setattr(runner, "KILLER_TESTS", _KILLERS)
    code = runner.main(["--sdk-root", str(sdk), "--scratch", str(tmp_path / "s"), "--python", sys.executable])
    out = capsys.readouterr().out
    assert code == runner.EXIT_BASELINE
    assert "BASELINE-RED" in out
    assert "M01" not in out


def test_main_counts_red_equivalent_and_survivors_8195(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sdk = _tree(tmp_path / "repo")
    rows = (
        _row("pkg/mod.py", "VALUE = 1", "VALUE = 2"),
        _row("pkg/mod.py", "VALUE = 1", "VALUE = 1  # eq", equivalent=True),
        _row("pkg/other.py", "OTHER = 1", "OTHER = 1  # live", ("tests/test_o.py",)),
    )
    monkeypatch.setattr(runner, "MUTANTS", rows)
    monkeypatch.setattr(runner, "KILLER_TESTS", _KILLERS)
    code = runner.main(
        ["--sdk-root", str(sdk), "--scratch", str(tmp_path / "s"), "--python", sys.executable, "--jobs", "1"]
    )
    out = capsys.readouterr().out
    assert code == runner.EXIT_BAD
    assert "RED 1 / EQUIVALENT 1 / SURVIVES 1" in out


def test_copy_keeps_the_repository_layout_8195(tmp_path: Path) -> None:
    sdk = _tree(tmp_path / "repo")
    tree = runner.stage_tree(sdk, tmp_path / "s" / "copy")
    assert (tree / "pkg" / "mod.py").is_file()
    assert (tree.parents[1] / _WORKFLOW).is_file()
