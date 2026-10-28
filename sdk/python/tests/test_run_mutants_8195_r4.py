"""Mutant table integrity and the scheme gate on the PR's own fixtures (#8195 round 4).

``code r3 F1`` (``check-sdk-tls-scheme`` sees no plaintext daemon URL in the tests), ``F3``/``F4``
(the M66 rationale and the false test comment), ``F5`` (every row names its killers).
"""
from __future__ import annotations

import pathlib
import re
import sys

from . import run_mutants_8195 as runner
from ._mutants_8195 import KILLER_TESTS, MUTANTS, Mutant

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
#: The gate's pattern (scripts/check-sdk-tls-scheme.sh FORBIDDEN_RE), assembled so this file passes it.
_GATE_RE = re.compile("http" + r"://(localhost|127\.0\.0\.1)")
_SUFFIXES = (".ts", ".js", ".py", ".md", ".json", ".toml", ".sh")
_SKIP_PARTS = ("node_modules", "dist", "__pycache__", ".venv", ".local-runs", "egg-info")


#: The scan must reach more files than this, or a skipped ancestor directory emptied it (code r4 F4).
_MIN_SCANNED = 20


def _scan(root: pathlib.Path) -> "tuple[int, list[str]]":
    """Return (files scanned, plaintext daemon URL hits) under ``root``, the repository ``sdk`` parent."""
    scanned, hits = 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in _SUFFIXES:
            continue
        # Relative parts only: a checkout under ``.local-runs``, ``dist`` or ``.venv`` must still be scanned.
        parts = path.relative_to(root).parts
        if any(part in parts for part in _SKIP_PARTS) or any(p.endswith("egg-info") for p in parts):
            continue
        scanned += 1
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if _GATE_RE.search(line):
                hits.append(f"{path.relative_to(root)}:{number}")
    return scanned, hits


def test_no_sdk_file_carries_a_plaintext_daemon_url_8195() -> None:
    scanned, hits = _scan(_SDK.parent)
    assert scanned > _MIN_SCANNED, f"only {scanned} files scanned: the filter emptied the scan"
    assert hits == []


def test_scan_still_reads_a_checkout_that_sits_under_a_skipped_directory_name_8195(tmp_path: pathlib.Path) -> None:
    root = tmp_path / ".local-runs" / "dist" / ".venv" / "repo" / "sdk"
    (root / "python").mkdir(parents=True)
    (root / "python" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "python" / "bad.py").write_text('URL = "' + "http" + '://localhost:9077"\n', encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "skipped.py").write_text('URL = "' + "http" + '://localhost:1"\n', encoding="utf-8")
    scanned, hits = _scan(root)
    assert scanned == 2
    assert hits == ["python/bad.py:1"]


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


def _tree_with_an_unrelated_failing_test(tmp_path: pathlib.Path) -> pathlib.Path:
    sdk = tmp_path / "repo" / "sdk" / "python"
    (sdk / "pkg").mkdir(parents=True)
    (sdk / "tests").mkdir()
    (sdk / "pkg" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (sdk / "tests" / "test_k.py").write_text("def test_ok() -> None:\n    assert True\n", encoding="utf-8")
    (sdk / "tests" / "test_unrelated.py").write_text("def test_broken() -> None:\n    assert False\n", encoding="utf-8")
    return sdk


def test_no_op_row_beside_a_failing_unrelated_test_is_not_red_8195(tmp_path: pathlib.Path) -> None:
    sdk = _tree_with_an_unrelated_failing_test(tmp_path)
    row = Mutant("T", "synthetic", "pkg/mod.py", "VALUE = 1", "VALUE = 1  # no-op", killers=("tests/test_k.py",))
    # The failing unrelated file is present in the copy but is not one of the killer tests that run.
    result = runner.run_row(1, row, sdk, sys.executable, tmp_path / "s", 120, ("tests/test_k.py",))
    assert result.verdict == "SURVIVES"
    assert result.verdict not in {"RED", "EQUIVALENT"}


def test_failure_outside_the_named_killers_is_unattributed_never_red_8195(tmp_path: pathlib.Path) -> None:
    sdk = _tree_with_an_unrelated_failing_test(tmp_path)
    row = Mutant("T", "synthetic", "pkg/mod.py", "VALUE = 1", "VALUE = 1  # no-op", killers=("tests/test_k.py",))
    # The unrelated failing file runs with the killers; its failure must not be credited to the row.
    result = runner.run_row(
        1, row, sdk, sys.executable, tmp_path / "s", 120, ("tests/test_k.py", "tests/test_unrelated.py")
    )
    assert result.verdict == "UNATTRIBUTED"
    assert result.verdict not in runner.GOOD_VERDICTS


def _m66() -> Mutant:
    rows = [m for m in MUTANTS if "non-TLSVersion" in m.name]
    assert len(rows) == 1
    return rows[0]


def test_m66_rationale_names_the_identity_check_not_a_caller_that_catches_type_error_8195() -> None:
    row = _m66()
    assert row.equivalent is False
    assert "tests/test_tls_prepatch_8195_r5.py" in row.killers
    assert "tests/test_tls_prepatch_8195_r5.py" in KILLER_TESTS
    assert "_STOCK_HANDSHAKE" in row.name
    assert "captured at import" in row.name
    assert "TypeError" not in row.name
    assert "caller refuses" not in row.name
    assert "always yields" not in row.name


def test_floor_tests_do_not_claim_that_only_a_type_check_refuses_the_bounds_8195() -> None:
    text = (_TESTS / "test_tls_floor_8195_r2.py").read_text(encoding="utf-8")
    assert "only a type check refuses them" not in text
    assert "no public path reaches" not in text
    assert "equivalent" not in text.split("code r2 F2: a bound that is not")[1].split("_ORIG_BOUND")[0]


def test_the_cert_none_row_is_the_only_one_marked_equivalent_8195() -> None:
    flagged = [m for m in MUTANTS if m.equivalent]
    assert [m.label for m in flagged] == ["S02/C02"]
