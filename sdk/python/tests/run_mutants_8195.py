"""Opt-in mutation runner for ``_mutants_8195`` (not collected by pytest).

Order of work:

1. Row 0, the UNMUTATED baseline, runs the killer tests on a pristine copy. When it is
   red the whole run aborts with ``BASELINE-RED`` and exit code ``EXIT_BASELINE``: a red
   baseline would make every row look killed.
2. Each row is applied to a fresh copy and the killer tests run to completion (no
   ``-x``), so the result is the FULL set of failing test ids.
3. A row is RED only when at least one of its NAMED killers fails (``Mutant.killers``,
   required: a row without killers is ``NO-KILLERS``, a defect, and is not run). A failure
   outside the named killers is ``UNATTRIBUTED``, a runner defect, never RED. The run
   executes every file in ``KILLER_TESTS`` so an unattributed failure is visible.

The copy keeps the repository layout (``<copy>/sdk/python`` plus ``<copy>/.github``) so
tests that read the CI workflow resolve it the same way they do in the checkout.
Rows flagged ``equivalent`` are expected to survive and report ``EQUIVALENT``.

Usage (from ``sdk/python``)::

    python -m tests.run_mutants_8195 --python <venv python> --scratch <dir> [--only 1,5-9] [--jobs 6]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple, Optional, Sequence

from ._mutants_8195 import KILLER_TESTS, MUTANTS, Mutant

SDK_ROOT = Path(__file__).resolve().parents[1]
EXIT_OK = 0
EXIT_BAD = 1
EXIT_BASELINE = 2
GOOD_VERDICTS = frozenset({"RED", "EQUIVALENT"})
_FAILED_ID = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.MULTILINE)
_IGNORE = shutil.ignore_patterns("__pycache__", "*.egg-info", ".local-runs", ".pytest_cache")
_REPORT_IDS = 20


class BaselineRed(Exception):
    """The unmutated tree fails its own killer tests."""


class RowResult(NamedTuple):
    verdict: str
    line: str


def _result_line(out: str) -> str:
    hits = [ln for ln in out.splitlines() if " in " in ln and ("passed" in ln or "failed" in ln or "error" in ln)]
    return hits[-1].strip() if hits else "(no result line)"


def stage_tree(sdk_root: Path, dest: Path) -> Path:
    """Copy ``sdk_root`` to ``<dest>/sdk/python`` and its ``.github`` workflows beside it."""
    if dest.exists():
        shutil.rmtree(dest)
    tree = dest / "sdk" / "python"
    shutil.copytree(sdk_root, tree, ignore=_IGNORE)
    workflows = sdk_root.parents[1] / ".github" / "workflows"
    if workflows.is_dir():
        shutil.copytree(workflows, dest / ".github" / "workflows")
    return tree


def _run_tests(tree: Path, python: str, timeout: int, killers: Sequence[str]) -> "tuple[int, list[str], str]":
    cmd = [python, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", *killers]
    try:
        res = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return -9, [], "TIMEOUT"
    out = res.stdout + res.stderr
    return res.returncode, sorted(set(_FAILED_ID.findall(out))), _result_line(out)


def _matches(failing: str, killer: str) -> bool:
    return failing == killer or failing.startswith(killer + "::") or failing.startswith(killer + "[")


def _shown(ids: Sequence[str]) -> str:
    extra = f" (+{len(ids) - _REPORT_IDS} more)" if len(ids) > _REPORT_IDS else ""
    return ", ".join(ids[:_REPORT_IDS]) + extra


def _classify(mutant: Mutant, code: int, failing: Sequence[str], killer_tests: Sequence[str]) -> str:
    if code == -9:
        return "TIMEOUT"
    named = mutant.killers
    if not named:
        return "NO-KILLERS"
    if code == 0:
        verdict = "SURVIVES"
    elif any(_matches(f, k) for f in failing for k in named):
        verdict = "RED"
    else:
        return "UNATTRIBUTED"
    if mutant.equivalent:
        return "EQUIVALENT" if verdict == "SURVIVES" else "EQUIVALENT-KILLED"
    return verdict


def run_baseline(sdk_root: Path, python: str, scratch: Path, timeout: int, killer_tests: Sequence[str]) -> str:
    """Run the killers on an unmutated copy; raise ``BaselineRed`` unless all are green."""
    tree = stage_tree(sdk_root, scratch / "m000")
    try:
        code, failing, line = _run_tests(tree, python, timeout, killer_tests)
    finally:
        shutil.rmtree(scratch / "m000", ignore_errors=True)
    if code != 0:
        raise BaselineRed(f"rc {code} | {line} | failing: {_shown(failing) or '(none parsed)'}")
    return f"M00 | baseline | unmutated | GREEN | rc 0 | {line}"


def run_row(
    index: int, mutant: Mutant, sdk_root: Path, python: str, scratch: Path, timeout: int, killer_tests: Sequence[str]
) -> RowResult:
    head = f"M{index:02d} | {mutant.label} | {mutant.name}"
    if not mutant.killers:
        return RowResult("NO-KILLERS", f"{head} | NO-KILLERS (every row names its killers, code r3 F5)")
    dest = scratch / f"m{index:03d}"
    tree = stage_tree(sdk_root, dest)
    try:
        target = tree / mutant.path
        text = target.read_text(encoding="utf-8")
        if text.count(mutant.old) != 1:
            return RowResult("NOT-APPLIED", f"{head} | NOT-APPLIED ({text.count(mutant.old)})")
        target.write_text(text.replace(mutant.old, mutant.new), encoding="utf-8")
        code, failing, line = _run_tests(tree, python, timeout, killer_tests)
        verdict = _classify(mutant, code, failing, killer_tests)
        killed = f" | failing: {_shown(failing)}" if failing else ""
        return RowResult(verdict, f"{head} | {verdict} | rc {code} | {line}{killed}")
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def _parse_only(spec: str) -> "set[int]":
    chosen: "set[int]" = set()
    for part in filter(None, spec.split(",")):
        low, _, high = part.partition("-")
        chosen.update(range(int(low), int(high or low) + 1))
    return chosen


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--sdk-root", type=Path, default=SDK_ROOT)
    parser.add_argument("--only", default="")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    os.umask(0o022)
    args.scratch.mkdir(parents=True, exist_ok=True)
    args.scratch.chmod(0o755)
    mutants, killer_tests = MUTANTS, KILLER_TESTS
    try:
        print(re.sub(r"\s+", " ", run_baseline(args.sdk_root, args.python, args.scratch, args.timeout, killer_tests)), flush=True)
    except BaselineRed as red:
        print(re.sub(r"\s+", " ", f"BASELINE-RED: {red}; no row was run"), flush=True)
        return EXIT_BASELINE
    only = _parse_only(args.only)
    todo = [i for i in range(1, len(mutants) + 1) if not only or i in only]
    counts = {"RED": 0, "EQUIVALENT": 0, "SURVIVES": 0}
    defects = 0
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = pool.map(
            lambda i: run_row(i, mutants[i - 1], args.sdk_root, args.python, args.scratch, args.timeout, killer_tests),
            todo,
        )
        for result in results:
            print(re.sub(r"\s+", " ", result.line), flush=True)
            if result.verdict in counts:
                counts[result.verdict] += 1
            if result.verdict not in GOOD_VERDICTS:
                defects += 1
    print(
        f"RED {counts['RED']} / EQUIVALENT {counts['EQUIVALENT']} / SURVIVES {counts['SURVIVES']}"
        f" / OTHER-DEFECTS {defects - counts['SURVIVES']} (rows run: {len(todo)})"
    )
    return EXIT_BAD if defects else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
