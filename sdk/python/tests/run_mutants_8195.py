"""Opt-in mutation runner for ``_mutants_8195`` (not collected by pytest).

Each row is applied to a fresh copy of ``sdk/python`` under ``--scratch`` and the killer
tests run with ``-x``. RED means the suite fails (the mutant is caught); SURVIVES means
it stayed green. Rows flagged ``equivalent`` are expected to survive.

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

from ._mutants_8195 import KILLER_TESTS, MUTANTS

SDK_ROOT = Path(__file__).resolve().parents[1]
EXIT_OK = 0
EXIT_BAD = 1


def _result_line(out: str) -> str:
    hits = [ln for ln in out.splitlines() if " in " in ln and ("passed" in ln or "failed" in ln or "error" in ln)]
    return hits[-1].strip() if hits else "(no result line)"


def _run_one(index: int, python: str, scratch: Path, timeout: int) -> str:
    mutant = MUTANTS[index - 1]
    tree = scratch / f"m{index:03d}"
    if tree.exists():
        shutil.rmtree(tree)
    shutil.copytree(
        SDK_ROOT, tree, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", ".local-runs", ".pytest_cache")
    )
    try:
        target = tree / mutant.path
        text = target.read_text(encoding="utf-8")
        if text.count(mutant.old) != 1:
            return f"M{index:02d} | {mutant.label} | {mutant.name} | NOT-APPLIED ({text.count(mutant.old)})"
        target.write_text(text.replace(mutant.old, mutant.new), encoding="utf-8")
        cmd = [python, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *KILLER_TESTS]
        try:
            res = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, timeout=timeout, check=False)
            code, out = res.returncode, res.stdout + res.stderr
        except subprocess.TimeoutExpired:
            code, out = -9, "TIMEOUT"
        verdict = "RED" if code != 0 else "SURVIVES"
        if mutant.equivalent:
            verdict += " (documented equivalent)"
        return f"M{index:02d} | {mutant.label} | {mutant.name} | {verdict} | rc {code} | {_result_line(out)}"
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def _parse_only(spec: str) -> set[int]:
    chosen: set[int] = set()
    for part in filter(None, spec.split(",")):
        low, _, high = part.partition("-")
        chosen.update(range(int(low), int(high or low) + 1))
    return chosen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--only", default="")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    os.umask(0o022)
    args.scratch.mkdir(parents=True, exist_ok=True)
    args.scratch.chmod(0o755)
    only = _parse_only(args.only)
    todo = [i for i in range(1, len(MUTANTS) + 1) if not only or i in only]
    survivors = 0
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for line in pool.map(lambda i: _run_one(i, args.python, args.scratch, args.timeout), todo):
            print(re.sub(r"\s+", " ", line), flush=True)
            if "SURVIVES" in line and "equivalent" not in line or "NOT-APPLIED" in line:
                survivors += 1
    print(f"survivors (excluding documented equivalents): {survivors}")
    return EXIT_BAD if survivors else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
