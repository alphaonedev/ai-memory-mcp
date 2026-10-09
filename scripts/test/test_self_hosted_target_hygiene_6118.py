#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin self-hosted runner target-dir hygiene (#6118).

THE DEFECT (#6118).  The self-hosted runners keep a PERSISTENT workspace
``target/`` (it is the warm cache for the pg tier; see the #3128 comments in
ci.yml).  One full ``cargo test`` build wrote ~1000 test executables of
~170 MB each into ``target/debug/deps`` (~164 GB per runner), and no job step
ever removed them, so the shared root filesystem fell from 224G to 78G free in
two hours.  Two parallel fresh builds would have hit ENOSPC mid-job.

THE RULE PINNED HERE (closed world: a job the reader cannot classify fails).
Every job in .github/workflows/*.yml that BOTH
  (1) can run on a ``self-hosted`` runner label (a literal ``runs-on`` list, or
      a ``runs-on`` that reads a matrix key whose value names ``self-hosted``),
  AND
  (2) runs ``cargo test`` / ``cargo llvm-cov`` / ``cargo nextest``,
must
  (a) carry BOTH ``CARGO_PROFILE_DEV_DEBUG`` and ``CARGO_PROFILE_TEST_DEBUG``
      in its effective env (workflow-level ``env:`` plus job-level ``env:``),
      set to the SAME reduced debuginfo level (``0`` / ``false`` / ``none`` /
      ``line-tables-only`` / ``line-directives-only``) -- TEST is pinned with
      DEV because the ``test`` profile only inherits ``dev`` while nothing
      overrides it (#3453/#3461), and
  (b) end with an ``always()``-guarded, self-hosted-only step (its ``if:``
      holds ``always()`` and ``runner.environment != 'github-hosted'``) that
      runs ``scripts/ci/prune_test_binaries.py``, placed AFTER every step that
      invokes cargo, so a failed or cancelled test run still reclaims the disk.

The second test case drives ``scripts/ci/prune_test_binaries.py`` itself on a
synthetic target directory under ``.local-runs/``: it must delete only the
extension-less executables in ``debug/deps``, keep every ``.rlib`` / ``.rmeta``
/ ``.d`` / ``.so`` / ``.dylib`` and ``build/`` / ``incremental/`` /
``.fingerprint/``, honour ``--dry-run`` and ``--max-age-hours``, and refuse a
``deps`` directory that resolves outside ``--target-dir``.

The workflow reader is the Python standard library only (no PyYAML on the
runners), in the line-oriented style of test_workflow_pr_triggers_5447.py.

Run:  python3 -I scripts/test/test_self_hosted_target_hygiene_6118.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PRUNE_SCRIPT = ROOT / "scripts" / "ci" / "prune_test_binaries.py"
PRUNE_REL = "scripts/ci/prune_test_binaries.py"
SCRATCH_PARENT = ROOT / ".local-runs"

DEBUG_VARS = ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")
REDUCED_DEBUG_LEVELS = frozenset(
    {"0", "false", "none", "line-tables-only", "line-directives-only"}
)
SELF_HOSTED = "self-hosted"
HOSTED_GUARD = "runner.environment != 'github-hosted'"
ALWAYS = "always()"

CARGO_TEST_RE = re.compile(r"\bcargo\s+(?:\+\S+\s+)?(?:test|llvm-cov|nextest)\b")
CARGO_ANY_RE = re.compile(r"\bcargo\s+(?:\+\S+\s+)?[a-z]")
JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
TOP_KEY_RE = re.compile(r"^[A-Za-z\"'][^:]*:")
MATRIX_REF_RE = re.compile(r"matrix\.([A-Za-z0-9_-]+)")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def _strip_inline_comment(line: str) -> str:
    """Drop a trailing `` #...`` YAML comment (only when preceded by a space)."""
    out = []
    quote: Optional[str] = None
    prev = " "
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"') and prev in (" ", ":", "[", ",", "("):
            quote = ch
        elif ch == "#" and prev == " ":
            break
        out.append(ch)
        prev = ch
    return "".join(out).rstrip()


def _unquote(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _code_lines(lines: List[str]) -> List[str]:
    return [_strip_inline_comment(ln) for ln in lines if not _is_comment_or_blank(ln)]


def _child_mapping(lines: List[str], start: int, parent_indent: int) -> Dict[str, str]:
    """Read the ``KEY: value`` children of the mapping key at ``lines[start]``."""
    out: Dict[str, str] = {}
    child_indent: Optional[int] = None
    for ln in lines[start + 1:]:
        if _is_comment_or_blank(ln):
            continue
        ind = _indent(ln)
        if ind <= parent_indent:
            break
        if child_indent is None:
            child_indent = ind
        if ind != child_indent:
            continue
        body = _strip_inline_comment(ln).strip()
        if ":" not in body:
            continue
        key, _, val = body.partition(":")
        out[key.strip()] = _unquote(val)
    return out


def top_level_env(text: str) -> Dict[str, str]:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"^env:\s*(?:#.*)?$", ln):
            return _child_mapping(lines, i, 0)
    return {}


def split_jobs(text: str) -> List[Tuple[str, List[str]]]:
    """Return ``(job_id, block_lines)`` for every job under ``jobs:``."""
    lines = text.splitlines()
    jobs: List[Tuple[str, List[str]]] = []
    in_jobs = False
    cur: Optional[str] = None
    block: List[str] = []
    for ln in lines:
        if re.match(r"^jobs:\s*(?:#.*)?$", ln):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if TOP_KEY_RE.match(ln):
            break
        m = JOB_KEY_RE.match(ln)
        if m:
            if cur is not None:
                jobs.append((cur, block))
            cur, block = m.group(1), []
            continue
        if cur is not None:
            block.append(ln)
    if cur is not None:
        jobs.append((cur, block))
    return jobs


def job_key_value(block: List[str], key: str) -> Optional[str]:
    for ln in block:
        if _is_comment_or_blank(ln) or _indent(ln) != 4:
            continue
        body = _strip_inline_comment(ln).strip()
        if body.startswith(key + ":"):
            return body[len(key) + 1:].strip()
    return None


def job_env(block: List[str]) -> Dict[str, str]:
    for i, ln in enumerate(block):
        if _indent(ln) == 4 and re.match(r"^\s{4}env:\s*(?:#.*)?$", ln):
            return _child_mapping(block, i, 4)
    return {}


def runs_on_self_hosted(block: List[str]) -> Optional[bool]:
    """True/False, or None when the job has no runs-on (reusable workflow)."""
    runs_on = job_key_value(block, "runs-on")
    if runs_on is None:
        return None
    if SELF_HOSTED in runs_on:
        return True
    for key in MATRIX_REF_RE.findall(runs_on):
        pat = re.compile(r"^\s*(?:-\s+)?" + re.escape(key) + r":\s*(.*)$")
        for ln in _code_lines(block):
            m = pat.match(ln)
            if m and SELF_HOSTED in m.group(1):
                return True
    return False


def split_steps(block: List[str]) -> List[List[str]]:
    steps: List[List[str]] = []
    start = None
    for i, ln in enumerate(block):
        if _indent(ln) == 4 and re.match(r"^\s{4}steps:\s*(?:#.*)?$", ln):
            start = i
            break
    if start is None:
        return steps
    item_indent: Optional[int] = None
    cur: Optional[List[str]] = None
    for ln in block[start + 1:]:
        if _is_comment_or_blank(ln):
            if cur is not None:
                cur.append(ln)
            continue
        ind = _indent(ln)
        if ind <= 4:
            break
        if ln.lstrip().startswith("- ") and (item_indent is None or ind == item_indent):
            item_indent = ind
            if cur is not None:
                steps.append(cur)
            cur = [ln]
        elif cur is not None:
            cur.append(ln)
    if cur is not None:
        steps.append(cur)
    return steps


def step_if(step: List[str]) -> str:
    first = step[0]
    item_indent = _indent(first)
    head = first.lstrip()[2:]
    candidates = [(item_indent + 2, head)]
    for ln in step[1:]:
        if not _is_comment_or_blank(ln):
            candidates.append((_indent(ln), ln.strip()))
    for ind, body in candidates:
        if ind == item_indent + 2 and body.startswith("if:"):
            return _strip_inline_comment(body[3:]).strip()
    return ""


def step_runs_cargo(step: List[str]) -> bool:
    return any(CARGO_ANY_RE.search(ln) for ln in _code_lines(step))


def is_prune_step(step: List[str]) -> bool:
    cond = step_if(step)
    code = "\n".join(_code_lines(step))
    return ALWAYS in cond and HOSTED_GUARD in cond and PRUNE_REL in code


def job_violations(wf_env: Dict[str, str], job_id: str, block: List[str]) -> List[str]:
    """Return the #6118 violations of one job (empty when compliant or exempt)."""
    sh = runs_on_self_hosted(block)
    if not sh:
        return []
    code = _code_lines(block)
    if not any(CARGO_TEST_RE.search(ln) for ln in code):
        return []
    out: List[str] = []
    env = dict(wf_env)
    env.update(job_env(block))
    levels = []
    for var in DEBUG_VARS:
        val = env.get(var)
        if val is None:
            out.append(f"{job_id}: env lacks {var} (self-hosted cargo test job)")
        elif val.strip().lower() not in REDUCED_DEBUG_LEVELS:
            out.append(f"{job_id}: {var}={val!r} is not a reduced debuginfo level")
        else:
            levels.append(val.strip().lower())
    if len(levels) == 2 and levels[0] != levels[1]:
        out.append(f"{job_id}: {DEBUG_VARS[0]} and {DEBUG_VARS[1]} differ ({levels})")
    steps = split_steps(block)
    if not steps:
        out.append(f"{job_id}: no steps parsed (fail closed)")
        return out
    prune_idx = [i for i, s in enumerate(steps) if is_prune_step(s)]
    if not prune_idx:
        out.append(
            f"{job_id}: no step guarded by `if: {ALWAYS} && {HOSTED_GUARD}` runs {PRUNE_REL}"
        )
        return out
    last_cargo = max((i for i, s in enumerate(steps) if step_runs_cargo(s)), default=-1)
    if max(prune_idx) < last_cargo:
        out.append(f"{job_id}: the prune step runs before a later cargo step")
    return out


def workflow_violations(text: str) -> Tuple[List[str], List[str]]:
    """Return ``(violations, in_scope_job_ids)`` for one workflow text."""
    wf_env = top_level_env(text)
    viol: List[str] = []
    scope: List[str] = []
    for job_id, block in split_jobs(text):
        sh = runs_on_self_hosted(block)
        if sh and any(CARGO_TEST_RE.search(ln) for ln in _code_lines(block)):
            scope.append(job_id)
        viol.extend(job_violations(wf_env, job_id, block))
    return viol, scope


# --------------------------------------------------------------------------
# Synthetic controls: prove the reader is not vacuous.
# --------------------------------------------------------------------------
GOOD_WF = """\
name: t
on:
  push:
env:
  CARGO_PROFILE_DEV_DEBUG: line-tables-only
jobs:
  hosted:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
  t:
    runs-on: ${{ fromJSON(matrix.runner) }}
    env:
      CARGO_PROFILE_TEST_DEBUG: line-tables-only
    strategy:
      matrix:
        include:
          - runner: '["self-hosted","linux-fed"]'
    steps:
      - uses: actions/checkout@v4
      - name: test
        run: cargo test --lib
      # cleanup
      - name: Prune
        if: always() && runner.environment != 'github-hosted'
        run: python3 -I scripts/ci/prune_test_binaries.py --target-dir target
"""


class WorkflowReaderControls(unittest.TestCase):
    def test_good_control_passes(self) -> None:
        viol, scope = workflow_violations(GOOD_WF)
        self.assertEqual(scope, ["t"])
        self.assertEqual(viol, [])

    def test_missing_test_debug_fails(self) -> None:
        viol, _ = workflow_violations(GOOD_WF.replace("CARGO_PROFILE_TEST_DEBUG", "X_Y"))
        self.assertTrue(any("CARGO_PROFILE_TEST_DEBUG" in v for v in viol), viol)

    def test_full_debug_level_fails(self) -> None:
        viol, _ = workflow_violations(
            GOOD_WF.replace("DEV_DEBUG: line-tables-only", "DEV_DEBUG: \"2\"")
        )
        self.assertTrue(any("reduced debuginfo" in v for v in viol), viol)

    def test_unguarded_prune_fails(self) -> None:
        viol, _ = workflow_violations(GOOD_WF.replace("always() && ", ""))
        self.assertTrue(any("guarded" in v for v in viol), viol)

    def test_missing_prune_fails(self) -> None:
        viol, _ = workflow_violations(GOOD_WF.replace(PRUNE_REL, "scripts/ci/other.py"))
        self.assertTrue(any("guarded" in v for v in viol), viol)

    def test_prune_before_cargo_fails(self) -> None:
        mutated = GOOD_WF + "      - run: cargo build --release\n"
        viol, _ = workflow_violations(mutated)
        self.assertTrue(any("before a later cargo step" in v for v in viol), viol)

    def test_literal_self_hosted_list_is_in_scope(self) -> None:
        mutated = GOOD_WF.replace(
            "runs-on: ${{ fromJSON(matrix.runner) }}", "runs-on: [self-hosted, linux-fed]"
        ).replace("          - runner: '[\"self-hosted\",\"linux-fed\"]'\n", "")
        _, scope = workflow_violations(mutated)
        self.assertEqual(scope, ["t"])

    def test_comment_only_cargo_mention_is_out_of_scope(self) -> None:
        mutated = GOOD_WF.replace("run: cargo test --lib", "run: echo hi  # cargo test")
        _, scope = workflow_violations(mutated)
        self.assertEqual(scope, [])


class LiveWorkflows(unittest.TestCase):
    def test_every_self_hosted_cargo_test_job_is_hygienic(self) -> None:
        files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertTrue(files, "no workflow files found")
        all_scope: List[str] = []
        for wf in files:
            viol, scope = workflow_violations(wf.read_text(encoding="utf-8"))
            all_scope.extend(f"{wf.name}:{j}" for j in scope)
            for v in viol:
                with self.subTest(workflow=wf.name, violation=v):
                    self.fail(f"{wf.name}: {v}")
        # Non-vacuity: the 2x2 `check` matrix is the heaviest self-hosted
        # cargo-test job; if the reader stops seeing it the pin is dead.
        self.assertIn("ci.yml:check", all_scope)


# --------------------------------------------------------------------------
# Prune helper behaviour on a synthetic target directory.
# --------------------------------------------------------------------------
def _write(path: Path, data: bytes = b"x" * 64, exe: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    mode = 0o755 if exe else 0o644
    path.chmod(mode)
    return path


def _age(path: Path, hours: float) -> None:
    t = time.time() - hours * 3600.0
    os.utime(path, (t, t))


class PruneHelper(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH_PARENT.mkdir(parents=True, exist_ok=True)
        self.scratch = Path(tempfile.mkdtemp(prefix="prune-6118-", dir=SCRATCH_PARENT))
        self.target = self.scratch / "target"
        deps = self.target / "debug" / "deps"
        self.exe_new = _write(deps / "store_parity-0123456789abcdef", b"E" * 4096, exe=True)
        self.exe_old = _write(deps / "recall_tests-fedcba9876543210", b"O" * 2048, exe=True)
        _age(self.exe_old, 48)
        self.keep = [
            _write(deps / "libai_memory-0123456789abcdef.rlib"),
            _write(deps / "libai_memory-0123456789abcdef.rmeta"),
            _write(deps / "store_parity-0123456789abcdef.d"),
            _write(deps / "libserde_derive-0123456789abcdef.so", exe=True),
            _write(deps / "libfoo-0123456789abcdef.dylib", exe=True),
            # extension-less but NOT executable: not a test binary.
            _write(deps / "plain-0123456789abcdef"),
            _write(self.target / "debug" / "build" / "x-01" / "build-script-build", exe=True),
            _write(self.target / "debug" / "incremental" / "x-01" / "blob", exe=True),
            _write(self.target / "debug" / ".fingerprint" / "x-01" / "bin-x", exe=True),
            _write(self.target / "debug" / "ai-memory", exe=True),
        ]
        for p in self.keep:
            _age(p, 48)

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def run_prune(self, *args: str) -> subprocess.CompletedProcess:
        self.assertTrue(PRUNE_SCRIPT.is_file(), f"{PRUNE_REL} does not exist")
        return subprocess.run(
            [sys.executable, "-I", str(PRUNE_SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

    def assert_kept(self) -> None:
        for p in self.keep:
            self.assertTrue(p.exists(), f"{p.name} must never be pruned")

    def test_deletes_only_test_executables_and_reports_bytes(self) -> None:
        r = self.run_prune("--target-dir", str(self.target))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.exe_new.exists())
        self.assertFalse(self.exe_old.exists())
        self.assert_kept()
        self.assertRegex(r.stdout, r"freed 6144 bytes")

    def test_dry_run_deletes_nothing(self) -> None:
        r = self.run_prune("--target-dir", str(self.target), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.exe_new.exists())
        self.assertTrue(self.exe_old.exists())
        self.assert_kept()
        self.assertRegex(r.stdout, r"6144 bytes")

    def test_max_age_hours_spares_recent_binaries(self) -> None:
        r = self.run_prune("--target-dir", str(self.target), "--max-age-hours", "24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.exe_new.exists(), "a fresh binary is younger than 24h")
        self.assertFalse(self.exe_old.exists(), "a 48h-old binary is older than 24h")
        self.assert_kept()
        self.assertRegex(r.stdout, r"freed 2048 bytes")

    def test_nothing_to_prune_exits_zero(self) -> None:
        empty = self.scratch / "empty-target"
        empty.mkdir()
        r = self.run_prune("--target-dir", str(empty))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"freed 0 bytes")

    def test_missing_target_dir_exits_zero(self) -> None:
        r = self.run_prune("--target-dir", str(self.scratch / "never-built"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_refuses_deps_resolving_outside_target_dir(self) -> None:
        outside = self.scratch / "outside"
        victim = _write(outside / "victim-0123456789abcdef", b"V" * 128, exe=True)
        other = self.scratch / "other-target"
        (other / "debug").mkdir(parents=True)
        (other / "debug" / "deps").symlink_to(outside, target_is_directory=True)
        r = self.run_prune("--target-dir", str(other))
        self.assertNotEqual(r.returncode, 0, "an escaping deps dir must be refused")
        self.assertTrue(victim.exists(), "nothing outside --target-dir may be deleted")

    def test_skips_symlinked_entries(self) -> None:
        outside = self.scratch / "outside2"
        victim = _write(outside / "victim-fedcba9876543210", b"V" * 128, exe=True)
        link = self.target / "debug" / "deps" / "link-0123456789abcdef"
        link.symlink_to(victim)
        r = self.run_prune("--target-dir", str(self.target))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(victim.exists(), "a symlink target outside --target-dir survives")

    def test_negative_max_age_is_rejected(self) -> None:
        r = self.run_prune("--target-dir", str(self.target), "--max-age-hours", "-1")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(self.exe_new.exists())


if __name__ == "__main__":
    if os.name != "posix":  # executables are detected by POSIX mode bits
        print("skip: POSIX only")
        sys.exit(0)
    unittest.main(verbosity=2)
