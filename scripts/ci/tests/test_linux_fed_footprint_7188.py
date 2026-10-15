#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #7188 linux-fed CI footprint reductions.

Four properties, read from the repository text (stdlib only, Python 3.9+; the
workflow and Cargo.toml are parsed by line because PyYAML and ``tomllib`` are
not guaranteed on every node):

  (a) the self-hosted linux-fed enterprise-fed matrix leg opts in to a PER-RUNNER
      ``CARGO_TARGET_DIR`` (a matrix flag + one helper step); the
      hosted and macOS legs do not;
  (b) the dev profile strips debuginfo from dependencies;
  (c) a post-job prune step runs ``if: always()`` on the opted-in leg and the
      prune helper can never target the shared target path;
  (d) a concurrency cap is declared on the ``check`` job strategy.

Run: python3 -m unittest discover -s scripts/ci/tests
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
CARGO_TOML = REPO / "Cargo.toml"
CI_DIR = REPO / "scripts" / "ci"
SHARED_FLAG = "shared_target"
SHARED_HELPER = "scripts/ci/shared_cargo_target.py"
PRUNE_HELPER = "scripts/ci/prune_runner_artifacts.py"
CAP_KEY = "max-parallel"
EXPECTED_CAP = 3
SHARED_LEG = "linux-fed,enterprise-fed"


def read(path):
    return path.read_text(encoding="utf-8")


def check_job_lines():
    """Lines of the top-level ``check:`` job, from its header to the next job."""
    lines = read(CI_YML).splitlines()
    start = lines.index("  check:")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i]):
            end = i
            break
    return lines[start:end]


def matrix_legs(job):
    """Map leg name -> list of its matrix lines (include entries)."""
    legs = {}
    current = None
    for ln in job:
        m = re.match(r"^          - leg: (\S+)\s*$", ln)
        if m:
            current = m.group(1)
            legs[current] = []
        elif current is not None:
            if re.match(r"^    steps:\s*$", ln):
                break
            legs[current].append(ln)
    return legs


def active(lines):
    return [ln for ln in lines if not ln.lstrip().startswith("#")]


class SharedTargetLeg(unittest.TestCase):
    def test_only_self_hosted_linux_fed_enterprise_leg_opts_in(self):
        legs = matrix_legs(check_job_lines())
        self.assertEqual(
            sorted(legs),
            ["linux-fed,enterprise-fed", "macos-fed,enterprise-fed",
             "macos-fed,sqlite", "ubuntu-latest,sqlite"],
        )
        pat = re.compile(r"^\s+%s:\s*true\s*$" % SHARED_FLAG)
        for name, body in legs.items():
            flagged = any(pat.match(ln) for ln in active(body))
            self.assertEqual(flagged, name == SHARED_LEG, name)

    def test_shared_target_step_is_gated_on_the_flag(self):
        job = "\n".join(active(check_job_lines()))
        self.assertIn(SHARED_HELPER + " --github-env", job)
        self.assertRegex(job, r"if:[^\n]*&& matrix\.%s\b" % SHARED_FLAG)
        self.assertIn('--runner-name "${{ runner.name }}"', job)
        self.assertNotIn("touch_workspace_sources", job)

    def test_no_literal_target_dir_in_the_job(self):
        job = "\n".join(active(check_job_lines()))
        self.assertNotRegex(job, r"(?m)^\s+CARGO_TARGET_DIR:")

    def test_helper_defines_the_path_once_outside_tmp(self):
        helper = CI_DIR / "shared_cargo_target.py"
        self.assertTrue(helper.is_file(), "missing " + str(helper))
        sys.path.insert(0, str(CI_DIR))
        try:
            import shared_cargo_target as mod
        finally:
            sys.path.pop(0)
        path = mod.runner_target_dir(Path("/home/runner-user"), "linux-fed-1")
        self.assertEqual(path.parts[:3], ("/", "home", "runner-user"))
        self.assertEqual(path.name, "linux-fed-1")
        for banned in ("/tmp", "/var/tmp", "/dev/shm"):
            self.assertFalse(str(path).startswith(banned))


class DependencyProfile(unittest.TestCase):
    def test_dev_package_profile_strips_dependency_debuginfo(self):
        text = read(CARGO_TOML)
        m = re.search(r'(?ms)^\[profile\.dev\.package\."\*"\]\s*\n(.*?)(?=^\[|\Z)', text)
        self.assertIsNotNone(m, 'missing [profile.dev.package."*"]')
        body = m.group(1)
        self.assertRegex(body, r"(?m)^debug\s*=\s*0\s*(#.*)?$")
        self.assertRegex(body, r'(?m)^strip\s*=\s*"debuginfo"\s*(#.*)?$')

    def test_release_profile_is_untouched(self):
        m = re.search(r"(?ms)^\[profile\.release\]\s*\n(.*?)(?=^\[|\Z)", read(CARGO_TOML))
        self.assertIsNotNone(m)
        self.assertRegex(m.group(1), r"(?m)^strip\s*=\s*true\s*$")


class PostJobPrune(unittest.TestCase):
    def test_prune_step_runs_always_on_the_flagged_leg(self):
        job = active(check_job_lines())
        idx = [i for i, ln in enumerate(job) if PRUNE_HELPER in ln]
        self.assertEqual(len(idx), 1, "prune helper must be called exactly once")
        step_start = max(i for i in range(idx[0]) if job[i].startswith("      - name:"))
        step = "\n".join(job[step_start:idx[0] + 1])
        self.assertIn("if: always() && matrix.%s" % SHARED_FLAG, step)

    def test_prune_helper_exists_and_never_names_the_shared_target(self):
        helper = CI_DIR / "prune_runner_artifacts.py"
        self.assertTrue(helper.is_file(), "missing " + str(helper))
        text = read(helper)
        self.assertIn("--dry-run", text)
        self.assertIn("is_protected", text)


class ConcurrencyCap(unittest.TestCase):
    def test_cap_declared_on_check_strategy(self):
        job = active(check_job_lines())
        caps = [ln for ln in job if re.match(r"^      %s:\s*\d+\s*$" % CAP_KEY, ln)]
        self.assertEqual(len(caps), 1, "check strategy must declare %s" % CAP_KEY)
        self.assertEqual(int(caps[0].split(":")[1]), EXPECTED_CAP)


if __name__ == "__main__":
    unittest.main()
