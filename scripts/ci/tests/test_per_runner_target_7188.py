#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Per-runner cargo target isolation (#7188, HIGH-1 final form).

Three groups:

  * the helper scripts/ci/shared_cargo_target.py derives
    ``~/.cache/ai-memory-ci/cargo-target/<runner-name>`` from an explicit
    ``--runner-name`` and FAILS CLOSED (exit EXIT_USAGE, nothing exported, no
    shared fallback) on a missing, empty, dotted or non ``[A-Za-z0-9._-]`` name;
  * the cargo wrapper resolver (#7198): the wrapper is read from the
    environment variable named by ``CARGO_SLOT_ENV`` (``AI_MEMORY_CARGO_SLOT``)
    when set, else plain ``cargo`` from PATH is run. No host path is committed;
  * the reviewers' E3 recipe on a tiny dependency-free toy workspace: cargo
    releases the build lock before it executes test binaries, so with ONE shared
    target a second checkout's ``cargo test --no-run`` replaces a binary that the
    first checkout has yet to run. With helper-derived PER-RUNNER targets
    checkout A always executes MARK_A. The shared-target leg is NOT a default
    assertion; it is the opt-in defect proof:

        python3 scripts/ci/tests/test_per_runner_target_7188.py --prove-defect

Toy targets live under <repo>/.local-runs/ and are deleted on teardown; the
toy tests are skipped when cargo is absent. Optional environment:
AI_MEMORY_CARGO_SLOT = path of a cargo slot wrapper script, run with this Python.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HELPER = REPO / "scripts" / "ci" / "shared_cargo_target.py"
SCRATCH = REPO / ".local-runs" / "per-runner-7188"
CARGO_SLOT_ENV = "AI_MEMORY_CARGO_SLOT"
EXIT_OK = 0
EXIT_USAGE = 2
TARGET_ROOT_PARTS = (".cache", "ai-memory-ci", "cargo-target")
ROOT_ENV_NAME = "AI_MEMORY_CI_TARGET_ROOT"
STARTED_FILE = "started"
SLEEP_SECS = 6
WAIT_STARTED_SECS = 120
CARGO_JOBS = "1"
PROVE_FLAG = "--prove-defect"
HOST_PATH_NEEDLE = "/ai-" + "scratch"


def cargo_command(environ=None):
    """Return the cargo launcher: the wrapper from CARGO_SLOT_ENV, else cargo."""
    env = os.environ if environ is None else environ
    wrapper = env.get(CARGO_SLOT_ENV)
    if wrapper:
        return [sys.executable, wrapper, "cargo"]
    return ["cargo"]


def cargo_cmd(args, tail=()):
    return cargo_command() + list(args) + ["-j", CARGO_JOBS] + list(tail)


def run_helper(home, *extra):
    env_file = Path(home) / "github_env"
    proc = subprocess.run(
        [sys.executable, str(HELPER), "--home", str(home), "--github-env", str(env_file)]
        + list(extra),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
    )
    exported = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    return proc.returncode, proc.stdout, exported


class HelperPerRunnerPath(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.home = Path(tempfile.mkdtemp(dir=str(SCRATCH)))

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def target(self, name):
        rc, out, exported = run_helper(self.home, "--runner-name", name)
        self.assertEqual(rc, EXIT_OK, out)
        return Path(out.strip()), exported

    def test_two_runner_names_give_two_paths_under_one_root(self):
        path_1, exp_1 = self.target("linux-fed-1")
        path_2, exp_2 = self.target("linux-fed-2")
        root = self.home.joinpath(*TARGET_ROOT_PARTS)
        self.assertNotEqual(path_1, path_2)
        self.assertEqual(path_1.parent, root)
        self.assertEqual(path_2.parent, root)
        self.assertIn("CARGO_TARGET_DIR=%s\n" % path_1, exp_1)
        self.assertIn("CARGO_TARGET_DIR=%s\n" % path_2, exp_2)

    def test_root_is_exported_for_the_prune_step(self):
        _, exported = self.target("linux-fed-1")
        root = self.home.joinpath(*TARGET_ROOT_PARTS)
        self.assertIn("%s=%s\n" % (ROOT_ENV_NAME, root), exported)

    def test_fail_closed_cases_exit_usage_and_export_nothing(self):
        bad_names = ["", " ", ".", "..", "a/b", "../x", "a b", "a;b", "ré", "a\nb"]
        for name in bad_names:
            with self.subTest(name=name):
                rc, out, exported = run_helper(self.home, "--runner-name", name)
                self.assertEqual(rc, EXIT_USAGE)
                self.assertEqual(exported, "")
                self.assertEqual(out, "")
        self.assertFalse(self.home.joinpath(*TARGET_ROOT_PARTS).exists())

    def test_missing_runner_name_exits_usage_and_exports_nothing(self):
        rc, out, exported = run_helper(self.home)
        self.assertEqual(rc, EXIT_USAGE)
        self.assertEqual(exported, "")
        self.assertFalse(self.home.joinpath(*TARGET_ROOT_PARTS).exists())


class CargoWrapperResolver(unittest.TestCase):
    def test_plain_cargo_without_the_env(self):
        self.assertEqual(cargo_command({}), ["cargo"])

    def test_wrapper_from_the_env(self):
        self.assertEqual(
            cargo_command({CARGO_SLOT_ENV: "/opt/wrap/slot.py"}),
            [sys.executable, "/opt/wrap/slot.py", "cargo"],
        )

    def test_empty_env_is_plain_cargo(self):
        self.assertEqual(cargo_command({CARGO_SLOT_ENV: ""}), ["cargo"])

    def test_no_host_wrapper_path_is_committed(self):
        text = Path(__file__).read_text(encoding="utf-8")
        self.assertNotIn(HOST_PATH_NEEDLE, text)


def make_checkout(root, mark):
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "Cargo.toml").write_text(
        '[package]\nname = "toyrun"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\n',
        encoding="utf-8",
    )
    (root / "src" / "lib.rs").write_text("", encoding="utf-8")
    # Runs first (alphabetical): announces itself, then sleeps while B builds.
    (root / "tests" / "a_slow.rs").write_text(
        "use std::{env, fs, thread, time::Duration};\n"
        "#[test] fn slow() {\n"
        '    fs::write(env::var("TOY_STARTED").unwrap(), "x").unwrap();\n'
        "    thread::sleep(Duration::from_secs(%d));\n}\n" % SLEEP_SECS,
        encoding="utf-8",
    )
    # Runs second: the binary that B's `cargo test --no-run` may replace.
    (root / "tests" / "z_mark.rs").write_text(
        '#[test] fn mark() { println!("RAN_%s"); }\n' % mark, encoding="utf-8",
    )


def run_e3(scratch, target_a, target_b):
    """Run checkout A's `cargo test` while checkout B runs `cargo test --no-run`.

    Returns the set of letters ("A", "B") whose mark A's run printed.
    """
    shutil.rmtree(scratch, ignore_errors=True)
    a, b = scratch / "checkout-a", scratch / "checkout-b"
    make_checkout(a, "MARK_A_7188")
    make_checkout(b, "MARK_B_7188")
    started = scratch / STARTED_FILE
    base = dict(
        os.environ, CARGO_INCREMENTAL="0", CARGO_SLOT_SKIP_DISK_FLOOR="1",
        CARGO_SLOT_NO_CACHE_ENV="1", TOY_STARTED=str(started),
    )
    env_a = dict(base, CARGO_TARGET_DIR=str(target_a))
    env_b = dict(base, CARGO_TARGET_DIR=str(target_b))
    subprocess.run(
        cargo_cmd(["test", "--no-run"]), cwd=str(a), env=env_a, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.1)  # B's sources must be newer than A's artifacts
    (b / "tests" / "z_mark.rs").touch()
    proc_a = subprocess.Popen(
        cargo_cmd(["test"], ["--", "--nocapture"]), cwd=str(a), env=env_a,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
    )
    deadline = time.time() + WAIT_STARTED_SECS
    while not started.exists() and time.time() < deadline and proc_a.poll() is None:
        time.sleep(0.1)
    subprocess.run(
        cargo_cmd(["test", "--no-run"]), cwd=str(b), env=env_b, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    out = proc_a.communicate()[0]
    return {letter for letter in ("A", "B") if "RAN_MARK_%s_7188" % letter in out}


@unittest.skipUnless(shutil.which("cargo"), "cargo not installed")
class E3PerRunnerTargets(unittest.TestCase):
    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_checkout_a_executes_mark_a_with_per_runner_targets(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        home = SCRATCH / "home"
        home.mkdir()
        paths = []
        for name in ("runner-1", "runner-2"):
            rc, out, _ = run_helper(home, "--runner-name", name)
            self.assertEqual(rc, EXIT_OK)
            paths.append(Path(out.strip()))
        self.assertNotEqual(paths[0], paths[1])
        self.assertEqual(run_e3(SCRATCH / "e3", paths[0], paths[1]), {"A"})


def prove_defect():
    """Opt-in: ONE shared target; the defect is reproduced when A runs B's mark."""
    scratch = REPO / ".local-runs" / "per-runner-7188-shared"
    shared = scratch / "shared-target"
    try:
        ran = run_e3(scratch / "e3", shared, shared)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print("E3 shared-target leg: MARK_A=%s MARK_B=%s" % ("A" in ran, "B" in ran))
    return 0 if ran == {"B"} else 1


class WorkflowNoExpressionInRun(unittest.TestCase):
    """r3 F2 + #7284 S3: no ${{ expression is spliced into any line of a ``run:`` body."""

    def ci_text(self):
        return (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def step_run(self, name):
        return self.run_body(self.ci_text(), name)

    def test_per_runner_target_step_has_no_expression_in_run(self):
        run = self.step_run("Per-runner cargo target (#7188)")
        self.assertNotIn("${{", run)
        self.assertIn("RUNNER_NAME_ARG", run)

    def test_prune_step_has_no_expression_in_run(self):
        self.assertNotIn("${{", self.step_run("Prune stale runner artifacts (#7188)"))

    def test_the_pin_reads_every_line_of_a_block_scalar(self):
        fixture = (
            "jobs:\n  a:\n    steps:\n"
            "      - name: Demo step\n"
            "        run: |\n"
            "          echo first\n"
            "          echo ${{ github.event.head_commit.message }}\n"
            "      - name: Next step\n"
            "        run: echo clean\n")
        self.assertIn("${{", self.run_body(fixture, "Demo step"))
        self.assertNotIn("${{", self.run_body(fixture, "Next step"))

    def test_the_pin_reads_folded_and_single_line_run_bodies(self):
        fixture = (
            "      - name: Folded\n"
            "        run: >\n"
            "          echo one\n"
            "          ${{ x }}\n"
            "      - name: Single\n"
            "        run: echo ${{ y }}\n")
        self.assertIn("${{", self.run_body(fixture, "Folded"))
        self.assertIn("${{", self.run_body(fixture, "Single"))

    def test_a_clean_block_scalar_passes_the_pin(self):
        fixture = (
            "      - name: Clean\n"
            "        env:\n"
            "          RUNNER_NAME_ARG: ${{ runner.name }}\n"
            "        run: |\n"
            "          python3 x.py \"$RUNNER_NAME_ARG\"\n"
            "          echo done\n")
        body = self.run_body(fixture, "Clean")
        self.assertNotIn("${{", body)
        self.assertIn("echo done", body)


if __name__ == "__main__":
    if PROVE_FLAG in sys.argv:
        sys.exit(prove_defect())
    unittest.main()
