#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Run and validate the fail-closed #3573 certification leg without shell tools."""
import argparse
import contextlib
import io
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


CELLS = {f"query-{engine}-{depth}" for engine in ("cte", "age") for depth in (1, 2, 3)}
CELLS |= {f"lineage-{engine}-{direction}" for engine in ("cte", "age") for direction in ("true", "false")}
CELLS |= {"paths-on-age", "paths-invalidated", "timeline-cte", "timeline-age", "invalidate-cte",
          "invalidate-age", "divergence-timeline-cte", "divergence-timeline-age"}


def verify(root):
    listed = sum(line.endswith(": test") for line in (root / "list.log").read_text().splitlines())
    log = (root / "run.log").read_text()
    result = re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", log)
    if len(result) != 1 or int(result[0]) != listed or listed < 5:
        raise ValueError("missing/partial test execution")
    if re.search(r"\bskip(?:ped)?\s*:", log, re.I):
        raise ValueError("skip in mandatory cert leg")
    if log.count("GRAPH_CASE declared-present") != 2:
        raise ValueError("both native tests must declare actual AGE")
    cells = re.findall(r"GRAPH_CELL ([\w-]+) plans=(\d+)", log)
    if {cell for cell, _ in cells} != CELLS or len(cells) != len(CELLS):
        raise ValueError("missing or duplicate matrix cell")
    for cell, count in cells:
        plans = (root / f"{cell}.jsonl").read_text().splitlines()
        if len(plans) != int(count) or not plans or any(not p.startswith(f"PLAN {cell} ") for p in plans):
            raise ValueError("missing plan evidence")
    return f"GRAPH_COMPLETE tests={listed} cells={len(cells)}"


def run_command(command, log_path, seconds, env, label):
    """Stream to disk; deadlines and owned child cleanup need no timeout binary."""
    print(f"GRAPH_STEP {label}", flush=True)
    code = 127
    with log_path.open("w") as log:
        try:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        except OSError:
            print(f"GRAPH_ERROR {label}: cannot start required executable", file=log)
        else:
            try:
                code = child.wait(timeout=seconds)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                code = 124 if isinstance(error, subprocess.TimeoutExpired) else 130
                reason = "timed out" if code == 124 else "interrupted"
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    # Reaping the leader does not prove its descendants exited.
                    # This group belongs to the session we created above.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
                print(f"GRAPH_ERROR {label}: {reason}", file=log)
    with log_path.open() as log:
        shutil.copyfileobj(log, sys.stdout)
    print(f"GRAPH_STEP_EXIT {label}={code}", flush=True)
    return code


def inventory_complete(log):
    rows = re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", log)
    return len(rows) == 1 and int(rows[0]) >= 3


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true", help="test Python gate and Rust inventory")
    modes.add_argument("--unit-test", action="store_true", help="test the Python gate without compiling Rust")
    parser.add_argument("evidence", nargs="?", type=pathlib.Path, help="validate existing evidence only")
    args = parser.parse_args(argv)
    if args.evidence is not None and (args.self_test or args.unit_test):
        parser.error("an evidence directory cannot be combined with a test mode")
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        if args.evidence is not None:
            print(verify(args.evidence))
            return 0
        out = ROOT / ".local-runs/graph-conformance"
        out.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.self_test or args.unit_test:
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
                return 1
            if args.unit_test:
                return 0
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                      text=True, timeout=10).strip()
        print(f"GRAPH_COMMIT={sha}", flush=True)
        env = os.environ.copy()
        env["AI_MEMORY_NO_CONFIG"] = "1"
        env.setdefault("CARGO_BUILD_JOBS", "2")
        print("CARGO_TARGET_DIR=" + env.get("CARGO_TARGET_DIR", "<cargo default>"), flush=True)
        cargo = ["cargo", "test", "--features", "sal-postgres", "--lib"]
        if args.self_test:
            code = run_command(cargo + ["graph_conformance::inventory", "--", "--nocapture"],
                               out / "inventory.log", 1800, env, "inventory")
            if code == 0 and not inventory_complete((out / "inventory.log").read_text()):
                print("GRAPH_ERROR inventory: missing/partial test execution", flush=True)
                return 1
            return code
        cargo += ["graph_conformance"]
        steps = [
            ("build", cargo + ["--no-run"], 1800),
            ("list", cargo + ["--", "--include-ignored", "--list"], 60),
            ("run", cargo + ["--", "--include-ignored", "--test-threads=1", "--nocapture"], 300),
        ]
        for label, command, seconds in steps:
            code = run_command(command, out / f"{label}.log", seconds, env, label)
            if code:
                print(f"GRAPH_EXIT={code}", flush=True)
                return code
        print(verify(out), flush=True)
        print("GRAPH_EXIT=0", flush=True)
        return 0
    except ValueError as error:
        print(f"GRAPH_ERROR evidence: {error}", flush=True)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("GRAPH_ERROR certification: command or evidence validation failed", flush=True)
        return 1
    except KeyboardInterrupt:
        print("GRAPH_ERROR certification: interrupted", flush=True)
        return 130
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


class GateTests(unittest.TestCase):
    """Each rejection starts with a valid control over the same sink."""
    def setUp(self):
        scratch = pathlib.Path(__file__).resolve().parents[1] / ".local-runs"
        scratch.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="graph-gate-", dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "list.log").write_text("".join(f"test_{n}: test\n" for n in range(5)))
        self.log = "GRAPH_CASE declared-present\n" * 2
        self.log += "".join(f"GRAPH_CELL {cell} plans=1\n" for cell in sorted(CELLS))
        self.log += "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        (self.root / "run.log").write_text(self.log)
        for cell in CELLS:
            (self.root / f"{cell}.jsonl").write_text(f"PLAN {cell} synthetic-test-only\n")
        self.assertEqual(verify(self.root), "GRAPH_COMPLETE tests=5 cells=18")

    def test_rejects_vacuous_summary(self):
        (self.root / "run.log").write_text(self.log.replace("5 passed", "0 passed"))
        with self.assertRaisesRegex(ValueError, "partial test execution"):
            verify(self.root)

    def test_rejects_missing_summary(self):
        (self.root / "run.log").write_text(self.log.split("test result:")[0])
        with self.assertRaisesRegex(ValueError, "partial test execution"):
            verify(self.root)

    def test_rejects_hidden_skip(self):
        (self.root / "run.log").write_text(self.log + "skip: AGE absent\n")
        with self.assertRaisesRegex(ValueError, "skip in mandatory"):
            verify(self.root)

    def test_rejects_missing_cell_even_with_stale_plan_file(self):
        (self.root / "run.log").write_text(self.log.replace("GRAPH_CELL invalidate-age plans=1\n", ""))
        with self.assertRaisesRegex(ValueError, "matrix cell"):
            verify(self.root)

    def test_rejects_empty_plan(self):
        (self.root / "invalidate-age.jsonl").write_text("")
        with self.assertRaisesRegex(ValueError, "plan evidence"):
            verify(self.root)

    def test_rejects_undeclared_engine(self):
        (self.root / "run.log").write_text(self.log.replace("declared-present", "undeclared"))
        with self.assertRaisesRegex(ValueError, "declare actual AGE"):
            verify(self.root)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="graph-runner-", dir=ROOT / ".local-runs")
        self.addCleanup(self.tmp.cleanup)
        self.log = pathlib.Path(self.tmp.name) / "child.log"

    def invoke(self, code, seconds=5):
        env = os.environ.copy()
        env["PATH"] = ""  # Neither timeout nor gtimeout is available.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = run_command([sys.executable, "-c", code], self.log, seconds, env, "probe")
        return result, output.getvalue()

    def test_success_without_external_timer(self):
        code, output = self.invoke('print("child executed")')
        self.assertEqual(code, 0)
        self.assertIn("child executed", self.log.read_text())
        self.assertIn("GRAPH_STEP_EXIT probe=0", output)

    def test_failed_child_is_reported_and_preserved(self):
        self.assertEqual(self.invoke('print("positive control")')[0], 0)
        code, output = self.invoke('import sys; print("deliberate failure"); sys.exit(17)')
        self.assertEqual(code, 17)
        self.assertIn("deliberate failure", output)
        self.assertIn("GRAPH_STEP_EXIT probe=17", output)

    def test_timeout_is_loud_and_fails_closed(self):
        self.assertEqual(self.invoke('print("positive control")')[0], 0)
        code, output = self.invoke('import time; time.sleep(30)', seconds=0.2)
        self.assertEqual(code, 124)
        self.assertIn("GRAPH_ERROR probe: timed out", output)
        self.assertIn("GRAPH_STEP_EXIT probe=124", output)

    def test_missing_command_is_loud_and_fails_closed(self):
        self.assertEqual(self.invoke('print("positive control")')[0], 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = run_command([str(self.log.parent / "missing")], self.log, 5,
                               os.environ.copy(), "probe")
        self.assertEqual(code, 127)
        self.assertIn("GRAPH_ERROR probe: cannot start required executable", output.getvalue())
        self.assertIn("GRAPH_STEP_EXIT probe=127", output.getvalue())

    def test_timeout_kills_descendant_after_leader_exits(self):
        ready = self.log.parent / "ready"
        survivor = self.log.parent / "survivor"
        descendant = (
            "import pathlib, signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"pathlib.Path({str(ready)!r}).touch(); "
            "time.sleep(1); "
            f"pathlib.Path({str(survivor)!r}).touch()"
        )
        parent = (
            "import subprocess, sys, time; "
            f"child = subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
        )
        # The same child writes the marker normally. Both versions are finite,
        # so a broken timeout implementation cannot leave an unbounded orphan.
        self.assertEqual(self.invoke(parent + "child.wait(timeout=5)")[0], 0)
        self.assertTrue(ready.exists())
        self.assertTrue(survivor.exists())
        ready.unlink()
        survivor.unlink()
        code, output = self.invoke(parent + "time.sleep(30)", seconds=0.5)
        self.assertEqual(code, 124)
        self.assertIn("GRAPH_ERROR probe: timed out", output)
        self.assertTrue(ready.exists(), "descendant must install its signal handler")
        time.sleep(1.2)
        self.assertFalse(survivor.exists(), "descendant survived the owned group timeout")

    def test_inventory_self_test_cannot_count_zero_tests(self):
        good = "test result: ok. 3 passed; 0 failed; 0 ignored;"
        self.assertTrue(inventory_complete(good))
        for bad in ["", good.replace("3 passed", "0 passed"), good + good,
                    good.replace("0 failed", "1 failed"), good.replace("0 ignored", "1 ignored")]:
            with self.subTest(log=bad):
                self.assertFalse(inventory_complete(bad))


if __name__ == "__main__":
    sys.exit(main())
