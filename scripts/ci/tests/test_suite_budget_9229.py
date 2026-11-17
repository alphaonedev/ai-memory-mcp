#!/usr/bin/env python3
"""Suite margin gate of the sqlite full test suite (#9229, ruling b29 17183e98).

Class invariant: every sqlite test invocation of the `Run tests (impact-aware)` step ends with at least
MARGIN_PCT percent of its per-invocation watchdog budget left; losing it is a named red even when every test
passed, and the still-running case is a named red at the margin deadline, before the watchdog kills it. The
full suite runs as four sequential invocations (lib, the other test targets in two round-robin parts, doc
tests) derived from cargo metadata, and anything the derivation cannot judge falls back to the one unsharded
invocation. The whole-suite ceiling (ruling b29 cdfe800f) bounds the sum of those invocations, and that
ceiling with the same margin must fit the timeout of the enclosing job as ci.yml states it.

Run: python3 -m unittest discover -s scripts/ci/tests
Standard library only.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "ci" / "suite_budget.py"
CI = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

BUDGET = 2100  # the ubuntu-latest sqlite per-invocation watchdog budget (ci.yml WATCHDOG_SECS)
DEADLINE = 1680  # 80 percent of BUDGET: the last second of wall that still holds the 20 percent margin
CEILING = 3600  # WHOLE_SUITE_CEILING_SECS: the most seconds the invocations of the sqlite full suite may sum to
# The text every margin red carries, so a lane reads it as the suite's cost, not its own failure (cdfe800f).
ISSUE_NOTE = "this red is issue #9229 (the cost of the sqlite suite), not a failure of the change under test"
SCAN_LINES = 200_000  # a log larger than any real sqlite suite log (about 53k lines at the kill)
SCAN_CEILING_SECS = 20.0  # linear scan of SCAN_LINES; a quadratic scan takes minutes
STEP_TIMEOUT_SECS = 120
REAL_MANIFEST_TEST = "test_every_tested_target_of_the_real_manifest_is_selected_once"
CI_ENV = "GITHUB_ACTIONS"
# The text of the red a CI leg without cargo gets: a skip there would hide the real-manifest check.
CI_NO_CARGO_MSG = "the real-manifest check cannot run on a CI leg without cargo: install cargo or fix PATH"
NO_CARGO_SKIP_MSG = "cargo metadata unavailable: no cargo on PATH"


def manifest_check_gap(environ, detail):
    """What a test does when the real-manifest check cannot run: ("fail", text) on a CI leg, ("skip", text) elsewhere."""
    if environ.get(CI_ENV) == "true":
        return "fail", CI_NO_CARGO_MSG if detail is None else "%s (%s)" % (CI_NO_CARGO_MSG, detail)
    return "skip", "cargo metadata unavailable: %s" % ("no cargo on PATH" if detail is None else detail)


def load():
    spec = importlib.util.spec_from_file_location("suite_budget_9229", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scratch():
    root = REPO / ".local-runs"
    root.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=str(root), prefix="suite-budget-9229-")


def run_main(sb, argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = sb.main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


class Judge(unittest.TestCase):
    def setUp(self):
        self.sb = load()

    def test_named_constants(self):
        self.assertEqual(self.sb.MARGIN_PCT, 20)
        self.assertEqual(self.sb.EXIT_MARGIN_LOST, 3)
        self.assertEqual(self.sb.EXIT_MALFORMED, 2)
        self.assertEqual(self.sb.margin_deadline(BUDGET), DEADLINE)

    def test_table(self):
        rows = (
            # elapsed, rc, verdict, words in the message
            (0, 0, "ok", "wall 0s of the 2100s budget (0 percent used, 2100s left; required margin 20 percent = 420s)"),
            (1593, 0, "ok", "1593s of the 2100s budget (75 percent used"),
            (DEADLINE, 0, "ok", "1680s of the 2100s budget (80 percent used, 420s left"),
            (DEADLINE + 1, 0, "margin-lost", "passed but used 1681s of the 2100s budget (80 percent, 419s left); "
                                             "the required margin is 20 percent (420s, so at most 1680s of "
                                             "wall)"),
            (2099, 0, "margin-lost", "passed but used 2099s"),
            (1000, 101, "ok", "1000s of the 2100s budget"),
            (DEADLINE + 1, 101, "margin-lost", "failed (rc 101) but used 1681s"),
            (2100, 124, "margin-lost", "killed by the watchdog (rc 124) after 2100s of the 2100s budget"),
            (2160, 137, "margin-lost", "killed by the watchdog (rc 137) after 2160s"),
            (5, 124, "margin-lost", "killed by the watchdog (rc 124) after 5s"),
        )
        for elapsed, rc, verdict, words in rows:
            with self.subTest(elapsed=elapsed, rc=rc):
                got, message = self.sb.judge(elapsed, BUDGET, rc)
                self.assertEqual(got, verdict)
                self.assertIn(words, message)
                if verdict != "ok":
                    self.assertIn("cut the suite cost or shard it, do not raise the budget", message)

    def test_generative_boundary(self):
        for budget in range(1, 8000, 37):
            for margin in (1, 20, 50, 99):
                deadline = self.sb.margin_deadline(budget, margin)
                for elapsed in {0, max(0, deadline - 1), deadline, deadline + 1, budget, budget + 1}:
                    with self.subTest(budget=budget, margin=margin, elapsed=elapsed):
                        verdict, _ = self.sb.judge(elapsed, budget, 0, margin)
                        held = elapsed * 100 <= budget * (100 - margin)
                        self.assertEqual(verdict, "ok" if held else "margin-lost")

    def test_malformed_is_named_never_a_pass(self):
        rows = (
            (dict(elapsed=-1, budget=BUDGET, rc=0), "elapsed must be a non-negative integer, got -1"),
            (dict(elapsed="10", budget=BUDGET, rc=0), "elapsed must be a non-negative integer, got '10'"),
            (dict(elapsed=True, budget=BUDGET, rc=0), "elapsed must be a non-negative integer, got True"),
            (dict(elapsed=1, budget=BUDGET, rc=-1), "rc must be a non-negative integer, got -1"),
            (dict(elapsed=1, budget=0, rc=0), "budget must be a positive integer of seconds, got 0"),
            (dict(elapsed=1, budget=2.5, rc=0), "budget must be a positive integer of seconds, got 2.5"),
            (dict(elapsed=1, budget=BUDGET, rc=0, margin_pct=0), "margin must be an integer percent in [1, 99], got 0"),
            (dict(elapsed=1, budget=BUDGET, rc=0, margin_pct=100), "margin must be an integer percent in [1, 99], got 100"),
        )
        for kwargs, message in rows:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(self.sb.MalformedInput) as caught:
                    self.sb.judge(**kwargs)
                self.assertEqual(str(caught.exception), message)


class GateCli(unittest.TestCase):
    def setUp(self):
        self.sb = load()

    def gate(self, *extra, elapsed=1000, rc=0, budget=BUDGET):
        return run_main(self.sb, ["gate", "--label", "full suite shard 2/3", "--elapsed", str(elapsed),
                                  "--budget", str(budget), "--rc", str(rc), *extra])

    def test_margin_held_is_a_notice_and_exit_0(self):
        rc, out, _ = self.gate()
        self.assertEqual(rc, 0)
        self.assertEqual(out, "::notice::[#9229 margin] 'full suite shard 2/3': margin held: wall 1000s of the "
                              "2100s budget (47 percent used, 1100s left; required margin 20 percent = 420s)\n")

    def test_margin_lost_after_a_pass_is_the_named_red(self):
        rc, out, _ = self.gate(elapsed=1700)
        self.assertEqual(rc, 3)
        self.assertEqual(out, "::error::[#9229 margin] 'full suite shard 2/3' lost the suite margin: passed "
                              "but used 1700s of the 2100s budget (80 percent, 400s left); the required margin is 20 percent "
                              "(420s, so at most 1680s of wall); cut the suite cost or shard it, do not raise "
                              "the budget; " + ISSUE_NOTE + "; slowest binaries: none profiled\n")

    def test_kill_names_the_slowest_binaries_of_its_own_invocation(self):
        with scratch() as d:
            log = Path(d) / "result.log"
            first = "     Running unittests src/lib.rs (target/debug/deps/ai_memory-1)\n" \
                    "test result: ok. 9 passed; 0 failed; finished in 400.00s\n" \
                    "::notice::[#1492] 'full suite shard 1/3: lib unit tests' ran 401s of the 2100s " \
                    "per-invocation watchdog budget (19% used)\n"
            log.write_text(first + "     Running tests/slow_one.rs (target/debug/deps/slow_one-2)\n"
                           "test result: ok. 1 passed; 0 failed; finished in 1500.00s\n"
                           "     Running tests/hung.rs (target/debug/deps/hung-3)\n", encoding="utf-8")
            rc, out, _ = self.gate("--log", str(log), "--log-offset", str(len(first.encode())),
                                   elapsed=2100, rc=124)
        self.assertEqual(rc, 3)
        self.assertIn("killed by the watchdog (rc 124) after 2100s of the 2100s budget", out)
        self.assertIn("do not raise the budget; " + ISSUE_NOTE + "; still running tests/hung.rs; slowest binaries: "
                      "tests/slow_one.rs 1500s", out)
        self.assertNotIn("src/lib.rs", out)

    def test_malformed_input_exits_2_with_a_named_error(self):
        rows = (
            (dict(budget=0), "malformed gate input: budget must be a positive integer of seconds, got 0"),
            (dict(elapsed=-5), "malformed gate input: elapsed must be a non-negative integer, got -5"),
        )
        for kwargs, words in rows:
            with self.subTest(kwargs=kwargs):
                rc, out, _ = self.gate(**kwargs)
                self.assertEqual(rc, 2)
                self.assertTrue(out.startswith("::error::[#9229 margin] 'full suite shard 2/3': "), out)
                self.assertIn(words, out)
                self.assertIn("refusing to pass (#9229)", out)

    def test_non_integer_argument_is_usage_exit_2(self):
        rc, out, err = run_main(self.sb, ["gate", "--label", "x", "--elapsed", "ten", "--budget", "1", "--rc", "0"])
        self.assertEqual(rc, 2)
        self.assertEqual(err, "")
        self.assertEqual(out, "::error::[#9229 margin] suite_budget: malformed arguments: argument --elapsed: not an "
                              "integer of at most 18 ASCII digits; refusing to pass (#9229)\n")

    def test_unreadable_log_or_bad_offset_on_a_lost_margin_is_malformed(self):
        with scratch() as d:
            log = Path(d) / "short.log"
            log.write_text("x\n", encoding="utf-8")
            rows = (
                (("--log", str(Path(d) / "absent.log")), "absent.log cannot be opened or read; refusing to pass"),
                (("--log", str(log), "--log-offset", "99"), "log offset 99 is past the end of"),
                (("--log", str(log), "--log-offset", "-1"), "log offset must be a non-negative integer, got -1"),
            )
            for extra, words in rows:
                with self.subTest(extra=extra):
                    rc, out, _ = self.gate(*extra, elapsed=2000)
                    self.assertEqual(rc, 2)
                    self.assertIn(words, out)


class Timer(unittest.TestCase):
    def setUp(self):
        self.sb = load()

    def test_in_flight_red_fires_at_the_deadline_before_the_kill(self):
        now = [10_000.0]
        slept = []

        def sleep(secs):
            slept.append(secs)
            now[0] += secs

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.sb.run_timer("full suite shard 2/3", BUDGET, 20, "", sleep_fn=sleep, clock=lambda: now[0])
        self.assertEqual(rc, 3)
        # One boundary with the gate (F3): 1680 s still holds the margin, so the timer fires at 1681 s.
        self.assertEqual(now[0] - 10_000.0, DEADLINE + 1)
        self.assertEqual(self.sb.judge(DEADLINE, BUDGET, 0)[0], "ok")
        self.assertEqual(self.sb.judge(DEADLINE + 1, BUDGET, 0)[0], "margin-lost")
        self.assertLess(DEADLINE + 1, BUDGET)
        self.assertLessEqual(max(slept), 60)
        self.assertEqual(out.getvalue(), "::error::[#9229 margin] 'full suite shard 2/3' lost the suite margin while "
                                         "still running: 1681s of the 2100s budget used, over the 1680s margin "
                                         "deadline; the required margin is 20 percent (420s); the watchdog kills it "
                                         "at 2100s unless it ends first; " + ISSUE_NOTE
                                         + "; slowest binaries: none profiled\n")

    def test_in_flight_red_names_the_running_binary(self):
        with scratch() as d:
            log = Path(d) / "result.log"
            log.write_text("2026-11-16T10:00:00.0Z      Running tests/a.rs (target/debug/deps/a-1)\n"
                           "2026-11-16T10:00:05.0Z test result: ok. 1 passed; 0 failed; finished in 5.00s\n"
                           "2026-11-16T10:00:05.0Z      Running tests/wedged.rs (target/debug/deps/wedged-2)\n",
                           encoding="utf-8")
            now = [time.time()]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = self.sb.run_timer("s", 100, 20, str(log), 0, sleep_fn=lambda s: now.__setitem__(0, now[0] + s),
                                       clock=lambda: now[0])
        self.assertEqual(rc, 3)
        self.assertIn("still running tests/wedged.rs", out.getvalue())

    def test_malformed_budget_refuses_to_arm(self):
        rc, out, _ = run_main(self.sb, ["timer", "--label", "x", "--budget", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("malformed timer input: budget must be a positive integer of seconds, got 0", out)


class Profile(unittest.TestCase):
    def setUp(self):
        self.sb = load()

    def test_timestamped_walls_child_lines_and_end_notice(self):
        lines = [
            "2026-11-16T10:00:00.0000000Z      Running unittests src/lib.rs (target/debug/deps/ai_memory-1)",
            "2026-11-16T10:00:01.0000000Z test result: ok. 1 passed; 0 failed; finished in 0.50s",
            "2026-11-16T10:07:00.0000000Z test result: ok. 900 passed; 0 failed; finished in 419.00s",
            "2026-11-16T10:07:00.0000000Z      Running tests/b.rs (target/debug/deps/b-2)",
            "2026-11-16T10:07:30.0000000Z test result: FAILED. 1 passed; 1 failed; finished in 29.00s",
            "2026-11-16T10:08:00.0000000Z ::notice::[#1492] 'x' ran 480s of the 2100s per-invocation watchdog budget",
            "2026-11-16T10:30:00.0000000Z job teardown",
        ]
        rows = self.sb.profile_lines(lines)
        self.assertEqual([(r["name"], r["secs"], r["libtest_secs"], r["status"]) for r in rows],
                         [("unittests src/lib.rs", 420.0, 419.0, "ok"), ("tests/b.rs", 60.0, 29.0, "FAILED")])

    def test_plain_tee_log_uses_libtest_seconds_and_doc_tests(self):
        lines = ["\x1b[32m     Running\x1b[0m tests/a.rs (target/debug/deps/a-1)",
                 "test result: ok. 3 passed; 0 failed; finished in 2.25s",
                 "   Doc-tests ai_memory",
                 "test result: ok. 7 passed; 0 failed; finished in 11.00s"]
        rows = self.sb.profile_lines(lines)
        self.assertEqual([(r["name"], r["secs"]) for r in rows], [("tests/a.rs", 2.25), ("ai_memory", 11.0)])

    def test_previous_end_notice_before_any_binary_is_not_the_end(self):
        # The offset is measured while the previous invocation's notice may still be in the tee pipe.
        lines = ["::notice::[#1492] 'shard 1' ran 400s of the 2100s per-invocation watchdog budget (19% used)",
                 "     Running tests/a.rs (target/debug/deps/a-1)",
                 "test result: ok. 1 passed; 0 failed; finished in 3.00s",
                 "::notice::[#1492] 'shard 2' ran 4s of the 2100s per-invocation watchdog budget (0% used)",
                 "     Running tests/after_end.rs (x)"]
        self.assertEqual([(r["name"], r["secs"]) for r in self.sb.profile_lines(lines)], [("tests/a.rs", 3.0)])

    def test_scan_is_linear_on_a_large_log(self):
        lines = []
        for i in range(SCAN_LINES // 2):
            lines.append("2026-11-16T10:00:00.0Z      Running tests/t%d.rs (target/debug/deps/t%d-1)" % (i, i))
            lines.append("2026-11-16T10:00:00.5Z test result: ok. 1 passed; 0 failed; finished in 0.50s")
        started = time.monotonic()
        rows = self.sb.profile_lines(lines)
        self.assertLess(time.monotonic() - started, SCAN_CEILING_SECS)
        self.assertEqual(len(rows), SCAN_LINES // 2)

    def test_profile_cli_ranks(self):
        with scratch() as d:
            log = Path(d) / "r.log"
            log.write_text("     Running tests/fast.rs (x)\ntest result: ok. 1 passed; finished in 1.00s\n"
                           "     Running tests/slow.rs (x)\ntest result: ok. 1 passed; finished in 9.00s\n",
                           encoding="utf-8")
            rc, out, _ = run_main(self.sb, ["profile", "--log", str(log), "--top", "1"])
        self.assertEqual(rc, 0)
        self.assertIn("binaries 2, summed wall 10.0s", out)
        self.assertIn("tests/slow.rs", out)
        self.assertNotIn("tests/fast.rs", out)


def metadata(targets=None, features=None, members=("pkg 1.0",)):
    if targets is None:
        targets = [
            {"kind": ["lib"], "name": "ai_memory", "test": True, "doctest": True},
            {"kind": ["bin"], "name": "ai-memory", "test": True},
            {"kind": ["test"], "name": "alpha", "test": True},
            {"kind": ["test"], "name": "beta_9229", "test": True, "required-features": []},
            {"kind": ["test"], "name": "gated", "test": True, "required-features": ["sal"]},
            {"kind": ["example"], "name": "ex_tested", "test": True},
            {"kind": ["example"], "name": "ex_plain", "test": False},
            {"kind": ["bench"], "name": "bench_plain", "test": False},
            {"kind": ["custom-build"], "name": "build-script-build", "test": False},
        ]
    if features is None:
        features = {"default": ["sqlite-bundled"], "sqlite-bundled": ["rusqlite/bundled"],
                    "sal": ["dep:bitflags"], "sal-postgres": ["sal", "dep:sqlx"]}
    return {"packages": [{"id": "pkg 1.0", "targets": targets, "features": features}],
            "workspace_members": list(members), "workspace_default_members": list(members)}


DEFAULT_SHARD = ["--bin", "ai-memory", "--test", "alpha", "--test", "beta_9229", "--example", "ex_tested"]


class ShardArgs(unittest.TestCase):
    def setUp(self):
        self.sb = load()

    def test_default_selection_minus_lib_and_doc(self):
        self.assertEqual(self.sb.shard_args(metadata()), DEFAULT_SHARD)

    def test_required_features_follow_the_enabled_closure(self):
        self.assertEqual(self.sb.shard_args(metadata(), ["sal-postgres"]),
                         DEFAULT_SHARD[:6] + ["--test", "gated"] + DEFAULT_SHARD[6:])

    def fail_or_skip(self, gap):
        kind, text = gap
        if kind == "fail":
            self.fail(text)
        self.skipTest(text)

    def test_every_tested_target_of_the_real_manifest_is_selected_once(self):
        with scratch() as d:
            meta = Path(d) / "m.json"
            if shutil.which("cargo") is None:  # a host without a toolchain skips; a CI leg fails
                self.fail_or_skip(manifest_check_gap(os.environ, None))
            with meta.open("w", encoding="utf-8") as out:
                proc = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
                                      cwd=str(REPO), stdout=out, stderr=subprocess.PIPE, timeout=120,
                                      check=False)
            if proc.returncode != 0:
                self.fail_or_skip(manifest_check_gap(os.environ, proc.stderr[-200:]))
            data = json.loads(meta.read_text(encoding="utf-8"))
        args = self.sb.shard_args(data)
        names = args[1::2]
        self.assertEqual(len(names), len(set(names)))
        package = data["packages"][0]
        want = sorted(t["name"] for t in package["targets"]
                      if t["test"] and not set(t["kind"]) & self.sb._LIB_KINDS
                      and "custom-build" not in t["kind"] and not t.get("required-features"))
        self.assertEqual(sorted(names), want)
        # The two round-robin parts the step runs: every target of the default selection exactly once,
        # none dropped and none twice, each name still behind its own kind flag.
        whole = list(zip(args[0::2], args[1::2]))
        part_1, part_2 = (self.sb.shard_args(data, part=(k, 2)) for k in (1, 2))
        pairs = list(zip(part_1[0::2], part_1[1::2])) + list(zip(part_2[0::2], part_2[1::2]))
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertEqual(sorted(pairs), sorted(whole))
        self.assertEqual(sorted(n for _, n in pairs), want)
        self.assertLessEqual(abs(len(part_1) - len(part_2)), 2)

    def test_malformed_metadata_is_refused(self):
        lib = {"kind": ["lib"], "name": "ai_memory", "test": True, "doctest": True}
        t = {"kind": ["test"], "name": "alpha", "test": True}
        rows = (
            ([], "cargo metadata is not a JSON object"),
            (metadata(members=()), "cargo metadata must name exactly one default workspace member"),
            (metadata(members=("pkg 1.0", "other")), "exactly one default workspace member"),
            (metadata(members=("missing",)), "the default workspace member has no target list"),
            (metadata(targets=[t]), "the package must have exactly one lib target, found 0"),
            (metadata(targets=[lib, lib, t]), "exactly one lib target, found 2"),
            (metadata(targets=[dict(lib, doctest=False), t]), "lib target ai_memory must have test and doctest on"),
            (metadata(targets=[dict(lib, test=False), t]), "lib target ai_memory must have test and doctest on"),
            (metadata(targets=[lib, dict(t, name="a b")]), "target name 'a b' is outside [A-Za-z0-9_-]"),
            (metadata(targets=[lib, dict(t, name="a;rm")]), "target name 'a;rm' is outside"),
            (metadata(targets=[lib, dict(t, name="--lib")]), "target name '--lib' is outside [A-Za-z0-9_-] (no leading dash)"),
            (metadata(targets=[lib, dict(t, name="-x")]), "no leading dash"),
            (metadata(targets=[lib, dict(t, name="")]), "target name '' is outside"),
            (metadata(targets=[lib, dict(t, name=None)]), "target name None is outside"),
            (metadata(targets=[lib, dict(t, kind=["weird"])]), "target alpha has an unknown kind ['weird']"),
            (metadata(targets=[lib, dict(t, kind=["test", "bin"])]), "has an unknown kind"),
            (metadata(targets=[lib, dict(t, kind="test")]), "a target has no kind list"),
            (metadata(targets=[lib, dict(t, **{"required-features": ["serde/std"]})]),
             "target alpha requires a dependency feature this gate cannot judge"),
            (metadata(targets=[lib, dict(t, **{"required-features": "sal"})]), "malformed required-features list"),
            (metadata(targets=[lib, dict(t, test=False)]), "the second shard selects no target"),
            (metadata(features=[]), "package features is not an object"),
            (metadata(features={"default": "x"}), "feature 'default' is not a list"),
        )
        for meta, words in rows:
            with self.subTest(words=words):
                with self.assertRaises(self.sb.MalformedInput) as caught:
                    self.sb.shard_args(meta)
                self.assertIn(words, str(caught.exception))

    def test_parts_partition_the_second_shard_exactly(self):
        """Generative: for every target count and part count the parts are disjoint, cover every pair once,
        keep each flag with its name, and differ in size by at most one target."""
        lib = {"kind": ["lib"], "name": "ai_memory", "test": True, "doctest": True}
        for count in range(1, 40):
            targets = [lib] + [{"kind": ["test"], "name": "t%03d" % i, "test": True} for i in range(count)]
            full = self.sb.shard_args(metadata(targets=targets))
            want = list(zip(full[0::2], full[1::2]))
            for parts in range(1, self.sb.MAX_PARTS + 1):
                with self.subTest(count=count, parts=parts):
                    if parts > count:
                        with self.assertRaises(self.sb.MalformedInput) as caught:
                            self.sb.shard_args(metadata(targets=targets), part=(parts, parts))
                        self.assertIn("selects no target", str(caught.exception))
                        continue
                    got, sizes = [], []
                    for k in range(1, parts + 1):
                        args = self.sb.shard_args(metadata(targets=targets), part=(k, parts))
                        pairs = list(zip(args[0::2], args[1::2]))
                        self.assertTrue(all(f == "--test" for f, _ in pairs))
                        got.extend(pairs)
                        sizes.append(len(pairs))
                    self.assertEqual(sorted(got), sorted(want))
                    self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_part_is_round_robin_in_manifest_order(self):
        self.assertEqual(self.sb.shard_args(metadata(), part=(1, 2)),
                         ["--bin", "ai-memory", "--test", "beta_9229"])
        self.assertEqual(self.sb.shard_args(metadata(), part=(2, 2)), ["--test", "alpha", "--example", "ex_tested"])
        self.assertEqual(self.sb.shard_args(metadata(), part=(1, 1)), DEFAULT_SHARD)

    def test_malformed_part_is_refused(self):
        for text, words in (("0/2", "part '0/2' is outside 1..N"), ("3/2", "part '3/2' is outside 1..N"),
                            ("1/0", "part '1/0' is outside"), ("1/17", "part '1/17' is outside"),
                            ("1", "part '1' is not K/N"), ("a/b", "part 'a/b' is not K/N"),
                            ("1/2/3", "is not K/N"), ("-1/2", "is not K/N"), (" 1/2", "is not K/N"),
                            ("1/" + "9" * 5000, "is not K/N")):
            with self.subTest(text=text[:20]):
                with self.assertRaises(self.sb.MalformedInput) as caught:
                    self.sb.parse_part(text)
                self.assertIn(words, str(caught.exception))
        self.assertEqual(self.sb.parse_part("2/2"), (2, 2))

    def test_cli_part_and_bad_part(self):
        with scratch() as d:
            good = Path(d) / "m.json"
            good.write_text(json.dumps(metadata()), encoding="utf-8")
            rc, out, _ = run_main(self.sb, ["shard-args", "--metadata", str(good), "--part", "2/2"])
            self.assertEqual((rc, out.splitlines()), (0, ["--test", "alpha", "--example", "ex_tested"]))
            rc, out, err = run_main(self.sb, ["shard-args", "--metadata", str(good), "--part", "5/2"])
            self.assertEqual((rc, out), (2, ""))
            self.assertIn("::warning::[#9229 margin] shard-args: part '5/2' is outside 1..N", err)
            self.assertIn("the full suite runs unsharded (#9229)", err)

    def test_unknown_requested_feature_is_refused(self):
        with self.assertRaises(self.sb.MalformedInput) as caught:
            self.sb.shard_args(metadata(), ["nope"])
        self.assertIn("requested feature 'nope' is not a feature of the package", str(caught.exception))
        with self.assertRaises(self.sb.MalformedInput):
            self.sb.shard_args(metadata(), ["a b"])

    def test_cli_prints_one_argument_per_line_or_warns_and_exits_2(self):
        with scratch() as d:
            good = Path(d) / "m.json"
            good.write_text(json.dumps(metadata()), encoding="utf-8")
            rc, out, _ = run_main(self.sb, ["shard-args", "--metadata", str(good)])
            self.assertEqual(rc, 0)
            self.assertEqual(out.splitlines(), DEFAULT_SHARD)
            refused = "cannot be read as JSON (unreadable, not UTF-8, or not JSON within the decoder's depth); the full"
            for body, words in (("", refused), ("{", refused), (None, refused)):
                bad = Path(d) / "bad.json"
                if bad.exists():
                    bad.unlink()
                if body is not None:
                    bad.write_text(body, encoding="utf-8")
                with self.subTest(body=body):
                    rc, out, err = run_main(self.sb, ["shard-args", "--metadata", str(bad)])
                    self.assertEqual(rc, 2)
                    self.assertEqual(out, "")
                    self.assertIn("::warning::[#9229 margin] shard-args: ", err)
                    self.assertIn(words, err)
                    self.assertIn("the full suite runs unsharded (#9229)", err)


LEGS_FIXTURE = """jobs:
  lint:
    timeout-minutes: 15
  check:
    name: Check (${{ matrix.leg }})
    timeout-minutes: %(job_timeout)s
    strategy:
      matrix:
        include:
%(legs)s    steps:
      - name: Run tests (impact-aware)
  other:
    timeout-minutes: 5
"""
LEG = """          - leg: %(node)s,%(tier)s
            node: %(node)s
            tier: %(tier)s
%(timeout)s"""


def workflow(job_timeout="${{ matrix.timeout }}", legs=(("ubuntu-latest", "sqlite", "95"),)):
    body = ""
    for node, tier, timeout in legs:
        line = "" if timeout is None else "            timeout: %s  # minutes\n" % timeout
        body += LEG % {"node": node, "tier": tier, "timeout": line}
    return LEGS_FIXTURE % {"job_timeout": job_timeout, "legs": body}


class RealManifestCheckOnCi(unittest.TestCase):
    """The real-manifest cell is never silently skipped on a CI leg (#9229)."""

    def run_real_manifest_cell(self, environ):
        case = ShardArgs(REAL_MANIFEST_TEST)
        result = unittest.TestResult()
        with mock.patch.dict(os.environ, environ), mock.patch.object(shutil, "which", return_value=None):
            if CI_ENV not in environ:
                os.environ.pop(CI_ENV, None)
            case.run(result)
        return result

    def test_ci_leg_without_cargo_fails_with_the_named_message(self):
        result = self.run_real_manifest_cell({CI_ENV: "true"})
        self.assertEqual(result.skipped, [])
        self.assertEqual(len(result.failures), 1, result.errors)
        self.assertTrue(result.failures[0][1].rstrip().endswith("AssertionError: " + CI_NO_CARGO_MSG))

    def test_host_without_the_ci_variable_and_without_cargo_skips_as_before(self):
        result = self.run_real_manifest_cell({})
        self.assertEqual((result.failures, result.errors), ([], []))
        self.assertEqual([reason for _, reason in result.skipped], [NO_CARGO_SKIP_MSG])

    def test_ci_leg_with_failing_cargo_metadata_fails_and_other_host_skips(self):
        failed = subprocess.CompletedProcess([], 1, stderr=b"boom")
        for environ, want in (({CI_ENV: "true"}, "fail"), ({}, "skip")):
            case = ShardArgs(REAL_MANIFEST_TEST)
            result = unittest.TestResult()
            with mock.patch.dict(os.environ, environ), mock.patch.object(shutil, "which", return_value="cargo"), \
                    mock.patch.object(subprocess, "run", return_value=failed):
                if not environ:
                    os.environ.pop(CI_ENV, None)
                case.run(result)
            if want == "fail":
                self.assertEqual(result.skipped, [])
                self.assertTrue(result.failures[0][1].rstrip().endswith(
                    "AssertionError: %s (b'boom')" % CI_NO_CARGO_MSG))
            else:
                self.assertEqual((result.failures, result.errors), ([], []))
                self.assertEqual([r for _, r in result.skipped], ["cargo metadata unavailable: b'boom'"])


class WholeSuite(unittest.TestCase):
    """Ruling b29 cdfe800f: one named ceiling for the sum of the full-suite invocations, and that ceiling plus
    the same margin fits the timeout of the enclosing job as ci.yml states it."""

    def setUp(self):
        self.sb = load()

    def test_named_ceiling_fits_every_sqlite_leg_of_the_real_workflow(self):
        self.assertEqual(self.sb.WHOLE_SUITE_CEILING_SECS, CEILING)
        for node, minutes in (("ubuntu-latest", 95), ("macos-fed", 80)):
            with self.subTest(node=node):
                secs = self.sb.job_timeout_secs(CI, "check", node, "sqlite")
                self.assertEqual(secs, minutes * 60)
                self.assertLessEqual(CEILING, self.sb.margin_deadline(secs))
        # The four per-invocation budgets must not become a silent 8400 s suite.
        self.assertLess(CEILING, 4 * BUDGET)

    def seconds(self, rows, expect=None):
        expect = len(rows) if expect is None else expect
        return run_main(self.sb, ["suite-sum", "--expect", str(expect), "--", *rows])

    def test_sum_within_the_ceiling_is_a_notice(self):
        rc, out, _ = self.seconds(["600\tlib", "1500\tpart 1/2", "1400\tpart 2/2", "100\tdoc tests"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "::notice::[#9229 margin] whole sqlite suite: 4 invocations ran 3600s of the 3600s "
                              "whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: lib 600s, part 1/2 "
                              "1500s, part 2/2 1400s, doc tests 100s\n")

    def test_sum_over_the_ceiling_is_the_named_red_with_each_invocation(self):
        rc, out, _ = self.seconds(["600\tlib", "1500\tpart 1/2", "1401\tpart 2/2", "100\tdoc tests"])
        self.assertEqual(rc, 3)
        self.assertEqual(out, "::error::[#9229 margin] whole sqlite suite lost its ceiling: 4 invocations ran 3601s, "
                              "over the 3600s whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: lib "
                              "600s, part 1/2 1500s, part 2/2 1401s, doc tests 100s; " + ISSUE_NOTE + "; cut the "
                              "suite cost or shard it, do not raise the ceiling\n")

    def test_malformed_seconds_are_named_never_a_pass(self):
        rows = (
            # rows, expected count (None = as many as given), reason
            ([], 1, "expected 1 invocation rows, found 0"),
            ([], 0, "the expected invocation count must be a positive integer, got 0"),
            (["100\tlib", "ten\tdoc tests"], None, "invocation row 2 has a non-numeric seconds value 'ten'"),
            (["100\tlib", "1.5\tdoc"], None, "invocation row 2 has a non-numeric seconds value '1.5'"),
            (["\tlib"], None, "invocation row 1 has a non-numeric seconds value ''"),
            (["-5\tlib"], None, "invocation row 1 has a negative seconds value -5"),
            (["100\tlib", "200\tpart", "300\tlib"], None, "invocation row 3 repeats the invocation 'lib'"),
            (["100 lib"], None, "invocation row 1 is not '<seconds><TAB><label>'"),
            (["100\t"], None, "invocation row 1 is not '<seconds><TAB><label>'"),
            (["100\tlib", ""], None, "invocation row 2 is not '<seconds><TAB><label>'"),
        )
        for given, expect, reason in rows:
            with self.subTest(rows=given, expect=expect):
                rc, out, _ = self.seconds(given, expect)
                self.assertEqual(rc, 2)
                self.assertEqual(out, "::error::[#9229 margin] whole sqlite suite: malformed input: %s; "
                                      "refusing to pass (#9229)\n" % reason)

    def plan(self, d, text, node="ubuntu-latest", tier="sqlite"):
        path = Path(d) / "ci.yml"
        if path.exists():
            path.unlink()
        if text is not None:
            path.write_text(text, encoding="utf-8")
        return run_main(self.sb, ["suite-plan", "--workflow", str(path), "--job", "check", "--node", node,
                                  "--tier", tier])

    def test_plan_of_the_real_workflow_fits(self):
        rc, out, _ = run_main(self.sb, ["suite-plan", "--workflow", str(REPO / ".github" / "workflows" / "ci.yml"),
                                        "--job", "check", "--node", "ubuntu-latest", "--tier", "sqlite"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "::notice::[#9229 margin] whole-suite plan: the 3600s whole-suite ceiling fits the "
                              "95-minute timeout of job 'check' (node=ubuntu-latest tier=sqlite) with the required "
                              "20 percent margin (at most 4560s)\n")

    def test_a_ceiling_that_cannot_fit_the_job_is_a_named_red_at_derivation(self):
        with scratch() as d:
            rc, out, _ = self.plan(d, workflow(legs=(("ubuntu-latest", "sqlite", "74"),)))
            self.assertEqual(rc, 3)
            self.assertEqual(out, "::error::[#9229 margin] whole-suite plan refused: the 3600s whole-suite ceiling "
                                  "(WHOLE_SUITE_CEILING_SECS) does not fit the 74-minute timeout of job 'check' "
                                  "(node=ubuntu-latest tier=sqlite) with the required 20 percent margin (at most 3552s); "
                                  + ISSUE_NOTE + "; cut the suite cost or shard it, do not raise the ceiling\n")
            rc, _, _ = self.plan(d, workflow(legs=(("ubuntu-latest", "sqlite", "75"),)))
            self.assertEqual(rc, 0)  # 75 min = 4500 s, 80 percent = 3600 s: the ceiling exactly fits
            rc, out, _ = self.plan(d, workflow(job_timeout="80"))
            self.assertEqual(rc, 0)  # a literal job timeout is read as it stands
            self.assertIn("fits the 80-minute timeout of job 'check'", out)

    def test_absent_or_unreadable_job_timeout_is_named_never_a_pass(self):
        rows = (
            (None, {}, "the workflow file cannot be read (unreadable or not UTF-8)"),
            ("jobs:\n  lint:\n    timeout-minutes: 5\n", {}, "the workflow has no job 'check'"),
            ("check:\n  timeout-minutes: 5\n", {}, "the workflow has no job 'check'"),
            (workflow().replace("    timeout-minutes: ${{ matrix.timeout }}\n", ""), {},
             "job 'check' has no timeout-minutes"),
            (workflow(job_timeout="soon"), {},
             "job 'check' timeout-minutes 'soon' is neither an integer of minutes nor ${{ matrix.timeout }}"),
            (workflow(job_timeout="0"), {},
             "job 'check' timeout-minutes '0' is neither an integer of minutes nor ${{ matrix.timeout }}"),
            (workflow(), {"node": "macos-fed"}, "job 'check' has no matrix leg node=macos-fed tier=sqlite"),
            (workflow(legs=(("ubuntu-latest", "sqlite", None),)), {},
             "matrix leg node=ubuntu-latest tier=sqlite of job 'check' has no timeout"),
            (workflow(legs=(("ubuntu-latest", "sqlite", "ninety"),)), {},
             "matrix leg node=ubuntu-latest tier=sqlite of job 'check' timeout 'ninety' is not a positive "
             "integer of minutes"),
            (workflow(legs=(("ubuntu-latest", "sqlite", "-95"),)), {},
             "matrix leg node=ubuntu-latest tier=sqlite of job 'check' timeout '-95' is not a positive "
             "integer of minutes"),
            (workflow(legs=(("ubuntu-latest", "sqlite", "95"), ("ubuntu-latest", "sqlite", "60"))), {},
             "job 'check' has 2 matrix legs node=ubuntu-latest tier=sqlite"),
        )
        with scratch() as d:
            for text, kwargs, reason in rows:
                with self.subTest(reason=reason):
                    rc, out, _ = self.plan(d, text, **kwargs)
                    self.assertEqual(rc, 2)
                    self.assertEqual(out, "::error::[#9229 margin] whole-suite plan: malformed input: %s; "
                                          "refusing to pass (#9229)\n" % reason)
            bad = Path(d) / "ci.yml"
            bad.write_bytes(b"\xff\xfe jobs:\n")
            rc, out, _ = run_main(self.sb, ["suite-plan", "--workflow", str(bad), "--job", "check", "--node",
                                            "ubuntu-latest", "--tier", "sqlite"])
            self.assertEqual(rc, 2)
            self.assertIn("malformed input: the workflow file cannot be read (unreadable or not UTF-8); refusing", out)


def function_body(text, name):
    m = re.search(r"^(\s*)%s\(\) \{\n" % re.escape(name), text, re.M)
    if not m:
        raise AssertionError("function %s() not found" % name)
    end = text.index("\n%s}\n" % m.group(1), m.end())
    return text[m.end():end]


def step_script():
    m = re.search(r"      - name: Run tests \(impact-aware\)\n(.*?)\n        run: \|\n(.*?)\n      (?:#|- )", CI, re.S)
    if not m:
        raise AssertionError("Run tests step not found")
    return textwrap.dedent(m.group(2))


class Wiring(unittest.TestCase):
    """Text pins: the gate wraps every sqlite invocation and never the enterprise shard chains."""

    def test_timer_before_the_watchdog_and_gate_after_it(self):
        for fn, watchdog in (("run_tests", 'cargo test --no-fail-fast "$@" || rc=$?'),
                             ("run_doc_tests", 'cargo test --doc --no-fail-fast "$@" || rc=$?')):
            with self.subTest(fn=fn):
                body = function_body(CI, fn)
                timer = body.index("scripts/ci/suite_budget.py timer")
                kill = body.index('"$TIMEOUT_BIN" --signal=TERM --kill-after=60 "$WATCHDOG_SECS" ' + watchdog)
                gate = body.index("scripts/ci/suite_budget.py gate")
                self.assertLess(timer, kill)
                self.assertLess(kill, gate)
                self.assertIn('[ "${SUITE_MARGIN_GATE:-0}" = "1" ]', body)
                self.assertIn('--budget "$WATCHDOG_SECS"', body[gate:])

    def test_sqlite_full_suite_is_sharded_and_gated(self):
        body = function_body(CI, "run_sqlite_full_suite")
        self.assertIn("scripts/ci/suite_budget.py shard-args", body)
        for label in ('"full suite shard 1/4: lib unit tests" $FEAT --lib $TAIL',
                      '"full suite shard 2/4: bins, integration tests and tested examples, part 1/2" $FEAT '
                      '"${part_1[@]}" $TAIL',
                      '"full suite shard 3/4: bins, integration tests and tested examples, part 2/2" $FEAT '
                      '"${part_2[@]}" $TAIL',
                      '"full suite shard 4/4: doc tests" $FEAT $TAIL',
                      '"full suite (cargo test)" $FEAT $TAIL',
                      "--part 1/2", "--part 2/2"):
            self.assertIn(label, body)
        self.assertEqual(body.count("SUITE_MARGIN_GATE=1 run_"), 5)
        plan = body.index("scripts/ci/suite_budget.py suite-plan")
        total = body.index("scripts/ci/suite_budget.py suite-sum")
        self.assertLess(plan, body.index("SUITE_MARGIN_GATE=1 run_"))
        self.assertLess(body.rindex("SUITE_MARGIN_GATE=1 run_"), total)
        for fn in ("run_tests", "run_doc_tests"):
            with self.subTest(fn=fn):
                self.assertIn('SUITE_SECONDS+=("${elapsed}"$\'\\t\'"${label}")', function_body(CI, fn))
        self.assertIn('local -a SUITE_SECONDS=()', body)
        self.assertIn('suite-sum --expect "$expect" -- ${SUITE_SECONDS[@]+"${SUITE_SECONDS[@]}"}', body)
        self.assertNotIn("SUITE_SECONDS_FILE", CI)

    def test_enterprise_shard_chains_carry_no_margin_gate(self):
        for fn in ("run_shard", "run_sharded"):
            with self.subTest(fn=fn):
                self.assertNotIn("SUITE_MARGIN_GATE", function_body(CI, fn))

    def test_ceilings_unchanged(self):
        self.assertIn("          WATCHDOG_SECS=2100\n", CI)
        self.assertIn("              WATCHDOG_SECS=2400\n", CI)


STUB_CARGO = """#!%(python)s
\"\"\"Stub cargo: records its arguments; each timed `test` run advances the clock file; `metadata` prints the fixture.\"\"\"
import sys
from pathlib import Path
with open(%(calls)r, "a", encoding="utf-8") as calls:
    calls.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["test"] and "--no-run" not in sys.argv[1:]:
    clock = Path(%(clock)r)
    clock.write_text(str(int(clock.read_text()) + %(secs)d))
if sys.argv[1:2] == ["metadata"] and Path(%(meta)r).is_file():
    sys.stdout.write(Path(%(meta)r).read_text(encoding="utf-8"))
sys.exit(0)
"""
STUB_PYTHON = """#!%(python)s
\"\"\"Stub python3: every suite_budget.py gate call is red (exit 3); any other call runs the real interpreter.\"\"\"
import os
import sys
if "gate" in sys.argv[1:]:
    print("stub gate red", flush=True)
    sys.exit(3)
os.execv(%(python)r, [%(python)r] + sys.argv[1:])
"""
# The step measures each invocation with `date +%s`. The stub clock is a file: the stub date answers the frozen epoch
# plus the file, and every timed stub-cargo `test` run adds CARGO_RUN_SECS to it (the clock-file method of the
# integrity test file), so each invocation's wall is exactly CARGO_RUN_SECS at any host load and a step that stops
# reading the clock for any invocation shows a different, exact number.
FROZEN_EPOCH = 1_800_000_000
CARGO_RUN_SECS = 10
STUB_DATE = """#!%(python)s
\"\"\"Stub date: +%%s answers the frozen epoch plus the clock file; every other form is the real date.\"\"\"
import os
import sys
from pathlib import Path
if sys.argv[1:] == ["+%%s"]:
    print(%(epoch)d + int(Path(%(clock)r).read_text()))
    sys.exit(0)
os.execv(%(real)r, [%(real)r] + sys.argv[1:])
"""
SUM_RE = re.compile(r"^::(?:notice|error)::\[#9229 margin\] whole sqlite suite(?: lost its ceiling)?: .*$", re.M)


class StepExec(unittest.TestCase):
    """Runs the extracted step with a stub cargo (precedent test_ci_test_step_exec_6795)."""

    def run_step(self, meta=None, impact="__ALL__", red_gate=False, node="ubuntu-latest"):
        with scratch() as d:
            d = Path(d)
            calls = d / "cargo.calls"
            bindir = d / "bin"
            bindir.mkdir()
            meta_path = d / "fixture-metadata.json"
            if meta is not None:
                meta_path.write_text(json.dumps(meta), encoding="utf-8")
            stub = bindir / "cargo"
            clock = d / "clock"
            clock.write_text("0")
            stub.write_text(STUB_CARGO % {"python": sys.executable, "calls": str(calls), "meta": str(meta_path),
                                          "clock": str(clock), "secs": CARGO_RUN_SECS})
            stub.chmod(0o755)
            date = bindir / "date"
            date.write_text(STUB_DATE % {"python": sys.executable, "epoch": FROZEN_EPOCH,
                                         "clock": str(clock), "real": shutil.which("date")})
            date.chmod(0o755)
            if red_gate:
                py = bindir / "python3"
                py.write_text(STUB_PYTHON % {"python": sys.executable})
                py.chmod(0o755)
            script = d / "step.sh"
            script.write_text("#!/bin/bash\n" + step_script() + "\n")
            env = dict(os.environ)
            env.update({
                "PATH": "%s:%s" % (bindir, env.get("PATH", "")),
                "AI_MEMORY_NO_CONFIG": "1", "TIER": "sqlite", "CI_NODE": node,
                "TEST_IMPACT": impact, "JOB_TIMEOUT_MIN": "95", "JOB_T0": str(FROZEN_EPOCH),
                "RUNNER_TEMP": str(d), "GITHUB_ENV": str(d / "env"),
            })
            r = subprocess.run(["bash", str(script)], cwd=str(REPO), env=env, capture_output=True, text=True,
                               timeout=STEP_TIMEOUT_SECS)
            lines = calls.read_text().splitlines() if calls.exists() else []
            # The step keeps the seconds in shell memory (S1): the suite-sum line is the record of the rows.
            self.assertEqual(sorted(p.name for p in d.iterdir() if "seconds" in p.name), [])
            sums = SUM_RE.findall(r.stdout)
            self.sum_line = sums[0] if len(sums) == 1 else None
            return r, lines

    def test_full_suite_runs_four_gated_shards(self):
        r, calls = self.run_step(meta=metadata())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        timed = [c for c in calls if c.startswith("test ") and "--no-run" not in c]
        self.assertEqual(timed, ["test --no-fail-fast --lib",
                                 "test --no-fail-fast --bin ai-memory --test beta_9229",
                                 "test --no-fail-fast --test alpha --example ex_tested",
                                 "test --doc --no-fail-fast"])
        for label in ("full suite shard 1/4: lib unit tests",
                      "full suite shard 2/4: bins, integration tests and tested examples, part 1/2",
                      "full suite shard 3/4: bins, integration tests and tested examples, part 2/2",
                      "full suite shard 4/4: doc tests"):
            self.assertIn("::notice::[#9229 margin] '%s': margin held: wall %ds of the 2100s budget"
                          % (label, CARGO_RUN_SECS), r.stdout)
        self.assertEqual(self.sum_line, "::notice::[#9229 margin] whole sqlite suite: 4 invocations ran 40s of the "
                                        "3600s whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: "
                                        "full suite shard 1/4: lib unit tests 10s, "
                                        "full suite shard 2/4: bins, integration tests and tested examples, part 1/2 10s, "
                                        "full suite shard 3/4: bins, integration tests and tested examples, part 2/2 10s, "
                                        "full suite shard 4/4: doc tests 10s")
        self.assertIn("::notice::[#9229 margin] whole-suite plan: the 3600s whole-suite ceiling fits the 95-minute "
                      "timeout of job 'check'", r.stdout)
        self.assertIn("::notice::[#9229 margin] whole sqlite suite: 4 invocations ran 40s of the 3600s whole-suite "
                      "ceiling", r.stdout)
        self.assertLess(r.stdout.index("whole-suite plan"), r.stdout.index("'full suite shard 1/4"))
        self.assertLess(r.stdout.index("'full suite shard 4/4: doc tests': margin held"),
                        r.stdout.index("whole sqlite suite: 4 invocations"))

    def test_underivable_shards_fall_back_to_the_one_gated_invocation(self):
        r, calls = self.run_step(meta=None)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        timed = [c for c in calls if c.startswith("test ") and "--no-run" not in c]
        self.assertEqual(timed, ["test --no-fail-fast"])
        self.assertIn("::warning::[#9229 margin] shard-args: ", r.stdout + r.stderr)
        self.assertIn("::notice::[#9229 margin] 'full suite (cargo test)': margin held: wall 10s of the 2100s budget", r.stdout)
        # The fallback keeps the gate, the doc tests (inside the one cargo test) and the whole-suite ceiling.
        self.assertEqual(self.sum_line, "::notice::[#9229 margin] whole sqlite suite: 1 invocations ran 10s of the "
                                        "3600s whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: "
                                        "full suite (cargo test) 10s")
        self.assertIn("::notice::[#9229 margin] whole sqlite suite: 1 invocations ran 10s", r.stdout)

    def test_a_part_that_selects_nothing_falls_back_to_the_one_gated_invocation(self):
        lib = {"kind": ["lib"], "name": "ai_memory", "test": True, "doctest": True}
        r, calls = self.run_step(meta=metadata(targets=[lib, {"kind": ["test"], "name": "only", "test": True}]))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        timed = [c for c in calls if c.startswith("test ") and "--no-run" not in c]
        self.assertEqual(timed, ["test --no-fail-fast"])
        self.assertIn("::warning::[#9229 margin] shard-args: the second shard part 2/2 selects no target",
                      r.stdout + r.stderr)

    def test_impact_path_is_gated_too(self):
        r, _ = self.run_step(meta=metadata(), impact="recall_observability")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("::notice::[#9229 margin] 'cargo test --lib': margin held: wall 10s of the 2100s budget", r.stdout)

    def test_a_red_gate_fails_the_step_even_when_cargo_passed(self):
        r, calls = self.run_step(meta=metadata(), red_gate=True)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)  # exit 3 reaches the step, never swallowed
        self.assertIn("stub gate red", r.stdout)
        # A red gate does not stop the later invocations or the whole-suite sum.
        self.assertIsNotNone(self.sum_line)
        self.assertIn("whole sqlite suite: 4 invocations ran 40s", self.sum_line)
        self.assertEqual(self.sum_line.count("full suite shard "), 4)
        self.assertEqual(r.stdout.count("stub gate red"), 4)
        self.assertIn("whole sqlite suite: 4 invocations ran", r.stdout)

    def test_a_plan_that_cannot_be_derived_is_red_before_any_test(self):
        r, calls = self.run_step(meta=metadata(), node="nowhere")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("::error::[#9229 margin] whole-suite plan: malformed input: job 'check' has no matrix leg "
                      "node=nowhere tier=sqlite; refusing to pass (#9229)", r.stdout)
        self.assertEqual([c for c in calls if c.startswith("test ")], [])


if __name__ == "__main__":
    unittest.main()
