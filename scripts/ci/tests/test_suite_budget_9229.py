#!/usr/bin/env python3
"""Suite margin gate of the sqlite full test suite (#9229, ruling b29 17183e98).

Class invariant: every sqlite test invocation of the `Run tests (impact-aware)` step ends with at least
MARGIN_PCT percent of its per-invocation watchdog budget left; losing it is a named red even when every test
passed, and the still-running case is a named red at the margin deadline, before the watchdog kills it. The
full suite runs as three sequential invocations (lib, the other test targets, doc tests) derived from cargo
metadata, and anything the derivation cannot judge falls back to the one unsharded invocation.

Run: python3 -m unittest discover -s scripts/ci/tests
Standard library only.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "ci" / "suite_budget.py"
CI = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

BUDGET = 2100  # the ubuntu-latest sqlite per-invocation watchdog budget (ci.yml WATCHDOG_SECS)
DEADLINE = 1680  # 80 % of BUDGET: the last second of wall that still holds the 20 % margin
SCAN_LINES = 200_000  # a log larger than any real sqlite suite log (about 53k lines at the kill)
SCAN_CEILING_SECS = 20.0  # linear scan of SCAN_LINES; a quadratic scan takes minutes
STEP_TIMEOUT_SECS = 120


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
            (0, 0, "ok", "wall 0s of the 2100s budget (0% used, 2100s left; required margin 20% = 420s)"),
            (1593, 0, "ok", "1593s of the 2100s budget (75% used"),
            (DEADLINE, 0, "ok", "1680s of the 2100s budget (80% used, 420s left"),
            (DEADLINE + 1, 0, "margin-lost", "passed but used 1681s of the 2100s budget (80%, 419s left); the "
                                             "required margin is 20% (420s, so at most 1680s of wall)"),
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
                              "2100s budget (47\\x25 used, 1100s left; required margin 20\\x25 = 420s)\n")

    def test_margin_lost_after_a_pass_is_the_named_red(self):
        rc, out, _ = self.gate(elapsed=1700)
        self.assertEqual(rc, 3)
        self.assertEqual(out, "::error::[#9229 margin] 'full suite shard 2/3' lost the suite margin (#9229): passed "
                              "but used 1700s of the 2100s budget (80\\x25, 400s left); the required margin is 20\\x25 "
                              "(420s, so at most 1680s of wall); cut the suite cost or shard it, do not raise "
                              "the budget\n")

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
        self.assertIn("still running tests/hung.rs", out)
        self.assertIn("slowest: tests/slow_one.rs 1500s", out)
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
        rc, _, err = run_main(self.sb, ["gate", "--label", "x", "--elapsed", "ten", "--budget", "1", "--rc", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("not an integer: 'ten'", err)

    def test_unreadable_log_or_bad_offset_on_a_lost_margin_is_malformed(self):
        with scratch() as d:
            log = Path(d) / "short.log"
            log.write_text("x\n", encoding="utf-8")
            rows = (
                (("--log", str(Path(d) / "absent.log")), "cannot be read (FileNotFoundError)"),
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
        self.assertEqual(now[0] - 10_000.0, DEADLINE)
        self.assertLess(DEADLINE, BUDGET)
        self.assertLessEqual(max(slept), 60)
        self.assertEqual(out.getvalue(), "::error::[#9229 margin] 'full suite shard 2/3' lost the suite margin while "
                                         "still running (#9229): 1680s of the 2100s budget used, the required "
                                         "margin is 20\\x25 (420s); the watchdog kills it at 2100s unless it ends "
                                         "first\n")

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

    def test_every_tested_target_of_the_real_manifest_is_selected_once(self):
        with scratch() as d:
            meta = Path(d) / "m.json"
            proc = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
                                  cwd=str(REPO), stdout=meta.open("w"), stderr=subprocess.PIPE, timeout=120,
                                  check=False)
            if proc.returncode != 0:
                self.skipTest("cargo metadata unavailable: %s" % proc.stderr[-200:])
            data = json.loads(meta.read_text(encoding="utf-8"))
        args = self.sb.shard_args(data)
        names = args[1::2]
        self.assertEqual(len(names), len(set(names)))
        package = data["packages"][0]
        want = sorted(t["name"] for t in package["targets"]
                      if t["test"] and not set(t["kind"]) & self.sb._LIB_KINDS
                      and "custom-build" not in t["kind"] and not t.get("required-features"))
        self.assertEqual(sorted(names), want)

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
            for body, words in (("", "cannot be read as JSON (JSONDecodeError)"), ("{", "cannot be read as JSON"),
                                (None, "cannot be read as JSON (FileNotFoundError)")):
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
        for label in ('"full suite shard 1/3: lib unit tests" $FEAT --lib $TAIL',
                      '"full suite shard 3/3: doc tests" $FEAT $TAIL',
                      '"full suite (cargo test)" $FEAT $TAIL'):
            self.assertIn(label, body)
        self.assertEqual(body.count("SUITE_MARGIN_GATE=1 run_"), 4)

    def test_enterprise_shard_chains_carry_no_margin_gate(self):
        for fn in ("run_shard", "run_sharded"):
            with self.subTest(fn=fn):
                self.assertNotIn("SUITE_MARGIN_GATE", function_body(CI, fn))

    def test_ceilings_unchanged(self):
        self.assertIn("          WATCHDOG_SECS=2100\n", CI)
        self.assertIn("              WATCHDOG_SECS=2400\n", CI)


STUB_CARGO = """#!/bin/sh
echo "$@" >> "%(calls)s"
if [ "$1" = metadata ]; then
  if [ -f "%(meta)s" ]; then cat "%(meta)s"; fi
fi
exit 0
"""
STUB_PYTHON = """#!/bin/sh
for a in "$@"; do
  if [ "$a" = gate ]; then echo "stub gate red"; exit 3; fi
done
exec "%(python)s" "$@"
"""


class StepExec(unittest.TestCase):
    """Runs the extracted step with a stub cargo (precedent test_ci_test_step_exec_6795)."""

    def run_step(self, meta=None, impact="__ALL__", red_gate=False):
        with scratch() as d:
            d = Path(d)
            calls = d / "cargo.calls"
            bindir = d / "bin"
            bindir.mkdir()
            meta_path = d / "fixture-metadata.json"
            if meta is not None:
                meta_path.write_text(json.dumps(meta), encoding="utf-8")
            stub = bindir / "cargo"
            stub.write_text(STUB_CARGO % {"calls": calls, "meta": meta_path})
            stub.chmod(0o755)
            if red_gate:
                py = bindir / "python3"
                py.write_text(STUB_PYTHON % {"python": sys.executable})
                py.chmod(0o755)
            script = d / "step.sh"
            script.write_text("#!/bin/bash\n" + step_script() + "\n")
            env = dict(os.environ)
            env.update({
                "PATH": "%s:%s" % (bindir, env.get("PATH", "")),
                "AI_MEMORY_NO_CONFIG": "1", "TIER": "sqlite", "CI_NODE": "ubuntu-latest",
                "TEST_IMPACT": impact, "JOB_TIMEOUT_MIN": "95", "JOB_T0": str(int(time.time())),
                "RUNNER_TEMP": str(d), "GITHUB_ENV": str(d / "env"),
            })
            r = subprocess.run(["bash", str(script)], cwd=str(REPO), env=env, capture_output=True, text=True,
                               timeout=STEP_TIMEOUT_SECS)
            lines = calls.read_text().splitlines() if calls.exists() else []
            return r, lines

    def test_full_suite_runs_three_gated_shards(self):
        r, calls = self.run_step(meta=metadata())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        timed = [c for c in calls if c.startswith("test ") and "--no-run" not in c]
        self.assertEqual(timed, ["test --no-fail-fast --lib",
                                 "test --no-fail-fast " + " ".join(DEFAULT_SHARD),
                                 "test --doc --no-fail-fast"])
        for label in ("full suite shard 1/3: lib unit tests",
                      "full suite shard 2/3: bins, integration tests and tested examples",
                      "full suite shard 3/3: doc tests"):
            self.assertIn("::notice::[#9229 margin] '%s': margin held: wall 0s of the 2100s budget" % label,
                          r.stdout)

    def test_underivable_shards_fall_back_to_the_one_gated_invocation(self):
        r, calls = self.run_step(meta=None)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        timed = [c for c in calls if c.startswith("test ") and "--no-run" not in c]
        self.assertEqual(timed, ["test --no-fail-fast"])
        self.assertIn("::warning::[#9229 margin] shard-args: ", r.stdout + r.stderr)
        self.assertIn("::notice::[#9229 margin] 'full suite (cargo test)': margin held", r.stdout)

    def test_impact_path_is_gated_too(self):
        r, _ = self.run_step(meta=metadata(), impact="alpha")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("::notice::[#9229 margin] 'cargo test --lib': margin held", r.stdout)

    def test_a_red_gate_fails_the_step_even_when_cargo_passed(self):
        r, calls = self.run_step(meta=metadata(), red_gate=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("stub gate red", r.stdout)


if __name__ == "__main__":
    unittest.main()
