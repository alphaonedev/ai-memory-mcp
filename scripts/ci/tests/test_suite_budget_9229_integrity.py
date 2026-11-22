#!/usr/bin/env python3
"""Integrity invariants of the #9229 suite margin gate (PR 9422 round 1: F1-F5, S1-S3).

A. Step-result integrity: every non-zero outcome of a test invocation, of a suite_budget.py gate call and
   of the whole-suite sum reaches the exit code of the `Run tests (impact-aware)` step unchanged (101, 124,
   3 and 2 alike). MUTATIONS is the named table of every propagation site; each row applies one mutant to
   a copy of the step text and the row is red unless the mutated step exits wrong in its scenario.
B. Whole-suite sum completeness: the sum is judged over exactly the invocations the step ran, kept in the
   step shell, never in a file a test process can write.
C. Input totality: every subcommand ends with exit 0, 2 or 3 and a named reason line for every input up to
   the size bound, never a traceback or exit 1, and in linear time.
D. One boundary: the timer and the gate share margin_lost(); no invocation gets both the lost-margin error
   and the margin-held notice, and an emitted lost-margin error makes the step red.
E. No #9229 annotation carries a percent sign or its escaped form.
F. Every invocation prints its #6202 / #1492 notices, also when a gate red returns early, and a failed
   `cargo metadata` warns before the gated, summed fallback runs.
G. A short row count after a non-zero rc (an invocation that ended before its gate) is one notice naming rc,
   k and N, no margin-class error, and the first failing rc unchanged; with rc 0 it stays the malformed red.
H. No #9229 message carries text the interpreter or the standard library chose: one fixed reason per except
   site for every member of its tuple, one exact gate-owned line per usage-error kind.

The step harness runs the real step text with Python stubs for cargo and date (a frozen clock that the stub
cargo advances by the planned seconds of each invocation) and the real suite_budget.py.

Run: python3 -m unittest discover -s scripts/ci/tests -p "test_suite_budget_9229*.py"
Standard library only.
"""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import unittest
import unittest.mock as mock
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _base_tests():
    """The helpers of test_suite_budget_9229.py, loaded by path (its test classes are not collected twice)."""
    spec = importlib.util.spec_from_file_location("suite_budget_9229_base_helpers", str(HERE / "test_suite_budget_9229.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _base_tests()
REPO = base.REPO
BUDGET, DEADLINE, CEILING, ISSUE_NOTE = base.BUDGET, base.DEADLINE, base.CEILING, base.ISSUE_NOTE

EXIT_TEST_FAILED = 101  # cargo test with a failing test
EXIT_WATCHDOG = 124  # GNU timeout fired
EXIT_MARGIN_LOST = 3
EXIT_MALFORMED = 2
TIMER_KILLED = 143  # the margin timer killed by SIGTERM before its deadline (128 + 15)
FAKE_EPOCH = 1_800_000_000  # the frozen clock of the step harness
STEP_WORKERS = 8
STEP_TIMEOUT_SECS = 180
SLOW = DEADLINE + 1  # 1681 s: one second over the margin deadline
LABEL_SHARD = {
    1: "full suite shard 1/4: lib unit tests",
    2: "full suite shard 2/4: bins, integration tests and tested examples, part 1/2",
    3: "full suite shard 3/4: bins, integration tests and tested examples, part 2/2",
    4: "full suite shard 4/4: doc tests",
}
LABEL_FALLBACK = "full suite (cargo test)"
IMPACT = "recall_observability"
FORGED_SECONDS_FILE = "suite-9229-seconds.txt"  # the RUNNER_TEMP path the base step summed (S1)

# Hostile corpus (class C), named constants.
INVALID_TS = "2026-13-45T25:61:61Z"  # timestamp-shaped, no such date
OVERFLOW_DIGITS = "9" * 5000  # past every integer bound and past Python's int string limit
FLOAT_OVERFLOW = "9" * 400  # float() of it is inf
NON_ASCII_DIGITS = "١٢"  # Arabic-Indic 12: int() accepts it, the gate must not
NUL_BYTES = "\x00" * 64
DEEP_JSON = "[" * 100_000  # the decoder raises RecursionError or JSONDecodeError, by interpreter and host
# H. No #9229 message carries text the interpreter or the standard library chose (ruling b7d69f55): every except
# site prints ONE fixed reason for every member of its tuple, and a usage error is one exact gate-owned line per
# kind, so the deep input and a bad argument read the same on every runner image.
JSON_REFUSED = "unreadable, not UTF-8, or not JSON within the decoder's depth"
TEXT_REFUSED = "unreadable or not UTF-8"
LOG_REFUSED = "cannot be opened or read"
INTERNAL_ERROR_LINE = "::error::[#9229 margin] suite_budget: internal error; refusing to pass (#9229)\n"
BAD_ARGS = "::error::[#9229 margin] suite_budget: malformed arguments: "
INT_ARG_REFUSED = "argument %s: not an integer of at most 18 ASCII digits"
ARG_REFUSED = "argument %s: missing, or not one of its allowed values"
ARG_LIST_REFUSED = ("the argument list is not a suite_budget command line (a required argument is missing, or one is "
                    "unknown)")
# Exception names and messages the interpreter, the standard library or argparse choose.
INTERPRETER_TEXT_RE = re.compile(
    r"[A-Za-z]*(?:Error|Exception)\b|Errno|the following arguments are required|invalid choice|unrecognized "
    r"arguments|expected one argument|usage:|Expecting value|invalid start byte|recursion depth|No such file|"
    r"Permission denied|Is a directory|Input/output error|embedded null")
HOSTILE_LINES = 120_000  # a 100K+ line input
LONG_LINE_CHARS = 100_000  # one 100K-character line
CORPUS_CEILING_SECS = 10.0  # linear work over the corpus; the quadratic YAML scalar regexes took minutes
PERCENT_FORMS = ("%", "\\x25")

STUB_CARGO = '''#!%(python)s -I
"""Stub cargo of the step harness: logs its arguments and follows the plans in its directory."""
import os
import sys
import time
from pathlib import Path

d = Path(%(dir)r)


def pop(name, default):
    path = d / name
    lines = path.read_text().splitlines() if path.exists() else []
    if not lines:
        return default
    path.write_text("".join(line + "\\n" for line in lines[1:]))
    return lines[0]


args = sys.argv[1:]
with open(d / "cargo.calls", "a") as handle:
    handle.write(" ".join(args) + "\\n")
if args[:1] == ["metadata"]:
    rc = int((d / "metadata.rc").read_text())
    if rc == 0 and (d / "metadata.json").exists():
        sys.stdout.write((d / "metadata.json").read_text())
    sys.exit(rc)
if args[:1] == ["test"] and "--no-run" in args:
    sys.exit(int(pop("prebuild.plan", "0")))
if args[:1] == ["test"]:
    fields = pop("run.plan", "10 0").split()
    secs, rc = int(fields[0]), int(fields[1])
    if "tamper" in fields[2:]:
        # A test process rewrites the seconds file the base step summed (S1).
        forged = Path(os.environ["RUNNER_TEMP"]) / %(forged)r
        forged.write_text("1\\tforged lib\\n1\\tforged part 1\\n1\\tforged part 2\\n")
    clock = d / "clock"
    clock.write_text(str(int(clock.read_text()) + secs))
    runs = sum(1 for line in (d / "cargo.calls").read_text().splitlines()
               if line.startswith("test") and "--no-run" not in line.split())
    marked = d / "timer.index"
    if marked.exists() and runs == int(marked.read_text()):
        # The stubbed timer of this invocation fires "during" the run: the run ends only once it has
        # exited, as a real timer past its deadline would (on a loaded host its start can lag the run).
        waited = 0
        while not (d / "timer.done").exists() and waited < 600:
            time.sleep(0.05)
            waited += 1
    print("stub cargo test: %%ds rc %%d" %% (secs, rc))
    sys.exit(rc)
sys.exit(0)
'''

STUB_DATE = '''#!%(python)s -I
"""Stub date: +%%s answers the frozen clock of the harness; every other form is the real date."""
import os
import sys
from pathlib import Path

if sys.argv[1:] == ["+%%s"]:
    print(%(epoch)d + int(Path(%(clock)r).read_text()))
    sys.exit(0)
os.execv(%(real)r, [%(real)r] + sys.argv[1:])
'''

STUB_PYTHON = '''#!%(python)s -I
"""Stub python3: the margin timer of the invocation whose label holds the marker reports the lost margin
at once (exit 3), as if its deadline passed; every other call is the real interpreter."""
import os
import sys

args = sys.argv[1:]
if "timer" in args and "--label" in args and %(marker)r in args[args.index("--label") + 1]:
    print("::error::stub timer fired: " + args[args.index("--label") + 1], flush=True)
    open(%(done)r, "w").close()
    sys.exit(3)
os.execv(%(python)r, [%(python)r] + args)
'''

REAL_DATE = shutil.which("date")


def _write_exec(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def run_step(text, runs=(), prebuild=(), metadata_rc=0, meta="default", impact="__ALL__", node="ubuntu-latest",
             timer_fires=None):
    """(exit code, stdout+stderr, cargo calls, RUNNER_TEMP listing) of the step ``text`` under the stubs."""
    with base.scratch() as d:
        d = Path(d)
        bindir = d / "bin"
        bindir.mkdir()
        runner_temp = d / "runner-temp"
        runner_temp.mkdir()
        (d / "clock").write_text("0")
        (d / "metadata.rc").write_text(str(metadata_rc))
        if meta is not None:
            (d / "metadata.json").write_text(json.dumps(base.metadata() if meta == "default" else meta))
        (d / "run.plan").write_text("".join(line + "\n" for line in runs))
        (d / "prebuild.plan").write_text("".join(str(rc) + "\n" for rc in prebuild))
        _write_exec(bindir / "cargo", STUB_CARGO % {"python": sys.executable, "dir": str(d),
                                                    "forged": FORGED_SECONDS_FILE})
        _write_exec(bindir / "date", STUB_DATE % {"python": sys.executable, "epoch": FAKE_EPOCH,
                                                  "clock": str(d / "clock"), "real": REAL_DATE})
        if timer_fires is not None:
            _write_exec(bindir / "python3", STUB_PYTHON % {"python": sys.executable, "marker": timer_fires,
                                                           "done": str(d / "timer.done")})
            shard = re.search(r"shard ([0-9])/", timer_fires)
            if shard:  # the stub cargo of that invocation returns only after the stubbed timer exited
                (d / "timer.index").write_text(shard.group(1))
        script = d / "step.sh"
        script.write_text("#!/bin/bash\n" + text + "\n", encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "PATH": "%s:%s" % (bindir, env.get("PATH", "")),
            "AI_MEMORY_NO_CONFIG": "1", "TIER": "sqlite", "CI_NODE": node, "TEST_IMPACT": impact,
            "TEST_STEP_DEADLINE_MIN": "83", "JOB_T0": "",  # no job-left caps: the frozen clock is far from real time
            "RUNNER_TEMP": str(runner_temp), "GITHUB_ENV": str(d / "github-env"),
        })
        r = subprocess.run(["bash", str(script)], cwd=str(REPO), env=env, capture_output=True, text=True,
                           timeout=STEP_TIMEOUT_SECS)
        calls = (d / "cargo.calls").read_text().splitlines() if (d / "cargo.calls").exists() else []
        temp = sorted(p.name for p in runner_temp.iterdir())
        return r.returncode, r.stdout + r.stderr, calls, temp


def plan(slow=None, fail=None, secs=10):
    """Run plan of the four shards: shard ``slow`` takes SLOW seconds, shard ``fail`` exits 101."""
    rows = []
    for k in range(1, 5):
        rows.append("%d %d" % (SLOW if k == slow else secs, EXIT_TEST_FAILED if k == fail else 0))
    return tuple(rows)


# name: (run_step keyword arguments, the exit code the step must end with)
SCENARIOS = {
    "pass": ({"runs": plan()}, 0),
    "fail1": ({"runs": plan(fail=1)}, EXIT_TEST_FAILED),
    "fail2": ({"runs": plan(fail=2)}, EXIT_TEST_FAILED),
    "fail3": ({"runs": plan(fail=3)}, EXIT_TEST_FAILED),
    "fail4": ({"runs": plan(fail=4)}, EXIT_TEST_FAILED),
    "slow1": ({"runs": plan(slow=1)}, EXIT_MARGIN_LOST),
    "slow2": ({"runs": plan(slow=2)}, EXIT_MARGIN_LOST),
    "slow3": ({"runs": plan(slow=3)}, EXIT_MARGIN_LOST),
    "slow4": ({"runs": plan(slow=4)}, EXIT_MARGIN_LOST),
    "watchdog2": ({"runs": ("10 0", "10 %d" % EXIT_WATCHDOG, "10 0", "10 0")}, EXIT_WATCHDOG),
    "prebuild1": ({"runs": plan(), "prebuild": (EXIT_TEST_FAILED,)}, EXIT_TEST_FAILED),
    "prebuild4": ({"runs": plan(), "prebuild": (0, 0, 0, EXIT_TEST_FAILED)}, EXIT_TEST_FAILED),
    "sum3600": ({"runs": plan(secs=900)}, 0),
    "sum3601": ({"runs": ("900 0", "900 0", "900 0", "901 0")}, EXIT_MARGIN_LOST),
    "sum4000": ({"runs": plan(secs=1000)}, EXIT_MARGIN_LOST),
    "sum_forged": ({"runs": ("1000 0", "1000 0", "1000 0", "1000 0 tamper")}, EXIT_MARGIN_LOST),
    "timer2": ({"runs": plan(), "timer_fires": "shard 2/4"}, EXIT_MARGIN_LOST),
    "timer4": ({"runs": plan(), "timer_fires": "shard 4/4"}, EXIT_MARGIN_LOST),
    "fallback_pass": ({"runs": ("10 0",), "metadata_rc": EXIT_TEST_FAILED}, 0),
    "fallback_fail": ({"runs": ("10 %d" % EXIT_TEST_FAILED,), "metadata_rc": EXIT_TEST_FAILED}, EXIT_TEST_FAILED),
    "fallback_slow": ({"runs": ("%d 0" % SLOW,), "metadata_rc": EXIT_TEST_FAILED}, EXIT_MARGIN_LOST),
    "plan_refused": ({"runs": plan(), "node": "nowhere"}, EXIT_MALFORMED),
    "impact_pass": ({"runs": ("10 0", "10 0"), "impact": IMPACT}, 0),
    "impact_lib_fail": ({"runs": ("10 %d" % EXIT_TEST_FAILED, "10 0"), "impact": IMPACT}, EXIT_TEST_FAILED),
    "impact_bins_fail": ({"runs": ("10 0", "10 %d" % EXIT_TEST_FAILED), "impact": IMPACT}, EXIT_TEST_FAILED),
    "impact_lib_slow": ({"runs": ("%d 0" % SLOW, "10 0"), "impact": IMPACT}, EXIT_MARGIN_LOST),
    "impact_bins_slow": ({"runs": ("10 0", "%d 0" % SLOW), "impact": IMPACT}, EXIT_MARGIN_LOST),
}

SHARD_FAIL_HANDLER = ' || { r=$?; [ "$rc" -ne 0 ] || rc=$r; }'
# The propagation sites of the step (class A). Row: (name, function or None for the whole step, anchor that
# occurs exactly once there, operation, replacement, scenario). Operations: "delete-line" drops the line
# holding the anchor, "replace" swaps the anchor for the replacement, "append" adds it after the anchor.
MUTATIONS = (
    ("run_tests: gate return deleted (ci.yml:2115)", "run_tests", 'then return "$gate_rc"; fi', "delete-line",
     None, "slow2"),
    ("run_doc_tests: gate return deleted", "run_doc_tests", 'then return "$gate_rc"; fi', "delete-line", None,
     "slow4"),
    ("run_tests: gate rc dropped (|| true)", "run_tests", "|| gate_rc=$?", "replace", "|| true", "slow2"),
    ("run_doc_tests: gate rc dropped (|| true)", "run_doc_tests", "|| gate_rc=$?", "replace", "|| true", "slow4"),
    ("run_tests: timer rc not forwarded", "run_tests", 'wait "$timer_pid" 2>/dev/null || timer_rc=$?', "replace",
     'wait "$timer_pid" 2>/dev/null || true', "timer2"),
    ("run_doc_tests: timer rc not forwarded", "run_doc_tests", 'wait "$timer_pid" 2>/dev/null || timer_rc=$?',
     "replace", 'wait "$timer_pid" 2>/dev/null || true', "timer4"),
    ("run_tests: return rc overwritten with 0", "run_tests", 'return "$rc"', "replace", "return 0", "fail2"),
    ("run_doc_tests: return rc overwritten with 0", "run_doc_tests", 'return "$rc"', "replace", "return 0",
     "fail4"),
    ("run_tests: watchdog rc overwritten with 0", "run_tests",
     '"$WATCHDOG_SECS" cargo test --no-fail-fast "$@" || rc=$?', "replace",
     '"$WATCHDOG_SECS" cargo test --no-fail-fast "$@" || rc=0', "fail2"),
    ("run_doc_tests: watchdog rc overwritten with 0", "run_doc_tests",
     '"$WATCHDOG_SECS" cargo test --doc --no-fail-fast "$@" || rc=$?', "replace",
     '"$WATCHDOG_SECS" cargo test --doc --no-fail-fast "$@" || rc=0', "fail4"),
    ("run_tests: prebuild failure dropped (|| true)", "run_tests", 'cargo test --no-run "$@" || return "$?"',
     "replace", 'cargo test --no-run "$@" || true', "prebuild1"),
    ("run_doc_tests: prebuild failure dropped (|| true)", "run_doc_tests",
     'cargo test --no-run "$@" || return "$?"', "replace", 'cargo test --no-run "$@" || true', "prebuild4"),
    ("run_tests: seconds row not kept", "run_tests", "SUITE_SECONDS+=(", "delete-line", None, "sum4000"),
    ("run_doc_tests: seconds row not kept", "run_doc_tests", "SUITE_SECONDS+=(", "delete-line", None, "sum4000"),
    ("shard 1/4: failure dropped (|| true)", "run_sqlite_full_suite", "--lib $TAIL || rc=$?", "replace",
     "--lib $TAIL || true", "fail1"),
    ("shard 2/4: failure dropped (|| true, ci.yml:2221)", "run_sqlite_full_suite",
     '"${part_1[@]}" $TAIL' + SHARD_FAIL_HANDLER, "replace", '"${part_1[@]}" $TAIL || true', "fail2"),
    ("shard 3/4: failure dropped (|| true, ci.yml:2222)", "run_sqlite_full_suite",
     '"${part_2[@]}" $TAIL' + SHARD_FAIL_HANDLER, "replace", '"${part_2[@]}" $TAIL || true', "fail3"),
    ("shard 4/4: failure dropped (|| true, ci.yml:2223)", "run_sqlite_full_suite",
     '"full suite shard 4/4: doc tests" $FEAT $TAIL' + SHARD_FAIL_HANDLER, "replace",
     '"full suite shard 4/4: doc tests" $FEAT $TAIL || true', "fail4"),
    ("shard 2/4: rc overwritten with 0", "run_sqlite_full_suite", '"${part_1[@]}" $TAIL' + SHARD_FAIL_HANDLER,
     "replace", '"${part_1[@]}" $TAIL || { r=$?; [ "$rc" -ne 0 ] || rc=0; }', "fail2"),
    ("shard 2/4: gate red dropped (|| true)", "run_sqlite_full_suite", '"${part_1[@]}" $TAIL' + SHARD_FAIL_HANDLER,
     "replace", '"${part_1[@]}" $TAIL || true', "slow2"),
    ("fallback: failure dropped (|| true)", "run_sqlite_full_suite", '"full suite (cargo test)" $FEAT $TAIL || rc=$?',
     "replace", '"full suite (cargo test)" $FEAT $TAIL || true', "fallback_fail"),
    ("fallback: gate red dropped (|| true)", "run_sqlite_full_suite",
     '"full suite (cargo test)" $FEAT $TAIL || rc=$?', "replace", '"full suite (cargo test)" $FEAT $TAIL || true',
     "fallback_slow"),
    ("suite-sum: red dropped (|| true, ci.yml:2225)", "run_sqlite_full_suite",
     '"${SUITE_SECONDS[@]}"}' + SHARD_FAIL_HANDLER, "replace", '"${SUITE_SECONDS[@]}"} || true', "sum4000"),
    ("suite-plan: refusal dropped (|| true)", "run_sqlite_full_suite",
     '--tier "${TIER:-sqlite}" || return "$?"', "replace", '--tier "${TIER:-sqlite}" || true', "plan_refused"),
    ("full suite: return rc overwritten with 0", "run_sqlite_full_suite", 'return "$rc"', "replace", "return 0",
     "fail2"),
    ("impact path: lib failure dropped (|| true appended)", None,
     'SUITE_MARGIN_GATE=1 run_tests "cargo test --lib" $FEAT --lib $TAIL', "append", " || true", "impact_lib_fail"),
    ("impact path: lib gate red dropped (|| true appended)", None,
     'SUITE_MARGIN_GATE=1 run_tests "cargo test --lib" $FEAT --lib $TAIL', "append", " || true", "impact_lib_slow"),
    ("impact path: bins failure dropped (|| true appended)", None, '$FEAT "${ARGS[@]}" $TAIL\n', "replace",
     '$FEAT "${ARGS[@]}" $TAIL || true\n', "impact_bins_fail"),
)


def mutate(text, fn, anchor, op, replacement):
    """``text`` with one mutant applied inside function ``fn`` (or the whole text); the anchor must be unique."""
    region = text if fn is None else base.function_body(text, fn)
    if text.count(region) != 1:
        raise AssertionError("region of %s is not unique in the step" % fn)
    if region.count(anchor) != 1:
        raise AssertionError("anchor %r occurs %d times in %s" % (anchor, region.count(anchor), fn or "the step"))
    if op == "delete-line":
        lines = region.split("\n")
        mutated = "\n".join(line for line in lines if anchor not in line)
    elif op == "replace":
        mutated = region.replace(anchor, replacement)
    elif op == "append":
        mutated = region.replace(anchor, anchor + replacement)
    else:
        raise AssertionError("unknown operation %r" % op)
    return text.replace(region, mutated, 1)


_RESULTS = {}


def _scenario_results():
    """Exit code and output of every scenario on the real step and of every mutant, computed once in parallel."""
    if _RESULTS:
        return _RESULTS
    text = base.step_script()
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=STEP_WORKERS) as pool:
        for name, (kwargs, _) in SCENARIOS.items():
            jobs[("step", name)] = pool.submit(run_step, text, **kwargs)
        for row in MUTATIONS:
            name, fn, anchor, op, replacement, scenario = row
            try:
                mutant = mutate(text, fn, anchor, op, replacement)
            except AssertionError as exc:
                jobs[("mutant", name)] = exc
                continue
            jobs[("mutant", name)] = pool.submit(run_step, mutant, **SCENARIOS[scenario][0])
        for key, job in jobs.items():
            _RESULTS[key] = job if isinstance(job, Exception) else job.result()
    return _RESULTS


class StepResultIntegrity(unittest.TestCase):
    """Class A (F4, S2, item d): every non-zero outcome reaches the step exit code unchanged."""

    def test_every_scenario_ends_with_its_exit_code(self):
        results = _scenario_results()
        for name, (_, expected) in SCENARIOS.items():
            with self.subTest(scenario=name):
                rc, out, _, _ = results[("step", name)]
                self.assertEqual(rc, expected, out[-3000:])

    def test_each_shard_failing_in_turn_ends_the_step_with_101(self):
        results = _scenario_results()
        for k in range(1, 5):
            with self.subTest(shard=k):
                rc, out, calls, _ = results[("step", "fail%d" % k)]
                self.assertEqual(rc, EXIT_TEST_FAILED, out[-3000:])
                # A failed shard does not stop the later ones (#2500 evidence).
                self.assertEqual(len([c for c in calls if c.startswith("test ") and "--no-run" not in c]), 4)

    def test_mutation_table_every_propagation_site_is_pinned(self):
        results = _scenario_results()
        for name, fn, anchor, op, replacement, scenario in MUTATIONS:
            with self.subTest(mutant=name):
                result = results[("mutant", name)]
                if isinstance(result, Exception):
                    self.fail("mutant cannot be applied: %s" % result)
                expected = SCENARIOS[scenario][1]
                self.assertEqual(results[("step", scenario)][0], expected)
                self.assertNotEqual(result[0], expected,
                                    "mutant survived: the step still exits %d in scenario %s" % (expected, scenario))

    def test_mutation_table_names_every_required_form(self):
        names = {row[0] for row in MUTATIONS}
        for required in ("run_tests: gate return deleted (ci.yml:2115)",
                         "suite-sum: red dropped (|| true, ci.yml:2225)",
                         "shard 2/4: failure dropped (|| true, ci.yml:2221)",
                         "shard 3/4: failure dropped (|| true, ci.yml:2222)",
                         "shard 4/4: failure dropped (|| true, ci.yml:2223)"):
            self.assertIn(required, names)


class SumCompleteness(unittest.TestCase):
    """Class B (S1): the sum is judged over exactly the invocations the step ran, kept in the step shell."""

    def setUp(self):
        self.sb = base.load()

    def sum(self, rows, expect):
        return base.run_main(self.sb, ["suite-sum", "--expect", str(expect), "--"] + list(rows))

    def malformed(self, reason):
        return "::error::[#9229 margin] whole sqlite suite: malformed input: %s; refusing to pass (#9229)\n" % reason

    def test_count_rows_and_values(self):
        four = ["600\tlib", "1500\tpart 1/2", "1400\tpart 2/2", "100\tdoc tests"]
        rows = (
            ("count short", four[:3], 4, EXIT_MALFORMED, self.malformed("expected 4 invocation rows, found 3")),
            ("count long", four + ["1\textra"], 4, EXIT_MALFORMED,
             self.malformed("expected 4 invocation rows, found 5")),
            ("no rows", [], 1, EXIT_MALFORMED, self.malformed("expected 1 invocation rows, found 0")),
            ("N = 0", [], 0, EXIT_MALFORMED,
             self.malformed("the expected invocation count must be a positive integer, got 0")),
            ("non-numeric", ["100\tlib", "ten\tdoc tests"], 2, EXIT_MALFORMED,
             self.malformed("invocation row 2 has a non-numeric seconds value 'ten'")),
            ("negative", ["-5\tlib"], 1, EXIT_MALFORMED,
             self.malformed("invocation row 1 has a negative seconds value -5")),
            ("overflow digits", [OVERFLOW_DIGITS + "\tlib"], 1, EXIT_MALFORMED,
             self.malformed("invocation row 1 has a non-numeric seconds value %r" % OVERFLOW_DIGITS[:40])),
            ("non-ASCII digits", [NON_ASCII_DIGITS + "\tlib"], 1, EXIT_MALFORMED,
             self.malformed("invocation row 1 has a non-numeric seconds value %r" % NON_ASCII_DIGITS)),
            ("repeated label", ["1\tlib", "2\tlib"], 2, EXIT_MALFORMED,
             self.malformed("invocation row 2 repeats the invocation 'lib'")),
            ("empty row", ["1\tlib", ""], 2, EXIT_MALFORMED,
             self.malformed("invocation row 2 is not '<seconds><TAB><label>'")),
            ("sum 3600", ["900\ta", "900\tb", "900\tc", "900\td"], 4, 0,
             "::notice::[#9229 margin] whole sqlite suite: 4 invocations ran 3600s of the 3600s whole-suite "
             "ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: a 900s, b 900s, c 900s, d 900s\n"),
            ("sum 3601", ["900\ta", "900\tb", "900\tc", "901\td"], 4, EXIT_MARGIN_LOST,
             "::error::[#9229 margin] whole sqlite suite lost its ceiling: 4 invocations ran 3601s, over the 3600s "
             "whole-suite ceiling (WHOLE_SUITE_CEILING_SECS); per invocation: a 900s, b 900s, c 900s, d 901s; "
             + ISSUE_NOTE + "; cut the suite cost or shard it, do not raise the ceiling\n"),
        )
        for name, given, expect, rc_expected, out_expected in rows:
            with self.subTest(row=name):
                rc, out, _ = self.sum(given, expect)
                self.assertEqual((rc, out), (rc_expected, out_expected))

    def test_the_step_keeps_no_seconds_file(self):
        body = base.function_body(base.step_script(), "run_sqlite_full_suite")
        self.assertNotIn("SUITE_SECONDS_FILE", base.step_script())
        self.assertNotIn("--seconds", body)
        self.assertIn('--expect "$expect"', body)
        self.assertIn("local -a SUITE_SECONDS=()", body)

    def test_a_test_process_writing_runner_temp_cannot_turn_the_sum_green(self):
        rc, out, _, temp = _scenario_results()[("step", "sum_forged")]
        self.assertEqual(rc, EXIT_MARGIN_LOST, out[-3000:])
        self.assertIn("whole sqlite suite lost its ceiling: 4 invocations ran 4000s", out)
        self.assertIn(FORGED_SECONDS_FILE, temp)  # the forged file exists and is no input of the verdict

    def test_the_step_sum_names_each_invocation(self):
        rc, out, _, _ = _scenario_results()[("step", "pass")]
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn("whole sqlite suite: 4 invocations ran 40s of the 3600s whole-suite ceiling "
                      "(WHOLE_SUITE_CEILING_SECS); per invocation: %s 10s, %s 10s, %s 10s, %s 10s"
                      % tuple(LABEL_SHARD[k] for k in range(1, 5)), out)


# Class G (PR 9422 r2 R2-2): an invocation that ends before its gate (a failed prebuild returns before the
# SUITE_SECONDS row) leaves fewer than N rows. With a non-zero rc already set the sum is not judged: exactly one
# notice naming rc, k and N, no error of the margin class, and the first failing rc unchanged. With rc 0 a short
# row count stays the named malformed-input red, exit 2 (the S1 guard).
UNJUDGED_RCS = (0, EXIT_TEST_FAILED, EXIT_MALFORMED, EXIT_WATCHDOG)
UNJUDGED_NS = (4, 1)  # the sharded path (4 invocations) and the unsharded fallback (1)
UNJUDGED_LATER_RC = 1  # what every invocation after the first failing one returns; it must never win
UNJUDGED_ROW_SECS = 10
MARGIN_ERROR_PREFIX = "::error::[#9229 margin]"


def unjudged_notice(rc, kept, expect):
    return ("::notice::[#9229 margin] whole sqlite suite: not judged, an invocation ended before its gate "
            "(rc %d); %d of %d invocation rows kept (#9229)" % (rc, kept, expect))


def short_count_error(kept, expect):
    return ("::error::[#9229 margin] whole sqlite suite: malformed input: expected %d invocation rows, found %d; "
            "refusing to pass (#9229)" % (expect, kept))


# Row: (name, N, k rows kept, rc of the first ending invocation, the one exact whole-suite line, step exit code).
UNJUDGED_TABLE = tuple(
    ("N=%d k=%d rc=%d" % (n, k, rc), n, k, rc,
     unjudged_notice(rc, k, n) if rc else short_count_error(k, n), rc if rc else EXIT_MALFORMED)
    for n in UNJUDGED_NS for k in range(n) for rc in UNJUDGED_RCS)
UNJUDGED_TABLE_COUNT = 20  # pinned: (4 + 1) values of k times 4 values of rc

# Stubs for the callees of the real run_sqlite_full_suite: invocation i keeps a row when STUB_ROWS[i] is 1 and
# returns STUB_RCS[i]. SUITE_SECONDS is the caller's local (bash dynamic scope), as in run_tests.
UNJUDGED_HARNESS = '''STUB_RCS=(%(rcs)s)
STUB_ROWS=(%(rows)s)
STUB_NEXT=0
_stub_invocation() {
  local label="$1" i="$STUB_NEXT"
  STUB_NEXT=$((i + 1))
  if [ "${STUB_ROWS[$i]}" = 1 ]; then SUITE_SECONDS+=("%(secs)d"$'\\t'"${label}"); fi
  echo "stub invocation $((i + 1)): ${label}"
  return "${STUB_RCS[$i]}"
}
run_tests() { _stub_invocation "$1"; }
run_doc_tests() { _stub_invocation "$1"; }
run_sqlite_full_suite() {
%(body)s
}
run_sqlite_full_suite
exit "$?"
'''


def unjudged_plan(n, k, rc):
    """(rcs, rows) of the n invocations: k keep a row and pass, the next ends with rc and no row, later ones
    keep no row and return UNJUDGED_LATER_RC (0 when rc is 0)."""
    later = UNJUDGED_LATER_RC if rc else 0
    rcs = [0] * k + [rc] + [later] * (n - k - 1)
    rows = [1] * k + [0] * (n - k)
    return rcs, rows


def run_unjudged(step_text, n, k, rc):
    """(exit code, output, stub invocation count) of the real run_sqlite_full_suite of ``step_text``."""
    rcs, rows = unjudged_plan(n, k, rc)
    text = UNJUDGED_HARNESS % {"rcs": " ".join(map(str, rcs)), "rows": " ".join(map(str, rows)),
                               "secs": UNJUDGED_ROW_SECS,
                               "body": base.function_body(step_text, "run_sqlite_full_suite")}
    code, out, _, _ = run_step(text, metadata_rc=0 if n == 4 else EXIT_TEST_FAILED)
    return code, out, len(re.findall(r"^stub invocation \d+: ", out, re.M))


def unjudged_results(step_text):
    """{row name: run_unjudged result} over UNJUDGED_TABLE, in parallel."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=STEP_WORKERS) as pool:
        jobs = {row[0]: pool.submit(run_unjudged, step_text, row[1], row[2], row[3]) for row in UNJUDGED_TABLE}
        return {name: job.result() for name, job in jobs.items()}


def unjudged_failures(results):
    """{row name: why} for every UNJUDGED_TABLE row whose result breaks the invariant."""
    failures = {}
    for name, n, k, rc, line, exit_expected in UNJUDGED_TABLE:
        code, out, invocations = results[name]
        suite_lines = [l for l in out.splitlines() if "whole sqlite suite" in l]
        margin_errors = [l for l in out.splitlines() if l.startswith(MARGIN_ERROR_PREFIX)]
        if invocations != n:
            failures[name] = "ran %d invocations, expected %d" % (invocations, n)
        elif code != exit_expected:
            failures[name] = "exit %d, expected %d" % (code, exit_expected)
        elif suite_lines != [line]:
            failures[name] = "whole-suite lines %r, expected [%r]" % (suite_lines, line)
        elif margin_errors != ([] if rc else [line]):
            failures[name] = "margin-class errors %r" % margin_errors
    return failures


UNJUDGED_CONDITION = 'if [ "$rc" -ne 0 ] && [ "${#SUITE_SECONDS[@]}" -lt "$expect" ]; then'
UNJUDGED_NOTICE_ARGS = '"$rc" "${#SUITE_SECONDS[@]}" "$expect"'
SUITE_SUM_CALL = ('python3 -I scripts/ci/suite_budget.py suite-sum --expect "$expect" -- '
                  '${SUITE_SECONDS[@]+"${SUITE_SECONDS[@]}"}')
# Row: (name, anchor unique in run_sqlite_full_suite, operation, replacement, a row name that must turn red).
UNJUDGED_MUTANTS = (
    ("notice branch taken on rc 0", UNJUDGED_CONDITION, "replace",
     'if [ "${#SUITE_SECONDS[@]}" -lt "$expect" ]; then', "N=4 k=2 rc=0"),
    ("error still printed on rc 101", UNJUDGED_NOTICE_ARGS, "append", "; " + SUITE_SUM_CALL, "N=4 k=2 rc=101"),
    ("rc overwritten by 2", UNJUDGED_NOTICE_ARGS, "append", "; rc=2", "N=4 k=2 rc=101"),
)


class UnjudgedSum(unittest.TestCase):
    """Class G (R2-2): a short row count after a failure is one notice, never a second margin-class red."""

    def test_table_has_its_pinned_count(self):
        self.assertEqual(len(UNJUDGED_TABLE), UNJUDGED_TABLE_COUNT)
        self.assertEqual(len({row[0] for row in UNJUDGED_TABLE}), UNJUDGED_TABLE_COUNT)

    def test_every_row_prints_its_one_line_and_exit_code(self):
        results = unjudged_results(base.step_script())
        failures = unjudged_failures(results)
        for name, _, _, _, _, _ in UNJUDGED_TABLE:
            with self.subTest(row=name):
                self.assertNotIn(name, failures, results[name][1][-3000:])

    def test_each_mutant_of_the_branch_is_red(self):
        text = base.step_script()
        for name, anchor, op, replacement, must_fail in UNJUDGED_MUTANTS:
            with self.subTest(mutant=name):
                failures = unjudged_failures(unjudged_results(mutate(text, "run_sqlite_full_suite", anchor, op,
                                                                     replacement)))
                self.assertIn(must_fail, failures, "mutant survived")

    def test_a_failed_prebuild_on_the_real_step_is_one_notice(self):
        results = _scenario_results()
        for scenario in ("prebuild1", "prebuild4"):
            with self.subTest(scenario=scenario):
                rc, out, _, _ = results[("step", scenario)]
                self.assertEqual(rc, EXIT_TEST_FAILED, out[-3000:])
                self.assertEqual([l for l in out.splitlines() if "whole sqlite suite" in l],
                                 [unjudged_notice(EXIT_TEST_FAILED, 3, 4)])
                self.assertEqual([l for l in out.splitlines() if l.startswith(MARGIN_ERROR_PREFIX)], [])


def call_main(sb, argv):
    """(rc, stdout + stderr) of sb.main(argv); a traceback or a SystemExit is reported as the rc."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = sb.main(argv)
        except SystemExit as exc:
            rc = "SystemExit %r" % (exc.code,)
        except Exception:  # a traceback is the defect under test
            rc = "traceback: " + traceback.format_exc(limit=1).splitlines()[-1]
    return rc, out.getvalue() + err.getvalue()


class OddNameError(Exception):
    """An exception class the gate has never seen: its name must not reach the backstop line."""


# Members forced at each except site by a stub loader (class H). Each one carries the interpreter's own message.
OPEN_FAILURES = (FileNotFoundError(2, "No such file or directory"), PermissionError(13, "Permission denied"),
                 IsADirectoryError(21, "Is a directory"), OSError(5, "Input/output error"))
TEXT_FAILURES = (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), ValueError("embedded null byte"))
DECODE_FAILURES = (RecursionError("maximum recursion depth exceeded"), json.JSONDecodeError("Expecting value", "", 0),
                   ValueError("Expecting value"))
BACKSTOP_FAILURES = (KeyError("synthetic"), TypeError("unsupported operand"), RuntimeError("x"),
                     ZeroDivisionError("division by zero"), OddNameError("x"))
STUB_PATH = "stub-input.txt"  # never opened: the stub loader raises before any read
SHARD_LINE = ("::warning::[#9229 margin] shard-args: cargo metadata %s cannot be read as JSON (%s); the full suite "
              "runs unsharded (#9229)\n" % (STUB_PATH, JSON_REFUSED))
PLAN_LINE = ("::error::[#9229 margin] whole-suite plan: malformed input: the workflow file cannot be read (%s); "
             "refusing to pass (#9229)\n" % TEXT_REFUSED)
GATE_LOG_LINE = ("::error::[#9229 margin] 'x': malformed gate input: log %s %s; refusing to pass (#9229)\n"
                 % (STUB_PATH, LOG_REFUSED))
PROFILE_LOG_LINE = "[#9229 margin] profile: log %s %s\n" % (STUB_PATH, LOG_REFUSED)
SHARD_ARGV = ["shard-args", "--metadata", STUB_PATH]
PLAN_ARGV = ["suite-plan", "--workflow", STUB_PATH, "--job", "check", "--node", "n", "--tier", "t"]
GATE_LOG_ARGV = ["gate", "--label", "x", "--elapsed", str(SLOW), "--budget", str(BUDGET), "--rc", "0", "--log",
                 STUB_PATH]
GATE_OK = ["gate", "--label", "x", "--elapsed", "1", "--budget", str(BUDGET), "--rc", "0"]
# (cell, argv, exact stdout + stderr): one line per usage-error kind, never argparse's wording.
USAGE_CELLS = (
    ("usage: integer refused", GATE_OK[:4] + ["ten"] + GATE_OK[5:], INT_ARG_REFUSED % "--elapsed"),
    ("usage: integer past 18 digits", GATE_OK[:4] + [OVERFLOW_DIGITS] + GATE_OK[5:], INT_ARG_REFUSED % "--elapsed"),
    ("usage: integer value missing", GATE_OK[:-1], INT_ARG_REFUSED % "--rc"),
    ("usage: text value missing", ["gate", "--label"], ARG_REFUSED % "--label"),
    ("usage: unknown subcommand", ["nope"], ARG_REFUSED % "cmd"),
    ("usage: required arguments missing", ["gate", "--label", "x"], ARG_LIST_REFUSED),
    ("usage: no subcommand", [], ARG_LIST_REFUSED),
    ("usage: unknown option", GATE_OK + ["--bogus"], ARG_LIST_REFUSED),
    ("usage: extra positional", ["profile", "--log", STUB_PATH, "extra"], ARG_LIST_REFUSED),
)


def interpreter_cells(sb):
    """(cell, argv, exact output, patches): every member of every except tuple of suite_budget.py, forced by a
    stub loader, and every usage-error kind on the real parser. The expected output is one fixed line."""
    cells = []
    for exc in OPEN_FAILURES:
        stub = mock.patch.object(sb, "open", create=True, side_effect=exc)
        name = type(exc).__name__
        cells += [("shard-args open %s" % name, SHARD_ARGV, SHARD_LINE, stub),
                  ("suite-plan open %s" % name, PLAN_ARGV, PLAN_LINE, stub),
                  ("gate log open %s" % name, GATE_LOG_ARGV, GATE_LOG_LINE, stub),
                  ("profile log open %s" % name, ["profile", "--log", STUB_PATH], PROFILE_LOG_LINE, stub)]
    for exc in TEXT_FAILURES:
        stub = mock.patch.object(sb, "_read_bounded", side_effect=exc)
        name = type(exc).__name__
        cells += [("shard-args text %s" % name, SHARD_ARGV, SHARD_LINE, stub),
                  ("suite-plan text %s" % name, PLAN_ARGV, PLAN_LINE, stub)]
    for exc in DECODE_FAILURES:
        stub = (mock.patch.object(sb, "_read_bounded", return_value="{}"),
                mock.patch.object(sb.json, "loads", side_effect=exc))
        cells.append(("shard-args decode %s" % type(exc).__name__, SHARD_ARGV, SHARD_LINE, stub))
    for exc in BACKSTOP_FAILURES:
        stub = mock.patch.object(sb, "run_suite_sum", side_effect=exc)
        cells.append(("backstop %s" % type(exc).__name__, ["suite-sum", "--expect", "1", "1\tlib"],
                      INTERNAL_ERROR_LINE, stub))
    for cell, argv, reason in USAGE_CELLS:
        cells.append((cell, argv, BAD_ARGS + reason + "; refusing to pass (#9229)\n", ()))
    return cells


def interpreter_text_failures(sb):
    """Names of the class H cells whose output is not exactly their one line, exit 2, free of interpreter text."""
    failed = []
    for cell, argv, expected, stubs in interpreter_cells(sb):
        with contextlib.ExitStack() as stack:
            for stub in (stubs if isinstance(stubs, tuple) else (stubs,)):
                stack.enter_context(stub)
            rc, out = call_main(sb, argv)
        if rc != EXIT_MALFORMED or out != expected or INTERPRETER_TEXT_RE.search(out):
            failed.append(cell)
    return failed



# Mutants of suite_budget.py for class H: (name, old text, new text, a cell that must turn red).
INTERPRETER_MUTANTS = (
    ("class name back in the log reason", '"log %s cannot be opened or read" % (path,)',
     '"log %s cannot be opened or read (%s)" % (path, type(sys.exception()).__name__)', "gate log open OSError"),
    ("class name back in the decoder reason", '"within the decoder\'s depth)" % (metadata_path,)',
     '"within the decoder\'s depth) %s" % (metadata_path, type(sys.exception()).__name__)',
     "shard-args decode RecursionError"),
    ("class name back in the backstop", '"%s suite_budget: internal error; refusing to pass (#9229)" % TAG',
     '"%s suite_budget: internal error (%s); refusing to pass (#9229)" % (TAG, type(sys.exception()).__name__)',
     "backstop KeyError"),
    ("ArgumentParser.error override removed", "    def error(self, message):",
     "    def _error_removed(self, message):", "usage: unknown subcommand"),
)


def load_mutant(d, old, new):
    """suite_budget.py with one edit, next to a copy of workflow_annotation.py in ``d``, loaded by path."""
    source = base.SCRIPT.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise AssertionError("mutant anchor %r: %d hits" % (old, source.count(old)))
    shutil.copy(base.SCRIPT.parent / "workflow_annotation.py", Path(d) / "workflow_annotation.py")
    path = Path(d) / "suite_budget.py"
    path.write_text(source.replace(old, new), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("suite_budget_9229_mutant", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class InputTotality(unittest.TestCase):
    """Class C (F2): exit 0, 2 or 3 with a named reason for every input, never a traceback, in linear time."""

    def setUp(self):
        self.sb = base.load()

    def call(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = self.sb.main(argv)
            except SystemExit as exc:
                rc = exc.code
            except Exception:  # a traceback is the defect under test
                rc = "traceback: " + traceback.format_exc(limit=1).splitlines()[-1]
        return rc, out.getvalue() + err.getvalue()

    def write(self, d, name, text):
        path = Path(d) / name
        path.write_bytes(text.encode("utf-8", "surrogatepass"))
        return str(path)

    def assert_row(self, name, argv, rc_expected, reason):
        start = time.monotonic()
        rc, out = self.call(argv)
        took = time.monotonic() - start
        with self.subTest(row=name):
            self.assertEqual(rc, rc_expected, out[-2000:])
            self.assertIn(reason, out)
            self.assertNotIn("internal error", out)  # the backstop is never what a corpus row reaches
            self.assertNotRegex(out, INTERPRETER_TEXT_RE)
            self.assertLess(took, CORPUS_CEILING_SECS)

    def test_hostile_corpus(self):
        timed_invalid = "%s     Running tests/x.rs (target/debug/deps/x)\n" % INVALID_TS
        inf_result = ("     Running tests/overflow_bin.rs (target/debug/deps/overflow_bin)\n"
                      "test result: ok. 1 passed; 0 failed; finished in %ss\n" % FLOAT_OVERFLOW)
        many_invalid = "".join("%s line %d\n" % (INVALID_TS, i) for i in range(HOSTILE_LINES))
        long_key = "jobs:\n  check:\n    timeout-minutes: 95\n    note: a%sb\n" % (" " * LONG_LINE_CHARS)
        long_comment = ("jobs:\n  check:\n    timeout-minutes: ${{ matrix.timeout }}\n    strategy:\n      matrix:\n"
                        "        include:\n          - node: ubuntu-latest\n            tier: sqlite\n"
                        "            timeout: 95%s# minutes\n" % (" " * LONG_LINE_CHARS))
        gate = ["gate", "--label", "x", "--budget", str(BUDGET), "--rc", "0"]
        held = "::notice::[#9229 margin] 'x': margin held"
        lost = "::error::[#9229 margin] 'x' lost the suite margin"
        bad_args = "::error::[#9229 margin] suite_budget: malformed arguments: "
        with base.scratch() as d:
            rows = (
                ("profile: invalid timestamp", ["profile", "--log", self.write(d, "a.log", timed_invalid)], 0,
                 "binaries 1, summed wall 0.0s"),
                ("profile: 100K+ invalid timestamps", ["profile", "--log", self.write(d, "b.log", many_invalid)], 0,
                 "binaries 0, summed wall 0.0s"),
                ("profile: float overflow", ["profile", "--log", self.write(d, "c.log", inf_result)], 0,
                 "binaries 1, summed wall 0.0s"),
                ("profile: NUL bytes", ["profile", "--log", self.write(d, "d.log", NUL_BYTES)], 0,
                 "binaries 0, summed wall 0.0s"),
                ("profile: empty", ["profile", "--log", self.write(d, "e.log", "")], 0, "binaries 0, summed wall 0.0s"),
                ("profile: top overflow", ["profile", "--log", str(Path(d) / "e.log"), "--top", OVERFLOW_DIGITS],
                 EXIT_MALFORMED, bad_args + "argument --top: not an integer of at most 18 ASCII digits"),
                ("gate: invalid timestamp in the log", gate + ["--elapsed", str(SLOW), "--log",
                                                               str(Path(d) / "a.log")], EXIT_MARGIN_LOST,
                 lost + ": passed but used 1681s"),
                ("gate: float overflow in the log", gate + ["--elapsed", str(SLOW), "--log", str(Path(d) / "c.log")],
                 EXIT_MARGIN_LOST, "slowest binaries: tests/overflow_bin.rs 0s"),
                ("gate: overflow digits", gate + ["--elapsed", OVERFLOW_DIGITS], EXIT_MALFORMED,
                 bad_args + INT_ARG_REFUSED % "--elapsed" + "; refusing to pass (#9229)"),
                ("gate: non-ASCII digits", gate + ["--elapsed", NON_ASCII_DIGITS], EXIT_MALFORMED,
                 bad_args + INT_ARG_REFUSED % "--elapsed" + "; refusing to pass (#9229)"),
                ("gate: empty integer", gate + ["--elapsed", ""], EXIT_MALFORMED,
                 bad_args + INT_ARG_REFUSED % "--elapsed" + "; refusing to pass (#9229)"),
                ("gate: missing argument", ["gate", "--label", "x"], EXIT_MALFORMED,
                 bad_args + ARG_LIST_REFUSED + "; refusing to pass (#9229)"),
                ("gate: unknown subcommand", ["nope"], EXIT_MALFORMED,
                 bad_args + ARG_REFUSED % "cmd" + "; refusing to pass (#9229)"),
                ("gate: timer rc out of range", gate + ["--elapsed", "10", "--timer-rc", "7"], EXIT_MALFORMED,
                 "malformed gate input: the margin timer ended with rc 7 (143 when killed before its deadline, 3 "
                 "when it reported the lost margin)"),
                ("gate: held", gate + ["--elapsed", str(DEADLINE), "--timer-rc", str(TIMER_KILLED)], 0, held),
                ("timer: overflow budget", ["timer", "--label", "x", "--budget", OVERFLOW_DIGITS], EXIT_MALFORMED,
                 bad_args + "argument --budget: not an integer of at most 18 ASCII digits"),
                ("timer: zero budget", ["timer", "--label", "x", "--budget", "0"], EXIT_MALFORMED,
                 "malformed timer input: budget must be a positive integer of seconds, got 0"),
                ("shard-args: NUL bytes", ["shard-args", "--metadata", self.write(d, "nul.json", NUL_BYTES)],
                 EXIT_MALFORMED, "cannot be read as JSON (%s); the full suite runs unsharded" % JSON_REFUSED),
                ("shard-args: empty", ["shard-args", "--metadata", self.write(d, "empty.json", "")], EXIT_MALFORMED,
                 "cannot be read as JSON (%s); the full suite runs unsharded" % JSON_REFUSED),
                ("shard-args: unhashable kind",
                 ["shard-args", "--metadata", self.write(d, "kind.json", json.dumps(base.metadata(
                     targets=[{"kind": [["lib"]], "name": "x", "test": True, "doctest": True}])))], EXIT_MALFORMED,
                 "a target has a kind that is not a string"),
                ("shard-args: part overflow", ["shard-args", "--metadata", str(Path(d) / "kind.json"), "--part",
                                               OVERFLOW_DIGITS + "/2"], EXIT_MALFORMED,
                 "part %r is not K/N" % (OVERFLOW_DIGITS + "/2")[:40]),
                ("suite-plan: 100K-character key line",
                 ["suite-plan", "--workflow", self.write(d, "long-key.yml", long_key), "--job", "check", "--node",
                  "ubuntu-latest", "--tier", "sqlite"], 0, "whole-suite plan: the 3600s whole-suite ceiling fits"),
                ("suite-plan: 100K-character comment gap",
                 ["suite-plan", "--workflow", self.write(d, "long-comment.yml", long_comment), "--job", "check",
                  "--node", "ubuntu-latest", "--tier", "sqlite"], 0,
                 "whole-suite plan: the 3600s whole-suite ceiling fits"),
                ("suite-plan: NUL bytes", ["suite-plan", "--workflow", self.write(d, "nul.yml", NUL_BYTES), "--job",
                                           "check", "--node", "n", "--tier", "t"], EXIT_MALFORMED,
                 "the workflow has no job 'check'"),
                ("suite-sum: expect overflow", ["suite-sum", "--expect", OVERFLOW_DIGITS, "1\tlib"], EXIT_MALFORMED,
                 bad_args + "argument --expect: not an integer of at most 18 ASCII digits"),
            )
            for name, argv, rc_expected, reason in rows:
                self.assert_row(name, argv, rc_expected, reason)
            self.assert_deep_json_row(self.write(d, "deep.json", DEEP_JSON))

    def assert_deep_json_row(self, path):
        """The deep input fails closed with the ONE fixed reason on every interpreter: a full-line match."""
        argv = ["shard-args", "--metadata", path]
        start = time.monotonic()
        rc, out = self.call(argv)
        took = time.monotonic() - start
        line = ("::warning::[#9229 margin] shard-args: cargo metadata %s cannot be read as JSON (%s); the full suite "
                "runs unsharded (#9229)" % (path, JSON_REFUSED))
        with self.subTest(row="shard-args: deep JSON"):
            self.assertEqual(rc, EXIT_MALFORMED, out[-2000:])
            self.assertEqual(out.splitlines(), [line])
            self.assertNotRegex(out, INTERPRETER_TEXT_RE)
            self.assertLess(took, CORPUS_CEILING_SECS)

    def test_the_recursion_branch_is_forced(self):
        with base.scratch() as d:
            path = self.write(d, "ok.json", json.dumps(base.metadata()))
            with mock.patch.object(self.sb.json, "loads", side_effect=RecursionError):
                self.assert_row("shard-args: decoder recursion", ["shard-args", "--metadata", path], EXIT_MALFORMED,
                                "cargo metadata %s cannot be read as JSON (%s); the full suite runs "
                                "unsharded (#9229)" % (path, JSON_REFUSED))

    def test_every_except_member_and_usage_kind_is_one_fixed_line(self):
        self.assertEqual(interpreter_text_failures(self.sb), [])

    def test_each_interpreter_text_mutant_is_red(self):
        for name, old_text, new_text, cell in INTERPRETER_MUTANTS:
            with self.subTest(mutant=name), base.scratch() as d:
                self.assertIn(cell, interpreter_text_failures(load_mutant(d, old_text, new_text)))

    def test_size_bound_refuses_larger_inputs(self):
        with base.scratch() as d:
            big = Path(d) / "big.json"
            big.write_text(" " * 2048)
            wf = Path(d) / "big.yml"
            wf.write_text("#" * 2048)
            saved = self.sb.MAX_TEXT_BYTES
            self.sb.MAX_TEXT_BYTES = 1024
            try:
                self.assert_row("shard-args over the bound", ["shard-args", "--metadata", str(big)], EXIT_MALFORMED,
                                "cargo metadata %s cannot be read as JSON (larger than 1024 bytes)" % big)
                self.assert_row("suite-plan over the bound", ["suite-plan", "--workflow", str(wf), "--job", "check",
                                                              "--node", "n", "--tier", "t"], EXIT_MALFORMED,
                                "the workflow file cannot be read (larger than 1024 bytes)")
            finally:
                self.sb.MAX_TEXT_BYTES = saved

    def test_timer_reads_a_hostile_log_without_a_traceback(self):
        now = [0.0]

        def sleep(secs):
            now[0] += secs

        with base.scratch() as d:
            log = Path(d) / "t.log"
            log.write_text("%s     Running tests/x.rs (target/debug/deps/x)\n" % INVALID_TS)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = self.sb.run_timer("x", BUDGET, 20, str(log), sleep_fn=sleep, clock=lambda: now[0])
        self.assertEqual(rc, EXIT_MARGIN_LOST)
        self.assertIn("still running tests/x.rs", out.getvalue())

    def test_unexpected_exception_is_a_named_exit_2(self):
        def boom(*_args, **_kwargs):
            raise KeyError("synthetic")

        saved = self.sb.run_suite_sum
        self.sb.run_suite_sum = boom
        try:
            rc, out = self.call(["suite-sum", "--expect", "1", "1\tlib"])
        finally:
            self.sb.run_suite_sum = saved
        self.assertEqual(rc, EXIT_MALFORMED)
        self.assertEqual(out, INTERNAL_ERROR_LINE)


REAL_TIME_BUDGET = 5  # WATCHDOG_SECS of the real-time boundary run: margin deadline 4 s
REAL_TIME_AT_DEADLINE = 4.4  # cargo seconds: measured wall 4 s, exactly at the deadline
REAL_TIME_OVER = 6.5  # cargo seconds: past deadline + 1, the timer fires while cargo runs

STUB_SLEEP_CARGO = '''#!%(python)s -I
import sys
import time
if "--no-run" not in sys.argv:
    time.sleep(%(secs)r)
sys.exit(0)
'''

STUB_ANCHORED_DATE = '''#!%(python)s -I
"""Stub date: +%%s is whole seconds since its first call (plus a base), so the measured wall is exact."""
import os
import sys
import time
from pathlib import Path

anchor = Path(%(anchor)r)
if sys.argv[1:] == ["+%%s"]:
    if not anchor.exists():
        anchor.write_text(repr(time.time()))
    print(1_000_000 + int(time.time() - float(anchor.read_text())))
    sys.exit(0)
os.execv(%(real)r, [%(real)r] + sys.argv[1:])
'''


def run_real_time(cargo_secs):
    """run_tests of the step, gated, under a REAL_TIME_BUDGET watchdog budget and a cargo of ``cargo_secs``."""
    text = base.step_script()
    functions = "".join("%s() {\n%s\n}\n" % (fn, base.function_body(text, fn)) for fn in ("cap_to_job_left", "run_tests"))
    with base.scratch() as d:
        d = Path(d)
        bindir = d / "bin"
        bindir.mkdir()
        _write_exec(bindir / "cargo", STUB_SLEEP_CARGO % {"python": sys.executable, "secs": cargo_secs})
        _write_exec(bindir / "date", STUB_ANCHORED_DATE % {"python": sys.executable, "anchor": str(d / "anchor"),
                                                           "real": REAL_DATE})
        log = d / "result.log"
        log.write_text("")
        script = d / "boundary.sh"
        script.write_text("#!/bin/bash\nset -euo pipefail\n" + functions +
                          'JOB_T0_VALID=0\nWATCHDOG_SECS=%d\nTIMEOUT_BIN=""\nRESULT_LOG=%s\n'
                          'SUITE_MARGIN_GATE=1 run_tests "boundary"\n' % (REAL_TIME_BUDGET, log))
        env = dict(os.environ)
        env["PATH"] = "%s:%s" % (bindir, env.get("PATH", ""))
        r = subprocess.run(["bash", str(script)], cwd=str(REPO), env=env, capture_output=True, text=True,
                           timeout=STEP_TIMEOUT_SECS)
        return r.returncode, r.stdout + r.stderr


class OneBoundary(unittest.TestCase):
    """Class D (F3): one predicate; never both the lost-margin error and the held notice."""

    def setUp(self):
        self.sb = base.load()

    def test_margin_lost_boundary(self):
        for secs, lost in ((DEADLINE - 1, False), (DEADLINE, False), (DEADLINE + 1, True)):
            with self.subTest(secs=secs):
                self.assertIs(self.sb.margin_lost(secs, BUDGET), lost)
                self.assertEqual(self.sb.judge(secs, BUDGET, 0)[0], "margin-lost" if lost else "ok")
        self.assertEqual(self.sb.MARGIN_PCT, 20)
        self.assertEqual(self.sb.WHOLE_SUITE_CEILING_SECS, CEILING)

    def test_timer_fires_only_past_the_deadline(self):
        now = [0.0]
        seen = []

        def sleep(secs):
            now[0] += secs
            seen.append(now[0])

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.sb.run_timer("x", BUDGET, 20, "", sleep_fn=sleep, clock=lambda: now[0])
        self.assertEqual(rc, EXIT_MARGIN_LOST)
        self.assertEqual(now[0], DEADLINE + 1)
        self.assertIn(float(DEADLINE), seen)  # it was awake at the deadline itself and did not fire there
        self.assertIn("'x' lost the suite margin while still running: 1681s of the 2100s budget used", out.getvalue())

    def test_gate_with_a_fired_timer_is_red(self):
        rc, out, _ = base.run_main(self.sb, ["gate", "--label", "x", "--elapsed", "10", "--budget", str(BUDGET),
                                             "--rc", "0", "--timer-rc", "3"])
        self.assertEqual(rc, EXIT_MARGIN_LOST)
        self.assertNotIn("margin held", out)
        self.assertIn("::error::[#9229 margin] 'x' lost the suite margin: the in-flight timer already reported the "
                      "lost margin (measured wall 10s of the 2100s budget)", out)

    def test_step_boundary_rows(self):
        results = _scenario_results()
        for scenario, label, secs in (("sum3600", LABEL_SHARD[2], 900), ("slow2", LABEL_SHARD[2], SLOW)):
            with self.subTest(scenario=scenario):
                _, out, _, _ = results[("step", scenario)]
                held = "'%s': margin held" % label in out
                lost = "'%s' lost the suite margin" % label in out
                self.assertNotEqual(held, lost, out[-3000:])
                self.assertEqual(lost, secs > DEADLINE)

    def test_real_run_ending_at_the_deadline_gets_one_verdict(self):
        rc, out = run_real_time(REAL_TIME_AT_DEADLINE)
        self.assertIn("'boundary': margin held: wall 4s of the 5s budget", out)
        self.assertNotIn("lost the suite margin", out)
        self.assertEqual(rc, 0, out)

    def test_real_run_past_the_deadline_is_red_once(self):
        rc, out = run_real_time(REAL_TIME_OVER)
        self.assertIn("'boundary' lost the suite margin while still running", out)
        self.assertNotIn("margin held", out)
        self.assertEqual(rc, EXIT_MARGIN_LOST, out)


class AnnotationText(unittest.TestCase):
    """Class E (F1): no #9229 annotation carries a percent sign or its escaped form."""

    def setUp(self):
        self.sb = base.load()

    def test_no_percent_in_any_9229_annotation(self):
        now = [0.0]

        def sleep(secs):
            now[0] += secs

        gate = ["gate", "--label", "x", "--budget", str(BUDGET)]
        outputs = []
        for argv in (gate + ["--elapsed", "10", "--rc", "0"], gate + ["--elapsed", str(SLOW), "--rc", "0"],
                     gate + ["--elapsed", "10", "--rc", "124"], gate + ["--elapsed", str(SLOW), "--rc", "101"],
                     gate + ["--elapsed", "-1", "--rc", "0"], gate + ["--elapsed", "10", "--rc", "0", "--margin-pct",
                                                                    "0"],
                     ["suite-plan", "--workflow", str(REPO / ".github" / "workflows" / "ci.yml"), "--job", "check",
                      "--node", "ubuntu-latest", "--tier", "sqlite"],
                     ["suite-sum", "--expect", "1", "4000\tlib"], ["suite-sum", "--expect", "1", "10\tlib"]):
            rc, out, err = base.run_main(self.sb, argv)
            outputs.append(out + err)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.sb.run_timer("x", BUDGET, 20, "", sleep_fn=sleep, clock=lambda: now[0])
        outputs.append(out.getvalue())
        for name, (_, _) in SCENARIOS.items():
            outputs.append(_scenario_results()[("step", name)][1])
        lines = [line for text in outputs for line in text.splitlines() if "[#9229" in line]
        self.assertGreater(len(lines), 20)
        for line in lines:
            for form in PERCENT_FORMS:
                self.assertNotIn(form, line)


class TelemetryEveryPath(unittest.TestCase):
    """Class F (F5, S3): telemetry on every invocation and the metadata-failure warning."""

    def test_an_early_return_on_a_gate_red_prints_its_notices(self):
        results = _scenario_results()
        for scenario, k in (("slow2", 2), ("slow4", 4), ("slow1", 1)):
            with self.subTest(scenario=scenario):
                _, out, _, _ = results[("step", scenario)]
                self.assertIn("::notice::[#1492] '%s' ran %ds of the 2100s per-invocation watchdog budget"
                              % (LABEL_SHARD[k], SLOW), out)
                if k != 4:  # run_doc_tests prints no #6202 line on any path
                    self.assertIn("::notice::[#6202] '%s' passed: suite wall %ds of the 2100s watchdog budget"
                                  % (LABEL_SHARD[k], SLOW), out)

    def test_impact_early_return_prints_its_notices(self):
        _, out, _, _ = _scenario_results()[("step", "impact_lib_slow")]
        self.assertIn("::notice::[#1492] 'cargo test --lib' ran %ds" % SLOW, out)

    def test_a_failed_metadata_derivation_warns_before_the_gated_fallback(self):
        results = _scenario_results()
        warning = ("::warning::[#9229 margin] cargo metadata failed (rc %d); the full suite runs unsharded, "
                   "gated (#9229)" % EXIT_TEST_FAILED)
        for scenario, rc_expected in (("fallback_pass", 0), ("fallback_slow", EXIT_MARGIN_LOST)):
            with self.subTest(scenario=scenario):
                rc, out, calls, _ = results[("step", scenario)]
                self.assertEqual(rc, rc_expected, out[-3000:])
                self.assertIn(warning, out)
                self.assertLess(out.index(warning), out.index("'%s'" % LABEL_FALLBACK))
                self.assertEqual([c for c in calls if c.startswith("test ") and "--no-run" not in c],
                                 ["test --no-fail-fast"])
                self.assertIn("whole sqlite suite: 1 invocations ran" if rc_expected == 0
                              else "'%s' lost the suite margin" % LABEL_FALLBACK, out)


if __name__ == "__main__":
    unittest.main()
