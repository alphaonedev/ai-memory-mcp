#!/usr/bin/env python3
"""The `Run tests (impact-aware)` step of the `check` job is bounded below its job limit and streams the shard logs (#9852).

Run 39893573617 (Check linux-fed,enterprise-fed, chain/promo6-ssh-r2) ran the test step until GitHub's job limit
cancelled the whole job: the step had no `timeout-minutes` of its own, the shard logs were printed only after every
shard exited, so the job log held nothing of the shards, and nothing named the step that ran out of time. Invariants:

1. On every leg of the `check` matrix the test step has a step-level `timeout-minutes` read from the leg key
   `test_step_timeout`, which is exactly `timeout - POST_STEP_MARGIN_MIN`, so the steps after it (the uploads, the
   database cleanup, the target sweeps) still run inside the job limit. The watchdog budget of the step
   (`JOB_TIMEOUT_MIN`, from which job_left, cap_to_job_left and the serial shard budget are derived) is the step
   bound, so each named watchdog fires before the step bound does.
2. The shard logs reach the job log while the shards run: one python3 follower started after the three shard
   launches prints every complete line once, prefixed with the shard name, through workflow_annotation.log_line,
   and is stopped and reaped after the waits; the old print-after-exit loop is gone, so no line is printed twice.
3. The three upload steps run after a failed, timed-out or cancelled test step (`always()` plus their conditions).

Siblings bounded in the same job: the prebuild, enterprise-fed configure and live-cell steps (SIBLING_BOUNDS).

Run: python3 -m unittest discover -s scripts/ci/tests
Set WORKFLOW_UNDER_TEST to check another copy of ci.yml (the mutation runs of the PR use it).
"""
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_text  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
CI_YML = Path(os.environ.get("WORKFLOW_UNDER_TEST") or REPO / ".github" / "workflows" / "ci.yml")
SCRATCH_ROOT = REPO / ".local-runs"
JOB = "check"
TEST_STEP = "Run tests (impact-aware)"
STEP_TIMEOUT_KEY = "test_step_timeout"
STEP_TIMEOUT_EXPR = "${{ matrix.test_step_timeout }}"
POST_STEP_MARGIN_MIN = 12  # minutes the job keeps after the test step bound for the steps that follow it

# leg -> (job timeout, test step timeout), minutes, written out.
EXPECTED_LEG_BOUNDS = {
    "ubuntu-latest,sqlite": (95, 83),
    "linux-fed,enterprise-fed": (300, 288),
    "macos-fed,sqlite": (80, 68),
    "macos-fed,enterprise-fed": (160, 148),
}

SIBLING_BOUNDS = {
    "Prebuild t0 orchestrator (macOS e1 anti-flake, #1853)": "20",
    "Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)": "10",
    "Run the pg_isolated_binary live cells (enterprise-fed legs only)": "10",
}

EXPECTED_UPLOAD_IFS = {
    "Upload test results (durable audit history)":
        "needs.classify.outputs.cargo_skip != 'true' && always() && env.TEST_RESULT_LOG != ''",
    "Upload shard logs (#6344)":
        "always() && needs.classify.outputs.cargo_skip != 'true' && matrix.tier == 'enterprise-fed'",
    "Upload isolated-lane per-binary logs (#6383)":
        "needs.classify.outputs.cargo_skip != 'true' && always() && matrix.tier == 'enterprise-fed'",
}

# The live follower in run_sharded (invariant 2).
FOLLOWER_MARKER = "[#9852] live shard output"
FOLLOWER_OPEN = "python3 -I -c 'if True:"
FOLLOWER_ARGS_LINE = "' \"$sd/serial.log\" \"$sd/parallel_1.log\" \"$sd/parallel_2.log\" &"
FOLLOWER_PID_LINE = "fl=$!"
FOLLOWER_KILL_LINE = 'kill "$fl" 2>/dev/null || true'
FOLLOWER_WAIT_LINE = ('wait "$fl" || { echo "[#9852] live shard output ended early: python3 exited $?;'
                      ' the shard-logs artifact holds every line" >&2 || true; }')
LAST_LAUNCH_LINE = "pid_2=$!"
FIRST_WAIT_LINE = 'wait "$pid_s" || rc_s=$?'
HB_WAIT_LINE = 'wait "$hb" 2>/dev/null || true'
OLD_PRINT_LOOP_LINE = 'cat "$sd/$n.log"'
SHARD_NAMES = ("serial", "parallel_1", "parallel_2")
PIECE_CHARS = 4096  # the follower's piece size, written out

# Behavioural cell: the follower program run on fixture logs.
SEEN_DEADLINE_SECS = 30.0
STOP_DEADLINE_SECS = 30.0
POLL_SLEEP_SECS = 0.05
LONG_LINE_CHARS = 9000


def read_text():
    return CI_YML.read_text()


def matrix_legs(text):
    """{leg: {key: value}} of the `check` job matrix, read from the `include:` list items."""
    lines = text.split("\n")
    start = lines.index("  %s:" % JOB)
    legs, current = {}, None
    for line in lines[start + 1:]:
        if line == "    steps:":
            break
        leg = re.fullmatch(r"          - leg: (\S+)", line)
        if leg:
            current = legs.setdefault(leg.group(1), {})
            continue
        key = re.fullmatch(r"            ([a-z_]+): (\S+)", line)
        if key and current is not None:
            current[key.group(1)] = key.group(2)
    return legs


def step(name):
    found = [s for s in workflow_text.read_steps(CI_YML, JOB) if s["name"] == name]
    if len(found) != 1:
        raise AssertionError("expected one %r step in job %s, found %d" % (name, JOB, len(found)))
    return found[0]


def run_sharded_lines():
    run = step(TEST_STEP)["run"] or ""
    lines = run.split("\n")
    starts = [i for i, line in enumerate(lines) if line.strip() == "run_sharded() {"]
    if len(starts) != 1:
        raise AssertionError("expected one run_sharded() in %r, found %d" % (TEST_STEP, len(starts)))
    indent = lines[starts[0]][:len(lines[starts[0]]) - len(lines[starts[0]].lstrip())]
    end = lines.index(indent + "}", starts[0])
    return lines[starts[0] + 1:end]


def follower_program(lines):
    """The python program of the follower (the text between the -c quotes) and the index of its last line."""
    stripped = [line.strip() for line in lines]
    for i, line in enumerate(stripped):
        if line != FOLLOWER_OPEN:
            continue
        # The program holds no single quote, so the first line after the open that holds one closes it.
        close = next((j for j in range(i + 1, len(lines)) if "'" in lines[j]), None)
        if close is None or not lines[close].endswith(FOLLOWER_ARGS_LINE):
            continue
        body = "\n".join(lines[i:close + 1])
        if FOLLOWER_MARKER not in body:
            continue
        program = body[body.index("'") + 1:body.rindex(FOLLOWER_ARGS_LINE)]
        return program, i, close
    raise AssertionError("run_sharded has no follower %r holding %r" % (FOLLOWER_OPEN, FOLLOWER_MARKER))


class StepBoundTests(unittest.TestCase):
    """Invariant 1: a step-level bound below the job limit on every leg, and the watchdogs measured against it."""

    def test_each_leg_states_the_expected_test_step_bound(self):
        legs = matrix_legs(read_text())
        got = {leg: (int(keys.get("timeout", "0")), int(keys.get(STEP_TIMEOUT_KEY, "0"))) for leg, keys in legs.items()}
        self.assertEqual(got, EXPECTED_LEG_BOUNDS)

    def test_the_bound_leaves_the_post_step_margin_on_every_leg(self):
        for leg, keys in matrix_legs(read_text()).items():
            with self.subTest(leg=leg):
                self.assertIn(STEP_TIMEOUT_KEY, keys, "%s: the leg has no %s key" % (leg, STEP_TIMEOUT_KEY))
                timeout, bound = int(keys["timeout"]), int(keys[STEP_TIMEOUT_KEY])
                self.assertLess(bound, timeout, "%s: test step bound %d is not below the job limit %d"
                                % (leg, bound, timeout))
                self.assertEqual(timeout - bound, POST_STEP_MARGIN_MIN,
                                 "%s: test step bound %d leaves %d min of the %d min job limit, expected %d"
                                 % (leg, bound, timeout - bound, timeout, POST_STEP_MARGIN_MIN))

    def test_the_test_step_reads_the_leg_bound(self):
        self.assertEqual(step(TEST_STEP)["timeout-minutes"], STEP_TIMEOUT_EXPR)

    def test_the_watchdog_budget_is_the_step_bound(self):
        self.assertEqual(step(TEST_STEP)["env"].get("JOB_TIMEOUT_MIN"), STEP_TIMEOUT_EXPR)

    def test_sibling_steps_are_bounded(self):
        self.assertEqual({name: step(name)["timeout-minutes"] for name in SIBLING_BOUNDS}, SIBLING_BOUNDS)


class UploadAfterFailureTests(unittest.TestCase):
    """Invariant 3: every upload runs after a failed, timed-out or cancelled test step."""

    def test_upload_conditions_hold_always(self):
        got = {name: step(name)["if"] for name in EXPECTED_UPLOAD_IFS}
        self.assertEqual(got, EXPECTED_UPLOAD_IFS)
        for name, cond in got.items():
            self.assertIn("always()", cond or "", "%s: no always() in %r" % (name, cond))


class LiveShardOutputTests(unittest.TestCase):
    """Invariant 2: the shard logs are printed while the shards run, once, escaped."""

    def test_follower_starts_after_the_launches_and_is_reaped_after_the_waits(self):
        lines = run_sharded_lines()
        stripped = [line.strip() for line in lines]
        _, open_at, close_at = follower_program(lines)
        self.assertEqual(stripped[close_at + 1], FOLLOWER_PID_LINE)
        launch = stripped.index(LAST_LAUNCH_LINE)
        first_wait = stripped.index(FIRST_WAIT_LINE)
        hb_reap = stripped.index(HB_WAIT_LINE)
        kill = stripped.index(FOLLOWER_KILL_LINE)
        self.assertEqual(stripped[kill + 1], FOLLOWER_WAIT_LINE)
        self.assertTrue(launch < open_at < first_wait < hb_reap < kill,
                        "order launch=%d follower=%d first-wait=%d hb-reap=%d kill=%d"
                        % (launch, open_at, first_wait, hb_reap, kill))

    def test_follower_prints_through_log_line(self):
        program, _, _ = follower_program(run_sharded_lines())
        self.assertIn("import workflow_annotation as wa", program)
        self.assertIn('print(wa.log_line("[%s] %s" % (name, text[start:start + PIECE_CHARS])), flush=True)', program)
        self.assertEqual(program.count("print("), 1, "every follower line goes through the one log_line print")

    def test_the_print_after_exit_loop_is_gone(self):
        self.assertNotIn(OLD_PRINT_LOOP_LINE, [line.strip() for line in run_sharded_lines()])


class FollowerBehaviourTests(unittest.TestCase):
    """Invariant 2 by execution: the follower program from ci.yml on fixture logs."""

    def setUp(self):
        SCRATCH_ROOT.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH_ROOT, prefix="t9852-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.program, _, _ = follower_program(run_sharded_lines())

    def start(self):
        paths = [str(self.dir / ("%s.log" % name)) for name in SHARD_NAMES]
        self.out_path = self.dir / "out.txt"
        self.out = open(self.out_path, "wb")
        self.addCleanup(self.out.close)
        proc = subprocess.Popen([sys.executable, "-I", "-c", self.program] + paths, cwd=REPO, stdout=self.out,
                                stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def output(self):
        return self.out_path.read_bytes().decode("utf-8").split("\n")

    def wait_for(self, line, proc):
        deadline = time.monotonic() + SEEN_DEADLINE_SECS
        while line not in self.output():
            if proc.poll() is not None:
                self.fail("follower exited %s before printing %r" % (proc.returncode, line))
            if time.monotonic() > deadline:
                self.fail("follower did not print %r within %ss" % (line, SEEN_DEADLINE_SECS))
            time.sleep(POLL_SLEEP_SECS)

    def test_lines_arrive_live_once_escaped_and_the_tail_is_drained_on_stop(self):
        (self.dir / "serial.log").write_bytes(b"first\n::error::forged\n")
        (self.dir / "parallel_2.log").write_bytes(b"##[group]forged\n" + b"x" * LONG_LINE_CHARS + b"\n")
        proc = self.start()
        self.wait_for("[serial] first", proc)
        with open(self.dir / "serial.log", "ab") as log:
            log.write(b"second\ncr\rinside\nno-line-feed")
        self.wait_for("[serial] second", proc)
        (self.dir / "parallel_1.log").write_bytes(b"late\n")
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=STOP_DEADLINE_SECS)
        self.assertEqual((proc.returncode, err), (0, b""))
        lines = self.output()
        self.assertEqual(lines[-1], "", "the output ends with a line feed")
        by_shard = {name: [line for line in lines if line.startswith("[%s] " % name)] for name in SHARD_NAMES}
        self.assertEqual(by_shard, {
            "serial": ["[serial] first", "[serial] ::error::forged", "[serial] second", "[serial] cr\\x0dinside",
                       "[serial] no-line-feed"],
            "parallel_1": ["[parallel_1] late"],
            "parallel_2": ["[parallel_2] ##\\x5bgroup]forged", "[parallel_2] " + "x" * PIECE_CHARS,
                           "[parallel_2] " + "x" * PIECE_CHARS,
                           "[parallel_2] " + "x" * (LONG_LINE_CHARS - 2 * PIECE_CHARS)],
        })
        self.assertEqual(len(lines) - 1, sum(len(v) for v in by_shard.values()), "no other line is printed")

    def test_a_missing_or_non_regular_log_is_skipped(self):
        (self.dir / "serial.log").mkdir()
        (self.dir / "parallel_1.log").write_bytes(b"only\n")
        proc = self.start()
        self.wait_for("[parallel_1] only", proc)
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=STOP_DEADLINE_SECS)
        self.assertEqual((proc.returncode, err, self.output()), (0, b"", ["[parallel_1] only", ""]))


if __name__ == "__main__":
    unittest.main()
