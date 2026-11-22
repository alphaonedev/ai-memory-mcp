#!/usr/bin/env python3
"""The `Run tests (impact-aware)` step of the `check` job is bounded below its job limit and streams the shard logs (#9852).

Run 39893573617 (Check linux-fed,enterprise-fed, chain/promo6-ssh-r2) ran the test step until GitHub's job limit
cancelled the whole job: the step had no `timeout-minutes` of its own, the shard logs were printed only after every
shard exited, so the job log held nothing of the shards, and nothing named the step that ran out of time. Invariants:

1. Whenever the test step starts, its own bound ends it no later than the test step deadline, counted from JOB start:
   the job timeout minus POST_STEP_MARGIN_MIN (suite_budget.test_step_deadline_secs). The `Test step bound (#9852)`
   step computes the bound at run time (the whole minutes left to the deadline) and refuses with a named error when
   fewer than MIN_TEST_STEP_MIN minutes are left, so the steps after the test step (the uploads, the database
   cleanup, the target sweeps) always keep the margin of the job limit.
2. One source for the limit the test step runs under: the deadline. The step bound, the in-step budgets (job_left,
   the serial shard budget and its notice, all from TEST_STEP_DEADLINE_MIN, the bound step's `deadline_min` output),
   the suite-plan 20 percent gate and the #7914 budget identity all read it; no consumer reads the job timeout.
3. The shard logs reach the job log while the shards run: one python3 follower started after the three shard
   launches prints every complete line once, prefixed with the shard name, through workflow_annotation.log_line, and
   is stopped (a stop file, or its parent shell gone) and reaped after the waits. It is bounded in the memory it holds
   (HOLD_BYTES of an unterminated tail), the bytes it reads per poll (LIVE_CHUNKS * CHUNK_BYTES per source) and the
   bytes it prints (PRINT_BYTES per source, then one notice), and it is the one writer of the step output while the
   shards run: the #6344 heartbeat writes to a file the follower relays, so no line of either is cut by the other.
4. The three upload steps run after a failed, timed-out or cancelled test step (`always()` plus their conditions).

Siblings bounded in the same job: the prebuild, enterprise-fed configure and live-cell steps (SIBLING_BOUNDS).

Run: python3 -m unittest discover -s scripts/ci/tests
Set WORKFLOW_UNDER_TEST to check another copy of ci.yml (the mutation runs of the PR use it).
"""
import importlib.util
import os
import re
import shutil
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
SUITE_BUDGET = REPO / "scripts" / "ci" / "suite_budget.py"
SCRATCH_ROOT = REPO / ".local-runs"
JOB = "check"
TEST_STEP = "Run tests (impact-aware)"
LOAD_GATE_STEP = "Load gate (#6795)"
BOUND_STEP = "Test step bound (#9852)"
BOUND_STEP_ID = "test_step_bound"
BOUND_STEP_IF = "needs.classify.outputs.cargo_skip != 'true'"
BOUND_STEP_TIMEOUT = "2"
BOUND_STEP_RUN = ('python3 -I scripts/ci/suite_budget.py step-bound --workflow .github/workflows/ci.yml --job check '
                  '--node "${{ matrix.node }}" --tier "${{ matrix.tier }}" --job-start "$JOB_T0" '
                  '--github-output "$GITHUB_OUTPUT"\n')
STEP_TIMEOUT_EXPR = "${{ fromJSON(steps.test_step_bound.outputs.minutes) }}"
DEADLINE_ENV = "TEST_STEP_DEADLINE_MIN"
DEADLINE_EXPR = "${{ steps.test_step_bound.outputs.deadline_min }}"
OLD_LEG_KEY = "test_step_timeout"
OLD_BUDGET_ENV = "JOB_TIMEOUT_MIN"
POST_STEP_MARGIN_MIN = 12  # minutes the job keeps after the test step deadline, written out
MIN_TEST_STEP_MIN = 10  # the fewest minutes a step bound may give, written out

# leg -> (job timeout, test step deadline from job start), minutes, written out.
EXPECTED_LEG_BOUNDS = {
    "ubuntu-latest,sqlite": (95, 83),
    "linux-fed,enterprise-fed": (300, 288),
    "macos-fed,sqlite": (87, 75),
    "macos-fed,enterprise-fed": (160, 148),
}

# The in-step consumers of the deadline (invariant 2), written out.
JOB_LEFT_LINE = "local left=$(( TEST_STEP_DEADLINE_MIN * 60 - ($(date +%s) - JOB_T0) - 300 ))"
SERIAL_BUDGET_LINE = "SERIAL_BUDGET_SECS=$(( TEST_STEP_DEADLINE_MIN * 60 - (job_now - JOB_T0) - 300 ))"
SERIAL_NOTICE_LINE = ('echo "::notice::[#6795] serial shard budget ${SERIAL_BUDGET_SECS}s (test step deadline '
                      '${TEST_STEP_DEADLINE_MIN} min from job start, the job limit minus the 12-min post-step margin '
                      '- ${job_elapsed}s elapsed since job start - 300s safety); parallel shards '
                      'min(${WATCHDOG_SECS}s, time left to the test step deadline)"')

# The step-bound table (invariant 1): leg linux-fed,enterprise-fed (job limit 300 min, deadline 17280 s), a job
# start T0 and the second the bound step runs, as an offset from T0.
T0 = 1800000000
LINUX_LEG = ("linux-fed", "enterprise-fed")
WHERE = ("job 'check' (node=linux-fed tier=enterprise-fed): job limit 300 min - %ds elapsed since job start - "
         "post-step margin 12 min")
OK_NOTICE = "::notice::[#9852 step bound] test step bound %d min: " + WHERE + "; step deadline 288 min from job start\n"
REFUSED = ("::error::[#9852 step bound] refused: " + WHERE + " leaves %d min, below the 10-min minimum test step; "
           "the steps before the test step used the job's time\n")
STEP_BOUND_TABLE = (
    # offset from job start, exit code, minutes (None when refused), the exact output
    (0, 0, 288, OK_NOTICE % (288, 0)),
    (1230, 0, 267, OK_NOTICE % (267, 1230)),  # a full load-gate wait of 1200 s plus setup
    (16200, 0, 18, OK_NOTICE % (18, 16200)),
    (16680, 0, 10, OK_NOTICE % (10, 16680)),  # exactly the minimum
    (16740, 3, None, REFUSED % (16740, 9)),
    (17340, 3, None, REFUSED % (17340, 0)),  # later than the job limit minus the margin
)
MALFORMED = "::error::[#9852 step bound] malformed input: %s; refusing to start the test step\n"
GENERATIVE_STEP_SECS = 7

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

# The live follower in run_sharded (invariant 3).
FOLLOWER_MARKER = "[#9852] live shard output"
FOLLOWER_OPEN = "python3 -I -c 'if True:"
FOLLOWER_ARGS_LINE = ("' \"$sd/follow.stop\" \"$sd/progress.out\" \"$sd/serial.log\" \"$sd/parallel_1.log\" "
                      "\"$sd/parallel_2.log\" &")
FOLLOWER_PID_LINE = "fl=$!"
FOLLOWER_KILL_LINE = 'touch "$sd/follow.stop" 2>/dev/null || kill "$fl" 2>/dev/null || true'
FOLLOWER_WAIT_LINE = ('wait "$fl" || { echo "[#9852] live shard output ended early: python3 exited $?;'
                      ' the shard-logs artifact holds every line" >&2 || true; }')
HB_GROUP_OPEN = "{"
HB_LOOP_OPEN = "( while true; do"
HB_PID_LINE = "hb=$!"
HB_GROUP_CLOSE = '} > "$sd/progress.out" 2>&1'
HB_KILL_LINE = 'kill "$hb" 2>/dev/null || true'
LAST_LAUNCH_LINE = "pid_2=$!"
FIRST_WAIT_LINE = 'wait "$pid_s" || rc_s=$?'
HB_WAIT_LINE = 'wait "$hb" 2>/dev/null || true'
OLD_PRINT_LOOP_LINE = 'cat "$sd/$n.log"'
SHARD_NAMES = ("serial", "parallel_1", "parallel_2")
# The follower's bounds, written out.
PIECE_CHARS = 4096
HOLD_BYTES = 65536
LIVE_READ_BYTES = 16 * 262144  # LIVE_CHUNKS * CHUNK_BYTES: bytes read per source per poll while the shards run
PRINT_BYTES = 8388608
CAP_NOTICE = ("::notice::[#9852] live output of %s capped at 8388608 bytes; the shard-logs artifact holds every "
              "line")
PROGRESS_NOTICE = "::notice::[#6344] progress | serial: %s | parallel_1:  | parallel_2: "

# Behavioural cells: the follower program run on fixture logs.
SEEN_DEADLINE_SECS = 30.0
LIVE_DEADLINE_SECS = 15.0  # a held tail or a second source is printed within this, long before any stop
STOP_DEADLINE_SECS = 60.0
WALL_CEILING_SECS = 90.0  # the whole of one large-input cell, follower start to exit
POLL_SLEEP_SECS = 0.05
LONG_LINE_CHARS = 9000
UNTERMINATED_BYTES = 70000  # above HOLD_BYTES, no line feed
BACKLOG_LINE_BYTES = 1024
BACKLOG_BYTES = 20 * 1048576  # a serial backlog of 20 MiB, five live reads deep
EMPTY_LINES = 2 * 1048576  # 2 MiB of empty lines: 20 MiB printed without the cap
INTERLEAVE_LINES = 300
HEARTBEAT_STUB_SLEEP_SECS = "0.05"
PIPE_READ_BYTES = 4096
PIPE_READ_PAUSE_SECS = 0.002


# Starts the follower program (argv[3]) with the rest of argv, writes its PID to argv[2], waits until the follower
# has printed into argv[1] (so it has read its parent PID) and exits without waiting for it.
ORPHAN_LAUNCHER = ("import pathlib, subprocess, sys, time\n"
                   "child = subprocess.Popen([sys.executable, '-I', '-c'] + sys.argv[3:])\n"
                   "pathlib.Path(sys.argv[2]).write_text(str(child.pid))\n"
                   "deadline = time.monotonic() + 30\n"
                   "while not pathlib.Path(sys.argv[1]).read_bytes() and time.monotonic() < deadline:\n"
                   "    time.sleep(0.05)\n")


def process_alive(pid):
    """True while `pid` runs; a zombie (exited, not yet reaped by its new parent) counts as ended."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat_path = Path("/proc/%d/stat" % pid)
    try:
        return stat_path.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


def read_text():
    return CI_YML.read_text()


def load_suite_budget():
    spec = importlib.util.spec_from_file_location("suite_budget_9852", str(SUITE_BUDGET))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def steps():
    return workflow_text.read_steps(CI_YML, JOB)


def step(name):
    found = [s for s in steps() if s["name"] == name]
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


def run_step_bound(workflow, node, tier, job_start, output, now=None):
    argv = [sys.executable, "-I", str(SUITE_BUDGET), "step-bound", "--workflow", str(workflow), "--job", JOB,
            "--node", node, "--tier", tier, "--job-start", job_start, "--github-output", str(output)]
    if now is not None:
        argv += ["--now", now]
    r = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=STOP_DEADLINE_SECS)
    return r.returncode, r.stdout, r.stderr


def scratch_dir(case):
    SCRATCH_ROOT.mkdir(exist_ok=True)
    tmp = tempfile.TemporaryDirectory(dir=SCRATCH_ROOT, prefix="t9852-")
    case.addCleanup(tmp.cleanup)
    return Path(tmp.name)


class StepBoundWiringTests(unittest.TestCase):
    """Invariants 1 and 2 in ci.yml: the bound step, the step timeout and every consumer read the deadline."""

    def test_the_bound_step_runs_directly_before_the_test_step(self):
        names = [s["name"] for s in steps()]
        bound = step(BOUND_STEP)
        self.assertEqual((bound["id"], bound["if"], bound["timeout-minutes"], bound["run"]),
                         (BOUND_STEP_ID, BOUND_STEP_IF, BOUND_STEP_TIMEOUT, BOUND_STEP_RUN))
        self.assertEqual(names.index(BOUND_STEP) + 1, names.index(TEST_STEP))
        self.assertEqual(names.index(LOAD_GATE_STEP) + 1, names.index(BOUND_STEP))
        self.assertEqual(step(TEST_STEP)["if"], BOUND_STEP_IF, "the bound step runs whenever the test step does")

    def test_the_test_step_runs_under_the_computed_bound(self):
        self.assertEqual(step(TEST_STEP)["timeout-minutes"], STEP_TIMEOUT_EXPR)

    def test_the_in_step_budget_is_the_deadline_output(self):
        env = step(TEST_STEP)["env"]
        self.assertEqual(env.get(DEADLINE_ENV), DEADLINE_EXPR)
        self.assertNotIn(OLD_BUDGET_ENV, env)

    def test_every_in_step_consumer_reads_the_deadline(self):
        run = [line.strip() for line in (step(TEST_STEP)["run"] or "").split("\n")]
        for line in (JOB_LEFT_LINE, SERIAL_BUDGET_LINE, SERIAL_NOTICE_LINE):
            with self.subTest(line=line[:40]):
                self.assertEqual(run.count(line), 1)
        text = read_text()
        self.assertEqual(text.count("%s * 60" % DEADLINE_ENV), 2, "job_left and the serial budget, nothing else")
        self.assertNotIn(OLD_BUDGET_ENV, text)
        self.assertNotIn(OLD_LEG_KEY, text)
        self.assertEqual(text.count("matrix.timeout"), 1, "only the job's own timeout-minutes reads the leg timeout")

    def test_each_leg_states_the_expected_job_limit(self):
        legs = matrix_legs(read_text())
        self.assertEqual({leg: int(keys.get("timeout", "0")) for leg, keys in legs.items()},
                         {leg: bounds[0] for leg, bounds in EXPECTED_LEG_BOUNDS.items()})

    def test_the_deadline_is_one_source_for_every_leg(self):
        sb = load_suite_budget()
        self.assertEqual((sb.POST_STEP_MARGIN_MIN, sb.MIN_TEST_STEP_MIN), (POST_STEP_MARGIN_MIN, MIN_TEST_STEP_MIN))
        text = read_text()
        d = scratch_dir(self)
        for leg, (limit, deadline) in EXPECTED_LEG_BOUNDS.items():
            node, tier = leg.split(",")
            with self.subTest(leg=leg):
                self.assertEqual(sb.test_step_deadline_secs(text, JOB, node, tier), deadline * 60)
                self.assertEqual(limit - deadline, POST_STEP_MARGIN_MIN)
                out = d / ("%s-%s.out" % (node, tier))
                rc, _, _ = run_step_bound(CI_YML, node, tier, str(T0), out, now=str(T0))
                self.assertEqual((rc, out.read_text()), (0, "minutes=%d\ndeadline_min=%d\n" % (deadline, deadline)))

    def test_sibling_steps_are_bounded(self):
        self.assertEqual({name: step(name)["timeout-minutes"] for name in SIBLING_BOUNDS}, SIBLING_BOUNDS)


class StepBoundTableTests(unittest.TestCase):
    """Invariant 1 by execution: the bound for each step start offset, or the exact refusal."""

    def test_the_table_of_step_start_offsets(self):
        d = scratch_dir(self)
        for offset, code, minutes, text in STEP_BOUND_TABLE:
            with self.subTest(offset=offset):
                out = d / ("%d.out" % offset)
                out.write_text("EARLIER=1\n")
                rc, stdout, stderr = run_step_bound(CI_YML, *LINUX_LEG, str(T0), out, now=str(T0 + offset))
                self.assertEqual((rc, stdout, stderr), (code, text, ""))
                written = "" if minutes is None else "minutes=%d\ndeadline_min=288\n" % minutes
                self.assertEqual(out.read_text(), "EARLIER=1\n" + written, "appended, never truncated")

    def test_every_start_ends_by_the_deadline_with_the_margin_left(self):
        sb = load_suite_budget()
        text = read_text()
        for leg, (limit, _) in EXPECTED_LEG_BOUNDS.items():
            node, tier = leg.split(",")
            deadline = sb.test_step_deadline_secs(text, JOB, node, tier)
            for offset in range(0, deadline + 600, GENERATIVE_STEP_SECS):
                minutes = sb.step_bound(deadline, T0, T0 + offset)
                if minutes < MIN_TEST_STEP_MIN:
                    self.assertLess(deadline - offset, MIN_TEST_STEP_MIN * 60, "%s offset %d" % (leg, offset))
                    continue
                end = offset + minutes * 60
                self.assertLessEqual(end, deadline, "%s offset %d: the bound ends after the deadline" % (leg, offset))
                self.assertGreater(end + 60, deadline, "%s offset %d: a whole minute was left unused" % (leg, offset))
                self.assertGreaterEqual(limit * 60 - end, POST_STEP_MARGIN_MIN * 60,
                                        "%s offset %d: the margin before the job limit is gone" % (leg, offset))

    def test_malformed_clock_or_output_is_named_never_a_bound(self):
        d = scratch_dir(self)
        rows = (
            (str(T0 + 100), str(T0), MALFORMED % ("job start %d is after now %d" % (T0 + 100, T0))),
            ("0", str(T0), MALFORMED % "job start 0 is not an epoch second"),
            (str(T0), str(10 ** 11), MALFORMED % "now 100000000000 is not an epoch second"),
            ("", str(T0), "::error::[#9229 margin] suite_budget: malformed arguments: argument --job-start: not an "
                          "integer of at most 18 ASCII digits; refusing to pass (#9229)\n"),
        )
        for job_start, now, text in rows:
            with self.subTest(job_start=job_start, now=now):
                out = d / "out"
                rc, stdout, _ = run_step_bound(CI_YML, *LINUX_LEG, job_start, out, now=now)
                self.assertEqual((rc, stdout, out.exists()), (2, text, False))
        (d / "dir.out").mkdir()
        rc, stdout, _ = run_step_bound(CI_YML, *LINUX_LEG, str(T0), d / "dir.out", now=str(T0))
        self.assertEqual((rc, stdout), (2, "::error::[#9852 step bound] cannot append to the step output file "
                                           "(IsADirectoryError); refusing to start the test step\n"))

    def test_a_job_limit_inside_the_margin_is_named(self):
        d = scratch_dir(self)
        workflow = d / "ci.yml"
        workflow.write_text("jobs:\n  check:\n    timeout-minutes: 21\n    steps:\n      - run: true\n")
        rc, stdout, _ = run_step_bound(workflow, *LINUX_LEG, str(T0), d / "out", now=str(T0))
        self.assertEqual((rc, stdout), (2, MALFORMED % (
            "job 'check' (node=linux-fed tier=enterprise-fed) timeout leaves 540s after the 12-min post-step margin, "
            "below the 10-min minimum test step")))


class UploadAfterFailureTests(unittest.TestCase):
    """Invariant 4: every upload runs after a failed, timed-out or cancelled test step."""

    def test_upload_conditions_hold_always(self):
        got = {name: step(name)["if"] for name in EXPECTED_UPLOAD_IFS}
        self.assertEqual(got, EXPECTED_UPLOAD_IFS)
        for name, cond in got.items():
            self.assertIn("always()", cond or "", "%s: no always() in %r" % (name, cond))


class LiveShardOutputTests(unittest.TestCase):
    """Invariant 3: the shard logs are printed while the shards run, once, escaped, by the one writer."""

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

    def test_the_heartbeat_writes_to_the_file_the_follower_relays(self):
        stripped = [line.strip() for line in run_sharded_lines()]
        loop = stripped.index(HB_LOOP_OPEN)
        pid = stripped.index(HB_PID_LINE)
        self.assertEqual((stripped[loop - 1], stripped[pid + 1]), (HB_GROUP_OPEN, HB_GROUP_CLOSE))
        self.assertEqual(stripped.count(HB_GROUP_CLOSE), 1)

    def test_follower_writes_through_log_line_with_one_write(self):
        program, _, _ = follower_program(run_sharded_lines())
        self.assertIn("import workflow_annotation as wa", program)
        self.assertIn('wa.log_line("[%s] %s" % (names[index], text[start:start + PIECE_CHARS]))', program)
        self.assertEqual(program.count("os.write("), 1, "every follower byte goes through the one write")
        self.assertNotIn("print(", program)
        self.assertNotIn("sys.stdout", program)

    def test_the_print_after_exit_loop_is_gone(self):
        self.assertNotIn(OLD_PRINT_LOOP_LINE, [line.strip() for line in run_sharded_lines()])


class FollowerBehaviourTests(unittest.TestCase):
    """Invariant 3 by execution: the follower program from ci.yml on fixture logs."""

    def setUp(self):
        self.dir = scratch_dir(self)
        self.program, _, _ = follower_program(run_sharded_lines())

    def start(self):
        self.out_path = self.dir / "out.txt"
        self.out = open(self.out_path, "wb")
        self.addCleanup(self.out.close)
        proc = subprocess.Popen([sys.executable, "-I", "-c", self.program] + self.args(), cwd=REPO,
                                stdout=self.out, stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def args(self):
        self.stop_path = self.dir / "follow.stop"
        return ([str(self.stop_path), str(self.dir / "progress.out")]
                + [str(self.dir / ("%s.log" % name)) for name in SHARD_NAMES])

    def stop(self, proc):
        self.stop_path.touch()
        _, err = proc.communicate(timeout=STOP_DEADLINE_SECS)
        return proc.returncode, err

    def output(self):
        return self.out_path.read_bytes().decode("utf-8").split("\n")

    def wait_for(self, line, proc, deadline_secs=SEEN_DEADLINE_SECS):
        deadline = time.monotonic() + deadline_secs
        while line not in self.output():
            if proc.poll() is not None:
                self.fail("follower exited %s before printing %r" % (proc.returncode, line[:80]))
            if time.monotonic() > deadline:
                self.fail("follower did not print %r within %ss" % (line[:80], deadline_secs))
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
        self.assertEqual(self.stop(proc), (0, b""))
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
        self.assertEqual(self.stop(proc) + (self.output(),), (0, b"", ["[parallel_1] only", ""]))

    def test_progress_notices_are_relayed_whole_and_anything_else_escaped(self):
        notice = PROGRESS_NOTICE % "running 3 tests"
        (self.dir / "progress.out").write_bytes(
            notice.encode() + b"\n::error::forged\n"
            + (PROGRESS_NOTICE % "x::error::y").encode() + b"\n"
            + (PROGRESS_NOTICE % ("z" * 2000)).encode() + b"\n"
            + (PROGRESS_NOTICE % "##[group]g").encode() + b"\n"
            + b"[#6344] progress notice not written: python3 exited 1\n")
        proc = self.start()
        self.wait_for(notice, proc)
        self.assertEqual(self.stop(proc), (0, b""))
        self.assertEqual(self.output(), [
            notice,
            "[progress] ::error::forged",
            "[progress] ::notice::[#6344] progress | serial: x::error::y | parallel_1:  | parallel_2: ",
            "[progress] ::notice::[#6344] progress | serial: " + "z" * 2000 + " | parallel_1:  | parallel_2: ",
            "[progress] ::notice::[#6344] progress | serial: ##\\x5bgroup]g | parallel_1:  | parallel_2: ",
            "[progress] [#6344] progress notice not written: python3 exited 1",
            "",
        ])

    def test_an_unterminated_line_above_the_hold_bound_is_printed_live(self):
        (self.dir / "serial.log").write_bytes(b"h" * UNTERMINATED_BYTES)
        proc = self.start()
        self.wait_for("[serial] " + "h" * PIECE_CHARS, proc, LIVE_DEADLINE_SECS)
        self.assertFalse(self.stop_path.exists(), "printed while the shards run, not at the stop")
        self.assertEqual(self.stop(proc), (0, b""))
        pieces = ["[serial] " + "h" * PIECE_CHARS] * (UNTERMINATED_BYTES // PIECE_CHARS)
        self.assertEqual(self.output(), pieces + ["[serial] " + "h" * (UNTERMINATED_BYTES % PIECE_CHARS), ""])

    def test_a_large_backlog_never_starves_another_shard(self):
        # 20 MiB of serial lines are waiting; the parallel_1 line is printed after one live read of the serial log,
        # before the serial log reaches its print cap. The whole cell has a wall-clock ceiling.
        line = b"s" * (BACKLOG_LINE_BYTES - 1) + b"\n"
        (self.dir / "serial.log").write_bytes(line * (BACKLOG_BYTES // BACKLOG_LINE_BYTES))
        (self.dir / "parallel_1.log").write_bytes(b"parallel-line\n")
        began = time.monotonic()
        proc = self.start()
        self.wait_for(CAP_NOTICE % "serial", proc, WALL_CEILING_SECS)
        self.assertEqual(self.stop(proc), (0, b""))
        self.assertLess(time.monotonic() - began, WALL_CEILING_SECS)
        lines = self.output()
        serial = "[serial] " + "s" * (BACKLOG_LINE_BYTES - 1)
        printed = PRINT_BYTES // (len(serial) + 1)
        live = LIVE_READ_BYTES // BACKLOG_LINE_BYTES
        self.assertEqual(lines, [serial] * live + ["[parallel_1] parallel-line"] + [serial] * (printed - live)
                         + [CAP_NOTICE % "serial", ""])

    def test_printed_bytes_are_capped_per_source(self):
        # Empty lines print ten bytes each ("[serial] " and the line feed): 20 MiB without the cap.
        (self.dir / "serial.log").write_bytes(b"\n" * EMPTY_LINES)
        (self.dir / "parallel_2.log").write_bytes(b"after\n")
        began = time.monotonic()
        proc = self.start()
        self.wait_for("[parallel_2] after", proc, WALL_CEILING_SECS)
        self.assertEqual(self.stop(proc), (0, b""))
        self.assertLess(time.monotonic() - began, WALL_CEILING_SECS)
        self.assertLessEqual(self.out_path.stat().st_size, PRINT_BYTES + 2 * len(CAP_NOTICE) + 64)
        self.assertEqual(self.output(), ["[serial] "] * (PRINT_BYTES // 10) + [CAP_NOTICE % "serial",
                                                                            "[parallel_2] after", ""])

    def test_a_follower_whose_parent_is_gone_drains_and_exits(self):
        # The follower's parent exits at once and no stop file is ever written: the follower still prints and ends,
        # so a shell killed between the launch and the stop never leaves it running.
        (self.dir / "serial.log").write_bytes(b"orphan\n")
        self.out_path = self.dir / "out.txt"
        pid_path = self.dir / "pid.txt"
        with open(self.out_path, "wb") as out:
            subprocess.run([sys.executable, "-I", "-c", ORPHAN_LAUNCHER, str(self.out_path), str(pid_path),
                            self.program] + self.args(), cwd=REPO, stdout=out, check=True,
                           timeout=STOP_DEADLINE_SECS)
        pid = int(pid_path.read_text())
        deadline = time.monotonic() + STOP_DEADLINE_SECS
        while process_alive(pid):
            if time.monotonic() > deadline:
                os.kill(pid, 9)
                self.fail("the orphaned follower %d was still running after %ss" % (pid, STOP_DEADLINE_SECS))
            time.sleep(POLL_SLEEP_SECS)
        self.assertEqual(self.output(), ["[serial] orphan", ""])
        self.assertFalse(self.stop_path.exists())


class SingleWriterTests(unittest.TestCase):
    """Invariant 3, one writer: the heartbeat block and the follower of ci.yml, run together on a pipe that is read
    slowly, while long shard lines (each piece above PIPE_BUF) are printed: every line out is whole."""

    def test_no_line_is_cut_by_a_heartbeat(self):
        d = scratch_dir(self)
        lines = run_sharded_lines()
        stripped = [line.strip() for line in lines]
        _, _, close_at = follower_program(lines)
        block = lines[stripped.index(HB_LOOP_OPEN) - 1:close_at + 2]
        stop = [lines[stripped.index(name)] for name in (HB_KILL_LINE, HB_WAIT_LINE, FOLLOWER_KILL_LINE,
                                                         FOLLOWER_WAIT_LINE)]
        bindir = d / "bin"
        bindir.mkdir()
        real_sleep = shutil.which("sleep")
        (bindir / "sleep").write_text("#!/bin/sh\nexec %s %s\n" % (real_sleep, HEARTBEAT_STUB_SLEEP_SECS))
        (bindir / "sleep").chmod(0o755)
        long_line = b"a" * LONG_LINE_CHARS + b"\n"
        (d / "serial.log").write_bytes(long_line * INTERLEAVE_LINES)
        script = d / "step.sh"
        script.write_text("#!/bin/bash\nset -e\nsd=%s\n%s\n%s -c 'import time; time.sleep(3)'\n%s\n"
                          % (d, "\n".join(block), sys.executable, "\n".join(stop)))
        env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ.get("PATH", "")))
        proc = subprocess.Popen(["bash", str(script)], cwd=REPO, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        chunks, began = [], time.monotonic()
        while True:
            chunk = proc.stdout.read1(PIPE_READ_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            time.sleep(PIPE_READ_PAUSE_SECS)
            self.assertLess(time.monotonic() - began, WALL_CEILING_SECS)
        proc.wait(timeout=STOP_DEADLINE_SECS)
        out = b"".join(chunks).decode("utf-8").split("\n")
        notice = PROGRESS_NOTICE % ("a" * 90)
        follower = [line for line in out if line != notice]
        piece = "[serial] " + "a" * PIECE_CHARS
        tail = "[serial] " + "a" * (LONG_LINE_CHARS - 2 * PIECE_CHARS)
        self.assertEqual(follower, [piece, piece, tail] * INTERLEAVE_LINES + [""],
                         "a follower line was cut, or a line that is neither a notice nor a follower line was written")
        self.assertGreater(out.count(notice), 0, "no heartbeat notice was relayed")
        self.assertEqual(proc.returncode, 0, proc.stderr.read().decode("utf-8", "replace")[-2000:])


if __name__ == "__main__":
    unittest.main()
