#!/usr/bin/env python3
"""Workflow wiring invariants for the CI speed change of #9593.

Class: the changes that must leave the set of tests and the set of reported check names
unchanged (invariant for every push):
  (a) debuginfo is off on the self-hosted linux-fed enterprise-fed Check leg ONLY;
  (c) the scripts/ci unit-test step lives in exactly one job that is no `needs` ancestor of any
      Check leg, runs on every push and carries no path filter or job-level `if:`.
  (d) the job ids and names of ci.yml equal the list pinned from the base (6c67b17b7).
  (e) what the moved unit-test step needs holds in its new job: the checkout keeps
      `fetch-depth: 2` (a push anchors the corpus ratchet on HEAD^), the 7987, 7988 and 9303
      preparation steps run right before it in that order with their load-bearing lines,
      and the job timeout stays above the measured step time with headroom.

Every check is a pure function over workflow TEXT that returns the problem lines; the cells
assert an empty list on the real files and an exact message on a deliberately broken copy.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.12+, standard library only (the workflows are read as text).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"

CI = "ci.yml"
LINUX_FED_LEG = "linux-fed,enterprise-fed"
OTHER_CHECK_LEGS = ("ubuntu-latest,sqlite", "macos-fed,sqlite", "macos-fed,enterprise-fed")
DEBUG_KEY = "cargo_debug"
DEBUG_EXPR = "${{ matrix.cargo_debug || 'line-tables-only' }}"
UNIT_COMMAND = "python3 -m unittest discover -s scripts/ci/tests"
UNIT_JOB = "build-script-vetting"
UNIT_STEP = "Shard partition and wiring unit tests (#6344)"
# (e) The checkout line a push needs: the Resolve step anchors the ratchet on HEAD^.
UNIT_CHECKOUT_ACTION = "actions/checkout@"
UNIT_CHECKOUT_DEPTH = "          fetch-depth: 2"
# (e) The steps the unit-test step needs, in this order, right before it, each with the line
# that does its work (moved byte for byte from `classify` at the base 6c67b17b7).
UNIT_PREP_STEPS = (
    ("Resolve the corpus ratchet base (#7987)", 'echo "CERT_MANIFEST_BASE_REF=HEAD^" >> "$GITHUB_ENV"'),
    ("Fetch the corpus replay objects (#7988)",
     "run: python3 -I scripts/ci/tests/test_check_cert_expiry_corpus.py --print-replay-shas"
     " | xargs git fetch --no-tags --depth=1 origin"),
    ("Fetch the amendment ledger replay objects (#9303)",
     "run: python3 -I scripts/ci/tests/test_cert_amendment_ledger_6124.py --print-replay-shas"
     " | xargs git fetch --no-tags --depth=1 origin"),
)
# (e) Timeout floor: the step took 674.9 s in build-script-vetting (run 44738653471) and
# 11.7 min in classify; the job's own gate work is about 0.5 min. Rounded up, then doubled.
UNIT_STEP_MEASURED_MIN = 12
UNIT_JOB_OWN_MIN = 1
TIMEOUT_HEADROOM_FACTOR = 2
UNIT_JOB_TIMEOUT_FLOOR_MIN = TIMEOUT_HEADROOM_FACTOR * (UNIT_STEP_MEASURED_MIN + UNIT_JOB_OWN_MIN)
# Job id -> `name:` of ci.yml at the base 6c67b17b7, in file order.
PINNED_JOBS = (
    ("select", "Impact selection"),
    ("classify", "Classify changes"),
    ("lint", "Lint (fmt + clippy)"),
    ("build-script-vetting", "Build-script custom-build ledger gate (#2635)"),
    ("actionlint", "actionlint (workflow-injection guard)"),
    ("msrv", "MSRV (Rust 1.98)"),
    ("draft-admission", "Draft admission re-check"),  # #9821, after the base list
    ("check", "Check (${{ matrix.leg }})"),
    ("postgres-feature", "Postgres feature gate"),
    ("mobile-cross-compile", "Cross-compile (${{ matrix.target }})"),
    ("sal-feature", "SAL-only feature gate"),
    ("vectorlite-feature", "vectorlite feature gate"),
    ("dockerfile-validate", "Dockerfile build (no push)"),
    ("ci-gate", "ci-gate"),
)

JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$")
KEY_RE = re.compile(r"^    ([A-Za-z0-9_-]+):(.*)$")
STEP_RE = re.compile(r"^      - name: (.*)$")


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text()


def jobs_of(text: str) -> dict:
    """Job id -> its block of lines, in file order (a dict keeps the order)."""
    out: dict = {}
    lines = text.split("\n")
    try:
        start = lines.index("jobs:") + 1
    except ValueError:
        return out
    current = None
    for line in lines[start:]:
        match = JOB_RE.match(line)
        if match:
            current = match.group(1)
            out[current] = []
        elif current is not None:
            out[current].append(line)
    return out


def job_name(block: list) -> str:
    for line in block:
        match = KEY_RE.match(line)
        if match and match.group(1) == "name":
            return match.group(2).strip().strip('"')
    return ""


def job_needs(block: list) -> list:
    """The job-level `needs:` ids: `needs: a`, `needs: [a, b]` or a block list."""
    ids: list = []
    for index, line in enumerate(block):
        match = KEY_RE.match(line)
        if not match or match.group(1) != "needs":
            continue
        rest = match.group(2).strip()
        if rest:
            ids += [w for w in re.split(r"[\s,\[\]]+", rest) if w]
        else:
            for item in block[index + 1:]:
                m2 = re.match(r"^      - ([A-Za-z0-9_-]+)\s*$", item)
                if not m2:
                    break
                ids.append(m2.group(1))
        break
    return ids


def job_has_key(block: list, key: str) -> bool:
    return any(m.group(1) == key for m in map(KEY_RE.match, block) if m)


def ancestors(jobs: dict, job: str) -> set:
    seen: set = set()
    todo = list(job_needs(jobs.get(job, [])))
    while todo:
        nxt = todo.pop()
        if nxt in seen:
            continue
        seen.add(nxt)
        todo += job_needs(jobs.get(nxt, []))
    return seen


def matrix_entry(block: list, leg: str) -> list:
    """The lines of the `include:` entry whose `leg:` is LEG, up to the next entry."""
    text = "\n".join(block)
    entries = re.split(r"\n          - (?=leg: )", text)
    for entry in entries[1:]:
        if entry.startswith("leg: %s\n" % leg):
            return entry.split("\n")
    return []


def step_run(text: str, name: str) -> str:
    start = text.find("      - name: %s\n" % name)
    if start < 0:
        return ""
    nxt = text.find("\n      - name: ", start + 1)
    return text[start:] if nxt < 0 else text[start:nxt]


# ---------------------------------------------------------------------------------------
# (a) debuginfo on the linux-fed leg only
# ---------------------------------------------------------------------------------------

def problems_debuginfo(workflows: dict) -> list:
    out: list = []
    jobs = jobs_of(workflows[CI])
    check = jobs.get("check", [])
    for var in ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"):
        want = "      %s: %s" % (var, DEBUG_EXPR)
        if want not in check:
            out.append("ci.yml check: the job env must read %r" % want)
    fed = matrix_entry(check, LINUX_FED_LEG)
    if "            %s: '0'" % DEBUG_KEY not in fed:
        out.append("ci.yml check: leg %s must set %s: '0'" % (LINUX_FED_LEG, DEBUG_KEY))
    for leg in OTHER_CHECK_LEGS:
        entry = matrix_entry(check, leg)
        if not entry:
            out.append("ci.yml check: leg %s is missing from the matrix" % leg)
        elif any(DEBUG_KEY in line for line in entry):
            out.append("ci.yml check: leg %s must not set %s" % (leg, DEBUG_KEY))
    for job, block in jobs.items():
        if job != "check" and any("CARGO_PROFILE_" in line and "_DEBUG" in line for line in block):
            out.append("ci.yml %s: only the check job may set a CARGO_PROFILE_*_DEBUG variable" % job)
    for name, text in workflows.items():
        if name != CI and DEBUG_KEY in text:
            out.append("%s: release-shaped and coverage builds must not use %s" % (name, DEBUG_KEY))
    return out


# ---------------------------------------------------------------------------------------
# (c) the unit-test step: one job, no path to a Check leg, every push
# ---------------------------------------------------------------------------------------

def problems_unit_placement(workflows: dict) -> list:
    out: list = []
    text = workflows[CI]
    jobs = jobs_of(text)
    holders = [job for job, block in jobs.items() if any(line.strip() == "run: " + UNIT_COMMAND for line in block)]
    if holders != [UNIT_JOB]:
        out.append("ci.yml: the unit-test step must be in exactly the job %s, found %r" % (UNIT_JOB, holders))
    block = jobs.get(UNIT_JOB, [])
    if not any(line == "      - name: " + UNIT_STEP for line in block):
        out.append("ci.yml %s: the step %r is missing" % (UNIT_JOB, UNIT_STEP))
    for job in holders:
        blk = jobs[job]
        if job_needs(blk):
            out.append("ci.yml %s: the unit-test job must have no needs" % job)
        if job_has_key(blk, "if"):
            out.append("ci.yml %s: the unit-test job must have no job-level if" % job)
        for leg_job in jobs:
            if job in ancestors(jobs, leg_job) and leg_job == "check":
                out.append("ci.yml: %s is a needs ancestor of check" % job)
    if "ci-gate" in jobs and UNIT_JOB not in job_needs(jobs["ci-gate"]):
        out.append("ci.yml ci-gate: must keep %s in needs" % UNIT_JOB)
    head = text.split("\njobs:", 1)[0]
    if re.search(r"^\s+paths(-ignore)?:", head, re.M):
        out.append("ci.yml: a path filter on the triggers would skip the unit-test job")
    if not any(event in head for event in ("  push:", "  pull_request:")):
        out.append("ci.yml: push and pull_request triggers are missing")
    return out


# ---------------------------------------------------------------------------------------
# (e) what the moved unit-test step needs, in its new job
# ---------------------------------------------------------------------------------------

STEP_START_RE = re.compile(r"^      - ")
STEP_NAME_RE = re.compile(r"^      (?:- |  )name: (.*)$")


def job_steps(block: list) -> list:
    """(step name, its lines) per step of a job block; a `uses:` step without a name gets ''."""
    steps: list = []
    for line in block:
        if STEP_START_RE.match(line):
            steps.append(["", []])
        if steps:
            steps[-1][1].append(line)
            match = STEP_NAME_RE.match(line)
            if match and not steps[-1][0]:
                steps[-1][0] = match.group(1).strip()
    return [(name, lines) for name, lines in steps]


def job_timeout(block: list):
    for line in block:
        match = KEY_RE.match(line)
        if match and match.group(1) == "timeout-minutes":
            value = match.group(2).strip()
            return int(value) if value.isdigit() else None
    return None


def problems_unit_needs(workflows: dict) -> list:
    out: list = []
    block = jobs_of(workflows[CI]).get(UNIT_JOB, [])
    where = "ci.yml %s" % UNIT_JOB
    steps = job_steps(block)
    checkouts = [lines for _name, lines in steps if any(UNIT_CHECKOUT_ACTION in line for line in lines[:1])]
    if len(checkouts) != 1 or UNIT_CHECKOUT_DEPTH not in checkouts[0]:
        out.append("%s: the checkout must set fetch-depth: 2 (a push anchors the corpus ratchet on HEAD^)" % where)
    names = [name for name, _lines in steps]
    if UNIT_STEP not in names:
        out.append("%s: the step %r is missing" % (where, UNIT_STEP))
        return out
    unit_at = names.index(UNIT_STEP)
    present = []
    for name, line_needed in UNIT_PREP_STEPS:
        if name not in names:
            out.append("%s: the step %r the unit-test step needs is missing" % (where, name))
            continue
        present.append(name)
        if not any(line.strip() == line_needed for line in steps[names.index(name)][1]):
            out.append("%s: the step %r must carry %r" % (where, name, line_needed))
    if names[max(unit_at - len(present), 0):unit_at] != present:
        out.append("%s: the preparation steps must run right before the unit-test step, in the order "
                   "7987, 7988, 9303" % where)
    timeout = job_timeout(block)
    if timeout is None or timeout < UNIT_JOB_TIMEOUT_FLOOR_MIN:
        out.append("%s: timeout-minutes %s is under the floor %d (%d x (%d min measured unit step + %d min own work))"
                   % (where, timeout, UNIT_JOB_TIMEOUT_FLOOR_MIN, TIMEOUT_HEADROOM_FACTOR,
                      UNIT_STEP_MEASURED_MIN, UNIT_JOB_OWN_MIN))
    return out


# ---------------------------------------------------------------------------------------
# (d) job ids and names pinned from the base
# ---------------------------------------------------------------------------------------

def problems_job_names(workflows: dict) -> list:
    jobs = jobs_of(workflows[CI])
    got = tuple((job, job_name(block)) for job, block in jobs.items())
    if got != PINNED_JOBS:
        return ["ci.yml: job ids and names differ from the pinned base list: added %r, removed %r" % (
            sorted(set(got) - set(PINNED_JOBS)), sorted(set(PINNED_JOBS) - set(got)))]
    return []


def real_workflows() -> dict:
    return {path.name: path.read_text() for path in sorted(WORKFLOWS.glob("*.yml"))}


class RealFiles(unittest.TestCase):
    def test_9593_debuginfo_off_on_the_linux_fed_leg_only(self):
        self.assertEqual(problems_debuginfo(real_workflows()), [])

    def test_9593_unit_test_step_is_in_one_job_with_no_path_to_a_check_leg(self):
        self.assertEqual(problems_unit_placement(real_workflows()), [])

    def test_9593_job_ids_and_names_equal_the_pinned_base_list(self):
        self.assertEqual(problems_job_names(real_workflows()), [])

    def test_9593_unit_step_keeps_what_it_needs_in_its_new_job(self):
        self.assertEqual(problems_unit_needs(real_workflows()), [])


# (e) Broken copies of the unit-test job: (cell id, text in the job, replacement, exact problems).
WHERE = "ci.yml " + UNIT_JOB
NEEDS_MUTANTS = (
    ("fetch_depth_removed", UNIT_CHECKOUT_DEPTH + "\n", "",
     [WHERE + ": the checkout must set fetch-depth: 2 (a push anchors the corpus ratchet on HEAD^)"]),
    ("replay_fetch_7988_dropped",
     "      - name: Fetch the corpus replay objects (#7988)\n        " + UNIT_PREP_STEPS[1][1] + "\n", "",
     [WHERE + ": the step 'Fetch the corpus replay objects (#7988)' the unit-test step needs is missing"]),
    ("timeout_lowered_40_to_15", "    timeout-minutes: 40\n", "    timeout-minutes: 15\n",
     [WHERE + ": timeout-minutes 15 is under the floor 26 (2 x (12 min measured unit step + 1 min own work))"]),
    ("ratchet_anchor_line_changed", 'echo "CERT_MANIFEST_BASE_REF=HEAD^"', 'echo "CERT_MANIFEST_BASE_REF=HEAD"',
     [WHERE + ": the step 'Resolve the corpus ratchet base (#7987)' must carry "
      + repr(UNIT_PREP_STEPS[0][1])]),
    ("step_between_prep_and_unit",
     "      - name: " + UNIT_STEP + "\n", "      - name: Interloper\n        run: true\n      - name: " + UNIT_STEP + "\n",
     [WHERE + ": the preparation steps must run right before the unit-test step, in the order 7987, 7988, 9303"]),
    ("replay_fetch_9303_dropped",
     "      - name: Fetch the amendment ledger replay objects (#9303)\n        " + UNIT_PREP_STEPS[2][1] + "\n", "",
     [WHERE + ": the step 'Fetch the amendment ledger replay objects (#9303)' the unit-test step needs is missing"]),
)


class NeedsBrokenCopies(unittest.TestCase):
    """(e) Each need of the moved step is red, with its exact message, when a copy breaks it."""

    @staticmethod
    def _broken_job(old: str, new: str) -> dict:
        workflows = real_workflows()
        text = workflows[CI]
        start = text.index("\n  %s:\n" % UNIT_JOB) + 1
        rest = text[start:].split("\n")
        end = start + len(rest[0]) + 1
        for line in rest[1:]:
            if JOB_RE.match(line):
                break
            end += len(line) + 1
        job = text[start:end]
        if job.count(old) != 1:
            raise AssertionError("mutant anchor %r occurs %d times in the %s job" % (old, job.count(old), UNIT_JOB))
        workflows[CI] = text[:start] + job.replace(old, new) + text[end:]
        return workflows

    def test_each_need_is_red_on_its_broken_copy(self):
        for cell, old, new, want in NEEDS_MUTANTS:
            with self.subTest(cell=cell):
                self.assertEqual(problems_unit_needs(self._broken_job(old, new)), want)


class BrokenCopies(unittest.TestCase):
    """Each check is red, with its exact message, on a deliberately broken copy."""

    def _broken(self, name: str, old: str, new: str) -> dict:
        workflows = real_workflows()
        self.assertEqual(workflows[name].count(old), 1, old)
        workflows[name] = workflows[name].replace(old, new)
        return workflows

    def test_debuginfo_key_on_a_second_leg(self):
        workflows = self._broken(CI, "            node: macos-fed\n            tier: sqlite\n",
                                 "            node: macos-fed\n            tier: sqlite\n            cargo_debug: '0'\n")
        self.assertEqual(problems_debuginfo(workflows), ["ci.yml check: leg macos-fed,sqlite must not set cargo_debug"])

    def test_debuginfo_key_missing_on_the_linux_fed_leg(self):
        workflows = self._broken(CI, "            cargo_debug: '0'\n", "")
        self.assertEqual(problems_debuginfo(workflows),
                         ["ci.yml check: leg linux-fed,enterprise-fed must set cargo_debug: '0'"])

    def test_debuginfo_key_in_a_coverage_style_workflow(self):
        workflows = real_workflows()
        workflows["coverage.yml"] += "\n# cargo_debug\n"
        self.assertEqual(problems_debuginfo(workflows),
                         ["coverage.yml: release-shaped and coverage builds must not use cargo_debug"])

    def test_unit_step_back_in_classify(self):
        workflows = real_workflows()
        text = workflows[CI]
        i = text.index("  classify:\n")
        j = text.index("      - name: AGE self-heal helper unit test (#6161)")
        workflows[CI] = text[:j] + "      - name: Dup\n        run: " + UNIT_COMMAND + "\n" + text[j:]
        self.assertTrue(i < j)
        self.assertEqual(problems_unit_placement(workflows), [
            "ci.yml: the unit-test step must be in exactly the job build-script-vetting, found "
            "['classify', 'build-script-vetting']",
            "ci.yml: classify is a needs ancestor of check"])

    def test_unit_job_gets_a_needs_edge_to_classify(self):
        workflows = self._broken(CI, '    name: "Build-script custom-build ledger gate (#2635)"\n',
                                 '    name: "Build-script custom-build ledger gate (#2635)"\n    needs: classify\n')
        self.assertEqual(problems_unit_placement(workflows),
                         ["ci.yml build-script-vetting: the unit-test job must have no needs"])

    def test_job_renamed(self):
        workflows = self._broken(CI, '    name: "Build-script custom-build ledger gate (#2635)"\n',
                                 '    name: "Build-script vetting"\n')
        self.assertEqual(problems_job_names(workflows), [
            "ci.yml: job ids and names differ from the pinned base list: added "
            "[('build-script-vetting', 'Build-script vetting')], removed "
            "[('build-script-vetting', 'Build-script custom-build ledger gate (#2635)')]"])

    def test_job_added(self):
        workflows = real_workflows()
        workflows[CI] = workflows[CI].rstrip("\n") + "\n  extra:\n    name: Extra\n"
        self.assertEqual(problems_job_names(workflows), [
            "ci.yml: job ids and names differ from the pinned base list: added [('extra', 'Extra')], removed []"])


if __name__ == "__main__":
    unittest.main()
