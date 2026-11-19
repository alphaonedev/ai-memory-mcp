#!/usr/bin/env python3
"""Workflow wiring invariants for the CI speed change of #9593.

Class: the changes that must leave the set of tests and the set of reported check names
unchanged (invariant for every push):
  (a) debuginfo is off on the self-hosted linux-fed enterprise-fed Check leg ONLY;
  (c) the scripts/ci unit-test step lives in exactly one job that is no `needs` ancestor of any
      Check leg, runs on every push and carries no path filter or job-level `if:`.
  (d) the job ids and names of ci.yml equal the list pinned from the base (6c67b17b7).

Every check is a pure function over workflow TEXT that returns the problem lines; the cells
assert an empty list on the real files and an exact message on a deliberately broken copy.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (the workflows are read as text).
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
# Job id -> `name:` of ci.yml at the base 6c67b17b7, in file order.
PINNED_JOBS = (
    ("select", "Impact selection"),
    ("classify", "Classify changes"),
    ("lint", "Lint (fmt + clippy)"),
    ("build-script-vetting", "Build-script custom-build ledger gate (#2635)"),
    ("actionlint", "actionlint (workflow-injection guard)"),
    ("msrv", "MSRV (Rust 1.98)"),
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
