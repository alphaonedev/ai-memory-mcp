"""Per-leg runner trust boundary over every workflow file (issue #9455, part 1).

Invariant (3-agent vote 71472661): a job that can resolve to a persistent self-hosted runner
has no trusted trigger. It holds for every workflow file, every job, every matrix leg and
every `runs-on` form (literal, list, group mapping, `matrix.<axis>`, `fromJSON(matrix.<axis>)`,
any other expression). A leg is persistent unless every label of it is a GitHub-hosted image
label (`taint_boundary._leg_hosted`); an expression other than a matrix axis is one opaque
leg and so persistent. A `runs-on` form the walker cannot classify is a FINDING with its
exact reason text, never a pass.

The legs that still break the invariant are the named open rows below (workflow, job, leg,
issue). Each stage of #9455 removes its rows and lowers the pin in the same commit; the
table equals the breaking legs exactly, so a stale row and a new breaking leg both fail.

Every cell works on in-memory text: the real workflows are read once from the checkout and
synthetic workflows are named constants. No file is written and no cell makes a network call.
"""

from __future__ import annotations

import json
import re
import sys
import time
import unittest
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))
try:
    import taint_boundary as tb
except ImportError as _import_error:  # every cell fails on its own
    tb = None
    IMPORT_ERROR = repr(_import_error)
else:
    IMPORT_ERROR = ""

RUNNER_ISSUE = 9455
# The check job's `runs-on` (#9821), exactly as the classifier prints the one opaque leg.
CHECK_FLIP_LEG = (
    '["${{ fromJSON(github.event_name == \'pull_request\' && github.event.pull_request.draft == true'
    " && contains(matrix.runner, 'self-hosted') && !contains(github.event.pull_request.labels.*.name, 'ci-fix')"
    " && !contains(github.event.pull_request.labels.*.name, 'run-self-hosted')"
    ' && \'[\\"ubuntu-latest\\"]\' || matrix.runner) }}"]'
)
SESSION_BOOT_WORKFLOW = "session-boot-lifetime.yml"
SESSION_BOOT_JOB = "lifetime-tests"
SESSION_BOOT_PERSISTENT_LEG = '["self-hosted","macos-fed"]'
SESSION_BOOT_HOSTED_LEG = '["macos-latest"]'
SESSION_BOOT_MATRIX_LITERAL = "runner: '{leg}'"
# The check name the macOS leg reports; branch protection and the release context list pin it.
SESSION_BOOT_MACOS_OS = "os: macos-fed"
SYNTH = "synthetic.yml"
CALLEE = "callee.yml"
JOB = "j"
ROW_MESSAGE = "runner leg not provably GitHub-hosted under a trusted trigger and no open row: {wf}/{job} leg {leg}"
STALE_MESSAGE = "stale open runner-leg row (the leg is hosted or gone): {wf}/{job} leg {leg}"
MANY_LEGS = 100_001
SCAN_CEILING_S = 10.0


class OpenLegRow(NamedTuple):
    workflow: str
    job: str
    leg: str
    issue: int


# The legs that still break the invariant; each is a later stage of #9455 (stage 0,
# issuecomment-7017025012): ci.yml check needs a hosted-aware shared cargo target, the two
# postgres jobs need a PG 18 + AGE + pgvector tier a hosted run reaches.
OPEN_RUNNER_LEG_ROWS = (
    OpenLegRow("cert-postgres-age.yml", "cert-postgres-age", '["self-hosted","linux-fed"]', RUNNER_ISSUE),
    # #9821: the check job's runs-on is one opaque expression (a skipped draft leg flips to hosted),
    # which the classifier reads as one non-hosted leg; it replaces the two literal matrix rows.
    OpenLegRow("ci.yml", "check", CHECK_FLIP_LEG, RUNNER_ISSUE),
    OpenLegRow("postgres-ignored.yml", "postgres-ignored", '["self-hosted","linux-fed"]', RUNNER_ISSUE),
)
OPEN_RUNNER_LEG_PIN = 3


def leg_text(leg: tuple[str, ...]) -> str:
    """One leg as compact JSON, the form a `fromJSON` matrix value carries."""
    return json.dumps(list(leg), separators=(",", ":"))


def _walk(name: str, workflows: dict[str, str], caller_events: set[str] | None, prefix: str, depth: int,
          rows: set[tuple[str, str, str]], findings: list[str]) -> None:
    if depth > tb.MAX_INDIRECTION_DEPTH:
        raise tb.Unclassifiable(f"{name}: reusable workflow nesting deeper than {tb.MAX_INDIRECTION_DEPTH}")
    doc = tb.parse_yaml(workflows[name], name)
    if not isinstance(doc, dict):
        raise tb.Unclassifiable(f"{name}: top level is not a mapping")
    events = tb._workflow_events(doc, name)
    if caller_events is not None:
        events = set(caller_events)
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise tb.Unclassifiable(f"{name}: no jobs mapping")
    for job_id, job in jobs.items():
        workflow, job_key = (prefix.split("/")[0], prefix.split("/", 1)[1] + job_id) if prefix else (name, job_id)
        label = f"{name}/{job_id}"
        try:
            if not isinstance(job, dict):
                raise tb.Unclassifiable(f"{label}: job is not a mapping")
            # One reader: the classifier's own closed list of job and matrix forms, so the walker
            # is never more permissive than the classifier (#9646 N2).
            tb._check_job_form(job, label)
            job_events = tb._job_events(job, events)
            uses = job.get("uses")
            if isinstance(uses, str):
                target = tb._local_workflow(uses, workflows)
                if target is None:
                    raise tb.Unclassifiable(f"{label}: reusable workflow {uses!r} not found in this repository")
                _walk(target, workflows, job_events, f"{workflow}/{job_key} > ", depth + 1, rows, findings)
                continue
            # Every form is classified, trusted trigger or not: an unknown form is a finding.
            legs = tb._runs_on_legs(job, label)
            if not job_events & tb.R2_TRUSTED_EVENTS:
                continue
            for leg in legs:
                if not tb._leg_hosted(leg):
                    rows.add((workflow, job_key, leg_text(leg)))
        except tb.Unclassifiable as exc:
            findings.append(str(exc))


def persistent_trusted_legs(workflows: dict[str, str]) -> tuple[set[tuple[str, str, str]], list[str]]:
    """Every (workflow, job, leg) that is not provably hosted under a trusted trigger, and the findings."""
    rows: set[tuple[str, str, str]] = set()
    findings: list[str] = []
    for name in sorted(workflows):
        try:
            _walk(name, workflows, None, "", 0, rows, findings)
        except tb.Unclassifiable as exc:
            findings.append(str(exc))
    return rows, findings


def check_open_rows(rows: set[tuple[str, str, str]], open_rows: tuple[OpenLegRow, ...]) -> list[str]:
    """The breaking legs without a row, then the rows whose leg no longer breaks the invariant."""
    held = {(r.workflow, r.job, r.leg) for r in open_rows}
    out = [ROW_MESSAGE.format(wf=wf, job=job, leg=leg) for wf, job, leg in sorted(rows - held)]
    out += [STALE_MESSAGE.format(wf=wf, job=job, leg=leg) for wf, job, leg in sorted(held - rows)]
    return out


_REAL: dict[str, dict[str, str]] = {}


def _real_workflows() -> dict[str, str]:
    if "workflows" not in _REAL:
        _REAL["workflows"] = tb.load_repo(REPO_ROOT)[0]
    return _REAL["workflows"]


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"classifier module scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


# ---------------------------------------------------------------------------------------
# Synthetic corpus: one workflow per `runs-on` form.
# ---------------------------------------------------------------------------------------

TRUSTED_HEADER = """\
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 4 * * *'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  j:
"""
PR_ONLY_HEADER = """\
on:
  pull_request:
permissions:
  contents: read
jobs:
  j:
"""
STEPS = """\
    steps:
      - run: echo done
"""

# (case name, job body between the header and the steps, expected rows, expected findings).
FORM_CASES = (
    ("literal hosted", "    runs-on: ubuntu-latest\n", set(), []),
    ("literal hosted macos", "    runs-on: macos-latest\n", set(), []),
    ("literal self-hosted", "    runs-on: self-hosted\n", {(SYNTH, JOB, '["self-hosted"]')}, []),
    ("list hosted", "    runs-on: [macos-15]\n", set(), []),
    ("list self-hosted", "    runs-on: [self-hosted, macos-fed]\n",
     {(SYNTH, JOB, '["self-hosted","macos-fed"]')}, []),
    ("list mixed hosted and self-hosted", "    runs-on: [ubuntu-latest, self-hosted]\n",
     {(SYNTH, JOB, '["ubuntu-latest","self-hosted"]')}, []),
    ("group", "    runs-on:\n      group: fleet\n", {(SYNTH, JOB, '["group:fleet"]')}, []),
    ("group with hosted labels", "    runs-on:\n      group: fleet\n      labels: [ubuntu-latest]\n",
     {(SYNTH, JOB, '["ubuntu-latest","group:fleet"]')}, []),
    ("matrix axis",
     "    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n    runs-on: ${{ matrix.os }}\n",
     {(SYNTH, JOB, '["self-hosted"]')}, []),
    ("fromJSON matrix include",
     "    strategy:\n      matrix:\n        include:\n          - runner: '[\"ubuntu-latest\"]'\n"
     "          - runner: '[\"self-hosted\",\"macos-fed\"]'\n    runs-on: ${{ fromJSON(matrix.runner) }}\n",
     {(SYNTH, JOB, '["self-hosted","macos-fed"]')}, []),
    ("fromJSON matrix include all hosted",
     "    strategy:\n      matrix:\n        include:\n          - runner: '[\"ubuntu-latest\"]'\n"
     "          - runner: '[\"macos-latest\"]'\n    runs-on: ${{ fromJSON(matrix.runner) }}\n",
     set(), []),
    ("opaque expression", "    runs-on: ${{ inputs.runner }}\n", {(SYNTH, JOB, '["${{ inputs.runner }}"]')}, []),
    ("unclassifiable: number", "    runs-on: 42\n", set(),
     [f"{SYNTH}/{JOB}: runs-on value 42 outside the known forms"]),
    ("unclassifiable: unterminated expression", "    runs-on: ${{ inputs.runner\n", set(),
     [f"{SYNTH}/{JOB}: runs-on unterminated `${{{{` expression"]),
    ("unclassifiable: fromJSON value not JSON",
     "    strategy:\n      matrix:\n        include:\n          - runner: 'not json'\n"
     "    runs-on: ${{ fromJSON(matrix.runner) }}\n",
     set(), [f"{SYNTH}/{JOB}: fromJSON matrix value is not JSON"]),
    ("unclassifiable: matrix axis without values",
     "    strategy:\n      matrix:\n        os: [a]\n    runs-on: ${{ matrix.runner }}\n",
     set(), [f"{SYNTH}/{JOB}: matrix axis 'runner' has no static values"]),
    ("unclassifiable: no runs-on", "", set(), [f"{SYNTH}/{JOB}: job without runs-on"]),
)

# The classifier's own closed list of job and matrix forms (`taint_boundary._check_job_form`):
# (case name, extra job lines after a hosted literal `runs-on`, the exact reason). The walker
# is never more permissive than the classifier, so each one is a finding (#9646 N2).
MATRIX_HEAD = "    strategy:\n      matrix:\n"
CLOSED_LIST_CASES = (
    ("job key off the closed list", "    bogus: 1\n", "job key 'bogus' is not on the closed list"),
    ("strategy not a mapping", "    strategy: fast\n", "strategy is not a mapping"),
    ("matrix is an expression", "    strategy:\n      matrix: ${{ fromJSON(inputs.m) }}\n",
     "matrix is an expression"),
    ("matrix not a mapping", "    strategy:\n      matrix: [a]\n", "matrix is not a mapping"),
    ("matrix include expression",
     MATRIX_HEAD + "        os: [ubuntu-latest]\n        include: ${{ fromJSON(inputs.m) }}\n",
     "matrix include holds an expression"),
    ("matrix exclude expression",
     MATRIX_HEAD + "        os: [ubuntu-latest]\n        exclude: ${{ fromJSON(inputs.m) }}\n",
     "matrix exclude holds an expression"),
    ("matrix include not mappings",
     MATRIX_HEAD + "        os: [ubuntu-latest]\n        include: [a]\n",
     "matrix include is not a list of mappings"),
    ("matrix axis expression", MATRIX_HEAD + "        os: ${{ inputs.os }}\n", "matrix axis 'os' is an expression"),
    ("matrix axis not a list", MATRIX_HEAD + "        os: ubuntu-latest\n", "matrix axis 'os' is not a list"),
    ("matrix axis value expression", MATRIX_HEAD + "        os: ['${{ inputs.os }}']\n",
     "matrix axis 'os' is an expression"),
)


class RunnerLegForms(unittest.TestCase):
    """Table-driven: every `runs-on` form, each with its rows or its exact finding."""

    def test_9455_every_runs_on_form(self) -> None:
        _need_module(self)
        for name, body, rows, findings in FORM_CASES:
            with self.subTest(form=name):
                got_rows, got_findings = persistent_trusted_legs({SYNTH: TRUSTED_HEADER + body + STEPS})
                self.assertEqual((got_rows, got_findings), (rows, findings))

    def test_9646_every_form_the_classifier_refuses_is_a_finding_in_the_walker(self) -> None:
        _need_module(self)
        for name, extra, reason in CLOSED_LIST_CASES:
            with self.subTest(form=name):
                for header in (TRUSTED_HEADER, PR_ONLY_HEADER):
                    text = header + "    runs-on: ubuntu-latest\n" + extra + STEPS
                    with self.assertRaises(tb.Unclassifiable) as ctx:
                        tb._check_job_form(tb.parse_yaml(text, SYNTH)["jobs"][JOB], f"{SYNTH}/{JOB}")
                    self.assertEqual(str(ctx.exception), f"{SYNTH}/{JOB}: {reason}")
                    self.assertEqual(persistent_trusted_legs({SYNTH: text}), (set(), [f"{SYNTH}/{JOB}: {reason}"]))

    def test_9455_a_pull_request_only_job_holds_the_invariant(self) -> None:
        _need_module(self)
        rows, findings = persistent_trusted_legs(
            {SYNTH: PR_ONLY_HEADER + "    runs-on: [self-hosted, macos-fed]\n" + STEPS})
        self.assertEqual((rows, findings), (set(), []))

    def test_9455_an_unclassifiable_form_is_a_finding_under_a_pull_request_trigger_too(self) -> None:
        _need_module(self)
        rows, findings = persistent_trusted_legs({SYNTH: PR_ONLY_HEADER + "    runs-on: 42\n" + STEPS})
        self.assertEqual((rows, findings), (set(), [f"{SYNTH}/{JOB}: runs-on value 42 outside the known forms"]))

    def test_9455_a_job_if_on_the_pull_request_event_narrows_the_trusted_triggers(self) -> None:
        _need_module(self)
        body = "    if: github.event_name == 'pull_request'\n    runs-on: [self-hosted, macos-fed]\n"
        header = TRUSTED_HEADER.replace("on:\n", "on:\n  pull_request:\n", 1)
        self.assertEqual(persistent_trusted_legs({SYNTH: header + body + STEPS}), (set(), []))
        body = "    if: github.event_name == 'push'\n    runs-on: [self-hosted, macos-fed]\n"
        self.assertEqual(persistent_trusted_legs({SYNTH: header + body + STEPS}),
                         ({(SYNTH, JOB, '["self-hosted","macos-fed"]')}, []))

    def test_9455_a_reusable_workflow_leg_carries_the_caller_triggers(self) -> None:
        _need_module(self)
        caller = TRUSTED_HEADER + f"    uses: ./.github/workflows/{CALLEE}\n"
        callee = ("on:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  inner:\n"
                  "    runs-on: [self-hosted, linux-fed]\n" + STEPS)
        rows, findings = persistent_trusted_legs({SYNTH: caller, CALLEE: callee})
        self.assertIn((SYNTH, f"{JOB} > inner", '["self-hosted","linux-fed"]'), rows)
        self.assertEqual(findings, [])
        missing = TRUSTED_HEADER + "    uses: ./.github/workflows/absent.yml\n"
        self.assertEqual(persistent_trusted_legs({SYNTH: missing}),
                         (set(), [f"{SYNTH}/{JOB}: reusable workflow './.github/workflows/absent.yml' "
                                  "not found in this repository"]))

    def test_9455_an_unknown_trigger_is_a_finding(self) -> None:
        _need_module(self)
        text = "on: [push, not_an_event]\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: x\n" + STEPS
        self.assertEqual(persistent_trusted_legs({SYNTH: text}),
                         (set(), [f"{SYNTH}: unknown trigger(s) ['not_an_event']"]))

    def test_9455_open_row_check_reports_new_and_stale_legs_exactly(self) -> None:
        _need_module(self)
        rows = {(SYNTH, JOB, '["self-hosted"]')}
        stale = (OpenLegRow(SYNTH, "gone", '["self-hosted"]', RUNNER_ISSUE),)
        self.assertEqual(check_open_rows(rows, stale), [
            ROW_MESSAGE.format(wf=SYNTH, job=JOB, leg='["self-hosted"]'),
            STALE_MESSAGE.format(wf=SYNTH, job="gone", leg='["self-hosted"]'),
        ])
        self.assertEqual(check_open_rows(rows, (OpenLegRow(SYNTH, JOB, '["self-hosted"]', RUNNER_ISSUE),)), [])

    def test_9455_many_legs_scan_in_linear_time(self) -> None:
        _need_module(self)
        include = "".join(f"          - runner: '[\"self-hosted\",\"l{i}\"]'\n" for i in range(MANY_LEGS))
        body = "    strategy:\n      matrix:\n        include:\n" + include + "    runs-on: ${{ fromJSON(matrix.runner) }}\n"
        start = time.monotonic()
        rows, findings = persistent_trusted_legs({SYNTH: TRUSTED_HEADER + body + STEPS})
        elapsed = time.monotonic() - start
        self.assertEqual((len(rows), findings), (MANY_LEGS, []))
        self.assertLess(elapsed, SCAN_CEILING_S)


class RealRunnerLegs(unittest.TestCase):
    """The invariant over every real workflow file, with the open rows of #9455."""

    def test_9455_no_runs_on_form_of_a_real_workflow_is_unclassifiable(self) -> None:
        _need_module(self)
        self.assertEqual(persistent_trusted_legs(_real_workflows())[1], [])

    def test_9455_every_trusted_leg_is_hosted_or_an_open_row(self) -> None:
        _need_module(self)
        rows, _ = persistent_trusted_legs(_real_workflows())
        self.assertEqual(check_open_rows(rows, OPEN_RUNNER_LEG_ROWS), [])

    def test_9455_open_rows_are_pinned_and_name_the_runner_issue(self) -> None:
        _need_module(self)
        self.assertEqual(len(OPEN_RUNNER_LEG_ROWS), OPEN_RUNNER_LEG_PIN)
        self.assertEqual(len(set(OPEN_RUNNER_LEG_ROWS)), OPEN_RUNNER_LEG_PIN)
        self.assertEqual({r.issue for r in OPEN_RUNNER_LEG_ROWS}, {RUNNER_ISSUE})
        # Each job with an open leg row is an R2 row of the job-level table under the same issue.
        r2_jobs = {(r.workflow, r.job) for r in tb.TAINT_ALLOW if r.step == tb.R2_STEP_LABEL and r.issue == RUNNER_ISSUE}
        self.assertEqual({(r.workflow, r.job) for r in OPEN_RUNNER_LEG_ROWS}, r2_jobs)

    def test_9455_session_boot_lifetime_runs_only_on_hosted_legs(self) -> None:
        _need_module(self)
        workflows = _real_workflows()
        rows, findings = persistent_trusted_legs({SESSION_BOOT_WORKFLOW: workflows[SESSION_BOOT_WORKFLOW]})
        self.assertEqual((rows, findings), (set(), []))
        text = workflows[SESSION_BOOT_WORKFLOW]
        # The check name `Lifetime suite (macos-fed)` comes from the `os` axis; it stays.
        self.assertIn(SESSION_BOOT_MACOS_OS, text)
        self.assertIn(SESSION_BOOT_MATRIX_LITERAL.format(leg=SESSION_BOOT_HOSTED_LEG), text)

    def test_9455_session_boot_lifetime_reverted_to_the_persistent_runner_is_red(self) -> None:
        _need_module(self)
        text = _real_workflows()[SESSION_BOOT_WORKFLOW]
        hosted = SESSION_BOOT_MATRIX_LITERAL.format(leg=SESSION_BOOT_HOSTED_LEG)
        self.assertIn(hosted, text)
        broken = text.replace(hosted, SESSION_BOOT_MATRIX_LITERAL.format(leg=SESSION_BOOT_PERSISTENT_LEG))
        rows, _ = persistent_trusted_legs({SESSION_BOOT_WORKFLOW: broken})
        self.assertEqual(check_open_rows(rows, ()), [ROW_MESSAGE.format(
            wf=SESSION_BOOT_WORKFLOW, job=SESSION_BOOT_JOB, leg=SESSION_BOOT_PERSISTENT_LEG)])


# ---------------------------------------------------------------------------------------
# #9646 N1: a workflow comment that spells the path of a test file the cargo-skip set holds is
# read by the cargo-skip read-set tests (test_impact_cargo_skip_8322 / _8328) as a workflow use
# of that file, so the PR turns CI red. Test files outside the skip set (Rust `tests/*.rs`, the
# `scripts/test` suites) are cargo or gate inputs already and are not part of this class.
# ---------------------------------------------------------------------------------------

WORKFLOW_DIR = ".github/workflows"
PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_./@-]+")
TOKEN_TRAILING_PUNCTUATION = ".,:;)"
TEST_DIR_NAMES = frozenset({"test", "tests"})
TEST_FILE_PREFIX = "test_"
TEST_FILE_SUFFIXES = ("_test.py", "_test.rs", "_tests.py", "_tests.rs")
OFFENDER_MESSAGE = "{wf}:{line} comment spells the skippable test file path {path}"
SPELLED = "scripts/ci/tests/test_example_9646.py"
# The synthetic spellable set: one skippable test file. A test file outside the skip set (the
# second path) is a read of cargo already and may be spelled.
SPELLABLE = frozenset({SPELLED})
NOT_SKIPPABLE_TEST = "scripts/test/test_example_9646.py"

# (case name, workflow text, expected offender messages)
COMMENT_CASES = (
    ("comment spells a skippable test path", f"# see {SPELLED} for the cells\n",
     [OFFENDER_MESSAGE.format(wf=SYNTH, line=1, path=SPELLED)]),
    ("trailing comment spells a skippable test path", f"name: x  # {SPELLED}.\n",
     [OFFENDER_MESSAGE.format(wf=SYNTH, line=1, path=SPELLED)]),
    # The read-set matches a bare file name too (`hit.endswith("/" + name)`), so the name alone
    # is the same use as the path.
    ("comment spells the bare file name", f"# {SPELLED.rsplit('/', 1)[1]} pins this\n",
     [OFFENDER_MESSAGE.format(wf=SYNTH, line=1, path=SPELLED.rsplit("/", 1)[1])]),
    ("comment names the test by issue and suite only", "# the runner-legs cells of #9455 pin this\n", []),
    ("comment spells a non-test path", "# scripts/ci/taint_boundary.py classifies\n", []),
    ("comment spells a test path outside the skip set", f"# {NOT_SKIPPABLE_TEST}\n", []),
    ("a non-comment line is not read here", f"run: echo {SPELLED}\n", []),
    ("second line is reported by number", f"a: 1\n  # {SPELLED}\n",
     [OFFENDER_MESSAGE.format(wf=SYNTH, line=2, path=SPELLED)]),
)


def is_test_file(path: str) -> bool:
    parts = path.split("/")
    return (bool(TEST_DIR_NAMES & set(parts[:-1])) or parts[-1].startswith(TEST_FILE_PREFIX)
            or parts[-1].endswith(TEST_FILE_SUFFIXES))


def comment_test_paths(name: str, text: str, spellable: frozenset[str]) -> list[str]:
    """Every comment of one workflow that spells a path or bare file name of `spellable`."""
    out: list[str] = []
    spelled = spellable | {p.rsplit("/", 1)[-1] for p in spellable}
    for number, line in enumerate(text.splitlines(), 1):
        for start in (m.start() for m in re.finditer("#", line)):
            if start and not line[start - 1].isspace():
                continue
            for token in PATH_TOKEN_RE.findall(line[start:]):
                path = token.rstrip(TOKEN_TRAILING_PUNCTUATION)
                if path in spelled:
                    out.append(OFFENDER_MESSAGE.format(wf=name, line=number, path=path))
            break
    return out


def skippable_test_files() -> frozenset[str]:
    """Every tracked test file the cargo-skip set holds (the paths whose spelling the read-set counts)."""
    from impact import cargo_skip, read_set  # the read-set tests' own readers

    section = cargo_skip.load_section()
    return frozenset(p for p in read_set.tracked_files(REPO_ROOT)
                     if is_test_file(p) and cargo_skip.is_skippable(section, p))


class WorkflowCommentsSpellNoTestPath(unittest.TestCase):
    """Class invariant: no comment of any workflow file spells the path of a skippable test file."""

    def test_9646_no_workflow_comment_spells_a_skippable_test_file_path(self) -> None:
        _need_module(self)
        for name, text, expected in COMMENT_CASES:
            with self.subTest(case=name):
                self.assertEqual(comment_test_paths(SYNTH, text, SPELLABLE), expected)
        spellable = skippable_test_files()
        self.assertIn(f"scripts/ci/tests/{Path(__file__).name}", spellable)  # the scan is not vacuous
        offenders: list[str] = []
        for rel in sorted((REPO_ROOT / WORKFLOW_DIR).glob("*.y*ml")):
            offenders += comment_test_paths(rel.name, rel.read_text(encoding="utf-8"), spellable)
        self.assertEqual(offenders, [])


# ---------------------------------------------------------------------------------------
# #9646 N3: the docs list the trusted triggers of the classifier's constant, nothing else.
# ---------------------------------------------------------------------------------------

DOC_PATH = "docs/DEV-CI-ENVIRONMENT.md"
DOC_ANCHOR = "**Trusted triggers stay off this runner (#9455).**"
DOC_BULLET_END = "\n- "
DOC_RULE_TEXT = "Every event except `pull_request`"
BACKTICK_RE = re.compile(r"`([a-z_]+)`")


class TrustedTriggerDocList(unittest.TestCase):
    def test_9646_doc_lists_exactly_the_classifier_trusted_events(self) -> None:
        _need_module(self)
        doc = (REPO_ROOT / DOC_PATH).read_text(encoding="utf-8")
        self.assertIn(DOC_ANCHOR, doc)
        paragraph = doc.split(DOC_ANCHOR, 1)[1].split(DOC_BULLET_END, 1)[0]
        self.assertIn(DOC_RULE_TEXT, paragraph)
        named = {e for e in BACKTICK_RE.findall(paragraph) if e in tb.KNOWN_EVENTS}
        self.assertEqual(named, set(tb.R2_TRUSTED_EVENTS) | set(tb.R2_UNTRUSTED_EVENTS))
        self.assertEqual(len(tb.R2_TRUSTED_EVENTS), 8)


if __name__ == "__main__":
    unittest.main()
