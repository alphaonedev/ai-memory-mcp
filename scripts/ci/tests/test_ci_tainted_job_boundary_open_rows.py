"""Open rows of the tainted-job boundary (umbrella #9452, ruling 59117c3e).

decision: open rows that each cite one open issue over fixing the seven forms inside PR 9508,
because an Unclassifiable job is a finding that is tracked, not a job proven clean (conductor
ruling 59117c3e).

Class: an open row that is wider than the one finding it tracks.
Invariant, for every workflow input: a job reads clean only when it holds the boundary; a real
Unclassifiable form reads "open row" only when exactly one row names its workflow file, job id,
step, form class, operand and one issue of the fixed set; every other Unclassifiable form, in a
row-covered step too, is a finding. The row count equals the pin, and the pin only goes down.

R-1 one row per job and step, every field present, no glob or wildcard, no row without a step;
    the rows are exactly the pinned real forms.
R-2 a row matches only the form it names: a second form in a row-covered step, and the same
    form in another step, job or file, is a finding with its exact reason.
R-3 a row citing an issue outside the fixed set fails; a pin above the ceiling fails; a row
    count that differs from the pin fails; the removal rule is in the classifier header.
R-4 the rows of the two gate-step issues carry the gate-step mark and no other row does.

Every corpus is a named constant; every cell works on in-memory text. No file is written and no
cell makes a network call.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import taint_boundary as tb
except ImportError as _import_error:  # red at the base: every cell fails on its own
    tb = None
    IMPORT_ERROR = repr(_import_error)
else:
    IMPORT_ERROR = ""

from test_ci_tainted_job_boundary import REAL_UNCLASSIFIABLE  # noqa: E402

SYNTH = "synthetic.yml"
OTHER_FILE = "other-synthetic.yml"
JOB = "j"
OTHER_JOB = "k"
STEP = "S"
OTHER_STEP = "T"
# The fixed set of open-row issues (ruling 59117c3e); a row naming any other value is a finding.
OPEN_ROW_ISSUES = frozenset(range(9533, 9540))
# The two issues whose rows sit in a gate step: a change there needs the conductor's word.
GATE_STEP_ISSUES = frozenset({9536, 9537})
# The pin may only go down after PR 9508: 13 allow rows plus 11 open rows.
PIN_CEILING = 24
ALLOW_ROW_COUNT = 13
OPEN_ROW_COUNT = 11
GATE_STEP_ROW_COUNT = 4
GLOB_CHARS = "*?[]{}"
R2_STEP = "runs-on"
# Bad values of the issue field: outside the fixed set, an allow-row issue, not a plain int.
BAD_ISSUES = (9532, 9540, 9454, 0, None, True, "9533")

# The four form classes an open row can name, and the exact reason each raises.
FORM_NOT_LITERAL = "command-word-not-literal"
FORM_NOT_LISTED = "command-not-listed"
FORM_PY_MODULE = "python-module-not-listed"
FORM_INTERP_PATH = "interpreter-path-unbound"
FORM_REASONS = {
    FORM_NOT_LITERAL: "command word {!r} is not a literal word",
    FORM_NOT_LISTED: "command word {!r} is not on the closed command list",
    FORM_PY_MODULE: "python module {!r} is not on the closed module list",
    FORM_INTERP_PATH: "interpreter path {!r} is neither in the workspace nor bound to base content",
}
# Shell text that raises exactly the form of its class with the operand filled in.
FORM_TEXTS = {
    FORM_NOT_LITERAL: '"{}" --version',
    FORM_NOT_LISTED: "{} --version",
    FORM_PY_MODULE: "python3 -I -c 'import {}'",
    FORM_INTERP_PATH: 'python3 -I "{}"',
}
# A second form of every class, with an operand no row names.
SECOND_OPERANDS = {
    FORM_NOT_LITERAL: "$SECOND_FORM",
    FORM_NOT_LISTED: "unlisted-second-form",
    FORM_PY_MODULE: "second_form",
    FORM_INTERP_PATH: "$SECOND_FORM_DIR/x.py",
}
# The same operand under another class: a row names its class, never its operand alone.
CROSS_CLASS = {
    (FORM_NOT_LITERAL, "$BIN"): FORM_INTERP_PATH,
    (FORM_NOT_LITERAL, "$PSQL"): FORM_INTERP_PATH,
    (FORM_PY_MODULE, "os"): FORM_NOT_LISTED,
    (FORM_INTERP_PATH, "$trust_impact/cargo_skip.py"): FORM_NOT_LITERAL,
    (FORM_NOT_LISTED, "xcrun"): FORM_PY_MODULE,
    (FORM_NOT_LISTED, "udevadm"): FORM_PY_MODULE,
}
INSERT_AT_START = "start"
INSERT_AT_END = "end"

# The eleven open rows: (workflow, job, step label, form class, operand, issue, gate step).
EXPECTED_OPEN_ROWS = (
    ("batman-mode-acceptance.yml", "rust-integration", "Assert binary refuses /tmp write under R001 end-to-end",
     FORM_NOT_LITERAL, "$BIN", 9533, False),
    ("batman-mode-acceptance.yml", "bash-integration", "Install sqlite3 + jq (bounded+retry",
     FORM_NOT_LISTED, "apt-get", 9534, False),
    ("ci.yml", "check", "Free disk before tests (hosted image only,", FORM_NOT_LISTED, "apt-get", 9534, False),
    ("coverage.yml", "per-module-thresholds", "Free disk + add swap (#1148 belt-and-suspenders, aggressive)",
     FORM_NOT_LISTED, "apt-get", 9534, False),
    ("cert-postgres-age.yml", "cert-postgres-age",
     "Ensure AGE + vector extensions present (best-effort — tier is pre-provisioned)",
     FORM_NOT_LITERAL, "$PSQL", 9535, False),
    ("ci.yml", "select", "Materialise the base selector (#8240)", FORM_PY_MODULE, "os", 9536, True),
    ("ci.yml", "ci-gate", "Materialise the base gate (#8240)", FORM_PY_MODULE, "os", 9536, True),
    ("ci.yml", "classify", "id:cls", FORM_INTERP_PATH, "$trust_impact/cargo_skip.py", 9537, True),
    ("coverage.yml", "classify", "id:cls", FORM_INTERP_PATH, "$trust_impact/cargo_skip.py", 9537, True),
    ("mobile-runtime.yml", "ios-simulator", "Boot iOS Simulator (best-available iPhone)",
     FORM_NOT_LISTED, "xcrun", 9538, False),
    ("mobile-runtime.yml", "android-emulator", "Enable KVM", FORM_NOT_LISTED, "udevadm", 9539, False),
)
# The removal rule the classifier header states (R-3).
REMOVAL_RULE_PHRASES = (
    "the fix PR of an issue deletes its rows and lowers the pin in the same commit",
    "the pin only goes down",
    "no network call",
    "the conductor checks that every cited issue is open at each landing of a fix",
    "release checklist",
)
UNCLASSIFIABLE_PREFIX = "unclassifiable: "


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _row_tuple(row: object) -> tuple:
    return (row.workflow, row.job, row.step, row.form, row.operand, row.issue, row.gate_step)


def _form_text(form: str, operand: str) -> str:
    return FORM_TEXTS[form].format(operand)


def _reason(form: str, operand: str) -> str:
    return FORM_REASONS[form].format(operand)


def _wf(jobs: dict[str, list[tuple[str, str]]]) -> str:
    """A pull-request workflow; each job checks out without credentials, then runs its steps."""
    out = ["on: pull_request", "permissions:", "  contents: read", "jobs:"]
    for job, steps in jobs.items():
        out += [f"  {job}:", "    runs-on: ubuntu-latest", "    steps:", "      - uses: actions/checkout@v4",
                "        with:", "          persist-credentials: false"]
        for name, run in steps:
            out += [f"      - name: {name}", "        run: |"] + [f"          {line}" for line in run.split("\n")]
    return "\n".join(out) + "\n"


def _row(form: str = FORM_NOT_LISTED, operand: str = "apt-get", issue: object = 9534, gate_step: bool = False,
         workflow: str = SYNTH, job: str = JOB, step: str = STEP) -> object:
    return tb.OpenRow(workflow, job, step, form, operand, issue, gate_step)


def _problems(workflows: dict[str, str], rows: tuple) -> list[str]:
    result = tb.scan_texts(workflows, {}, frozenset(), open_rows=rows)
    return tb.check(result, allow=(), pin=len(rows))


def _message(workflow: str, job: str, step: str, reason: str) -> str:
    return f"{UNCLASSIFIABLE_PREFIX}{workflow}/{job}: step {step!r}: {reason}"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _insert(text: str, job: str, step: str, extra: str, where: str) -> str:
    """The workflow text with one shell line added at the start or the end of the step's run block."""
    lines = text.split("\n")
    head = lines.index(f"  {job}:")
    key = f"id: {step[len('id:'):]}" if step.startswith("id:") else f"name: {step}"
    at = next(i for i in range(head + 1, len(lines)) if lines[i].strip().lstrip("- ").startswith(key))
    run = next(i for i in range(at, len(lines)) if lines[i].strip() in ("run: |", "run: |-", "run: |+"))
    body = _indent(lines[run + 1])
    pos = run + 1
    if where == INSERT_AT_END:
        while pos < len(lines) and (not lines[pos].strip() or _indent(lines[pos]) >= body):
            pos += 1
        while not lines[pos - 1].strip():
            pos -= 1
    lines.insert(pos, " " * body + extra)
    return "\n".join(lines)


_REAL: dict[str, object] = {}


def _real() -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    if "repo" not in _REAL:
        _REAL["repo"] = tb.load_repo(REPO_ROOT)
    return _REAL["repo"]  # type: ignore[return-value]


class OpenRowShape(unittest.TestCase):
    """R-1: one row per job and step, every field exact, the rows are the pinned real forms."""

    def test_9452_open_rows_are_exactly_the_eleven_pinned_rows(self) -> None:
        _need_module(self)
        self.assertEqual(tuple(_row_tuple(r) for r in tb.OPEN_ROWS), EXPECTED_OPEN_ROWS)
        self.assertEqual(len(tb.OPEN_ROWS), OPEN_ROW_COUNT)

    def test_9452_open_rows_cover_exactly_the_real_unclassifiable_forms(self) -> None:
        _need_module(self)
        covered = sorted((r.workflow, r.job, r.step, _reason(r.form, r.operand)) for r in tb.OPEN_ROWS)
        self.assertEqual(covered, sorted(REAL_UNCLASSIFIABLE))

    def test_9452_every_open_row_field_is_present_and_exact(self) -> None:
        _need_module(self)
        self.assertEqual(tb.FORM_CLASSES, frozenset(FORM_REASONS))
        for row in tb.OPEN_ROWS:
            with self.subTest(row=row):
                for value in (row.workflow, row.job, row.step, row.form, row.operand):
                    self.assertIs(type(value), str)
                    self.assertNotEqual(value.strip(), "")
                for value in (row.workflow, row.job, row.step):
                    self.assertEqual([c for c in value if c in GLOB_CHARS], [])
                self.assertNotEqual(row.step, R2_STEP)
                self.assertIn(row.form, FORM_REASONS)
                self.assertIs(type(row.issue), int)
                self.assertIs(type(row.gate_step), bool)
        keys = [(r.workflow, r.job, r.step) for r in tb.OPEN_ROWS]
        self.assertEqual(len(keys), len(set(keys)))

    def test_9452_check_refuses_a_row_without_an_exact_place(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get"))]})}
        for workflow, job, step in (("", JOB, STEP), (SYNTH, "", STEP), (SYNTH, JOB, ""), (SYNTH, JOB, " "),
                                    (SYNTH, JOB, "*"), (SYNTH, JOB, "S*"), (SYNTH, JOB, "S?"), (SYNTH, JOB, "[S]"),
                                    ("*.yml", JOB, STEP), (SYNTH, "*", STEP), (SYNTH, "{j,k}", STEP),
                                    (SYNTH, JOB, R2_STEP)):
            with self.subTest(place=(workflow, job, step)):
                row = _row(workflow=workflow, job=job, step=step)
                self.assertIn(f"open row without an exact workflow, job and step: {workflow}/{job}/{step}",
                              _problems(workflows, (row,)))

    def test_9452_check_refuses_a_row_with_an_unknown_form(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get"))]})}
        for form, operand in (("", "apt-get"), ("command", "apt-get"), ("*", "apt-get"), (FORM_NOT_LISTED, ""),
                              (FORM_NOT_LISTED, "*"), (FORM_NOT_LISTED, None)):
            with self.subTest(form=form, operand=operand):
                row = _row(form=form, operand=operand)
                self.assertIn(f"open row with an unknown form: {SYNTH}/{JOB}/{STEP}", _problems(workflows, (row,)))

    def test_9452_two_rows_for_one_step_are_a_failure(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get") + "\n"
                                        + _form_text(FORM_NOT_LISTED, "xcrun"))]})}
        rows = (_row(), _row(operand="xcrun", issue=9538))
        self.assertIn(f"duplicate open row {(SYNTH, JOB, STEP)}", _problems(workflows, rows))

    def test_9452_stale_open_row_is_a_failure(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, "echo done")]})}
        self.assertEqual(_problems(workflows, (_row(),)),
                         [f"stale open row (no such form in the step): {SYNTH}/{JOB}/{STEP}"])


class OpenRowMatchesOneForm(unittest.TestCase):
    """R-2: a row matches only the form it names, in the step it names."""

    def test_9452_row_covers_its_own_form_and_the_job_stays_unclassifiable(self) -> None:
        _need_module(self)
        for workflow, job, step, form, operand, issue, gate in EXPECTED_OPEN_ROWS:
            with self.subTest(form=form, operand=operand):
                text = _wf({JOB: [(STEP, _form_text(form, operand) + "\n" + _form_text(form, operand))]})
                row = _row(form, operand, issue, gate)
                result = tb.scan_texts({SYNTH: text}, {}, frozenset(), open_rows=(row,))
                self.assertEqual(tb.check(result, allow=(), pin=1), [])
                # A row-covered job is NOT shown to hold the boundary.
                self.assertEqual(result.verdicts[(SYNTH, JOB)], tb.UNCLASSIFIABLE)
                self.assertEqual(result.unclassifiable, [f"{SYNTH}/{JOB}: step {STEP!r}: {_reason(form, operand)}"])

    def test_9452_second_form_in_a_synthetic_row_covered_step_is_a_finding(self) -> None:
        _need_module(self)
        for _, _, _, form, operand, issue, gate in EXPECTED_OPEN_ROWS:
            seconds = [(k, SECOND_OPERANDS[k]) for k in FORM_REASONS]
            if (form, operand) in CROSS_CLASS:
                seconds.append((CROSS_CLASS[form, operand], operand))
            for second_form, second_operand in seconds:
                for first, last in (((form, operand), (second_form, second_operand)),
                                    ((second_form, second_operand), (form, operand))):
                    with self.subTest(row=(form, operand), second=(second_form, second_operand), first=first):
                        run = _form_text(*first) + "\n" + _form_text(*last)
                        problems = _problems({SYNTH: _wf({JOB: [(STEP, run)]})}, (_row(form, operand, issue, gate),))
                        self.assertIn(_message(SYNTH, JOB, STEP, _reason(second_form, second_operand)), problems)

    def test_9452_second_form_in_a_real_row_covered_step_is_a_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        for workflow, job, step, form, operand, _, _ in EXPECTED_OPEN_ROWS:
            seconds = [(k, SECOND_OPERANDS[k]) for k in FORM_REASONS]
            if (form, operand) in CROSS_CLASS:
                seconds.append((CROSS_CLASS[form, operand], operand))
            for second_form, second_operand in seconds:
                for where in (INSERT_AT_START, INSERT_AT_END):
                    with self.subTest(row=(workflow, job), second=(second_form, second_operand), where=where):
                        text = _insert(workflows[workflow], job, step, _form_text(second_form, second_operand), where)
                        result = tb.scan_texts(dict(workflows, **{workflow: text}), actions, files,
                                               open_rows=tb.OPEN_ROWS)
                        problems = tb.check(result)
                        self.assertIn(_message(workflow, job, step, _reason(second_form, second_operand)), problems)
                        self.assertEqual(result.verdicts[(workflow, job)], tb.UNCLASSIFIABLE)

    def test_9452_same_form_in_another_step_job_or_file_is_a_finding(self) -> None:
        _need_module(self)
        for _, _, _, form, operand, issue, gate in EXPECTED_OPEN_ROWS:
            text = _form_text(form, operand)
            reason = _reason(form, operand)
            row = _row(form, operand, issue, gate)
            cases = (
                ({SYNTH: _wf({JOB: [(STEP, text), (OTHER_STEP, text)]})}, (SYNTH, JOB, OTHER_STEP)),
                ({SYNTH: _wf({JOB: [(STEP, text)], OTHER_JOB: [(STEP, text)]})}, (SYNTH, OTHER_JOB, STEP)),
                ({SYNTH: _wf({JOB: [(STEP, text)]}), OTHER_FILE: _wf({JOB: [(STEP, text)]})}, (OTHER_FILE, JOB, STEP)),
            )
            for workflows, (workflow, job, step) in cases:
                with self.subTest(form=form, operand=operand, place=(workflow, job, step)):
                    problems = _problems(workflows, (row,))
                    self.assertEqual(problems, [_message(workflow, job, step, reason)])

    def test_9452_real_row_covered_jobs_are_not_shown_to_hold_the_boundary(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files, open_rows=tb.OPEN_ROWS)
        for workflow, job, *_ in EXPECTED_OPEN_ROWS:
            with self.subTest(job=(workflow, job)):
                self.assertEqual(result.verdicts[(workflow, job)], tb.UNCLASSIFIABLE)
                self.assertEqual([v for v in result.violations if (v.workflow, v.job) == (workflow, job)], [])
        self.assertEqual(sorted((h.row.workflow, h.row.job, h.row.step) for h in result.open_forms),
                         sorted((r[0], r[1], r[2]) for r in EXPECTED_OPEN_ROWS))


class OpenRowIssues(unittest.TestCase):
    """R-3: the fixed issue set, the pin ceiling, the count pin and the removal rule."""

    def test_9452_open_row_issue_outside_the_fixed_set_is_a_failure(self) -> None:
        _need_module(self)
        self.assertEqual(tb.OPEN_ROW_ISSUES, OPEN_ROW_ISSUES)
        self.assertEqual({r.issue for r in tb.OPEN_ROWS}, OPEN_ROW_ISSUES)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get"))]})}
        for issue in BAD_ISSUES:
            with self.subTest(issue=issue):
                self.assertIn(f"open row without an issue of the fixed set: {SYNTH}/{JOB}/{STEP}",
                              _problems(workflows, (_row(issue=issue),)))

    def test_9452_pin_above_the_ceiling_is_a_failure(self) -> None:
        _need_module(self)
        self.assertEqual(tb.PIN_CEILING, PIN_CEILING)
        self.assertLessEqual(tb.TAINT_ALLOW_PIN, PIN_CEILING)
        result = tb.scan_texts({SYNTH: _wf({JOB: [(STEP, "echo done")]})}, {}, frozenset())
        for pin in (PIN_CEILING + 1, PIN_CEILING * 2):
            with self.subTest(pin=pin):
                self.assertIn(f"pin {pin} is above the ceiling {PIN_CEILING}", tb.check(result, allow=(), pin=pin))
        self.assertNotIn(f"pin {PIN_CEILING} is above the ceiling {PIN_CEILING}",
                         tb.check(result, allow=(), pin=PIN_CEILING))

    def test_9452_row_count_differs_from_pin_is_a_failure(self) -> None:
        _need_module(self)
        self.assertEqual(len(tb.TAINT_ALLOW), ALLOW_ROW_COUNT)
        self.assertEqual(len(tb.TAINT_ALLOW) + len(tb.OPEN_ROWS), tb.TAINT_ALLOW_PIN)
        self.assertEqual(tb.TAINT_ALLOW_PIN, PIN_CEILING)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files, open_rows=tb.OPEN_ROWS)
        self.assertEqual(tb.check(result), [])
        self.assertIn(f"allow table has {PIN_CEILING} rows, pin is {PIN_CEILING - 1}",
                      tb.check(result, pin=PIN_CEILING - 1))
        synthetic = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get"))]})}
        one = tb.scan_texts(synthetic, {}, frozenset(), open_rows=(_row(),))
        self.assertEqual(tb.check(one, allow=(), pin=0), ["allow table has 1 rows, pin is 0"])

    def test_9452_header_states_the_removal_rule(self) -> None:
        _need_module(self)
        header = " ".join(tb.__doc__.split())
        for phrase in REMOVAL_RULE_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, header)


class OpenRowGateStep(unittest.TestCase):
    """R-4: the rows of the two gate-step issues carry the mark and no other row does."""

    def test_9452_gate_step_marks_exactly_the_gate_step_issue_rows(self) -> None:
        _need_module(self)
        self.assertEqual(tb.GATE_STEP_ISSUES, GATE_STEP_ISSUES)
        marked = [r for r in tb.OPEN_ROWS if r.gate_step is True]
        self.assertEqual(marked, [r for r in tb.OPEN_ROWS if r.issue in GATE_STEP_ISSUES])
        self.assertEqual(len(marked), GATE_STEP_ROW_COUNT)
        self.assertEqual({r.issue for r in marked}, GATE_STEP_ISSUES)

    def test_9452_check_refuses_a_wrong_gate_step_mark(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, "apt-get"))]})}
        for issue, gate in ((9536, False), (9537, False), (9533, True), (9534, True), (9536, 1)):
            with self.subTest(issue=issue, gate=gate):
                self.assertIn(f"open row gate-step mark does not match issue {issue}: {SYNTH}/{JOB}/{STEP}",
                              _problems(workflows, (_row(issue=issue, gate_step=gate),)))


if __name__ == "__main__":
    unittest.main()
