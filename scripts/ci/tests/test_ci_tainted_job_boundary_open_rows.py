"""Rows of the tainted-job boundary: three kinds, three pins (umbrella #9452, ruling f367b2f1,
FINAL words efb2b9e8 and 0773f6ce).

decision: three row tables, one per kind, over one table with a kind field, because a row of one
kind must never cover a finding of another kind and a table of the wrong kind is then a failure
by construction (F-1).

Class: a fail-closed classifier whose rows could hide a form.
Invariant, for every workflow input: every form the checker cannot read and every violation the
scan reaches is covered by exactly one row of its own kind that names it (workflow file, job,
step, form class or NO-CLASS reason, operand, one issue of that kind's fixed set) or it is a
finding; a row covers nothing but what it names; the scan goes on past a covered form to the end
of the job; each pin equals its row count, sits at or under its ceiling and only goes down.

E-2/F-1 three kinds never mixed: a row in the table of another kind is a failure and covers
        nothing; each pin raised fails; an issue outside a kind's fixed set fails.
E-4/F-2 all rows applied: zero findings and exactly three not-analysed lines; any ONE row
        removed: exactly that form, line or violation, with its exact reason text. This is a proof
        for what the scan reaches only.
E-5     every row carries the gate-step mark exactly when its place is a gate step (its job is a
        gate job of its workflow file, or its step is the gate step of job check), whatever its
        issue; the NO-CLASS rows (dunder, arithmetic) sit in gate steps.
F-5     a pin above its row count fails; the header states the removal rule.

Every corpus is a named constant; every cell works on in-memory text. No file is written and no
cell makes a network call.
"""

from __future__ import annotations

import re
import sys
import time
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

from test_ci_tainted_job_boundary import (  # noqa: E402
    REAL_NEW_VIOLATIONS,
    REAL_NOT_ANALYSED,
    REAL_UNCLASSIFIABLE,
)

SYNTH = "synthetic.yml"
OTHER_FILE = "other-synthetic.yml"
JOB = "j"
OTHER_JOB = "k"
STEP = "S"
OTHER_STEP = "T"
R2_STEP = "runs-on"
GLOB_CHARS = "*?[]{}"
# The one brace an operand may hold: a braced parameter reference of one plain name (the shell
# word as the scanner quotes it, matched by exact equality).
OPERAND_BOUND_REPEAT = 40_000
OPERAND_CEILING_S = 2.0
OPERAND_PARAM_REF = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")

# The three kinds and their pins (FINAL 0773f6ce): each pin only goes down.
KIND_UNCLASSIFIABLE = "unclassifiable"
KIND_VIOLATION = "violation"
KIND_NOT_ANALYSED = "not-analysed"
OPEN_PIN = 47
NOT_ANALYSED_PIN = 3
VIOLATION_PIN = 17
PIN_CEILINGS = {KIND_UNCLASSIFIABLE: OPEN_PIN, KIND_VIOLATION: VIOLATION_PIN, KIND_NOT_ANALYSED: NOT_ANALYSED_PIN}
# The name each kind's table carries in a pin line.
TABLE_NAMES = {KIND_UNCLASSIFIABLE: "unclassifiable", KIND_VIOLATION: "allow", KIND_NOT_ANALYSED: "not-analysed"}
PINS_LINE = "unclassifiable 47; not-analysed 3; violation 17"

# The fixed issue set of each kind; a row naming any other value is a finding.
# 9559, 9560 and 9561: the three issues of forms the merge of the chain tip brought (baseline of the landing tree).
OPEN_ROW_ISSUES = frozenset(range(9533, 9540)) | frozenset(range(9544, 9550)) | frozenset({9559, 9560, 9561})
NOT_ANALYSED_ROW_ISSUES = frozenset({9550, 9551, 9552})
VIOLATION_ROW_ISSUES = frozenset({9454, 9455, 9456, 9471, 9553})
# Gate-step places (E-5, conductor's word b29): a change there needs the conductor's word. The
# mark follows the place: the gate jobs of each workflow file and the one gate step of job check.
GATE_JOBS = {"ci.yml": frozenset({"classify", "select", "ci-gate"}), "coverage.yml": frozenset({"classify"})}
GATE_STEPS = {("ci.yml", "check"): frozenset({"Run tests (impact-aware)"})}
# One place of each clause, each with a real row; a synthetic workflow of that name puts a row there.
GATE_PLACES = (
    ("ci.yml", "classify", STEP),
    ("ci.yml", "select", STEP),
    ("ci.yml", "ci-gate", STEP),
    ("coverage.yml", "classify", STEP),
    ("ci.yml", "check", "Run tests (impact-aware)"),
)
# Places one field away from a gate step: another job, another workflow file, another step of check.
NOT_GATE_PLACES = (
    (SYNTH, JOB, STEP),
    ("ci.yml", "check", STEP),
    ("coverage.yml", "select", STEP),
    ("coverage.yml", "check", "Run tests (impact-aware)"),
    (SYNTH, "classify", STEP),
)
# Bad values of the issue field per kind: another kind's issue, a neighbour, not a plain int.
BAD_OPEN_ISSUES = (9532, 9540, 9543, 9550, 9553, 9454, 0, None, True, "9533")
BAD_NOT_ANALYSED_ISSUES = (9549, 9553, 9533, 9454, 0, None, True, "9550")
BAD_VIOLATION_ISSUES = (9533, 9549, 9550, 9552, 9554, 0, None, True, "9553")

# The form classes and the exact reason each raises.
FORM_NOT_LITERAL = "command-word-not-literal"
FORM_NOT_LISTED = "command-not-listed"
FORM_PY_MODULE = "python-module-not-listed"
FORM_INTERP_PATH = "interpreter-path-unbound"
FORM_NO_CLASS = "NO-CLASS"
NO_OPERAND = "-"
FORM_REASONS = {
    FORM_NOT_LITERAL: "command word '{}' is not a literal word",
    FORM_NOT_LISTED: "command word '{}' is not on the closed command list",
    FORM_PY_MODULE: "python module '{}' is not on the closed module list",
    FORM_INTERP_PATH: "interpreter path '{}' is neither in the workspace nor bound to base content",
}
# The operand of the array append SUITE_SECONDS+=("${elapsed}"$'\t'"${label}"): the inside of
# the repr the scanner prints, so its one backslash shows as two.
ELAPSED_OPERAND = r"${elapsed}$\\t${label}"
# Shell text of an operand the class template cannot spell (the ANSI-C quote of the tab).
FORM_TEXT_OF_OPERAND = {(FORM_NOT_LITERAL, ELAPSED_OPERAND): '"${elapsed}"$\'\\t\'"${label}" --version'}
# The operand shape corpus (conductor's word b29 664a317e, condition of the operand line): an
# operand row holds a ``${`` only as ``${NAME}`` with NAME of [A-Za-z_][A-Za-z0-9_]*, read as ``$``.
OPERAND_SHAPE_ACCEPTED = {
    "${x}": "$", "${_}": "$", "${_a1}": "$", "${A9_b}": "$", "${x}${y}": "$$", "a${x}b": "a$b",
    ELAPSED_OPERAND: r"$$\\t$", "$line": "$line", "$RUNNER_TEMP/impact/gate.py": "$RUNNER_TEMP/impact/gate.py",
    "apt-get": "apt-get",
}
OPERAND_SHAPE_REFUSED = {
    "command substitution": "$(date)",
    "command substitution after a reference": "${x}$(id)",
    "arithmetic expansion": "$((1+2))",
    "backtick form": "`date`",
    "backtick form inside a word": "a`id`b",
    "nested expansion": "${a${b}}",
    "nested expansion first": "${${a}}",
    # The outer brace never closes: only a span that FULLY matches is a reference, never a match inside it.
    "nested expansion, outer brace open": "${x${y}",
    "default value of a nested reference, outer brace open": "${a:-${b}",
    "default value colon-dash": "${a:-b}",
    "default value dash": "${a-b}",
    "assign default": "${a:=b}",
    "alternate value": "${a:+b}",
    "error if unset": "${a:?b}",
    "index form": "${a[0]}",
    "length form": "${#a}",
    "empty brace": "${}",
    "name starting with a digit": "${1a}",
    "positional digit": "${1}",
    "unterminated brace": "${a",
    "unterminated after a reference": "${x}${a",
}
# One operand of each long shape, 100K+ characters, read under the ceiling (the check is linear).
OPERAND_LINEAR_REPEAT = 50_000
OPERAND_LINEAR_MIN_LEN = 100_000
OPERAND_LINEAR_CEILING_S = 1.0
OPERAND_LINEAR_SHAPES = {"accepted references": ("${a}", True), "open braces": ("${", False),
                         "unterminated names": ("${a", False), "substitutions": ("$(", False),
                         "backticks": ("``", False), "nested": ("${a${b}", False)}
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
# The command word of the synthetic off-list form: a word no handler reads, with its own open row group.
UNLISTED = "adb"
UNLISTED_ISSUE = 9546
DEFAULT = object()  # the reason the form class raises for the operand
INSERT_AT_START = "start"
INSERT_AT_END = "end"

# The issue of each row group (FACTS groups, ruling f367b2f1): (form, operand or NO-CLASS reason).
GROUP_ISSUES = {
    (FORM_NOT_LITERAL, "$BIN"): 9533,
    (FORM_NOT_LISTED, "apt-get"): 9534,
    (FORM_NOT_LITERAL, "$PSQL"): 9535,
    (FORM_PY_MODULE, "os"): 9536,
    (FORM_PY_MODULE, "shutil"): 9536,
    (FORM_PY_MODULE, "subprocess"): 9536,
    (FORM_INTERP_PATH, "$RUNNER_TEMP/impact-base/impact/gate.py"): 9537,
    (FORM_INTERP_PATH, "$RUNNER_TEMP/impact-base/impact/build_index.py"): 9537,
    (FORM_INTERP_PATH, "$RUNNER_TEMP/impact-base/impact/select.py"): 9537,
    (FORM_INTERP_PATH, "$trust_impact/cargo_skip.py"): 9537,
    (FORM_NOT_LISTED, "xcrun"): 9538,
    (FORM_NOT_LISTED, "udevadm"): 9539,
    (FORM_NOT_LISTED, "fallocate"): 9544,
    (FORM_NOT_LISTED, "mkswap"): 9544,
    (FORM_NOT_LISTED, "swapon"): 9544,
    (FORM_NOT_LISTED, "mold"): 9545,
    (FORM_NOT_LISTED, "adb"): 9546,
    (FORM_NOT_LISTED, "--test"): 9547,
    (FORM_NOT_LISTED, "--lib"): 9547,
    (FORM_NOT_LISTED, "--skip"): 9547,
    (FORM_NOT_LITERAL, "$TIMEOUT_BIN"): 9548,
    (FORM_NOT_LITERAL, "$l"): 9548,
    (FORM_NOT_LITERAL, "$tflag"): 9548,
    (FORM_NOT_LITERAL, ELAPSED_OPERAND): 9559,
    (FORM_NOT_LITERAL, "$line"): 9547,
    (FORM_NOT_LISTED, "line"): 9560,
    (FORM_PY_MODULE, "stat"): 9536,
    (FORM_PY_MODULE, "workflow_annotation"): 9561,
    (FORM_NO_CLASS, "python code uses a dunder name"): 9549,
}
# The not-analysed rows: (reason, issue, gate step), in table order.
NOT_ANALYSED_ISSUES = (
    ("arithmetic expansion holding a command substitution", 9550, True),
    ("timeout option '--version' is not on the closed option list", 9551, True),
    ("psql option '--version' is not on the closed option list", 9552, False),
)
NOT_ANALYSED_MARKER = "rest-not-analysed"
REST_NOTE = "command {!r}: the rest of this command is not analysed after this form"
ARITH_NOTE = "the command substitution inside the arithmetic expansion is not analysed"

# A form behind a stopping form in the same command (or substitution): the scan reports only the
# stopping form, and its row says the rest is not analysed. (run text, stop reason, note).
BEHIND_SILENT = (
    ('timeout --version "$HIDDEN_FORM" x', "timeout option '--version' is not on the closed option list",
     REST_NOTE.format("timeout")),
    ('psql --version "$HIDDEN_FORM"', "psql option '--version' is not on the closed option list",
     REST_NOTE.format("psql")),
    ("echo $(( $(unlisted-hidden-form) + 1 ))", "arithmetic expansion holding a command substitution", ARITH_NOTE),
)
# A form after the stopping command, on the same line or a later one, is read and reported.
LATER_SEPARATORS = ("\n", "; ", " && ", " || ")
LATER_FORM = "unlisted-later-form"

# The removal rule and the pins the classifier header states (R-3, F-5).
REMOVAL_RULE_PHRASES = (
    "the fix PR of an issue deletes its rows and lowers that kind's pin in the same commit",
    "each pin only goes down",
    "a pin above its ceiling in ``PIN_CEILINGS`` is a failure",
    "a pin that differs from its row count is a failure",
    "Pins at PR 9508: unclassifiable 47, not-analysed 3, violation 17",
    "The pins are the baseline of the tree PR 9508 lands on",
    "moved the unclassifiable pin 41 -> 47 once); after it lands they only go down",
    "is a proof for what the scan reaches only",
    "the list behind these rows is NOT complete",
    "rest-not-analysed",
    "no network call",
    "the conductor checks that every cited issue is open at each landing of a fix",
    "release checklist",
)
# Size and time bound: one step with more than 100K distinct forms is scanned and checked in
# linear time (the form record keeps a set, never a list scan per form).
MANY_FORMS = 100_001
SCAN_CEILING_S = 5.0
UNCLASSIFIABLE_PREFIX = "unclassifiable: "
NOT_ANALYSED_PREFIX = "not-analysed form without a row: "


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _form_text(form: str, operand: str) -> str:
    return FORM_TEXT_OF_OPERAND.get((form, operand)) or FORM_TEXTS[form].format(operand)


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


def _open(form: str = FORM_NOT_LISTED, operand: str = UNLISTED, issue: object = UNLISTED_ISSUE, gate_step: object = False,
          workflow: str = SYNTH, job: str = JOB, step: str = STEP, reason: object = DEFAULT) -> object:
    if reason is DEFAULT:
        reason = _reason(form, operand) if form in FORM_REASONS else "no reason"
    return tb.OpenRow(workflow, job, step, form, operand, reason, issue, gate_step)


def _stop(reason: str = BEHIND_SILENT[0][1], note: str = BEHIND_SILENT[0][2], operand: str = "--version",
          issue: object = 9551, gate_step: object = False, workflow: str = SYNTH, job: str = JOB, step: str = STEP,
          marker: str = NOT_ANALYSED_MARKER) -> object:
    return tb.NotAnalysedRow(workflow, job, step, FORM_NO_CLASS, operand, reason, note, issue, gate_step, marker)


def _scan(workflows: dict[str, str]) -> object:
    return tb.scan_texts(workflows, {}, frozenset())


def _problems(workflows: dict[str, str], opens: tuple = (), stops: tuple = (), allow: tuple = ()) -> list[str]:
    return tb.check(_scan(workflows), allow, len(allow), opens, len(opens), stops, len(stops))


def _message(workflow: str, job: str, step: str, reason: str) -> str:
    return f"{workflow}/{job}: step {step!r}: {reason}"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _insert(text: str, job: str, step: str, extra: str, where: str) -> str:
    """The workflow text with one shell line added at the start or the end of the step's run block."""
    lines = text.split("\n")
    head = lines.index(f"  {job}:")
    key = f"id: {step[len('id:'):]}" if step.startswith("id:") else f"name: {step}"
    at = next(i for i in range(head + 1, len(lines)) if lines[i].strip().lstrip("- ").startswith(key))
    run = next(i for i in range(at, len(lines)) if lines[i].strip().startswith(("run:", "script:")))
    if lines[run].strip().startswith("script:"):
        pass  # the shell block of an emulator-runner step (``with: script: |``)
    elif lines[run].strip() not in ("run: |", "run: |-", "run: |+"):
        # A plain one-line run: the same shell text as a block, so a line can be added.
        pad = " " * (_indent(lines[run]) + 2)
        lines[run:run + 1] = [f"{pad[:-2]}run: |", pad + lines[run].strip()[len("run:"):].strip()]
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


def _real_scan() -> object:
    if "scan" not in _REAL:
        _REAL["scan"] = tb.scan_texts(*_real())
    return _REAL["scan"]


def _tables() -> dict[str, tuple]:
    return {KIND_VIOLATION: tb.TAINT_ALLOW, KIND_UNCLASSIFIABLE: tb.OPEN_ROWS, KIND_NOT_ANALYSED: tb.NOT_ANALYSED_ROWS}


def _check(result: object, tables: dict[str, tuple], pins: dict[str, int] | None = None) -> list[str]:
    """``check`` over three tables; each pin defaults to its table's row count."""
    pins = pins or {kind: len(rows) for kind, rows in tables.items()}
    return tb.check(result, tables[KIND_VIOLATION], pins[KIND_VIOLATION], tables[KIND_UNCLASSIFIABLE],
                    pins[KIND_UNCLASSIFIABLE], tables[KIND_NOT_ANALYSED], pins[KIND_NOT_ANALYSED])


def _place(row: object) -> str:
    return f"{row.workflow}/{row.job}/{row.step}"


def _uncovered(row: object, result: object) -> list[str]:
    """The exact finding(s) a row covers: what the check reports once the row is gone."""
    if row.kind == KIND_UNCLASSIFIABLE:
        return [f"{UNCLASSIFIABLE_PREFIX}{_message(row.workflow, row.job, row.step, row.reason)}"]
    if row.kind == KIND_NOT_ANALYSED:
        return [f"{NOT_ANALYSED_PREFIX}{_message(row.workflow, row.job, row.step, row.reason)}: {row.note}"]
    return sorted(f"violation class ({v.klass}) without an allow row: {v.workflow}/{v.job}/{v.step}: {v.detail}"
                  for v in result.violations
                  if (v.workflow, v.job, v.step) == (row.workflow, row.job, row.step) and v.klass in row.classes)


def _not_analysed_line(workflow: str, job: str, step: str, reason: str, note: str, issue: int) -> str:
    return f"not-analysed: {_message(workflow, job, step, reason)}: {note} [{NOT_ANALYSED_MARKER}, #{issue}]"


class RowTables(unittest.TestCase):
    """F-1: three tables, three kinds, three pins; the rows are exactly the pinned real findings."""

    def test_9452_three_kinds_three_tables_three_pins(self) -> None:
        _need_module(self)
        self.assertEqual((tb.KIND_UNCLASSIFIABLE, tb.KIND_VIOLATION, tb.KIND_NOT_ANALYSED),
                         (KIND_UNCLASSIFIABLE, KIND_VIOLATION, KIND_NOT_ANALYSED))
        self.assertEqual(tb.PIN_CEILINGS, PIN_CEILINGS)
        self.assertEqual((tb.OPEN_ROW_PIN, tb.NOT_ANALYSED_PIN, tb.TAINT_ALLOW_PIN),
                         (OPEN_PIN, NOT_ANALYSED_PIN, VIOLATION_PIN))
        for kind, rows in _tables().items():
            with self.subTest(kind=kind):
                self.assertEqual({type(r).kind for r in rows}, {kind})
                self.assertEqual(len(rows), PIN_CEILINGS[kind])
        held = f"unclassifiable {len(tb.OPEN_ROWS)}; not-analysed {len(tb.NOT_ANALYSED_ROWS)}; " \
               f"violation {len(tb.TAINT_ALLOW)}"
        self.assertEqual(held, PINS_LINE)

    def test_9452_open_rows_are_exactly_the_real_unclassifiable_forms(self) -> None:
        _need_module(self)
        self.assertEqual(sorted((r.workflow, r.job, r.step, r.reason) for r in tb.OPEN_ROWS), sorted(REAL_UNCLASSIFIABLE))
        for row in tb.OPEN_ROWS:
            with self.subTest(row=_place(row), operand=row.operand):
                self.assertEqual(tb.form_class(row.reason), (row.form, row.operand))
                group = (row.form, row.reason if row.form == FORM_NO_CLASS else row.operand)
                self.assertIs(type(row.issue), int)
                self.assertEqual(row.issue, GROUP_ISSUES[group])
                self.assertIs(row.gate_step, tb.gate_step_of(row.workflow, row.job, row.step))
        self.assertEqual({r.issue for r in tb.OPEN_ROWS}, OPEN_ROW_ISSUES)

    def test_9452_not_analysed_rows_are_exactly_the_three_stopping_forms(self) -> None:
        _need_module(self)
        rows = tb.NOT_ANALYSED_ROWS
        self.assertEqual([(r.workflow, r.job, r.step, r.reason, r.note) for r in rows], list(REAL_NOT_ANALYSED))
        self.assertEqual([(r.reason, r.issue, r.gate_step) for r in rows], list(NOT_ANALYSED_ISSUES))
        for row in rows:
            with self.subTest(row=row.reason):
                self.assertEqual(row.marker, NOT_ANALYSED_MARKER)
                self.assertEqual(row.form, FORM_NO_CLASS)
                self.assertEqual(tb.form_class(row.reason), (FORM_NO_CLASS, row.operand))
                self.assertIn("not analysed", row.note)
        self.assertEqual({r.issue for r in rows}, NOT_ANALYSED_ROW_ISSUES)

    def test_9452_violation_rows_keep_their_issues_and_add_the_four_new(self) -> None:
        _need_module(self)
        self.assertEqual({r.issue for r in tb.TAINT_ALLOW}, VIOLATION_ROW_ISSUES)
        self.assertEqual(sorted((r.workflow, r.job, r.step, r.classes) for r in tb.TAINT_ALLOW if r.issue == 9553),
                         sorted((wf, job, step, (klass,)) for wf, job, step, klass, _ in REAL_NEW_VIOLATIONS))
        for row in tb.TAINT_ALLOW:
            with self.subTest(row=_place(row)):
                self.assertIs(row.gate_step, tb.gate_step_of(row.workflow, row.job, row.step))

    def test_9452_fixed_issue_and_gate_sets(self) -> None:
        _need_module(self)
        self.assertEqual((tb.OPEN_ROW_ISSUES, tb.NOT_ANALYSED_ROW_ISSUES, tb.FIX_ISSUES),
                         (OPEN_ROW_ISSUES, NOT_ANALYSED_ROW_ISSUES, VIOLATION_ROW_ISSUES))
        self.assertEqual((tb.GATE_JOBS, tb.GATE_STEPS), (GATE_JOBS, GATE_STEPS))
        # The gate-step set is derived from the place: no issue-keyed gate set is left.
        for name in ("OPEN_GATE_ISSUES", "NOT_ANALYSED_GATE_ISSUES", "VIOLATION_GATE_ISSUES"):
            self.assertFalse(hasattr(tb, name), name)
        sets = (OPEN_ROW_ISSUES, NOT_ANALYSED_ROW_ISSUES, VIOLATION_ROW_ISSUES)
        self.assertEqual([a & b for i, a in enumerate(sets) for b in sets[i + 1:]], [frozenset()] * 3)

    def test_9452_every_form_row_field_is_present_and_exact(self) -> None:
        _need_module(self)
        self.assertEqual(tb.FORM_CLASSES, frozenset(FORM_REASONS))
        for row in tb.OPEN_ROWS + tb.NOT_ANALYSED_ROWS:
            with self.subTest(row=_place(row), reason=row.reason):
                for value in (row.workflow, row.job, row.step, row.form, row.operand, row.reason):
                    self.assertIs(type(value), str)
                    self.assertNotEqual(value.strip(), "")
                for value in (row.workflow, row.job, row.step, OPERAND_PARAM_REF.sub("$", row.operand)):
                    self.assertEqual([c for c in value if c in GLOB_CHARS], [])
                self.assertNotEqual(row.step, R2_STEP)
                self.assertIs(type(row.issue), int)
                self.assertIs(type(row.gate_step), bool)

    def test_9452_check_refuses_a_row_without_an_exact_place(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        for workflow, job, step in (("", JOB, STEP), (SYNTH, "", STEP), (SYNTH, JOB, ""), (SYNTH, JOB, " "),
                                    (SYNTH, JOB, "*"), (SYNTH, JOB, "S*"), (SYNTH, JOB, "S?"), (SYNTH, JOB, "[S]"),
                                    ("*.yml", JOB, STEP), (SYNTH, "*", STEP), (SYNTH, "{j,k}", STEP),
                                    (SYNTH, JOB, R2_STEP)):
            with self.subTest(place=(workflow, job, step)):
                self.assertIn(f"open row without an exact workflow, job and step: {workflow}/{job}/{step}",
                              _problems(workflows, (_open(workflow=workflow, job=job, step=step),)))
                self.assertIn(f"not-analysed row without an exact workflow, job and step: {workflow}/{job}/{step}",
                              _problems(workflows, stops=(_stop(workflow=workflow, job=job, step=step),)))

    def test_9452_check_refuses_a_row_with_an_unknown_form(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        unlisted = _reason(FORM_NOT_LISTED, UNLISTED)
        for form, operand, reason in (("", UNLISTED, unlisted), ("command", UNLISTED, unlisted), ("*", UNLISTED, unlisted),
                                      (FORM_NOT_LISTED, "", unlisted), (FORM_NOT_LISTED, "*", unlisted),
                                      (FORM_NOT_LISTED, None, unlisted), (FORM_NOT_LISTED, "xcrun", unlisted),
                                      (FORM_NOT_LITERAL, UNLISTED, unlisted), (FORM_NO_CLASS, UNLISTED, unlisted),
                                      (FORM_NOT_LISTED, UNLISTED, None), (FORM_NOT_LISTED, UNLISTED, "x")):
            with self.subTest(form=form, operand=operand, reason=reason):
                row = _open(form=form, operand=operand, reason=reason)
                self.assertIn(f"open row with an unknown form: {SYNTH}/{JOB}/{STEP}", _problems(workflows, (row,)))

    def test_9452_operand_braces_only_as_a_plain_parameter_reference(self) -> None:
        _need_module(self)
        # A braced reference of one plain name is the shell word, matched exactly: accepted.
        for operand in ("${x}", "${_a1}", ELAPSED_OPERAND):
            with self.subTest(accepted=operand):
                text = FORM_TEXT_OF_OPERAND.get((FORM_NOT_LITERAL, operand)) or f'"{operand}" --version'
                workflows = {SYNTH: _wf({JOB: [(STEP, text)]})}
                row = _open(FORM_NOT_LITERAL, operand, 9548)
                self.assertEqual(_problems(workflows, (row,)), [])
        # Any other brace or glob character in the operand is refused, the reason matching or not.
        for operand in ("{a,b}", "${a:-b}", "${a}*", "${}", "${1}", "${a", "$a}", "${a}[b]", "${a}?", "${${a}}"):
            with self.subTest(refused=operand):
                workflows = {SYNTH: _wf({JOB: [(STEP, f'"{operand}" --version')]})}
                row = _open(FORM_NOT_LITERAL, operand, 9548)
                self.assertIn(f"open row with an unknown form: {SYNTH}/{JOB}/{STEP}", _problems(workflows, (row,)))
        # Bound: a 100K+ operand of near-references is read in linear time.
        for big in ("${a" * OPERAND_BOUND_REPEAT, "${a}" * OPERAND_BOUND_REPEAT + "{"):
            with self.subTest(bound=len(big)):
                start = time.monotonic()
                self.assertFalse(tb._exact_operand(big))
                self.assertLess(time.monotonic() - start, OPERAND_CEILING_S)

    def test_9452_operand_shape_is_one_braced_plain_name_9452(self) -> None:
        """Every ``${`` span of an operand fully matches ``${NAME}``; every other expansion form is refused."""
        _need_module(self)
        unknown = [f"open row with an unknown form: {SYNTH}/{JOB}/{STEP}"]
        for operand, plain in OPERAND_SHAPE_ACCEPTED.items():
            with self.subTest(accepted=operand):
                self.assertEqual(tb._operand_plain_form(operand), plain)
                self.assertTrue(tb._exact_operand(operand))
                self.assertEqual(tb._form_row_problems([_open(FORM_NOT_LITERAL, operand, 9548)], "open row",
                                                       tb.OPEN_ROW_ISSUES), [])
        for label, operand in OPERAND_SHAPE_REFUSED.items():
            with self.subTest(refused=label):
                self.assertFalse(tb._exact_operand(operand))
                self.assertEqual(tb._form_row_problems([_open(FORM_NOT_LITERAL, operand, 9548)], "open row",
                                                       tb.OPEN_ROW_ISSUES), unknown)
        for label, (unit, accepted) in OPERAND_LINEAR_SHAPES.items():
            big = unit * OPERAND_LINEAR_REPEAT
            with self.subTest(linear=label, size=len(big)):
                self.assertGreaterEqual(len(big), OPERAND_LINEAR_MIN_LEN)
                start = time.monotonic()
                self.assertIs(tb._exact_operand(big), accepted)
                self.assertLess(time.monotonic() - start, OPERAND_LINEAR_CEILING_S)

    def test_9452_two_rows_for_one_form_are_a_failure(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        key = (SYNTH, JOB, STEP, FORM_NOT_LISTED, UNLISTED, "")
        self.assertIn(f"duplicate open row {key}", _problems(workflows, (_open(), _open())))
        # Two forms in one step, one row each: no failure.
        two = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED) + "\n"
                                  + _form_text(FORM_NOT_LISTED, "xcrun"))]})}
        self.assertEqual(_problems(two, (_open(), _open(operand="xcrun", issue=9538))), [])

    def test_9452_stale_rows_are_a_failure(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, "echo done")]})}
        self.assertEqual(_problems(workflows, (_open(),)),
                         [f"stale open row (no such form in the step): {SYNTH}/{JOB}/{STEP}"])
        self.assertEqual(_problems(workflows, stops=(_stop(),)),
                         [f"stale not-analysed row (no such form and line in the step): {SYNTH}/{JOB}/{STEP}"])


class OneRowOneForm(unittest.TestCase):
    """A row covers only the form it names, in the step it names; the scan goes on past it."""

    def test_9452_row_covers_its_own_form_and_the_job_stays_unclassifiable(self) -> None:
        _need_module(self)
        for (form, operand), issue in GROUP_ISSUES.items():
            if form == FORM_NO_CLASS:
                continue
            with self.subTest(form=form, operand=operand):
                text = _wf({JOB: [(STEP, _form_text(form, operand) + "\n" + _form_text(form, operand))]})
                result = _scan({SYNTH: text})
                row = _open(form, operand, issue)
                self.assertEqual(tb.check(result, (), 0, (row,), 1), [])
                # A row-covered job is NOT shown to hold the boundary.
                self.assertEqual(result.verdicts[(SYNTH, JOB)], tb.UNCLASSIFIABLE)
                self.assertEqual([f.message() for f in result.forms], [_message(SYNTH, JOB, STEP, _reason(form, operand))])

    def test_9452_a_row_never_covers_another_operand_or_class(self) -> None:
        _need_module(self)
        # (row form, row operand, form in the step): same class other operand, same operand other class.
        for row_form, row_operand, found_form, found_operand in (
                (FORM_NOT_LISTED, UNLISTED, FORM_NOT_LISTED, "fallocate"),
                (FORM_NOT_LISTED, "fallocate", FORM_NOT_LISTED, UNLISTED),
                (FORM_NOT_LISTED, "xcrun", FORM_NOT_LISTED, "xcrunx"),
                (FORM_NOT_LITERAL, "$BIN", FORM_INTERP_PATH, "$BIN"),
                (FORM_INTERP_PATH, "$BIN", FORM_NOT_LITERAL, "$BIN"),
                (FORM_PY_MODULE, "os", FORM_NOT_LISTED, "os"),
                (FORM_NOT_LISTED, "os", FORM_PY_MODULE, "os"),
                (FORM_PY_MODULE, "os", FORM_PY_MODULE, "shutil")):
            with self.subTest(row=(row_form, row_operand), found=(found_form, found_operand)):
                workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(found_form, found_operand))]})}
                row = _open(row_form, row_operand, UNLISTED_ISSUE)
                self.assertEqual(sorted(_problems(workflows, (row,))),
                                 sorted([f"stale open row (no such form in the step): {SYNTH}/{JOB}/{STEP}",
                                         UNCLASSIFIABLE_PREFIX
                                         + _message(SYNTH, JOB, STEP, _reason(found_form, found_operand))]))

    def test_9452_a_no_class_row_covers_only_its_exact_reason(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, BEHIND_SILENT[0][0])]})}
        # The psql reason under the same NO-CLASS and operand does not cover the timeout form.
        other = _stop(reason=BEHIND_SILENT[1][1], note=BEHIND_SILENT[0][2])
        self.assertEqual(sorted(_problems(workflows, stops=(other,))),
                         sorted([f"stale not-analysed row (no such form and line in the step): {SYNTH}/{JOB}/{STEP}",
                                 f"{NOT_ANALYSED_PREFIX}{_message(SYNTH, JOB, STEP, BEHIND_SILENT[0][1])}: "
                                 f"{BEHIND_SILENT[0][2]}"]))
        # The right reason with another line does not cover it either.
        wrong_line = _stop(note=BEHIND_SILENT[1][2])
        self.assertEqual(sorted(_problems(workflows, stops=(wrong_line,))),
                         sorted([f"stale not-analysed row (no such form and line in the step): {SYNTH}/{JOB}/{STEP}",
                                 f"{NOT_ANALYSED_PREFIX}{_message(SYNTH, JOB, STEP, BEHIND_SILENT[0][1])}: "
                                 f"{BEHIND_SILENT[0][2]}"]))

    def test_9452_second_form_in_a_synthetic_row_covered_step_is_a_finding(self) -> None:
        _need_module(self)
        for (form, operand), issue in GROUP_ISSUES.items():
            if form == FORM_NO_CLASS:
                continue
            row = _open(form, operand, issue)
            for second_form, second_operand in SECOND_OPERANDS.items():
                for first, last in (((form, operand), (second_form, second_operand)),
                                    ((second_form, second_operand), (form, operand))):
                    with self.subTest(row=(form, operand), second=second_form, first=first):
                        run = _form_text(*first) + "\n" + _form_text(*last)
                        self.assertEqual(_problems({SYNTH: _wf({JOB: [(STEP, run)]})}, (row,)),
                                         [UNCLASSIFIABLE_PREFIX
                                          + _message(SYNTH, JOB, STEP, _reason(second_form, second_operand))])

    def test_9452_second_form_in_a_real_row_covered_step_is_a_finding(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        places = sorted({(r.workflow, r.job, r.step) for r in tb.OPEN_ROWS + tb.NOT_ANALYSED_ROWS})
        for workflow, job, step in places:
            for second_form, second_operand in SECOND_OPERANDS.items():
                for where in (INSERT_AT_START, INSERT_AT_END):
                    with self.subTest(place=(workflow, job, step), second=second_form, where=where):
                        text = _insert(workflows[workflow], job, step, _form_text(second_form, second_operand), where)
                        result = tb.scan_texts(dict(workflows, **{workflow: text}), actions, files)
                        self.assertEqual(tb.check_repo(result),
                                         [UNCLASSIFIABLE_PREFIX
                                          + _message(workflow, job, step, _reason(second_form, second_operand))])
                        self.assertEqual(result.verdicts[(workflow, job)], tb.UNCLASSIFIABLE)

    def test_9452_same_form_in_another_step_job_or_file_is_a_finding(self) -> None:
        _need_module(self)
        for (form, operand), issue in GROUP_ISSUES.items():
            if form == FORM_NO_CLASS:
                continue
            text = _form_text(form, operand)
            row = _open(form, operand, issue)
            cases = (
                ({SYNTH: _wf({JOB: [(STEP, text), (OTHER_STEP, text)]})}, (SYNTH, JOB, OTHER_STEP)),
                ({SYNTH: _wf({JOB: [(STEP, text)], OTHER_JOB: [(STEP, text)]})}, (SYNTH, OTHER_JOB, STEP)),
                ({SYNTH: _wf({JOB: [(STEP, text)]}), OTHER_FILE: _wf({JOB: [(STEP, text)]})}, (OTHER_FILE, JOB, STEP)),
            )
            for workflows, (workflow, job, step) in cases:
                with self.subTest(form=form, operand=operand, place=(workflow, job, step)):
                    self.assertEqual(_problems(workflows, (row,)),
                                     [UNCLASSIFIABLE_PREFIX + _message(workflow, job, step, _reason(form, operand))])

    def test_9452_real_row_covered_jobs_are_not_shown_to_hold_the_boundary(self) -> None:
        _need_module(self)
        result = _real_scan()
        for row in tb.OPEN_ROWS + tb.NOT_ANALYSED_ROWS:
            with self.subTest(row=_place(row)):
                self.assertEqual(result.verdicts[(row.workflow, row.job)], tb.UNCLASSIFIABLE)
                self.assertIn((row.workflow, row.job), result.open_jobs)


class KindsNeverMix(unittest.TestCase):
    """E-2/F-1: a row in the table of another kind is a failure and covers nothing."""

    def test_9452_a_row_in_the_table_of_another_kind_is_a_failure_and_covers_nothing(self) -> None:
        _need_module(self)
        result = _real_scan()
        real = _tables()
        for src, rows in real.items():
            for index, row in enumerate(rows):
                for dst in real:
                    if dst == src:
                        continue
                    with self.subTest(row=_place(row), src=src, dst=dst):
                        tables = dict(real)
                        tables[src] = rows[:index] + rows[index + 1:]
                        tables[dst] = real[dst] + (row,)
                        pins = {k: len(v) for k, v in real.items()}
                        expected = [f"row of kind {src} in the table of kind {dst}: {_place(row)}",
                                    f"{TABLE_NAMES[src]} table has {pins[src] - 1} rows, pin is {pins[src]}",
                                    f"{TABLE_NAMES[dst]} table has {pins[dst] + 1} rows, pin is {pins[dst]}"]
                        expected += _uncovered(row, result)
                        self.assertEqual(sorted(_check(result, tables, pins)), sorted(expected))

    def test_9452_a_form_row_never_covers_a_violation_and_back(self) -> None:
        _need_module(self)
        result = _real_scan()
        real = _tables()
        # The four #9553 steps also hold an open row: that row never covers their violation.
        for wf, job, step, klass, detail in REAL_NEW_VIOLATIONS:
            with self.subTest(step=(wf, job, step)):
                self.assertTrue(any((r.workflow, r.job, r.step) == (wf, job, step) for r in tb.OPEN_ROWS))
                tables = dict(real)
                tables[KIND_VIOLATION] = tuple(r for r in real[KIND_VIOLATION]
                                               if (r.workflow, r.job, r.step) != (wf, job, step))
                self.assertEqual(_check(result, tables),
                                 [f"violation class ({klass}) without an allow row: {wf}/{job}/{step}: {detail}"])
        # A violation row at the step of a form never covers the form.
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        allow = (tb.AllowRow(SYNTH, JOB, STEP, ("iii",), 9553),)
        self.assertEqual(sorted(_problems(workflows, allow=allow)),
                         sorted([f"stale allow row (no longer violates class iii): {SYNTH}/{JOB}/{STEP}",
                                 UNCLASSIFIABLE_PREFIX
                                 + _message(SYNTH, JOB, STEP, _reason(FORM_NOT_LISTED, UNLISTED))]))

    def test_9452_an_open_row_never_covers_a_not_analysed_form_and_back(self) -> None:
        _need_module(self)
        run, reason, note = BEHIND_SILENT[0]
        workflows = {SYNTH: _wf({JOB: [(STEP, run)]})}
        as_open = _open(FORM_NO_CLASS, "--version", 9547, reason=reason)
        self.assertEqual(sorted(_problems(workflows, (as_open,))),
                         sorted([f"stale open row (no such form in the step): {SYNTH}/{JOB}/{STEP}",
                                 f"{NOT_ANALYSED_PREFIX}{_message(SYNTH, JOB, STEP, reason)}: {note}"]))
        plain = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        as_stop = _stop(reason=_reason(FORM_NOT_LISTED, UNLISTED), operand=UNLISTED, note=note)
        problems = _problems(plain, stops=(as_stop,))
        self.assertIn(f"stale not-analysed row (no such form and line in the step): {SYNTH}/{JOB}/{STEP}", problems)
        self.assertIn(UNCLASSIFIABLE_PREFIX + _message(SYNTH, JOB, STEP, _reason(FORM_NOT_LISTED, UNLISTED)), problems)

    def test_9452_a_row_without_a_kind_is_refused_in_every_table(self) -> None:
        _need_module(self)

        class Bare:
            workflow, job, step = SYNTH, JOB, STEP

        result = _scan({SYNTH: _wf({JOB: [(STEP, "echo done")]})})
        for kind in (KIND_VIOLATION, KIND_UNCLASSIFIABLE, KIND_NOT_ANALYSED):
            with self.subTest(kind=kind):
                tables = {k: () for k in _tables()}
                tables[kind] = (Bare(),)
                self.assertEqual(_check(result, tables), [f"row of kind None in the table of kind {kind}: {SYNTH}/{JOB}/{STEP}"])


class Fixpoint(unittest.TestCase):
    """E-4/F-2 over ALL rows of all three kinds. This is a proof for what the scan reaches only:
    a form behind a not-analysed row is not read, so the list behind those rows is NOT complete."""

    def test_9452_all_rows_applied_give_zero_findings_and_three_not_analysed_lines(self) -> None:
        _need_module(self)
        result = _real_scan()
        self.assertEqual(tb.check_repo(result), [])
        self.assertEqual(_check(result, _tables()), [])
        self.assertEqual(tb.not_analysed_lines(result),
                         [_not_analysed_line(wf, job, step, reason, note, issue)
                          for (wf, job, step, reason, note), (_, issue, _) in zip(REAL_NOT_ANALYSED, NOT_ANALYSED_ISSUES)])

    def test_9452_any_one_row_removed_reports_exactly_that_form_line_or_violation(self) -> None:
        _need_module(self)
        result = _real_scan()
        real = _tables()
        removed = 0
        for kind, rows in real.items():
            for index, row in enumerate(rows):
                with self.subTest(kind=kind, row=_place(row), what=getattr(row, "reason", getattr(row, "classes", ""))):
                    tables = dict(real)
                    tables[kind] = rows[:index] + rows[index + 1:]
                    expected = _uncovered(row, result)
                    self.assertNotEqual(expected, [])
                    self.assertEqual(_check(result, tables), expected)
                    lines = tb.not_analysed_lines(result, tables[KIND_NOT_ANALYSED])
                    self.assertEqual(len(lines), NOT_ANALYSED_PIN - (kind == KIND_NOT_ANALYSED))
                    removed += 1
        self.assertEqual(removed, OPEN_PIN + NOT_ANALYSED_PIN + VIOLATION_PIN)

    def test_9452_removing_a_new_violation_row_reports_its_pinned_line(self) -> None:
        _need_module(self)
        result = _real_scan()
        for wf, job, step, klass, detail in REAL_NEW_VIOLATIONS:
            with self.subTest(step=(wf, job, step)):
                row = next(r for r in tb.TAINT_ALLOW if (r.workflow, r.job, r.step) == (wf, job, step))
                self.assertEqual(_uncovered(row, result),
                                 [f"violation class ({klass}) without an allow row: {wf}/{job}/{step}: {detail}"])


class CannotContinue(unittest.TestCase):
    """The three cannot-continue places. decision: a form behind a stopping form inside the same
    command (or substitution) is not reported, and the row line says rest-not-analysed; a form in
    a later command, line or step is read and reported. Both are asserted exactly."""

    def test_9452_cannot_continue_rows_are_kind_not_analysed_with_the_mark(self) -> None:
        _need_module(self)
        for row in tb.NOT_ANALYSED_ROWS:
            with self.subTest(issue=row.issue):
                self.assertEqual(type(row).kind, KIND_NOT_ANALYSED)
                self.assertEqual(row.marker, NOT_ANALYSED_MARKER)
                self.assertNotIn(row, tb.OPEN_ROWS)
        workflows = {SYNTH: _wf({JOB: [(STEP, BEHIND_SILENT[0][0])]})}
        for marker in ("", "rest", "Rest-Not-Analysed", None):
            with self.subTest(marker=marker):
                self.assertIn(f"not-analysed row without the {NOT_ANALYSED_MARKER} mark and its line: {SYNTH}/{JOB}/{STEP}",
                              _problems(workflows, stops=(_stop(marker=marker),)))
        for note in ("", " ", None):
            with self.subTest(note=note):
                self.assertIn(f"not-analysed row without the {NOT_ANALYSED_MARKER} mark and its line: {SYNTH}/{JOB}/{STEP}",
                              _problems(workflows, stops=(_stop(note=note),)))

    def test_9452_a_form_behind_a_stopping_form_is_not_covered_by_silence(self) -> None:
        _need_module(self)
        for (run, reason, note), (_, issue, _) in zip(BEHIND_SILENT, NOT_ANALYSED_ISSUES):
            with self.subTest(run=run):
                result = _scan({SYNTH: _wf({JOB: [(STEP, run)]})})
                # The hidden form is not reported: only the stopping form, with its line.
                self.assertEqual([(f.message(), f.note) for f in result.forms], [(_message(SYNTH, JOB, STEP, reason), note)])
                self.assertEqual(result.verdicts[(SYNTH, JOB)], tb.UNCLASSIFIABLE)
                # Without a row it is a finding; with its row the line says rest-not-analysed.
                self.assertEqual(_problems({SYNTH: _wf({JOB: [(STEP, run)]})}),
                                 [f"{NOT_ANALYSED_PREFIX}{_message(SYNTH, JOB, STEP, reason)}: {note}"])
                operand = tb.form_class(reason)[1]
                row = _stop(reason=reason, note=note, operand=operand, issue=issue)
                self.assertEqual(tb.check(result, (), 0, (), 0, (row,), 1), [])
                self.assertEqual(tb.not_analysed_lines(result, (row,)),
                                 [_not_analysed_line(SYNTH, JOB, STEP, reason, note, issue)])

    def test_9452_a_form_after_the_stopping_command_is_reported(self) -> None:
        _need_module(self)
        later = UNCLASSIFIABLE_PREFIX + _message(SYNTH, JOB, STEP, _reason(FORM_NOT_LISTED, LATER_FORM))
        for (run, reason, note), (_, issue, _) in zip(BEHIND_SILENT, NOT_ANALYSED_ISSUES):
            row = _stop(reason=reason, note=note, operand=tb.form_class(reason)[1], issue=issue)
            for sep in LATER_SEPARATORS:
                with self.subTest(run=run, sep=sep):
                    text = _wf({JOB: [(STEP, run + sep + LATER_FORM)]})
                    self.assertEqual(_problems({SYNTH: text}, stops=(row,)), [later])
            with self.subTest(run=run, later="next step"):
                text = _wf({JOB: [(STEP, run), (OTHER_STEP, LATER_FORM)]})
                self.assertEqual(_problems({SYNTH: text}, stops=(row,)),
                                 [UNCLASSIFIABLE_PREFIX
                                  + _message(SYNTH, JOB, OTHER_STEP, _reason(FORM_NOT_LISTED, LATER_FORM))])

    def test_9452_real_cannot_continue_places_report_a_later_form(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        for row in tb.NOT_ANALYSED_ROWS:
            with self.subTest(issue=row.issue):
                text = _insert(workflows[row.workflow], row.job, row.step, LATER_FORM, INSERT_AT_END)
                result = tb.scan_texts(dict(workflows, **{row.workflow: text}), actions, files)
                self.assertEqual(tb.check_repo(result),
                                 [UNCLASSIFIABLE_PREFIX
                                  + _message(row.workflow, row.job, row.step, _reason(FORM_NOT_LISTED, LATER_FORM))])


class Pins(unittest.TestCase):
    """F-1 and F-5: each pin raised fails; a pin above its row count fails; issues and marks."""

    def test_9452_each_pin_raised_fails(self) -> None:
        _need_module(self)
        result = _real_scan()
        real = _tables()
        for kind in real:
            for raise_by in (1, 2, PIN_CEILINGS[kind]):
                with self.subTest(kind=kind, raise_by=raise_by):
                    pins = {k: len(rows) for k, rows in real.items()}
                    pins[kind] += raise_by
                    self.assertEqual(_check(result, real, pins),
                                     [f"{TABLE_NAMES[kind]} table has {len(real[kind])} rows, pin is {pins[kind]}",
                                      f"{kind} pin {pins[kind]} is above the ceiling {PIN_CEILINGS[kind]}"])

    def test_9452_a_pin_above_its_row_count_fails(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: _wf({JOB: [(STEP, "echo done")]})})
        for kind in _tables():
            for pin in range(1, PIN_CEILINGS[kind] + 1):
                with self.subTest(kind=kind, pin=pin):
                    pins = {k: 0 for k in _tables()}
                    pins[kind] = pin
                    self.assertEqual(_check(result, {k: () for k in _tables()}, pins),
                                     [f"{TABLE_NAMES[kind]} table has 0 rows, pin is {pin}"])

    def test_9452_a_pin_below_its_row_count_fails(self) -> None:
        _need_module(self)
        result = _real_scan()
        real = _tables()
        for kind in real:
            with self.subTest(kind=kind):
                pins = {k: len(rows) for k, rows in real.items()}
                pins[kind] -= 1
                self.assertEqual(_check(result, real, pins),
                                 [f"{TABLE_NAMES[kind]} table has {len(real[kind])} rows, pin is {pins[kind]}"])

    def test_9452_an_issue_outside_the_fixed_set_fails_for_every_kind(self) -> None:
        _need_module(self)
        workflows = {SYNTH: _wf({JOB: [(STEP, _form_text(FORM_NOT_LISTED, UNLISTED))]})}
        stop_wf = {SYNTH: _wf({JOB: [(STEP, BEHIND_SILENT[0][0])]})}
        for issue in BAD_OPEN_ISSUES:
            with self.subTest(kind=KIND_UNCLASSIFIABLE, issue=issue):
                self.assertIn(f"open row without an issue of the fixed set: {SYNTH}/{JOB}/{STEP}",
                              _problems(workflows, (_open(issue=issue),)))
        for issue in BAD_NOT_ANALYSED_ISSUES:
            with self.subTest(kind=KIND_NOT_ANALYSED, issue=issue):
                self.assertIn(f"not-analysed row without an issue of the fixed set: {SYNTH}/{JOB}/{STEP}",
                              _problems(stop_wf, stops=(_stop(issue=issue),)))
        result = _scan({SYNTH: _wf({JOB: [(STEP, "echo done")]})})
        for issue in BAD_VIOLATION_ISSUES:
            with self.subTest(kind=KIND_VIOLATION, issue=issue):
                row = tb.AllowRow(SYNTH, JOB, STEP, ("i",), issue)
                self.assertIn(f"allow row without an open fix issue: {SYNTH}/{JOB}/{STEP}", tb.check(result, (row,), 1))

    def test_9452_every_row_gate_step_mark_follows_its_job_and_step(self) -> None:
        _need_module(self)
        # The mark of every row of the three tables is the one the place rule derives; a row
        # that disagrees is named with its kind, place, operand (a form row), issue and both marks.
        wrong = [f"{type(r).kind} row {_place(r)}{' ' + repr(r.operand) if hasattr(r, 'operand') else ''} "
                 f"(#{r.issue}): mark {r.gate_step!r}, "
                 f"place gives {tb.gate_step_of(r.workflow, r.job, r.step)!r}"
                 for rows in _tables().values() for r in rows
                 if type(r.gate_step) is not bool or r.gate_step is not tb.gate_step_of(r.workflow, r.job, r.step)]
        self.assertEqual(wrong, [])
        # E-5: the NO-CLASS dunder and arithmetic rows are gate steps.
        no_class = [r for r in tb.OPEN_ROWS + tb.NOT_ANALYSED_ROWS
                    if r.reason in ("python code uses a dunder name", NOT_ANALYSED_ISSUES[0][0])]
        self.assertEqual(len(no_class), 3)
        self.assertEqual({r.gate_step for r in no_class}, {True})

    def test_9452_gate_step_rule_names_exactly_the_gate_places(self) -> None:
        _need_module(self)
        for place in GATE_PLACES + NOT_GATE_PLACES:
            with self.subTest(place=place):
                self.assertIs(tb.gate_step_of(*place), place in GATE_PLACES)
        # Every clause of the rule holds a real row, so dropping a clause turns a real row red.
        real_places = {(r.workflow, r.job) for rows in _tables().values() for r in rows if r.gate_step}
        for workflow, jobs in GATE_JOBS.items():
            for job in jobs:
                self.assertIn((workflow, job), real_places)
        real_steps = {(r.workflow, r.job, r.step) for rows in _tables().values() for r in rows}
        for (workflow, job), steps in GATE_STEPS.items():
            for step in steps:
                self.assertIn((workflow, job, step), real_steps)

    def test_9452_check_refuses_a_wrong_gate_step_mark(self) -> None:
        _need_module(self)
        # The mark follows the place, for every issue of every kind: the wrong bool and a
        # non-bool are failures; the right bool is not.
        for workflow, job, step in GATE_PLACES + NOT_GATE_PLACES:
            right = (workflow, job, step) in GATE_PLACES
            result = _scan({workflow: _wf({job: [(step, "echo done")]})})
            makers = (
                ("open row", lambda i, g: dict(open_rows=(_open(issue=i, gate_step=g, workflow=workflow, job=job,
                                                               step=step),), open_pin=1), OPEN_ROW_ISSUES),
                ("not-analysed row", lambda i, g: dict(not_analysed=(_stop(issue=i, gate_step=g, workflow=workflow,
                                                                         job=job, step=step),), not_analysed_pin=1),
                 NOT_ANALYSED_ROW_ISSUES),
                ("allow row", lambda i, g: dict(allow=(tb.AllowRow(workflow, job, step, ("i",), i, g),), pin=1),
                 VIOLATION_ROW_ISSUES),
            )
            line = f"gate-step mark does not match its place: {workflow}/{job}/{step}"
            for word, make, issues in makers:
                for issue in sorted(issues):
                    with self.subTest(place=(workflow, job, step), kind=word, issue=issue):
                        base = dict(allow=(), pin=0)
                        self.assertNotIn(f"{word} {line}", tb.check(result, **{**base, **make(issue, right)}))
                        for bad in (not right, int(right)):
                            self.assertIn(f"{word} {line}", tb.check(result, **{**base, **make(issue, bad)}))

    def test_9452_header_states_the_pins_and_the_removal_rule(self) -> None:
        _need_module(self)
        header = " ".join(tb.__doc__.split())
        for phrase in REMOVAL_RULE_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, header)


class Bounds(unittest.TestCase):
    """Unbounded input: 100K+ distinct forms in one step stay under the wall-clock ceiling."""

    def test_9452_many_distinct_forms_in_one_step_scan_under_ceiling(self) -> None:
        _need_module(self)
        run = "\n".join(f"u{i}" for i in range(MANY_FORMS))
        workflows = {SYNTH: _wf({JOB: [(STEP, run)]})}
        started = time.monotonic()
        result = _scan(workflows)
        problems = tb.check(result, (), 0)
        elapsed = time.monotonic() - started
        self.assertGreater(len(run), MANY_FORMS * 2)
        self.assertEqual(len(result.forms), MANY_FORMS)
        self.assertEqual(len(problems), MANY_FORMS)
        self.assertEqual(problems[-1], UNCLASSIFIABLE_PREFIX
                         + _message(SYNTH, JOB, STEP, _reason(FORM_NOT_LISTED, f"u{MANY_FORMS - 1}")))
        self.assertLess(elapsed, SCAN_CEILING_S)


if __name__ == "__main__":
    unittest.main()
