"""The pre-scan of the tainted-job boundary never skips a step form it cannot read (#9566 item 3).

Class: a pre-scan that decides 'trusted-only' while skipping step forms it cannot read.

Invariant, for every workflow job: the pre-scan returns trusted-only only when every step of the
job was read and judged; a uses: step, a shell: key or any step form the pre-scan does not model
is never skipped. The job goes to the full analysis (fail closed), and the gate result for a job
equals the full-analysis result or is stricter.

P-1 release.yml/docker on the real tree: the full analysis runs, its three results are named by
    allow rows of #9570, and without those rows the gate fails with exactly those three lines.
P-2 a table of step forms: the pre-scan returns its exact reason for each form, and a clean run
    step stays trusted-only (the control).
P-3 a differential, gate against full analysis, over every workflow of the tree and over the
    synthetic forms: zero jobs where the gate is laxer.
P-4 one mutant per syntactic form of the pre-scan, container forms included: each is red.
P-5 a 100K+ input through the pre-scan and the scan stays under a wall-clock ceiling.
P-6 the allow pin and the violation ceiling move together, and one above or one below fails.

Every expected value is written here by hand; none is read from the code under test. Mutants
are built in memory from the module source; no file is written.
"""

from __future__ import annotations

import contextlib
import sys
import time
import types
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))
try:
    import taint_boundary as tb
except ImportError as _import_error:  # red at the base: every cell fails on its own
    tb = None
    IMPORT_ERROR = repr(_import_error)
else:
    IMPORT_ERROR = ""

SYNTH = "synthetic.yml"
JOB = "j"
RELEASE = "release.yml"
DOCKER = "docker"
DOCKER_ISSUE = 9570
DOCKER_ATTEST = "Attest build provenance (Docker image)"
DOCKER_LOGIN = "Log in to GitHub Container Registry"
DOCKER_VERDICT = "i,ii"
# The three full-analysis results of release.yml/docker (security lens r1 of PR 9671).
DOCKER_LINES = frozenset({
    f"violation class (i) without an allow row: {RELEASE}/{DOCKER}/{DOCKER_ATTEST}: "
    "secret or token used after pull-request code ran",
    f"violation class (ii) without an allow row: {RELEASE}/{DOCKER}/{DOCKER_ATTEST}: "
    "job token has a write scope",
    f"violation class (i) without an allow row: {RELEASE}/{DOCKER}/{DOCKER_LOGIN}: "
    "secret held before pull-request code ran can persist into it",
})
DOCKER_ROWS = frozenset({(DOCKER_ATTEST, ("i", "ii")), (DOCKER_LOGIN, ("i",))})
# The allow-table row count after the merge of the 9671 head: 32 rows there plus the two docker rows.
ALLOW_PIN = 34
VIOLATION_CEILING = 34
VIOLATION_KIND = "violation"
TRUSTED_ONLY = "trusted-only"
NO_PR_CODE = "no-pr-code"
LAX_VERDICTS = frozenset({TRUSTED_ONLY, NO_PR_CODE})
FORCED_REASON = "forced to the full analysis by the differential"
SCAN_CEILING_S = 5.0
BIG_BYTES = 120_000
BIG_STEPS = 4_000

# --- P-2: the step-form table. Each row: name, step bodies by label (a non-dict body is kept as
# is), job mapping, workflow mapping, the exact reason. ---
USES_REASON = "step {!r} uses an action, which the pre-scan does not read"
COMPOSITE_REASON = "step {!r} runs inside a composite action, which the pre-scan does not read"
SHELL_REASON = "{} sets a shell, which the pre-scan does not read"
FORM_REASON = "{} has a form the pre-scan does not read: {}"
WINDOWS_REASON = "the job may run on a Windows leg, whose default shell the pre-scan does not read"
NOT_MAP = "it is not a mapping"
NOT_LIST = "it is not a list"
NO_RUN = "it has no run key"
ITEM_FORM = "an item is not a step"
RUN_NOT_TEXT = "run is not text"
RUN_EMPTY = "run is empty text"
# The run-value forms carry the reason text of the 9671 F1 table (a present run key that is not
# non-empty text); the step shapes carry FORM_REASON.
UNREAD_REASON = "step {!r} cannot be read by the pre-scan: {}"
# Every blank form of str.strip() with no argument, alone and mixed, written as code points.
BLANK_RUNS: tuple[tuple[str, str], ...] = (
    ("empty", ""), ("space", " "), ("spaces", "   "), ("tab", "\t"), ("newline", "\n"),
    ("space-tab-newline", " \t\n"), ("crlf", "\r\n"), ("vertical-tab", "\x0b"), ("form-feed", "\x0c"),
    ("file-separator", "\x1c"), ("group-separator", "\x1d"), ("record-separator", "\x1e"),
    ("unit-separator", "\x1f"), ("next-line", "\x85"), ("no-break-space", "\xa0"), ("ogham-space", " "),
    ("em-space", " "), ("line-separator", " "), ("paragraph-separator", " "),
    ("narrow-no-break-space", " "), ("medium-math-space", " "), ("ideographic-space", "　"),
    ("mixed-unicode", " \t\xa0　 "),
)
KEY_FORM = "key {!r} is not on the pre-scan list"
STEP = "step {!r}"
JOB_STEPS = "the job steps"
JOB_DEFAULTS = "the job defaults"
JOB_DEFAULTS_RUN = "the job defaults.run"
WF_DEFAULTS = "the workflow defaults"
WF_DEFAULTS_RUN = "the workflow defaults.run"
CLEAN_RUN = {"name": "s", "run": "echo hello"}
UNTRUSTED_SCRIPT = "core.setOutput('x', '${{ github.event.inputs.title }}')"

STEP_FORMS: tuple[tuple[str, object, dict, dict, str], ...] = (
    ("uses-with-untrusted-input", {"s": {"uses": "actions/github-script@v7", "with": {"script": UNTRUSTED_SCRIPT}}},
     {}, {}, USES_REASON.format("s")),
    ("uses-remote-after-clean-run", {"a": CLEAN_RUN, "s": {"uses": "someone/tool@v1"}}, {}, {},
     USES_REASON.format("s")),
    ("uses-local-action", {"s": {"uses": "./act"}}, {}, {}, USES_REASON.format("s")),
    ("uses-not-text", {"s": {"uses": 3}}, {}, {}, USES_REASON.format("s")),
    ("uses-empty-text", {"s": {"uses": ""}}, {}, {}, USES_REASON.format("s")),
    ("uses-null", {"s": {"uses": None}}, {}, {}, USES_REASON.format("s")),
    ("uses-zero", {"s": {"uses": 0}}, {}, {}, USES_REASON.format("s")),
    ("uses-false", {"s": {"uses": False}}, {}, {}, USES_REASON.format("s")),
    ("uses-empty-list", {"s": {"uses": []}}, {}, {}, USES_REASON.format("s")),
    ("uses-empty-map", {"s": {"uses": {}}}, {}, {}, USES_REASON.format("s")),
    ("composite-step", {"s": {"run": "echo hi", "_composite": "act"}}, {}, {}, COMPOSITE_REASON.format("s")),
    ("shell-bash", {"s": {"run": "echo hi", "shell": "bash"}}, {}, {}, SHELL_REASON.format(STEP.format("s"))),
    ("shell-pwsh", {"s": {"run": "echo hi", "shell": "pwsh"}}, {}, {}, SHELL_REASON.format(STEP.format("s"))),
    ("shell-python", {"s": {"run": "print(1)", "shell": "python"}}, {}, {}, SHELL_REASON.format(STEP.format("s"))),
    ("shell-custom", {"s": {"run": "echo hi", "shell": "perl {0}"}}, {}, {}, SHELL_REASON.format(STEP.format("s"))),
    ("job-defaults-shell", {"s": CLEAN_RUN}, {"defaults": {"run": {"shell": "pwsh"}}}, {},
     SHELL_REASON.format(JOB_DEFAULTS_RUN)),
    ("workflow-defaults-shell", {"s": CLEAN_RUN}, {}, {"defaults": {"run": {"shell": "python"}}},
     SHELL_REASON.format(WF_DEFAULTS_RUN)),
    ("job-defaults-not-map", {"s": CLEAN_RUN}, {"defaults": "bash"}, {}, FORM_REASON.format(JOB_DEFAULTS, NOT_MAP)),
    ("job-defaults-run-list", {"s": CLEAN_RUN}, {"defaults": {"run": ["bash"]}}, {},
     FORM_REASON.format(JOB_DEFAULTS_RUN, NOT_MAP)),
    ("job-defaults-run-null", {"s": CLEAN_RUN}, {"defaults": {"run": None}}, {},
     FORM_REASON.format(JOB_DEFAULTS_RUN, NOT_MAP)),
    ("job-defaults-other-key", {"s": CLEAN_RUN}, {"defaults": {"shell": "bash"}}, {},
     FORM_REASON.format(JOB_DEFAULTS, KEY_FORM.format("shell"))),
    ("workflow-defaults-run-key", {"s": CLEAN_RUN}, {}, {"defaults": {"run": {"working-directory": "x"}}},
     FORM_REASON.format(WF_DEFAULTS_RUN, KEY_FORM.format("working-directory"))),
    ("windows-runs-on", {"s": CLEAN_RUN}, {"runs-on": "windows-latest"}, {}, WINDOWS_REASON),
    ("windows-matrix-leg", {"s": CLEAN_RUN},
     {"runs-on": "${{ matrix.os }}", "strategy": {"matrix": {"os": ["ubuntu-latest", "Windows-2022"]}}}, {},
     WINDOWS_REASON),
    ("run-number", {"s": {"run": 3}}, {}, {}, UNREAD_REASON.format("s", RUN_NOT_TEXT)),
    ("run-empty", {"s": {"run": None}}, {}, {}, UNREAD_REASON.format("s", RUN_NOT_TEXT)),
    ("run-list", {"s": {"run": ["echo hi"]}}, {}, {}, UNREAD_REASON.format("s", RUN_NOT_TEXT)),
    ("run-map", {"s": {"run": {"a": "b"}}}, {}, {}, UNREAD_REASON.format("s", RUN_NOT_TEXT)),
    ("run-bool", {"s": {"run": True}}, {}, {}, UNREAD_REASON.format("s", RUN_NOT_TEXT)),
    *((f"run-blank-{blank}", {"s": {"run": value}}, {}, {}, UNREAD_REASON.format("s", RUN_EMPTY))
      for blank, value in BLANK_RUNS),
    ("run-blank-after-clean-run", {"a": CLEAN_RUN, "s": {"run": " "}}, {}, {}, UNREAD_REASON.format("s", RUN_EMPTY)),
    ("neither-run-nor-uses", {"s": {"name": "s"}}, {}, {}, FORM_REASON.format(STEP.format("s"), NO_RUN)),
    ("step-not-map", {"s": ["echo hi"]}, {}, {}, FORM_REASON.format(STEP.format("s"), NOT_MAP)),
    ("step-key-with", {"s": {"run": "echo hi", "with": {"a": "b"}}}, {}, {},
     FORM_REASON.format(STEP.format("s"), KEY_FORM.format("with"))),
    ("step-key-working-directory", {"s": {"run": "echo hi", "working-directory": "x"}}, {}, {},
     FORM_REASON.format(STEP.format("s"), KEY_FORM.format("working-directory"))),
    ("steps-not-list", "steps-map", {}, {}, FORM_REASON.format(JOB_STEPS, NOT_LIST)),
    ("item-not-step-text", ["x"], {}, {}, FORM_REASON.format(JOB_STEPS, ITEM_FORM)),
    ("item-not-step-null", [None], {}, {}, FORM_REASON.format(JOB_STEPS, ITEM_FORM)),
    ("item-not-step-map", [{"run": "echo hi"}], {}, {}, FORM_REASON.format(JOB_STEPS, ITEM_FORM)),
    ("item-not-step-int", [3], {}, {}, FORM_REASON.format(JOB_STEPS, ITEM_FORM)),
)
STEP_FORM_NAMES = tuple(row[0] for row in STEP_FORMS)
# The control: a plain run step on a Linux leg is read in full and judged.
CLEAN_FORMS: tuple[tuple[str, dict, dict, dict], ...] = (
    ("clean-run", {"s": CLEAN_RUN}, {"runs-on": "ubuntu-latest"}, {}),
    ("clean-run-every-step-key", {"s": {"name": "s", "id": "x", "if": "always()", "env": {"A": "b"},
                                        "run": "echo hi", "timeout-minutes": 5, "continue-on-error": True}},
     {}, {}),
    ("clean-run-empty-defaults", {"s": CLEAN_RUN}, {"defaults": {}}, {"defaults": {"run": {}}}),
)

# --- P-4: one mutant per syntactic form of the pre-scan. Each row: the form, the exact source
# line, its replacement and the STEP_FORMS row that must go red. ---
MUTANTS: tuple[tuple[str, str, str, str], ...] = (
    ("steps container is a list", "    if not isinstance(steps, list):  # the pre-scan steps container",
     "    if False:", "steps-not-list"),
    ("defaults container is a map", "    if not isinstance(defaults, dict):", "    if False:", "job-defaults-not-map"),
    ("defaults key is run", '        if key != "run":', "        if False:", "job-defaults-other-key"),
    ("defaults.run container is a map", "    if not isinstance(run, dict):", "    if False:",
     "job-defaults-run-list"),
    ("defaults.run shell", '    if "shell" in run:', "    if False:", "job-defaults-shell"),
    ("defaults.run other key", "    if run:", "    if False:", "workflow-defaults-run-key"),
    ("windows leg", "    if WINDOWS_LABEL_WORD in _dump([job.get(\"runs-on\"), job.get(\"strategy\")]).lower():",
     "    if False:", "windows-runs-on"),
    ("step container is a map", "    if not isinstance(body, dict):", "    if False:", "step-not-map"),
    ("uses step", '    if "uses" in body:', "    if False:", "uses-local-action"),
    ("uses truthy", '    if "uses" in body:', '    if body.get("uses"):', "uses-empty-text"),
    ("item is a step", "    if not isinstance(step, _Step):", "    if False:", "item-not-step-text"),
    ("composite step", "    if COMPOSITE_MARK in body:", "    if False:", "composite-step"),
    ("step shell", '    if "shell" in body:', "    if False:", "shell-custom"),
    ("step key list", "        if key not in PRE_SCAN_STEP_KEYS:", "        if False:", "step-key-working-directory"),
    ("run key present", '    if "run" not in body:', "    if False:", "neither-run-nor-uses"),
    ("run is text", "    if not isinstance(run_text, str):", "    if False:", "run-list"),
    ("run is non-blank text", "    if not run_text.strip():", "    if False:", "run-blank-space"),
)
MUTANT_FORMS = frozenset(row[3] for row in MUTANTS)
# The caller mutant brings back the short cut past the full analysis.
CALLER_LINE = "    pre_scan = None if strict else _pre_scan_fetch(steps, job, doc)"
CALLER_MUTANT = (CALLER_LINE + "\n    if pre_scan is None and not strict:\n"
                 "        return \"trusted-only\" if r2 is None else CLASS_PERSISTENT_STATE")


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _steps(module: types.ModuleType, bodies: object) -> object:
    if not isinstance(bodies, dict):
        return bodies
    return [module._Step(label, body, pos) for pos, (label, body) in enumerate(bodies.items())]


def _form(name: str) -> tuple[str, object, dict, dict, str]:
    return next(row for row in STEP_FORMS if row[0] == name)


@contextlib.contextmanager
def _full_analysis(module: types.ModuleType):
    """Every job, whatever its triggers, goes to the full analysis."""
    with unittest.mock.patch.object(module, "_pre_scan_fetch", lambda steps, job, doc: FORCED_REASON):
        yield


def _mutant(old: str, new: str) -> types.ModuleType:
    source = Path(tb.__file__).read_text(encoding="utf-8")
    if source.count(old + "\n") != 1:
        raise AssertionError(f"mutant line not found exactly once: {old!r}")
    name = f"taint_boundary_mutant_{abs(hash(old))}"
    module = types.ModuleType(name)
    module.__file__ = tb.__file__
    sys.modules[name] = module
    try:
        exec(compile(source.replace(old + "\n", new + "\n"), tb.__file__, "exec"), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


def _laxer(module: types.ModuleType, workflows: dict[str, str], actions: dict[str, str]) -> list[str]:
    """Every job verdict and problem the full analysis has and the gate lacks (zero is the bar)."""
    gate = module.scan_texts(workflows, actions, frozenset())
    with _full_analysis(module):
        full = module.scan_texts(workflows, actions, frozenset())
    out = [f"verdict {key}: gate {gate.verdicts.get(key)} full {verdict}"
           for key, verdict in sorted(full.verdicts.items())
           if verdict not in LAX_VERDICTS and gate.verdicts.get(key) in LAX_VERDICTS]
    gate_problems = set(module.check(gate, allow=(), pin=0))
    out += sorted(p for p in module.check(full, allow=(), pin=0) if p not in gate_problems)
    return out


def _wf(steps: str, on: str = "workflow_dispatch", job_extra: str = "", top_extra: str = "",
        perms: str = "permissions:\n  contents: write\n", runs_on: str = "ubuntu-latest") -> str:
    return (f"on: {on}\n{perms}{top_extra}jobs:\n  {JOB}:\n    runs-on: {runs_on}\n{job_extra}"
            f"    steps:\n{steps}")


PAYLOAD_CHECKOUT = ("      - uses: actions/checkout@v4\n        with:\n"
                    "          ref: ${{ github.event.client_payload.ref }}\n          persist-credentials: false\n")
SECRET_STEP = ("      - name: Publish\n        env:\n          T: ${{ secrets.X }}\n"
               "        run: echo done\n")
NODE_ACTION = "runs:\n  using: node20\n  main: index.js\n"
# --- P-3 synthetic forms: name, workflow text, local actions, the exact text a problem carries.
SYNTHETIC: tuple[tuple[str, str, dict[str, str], str], ...] = (
    ("dispatch-payload-local-action",
     _wf(PAYLOAD_CHECKOUT + "      - name: Build\n        uses: ./act\n" + SECRET_STEP, on="repository_dispatch"),
     {"act": NODE_ACTION},
     f"violation class (i) without an allow row: {SYNTH}/{JOB}/Publish: secret or token used after "
     "pull-request code ran"),
    ("dispatch-payload-unknown-action",
     _wf(PAYLOAD_CHECKOUT + "      - name: Tool\n        uses: someone/tool@v1\n" + SECRET_STEP,
         on="repository_dispatch"),
     {}, "unknown action 'someone/tool'"),
    ("step-shell-custom",
     _wf(PAYLOAD_CHECKOUT + "      - name: Perl\n        shell: perl {0}\n        run: print 1\n"),
     {}, "shell 'perl' is not on the closed shell list"),
    ("job-defaults-shell",
     _wf("      - name: Echo\n        run: echo hi\n", job_extra="    defaults:\n      run:\n        shell: pwsh\n"),
     {}, "shell 'pwsh' is not on the closed shell list"),
    ("workflow-defaults-shell",
     _wf("      - name: Echo\n        run: echo hi\n", top_extra="defaults:\n  run:\n    shell: python\n"),
     {}, "shell 'python' is not on the closed shell list"),
    ("windows-leg-default-shell",
     _wf("      - name: Echo\n        run: echo hi\n", runs_on="windows-latest"),
     {}, "the default shell of a Windows leg is pwsh"),
    ("run-number", _wf("      - name: Num\n        run: 3\n"), {}, "run is not text"),
    ("run-empty", _wf("      - name: Empty\n        run:\n"), {}, "run is not text"),
    ("run-list", _wf("      - name: List\n        run:\n          - echo hi\n"), {}, "run is not text"),
    ("run-map", _wf("      - name: Map\n        run:\n          a: b\n"), {}, "run is not text"),
    ("env-name-only-the-full-analysis-reads",
     _wf("      - name: Env\n        run: echo ${{ env.NOPE }}\n"),
     {}, "expression `env.NOPE` names no env value declared in the workflow"),
    ("neither-run-nor-uses", _wf("      - name: Bare\n"), {}, "needs exactly one of run/uses"),
    ("step-not-map", _wf("      - echo hi\n"), {}, "step 0 is not a mapping"),
    ("steps-not-list", f"on: workflow_dispatch\npermissions:\n  contents: read\njobs:\n  {JOB}:\n"
     "    runs-on: ubuntu-latest\n    steps: echo\n", {}, "steps is not a list"),
)


class DockerJobIsAnalysedInFull(unittest.TestCase):
    """P-1: release.yml/docker on the real tree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = tb.scan(REPO_ROOT) if tb is not None else None

    def test_9566_docker_verdict_is_the_full_analysis(self) -> None:
        _need_module(self)
        self.assertEqual(self.result.verdicts.get((RELEASE, DOCKER)), DOCKER_VERDICT)

    def test_9566_docker_gate_fails_without_its_rows(self) -> None:
        _need_module(self)
        rows = tuple(r for r in tb.TAINT_ALLOW if (r.workflow, r.job) != (RELEASE, DOCKER))
        problems = tb.check(self.result, rows, len(rows), tb.OPEN_ROWS, tb.OPEN_ROW_PIN,
                            tb.NOT_ANALYSED_ROWS, tb.NOT_ANALYSED_PIN)
        self.assertEqual(set(problems), set(DOCKER_LINES))
        self.assertEqual(len(problems), len(DOCKER_LINES))

    def test_9566_docker_rows_name_9570(self) -> None:
        _need_module(self)
        rows = [r for r in tb.TAINT_ALLOW if (r.workflow, r.job) == (RELEASE, DOCKER)]
        self.assertEqual({(r.step, tuple(r.classes)) for r in rows}, set(DOCKER_ROWS))
        self.assertEqual({r.issue for r in rows}, {DOCKER_ISSUE})
        self.assertEqual({r.gate_step for r in rows}, {False})

    def test_9566_real_tree_gate_is_clean(self) -> None:
        _need_module(self)
        self.assertEqual(tb.check_repo(self.result), [])


class PreScanReadsEveryStepForm(unittest.TestCase):
    """P-2: the exact reason per step form, and the clean control."""

    def test_9566_every_form_has_its_exact_reason(self) -> None:
        _need_module(self)
        for name, bodies, job, doc, reason in STEP_FORMS:
            with self.subTest(form=name):
                self.assertEqual(tb._pre_scan_fetch(_steps(tb, bodies), job, doc), reason)

    def test_9566_clean_run_step_is_read_and_judged(self) -> None:
        _need_module(self)
        for name, bodies, job, doc in CLEAN_FORMS:
            with self.subTest(form=name):
                self.assertIsNone(tb._pre_scan_fetch(_steps(tb, bodies), job, doc))

    def test_9566_no_form_is_trusted_only_in_a_scan(self) -> None:
        _need_module(self)
        for name, text, actions, _ in SYNTHETIC:
            with self.subTest(form=name):
                result = tb.scan_texts({SYNTH: text}, actions, frozenset())
                self.assertNotEqual(result.verdicts.get((SYNTH, JOB)), TRUSTED_ONLY)


class GateIsNeverLaxerThanFullAnalysis(unittest.TestCase):
    """P-3: the differential, over the whole tree and over the synthetic forms."""

    def test_9566_real_tree_differential_has_no_laxer_job(self) -> None:
        _need_module(self)
        workflows, actions, _ = tb.load_repo(REPO_ROOT)
        self.assertGreater(len(workflows), 0)
        self.assertEqual(_laxer(tb, workflows, actions), [])

    def test_9566_blank_run_forms_differential_and_never_trusted_only(self) -> None:
        # The 9671 F1 blank forms in a scan: the gate verdict is the full-analysis verdict, never
        # trusted-only, with and without pull-request code before the blank step.
        _need_module(self)
        for blank, value in BLANK_RUNS:
            quoted = '"' + "".join(f"\\u{ord(char):04x}" for char in value) + '"'
            blank_step = f"      - name: Blank\n        run: {quoted}\n"
            for carrier, text in (("plain", _wf(blank_step)),
                                  ("payload", _wf(PAYLOAD_CHECKOUT + blank_step + SECRET_STEP,
                                                  on="repository_dispatch"))):
                with self.subTest(form=blank, carrier=carrier):
                    doc = tb.parse_yaml(text, SYNTH)
                    blank_index = 1 if carrier == "payload" else 0
                    self.assertEqual(doc["jobs"][JOB]["steps"][blank_index]["run"], value)
                    gate = tb.scan_texts({SYNTH: text}, {}, frozenset())
                    with _full_analysis(tb):
                        full = tb.scan_texts({SYNTH: text}, {}, frozenset())
                    self.assertNotEqual(gate.verdicts.get((SYNTH, JOB)), TRUSTED_ONLY)
                    self.assertEqual(gate.verdicts.get((SYNTH, JOB)), full.verdicts.get((SYNTH, JOB)))
                    self.assertEqual(_laxer(tb, {SYNTH: text}, {}), [])

    def test_9566_synthetic_forms_differential_and_exact_problem(self) -> None:
        _need_module(self)
        for name, text, actions, expected in SYNTHETIC:
            with self.subTest(form=name):
                self.assertEqual(_laxer(tb, {SYNTH: text}, actions), [])
                problems = tb.check(tb.scan_texts({SYNTH: text}, actions, frozenset()), allow=(), pin=0)
                self.assertTrue(any(expected in p for p in problems), problems)


class EveryMutantIsRed(unittest.TestCase):
    """P-4: one mutant per syntactic form; the table or the differential goes red on each."""

    def test_9566_mutants_cover_the_container_forms(self) -> None:
        self.assertTrue({"steps-not-list", "step-not-map", "job-defaults-not-map", "job-defaults-run-list",
                         "run-list"} <= MUTANT_FORMS)
        self.assertTrue(MUTANT_FORMS <= set(STEP_FORM_NAMES))

    def test_9566_each_form_mutant_is_red(self) -> None:
        _need_module(self)
        for form, old, new, case in MUTANTS:
            with self.subTest(mutant=form):
                module = _mutant(old, new)
                _, bodies, job, doc, reason = _form(case)
                try:
                    got = module._pre_scan_fetch(_steps(module, bodies), job, doc)
                except (AttributeError, KeyError, TypeError, ValueError, module.Unclassifiable) as exc:
                    # a crash on a mutant form is red too; the exception is named in the result
                    got = f"raised {type(exc).__name__}"
                self.assertNotEqual(got, reason, f"mutant {form!r} survived")

    def test_9566_caller_mutant_is_red(self) -> None:
        _need_module(self)
        module = _mutant(CALLER_LINE, CALLER_MUTANT)
        _, text, actions, _ = next(row for row in SYNTHETIC if row[0] == "env-name-only-the-full-analysis-reads")
        self.assertNotEqual(_laxer(module, {SYNTH: text}, actions), [])


class PreScanIsBounded(unittest.TestCase):
    """P-5: 100K+ inputs stay under the ceiling."""

    def test_9566_many_steps_under_ceiling(self) -> None:
        _need_module(self)
        bodies = {f"s{i}": {"name": f"s{i}", "run": "echo hello world " + "x" * 16} for i in range(BIG_STEPS)}
        steps = _steps(tb, bodies)
        self.assertGreater(sum(len(b["run"]) for b in bodies.values()), BIG_BYTES)
        start = time.monotonic()
        self.assertIsNone(tb._pre_scan_fetch(steps, {}, {}))
        self.assertLess(time.monotonic() - start, SCAN_CEILING_S)

    def test_9566_long_run_and_many_uses_steps_under_ceiling(self) -> None:
        _need_module(self)
        long_run = {"s": {"name": "s", "run": "echo " + "a" * BIG_BYTES}}
        start = time.monotonic()
        self.assertIsNone(tb._pre_scan_fetch(_steps(tb, long_run), {}, {}))
        uses = "".join(f"      - name: U{i}\n        uses: actions/checkout@v4\n        with:\n"
                       "          persist-credentials: false\n" for i in range(BIG_STEPS // 2))
        text = _wf(uses, perms="permissions:\n  contents: read\n")
        self.assertGreater(len(text), BIG_BYTES)
        tb.scan_texts({SYNTH: text}, {}, frozenset())
        self.assertLess(time.monotonic() - start, SCAN_CEILING_S)


class AllowPinMovesWithTheDockerRows(unittest.TestCase):
    """P-6: the allow pin and the violation ceiling, one above and one below."""

    def test_9566_pin_and_ceiling(self) -> None:
        _need_module(self)
        self.assertEqual(tb.TAINT_ALLOW_PIN, ALLOW_PIN)
        self.assertEqual(len(tb.TAINT_ALLOW), ALLOW_PIN)
        self.assertEqual(tb.PIN_CEILINGS[tb.KIND_VIOLATION], VIOLATION_CEILING)

    def test_9566_pin_one_below_and_one_above_fail(self) -> None:
        _need_module(self)
        below = tb._pin_problems(tb.KIND_VIOLATION, ALLOW_PIN, ALLOW_PIN - 1, "allow")
        self.assertEqual(below, [f"allow table has {ALLOW_PIN} rows, pin is {ALLOW_PIN - 1}"])
        above = tb._pin_problems(tb.KIND_VIOLATION, ALLOW_PIN, ALLOW_PIN + 1, "allow")
        self.assertEqual(above, [f"allow table has {ALLOW_PIN} rows, pin is {ALLOW_PIN + 1}",
                                 f"{VIOLATION_KIND} pin {ALLOW_PIN + 1} is above the ceiling {VIOLATION_CEILING}"])
        self.assertEqual(tb._pin_problems(tb.KIND_VIOLATION, ALLOW_PIN, ALLOW_PIN, "allow"), [])


if __name__ == "__main__":
    unittest.main()
