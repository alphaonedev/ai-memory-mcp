"""Closed-list invariants of the tainted-job boundary classifier (umbrella #9452, round-1 fix).

decision: closed positive lists with Unclassifiable as a finding for every unknown form, over
a patch per reported form, because two review lenses found twelve forms of one class in one
round (conductor ruling b44e2422).

I-1 a job reads clean only by positive proof: every command word, git/gh/docker subcommand,
    option that runs a command, expression context, matrix form, job key and step key is on a
    closed list; every other form is Unclassifiable with an exact reason, and Unclassifiable is
    a finding.
I-2 taint and base materialisation are per step and ordered; a secret held at or before the
    taint point by any carrier counts.
I-3 an allow row matches exactly one step.
I-4 every scanner is linear: a 100K+ adversarial input per scanner stays under a named ceiling.
I-5 nothing from a workflow reaches stdout unescaped; oversized, deeply nested, empty-`on`,
    null-`permissions` and workflow_call-only inputs each end with their own exact reason.
I-6 this test runs in an existing hosted job, and that step itself holds the boundary.

Every corpus is a named constant; every cell works on in-memory text. No file is written.
"""

from __future__ import annotations

import ast
import contextlib
import io
import re
import sys
import time
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
SCAN_CEILING_S = 5.0
ADVERSARIAL_BYTES = 120_000
MAX_NESTING = 64
MAX_YAML_BYTES = 8 * 1024 * 1024
FIX_ISSUES = frozenset({9454, 9455, 9456, 9471, 9553})
UNCLASSIFIABLE_PREFIX = "unclassifiable: "
# The hosted job and step that already run the scripts/ci unit tests (I-6).
HOST_WORKFLOW = "ci.yml"
HOST_JOB = "build-script-vetting"
HOST_STEP = "Shard partition and wiring unit tests (#6344)"
HOST_COMMAND = "python3 -m unittest discover -s scripts/ci/tests"
HOSTED_LABEL = "ubuntu-latest"
# The module-level patterns that remain, by name; a new pattern needs a review and a time cell.
REGEX_NAMES_EXPECTED = frozenset({
    "GITHUB_HOSTED_LABEL_RE", "SECRET_REF_RE", "EVENT_EQ_RE", "ENV_FILE_WRITE_RE",
    "BLOCK_HEADER_RE", "NAME_RE", "QUOTED_RE",
    # A row operand check, never run on workflow text: one braced plain name, no nested quantifier.
    "OPERAND_PARAM_REF_RE",
})
REMOVED_NAMES = ("BASE_MATERIALISE_RE", "CHECKOUT_IN_RUN_RE", "RUNNER_BOUNDARY_FACTS", "VERSION_ARGS",
                 "HOST_CREDENTIAL_RE", "MATRIX_RUNS_ON_RE", "STEP_OUTPUT_REF_RE")


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _wf(steps: str, on: str = "pull_request", job_extra: str = "", top_extra: str = "",
        perms: str = "permissions:\n  contents: read\n", runs_on: str = "ubuntu-latest") -> str:
    return (f"on: {on}\n{perms}{top_extra}jobs:\n  {JOB}:\n    runs-on: {runs_on}\n{job_extra}"
            f"    steps:\n{steps}")


CHECKOUT = "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
SECRET_STEP = ("      - name: Late secret\n        env:\n          T: ${{ secrets.X }}\n"
               "        run: echo done\n")


def _run_step(name: str, run: str, env: str = "") -> str:
    body = "".join(f"          {line}\n" for line in run.split("\n"))
    env_block = f"        env:\n{env}" if env else ""
    return f"      - name: {name}\n{env_block}        run: |\n{body}"


def _scan(text: str, extra: dict[str, str] | None = None) -> object:
    return tb.scan_texts(dict({SYNTH: text}, **(extra or {})), {}, frozenset())


def _found(result: object) -> list[str]:
    """Every form the scan found: a stop (no sink) or a recorded form a row can cover."""
    return result.unclassifiable + [f.message() for f in result.forms]


def _problems(text: str, extra: dict[str, str] | None = None) -> list[str]:
    return tb.check(_scan(text, extra), allow=(), pin=0)


def _classify(text: str) -> bool:
    return tb._shell_runs_pr_code(text)


# ---------------------------------------------------------------------------------------
# I-1 corpora. Each row: shell text, exact reason. The first rows are the reviewers' forms;
# the rows marked sibling were named by neither lens.
# ---------------------------------------------------------------------------------------

SHELL_UNCLASSIFIABLE = (
    ("unknowncmd --x", "command word 'unknowncmd' is not on the closed command list"),
    ("$TOOL --flag", "command word '$TOOL' is not a literal word"),
    ("trap 'unknowncmd' EXIT", "command word 'unknowncmd' is not on the closed command list"),
    ("env -S 'unknowncmd x'", "command word 'unknowncmd' is not on the closed command list"),
    ("xargs unknowncmd < list", "command word 'unknowncmd' is not on the closed command list"),
    ("find . -exec unknowncmd {} \\;", "command word 'unknowncmd' is not on the closed command list"),
    ("timeout 5 unknowncmd", "command word 'unknowncmd' is not on the closed command list"),
    ("git frobnicate", "git subcommand 'frobnicate' is not on the closed list"),
    ("git -c core.fsmonitor=x status", "git -c key 'core.fsmonitor' is not on the closed key list"),
    ("gh frob", "gh subcommand 'frob' is not on the closed list"),
    ("docker frob", "docker subcommand 'frob' is not on the closed list"),
    ("tar --to-command=sh -xf a.tar", "tar option '--to-command' runs a command"),
    ("sed 'k' f", "sed command 'k' is not on the closed sed list"),
    ("awk 'BEGIN { system(\"x\") }'", "awk program calls system()"),
    ("awk '{ print | \"sh\" }' f", "awk program pipes to or from a command"),
    ("awk '@include \"x\"' f", "awk program loads a source file"),
    ("psql -c '\\! id'", "psql meta-command in SQL text"),
    ("echo $(( $(id) + 1 ))", "arithmetic expansion holding a command substitution"),
    ("echo ${x:-$(id)}", "parameter expansion holding a command substitution"),
    ("python3 -I -c 'import subprocess'", "python module 'subprocess' is not on the closed module list"),
    ("python3 -I -c 'x.__class__'", "python code uses a dunder name"),
    ("python3 -I /opt/x.py", "interpreter path '/opt/x.py' is neither in the workspace nor bound to base content"),
    ("sudo -i", "sudo option '-i' is not on the closed option list"),
    # sibling forms of the exec-option class (neither lens named them)
    ("sort --compress-program=sh f", "sort option '--compress-program' runs a command"),
    ("rsync -e ssh a b", "rsync option '-e' runs a command"),
    ("zip -TT x a.zip f", "zip option '-TT' runs a command"),
    ("openssl req -engine x", "openssl option '-engine' loads code"),
    ("install --strip-program=x a b", "install option '--strip-program' runs a command"),
)

SHELL_PR_CODE = (
    # reviewers' forms
    ("flock /var/lock/x -c 'make all'", True),
    ("trap 'cargo build' EXIT", True),
    ("env -S 'cargo build'", True),
    ("awk -f x.awk f", True),
    ("git submodule foreach 'make'", True),
    ("git rebase --exec 'make' HEAD~1", True),
    ("sed -e '1e' f", True),
    ("sed 's/x/y/e' f", True),
    ("find . -name x -exec make {} \\;", True),
    ("xargs make < list", True),
    ("docker run --rm -v \"$PWD:/w\" img true", True),
    ("cargo --version", True),
    ("python3 -I - < scripts/x.py", True),
    ("python3 -I -c \"$(cat x)\"", True),
    ("python3 -I -c 'exec(open(\"x\").read())'", True),
    ("psql -f x.sql", True),
    ("psql < x.sql", True),
    ("sqlite3 db < x.sql", True),
    ("case \"$x\" in a) ( bash x ) ;; esac", True),
    ("echo [[ ; bash x", True),
    ("gh extension install x", True),
    # sibling forms (neither lens named them)
    ("cat x.sh | bash", True),
    ("nice -n 5 make", True),
    ("command make", True),
    ("stdbuf -oL make", True),
    ("rustup show", True),
    ("npm --version", True),
    ("git bisect run make", True),
    # python -m: only a listed module under -I is inert (PY_INERT_MODULES)
    ("python3 -I -m pytest", True),
    ("python3 -I -m os", True),
    ("python3 -m json.tool f.json", True),
)

SHELL_INERT = (
    ("echo hi && grep -c x file | wc -l", False),
    ("git diff --name-only HEAD~1 > changed.txt", False),
    ("bash -c 'echo hi'", False),
    ("python3 -I -m json.tool f.json", False),
    ("python3 -I -c 'import json, sys; print(json.dumps(sys.argv))'", False),
    ("python3 --version", False),
    ("for f in a b; do echo \"$f\"; done", False),
    ("case \"$x\" in a|b) echo y ;; *) echo n ;; esac", False),
    ("if [[ -n \"$x\" && -f y ]]; then echo ok; fi", False),
    ("(( n += 1 ))", False),
    ("f() { echo hi; }\nf", False),
    ("find . -name '*.tmp' -exec rm {} \\;", False),
    ("cat <<'EOF'\n$(cargo build)\nEOF", False),
    ("python3 -I - <<'PY'\nimport json\nprint(json.dumps(1))\nPY", False),
    ("echo x 2>&1 | tee out.log", False),
    ("sed -n 's/^a=//p' f", False),
    ("awk '{ print $1 }' f", False),
    ("psql -c 'select 1'", False),
    ("timeout 30 sleep 1", False),
    ("command -v jq", False),
    ("git -c user.name=x -C . log --oneline -1", False),
)

# Expression contexts in a run step (I-1): exact reason per unknown context.
EXPR_UNCLASSIFIABLE = (
    ("echo ${{ frob.x }}", "expression context 'frob' is not on the closed context list"),
    ("echo ${{ github.frob }}", "expression context 'github.frob' is not on the closed context list"),
    ("echo ${{ env.NOPE }}", "expression `env.NOPE` names no env value declared in the workflow"),
    ("${{ github.sha }} --run", "command word '${{ }}' is not a literal word"),
    # sibling: a quoted expression is a literal part of the word, still not a literal command word
    ("'${{ github.sha }}' --run", "command word '${{ }}' is not a literal word"),
)

# Job and step forms (I-1).
FORM_UNCLASSIFIABLE = (
    ("job key", _wf(CHECKOUT, job_extra="    frob: 1\n"), "job key 'frob' is not on the closed list"),
    ("step key", _wf(CHECKOUT + "      - run: echo x\n        frob: 1\n"), "step key 'frob' is not on the closed list"),
    ("empty shell", _wf(CHECKOUT + "      - run: echo x\n        shell: ''\n"), "`shell:` is empty"),
    ("pwsh", _wf(CHECKOUT + "      - run: echo x\n        shell: pwsh\n"), "shell 'pwsh' is not on the closed shell list"),
    ("windows default shell", _wf(CHECKOUT + "      - run: echo x\n", runs_on="windows-latest"),
     "the default shell of a Windows leg is pwsh, which is not on the closed shell list"),
    ("matrix axis expression",
     _wf(CHECKOUT, runs_on="${{ matrix.os }}",
         job_extra="    strategy:\n      matrix:\n        os: ${{ fromJSON(vars.OS) }}\n"
                   "        include:\n          - os: ubuntu-latest\n"),
     "matrix axis 'os' is an expression"),
    ("matrix include expression",
     _wf(CHECKOUT, runs_on="${{ matrix.os }}",
         job_extra="    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include: ${{ fromJSON(vars.I) }}\n"),
     "matrix include holds an expression"),
    ("matrix include scalar",
     _wf(CHECKOUT, runs_on="${{ matrix.os }}",
         job_extra="    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include: 5\n"),
     "matrix include is not a list of mappings"),
    ("matrix axis scalar",
     _wf(CHECKOUT, runs_on="${{ matrix.os }}", job_extra="    strategy:\n      matrix:\n        os: ubuntu-latest\n"),
     "matrix axis 'os' is not a list"),
)

# ---------------------------------------------------------------------------------------
# I-2 corpora: tree changes inside run steps, event text, per-step binding, early secrets.
# ---------------------------------------------------------------------------------------

TREE_CHANGE_RUNS = (
    ("pull_request_target", "git -C . fetch origin pull/1/head\ngit -C . checkout FETCH_HEAD"),
    ("push", "gh pr checkout 1"),
    ("pull_request_target", "git fetch origin x && git checkout FETCH_HEAD"),
    # sibling forms
    ("pull_request_target", "git switch -c x FETCH_HEAD"),
    ("pull_request_target", "git worktree add ../w FETCH_HEAD"),
    ("pull_request_target", "git reset --hard FETCH_HEAD"),
)

EVENT_TEXT_RUNS = (
    "echo \"${{ github.event.pull_request.title }}\"",
    "echo \"${{ github.head_ref }}\"",
    "echo '${{ toJSON(github.event) }}'",
    "echo ${{ github.event.pull_request.body }}",
)

UNBOUND_TEMP_RUNS = (
    ("cp scripts/x.py \"$RUNNER_TEMP/x.py\"\npython3 -I \"$RUNNER_TEMP/x.py\"", "$RUNNER_TEMP/x.py"),
    ("python3 -I \"$RUNNER_TEMP/../ws/x.py\"", "$RUNNER_TEMP/../ws/x.py"),
    ("git show HEAD:x.py > \"$RUNNER_TEMP/x.py\"\npython3 -I \"$RUNNER_TEMP/x.py\"", "$RUNNER_TEMP/x.py"),
    # siblings: a write after the bind unbinds; a `..` destination never binds
    ("git show \"$BASE:x.py\" > \"$RUNNER_TEMP/x.py\"\necho x >> \"$RUNNER_TEMP/x.py\"\n"
     "python3 -I \"$RUNNER_TEMP/x.py\"", "$RUNNER_TEMP/x.py"),
    ("git show \"$BASE:x.py\" > \"$RUNNER_TEMP/../x.py\"\npython3 -I \"$RUNNER_TEMP/../x.py\"",
     "$RUNNER_TEMP/../x.py"),
    ("git show \"$OTHER:x.py\" > \"$RUNNER_TEMP/x.py\"\npython3 -I \"$RUNNER_TEMP/x.py\"", "$RUNNER_TEMP/x.py"),
)
BASE_ENV = "          BASE: ${{ github.event.pull_request.base.sha }}\n          OTHER: ${{ github.sha }}\n"
BOUND_TEMP_RUNS = (
    "git show \"$BASE:x.py\" > \"$RUNNER_TEMP/x.py\"\npython3 -I \"$RUNNER_TEMP/x.py\"",
    "d=\"$RUNNER_TEMP/t\"\nmkdir -p \"$d\"\nfor f in a.py b.json; do\n  git show \"${BASE}:x/${f}\" > \"$d/$f\"\ndone\n"
    "python3 -I \"$d/a.py\" --rules \"$d/b.json\"",
    "ref=$(git merge-base HEAD \"$BASE\")\ngit show \"$ref:x.py\" > \"$RUNNER_TEMP/x.py\"\npython3 -I \"$RUNNER_TEMP/x.py\"",
)

EARLY_SECRET_STEPS = (
    ("secret into GITHUB_ENV",
     _run_step("Stash", "echo \"T=$T\" >> \"$GITHUB_ENV\"", "          T: ${{ secrets.X }}\n"), "Stash"),
    ("credential action",
     "      - name: Login\n        uses: docker/login-action@v3\n        with:\n"
     "          password: ${{ secrets.X }}\n", "Login"),
    # siblings
    ("secret into GITHUB_OUTPUT",
     _run_step("Out", "echo \"t=$T\" >> \"$GITHUB_OUTPUT\"", "          T: ${{ secrets.X }}\n"), "Out"),
    ("secret into a home file",
     _run_step("Home", "echo \"$T\" > ~/.token", "          T: ${{ secrets.X }}\n"), "Home"),
    ("token to a tool",
     _run_step("Query", "gh api repos/x/y > list.txt", "          GH_TOKEN: ${{ github.token }}\n"), "Query"),
)
EARLY_SECRET_DETAIL = "secret held before pull-request code ran can persist into it"
CONTAINER_DETAIL = "container or service holds a secret for a tainted job"
CONTAINER_FORMS = (
    "    container:\n      image: x\n      env:\n        T: ${{ secrets.X }}\n",
    "    services:\n      db:\n        image: x\n        env:\n          T: ${{ secrets.X }}\n",
    # siblings
    "    container:\n      image: x\n      credentials:\n        password: ${{ secrets.X }}\n",
    "    services:\n      db:\n        image: x\n        credentials:\n          password: ${{ secrets.X }}\n",
)


class ClosedCommandList(unittest.TestCase):
    """I-1: every command form is on a closed list or Unclassifiable with an exact reason."""

    def test_9452_unknown_shell_forms_are_unclassifiable_with_exact_reason(self) -> None:
        _need_module(self)
        for text, reason in SHELL_UNCLASSIFIABLE:
            with self.subTest(text=text):
                with self.assertRaises(tb.Unclassifiable) as ctx:
                    _classify(text)
                self.assertEqual(str(ctx.exception), reason)

    def test_9452_listed_forms_that_run_pr_code(self) -> None:
        _need_module(self)
        for text, expected in SHELL_PR_CODE + SHELL_INERT:
            with self.subTest(text=text):
                self.assertIs(_classify(text), expected)

    def test_9452_unknown_expression_context_is_a_finding(self) -> None:
        _need_module(self)
        for run, reason in EXPR_UNCLASSIFIABLE:
            with self.subTest(run=run):
                problems = _problems(_wf(CHECKOUT + _run_step("S", run)))
                self.assertIn(f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'S': {reason}", problems)

    def test_9452_unknown_job_and_step_forms_are_findings(self) -> None:
        _need_module(self)
        for name, text, reason in FORM_UNCLASSIFIABLE:
            with self.subTest(form=name):
                problems = _problems(text)
                hits = [p for p in problems if p.startswith(UNCLASSIFIABLE_PREFIX) and p.endswith(": " + reason)]
                self.assertEqual(len(hits), 1, problems)

    def test_9452_rust_cache_runs_pr_code(self) -> None:
        _need_module(self)
        text = _wf(CHECKOUT + "      - name: Cache\n        uses: Swatinem/rust-cache@v2\n" + SECRET_STEP)
        result = _scan(text)
        self.assertEqual(result.taint_steps[(SYNTH, JOB)], "Cache")

    def test_9452_unclassifiable_never_reads_clean(self) -> None:
        _need_module(self)
        result = _scan(_wf(CHECKOUT + _run_step("S", "unknowncmd")))
        self.assertEqual(result.verdicts[(SYNTH, JOB)], "unclassifiable")


class PerStepTaint(unittest.TestCase):
    """I-2: taint and base materialisation are per step and ordered; every carrier counts."""

    def test_9452_tree_change_in_a_run_step_taints(self) -> None:
        _need_module(self)
        for event, run in TREE_CHANGE_RUNS:
            with self.subTest(run=run):
                text = _wf(_run_step("Fetch", run) + _run_step("Build", "make") + SECRET_STEP, on=event)
                result = _scan(text)
                self.assertEqual(result.taint_steps.get((SYNTH, JOB)), "Build")
                self.assertIn("i", result.verdicts[(SYNTH, JOB)].split(","))

    def test_9452_event_text_in_a_run_step_is_the_taint_point(self) -> None:
        _need_module(self)
        for run in EVENT_TEXT_RUNS:
            with self.subTest(run=run):
                result = _scan(_wf(_run_step("Echo", run) + SECRET_STEP, on="pull_request_target"))
                self.assertEqual(result.taint_steps.get((SYNTH, JOB)), "Echo")
                self.assertEqual(result.verdicts[(SYNTH, JOB)], "i")

    def test_9452_unbound_runner_temp_path_is_not_trusted(self) -> None:
        _need_module(self)
        for run, path in UNBOUND_TEMP_RUNS:
            with self.subTest(run=run):
                problems = _problems(_wf(CHECKOUT + _run_step("S", run, BASE_ENV)))
                reason = f"interpreter path {path!r} is neither in the workspace nor bound to base content"
                self.assertIn(f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'S': {reason}", problems)

    def test_9452_bound_runner_temp_path_in_the_same_step_is_trusted(self) -> None:
        _need_module(self)
        for run in BOUND_TEMP_RUNS:
            with self.subTest(run=run):
                result = _scan(_wf(CHECKOUT + _run_step("S", run, BASE_ENV) + SECRET_STEP))
                self.assertEqual(_found(result), [])
                self.assertEqual(result.verdicts[(SYNTH, JOB)], "no-pr-code")

    def test_9452_a_bind_in_one_step_says_nothing_about_the_next(self) -> None:
        _need_module(self)
        bind = _run_step("Bind", "git show \"$BASE:x.py\" > \"$RUNNER_TEMP/x.py\"", BASE_ENV)
        use = _run_step("Use", "python3 -I \"$RUNNER_TEMP/x.py\"")
        problems = _problems(_wf(CHECKOUT + bind + use))
        reason = "interpreter path '$RUNNER_TEMP/x.py' is neither in the workspace nor bound to base content"
        self.assertIn(f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'Use': {reason}", problems)

    def test_9452_a_secret_held_before_the_taint_point_counts(self) -> None:
        _need_module(self)
        for name, step, label in EARLY_SECRET_STEPS:
            with self.subTest(form=name):
                result = _scan(_wf(step + CHECKOUT + _run_step("Build", "make")))
                got = {(v.step, v.klass, v.detail) for v in result.violations}
                self.assertIn((label, "i", EARLY_SECRET_DETAIL), got)

    def test_9452_container_and_service_secrets_count(self) -> None:
        _need_module(self)
        for extra in CONTAINER_FORMS:
            with self.subTest(form=extra):
                result = _scan(_wf(CHECKOUT + _run_step("Build", "make"), job_extra=extra))
                got = {(v.step, v.klass, v.detail) for v in result.violations}
                self.assertIn(("Build", "i", CONTAINER_DETAIL), got)

    def test_9452_leg_ii_write_all_after_pr_code(self) -> None:
        _need_module(self)
        result = _scan(_wf(CHECKOUT + _run_step("Build", "make"), perms="permissions: write-all\n"))
        got = {(v.step, v.klass) for v in result.violations}
        self.assertEqual(got, {("Build", "ii")})

    def test_9452_leg_iii_env_output_after_pr_code(self) -> None:
        _need_module(self)
        extra = "    outputs:\n      x: ${{ env.X }}\n"
        result = _scan(_wf(CHECKOUT + _run_step("Build", "make"), job_extra=extra))
        got = {(v.step, v.klass) for v in result.violations}
        self.assertEqual(got, {("Build", "iii")})

    def test_9452_leg_iii_reads_every_step_field(self) -> None:
        _need_module(self)
        for value in ("${{ steps.b.outcome }}", "${{ steps.b.conclusion }}", "${{ toJSON(steps) }}",
                      "${{ hashFiles('x') }}", "${{ job.status }}"):
            with self.subTest(value=value):
                extra = f"    outputs:\n      x: {value}\n"
                steps = CHECKOUT + "      - name: Build\n        id: b\n        run: make\n"
                result = _scan(_wf(steps, job_extra=extra))
                self.assertIn("iii", result.verdicts[(SYNTH, JOB)].split(","))


class OneRowOneStep(unittest.TestCase):
    """I-3: an allow row matches exactly one step of exactly one job."""

    def test_9452_duplicate_step_labels_are_a_finding(self) -> None:
        _need_module(self)
        for steps in (_run_step("Same", "echo a") + _run_step("Same", "echo b"),
                      "      - id: x\n        run: echo a\n      - name: id:x\n        run: echo b\n"):
            with self.subTest(steps=steps):
                problems = _problems(_wf(CHECKOUT + steps))
                self.assertTrue(any(p.startswith(UNCLASSIFIABLE_PREFIX) and "two steps share the label" in p
                                    for p in problems), problems)

    def test_9452_allow_row_issue_must_be_an_int_fix_issue(self) -> None:
        _need_module(self)
        result = _scan(_wf(CHECKOUT + _run_step("Build", "make") + SECRET_STEP))
        for issue in (True, 1, 0, None, "9455"):
            with self.subTest(issue=issue):
                row = tb.AllowRow(SYNTH, JOB, "Late secret", ("i",), issue)
                self.assertIn(f"allow row without an open fix issue: {SYNTH}/{JOB}/Late secret",
                              tb.check(result, allow=(row,), pin=1))
        self.assertEqual(tb.FIX_ISSUES, FIX_ISSUES)


def _refusal_of(func, *args) -> str:
    """The reason a scanner refuses this input with (the oracle of the reason cell)."""
    try:
        func(*args)
    except tb.Unclassifiable as exc:
        return str(exc)
    raise AssertionError(f"{func.__name__} did not refuse")


class LinearScanners(unittest.TestCase):
    """I-4: one 100K+ adversarial input per scanner under a named wall-clock ceiling."""

    def _timed(self, func, *args) -> str | None:
        """Run one scanner under the ceiling; its refusal reason (never empty), or None for a result."""
        start = time.monotonic()
        reason = None
        try:
            func(*args)
        except tb.Unclassifiable as exc:
            reason = str(exc)
            self.assertNotEqual(reason.strip(), "", f"{func.__name__} refused with no reason")
        self.assertLess(time.monotonic() - start, SCAN_CEILING_S)
        return reason

    def test_9452_timed_returns_the_refusal_reason_or_none(self) -> None:
        _need_module(self)
        self.assertIsNone(self._timed(len, "x"))
        self.assertEqual(self._timed(tb.parse_yaml, "a: {", "big"), _refusal_of(tb.parse_yaml, "a: {", "big"))

        def refuse_empty() -> None:
            raise tb.Unclassifiable(" ")

        with self.assertRaises(AssertionError) as caught:
            self._timed(refuse_empty)
        self.assertIn("refuse_empty refused with no reason", str(caught.exception))

    def test_9452_removed_patterns_and_globals_are_gone(self) -> None:
        _need_module(self)
        for name in REMOVED_NAMES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(tb, name), name)
        patterns = {name for name, value in vars(tb).items() if isinstance(value, re.Pattern)}
        self.assertEqual(patterns, REGEX_NAMES_EXPECTED)

    def test_9452_shell_scanners_under_ceiling(self) -> None:
        _need_module(self)
        n = ADVERSARIAL_BYTES
        inputs = (
            "git " + "--x " * (n // 4) + "z",
            "git " + "-c " * (n // 3) + "show",
            "echo " + "\"$(echo " * MAX_NESTING + "x" + ")\"" * MAX_NESTING + " a" * n,
            "sed '" + "s/a/b/;" * (n // 7) + "' f",
            "awk '" + "{ x = x \"a\" } " * (n // 14 + 1) + "' f",
            "echo " + "'a' \"b\" " * (n // 8),
            "case x in " + "a) echo ;; " * (n // 11) + "esac",
            "cat <<EOF\n" + "$x line\n" * (n // 8) + "EOF",
            "python3 -I -c '" + "x = 1\n" * (n // 6) + "'",
        )
        for text in inputs:
            with self.subTest(head=text[:24]):
                self.assertGreater(len(text), ADVERSARIAL_BYTES)
                self._timed(_classify, text)

    def test_9452_reason_class_scan_under_ceiling(self) -> None:
        _need_module(self)
        n = ADVERSARIAL_BYTES
        for reason in ("'" + "\\'" * (n // 2) + "'", '"' + "a" * n, "`" * (n + 1), "'a' " * (n // 4 + 1),
                       "command word " + "'" * n):
            with self.subTest(head=reason[:24]):
                self.assertGreater(len(reason), ADVERSARIAL_BYTES)
                start = time.monotonic()
                tb.form_class(reason)
                self.assertLess(time.monotonic() - start, SCAN_CEILING_S)

    def test_9452_host_credential_scan_under_ceiling(self) -> None:
        _need_module(self)
        n = ADVERSARIAL_BYTES
        for text in ("$HOME/." + "a" * n + " ", "sudo " + "-x " * (n // 3) + "-u nobody",
                     "psql" + " " * n + "-U x", "~/." + "a." * (n // 2)):
            with self.subTest(head=text[:24]):
                start = time.monotonic()
                tb._host_credential_in({"run": text})
                self.assertLess(time.monotonic() - start, SCAN_CEILING_S)

    def test_9452_expression_and_yaml_scanners_under_ceiling(self) -> None:
        _need_module(self)
        n = ADVERSARIAL_BYTES
        self._timed(tb._expression_contexts, "a." * (n // 2))
        self._timed(tb._expression_contexts, "toJSON(" * (n // 7))
        self._timed(tb.parse_yaml, "a: {" + "b " * n + "}", "big")
        self._timed(tb.parse_yaml, "a: {" + "'x' " * (n // 4) + ": 1}", "big")
        self._timed(_scan, _wf(CHECKOUT, runs_on="${{ matrix.x" + " " * n + "}}"))


class Bounded(unittest.TestCase):
    """I-5: escaped output and an exact reason for every refused input shape."""

    def test_9452_step_names_are_escaped_on_stdout(self) -> None:
        _need_module(self)
        name = "x\n::error::injected"
        text = _wf(CHECKOUT + f"      - name: \"x\\n::error::injected\"\n        run: make\n" + SECRET_STEP)
        result = _scan(text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            tb.emit(result, tb.check(result, allow=(), pin=0), verdicts=True)
        lines = out.getvalue().split("\n")
        self.assertFalse(any(line.startswith("::") for line in lines))
        self.assertTrue(any("x%0A::error::injected" in line for line in lines))
        self.assertNotIn(name, out.getvalue())

    def test_9452_deep_yaml_has_its_own_reason(self) -> None:
        _need_module(self)
        deep = "".join(" " * (2 * d) + f"k{d}:\n" for d in range(MAX_NESTING + 1)) + " " * (2 * (MAX_NESTING + 1)) + "v: 1\n"
        with self.assertRaises(tb.YamlError) as ctx:
            tb.parse_yaml(deep, "deep")
        self.assertTrue(str(ctx.exception).endswith(f"nesting deeper than {MAX_NESTING} levels"), str(ctx.exception))
        shallow = "".join(" " * (2 * d) + f"k{d}:\n" for d in range(8)) + " " * 16 + "v: 1\n"
        self.assertIsInstance(tb.parse_yaml(shallow, "shallow"), dict)

    def test_9452_refused_shapes_have_their_own_reason(self) -> None:
        _need_module(self)
        cases = (
            (_wf(CHECKOUT, on="{}"), f"{SYNTH}: `on:` names no trigger"),
            (_wf(CHECKOUT, perms="permissions:\n"), f"{SYNTH}/{JOB}: `permissions:` is null"),
            (_wf(CHECKOUT, on="workflow_call"), f"{SYNTH}: workflow_call-only workflow has no caller in this repository"),
        )
        for text, reason in cases:
            with self.subTest(reason=reason):
                self.assertIn(UNCLASSIFIABLE_PREFIX + reason, _problems(text))

    def test_9452_load_refusals_have_their_own_reason(self) -> None:
        _need_module(self)
        cases = (
            (_FakePath("a.yml", data=b"on: push\n"), None),
            (_FakePath("big.yml", size=MAX_YAML_BYTES + 1), f"larger than {MAX_YAML_BYTES} bytes"),
            (_FakePath("bad.yml", data=b"on: \xff\n"), "not UTF-8 (byte 4)"),
            (_FakePath("gone.yml", data=b"on: push\n", read_error=PermissionError(13, "denied")),
             "cannot be read as a regular file (PermissionError)"),
            (_FakePath("link.yml", link=True), "is a symbolic link"),
            (_FakePath("fifo.yml", regular=False), "is not a regular file"),
            (_FakePath("UP.YML", data=b"on: push\n"), "workflow suffix '.YML' is not on the closed suffix list"),
        )
        for path, reason in cases:
            with self.subTest(path=path.name):
                text = tb._load_one(path, workflow=True)
                if reason is None:
                    self.assertEqual(text, "on: push\n")
                    continue
                with self.assertRaises(tb.YamlError) as ctx:
                    tb.parse_yaml(text, path.name)
                self.assertEqual(str(ctx.exception), f"{path.name}: {reason}")

    def test_9452_missing_workflow_dir_is_a_finding(self) -> None:
        _need_module(self)
        result = tb.scan_texts(*tb._load_dir(None))
        self.assertIn(UNCLASSIFIABLE_PREFIX + ".github/workflows: no .github/workflows directory",
                      tb.check(result, allow=(), pin=0))


class _FakeStat:
    def __init__(self, size: int) -> None:
        self.st_size = size


class _FakePath:
    """A path double for the loader: no file is written."""

    def __init__(self, name: str, data: bytes = b"", size: int | None = None, link: bool = False,
                 regular: bool = True, read_error: OSError | None = None) -> None:
        self.name = name
        self._read_error = read_error
        self.suffix = name[name.rfind("."):] if "." in name else ""
        self._data = data
        self._size = len(data) if size is None else size
        self._link = link
        self._regular = regular
        self.reads = 0

    def is_symlink(self) -> bool:
        return self._link

    def is_file(self) -> bool:
        return self._regular

    def lstat(self) -> _FakeStat:
        return _FakeStat(self._size)

    def read_bytes_bounded(self, limit: int) -> bytes:
        self.reads += 1
        if self._read_error is not None:
            raise self._read_error
        return (self._data or b"x" * min(self._size, limit))[:limit]


# The files of this boundary whose except handlers the walk reads (the classifier and its cells).
HANDLER_FILES = ("taint_boundary.py",)
HANDLER_TEST_GLOB = "test_ci_tainted_*.py"
UNREAD_SHELL = (
    ("echo 'x", "unterminated single quote"),
    ("echo $(", "unterminated command substitution"),
    ("echo ${a", "unterminated parameter expansion"),
)
NON_STRICT_UNREAD = ("gh attestation verify x", "gh subcommand 'attestation' is not on the closed list")
UNCLOSED_ENTRY = ("a:\n  - 'x\n", "a quoted scalar that does not close: t: line 2: unterminated or multi-line quoted scalar")


def _swallowing_handlers(source: str) -> list[int]:
    """Lines of the except handlers that only drop the exception (pass, continue, break, a constant
    expression, return or assignment of a constant) or catch everything (bare, Exception)."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        only = body[0] if len(body) == 1 else None
        value = getattr(only, "value", None)
        if isinstance(only, (ast.Pass, ast.Continue, ast.Break)) \
                or (isinstance(only, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Return))
                    and (value is None or isinstance(value, ast.Constant))):
            lines.append(node.lineno)
        elif node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException")):
            lines.append(node.lineno)
    return lines


class HandlerReasons(unittest.TestCase):
    """M-5: every handler of the boundary names its exception and acts on the reason."""

    def test_9452_pre_scan_returns_the_unread_reason(self) -> None:
        _need_module(self)
        for text, reason in UNREAD_SHELL:
            with self.subTest(text=text):
                steps = [tb._Step("first", {"run": "echo ok"}, 0), tb._Step("second", {"run": text}, 1)]
                self.assertEqual(tb._pre_scan_fetch(steps, {}, {}),
                                 tb.PRE_SCAN_UNREAD_REASON.format(step="second", reason=reason))
                self.assertEqual(tb._pre_scan_fetch(steps, {}, {}),
                                 f"step 'second' cannot be read by the pre-scan: {reason}")

    def test_9452_pre_scan_returns_the_fetch_reason_or_none(self) -> None:
        _need_module(self)
        fetch = [tb._Step("get", {"run": "git fetch origin pull/1/head"}, 0)]
        self.assertEqual(tb._pre_scan_fetch(fetch, {}, {}), "step 'get' fetches a pull-request tree")
        self.assertIsNone(tb._pre_scan_fetch([tb._Step("ok", {"run": "echo ok"}, 0)], {}, {}))
        self.assertIsNone(tb._pre_scan_fetch([tb._Step("uses", {"uses": "./x"}, 0)], {}, {}))

    def test_9452_pre_scan_unread_job_is_analysed_in_full(self) -> None:
        _need_module(self)
        text = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - name: s\n        run: echo 'x\n"
        result = tb.scan_texts({SYNTH: text})
        self.assertNotEqual(result.verdicts.get((SYNTH, "j")), "trusted-only")

    def test_9452_non_strict_handler_records_the_reason(self) -> None:
        _need_module(self)
        text, reason = NON_STRICT_UNREAD
        ctx = tb._ShellCtx(strict=False)
        tb._shell_runs_pr_code(tb._joined(text, tb.MARK), ctx)
        self.assertEqual(ctx.unread, [reason])
        clean = tb._ShellCtx(strict=False)
        tb._shell_runs_pr_code(tb._joined("echo ok", tb.MARK), clean)
        self.assertEqual(clean.unread, [])

    def test_9452_unclosed_quoted_entry_raises_with_its_reason(self) -> None:
        _need_module(self)
        text, reason = UNCLOSED_ENTRY
        with self.assertRaises(tb.YamlError) as caught:
            tb.parse_yaml(text, "t")
        self.assertEqual(str(caught.exception), reason)
        self.assertIsInstance(caught.exception.__cause__, tb.YamlError)

    def test_9452_pyyaml_import_reason_is_kept(self) -> None:
        import test_ci_tainted_job_boundary as main_cells
        self.assertEqual(main_cells.pyyaml is None, main_cells.PYYAML_IMPORT_ERROR != "")

    def test_9452_no_handler_only_drops_its_exception(self) -> None:
        here = Path(__file__).resolve().parent
        files = [here.parent / name for name in HANDLER_FILES] + sorted(here.glob(HANDLER_TEST_GLOB))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            with self.subTest(file=path.name):
                self.assertEqual(_swallowing_handlers(path.read_text(encoding="utf-8")), [])

    def test_9452_handler_walk_finds_each_swallow(self) -> None:
        for body in ("pass", "continue", "break", "None", "'x'", "return", "return False", "return 0",
                     "found = None", "found: int = 0"):
            with self.subTest(body=body):
                source = ("def f():\n    for _ in ():\n        try:\n            g()\n"
                          f"        except ValueError:\n            {body}\n")
                self.assertEqual(_swallowing_handlers(source), [5])
        for head in ("except:", "except Exception as exc:", "except BaseException as exc:"):
            with self.subTest(head=head):
                self.assertEqual(_swallowing_handlers(f"try:\n    g()\n{head}\n    raise\n"), [3])
        for body in ("return str(exc)", "raise", "found.append(str(exc))", "found.append(exc)\n        return False"):
            with self.subTest(kept=body):
                source = f"def f():\n    try:\n        g()\n    except ValueError as exc:\n        {body}\n"
                self.assertEqual(_swallowing_handlers(source), [])


class HostedGuard(unittest.TestCase):
    """I-6: this file runs in an existing hosted job, and that step holds the boundary."""

    def test_9452_boundary_test_runs_in_a_hosted_pr_job(self) -> None:
        _need_module(self)
        workflows, actions, files = tb.load_repo(REPO_ROOT)
        doc = tb.parse_yaml(workflows[HOST_WORKFLOW], HOST_WORKFLOW)
        self.assertIn("pull_request", doc["on"])
        job = doc["jobs"][HOST_JOB]
        self.assertEqual(job["runs-on"], HOSTED_LABEL)
        steps = [s for s in job["steps"] if s.get("name") == HOST_STEP]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["run"].strip(), HOST_COMMAND)
        self.assertTrue(Path(__file__).name.startswith("test"))
        self.assertEqual(Path(__file__).parent, REPO_ROOT / "scripts" / "ci" / "tests")
        # The step itself is a listed form: it runs pull-request code and raises no finding.
        self.assertIs(tb._shell_runs_pr_code(HOST_COMMAND), True)
        result = tb.scan_texts(workflows, actions, files)
        host_prefix = f"{HOST_WORKFLOW}/{HOST_JOB}: step {HOST_STEP!r}"
        self.assertEqual([u for u in _found(result) if u.startswith(host_prefix)], [])
        self.assertEqual([v for v in result.violations if (v.workflow, v.job, v.step) == (HOST_WORKFLOW, HOST_JOB, HOST_STEP)],
                         [])


# I-1 list entry GITHUB_ACTION_PATH: inside a local composite action it names that action's
# workspace directory, and `..` resolves inside the workspace only, never above its root.
ACTION_DIR = ".github/actions/a"
ACTION_STEP = "Outer"


def _composite(run: str) -> dict[str, str]:
    body = "".join(f"        {line}\n" for line in run.split("\n"))
    return {ACTION_DIR: "runs:\n  using: composite\n  steps:\n    - name: Inner\n      shell: bash\n"
                        f"      run: |\n{body}"}


def _composite_scan(run: str) -> object:
    steps = CHECKOUT + f"      - name: {ACTION_STEP}\n        uses: ./{ACTION_DIR}\n" + SECRET_STEP
    return tb.scan_texts({SYNTH: _wf(steps)}, _composite(run), frozenset())


ACTION_PATH_PR_CODE = (
    'python3 -I "${GITHUB_ACTION_PATH}/../../../scripts/x.py"',
    'python3 -I "$GITHUB_ACTION_PATH/tool.py"',
    'python3 -I "${GITHUB_ACTION_PATH}/./../a/tool.py"',
)
# (run text, the exact interpreter path in the reason)
ACTION_PATH_UNKNOWN = (
    ('python3 -I "${GITHUB_ACTION_PATH}/../../../../x.py"', "${GITHUB_ACTION_PATH}/../../../../x.py"),
    ('GITHUB_ACTION_PATH=/opt\npython3 -I "${GITHUB_ACTION_PATH}/x.py"', "${GITHUB_ACTION_PATH}/x.py"),
    ('python3 -I "${GITHUB_ACTION_PATH:-/opt}/x.py"', "${GITHUB_ACTION_PATH:-/opt}/x.py"),
    ('python3 -I "$RUNNER_TEMP/../x.py"', "$RUNNER_TEMP/../x.py"),
    ('python3 -I "$GITHUB_WORKSPACE/../x.py"', "$GITHUB_WORKSPACE/../x.py"),
)


class ListEntryActionPath(unittest.TestCase):
    """GITHUB_ACTION_PATH has one meaning (I-1); every other form of it is Unclassifiable."""

    def test_9452_action_path_in_a_local_composite_is_pull_request_code(self) -> None:
        _need_module(self)
        for run in ACTION_PATH_PR_CODE:
            with self.subTest(run=run):
                result = _composite_scan(run)
                self.assertEqual(_found(result), [])
                # The taint point is the outer step that calls the action.
                self.assertEqual(result.taint_steps[(SYNTH, JOB)], ACTION_STEP)
                self.assertEqual(result.verdicts[(SYNTH, JOB)], "i")

    def test_9452_action_path_outside_the_workspace_or_redefined_is_unclassifiable(self) -> None:
        _need_module(self)
        for run, path in ACTION_PATH_UNKNOWN:
            with self.subTest(run=run):
                result = _composite_scan(run)
                reason = f"interpreter path {path!r} is neither in the workspace nor bound to base content"
                self.assertEqual(_found(result), [f"{SYNTH}/{JOB}: step '{ACTION_STEP} > Inner': {reason}"])

    def test_9452_action_path_outside_a_composite_has_no_meaning(self) -> None:
        _need_module(self)
        run = 'python3 -I "${GITHUB_ACTION_PATH}/tool.py"'
        reason = "interpreter path '${GITHUB_ACTION_PATH}/tool.py' is neither in the workspace nor bound to base content"
        self.assertIn(f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'S': {reason}",
                      _problems(_wf(CHECKOUT + _run_step("S", run))))

    def test_9452_step_env_redefining_action_path_shadows_it(self) -> None:
        _need_module(self)
        ctx = tb._ShellCtx(True, shadowed=frozenset({"GITHUB_ACTION_PATH"}), action_dir=f"{tb.WS}/{ACTION_DIR}")
        with self.assertRaises(tb.Unclassifiable) as caught:
            tb._shell_runs_pr_code('python3 -I "${GITHUB_ACTION_PATH}/tool.py"', ctx)
        self.assertEqual(str(caught.exception), "interpreter path '${GITHUB_ACTION_PATH}/tool.py' is neither "
                                                "in the workspace nor bound to base content")
        self.assertIn("GITHUB_ACTION_PATH", tb.SCANNER_NAMES)


# psql getopt bundles (I-1 argument grammar): listed one-letter flags, then at most one
# letter that takes an argument. (text, runs pull-request code or the exact reason)
PSQL_BUNDLES = (
    ("psql -tAc 'SELECT 1'", False),
    ("psql -tAcSELECT", False),
    ("psql -qtAf x.sql", True),
    ("psql -tAo out.txt -c 'SELECT 1'", False),
    ("psql -tAo '|sh' -c 'SELECT 1'", "psql option '-o' runs a command"),
    ("psql -tAc 'COPY t TO PROGRAM x'", "psql SQL text runs a program"),
    ("psql -tAc '\\! id'", "psql meta-command in SQL text"),
    ("psql -tAY", "psql option '-tAY' is not on the closed option list"),
    ("psql -cSELECT", "psql option '-cSELECT' is not on the closed option list"),
    # an expansion is a positional argument only when the whole word is double-quoted
    ('psql "$URL" -v ON_ERROR_STOP=1 -c "SELECT 1"', False),
    ('psql $FLAGS -c "SELECT 1"', "psql word '$FLAGS' is an unquoted expansion in an option position"),
    ('psql "$A"$B -c "SELECT 1"', "psql word '$A$B' is an unquoted expansion in an option position"),
)


class ListEntryPsqlBundle(unittest.TestCase):
    def test_9452_psql_option_bundles(self) -> None:
        _need_module(self)
        for text, expected in PSQL_BUNDLES:
            with self.subTest(text=text):
                if isinstance(expected, str):
                    with self.assertRaises(tb.Unclassifiable) as caught:
                        _classify(text)
                    self.assertEqual(str(caught.exception), expected)
                else:
                    self.assertIs(_classify(text), expected)


class RowOfAnUnclassifiableJob(unittest.TestCase):
    """A row of an unclassifiable job is never reported stale: its verdict is unknown."""

    def test_9452_row_of_an_unclassifiable_job_is_not_called_stale(self) -> None:
        _need_module(self)
        result = _scan(_wf(CHECKOUT + _run_step("S", "unknowncmd") + SECRET_STEP))
        row = tb.AllowRow(SYNTH, JOB, "Late secret", ("i",), 9455)
        problems = tb.check(result, allow=(row,), pin=1)
        self.assertEqual(problems, [f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'S': "
                                    "command word 'unknowncmd' is not on the closed command list"])
        clean = _scan(_wf(CHECKOUT + _run_step("S", "echo hi")))
        self.assertEqual(tb.check(clean, allow=(row,), pin=1),
                         [f"stale allow row (no longer violates class i): {SYNTH}/{JOB}/Late secret"])


# Cells named by the r1fix mutation run: each pins one guard that a broken copy left green.
NESTED_ACTION_DIR = ".github/actions/a/b"
BASE_REF_ENV = "          BASE: ${{ github.event.pull_request.base.sha }}\n"
BASE_COPY_RUN = 'git show "{ref}:x.py" > "$RUNNER_TEMP/x.py"\npython3 -I "$RUNNER_TEMP/x.py"'
NESTING_FORMS = (
    ("subshell", lambda d: "( " * d + "echo x" + " )" * d),
    ("if", lambda d: "if true; then " * d + "echo x; " + "fi; " * (d - 1) + "fi"),
    ("brace group", lambda d: "{ " * d + "echo x; " + "}; " * (d - 1) + "}"),
)


class MutationPinnedGuards(unittest.TestCase):
    def test_9452_shell_nesting_has_its_own_reason(self) -> None:
        _need_module(self)
        for name, build in NESTING_FORMS:
            with self.subTest(form=name):
                self.assertIs(_classify(build(MAX_NESTING)), False)
                with self.assertRaises(tb.Unclassifiable) as caught:
                    _classify(build(MAX_NESTING + 1))
                self.assertEqual(str(caught.exception), f"shell nesting deeper than {MAX_NESTING} levels")

    def test_9452_action_path_names_the_innermost_composite(self) -> None:
        _need_module(self)
        # From .github/actions/a/b four `..` reach the workspace root; from .github/actions/a they would not.
        inner_run = 'python3 -I "${GITHUB_ACTION_PATH}/../../../../x.py"'
        actions = {
            ACTION_DIR: f"runs:\n  using: composite\n  steps:\n    - name: Mid\n      uses: ./{NESTED_ACTION_DIR}\n",
            NESTED_ACTION_DIR: "runs:\n  using: composite\n  steps:\n    - name: Inner\n      shell: bash\n"
                               f"      run: {inner_run}\n",
        }
        steps = CHECKOUT + f"      - name: {ACTION_STEP}\n        uses: ./{ACTION_DIR}\n" + SECRET_STEP
        result = tb.scan_texts({SYNTH: _wf(steps)}, actions, frozenset())
        self.assertEqual(_found(result), [])
        self.assertEqual(result.verdicts[(SYNTH, JOB)], "i")

    def test_9452_a_base_ref_that_can_be_empty_binds_only_with_a_guard(self) -> None:
        _need_module(self)
        # Under push the pull-request base sha is empty and `git show ":x.py"` reads the index.
        bare = _run_step("S", BASE_COPY_RUN.format(ref="$BASE"), BASE_REF_ENV) + SECRET_STEP
        reason = "interpreter path '$RUNNER_TEMP/x.py' is neither in the workspace nor bound to base content"
        self.assertIn(f"{UNCLASSIFIABLE_PREFIX}{SYNTH}/{JOB}: step 'S': {reason}",
                      _problems(_wf(CHECKOUT + bare, on="[pull_request, push]")))
        for on, ref in (("pull_request", "$BASE"), ("[pull_request, push]", "${BASE:?}")):
            with self.subTest(on=on, ref=ref):
                steps = CHECKOUT + _run_step("S", BASE_COPY_RUN.format(ref=ref), BASE_REF_ENV) + SECRET_STEP
                result = _scan(_wf(steps, on=on))
                self.assertEqual(_found(result), [])
                self.assertEqual(result.verdicts[(SYNTH, JOB)], "no-pr-code")

    def test_9452_oversized_file_is_refused_before_any_read(self) -> None:
        _need_module(self)
        big = _FakePath("big.yml", size=MAX_YAML_BYTES + 1)
        with self.assertRaises(tb.YamlError) as ctx:
            tb.parse_yaml(tb._load_one(big, workflow=True), big.name)
        self.assertEqual(str(ctx.exception), f"big.yml: larger than {MAX_YAML_BYTES} bytes")
        self.assertEqual(big.reads, 0)

    def test_9452_a_bool_is_never_an_issue_number(self) -> None:
        _need_module(self)
        result = _scan(_wf(CHECKOUT + _run_step("Build", "make") + SECRET_STEP))
        stale = f"allow row without an open fix issue: {SYNTH}/{JOB}/Late secret"
        with unittest.mock.patch.object(tb, "FIX_ISSUES", FIX_ISSUES | {1}):
            self.assertIn(stale, tb.check(result, allow=(tb.AllowRow(SYNTH, JOB, "Late secret", ("i",), True),), pin=1))
            self.assertNotIn(stale, tb.check(result, allow=(tb.AllowRow(SYNTH, JOB, "Late secret", ("i",), 1),), pin=1))


if __name__ == "__main__":
    unittest.main()
