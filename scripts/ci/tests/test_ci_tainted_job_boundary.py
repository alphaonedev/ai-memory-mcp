"""Structural test of the tainted-job boundary for every workflow (umbrella #9452).

Invariant: after the first step of a job that runs pull-request code, no step of that job
holds (i) a secret, (ii) a write token, (iii) an output that feeds a gate decision, or
(iv) persistent state a trusted run later reads. A workflow or a job the classifier cannot
classify is a failure. Known violations need an allow row naming the open fix issue; the
row count is pinned and a stale row is a failure. The (iv) rule reads the OS boundary facts
of issue #9455 and never a path layout (3-agent vote (71472661), condition T-4).

Every cell works on in-memory text: the real workflows are read once from the checkout and
synthetic workflows are named constants below. No file is written.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "ci"))
try:
    import taint_boundary as tb
except ImportError as _import_error:  # red at the base: every cell fails on its own
    tb = None
    IMPORT_ERROR = repr(_import_error)
else:
    IMPORT_ERROR = ""

try:
    import yaml as pyyaml  # parity oracle only; the classifier never imports it
except ImportError:
    pyyaml = None

ALLOW_PIN_EXPECTED = 6
JOB_COUNT_LARGE = 200
LARGE_SCAN_CEILING_S = 10.0
RUN_TEXT_BYTES_LARGE = 120_000
RUN_TEXT_CEILING_S = 5.0
FIX_ISSUES = frozenset({9454, 9455, 9456})
PERSISTENT_LABEL = "linux-fed"
SYNTH = "synthetic.yml"

# ---------------------------------------------------------------------------------------
# Synthetic corpus: one job per class and per clean form.
# ---------------------------------------------------------------------------------------

HEADER = """\
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
"""

JOB_CLASS_I = """\
  class-i:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
      - name: Use token
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh api repos/x/y
"""

JOB_CLASS_II = """\
  class-ii:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Test
        run: make test
"""

JOB_CLASS_III = """\
  class-iii:
    runs-on: ubuntu-24.04
    outputs:
      picked: ${{ steps.pick.outputs.value }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Pick
        id: pick
        run: scripts/pick.sh >> "$GITHUB_OUTPUT"
"""

JOB_CLASS_IV = """\
  class-iv:
    runs-on: [self-hosted, linux-fed]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo test --no-run
"""

JOB_CLEAN_SECRET_BEFORE = """\
  clean-secret-before:
    runs-on: ubuntu-24.04
    steps:
      - name: Query with token
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh api repos/x/y > list.txt
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
"""

JOB_CLEAN_OUTPUT_BEFORE = """\
  clean-output-before:
    runs-on: ubuntu-24.04
    outputs:
      files: ${{ steps.list.outputs.files }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 2
      - name: List
        id: list
        run: |
          files="$(git diff --name-only HEAD~1 | wc -l)"
          echo "files=$files" >> "$GITHUB_OUTPUT"
      - name: Build
        run: cargo build
"""

JOB_CLEAN_BASE_TREE = """\
  clean-base-tree:
    runs-on: [self-hosted, linux-fed]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Materialise the base tool
        run: |
          base_dir="$RUNNER_TEMP/base"
          mkdir -p "$base_dir"
          git show "origin/main:scripts/tool.py" > "$base_dir/tool.py"
          python3 -I "$base_dir/tool.py" --data .
"""

JOB_CLEAN_TRUSTED_ONLY = """\
  clean-trusted-only:
    if: github.event_name == 'push'
    runs-on: [self-hosted, linux-fed]
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: Release
        env:
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
        run: cargo publish
"""

JOB_CLEAN_GITHUB_HOSTED = """\
  clean-hosted:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build --release
      - name: Path
        run: echo "$PWD/target/release" >> "$GITHUB_PATH"
"""

SYNTH_WORKFLOW = HEADER + "".join((
    JOB_CLASS_I, JOB_CLASS_II, JOB_CLASS_III, JOB_CLASS_IV, JOB_CLEAN_SECRET_BEFORE,
    JOB_CLEAN_OUTPUT_BEFORE, JOB_CLEAN_BASE_TREE, JOB_CLEAN_TRUSTED_ONLY, JOB_CLEAN_GITHUB_HOSTED,
))

SYNTH_VERDICTS = {
    "class-i": "i",
    "class-ii": "ii",
    "class-iii": "iii",
    "class-iv": "iv",
    "clean-secret-before": "clean",
    "clean-output-before": "clean",
    "clean-base-tree": "no-pr-code",
    "clean-trusted-only": "trusted-only",
    "clean-hosted": "clean",
}

SYNTH_VIOLATIONS = {
    ("class-i", "Use token", "i"),
    ("class-ii", "Test", "ii"),
    ("class-iii", "Pick", "iii"),
    ("class-iv", "Build", "iv"),
}

WF_LEAKY_CHECKOUT = HEADER + """\
  leaky:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build
        run: cargo build
"""

WF_PR_TARGET_BASE = """\
on: pull_request_target
permissions:
  contents: read
jobs:
  compare:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          persist-credentials: false
      - name: Compare
        run: python3 -I scripts/compare.py
"""

WF_PR_TARGET_HEAD = """\
on: pull_request_target
permissions:
  contents: read
jobs:
  compare:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - name: Compare
        run: python3 scripts/compare.py
      - name: Comment
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: out.md
"""

WF_UNPARSABLE = HEADER + """\
  anchors:
    runs-on: &runner ubuntu-24.04
    steps:
      - run: echo hi
"""

WF_NO_RUNS_ON = HEADER + """\
  floating:
    steps:
      - run: echo hi
"""

WF_NO_PERMISSIONS = """\
on: pull_request
jobs:
  open:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: cargo build
"""

WF_UNKNOWN_ACTION = HEADER + """\
  mystery:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Mystery
        uses: someone/unknown-action@v1
"""

WF_UNKNOWN_EVENT = """\
on: issue_comment
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
"""

WF_COMPOSITE = HEADER + """\
  composite:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Local tool
        uses: ./.github/actions/tool
"""

ACTION_TOOL = """\
name: tool
runs:
  using: composite
  steps:
    - name: Inner
      shell: bash
      run: echo inner
    - name: Comment
      uses: marocchino/sticky-pull-request-comment@v2
      with:
        path: out.md
"""

ACTION_LOOP_A = """\
runs:
  using: composite
  steps:
    - uses: ./.github/actions/loop-b
"""

ACTION_LOOP_B = """\
runs:
  using: composite
  steps:
    - uses: ./.github/actions/loop-a
"""

WF_COMPOSITE_LOOP = HEADER + """\
  loop:
    runs-on: ubuntu-24.04
    steps:
      - uses: ./.github/actions/loop-a
"""

WF_CALLER = HEADER + """\
  call:
    uses: ./.github/workflows/inner.yml
"""

WF_INNER = """\
on: workflow_call
permissions:
  contents: read
jobs:
  inner-job:
    runs-on: [self-hosted, linux-fed]
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Inner build
        run: cargo build
"""

WF_MATRIX = HEADER + """\
  matrix:
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
        include:
          - os: linux-fed
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: cargo build
"""

BOUNDARY_PROOF = "scripts/ci/tests/test_runner_boundary_9455.py"
BOUNDARY_FACTS_FULL = {
    "pr_tier_user": "ci-pr",
    "trusted_user": "ci-trusted",
    "trusted_root_unwritable": True,
    "trusted_cargo_home_unwritable": True,
    "trusted_rustup_toolchains_unwritable": True,
    "trusted_path_entries_unwritable": True,
    "trusted_home_credentials_unreadable": True,
    "proof_test": BOUNDARY_PROOF,
}

# Shell text -> runs pull-request code (fail closed on everything unknown).
SHELL_CASES = (
    ("echo hi && grep -c x file | wc -l", False),
    ("git diff --name-only HEAD~1 > changed.txt", False),
    ("cargo build", True),
    ("scripts/ci-test-impact.sh a b", True),
    ("./run.sh", True),
    ("bash scripts/check.sh", True),
    ("bash -c 'echo hi'", False),
    ("bash -c 'make all'", True),
    ("source scripts/lib.sh", True),
    (". scripts/lib.sh", True),
    ("eval \"$cmd\"", True),
    ("$TOOL --flag", True),
    ("python3 scripts/x.py", True),
    ("python3 -I scripts/x.py", True),
    ("python3 -m pip install pytest", True),
    ("python3 -I -m json.tool f.json", False),
    ("python3 -c 'print(1)'", True),
    ("python3 -I -c 'print(1)'", False),
    ("python3 --version", False),
    ("node --version", False),
    ("npm ci", True),
    ("unknowncmd --x", True),
    ("x=$(cargo metadata)", True),
    ("echo \"$(make -s version)\"", True),
    ("echo `npm bin`", True),
    ("for f in a b; do echo \"$f\"; done", False),
    ("case \"$x\" in a|b) echo y ;; *) echo n ;; esac", False),
    ("case \"$x\" in a|b) make ;; esac", True),
    ("if [[ -n \"$x\" && -f y ]]; then echo ok; fi", False),
    ("(( n += 1 ))", False),
    ("f() { echo hi; }\nf", False),
    ("sudo -u nobody cargo build", True),
    ("timeout 30 cargo test", True),
    ("env A=1 make", True),
    ("find . -name '*.rs' -exec rustfmt {} \\;", True),
    ("find . -name '*.tmp' -exec rm {} \\;", False),
    ("awk -f scripts/x.awk file", True),
    ("docker build -t x .", True),
    ("docker run --rm img true", False),
    ("cat <<'EOF'\n$(cargo build)\nEOF", False),
    ("cat <<EOF\n$(cargo build)\nEOF", True),
    ("python3 - <<'PY'\nprint(1)\nPY", True),
    ("python3 -I - <<'PY'\nprint(1)\nPY", False),
    ("echo x 2>&1 | tee out.log", False),
    ("echo GHA_EXPR", False),
    ("GHA_EXPR --run", True),
)


def _need_module(case: unittest.TestCase) -> None:
    if tb is None:
        case.fail(f"classifier module scripts/ci/taint_boundary.py is missing: {IMPORT_ERROR}")


def _scan(workflows: dict[str, str], actions: dict[str, str] | None = None,
          repo_files: frozenset[str] = frozenset()) -> "tb.ScanResult":
    return tb.scan_texts(workflows, actions or {}, repo_files)


_REAL: dict[str, object] = {}


def _real() -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    if "repo" not in _REAL:
        _REAL["repo"] = tb.load_repo(REPO_ROOT)
    return _REAL["repo"]  # type: ignore[return-value]


def _real_job(workflow: str, job: str) -> dict[str, object]:
    workflows, _, _ = _real()
    doc = tb.parse_yaml(workflows[workflow], workflow)
    return doc["jobs"][job]


def _real_step(workflow: str, job: str, label: str) -> dict[str, object]:
    steps = _real_job(workflow, job)["steps"]
    for pos, step in enumerate(steps):
        if tb._step_label(step, pos) == label:
            return step
    raise AssertionError(f"{workflow}/{job}: no step labelled {label!r}")


class SyntheticCorpusVerdicts(unittest.TestCase):
    """One job per class and per clean form gets its exact verdict and violation."""

    def test_9452_each_synthetic_job_gets_its_exact_verdict(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: SYNTH_WORKFLOW})
        self.assertEqual(result.unclassifiable, [])
        got = {job: verdict for (wf, job), verdict in result.verdicts.items() if wf == SYNTH}
        self.assertEqual(got, SYNTH_VERDICTS)

    def test_9452_each_synthetic_violation_names_job_step_and_class(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: SYNTH_WORKFLOW})
        got = {(v.job, v.step, v.klass) for v in result.violations}
        self.assertEqual(got, SYNTH_VIOLATIONS)

    def test_9452_checkout_keeping_the_token_before_pr_code_is_class_i(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_LEAKY_CHECKOUT})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Checkout", "i")})

    def test_9452_pull_request_target_base_checkout_runs_no_pr_code(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_PR_TARGET_BASE})
        self.assertEqual(result.verdicts[(SYNTH, "compare")], "no-pr-code")
        self.assertEqual(result.violations, [])

    def test_9452_pull_request_target_head_checkout_is_tainted(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_PR_TARGET_HEAD})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Comment", "i")})
        self.assertEqual(result.taint_steps[(SYNTH, "compare")], "Compare")

    def test_9452_matrix_leg_on_a_persistent_runner_is_class_iv(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_MATRIX})
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Build", "iv")})


class FailClosed(unittest.TestCase):
    """An unparsable workflow, an unclassifiable job or an unknown action is a failure."""

    def assert_unclassifiable(self, text: str, needle: str) -> None:
        result = _scan({SYNTH: text})
        problems = tb.check(result, allow=(), pin=0)
        self.assertTrue(any(p.startswith("unclassifiable:") and needle in p for p in problems), problems)

    def test_9452_unparsable_workflow_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNPARSABLE, "outside the subset")

    def test_9452_job_without_runs_on_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_NO_RUNS_ON, "job without runs-on")

    def test_9452_job_without_permissions_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_NO_PERMISSIONS, "no `permissions:`")

    def test_9452_unknown_action_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNKNOWN_ACTION, "unknown action 'someone/unknown-action'")

    def test_9452_unknown_trigger_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_UNKNOWN_EVENT, "unknown trigger")

    def test_9452_missing_local_action_is_a_failure(self) -> None:
        _need_module(self)
        self.assert_unclassifiable(WF_COMPOSITE, "local action ./.github/actions/tool not found")

    def test_9452_composite_action_cycle_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_COMPOSITE_LOOP},
                       {".github/actions/loop-a": ACTION_LOOP_A, ".github/actions/loop-b": ACTION_LOOP_B})
        self.assertTrue(any("composite action cycle" in m for m in result.unclassifiable), result.unclassifiable)

    def test_9452_yaml_subset_refuses_each_unsupported_form(self) -> None:
        _need_module(self)
        refused = {
            "anchor": "a: &x 1\n",
            "alias": "a: *x\n",
            "tag": "a: !!str 1\n",
            "merge key": "<<: {a: 1}\n",
            "complex key": "? a\n: b\n",
            "duplicate key": "a: 1\na: 2\n",
            "tab indent": "a:\n\tb: 1\n",
            "multi-line plain": "a: one\n  two\n",
            "multi-line quoted": "a: \"one\n  two\"\n",
            "nested flow": "a: [[1]]\n",
            "second document": "a: 1\n---\nb: 2\n",
            "inline mapping": "a: b: c\n",
        }
        for label, text in refused.items():
            with self.subTest(form=label):
                with self.assertRaises(tb.YamlError):
                    tb.parse_yaml(text, label)

    def test_9452_yaml_subset_parses_each_supported_form(self) -> None:
        _need_module(self)
        text = (
            "on: [push, pull_request]\n"
            "a: {x: 1, 'y': \"two\"}\n"
            "b: |\n  line1\n  line2\n"
            "c: >-\n  folded\n  text\n\n  para\n"
            "d: 'it''s' # comment\n"
            "e: \"tab\\there\"\n"
            "f: {}\n"
            "g:\n- k: 1\n  m: [a, b]\n- plain\n"
            "h: 010\n"
        )
        self.assertEqual(tb.parse_yaml(text, "forms"), {
            "on": ["push", "pull_request"],
            "a": {"x": 1, "y": "two"},
            "b": "line1\nline2\n",
            "c": "folded text\npara",
            "d": "it's",
            "e": "tab\there",
            "f": {},
            "g": [{"k": 1, "m": ["a", "b"]}, "plain"],
            "h": "010",
        })


class Indirection(unittest.TestCase):
    """Composite actions and reusable workflows under `uses: ./` are followed, not skipped."""

    def test_9452_composite_action_steps_are_followed(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_COMPOSITE}, {".github/actions/tool": ACTION_TOOL})
        self.assertEqual(result.taint_steps[(SYNTH, "composite")], "Local tool")
        self.assertEqual({(v.step, v.klass) for v in result.violations}, {("Local tool > Comment", "i")})

    def test_9452_reusable_workflow_jobs_are_followed(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: WF_CALLER, "inner.yml": WF_INNER})
        got = {(v.workflow, v.job, v.step, v.klass) for v in result.violations}
        self.assertIn((SYNTH, "call > inner-job", "Inner build", "iv"), got)

    def test_9452_reusable_workflow_outside_the_repository_is_a_failure(self) -> None:
        _need_module(self)
        text = HEADER + "  call:\n    uses: other/repo/.github/workflows/x.yml@v1\n"
        result = _scan({SYNTH: text})
        self.assertTrue(any("not found in this repository" in m for m in result.unclassifiable))


class AllowTable(unittest.TestCase):
    """Rows need an open issue, a stale row fails, the count is pinned."""

    ROW = None

    def rows(self) -> tuple:
        return (tb.AllowRow(SYNTH, "class-iv", "Build", ("iv",), 9455),)

    def test_9452_allowed_violation_passes_and_unallowed_fails(self) -> None:
        _need_module(self)
        text = HEADER + JOB_CLASS_IV
        result = _scan({SYNTH: text})
        self.assertEqual(tb.check(result, allow=self.rows(), pin=1), [])
        problems = tb.check(result, allow=(), pin=0)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("violation class (iv) without an allow row: synthetic.yml/class-iv/Build"))

    def test_9452_row_without_issue_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLASS_IV})
        rows = (tb.AllowRow(SYNTH, "class-iv", "Build", ("iv",), None),)
        self.assertEqual(tb.check(result, allow=rows, pin=1),
                         ["allow row without an open issue: synthetic.yml/class-iv/Build"])

    def test_9452_stale_row_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLEAN_GITHUB_HOSTED})
        rows = (tb.AllowRow(SYNTH, "clean-hosted", "Build", ("iv",), 9455),)
        self.assertEqual(tb.check(result, allow=rows, pin=1),
                         ["stale allow row (no longer violates class iv): synthetic.yml/clean-hosted/Build"])

    def test_9452_row_count_differs_from_pin_is_a_failure(self) -> None:
        _need_module(self)
        result = _scan({SYNTH: HEADER + JOB_CLASS_IV})
        self.assertEqual(tb.check(result, allow=self.rows(), pin=2), ["allow table has 1 rows, pin is 2"])

    def test_9452_real_allow_table_is_pinned_and_names_fix_issues(self) -> None:
        _need_module(self)
        self.assertEqual(tb.TAINT_ALLOW_PIN, ALLOW_PIN_EXPECTED)
        self.assertEqual(len(tb.TAINT_ALLOW), ALLOW_PIN_EXPECTED)
        self.assertEqual({row.issue for row in tb.TAINT_ALLOW}, FIX_ISSUES)

    def test_9452_new_workflow_with_a_violating_job_and_no_row_fails(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        extended = dict(workflows, **{"new-workflow.yml": HEADER + JOB_CLASS_II})
        problems = tb.check(tb.scan_texts(extended, actions, files))
        self.assertEqual(problems, [
            "violation class (ii) without an allow row: new-workflow.yml/class-ii/Test: job token has a write scope",
        ])


class PersistentRunnerBoundary(unittest.TestCase):
    """The (iv) rule reads the OS boundary facts of #9455, never a path split (vote T-4)."""

    def verdict(self, facts: dict[str, object] | None, files: frozenset[str]) -> str:
        patch = {PERSISTENT_LABEL: facts} if facts is not None else {}
        with mock.patch.dict(tb.RUNNER_BOUNDARY_FACTS, patch, clear=True):
            result = _scan({SYNTH: HEADER + JOB_CLASS_IV}, repo_files=files)
        return result.verdicts[(SYNTH, "class-iv")]

    def test_9452_no_boundary_facts_means_class_iv(self) -> None:
        _need_module(self)
        self.assertEqual(self.verdict(None, frozenset()), "iv")

    def test_9452_full_boundary_facts_with_proof_test_clear_class_iv(self) -> None:
        _need_module(self)
        self.assertEqual(self.verdict(BOUNDARY_FACTS_FULL, frozenset({BOUNDARY_PROOF})), "clean")

    def test_9452_path_split_on_one_os_user_does_not_clear_class_iv(self) -> None:
        _need_module(self)
        same_user = dict(BOUNDARY_FACTS_FULL, trusted_user="ci-pr")
        self.assertEqual(self.verdict(same_user, frozenset({BOUNDARY_PROOF})), "iv")

    def test_9452_each_missing_boundary_fact_keeps_class_iv(self) -> None:
        _need_module(self)
        for key in tb.BOUNDARY_REQUIRED_TRUE:
            with self.subTest(fact=key):
                facts = dict(BOUNDARY_FACTS_FULL, **{key: False})
                self.assertEqual(self.verdict(facts, frozenset({BOUNDARY_PROOF})), "iv")

    def test_9452_boundary_facts_without_the_proof_test_keep_class_iv(self) -> None:
        _need_module(self)
        self.assertEqual(self.verdict(BOUNDARY_FACTS_FULL, frozenset()), "iv")

    def test_9452_real_boundary_facts_are_empty_until_the_fix_lands(self) -> None:
        _need_module(self)
        self.assertEqual(tb.RUNNER_BOUNDARY_FACTS, {})


class ShellClassifier(unittest.TestCase):
    """Run text -> runs pull-request code, fail closed on every unknown form."""

    def test_9452_shell_text_table(self) -> None:
        _need_module(self)
        for text, expected in SHELL_CASES:
            with self.subTest(text=text):
                self.assertIs(tb._shell_runs_pr_code(text, tb._ShellCtx(False)), expected)

    def test_9452_runner_temp_path_needs_isolation_and_a_base_copy(self) -> None:
        _need_module(self)
        text = 'root="$RUNNER_TEMP/base"\npython3 -I "$root/tool.py"'
        self.assertFalse(tb._shell_runs_pr_code(text, tb._ShellCtx(True)))
        self.assertTrue(tb._shell_runs_pr_code(text, tb._ShellCtx(False)))
        self.assertTrue(tb._shell_runs_pr_code(text.replace(" -I", ""), tb._ShellCtx(True)))

    def test_9452_unterminated_forms_are_unclassifiable(self) -> None:
        _need_module(self)
        for text in ("echo 'open", "echo \"open", "x=$(echo", "cat <<EOF\nbody", "echo `x"):
            with self.subTest(text=text):
                with self.assertRaises(tb.Unclassifiable):
                    tb._shell_runs_pr_code(text, tb._ShellCtx(False))


class Bounds(unittest.TestCase):
    """Scanning time stays linear: 200 jobs and a 100K+ run text under a wall-clock ceiling."""

    def test_9452_two_hundred_job_workflow_under_ceiling(self) -> None:
        _need_module(self)
        jobs = "".join(JOB_CLASS_IV.replace("class-iv:", f"job-{n}:") for n in range(JOB_COUNT_LARGE))
        start = time.monotonic()
        result = _scan({SYNTH: HEADER + jobs})
        elapsed = time.monotonic() - start
        self.assertEqual(len(result.violations), JOB_COUNT_LARGE)
        self.assertLess(elapsed, LARGE_SCAN_CEILING_S)

    def test_9452_large_run_text_under_ceiling(self) -> None:
        _need_module(self)
        line = 'echo "$(printf %s abc)" | grep -c x >> out.txt # note\n'
        text = line * (RUN_TEXT_BYTES_LARGE // len(line) + 1)
        self.assertGreater(len(text), RUN_TEXT_BYTES_LARGE)
        start = time.monotonic()
        self.assertFalse(tb._shell_runs_pr_code(text, tb._ShellCtx(False)))
        self.assertLess(time.monotonic() - start, RUN_TEXT_CEILING_S)

    def test_9452_oversized_yaml_is_refused(self) -> None:
        _need_module(self)
        with self.assertRaises(tb.YamlError):
            tb.parse_yaml("a: " + "x" * (tb.MAX_YAML_BYTES + 1), "big")


class RealWorkflows(unittest.TestCase):
    """The invariant over every real workflow at the checkout, and the real step texts."""

    def test_9452_every_real_job_holds_the_boundary_or_has_an_open_row(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        self.assertEqual(tb.check(tb.scan_texts(workflows, actions, files)), [])

    def test_9452_every_allow_row_names_a_real_step(self) -> None:
        _need_module(self)
        for row in tb.TAINT_ALLOW:
            with self.subTest(row=row):
                self.assertIsInstance(_real_step(row.workflow, row.job, row.step), dict)

    def test_9452_real_trusted_classify_step_runs_no_pr_code(self) -> None:
        _need_module(self)
        for workflow, job, step_id in (("ci.yml", "classify", "id:cls"), ("coverage.yml", "classify", "id:cls")):
            with self.subTest(workflow=workflow):
                step = _real_step(workflow, job, step_id)
                text = tb._expr_free(step["run"])
                self.assertRegex(text, tb.BASE_MATERIALISE_RE)
                self.assertFalse(tb._shell_runs_pr_code(text, tb._ShellCtx(True)))
                self.assertTrue(tb._shell_runs_pr_code(text, tb._ShellCtx(False)))

    def test_9452_real_impact_step_runs_pr_code(self) -> None:
        _need_module(self)
        step = _real_step("ci.yml", "classify", "id:impact")
        self.assertTrue(tb._shell_runs_pr_code(tb._expr_free(step["run"]), tb._ShellCtx(True)))

    def test_9452_real_select_job_runs_only_the_base_copy(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        self.assertEqual(result.verdicts[("ci.yml", "select")], "no-pr-code")

    def test_9452_real_prune_step_is_the_taint_point_of_the_persistent_jobs(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        for key in (("ci.yml", "check"), ("cert-postgres-age.yml", "cert-postgres-age"),
                    ("postgres-ignored.yml", "postgres-ignored")):
            with self.subTest(job=key):
                self.assertEqual(result.taint_steps[key], "Prune stale runner TMPDIR (#8634)")
                self.assertEqual(result.verdicts[key], "iv")

    def test_9452_real_hit_verdicts(self) -> None:
        _need_module(self)
        workflows, actions, files = _real()
        result = tb.scan_texts(workflows, actions, files)
        hits = {key: v for key, v in result.verdicts.items() if v not in ("clean", "no-pr-code", "trusted-only")}
        self.assertEqual(hits, {
            ("c8-precheck.yml", "required-contexts-gate"): "i",
            ("coverage.yml", "per-module-thresholds"): "i,ii",
            ("ci.yml", "classify"): "iii",
            ("ci.yml", "check"): "iv",
            ("cert-postgres-age.yml", "cert-postgres-age"): "iv",
            ("postgres-ignored.yml", "postgres-ignored"): "iv",
        })

    @unittest.skipUnless(pyyaml is not None, "PyYAML not installed: parity oracle skipped")
    def test_9452_subset_parser_matches_pyyaml_on_every_real_file(self) -> None:
        _need_module(self)
        workflows, actions, _ = _real()
        for name, text in list(workflows.items()) + list(actions.items()):
            with self.subTest(file=name):
                oracle = pyyaml.safe_load(text)
                if isinstance(oracle, dict) and True in oracle:
                    oracle["on"] = oracle.pop(True)
                self.assertEqual(tb.parse_yaml(text, name), oracle)


if __name__ == "__main__":
    unittest.main()
