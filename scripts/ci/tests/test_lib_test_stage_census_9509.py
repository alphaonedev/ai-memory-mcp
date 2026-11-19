#!/usr/bin/env python3
"""Census of every lib-test job of every workflow: stage step or named skip (#9509).

Class: a test (or a test prerequisite) whose verdict depends on host state that the job
did not build. The lib test
``handlers::tests::b3_precompute_with_local_embedder_populates_eight_descriptors`` needs
the offline embedder cache and fails loud ("prerequisite missing: offline embedder
cache") without it; a quiet skip inside the test is the 9509 class itself (ruling b29
127a16a7 (2)).

Invariant: every run line of every job (of every workflow and composite action) that runs
the lib unit tests, and could select that test, EITHER comes after a stage step
(``python3 -I scripts/ci/stage_hf_cache.py --models embedder|all``) of the same job that
runs whenever the test step runs (no ``if:``, or the test step's own ``if:``), OR names
that test in an explicit ``--skip`` argument with a shell comment naming 9509 in the same
run block. A run line with neither is a finding; a workflow the parser cannot read is an
error, never clean.

ci.yml is held to the narrower form (conductor b29 6a339cef, condition (2)): for EVERY job
of ci.yml that runs the lib tests the stage step is present (a named skip does not count
there) AND its condition is not narrower than the condition of the lib test step: the same
``if:`` (compared after removing a whole ``${{ }}`` wrapper and folding blanks), or none.
A cell copies the ``cargo_skip`` condition of job check into the stage step of job
sal-feature in the real ci.yml text and requires the census to turn red on it.

The real workflow files are read from the checkout; synthetic jobs are named constants
below. No file is written, no network is used.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_lib_test_stage_census_9509.py'
Python 3.12 floor, standard library only (the YAML subset parser of taint_boundary).
"""

from __future__ import annotations

import re
import shlex
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import taint_boundary as tb  # noqa: E402  (path set above; standard library only)

B3 = "handlers::tests::b3_precompute_with_local_embedder_populates_eight_descriptors"
B3_FN = B3.rsplit("::", 1)[1]
B3_FILE = "src/handlers/tests.rs"
ISSUE_MARK = "9509"
STAGE_SCRIPT = "scripts/ci/stage_hf_cache.py"
# Model sets of scripts/ci/stage_hf_cache.py MODEL_SETS that hold the embedder.
EMBEDDER_SETS = frozenset({"embedder", "all"})
PREREQ_FN = "with_offline_staged_embedder"
PREREQ_DEF_FILE = "src/embeddings.rs"

REASON_NO_STAGE = "neither a stage step before it nor a named skip"
REASON_STAGE_IF = "the stage step before it runs under a condition the test step does not have"
REASON_SKIP_NO_MARK = "names the skip without a shell comment naming 9509"
REASON_UNREADABLE = "job is not a mapping"
REASON_CI_NO_STAGE = "no stage step before it (ci.yml takes the stage step, a named skip does not count)"
# Workflow files held to the stage-step-only form (condition (2) of b29 6a339cef).
STAGE_ONLY_FILES = frozenset({"ci.yml"})
CARGO_SKIP_IF = "needs.classify.outputs.cargo_skip != 'true'"
STAGE_RUN_LINE = "run: python3 -I scripts/ci/stage_hf_cache.py --models embedder"

# Lib-test jobs the census must see on the real tree (a superset check).
KNOWN_LIB_JOBS = frozenset({
    ("ci.yml", "check"),
    ("ci.yml", "sal-feature"),
    ("coverage.yml", "per-module-thresholds"),
})
LARGE_JOBS = 400
LARGE_RUN_BYTES = 120_000
LARGE_CEILING_S = 10.0

SELECTORS = ("--test", "--bin", "--bins", "--example", "--examples", "--doc", "--bench", "--benches")
VALUE_FLAGS = frozenset({
    "--features", "-F", "--target", "--test-threads", "--skip", "--format", "-p", "--package",
    "--message-format", "--output-path", "--log-dir", "-j", "--jobs", "--color", "--exclude",
})
OPS = frozenset({"||", "&&", ";", "|", "&", "(", ")", "|&", ";;"})


def logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop whole-line shell comments."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out


def simple_commands(line: str) -> list[list[str]]:
    """Split one shell line into simple commands (quoted words stay whole)."""
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = "#"
    try:
        toks = list(lex)
    except ValueError:
        toks = line.split()
    out: list[list[str]] = []
    cur: list[str] = []
    for tok in toks:
        if tok in OPS or (re.fullmatch(r"[<>&|;()0-9]+", tok) and any(c in tok for c in "<>|&;()")):
            if cur:
                out.append(cur)
            cur = []
            continue
        cur.append(tok)
    if cur:
        out.append(cur)
    return out


def strip_assignments(words: list[str]) -> list[str]:
    while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
        words = words[1:]
    return words


def is_stage(words: list[str]) -> bool:
    """True for the one staging form that stages the embedder."""
    words = strip_assignments(words)
    return (
        len(words) == 5
        and words[:4] == ["python3", "-I", STAGE_SCRIPT, "--models"]
        and words[4] in EMBEDDER_SETS
    )


def test_command(words: list[str]) -> list[str] | None:
    """The cargo words of a test command (cargo test, llvm-cov, nextest run, run_tests)."""
    words = strip_assignments(words)
    if not words or words[0] in ("echo", "printf", "local"):
        return None
    if words[0] == "run_tests" and len(words) > 1:
        return ["cargo", "test"] + words[2:]
    for i, word in enumerate(words[:-1]):
        if word == "cargo":
            rest = words[i + 1:]
            if rest and rest[0].startswith("+"):
                rest = rest[1:]
            if rest and (rest[0] in ("test", "llvm-cov") or rest[:2] == ["nextest", "run"]):
                return ["cargo"] + rest
            return None
    return None


def can_run_b3(toks: list[str]) -> bool:
    """True when the command runs lib unit tests with a filter that can select B3."""
    if '"$@"' in " ".join(toks) or "$@" in toks or "--no-run" in toks:
        return False  # a wrapper body forwards its caller's words; build-only runs nothing
    if "--" in toks:
        cut = toks.index("--")
        pre, post = toks[:cut], toks[cut + 1:]
    else:
        pre, post = toks, []
    if "--list" in post:
        return False
    if "--lib" not in pre and any(t in SELECTORS or t.split("=")[0] in SELECTORS for t in pre):
        return False
    if "--lib" not in pre and any(t.startswith("${") and t.endswith("[@]}") for t in pre):
        return False  # target array without --lib: integration binaries only
    if "--ignored" in post and "--include-ignored" not in post:
        return False
    filters: list[str] = []
    skip_next = False
    sub = 3 if len(pre) > 2 and pre[2] == "run" else 2
    for tok in pre[sub:] + post:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            skip_next = tok in VALUE_FLAGS and "=" not in tok
            continue
        if tok.startswith("$"):
            continue
        filters.append(tok)
    exact = "--exact" in post
    return not filters or any((f == B3) if exact else (f in B3) for f in filters)


def names_b3_skip(toks: list[str]) -> bool:
    post = toks[toks.index("--") + 1:] if "--" in toks else []
    for i, tok in enumerate(post):
        if tok == "--skip" and i + 1 < len(post) and post[i + 1] == B3:
            return True
        if tok == f"--skip={B3}":
            return True
    return False


def has_issue_comment(text: str) -> bool:
    return any(line.strip().startswith("#") and ISSUE_MARK in line for line in text.splitlines())


def condition(step: dict) -> str | None:
    """The step condition, normalised: a whole ``${{ }}`` wrapper removed, blanks folded."""
    cond = step.get("if")
    if cond is None:
        return None
    text = str(cond).strip()
    if text.startswith("${{") and text.endswith("}}") and text.count("${{") == 1:
        text = text[3:-2].strip()
    return " ".join(text.split())


def job_census(label: str, job_id: str, job: object) -> tuple[bool, list[str]]:
    """Return (job runs lib tests able to select B3, findings) for one job.

    In a file of STAGE_ONLY_FILES a named skip does not count: the stage step is required.
    """
    stage_only = label in STAGE_ONLY_FILES
    if not isinstance(job, dict):
        return False, [f"{label}: job {job_id}: {REASON_UNREADABLE}"]
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False, []  # a reusable-workflow call: that workflow is scanned on its own
    stage_conds: list[str | None] = []
    runs_lib = False
    findings: list[str] = []
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            findings.append(f"{label}: job {job_id}: step {idx}: step is not a mapping")
            continue
        run = step.get("run")
        if run is None:
            continue
        text = str(run)
        name = str(step.get("name", f"step {idx}"))
        cond = condition(step)
        for line in logical_lines(text):
            for words in simple_commands(line):
                if is_stage(words):
                    stage_conds.append(cond)
                    continue
                toks = test_command(words)
                if toks is None or not can_run_b3(toks):
                    continue
                runs_lib = True
                cmd = " ".join(toks)
                where = f"{label}: job {job_id}: step {name!r}: `{cmd}`"
                if names_b3_skip(toks) and not stage_only:
                    if not has_issue_comment(text):
                        findings.append(f"{where}: {REASON_SKIP_NO_MARK}")
                elif not stage_conds:
                    findings.append(f"{where}: {REASON_CI_NO_STAGE if stage_only else REASON_NO_STAGE}")
                elif not any(c is None or c == cond for c in stage_conds):
                    findings.append(f"{where}: {REASON_STAGE_IF}")
    return runs_lib, findings


def census_text(text: str, label: str, action: bool = False) -> tuple[set[tuple[str, str]], list[str]]:
    """Census of one workflow (or composite action) text; a parse failure raises."""
    doc = tb.parse_yaml(text, label)
    if not isinstance(doc, dict):
        raise ValueError(f"{label}: top level is not a mapping")
    if action:
        runs = doc.get("runs")
        jobs = {"(action)": runs} if isinstance(runs, dict) and "steps" in runs else {}
    else:
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            raise ValueError(f"{label}: no jobs mapping")
    lib_jobs: set[tuple[str, str]] = set()
    findings: list[str] = []
    for job_id, job in jobs.items():
        runs_lib, found = job_census(label, str(job_id), job)
        if runs_lib:
            lib_jobs.add((label, str(job_id)))
        findings += found
    return lib_jobs, findings


def census_tree(root: Path) -> tuple[set[tuple[str, str]], list[str]]:
    lib_jobs: set[tuple[str, str]] = set()
    findings: list[str] = []
    wf_dir = root / ".github" / "workflows"
    for path in sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml")):
        jobs, found = census_text(path.read_text(), path.name)
        lib_jobs |= jobs
        findings += found
    actions = root / ".github" / "actions"
    if actions.is_dir():
        for path in sorted(actions.glob("**/action.y*ml")):
            label = str(path.relative_to(root))
            jobs, found = census_text(path.read_text(), label, action=True)
            lib_jobs |= jobs
            findings += found
    return lib_jobs, findings


def step(name: str, run: str, cond: str | None = None) -> dict:
    out = {"name": name, "run": run}
    if cond is not None:
        out["if"] = cond
    return out


STAGE = step("Stage HF embedder cache (#9509)", "python3 -I scripts/ci/stage_hf_cache.py --models embedder")
STAGE_ALL = step("Stage", "python3 -I scripts/ci/stage_hf_cache.py --models all")
LIB = step("Run lib tests", "cargo test --features sal --lib")
COND = "needs.classify.outputs.cargo_skip != 'true'"
SKIP_RUN = f"# #9509: no network on this runner, the b3 test is skipped by name\ncargo test --lib -- --skip {B3}"

# (row id, steps, expected finding reasons in order)
SYNTHETIC_ROWS: tuple[tuple[str, list[dict], list[str]], ...] = (
    ("no-stage", [LIB], [REASON_NO_STAGE]),
    ("stage-before", [STAGE, LIB], []),
    ("stage-all-before", [STAGE_ALL, LIB], []),
    ("stage-after", [LIB, STAGE], [REASON_NO_STAGE]),
    ("stage-same-step-before", [step("both", "python3 -I scripts/ci/stage_hf_cache.py --models embedder\ncargo test --lib")], []),
    ("stage-same-step-after", [step("both", "cargo test --lib\npython3 -I scripts/ci/stage_hf_cache.py --models embedder")], [REASON_NO_STAGE]),
    ("stage-verify-only", [step("v", "python3 -I scripts/ci/stage_hf_cache.py --models embedder --verify-only"), LIB], [REASON_NO_STAGE]),
    ("stage-unknown-set", [step("r", "python3 -I scripts/ci/stage_hf_cache.py --models reranker"), LIB], [REASON_NO_STAGE]),
    ("stage-commented-out", [step("c", "# python3 -I scripts/ci/stage_hf_cache.py --models embedder\ntrue"), LIB], [REASON_NO_STAGE]),
    ("stage-echoed", [step("e", "echo python3 -I scripts/ci/stage_hf_cache.py --models embedder"), LIB], [REASON_NO_STAGE]),
    ("stage-if-test-none", [step("s", STAGE["run"], COND), LIB], [REASON_STAGE_IF]),
    ("stage-if-equal", [step("s", STAGE["run"], COND), step("t", LIB["run"], COND)], []),
    ("stage-if-differs", [step("s", STAGE["run"], COND), step("t", LIB["run"], "always()")], [REASON_STAGE_IF]),
    ("stage-none-test-if", [STAGE, step("t", LIB["run"], COND)], []),
    ("skip-with-mark", [step("t", SKIP_RUN)], []),
    ("skip-eq-form-with-mark", [step("t", f"# 9509\ncargo test --lib -- --skip={B3}")], []),
    ("skip-without-mark", [step("t", f"cargo test --lib -- --skip {B3}")], [REASON_SKIP_NO_MARK]),
    ("skip-partial-name", [step("t", "# 9509\ncargo test --lib -- --skip b3_precompute")], [REASON_NO_STAGE]),
    ("skip-other-test", [step("t", "# 9509\ncargo test --lib -- --skip config::tests")], [REASON_NO_STAGE]),
    ("skip-before-separator", [step("t", f"# 9509\ncargo test --lib --skip {B3}")], [REASON_NO_STAGE]),
    ("integration-only", [step("t", "cargo test --test coverage_uplift_3885")], []),
    ("target-array", [step("t", 'cargo test "${TARGETS[@]}"')], []),
    ("build-only", [step("t", "cargo test --lib --no-run")], []),
    ("list-only", [step("t", "cargo test --lib -- --list")], []),
    ("ignored-only", [step("t", "cargo test -- --ignored")], []),
    ("filter-not-b3", [step("t", "cargo test --lib sizes::tests::no_tool_exceeds_1500_tokens")], []),
    ("filter-selects-b3", [step("t", "cargo test --lib handlers::tests")], [REASON_NO_STAGE]),
    ("filter-exact-b3", [step("t", f"cargo test --lib -- --exact {B3}")], [REASON_NO_STAGE]),
    ("no-selector", [step("t", "cargo test")], [REASON_NO_STAGE]),
    ("llvm-cov", [step("t", "cargo llvm-cov --no-report --features sal --lib -- --test-threads=1")], [REASON_NO_STAGE]),
    ("nextest", [step("t", "cargo nextest run --lib")], [REASON_NO_STAGE]),
    ("toolchain-plus", [step("t", "cargo +1.99.1 test --lib")], [REASON_NO_STAGE]),
    ("env-prefix", [step("t", "AI_MEMORY_NO_CONFIG=1 cargo test --lib")], [REASON_NO_STAGE]),
    ("continuation", [step("t", "cargo test \\\n  --features sal \\\n  --lib")], [REASON_NO_STAGE]),
    ("after-and", [step("t", "cd . && cargo test --lib")], [REASON_NO_STAGE]),
    ("run-tests-wrapper", [step("t", "run_tests sqlite --lib")], [REASON_NO_STAGE]),
    ("wrapper-body", [step("t", 'run_tests() { cargo test "$@"; }')], []),
    ("two-lines-one-stage", [STAGE, step("t", "cargo test --lib\ncargo test --features sal --lib")], []),
    ("two-lines-no-stage", [step("t", "cargo test --lib\ncargo test --features sal --lib")], [REASON_NO_STAGE, REASON_NO_STAGE]),
)

# (row id, steps, expected finding reasons) judged as jobs of ci.yml (stage step only).
CI_ROWS: tuple[tuple[str, list[dict], list[str]], ...] = (
    ("ci-no-stage", [LIB], [REASON_CI_NO_STAGE]),
    ("ci-stage-before", [STAGE, LIB], []),
    ("ci-skip-with-mark", [step("t", SKIP_RUN)], [REASON_CI_NO_STAGE]),
    ("ci-skip-without-mark", [step("t", f"cargo test --lib -- --skip {B3}")], [REASON_CI_NO_STAGE]),
    ("ci-skip-and-stage", [STAGE, step("t", SKIP_RUN)], []),
    ("ci-stage-after", [LIB, STAGE], [REASON_CI_NO_STAGE]),
    ("ci-cargo-skip-if-copied", [step("s", STAGE["run"], COND), LIB], [REASON_STAGE_IF]),
    ("ci-cargo-skip-if-both", [step("s", STAGE["run"], COND), step("t", LIB["run"], COND)], []),
    ("ci-wrapped-equal", [step("s", STAGE["run"], "${{ " + COND + " }}"), step("t", LIB["run"], COND)], []),
    ("ci-blank-folded-equal", [step("s", STAGE["run"], COND.replace(" != ", "  !=  ")), step("t", LIB["run"], COND)], []),
    ("ci-narrower-and", [step("s", STAGE["run"], COND + " && runner.os == 'Linux'"), step("t", LIB["run"], COND)], [REASON_STAGE_IF]),
    ("ci-stage-none-test-if", [STAGE, step("t", LIB["run"], COND)], []),
    ("ci-stage-other-if", [step("s", STAGE["run"], "always()"), LIB], [REASON_STAGE_IF]),
    ("ci-two-stages-one-ok", [step("s1", STAGE["run"], COND), STAGE, LIB], []),
)


def with_stage_if_in_job(text: str, job_id: str, cond: str) -> str:
    """Copy ``if: <cond>`` into the embedder stage step of one job of a workflow text.

    Raises ValueError when the job or its stage step is not found, so the mutant cell is red
    on a tree whose job has no stage step.
    """
    lines = text.split("\n")
    head = f"  {job_id}:"
    try:
        start = lines.index(head)
    except ValueError:
        raise ValueError(f"job {job_id} not found") from None
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            break
        if line.strip() == STAGE_RUN_LINE:
            indent = line[: len(line) - len(line.lstrip())]
            return "\n".join(lines[:i] + [f"{indent}if: {cond}"] + lines[i:])
    raise ValueError(f"job {job_id}: no stage step `{STAGE_RUN_LINE}`")


REAL_FORM_WORKFLOW = f"""name: synthetic
on: pull_request
jobs:
  good:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - name: Stage HF embedder cache (#9509)
        run: python3 -I scripts/ci/stage_hf_cache.py --models embedder
      - name: Run lib tests
        env:
          AI_MEMORY_NO_CONFIG: "1"
        run: cargo test --features sal --lib
  skipped:
    runs-on: ubuntu-latest
    steps:
      - name: Run lib tests
        run: |
          # 9509: the b3 test is skipped by name on this job
          cargo test --lib -- --skip {B3}
  bad:
    runs-on: ubuntu-latest
    steps:
      # 9509 in a YAML comment is not in the run block
      - name: Run lib tests
        run: cargo test --lib -- --skip {B3}
  plain:
    runs-on: ubuntu-latest
    steps:
      - name: Run lib tests
        run: cargo test --lib
"""


def reasons(findings: list[str]) -> list[str]:
    return [f.rsplit(": ", 1)[1] for f in findings]


class SyntheticRows(unittest.TestCase):
    def test_every_row_gives_its_exact_reasons(self):
        for row_id, steps, expected in SYNTHETIC_ROWS:
            with self.subTest(row=row_id):
                runs_lib, findings = job_census("synthetic.yml", row_id, {"steps": steps})
                self.assertEqual(reasons(findings), expected, findings)
                if expected:
                    self.assertTrue(runs_lib)

    def test_every_ci_row_gives_its_exact_reasons(self):
        for row_id, steps, expected in CI_ROWS:
            with self.subTest(row=row_id):
                runs_lib, findings = job_census("ci.yml", row_id, {"steps": steps})
                self.assertEqual(reasons(findings), expected, findings)
                self.assertTrue(runs_lib)

    def test_condition_normalisation(self):
        self.assertIsNone(condition({}))
        self.assertEqual(condition({"if": "${{ a  &&  b }}"}), "a && b")
        self.assertEqual(condition({"if": "${{ a }} && ${{ b }}"}), "${{ a }} && ${{ b }}")

    def test_mutation_helper_fails_closed(self):
        with self.assertRaisesRegex(ValueError, r"^job nope not found$"):
            with_stage_if_in_job("jobs:\n  a:\n    steps: []\n", "nope", COND)
        with self.assertRaisesRegex(ValueError, r"^job a: no stage step "):
            with_stage_if_in_job("jobs:\n  a:\n    steps: []\n  b:\n      " + STAGE_RUN_LINE + "\n", "a", COND)

    def test_unreadable_job_is_a_finding(self):
        _, findings = job_census("synthetic.yml", "j", ["not", "a", "mapping"])
        self.assertEqual(findings, [f"synthetic.yml: job j: {REASON_UNREADABLE}"])

    def test_reusable_workflow_call_job_has_no_steps_to_judge(self):
        self.assertEqual(job_census("synthetic.yml", "j", {"uses": "./.github/workflows/x.yml"}), (False, []))

    def test_finding_text_names_workflow_job_step_and_command(self):
        _, findings = job_census("ci.yml", "sal-feature", {"steps": [LIB]})
        self.assertEqual(findings, [
            "ci.yml: job sal-feature: step 'Run lib tests': `cargo test --features sal --lib`: "
            + REASON_CI_NO_STAGE
        ])

    def test_yaml_text_path_reads_run_blocks_and_comments(self):
        lib_jobs, findings = census_text(REAL_FORM_WORKFLOW, "synthetic.yml")
        self.assertEqual(lib_jobs, {("synthetic.yml", j) for j in ("good", "skipped", "bad", "plain")})
        self.assertEqual(findings, [
            f"synthetic.yml: job bad: step 'Run lib tests': `cargo test --lib -- --skip {B3}`: {REASON_SKIP_NO_MARK}",
            f"synthetic.yml: job plain: step 'Run lib tests': `cargo test --lib`: {REASON_NO_STAGE}",
        ])

    def test_unparseable_workflow_raises(self):
        with self.assertRaises(tb.YamlError):
            census_text("jobs:\n  a: [unclosed\n", "broken.yml")

    def test_workflow_without_jobs_raises(self):
        with self.assertRaisesRegex(ValueError, r"^broken\.yml: no jobs mapping$"):
            census_text("name: x\non: push\n", "broken.yml")

    def test_large_input_is_linear(self):
        long_run = "\n".join(["echo step"] * (LARGE_RUN_BYTES // 10) + ["cargo test --lib"])
        self.assertGreater(len(long_run), LARGE_RUN_BYTES)
        start = time.monotonic()
        total = 0
        for i in range(LARGE_JOBS):
            _, findings = job_census("large.yml", f"j{i}", {"steps": [STAGE, LIB]})
            total += len(findings)
        _, findings = job_census("large.yml", "long", {"steps": [step("t", long_run)]})
        elapsed = time.monotonic() - start
        self.assertEqual(total, 0)
        self.assertEqual(reasons(findings), [REASON_NO_STAGE])
        self.assertLess(elapsed, LARGE_CEILING_S)


class RealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib_jobs, cls.findings = census_tree(ROOT)

    def test_census_sees_the_known_lib_test_jobs(self):
        self.assertLessEqual(KNOWN_LIB_JOBS, self.lib_jobs, sorted(self.lib_jobs))

    def test_every_lib_test_job_stages_or_skips_b3_by_name(self):
        self.assertEqual(self.findings, [])

    def test_every_ci_lib_test_job_has_a_stage_step_not_narrower_than_its_test(self):
        ci_jobs = sorted(j for f, j in self.lib_jobs if f == "ci.yml")
        self.assertLessEqual({j for f, j in KNOWN_LIB_JOBS if f == "ci.yml"}, set(ci_jobs))
        ci_findings = [f for f in self.findings if f.startswith("ci.yml: ")]
        self.assertEqual(ci_findings, [], ci_jobs)

    def test_cargo_skip_if_copied_into_sal_feature_is_red(self):
        """Mutant of condition (2): the check job's step-level if copied into sal-feature."""
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        mutated = with_stage_if_in_job(text, "sal-feature", CARGO_SKIP_IF)
        _, findings = census_text(mutated, "ci.yml")
        self.assertEqual(findings, [
            "ci.yml: job sal-feature: step 'Run lib tests (sal feature)': "
            f"`cargo test --features sal --lib`: {REASON_STAGE_IF}"
        ])


class OnlyHostCacheTest(unittest.TestCase):
    """The census names one test: B3 must be the only caller of the staged-cache
    prerequisite, so a new caller turns this cell red until the census names it."""

    def test_b3_is_the_only_caller_of_the_prerequisite(self):
        callers = []
        call = re.compile(rf"(?<![A-Za-z0-9_]){PREREQ_FN}\s*\(")
        definition = re.compile(rf"\bfn {PREREQ_FN}\b")
        for path in sorted(ROOT.glob("src/**/*.rs")) + sorted(ROOT.glob("tests/**/*.rs")):
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                code = line.split("//", 1)[0]
                if call.search(code) and not definition.search(code):
                    callers.append((str(path.relative_to(ROOT)), lineno))
        self.assertEqual([c[0] for c in callers], [B3_FILE], callers)
        lines = (ROOT / B3_FILE).read_text().splitlines()
        fn_line = max(i for i, l in enumerate(lines, 1) if i < callers[0][1] and re.search(r"\bfn \w+\(", l))
        self.assertIn(f"fn {B3_FN}(", lines[fn_line - 1])


if __name__ == "__main__":
    unittest.main()
