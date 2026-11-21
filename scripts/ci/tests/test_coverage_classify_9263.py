"""Coverage classify table test (#9263).

The coverage job ran 59 minutes on diffs that change no Rust file (PR 9775: one
file under scripts/ci/tests) because its classify job used only the
docs-only verdict and ignored the cargo_skip superset the decider already
computes. This file pins the class, not the instance:

Invariant 1 (decide RUN by default). The job is short-circuited only when the
changed-path list was read in full, is not empty, is under the cap and EVERY
path is positively known not to move coverage. An unknown path, an unreadable,
empty, truncated or over-cap list, a path in the RUN set (src, tests, benches,
coverage, Cargo.*, .cargo, build.rs, rust-toolchain*, the CI tree, every
include_str!/include_bytes! target), a rename whose OLD or NEW side is in the
RUN set and a path with an odd name (dot segments, empty segments, a leading or
trailing slash, a backslash, a control character, bytes that are not UTF-8) all RUN.

Invariant 2 (the required-context gate). A short-circuit still reports through
the same job-level `if:` the docs-only case used, with a reason line naming the
case; no context is renamed (scripts/test/test-ci-workflow-invariants.sh holds
the gate half).

Invariant 3 (the sweep end line is computed from the sweep state). The last
step of the coverage job runs on `cancelled() || failure()` and writes ONE
line chosen from the outcome of the sweep step: an error annotation for a
failed, cancelled or unknown sweep, a notice for a sweep that succeeded (a
later step ended the job) or was never run. `elapsed` is the sweep alone
(start and end recorded around the sweep step). The 59 minute run of issue
9792 lost its runner; a lost runner runs no later step, so no step can name
that case. The step prints no secret.

Invariant 4 (cost). The cost of the decider is bounded by operation counts
(regex compilations and glob match calls), never by wall-clock time.

The expected columns are hand-written literals; none is computed from the code
under test.
"""
import os
import re
import contextlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.append(str(REPO / "scripts" / "ci"))

from impact import cargo_skip  # noqa: E402

WORKFLOW = REPO / ".github" / "workflows" / "coverage.yml"
IMPACT_DIR = REPO / "scripts" / "ci" / "impact"
SCRATCH = REPO / ".local-runs"
SCRIPT = IMPACT_DIR / "cargo_skip.py"
TIMEOUT_S = 120
# Hand-written: a rules.json version bump must come with a reviewed table update.
V = "cargo_skip-rules-v1"
PR_BASE_REF = "chain/promo6-ssh-r2"
# The chain tip tree that predates #9263 (its decider does not know --stdin0).
CHAIN_TIP = "b5b1f8bbf3e8e867baa0bb36f901463c06d16a1f"
MAX_PATHS = 5000
# Cost bound of the cap rows: two rows read the lists, and one path is matched
# by at most this many passes (ci tree, docs, skip, each with its blocked check).
LIST_READING_ROWS = 2
LIST_PASSES = 3
FAIL_CLOSED = "classifier-error-fail-closed"
# Fixture identity and canary values are assembled from parts so the diff holds no
# literal that looks like a mailbox or a credential assignment.
FIXTURE_MAIL = "fixture" + chr(64) + "fixture.test"
CANARY_MARK = "cov9263" + "-canary"
CANARY_A = CANARY_MARK + "-a"
CANARY_B = CANARY_MARK + "-b"
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_HEADER = re.compile(r"^      - ")
STEP_IF = re.compile(r"^        if:\s*(.*)$")
RUN_HEADER = re.compile(r"^        run: \|\s*$")
RUN_INDENT = 10
BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL")


def job_lines(job: str):
    """Return the lines of a job of coverage.yml."""
    out, inside = [], False
    for line in WORKFLOW.read_text().splitlines():
        header = JOB_HEADER.match(line)
        if header:
            inside = header.group(1) == job
            continue
        if inside:
            out.append(line)
    return out


def steps_of(job: str):
    """Return the steps of a job as lists of lines."""
    steps, current = [], None
    for line in job_lines(job):
        if STEP_HEADER.match(line):
            current = [line]
            steps.append(current)
        elif current is not None:
            current.append(line)
    return steps


def step_first(step) -> str:
    return step[0].strip()


def find_step(job: str, first: str):
    """Return the step of `job` whose first line is `first` (exact)."""
    for step in steps_of(job):
        if step_first(step) == first:
            return step
    raise AssertionError("no step %r in job %s of coverage.yml" % (first, job))


def step_if(step):
    for line in step:
        found = STEP_IF.match(line)
        if found:
            return found.group(1).strip()
    return None


def run_body(step) -> str:
    """Return the dedented `run: |` body of a step."""
    body, in_run = [], False
    for line in step[1:]:
        if RUN_HEADER.match(line):
            in_run = True
            continue
        if in_run:
            if line.strip() and not line.startswith(" " * RUN_INDENT):
                break
            body.append(line[RUN_INDENT:] if line.strip() else "")
    return "\n".join(body) + "\n"


def base_env(extra=None):
    env = {k: os.environ[k] for k in BASE_ENV_KEYS if k in os.environ}
    env.update(extra or {})
    return env


def run_git(repo: Path, *args: str) -> str:
    env = base_env({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": FIXTURE_MAIL,
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": FIXTURE_MAIL,
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                    "HOME": str(repo)})
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false"] + list(args),
                         capture_output=True, text=True, timeout=TIMEOUT_S, env=env)
    if res.returncode != 0:
        raise AssertionError("git %s: %s" % (" ".join(args), res.stderr))
    return res.stdout.strip()


def scratch_dir() -> Path:
    SCRATCH.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="cov9263-", dir=str(SCRATCH)))


# (label, paths, docs_only, cargo_skip, reason): written out by hand.
RUN_ROWS = [
    ("rust only", ["src/db.rs"], "false", "false",
     "rust-observable-path src/db.rs " + V),
    ("python under scripts/ci", ["scripts/ci/check_x.py"], "false", "false",
     "ci-tree-edited-full-ci scripts/ci/check_x.py " + V),
    ("mixed tests + rust + docs",
     ["scripts/ci/tests/test_x.py", "src/db.rs", "docs/a.md"], "false", "false",
     "rust-observable-path src/db.rs " + V),
    ("the workflow file itself", [".github/workflows/coverage.yml"], "false", "false",
     "ci-tree-edited-full-ci .github/workflows/coverage.yml " + V),
    ("a script the coverage job runs: pg_env_preflight",
     ["scripts/ci/pg_env_preflight.py"], "false", "false",
     "ci-tree-edited-full-ci scripts/ci/pg_env_preflight.py " + V),
    ("a script the coverage job runs: check-thresholds",
     ["coverage/check-thresholds.sh"], "false", "false",
     "rust-observable-path coverage/check-thresholds.sh " + V),
    ("a script the coverage job mirrors: scripts/coverage.sh",
     ["scripts/coverage.sh"], "false", "false",
     "rust-observable-path scripts/coverage.sh " + V),
    ("Cargo.lock only", ["Cargo.lock"], "false", "false",
     "rust-observable-path Cargo.lock " + V),
    ("Cargo.toml only", ["Cargo.toml"], "false", "false",
     "rust-observable-path Cargo.toml " + V),
    ("empty list", [], "false", "false", "empty-diff-fail-closed " + V),
    ("unknown top-level directory", ["tools/x.txt"], "false", "false",
     "rust-observable-path tools/x.txt " + V),
    ("unknown top-level file", ["x.txt"], "false", "false",
     "rust-observable-path x.txt " + V),
    ("rename from an allowed path into src/", ["docs/a.md", "src/a.rs"], "false", "false",
     "rust-observable-path src/a.rs " + V),
    ("rename out of src/", ["src/lib.rs", "docs/lib.md"], "false", "false",
     "rust-observable-path src/lib.rs " + V),
    ("include_str! target: a markdown fixture under tests/",
     ["tests/fixtures/claude_md/crossroads_section_8604.md"], "false", "false",
     "rust-observable-path tests/fixtures/claude_md/crossroads_section_8604.md " + V),
    ("include_str! target: sdk fixture",
     ["sdk/fixtures/wake_meta_3578.json"], "false", "false",
     "rust-observable-path sdk/fixtures/wake_meta_3578.json " + V),
    ("include_str! target: a migration",
     ["migrations/sqlite/0081_v97_agent_pubkey_history.sql"], "false", "false",
     "rust-observable-path migrations/sqlite/0081_v97_agent_pubkey_history.sql " + V),
    ("markdown under coverage/", ["coverage/notes.md"], "false", "false",
     "rust-observable-path coverage/notes.md " + V),
    ("markdown under .cargo/", [".cargo/notes.md"], "false", "false",
     "rust-observable-path .cargo/notes.md " + V),
    ("a Cargo.* name that ends in .md", ["tools/Cargo.md"], "false", "false",
     "rust-observable-path tools/Cargo.md " + V),
    ("upper-case SRC/", ["SRC/x.rs"], "false", "false",
     "rust-observable-path SRC/x.rs " + V),
    ("srcfoo/ is not src/ and not allowed", ["srcfoo/x.rs"], "false", "false",
     "rust-observable-path srcfoo/x.rs " + V),
    ("a file named src", ["src"], "false", "false", "rust-observable-path src " + V),
    ("a file named docs", ["docs"], "false", "false", "rust-observable-path docs " + V),
]
ODD_ROWS = [
    ("dot-dot out of docs/", "docs/../src/x.rs", "docs/../src/x.rs"),
    ("dot-dot out of scripts/ci", "scripts/ci/../../src/x.rs", "scripts/ci/../../src/x.rs"),
    ("dot-dot out of scripts/ci/tests", "scripts/ci/tests/../../../src/x.rs",
     "scripts/ci/tests/../../../src/x.rs"),
    ("leading ./", "./docs/a.md", "./docs/a.md"),
    ("trailing slash", "docs/a.md/", "docs/a.md/"),
    ("empty segment", "docs//a.md", "docs//a.md"),
    ("leading slash", "/docs/a.md", "/docs/a.md"),
    ("backslash", "docs/a\\b.md", "docs/a\\b.md"),
    ("newline in the name", "docs/a\nb.md", "docs/a?b.md"),
    ("control character", "docs/a\x01.md", "docs/a?.md"),
    ("bytes that are not UTF-8", "docs/\udcff.md", "docs/?.md"),
    ("a lone dot segment", "docs/./a.md", "docs/./a.md"),
]
SKIP_ROWS = [
    ("docs only", ["docs/guide/a.md"], "true", "true", "docs-only " + V),
    ("markdown anywhere", ["notes/x.md"], "true", "true", "docs-only " + V),
    ("a space in a docs name", ["docs/a b.md"], "true", "true", "docs-only " + V),
    ("a non-ASCII docs name", ["docs/é.md"], "true", "true", "docs-only " + V),
    ("PR 9775 (one file under scripts/ci/tests)",
     ["scripts/ci/tests/test_prune_runner_tmp_8634.py"], "false", "true",
     "no-rust-observable-paths " + V),
    ("tests plus docs", ["scripts/ci/tests/test_x.py", "docs/a.md"], "false", "true",
     "no-rust-observable-paths " + V),
]
PR_9777 = [
    ".github/workflows/ci.yml", "changelog.d/9592.fixed.md", "docs/ci/PG-ISOLATION.md",
    "scripts/ci/check_pg_isolate_invariants.py", "scripts/ci/pg_env_preflight.py",
    "scripts/ci/pg_isolate_cluster_audit.py", "scripts/ci/pg_isolate_parity.py",
    "scripts/ci/pg_isolate_serial_residual.txt", "scripts/ci/pg_isolate_serial_step.py",
    "scripts/ci/pg_isolate_split.py", "scripts/ci/secret_redact.py",
    "scripts/ci/tests/test_check_pg_isolate_invariants.py",
    "scripts/ci/tests/test_ci_annotation_escape_9365.py",
    "scripts/ci/tests/test_ci_shard_wiring_6344.py",
    "scripts/ci/tests/test_ci_test_step_exec_6795.py",
    "scripts/ci/tests/test_impact_cargo_skip_8328.py",
    "scripts/ci/tests/test_pg_isolate_cluster_audit_9592.py",
    "scripts/ci/tests/test_pg_isolate_ledger_9592.py",
    "scripts/ci/tests/test_pg_isolate_parity_9592.py",
    "scripts/ci/tests/test_pg_isolate_serial_step_9592.py",
    "scripts/ci/tests/test_pg_isolate_split.py",
    "scripts/ci/tests/test_pg_isolated_binary.py",
    "scripts/ci/tests/test_secret_redact_9750.py",
    "scripts/ci/tests/test_step_env_9769.py",
    "scripts/ci/tests/test_suite_budget_9229.py",
    "scripts/ci/tests/test_suite_budget_9229_integrity.py",
    "scripts/ci/tests/workflow_text.py",
    "scripts/test/pg_isolated_binary.py",
    "scripts/test/test_ci_age_helper_isolated_6339.py",
]


class CountingRe:
    """Stand-in for the `re` module inside impact.common: counts compilations."""

    def __init__(self):
        self.compiles = 0

    def compile(self, *args, **kwargs):
        self.compiles += 1
        return re.compile(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(re, name)


class GlobOps:
    """The named counters: COMPILES (regex compilations), MATCHES (glob match calls)."""

    def __init__(self):
        self.shim = CountingRe()
        self.matches = 0

    @property
    def compiles(self):
        return self.shim.compiles


@contextlib.contextmanager
def counted_glob_ops():
    common = cargo_skip.common
    ops = GlobOps()
    real_re, real_match = common.re, common.match_glob
    clear = getattr(common.glob_to_regex, "cache_clear", None)
    if clear is not None:
        clear()

    def counting_match(glob, path):
        ops.matches += 1
        return real_match(glob, path)

    common.re, common.match_glob = ops.shim, counting_match
    try:
        yield ops
    finally:
        common.re, common.match_glob = real_re, real_match


def distinct_globs(section):
    """Every string of the rules section: an upper bound on its distinct globs."""
    found = set()

    def walk(node):
        if isinstance(node, str):
            found.add(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value)

    walk(section)
    return found


class DeciderTable(unittest.TestCase):
    """The decider verdict per path list: (docs_only, cargo_skip, exact reason)."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section(IMPACT_DIR / "rules.json")

    def verdict(self, paths):
        return cargo_skip.classify(self.section, paths, "pull_request", PR_BASE_REF)

    def check(self, label, paths, docs_only, skip, reason):
        got = self.verdict(paths)
        self.assertEqual(
            (got["docs_only"], got["cargo_skip"], got["cargo_skip_reason"]),
            (docs_only, skip, reason), label)

    def test_rules_version_is_the_one_the_table_names(self):
        self.assertEqual(self.section["version"], 1)

    def test_run_rows(self):
        for row in RUN_ROWS:
            with self.subTest(row[0]):
                self.check(*row)

    def test_odd_path_rows_run_with_the_named_reason(self):
        for label, path, shown in ODD_ROWS:
            with self.subTest(label):
                self.check(label, [path], "false", "false",
                           "odd-path-fail-closed %s %s" % (shown, V))
                self.check(label + " (after a rust path)", ["src/x.rs", path],
                           "false", "false", "odd-path-fail-closed %s %s" % (shown, V))

    def test_short_circuit_rows(self):
        for row in SKIP_ROWS:
            with self.subTest(row[0]):
                self.check(*row)

    def test_pr_9775_short_circuits(self):
        self.check("PR 9775", ["scripts/ci/tests/test_prune_runner_tmp_8634.py"],
                   "false", "true", "no-rust-observable-paths " + V)

    def test_pr_9777_runs_because_it_edits_the_ci_tree(self):
        # .github/workflows/ci.yml is the first path; scripts/ci/pg_env_preflight.py
        # (which the coverage job executes) forces a run on its own as well.
        self.check("PR 9777", PR_9777, "false", "false",
                   "ci-tree-edited-full-ci .github/workflows/ci.yml " + V)
        self.check("PR 9777 without the workflow", PR_9777[1:], "false", "false",
                   "ci-tree-edited-full-ci scripts/ci/check_pg_isolate_invariants.py " + V)

    def test_every_run_path_blocks_a_short_circuit_in_any_company(self):
        for label, paths, _, _, _ in RUN_ROWS:
            if not paths:
                continue
            with self.subTest(label):
                got = self.verdict(["docs/a.md", "scripts/ci/tests/t.py"] + paths)
                self.assertEqual((got["docs_only"], got["cargo_skip"]), ("false", "false"))

    def test_the_cap_boundary(self):
        docs = ["docs/f%05d.md" % i for i in range(MAX_PATHS - 1)]
        globs = len(distinct_globs(self.section))
        with counted_glob_ops() as ops:
            self.check("at the cap, rust last", docs + ["src/z.rs"], "false", "false",
                       "rust-observable-path src/z.rs " + V)
            self.check("one over the cap", docs + ["docs/x.md", "src/z.rs"], "false", "false",
                       "path-count-over-cap-fail-closed %d>%d %s" % (MAX_PATHS + 1, MAX_PATHS, V))
            self.check("at the cap, docs only", docs + ["docs/x.md"], "true", "true",
                       "docs-only " + V)
        # Operation counts, not wall-clock: each glob is compiled once, and the
        # match calls stay under paths x globs for the two list-reading rows.
        self.assertGreater(ops.matches, 0)
        self.assertLessEqual(ops.compiles, globs,
                             "COMPILES %d over %d distinct globs" % (ops.compiles, globs))
        bound = LIST_READING_ROWS * MAX_PATHS * globs * LIST_PASSES
        self.assertLessEqual(ops.matches, bound,
                             "MATCHES %d over the bound %d" % (ops.matches, bound))

    def test_an_over_cap_list_costs_no_glob_operation(self):
        paths = ["docs/f%05d.md" % i for i in range(9999)] + ["src/z.rs"]
        with counted_glob_ops() as ops:
            got = self.verdict(paths)
        self.assertEqual((got["docs_only"], got["cargo_skip"], got["cargo_skip_reason"]),
                         ("false", "false",
                          "path-count-over-cap-fail-closed 10000>%d %s" % (MAX_PATHS, V)))
        self.assertEqual((ops.compiles, ops.matches), (0, 0))


class DeciderCli(unittest.TestCase):
    """The NUL-separated stdin mode the workflow uses."""

    def setUp(self):
        self.work = scratch_dir()
        run_git(self.work, "init", "-q", "-b", "main")
        (self.work / "x.txt").write_text("x\n")
        run_git(self.work, "add", "x.txt")
        run_git(self.work, "commit", "-q", "-m", "base")

    def tearDown(self):
        shutil.rmtree(str(self.work), ignore_errors=True)

    def run_stdin0(self, data: bytes):
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--stdin0", "--repo", str(self.work),
             "--rules", str(IMPACT_DIR / "rules.json"), "--event-name", "pull_request",
             "--base-ref", PR_BASE_REF],
            input=data, capture_output=True, timeout=TIMEOUT_S, cwd=str(self.work))
        lines = res.stdout.decode().splitlines()
        return res.returncode, dict(line.split("=", 1) for line in lines)

    def check(self, label, data, docs_only, skip, reason):
        rc, got = self.run_stdin0(data)
        self.assertEqual(rc, 0, label)
        self.assertEqual((got["docs_only"], got["cargo_skip"], got["cargo_skip_reason"]),
                         (docs_only, skip, reason), label)

    def test_rows(self):
        self.check("tests only", b"scripts/ci/tests/t.py\0", "false", "true",
                   "no-rust-observable-paths " + V)
        self.check("two paths", b"docs/a.md\0scripts/ci/tests/t.py\0", "false", "true",
                   "no-rust-observable-paths " + V)
        self.check("empty input", b"", "false", "false", "empty-diff-fail-closed " + V)
        self.check("truncated list (no final NUL)", b"docs/a.md\0docs/b", "false", "false",
                   "truncated-list-fail-closed " + V)
        self.check("newline in a name stays one path", b"docs/a\nb.md\0", "false", "false",
                   "odd-path-fail-closed docs/a?b.md " + V)
        self.check("bytes that are not UTF-8", b"docs/\xff.md\0", "false", "false",
                   "odd-path-fail-closed docs/?.md " + V)
        self.check("rust path", b"docs/a.md\0src/x.rs\0", "false", "false",
                   "rust-observable-path src/x.rs " + V)

    def test_a_hundred_fifty_thousand_paths_are_refused(self):
        data = b"".join(b"docs/f%06d.md\0" % i for i in range(150000)) + b"src/z.rs\0"
        self.check("over the cap", data, "false", "false",
                   "path-count-over-cap-fail-closed 150001>%d %s" % (MAX_PATHS, V))

    def test_unreadable_base_fails_closed_with_the_bare_reason(self):
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--repo", str(self.work), "--base",
             "0123456789012345678901234567890123456789", "--rules",
             str(IMPACT_DIR / "rules.json")],
            capture_output=True, text=True, timeout=TIMEOUT_S, cwd=str(self.work))
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.splitlines(),
                         ["docs_only=false", "cargo_skip=false",
                          "cargo_skip_reason=classifier-error-fail-closed"])

    def test_git_lists_both_sides_of_a_rename(self):
        (self.work / "docs").mkdir()
        (self.work / "docs" / "a.md").write_text("a\n")
        run_git(self.work, "add", "docs/a.md")
        run_git(self.work, "commit", "-q", "-m", "docs")
        base = run_git(self.work, "rev-parse", "HEAD")
        (self.work / "src").mkdir()
        run_git(self.work, "mv", "docs/a.md", "src/a.rs")
        run_git(self.work, "commit", "-q", "-m", "rename")
        got = cargo_skip.diff_paths(self.work, base, "HEAD")
        self.assertEqual(sorted(got), ["docs/a.md", "src/a.rs"])


class CoverageClassifyRuns(unittest.TestCase):
    """The coverage.yml cls block, extracted and run against git fixtures."""

    BASE_FILES = {
        "src/lib.rs": "fn main() {}\n",
        "docs/a.md": "# a\n",
        "README.md": "# r\n",
        "coverage/README.md": "# c\n",
        "scripts/ci/tests/t.py": "# t\n",
    }
    IMPACT_FILES = ("__init__.py", "common.py", "cargo_skip.py", "rules.json")

    @classmethod
    def setUpClass(cls):
        cls.body = run_body(find_step("classify", "- id: cls"))

    def setUp(self):
        self.work = scratch_dir()
        self.repo = self.work / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "-q", "-b", "main")

    def tearDown(self):
        shutil.rmtree(str(self.work), ignore_errors=True)

    def commit_base(self, with_impact=True):
        for rel, text in self.BASE_FILES.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        if with_impact:
            target = self.repo / "scripts" / "ci" / "impact"
            target.mkdir(parents=True, exist_ok=True)
            for name in self.IMPACT_FILES:
                shutil.copy(str(IMPACT_DIR / name), str(target / name))
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-q", "-m", "base")
        return run_git(self.repo, "rev-parse", "HEAD")

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message="change"):
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-q", "-m", message)

    def failing_diff_path(self):
        """PATH whose `git diff` exits 129 and whose other git verbs run as usual."""
        real = shutil.which("git")
        self.assertIsNotNone(real)
        shim_dir = self.work / "shim"
        shim_dir.mkdir(exist_ok=True)
        shim = shim_dir / "git"
        shim.write_text("#!%s\nimport os\nimport sys\n"
                        "if sys.argv[1:2] == [\"diff\"]:\n    sys.exit(129)\n"
                        "os.execv(%r, [%r] + sys.argv[1:])\n" % (sys.executable, real, real))
        shim.chmod(0o755)
        return str(shim_dir) + os.pathsep + os.environ.get("PATH", "")

    def run_cls(self, base, event="pull_request", base_ref=PR_BASE_REF, path=None):
        script = self.work / "cls.sh"
        script.write_text(self.body)
        out = self.work / "gh_output"
        out.write_text("")
        temp = self.work / "rt"
        temp.mkdir(exist_ok=True)
        env = base_env({
            "GITHUB_OUTPUT": str(out), "RUNNER_TEMP": str(temp),
            "COV_EVENT_NAME": event, "COV_BASE_REF": base_ref,
            "COV_PR_BASE_SHA": base, "COV_PUSH_BEFORE": "",
            "HOME": str(self.work), "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull})
        if path is not None:
            env["PATH"] = path
        res = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
                             cwd=str(self.repo), env=env, capture_output=True, text=True,
                             timeout=TIMEOUT_S)
        values = {}
        for line in out.read_text().splitlines():
            key, _, value = line.partition("=")
            values[key] = value
        return values, res.stdout

    def expect(self, label, values, docs_only, skip, reason):
        self.assertEqual(
            (values.get("docs_only"), values.get("cargo_skip"), values.get("cargo_skip_reason")),
            (docs_only, skip, reason), label)

    def test_block_has_no_inline_expression(self):
        self.assertNotIn("${{", self.body,
                         "event data reaches the script through env, never inline")

    def test_tests_only_short_circuits_with_a_reason_line(self):
        base = self.commit_base()
        self.write("scripts/ci/tests/t.py", "# changed\n")
        self.commit()
        values, stdout = self.run_cls(base)
        self.expect("tests only (PR 9775 shape)", values, "false", "true",
                    "no-rust-observable-paths " + V)
        notices = [ln for ln in stdout.splitlines() if ln.startswith("::notice::")]
        self.assertEqual(len(notices), 1, stdout)
        self.assertIn("no-rust-observable-paths " + V, notices[0])
        self.assertIn("skipping", notices[0])

    def test_docs_only_keeps_its_reason(self):
        base = self.commit_base()
        self.write("docs/a.md", "# changed\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("docs only", values, "true", "true", "docs-only " + V)

    def test_rename_into_src_runs(self):
        base = self.commit_base()
        run_git(self.repo, "mv", "docs/a.md", "src/a.rs")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("rename into src", values, "false", "false",
                    "rust-observable-path src/a.rs " + V)

    def test_rename_out_of_src_runs(self):
        base = self.commit_base()
        run_git(self.repo, "mv", "src/lib.rs", "docs/lib.md")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("rename out of src", values, "false", "false",
                    "rust-observable-path src/lib.rs " + V)

    def test_a_newline_in_a_path_runs_with_the_odd_path_reason(self):
        base = self.commit_base()
        self.write("docs/a\nb.md", "x\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("newline name", values, "false", "false",
                    "odd-path-fail-closed docs/a?b.md " + V)

    def test_a_workflow_edit_runs(self):
        base = self.commit_base()
        self.write(".github/workflows/coverage.yml", "name: x\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("workflow edit", values, "false", "false",
                    "classifier-or-workflow-edited-fail-closed")

    def test_markdown_under_coverage_runs(self):
        base = self.commit_base()
        self.write("coverage/README.md", "# changed\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("coverage markdown", values, "false", "false",
                    "rust-observable-path coverage/README.md " + V)

    def test_the_whole_pr_diff_decides_not_the_last_push(self):
        base = self.commit_base()
        self.write("src/lib.rs", "fn main() { let _ = 1; }\n")
        self.commit("code")
        self.write("docs/a.md", "# changed\n")
        self.commit("docs")
        values, _ = self.run_cls(base)
        self.expect("code then docs", values, "false", "false",
                    "rust-observable-path src/lib.rs " + V)

    def test_empty_net_diff_runs(self):
        base = self.commit_base()
        self.write("docs/a.md", "# changed\n")
        self.commit("one")
        run_git(self.repo, "revert", "--no-edit", "HEAD")
        values, _ = self.run_cls(base)
        self.expect("empty net diff", values, "false", "false", "empty-diff-fail-closed")

    def test_an_unreadable_diff_runs_never_an_empty_list(self):
        base = self.commit_base()
        self.write("docs/a.md", "# changed\n")
        self.commit()
        values, out = self.run_cls(base, path=self.failing_diff_path())
        self.expect("git diff fails", values, "false", "false", "diff-unreadable-fail-closed")
        self.assertIn("::notice::coverage RUN (diff-unreadable-fail-closed)", out)

    def test_unresolvable_base_runs(self):
        self.commit_base()
        values, _ = self.run_cls("0" * 40)
        self.expect("zero base", values, "false", "false", "base-unresolvable-full-ci")
        values, _ = self.run_cls("1234567890123456789012345678901234567890")
        self.expect("unknown base", values, "false", "false", "base-unresolvable-full-ci")

    def test_merge_group_runs_even_on_a_docs_diff(self):
        base = self.commit_base()
        self.write("docs/a.md", "# changed\n")
        self.commit()
        values, _ = self.run_cls(base, event="merge_group")
        self.expect("merge group", values, "false", "false", "merge-group-full-ci")

    def test_protected_base_runs_even_on_a_tests_diff(self):
        base = self.commit_base()
        self.write("scripts/ci/tests/t.py", "# changed\n")
        self.commit()
        for ref in ("main", "develop", "release/v1.0.0"):
            values, _ = self.run_cls(base, base_ref=ref)
            self.expect("base " + ref, values, "false", "false",
                        "protected-base-full-ci " + V)

    def test_a_base_without_the_classifier_runs(self):
        base = self.commit_base(with_impact=False)
        self.write("docs/a.md", "# changed\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("no trusted classifier", values, "false", "false",
                    "trusted-classifier-missing-in-base-fail-closed")

    def planted_answer(self, label, docs_only, skip, reason):
        """Commit a trusted decider that prints this exact answer; return a docs-edit result."""
        planted = self.repo / "scripts" / "ci" / "impact" / "cargo_skip.py"
        text = "docs_only=%s\ncargo_skip=%s\ncargo_skip_reason=%s\n" % (docs_only, skip, reason)
        planted.write_text("import sys\nsys.stdout.write(%r)\n" % text)
        self.commit("trusted decider " + label)
        base = run_git(self.repo, "rev-parse", "HEAD")
        self.write("docs/a.md", "# changed %s\n" % label)
        self.commit()
        values, _ = self.run_cls(base)
        return values

    def test_a_decider_answer_of_the_wrong_shape_runs(self):
        """Each of the two values is checked on its own against {true, false}."""
        self.commit_base()
        run = ("false", "false", FAIL_CLOSED)
        rows = [
            ("docs true, skip false", "true", "false", "planted"),
            ("docs valid, skip invalid", "true", "maybe", "planted"),
            ("docs invalid, skip valid true", "maybe", "true", "planted"),
            ("docs valid false, skip invalid", "false", "maybe", "planted"),
            ("docs invalid, skip valid false", "maybe", "false", "planted"),
            ("split values falset + rue", "falset", "rue", "planted"),
            ("split values truet + rue", "truet", "rue", "planted"),
            ("split values tru + efalse", "tru", "efalse", "planted"),
            ("both empty", "", "", "planted"),
            ("docs empty", "", "true", "planted"),
            ("skip empty", "true", "", "planted"),
            ("docs trailing blank", "true ", "true", "planted"),
            ("docs leading blank", " true", "true", "planted"),
            ("skip trailing blank", "true", "true ", "planted"),
            ("skip tab", "false", "\t", "planted"),
            ("docs carriage return", "true\r", "true", "planted"),
            ("skip carriage return", "true", "true\r", "planted"),
            ("newline inside docs", "tr\nue", "true", "planted"),
            ("newline inside skip", "true", "tr\nue", "planted"),
            ("upper case", "TRUE", "TRUE", "planted"),
        ]
        for label, docs_only, skip, reason in rows:
            with self.subTest(label):
                values = self.planted_answer(label, docs_only, skip, reason)
                self.expect(label, values, *run)

    def test_a_valid_decider_answer_passes_through_with_its_reason(self):
        self.commit_base()
        rows = [
            ("false false", "false", "false", "planted-run"),
            ("false true", "false", "true", "planted-skip"),
            ("true true", "true", "true", "planted-docs"),
        ]
        for label, docs_only, skip, reason in rows:
            with self.subTest(label):
                values = self.planted_answer(label, docs_only, skip, reason)
                self.expect(label, values, docs_only, skip, reason)

    def test_an_empty_reason_never_yields_a_success_without_a_reason_line(self):
        self.commit_base()
        run = ("false", "false", FAIL_CLOSED)
        rows = [
            ("run with an empty reason", "false", "false", ""),
            ("skip with an empty reason", "false", "true", ""),
            ("docs skip with an empty reason", "true", "true", ""),
            ("skip with control characters only", "true", "true", "\x01\x02"),
            ("skip with a bare DEL", "false", "true", "\x7f"),
        ]
        for label, docs_only, skip, reason in rows:
            with self.subTest(label):
                values = self.planted_answer(label, docs_only, skip, reason)
                self.expect(label, values, *run)

    def planted_files(self, files, label, rel_path):
        """Commit these files as the trusted impact tree, then edit `rel_path` in the PR."""
        target = self.repo / "scripts" / "ci" / "impact"
        for name, data in files.items():
            (target / name).write_bytes(data)
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-q", "--allow-empty", "-m", "trusted impact tree " + label)
        base = run_git(self.repo, "rev-parse", "HEAD")
        self.write(rel_path, "# changed %s\n" % label)
        self.commit()
        values, _ = self.run_cls(base)
        return values

    @staticmethod
    def chain_tip_files():
        """The impact files of the chain tip, or None when the objects are not here."""
        out = {}
        for name in CoverageClassifyRuns.IMPACT_FILES:
            res = subprocess.run(
                ["git", "-C", str(REPO), "show", "%s:scripts/ci/impact/%s" % (CHAIN_TIP, name)],
                capture_output=True, timeout=TIMEOUT_S, env=base_env())
            if res.returncode != 0:
                return None
            out[name] = res.stdout
        return out

    def test_a_decider_that_does_not_answer_in_the_new_shape_runs(self):
        """A PR whose merge-base predates #9263 runs the old decider with `--stdin0`.

        Forms used. Stand-in rows (a) to (d) always run: they are the minimal
        deciders that do not answer in the new shape and they do not depend on
        the repository history. The REAL row reads the decider of the chain tip
        (CHAIN_TIP) with `git show` from the repository this test runs in; it
        runs when those objects are readable and its rows are left out
        otherwise (the stand-ins still assert the same invariant), because a
        shallow checkout cannot read them: the coverage.yml checkout fetches
        with `fetch-depth: 2`. Measured on this clone: the tip
        objects are readable and its decider rejects `--stdin0` with exit 2
        (the same outcome as row (a)).

        Invariant: every such decider ends as a RUN with the exact reason
        `classifier-error-fail-closed`, never a skip, on a docs-only diff and on
        a tests-only diff. The expected column is written by hand.
        """
        self.commit_base()
        argparse_old = (
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--stdin', action='store_true')\n"
            "p.add_argument('--rules')\n"
            "p.add_argument('--event-name')\n"
            "p.add_argument('--base-ref')\n"
            "p.parse_args()\n"
            "print('docs_only=true')\nprint('cargo_skip=true')\n"
            "print('cargo_skip_reason=old-skip')\n").encode()
        silent = b"import sys\n"
        old_shape = b"print('docs_only=true')\n"
        exit_one = (b"import sys\nprint('docs_only=true')\nprint('cargo_skip=true')\n"
                    b"print('cargo_skip_reason=old-skip')\nsys.exit(1)\n")
        deciders = [
            ("(a) rejects --stdin0 with exit 2", {"cargo_skip.py": argparse_old}),
            ("(b) exit 0, prints nothing", {"cargo_skip.py": silent}),
            ("(c) exit 0, old shape docs_only=true only", {"cargo_skip.py": old_shape}),
            ("(d) exit 1 after a full skip answer", {"cargo_skip.py": exit_one}),
        ]
        tip = self.chain_tip_files()
        if tip is not None:
            deciders.append(("REAL chain tip decider", tip))
        diffs = [("docs only", "docs/a.md"), ("tests only", "scripts/ci/tests/x.py")]
        for dlabel, files in deciders:
            for flabel, rel in diffs:
                label = "%s | %s" % (dlabel, flabel)
                with self.subTest(label):
                    values = self.planted_files(files, label, rel)
                    self.expect(label, values, "false", "false", FAIL_CLOSED)

    def test_a_pr_cannot_replace_its_own_classifier(self):
        base = self.commit_base()
        planted = self.repo / "scripts" / "ci" / "impact" / "cargo_skip.py"
        planted.write_text('print("docs_only=true")\nprint("cargo_skip=true")\n'
                           'print("cargo_skip_reason=planted")\n')
        self.write("src/lib.rs", "fn main() { let _ = 2; }\n")
        self.commit()
        values, _ = self.run_cls(base)
        self.expect("planted decider", values, "false", "false",
                    "classifier-or-workflow-edited-fail-closed")


class CoverageJobWiring(unittest.TestCase):
    """Invariant 2 and 3: the same job-level gate, names unchanged, the final step."""

    def test_required_context_names_are_unchanged(self):
        text = WORKFLOW.read_text()
        self.assertIn("    name: Coverage classify (docs-only short-circuit)\n", text)
        self.assertIn("    name: Per-Module Coverage Thresholds\n", text)

    def test_classify_outputs_carry_the_verdict_and_its_reason(self):
        text = "\n".join(job_lines("classify"))
        for key in ("docs_only", "cargo_skip", "cargo_skip_reason"):
            self.assertIn("      %s: ${{ steps.cls.outputs.%s }}" % (key, key), text)

    def test_the_job_level_gate_reads_cargo_skip(self):
        lines = [ln for ln in job_lines("per-module-thresholds") if ln.startswith("    if:")]
        self.assertEqual(lines, ["    if: needs.classify.outputs.cargo_skip != 'true'"])

    def test_classify_has_no_job_level_if(self):
        self.assertEqual([ln for ln in job_lines("classify") if ln.startswith("    if:")], [])

    def test_the_sweep_step_has_an_id_and_a_recorded_start(self):
        steps = steps_of("per-module-thresholds")
        names = [step_first(s) for s in steps]
        # The name stays the first line: test_check_pg_preflight_workflows_9235
        # locates the sweep step by "      - name: Generate coverage JSON".
        sweep = names.index("- name: Generate coverage JSON") if "- name: Generate coverage JSON" in names else -1
        self.assertGreaterEqual(sweep, 1, names)
        self.assertTrue(any(ln.strip() == "id: sweep" for ln in steps[sweep]))
        start = steps[sweep - 1]
        self.assertIn('echo "COV_SWEEP_START=$(date +%s)" >> "$GITHUB_ENV"', run_body(start))

    def test_the_final_step_is_last_and_runs_on_cancel_or_failure(self):
        steps = steps_of("per-module-thresholds")
        last = steps[-1]
        self.assertEqual(step_first(last), "- name: Name the coverage sweep end (#9263)")
        self.assertEqual(step_if(last), "cancelled() || failure()")

    def final_step_run(self, env):
        body = run_body(steps_of("per-module-thresholds")[-1])
        res = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", body],
                             capture_output=True, text=True, timeout=TIMEOUT_S, env=base_env(env))
        return res.returncode, res.stdout, res.stderr

    def job_limit(self):
        limit = None
        for ln in job_lines("per-module-thresholds"):
            found = re.match(r"^    timeout-minutes:\s*(\d+)\s*$", ln)
            if found:
                limit = found.group(1)
        return limit

    def check_line(self, label, env, expected):
        env = dict(env)
        env.update({"GITHUB_TOKEN": CANARY_A, "SECRET_CANARY": CANARY_B})
        rc, stdout, stderr = self.final_step_run(env)
        self.assertEqual(rc, 0, label)
        self.assertEqual(stdout.splitlines(), [expected], label)
        self.assertNotIn(CANARY_MARK, stdout + stderr, label)

    def test_the_end_line_is_chosen_from_the_sweep_and_later_step_outcomes(self):
        """One row per (sweep outcome, later-step outcome); hand-written lines."""
        limit = self.job_limit()
        self.assertEqual(limit, "110")
        head = 'step "Generate coverage JSON" '
        err = "::error title=Coverage sweep ended::" + head
        ended = "elapsed=3 min (job limit 110 min)"
        sweep_lines = {
            "success": {
                "success": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=success",
                "failure": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=failure",
                "cancelled": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=cancelled",
                "skipped": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=skipped",
                "": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=unknown",
                "x\n::error::forged": "::notice title=Coverage sweep finished::" + head + "outcome=success elapsed=3 min; Enforce per-module thresholds outcome=unknown",
            },
            "failure": {g: err + "outcome=failure " + ended for g in
                        ("success", "failure", "cancelled", "skipped", "", "x\n::error::forged")},
            "cancelled": {g: err + "outcome=cancelled " + ended for g in
                          ("success", "failure", "cancelled", "skipped", "", "x\n::error::forged")},
            "skipped": {g: "::notice title=Coverage sweep not run::" + head + "outcome=skipped (an earlier step ended the job)"
                        for g in ("success", "failure", "cancelled", "skipped", "", "x\n::error::forged")},
            "": {g: err + "outcome=unknown " + ended for g in
                 ("success", "failure", "cancelled", "skipped", "", "x\n::error::forged")},
            "x\n::error::forged": {g: err + "outcome=unknown " + ended for g in
                                   ("success", "failure", "cancelled", "skipped", "", "x\n::error::forged")},
        }
        for sweep, by_gate in sweep_lines.items():
            for gate, expected in by_gate.items():
                with self.subTest(sweep=sweep, gate=gate):
                    env = {"COV_SWEEP_START": "1000000", "COV_SWEEP_END": "1000185",
                           "SWEEP_OUTCOME": sweep, "GATE_OUTCOME": gate,
                           "COV_JOB_LIMIT_MIN": limit}
                    self.check_line("%r/%r" % (sweep, gate), env, expected)

    def test_a_threshold_failure_after_a_good_sweep_never_prints_the_ended_line(self):
        env = {"COV_SWEEP_START": "1000000", "COV_SWEEP_END": "1003540",
               "SWEEP_OUTCOME": "success", "GATE_OUTCOME": "failure",
               "COV_JOB_LIMIT_MIN": self.job_limit()}
        rc, stdout, _ = self.final_step_run(env)
        self.assertEqual(rc, 0)
        self.assertNotIn("Coverage sweep ended", stdout)
        self.assertNotIn("::error", stdout)

    def test_elapsed_is_the_sweep_alone(self):
        limit = self.job_limit()
        head = '::error title=Coverage sweep ended::step "Generate coverage JSON" outcome=failure elapsed=%s (job limit 110 min)'
        rows = [
            ("59 minutes", "1000000", "1003545", "59 min"),
            ("zero minutes", "1000000", "1000059", "0 min"),
            ("never started", "", "1003545", "not-started"),
            ("start not a number", "abc", "1003545", "unknown"),
            ("end missing", "1000000", "", "unknown"),
            ("end not a number", "1000000", "abc", "unknown"),
            ("end before start", "1000000", "999999", "unknown"),
            ("thirteen digit start", "1000000000000", "1000000000001", "unknown"),
        ]
        for label, start, end, elapsed in rows:
            with self.subTest(label):
                env = {"COV_SWEEP_START": start, "COV_SWEEP_END": end,
                       "SWEEP_OUTCOME": "failure", "GATE_OUTCOME": "skipped",
                       "COV_JOB_LIMIT_MIN": limit}
                self.check_line(label, env, head % elapsed)

    def test_the_job_limit_is_read_from_one_place(self):
        """No fallback default; every COV_JOB_LIMIT_MIN equals timeout-minutes."""
        limit = self.job_limit()
        self.assertIsNotNone(limit)
        text = "\n".join(job_lines("per-module-thresholds"))
        self.assertEqual(re.findall(r"COV_JOB_LIMIT_MIN:?-[^}\s]", text), [],
                         "a default value for the job limit")
        values = re.findall(r'COV_JOB_LIMIT_MIN:\s*"?(\d+)"?', text)
        self.assertEqual(values, [limit])
        self.assertEqual(re.findall(r"\b%s\b" % limit, run_body(steps_of("per-module-thresholds")[-1])), [])
        header = '::error title=Coverage sweep ended::step "Generate coverage JSON" outcome=failure elapsed=1 min (job limit %s min)'
        env = {"COV_SWEEP_START": "1000000", "COV_SWEEP_END": "1000060",
               "SWEEP_OUTCOME": "failure", "GATE_OUTCOME": "skipped"}
        self.check_line("limit unset", env, header % "unknown")

    def test_the_sweep_end_is_recorded_right_after_the_sweep(self):
        steps = steps_of("per-module-thresholds")
        names = [step_first(s) for s in steps]
        sweep = names.index("- name: Generate coverage JSON")
        record = steps[sweep + 1]
        self.assertEqual(step_first(record), "- name: Record the coverage sweep end (#9263)")
        self.assertEqual(step_if(record), "always()")
        self.assertIn('echo "COV_SWEEP_END=$(date +%s)" >> "$GITHUB_ENV"', run_body(record))

    def test_the_end_step_reads_the_gate_outcome_and_the_sweep_outcome(self):
        last = steps_of("per-module-thresholds")[-1]
        text = "\n".join(last)
        self.assertIn("SWEEP_OUTCOME: ${{ steps.sweep.outcome }}", text)
        self.assertIn("GATE_OUTCOME: ${{ steps.thresholds.outcome }}", text)

    def test_the_end_step_comment_states_the_runner_loss(self):
        lines = WORKFLOW.read_text().splitlines()
        at = lines.index("      - name: Name the coverage sweep end (#9263)")
        block = []
        for line in reversed(lines[:at]):
            if not line.startswith("      #"):
                break
            block.append(line)
        comment = " ".join(ln.strip().lstrip("#").strip() for ln in reversed(block))
        comment = " ".join(comment.split())
        self.assertIn("lost its runner", comment)
        self.assertIn("#9792", comment)
        self.assertIn("runs no later step", comment)
        self.assertNotIn("ended on the job time limit", comment)
        self.assertNotIn("time limit cancels it", comment)


if __name__ == "__main__":
    unittest.main()
