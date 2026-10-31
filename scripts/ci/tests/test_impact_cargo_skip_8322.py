"""Guard for the cargo_skip classify output (#8322, 3-agent vote 6def5ab6).

Four properties:

1. Verdicts: the classifier returns the expected cargo_skip / docs_only values
   for synthetic diffs (scripts/ci/tests-only, docs-only, CLAUDE.md-only,
   scripts/check-*.py-only, src-only, empty, Cargo.lock-only and more).
2. Read set: no path a tests/ or src/ Rust file can open (include_str!,
   include_bytes!, fs::read*, read_to_string, Path/PathBuf literals, Command
   arguments, followed scripts) is in the skip set. Offenders are printed.
3. #2494 invariant: no required matrix job carries a job-level `if:`; the
   cargo legs no-op inside steps.
4. Wiring: the `check` and `mobile-cross-compile` jobs consume
   `needs.classify.outputs.cargo_skip` and print one no-op line.
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts" / "ci"))

from impact import cargo_skip, common, read_set  # noqa: E402

CI_YML = REPO / ".github" / "workflows" / "ci.yml"
ALLOWLIST_DIR = REPO / "scripts" / "qc-allowlists"
REQUIRED_GLOB = "required-contexts-*.txt"
NON_DECLARATIVE = ("required-contexts-not-required.txt",
                   "required-contexts-joblevel-if-allow.txt")
CARGO_JOBS = ("check", "mobile-cross-compile")
CLASS_REF = "needs.classify.outputs.cargo_skip"
NOOP_CONDITION = "needs.classify.outputs.cargo_skip == 'true'"
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
SCRIPT = REPO / "scripts" / "ci" / "impact" / "cargo_skip.py"

# (label, changed paths, cargo_skip, docs_only)
CASES = [
    ("scripts/ci/tests-only", ["scripts/ci/tests/test_anything_1.py"], "true", "false"),
    ("scripts/ci/tests plus a new test", ["scripts/ci/tests/a.py", "scripts/ci/tests/b.py"], "true", "false"),
    ("docs-only", ["docs/ADMIN_GUIDE.md"], "true", "true"),
    ("docs plus scripts/ci/tests", ["docs/ADMIN_GUIDE.md", "scripts/ci/tests/a.py"], "true", "false"),
    ("CLAUDE.md-only (read by tests)", ["CLAUDE.md"], "false", "false"),
    ("docs/API_REFERENCE.md-only (read by tests)", ["docs/API_REFERENCE.md"], "false", "false"),
    ("docs/deploy (read by tests)", ["docs/deploy/config.standard.toml"], "false", "false"),
    ("docs/integrations (read by tests)", ["docs/integrations/aider.md"], "false", "false"),
    ("scripts/check-*.py-only", ["scripts/check-claude-md-size.py"], "false", "false"),
    ("scripts/test-*.py-only", ["scripts/test-install-upgrade.py"], "false", "false"),
    ("scripts/*.py-only", ["scripts/anything_new.py"], "false", "false"),
    ("shell script", ["scripts/anything.sh"], "false", "false"),
    ("qc allowlist", ["scripts/qc-allowlists/required-contexts-release.txt"], "false", "false"),
    ("scripts/ci non-test file", ["scripts/ci/load_gate.py"], "false", "false"),
    ("selector rules", ["scripts/ci/impact/rules.json"], "false", "false"),
    ("workflow", [".github/workflows/ci.yml"], "false", "false"),
    ("src-only", ["src/lib.rs"], "false", "false"),
    ("tests-only", ["tests/doc_claims_integrity.rs"], "false", "false"),
    ("empty diff", [], "false", "false"),
    ("Cargo.lock-only", ["Cargo.lock"], "false", "false"),
    ("Cargo.toml-only", ["Cargo.toml"], "false", "false"),
    ("docs plus src", ["docs/ADMIN_GUIDE.md", "src/lib.rs"], "false", "false"),
    ("markdown under src", ["src/some_module/NOTES.md"], "false", "false"),
    ("markdown elsewhere", ["sdk/typescript/CHANGELOG.md"], "true", "true"),
    ("Dockerfile", ["Dockerfile"], "false", "false"),
    ("migration", ["migrations/0001_init.sql"], "false", "false"),
]


def job_blocks(text):
    """Return {job key: its lines} for the top-level jobs of a workflow."""
    blocks = {}
    current = None
    in_jobs = False
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^\S", line):
            in_jobs = False
            current = None
        header = JOB_HEADER.match(line) if in_jobs else None
        if header:
            current = header.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return blocks


def required_names():
    """Return the declared required status-check names."""
    names = set()
    for path in sorted(ALLOWLIST_DIR.glob(REQUIRED_GLOB)):
        if path.name in NON_DECLARATIVE:
            continue
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                names.add(line)
    return names


def job_name_regex(lines):
    """Return a regex for the job's `name:`, expressions widened, or None."""
    for line in lines:
        match = re.match(r"^    name:\s*(.+?)\s*$", line)
        if match:
            raw = match.group(1).strip("\"'")
            parts = [re.escape(p) for p in EXPRESSION.split(raw)]
            return re.compile("^" + ".+".join(parts) + "$")
    return None


def is_matrix_job(lines):
    """Return True when the job declares strategy.matrix."""
    strategy = False
    for line in lines:
        if re.match(r"^    strategy:\s*$", line):
            strategy = True
        elif strategy and re.match(r"^      matrix:", line):
            return True
        elif strategy and re.match(r"^    \S", line):
            strategy = False
    return False


def has_job_level_if(lines):
    """Return True when the job has a 4-space `if:` key."""
    return any(re.match(r"^    if:", line) for line in lines)


class CargoSkipVerdicts(unittest.TestCase):
    """(i) the classifier on synthetic diffs."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()

    def test_verdicts(self):
        for label, paths, want_skip, want_docs in CASES:
            with self.subTest(label):
                got = cargo_skip.classify(self.section, paths)
                self.assertEqual(
                    (got["cargo_skip"], got["docs_only"]), (want_skip, want_docs),
                    "%s: cargo_skip/docs_only expected %s/%s, got %s/%s (%s)"
                    % (label, want_skip, want_docs, got["cargo_skip"],
                       got["docs_only"], got["cargo_skip_reason"]))

    def test_cargo_skip_is_superset_of_docs_only(self):
        for label, paths, _, _ in CASES:
            got = cargo_skip.classify(self.section, paths)
            if got["docs_only"] == "true":
                self.assertEqual(got["cargo_skip"], "true", label)

    def test_reason_is_one_line_and_names_the_rules_version(self):
        for label, paths, _, _ in CASES:
            reason = cargo_skip.classify(self.section, paths)["cargo_skip_reason"]
            self.assertNotIn("\n", reason, label)
            self.assertIn("cargo_skip-rules-v%s" % self.section["version"], reason, label)

    def test_cli_prints_the_three_output_lines(self):
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--stdin"],
            input="scripts/ci/tests/test_anything_1.py\n",
            capture_output=True, text=True, cwd=str(REPO), timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        lines = res.stdout.splitlines()
        self.assertEqual([ln.split("=", 1)[0] for ln in lines],
                         ["docs_only", "cargo_skip", "cargo_skip_reason"])
        self.assertEqual(lines[1], "cargo_skip=true")

    def test_cli_fails_closed_on_unreadable_rules(self):
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--stdin", "--rules",
             str(REPO / "scripts" / "ci" / "impact" / "no-such-rules.json")],
            input="docs/ADMIN_GUIDE.md\n", capture_output=True, text=True,
            cwd=str(REPO), timeout=60)
        self.assertEqual(res.returncode, 0)
        self.assertIn("cargo_skip=false", res.stdout)
        self.assertIn("docs_only=false", res.stdout)

    def test_cli_fails_closed_on_empty_input(self):
        res = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--stdin"], input="",
            capture_output=True, text=True, cwd=str(REPO), timeout=60)
        self.assertIn("cargo_skip=false", res.stdout)
        self.assertIn("docs_only=false", res.stdout)


class SkipSetAgainstReadSet(unittest.TestCase):
    """(ii) no tests/ or src/ path literal reaches the skip set."""

    @classmethod
    def setUpClass(cls):
        cls.section = cargo_skip.load_section()
        cls.tracked = read_set.tracked_files(REPO)
        cls.referenced = read_set.referenced_paths(
            REPO, cls.tracked, read_set.guarded_map(cls.section))

    def test_scanner_finds_the_known_readers(self):
        for known in ("CLAUDE.md", "docs/API_REFERENCE.md", "README.md"):
            self.assertIn(known, self.referenced,
                          "scanner lost a known test-read file: %s" % known)

    def test_no_read_path_is_in_the_skip_set(self):
        offenders = sorted(
            "%s (read by %s)" % (path, source)
            for path, source in self.referenced.items()
            if cargo_skip.is_skippable(self.section, path)
            or cargo_skip.is_doc(self.section, path))
        self.assertEqual(
            offenders, [],
            "paths opened by tests/src are inside the cargo_skip set:\n  "
            + "\n  ".join(offenders))

    def test_skip_set_is_not_vacuous(self):
        skippable = [p for p in self.tracked if cargo_skip.is_skippable(self.section, p)]
        self.assertIn("scripts/ci/tests/test_impact_select.py", skippable)
        self.assertGreater(
            len([p for p in skippable if p.startswith("docs/")]), 100,
            "the docs part of the skip set collapsed")

    def test_never_skip_families_are_never_skippable(self):
        for path in self.tracked:
            if path.startswith(("src/", "tests/", "migrations/", ".github/",
                                "scripts/qc-allowlists/", "scripts/ci/impact/")) \
                    or path in ("Cargo.toml", "Cargo.lock", "build.rs") \
                    or path.endswith(".sh") \
                    or re.match(r"^scripts/[^/]+\.py$", path):
                self.assertFalse(cargo_skip.is_skippable(self.section, path), path)

    def test_every_test_read_glob_matches_a_tracked_file(self):
        for glob in self.section["test_read_globs"]:
            self.assertTrue(
                any(common.match_glob(glob, p) for p in self.tracked),
                "stale test_read_globs entry: %s" % glob)


class RequiredMatrixInvariant(unittest.TestCase):
    """(iii) #2494/#2496: required matrix jobs carry no job-level `if:`."""

    @classmethod
    def setUpClass(cls):
        cls.blocks = job_blocks(CI_YML.read_text())
        cls.required = required_names()

    def test_parser_sees_the_check_matrix_as_required(self):
        lines = self.blocks["check"]
        self.assertTrue(is_matrix_job(lines))
        regex = job_name_regex(lines)
        self.assertTrue(any(regex.match(n) for n in self.required),
                        "no required context matches the check matrix name")

    def test_no_required_matrix_job_has_a_job_level_if(self):
        bad = []
        for key, lines in self.blocks.items():
            if not is_matrix_job(lines):
                continue
            regex = job_name_regex(lines)
            if regex is None or not any(regex.match(n) for n in self.required):
                continue
            if has_job_level_if(lines):
                bad.append(key)
        self.assertEqual(bad, [], "job-level if: on required matrix jobs: %s" % bad)


class CargoLegWiring(unittest.TestCase):
    """(iv) the cargo legs consume cargo_skip and keep their job names."""

    @classmethod
    def setUpClass(cls):
        cls.text = CI_YML.read_text()
        cls.blocks = job_blocks(cls.text)

    def test_classify_declares_the_outputs(self):
        classify = "\n".join(self.blocks["classify"])
        self.assertTrue("cargo_skip: ${{ steps.cls.outputs.cargo_skip }}" in classify, "classify output cargo_skip missing")
        self.assertTrue("cargo_skip_reason: ${{ steps.cls.outputs.cargo_skip_reason }}" in classify, "classify output cargo_skip_reason missing")

    def test_cargo_legs_gate_their_steps_on_cargo_skip(self):
        for key in CARGO_JOBS:
            block = "\n".join(self.blocks[key])
            self.assertTrue(CLASS_REF in block, "%s: no cargo_skip consumer" % key)
            self.assertFalse("needs.classify.outputs.docs_only != 'true'" in block, "%s: still gated on docs_only" % key)
            self.assertTrue(("if: " + NOOP_CONDITION) in block, "%s: no no-op step" % key)

    def test_noop_step_prints_one_line_with_reason_and_version(self):
        for key in CARGO_JOBS:
            block = "\n".join(self.blocks[key])
            self.assertTrue(("if: " + NOOP_CONDITION) in block, "%s: no no-op step" % key)
            noop = block.split("if: " + NOOP_CONDITION, 1)[1].split("\n      - ", 1)[0]
            echoes = re.findall(r"^\s+(?:run: )?echo ", noop, re.M)
            self.assertEqual(len(echoes), 1, "%s: no-op step must print exactly one line" % key)
            self.assertTrue("cargo_skip_reason" in noop, "%s: no-op lacks the reason" % key)

    def test_cargo_legs_have_no_job_level_if(self):
        for key in CARGO_JOBS:
            self.assertFalse(has_job_level_if(self.blocks[key]), key)


if __name__ == "__main__":
    unittest.main()
