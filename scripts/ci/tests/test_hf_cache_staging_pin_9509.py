#!/usr/bin/env python3
"""Pin cells for the one HuggingFace cache staging form (#9509, #9515).

Class: a CI job whose test depends on a prerequisite that no step of the job
provides. Invariant: the job provides the offline embedder cache itself, or
ends in the cache step with its own named error before any test runs, and no
test fetches a model from the network.

These cells pin: the two workflow call sites of scripts/ci/stage_hf_cache.py
(ci.yml `check` job, coverage.yml `per-module-thresholds` job), their order
before the first test step, the offline env on the test step, the absence of
any third staging form, and that no Rust test reaches the model fetch with
offline unset.

Open point (kept open): what filled the model files in the green jobs is not
proven.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_hf_cache_staging_pin_9509.py'
Python 3.12 floor, standard library only.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
COVERAGE = WORKFLOWS / "coverage.yml"
SCRIPT_REL = "scripts/ci/stage_hf_cache.py"
CALL_RE = re.compile(r"python3 -I scripts/ci/stage_hf_cache\.py(?P<args>[^\n]*)")
OFFLINE_LINE = 'AI_MEMORY_EMBED_OFFLINE: "1"'
TEST_STEP = "Run tests (impact-aware)"
CHECK_JOB = "check"
COVERAGE_JOB = "per-module-thresholds"

# Any of these in a workflow or action is a staging form of its own.
STAGING_TOKENS = (
    "snapshot_download",
    "hf_hub_download",
    "huggingface_hub",
    "huggingface-cli",
    "hf download",
)
JOB_ID_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_RE = re.compile(r"^      - (?:name: (?P<name>.*)|uses: .*)$")

# Rust test code that builds the real embedder (not the Mock).
EMBEDDER_CALL_RE = re.compile(r"(?<![A-Za-z0-9_])Embedder::(?:new_local|new)\(\)")
FN_START_RE = re.compile(r"^\s*(?:pub(?:\([a-z]+\))? )?(?:async )?fn [A-Za-z0-9_]+", re.M)
PREREQ_MARKERS = ("AI_MEMORY_EMBED_OFFLINE", "HF_HUB_OFFLINE", "load_from_fallback")
RUST_TEST_GLOBS = ("tests/*.rs", "src/handlers/tests.rs", "src/embeddings.rs")


def job_lines(path: Path, job: str) -> list[str]:
    """Lines of one job of a workflow file (job ids at two-space indent)."""
    lines = path.read_text().split("\n")
    out: list[str] = []
    inside = False
    in_jobs = False
    for line in lines:
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        match = JOB_ID_RE.match(line)
        if match:
            if inside:
                break
            inside = match.group(1) == job
        if inside:
            out.append(line)
    return out


def steps(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Split job lines into (step name, step lines); `uses:` steps are named by it."""
    result: list[tuple[str, list[str]]] = []
    for line in lines:
        match = STEP_RE.match(line)
        if match:
            name = match.group("name") or line.strip()[2:]
            result.append((name.strip(), [line]))
        elif result:
            result[-1][1].append(line)
    return result


def code_lines(text: str) -> str:
    """Drop whole-line comments so prose that names a token is not a call."""
    return "\n".join(
        line for line in text.split("\n") if not line.lstrip().startswith(("#", "//"))
    )


class CallSites(unittest.TestCase):
    def check_calls(self):
        return [(n, "\n".join(b)) for n, b in steps(job_lines(CI, CHECK_JOB))]

    def cov_calls(self):
        return [(n, "\n".join(b)) for n, b in steps(job_lines(COVERAGE, COVERAGE_JOB))]

    def test_jobs_found(self):
        self.assertGreater(len(self.check_calls()), 20)
        self.assertGreater(len(self.cov_calls()), 5)

    def staging_steps(self, pairs):
        return [(i, n, b) for i, (n, b) in enumerate(pairs) if CALL_RE.search(code_lines(b))]

    def test_ci_check_job_has_exactly_one_call_with_embedder_set(self):
        found = self.staging_steps(self.check_calls())
        self.assertEqual(len(found), 1, [n for _, n, _ in found])
        match = CALL_RE.search(code_lines(found[0][2]))
        self.assertIn("--models embedder", match.group("args"))

    def test_ci_call_is_before_the_first_test_step_and_has_its_cache_step(self):
        pairs = self.check_calls()
        names = [n for n, _ in pairs]
        call_idx = self.staging_steps(pairs)[0][0]
        test_idx = names.index(TEST_STEP)
        self.assertLess(call_idx, test_idx)
        cache_idx = [i for i, (n, b) in enumerate(pairs) if "actions/cache@" in b and "huggingface" in b]
        self.assertEqual(len(cache_idx), 1)
        self.assertLess(cache_idx[0], call_idx)
        self.assertIn("path: ~/.cache/huggingface", pairs[cache_idx[0]][1])

    def test_ci_staging_step_runs_when_the_test_step_runs(self):
        pairs = self.check_calls()
        call = dict((n, b) for n, b in pairs)[self.staging_steps(pairs)[0][1]]
        test = dict(pairs)[TEST_STEP]
        cond = lambda b: re.search(r"^\s+if: (.*)$", b, re.M).group(1).strip()  # noqa: E731
        self.assertEqual(cond(call), cond(test))

    def test_staging_step_uses_no_secret_or_token(self):
        for pairs in (self.check_calls(), self.cov_calls()):
            for _, name, body in self.staging_steps(pairs):
                with self.subTest(step=name):
                    self.assertNotRegex(body, r"secrets\.|GITHUB_TOKEN|HF_TOKEN|token:")

    def test_test_step_runs_offline(self):
        body = dict(self.check_calls())[TEST_STEP]
        env_block = body.split("        env:", 1)[1].split("        run:", 1)[0]
        self.assertIn(OFFLINE_LINE, env_block)

    def test_coverage_job_has_exactly_one_call_with_all_set(self):
        found = self.staging_steps(self.cov_calls())
        self.assertEqual(len(found), 1, [n for _, n, _ in found])
        self.assertIn("--models all", CALL_RE.search(code_lines(found[0][2])).group("args"))

    def test_coverage_call_is_before_the_first_cargo_llvm_cov_step(self):
        pairs = self.cov_calls()
        call_idx = self.staging_steps(pairs)[0][0]
        first_cov = next(i for i, (_, b) in enumerate(pairs) if "cargo llvm-cov" in b or "cargo-llvm-cov" in b)
        self.assertLess(call_idx, first_cov)

    def test_both_workflows_name_the_script_exactly_once_per_job(self):
        self.assertTrue((ROOT / SCRIPT_REL).is_file())
        for path in (CI, COVERAGE):
            self.assertEqual(code_lines(path.read_text()).count(SCRIPT_REL), 1, path.name)


class NoThirdForm(unittest.TestCase):
    def workflow_files(self):
        files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        files += sorted((ROOT / ".github" / "actions").glob("**/action.y*ml"))
        return files

    def test_no_staging_token_in_any_workflow_or_action(self):
        offenders = []
        for path in self.workflow_files():
            text = code_lines(path.read_text())
            for token in STAGING_TOKENS:
                if token in text:
                    offenders.append(f"{path.name}: {token}")
        self.assertEqual(offenders, [])

    def test_only_two_files_call_the_script(self):
        callers = [
            p.name for p in self.workflow_files() if SCRIPT_REL in code_lines(p.read_text())
        ]
        self.assertEqual(sorted(callers), ["ci.yml", "coverage.yml"])

    def test_no_other_hf_cache_restore_step(self):
        offenders = []
        for path in self.workflow_files():
            for _, body in steps(path.read_text().split("\n")):
                text = "\n".join(body)
                if "actions/cache@" in text and "huggingface" in code_lines(text):
                    offenders.append(path.name)
        self.assertEqual(sorted(offenders), ["ci.yml", "coverage.yml"])


class NoTestFetchesWithOfflineUnset(unittest.TestCase):
    """A Rust test that builds the real embedder must own the offline knob or
    probe the staged cache (the named prerequisite failure) first, so it can
    never reach `download_via_hf_hub` with the network open (#9515)."""

    def rust_files(self):
        files: list[Path] = []
        for pattern in RUST_TEST_GLOBS:
            files += sorted(ROOT.glob(pattern))
        return files

    def test_scan_sees_the_known_callers(self):
        hits = []
        for path in self.rust_files():
            for fn_body in self.fn_bodies(path):
                if EMBEDDER_CALL_RE.search(fn_body[1]):
                    hits.append(path.name)
        self.assertGreaterEqual(len(set(hits)), 4, hits)

    @staticmethod
    def fn_bodies(path: Path):
        text = code_lines(path.read_text())
        starts = [m.start() for m in FN_START_RE.finditer(text)] + [len(text)]
        for a, b in zip(starts, starts[1:]):
            chunk = text[a:b]
            yield chunk.split("{", 1)[0].strip(), chunk

    def test_every_embedder_building_test_owns_offline_or_probes_the_cache(self):
        offenders = []
        for path in self.rust_files():
            for head, chunk in self.fn_bodies(path):
                if EMBEDDER_CALL_RE.search(chunk) and not any(m in chunk for m in PREREQ_MARKERS):
                    offenders.append(f"{path.relative_to(ROOT)}: {head}")
        self.assertEqual(offenders, [])

    def test_no_skip_branch_on_embedder_failure(self):
        offenders = []
        for path in self.rust_files():
            text = code_lines(path.read_text())
            for m in re.finditer(r"Embedder::new_local\(\)\s*else\s*\{", text):
                offenders.append(f"{path.relative_to(ROOT)}@{m.start()}")
            for m in re.finditer(r"Embedder::new_local\(\) \{\s*Ok\(e\) => e,\s*Err\(_\) => (?:\{\s*)?return", text):
                offenders.append(f"{path.relative_to(ROOT)}@{m.start()}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
