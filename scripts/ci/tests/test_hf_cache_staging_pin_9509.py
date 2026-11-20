#!/usr/bin/env python3
"""Pin cells for the one HuggingFace cache staging form (#9509, #9515).

Class: a CI job whose test depends on a prerequisite that no step of the job
provides, and a test that can reach a network model fetch. Invariants (fix
notice 9531-r1, 3-agent vote 71472661 D1-1 .. D2-4):

A. No test and no CI step can reach a network model fetch. Every workflow
   step that runs Rust tests sees AI_MEMORY_EMBED_OFFLINE=1 from one source:
   the workflow-level env line, or, in a workflow whose workflow env the
   #8240 pre-trust gate pins (ci.yml), one job-level line per job that runs
   Rust tests (no step overrides it, nothing else names it), and Rust test code
   never names a network-capable constructor (`Embedder::new_local`,
   `Embedder::new`, `Embedder::for_model(MiniLmL6V2)`,
   `CrossEncoder::new_neural`) outside the argument of a knob runner that
   asserts the knob before it builds. The staged constructors
   (`new_local_staged`, `new_neural_staged`, `new_neural_in`) never fetch.
C. No job reads or writes the runner user's real model cache: every staging
   job sets a private HF_HOME under runner.temp first (hf_home_private.py),
   restores and saves only `${{ env.HF_HOME }}/hub`, and no actions/cache path
   anywhere names a home directory.
D1. The cache key carries both pinned revisions of stage_hf_cache.py, there
   are no restore-keys, and the save step runs only after a verified stage.

Each staging job (ci.yml `check` and `sal-feature`, coverage.yml
`per-module-thresholds`) holds the same four steps, word for word, directly
before its first test step; job `check` adds its cargo_skip guard.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_hf_cache_staging_pin_9509.py'
Python 3.12 floor, standard library only.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CI_DIR = ROOT / "scripts" / "ci"
sys.path.insert(0, str(CI_DIR))
import stage_hf_cache as shc  # noqa: E402

WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"
CI = WORKFLOWS / "ci.yml"
COVERAGE = WORKFLOWS / "coverage.yml"
STAGE_REL = "scripts/ci/stage_hf_cache.py"
PRIVATE_REL = "scripts/ci/hf_home_private.py"
KNOB = "AI_MEMORY_EMBED_OFFLINE"
KNOB_VALUE = '"1"'
# Workflows whose workflow-level env is pinned key for key by the #8240
# pre-trust gate (scripts/ci/tests/test_ci_base_selector_8240.py
# WORKFLOW_ENV_VALUES): the knob is one job-level line per Rust-test job there.
JOB_LEVEL_KNOB_FILES = ("ci.yml",)
CHECK_JOB = "check"
SAL_JOB = "sal-feature"
COVERAGE_JOB = "per-module-thresholds"
CHECK_TEST_STEP = "Run tests (impact-aware)"
SAL_TEST_STEP = "Run lib tests (sal feature)"
CHECK_GUARD = "needs.classify.outputs.cargo_skip != 'true'"
CACHE_SHA = "0057852bfaa89a56745cba8c7296529d2fc39830"
RESTORE_ID = "hf_restore"
HUB_PATH = "${{ env.HF_HOME }}/hub"
CACHE_KEY = (
    f"hf-hub-minilm-l6-v2-{shc.EMBEDDER_REVISION}-marco-l6-v2-{shc.RERANKER_REVISION}-v3"
)
PRIVATE_STEP = "Private HF home (#9509)"
RESTORE_STEP = "Restore HuggingFace models (#9509)"
STAGE_STEP = "Stage HF model cache (#9509)"
SAVE_STEP = "Save HuggingFace models (#9509)"
STAGING_STEPS = (PRIVATE_STEP, RESTORE_STEP, STAGE_STEP, SAVE_STEP)
# (workflow, job, first test step) of every job that stages the model cache.
STAGING_JOBS = (
    (CI, CHECK_JOB, CHECK_TEST_STEP),
    (CI, SAL_JOB, SAL_TEST_STEP),
    (COVERAGE, COVERAGE_JOB, None),
)
# Code (non-comment) occurrences per workflow file: one per job that stages.
SCRIPT_CALLS_PER_FILE = {"ci.yml": 2, "coverage.yml": 1}
CACHE_USES_RE = re.compile(r"uses: actions/cache(?:/restore|/save)?@")
# A cache path naming one of these reads or writes a home directory (D2-2).
HOME_MARKERS = ("~", "$HOME", "env.HOME", "/home/", "/Users/", "/root")
# A step whose code matches this runs Rust tests (directly or through a script).
TEST_RE = re.compile(
    r"cargo (?:\+\S+ )?(?:test|nextest|llvm-cov)|cargo-llvm-cov|scripts/coverage\.sh|run_isolated|ci_pg_isolate"
)
# Any of these in a workflow or action is a staging form of its own.
STAGING_TOKENS = ("snapshot_download", "hf_hub_download", "huggingface_hub", "huggingface-cli", "hf download")
JOB_ID_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_RE = re.compile(r"^      - (?:name: (?P<name>.*)|uses: .*)$")
IF_LINE_RE = re.compile(r"^\s+if: .*$")

# Rust test code that names a network-capable model constructor.
NET_CTOR_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:Embedder::(?:new_local|new)(?![A-Za-z0-9_])"
    r"|Embedder::for_model\(\s*(?:(?:crate|ai_memory)::config::)?EmbeddingModel::MiniLmL6V2"
    r"|CrossEncoder::new_neural(?![A-Za-z0-9_]))"
)
# A call whose argument span may name one: the runner asserts the offline knob first.
KNOB_RUNNERS = ("offline_empty_cache_error",)
# A test item: `#[cfg(test)]` (also inside all/any) or a `#[test]` / `#[tokio::test]` function.
CFG_TEST_RE = re.compile(r"#\[(?:cfg\(\s*(?:(?:all|any)\(\s*)?test\b|(?:tokio::)?test\b)")
ATTR_RE = re.compile(r"\s*#\[")
MOD_DECL_RE = re.compile(r"\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;")
PATH_ATTR_RE = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
# Production sites that build the real models: the census must see them as non-test.
KNOWN_PRODUCTION_FILES = ("src/daemon_runtime.rs", "src/mcp/mod.rs")


def job_lines(path: Path, job: str) -> list[str]:
    """Lines of one job of a workflow file (job ids at two-space indent)."""
    out: list[str] = []
    inside = in_jobs = False
    for line in path.read_text().split("\n"):
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


def jobs_of(path: Path) -> list[str]:
    ids, in_jobs = [], False
    for line in path.read_text().split("\n"):
        if line == "jobs:":
            in_jobs = True
        elif in_jobs and (m := JOB_ID_RE.match(line)):
            ids.append(m.group(1))
        elif in_jobs and line and not line.startswith(" ") and not line.startswith("#"):
            in_jobs = False
    return ids


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
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith(("#", "//")))


def step_code(body: str) -> list[str]:
    """The code lines of one step, comments and blank lines dropped."""
    return [line for line in code_lines(body).split("\n") if line.strip()]


def env_block(lines: list[str], indent: int) -> dict[str, str]:
    """`KEY: value` pairs of the first `env:` line at `indent` spaces (values verbatim)."""
    head = " " * indent + "env:"
    out: dict[str, str] = {}
    for i, line in enumerate(lines):
        if line.rstrip() != head:
            continue
        for row in lines[i + 1:]:
            if not row.strip() or row.lstrip().startswith("#"):
                continue
            if len(row) - len(row.lstrip()) <= indent:
                break
            key, _, value = row.strip().partition(":")
            out[key] = value.strip()
        break
    return out


def top_env(path: Path) -> dict[str, str]:
    lines = path.read_text().split("\n")
    return env_block(lines[: lines.index("jobs:")] if "jobs:" in lines else lines, 0)


def job_env(lines: list[str]) -> dict[str, str]:
    """The job-level env (4-space `env:` before the first step)."""
    head: list[str] = []
    for line in lines:
        if STEP_RE.match(line):
            break
        head.append(line)
    return env_block(head, 4)


def staging_block(cache_guard: str | None) -> list[str]:
    """The four staging steps of one job, as code lines (D1 + D2, one form)."""
    guard = [f"        if: {cache_guard}"] if cache_guard else []
    save_if = f"{cache_guard} && " if cache_guard else ""
    args = '--runner-temp "$RUNNER_TEMP_ARG" --workspace "$WORKSPACE_ARG"'
    env = [
        "        env:",
        "          RUNNER_TEMP_ARG: ${{ runner.temp }}",
        "          WORKSPACE_ARG: ${{ github.workspace }}",
    ]
    cache_with = ["        with:", f"          path: {HUB_PATH}", f"          key: {CACHE_KEY}"]
    return [
        f"      - name: {PRIVATE_STEP}", *guard, *env,
        f'        run: python3 -I {PRIVATE_REL} {args} --github-env "$GITHUB_ENV"',
        f"      - name: {RESTORE_STEP}", *guard, f"        id: {RESTORE_ID}",
        f"        uses: actions/cache/restore@{CACHE_SHA} # v4", *cache_with,
        f"      - name: {STAGE_STEP}", *guard, *env,
        f"        run: python3 -I {STAGE_REL} --models all {args}",
        f"      - name: {SAVE_STEP}",
        f"        if: {save_if}steps.{RESTORE_ID}.outputs.cache-hit != 'true'",
        f"        uses: actions/cache/save@{CACHE_SHA} # v4", *cache_with,
    ]


def workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def action_files() -> list[Path]:
    return sorted(ACTIONS.glob("**/action.y*ml"))


class StagingJobs(unittest.TestCase):
    """C + D1: the four steps, word for word, directly before the first test step."""

    def pairs(self, path: Path, job: str) -> list[tuple[str, str]]:
        return [(n, "\n".join(b)) for n, b in steps(job_lines(path, job))]

    def test_every_staging_job_holds_the_four_steps_word_for_word_9509(self):
        for path, job, _ in STAGING_JOBS:
            with self.subTest(job=job):
                pairs = self.pairs(path, job)
                names = [n for n, _ in pairs]
                for name in STAGING_STEPS:
                    self.assertEqual(names.count(name), 1, name)
                start = names.index(PRIVATE_STEP)
                self.assertEqual(names[start:start + 4], list(STAGING_STEPS))
                got = [line for _, body in pairs[start:start + 4] for line in step_code(body)]
                self.assertEqual(got, staging_block(CHECK_GUARD if job == CHECK_JOB else None))

    def test_staging_is_directly_before_the_first_test_step_9509(self):
        for path, job, test_step in STAGING_JOBS:
            with self.subTest(job=job):
                pairs = self.pairs(path, job)
                names = [n for n, _ in pairs]
                first_test = next(i for i, (_, b) in enumerate(pairs) if TEST_RE.search(code_lines(b)))
                if test_step is not None:
                    self.assertEqual(names[first_test], test_step)
                self.assertIn(SAVE_STEP, names)
                self.assertIn(PRIVATE_STEP, names)
                self.assertLess(names.index(SAVE_STEP), first_test)
                checkout = next(i for i, n in enumerate(names) if n.startswith("uses: actions/checkout@"))
                self.assertLess(checkout, names.index(PRIVATE_STEP))

    def test_check_test_step_carries_the_same_guard_9509(self):
        body = dict(self.pairs(CI, CHECK_JOB))[CHECK_TEST_STEP]
        self.assertIn(f"        if: {CHECK_GUARD}", step_code(body))

    def test_cache_key_carries_both_pinned_revisions_9509(self):
        for path in (CI, COVERAGE):
            keys = re.findall(r"^\s+key: (.*)$", code_lines(path.read_text()), re.M)
            hf_keys = [k for k in keys if k.startswith("hf-")]
            with self.subTest(file=path.name):
                self.assertEqual(len(hf_keys), 2 * SCRIPT_CALLS_PER_FILE[path.name])
                for key in hf_keys:
                    self.assertIn(shc.EMBEDDER_REVISION, key)
                    self.assertIn(shc.RERANKER_REVISION, key)

    def test_no_restore_keys_anywhere_9509(self):
        for path in workflow_files() + action_files():
            with self.subTest(file=path.name):
                self.assertNotIn("restore-keys", code_lines(path.read_text()))

    def test_staging_steps_install_nothing_and_read_no_token_9509(self):
        for path, job, _ in STAGING_JOBS:
            pairs = dict(self.pairs(path, job))
            for name in STAGING_STEPS:
                with self.subTest(job=job, step=name):
                    self.assertIn(name, pairs)
                    text = code_lines(pairs[name])
                    self.assertNotRegex(text, r"pip|install|secrets\.|GITHUB_TOKEN|HF_TOKEN|token:")

    def test_each_file_names_each_script_once_per_staging_job_9509(self):
        self.assertTrue((ROOT / STAGE_REL).is_file())
        self.assertTrue((ROOT / PRIVATE_REL).is_file())
        for path in workflow_files() + action_files():
            text = code_lines(path.read_text())
            want = SCRIPT_CALLS_PER_FILE.get(path.name, 0)
            with self.subTest(file=path.name):
                self.assertEqual(text.count(STAGE_REL), want)
                self.assertEqual(text.count(PRIVATE_REL), want)


class OfflineKnob(unittest.TestCase):
    """A: every step that runs Rust tests sees the knob from its one source."""

    def rust_test_steps(self, path: Path):
        for job in jobs_of(path):
            lines = job_lines(path, job)
            for name, body in steps(lines):
                if TEST_RE.search(code_lines("\n".join(body))):
                    yield job, name, lines, body

    def rust_test_jobs(self, path: Path) -> list[str]:
        return sorted({job for job, _, _, _ in self.rust_test_steps(path)})

    def test_every_test_step_runs_with_the_knob_9509(self):
        offenders, seen = [], 0
        for path in workflow_files():
            wf = top_env(path)
            for job, name, lines, body in self.rust_test_steps(path):
                seen += 1
                env = {**wf, **job_env(lines), **env_block(body, 8)}
                if env.get(KNOB) != KNOB_VALUE:
                    offenders.append(f"{path.name}:{job}:{name}")
        self.assertGreater(seen, 10)
        self.assertEqual(offenders, [])

    def test_knob_has_one_source_per_workflow_9509(self):
        for path in workflow_files():
            text = code_lines(path.read_text())
            test_jobs = self.rust_test_jobs(path)
            with self.subTest(file=path.name):
                if path.name in JOB_LEVEL_KNOB_FILES:
                    self.assertGreater(len(test_jobs), 0)
                    self.assertNotIn(KNOB, top_env(path))
                    self.assertEqual(text.count(KNOB), len(test_jobs))
                    for job in test_jobs:
                        self.assertEqual(job_env(job_lines(path, job)).get(KNOB), KNOB_VALUE, job)
                    continue
                self.assertEqual(text.count(KNOB), 1 if test_jobs else 0)
                if test_jobs:
                    self.assertEqual(top_env(path).get(KNOB), KNOB_VALUE)

    def test_job_level_knob_files_have_pinned_workflow_env_9509(self):
        """The job-level exception holds only where the #8240 gate pins the workflow env."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_ci_base_selector_8240 as selector  # noqa: PLC0415

        self.assertEqual(JOB_LEVEL_KNOB_FILES, (CI.name,))
        self.assertNotIn(KNOB, selector.WORKFLOW_ENV_VALUES)
        self.assertEqual(set(top_env(CI)), set(selector.WORKFLOW_ENV_VALUES))

    def test_sal_lib_test_step_reads_the_job_knob_9509(self):
        """The inverted sal pin: the lib tests run offline, from the job-level line."""
        body = "\n".join(dict(steps(job_lines(CI, SAL_JOB)))[SAL_TEST_STEP])
        self.assertNotIn(KNOB, top_env(CI))
        self.assertEqual(job_env(job_lines(CI, SAL_JOB)).get(KNOB), KNOB_VALUE)
        self.assertNotIn(KNOB, env_block(body.split("\n"), 8))
        self.assertEqual(step_code(body)[-1].strip(), "run: cargo test --features sal --lib")

    def test_no_composite_action_runs_rust_tests_9509(self):
        for path in action_files():
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertIsNone(TEST_RE.search(code_lines(path.read_text())))


class NoHomeCache(unittest.TestCase):
    """C (D2-2): no actions/cache path anywhere names a home directory."""

    def test_no_cache_path_under_a_home_directory_9509(self):
        offenders, seen = [], 0
        for path in workflow_files() + action_files():
            for name, body in steps(path.read_text().split("\n")):
                text = code_lines("\n".join(body))
                if not CACHE_USES_RE.search(text):
                    continue
                seen += 1
                with_part = text.split("with:", 1)[1] if "with:" in text else ""
                for marker in HOME_MARKERS:
                    if marker in with_part:
                        offenders.append(f"{path.name}:{name}:{marker}")
        self.assertGreaterEqual(seen, 6)
        self.assertEqual(offenders, [])

    def test_every_hf_cache_step_is_a_staging_restore_or_save_9509(self):
        found = []
        for path in workflow_files() + action_files():
            for name, body in steps(path.read_text().split("\n")):
                text = code_lines("\n".join(body))
                if CACHE_USES_RE.search(text) and ("huggingface" in text.lower() or "HF_HOME" in text):
                    found.append((path.name, name))
        want = [(p.name, n) for p, _, _ in STAGING_JOBS for n in (RESTORE_STEP, SAVE_STEP)]
        self.assertEqual(sorted(found), sorted(want))

    def test_no_staging_token_in_any_workflow_or_action_9509(self):
        offenders = []
        for path in workflow_files() + action_files():
            text = code_lines(path.read_text())
            offenders += [f"{path.name}: {t}" for t in STAGING_TOKENS if t in text]
        self.assertEqual(offenders, [])


# ---- Rust census (invariant A) ------------------------------------------------------------


def strip_rust(text: str) -> str:
    """Blank comments, string and char literal contents; offsets and newlines are kept."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) and (
            m := re.match(r"b?r(#*)\"", text[i:i + 300])
        ):
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'" and (m := re.match(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", text[i:i + 16])):
            blank(i, i + m.end())
            i += m.end()
        else:
            i += 1
    return "".join(out)


def match_close(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index after the bracket closing the one at `start` (len(text) when unbalanced)."""
    depth = 0
    for k in range(start, len(text)):
        if text[k] == open_ch:
            depth += 1
        elif text[k] == close_ch:
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def child_module_file(parent: Path, name: str, path_attr: str | None) -> Path | None:
    base = parent.parent
    if path_attr is not None:
        candidates = [base / path_attr]
    else:
        if parent.name not in ("mod.rs", "lib.rs", "main.rs"):
            base = base / parent.stem
        candidates = [base / f"{name}.rs", base / name / "mod.rs"]
    return next((c for c in candidates if c.is_file()), None)


def test_regions(path: Path, text: str, stripped: str) -> tuple[list[tuple[int, int]], list[Path]]:
    """(spans of `#[cfg(test)]` items, files of `#[cfg(test)] mod x;` declarations)."""
    spans, files = [], []
    for m in CFG_TEST_RE.finditer(stripped):
        k = match_close(stripped, m.start() + 1, "[", "]")
        path_attr = None
        while (a := ATTR_RE.match(stripped, k)) is not None:
            end = match_close(stripped, a.end() - 1, "[", "]")
            if (p := PATH_ATTR_RE.search(text[a.start():end])) is not None:
                path_attr = p.group(1)
            k = end
        if (decl := MOD_DECL_RE.match(stripped, k)) is not None:
            if (child := child_module_file(path, decl.group(1), path_attr)) is not None:
                files.append(child)
            continue
        brace, semi = stripped.find("{", k), stripped.find(";", k)
        if brace < 0 or (0 <= semi < brace):
            spans.append((m.start(), semi + 1 if semi >= 0 else len(stripped)))
        else:
            spans.append((m.start(), match_close(stripped, brace, "{", "}")))
    return spans, files


def runner_spans(stripped: str) -> list[tuple[int, int]]:
    spans = []
    for runner in KNOB_RUNNERS:
        for m in re.finditer(rf"(?<![A-Za-z0-9_]){runner}\s*\(", stripped):
            spans.append((m.end() - 1, match_close(stripped, m.end() - 1, "(", ")")))
    return spans


def census(root: Path = ROOT) -> tuple[list[str], list[str]]:
    """(test-code hits outside a knob runner, production hits) of NET_CTOR_RE."""
    whole: set[Path] = {p.resolve() for p in (root / "tests").rglob("*.rs")}
    queue = sorted((root / "src").rglob("*.rs"))
    parsed: dict[Path, tuple[str, str, list[tuple[int, int]]]] = {}
    while queue:
        path = queue.pop()
        text = path.read_text()
        stripped = strip_rust(text)
        spans, files = test_regions(path, text, stripped)
        parsed[path.resolve()] = (text, stripped, spans)
        whole.update(f.resolve() for f in files)
    for path in whole:
        if path not in parsed:
            text = path.read_text()
            parsed[path] = (text, strip_rust(text), [])
    test_hits, prod_hits = [], []
    for path, (text, stripped, spans) in sorted(parsed.items()):
        allowed = runner_spans(stripped)
        for m in NET_CTOR_RE.finditer(stripped):
            where = f"{path.relative_to(root.resolve())}:{text.count(chr(10), 0, m.start()) + 1}"
            in_test = path in whole or any(a <= m.start() < b for a, b in spans)
            if not in_test:
                prod_hits.append(where)
            elif not any(a <= m.start() < b for a, b in allowed):
                test_hits.append(where)
    return test_hits, prod_hits


class NoTestNamesANetworkConstructor(unittest.TestCase):
    """A: the Rust half, for Embedder AND CrossEncoder, over src/ test regions and tests/."""

    def test_no_test_names_a_network_capable_constructor_9509(self):
        test_hits, _ = census()
        self.assertEqual(test_hits, [])

    def test_census_sees_the_production_sites_9509(self):
        _, prod_hits = census()
        for rel in KNOWN_PRODUCTION_FILES:
            self.assertTrue(any(h.startswith(rel + ":") for h in prod_hits), (rel, prod_hits))

    def test_scanner_regions_on_a_sample_9509(self):
        sample = (
            'fn prod() { let _ = Embedder::new_local(); let s = "Embedder::new()"; }\n'
            "// Embedder::new_local()\n"
            "#[cfg(test)]\n#[allow(dead_code)]\nmod t {\n"
            "    fn a() { let _ = CrossEncoder::new_neural(); }\n"
            "    fn b() { let _ = offline_empty_cache_error(Embedder::new_local); }\n"
            "    fn c() { let _ = Embedder::new_local_staged(); let _ = CrossEncoder::new_neural_in(p); }\n"
            "    fn d() { let _ = r#\"}\"#; let _ = '}'; let _ = Embedder::new(); }\n"
            "}\n"
            "fn prod2() { let _ = CrossEncoder::new_neural(); }\n"
            "#[tokio::test(flavor = \"current_thread\")]\n"
            "async fn e() { let _ = Embedder::for_model(EmbeddingModel::MiniLmL6V2, None); }\n"
        )
        stripped = strip_rust(sample)
        self.assertEqual(len(stripped), len(sample))
        spans, files = test_regions(Path("src/x.rs"), sample, stripped)
        self.assertEqual(files, [])
        self.assertEqual(len(spans), 2)
        hits = [m.start() for m in NET_CTOR_RE.finditer(stripped)]
        allowed = runner_spans(stripped)
        lines = sorted(
            (sample.count("\n", 0, h) + 1, any(a <= h < b for a, b in spans), any(a <= h < b for a, b in allowed))
            for h in hits
        )
        self.assertEqual(lines, [(1, False, False), (6, True, False), (7, True, True), (9, True, False),
                                 (11, False, False), (13, True, False)])

    def test_scanner_is_linear_on_a_large_input_9509(self):
        import time
        big = "fn f() { let s = \"x\"; let c = '{'; /* } */ }\n" * 20_000
        start = time.monotonic()
        stripped = strip_rust(big)
        test_regions(Path("src/x.rs"), big, stripped)
        self.assertGreater(len(big), 100_000)
        self.assertLess(time.monotonic() - start, 10.0)


if __name__ == "__main__":
    unittest.main()
