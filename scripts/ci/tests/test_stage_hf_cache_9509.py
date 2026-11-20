#!/usr/bin/env python3
"""Cells for scripts/ci/stage_hf_cache.py (#9509, PR 9531 round 1).

Class B invariant (3-agent vote 71472661, D1-1 .. D1-3): the stage step exits 0
only when refs/main byte-equals the pinned revision, the leaf
snapshots/<revision>/ is a real directory and every artifact of the pinned
manifest resolves inside the repo's own cache tree to a regular file with the
pinned size and sha256. Every other cache form is a named error with its own
exit code and exact text, never exit 0 and never a traceback. The table
`CACHE_FORMS` names each form; every row runs twice, once in process against a
small manifest (so the digest path is exercised with real bytes) and once
through the real CLI against the real MANIFEST.

Placement (D2-1): the hub must be `<runner-temp>/<PRIVATE_DIR_NAME>/hub`,
outside the checkout, else EXIT_PLACEMENT. HOME is never read (D2-3).

N7 / N8 by construction: the module imports no child-process API, installs
nothing, reads no token and sends no Authorization header.

The network and the sleep are injected (`Ops`), so no cell touches the network.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_stage_hf_cache_9509.py'
Python 3.12 floor, standard library only.
"""
import ast
import contextlib
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

CI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CI_DIR))
import stage_hf_cache as shc  # noqa: E402

SCRIPT = CI_DIR / "stage_hf_cache.py"
EMBEDDER = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER = "cross-encoder/ms-marco-MiniLM-L-6-v2"
ERROR_PREFIX = "::error::stage_hf_cache: "
NOTICE_PREFIX = "::notice::stage_hf_cache: "
EXIT_USAGE = 2
CLI_TIMEOUT_SECONDS = 120
OTHER_REVISION = "b" * 40
FILLER = b"x"
TRACEBACK_MARK = "Traceback"
# Small artifacts for the in-process half of the table: real bytes, real digests.
SMALL_BYTES = {
    shc.CONFIG_FILE: b'{"hidden_size": 384}',
    shc.TOKENIZER_FILE: b'{"model": {"type": "WordPiece"}}',
    shc.WEIGHTS_FILE: b"\x00\x01weights\x02\x03",
}


def small_manifest(repo: str) -> tuple[tuple[str, str, int, str], ...]:
    return tuple(
        (repo, name, len(data), hashlib.sha256(data).hexdigest()) for name, data in SMALL_BYTES.items()
    )


def repo_base(hub: Path, repo: str) -> Path:
    return hub / ("models--" + repo.replace("/", "--"))


def build_blob_tree(hub: Path, repo: str, revision: str, contents: dict[str, bytes]) -> Path:
    """The hf-hub layout: blobs/<sha256> plus snapshots/<rev>/<name> -> ../../blobs/<sha256>."""
    base = repo_base(hub, repo)
    snap = base / "snapshots" / revision
    (base / "blobs").mkdir(parents=True, exist_ok=True)
    snap.mkdir(parents=True, exist_ok=True)
    (base / "refs").mkdir(parents=True, exist_ok=True)
    (base / "refs" / "main").write_bytes(revision.encode("ascii"))
    for name, data in contents.items():
        digest = hashlib.sha256(data).hexdigest()
        (base / "blobs" / digest).write_bytes(data)
        os.symlink(os.path.join("..", "..", "blobs", digest), snap / name)
    return snap


# Each form changes config.json (or the ref, or the leaf) of an otherwise complete tree.
# The value is the problem text the step must print, with {rel} = snapshots/<revision>.
CACHE_FORMS: dict[str, str] = {
    "absent": "missing config.json in {rel}",
    "zero_byte": "config.json in {rel} has 0 bytes, pinned {size}",
    "wrong_digest": "config.json in {rel} sha256 differs from the pinned digest",
    "oversized": "config.json in {rel} has {over} bytes, pinned {size}",
    "file_symlink_out_of_repo": "config.json in {rel} resolves outside the repo cache",
    "blobs_dir_symlink_out_of_repo": "config.json in {rel} resolves outside the repo cache",
    "dangling_link": "missing config.json in {rel} (dangling link)",
    "directory_not_file": "config.json in {rel} is not a regular file",
    "leaf_dir_symlink": "missing snapshot dir {rel}",
    "legacy_snapshots_main_only": "missing snapshot dir {rel}",
    "missing_ref": "missing ref refs/main",
    "ref_is_symlink": "ref refs/main",
    "ref_is_directory": "ref refs/main",
    "unreadable_ref": "unreadable ref refs/main",
    "undecodable_ref": "undecodable ref refs/main",
    "ref_trailing_newline": "ref refs/main",
    "ref_other_revision": "ref refs/main",
    "ref_oversized": "ref refs/main",
}
REF_FORMS = {"missing_ref", "ref_is_symlink", "ref_is_directory", "unreadable_ref", "undecodable_ref",
             "ref_trailing_newline", "ref_other_revision", "ref_oversized"}
LEAF_FORMS = {"leaf_dir_symlink", "legacy_snapshots_main_only"}


def full_problem(form: str, repo: str, revision: str, size: int) -> str:
    """The exact problem line for one form (repo suffix included)."""
    if form == "undecodable_ref":
        return f"undecodable ref refs/main for {repo} (not ASCII)"
    if form in {"ref_trailing_newline", "ref_other_revision", "ref_oversized"}:
        return f"ref refs/main for {repo} is not the pinned revision {revision}"
    if form == "missing_ref":
        return f"missing ref refs/main for {repo}"
    if form in {"ref_is_symlink", "ref_is_directory"}:
        return f"ref refs/main for {repo} is not a regular file"
    if form == "unreadable_ref":
        return f"unreadable ref refs/main for {repo}"
    text = CACHE_FORMS[form].format(rel=f"snapshots/{revision}", size=size, over=size + 1)
    return f"{text} for {repo}"


def apply_form(form: str, hub: Path, outside: Path, repo: str, revision: str, size: int) -> None:
    """Turn the complete tree under `hub` into `form` (only the named part changes)."""
    base = repo_base(hub, repo)
    snap = base / "snapshots" / revision
    entry = snap / shc.CONFIG_FILE
    ref = base / "refs" / "main"
    outside.mkdir(parents=True, exist_ok=True)
    if form == "absent":
        entry.unlink()
    elif form == "zero_byte":
        entry.unlink()
        entry.write_bytes(b"")
    elif form == "wrong_digest":
        entry.unlink()
        entry.write_bytes(FILLER * size)
    elif form == "oversized":
        entry.unlink()
        entry.write_bytes(FILLER * (size + 1))
    elif form == "file_symlink_out_of_repo":
        target = outside / "config.json"
        target.write_bytes(entry.read_bytes())
        entry.unlink()
        os.symlink(target, entry)
    elif form == "blobs_dir_symlink_out_of_repo":
        moved = outside / "blobs"
        (base / "blobs").rename(moved)
        os.symlink(moved, base / "blobs")
    elif form == "dangling_link":
        entry.unlink()
        os.symlink(os.path.join("..", "..", "blobs", "0" * 64), entry)
    elif form == "directory_not_file":
        entry.unlink()
        entry.mkdir()
    elif form == "leaf_dir_symlink":
        moved = outside / "leaf"
        snap.rename(moved)
        os.symlink(moved, snap)
    elif form == "legacy_snapshots_main_only":
        snap.rename(base / "snapshots" / "main")
    elif form == "missing_ref":
        ref.unlink()
    elif form == "ref_is_symlink":
        real = outside / "main"
        real.write_bytes(revision.encode("ascii"))
        ref.unlink()
        os.symlink(real, ref)
    elif form == "ref_is_directory":
        ref.unlink()
        ref.mkdir()
    elif form == "unreadable_ref":
        # The refs/ dir loses search permission, so lstat of refs/main is EACCES.
        os.chmod(base / "refs", 0)
    elif form == "undecodable_ref":
        ref.write_bytes(b"\xff" * len(revision))
    elif form == "ref_trailing_newline":
        ref.write_bytes(revision.encode("ascii") + b"\n")
    elif form == "ref_other_revision":
        ref.write_bytes(OTHER_REVISION.encode("ascii"))
    elif form == "ref_oversized":
        ref.write_bytes(revision.encode("ascii") * 4)
    else:
        raise AssertionError(f"unknown form {form}")


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeNet:
    """Injected network: serves bytes by file name and records every URL and sleep."""

    def __init__(self, contents: dict[str, bytes], failures: int = 0, exc: Exception | None = None):
        self.contents = contents
        self.failures = failures
        self.exc = exc or urllib.error.URLError("offline")
        self.urls: list[str] = []
        self.sleeps: list[int] = []

    def open_url(self, url: str):
        self.urls.append(url)
        if self.failures > 0:
            self.failures -= 1
            raise self.exc
        return FakeResponse(self.contents[url.rsplit("/", 1)[1]])

    def ops(self) -> shc.Ops:
        return shc.Ops(open_url=self.open_url, sleep=self.sleeps.append)


class Scratch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(os.path.realpath(self._tmp.name))
        self.runner_temp = self.root / "runner-temp"
        self.workspace = self.root / "workspace"
        self.runner_temp.mkdir()
        self.workspace.mkdir()
        self.hf_home = self.runner_temp / shc.PRIVATE_DIR_NAME
        self.hub = self.hf_home / shc.HUB_DIR_NAME
        self.hub.mkdir(parents=True)
        self.outside = self.root / "outside"
        self.home = self.root / "home"
        self.home.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def stage_small(self, repo: str = EMBEDDER, verify_only: bool = True, net: FakeNet | None = None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = shc.stage(self.hub, (repo,), (net or FakeNet({})).ops(), verify_only, small_manifest(repo))
        return code, out.getvalue().splitlines()

    def run_cli(self, *args: str, hf_home: str | None = None):
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)}
        env[shc.HF_HOME_ENV] = str(self.hf_home) if hf_home is None else hf_home
        if hf_home == "":
            del env[shc.HF_HOME_ENV]
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), *args],
            env=env, capture_output=True, text=True, timeout=CLI_TIMEOUT_SECONDS, check=False,
        )

    def cli_args(self, *extra: str) -> list[str]:
        return ["--models", "embedder", "--runner-temp", str(self.runner_temp),
                "--workspace", str(self.workspace), *extra]


class ExitCodeTable(unittest.TestCase):
    def test_named_codes_9509(self):
        self.assertEqual(
            (shc.EXIT_OK, shc.EXIT_LAYOUT, shc.EXIT_FETCH, shc.EXIT_PLACEMENT), (0, 10, 11, 13)
        )

    def test_one_revision_constant_per_model_9509(self):
        self.assertEqual(shc.REVISIONS, {EMBEDDER: shc.EMBEDDER_REVISION, RERANKER: shc.RERANKER_REVISION})
        for revision in shc.REVISIONS.values():
            self.assertRegex(revision, r"\A[0-9a-f]{40}\Z")

    def test_manifest_is_one_tuple_per_artifact_9509(self):
        self.assertEqual(len(shc.MANIFEST), len(shc.REVISIONS) * len(shc.ARTIFACT_FILES))
        for repo in shc.REVISIONS:
            self.assertEqual(sorted(n for r, n, _, _ in shc.MANIFEST if r == repo), sorted(shc.ARTIFACT_FILES))
        for _, _, size, digest in shc.MANIFEST:
            self.assertGreater(size, 0)
            self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")


class CacheFormsInProcess(Scratch):
    """Class B, small manifest: each row has its exact exit code and exact text."""

    def test_complete_tree_passes_9509(self):
        build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, SMALL_BYTES)
        code, lines = self.stage_small()
        self.assertEqual(code, shc.EXIT_OK)
        self.assertEqual(
            lines, [f"{NOTICE_PREFIX}{EMBEDDER} matches the pinned manifest at {shc.EMBEDDER_REVISION}"]
        )

    def test_regular_file_leaf_passes_9509(self):
        snap = build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, SMALL_BYTES)
        for name, data in SMALL_BYTES.items():
            (snap / name).unlink()
            (snap / name).write_bytes(data)
        self.assertEqual(self.stage_small()[0], shc.EXIT_OK)

    def test_every_cache_form_is_its_named_error_9509(self):
        size = len(SMALL_BYTES[shc.CONFIG_FILE])
        for form in CACHE_FORMS:
            with self.subTest(form=form):
                self.tearDown()
                self.setUp()
                build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, SMALL_BYTES)
                apply_form(form, self.hub, self.outside, EMBEDDER, shc.EMBEDDER_REVISION, size)
                code, lines = self.stage_small()
                self.assertEqual(code, shc.EXIT_LAYOUT)
                problems = [full_problem(form, EMBEDDER, shc.EMBEDDER_REVISION, size)]
                if form == "blobs_dir_symlink_out_of_repo":
                    rel = f"snapshots/{shc.EMBEDDER_REVISION}"
                    problems += [f"{name} in {rel} resolves outside the repo cache for {EMBEDDER}"
                                 for name in (shc.TOKENIZER_FILE, shc.WEIGHTS_FILE)]
                self.assertEqual(lines, [ERROR_PREFIX + shc.clean(p) for p in problems])


class CacheFormsCli(Scratch):
    """Class B through the real CLI and the real MANIFEST: exit 10, exact stdout, no traceback."""

    def real_tree(self) -> None:
        """Pinned ref and leaf; config.json holds 612 placeholder bytes, the other two one byte."""
        contents = {shc.CONFIG_FILE: FILLER * shc.EMBEDDER_CONFIG_SIZE,
                    shc.TOKENIZER_FILE: FILLER, shc.WEIGHTS_FILE: FILLER + b"w"}
        build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, contents)

    def expected(self, form: str) -> list[str]:
        rev = shc.EMBEDDER_REVISION
        rel = f"snapshots/{rev}"
        if form in REF_FORMS or form in LEAF_FORMS:
            return [ERROR_PREFIX + shc.clean(full_problem(form, EMBEDDER, rev, shc.EMBEDDER_CONFIG_SIZE))]
        first = full_problem(form, EMBEDDER, rev, shc.EMBEDDER_CONFIG_SIZE)
        if form == "blobs_dir_symlink_out_of_repo":
            rest = [f"{name} in {rel} resolves outside the repo cache for {EMBEDDER}"
                    for name in (shc.TOKENIZER_FILE, shc.WEIGHTS_FILE)]
        else:
            rest = [f"{shc.TOKENIZER_FILE} in {rel} has 1 bytes, pinned {shc.EMBEDDER_TOKENIZER_SIZE} for {EMBEDDER}",
                    f"{shc.WEIGHTS_FILE} in {rel} has 2 bytes, pinned {shc.EMBEDDER_WEIGHTS_SIZE} for {EMBEDDER}"]
        return [ERROR_PREFIX + shc.clean(line) for line in [first, *rest]]

    def test_every_cache_form_via_cli_9509(self):
        for form in CACHE_FORMS:
            with self.subTest(form=form):
                self.tearDown()
                self.setUp()
                self.real_tree()
                apply_form(form, self.hub, self.outside, EMBEDDER, shc.EMBEDDER_REVISION,
                           shc.EMBEDDER_CONFIG_SIZE)
                proc = self.run_cli(*self.cli_args("--verify-only"))
                self.assertEqual(proc.returncode, shc.EXIT_LAYOUT, proc.stderr)
                self.assertEqual(proc.stdout.splitlines(), self.expected(form))
                self.assertNotIn(TRACEBACK_MARK, proc.stderr)

    def test_empty_hub_via_cli_9509(self):
        proc = self.run_cli(*self.cli_args("--verify-only"))
        self.assertEqual(proc.returncode, shc.EXIT_LAYOUT, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), [f"{ERROR_PREFIX}missing ref refs/main for {EMBEDDER}"])

    def test_unknown_model_set_is_usage_error_9509(self):
        proc = self.run_cli("--models", "bogus", "--runner-temp", str(self.runner_temp),
                            "--workspace", str(self.workspace))
        self.assertEqual(proc.returncode, EXIT_USAGE)
        self.assertNotIn(TRACEBACK_MARK, proc.stderr)

    def test_runner_temp_and_workspace_are_required_9509(self):
        for args in (["--models", "embedder"], ["--models", "embedder", "--runner-temp", str(self.runner_temp)]):
            with self.subTest(args=args):
                proc = self.run_cli(*args)
                self.assertEqual(proc.returncode, EXIT_USAGE)
                self.assertNotIn(TRACEBACK_MARK, proc.stderr)


class Placement(Scratch):
    """D2-1: the hub is the job-private root under runner.temp, outside the checkout, or exit 13."""

    def assert_placement(self, proc, text: str) -> None:
        self.assertEqual(proc.returncode, shc.EXIT_PLACEMENT, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), [ERROR_PREFIX + shc.clean(text)])
        self.assertNotIn(TRACEBACK_MARK, proc.stderr)

    def test_unset_hf_home_9509(self):
        self.assert_placement(self.run_cli(*self.cli_args("--verify-only"), hf_home=""),
                              "HF_HOME is not set; run scripts/ci/hf_home_private.py first")

    def test_blank_hf_home_9509(self):
        self.assert_placement(self.run_cli(*self.cli_args("--verify-only"), hf_home="  "),
                              "HF_HOME is not set; run scripts/ci/hf_home_private.py first")

    def test_runner_user_cache_is_refused_9509(self):
        user_cache = self.home / ".cache" / "huggingface"
        (user_cache / "hub").mkdir(parents=True)
        self.assert_placement(self.run_cli(*self.cli_args("--verify-only"), hf_home=str(user_cache)),
                              "HF_HOME is not the job-private root under the runner temp dir")

    def test_symlinked_private_root_to_user_cache_is_refused_9509(self):
        user_cache = self.home / ".cache" / "huggingface"
        (user_cache / "hub").mkdir(parents=True)
        link_temp = self.root / "rt-link"
        link_temp.mkdir()
        os.symlink(user_cache, link_temp / shc.PRIVATE_DIR_NAME)
        proc = self.run_cli("--models", "embedder", "--runner-temp", str(link_temp),
                            "--workspace", str(self.workspace), "--verify-only",
                            hf_home=str(link_temp / shc.PRIVATE_DIR_NAME))
        self.assert_placement(proc, "HF_HOME is not the job-private root under the runner temp dir")

    def test_runner_temp_inside_checkout_is_refused_9509(self):
        inner_temp = self.workspace / "rt"
        (inner_temp / shc.PRIVATE_DIR_NAME / "hub").mkdir(parents=True)
        proc = self.run_cli("--models", "embedder", "--runner-temp", str(inner_temp),
                            "--workspace", str(self.workspace), "--verify-only",
                            hf_home=str(inner_temp / shc.PRIVATE_DIR_NAME))
        self.assert_placement(proc, "HF_HOME overlaps the checkout")

    def test_relative_paths_are_refused_9509(self):
        proc = self.run_cli("--models", "embedder", "--runner-temp", "rt", "--workspace", str(self.workspace),
                            "--verify-only")
        self.assert_placement(proc, "runner temp and workspace must be absolute paths")

    def test_placement_problem_accepts_only_the_private_root_9509(self):
        self.assertIsNone(shc.placement_problem(self.hub, str(self.runner_temp), str(self.workspace)))


class HfHomeOnly(Scratch):
    """D2-3 (stage half): the step resolves from HF_HOME alone; HOME is never read."""

    def test_complete_cache_under_home_is_ignored_9509(self):
        build_blob_tree(self.home / ".cache" / "huggingface" / "hub", EMBEDDER, shc.EMBEDDER_REVISION,
                        SMALL_BYTES)
        proc = self.run_cli(*self.cli_args("--verify-only"))
        self.assertEqual(proc.returncode, shc.EXIT_LAYOUT, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), [f"{ERROR_PREFIX}missing ref refs/main for {EMBEDDER}"])

    def test_hub_root_reads_only_hf_home_9509(self):
        self.assertEqual(shc.hub_root({"HF_HOME": "/r/x", "HOME": "/h"}), Path("/r/x/hub"))
        self.assertIsNone(shc.hub_root({"HOME": "/h"}))
        self.assertIsNone(shc.hub_root({"HF_HOME": "", "HOME": "/h"}))


class Fetch(Scratch):
    def test_cold_cache_fetches_the_pinned_revision_never_main_9509(self):
        net = FakeNet(SMALL_BYTES)
        code, lines = self.stage_small(verify_only=False, net=net)
        self.assertEqual(code, shc.EXIT_OK)
        self.assertEqual(len(net.urls), len(SMALL_BYTES))
        for url in net.urls:
            self.assertTrue(url.startswith(f"{shc.HF_BASE_URL}/{EMBEDDER}/resolve/{shc.EMBEDDER_REVISION}/"), url)
            self.assertNotIn("/resolve/main/", url)
        self.assertEqual(lines[-1], f"{NOTICE_PREFIX}{EMBEDDER} matches the pinned manifest at {shc.EMBEDDER_REVISION}")
        ref = repo_base(self.hub, EMBEDDER) / "refs" / "main"
        self.assertEqual(ref.read_bytes(), shc.EMBEDDER_REVISION.encode("ascii"))

    def test_warm_cache_never_fetches_9509(self):
        build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, SMALL_BYTES)
        net = FakeNet(SMALL_BYTES)
        self.assertEqual(self.stage_small(verify_only=False, net=net)[0], shc.EXIT_OK)
        self.assertEqual(net.urls, [])

    # A form whose damage is a symlinked directory, a directory in place of a file or a refs/
    # dir without search permission is never written through: the fetch refuses it (exit 11).
    # Every other form is repaired per artifact.
    FETCH_REFUSED_FORMS = frozenset({"blobs_dir_symlink_out_of_repo", "leaf_dir_symlink", "directory_not_file",
                                     "ref_is_directory", "unreadable_ref"})

    def test_every_damaged_form_has_one_exact_fetch_outcome_9509(self):
        size = len(SMALL_BYTES[shc.CONFIG_FILE])
        for form in CACHE_FORMS:
            with self.subTest(form=form):
                self.tearDown()
                self.setUp()
                build_blob_tree(self.hub, EMBEDDER, shc.EMBEDDER_REVISION, SMALL_BYTES)
                apply_form(form, self.hub, self.outside, EMBEDDER, shc.EMBEDDER_REVISION, size)
                code, lines = self.stage_small(verify_only=False, net=FakeNet(SMALL_BYTES))
                if form in self.FETCH_REFUSED_FORMS:
                    self.assertEqual(code, shc.EXIT_FETCH)
                    self.assertEqual(lines[-1], f"{ERROR_PREFIX}could not stage {EMBEDDER} after "
                                                f"{shc.FETCH_ATTEMPTS} attempts")
                else:
                    self.assertEqual(code, shc.EXIT_OK, lines)
                    self.assertEqual(shc.repo_problems(self.hub, EMBEDDER, shc.EMBEDDER_REVISION,
                                                       small_manifest(EMBEDDER)), [])

    def test_fetch_failure_is_exit_11_with_backoff_9509(self):
        net = FakeNet(SMALL_BYTES, failures=shc.FETCH_ATTEMPTS * len(SMALL_BYTES))
        code, lines = self.stage_small(verify_only=False, net=net)
        self.assertEqual(code, shc.EXIT_FETCH)
        self.assertEqual(net.sleeps, [n * shc.BACKOFF_STEP_SECONDS for n in range(1, shc.FETCH_ATTEMPTS)])
        self.assertEqual(lines[-1], f"{ERROR_PREFIX}could not stage {EMBEDDER} after {shc.FETCH_ATTEMPTS} attempts")

    def test_retry_then_success_9509(self):
        net = FakeNet(SMALL_BYTES, failures=1)
        code, lines = self.stage_small(verify_only=False, net=net)
        self.assertEqual(code, shc.EXIT_OK)
        self.assertEqual(net.sleeps, [shc.BACKOFF_STEP_SECONDS])
        self.assertIn(f"{NOTICE_PREFIX}staged {EMBEDDER} at {shc.EMBEDDER_REVISION} (attempt 2)", lines)

    def test_served_bytes_that_differ_are_never_staged_9509(self):
        wrong = dict(SMALL_BYTES)
        wrong[shc.CONFIG_FILE] = FILLER * len(SMALL_BYTES[shc.CONFIG_FILE])
        oversized = dict(SMALL_BYTES)
        oversized[shc.CONFIG_FILE] = SMALL_BYTES[shc.CONFIG_FILE] + FILLER
        for served in (wrong, oversized):
            with self.subTest(size=len(served[shc.CONFIG_FILE])):
                self.tearDown()
                self.setUp()
                code, _ = self.stage_small(verify_only=False, net=FakeNet(served))
                self.assertEqual(code, shc.EXIT_FETCH)
                blobs = repo_base(self.hub, EMBEDDER) / "blobs"
                self.assertEqual(sorted(p.name for p in blobs.iterdir() if p.name.endswith(shc.INCOMPLETE_SUFFIX)), [])
                self.assertFalse((repo_base(self.hub, EMBEDDER) / "refs" / "main").exists())

    def test_timeout_is_a_failed_attempt_9509(self):
        net = FakeNet(SMALL_BYTES, failures=shc.FETCH_ATTEMPTS * len(SMALL_BYTES), exc=TimeoutError("slow"))
        self.assertEqual(self.stage_small(verify_only=False, net=net)[0], shc.EXIT_FETCH)

    def test_verify_only_never_fetches_9509(self):
        net = FakeNet(SMALL_BYTES)
        self.assertEqual(self.stage_small(verify_only=True, net=net)[0], shc.EXIT_LAYOUT)
        self.assertEqual(net.urls, [])

    def test_output_never_contains_a_host_path_9509(self):
        net = FakeNet(SMALL_BYTES, failures=shc.FETCH_ATTEMPTS * len(SMALL_BYTES))
        _, lines = self.stage_small(verify_only=False, net=net)
        for line in lines:
            self.assertNotIn(str(self.root), line)


class Redirects(unittest.TestCase):
    def test_redirect_to_plain_http_is_refused_9509(self):
        handler = shc.HttpsOnlyRedirect()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            handler.redirect_request(None, None, 302, "Found", {}, "http://cdn.example/blob")
        self.assertEqual(caught.exception.code, 302)
        self.assertEqual(caught.exception.reason, "redirect to a non-https URL refused")

    def test_non_https_url_is_refused_before_any_request_9509(self):
        with self.assertRaises(urllib.error.URLError) as caught:
            shc.open_url("http://huggingface.co/x")
        self.assertEqual(caught.exception.reason, "non-https URL refused")


class ByConstruction(unittest.TestCase):
    """N7 / N8: no child process, no package install, no token, no Authorization header."""

    ALLOWED_IMPORTS = frozenset({
        "__future__", "argparse", "hashlib", "os", "re", "stat", "sys", "time", "urllib.error",
        "urllib.parse", "urllib.request", "collections.abc", "dataclasses", "pathlib", "typing",
    })
    FORBIDDEN_NAMES = frozenset({"subprocess", "system", "popen", "spawn", "execv", "execvp", "pip"})
    FORBIDDEN_TEXT = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "Authorization", "huggingface_hub", "pip ")

    def tree(self) -> ast.Module:
        return ast.parse(SCRIPT.read_text(encoding="utf-8"))

    def test_imports_are_exactly_the_stdlib_set_9509(self):
        found = set()
        for node in ast.walk(self.tree()):
            if isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.add(node.module)
        self.assertEqual(found, self.ALLOWED_IMPORTS)

    def test_no_child_process_or_install_name_9509(self):
        names = {n.id for n in ast.walk(self.tree()) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(self.tree()) if isinstance(n, ast.Attribute)}
        self.assertEqual((names | attrs) & self.FORBIDDEN_NAMES, set())

    def test_no_token_or_auth_text_outside_docstrings_9509(self):
        module = self.tree()
        docstrings = set()
        for node in ast.walk(module):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and ast.get_docstring(node):
                docstrings.add(id(node.body[0].value))
        for node in ast.walk(module):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                for text in self.FORBIDDEN_TEXT:
                    self.assertNotIn(text, node.value)

    def test_the_only_environment_name_read_is_hf_home_9509(self):
        keys = set()
        for node in ast.walk(self.tree()):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "env" and node.args):
                keys.add(ast.unparse(node.args[0]))
        self.assertEqual(keys, {"HF_HOME_ENV"})


class Clean(unittest.TestCase):
    def test_hostile_names_cannot_form_a_workflow_command_9509(self):
        hostile = "a::error::b\n##[x]%0A,#[y] \x1b"
        cleaned = shc.clean(hostile)
        for bad in ("::", "##[", "%", "\n", " ", "\x1b", "#", "["):
            self.assertNotIn(bad, cleaned)

    def test_length_is_bounded_9509(self):
        self.assertEqual(len(shc.clean("a" * 100_000)), shc.MAX_MESSAGE_CHARS)


if __name__ == "__main__":
    unittest.main()
