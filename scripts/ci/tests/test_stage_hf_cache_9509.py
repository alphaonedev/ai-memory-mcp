#!/usr/bin/env python3
"""Cells for scripts/ci/stage_hf_cache.py (#9509).

One implementation stages (and verifies) the HuggingFace model cache for the
ci.yml `check` job and the coverage.yml `per-module-thresholds` job. Each
failure form has its own exit code and exact text. The fetch, the installer
and the sleep are injected, so no cell touches the network or sleeps; the one
cell that runs the real CLI fetch is gated on STAGE_HF_CACHE_NO_NETWORK=1
(set only by the network-less r2 container run).

Open point (kept open): what filled the model files in the green jobs is not
proven; this script only makes the job provide or refuse the cache itself.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_stage_hf_cache_9509.py'
Python 3.12 floor, standard library only.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CI_DIR))
import stage_hf_cache as shc  # noqa: E402

SCRIPT = CI_DIR / "stage_hf_cache.py"
EMBEDDER = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER = "cross-encoder/ms-marco-MiniLM-L-6-v2"
COMMIT = "a" * 40
PREFIX = "::error::stage_hf_cache: "
FILES = ("config.json", "tokenizer.json", "model.safetensors")
NO_NETWORK_ENV = "STAGE_HF_CACHE_NO_NETWORK"


def build_cache(hub: Path, repo: str, skip: str | None = None, ref: str | None = COMMIT) -> Path:
    """Write a layout the Rust loader resolves; `skip` names one file to omit."""
    base = hub / ("models--" + repo.replace("/", "--"))
    snap = base / "snapshots" / COMMIT
    snap.mkdir(parents=True, exist_ok=True)
    if ref is not None:
        (base / "refs").mkdir(parents=True, exist_ok=True)
        (base / "refs" / "main").write_text(ref + "\n")
    for name in FILES:
        if name != skip:
            (snap / name).write_text("x")
    return snap


class Recorder:
    """Injected operations; records every call."""

    def __init__(self, hub: Path, fetch_results=None, have_hub=True, install_ok=True, populate=True):
        self.hub = hub
        self.fetch_calls: list[str] = []
        self.sleeps: list[int] = []
        self.installs = 0
        self.fetch_results = fetch_results
        self.have = have_hub
        self.install_ok = install_ok
        self.populate = populate

    def ops(self) -> "shc.Ops":
        return shc.Ops(
            fetch=self.fetch,
            install=self.install,
            have_hub=lambda: self.have,
            sleep=self.sleeps.append,
        )

    def fetch(self, repo: str) -> bool:
        self.fetch_calls.append(repo)
        n = len(self.fetch_calls)
        if self.fetch_results is not None:
            result = self.fetch_results(n)
            if isinstance(result, BaseException):
                raise result
            if not result:
                return False
        if self.populate:
            build_cache(self.hub, repo)
        return True

    def install(self) -> bool:
        self.installs += 1
        return self.install_ok


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self._td.cleanup)
        self.home = Path(self._td.name)
        self.hub = self.home / ".cache" / "huggingface" / "hub"
        self.hub.mkdir(parents=True)

    def run_main(self, argv, rec: Recorder):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = shc.main(argv, ops=rec.ops(), env={"HOME": str(self.home)})
        return rc, out.getvalue().splitlines()


class ExitCodeTable(unittest.TestCase):
    def test_named_codes(self):
        self.assertEqual(
            (shc.EXIT_OK, shc.EXIT_LAYOUT, shc.EXIT_FETCH, shc.EXIT_INSTALL), (0, 10, 11, 12)
        )

    def test_retry_constants(self):
        self.assertEqual(shc.FETCH_ATTEMPTS, 5)
        self.assertEqual(shc.BACKOFF_STEP_SECONDS, 10)

    def test_model_sets_and_artifacts(self):
        self.assertEqual(shc.MODEL_SETS["embedder"], (EMBEDDER,))
        self.assertEqual(shc.MODEL_SETS["all"], (EMBEDDER, RERANKER))
        self.assertEqual(shc.ARTIFACT_FILES, FILES)


class HubRoot(unittest.TestCase):
    def test_hf_home_wins(self):
        self.assertEqual(shc.hub_root({"HF_HOME": "/h", "HOME": "/u"}), Path("/h/hub"))

    def test_blank_hf_home_falls_back_to_home(self):
        self.assertEqual(
            shc.hub_root({"HF_HOME": "  ", "HOME": "/u"}), Path("/u/.cache/huggingface/hub")
        )

    def test_home_default(self):
        self.assertEqual(shc.hub_root({"HOME": "/u"}), Path("/u/.cache/huggingface/hub"))


class LayoutCheck(Base):
    def problems(self, repo=EMBEDDER):
        return shc.layout_problems(self.hub, repo)

    def test_complete_layout_has_no_problem(self):
        build_cache(self.hub, EMBEDDER)
        self.assertEqual(self.problems(), [])

    def test_missing_ref(self):
        build_cache(self.hub, EMBEDDER, ref=None)
        self.assertEqual(self.problems(), [f"missing ref refs/main for {EMBEDDER}"])

    def test_missing_repo_dir_is_missing_ref(self):
        self.assertEqual(self.problems(), [f"missing ref refs/main for {EMBEDDER}"])

    def test_missing_snapshot_dir(self):
        base = self.hub / ("models--" + EMBEDDER.replace("/", "--"))
        (base / "refs").mkdir(parents=True)
        (base / "refs" / "main").write_text(COMMIT)
        self.assertEqual(
            self.problems(), [f"missing snapshot dir snapshots/{COMMIT} for {EMBEDDER}"]
        )

    def test_each_missing_file_is_red(self):
        for name in FILES:
            with self.subTest(missing=name):
                repo = f"org/{name.replace('.', '-')}"
                build_cache(self.hub, repo, skip=name)
                self.assertEqual(
                    shc.layout_problems(self.hub, repo),
                    [f"missing {name} in snapshots/{COMMIT} for {repo}"],
                )

    def test_dangling_symlink_counts_as_missing(self):
        snap = build_cache(self.hub, EMBEDDER, skip="model.safetensors")
        os.symlink(self.home / "nowhere", snap / "model.safetensors")
        self.assertEqual(
            self.problems(), [f"missing model.safetensors in snapshots/{COMMIT} for {EMBEDDER}"]
        )

    def test_hostile_ref_content_is_refused_not_followed(self):
        for bad in ("../../etc", "a/b", "", "x y", "\x1b[31m", "a\nb"):
            with self.subTest(ref=bad):
                repo = f"org/ref{abs(hash(bad))}"
                build_cache(self.hub, repo, ref=bad)
                self.assertEqual(
                    shc.layout_problems(self.hub, repo),
                    [f"invalid ref content in refs/main for {repo}"],
                )

    def test_all_problems_reported_for_one_repo(self):
        snap = build_cache(self.hub, EMBEDDER)
        (snap / "config.json").unlink()
        (snap / "tokenizer.json").unlink()
        self.assertEqual(
            self.problems(),
            [
                f"missing config.json in snapshots/{COMMIT} for {EMBEDDER}",
                f"missing tokenizer.json in snapshots/{COMMIT} for {EMBEDDER}",
            ],
        )


class Stage(Base):
    def test_warm_cache_never_fetches(self):
        build_cache(self.hub, EMBEDDER)
        rec = Recorder(self.hub)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(rec.fetch_calls, [])
        self.assertEqual(rec.installs, 0)
        self.assertEqual(out, [f"::notice::stage_hf_cache: {EMBEDDER} resolvable (3 artifacts)"])

    def test_cold_cache_fetches_then_verifies(self):
        rec = Recorder(self.hub)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(rec.fetch_calls, [EMBEDDER])
        self.assertIn(f"::notice::stage_hf_cache: staged {EMBEDDER} (attempt 1)", out)
        self.assertEqual(out[-1], f"::notice::stage_hf_cache: {EMBEDDER} resolvable (3 artifacts)")

    def test_all_set_tops_up_only_the_missing_repo(self):
        build_cache(self.hub, EMBEDDER)
        rec = Recorder(self.hub)
        rc, _ = self.run_main(["--models", "all"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(rec.fetch_calls, [RERANKER])

    def test_retry_then_success(self):
        rec = Recorder(self.hub, fetch_results=lambda n: n >= 3)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(len(rec.fetch_calls), 3)
        self.assertEqual(rec.sleeps, [10, 20])
        self.assertIn(f"::warning::stage_hf_cache: fetch {EMBEDDER} attempt 1 failed", out[0])
        self.assertIn(f"::notice::stage_hf_cache: staged {EMBEDDER} (attempt 3)", out)

    def test_fetch_failure_exit_and_text(self):
        rec = Recorder(self.hub, fetch_results=lambda n: False)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_FETCH)
        self.assertEqual(len(rec.fetch_calls), shc.FETCH_ATTEMPTS)
        self.assertEqual(rec.sleeps, [10, 20, 30, 40])
        self.assertEqual(
            out[-1], f"{PREFIX}could not stage {EMBEDDER} after {shc.FETCH_ATTEMPTS} attempts"
        )

    def test_fetch_timeout_is_a_failed_attempt(self):
        exc = subprocess.TimeoutExpired(cmd="x", timeout=1)
        rec = Recorder(self.hub, fetch_results=lambda n: exc if n == 1 else True)
        rc, _ = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(len(rec.fetch_calls), 2)

    def test_fetch_ok_but_files_missing_is_layout_error(self):
        rec = Recorder(self.hub, populate=False)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_LAYOUT)
        self.assertEqual(out[-1], f"{PREFIX}missing ref refs/main for {EMBEDDER}")

    def test_installer_runs_only_when_hub_absent_and_fails_with_own_code(self):
        rec = Recorder(self.hub, have_hub=False, install_ok=False)
        rc, out = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_INSTALL)
        self.assertEqual(rec.installs, 1)
        self.assertEqual(rec.fetch_calls, [])
        self.assertEqual(out[-1], f"{PREFIX}could not install huggingface_hub")

    def test_installer_success_then_fetch(self):
        rec = Recorder(self.hub, have_hub=False)
        rc, _ = self.run_main(["--models", "embedder"], rec)
        self.assertEqual(rc, shc.EXIT_OK)
        self.assertEqual(rec.installs, 1)

    def test_verify_only_never_fetches_or_installs(self):
        rec = Recorder(self.hub, have_hub=False)
        rc, out = self.run_main(["--models", "embedder", "--verify-only"], rec)
        self.assertEqual(rc, shc.EXIT_LAYOUT)
        self.assertEqual((rec.fetch_calls, rec.installs), ([], 0))
        self.assertEqual(out, [f"{PREFIX}missing ref refs/main for {EMBEDDER}"])

    def test_output_never_contains_the_home_path(self):
        rec = Recorder(self.hub, populate=False)
        _, out = self.run_main(["--models", "all"], rec)
        self.assertFalse([line for line in out if str(self.home) in line])


class Cli(Base):
    def run_cli(self, *args, env_extra=None):
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)}
        env.update(env_extra or {})
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_layout_red_on_empty_cache_via_cli(self):
        proc = self.run_cli("--models", "embedder", "--verify-only")
        self.assertEqual(proc.returncode, 10, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(), [f"{PREFIX}missing ref refs/main for {EMBEDDER}"])

    def test_layout_green_via_cli(self):
        build_cache(self.hub, EMBEDDER)
        proc = self.run_cli("--models", "embedder", "--verify-only")
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_unknown_model_set_is_usage_error(self):
        proc = self.run_cli("--models", "bogus")
        self.assertEqual(proc.returncode, 2)

    def test_hf_home_is_honoured_via_cli(self):
        other = self.home / "alt"
        build_cache(other / "hub", EMBEDDER)
        proc = self.run_cli("--models", "embedder", "--verify-only", env_extra={"HF_HOME": str(other)})
        self.assertEqual(proc.returncode, 0, proc.stdout)

    @unittest.skipUnless(
        os.environ.get(NO_NETWORK_ENV) == "1",
        f"real fetch cell runs only in the network-less container ({NO_NETWORK_ENV}=1)",
    )
    def test_real_fetch_without_network_ends_with_a_named_code(self):
        proc = self.run_cli("--models", "embedder")
        # huggingface_hub absent -> install fails (12); present -> fetch fails (11).
        self.assertIn(proc.returncode, (shc.EXIT_FETCH, shc.EXIT_INSTALL), proc.stdout)
        last = proc.stdout.splitlines()[-1]
        if proc.returncode == shc.EXIT_FETCH:
            self.assertEqual(
                last, f"{PREFIX}could not stage {EMBEDDER} after {shc.FETCH_ATTEMPTS} attempts"
            )
        else:
            self.assertEqual(last, f"{PREFIX}could not install huggingface_hub")


if __name__ == "__main__":
    unittest.main()
