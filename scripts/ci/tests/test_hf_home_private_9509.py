#!/usr/bin/env python3
"""Cells for scripts/ci/hf_home_private.py (#9509, 3-agent vote 71472661 D2-1).

The helper is the one place the job-private HF_HOME is defined: it appends
`HF_HOME=<runner-temp>/<PRIVATE_DIR_NAME>` to $GITHUB_ENV and creates that
directory mode 0700, or it refuses with exit 2 and exports nothing. Each
refusal form has its exact stderr line.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_hf_home_private_9509.py'
Python 3.12 floor, standard library only.
"""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CI_DIR))
import hf_home_private as hhp  # noqa: E402
import stage_hf_cache as shc  # noqa: E402

SCRIPT = CI_DIR / "hf_home_private.py"
CLI_TIMEOUT_SECONDS = 60
TRACEBACK_MARK = "Traceback"
REFUSING = "hf_home_private: refusing: "


class Scratch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(os.path.realpath(self._tmp.name))
        self.runner_temp = self.root / "runner-temp"
        self.workspace = self.root / "workspace"
        self.runner_temp.mkdir()
        self.workspace.mkdir()
        self.env_file = self.root / "github_env"
        self.env_file.write_text("")

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, runner_temp: str, workspace: str):
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--runner-temp", runner_temp, "--workspace", workspace,
             "--github-env", str(self.env_file)],
            env={"PATH": os.environ.get("PATH", "")}, capture_output=True, text=True,
            timeout=CLI_TIMEOUT_SECONDS, check=False,
        )

    def assert_refused(self, proc, reason: str) -> None:
        self.assertEqual(proc.returncode, hhp.EXIT_USAGE, proc.stderr)
        self.assertEqual(proc.stderr.splitlines(), [REFUSING + reason])
        self.assertEqual(proc.stdout, "")
        self.assertEqual(self.env_file.read_text(), "")


class Constants(unittest.TestCase):
    def test_private_dir_name_is_one_value_in_both_scripts_9509(self):
        self.assertEqual(hhp.PRIVATE_DIR_NAME, shc.PRIVATE_DIR_NAME)
        self.assertEqual(hhp.ENV_NAME, shc.HF_HOME_ENV)

    def test_exit_codes_9509(self):
        self.assertEqual((hhp.EXIT_OK, hhp.EXIT_USAGE, hhp.WA_EXIT_LOAD_REFUSED), (0, 2, 3))
        self.assertEqual(hhp.PRIVATE_DIR_MODE, 0o700)


class Export(Scratch):
    def test_exports_the_private_root_and_creates_it_0700_9509(self):
        proc = self.run_cli(str(self.runner_temp), str(self.workspace))
        root = self.runner_temp / hhp.PRIVATE_DIR_NAME
        self.assertEqual(proc.returncode, hhp.EXIT_OK, proc.stderr)
        self.assertEqual(self.env_file.read_text(), f"HF_HOME={root}\n")
        self.assertEqual(proc.stdout.splitlines(), [f"HF_HOME={root}"])
        info = os.lstat(root)
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), hhp.PRIVATE_DIR_MODE)

    def test_second_run_accepts_its_own_directory_9509(self):
        self.assertEqual(self.run_cli(str(self.runner_temp), str(self.workspace)).returncode, hhp.EXIT_OK)
        root = self.runner_temp / hhp.PRIVATE_DIR_NAME
        os.chmod(root, 0o755)
        self.assertEqual(self.run_cli(str(self.runner_temp), str(self.workspace)).returncode, hhp.EXIT_OK)
        self.assertEqual(stat.S_IMODE(os.lstat(root).st_mode), hhp.PRIVATE_DIR_MODE)

    def test_exported_root_passes_the_stage_placement_check_9509(self):
        self.assertEqual(self.run_cli(str(self.runner_temp), str(self.workspace)).returncode, hhp.EXIT_OK)
        hf_home = self.env_file.read_text().strip().split("=", 1)[1]
        hub = shc.hub_root({"HF_HOME": hf_home})
        self.assertIsNone(shc.placement_problem(hub, str(self.runner_temp), str(self.workspace)))


class Refusals(Scratch):
    def test_relative_runner_temp_9509(self):
        self.assert_refused(self.run_cli("rt", str(self.workspace)),
                            "runner temp dir 'rt' is not an absolute directory other than /")

    def test_filesystem_root_runner_temp_9509(self):
        self.assert_refused(self.run_cli("/", str(self.workspace)),
                            "runner temp dir '/' is not an absolute directory other than /")

    def test_relative_workspace_9509(self):
        self.assert_refused(self.run_cli(str(self.runner_temp), "ws"), "workspace 'ws' is not an absolute path")

    def test_runner_temp_inside_checkout_9509(self):
        inner = self.workspace / "rt"
        inner.mkdir()
        root = inner / hhp.PRIVATE_DIR_NAME
        self.assert_refused(self.run_cli(str(inner), str(self.workspace)),
                            f"private root {root} overlaps the checkout {self.workspace}")

    def test_checkout_inside_private_root_9509(self):
        root = self.runner_temp / hhp.PRIVATE_DIR_NAME
        workspace = root / "ws"
        self.assert_refused(self.run_cli(str(self.runner_temp), str(workspace)),
                            f"private root {root} overlaps the checkout {workspace}")

    def test_symlinked_root_9509(self):
        root = self.runner_temp / hhp.PRIVATE_DIR_NAME
        user_cache = self.root / "home" / ".cache" / "huggingface"
        user_cache.mkdir(parents=True)
        os.symlink(user_cache, root)
        self.assert_refused(self.run_cli(str(self.runner_temp), str(self.workspace)),
                            f"private root {root} is not a real directory")

    def test_regular_file_root_9509(self):
        root = self.runner_temp / hhp.PRIVATE_DIR_NAME
        root.write_text("x")
        self.assert_refused(self.run_cli(str(self.runner_temp), str(self.workspace)),
                            f"private root {root} is not a real directory")

    def test_line_break_in_path_9509(self):
        hostile = self.root / "rt\nHF_HOME=evil"
        hostile.mkdir()
        root = os.path.join(str(hostile), hhp.PRIVATE_DIR_NAME)
        proc = self.run_cli(str(hostile), str(self.workspace))
        self.assertEqual(proc.returncode, hhp.EXIT_USAGE, proc.stderr)
        self.assertNotIn(TRACEBACK_MARK, proc.stderr)
        self.assertEqual(self.env_file.read_text(), "")
        self.assertEqual(len(proc.stderr.splitlines()), 1)
        self.assertTrue(proc.stderr.startswith(REFUSING + "private root "))
        self.assertFalse(os.path.lexists(root))


if __name__ == "__main__":
    unittest.main()
