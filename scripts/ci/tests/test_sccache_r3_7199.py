# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""r3 review findings for #7199 / PR #7219: idle timeout, stats pinning, --stop name.

Run: python3 -m unittest discover -s scripts/ci/tests. The sccache client is
a fake script (the subprocess seam); nothing here touches a real sccache server.
"""
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH_PARENT = REPO / ".local-runs"
SCRATCH = None  # per-run mkdtemp dir, set by setUpModule (#8024)


def setUpModule():
    global SCRATCH
    SCRATCH_PARENT.mkdir(parents=True, exist_ok=True)
    SCRATCH = Path(tempfile.mkdtemp(prefix="sccache-r3-7199-", dir=str(SCRATCH_PARENT)))


def tearDownModule():
    shutil.rmtree(SCRATCH, ignore_errors=True)

sys.path.insert(0, str(REPO / "scripts" / "ci"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sccache_env  # noqa: E402
import shared_cargo_target as shared  # noqa: E402
from test_sccache_and_eviction_7199 import FAKE_SCCACHE, ME, parse_env  # noqa: E402


class R3(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.home = SCRATCH / "home"
        self.bin = SCRATCH / "bin"
        self.home.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        self.env_file = SCRATCH / "github.env"
        self.calls = SCRATCH / "calls.log"
        fake = self.bin / "sccache"
        fake.write_text(FAKE_SCCACHE % sys.executable, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        self.saved_env = dict(os.environ)
        os.environ["FAKE_SCCACHE_LOG"] = str(self.calls)
        os.environ.pop("FAKE_SCCACHE_LOCATION", None)
        os.environ.pop("SCCACHE_SERVER_PORT", None)
        os.environ["RUNNER_TRACKING_ID"] = "github_runner_tracking_7199"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved_env)
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def logged(self):
        text = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return [json.loads(line) for line in text.splitlines()]

    def run_main(self, argv):
        old = os.environ["PATH"]
        os.environ["PATH"] = str(self.bin)
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = sccache_env.main(argv)
        finally:
            os.environ["PATH"] = old
        return rc, out.getvalue(), err.getvalue()

    # MEDIUM 1
    def test_server_env_never_idles_out_and_ignores_io_errors(self):
        env = sccache_env.ci_server_env(os.environ, self.home / "d", self.home / "e.log")
        self.assertEqual(env["SCCACHE_IDLE_TIMEOUT"], "0")
        self.assertEqual(env["SCCACHE_IGNORE_SERVER_IO_ERROR"], "1")
        self.assertEqual(sccache_env.SCCACHE_IDLE_TIMEOUT_SECS, "0")
        self.assertEqual(sccache_env.SCCACHE_IGNORE_SERVER_IO_ERROR, "1")
        self.assertNotIn("RUNNER_TRACKING_ID", env)

    def test_github_env_carries_idle_timeout_and_io_error_flag(self):
        rc, _, _ = self.run_main(["--home", str(self.home), "--github-env", str(self.env_file)])
        self.assertEqual(rc, 0)
        pairs = parse_env(self.env_file)
        self.assertEqual(pairs["SCCACHE_IDLE_TIMEOUT"], "0")
        self.assertEqual(pairs["SCCACHE_IGNORE_SERVER_IO_ERROR"], "1")

    # LOW 2
    def test_stats_skip_when_the_job_has_no_ci_port(self):
        rc, out, _ = self.run_main(["--stats"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.logged(), [])
        self.assertIn("not configured", out)

    def test_stats_skip_when_the_job_port_is_not_the_ci_port(self):
        os.environ["SCCACHE_SERVER_PORT"] = str(sccache_env.SCCACHE_DEFAULT_PORT)
        rc, out, _ = self.run_main(["--stats"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.logged(), [])
        self.assertIn("not configured", out)

    def test_stats_query_the_ci_port_when_configured(self):
        os.environ["SCCACHE_SERVER_PORT"] = str(sccache_env.SCCACHE_SERVER_PORT)
        rc, out, _ = self.run_main(["--stats"])
        self.assertEqual(rc, 0)
        calls = self.logged()
        self.assertEqual([c["args"] for c in calls], [["--show-stats"]])
        self.assertEqual(calls[0]["port"], str(sccache_env.SCCACHE_SERVER_PORT))
        self.assertIn("Compile requests", out)

    # LOW 3
    def test_stop_without_runner_name_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_main(["--stop", "--home", str(self.home)])
        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(self.logged(), [])

    def test_stop_with_invalid_runner_name_is_a_usage_error(self):
        for bad in ("..", "a/b", "x y", ""):
            with self.assertRaises(SystemExit) as ctx:
                self.run_main(["--stop", "--home", str(self.home), "--runner-name", bad])
            self.assertEqual(ctx.exception.code, 2, bad)

    def test_own_fresh_marker_is_not_a_sibling_and_the_server_stops(self):
        root = shared.target_root_dir(self.home)
        (root / ME).mkdir(parents=True)
        shared.write_in_use_marker(root / ME, ME)
        rc, out, _ = self.run_main(["--stop", "--home", str(self.home), "--runner-name", ME])
        self.assertEqual(rc, 0)
        self.assertEqual([c["args"] for c in self.logged()], [["--stop-server"]])
        self.assertNotIn("sibling", out)


if __name__ == "__main__":
    unittest.main()
