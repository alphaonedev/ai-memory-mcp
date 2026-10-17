"""Guard for the tracked test-dashboard sources (#7313).

(a) every *state.json the dashboard pages fetch must be one the in-tree publisher produces
    (push-state.py writes state.json; deploy.py declares the per-page state files);
(b) deploy.py --help exits 0 and deploy.py never uses shell=True.
"""
import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

DASH = Path(__file__).resolve().parents[3] / "infra" / "cf-dashboard"
PUBLIC = DASH / "public"
NO_SHELL = "shell" + "=True"


def _produced():
    names = set(re.findall(r'"([A-Za-z0-9_-]*state\.json)"', (DASH / "push-state.py").read_text()))
    spec = importlib.util.spec_from_file_location("cf_deploy_7313", DASH / "deploy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return names | set(mod.PAGE_STATE_FILES)


class CfDashboard7313(unittest.TestCase):
    def test_fetched_state_files_are_produced(self):
        pages = sorted(PUBLIC.glob("*.html"))
        self.assertTrue(pages, "no tracked public/*.html")
        produced = _produced()
        self.assertIn("state.json", produced)
        for page in pages:
            for name in set(re.findall(r"([A-Za-z0-9_-]*state\.json)", page.read_text())):
                self.assertIn(name, produced, f"{page.name} fetches unproduced {name}")

    def test_deploy_help_and_no_shell_true(self):
        p = subprocess.run([sys.executable, str(DASH / "deploy.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(NO_SHELL, (DASH / "deploy.py").read_text())


if __name__ == "__main__":
    unittest.main()
