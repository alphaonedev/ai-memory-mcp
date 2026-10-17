"""Pins scripts/ci/watchdog_margin.py and its wiring into the CI test step (#7343)."""
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("watchdog_margin", str(ROOT / "scripts/ci/watchdog_margin.py"))
wm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wm)


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = wm.main(list(argv))
    return rc, buf.getvalue()


class MarginTests(unittest.TestCase):
    def test_pr_7298_serial_shard_warns(self):
        rc, out = run("--label", "[serial] test binaries", "--elapsed", "3611", "--budget", "3611")
        self.assertEqual(rc, 0)
        self.assertIn("::warning::[#7343]", out)
        self.assertIn("100% used", out)

    def test_over_85_percent_warns(self):
        rc, out = run("--label", "s", "--elapsed", "3714", "--budget", "3996")
        self.assertEqual(rc, 0)
        self.assertIn("92% used", out)

    def test_exactly_85_percent_is_quiet(self):
        self.assertEqual(run("--label", "s", "--elapsed", "85", "--budget", "100"), (0, ""))

    def test_healthy_shard_is_quiet(self):
        self.assertEqual(run("--label", "s", "--elapsed", "2745", "--budget", "9094"), (0, ""))

    def test_zero_budget_never_fails(self):
        self.assertEqual(run("--label", "s", "--elapsed", "5", "--budget", "0"), (0, ""))

    def test_threshold_is_configurable(self):
        rc, out = run("--label", "s", "--elapsed", "60", "--budget", "100", "--threshold", "50")
        self.assertIn("60% used", out)

    def test_workflow_calls_it_on_green_only(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        call = "scripts/ci/watchdog_margin.py"
        self.assertEqual(text.count(call), 1)
        before = text[: text.index(call)]
        # the call sits inside the rc == 0 branch that prints the #6202 notice
        self.assertGreater(before.rfind('if [ "$rc" -eq 0 ]; then'), before.rfind("elapsed=$(( $(date +%s) - started ))"))


if __name__ == "__main__":
    unittest.main()
