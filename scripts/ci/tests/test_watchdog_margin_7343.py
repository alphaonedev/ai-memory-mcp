"""Pins scripts/ci/watchdog_margin.py and its wiring into the CI test step (#7343)."""
import importlib.util
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
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

    def test_hostile_label_cannot_inject_a_workflow_command_7350(self):
        # GitHub escaping for workflow-command data: % -> %25, CR -> %0D, LF -> %0A.
        hostile = "x\n::error::injected\r::set-output name=a::b 100%"
        rc, out = run("--label", hostile, "--elapsed", "95", "--budget", "100",
                      "--tier", "t\n::error::t", "--node", "n\r\n::error::n")
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1, repr(out))  # exactly one line: the trailing newline only
        self.assertNotIn("\r", out)
        self.assertTrue(out.startswith("::warning::[#7343]"))
        self.assertIn("x%0A::error::injected%0D::set-output name=a::b 100%25", out)
        self.assertIn("tier=t%0A::error::t", out)
        self.assertIn("node=n%0D%0A::error::n", out)

    def test_percent_is_escaped_first_7350(self):
        self.assertEqual(wm.escape_data("%0A\n"), "%250A%0A")

    def test_bad_argument_exits_2_and_zero_budget_is_silent_7351(self):
        # the docstring states exactly this: argparse usage errors exit 2 (the workflow ignores them
        # with `|| true`); a zero or negative budget prints nothing and exits 0
        with self.assertRaises(SystemExit) as cm, redirect_stderr(io.StringIO()):
            wm.main(["--label", "s", "--elapsed", "oops", "--budget", "100"])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(run("--label", "s", "--elapsed", "5", "--budget", "-3"), (0, ""))
        doc = wm.__doc__
        self.assertIn("Exit 2", doc)
        self.assertNotIn("prints a notice and exits", doc)

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
