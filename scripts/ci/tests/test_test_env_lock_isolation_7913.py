#!/usr/bin/env python3
"""#7913: the Test-env HOME-lock gate census is isolated from its self-tests."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/check_test_env_lock_harness.py"
PROBE = "src/check_test_env_arm_e_probe_3523.rs"
PROBE_BODY = "// planted self-test fixture\n"


def load():
    spec = importlib.util.spec_from_file_location("harness_7913", str(HELPER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git(cwd, *args):
    subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@invalid",
         "-c", "commit.gpgsign=false"] + list(args),
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def census(root):
    """The real gate in a tree; returns (rc, output)."""
    res = subprocess.run(["bash", "scripts/check-test-env-lock.sh"], cwd=str(root),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return res.returncode, res.stdout.decode()


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.h = load()
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="isolation-7913-", dir=str(base)))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.root = self.tmp / "tree"
        for rel in ("scripts/check-test-env-lock.sh",):
            self._copy(rel)
        for sub in ("scripts/lib", "scripts/qc-allowlists"):
            for p in (ROOT / sub).rglob("*"):
                if p.is_file():
                    self._copy(str(p.relative_to(ROOT)))
        (self.root / "src").mkdir(parents=True, exist_ok=True)
        (self.root / "src/lib.rs").write_text("pub fn clean() {}\n")
        (self.root / "tests").mkdir()
        (self.root / "tests/.keep").write_text("")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "scratch")

    def _copy(self, rel):
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(ROOT / rel), str(dest))


class IsolationTest(TreeCase):
    def test_probe_in_scratch_tree_does_not_affect_clean_census(self):
        rc0, out0 = census(self.root)
        self.assertEqual(rc0, 0, out0[-400:])
        scratch = self.h.make_copy(self.root, self.tmp / "scratch")
        (scratch / PROBE).write_text(PROBE_BODY)
        self.assertTrue((scratch / PROBE).exists())
        rc1, out1 = census(self.root)
        self.assertEqual((rc1, out1), (rc0, out0))
        self.assertFalse((self.root / PROBE).exists())

    def test_preexisting_probe_in_census_tree_exits_3_with_message(self):
        (self.root / PROBE).write_text(PROBE_BODY)
        res = subprocess.run(
            ["python3", str(HELPER), "census", "--root", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(res.returncode, 3)
        self.assertEqual(res.stderr.decode().strip(),
                         "self-test fixture present: " + PROBE)
        self.assertEqual((self.root / PROBE).read_text(), PROBE_BODY)

    def test_clean_tree_census_passes_through_the_helper(self):
        res = subprocess.run(
            ["python3", str(HELPER), "census", "--root", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        self.assertEqual(res.returncode, 0, res.stdout.decode()[-400:])

    def test_selftest_copy_removed_after_simulated_failure(self):
        seen = []

        def failing(copy):
            seen.append(copy)
            self.assertTrue(copy.is_dir())
            (copy / PROBE).write_text(PROBE_BODY)
            return ["bash", "-c", "exit 7"]

        rc = self.h.run_isolated(self.root, failing, "failcase")
        self.assertEqual(rc, 7)
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())
        self.assertFalse((self.root / self.h.SELFTEST_DIR).exists())
        self.assertFalse((self.root / PROBE).exists())

    def test_selftest_copy_removed_when_the_runner_raises(self):
        def boom(copy):
            raise OSError("simulated launch failure")

        with self.assertRaises(OSError):
            self.h.run_isolated(self.root, boom, "raisecase")
        self.assertFalse((self.root / self.h.SELFTEST_DIR).exists())

    def test_copy_never_inherits_a_source_fixture(self):
        (self.root / PROBE).write_text(PROBE_BODY)
        copy = self.h.make_copy(self.root, self.tmp / "copy")
        self.assertFalse((copy / PROBE).exists())


FAKE_GATE = "scripts/fake-selftest-gate.sh"
# Stands in for ``check-test-env-lock.sh --self-test``: plants the plain and the
# dot-prefixed probes in ITS working tree, records where it ran, and leaves
# them behind (a real run removes them; the private copy is deleted anyway).
FAKE_GATE_BODY = """#!/usr/bin/env bash
set -u
mkdir -p src
: > src/check_test_env_arm_e_probe_9999.rs
: > src/.check_home_lock_violation_probe.rs
pwd > "@RECORD@"
"""


class SelftestIsolationTest(TreeCase):
    """#7919: observe WHERE ``selftest`` runs, not just that helpers exist."""

    def _fake_gate(self):
        gate = self.root / FAKE_GATE
        record = str(self.tmp / "record")
        gate.write_text(FAKE_GATE_BODY.replace("@RECORD@", record))
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "fake gate")

    def _snapshot(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")
                      if p.is_file() and ".git" not in p.parts)

    def observe_selftest(self):
        """Run ``selftest`` through ``main`` on the census tree; return violations."""
        self._fake_gate()
        record = self.tmp / "record"
        before = self._snapshot()
        rc = self.h.main(["selftest", "--root", str(self.root), "--gate", FAKE_GATE])
        problems = []
        if rc != 0:
            problems.append("selftest rc=%d" % rc)
        ran_in = Path(record.read_text().strip()).resolve()
        if ran_in == self.root.resolve():
            problems.append("self-test ran in the census checkout %s" % ran_in)
        leaked = sorted(p.name for p in (self.root / "src").glob("*probe*.rs"))
        leaked += sorted(p.name for p in (self.root / "src").glob(".*probe*.rs"))
        if leaked:
            problems.append("probe files in the census checkout: %s" % leaked)
        if self._snapshot() != before:
            problems.append("census tree changed during the self-test")
        return problems

    def test_selftest_never_touches_the_census_checkout(self):
        self.assertEqual(self.observe_selftest(), [])

    def test_in_place_helper_is_caught_by_the_observation(self):
        """Red proof: a helper that runs the self-test in place must FAIL here."""
        def in_place(root, argv_for, tag):
            return subprocess.run(argv_for(Path(root)), cwd=str(root),
                                  check=False).returncode

        self.h.run_isolated = in_place
        problems = self.observe_selftest()
        self.assertTrue(any("census checkout" in p for p in problems), problems)
        self.assertTrue(any("probe files" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
