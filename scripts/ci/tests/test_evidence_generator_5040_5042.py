#!/usr/bin/env python3
"""Issues #5040 and #5042: tests for the vendored certification evidence generator (scripts/evidence/).

#5042: build_bundle.check_run() false-refused a green run when a PASSING gates row merely contained the word RED
(the cert-expiry self-test summary reads "... watched-path violation RED with the ..."). The chain section of
legs.log is now judged on its own and failure markers match only the runner's own row grammar.
#5040: the generator is tracked, runs with --help, and its defaults are repo-relative (no agent-scratch path).

Scratch lives under the worktree's .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_5040_5042.py
"""
import argparse
import importlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tmp_runtime_guard_7393 import GuardedCase

REPO = Path(__file__).resolve().parents[3]
EVIDENCE = REPO / "scripts" / "evidence"
SCRATCH = REPO / ".local-runs"
SCRIPTS = ("run_cert.py", "build_bundle.py", "prep.py")
TIP = "a" * 40

# A chain section as run_cert.py writes it, then the gates rows that used to share the file (#5042).
CHAIN_SECTION = (
    f"== CERT LEGS 10:00Z HEAD={TIP} host=Linux 7.0.11 umask 022 wt=755\n"
    "BUILD_DEFAULT_EXIT 0 10:01Z\n"
    "TEST_EXIT 0 boot_fail_closed_config_3166 :: ok/15 passed/0 failed\n"
    "  COUNT_DIFF cli::backup::tests 81 -> 82 (explain in the RUN-RECORD)\n"
    "BATTERY_DONE aggregate_failures=0 10:20Z\n"
    "REMOVAL_PROOF_EXIT 0 :: overall: PASS :: PROVEN=15 CERT-RED=0 10:40Z\n"
    "CHAIN: removal new_failures=0\n"
    "CHAIN_DONE aggregate_failures=0 10:50Z\n"
)
PASSING_GATES = (
    "0 cert-expiry-upstream :: check-cert-expiry OK\n"
    "0 cert-expiry-selftest :: check-cert-expiry self-test OK: (a) watched-path violation RED with the "
    "§7 expiry sentence; (b) cert-doc touch GREEN\n"
    "signature %G?=G\n"
    "GATES head=" + TIP + " fails=0\n"
    "EXIT=0 leg=gates aggregate_failures=0 10:55Z\n"
)


def load(name):
    if str(EVIDENCE) not in sys.path:
        sys.path.insert(0, str(EVIDENCE))
    return importlib.import_module(name)


class ScratchCase(GuardedCase):
    def setUp(self):
        super().setUp()
        SCRATCH.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix="evidence-5042-", dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.dir), True)

    def legs(self, text):
        (self.dir / "legs.log").write_text(text)
        return self.dir


class CheckRun5042(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def test_passing_gates_row_containing_red_is_accepted_5042(self):
        outd = self.legs(CHAIN_SECTION + PASSING_GATES)
        diffs = self.bb.check_run(outd)
        self.assertEqual(diffs, ["COUNT_DIFF cli::backup::tests 81 -> 82 (explain in the RUN-RECORD)"])

    def test_chain_section_alone_is_accepted_5042(self):
        self.assertEqual(len(self.bb.check_run(self.legs(CHAIN_SECTION))), 1)

    def test_real_red_row_in_the_chain_is_refused_5042(self):
        text = CHAIN_SECTION.replace("BATTERY_DONE", "  RED boot_fail_closed_config_3166\nBATTERY_DONE")
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_real_red_row_after_the_chain_is_refused_5042(self):
        text = CHAIN_SECTION + PASSING_GATES + "  RED docs-vs-ssot\n"
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_vacuous_and_wrong_head_rows_are_refused_5042(self):
        for row in ("  VACUOUS some_bin (0 passed)\n", "BATTERY WRONG-HEAD/DIRTY head=x want=y dirty=1\n"):
            with self.subTest(row=row):
                with self.assertRaises(self.bb.Fatal):
                    self.bb.check_run(self.legs(row + CHAIN_SECTION))

    def test_nonzero_or_missing_chain_done_is_refused_5042(self):
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(CHAIN_SECTION.replace("aggregate_failures=0 10:50Z", "aggregate_failures=2 10:50Z")))
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(CHAIN_SECTION.replace("CHAIN_DONE", "CHAIN_STOPPED")))

    def test_a_red_gates_summary_without_the_row_grammar_does_not_decide_5042(self):
        # Free text that happens to start a word with RED mid-line is not a runner row.
        text = CHAIN_SECTION + "1 cert-expiry-selftest :: the verdict was RED then GREEN\n"
        self.assertEqual(len(self.bb.check_run(self.legs(text))), 1)


class GatesLogName5042(ScratchCase):
    def test_gates_leg_writes_gates_log_not_legs_log_5042(self):
        rc = load("run_cert")
        ns = argparse.Namespace(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="gates")
        self.assertEqual(rc.Run(ns).log.name, "gates.log")
        ns.leg = "chain"
        self.assertEqual(rc.Run(ns).log.name, "legs.log")


class Manifest5037(GuardedCase):
    def test_manifest_order_is_total_and_independent_of_insertion_order(self):
        bb = load("build_bundle")
        a = {"B.txt": b"1", "a.txt": b"2", "c.txt": b"3"}
        b = dict(reversed(list(a.items())))
        self.assertEqual(bb.manifest_text(a), bb.manifest_text(b))
        self.assertEqual([l.split("  ")[1] for l in bb.manifest_text(a).splitlines()], ["a.txt", "B.txt", "c.txt"])

    def test_case_colliding_names_are_refused(self):
        bb = load("build_bundle")
        with self.assertRaises(bb.Fatal):
            bb.manifest_text({"Readme.md": b"1", "README.md": b"2"})


class Vendored5040(GuardedCase):
    def test_scripts_are_tracked_and_run_with_help_5040(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                path = EVIDENCE / name
                self.assertTrue(path.is_file(), f"{path} missing")
                r = subprocess.run([sys.executable, "-I", str(path), "--help"], capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL, cwd=str(SCRATCH if SCRATCH.is_dir() else REPO))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("usage:", r.stdout)

    def test_defaults_are_repo_relative_5040(self):
        rc = load("run_cert")
        for attr in ("DEFAULT_TARGETS", "DEFAULT_TMPDIR"):
            with self.subTest(default=attr):
                p = Path(getattr(rc, attr)).resolve()
                self.assertTrue(str(p).startswith(str(REPO.resolve())), f"{attr}={p} is outside the checkout")
        for name in SCRIPTS:
            with self.subTest(script=name):
                text = (EVIDENCE / name).read_text()
                # leak-scan pattern lists in build_bundle.py legitimately name host prefixes; assign-style defaults must not.
                for line in text.splitlines():
                    if line.lstrip().startswith(("CARGO_SLOT =", "SLOT3_LOCK =", "TMPDIR =", "TARGETS =")):
                        self.fail(f"{name}: absolute default left: {line}")
                self.assertNotIn('default=Path("/', text)

    def test_leak_scan_prefix_set_is_the_attested_set_plus_7415_roots_5040(self):
        # decision: the pin grows by the macOS and root host roots (#7415) over staying frozen at the attested set
        # because the scan must catch those roots; the attested six stay and are asserted first.
        bb = load("build_bundle")
        added = {"/Users/", "/Volumes/", "/var/folders/", "/root/"}
        prefixes = set(bb.HOST_PATH_PREFIXES)
        self.assertLessEqual(added, prefixes)
        self.assertLessEqual({"/mnt/", "/home/"}, prefixes)
        scratch_root = "/" + "ai-" + "scratch"  # the exact attested scratch-root prefix (#7671)
        self.assertIn(scratch_root, prefixes, "the scratch root stays in the attested set")
        self.assertEqual(len(prefixes - added), 6, "the attested six stay and nothing else is added")
        attested = {"/" + part for part in ("mnt/", "home/", "ai-" + "scratch",
                                           "tmp/", "var/" + "tmp", "private/" + "tmp")}
        self.assertEqual(prefixes - added, attested, "each attested prefix stays exact (#7736)")
        self.assertLessEqual(prefixes, set(bb.leak_patterns(Path("/wt-x"), Path("/out-x"))))

    def test_prep_runs_against_the_default_repo_5040(self):
        r = subprocess.run([sys.executable, "-I", str(EVIDENCE / "prep.py"), "--base", "HEAD", "--tip", "HEAD"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=str(REPO))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WATCHED_TOTAL files=0", r.stdout)


RECAPTURE_PY = "scripts/recapture-cert-3607-posture.py"
RECAPTURE_SH = "scripts/recapture-cert-3607-posture.sh"
PY_BODY = (
    "#!/usr/bin/env python3\n"
    "import os\n"
    "from pathlib import Path\n"
    "ROOT = Path(os.path.abspath(__file__)).parent.parent  # logical path\n"
    'OUT = ROOT / "docs" / "compliance" / "evidence" / "cert-3607"\n'
    'FIX = ROOT / ".local-runs" / "cert-3607-fixtures"\n'
    "print(OUT, FIX)\n"
)
SH_BODY = (
    "#!/usr/bin/env bash\n"
    'ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
    'OUT="$ROOT/docs/compliance/evidence/cert-3607"\n'
    'FIX="$ROOT/.local-runs/cert-3607-fixtures"\n'
    'echo "$OUT" "$FIX"\n'
)


class RecaptureResolution7399(ScratchCase):
    """The recapture script is resolved .py first, .sh second; neither is an actionable refusal (#7399)."""

    def make_repo(self, files):
        wt = self.dir / "repo"
        wt.mkdir()
        git = ["git", "-c", "user.name=t", "-c", "user.email=" + "@".join(("t", "fixture.test")),"-c", "commit.gpgsign=false"]
        subprocess.run([*git, "init", "-q"], cwd=wt, check=True)
        (wt / "README").write_text("x\n")
        for rel, body in files.items():
            (wt / rel).parent.mkdir(parents=True, exist_ok=True)
            (wt / rel).write_text(body)
        subprocess.run([*git, "add", "-A"], cwd=wt, check=True)
        subprocess.run([*git, "commit", "-q", "-m", "fixture"], cwd=wt, check=True)
        tip = subprocess.run(["git", "rev-parse", "HEAD"], cwd=wt, capture_output=True, text=True, check=True).stdout.strip()
        return wt, tip

    def test_py_only_is_retargeted_in_python_form_7399(self):
        bb = load("build_bundle")
        wt, tip = self.make_repo({RECAPTURE_PY: PY_BODY})
        rel, src, body = bb.recapture_copy(wt, tip, "abcdef123")
        self.assertEqual(rel, RECAPTURE_PY)
        self.assertEqual(src, PY_BODY)
        self.assertIn('OUT = ROOT / "docs" / "compliance" / "evidence" / "cert-abcdef123"', body)
        self.assertIn('FIX = ROOT / ".local-runs" / "cert-abcdef123-fixtures"', body)
        self.assertIn(".parent.parent.parent.parent.parent", body)

    def test_sh_only_still_works_7399(self):
        bb = load("build_bundle")
        wt, tip = self.make_repo({RECAPTURE_SH: SH_BODY})
        rel, _src, body = bb.recapture_copy(wt, tip, "abcdef123")
        self.assertEqual(rel, RECAPTURE_SH)
        self.assertIn('OUT="$ROOT/docs/compliance/evidence/cert-abcdef123"', body)

    def test_py_wins_when_both_exist_7399(self):
        bb = load("build_bundle")
        wt, tip = self.make_repo({RECAPTURE_PY: PY_BODY, RECAPTURE_SH: SH_BODY})
        self.assertEqual(bb.recapture_copy(wt, tip, "abcdef123")[0], RECAPTURE_PY)

    def test_neither_is_an_actionable_refusal_7399(self):
        bb = load("build_bundle")
        wt, tip = self.make_repo({})
        with self.assertRaises(bb.Fatal) as cm:
            bb.recapture_copy(wt, tip, "abcdef123")
        msg = str(cm.exception)
        self.assertIn(RECAPTURE_PY, msg)
        self.assertIn(RECAPTURE_SH, msg)
        self.assertIn(tip, msg)

    def test_run_cert_resolves_the_same_order_7399(self):
        rc = load("run_cert")
        # #7411: the script is resolved in the tip TREE (git), not on disk, so each case is its own tip.
        wt, tip = self.make_repo({})
        with self.assertRaises(FileNotFoundError) as cm:
            rc.pick_recapture(wt, tip)
        self.assertIn(RECAPTURE_PY, str(cm.exception))
        self.assertIn(RECAPTURE_SH, str(cm.exception))
        shutil.rmtree(wt)
        wt, tip = self.make_repo({RECAPTURE_SH: SH_BODY})
        self.assertEqual(rc.pick_recapture(wt, tip), RECAPTURE_SH)
        shutil.rmtree(wt)
        wt, tip = self.make_repo({RECAPTURE_SH: SH_BODY, RECAPTURE_PY: PY_BODY})
        self.assertEqual(rc.pick_recapture(wt, tip), RECAPTURE_PY)


if __name__ == "__main__":
    unittest.main()
