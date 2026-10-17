#!/usr/bin/env python3
"""PR #7393 round 4: gate fixtures for the delta r3 review findings on the vendored certification evidence generator.

  #7486  every leg, `gates` included, runs through main() (no KeyError); malformed-row reasons are pinned (HIGH)
  #7487  the PLAN must equal the runner's PLANS[leg], be unique and be the row right after CONFIG
  #7488  a log with no CONFIG row, or rows before the first, needs every section complete and green
  #7489  the expiry gate copy lives in a private directory, never at a fixed in-tree path; a symlink is refused
  #7490  the docstring and the rows match the code: the preflight EXIT row records the real exit code, 64
  #7491  path replacement happens at a path boundary only
  #7492  no test touches a real tmp root

Scratch lives under .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r4_7393.py
"""
import argparse
import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path

from tmp_runtime_guard_7393 import GuardedCase
import unittest.mock as mock

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase, load
from test_evidence_generator_r2_7393 import GIT, make_repo
from test_evidence_generator_r3_7393 import (CHAIN_LEGS, CONFIG, DONE, GREEN_CHAIN, SEC, block, leg_text)

TESTS = Path(__file__).resolve().parent
ALL_LEGS = ("battery", "pg", "removal", "bootstrap", "chain", "gates")


class MainEveryLeg7486(ScratchCase):
    def run_main(self, leg, *extra):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        outd = self.dir / "o"
        argv = ["run_cert.py", leg, "--tip", tip, "--wt", str(wt), "--outd", str(outd),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp"), *extra]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch.object(rc.Run, leg, return_value=0), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main()
        return rc, code, outd, out.getvalue() + err.getvalue()

    def test_every_leg_runs_through_main_with_config_plan_and_exit_rows_7486(self):
        for leg in ALL_LEGS:
            with self.subTest(leg=leg):
                self.setUp()  # a fresh scratch dir per leg
                rc, code, outd, text = self.run_main(leg)
                self.assertEqual(code, 0, text)
                self.assertNotIn("Traceback", text)
                rows = (outd / ("gates.log" if leg == "gates" else "legs.log")).read_text().splitlines()
                self.assertTrue(rows[0].startswith("CONFIG "))
                self.assertEqual(rows[1], f"PLAN leg={leg} legs={','.join(rc.PLANS[leg])}")
                self.assertTrue(rows[-1].startswith(f"EXIT=0 leg={leg} "), rows[-1])

    def test_plans_has_an_entry_for_every_leg_7486(self):
        rc = load("run_cert")
        self.assertEqual(set(rc.PLANS), set(ALL_LEGS))
        self.assertEqual(rc.PLANS["gates"], ("gates",))

    def test_bad_also_evidence_id_is_refused_before_anything_is_written_7486(self):
        rc, code, outd, text = self.run_main("gates", "--also-evidence", "NOT-HEX")
        self.assertEqual(code, 64)
        self.assertIn("9-hex", text)
        self.assertFalse(outd.exists())

    def test_plan_row_never_raises_for_any_leg_7486(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        for leg in ALL_LEGS:
            r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / ("o-" + leg)), leg=leg,
                                          targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
            self.assertTrue(r.plan_row(leg).startswith(f"PLAN leg={leg} "))

    def test_malformed_rows_are_refused_with_the_grammar_reason_7486(self):
        bb = load("build_bundle")
        for bad in ("0.5", "+0", "", "-9"):
            with self.subTest(value=bad):
                text = GREEN_CHAIN.replace("PG_DONE aggregate_failures=0", f"PG_DONE aggregate_failures={bad}")
                (self.dir / "legs.log").write_text(text)
                with self.assertRaises(bb.Fatal) as cm:
                    bb.check_run(self.dir)
                reason = str(cm.exception)
                self.assertIn("not green" if bad == "-9" else "malformed", reason)


class PlanMustEqualThePlans7487(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text, reason=None):
        with self.assertRaises(self.bb.Fatal) as cm:
            self.bb.check_run(self.legs(text))
        if reason is not None:
            self.assertIn(reason, str(cm.exception))

    def test_plan_table_equals_the_runners_7487(self):
        rc = load("run_cert")
        self.assertEqual(dict(self.bb.PLANS), {k: v for k, v in rc.PLANS.items() if k != "gates"})

    def test_short_chain_plan_is_refused_7487(self):
        self.refused(block("chain", ("battery", "chain"), leg_text("battery") + "CHAIN_DONE aggregate_failures=0 10:55Z\n"))

    def test_duplicate_leg_in_a_plan_is_refused_7487(self):
        self.refused(block("pg", ("pg", "pg"), leg_text("pg")))

    def test_reordered_plan_is_refused_7487(self):
        self.refused(GREEN_CHAIN.replace("legs=battery,removal,pg,bootstrap,chain", "legs=chain,battery,removal,pg,bootstrap"))

    # #7528: a green chain in front, then a block whose PLAN is well formed and canonical but is NOT the row right
    # after CONFIG. Nothing else is wrong with these blocks, so only the position rule can refuse them, and the reason
    # is pinned: removing `plans[0][0] != 1` from check_block turns each of them red.
    POSITION = "right after its CONFIG row"
    PG_EXIT = "EXIT=0 leg=pg aggregate_failures=0 1\n"

    def test_plan_after_the_first_section_is_refused_7487(self):
        self.refused(GREEN_CHAIN + CONFIG + "\n" + SEC["pg"] + "PLAN leg=pg legs=pg\n" + DONE["pg"] + self.PG_EXIT,
                     self.POSITION)

    def test_plan_between_the_done_row_and_exit_is_refused_7487(self):
        self.refused(GREEN_CHAIN + CONFIG + "\n" + leg_text("pg") + "PLAN leg=pg legs=pg\n" + self.PG_EXIT, self.POSITION)

    def test_plan_two_rows_after_config_is_refused_7487(self):
        self.refused(GREEN_CHAIN + CONFIG + "\nCOUNT_DIFF note\nPLAN leg=pg legs=pg\n" + leg_text("pg") + self.PG_EXIT,
                     self.POSITION)

    def test_plan_after_the_exit_row_is_refused_7487(self):
        self.refused(GREEN_CHAIN + CONFIG + "\n" + leg_text("pg") + self.PG_EXIT + "PLAN leg=pg legs=pg\n", self.POSITION)

    def test_gates_plan_in_legs_log_is_refused_7487(self):
        self.refused(block("gates", ("gates",), ""))

    def test_the_correct_plans_are_still_accepted_7487(self):
        self.bb.check_run(self.legs(GREEN_CHAIN))
        self.bb.check_run(self.legs(GREEN_CHAIN + block("pg", ("pg",), leg_text("pg"))))


class LogWithoutConfig7488(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")
        self.legacy = "".join(leg_text(l) for l in CHAIN_LEGS[:-1]) + "CHAIN_DONE aggregate_failures=0 10:55Z\n"

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_complete_green_legacy_log_is_accepted_7488(self):
        self.bb.check_run(self.legs(self.legacy))

    def test_legacy_log_with_an_unfinished_section_after_the_chain_is_refused_7488(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.refused(self.legacy + SEC[leg])

    def test_unfinished_section_before_the_first_config_row_is_refused_7488(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.refused(SEC[leg] + GREEN_CHAIN)

    def test_legacy_section_missing_its_done_row_in_the_middle_is_refused_7488(self):
        self.refused(self.legacy.replace(DONE["pg"], ""))

    def test_complete_legacy_prefix_before_config_is_accepted_7488(self):
        self.bb.check_run(self.legs(self.legacy + GREEN_CHAIN))


class ExpiryGateWritesNothing7489(ScratchCase):
    def make(self, files=None):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", files if files is not None else {"scripts/check_cert_expiry.py": "BLOB = 1\n"})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        return rc, r, wt

    def test_no_copy_is_written_anywhere_in_the_checkout_7489(self):
        rc, r, wt = self.make()
        before = sorted(str(p.relative_to(wt)) for p in wt.rglob("*") if ".git" not in p.parts)
        argv, data, _sha = r.expiry_gate()
        self.assertEqual(argv[-1], str(wt / "scripts" / "check_cert_expiry.py"))  # so the gate's REPO_ROOT is the checkout
        self.assertEqual(data, b"BLOB = 1\n")
        self.assertEqual(sorted(str(p.relative_to(wt)) for p in wt.rglob("*") if ".git" not in p.parts), before)
        self.assertFalse((wt / ".local-runs").exists(), "the scratch directory is never created")

    def test_a_tracked_symlink_at_the_old_fixed_path_is_never_written_through_7489(self):
        rc, r, wt = self.make()
        (wt / "victim.txt").write_text("keep\n")
        os.symlink("../victim.txt", wt / "scripts" / ".cert-expiry-gate.py")
        subprocess.run([*GIT, "add", "-A"], cwd=wt, check=True)
        subprocess.run([*GIT, "commit", "-q", "-m", "link"], cwd=wt, check=True)
        r.expiry_gate()
        self.assertEqual((wt / "victim.txt").read_text(), "keep\n")
        status = subprocess.run(["git", "status", "--porcelain"], cwd=wt, capture_output=True, text=True).stdout
        self.assertEqual(status.strip(), "")

    def test_a_symlinked_scratch_directory_is_refused_7489(self):
        rc, r, wt = self.make()
        (self.dir / "elsewhere").mkdir()
        os.symlink(self.dir / "elsewhere", wt / ".local-runs")
        with self.assertRaises(ValueError):
            r.open_scratch()
        self.assertEqual(list((self.dir / "elsewhere").iterdir()), [])

    def test_nothing_is_left_behind_when_the_gates_body_raises_7489(self):
        rc, r, wt = self.make()
        with mock.patch.object(r, "_gates", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                r.gates("0" * 40, "", "")
        self.assertFalse((wt / ".local-runs").exists())


class RowsMatchTheCode7490(ScratchCase):
    def test_preflight_exit_row_records_the_real_exit_code_7490(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        outd = self.dir / "o"
        argv = ["run_cert.py", "pg", "--tip", tip, "--wt", str(wt), "--outd", str(outd), "--targets", str(self.dir / "t"),
                "--tmpdir", str(self.dir / "tmp"), "--cargo-slot", str(self.dir / "no-such-wrapper")]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rc.main(), 64)
        text = (outd / "legs.log").read_text()
        self.assertIn("EXIT=64 leg=pg", text)
        self.assertNotIn("EXIT=1 leg=pg", text)

    def test_path_refusals_write_nothing_7490(self):
        rc = load("run_cert")
        fake = self.dir / "faketmp"
        outd = fake / "o"
        argv = ["run_cert.py", "pg", "--tip", "a" * 40, "--wt", str(self.dir), "--outd", str(outd),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        with mock.patch.object(rc, "TMP_ROOTS", (str(fake),)), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rc.main(), 64)
        self.assertFalse(outd.exists())

    def test_docstring_describes_what_is_written_7490(self):
        doc = (EVIDENCE / "run_cert.py").read_text().split('"""')[1]
        self.assertIn("write nothing", doc)
        self.assertIn("EXIT=64", doc)
        self.assertIn("RED preflight", doc)


class PathBoundary7491(GuardedCase):
    def test_a_longer_sibling_path_is_not_rewritten_7491(self):
        bb = load("build_bundle")
        out = bb.sanitize_paths("/data/tt /data/t/x /data/t\n(/data/t) 'a/data/t' /data/t,", [], ["/data/t"])
        self.assertEqual(out, "/data/tt <run-path>/x <run-path>\n(<run-path>) 'a/data/t' <run-path>,")

    def test_the_worktree_forms_follow_the_same_rule_7491(self):
        bb = load("build_bundle")
        out = bb.sanitize_paths("/w/repo/a /w/repo2/a", ["/w/repo"], [])
        self.assertEqual(out, "<repo-root>/a /w/repo2/a")

    def test_path_at_the_end_of_the_text_is_rewritten_7491(self):
        bb = load("build_bundle")
        self.assertEqual(bb.sanitize_paths("at /data/t", [], ["/data/t"]), "at <run-path>")


# #7492 / #7534: the tmp-root guard is the AST walk in test_evidence_generator_r5_7393.py (every evidence test file).


if __name__ == "__main__":
    unittest.main()
