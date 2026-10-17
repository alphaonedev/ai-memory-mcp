#!/usr/bin/env python3
"""PR #7393 round 5: gate fixtures for the delta r4 review findings (#7527-#7535) on the vendored certification
evidence generator.

  #7527  check_block refuses rows after EXIT, sections of unplanned legs and legs out of the runner's order
  #7528  the #7487 PLAN position tests fail when the position rule is removed (see test_evidence_generator_r4_7393.py)
  #7529  SANITIZATION.md records which legs.log rule judged the run
  #7530  an OSError from the expiry copy ends the gates leg with an EXIT row and a failure, no traceback
  #7531  the expiry copy sees the checkout as its repo root and leaves no nested scratch directory
  #7532  stale .expiry-* directories are swept; the open flags are pinned; creation goes through a directory fd
  #7533  sanitize_paths replaces a run path only at a real path-component boundary on both sides (#7491)
  #7534  the tmp-root guard is an AST walk over every evidence test file and catches every spelling
  #7535  --push-branch and --parent are refused on every leg but gates

Scratch lives under .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r5_7393.py
"""
import argparse
import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase, load
from test_evidence_generator_r2_7393 import GIT, make_repo
from test_evidence_generator_r3_7393 import CHAIN_LEGS, CONFIG, DONE, GREEN_CHAIN, SEC, block, leg_text

TESTS = Path(__file__).resolve().parent
EXIT_PG = "EXIT=0 leg=pg aggregate_failures=0 12:00Z\n"
CHAIN_DONE_ROW = "CHAIN_DONE aggregate_failures=0 10:55Z\n"


def chain_body(order, chain_done_at=None):
    """The body of a chain block with the legs in `order` (a list of leg names) and CHAIN_DONE after them, or at
    index `chain_done_at` of the leg list."""
    parts = [leg_text(l) for l in order]
    parts.insert(len(parts) if chain_done_at is None else chain_done_at, CHAIN_DONE_ROW)
    return "".join(parts)


class BlockOrderAndExit7527(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal) as cm:
            self.bb.check_run(self.legs(text))
        return str(cm.exception)

    def bad_shapes(self):
        pg_block = block("pg", ("pg",), leg_text("pg"))
        return {
            "unfinished removal section after a pg block's EXIT": GREEN_CHAIN + pg_block + SEC["removal"],
            "unfinished bootstrap section inside a pg block": GREEN_CHAIN + block("pg", ("pg",), leg_text("pg") + SEC["bootstrap"]),
            "unfinished CERT LEGS section inside a pg block": GREEN_CHAIN + block("pg", ("pg",), leg_text("pg") + SEC["battery"]),
            "PG_DONE after EXIT": GREEN_CHAIN + block("pg", ("pg",), SEC["pg"], exit_row=False) + EXIT_PG + DONE["pg"],
            "EXIT=0 before every leg": block("chain", CHAIN_LEGS, "EXIT=0 leg=chain aggregate_failures=0 12:00Z\n"
                                             + chain_body(CHAIN_LEGS[:-1]), exit_row=False),
            "chain legs out of runner order": block("chain", CHAIN_LEGS, chain_body(["battery", "pg", "removal", "bootstrap"])),
            "CHAIN_DONE before the bootstrap leg": block("chain", CHAIN_LEGS, chain_body(CHAIN_LEGS[:-1], chain_done_at=3)),
            "a junk row after EXIT": GREEN_CHAIN + "unrelated row\n",
            "a section of a leg the plan does not name": GREEN_CHAIN + block("pg", ("pg",), SEC["removal"] + leg_text("pg")),
            "a duplicated section": GREEN_CHAIN + block("pg", ("pg",), SEC["pg"] + leg_text("pg")),
        }

    def test_every_bad_shape_is_refused_7527(self):
        for name, text in self.bad_shapes().items():
            with self.subTest(shape=name):
                self.refused(text)

    def test_the_good_shapes_are_accepted_7527(self):
        self.bb.check_run(self.legs(GREEN_CHAIN))
        for leg in ("battery", "removal", "pg", "bootstrap"):
            self.bb.check_run(self.legs(GREEN_CHAIN + block(leg, (leg,), leg_text(leg))))
        self.bb.check_run(self.legs(GREEN_CHAIN + GREEN_CHAIN))
        self.bb.check_run(self.legs(GREEN_CHAIN + "\n"))  # a trailing blank line is not a row

    def test_the_failure_names_the_ordering_rule_7527(self):
        text = self.refused(block("chain", CHAIN_LEGS, chain_body(["battery", "pg", "removal", "bootstrap"])))
        self.assertIn("order", text)
        text = self.refused(GREEN_CHAIN + "unrelated row\n")
        self.assertIn("after its EXIT row", text)


RECAPTURE_PY = (
    "import os\nfrom pathlib import Path\n"
    "ROOT = Path(os.path.abspath(__file__)).parent.parent\n"
    'OUT = ROOT / "docs" / "x"\n'
    'FIX = ROOT / "fixtures"\n')
CERT_BOOT = "CERT-BOOTSTRAP GATE: PASS\n"


class BundleFixture(ScratchCase):
    """A complete green run directory and a worktree whose HEAD is the tip: bb.main() builds a real bundle from it."""

    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")
        self.rc = load("run_cert")
        self.wt, self.tip = make_repo(self.dir / "repo", {"scripts/recapture-cert-3607-posture.py": RECAPTURE_PY})
        self.outd = self.dir / "run"
        (self.outd / "evidence").mkdir(parents=True)
        for f in self.bb.EVIDENCE_FILES:
            (self.outd / "evidence" / f).write_text("x\n")
        header = (f"CERT-PROOF: tip={self.tip} short={self.tip[:9]} branch=b worktree={self.wt.resolve()} dirty=0 "
                  "controls=15 started=now")
        (self.outd / "removal-proof-full.log").write_text(
            header + "\n" + "[PROVEN]\n" * 15 + header + "\noverall: PASS\n")
        self.boot("")
        ok = "test result: ok. 3 passed; 0 failed; 0 ignored\n"
        for n in self.rc.BINS:
            (self.outd / f"test-{n}.log").write_text(ok)
        for n in self.rc.LIBS:
            (self.outd / ("lib-" + n.replace(":", "_") + ".log")).write_text(ok)
        (self.outd / f"test-pg-{self.rc.PG_BIN[0]}.log").write_text(ok)
        (self.outd / f"lib-pg-{self.rc.PG_LIB[0]}.log").write_text(ok)
        (self.outd / "legs.log").write_text(GREEN_CHAIN)
        self.san = self.dir / "SANITIZATION.md"
        self.san.write_text("# Sanitization\nauthor prose\n")

    def boot(self, extra):
        (self.outd / "bootstrap-cert-gate.log").write_text(CERT_BOOT + extra)

    def build(self):
        argv = ["build_bundle.py", "--tip", self.tip, "--wt", str(self.wt), "--outd", str(self.outd),
                "--sanitization", str(self.san), "--date", "2026-10-17"]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.bb.main()
        return code, out.getvalue() + err.getvalue()

    def bundle_file(self, name):
        return (self.wt / "docs/compliance/evidence" / f"cert-{self.tip[:9]}" / name).read_text()


class RuleRecorded7529(BundleFixture):
    def rule_line(self):
        lines = [l for l in self.bundle_file("SANITIZATION.md").splitlines() if l.startswith("legs.log rule: ")]
        self.assertEqual(len(lines), 1, lines)
        return lines[0]

    def test_check_run_returns_the_rule_that_judged_the_log_7529(self):
        legacy = "".join(leg_text(l) for l in CHAIN_LEGS[:-1]) + CHAIN_DONE_ROW
        rules = {}
        for name, text in (("config", GREEN_CHAIN), ("legacy", legacy), ("mixed", legacy + GREEN_CHAIN)):
            rules[name] = self.bb.check_run(self.legs(text)).rule
        self.assertEqual(len(set(rules.values())), 3, rules)
        self.assertIn("CONFIG", rules["config"])
        self.assertNotIn("legacy", rules["config"])
        self.assertIn("legacy", rules["legacy"])
        self.assertNotIn("CONFIG", rules["legacy"])
        self.assertIn("CONFIG", rules["mixed"])
        self.assertIn("legacy", rules["mixed"])

    def test_check_run_still_returns_the_count_diff_notes_7529(self):
        self.assertEqual(list(self.bb.check_run(self.legs(GREEN_CHAIN))), [])

    def test_sanitization_md_records_the_config_rule_7529(self):
        code, text = self.build()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.rule_line(), "legs.log rule: " + self.bb.check_run(self.outd).rule)
        self.assertIn("CONFIG", self.rule_line())
        self.assertIn("author prose", self.bundle_file("SANITIZATION.md"))

    def test_sanitization_md_records_the_legacy_rule_7529(self):
        (self.outd / "legs.log").write_text("".join(leg_text(l) for l in CHAIN_LEGS[:-1]) + CHAIN_DONE_ROW)
        code, text = self.build()
        self.assertEqual(code, 0, text)
        self.assertIn("legacy", self.rule_line())
        self.assertNotIn("CONFIG", self.rule_line())


REWRITTEN = (  # (text, expected): a real run path /data/t at a real path-component boundary (#7533, #7491)
    ("see /data/t.", "see <run-path>."),
    ("see /data/t. Next", "see <run-path>. Next"),
    ("`/data/t`", "`<run-path>`"),
    ("/data/t<x>", "<run-path><x>"),
    ("{/data/t}", "{<run-path>}"),
    ("a|/data/t|b", "a|<run-path>|b"),
    ("wrote /data/t!", "wrote <run-path>!"),
    ("is /data/t?", "is <run-path>?"),
    ("//data/t", "/<run-path>"),
    ("x -/data/t y", "x -<run-path> y"),
    ("--out=/data/t", "--out=<run-path>"),
    ("PATH=/data/t:/usr/bin", "PATH=<run-path>:/usr/bin"),
    ("/data/t, /data/u", "<run-path>, /data/u"),
    ("(/data/t).", "(<run-path>)."),
    ("'/data/t'", "'<run-path>'"),
    ("/data/t\n", "<run-path>\n"),
    ("/data/t/x/y", "<run-path>/x/y"),
    ("at /data/t", "at <run-path>"),
)
KEPT = (  # different paths: never rewritten (#7533)
    "/data/t,v", "/data/t:old", "/data/t;1", "/data/t)x", "/data/t]x", "/data/t'x", "/data/t.bak", "/data/tt",
    "/data/t-old", "/data/t_x", "/data/t+x", "/data/t@x", "/data/t%x", "/data/t=x", "a/data/t", "x./data/t")


class SanitizeBoundary7533(unittest.TestCase):
    def setUp(self):
        self.bb = load("build_bundle")

    def test_real_run_paths_are_rewritten_7533(self):
        for text, want in REWRITTEN:
            with self.subTest(text=text):
                self.assertEqual(self.bb.sanitize_paths(text, [], ["/data/t"]), want)

    def test_different_paths_are_kept_7533(self):
        for text in KEPT:
            with self.subTest(text=text):
                self.assertEqual(self.bb.sanitize_paths(f"see {text} end", [], ["/data/t"]), f"see {text} end")

    def test_the_worktree_forms_follow_the_same_rule_7533(self):
        out = self.bb.sanitize_paths("`/w/repo`, /w/repo.bak /w/repo2/a /w/repo/a.", ["/w/repo"], [])
        self.assertEqual(out, "`<repo-root>`, /w/repo.bak /w/repo2/a <repo-root>/a.")

    def test_the_longest_path_is_replaced_first_7533(self):
        out = self.bb.sanitize_paths("/data/t/sub. /data/t.", [], ["/data/t", "/data/t/sub"])
        self.assertEqual(out, "<run-path>. <run-path>.")

    def test_the_leak_scan_uses_the_same_boundary_on_the_right_7533(self):
        pats = ["/data/t", "/mnt/"]
        for text, _want in REWRITTEN:
            with self.subTest(text=text):
                self.assertTrue(self.bb.hits(text, pats), text)
        for text in KEPT:
            if text.startswith(("a/", "x.")):
                continue  # a path with a leading name character stays a leak: the left side fails closed
            with self.subTest(text=text):
                self.assertEqual(self.bb.hits(f"see {text} end", pats), [])
        self.assertTrue(self.bb.hits("see a/data/t end", pats))
        self.assertTrue(self.bb.hits("under /mnt/whatever", pats), "a host prefix is still a plain substring")


class BuildKeepsSiblings7533(BundleFixture):
    SIBLINGS = ("/data/cert-t.bak", "/data/cert-tt", "/data/cert-t-old", "/data/cert-t,v", "/data/cert-t:old",
                "/data/cert-t)x")

    def test_a_kept_sibling_does_not_fail_the_build_and_a_real_path_is_rewritten_7533(self):
        self.boot("".join(f"kept {s}\n" for s in self.SIBLINGS) + "wrote /data/cert-t.\nfrom `/data/cert-d` and /data/cert-o/x\n")
        code, text = self.build()
        self.assertEqual(code, 0, text)
        log = self.bundle_file("bootstrap-cert-gate.log")
        for s in self.SIBLINGS:
            self.assertIn(f"kept {s}\n", log)
        self.assertIn("wrote <run-path>.\n", log)
        self.assertIn("from `<run-path>` and <run-path>/x\n", log)

    def test_a_run_path_that_cannot_be_rewritten_still_fails_the_build_7533(self):
        self.boot("under a/data/cert-t/x\n")  # a leading name character: not rewritten, still a leak
        code, text = self.build()
        self.assertEqual(code, 1)
        self.assertIn("leak scan", text)


class GatesRun(ScratchCase):
    def make(self, files=None):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", files if files is not None else {"scripts/check_cert_expiry.py": "BLOB = 1\n"})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        return rc, r, wt, tip


class OSErrorEndsTheGatesLeg7530(GatesRun):
    def drive(self, wt, tip):
        argv = ["run_cert.py", "gates", "--tip", tip, "--wt", str(wt), "--outd", str(self.dir / "o2"),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        rc = load("run_cert")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main()  # an uncaught OSError would raise here
        return code, out.getvalue(), (self.dir / "o2" / "legs.log").read_text()

    def test_a_regular_file_at_the_scratch_path_is_a_failure_with_an_exit_row_7530(self):
        rc, r, wt, tip = self.make()
        (wt / ".local-runs").write_text("not a directory\n")
        code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1)
        self.assertIn("RED expiry gate", out)
        self.assertRegex(log, r"EXIT=1 leg=gates aggregate_failures=[1-9]")
        self.assertNotIn("Traceback", out)

    def test_an_unwritable_scratch_directory_is_a_failure_with_an_exit_row_7530(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        rc, r, wt, tip = self.make()
        scratch = wt / ".local-runs"
        scratch.mkdir(exist_ok=True)
        scratch.chmod(0o500)
        self.addCleanup(scratch.chmod, 0o700)
        code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1)
        self.assertIn("RED expiry gate", out)
        self.assertRegex(log, r"EXIT=1 leg=gates aggregate_failures=[1-9]")


class ExpiryCopyLayout7531(GatesRun):
    def test_the_gate_sees_the_checkout_as_its_repo_root_7531(self):
        rc, r, wt, tip = self.make()
        copy = Path(r.pick_expiry()[1])
        self.assertEqual(copy.resolve().parent.parent, wt.resolve(), "the gate derives REPO_ROOT as parent.parent")
        r.drop_expiry()

    def test_no_nested_scratch_directory_is_left_7531(self):
        rc, r, wt, tip = self.make()
        r.pick_expiry()
        r.drop_expiry()
        self.assertEqual(sorted(p.name for p in (wt / ".local-runs").iterdir()), [])
        self.assertFalse((wt / ".local-runs" / ".local-runs").exists())

    def test_the_docstrings_state_the_layout_7531(self):
        doc = load("run_cert").Run.pick_expiry.__doc__
        self.assertIn("REPO_ROOT", doc)
        self.assertNotIn("0700 directory", doc)


class ExpiryCopyCreation7532(GatesRun):
    def test_the_copy_is_opened_exclusive_nofollow_and_private_7532(self):
        rc, r, wt, tip = self.make()
        flags = []
        real = os.open

        def spy(path, fl, mode=0o777, *a, **k):
            flags.append((str(path), fl, mode))
            return real(path, fl, mode, *a, **k)
        with mock.patch("os.open", side_effect=spy):
            r.pick_expiry()
        r.drop_expiry()
        mine = [f for f in flags if os.path.basename(f[0]).startswith(".expiry-")]
        self.assertTrue(mine, flags)
        _p, fl, mode = mine[-1]
        for flag in ("O_EXCL", "O_NOFOLLOW", "O_CREAT", "O_WRONLY"):
            self.assertTrue(fl & getattr(os, flag), flag)
        self.assertEqual(mode, 0o600)
        dirs = [f for f in flags if f[1] & getattr(os, "O_DIRECTORY", 0)]
        self.assertTrue(dirs and all(f[1] & os.O_NOFOLLOW for f in dirs), "the scratch dir is opened O_DIRECTORY|O_NOFOLLOW")

    def test_a_scratch_directory_swapped_for_a_symlink_is_refused_7532(self):
        rc, r, wt, tip = self.make()
        (self.dir / "elsewhere").mkdir()
        os.symlink(self.dir / "elsewhere", wt / ".local-runs")
        with self.assertRaises(ValueError):
            r.pick_expiry()
        self.assertEqual(list((self.dir / "elsewhere").iterdir()), [])

    def test_stale_copies_of_a_killed_run_are_swept_on_the_next_run_7532(self):
        rc, r, wt, tip = self.make()
        scratch = wt / ".local-runs"
        scratch.mkdir(exist_ok=True)
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        stale_file = scratch / f".expiry-{gone.pid}-aaaa.py"
        stale_dir = scratch / ".expiry-oldlayout"
        stale_file.write_text("x\n")
        stale_dir.mkdir()
        (stale_dir / "check_cert_expiry.py").write_text("x\n")
        live = scratch / f".expiry-{os.getppid()}-bbbb.py"  # a live process: its copy is not touched
        live.write_text("x\n")
        keep = scratch / "keep.txt"
        keep.write_text("keep\n")
        r.pick_expiry()
        self.assertFalse(stale_file.exists())
        self.assertFalse(stale_dir.exists())
        self.assertTrue(live.exists())
        self.assertTrue(keep.exists())
        r.drop_expiry()


if __name__ == "__main__":
    unittest.main()
